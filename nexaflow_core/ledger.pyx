# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
"""
Cython-optimized ledger management for NexaFlow.

The ledger stores:
  - Account balances (native NXF)
  - Trust lines (IOU balances & limits)
  - Open offers (order book)
  - Transaction history per ledger sequence
  - Ledger headers with hash-chained integrity

Mirrors NexaFlow's concept of sequential validated ledgers.
"""

import hashlib
import json
import struct
import copy
import time as _py_time

cimport cython
from libc.time cimport time as c_time

from nexaflow_core.staking import (
    StakingPool, StakeTier, TIER_NAMES, StakeRecord,
    TIER_CONFIG, MIN_STAKE_AMOUNT, SECONDS_PER_YEAR,
    EARLY_INTEREST_PENALTY, EARLY_PRINCIPAL_PENALTY,
)
from nexaflow_core.escrow import EscrowManager
from nexaflow_core.payment_channel import PaymentChannelManager
from nexaflow_core.check import CheckManager
from nexaflow_core.multi_sign import MultiSignManager
from nexaflow_core.amendments import AmendmentManager
from nexaflow_core.nftoken import NFTokenManager
from nexaflow_core.ticket import TicketManager


# ── GIL-free arithmetic helpers ──────────────────────────────────────────────

cdef inline bint _balance_ok(double balance, double debit, double reserve) nogil:
    """Check balance covers debit + reserve without touching Python objects."""
    return balance - debit >= reserve


cdef inline double _sub(double a, double b) nogil:
    """Subtract two doubles without the GIL."""
    return a - b


cdef inline double _add(double a, double b) nogil:
    """Add two doubles without the GIL."""
    return a + b


# ===================================================================
#  Confidential UTXO output — produced by confidential payments
# ===================================================================

@cython.freelist(16)
cdef class ConfidentialOutput:
    """
    A Pedersen-committed UTXO note produced by a confidential payment.

    Fields mirror a Monero transaction output:
      commitment    — C = v*G + b*H (hides the amount v)
      stealth_addr  — one-time address; only recipient can identify / spend
      ephemeral_pub — r*G published on chain so recipient can derive shared secret
      range_proof   — ZKP that v ≥ 0
      view_tag      — 1-byte hint for fast output scanning
      tx_id         — ID of the transaction that created this output
      spent         — True once a subsequent ring-sig references this output
    """
    cdef public bytes commitment
    cdef public bytes stealth_addr
    cdef public bytes ephemeral_pub
    cdef public bytes range_proof
    cdef public bytes view_tag
    cdef public str   tx_id
    cdef public bint  spent

    def __init__(self, bytes commitment, bytes stealth_addr,
                 bytes ephemeral_pub, bytes range_proof,
                 bytes view_tag, str tx_id):
        self.commitment    = commitment
        self.stealth_addr  = stealth_addr
        self.ephemeral_pub = ephemeral_pub
        self.range_proof   = range_proof
        self.view_tag      = view_tag
        self.tx_id         = tx_id
        self.spent         = False

    cpdef dict to_dict(self):
        return {
            "commitment":    self.commitment.hex(),
            "stealth_addr":  self.stealth_addr.hex(),
            "ephemeral_pub": self.ephemeral_pub.hex() if self.ephemeral_pub else "",
            "range_proof":   self.range_proof.hex()   if self.range_proof   else "",
            "view_tag":      self.view_tag.hex()       if self.view_tag      else "",
            "tx_id":         self.tx_id,
            "spent":         self.spent,
        }


# ===================================================================
#  Account entry stored in the ledger
# ===================================================================

@cython.freelist(8)
cdef class AccountEntry:
    """State of a single account inside a ledger."""
    cdef public str address
    cdef public double balance          # native NXF
    cdef public long long sequence      # next expected tx sequence
    cdef public long long owner_count   # number of owned objects
    cdef public dict trust_lines       # {(currency, issuer): TrustLineEntry}
    cdef public list open_offers
    cdef public double transfer_rate
    cdef public bint is_gateway
    cdef public bint require_dest    # asfRequireDest
    cdef public bint disable_master  # asfDisableMaster
    cdef public bint default_ripple  # asfDefaultRipple
    cdef public bint global_freeze   # asfGlobalFreeze
    cdef public bint deposit_auth    # asfDepositAuth
    cdef public str regular_key      # SetRegularKey address
    cdef public str domain           # domain verification string
    cdef public set deposit_preauth  # set of preauthorised addresses
    cdef public list tickets         # list of ticket_ids

    def __init__(self, str address, double balance=0.0):
        self.address = address
        self.balance = balance
        self.sequence = 1
        self.owner_count = 0
        self.trust_lines = {}
        self.open_offers = []
        self.transfer_rate = 1.0
        self.is_gateway = False
        self.require_dest = False
        self.disable_master = False
        self.default_ripple = False
        self.global_freeze = False
        self.deposit_auth = False
        self.regular_key = ""
        self.domain = ""
        self.deposit_preauth = set()
        self.tickets = []

    cpdef dict to_dict(self):
        cdef dict tl = {}
        for key, entry in self.trust_lines.items():
            tl[f"{key[0]}/{key[1][:8]}"] = entry.to_dict()
        return {
            "address": self.address,
            "balance": self.balance,
            "sequence": self.sequence,
            "owner_count": self.owner_count,
            "trust_lines": tl,
            "open_offers": len(self.open_offers),
            "is_gateway": self.is_gateway,
        }


# ===================================================================
#  Trust-line entry (stored inside AccountEntry)
# ===================================================================

@cython.freelist(8)
cdef class TrustLineEntry:
    """A single trust line between two accounts for an IOU currency."""
    cdef public str currency
    cdef public str issuer
    cdef public str holder
    cdef public double balance          # current IOU balance
    cdef public double limit            # max the holder trusts
    cdef public double limit_peer       # max the issuer trusts back
    cdef public bint no_ripple          # disable rippling flag
    cdef public bint frozen             # trust line freeze flag
    cdef public bint authorized         # authorized trust line flag
    cdef public double quality_in       # inbound quality (multiplier)
    cdef public double quality_out      # outbound quality (multiplier)

    def __init__(self, str currency, str issuer, str holder,
                 double limit=0.0):
        self.currency = currency
        self.issuer = issuer
        self.holder = holder
        self.balance = 0.0
        self.limit = limit
        self.limit_peer = 0.0
        self.no_ripple = False
        self.frozen = False
        self.authorized = False
        self.quality_in = 1.0
        self.quality_out = 1.0

    cpdef dict to_dict(self):
        return {
            "currency": self.currency,
            "issuer": self.issuer,
            "holder": self.holder,
            "balance": self.balance,
            "limit": self.limit,
            "limit_peer": self.limit_peer,
        }


# ===================================================================
#  Ledger header
# ===================================================================

@cython.freelist(4)
cdef class LedgerHeader:
    """Immutable header for a closed ledger."""
    cdef public long long sequence
    cdef public str hash
    cdef public str parent_hash
    cdef public str tx_hash            # merkle root of txns
    cdef public str state_hash         # hash of account states
    cdef public long long close_time
    cdef public long long tx_count
    cdef public double total_nxf

    def __init__(self, long long sequence, str parent_hash="0" * 64):
        self.sequence = sequence
        self.hash = ""
        self.parent_hash = parent_hash
        self.tx_hash = ""
        self.state_hash = ""
        self.close_time = <long long>c_time(NULL)
        self.tx_count = 0
        self.total_nxf = 0.0

    cpdef void compute_hash(self):
        """Compute this ledger's hash from its fields."""
        cdef bytes blob = struct.pack(">q", self.sequence)
        blob += self.parent_hash.encode()
        blob += self.tx_hash.encode()
        blob += self.state_hash.encode()
        blob += struct.pack(">q", self.close_time)
        blob += struct.pack(">q", self.tx_count)
        blob += struct.pack(">d", self.total_nxf)
        self.hash = hashlib.blake2b(blob, digest_size=32).hexdigest()

    cpdef dict to_dict(self):
        return {
            "sequence": self.sequence,
            "hash": self.hash,
            "parent_hash": self.parent_hash,
            "tx_hash": self.tx_hash,
            "state_hash": self.state_hash,
            "close_time": self.close_time,
            "tx_count": self.tx_count,
            "total_nxf": self.total_nxf,
        }


# ===================================================================
#  Main Ledger
# ===================================================================

cdef class Ledger:
    """
    The current mutable ledger state plus history of closed ledgers.

    Provides methods for:
      - account creation / lookup
      - trust-line management
      - applying validated transactions
      - closing ledgers (snapshot + hash chain)
    """
    cdef public dict accounts          # address -> AccountEntry
    cdef public list closed_ledgers    # list[LedgerHeader]
    cdef public list pending_txns     # txns in current open ledger
    cdef public long long current_sequence
    cdef public double total_supply
    cdef public double initial_supply   # snapshot of genesis supply (immutable)
    cdef public double total_burned     # cumulative fees & penalties burned
    cdef public double total_minted    # cumulative interest minted
    cdef public str genesis_account
    cdef public set spent_key_images   # bytes → kept for is_key_image_spent API
    cdef public set applied_tx_ids     # str  → duplicate-TX detection
    cdef public dict confidential_outputs  # stealth_addr_hex → ConfidentialOutput
    cdef public object staking_pool    # StakingPool instance
    cdef public object escrow_manager  # EscrowManager instance
    cdef public object channel_manager # PaymentChannelManager instance
    cdef public object check_manager   # CheckManager instance
    cdef public object multi_sign_manager  # MultiSignManager instance
    cdef public object amendment_manager   # AmendmentManager instance
    cdef public object nftoken_manager     # NFTokenManager instance
    cdef public object ticket_manager      # TicketManager instance

    def __init__(self, double total_supply=100_000_000_000.0,
                 str genesis_account="nGenesisNXF"):
        self.accounts = {}
        self.closed_ledgers = []
        self.pending_txns = []
        self.current_sequence = 1
        self.total_supply = total_supply
        self.initial_supply = total_supply
        self.total_burned = 0.0
        self.total_minted = 0.0
        self.genesis_account = genesis_account
        self.spent_key_images = set()
        self.applied_tx_ids = set()
        self.confidential_outputs = {}  # stealth_addr_hex → ConfidentialOutput
        self.staking_pool = StakingPool()
        self.escrow_manager = EscrowManager()
        self.channel_manager = PaymentChannelManager()
        self.check_manager = CheckManager()
        self.multi_sign_manager = MultiSignManager()
        self.amendment_manager = AmendmentManager()
        self.nftoken_manager = NFTokenManager()
        self.ticket_manager = TicketManager()

        # Create genesis account with full supply
        cdef AccountEntry genesis = AccountEntry(genesis_account, total_supply)
        genesis.is_gateway = True
        self.accounts[genesis_account] = genesis

    # ---- account management ----

    cpdef object get_account(self, str address):
        """Return AccountEntry or None."""
        return self.accounts.get(address)

    cpdef object create_account(self, str address, double initial_nxf=0.0):
        """Create a new account. Returns the AccountEntry."""
        if address in self.accounts:
            return self.accounts[address]
        cdef AccountEntry acc = AccountEntry(address, initial_nxf)
        self.accounts[address] = acc
        return acc

    cpdef bint account_exists(self, str address):
        return address in self.accounts

    # ---- trust-line management ----

    cpdef object set_trust_line(self, str holder, str currency,
                                str issuer, double limit):
        """
        Create or update a trust line from holder toward issuer.
        Returns the TrustLineEntry.
        """
        cdef AccountEntry acc = self.accounts.get(holder)
        if acc is None:
            return None
        cdef tuple key = (currency, issuer)
        cdef TrustLineEntry tl
        if key in acc.trust_lines:
            tl = acc.trust_lines[key]
            tl.limit = limit
        else:
            tl = TrustLineEntry(currency, issuer, holder, limit)
            acc.trust_lines[key] = tl
            acc.owner_count += 1
        return tl

    cpdef object get_trust_line(self, str holder, str currency, str issuer):
        """Retrieve a trust line entry or None."""
        cdef AccountEntry acc = self.accounts.get(holder)
        if acc is None:
            return None
        return acc.trust_lines.get((currency, issuer))

    # ---- transaction application ----

    cpdef int apply_payment(self, object tx):
        """
        Apply a Payment transaction to ledger state.
        Confidential transactions (with key_image set) are routed to
        _apply_confidential_payment; normal payments use the standard path.
        Returns a result code.
        """
        if tx.key_image:
            return self._apply_confidential_payment(tx)

        from nexaflow_core.transaction import Amount
        cdef object amount = tx.amount
        cdef object fee = tx.fee
        cdef str src = tx.account
        cdef str dst = tx.destination

        # Source must exist
        cdef AccountEntry src_acc = self.accounts.get(src)
        if src_acc is None:
            return 101  # tecUNFUNDED

        # Create destination if needed (for native payments)
        if dst not in self.accounts:
            self.create_account(dst)
        cdef AccountEntry dst_acc = self.accounts[dst]

        # Check sequence
        if tx.sequence != 0 and tx.sequence != src_acc.sequence:
            return 105  # tecBAD_SEQ

        cdef double amt = amount.value
        cdef double fee_val = fee.value
        cdef str cur
        cdef str iss
        cdef double effective_amt = amt
        cdef AccountEntry iss_acc

        if amount.is_native():
            # Native NXF payment
            if src_acc.balance < amt + fee_val:
                return 101  # tecUNFUNDED
            src_acc.balance -= (amt + fee_val)
            dst_acc.balance += amt
            # Burn the fee — permanently remove from circulation
            self.total_supply -= fee_val
            self.total_burned += fee_val
        else:
            # IOU payment — requires trust lines
            cur = amount.currency
            iss = amount.issuer

            # Debit fee in native
            if src_acc.balance < fee_val:
                return 104  # tecINSUF_FEE
            src_acc.balance -= fee_val
            # Burn the fee — permanently remove from circulation
            self.total_supply -= fee_val
            self.total_burned += fee_val

            # Check sender's trust line (or sender is issuer)
            effective_amt = amt
            if src != iss:
                tl_src = self.get_trust_line(src, cur, iss)
                if tl_src is None:
                    return 103  # tecNO_LINE
                # noRipple enforcement: if set, sender cannot ripple through
                if tl_src.no_ripple:
                    return 115  # tecNO_RIPPLE
                # Frozen trust line check
                if tl_src.frozen:
                    return 116  # tecFROZEN
                # Apply transfer_rate if sender is not the issuer
                iss_acc = self.accounts.get(iss)
                if iss_acc is not None and iss_acc.transfer_rate > 1.0:
                    effective_amt = amt * iss_acc.transfer_rate
                if tl_src.balance < effective_amt:
                    return 101  # tecUNFUNDED
                tl_src.balance -= effective_amt
            # Credit receiver's trust line (or receiver is issuer)
            if dst != iss:
                tl_dst = self.get_trust_line(dst, cur, iss)
                if tl_dst is None:
                    return 103  # tecNO_LINE
                if tl_dst.frozen:
                    return 116  # tecFROZEN
                if tl_dst.balance + amt > tl_dst.limit:
                    return 101  # tecUNFUNDED — would exceed trust
                tl_dst.balance += amt

        # Bump sequence
        src_acc.sequence += 1
        return 0  # tesSUCCESS

    cpdef int _apply_confidential_payment(self, object tx):
        """
        Apply a Confidential Payment (Monero-style UTXO note).

        Checks:
          1. Key image not already spent (double-spend prevention)
          2. Range proof integrity  (value ≥ 0 without revealing it)
          3. Ring signature validity (sender authorised without revealing address)
          4. Fee deducted from sender's public account
          5. New ConfidentialOutput UTXO recorded in ledger
          6. Key image marked as spent
        
        The hidden amount is never written to the account table; only the
        Pedersen commitment is stored in the UTXO output entry.
        """
        from nexaflow_core.privacy import RangeProof, verify_ring_signature

        # ── 1. Double-spend check (per tx_id) ────────────────────────────────
        if tx.tx_id and tx.tx_id in self.applied_tx_ids:
            return 107  # tecKEY_IMAGE_SPENT — duplicate transaction

        # ── 2. Range proof: value committed is non-negative ───────────────
        if tx.range_proof and tx.commitment:
            rp = RangeProof(tx.range_proof)
            if not rp.verify(tx.commitment):
                return 106  # tecBAD_SIG — range proof invalid

        # ── 3. Ring signature: sender is member of the ring ───────────────
        if tx.ring_signature:
            msg_hash = tx.hash_for_signing()
            if not verify_ring_signature(tx.ring_signature, msg_hash):
                return 106  # tecBAD_SIG — ring sig invalid

        # ── 4. Fee is paid publicly from the sender's account ────────────
        cdef str src = tx.account
        cdef double fee_val = tx.fee.value if hasattr(tx.fee, 'value') else 0.0
        cdef AccountEntry src_acc = self.accounts.get(src)
        if fee_val > 0.0:
            if src_acc is None:
                return 101  # tecUNFUNDED — no account to pay fee
            if src_acc.balance < fee_val:
                return 104  # tecINSUF_FEE
            src_acc.balance -= fee_val
            # Burn the fee — permanently remove from circulation
            self.total_supply -= fee_val
            self.total_burned += fee_val
        # Advance sequence so the tx cannot be replayed
        if src_acc is not None:
            if tx.sequence != 0 and tx.sequence != src_acc.sequence:
                return 105  # tecBAD_SEQ
            src_acc.sequence += 1

        # ── 5. Record the UTXO output ─────────────────────────────────────
        if tx.commitment and tx.stealth_address:
            sa_hex = tx.stealth_address.hex()
            output = ConfidentialOutput(
                tx.commitment,
                tx.stealth_address,
                tx.ephemeral_pub if tx.ephemeral_pub else b"",
                tx.range_proof if tx.range_proof else b"",
                tx.view_tag if tx.view_tag else b"",
                tx.tx_id,
            )
            self.confidential_outputs[sa_hex] = output

        # ── 6. Mark key image as spent and record applied tx_id ─────────────
        self.spent_key_images.add(tx.key_image)
        if tx.tx_id:
            self.applied_tx_ids.add(tx.tx_id)
        return 0  # tesSUCCESS

    cpdef int apply_trust_set(self, object tx):
        """Apply a TrustSet transaction."""
        cdef str src = tx.account
        cdef AccountEntry src_acc = self.accounts.get(src)
        if src_acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        if src_acc.balance < fee_val:
            return 104
        src_acc.balance -= fee_val
        # Burn the fee — permanently remove from circulation
        self.total_supply -= fee_val
        self.total_burned += fee_val

        if tx.sequence != 0 and tx.sequence != src_acc.sequence:
            return 105

        cdef object la = tx.limit_amount
        self.set_trust_line(src, la.currency, la.issuer, la.value)
        src_acc.sequence += 1
        return 0

    cpdef int apply_transaction(self, object tx):
        """Route a transaction to the correct handler. Returns result code."""
        cdef int tt = tx.tx_type
        cdef int result
        # Duplicate-TX detection (all types)
        if tx.tx_id and tx.tx_id in self.applied_tx_ids:
            tx.result_code = 109  # tecSTAKE_DUPLICATE (reuse for general dup)
            return 109
        if tt == 0:      # Payment
            result = self.apply_payment(tx)
        elif tt == 1:    # EscrowCreate
            result = self.apply_escrow_create(tx)
        elif tt == 2:    # EscrowFinish
            result = self.apply_escrow_finish(tx)
        elif tt == 3:    # AccountSet
            result = self.apply_account_set(tx)
        elif tt == 4:    # EscrowCancel
            result = self.apply_escrow_cancel(tx)
        elif tt == 5:    # SetRegularKey
            result = self.apply_set_regular_key(tx)
        elif tt == 7:    # OfferCreate
            result = self.apply_offer_create(tx)
        elif tt == 8:    # OfferCancel
            result = self.apply_offer_cancel(tx)
        elif tt == 12:   # SignerListSet
            result = self.apply_signer_list_set(tx)
        elif tt == 13:   # PayChanCreate
            result = self.apply_paychan_create(tx)
        elif tt == 14:   # PayChanFund
            result = self.apply_paychan_fund(tx)
        elif tt == 15:   # PayChanClaim
            result = self.apply_paychan_claim(tx)
        elif tt == 16:   # CheckCreate
            result = self.apply_check_create(tx)
        elif tt == 17:   # CheckCash
            result = self.apply_check_cash(tx)
        elif tt == 18:   # CheckCancel
            result = self.apply_check_cancel(tx)
        elif tt == 19:   # DepositPreauth
            result = self.apply_deposit_preauth(tx)
        elif tt == 20:   # TrustSet
            result = self.apply_trust_set(tx)
        elif tt == 21:   # AccountDelete
            result = self.apply_account_delete(tx)
        elif tt == 22:   # TicketCreate
            result = self.apply_ticket_create(tx)
        elif tt == 25:   # NFTokenMint
            result = self.apply_nftoken_mint(tx)
        elif tt == 26:   # NFTokenBurn
            result = self.apply_nftoken_burn(tx)
        elif tt == 27:   # NFTokenOfferCreate
            result = self.apply_nftoken_offer_create(tx)
        elif tt == 28:   # NFTokenOfferAccept
            result = self.apply_nftoken_offer_accept(tx)
        elif tt == 30:   # Stake
            result = self.apply_stake(tx)
        elif tt == 31:   # Unstake (early cancel)
            result = self.apply_unstake(tx)
        else:
            result = 0   # for simplicity, other types succeed
        tx.result_code = result
        if result == 0:
            self.pending_txns.append(tx)
            if tx.tx_id:
                self.applied_tx_ids.add(tx.tx_id)
        return result

    # ---- ledger closing ----

    cpdef object close_ledger(self):
        """
        Close the current ledger:
          1. Compute transaction merkle hash
          2. Compute state hash
          3. Build hash-chain header
          4. Archive the header and clear pending txns
        Returns the LedgerHeader for the closed ledger.
        """
        cdef str parent_hash = ""
        cdef int n_closed = len(self.closed_ledgers)
        if n_closed > 0:
            parent_hash = (<LedgerHeader>self.closed_ledgers[n_closed - 1]).hash
        else:
            parent_hash = "0" * 64

        cdef LedgerHeader header = LedgerHeader(self.current_sequence, parent_hash)
        header.tx_count = len(self.pending_txns)

        # ── Auto-mature stakes ──────────────────────────────────────────
        # Process all stakes that have reached maturity at this ledger close.
        # Credits principal + interest back to the staker's account.
        close_now = header.close_time
        matured_payouts = self.staking_pool.mature_stakes(now=close_now)
        for mat_addr, mat_principal, mat_interest in matured_payouts:
            mat_acc = <AccountEntry>self.accounts.get(mat_addr)
            if mat_acc is not None:
                mat_acc.balance += mat_principal + mat_interest
                # Interest is newly minted — adds to circulating supply
                self.total_supply += mat_interest
                self.total_minted += mat_interest

        # Transaction merkle hash (simplified: hash of all tx_ids concatenated)
        cdef bytes tx_blob = b""
        for tx in self.pending_txns:
            tx_blob += tx.tx_id.encode("utf-8")
        header.tx_hash = hashlib.blake2b(tx_blob, digest_size=32).hexdigest() if tx_blob else "0" * 64

        # State hash (simplified: hash of all account balances + confidential state)
        cdef bytes state_blob = b""
        for addr in sorted(self.accounts.keys()):
            acc = self.accounts[addr]
            state_blob += addr.encode("utf-8")
            state_blob += struct.pack(">d", acc.balance)
            state_blob += struct.pack(">q", acc.sequence)
        # Include commitment to confidential UTXOs and spent key images
        state_blob += struct.pack(">q", len(self.confidential_outputs))
        state_blob += struct.pack(">q", len(self.spent_key_images))
        for sa_hex in sorted(self.confidential_outputs.keys()):
            out = self.confidential_outputs[sa_hex]
            state_blob += out.commitment
        header.state_hash = hashlib.blake2b(state_blob, digest_size=32).hexdigest()

        header.total_nxf = self.total_supply
        header.compute_hash()

        self.closed_ledgers.append(header)
        self.pending_txns = []
        self.current_sequence += 1
        return header

    # ---- DEX offers ----

    cpdef int apply_offer_create(self, object tx):
        """Apply an OfferCreate transaction.

        Validates sequence, deducts fee, records the offer, and
        increments the account sequence.
        """
        cdef str src = tx.account
        cdef AccountEntry src_acc = self.accounts.get(src)
        if src_acc is None:
            return 101  # tecUNFUNDED

        cdef double fee_val = tx.fee.value
        if src_acc.balance < fee_val:
            return 104  # tecINSUF_FEE
        src_acc.balance -= fee_val
        # Burn the fee
        self.total_supply -= fee_val
        self.total_burned += fee_val

        if tx.sequence != 0 and tx.sequence != src_acc.sequence:
            return 105  # tecBAD_SEQ

        # Record the open offer on the account
        src_acc.open_offers.append({
            "taker_pays": tx.taker_pays,
            "taker_gets": tx.taker_gets,
            "tx_id": tx.tx_id,
        })
        src_acc.owner_count += 1

        src_acc.sequence += 1
        return 0  # tesSUCCESS

    cpdef int apply_offer_cancel(self, object tx):
        """Apply an OfferCancel transaction.

        Validates sequence, deducts fee, removes the matching offer,
        and increments the account sequence.
        """
        cdef str src = tx.account
        cdef AccountEntry src_acc = self.accounts.get(src)
        if src_acc is None:
            return 101  # tecUNFUNDED

        cdef double fee_val = tx.fee.value
        if src_acc.balance < fee_val:
            return 104  # tecINSUF_FEE
        src_acc.balance -= fee_val
        # Burn the fee
        self.total_supply -= fee_val
        self.total_burned += fee_val

        if tx.sequence != 0 and tx.sequence != src_acc.sequence:
            return 105  # tecBAD_SEQ

        # Remove the offer (best-effort, no error if not found)
        offer_id = tx.flags.get("offer_id", "") if tx.flags else ""
        if offer_id:
            src_acc.open_offers = [
                o for o in src_acc.open_offers if o.get("tx_id") != offer_id
            ]
            src_acc.owner_count = max(0, src_acc.owner_count - 1)

        src_acc.sequence += 1
        return 0  # tesSUCCESS

    # ---- staking: apply / cancel / maturity ----

    cpdef int apply_stake(self, object tx):
        """
        Apply a Stake transaction.

        1. Debit principal + fee from the sender.
        2. Record a StakeRecord in the pool (tx_id == stake_id).
        """
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101  # tecUNFUNDED

        cdef double amt = tx.amount.value
        cdef double fee_val = tx.fee.value

        if acc.balance < amt + fee_val:
            return 101  # tecUNFUNDED

        if tx.sequence != 0 and tx.sequence != acc.sequence:
            return 105  # tecBAD_SEQ

        tier_val = tx.flags.get("stake_tier", -1)
        try:
            StakeTier(tier_val)
        except (ValueError, KeyError):
            return 108  # tecSTAKE_LOCKED (invalid tier)

        if amt < MIN_STAKE_AMOUNT:
            return 101  # tecUNFUNDED (below minimum)

        # Debit
        acc.balance -= (amt + fee_val)
        # Burn the fee — permanently remove from circulation
        self.total_supply -= fee_val
        self.total_burned += fee_val

        # Record in staking pool
        self.staking_pool.record_stake(
            tx_id=tx.tx_id,
            address=src,
            amount=amt,
            tier=tier_val,
            circulating_supply=self.total_supply,
            now=tx.timestamp if tx.timestamp else None,
        )

        acc.sequence += 1
        return 0  # tesSUCCESS

    cpdef int apply_unstake(self, object tx):
        """
        Apply an Unstake (early cancellation) transaction.

        Looks up the stake by ``flags["stake_id"]``, computes penalty,
        credits payout to the account, and burns the principal penalty
        into the fee pool.
        """
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101  # tecUNFUNDED

        cdef double fee_val = tx.fee.value
        if acc.balance < fee_val:
            return 104  # tecINSUF_FEE

        if tx.sequence != 0 and tx.sequence != acc.sequence:
            return 105  # tecBAD_SEQ

        stake_id = tx.flags.get("stake_id", "")
        if not stake_id:
            return 108  # tecSTAKE_LOCKED (missing id)

        record = self.staking_pool.stakes.get(stake_id)
        if record is None:
            return 108
        if record.address != src:
            return 108  # not your stake
        if record.matured or record.cancelled:
            return 108  # already resolved

        # Debit fee
        acc.balance -= fee_val
        # Burn the fee — permanently remove from circulation
        self.total_supply -= fee_val
        self.total_burned += fee_val

        now_ts = tx.timestamp if tx.timestamp else None
        address, payout, interest_forfeited, principal_penalty = \
            self.staking_pool.cancel_stake(stake_id, now=now_ts)

        # Credit payout; burn the principal penalty permanently
        acc.balance += payout
        self.total_supply -= principal_penalty
        self.total_burned += principal_penalty

        acc.sequence += 1
        return 0  # tesSUCCESS

    # ---- fee helper (reused by all handlers) ----

    cdef int _debit_fee(self, object acc, double fee_val):
        """Debit fee from account, burn it. Returns 0 on success, 104 on fail."""
        if acc.balance < fee_val:
            return 104  # tecINSUF_FEE
        acc.balance -= fee_val
        self.total_supply -= fee_val
        self.total_burned += fee_val
        return 0

    cdef int _check_seq(self, object tx, object acc):
        """Verify sequence number. Returns 0 on match, 105 on mismatch."""
        if tx.sequence != 0 and tx.sequence != acc.sequence:
            return 105  # tecBAD_SEQ
        return 0

    # ---- escrow handlers ----

    cpdef int apply_escrow_create(self, object tx):
        """Lock NXF into an escrow."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double amt = tx.amount.value
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        if acc.balance < amt:
            return 101  # tecUNFUNDED
        # Debit escrowed amount
        acc.balance -= amt
        # Create destination if needed
        cdef str dst = tx.destination
        if dst and dst not in self.accounts:
            self.create_account(dst)
        # Create the escrow entry
        self.escrow_manager.create_escrow(
            escrow_id=tx.tx_id,
            account=src,
            destination=dst,
            amount=amt,
            condition=tx.flags.get("condition", ""),
            finish_after=tx.flags.get("finish_after", 0),
            cancel_after=tx.flags.get("cancel_after", 0),
        )
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_escrow_finish(self, object tx):
        """Release escrowed NXF to destination."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        escrow_id = tx.flags.get("escrow_id", "")
        fulfillment = tx.flags.get("fulfillment", "")
        try:
            entry, err = self.escrow_manager.finish_escrow(escrow_id, fulfillment)
        except KeyError:
            return 117  # tecNO_ENTRY
        if err:
            if "Condition" in err or "fulfillment" in err.lower():
                return 111  # tecESCROW_BAD_CONDITION
            return 112  # tecESCROW_NOT_READY
        # Credit destination
        dst_acc = <AccountEntry>self.accounts.get(entry.destination)
        if dst_acc is None:
            dst_acc = self.create_account(entry.destination)
        dst_acc.balance += entry.amount
        # Decrement owner count for the creator
        creator_acc = <AccountEntry>self.accounts.get(entry.account)
        if creator_acc is not None and creator_acc.owner_count > 0:
            creator_acc.owner_count -= 1
        acc.sequence += 1
        return 0

    cpdef int apply_escrow_cancel(self, object tx):
        """Return escrowed NXF to the creator."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        escrow_id = tx.flags.get("escrow_id", "")
        try:
            entry, err = self.escrow_manager.cancel_escrow(escrow_id, src)
        except KeyError:
            return 117  # tecNO_ENTRY
        if err:
            return 110  # tecNO_PERMISSION
        # Refund to creator
        creator_acc = <AccountEntry>self.accounts.get(entry.account)
        if creator_acc is not None:
            creator_acc.balance += entry.amount
            if creator_acc.owner_count > 0:
                creator_acc.owner_count -= 1
        acc.sequence += 1
        return 0

    # ---- AccountSet handler ----

    cpdef int apply_account_set(self, object tx):
        """Apply account configuration flags."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        # Process set_flags
        set_flags = tx.flags.get("set_flags", {})
        clear_flags = tx.flags.get("clear_flags", {})
        if set_flags.get("asfRequireDest"):
            acc.require_dest = True
        if set_flags.get("asfDisableMaster"):
            acc.disable_master = True
        if set_flags.get("asfDefaultRipple"):
            acc.default_ripple = True
        if set_flags.get("asfGlobalFreeze"):
            acc.global_freeze = True
        if set_flags.get("asfDepositAuth"):
            acc.deposit_auth = True
        # Process clear_flags
        if clear_flags.get("asfRequireDest"):
            acc.require_dest = False
        if clear_flags.get("asfDisableMaster"):
            acc.disable_master = False
        if clear_flags.get("asfDefaultRipple"):
            acc.default_ripple = False
        if clear_flags.get("asfGlobalFreeze"):
            acc.global_freeze = False
        if clear_flags.get("asfDepositAuth"):
            acc.deposit_auth = False
        # Transfer rate
        cdef double tr = tx.flags.get("transfer_rate", 0.0)
        if tr > 0.0:
            if tr < 1.0 or tr > 2.0:
                return 110  # tecNO_PERMISSION - invalid rate
            acc.transfer_rate = tr
        # Domain
        domain = tx.flags.get("domain", "")
        if domain:
            acc.domain = domain
        acc.sequence += 1
        return 0

    # ---- SetRegularKey handler ----

    cpdef int apply_set_regular_key(self, object tx):
        """Assign or remove a regular (secondary) signing key."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        regular_key = tx.flags.get("regular_key", "")
        acc.regular_key = regular_key
        self.multi_sign_manager.set_regular_key(src, regular_key)
        acc.sequence += 1
        return 0

    # ---- SignerListSet handler ----

    cpdef int apply_signer_list_set(self, object tx):
        """Set or remove an M-of-N signer list."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        quorum = tx.flags.get("signer_quorum", 0)
        entries = tx.flags.get("signer_entries", [])
        try:
            self.multi_sign_manager.set_signer_list(src, quorum, entries)
        except ValueError:
            return 110  # tecNO_PERMISSION
        # Update owner count
        if quorum > 0 and entries:
            acc.owner_count += 1
        acc.sequence += 1
        return 0

    # ---- payment channel handlers ----

    cpdef int apply_paychan_create(self, object tx):
        """Create a payment channel."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double amt = tx.amount.value
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        if acc.balance < amt:
            return 101
        acc.balance -= amt
        cdef str dst = tx.destination
        if dst and dst not in self.accounts:
            self.create_account(dst)
        self.channel_manager.create_channel(
            channel_id=tx.tx_id,
            account=src,
            destination=dst,
            amount=amt,
            settle_delay=tx.flags.get("settle_delay", 3600),
            public_key=tx.flags.get("public_key", ""),
            cancel_after=tx.flags.get("cancel_after", 0),
        )
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_paychan_fund(self, object tx):
        """Add funds to an existing payment channel."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double amt = tx.amount.value
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        if acc.balance < amt:
            return 101
        channel_id = tx.flags.get("channel_id", "")
        try:
            self.channel_manager.fund_channel(channel_id, amt)
        except (KeyError, ValueError):
            return 117  # tecNO_ENTRY
        acc.balance -= amt
        acc.sequence += 1
        return 0

    cpdef int apply_paychan_claim(self, object tx):
        """Claim NXF from a payment channel or request close."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        channel_id = tx.flags.get("channel_id", "")
        close_flag = tx.flags.get("close", False)
        claim_balance = tx.amount.value
        try:
            ch = self.channel_manager.get_channel(channel_id)
            if ch is None:
                return 117
            # Process claim if balance specified
            if claim_balance > 0:
                ch_obj, payout, err = self.channel_manager.claim(channel_id, claim_balance)
                if err:
                    return 113  # tecPAYCHAN_EXPIRED
                # Credit destination
                dst_acc = <AccountEntry>self.accounts.get(ch.destination)
                if dst_acc is not None:
                    dst_acc.balance += payout
            # Process close if requested
            if close_flag:
                ch_obj, is_closed, err = self.channel_manager.request_close(channel_id, src)
                if is_closed:
                    # Return remaining funds to creator
                    remaining = ch_obj.amount - ch_obj.balance
                    creator_acc = <AccountEntry>self.accounts.get(ch_obj.account)
                    if creator_acc is not None and remaining > 0:
                        creator_acc.balance += remaining
                    if creator_acc is not None and creator_acc.owner_count > 0:
                        creator_acc.owner_count -= 1
        except KeyError:
            return 117
        acc.sequence += 1
        return 0

    # ---- check handlers ----

    cpdef int apply_check_create(self, object tx):
        """Create a deferred pull-payment check."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        cdef double send_max = tx.amount.value
        cdef str cur = tx.amount.currency
        cdef str iss = tx.amount.issuer
        self.check_manager.create_check(
            check_id=tx.tx_id,
            account=src,
            destination=tx.destination,
            send_max=send_max,
            currency=cur,
            issuer=iss,
            expiration=tx.flags.get("expiration", 0),
        )
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_check_cash(self, object tx):
        """Cash a check — pull funds from the creator."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        check_id = tx.flags.get("check_id", "")
        deliver_min = tx.flags.get("deliver_min", 0.0)
        cash_amount = tx.amount.value
        try:
            entry, cashed_amt, err = self.check_manager.cash_check(
                check_id, cash_amount, deliver_min,
            )
        except KeyError:
            return 117
        if err:
            if "expired" in err.lower():
                return 114  # tecCHECK_EXPIRED
            return 110  # tecNO_PERMISSION
        # Verify casher is the destination
        if entry.destination != src:
            return 110  # tecNO_PERMISSION
        # Debit the check creator
        creator_acc = <AccountEntry>self.accounts.get(entry.account)
        if creator_acc is None:
            return 101
        if entry.currency == "NXF" or entry.currency == "":
            if creator_acc.balance < cashed_amt:
                return 101
            creator_acc.balance -= cashed_amt
            acc.balance += cashed_amt
        else:
            # IOU check
            tl_src = self.get_trust_line(entry.account, entry.currency, entry.issuer)
            if tl_src is None or tl_src.balance < cashed_amt:
                return 101
            tl_dst = self.get_trust_line(src, entry.currency, entry.issuer)
            if tl_dst is None:
                return 103
            tl_src.balance -= cashed_amt
            tl_dst.balance += cashed_amt
        if creator_acc.owner_count > 0:
            creator_acc.owner_count -= 1
        acc.sequence += 1
        return 0

    cpdef int apply_check_cancel(self, object tx):
        """Cancel a check."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        check_id = tx.flags.get("check_id", "")
        try:
            entry, err = self.check_manager.cancel_check(check_id, src)
        except KeyError:
            return 117
        if err:
            return 110
        creator_acc = <AccountEntry>self.accounts.get(entry.account)
        if creator_acc is not None and creator_acc.owner_count > 0:
            creator_acc.owner_count -= 1
        acc.sequence += 1
        return 0

    # ---- DepositPreauth handler ----

    cpdef int apply_deposit_preauth(self, object tx):
        """Preauthorise or de-authorise an account for deposits."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        auth = tx.flags.get("authorize", "")
        unauth = tx.flags.get("unauthorize", "")
        if auth:
            acc.deposit_preauth.add(auth)
        if unauth:
            acc.deposit_preauth.discard(unauth)
        acc.sequence += 1
        return 0

    # ---- AccountDelete handler ----

    cpdef int apply_account_delete(self, object tx):
        """Delete an account and transfer remaining NXF to destination."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        # Must have no owned objects
        if acc.owner_count > 0:
            return 110  # tecNO_PERMISSION — has owned objects
        if len(acc.trust_lines) > 0:
            return 110
        cdef str dst = tx.destination
        if dst not in self.accounts:
            return 101
        dst_acc = <AccountEntry>self.accounts[dst]
        # Transfer remaining balance
        dst_acc.balance += acc.balance
        # Remove account from ledger
        del self.accounts[src]
        return 0

    # ---- Ticket handler ----

    cpdef int apply_ticket_create(self, object tx):
        """Create sequence number reservation tickets."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        ticket_count = tx.flags.get("ticket_count", 1)
        if ticket_count < 1 or ticket_count > 250:
            return 110
        # Each ticket consumes a sequence number
        tickets = self.ticket_manager.create_tickets(
            src, acc.sequence + 1, ticket_count,
        )
        for t in tickets:
            acc.tickets.append(t.ticket_id)
        acc.owner_count += ticket_count
        acc.sequence += 1 + ticket_count  # skip consumed sequences
        return 0

    # ---- NFToken handlers ----

    cpdef int apply_nftoken_mint(self, object tx):
        """Mint a new non-fungible token."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        try:
            token = self.nftoken_manager.mint(
                issuer=src,
                uri=tx.flags.get("uri", ""),
                transfer_fee=tx.flags.get("transfer_fee", 0),
                nftoken_taxon=tx.flags.get("nftoken_taxon", 0),
                transferable=tx.flags.get("transferable", True),
                burnable=tx.flags.get("burnable", True),
            )
        except ValueError:
            return 110
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_nftoken_burn(self, object tx):
        """Burn (destroy) an NFToken."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        nftoken_id = tx.flags.get("nftoken_id", "")
        token, err = self.nftoken_manager.burn(nftoken_id, src)
        if err:
            if token is None:
                return 117  # tecNO_ENTRY
            return 110  # tecNO_PERMISSION
        acc.owner_count = max(0, acc.owner_count - 1)
        acc.sequence += 1
        return 0

    cpdef int apply_nftoken_offer_create(self, object tx):
        """Create a buy or sell offer for an NFToken."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        nftoken_id = tx.flags.get("nftoken_id", "")
        offer, err = self.nftoken_manager.create_offer(
            offer_id=tx.tx_id,
            nftoken_id=nftoken_id,
            owner=src,
            amount=tx.amount.value,
            destination=tx.destination,
            is_sell=tx.flags.get("is_sell", False),
            expiration=tx.flags.get("expiration", 0),
        )
        if err:
            return 119  # tecNFTOKEN_EXISTS
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_nftoken_offer_accept(self, object tx):
        """Accept an NFToken buy/sell offer, transferring the token."""
        cdef str src = tx.account
        acc = <AccountEntry>self.accounts.get(src)
        if acc is None:
            return 101
        cdef double fee_val = tx.fee.value
        cdef int rc = self._debit_fee(acc, fee_val)
        if rc:
            return rc
        rc = self._check_seq(tx, acc)
        if rc:
            return rc
        offer_id = tx.flags.get("offer_id", "")
        offer, err = self.nftoken_manager.accept_offer(offer_id, src)
        if err:
            if offer is None:
                return 117
            return 110
        # Handle NXF payment between buyer and seller
        if offer.amount > 0:
            if offer.is_sell:
                # Buyer (src) pays seller (offer.owner)
                if acc.balance < offer.amount:
                    return 101
                acc.balance -= offer.amount
                seller_acc = <AccountEntry>self.accounts.get(offer.owner)
                if seller_acc is not None:
                    seller_acc.balance += offer.amount
                    if seller_acc.owner_count > 0:
                        seller_acc.owner_count -= 1  # offer consumed
            else:
                # Buy offer: acceptor (current owner) receives payment from offer.owner
                buyer_acc = <AccountEntry>self.accounts.get(offer.owner)
                if buyer_acc is None or buyer_acc.balance < offer.amount:
                    return 101
                buyer_acc.balance -= offer.amount
                acc.balance += offer.amount
                if buyer_acc.owner_count > 0:
                    buyer_acc.owner_count -= 1
        acc.sequence += 1
        return 0

    # ---- queries ----

    cpdef double get_balance(self, str address):
        cdef AccountEntry acc = self.accounts.get(address)
        if acc is None:
            return 0.0
        return acc.balance

    cpdef dict get_state_summary(self):
        cdef dict pool = self.staking_pool.get_pool_summary()
        return {
            "ledger_sequence": self.current_sequence,
            "closed_ledgers": len(self.closed_ledgers),
            "total_accounts": len(self.accounts),
            "total_supply": self.total_supply,
            "initial_supply": self.initial_supply,
            "total_burned": self.total_burned,
            "total_minted": self.total_minted,
            "confidential_outputs": len(self.confidential_outputs),
            "spent_key_images": len(self.spent_key_images),
            "total_staked": pool["total_staked"],
            "active_stakes": pool["active_stakes"],
            "total_interest_paid": pool["total_interest_paid"],
        }

    # ---- confidential UTXO queries ----

    cpdef object get_confidential_output(self, str stealth_addr_hex):
        """Return the ConfidentialOutput for a stealth address, or None."""
        return self.confidential_outputs.get(stealth_addr_hex)

    cpdef list get_all_confidential_outputs(self):
        """
        Return all unspent confidential outputs as a list of dicts.
        Recipients call this to scan for payments addressed to them.
        """
        cdef list result = []
        for sa_hex, out in self.confidential_outputs.items():
            if not (<ConfidentialOutput>out).spent:
                result.append((<ConfidentialOutput>out).to_dict())
        return result

    cpdef bint is_key_image_spent(self, bytes key_image):
        """Return True if the key image has already been spent."""
        return key_image in self.spent_key_images

    cpdef bint is_stealth_address_used(self, str stealth_addr_hex):
        """Return True if a confidential output exists at this stealth address."""
        return stealth_addr_hex in self.confidential_outputs

    # ---- staking operations ----

    def get_staking_summary(self, str address, now=None):
        """Return staking summary for an address."""
        active = self.staking_pool.get_active_stakes(address)
        all_stakes = self.staking_pool.get_all_stakes(address)
        return {
            "address": address,
            "total_staked": self.staking_pool.get_total_staked_for_address(address),
            "stakes": [s.to_dict(now) for s in all_stakes],
            "demand_multiplier": self.staking_pool.get_demand_multiplier(
                self.total_supply
            ),
        }
