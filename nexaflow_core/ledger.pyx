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
from nexaflow_core.amm import AMMManager
from nexaflow_core.oracle import OracleManager
from nexaflow_core.did import DIDManager
from nexaflow_core.mpt import MPTManager
from nexaflow_core.credentials import CredentialManager
from nexaflow_core.xchain import XChainManager
from nexaflow_core.hooks import HooksManager, HookOn
from nexaflow_core.invariants import InvariantChecker
from nexaflow_core.tx_metadata import MetadataBuilder
from nexaflow_core.order_book import OrderBook
from nexaflow_core.shamap import SHAMap
from nexaflow_core.payment_path import PathFinder
from nexaflow_core.trust_line import TrustGraph
from nexaflow_core.directory import DirectoryManager


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
    cdef public bint allow_clawback  # asfAllowClawback (XLS-39)
    cdef public bint require_auth    # asfRequireAuth
    cdef public str regular_key      # SetRegularKey address
    cdef public str domain           # domain verification string
    cdef public set deposit_preauth  # set of preauthorised addresses
    cdef public list tickets         # list of ticket_ids
    cdef public str key_type         # "secp256k1" or "ed25519"

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
        self.allow_clawback = False
        self.require_auth = False
        self.regular_key = ""
        self.domain = ""
        self.deposit_preauth = set()
        self.tickets = []
        self.key_type = "secp256k1"

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

def _canonical_tx_sort_key(tx):
    """Sort key for deterministic transaction ordering in closed ledgers."""
    return (tx.tx_type, tx.account, tx.sequence, tx.tx_id)

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
    cdef public object amm_manager         # AMMManager instance
    cdef public object oracle_manager      # OracleManager instance
    cdef public object did_manager         # DIDManager instance
    cdef public object mpt_manager         # MPTManager instance
    cdef public object credential_manager  # CredentialManager instance
    cdef public object xchain_manager      # XChainManager instance
    cdef public object hooks_manager       # HooksManager instance
    cdef public object invariant_checker   # InvariantChecker instance
    cdef public list tx_metadata           # list of TransactionMetadata dicts
    cdef public object order_book          # OrderBook instance
    cdef public object directory_manager   # DirectoryManager instance

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
        self.amm_manager = AMMManager()
        self.oracle_manager = OracleManager()
        self.did_manager = DIDManager()
        self.mpt_manager = MPTManager()
        self.credential_manager = CredentialManager()
        self.xchain_manager = XChainManager()
        self.hooks_manager = HooksManager()
        self.invariant_checker = InvariantChecker()
        self.tx_metadata = []
        self.order_book = OrderBook()
        self.directory_manager = DirectoryManager()

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

        # ── RequireDest enforcement (Tier 1) ──
        # If destination has asfRequireDest set, payment MUST carry a
        # non-zero destination_tag.
        if dst_acc.require_dest:
            if not hasattr(tx, 'destination_tag') or tx.destination_tag == 0:
                return 131  # tecDST_TAG_NEEDED

        # ── Deposit Authorization enforcement ──
        # If destination has deposit_auth enabled, only the account itself
        # or pre-authorized senders can deposit.
        if dst_acc.deposit_auth:
            if src != dst and src not in dst_acc.deposit_preauth:
                return 135  # tecDEPOSIT_AUTH

        # ── Global Freeze enforcement (Tier 1) ──
        # If the source account has global_freeze set, only payments
        # back to the issuer are allowed for IOUs.
        if src_acc.global_freeze and not amount.is_native():
            if dst != amount.issuer:
                return 132  # tecGLOBAL_FREEZE

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

            # ── Issuer-level freeze / auth checks (Tier 1) ──
            iss_acc = self.accounts.get(iss)
            if iss_acc is not None:
                # Global freeze on issuer blocks ALL IOU movement except
                # payments returning tokens to the issuer.
                if iss_acc.global_freeze:
                    if src != iss and dst != iss:
                        return 132  # tecGLOBAL_FREEZE

            # Check sender's trust line (or sender is issuer)
            effective_amt = amt
            if src != iss:
                tl_src = self.get_trust_line(src, cur, iss)
                if tl_src is None:
                    # ── Multi-hop rippling fallback ──
                    # No direct trust line from src to issuer; attempt
                    # pathfinding through the trust graph.
                    rc = self._try_multi_hop_payment(
                        src, dst, cur, iss, amt, tx,
                    )
                    if rc == -1:
                        return 103  # tecNO_LINE – no path found either
                    # Multi-hop handler already adjusted all balances
                    src_acc.sequence += 1
                    return rc
                # RequireAuth enforcement: issuer demands authorized lines
                if iss_acc is not None and iss_acc.require_auth:
                    if not tl_src.authorized:
                        return 130  # tecREQUIRE_AUTH
                # noRipple enforcement: if set, sender cannot ripple through
                if tl_src.no_ripple:
                    return 115  # tecNO_RIPPLE
                # Frozen trust line check (individual freeze)
                if tl_src.frozen:
                    return 116  # tecFROZEN
                # Apply transfer_rate if sender is not the issuer
                if iss_acc is not None and iss_acc.transfer_rate > 1.0:
                    effective_amt = amt * iss_acc.transfer_rate
                # Apply quality_out on sender's trust line
                if tl_src.quality_out != 1.0 and tl_src.quality_out > 0.0:
                    effective_amt = effective_amt * tl_src.quality_out
                if tl_src.balance < effective_amt:
                    # ── Partial payment support (Tier 1) ──
                    is_partial = False
                    if hasattr(tx, 'flags') and tx.flags and tx.flags.get('tfPartialPayment'):
                        is_partial = True
                    if is_partial:
                        # Deliver as much as possible
                        amt = tl_src.balance / (iss_acc.transfer_rate if (iss_acc and iss_acc.transfer_rate > 1.0) else 1.0)
                        if tl_src.quality_out != 1.0 and tl_src.quality_out > 0.0:
                            amt = amt / tl_src.quality_out
                        if amt <= 0:
                            return 129  # tecPARTIAL_PAYMENT — nothing to deliver
                        effective_amt = tl_src.balance
                        tx.delivered_amount = amt
                    else:
                        return 101  # tecUNFUNDED
                tl_src.balance -= effective_amt
            # Credit receiver's trust line (or receiver is issuer)
            if dst != iss:
                tl_dst = self.get_trust_line(dst, cur, iss)
                if tl_dst is None:
                    return 103  # tecNO_LINE
                # RequireAuth on receiver's line too
                if iss_acc is not None and iss_acc.require_auth:
                    if not tl_dst.authorized:
                        return 130  # tecREQUIRE_AUTH
                if tl_dst.frozen:
                    return 116  # tecFROZEN
                # Apply quality_in on receiver's trust line
                credit_amt = amt
                if tl_dst.quality_in != 1.0 and tl_dst.quality_in > 0.0:
                    credit_amt = amt * tl_dst.quality_in
                if tl_dst.balance + credit_amt > tl_dst.limit:
                    if hasattr(tx, 'flags') and tx.flags and tx.flags.get('tfPartialPayment'):
                        credit_amt = max(0.0, tl_dst.limit - tl_dst.balance)
                        if credit_amt <= 0:
                            return 129  # tecPARTIAL_PAYMENT
                        tx.delivered_amount = credit_amt
                    else:
                        return 101  # tecUNFUNDED — would exceed trust
                tl_dst.balance += credit_amt

        # Bump sequence
        src_acc.sequence += 1
        return 0  # tesSUCCESS

    # ── Multi-hop rippling helpers ──

    cpdef object _build_trust_graph(self):
        """Build a TrustGraph snapshot from current ledger state."""
        tg = TrustGraph()
        tg.build_from_ledger(self)
        return tg

    cpdef int _try_multi_hop_payment(self, str src, str dst, str cur,
                                      str iss, double amt, object tx):
        """
        Attempt a multi-hop IOU payment by finding a path through the
        trust graph and executing rippling along each hop.

        Returns:
            0  on success (all balances adjusted along the path)
           -1  when no path is found (caller should return tecNO_LINE)
        """
        tg = self._build_trust_graph()
        pf = PathFinder(tg, self, self.order_book)
        path = pf.find_best_path(src, dst, cur, amt)
        if path is None:
            return -1  # no route

        # Execute rippling along the discovered hops.
        # Each consecutive pair (hop_i, hop_{i+1}) represents an IOU
        # transfer: hop_i sends currency to hop_{i+1} via their shared
        # trust line.
        hops = path.hops
        remaining = min(amt, path.max_amount)
        for i in range(len(hops) - 1):
            sender_addr = hops[i][0]
            receiver_addr = hops[i + 1][0]
            hop_cur = hops[i][1]
            hop_iss = hops[i][2] if hops[i][2] else iss

            if hop_cur == "NXF":
                # Native leg of a cross-currency bridge
                s_acc = <AccountEntry>self.accounts.get(sender_addr)
                r_acc = <AccountEntry>self.accounts.get(receiver_addr)
                if s_acc is None or r_acc is None:
                    return -1
                if s_acc.balance < remaining:
                    remaining = s_acc.balance
                    if remaining <= 0:
                        return -1
                s_acc.balance -= remaining
                r_acc.balance += remaining
            else:
                # IOU leg: adjust trust-line balances
                if sender_addr == hop_iss:
                    # Issuer sending: credit receiver's trust line
                    tl_r = self.get_trust_line(receiver_addr, hop_cur, hop_iss)
                    if tl_r is None:
                        return -1
                    if tl_r.frozen:
                        return -1
                    avail = tl_r.limit - tl_r.balance
                    if avail < remaining:
                        remaining = avail
                        if remaining <= 0:
                            return -1
                    tl_r.balance += remaining
                elif receiver_addr == hop_iss:
                    # Sending back to issuer: debit sender's trust line
                    tl_s = self.get_trust_line(sender_addr, hop_cur, hop_iss)
                    if tl_s is None:
                        return -1
                    if tl_s.frozen:
                        return -1
                    if tl_s.balance < remaining:
                        remaining = tl_s.balance
                        if remaining <= 0:
                            return -1
                    tl_s.balance -= remaining
                else:
                    # Rippling through an intermediary: debit sender's line,
                    # credit receiver's line, both toward hop_iss.
                    tl_s = self.get_trust_line(sender_addr, hop_cur, hop_iss)
                    tl_r = self.get_trust_line(receiver_addr, hop_cur, hop_iss)
                    if tl_s is None or tl_r is None:
                        return -1
                    if tl_s.frozen or tl_r.frozen:
                        return -1
                    if tl_s.no_ripple:
                        return -1
                    if tl_s.balance < remaining:
                        remaining = tl_s.balance
                        if remaining <= 0:
                            return -1
                    avail = tl_r.limit - tl_r.balance
                    if avail < remaining:
                        remaining = avail
                        if remaining <= 0:
                            return -1
                    tl_s.balance -= remaining
                    tl_r.balance += remaining

        # Record delivered amount for partial payments
        if remaining < amt:
            tx.delivered_amount = remaining
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

        # ── Process TrustSet flags (Tier 1) ──────────────────────────────
        cdef object tl = self.get_trust_line(src, la.currency, la.issuer)
        if tl is not None and tx.flags:
            # tfSetfAuth: issuer authorizes this trust line
            if tx.flags.get("tfSetfAuth"):
                tl.authorized = True
            # tfClearfAuth: revoke authorization
            if tx.flags.get("tfClearfAuth"):
                tl.authorized = False
            # tfSetNoRipple / tfClearNoRipple
            if tx.flags.get("tfSetNoRipple"):
                tl.no_ripple = True
            if tx.flags.get("tfClearNoRipple"):
                tl.no_ripple = False
            # tfSetFreeze / tfClearFreeze (individual trust-line freeze)
            if tx.flags.get("tfSetFreeze"):
                tl.frozen = True
            if tx.flags.get("tfClearFreeze"):
                tl.frozen = False
            # QualityIn / QualityOut (Tier 1)
            if "quality_in" in tx.flags:
                qv = tx.flags["quality_in"]
                tl.quality_in = max(0.0, float(qv))
            if "quality_out" in tx.flags:
                qv = tx.flags["quality_out"]
                tl.quality_out = max(0.0, float(qv))

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

        # ── Snapshot for rollback on invariant failure ──────────────────
        self.invariant_checker.capture(self)
        # Deep-copy affected account state for rollback
        _snapshot_accounts = {}
        for _addr, _acc in self.accounts.items():
            _snapshot_accounts[_addr] = (
                _acc.balance, _acc.sequence, _acc.owner_count,
            )
        _snapshot_supply = self.total_supply
        _snapshot_burned = self.total_burned
        _snapshot_minted = self.total_minted

        # ── MetadataBuilder ──
        meta = MetadataBuilder(tx_hash=tx.tx_id or "", tx_index=len(self.pending_txns))
        # Snapshot touched accounts
        src_entry = self.accounts.get(tx.account)
        if src_entry is not None:
            meta.snapshot_account(tx.account, src_entry)
        if hasattr(tx, 'destination') and tx.destination:
            dst_entry = self.accounts.get(tx.destination)
            if dst_entry is not None:
                meta.snapshot_account(tx.destination, dst_entry)

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
        elif tt == 29:   # NFTokenOfferCancel
            result = self.apply_nftoken_offer_cancel(tx)
        elif tt == 30:   # Stake
            result = self.apply_stake(tx)
        elif tt == 31:   # Unstake (early cancel)
            result = self.apply_unstake(tx)
        elif tt == 33:   # Clawback
            result = self.apply_clawback(tx)
        elif tt == 34:   # AMMCreate
            result = self.apply_amm_create(tx)
        elif tt == 35:   # AMMDeposit
            result = self.apply_amm_deposit(tx)
        elif tt == 36:   # AMMWithdraw
            result = self.apply_amm_withdraw(tx)
        elif tt == 37:   # AMMVote
            result = self.apply_amm_vote(tx)
        elif tt == 38:   # AMMBid
            result = self.apply_amm_bid(tx)
        elif tt == 39:   # AMMDelete
            result = self.apply_amm_delete(tx)
        elif tt == 40:   # OracleSet
            result = self.apply_oracle_set(tx)
        elif tt == 41:   # OracleDelete
            result = self.apply_oracle_delete(tx)
        elif tt == 42:   # DIDSet
            result = self.apply_did_set(tx)
        elif tt == 43:   # DIDDelete
            result = self.apply_did_delete(tx)
        elif tt == 44:   # MPTokenIssuanceCreate
            result = self.apply_mpt_issuance_create(tx)
        elif tt == 45:   # MPTokenIssuanceDestroy
            result = self.apply_mpt_issuance_destroy(tx)
        elif tt == 46:   # MPTokenAuthorize
            result = self.apply_mpt_authorize(tx)
        elif tt == 47:   # MPTokenIssuanceSet
            result = self.apply_mpt_issuance_set(tx)
        elif tt == 48:   # CredentialCreate
            result = self.apply_credential_create(tx)
        elif tt == 49:   # CredentialAccept
            result = self.apply_credential_accept(tx)
        elif tt == 50:   # CredentialDelete
            result = self.apply_credential_delete(tx)
        elif tt == 51:   # XChainCreateBridge
            result = self.apply_xchain_create_bridge(tx)
        elif tt == 52:   # XChainCreateClaimID
            result = self.apply_xchain_create_claim_id(tx)
        elif tt == 53:   # XChainCommit
            result = self.apply_xchain_commit(tx)
        elif tt == 54:   # XChainClaim
            result = self.apply_xchain_claim(tx)
        elif tt == 55:   # XChainAddAttestation
            result = self.apply_xchain_add_attestation(tx)
        elif tt == 56:   # XChainAccountCreate
            result = self.apply_xchain_account_create(tx)
        elif tt == 57:   # SetHook
            result = self.apply_set_hook(tx)
        else:
            result = 0   # for simplicity, other types succeed

        # Verify invariants after transaction; ROLLBACK on failure
        if result == 0:
            inv_ok, inv_msg = self.invariant_checker.verify(self)
            if not inv_ok:
                # ── ROLLBACK all state changes ──
                self.total_supply = _snapshot_supply
                self.total_burned = _snapshot_burned
                self.total_minted = _snapshot_minted
                for _addr, (_bal, _seq, _oc) in _snapshot_accounts.items():
                    _racc = self.accounts.get(_addr)
                    if _racc is not None:
                        _racc.balance = _bal
                        _racc.sequence = _seq
                        _racc.owner_count = _oc
                result = 128  # tecINVARIANT_FAILED

        # ── Build and store metadata ──
        if result == 0:
            # Record final state of touched accounts
            src_entry = self.accounts.get(tx.account)
            if src_entry is not None:
                meta.record_account_modify(tx.account, src_entry)
            if hasattr(tx, 'destination') and tx.destination:
                dst_entry = self.accounts.get(tx.destination)
                if dst_entry is not None:
                    meta.record_account_modify(tx.destination, dst_entry)
            if hasattr(tx, 'delivered_amount') and tx.delivered_amount >= 0:
                meta.set_delivered_amount(tx.delivered_amount)
        from nexaflow_core.transaction import RESULT_NAMES
        meta.set_result(result, RESULT_NAMES.get(result, "unknown"))
        self.tx_metadata.append(meta.build())

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

        # ── Canonical transaction ordering (Tier 3) ──────────────────
        # Sort pending transactions deterministically before hashing
        # so that all validators produce the same ledger hash.
        # Ordering: by tx_type (ascending), then by account (lexicographic),
        # then by sequence (ascending), then by tx_id as tiebreaker.
        self.pending_txns.sort(key=_canonical_tx_sort_key)

        # Transaction merkle hash — use SHAMap Merkle trie
        tx_trie = SHAMap()
        for tx in self.pending_txns:
            tx_id_str = tx.tx_id if tx.tx_id else ""
            if tx_id_str:
                tx_trie.insert(tx_id_str.encode("utf-8"), tx_id_str.encode("utf-8"))
        tx_root = tx_trie.root_hash
        header.tx_hash = tx_root.hex() if tx_root else "0" * 64

        # State hash — use SHAMap Merkle trie over all accounts
        state_trie = SHAMap()
        for addr in sorted(self.accounts.keys()):
            acc = self.accounts[addr]
            state_val = addr + ":" + str(acc.balance) + ":" + str(acc.sequence)
            state_trie.insert(addr.encode("utf-8"), state_val.encode("utf-8"))
        # Include confidential state
        for sa_hex in sorted(self.confidential_outputs.keys()):
            out = self.confidential_outputs[sa_hex]
            ct_key = ("ct:" + sa_hex).encode("utf-8")
            state_trie.insert(ct_key, out.commitment.hex().encode("utf-8"))
        state_root = state_trie.root_hash
        header.state_hash = state_root.hex() if state_root else "0" * 64

        header.total_nxf = self.total_supply
        header.compute_hash()

        self.closed_ledgers.append(header)
        self.pending_txns = []
        self.current_sequence += 1
        return header

    # ---- DEX offers ----

    cpdef int apply_offer_create(self, object tx):
        """Apply an OfferCreate transaction.

        Validates sequence, deducts fee, records the offer, attempts to
        cross against existing offers via the OrderBook, and increments
        the account sequence.
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

        # ── Offer execution flags (Tier 1) ──────────────────────────────
        cdef str time_in_force = "GTC"  # default: Good-Til-Cancelled
        cdef bint tf_sell = False
        if tx.flags:
            if tx.flags.get("tfImmediateOrCancel"):
                time_in_force = "IOC"
            elif tx.flags.get("tfFillOrKill"):
                time_in_force = "FOK"
            if tx.flags.get("tfSell"):
                tf_sell = True

        # ── DEX Offer Crossing via OrderBook ──────────────────────────
        # Determine pair, side, price from taker_pays / taker_gets
        taker_pays = tx.taker_pays   # what the offerer pays (what taker receives)
        taker_gets = tx.taker_gets   # what the offerer receives (what taker pays)
        base_currency = ""
        counter_currency = ""
        price = 0.0
        quantity = 0.0
        side = "sell"

        if taker_pays is not None and taker_gets is not None:
            base_currency = getattr(taker_gets, 'currency', '') or "NXF"
            counter_currency = getattr(taker_pays, 'currency', '') or "NXF"
            pair = base_currency + "/" + counter_currency
            if taker_gets.value > 0:
                price = taker_pays.value / taker_gets.value
            quantity = taker_gets.value

            # Check if auto-bridging is needed (cross-currency, neither is NXF)
            if base_currency != "NXF" and counter_currency != "NXF":
                fills = self.order_book.submit_auto_bridged_order(
                    account=src,
                    src_currency=counter_currency,
                    dst_currency=base_currency,
                    side=side,
                    amount=quantity,
                    order_id=tx.tx_id,
                )
            else:
                fills = self.order_book.submit_order(
                    account=src,
                    pair=pair,
                    side=side,
                    price=price,
                    quantity=quantity,
                    order_id=tx.tx_id,
                    time_in_force=time_in_force,
                )

            # Apply fills to ledger state (settle matched amounts)
            for fill in fills:
                self._settle_offer_fill(fill, base_currency, counter_currency)

        # Record the open offer on the account
        src_acc.open_offers.append({
            "taker_pays": tx.taker_pays,
            "taker_gets": tx.taker_gets,
            "tx_id": tx.tx_id,
            "time_in_force": time_in_force,
            "tf_sell": tf_sell,
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

    def _settle_offer_fill(self, fill, base_currency, counter_currency):
        """Settle a single DEX fill — transfer assets between maker and taker."""
        maker_acc = self.accounts.get(fill.maker_order_id.split("-")[0]) if "-" in fill.maker_order_id else None
        taker_acc = self.accounts.get(fill.taker_order_id.split("-")[0]) if "-" in fill.taker_order_id else None

        # Look up accounts by iterating the order book's order registry
        maker_order = self.order_book.get_order(fill.maker_order_id)
        taker_order = self.order_book.get_order(fill.taker_order_id)
        if maker_order is None or taker_order is None:
            return

        maker_acc = self.accounts.get(maker_order.account)
        taker_acc = self.accounts.get(taker_order.account)
        if maker_acc is None or taker_acc is None:
            return

        # fill.quantity is in base currency; fill.price * fill.quantity is counter
        base_amount = fill.quantity
        counter_amount = fill.price * fill.quantity

        # Taker sells base → taker base decreases, maker base increases
        # Taker buys counter ← maker counter decreases, taker counter increases
        if base_currency == "NXF":
            # Base is native NXF
            if taker_acc.balance >= base_amount:
                taker_acc.balance -= base_amount
                maker_acc.balance += base_amount
        else:
            # Base is IOU — adjust trust lines
            tl_taker = self.get_trust_line(taker_order.account, base_currency, "")
            tl_maker = self.get_trust_line(maker_order.account, base_currency, "")
            if tl_taker is not None:
                tl_taker.balance -= base_amount
            if tl_maker is not None:
                tl_maker.balance += base_amount

        if counter_currency == "NXF":
            if maker_acc.balance >= counter_amount:
                maker_acc.balance -= counter_amount
                taker_acc.balance += counter_amount
        else:
            tl_maker_c = self.get_trust_line(maker_order.account, counter_currency, "")
            tl_taker_c = self.get_trust_line(taker_order.account, counter_currency, "")
            if tl_maker_c is not None:
                tl_maker_c.balance -= counter_amount
            if tl_taker_c is not None:
                tl_taker_c.balance += counter_amount

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

        # Interest earned is newly minted NXF; negative means additional
        # forfeit beyond the principal penalty (burned)
        cdef double interest_earned = payout - (record.amount - principal_penalty)
        if interest_earned > 1e-10:
            self.total_supply += interest_earned
            self.total_minted += interest_earned
        elif interest_earned < -1e-10:
            # Extra forfeit: staker gets back less than principal - penalty
            self.total_supply += interest_earned   # further reduce supply
            self.total_burned -= interest_earned   # track as additional burn

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

    # ── Owner reserve enforcement (Tier 3) ──────────────────────────

    # Constants (in NXF; corresponds to rippled's 10 XRP base / 2 XRP inc)
    BASE_RESERVE = 10.0           # minimum account balance
    OWNER_RESERVE_INC = 2.0       # per owned object increment

    cpdef double owner_reserve(self, object acc):
        """Calculate the total reserve an account must maintain."""
        return self.BASE_RESERVE + self.OWNER_RESERVE_INC * max(0, acc.owner_count)

    cpdef bint check_owner_reserve(self, object acc, int additional=0):
        """
        Return True if the account's balance meets the reserve
        requirement (optionally including *additional* new objects).
        """
        cdef double required = self.BASE_RESERVE + self.OWNER_RESERVE_INC * max(0, acc.owner_count + additional)
        return acc.balance >= required

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
        if set_flags.get("asfAllowClawback"):
            acc.allow_clawback = True
        if set_flags.get("asfRequireAuth"):
            acc.require_auth = True
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
        if clear_flags.get("asfAllowClawback"):
            acc.allow_clawback = False
        if clear_flags.get("asfRequireAuth"):
            acc.require_auth = False
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
        # ── AccountDelete rules (Tier 3) ──────────────────────────────
        # Account must have consumed at least 256 sequence numbers
        # (prevents rapid create-delete spam).
        if acc.sequence < 256:
            return 134  # tecSEQ_TOO_LOW
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

    cpdef int apply_nftoken_offer_cancel(self, object tx):
        """Cancel an outstanding NFToken offer owned by the sender."""
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
        if not offer_id:
            return 110  # tecNO_PERMISSION – missing offer_id
        # Look up and remove the offer via nftoken_manager
        offer = self.nftoken_manager.offers.get(offer_id)
        if offer is None:
            return 117  # tecNO_ENTRY
        if offer.owner != src:
            return 110  # tecNO_PERMISSION – not your offer
        # Remove from manager indices
        del self.nftoken_manager.offers[offer_id]
        offer.cancelled = True
        acc.owner_count = max(0, acc.owner_count - 1)
        acc.sequence += 1
        return 0

    # ---- Clawback (XLS-39) handler ----

    cpdef int apply_clawback(self, object tx):
        """Claw back issued IOU tokens from a holder."""
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
        if not acc.allow_clawback:
            return 121  # tecCLAWBACK_DISABLED
        cdef str holder_addr = tx.destination
        cdef double amt = tx.amount.value
        cdef str cur = tx.amount.currency
        cdef str iss = tx.amount.issuer
        # Issuer must be the clawback account
        if iss and iss != src:
            return 110  # tecNO_PERMISSION
        tl = self.get_trust_line(holder_addr, cur, src)
        if tl is None:
            return 103  # tecNO_LINE
        actual = min(amt, tl.balance)
        tl.balance -= actual
        acc.sequence += 1
        return 0

    # ---- AMM (XLS-30) handlers ----

    cpdef int apply_amm_create(self, object tx):
        """Create a new AMM liquidity pool."""
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
        a1c = tx.flags.get("asset1_currency", "NXF")
        a1i = tx.flags.get("asset1_issuer", "")
        a2c = tx.flags.get("asset2_currency", "")
        a2i = tx.flags.get("asset2_issuer", "")
        amt1 = tx.flags.get("amount1", 0.0)
        amt2 = tx.flags.get("amount2", 0.0)
        tfee = tx.flags.get("trading_fee", 0)
        # Debit amounts from account (for native NXF side)
        if a1c == "NXF" and acc.balance < amt1:
            return 101
        if a1c == "NXF":
            acc.balance -= amt1
        ok, msg, pool = self.amm_manager.create_pool(
            src, a1c, a1i, a2c, a2i, amt1, amt2, tfee,
        )
        if not ok:
            return 120  # tecAMM_BALANCE
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_amm_deposit(self, object tx):
        """Deposit liquidity into an AMM pool."""
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
        pool_id = tx.flags.get("pool_id", "")
        amt1 = tx.flags.get("amount1", 0.0)
        amt2 = tx.flags.get("amount2", 0.0)
        lp_out = tx.flags.get("lp_token_out", 0.0)
        a1 = amt1 if amt1 > 0 else None
        a2 = amt2 if amt2 > 0 else None
        lp = lp_out if lp_out > 0 else None
        ok, msg, lp_minted = self.amm_manager.deposit(pool_id, src, a1, a2, lp)
        if not ok:
            return 120
        acc.sequence += 1
        return 0

    cpdef int apply_amm_withdraw(self, object tx):
        """Withdraw liquidity from an AMM pool."""
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
        pool_id = tx.flags.get("pool_id", "")
        lp_tokens = tx.flags.get("lp_tokens", 0.0)
        amt1 = tx.flags.get("amount1", 0.0)
        amt2 = tx.flags.get("amount2", 0.0)
        lp = lp_tokens if lp_tokens > 0 else None
        a1 = amt1 if amt1 > 0 else None
        a2 = amt2 if amt2 > 0 else None
        ok, msg, w1, w2 = self.amm_manager.withdraw(pool_id, src, lp, a1, a2)
        if not ok:
            return 120
        acc.sequence += 1
        return 0

    cpdef int apply_amm_vote(self, object tx):
        """Vote on AMM pool trading fee."""
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
        pool_id = tx.flags.get("pool_id", "")
        fee_val_vote = tx.flags.get("fee_val", 0)
        ok, msg = self.amm_manager.vote(pool_id, src, fee_val_vote)
        if not ok:
            return 120
        acc.sequence += 1
        return 0

    cpdef int apply_amm_bid(self, object tx):
        """Bid for AMM auction slot."""
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
        pool_id = tx.flags.get("pool_id", "")
        bid_amount = tx.flags.get("bid_amount", 0.0)
        ok, msg = self.amm_manager.bid(pool_id, src, bid_amount)
        if not ok:
            return 120
        acc.sequence += 1
        return 0

    cpdef int apply_amm_delete(self, object tx):
        """Delete an empty AMM pool."""
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
        pool_id = tx.flags.get("pool_id", "")
        ok, msg = self.amm_manager.delete_pool(pool_id, src)
        if not ok:
            return 120
        acc.owner_count = max(0, acc.owner_count - 1)
        acc.sequence += 1
        return 0

    # ---- Oracle (XLS-47) handlers ----

    cpdef int apply_oracle_set(self, object tx):
        """Create or update a price oracle."""
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
        doc_id = tx.flags.get("document_id", -1)
        doc_id = doc_id if doc_id >= 0 else None
        ok, msg, oracle = self.oracle_manager.set_oracle(
            owner=src,
            document_id=doc_id,
            provider=tx.flags.get("provider", ""),
            asset_class=tx.flags.get("asset_class", ""),
            uri=tx.flags.get("uri", ""),
            prices=tx.flags.get("prices", []),
        )
        if not ok:
            return 126  # tecORACLE_LIMIT
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_oracle_delete(self, object tx):
        """Delete a price oracle."""
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
        doc_id = tx.flags.get("document_id", 0)
        ok, msg = self.oracle_manager.delete_oracle(src, doc_id)
        if not ok:
            return 117  # tecNO_ENTRY
        acc.owner_count = max(0, acc.owner_count - 1)
        acc.sequence += 1
        return 0

    # ---- DID (XLS-40) handlers ----

    cpdef int apply_did_set(self, object tx):
        """Create or update a DID document."""
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
        ok, msg, did = self.did_manager.set_did(
            account=src,
            uri=tx.flags.get("uri", ""),
            data=tx.flags.get("data", ""),
            attestations=tx.flags.get("attestations", None),
        )
        if not ok:
            return 127  # tecDID_EXISTS
        acc.sequence += 1
        return 0

    cpdef int apply_did_delete(self, object tx):
        """Delete a DID document."""
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
        ok, msg = self.did_manager.delete_did(src)
        if not ok:
            return 117
        acc.sequence += 1
        return 0

    # ---- MPT (XLS-33) handlers ----

    cpdef int apply_mpt_issuance_create(self, object tx):
        """Create a new MPT issuance."""
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
        ok, msg, iss = self.mpt_manager.create_issuance(
            issuer=src,
            max_supply=tx.flags.get("max_supply", 0.0),
            transfer_fee=tx.flags.get("transfer_fee", 0),
            metadata=tx.flags.get("metadata", ""),
            flags=tx.flags.get("mpt_flags", 0),
        )
        if not ok:
            return 124  # tecMPT_MAX_SUPPLY
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_mpt_issuance_destroy(self, object tx):
        """Destroy an MPT issuance."""
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
        issuance_id = tx.flags.get("issuance_id", "")
        ok, msg = self.mpt_manager.destroy_issuance(src, issuance_id)
        if not ok:
            return 117
        acc.owner_count = max(0, acc.owner_count - 1)
        acc.sequence += 1
        return 0

    cpdef int apply_mpt_authorize(self, object tx):
        """Authorize a holder for an MPT issuance."""
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
        issuance_id = tx.flags.get("issuance_id", "")
        holder = tx.flags.get("holder", src)
        issuer_action = tx.flags.get("issuer_action", False)
        ok, msg = self.mpt_manager.authorize(
            issuance_id, holder, issuer_action, src,
        )
        if not ok:
            return 110
        acc.sequence += 1
        return 0

    cpdef int apply_mpt_issuance_set(self, object tx):
        """Update MPT issuance settings."""
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
        issuance_id = tx.flags.get("issuance_id", "")
        lock = tx.flags.get("lock", None)
        ok, msg = self.mpt_manager.set_issuance(src, issuance_id, lock)
        if not ok:
            return 110
        acc.sequence += 1
        return 0

    # ---- Credential handlers ----

    cpdef int apply_credential_create(self, object tx):
        """Create a credential."""
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
        ok, msg, cred = self.credential_manager.create(
            issuer=src,
            subject=tx.destination,
            credential_type=tx.flags.get("credential_type", ""),
            uri=tx.flags.get("uri", ""),
            expiration=tx.flags.get("expiration", 0.0),
        )
        if not ok:
            return 125  # tecCREDENTIAL_EXISTS
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_credential_accept(self, object tx):
        """Accept a credential."""
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
        credential_id = tx.flags.get("credential_id", "")
        ok, msg = self.credential_manager.accept(src, credential_id)
        if not ok:
            return 117
        acc.sequence += 1
        return 0

    cpdef int apply_credential_delete(self, object tx):
        """Delete a credential."""
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
        credential_id = tx.flags.get("credential_id", "")
        ok, msg = self.credential_manager.delete(src, credential_id)
        if not ok:
            return 117
        acc.owner_count = max(0, acc.owner_count - 1)
        acc.sequence += 1
        return 0

    # ---- XChain Bridge handlers ----

    cpdef int apply_xchain_create_bridge(self, object tx):
        """Create a cross-chain bridge."""
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
        ok, msg, bridge = self.xchain_manager.create_bridge(
            locking_chain_door=src,
            issuing_chain_door=tx.destination,
            locking_chain_issue=tx.flags.get("locking_chain_issue", {"currency": "NXF", "issuer": ""}),
            issuing_chain_issue=tx.flags.get("issuing_chain_issue", {"currency": "NXF", "issuer": ""}),
            min_account_create_amount=tx.flags.get("min_account_create_amount", 10.0),
            signal_reward=tx.flags.get("signal_reward", 0.01),
        )
        if not ok:
            return 110
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_xchain_create_claim_id(self, object tx):
        """Reserve a cross-chain claim ID."""
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
        bridge_id = tx.flags.get("bridge_id", "")
        dest = tx.flags.get("destination", "")
        ok, msg, claim_id = self.xchain_manager.create_claim_id(bridge_id, src, dest)
        if not ok:
            return 117
        acc.owner_count += 1
        acc.sequence += 1
        return 0

    cpdef int apply_xchain_commit(self, object tx):
        """Commit assets to a cross-chain bridge."""
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
        bridge_id = tx.flags.get("bridge_id", "")
        claim_id = tx.flags.get("claim_id", 0)
        dest = tx.flags.get("destination", "")
        ok, msg = self.xchain_manager.commit(bridge_id, src, amt, claim_id, dest)
        if not ok:
            return 123  # tecXCHAIN_NO_QUORUM
        acc.balance -= amt
        acc.sequence += 1
        return 0

    cpdef int apply_xchain_claim(self, object tx):
        """Claim assets from a cross-chain bridge."""
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
        bridge_id = tx.flags.get("bridge_id", "")
        claim_id = tx.flags.get("claim_id", 0)
        dest = tx.destination
        ok, msg, amount = self.xchain_manager.claim(bridge_id, claim_id, dest)
        if not ok:
            return 123
        # Credit destination
        if dest not in self.accounts:
            self.create_account(dest)
        dst_acc = <AccountEntry>self.accounts[dest]
        dst_acc.balance += amount
        self.total_supply += amount  # minted on issuing chain
        self.total_minted += amount
        acc.sequence += 1
        return 0

    cpdef int apply_xchain_add_attestation(self, object tx):
        """Add an attestation to a cross-chain claim."""
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
        bridge_id = tx.flags.get("bridge_id", "")
        claim_id = tx.flags.get("claim_id", 0)
        witness = tx.flags.get("witness", src)
        sig = tx.flags.get("signature", "")
        ok, msg = self.xchain_manager.add_attestation(bridge_id, claim_id, witness, sig)
        if not ok:
            return 123
        acc.sequence += 1
        return 0

    cpdef int apply_xchain_account_create(self, object tx):
        """Fund a new account via cross-chain bridge."""
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
        bridge_id = tx.flags.get("bridge_id", "")
        dest = tx.destination
        ok, msg = self.xchain_manager.account_create_commit(bridge_id, src, amt, dest)
        if not ok:
            return 123
        acc.balance -= amt
        acc.sequence += 1
        return 0

    # ---- Hooks handler ----

    cpdef int apply_set_hook(self, object tx):
        """Install or update a hook on an account."""
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
        hook_hash = tx.flags.get("hook_hash", "")
        position = tx.flags.get("position", 0)
        parameters = tx.flags.get("parameters", {})
        hook_on_str = tx.flags.get("hook_on", "before")
        hook_on = HookOn.BEFORE if hook_on_str == "before" else HookOn.AFTER
        ok, msg = self.hooks_manager.set_hook(src, position, hook_hash, parameters, hook_on)
        if not ok:
            return 122  # tecHOOKS_REJECTED
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
