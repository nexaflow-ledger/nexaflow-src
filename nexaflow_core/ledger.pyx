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

cimport cython
from libc.time cimport time as c_time


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

    def __init__(self, str address, double balance=0.0):
        self.address = address
        self.balance = balance
        self.sequence = 1
        self.owner_count = 0
        self.trust_lines = {}
        self.open_offers = []
        self.transfer_rate = 1.0
        self.is_gateway = False

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

    def __init__(self, str currency, str issuer, str holder,
                 double limit=0.0):
        self.currency = currency
        self.issuer = issuer
        self.holder = holder
        self.balance = 0.0
        self.limit = limit
        self.limit_peer = 0.0
        self.no_ripple = False

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
        self.hash = hashlib.sha256(blob).hexdigest()

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
    cdef public double fee_pool        # accumulated fees
    cdef public str genesis_account

    def __init__(self, double total_supply=100_000_000_000.0,
                 str genesis_account="nGenesisNXF"):
        self.accounts = {}
        self.closed_ledgers = []
        self.pending_txns = []
        self.current_sequence = 1
        self.total_supply = total_supply
        self.fee_pool = 0.0
        self.genesis_account = genesis_account

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
        Returns result code.
        """
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

        if amount.is_native():
            # Native NXF payment
            if src_acc.balance < amt + fee_val:
                return 101  # tecUNFUNDED
            src_acc.balance -= (amt + fee_val)
            dst_acc.balance += amt
            self.fee_pool += fee_val
        else:
            # IOU payment — requires trust lines
            cur = amount.currency
            iss = amount.issuer

            # Debit fee in native
            if src_acc.balance < fee_val:
                return 104  # tecINSUF_FEE
            src_acc.balance -= fee_val
            self.fee_pool += fee_val

            # Check sender's trust line (or sender is issuer)
            if src != iss:
                tl_src = self.get_trust_line(src, cur, iss)
                if tl_src is None:
                    return 103  # tecNO_LINE
                if tl_src.balance < amt:
                    return 101  # tecUNFUNDED
                tl_src.balance -= amt
            # Credit receiver's trust line (or receiver is issuer)
            if dst != iss:
                tl_dst = self.get_trust_line(dst, cur, iss)
                if tl_dst is None:
                    return 103  # tecNO_LINE
                if tl_dst.balance + amt > tl_dst.limit:
                    return 101  # tecUNFUNDED — would exceed trust
                tl_dst.balance += amt

        # Bump sequence
        src_acc.sequence += 1
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
        self.fee_pool += fee_val

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
        if tt == 0:      # Payment
            result = self.apply_payment(tx)
        elif tt == 20:   # TrustSet
            result = self.apply_trust_set(tx)
        else:
            result = 0   # for simplicity, other types succeed
        tx.result_code = result
        if result == 0:
            self.pending_txns.append(tx)
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

        # Transaction merkle hash (simplified: hash of all tx_ids concatenated)
        cdef bytes tx_blob = b""
        for tx in self.pending_txns:
            tx_blob += tx.tx_id.encode("utf-8")
        header.tx_hash = hashlib.sha256(tx_blob).hexdigest() if tx_blob else "0" * 64

        # State hash (simplified: hash of all account balances)
        cdef bytes state_blob = b""
        for addr in sorted(self.accounts.keys()):
            acc = self.accounts[addr]
            state_blob += addr.encode("utf-8")
            state_blob += struct.pack(">d", acc.balance)
            state_blob += struct.pack(">q", acc.sequence)
        header.state_hash = hashlib.sha256(state_blob).hexdigest()

        header.total_nxf = self.total_supply
        header.compute_hash()

        self.closed_ledgers.append(header)
        self.pending_txns = []
        self.current_sequence += 1
        return header

    # ---- queries ----

    cpdef double get_balance(self, str address):
        cdef AccountEntry acc = self.accounts.get(address)
        if acc is None:
            return 0.0
        return acc.balance

    cpdef dict get_state_summary(self):
        return {
            "ledger_sequence": self.current_sequence,
            "closed_ledgers": len(self.closed_ledgers),
            "total_accounts": len(self.accounts),
            "total_supply": self.total_supply,
            "fee_pool": self.fee_pool,
        }
