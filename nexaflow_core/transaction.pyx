# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
"""
Cython-optimized transaction processing for NexaFlow.

Supports multiple transaction types inspired by NexaFlow:
  - Payment          (native NXF or IOU)
  - TrustSet         (create / modify trust lines)
  - OfferCreate      (DEX limit orders)
  - OfferCancel
  - AccountSet       (account flags)

Each transaction is serialised to a compact binary blob for hashing,
signed with ECDSA, and assigned a deterministic transaction ID.
"""

import json
import struct

cimport cython
from libc.time cimport time as c_time

# Transaction type codes (cdef for internal C-speed use)
cdef int _TT_PAYMENT      = 0
cdef int _TT_TRUST_SET    = 20
cdef int _TT_OFFER_CREATE = 7
cdef int _TT_OFFER_CANCEL = 8
cdef int _TT_ACCOUNT_SET  = 3
cdef int _TT_STAKE        = 30
cdef int _TT_UNSTAKE      = 31

# Python-visible aliases
TT_PAYMENT      = _TT_PAYMENT
TT_TRUST_SET    = _TT_TRUST_SET
TT_OFFER_CREATE = _TT_OFFER_CREATE
TT_OFFER_CANCEL = _TT_OFFER_CANCEL
TT_ACCOUNT_SET  = _TT_ACCOUNT_SET
TT_STAKE        = _TT_STAKE
TT_UNSTAKE      = _TT_UNSTAKE

# Transaction result codes (cdef + Python-visible)
cdef int _TES_SUCCESS  = 0
cdef int _TEC_UNFUNDED = 101
cdef int _TEC_PATH_NOT_FOUND = 102
cdef int _TEC_NO_LINE  = 103
cdef int _TEC_INSUF_FEE = 104
cdef int _TEC_BAD_SEQ  = 105
cdef int _TEC_BAD_SIG  = 106
cdef int _TEC_KEY_IMAGE_SPENT = 107
cdef int _TEC_STAKE_LOCKED = 108
cdef int _TEC_STAKE_DUPLICATE = 109

TES_SUCCESS      = _TES_SUCCESS
TEC_UNFUNDED     = _TEC_UNFUNDED
TEC_PATH_NOT_FOUND = _TEC_PATH_NOT_FOUND
TEC_NO_LINE      = _TEC_NO_LINE
TEC_INSUF_FEE    = _TEC_INSUF_FEE
TEC_BAD_SEQ      = _TEC_BAD_SEQ
TEC_BAD_SIG      = _TEC_BAD_SIG
TEC_KEY_IMAGE_SPENT = _TEC_KEY_IMAGE_SPENT
TEC_STAKE_LOCKED = _TEC_STAKE_LOCKED
TEC_STAKE_DUPLICATE = _TEC_STAKE_DUPLICATE

# Map names to codes for external use
TX_TYPE_NAMES = {
    "Payment": TT_PAYMENT,
    "TrustSet": TT_TRUST_SET,
    "OfferCreate": TT_OFFER_CREATE,
    "OfferCancel": TT_OFFER_CANCEL,
    "AccountSet": TT_ACCOUNT_SET,
    "Stake": TT_STAKE,
    "Unstake": TT_UNSTAKE,
}

RESULT_NAMES = {
    TES_SUCCESS:        "tesSUCCESS",
    TEC_UNFUNDED:       "tecUNFUNDED",
    TEC_PATH_NOT_FOUND: "tecPATH_NOT_FOUND",
    TEC_NO_LINE:        "tecNO_LINE",
    TEC_INSUF_FEE:      "tecINSUF_FEE",
    TEC_BAD_SEQ:        "tecBAD_SEQ",
    TEC_BAD_SIG:        "tecBAD_SIG",
    TEC_KEY_IMAGE_SPENT: "tecKEY_IMAGE_SPENT",
    TEC_STAKE_LOCKED:    "tecSTAKE_LOCKED",
    TEC_STAKE_DUPLICATE: "tecSTAKE_DUPLICATE",
}



# ===================================================================
#  Amount helpers
# ===================================================================

@cython.freelist(16)
cdef class Amount:
    """Represents a currency amount — either native NXF or an IOU."""
    cdef public double value
    cdef public str currency
    cdef public str issuer

    def __init__(self, double value, str currency="NXF", str issuer=""):
        self.value = value
        self.currency = currency
        self.issuer = issuer

    cpdef bint is_native(self):
        return self.currency == "NXF"

    cpdef bytes serialize(self):
        """Pack amount into bytes for hashing."""
        cdef bytes cur = self.currency.encode("utf-8")[:3].ljust(3, b"\x00")
        cdef bytes iss = self.issuer.encode("utf-8")[:40].ljust(40, b"\x00")
        return struct.pack(">d", self.value) + cur + iss

    cpdef dict to_dict(self):
        if self.is_native():
            return {"value": self.value, "currency": "NXF"}
        return {"value": self.value, "currency": self.currency, "issuer": self.issuer}

    @staticmethod
    def from_dict(d):
        return Amount(
            float(d["value"]),
            d.get("currency", "NXF"),
            d.get("issuer", ""),
        )

    def __repr__(self):
        if self.is_native():
            return f"{self.value:.6f} NXF"
        return f"{self.value:.6f} {self.currency}/{self.issuer[:8]}..."


# ===================================================================
#  Transaction class
# ===================================================================

@cython.freelist(8)
cdef class Transaction:
    """
    A single ledger transaction.

    Attributes mirror NexaFlow's transaction fields:
      tx_type, account, destination, amount, fee, sequence,
      signing_pub_key, signature, tx_id, timestamp, memo,
      limit_amount (TrustSet), taker_pays / taker_gets (Offers).
    """
    cdef public int tx_type
    cdef public str account
    cdef public str destination
    cdef public object amount          # Amount
    cdef public object fee             # Amount
    cdef public long long sequence
    cdef public bytes signing_pub_key
    cdef public bytes signature
    cdef public str tx_id
    cdef public long long timestamp
    cdef public str memo
    cdef public int result_code
    cdef public object limit_amount    # Amount (TrustSet)
    cdef public object taker_pays     # Amount (OfferCreate)
    cdef public object taker_gets     # Amount (OfferCreate)
    cdef public long long offer_sequence  # OfferCancel
    cdef public dict flags
    # Privacy fields for confidential transactions
    cdef public bytes commitment
    cdef public bytes ring_signature
    cdef public bytes stealth_address
    cdef public bytes ephemeral_pub
    cdef public bytes view_tag
    cdef public bytes range_proof
    cdef public bytes key_image

    def __init__(self, int tx_type, str account, str destination="",
                 object amount=None, object fee=None,
                 long long sequence=0, str memo=""):
        self.tx_type = tx_type
        self.account = account
        self.destination = destination
        self.amount = amount if amount is not None else Amount(0.0)
        self.fee = fee if fee is not None else Amount(0.00001)
        self.sequence = sequence
        self.signing_pub_key = b""
        self.signature = b""
        self.tx_id = ""
        self.timestamp = <long long>c_time(NULL)
        self.memo = memo
        self.result_code = -1
        self.limit_amount = None
        self.taker_pays = None
        self.taker_gets = None
        self.offer_sequence = 0
        self.flags = {}
        # Initialize privacy fields
        self.commitment = b""
        self.ring_signature = b""
        self.stealth_address = b""
        self.ephemeral_pub = b""
        self.view_tag = b""
        self.range_proof = b""
        self.key_image = b""

    cpdef bytes serialize_for_signing(self):
        """
        Produce a deterministic binary blob for signature hashing.
        The blob layout:
          [4 byte tx_type][account utf8][destination utf8]
          [amount bytes][fee bytes]
          [8 byte sequence][8 byte timestamp]
          [optional: limit / offer fields]
          [memo utf8]
        """
        cdef bytearray buf = bytearray()
        buf.extend(struct.pack(">I", self.tx_type))
        buf.extend(self.account.encode("utf-8"))
        buf.extend(self.destination.encode("utf-8"))
        buf.extend((<Amount>self.amount).serialize())
        buf.extend((<Amount>self.fee).serialize())
        buf.extend(struct.pack(">q", self.sequence))
        buf.extend(struct.pack(">q", self.timestamp))
        if self.limit_amount is not None:
            buf.extend((<Amount>self.limit_amount).serialize())
        if self.taker_pays is not None:
            buf.extend((<Amount>self.taker_pays).serialize())
        if self.taker_gets is not None:
            buf.extend((<Amount>self.taker_gets).serialize())
        if self.offer_sequence != 0:
            buf.extend(struct.pack(">q", self.offer_sequence))
        buf.extend(self.memo.encode("utf-8"))
        # Include privacy fields in signing preimage.
        # NOTE: ring_signature is intentionally excluded — a signature must
        # never be part of its own signing preimage.
        if self.commitment:
            buf.extend(self.commitment)
        if self.stealth_address:
            buf.extend(self.stealth_address)
        if self.range_proof:
            buf.extend(self.range_proof)
        if self.key_image:
            buf.extend(self.key_image)
        # Include flags for deterministic stake / unstake hashing
        if self.flags:
            import json as _json
            buf.extend(_json.dumps(self.flags, sort_keys=True).encode("utf-8"))
        return bytes(buf)

    cpdef bytes hash_for_signing(self):
        """SHA-256 hash of the serialised blob — this is what gets signed."""
        import hashlib
        return hashlib.sha256(self.serialize_for_signing()).digest()

    cpdef void apply_signature(self, bytes pub_key, bytes sig, str tx_id):
        """Attach a computed signature and tx_id."""
        self.signing_pub_key = pub_key
        self.signature = sig
        self.tx_id = tx_id

    cpdef bint verify_signature(self):
        """Verify the attached signature."""
        from nexaflow_core.crypto_utils import verify
        if not self.signature or not self.signing_pub_key:
            return False
        return verify(self.signing_pub_key, self.hash_for_signing(), self.signature)

    cpdef dict to_dict(self):
        """Serialise transaction to a JSON-friendly dict."""
        cdef dict d = {
            "tx_type": self.tx_type,
            "tx_type_name": _tx_type_name(self.tx_type),
            "account": self.account,
            "destination": self.destination,
            "amount": (<Amount>self.amount).to_dict(),
            "fee": (<Amount>self.fee).to_dict(),
            "sequence": self.sequence,
            "timestamp": self.timestamp,
            "tx_id": self.tx_id,
            "memo": self.memo,
            "result": RESULT_NAMES.get(self.result_code, "unknown"),
        }
        if self.limit_amount is not None:
            d["limit_amount"] = (<Amount>self.limit_amount).to_dict()
        if self.taker_pays is not None:
            d["taker_pays"] = (<Amount>self.taker_pays).to_dict()
            d["taker_gets"] = (<Amount>self.taker_gets).to_dict() if self.taker_gets else {}
        if self.commitment:
            d["commitment"] = self.commitment.hex()
        if self.ring_signature:
            d["ring_signature"] = self.ring_signature.hex()
        if self.stealth_address:
            d["stealth_address"] = self.stealth_address.hex()
        if self.range_proof:
            d["range_proof"] = self.range_proof.hex()
        if self.key_image:
            d["key_image"] = self.key_image.hex()
        if self.flags:
            d["flags"] = self.flags
        return d

    def __repr__(self):
        return (f"TX({_tx_type_name(self.tx_type)} "
                f"{self.account[:8]}→{self.destination[:8] if self.destination else '—'} "
                f"{self.amount} seq={self.sequence} id={self.tx_id[:12]}...)")


# ===================================================================
#  Transaction builder helpers
# ===================================================================

cpdef object create_payment(str account, str destination,
                            double amount, str currency="NXF",
                            str issuer="", double fee=0.00001,
                            long long sequence=0, str memo=""):
    """Create a Payment transaction."""
    cdef Transaction tx = Transaction(
        TT_PAYMENT, account, destination,
        Amount(amount, currency, issuer),
        Amount(fee), sequence, memo,
    )
    return tx

cpdef object create_trust_set(str account, str currency, str issuer,
                              double limit, double fee=0.00001,
                              long long sequence=0):
    """Create a TrustSet transaction."""
    cdef Transaction tx = Transaction(
        TT_TRUST_SET, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.limit_amount = Amount(limit, currency, issuer)
    return tx

cpdef object create_offer(str account, object taker_pays, object taker_gets,
                          double fee=0.00001, long long sequence=0):
    """Create an OfferCreate transaction."""
    cdef Transaction tx = Transaction(
        TT_OFFER_CREATE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.taker_pays = taker_pays
    tx.taker_gets = taker_gets
    return tx


cpdef object create_stake(str account, double amount, int stake_tier,
                          double fee=0.00001, long long sequence=0,
                          str memo=""):
    """
    Create a Stake transaction.

    The destination is set to the account itself (self-payment on maturity).
    The ``flags`` dict carries ``stake_tier`` so the ledger knows which
    APY / lock duration to apply.
    """
    cdef Transaction tx = Transaction(
        TT_STAKE, account, account,  # destination = self
        Amount(amount), Amount(fee), sequence, memo,
    )
    tx.flags = {"stake_tier": stake_tier}
    return tx


cpdef object create_unstake(str account, str stake_id,
                            double fee=0.00001, long long sequence=0,
                            str memo=""):
    """
    Create an Unstake transaction (early cancellation).

    ``flags["stake_id"]`` identifies the stake to cancel.
    Locked-tier stakes will suffer a penalty; Flexible are free.
    """
    cdef Transaction tx = Transaction(
        TT_UNSTAKE, account, account,
        Amount(0.0), Amount(fee), sequence, memo,
    )
    tx.flags = {"stake_id": stake_id}
    return tx


# ===================================================================
#  Internal helpers
# ===================================================================

cdef str _tx_type_name(int code):
    for name, val in TX_TYPE_NAMES.items():
        if val == code:
            return name
    return f"Unknown({code})"
