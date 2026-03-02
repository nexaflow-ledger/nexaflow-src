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
cdef int _TT_PAYMENT           = 0
cdef int _TT_TRUST_SET         = 20
cdef int _TT_OFFER_CREATE      = 7
cdef int _TT_OFFER_CANCEL      = 8
cdef int _TT_ACCOUNT_SET       = 3
cdef int _TT_STAKE             = 30
cdef int _TT_UNSTAKE           = 31
cdef int _TT_ESCROW_CREATE     = 1
cdef int _TT_ESCROW_FINISH     = 2
cdef int _TT_ESCROW_CANCEL     = 4
cdef int _TT_SET_REGULAR_KEY   = 5
cdef int _TT_SIGNER_LIST_SET   = 12
cdef int _TT_PAYCHAN_CREATE    = 13
cdef int _TT_PAYCHAN_FUND      = 14
cdef int _TT_PAYCHAN_CLAIM     = 15
cdef int _TT_CHECK_CREATE      = 16
cdef int _TT_CHECK_CASH        = 17
cdef int _TT_CHECK_CANCEL      = 18
cdef int _TT_DEPOSIT_PREAUTH   = 19
cdef int _TT_ACCOUNT_DELETE    = 21
cdef int _TT_TICKET_CREATE     = 22
cdef int _TT_NFTOKEN_MINT      = 25
cdef int _TT_NFTOKEN_BURN      = 26
cdef int _TT_NFTOKEN_OFFER_CREATE = 27
cdef int _TT_NFTOKEN_OFFER_ACCEPT = 28
cdef int _TT_CLAWBACK          = 33
cdef int _TT_AMM_CREATE        = 34
cdef int _TT_AMM_DEPOSIT       = 35
cdef int _TT_AMM_WITHDRAW      = 36
cdef int _TT_AMM_VOTE          = 37
cdef int _TT_AMM_BID           = 38
cdef int _TT_AMM_DELETE        = 39
cdef int _TT_ORACLE_SET        = 40
cdef int _TT_ORACLE_DELETE     = 41
cdef int _TT_DID_SET           = 42
cdef int _TT_DID_DELETE        = 43
cdef int _TT_MPT_ISSUANCE_CREATE  = 44
cdef int _TT_MPT_ISSUANCE_DESTROY = 45
cdef int _TT_MPT_AUTHORIZE     = 46
cdef int _TT_MPT_ISSUANCE_SET  = 47
cdef int _TT_CREDENTIAL_CREATE = 48
cdef int _TT_CREDENTIAL_ACCEPT = 49
cdef int _TT_CREDENTIAL_DELETE = 50
cdef int _TT_XCHAIN_CREATE_BRIDGE       = 51
cdef int _TT_XCHAIN_CREATE_CLAIM_ID     = 52
cdef int _TT_XCHAIN_COMMIT              = 53
cdef int _TT_XCHAIN_CLAIM               = 54
cdef int _TT_XCHAIN_ADD_ATTESTATION     = 55
cdef int _TT_XCHAIN_ACCOUNT_CREATE      = 56
cdef int _TT_SET_HOOK           = 57
cdef int _TT_AMENDMENT         = 100

# Python-visible aliases
TT_PAYMENT           = _TT_PAYMENT
TT_TRUST_SET         = _TT_TRUST_SET
TT_OFFER_CREATE      = _TT_OFFER_CREATE
TT_OFFER_CANCEL      = _TT_OFFER_CANCEL
TT_ACCOUNT_SET       = _TT_ACCOUNT_SET
TT_STAKE             = _TT_STAKE
TT_UNSTAKE           = _TT_UNSTAKE
TT_ESCROW_CREATE     = _TT_ESCROW_CREATE
TT_ESCROW_FINISH     = _TT_ESCROW_FINISH
TT_ESCROW_CANCEL     = _TT_ESCROW_CANCEL
TT_SET_REGULAR_KEY   = _TT_SET_REGULAR_KEY
TT_SIGNER_LIST_SET   = _TT_SIGNER_LIST_SET
TT_PAYCHAN_CREATE    = _TT_PAYCHAN_CREATE
TT_PAYCHAN_FUND      = _TT_PAYCHAN_FUND
TT_PAYCHAN_CLAIM     = _TT_PAYCHAN_CLAIM
TT_CHECK_CREATE      = _TT_CHECK_CREATE
TT_CHECK_CASH        = _TT_CHECK_CASH
TT_CHECK_CANCEL      = _TT_CHECK_CANCEL
TT_DEPOSIT_PREAUTH   = _TT_DEPOSIT_PREAUTH
TT_ACCOUNT_DELETE    = _TT_ACCOUNT_DELETE
TT_TICKET_CREATE     = _TT_TICKET_CREATE
TT_NFTOKEN_MINT      = _TT_NFTOKEN_MINT
TT_NFTOKEN_BURN      = _TT_NFTOKEN_BURN
TT_NFTOKEN_OFFER_CREATE = _TT_NFTOKEN_OFFER_CREATE
TT_NFTOKEN_OFFER_ACCEPT = _TT_NFTOKEN_OFFER_ACCEPT
TT_CLAWBACK          = _TT_CLAWBACK
TT_AMM_CREATE        = _TT_AMM_CREATE
TT_AMM_DEPOSIT       = _TT_AMM_DEPOSIT
TT_AMM_WITHDRAW      = _TT_AMM_WITHDRAW
TT_AMM_VOTE          = _TT_AMM_VOTE
TT_AMM_BID           = _TT_AMM_BID
TT_AMM_DELETE        = _TT_AMM_DELETE
TT_ORACLE_SET        = _TT_ORACLE_SET
TT_ORACLE_DELETE     = _TT_ORACLE_DELETE
TT_DID_SET           = _TT_DID_SET
TT_DID_DELETE        = _TT_DID_DELETE
TT_MPT_ISSUANCE_CREATE  = _TT_MPT_ISSUANCE_CREATE
TT_MPT_ISSUANCE_DESTROY = _TT_MPT_ISSUANCE_DESTROY
TT_MPT_AUTHORIZE     = _TT_MPT_AUTHORIZE
TT_MPT_ISSUANCE_SET  = _TT_MPT_ISSUANCE_SET
TT_CREDENTIAL_CREATE = _TT_CREDENTIAL_CREATE
TT_CREDENTIAL_ACCEPT = _TT_CREDENTIAL_ACCEPT
TT_CREDENTIAL_DELETE = _TT_CREDENTIAL_DELETE
TT_XCHAIN_CREATE_BRIDGE       = _TT_XCHAIN_CREATE_BRIDGE
TT_XCHAIN_CREATE_CLAIM_ID     = _TT_XCHAIN_CREATE_CLAIM_ID
TT_XCHAIN_COMMIT              = _TT_XCHAIN_COMMIT
TT_XCHAIN_CLAIM               = _TT_XCHAIN_CLAIM
TT_XCHAIN_ADD_ATTESTATION     = _TT_XCHAIN_ADD_ATTESTATION
TT_XCHAIN_ACCOUNT_CREATE      = _TT_XCHAIN_ACCOUNT_CREATE
TT_SET_HOOK           = _TT_SET_HOOK
TT_AMENDMENT         = _TT_AMENDMENT

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
cdef int _TEC_NO_PERMISSION = 110
cdef int _TEC_ESCROW_BAD_CONDITION = 111
cdef int _TEC_ESCROW_NOT_READY = 112
cdef int _TEC_PAYCHAN_EXPIRED = 113
cdef int _TEC_CHECK_EXPIRED = 114
cdef int _TEC_NO_RIPPLE = 115
cdef int _TEC_FROZEN = 116
cdef int _TEC_NO_ENTRY = 117
cdef int _TEC_AMENDMENT_BLOCKED = 118
cdef int _TEC_NFTOKEN_EXISTS = 119
cdef int _TEC_AMM_BALANCE = 120
cdef int _TEC_CLAWBACK_DISABLED = 121
cdef int _TEC_HOOKS_REJECTED = 122
cdef int _TEC_XCHAIN_NO_QUORUM = 123
cdef int _TEC_MPT_MAX_SUPPLY = 124
cdef int _TEC_CREDENTIAL_EXISTS = 125
cdef int _TEC_ORACLE_LIMIT = 126
cdef int _TEC_DID_EXISTS = 127
cdef int _TEC_INVARIANT_FAILED = 128
cdef int _TEC_PARTIAL_PAYMENT = 129
cdef int _TEC_REQUIRE_AUTH = 130
cdef int _TEC_DST_TAG_NEEDED = 131
cdef int _TEC_GLOBAL_FREEZE = 132
cdef int _TEC_OWNER_RESERVE = 133
cdef int _TEC_SEQ_TOO_LOW = 134

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
TEC_NO_PERMISSION = _TEC_NO_PERMISSION
TEC_ESCROW_BAD_CONDITION = _TEC_ESCROW_BAD_CONDITION
TEC_ESCROW_NOT_READY = _TEC_ESCROW_NOT_READY
TEC_PAYCHAN_EXPIRED = _TEC_PAYCHAN_EXPIRED
TEC_CHECK_EXPIRED = _TEC_CHECK_EXPIRED
TEC_NO_RIPPLE = _TEC_NO_RIPPLE
TEC_FROZEN = _TEC_FROZEN
TEC_NO_ENTRY = _TEC_NO_ENTRY
TEC_AMENDMENT_BLOCKED = _TEC_AMENDMENT_BLOCKED
TEC_NFTOKEN_EXISTS = _TEC_NFTOKEN_EXISTS
TEC_AMM_BALANCE = _TEC_AMM_BALANCE
TEC_CLAWBACK_DISABLED = _TEC_CLAWBACK_DISABLED
TEC_HOOKS_REJECTED = _TEC_HOOKS_REJECTED
TEC_XCHAIN_NO_QUORUM = _TEC_XCHAIN_NO_QUORUM
TEC_MPT_MAX_SUPPLY = _TEC_MPT_MAX_SUPPLY
TEC_CREDENTIAL_EXISTS = _TEC_CREDENTIAL_EXISTS
TEC_ORACLE_LIMIT = _TEC_ORACLE_LIMIT
TEC_DID_EXISTS = _TEC_DID_EXISTS
TEC_INVARIANT_FAILED = _TEC_INVARIANT_FAILED
TEC_PARTIAL_PAYMENT = _TEC_PARTIAL_PAYMENT
TEC_REQUIRE_AUTH = _TEC_REQUIRE_AUTH
TEC_DST_TAG_NEEDED = _TEC_DST_TAG_NEEDED
TEC_GLOBAL_FREEZE = _TEC_GLOBAL_FREEZE
TEC_OWNER_RESERVE = _TEC_OWNER_RESERVE
TEC_SEQ_TOO_LOW = _TEC_SEQ_TOO_LOW

# Map names to codes for external use
TX_TYPE_NAMES = {
    "Payment": TT_PAYMENT,
    "TrustSet": TT_TRUST_SET,
    "OfferCreate": TT_OFFER_CREATE,
    "OfferCancel": TT_OFFER_CANCEL,
    "AccountSet": TT_ACCOUNT_SET,
    "Stake": TT_STAKE,
    "Unstake": TT_UNSTAKE,
    "EscrowCreate": TT_ESCROW_CREATE,
    "EscrowFinish": TT_ESCROW_FINISH,
    "EscrowCancel": TT_ESCROW_CANCEL,
    "SetRegularKey": TT_SET_REGULAR_KEY,
    "SignerListSet": TT_SIGNER_LIST_SET,
    "PayChanCreate": TT_PAYCHAN_CREATE,
    "PayChanFund": TT_PAYCHAN_FUND,
    "PayChanClaim": TT_PAYCHAN_CLAIM,
    "CheckCreate": TT_CHECK_CREATE,
    "CheckCash": TT_CHECK_CASH,
    "CheckCancel": TT_CHECK_CANCEL,
    "DepositPreauth": TT_DEPOSIT_PREAUTH,
    "AccountDelete": TT_ACCOUNT_DELETE,
    "TicketCreate": TT_TICKET_CREATE,
    "NFTokenMint": TT_NFTOKEN_MINT,
    "NFTokenBurn": TT_NFTOKEN_BURN,
    "NFTokenOfferCreate": TT_NFTOKEN_OFFER_CREATE,
    "NFTokenOfferAccept": TT_NFTOKEN_OFFER_ACCEPT,
    "Clawback": TT_CLAWBACK,
    "AMMCreate": TT_AMM_CREATE,
    "AMMDeposit": TT_AMM_DEPOSIT,
    "AMMWithdraw": TT_AMM_WITHDRAW,
    "AMMVote": TT_AMM_VOTE,
    "AMMBid": TT_AMM_BID,
    "AMMDelete": TT_AMM_DELETE,
    "OracleSet": TT_ORACLE_SET,
    "OracleDelete": TT_ORACLE_DELETE,
    "DIDSet": TT_DID_SET,
    "DIDDelete": TT_DID_DELETE,
    "MPTokenIssuanceCreate": TT_MPT_ISSUANCE_CREATE,
    "MPTokenIssuanceDestroy": TT_MPT_ISSUANCE_DESTROY,
    "MPTokenAuthorize": TT_MPT_AUTHORIZE,
    "MPTokenIssuanceSet": TT_MPT_ISSUANCE_SET,
    "CredentialCreate": TT_CREDENTIAL_CREATE,
    "CredentialAccept": TT_CREDENTIAL_ACCEPT,
    "CredentialDelete": TT_CREDENTIAL_DELETE,
    "XChainCreateBridge": TT_XCHAIN_CREATE_BRIDGE,
    "XChainCreateClaimID": TT_XCHAIN_CREATE_CLAIM_ID,
    "XChainCommit": TT_XCHAIN_COMMIT,
    "XChainClaim": TT_XCHAIN_CLAIM,
    "XChainAddAttestation": TT_XCHAIN_ADD_ATTESTATION,
    "XChainAccountCreate": TT_XCHAIN_ACCOUNT_CREATE,
    "SetHook": TT_SET_HOOK,
    "Amendment": TT_AMENDMENT,
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
    TEC_NO_PERMISSION:   "tecNO_PERMISSION",
    TEC_ESCROW_BAD_CONDITION: "tecESCROW_BAD_CONDITION",
    TEC_ESCROW_NOT_READY: "tecESCROW_NOT_READY",
    TEC_PAYCHAN_EXPIRED: "tecPAYCHAN_EXPIRED",
    TEC_CHECK_EXPIRED:   "tecCHECK_EXPIRED",
    TEC_NO_RIPPLE:       "tecNO_RIPPLE",
    TEC_FROZEN:          "tecFROZEN",
    TEC_NO_ENTRY:        "tecNO_ENTRY",
    TEC_AMENDMENT_BLOCKED: "tecAMENDMENT_BLOCKED",
    TEC_NFTOKEN_EXISTS:  "tecNFTOKEN_EXISTS",
    TEC_AMM_BALANCE:     "tecAMM_BALANCE",
    TEC_CLAWBACK_DISABLED: "tecCLAWBACK_DISABLED",
    TEC_HOOKS_REJECTED:  "tecHOOKS_REJECTED",
    TEC_XCHAIN_NO_QUORUM: "tecXCHAIN_NO_QUORUM",
    TEC_MPT_MAX_SUPPLY:  "tecMPT_MAX_SUPPLY",
    TEC_CREDENTIAL_EXISTS: "tecCREDENTIAL_EXISTS",
    TEC_ORACLE_LIMIT:    "tecORACLE_LIMIT",
    TEC_DID_EXISTS:      "tecDID_EXISTS",
    TEC_INVARIANT_FAILED: "tecINVARIANT_FAILED",
    TEC_PARTIAL_PAYMENT: "tecPARTIAL_PAYMENT",
    TEC_REQUIRE_AUTH:    "tecREQUIRE_AUTH",
    TEC_DST_TAG_NEEDED:  "tecDST_TAG_NEEDED",
    TEC_GLOBAL_FREEZE:   "tecGLOBAL_FREEZE",
    TEC_OWNER_RESERVE:   "tecOWNER_RESERVE",
    TEC_SEQ_TOO_LOW:     "tecSEQ_TOO_LOW",
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
            return f"{self.value:.8f} NXF"
        return f"{self.value:.8f} {self.currency}/{self.issuer[:8]}..."


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
    cdef public long long destination_tag   # Destination tag (0 = unset)
    cdef public long long source_tag        # Source tag (0 = unset)
    cdef public double delivered_amount     # Actual amount delivered (partial payments)
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
        self.destination_tag = 0
        self.source_tag = 0
        self.delivered_amount = -1.0  # -1 means not set
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
        if self.destination_tag != 0:
            buf.extend(struct.pack(">q", self.destination_tag))
        if self.source_tag != 0:
            buf.extend(struct.pack(">q", self.source_tag))
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
        """BLAKE2b-256 hash of the serialised blob — this is what gets signed."""
        import hashlib
        return hashlib.blake2b(self.serialize_for_signing(), digest_size=32).digest()

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
        if self.destination_tag != 0:
            d["destination_tag"] = self.destination_tag
        if self.source_tag != 0:
            d["source_tag"] = self.source_tag
        if self.delivered_amount >= 0:
            d["delivered_amount"] = self.delivered_amount
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

cpdef object create_escrow_create(str account, str destination,
                                  double amount, long long finish_after=0,
                                  long long cancel_after=0, str condition="",
                                  double fee=0.00001, long long sequence=0):
    """Create an EscrowCreate transaction."""
    cdef Transaction tx = Transaction(
        TT_ESCROW_CREATE, account, destination,
        Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {
        "finish_after": finish_after,
        "cancel_after": cancel_after,
        "condition": condition,
    }
    return tx

cpdef object create_escrow_finish(str account, str owner, str escrow_id,
                                  str fulfillment="",
                                  double fee=0.00001, long long sequence=0):
    """Create an EscrowFinish transaction."""
    cdef Transaction tx = Transaction(
        TT_ESCROW_FINISH, account, owner,
        Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"escrow_id": escrow_id, "fulfillment": fulfillment}
    return tx

cpdef object create_escrow_cancel(str account, str owner, str escrow_id,
                                  double fee=0.00001, long long sequence=0):
    """Create an EscrowCancel transaction."""
    cdef Transaction tx = Transaction(
        TT_ESCROW_CANCEL, account, owner,
        Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"escrow_id": escrow_id}
    return tx

cpdef object create_set_regular_key(str account, str regular_key,
                                    double fee=0.00001, long long sequence=0):
    """Create a SetRegularKey transaction."""
    cdef Transaction tx = Transaction(
        TT_SET_REGULAR_KEY, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"regular_key": regular_key}
    return tx

cpdef object create_signer_list_set(str account, int signer_quorum,
                                    list signer_entries,
                                    double fee=0.00001, long long sequence=0):
    """Create a SignerListSet transaction.
    signer_entries: list of {"account": str, "weight": int}
    """
    cdef Transaction tx = Transaction(
        TT_SIGNER_LIST_SET, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"signer_quorum": signer_quorum, "signer_entries": signer_entries}
    return tx

cpdef object create_paychan_create(str account, str destination,
                                   double amount, long long settle_delay,
                                   str public_key_hex="",
                                   long long cancel_after=0,
                                   double fee=0.00001, long long sequence=0):
    """Create a PaymentChannelCreate transaction."""
    cdef Transaction tx = Transaction(
        TT_PAYCHAN_CREATE, account, destination,
        Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {
        "settle_delay": settle_delay,
        "public_key": public_key_hex,
        "cancel_after": cancel_after,
    }
    return tx

cpdef object create_paychan_fund(str account, str channel_id,
                                 double amount, long long expiration=0,
                                 double fee=0.00001, long long sequence=0):
    """Fund an existing payment channel with additional NXF."""
    cdef Transaction tx = Transaction(
        TT_PAYCHAN_FUND, account, "", Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {"channel_id": channel_id, "expiration": expiration}
    return tx

cpdef object create_paychan_claim(str account, str channel_id,
                                  double balance, str signature_hex="",
                                  str public_key_hex="",
                                  bint close=False,
                                  double fee=0.00001, long long sequence=0):
    """Claim NXF from a payment channel."""
    cdef Transaction tx = Transaction(
        TT_PAYCHAN_CLAIM, account, "", Amount(balance), Amount(fee), sequence,
    )
    tx.flags = {
        "channel_id": channel_id,
        "claim_signature": signature_hex,
        "public_key": public_key_hex,
        "close": close,
    }
    return tx

cpdef object create_check_create(str account, str destination,
                                 double send_max, str currency="NXF",
                                 str issuer="", long long expiration=0,
                                 double fee=0.00001, long long sequence=0):
    """Create a Check."""
    cdef Transaction tx = Transaction(
        TT_CHECK_CREATE, account, destination,
        Amount(send_max, currency, issuer), Amount(fee), sequence,
    )
    tx.flags = {"expiration": expiration}
    return tx

cpdef object create_check_cash(str account, str check_id,
                               double amount=0.0, double deliver_min=0.0,
                               double fee=0.00001, long long sequence=0):
    """Cash a Check."""
    cdef Transaction tx = Transaction(
        TT_CHECK_CASH, account, "", Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {"check_id": check_id, "deliver_min": deliver_min}
    return tx

cpdef object create_check_cancel(str account, str check_id,
                                 double fee=0.00001, long long sequence=0):
    """Cancel a Check."""
    cdef Transaction tx = Transaction(
        TT_CHECK_CANCEL, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"check_id": check_id}
    return tx

cpdef object create_deposit_preauth(str account, str authorize="",
                                    str unauthorize="",
                                    double fee=0.00001, long long sequence=0):
    """Create a DepositPreauth transaction."""
    cdef Transaction tx = Transaction(
        TT_DEPOSIT_PREAUTH, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"authorize": authorize, "unauthorize": unauthorize}
    return tx

cpdef object create_account_delete(str account, str destination,
                                   double fee=0.00001, long long sequence=0):
    """Delete account and transfer remaining NXF to destination."""
    cdef Transaction tx = Transaction(
        TT_ACCOUNT_DELETE, account, destination,
        Amount(0.0), Amount(fee), sequence,
    )
    return tx

cpdef object create_account_set(str account, dict set_flags=None,
                                dict clear_flags=None,
                                double transfer_rate=0.0,
                                str domain="",
                                double fee=0.00001, long long sequence=0):
    """Create an AccountSet transaction to configure account flags."""
    cdef Transaction tx = Transaction(
        TT_ACCOUNT_SET, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {
        "set_flags": set_flags or {},
        "clear_flags": clear_flags or {},
        "transfer_rate": transfer_rate,
        "domain": domain,
    }
    return tx

cpdef object create_ticket_create(str account, int ticket_count=1,
                                  double fee=0.00001, long long sequence=0):
    """Create Ticket(s) for out-of-order sequence number usage."""
    cdef Transaction tx = Transaction(
        TT_TICKET_CREATE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"ticket_count": ticket_count}
    return tx

cpdef object create_nftoken_mint(str account, str uri="",
                                 int transfer_fee=0, int nftoken_taxon=0,
                                 bint transferable=True, bint burnable=True,
                                 double fee=0.00001, long long sequence=0):
    """Mint a new NFToken."""
    cdef Transaction tx = Transaction(
        TT_NFTOKEN_MINT, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {
        "uri": uri,
        "transfer_fee": transfer_fee,
        "nftoken_taxon": nftoken_taxon,
        "transferable": transferable,
        "burnable": burnable,
    }
    return tx

cpdef object create_nftoken_burn(str account, str nftoken_id,
                                 double fee=0.00001, long long sequence=0):
    """Burn (destroy) an NFToken."""
    cdef Transaction tx = Transaction(
        TT_NFTOKEN_BURN, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"nftoken_id": nftoken_id}
    return tx

cpdef object create_nftoken_offer_create(str account, str nftoken_id,
                                         double amount, str destination="",
                                         bint is_sell=False,
                                         long long expiration=0,
                                         double fee=0.00001, long long sequence=0):
    """Create an offer to buy or sell an NFToken."""
    cdef Transaction tx = Transaction(
        TT_NFTOKEN_OFFER_CREATE, account, destination,
        Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {
        "nftoken_id": nftoken_id,
        "is_sell": is_sell,
        "expiration": expiration,
    }
    return tx

cpdef object create_nftoken_offer_accept(str account, str offer_id,
                                         double fee=0.00001, long long sequence=0):
    """Accept an NFToken buy/sell offer."""
    cdef Transaction tx = Transaction(
        TT_NFTOKEN_OFFER_ACCEPT, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"offer_id": offer_id}
    return tx


# --------------- Clawback (XLS-39) ---------------

cpdef object create_clawback(str account, str holder, double amount,
                             str currency="NXF", str issuer="",
                             double fee=0.00001, long long sequence=0):
    """Claw back issued tokens from a holder."""
    cdef Transaction tx = Transaction(
        TT_CLAWBACK, account, holder,
        Amount(amount, currency, issuer), Amount(fee), sequence,
    )
    return tx


# --------------- AMM (XLS-30) ---------------

cpdef object create_amm_create(str account, str asset1_currency,
                               str asset1_issuer, str asset2_currency,
                               str asset2_issuer, double amount1,
                               double amount2, int trading_fee=0,
                               double fee=0.00001, long long sequence=0):
    """Create a new AMM liquidity pool."""
    cdef Transaction tx = Transaction(
        TT_AMM_CREATE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {
        "asset1_currency": asset1_currency, "asset1_issuer": asset1_issuer,
        "asset2_currency": asset2_currency, "asset2_issuer": asset2_issuer,
        "amount1": amount1, "amount2": amount2, "trading_fee": trading_fee,
    }
    return tx

cpdef object create_amm_deposit(str account, str pool_id,
                                double amount1=0.0, double amount2=0.0,
                                double lp_token_out=0.0,
                                double fee=0.00001, long long sequence=0):
    """Deposit liquidity into an AMM pool."""
    cdef Transaction tx = Transaction(
        TT_AMM_DEPOSIT, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"pool_id": pool_id, "amount1": amount1,
                "amount2": amount2, "lp_token_out": lp_token_out}
    return tx

cpdef object create_amm_withdraw(str account, str pool_id,
                                 double lp_tokens=0.0,
                                 double amount1=0.0, double amount2=0.0,
                                 double fee=0.00001, long long sequence=0):
    """Withdraw liquidity from an AMM pool."""
    cdef Transaction tx = Transaction(
        TT_AMM_WITHDRAW, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"pool_id": pool_id, "lp_tokens": lp_tokens,
                "amount1": amount1, "amount2": amount2}
    return tx

cpdef object create_amm_vote(str account, str pool_id, int fee_val,
                             double fee=0.00001, long long sequence=0):
    """Vote on AMM pool trading fee."""
    cdef Transaction tx = Transaction(
        TT_AMM_VOTE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"pool_id": pool_id, "fee_val": fee_val}
    return tx

cpdef object create_amm_bid(str account, str pool_id, double bid_amount,
                            double fee=0.00001, long long sequence=0):
    """Bid LP tokens for the AMM auction slot."""
    cdef Transaction tx = Transaction(
        TT_AMM_BID, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"pool_id": pool_id, "bid_amount": bid_amount}
    return tx

cpdef object create_amm_delete(str account, str pool_id,
                               double fee=0.00001, long long sequence=0):
    """Delete an empty AMM pool."""
    cdef Transaction tx = Transaction(
        TT_AMM_DELETE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"pool_id": pool_id}
    return tx


# --------------- Oracle (XLS-47) ---------------

cpdef object create_oracle_set(str account, int document_id=-1,
                               str provider="", str asset_class="",
                               str uri="", list prices=None,
                               double fee=0.00001, long long sequence=0):
    """Create or update a price oracle."""
    cdef Transaction tx = Transaction(
        TT_ORACLE_SET, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"document_id": document_id, "provider": provider,
                "asset_class": asset_class, "uri": uri,
                "prices": prices or []}
    return tx

cpdef object create_oracle_delete(str account, int document_id,
                                  double fee=0.00001, long long sequence=0):
    """Delete a price oracle."""
    cdef Transaction tx = Transaction(
        TT_ORACLE_DELETE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"document_id": document_id}
    return tx


# --------------- DID (XLS-40) ---------------

cpdef object create_did_set(str account, str uri="", str data="",
                            list attestations=None,
                            double fee=0.00001, long long sequence=0):
    """Create or update a DID document."""
    cdef Transaction tx = Transaction(
        TT_DID_SET, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"uri": uri, "data": data, "attestations": attestations or []}
    return tx

cpdef object create_did_delete(str account,
                               double fee=0.00001, long long sequence=0):
    """Delete a DID document."""
    cdef Transaction tx = Transaction(
        TT_DID_DELETE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    return tx


# --------------- MPT (XLS-33) ---------------

cpdef object create_mpt_issuance_create(str account, double max_supply=0.0,
                                        int transfer_fee=0, str metadata="",
                                        int mpt_flags=0,
                                        double fee=0.00001, long long sequence=0):
    """Create a new Multi-Purpose Token issuance."""
    cdef Transaction tx = Transaction(
        TT_MPT_ISSUANCE_CREATE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"max_supply": max_supply, "transfer_fee": transfer_fee,
                "metadata": metadata, "mpt_flags": mpt_flags}
    return tx

cpdef object create_mpt_issuance_destroy(str account, str issuance_id,
                                         double fee=0.00001, long long sequence=0):
    """Destroy an MPT issuance."""
    cdef Transaction tx = Transaction(
        TT_MPT_ISSUANCE_DESTROY, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"issuance_id": issuance_id}
    return tx

cpdef object create_mpt_authorize(str account, str issuance_id,
                                  str holder="", bint issuer_action=False,
                                  double fee=0.00001, long long sequence=0):
    """Authorize a holder for an MPT issuance."""
    cdef Transaction tx = Transaction(
        TT_MPT_AUTHORIZE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"issuance_id": issuance_id, "holder": holder,
                "issuer_action": issuer_action}
    return tx

cpdef object create_mpt_issuance_set(str account, str issuance_id,
                                     bint lock=False,
                                     double fee=0.00001, long long sequence=0):
    """Update MPT issuance settings (lock/unlock)."""
    cdef Transaction tx = Transaction(
        TT_MPT_ISSUANCE_SET, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"issuance_id": issuance_id, "lock": lock}
    return tx


# --------------- Credentials ---------------

cpdef object create_credential_create(str account, str subject,
                                      str credential_type, str uri="",
                                      double expiration=0.0,
                                      double fee=0.00001, long long sequence=0):
    """Create a credential."""
    cdef Transaction tx = Transaction(
        TT_CREDENTIAL_CREATE, account, subject,
        Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"credential_type": credential_type, "uri": uri,
                "expiration": expiration}
    return tx

cpdef object create_credential_accept(str account, str credential_id,
                                      double fee=0.00001, long long sequence=0):
    """Accept a credential."""
    cdef Transaction tx = Transaction(
        TT_CREDENTIAL_ACCEPT, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"credential_id": credential_id}
    return tx

cpdef object create_credential_delete(str account, str credential_id,
                                      double fee=0.00001, long long sequence=0):
    """Delete a credential."""
    cdef Transaction tx = Transaction(
        TT_CREDENTIAL_DELETE, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"credential_id": credential_id}
    return tx


# --------------- XChain Bridge ---------------

cpdef object create_xchain_create_bridge(str account,
                                         str issuing_chain_door,
                                         dict locking_chain_issue=None,
                                         dict issuing_chain_issue=None,
                                         double min_account_create=10.0,
                                         double signal_reward=0.01,
                                         double fee=0.00001, long long sequence=0):
    """Create a cross-chain bridge."""
    cdef Transaction tx = Transaction(
        TT_XCHAIN_CREATE_BRIDGE, account, issuing_chain_door,
        Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {
        "locking_chain_issue": locking_chain_issue or {"currency": "NXF", "issuer": ""},
        "issuing_chain_issue": issuing_chain_issue or {"currency": "NXF", "issuer": ""},
        "min_account_create_amount": min_account_create,
        "signal_reward": signal_reward,
    }
    return tx

cpdef object create_xchain_create_claim_id(str account, str bridge_id,
                                           str destination="",
                                           double fee=0.00001, long long sequence=0):
    """Reserve a cross-chain claim ID."""
    cdef Transaction tx = Transaction(
        TT_XCHAIN_CREATE_CLAIM_ID, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"bridge_id": bridge_id, "destination": destination}
    return tx

cpdef object create_xchain_commit(str account, str bridge_id,
                                  double amount, int claim_id,
                                  str destination="",
                                  double fee=0.00001, long long sequence=0):
    """Commit assets to a cross-chain bridge."""
    cdef Transaction tx = Transaction(
        TT_XCHAIN_COMMIT, account, "", Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {"bridge_id": bridge_id, "claim_id": claim_id,
                "destination": destination}
    return tx

cpdef object create_xchain_claim(str account, str bridge_id,
                                 int claim_id, str destination,
                                 double fee=0.00001, long long sequence=0):
    """Claim assets from a cross-chain bridge."""
    cdef Transaction tx = Transaction(
        TT_XCHAIN_CLAIM, account, destination,
        Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"bridge_id": bridge_id, "claim_id": claim_id}
    return tx

cpdef object create_xchain_add_attestation(str account, str bridge_id,
                                           int claim_id, str witness,
                                           str signature_hex="",
                                           double fee=0.00001, long long sequence=0):
    """Add an attestation to a cross-chain claim."""
    cdef Transaction tx = Transaction(
        TT_XCHAIN_ADD_ATTESTATION, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"bridge_id": bridge_id, "claim_id": claim_id,
                "witness": witness, "signature": signature_hex}
    return tx

cpdef object create_xchain_account_create(str account, str bridge_id,
                                          double amount, str destination,
                                          double fee=0.00001, long long sequence=0):
    """Fund a new account via cross-chain bridge."""
    cdef Transaction tx = Transaction(
        TT_XCHAIN_ACCOUNT_CREATE, account, destination,
        Amount(amount), Amount(fee), sequence,
    )
    tx.flags = {"bridge_id": bridge_id}
    return tx


# --------------- Hooks ---------------

cpdef object create_set_hook(str account, str hook_hash, int position=0,
                             dict parameters=None, str hook_on="before",
                             double fee=0.00001, long long sequence=0):
    """Install or update a hook on an account."""
    cdef Transaction tx = Transaction(
        TT_SET_HOOK, account, "", Amount(0.0), Amount(fee), sequence,
    )
    tx.flags = {"hook_hash": hook_hash, "position": position,
                "parameters": parameters or {}, "hook_on": hook_on}
    return tx


# ===================================================================
#  Internal helpers
# ===================================================================

cdef str _tx_type_name(int code):
    for name, val in TX_TYPE_NAMES.items():
        if val == code:
            return name
    return f"Unknown({code})"
