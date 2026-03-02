"""
STObject-style binary serialization for NexaFlow.

Mirrors the XRP Ledger's canonical binary format using type codes +
field codes.  Every serializable field has a unique (type_code, field_code)
pair.  Objects are serialized as type-length-value (TLV) sequences,
producing deterministic byte blobs suitable for hashing, signing, and
wire transmission.

Key design points:
  - Type codes: 1=UInt16, 2=UInt32, 3=UInt64, 5=Hash128,
    6=Hash256, 7=Amount, 8=Blob, 14=STObject, 15=STArray,
    16=UInt8, 17=AccountID, 19=String
  - Canonical ordering: fields sorted by (type_code, field_code)
  - Amount encoding: native NXF → 64-bit integer (drops);
    IOU → 8-byte mantissa/exponent + 3-byte currency + 20-byte issuer
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


# ═══════════════════════════════════════════════════════════════════
#  Type codes (matching rippled's serialization format)
# ═══════════════════════════════════════════════════════════════════

class STType(IntEnum):
    UINT16    = 1
    UINT32    = 2
    UINT64    = 3
    HASH128   = 5
    HASH256   = 6
    AMOUNT    = 7
    BLOB      = 8
    STOBJECT  = 14
    STARRAY   = 15
    UINT8     = 16
    ACCOUNT   = 17
    STRING    = 19


# ═══════════════════════════════════════════════════════════════════
#  Field registry: (type_code, field_code) → name
# ═══════════════════════════════════════════════════════════════════

@dataclass
class FieldDef:
    """Definition of a serializable field."""
    name: str
    type_code: int
    field_code: int
    is_signing: bool = True      # included in signing blob
    is_serialized: bool = True   # included in wire blob

    @property
    def sort_key(self) -> tuple[int, int]:
        return (self.type_code, self.field_code)


# Comprehensive field registry (matching rippled field codes)
FIELD_REGISTRY: dict[str, FieldDef] = {}
_FIELD_BY_CODE: dict[tuple[int, int], FieldDef] = {}


def _register(name: str, type_code: int, field_code: int,
              is_signing: bool = True, is_serialized: bool = True) -> None:
    fd = FieldDef(name, type_code, field_code, is_signing, is_serialized)
    FIELD_REGISTRY[name] = fd
    _FIELD_BY_CODE[(type_code, field_code)] = fd


# ── UInt16 (type 1) ──
_register("TransactionType", 1, 2)
_register("SignerWeight",    1, 3)
_register("TransferFee",    1, 4)

# ── UInt32 (type 2) ──
_register("Flags",               2, 2)
_register("SourceTag",           2, 3)
_register("Sequence",            2, 4)
_register("DestinationTag",      2, 14)
_register("LastLedgerSequence",  2, 27)
_register("TicketSequence",      2, 41)
_register("OwnerCount",          2, 17)
_register("TransferRate",        2, 11)
_register("QualityIn",           2, 20)
_register("QualityOut",          2, 21)
_register("OfferSequence",       2, 25)
_register("SignerQuorum",        2, 35)
_register("CancelAfter",        2, 36)
_register("FinishAfter",        2, 37)
_register("SettleDelay",         2, 40)
_register("Expiration",          2, 10)
_register("NFTokenTaxon",        2, 44)

# ── UInt64 (type 3) ──
_register("IndexPrevious",  3, 1)
_register("IndexNext",      3, 2)

# ── Hash256 (type 6) ──
_register("AccountTxnID",    6, 9)
_register("LedgerHash",      6, 1)
_register("ParentHash",      6, 2)
_register("TransactionHash", 6, 3)
_register("AccountHash",     6, 4)
_register("PreviousTxnID",   6, 5)
_register("BookDirectory",   6, 16)
_register("InvoiceID",       6, 17)
_register("Channel",         6, 7)
_register("NFTokenID",       6, 50)

# ── Amount (type 7) ──
_register("Amount",      7, 1)
_register("Balance",     7, 2)
_register("LimitAmount", 7, 3)
_register("TakerPays",   7, 4)
_register("TakerGets",   7, 5)
_register("Fee",         7, 8)
_register("SendMax",     7, 9)
_register("DeliverMin",  7, 10)
_register("MinimumOffer", 7, 16)
_register("RippleEscrow", 7, 17)
_register("DeliveredAmount", 7, 18)

# ── Blob (type 8) ──
_register("PublicKey",         8, 1)
_register("SigningPubKey",     8, 3, is_signing=True)
_register("TxnSignature",     8, 4, is_signing=False)  # excluded from signing
_register("Fulfillment",      8, 16)
_register("Condition",        8, 17)
_register("MemoType",         8, 12)
_register("MemoData",         8, 13)

# ── AccountID (type 17) ──
_register("Account",     17, 1)
_register("Destination", 17, 3)
_register("Issuer",      17, 4)
_register("RegularKey",  17, 8)
_register("Owner",       17, 2)

# ── String (type 19) ──
_register("Domain",    19, 7)
_register("URI",       19, 9)

# ── STObject (type 14) ──
_register("Memo",        14, 10)
_register("SignerEntry", 14, 16)

# ── STArray (type 15) ──
_register("Memos",        15, 9)
_register("Signers",      15, 3)
_register("SignerEntries", 15, 4)


# ═══════════════════════════════════════════════════════════════════
#  Amount encoding (drops-based for native, IOU format otherwise)
# ═══════════════════════════════════════════════════════════════════

DROPS_PER_NXF = 1_000_000


def encode_native_amount(value: float) -> bytes:
    """Encode a native NXF amount as 8 bytes (positive bit + drops)."""
    drops = int(round(value * DROPS_PER_NXF))
    # Bit 63 = 0 for native, bit 62 = 1 if positive
    if drops >= 0:
        raw = (1 << 62) | drops
    else:
        raw = abs(drops)
    return struct.pack(">Q", raw)


def decode_native_amount(data: bytes) -> float:
    """Decode 8-byte native amount back to NXF float."""
    raw = struct.unpack(">Q", data)[0]
    is_positive = bool(raw & (1 << 62))
    drops = raw & ((1 << 62) - 1)
    return drops / DROPS_PER_NXF if is_positive else -(drops / DROPS_PER_NXF)


def encode_currency_code(currency: str) -> bytes:
    """Encode a 3-character currency code into 20 bytes (ISO 4217 style)."""
    if len(currency) == 3 and currency.isalpha():
        buf = bytearray(20)
        buf[12] = ord(currency[0])
        buf[13] = ord(currency[1])
        buf[14] = ord(currency[2])
        return bytes(buf)
    # Non-standard: SHA-256 the currency name
    return hashlib.sha256(currency.encode("utf-8")).digest()[:20]


def decode_currency_code(data: bytes) -> str:
    """Decode 20-byte currency code back to string."""
    if data == b'\x00' * 20:
        return "NXF"
    # Check for ISO-style 3-char code
    if (data[:12] == b'\x00' * 12 and data[15:] == b'\x00' * 5
            and all(32 <= b <= 126 for b in data[12:15])):
        return chr(data[12]) + chr(data[13]) + chr(data[14])
    return data.hex()


def encode_iou_amount(value: float, currency: str, issuer: str) -> bytes:
    """Encode an IOU amount: 8-byte value + 20-byte currency + 20-byte issuer."""
    # Simplified: store float as 8 bytes with IOU bit flag
    drops = int(round(value * DROPS_PER_NXF))
    # Bit 63 = 1 for IOU, bit 62 = 1 if positive
    raw = (1 << 63)
    if drops >= 0:
        raw |= (1 << 62) | drops
    else:
        raw |= abs(drops)
    buf = struct.pack(">Q", raw)
    buf += encode_currency_code(currency)
    buf += issuer.encode("utf-8")[:20].ljust(20, b'\x00')
    return buf


def encode_amount(value: float, currency: str = "NXF",
                  issuer: str = "") -> bytes:
    """Encode an Amount, auto-detecting native vs IOU."""
    if currency in ("NXF", ""):
        return encode_native_amount(value)
    return encode_iou_amount(value, currency, issuer)


# ═══════════════════════════════════════════════════════════════════
#  Field header encoding
# ═══════════════════════════════════════════════════════════════════

def encode_field_id(type_code: int, field_code: int) -> bytes:
    """Encode the field header (1-3 bytes) per rippled encoding rules."""
    if type_code < 16 and field_code < 16:
        return bytes([(type_code << 4) | field_code])
    elif type_code < 16:
        return bytes([(type_code << 4), field_code])
    elif field_code < 16:
        return bytes([field_code, type_code])
    else:
        return bytes([0, type_code, field_code])


def decode_field_id(data: bytes, offset: int = 0) -> tuple[int, int, int]:
    """Decode field header, returning (type_code, field_code, bytes_consumed)."""
    b0 = data[offset]
    tc = (b0 >> 4) & 0x0F
    fc = b0 & 0x0F
    consumed = 1
    if tc == 0 and fc == 0:
        tc = data[offset + 1]
        fc = data[offset + 2]
        consumed = 3
    elif tc == 0:
        tc = data[offset + 1]
        consumed = 2
    elif fc == 0:
        fc = data[offset + 1]
        consumed = 2
    return tc, fc, consumed


def encode_vl_length(length: int) -> bytes:
    """Encode a variable-length field's length prefix (1-3 bytes)."""
    if length <= 192:
        return bytes([length])
    elif length <= 12_480:
        length -= 193
        b1 = (length >> 8) + 193
        b2 = length & 0xFF
        return bytes([b1, b2])
    else:
        length -= 12_481
        b1 = 241 + (length >> 16)
        b2 = (length >> 8) & 0xFF
        b3 = length & 0xFF
        return bytes([b1, b2, b3])


# ═══════════════════════════════════════════════════════════════════
#  STObject Serializer
# ═══════════════════════════════════════════════════════════════════

class STSerializer:
    """
    Serialize a transaction (or any ledger object) into canonical binary.

    Usage:
        s = STSerializer()
        s.add_uint16("TransactionType", 0)
        s.add_account("Account", "rSrcAddr")
        s.add_amount("Amount", 100.0, "NXF", "")
        blob = s.to_bytes()
        signing_blob = s.to_signing_bytes()
    """

    def __init__(self):
        self._fields: list[tuple[FieldDef, bytes]] = []

    def add_uint8(self, name: str, value: int) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        self._fields.append((fd, struct.pack(">B", value & 0xFF)))

    def add_uint16(self, name: str, value: int) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        self._fields.append((fd, struct.pack(">H", value & 0xFFFF)))

    def add_uint32(self, name: str, value: int) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        self._fields.append((fd, struct.pack(">I", value & 0xFFFFFFFF)))

    def add_uint64(self, name: str, value: int) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        self._fields.append((fd, struct.pack(">Q", value)))

    def add_hash256(self, name: str, value: str) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        data = bytes.fromhex(value) if len(value) == 64 else value.encode("utf-8")[:32].ljust(32, b'\x00')
        self._fields.append((fd, data))

    def add_amount(self, name: str, value: float,
                   currency: str = "NXF", issuer: str = "") -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        self._fields.append((fd, encode_amount(value, currency, issuer)))

    def add_blob(self, name: str, data: bytes) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        self._fields.append((fd, encode_vl_length(len(data)) + data))

    def add_account(self, name: str, address: str) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        # Encode account as VL-prefixed bytes
        addr_bytes = address.encode("utf-8")
        self._fields.append((fd, encode_vl_length(len(addr_bytes)) + addr_bytes))

    def add_string(self, name: str, value: str) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        data = value.encode("utf-8")
        self._fields.append((fd, encode_vl_length(len(data)) + data))

    def add_array(self, name: str, items: list["STSerializer"]) -> None:
        fd = FIELD_REGISTRY.get(name)
        if fd is None:
            return
        buf = bytearray()
        for item in items:
            buf.extend(item.to_bytes())
            buf.extend(b'\xe1')  # STObject end marker
        buf.extend(b'\xf1')  # STArray end marker
        self._fields.append((fd, bytes(buf)))

    def _sorted_fields(self, signing: bool = False) -> list[tuple[FieldDef, bytes]]:
        """Return fields sorted by canonical order, optionally filtering for signing."""
        filtered = [(fd, data) for fd, data in self._fields
                    if fd.is_serialized and (not signing or fd.is_signing)]
        filtered.sort(key=lambda x: x[0].sort_key)
        return filtered

    def to_bytes(self) -> bytes:
        """Produce the canonical binary serialization."""
        buf = bytearray()
        for fd, data in self._sorted_fields(signing=False):
            buf.extend(encode_field_id(fd.type_code, fd.field_code))
            buf.extend(data)
        return bytes(buf)

    def to_signing_bytes(self) -> bytes:
        """Produce the signing blob (excludes TxnSignature)."""
        buf = bytearray()
        for fd, data in self._sorted_fields(signing=True):
            buf.extend(encode_field_id(fd.type_code, fd.field_code))
            buf.extend(data)
        return bytes(buf)

    def to_hash(self) -> str:
        """BLAKE2b-256 hash of the canonical bytes — the transaction ID."""
        blob = self.to_bytes()
        return hashlib.blake2b(blob, digest_size=32).hexdigest()


def serialize_transaction(tx) -> STSerializer:
    """
    Convert a Transaction object into an STSerializer with all fields.

    This produces the canonical binary representation used for:
      - Transaction ID computation
      - Signing preimage
      - Wire format
    """
    s = STSerializer()
    s.add_uint16("TransactionType", tx.tx_type)
    s.add_uint32("Sequence", tx.sequence if tx.sequence else 0)
    if tx.destination_tag:
        s.add_uint32("DestinationTag", tx.destination_tag)
    if tx.source_tag:
        s.add_uint32("SourceTag", tx.source_tag)
    if hasattr(tx, 'last_ledger_sequence') and tx.last_ledger_sequence:
        s.add_uint32("LastLedgerSequence", tx.last_ledger_sequence)
    if hasattr(tx, 'ticket_sequence') and tx.ticket_sequence:
        s.add_uint32("TicketSequence", tx.ticket_sequence)
    if hasattr(tx, 'offer_sequence') and tx.offer_sequence:
        s.add_uint32("OfferSequence", tx.offer_sequence)

    # Hash256 fields
    if hasattr(tx, 'account_txn_id') and tx.account_txn_id:
        s.add_hash256("AccountTxnID", tx.account_txn_id)

    # Amount fields
    if tx.amount:
        amt = tx.amount
        s.add_amount("Amount", amt.value, amt.currency, amt.issuer)
    if tx.fee:
        fee = tx.fee
        s.add_amount("Fee", fee.value, fee.currency, fee.issuer)
    if hasattr(tx, 'limit_amount') and tx.limit_amount:
        la = tx.limit_amount
        s.add_amount("LimitAmount", la.value, la.currency, la.issuer)
    if hasattr(tx, 'taker_pays') and tx.taker_pays:
        tp = tx.taker_pays
        s.add_amount("TakerPays", tp.value, tp.currency, tp.issuer)
    if hasattr(tx, 'taker_gets') and tx.taker_gets:
        tg = tx.taker_gets
        s.add_amount("TakerGets", tg.value, tg.currency, tg.issuer)

    # Blob fields
    if tx.signing_pub_key:
        s.add_blob("SigningPubKey", tx.signing_pub_key)
    if tx.signature:
        s.add_blob("TxnSignature", tx.signature)

    # AccountID fields
    s.add_account("Account", tx.account)
    if tx.destination:
        s.add_account("Destination", tx.destination)

    # STArray — Memos
    if hasattr(tx, 'memos') and tx.memos:
        memo_serializers = []
        for memo in tx.memos:
            ms = STSerializer()
            if "MemoType" in memo:
                ms.add_blob("MemoType", memo["MemoType"].encode("utf-8"))
            if "MemoData" in memo:
                ms.add_blob("MemoData", memo["MemoData"].encode("utf-8"))
            memo_serializers.append(ms)
        s.add_array("Memos", memo_serializers)

    return s


def deserialize_field(data: bytes, offset: int) -> tuple[str, Any, int]:
    """
    Deserialize a single field from binary data starting at offset.
    Returns (field_name, value, new_offset).
    """
    tc, fc, hdr_len = decode_field_id(data, offset)
    offset += hdr_len
    fd = _FIELD_BY_CODE.get((tc, fc))
    name = fd.name if fd else f"Unknown({tc},{fc})"

    if tc == STType.UINT8:
        val = struct.unpack(">B", data[offset:offset + 1])[0]
        return name, val, offset + 1
    elif tc == STType.UINT16:
        val = struct.unpack(">H", data[offset:offset + 2])[0]
        return name, val, offset + 2
    elif tc == STType.UINT32:
        val = struct.unpack(">I", data[offset:offset + 4])[0]
        return name, val, offset + 4
    elif tc == STType.UINT64:
        val = struct.unpack(">Q", data[offset:offset + 8])[0]
        return name, val, offset + 8
    elif tc == STType.HASH256:
        val = data[offset:offset + 32].hex()
        return name, val, offset + 32
    elif tc == STType.AMOUNT:
        raw = struct.unpack(">Q", data[offset:offset + 8])[0]
        if raw & (1 << 63):  # IOU
            return name, raw, offset + 48  # 8 + 20 + 20
        return name, raw, offset + 8
    elif tc in (STType.BLOB, STType.ACCOUNT, STType.STRING):
        # VL-length prefix
        b0 = data[offset]
        if b0 <= 192:
            vl_len = b0
            offset += 1
        elif b0 <= 240:
            vl_len = 193 + ((b0 - 193) << 8) + data[offset + 1]
            offset += 2
        else:
            vl_len = 12481 + ((b0 - 241) << 16) + (data[offset + 1] << 8) + data[offset + 2]
            offset += 3
        val = data[offset:offset + vl_len]
        if tc == STType.ACCOUNT or tc == STType.STRING:
            val = val.decode("utf-8", errors="replace")
        return name, val, offset + vl_len
    else:
        # Skip unknown — can't determine length, return what we have
        return name, None, len(data)
