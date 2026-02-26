# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
"""
Cython-optimized cryptographic utilities for NexaFlow.

Provides fast hashing, key generation, ECDSA signing/verification,
and address derivation compatible with a NexaFlow-like system.
"""

import hashlib
import os
import struct

from libc.time cimport time as c_time
from libc.string cimport memcmp

# ---------- Base58 alphabet (NexaFlow-style) ----------
cdef str ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

cdef int ALPHABET_LEN = 58

# Pre-build reverse lookup
cdef dict _ALPHA_MAP = {c: i for i, c in enumerate(ALPHABET)}


# ===================================================================
#  Fast SHA-256 / SHA-512 / RIPEMD-160 helpers
# ===================================================================

cpdef bytes sha256(bytes data):
    """Single SHA-256 hash."""
    return hashlib.sha256(data).digest()

cpdef bytes sha256d(bytes data):
    """Double SHA-256 hash (used for checksums)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

cpdef bytes sha512_half(bytes data):
    """SHA-512 first 32 bytes — used for transaction hashing."""
    return hashlib.sha512(data).digest()[:32]

cpdef bytes ripemd160(bytes data):
    """RIPEMD-160 hash."""
    return hashlib.new("ripemd160", data).digest()

cpdef bytes hash160(bytes data):
    """SHA-256 then RIPEMD-160 — standard address hash."""
    return ripemd160(sha256(data))


# ===================================================================
#  Base58 encoding / decoding  (NexaFlow alphabet)
# ===================================================================

cpdef str base58_encode(bytes payload):
    """Encode bytes to NexaFlow-style base58 string."""
    cdef object n = int.from_bytes(payload, "big")  # Python int (arbitrary precision)
    cdef list chars = []
    cdef int remainder

    if n == 0:
        chars.append(ALPHABET[0])
    else:
        while n > 0:
            remainder = <int>(n % ALPHABET_LEN)
            n //= ALPHABET_LEN
            chars.append(ALPHABET[remainder])

    # Preserve leading zero-bytes
    cdef int i
    for i in range(len(payload)):
        if payload[i] == 0:
            chars.append(ALPHABET[0])
        else:
            break

    chars.reverse()
    return "".join(chars)


cpdef bytes base58_decode(str encoded):
    """Decode a NexaFlow-style base58 string to bytes."""
    cdef object n = 0  # Python int (arbitrary precision)
    cdef str c
    for c in encoded:
        n = n * ALPHABET_LEN + _ALPHA_MAP[c]

    # Convert to bytes (variable length, trim later)
    cdef bytes raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b"\x00"

    # Restore leading zeros
    cdef int pad = 0
    for c in encoded:
        if c == ALPHABET[0]:
            pad += 1
        else:
            break

    return b"\x00" * pad + raw


cpdef str base58check_encode(int version_byte, bytes payload):
    """Encode with version byte + 4-byte checksum (NexaFlow-style)."""
    cdef bytes versioned = bytes([version_byte]) + payload
    cdef bytes checksum = sha256d(versioned)[:4]
    return base58_encode(versioned + checksum)


cpdef bytes base58check_decode(str encoded):
    """Decode base58check, verify checksum, return payload (without version)."""
    cdef bytes decoded = base58_decode(encoded)
    cdef bytes payload = decoded[:-4]
    cdef bytes checksum = decoded[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("Invalid base58check checksum")
    return payload[1:]  # strip version byte


# ===================================================================
#  ECDSA key-pair generation & signing  (secp256k1)
# ===================================================================

cpdef tuple generate_keypair():
    """
    Generate an ECDSA secp256k1 key-pair.
    Returns (private_key_bytes, public_key_bytes).
    """
    from ecdsa import SigningKey, SECP256k1
    cdef object sk = SigningKey.generate(curve=SECP256k1)
    cdef bytes priv = sk.to_string()
    cdef bytes pub = sk.get_verifying_key().to_string()
    # Prefix uncompressed public key
    pub = b"\x04" + pub
    return priv, pub


cpdef bytes sign(bytes private_key, bytes message_hash):
    """Sign a 32-byte hash with the private key (DER-encoded)."""
    from ecdsa import SigningKey, SECP256k1
    cdef object sk = SigningKey.from_string(private_key, curve=SECP256k1)
    return sk.sign_digest(message_hash, sigencode=_sigencode_der)


cpdef bint verify(bytes public_key, bytes message_hash, bytes signature):
    """Verify a DER-encoded signature against a public key and hash."""
    from ecdsa import VerifyingKey, SECP256k1, BadSignatureError
    from ecdsa.errors import MalformedPointError
    cdef bytes raw_pub = public_key
    if raw_pub[0:1] == b"\x04":
        raw_pub = raw_pub[1:]
    try:
        vk = VerifyingKey.from_string(raw_pub, curve=SECP256k1)
        return vk.verify_digest(signature, message_hash, sigdecode=_sigdecode_der)
    except (BadSignatureError, MalformedPointError, ValueError, AssertionError):
        return False


# DER sigencode / sigdecode helpers (avoid pulling extra deps)
def _sigencode_der(r, s, order):
    """Encode r, s into DER format."""
    from ecdsa.util import sigencode_der
    return sigencode_der(r, s, order)


def _sigdecode_der(sig, order):
    """Decode DER signature into (r, s)."""
    from ecdsa.util import sigdecode_der
    return sigdecode_der(sig, order)


# ===================================================================
#  Address derivation
# ===================================================================

cpdef str derive_address(bytes public_key):
    """
    Derive a NexaFlow-style account address from a public key.
    Version byte 0 => prefix 'r' in NexaFlow alphabet.
    """
    cdef bytes h = hash160(public_key)
    return base58check_encode(0, h)


# ===================================================================
#  Fast nonce / unique-id generation
# ===================================================================

cpdef bytes generate_nonce(int length=32):
    """Cryptographically secure random bytes."""
    return os.urandom(length)


cpdef str generate_tx_id(bytes tx_blob):
    """Deterministic transaction ID from serialised blob."""
    return sha256d(tx_blob).hex()


# ===================================================================
#  Timestamp helpers  (NexaFlow epoch = 2000-01-01)
# ===================================================================

cdef long long _NEXAFLOW_EPOCH = 946684800  # Unix timestamp for 2000-01-01

# Python-visible alias
NEXAFLOW_EPOCH = _NEXAFLOW_EPOCH


cdef inline long long _nexaflow_timestamp() nogil:
    """GIL-free: seconds since the NexaFlow epoch."""
    return <long long>c_time(NULL) - _NEXAFLOW_EPOCH


cpdef long long nexaflow_timestamp():
    """Seconds since the NexaFlow epoch (2000-01-01 00:00:00 UTC)."""
    return _nexaflow_timestamp()


cdef inline double _unix_from_nexaflow(long long rts) nogil:
    """GIL-free: convert NexaFlow timestamp to Unix timestamp."""
    return <double>(rts + _NEXAFLOW_EPOCH)


cpdef double unix_from_nexaflow(long long rts):
    """Convert NexaFlow timestamp back to Unix timestamp."""
    return _unix_from_nexaflow(rts)
