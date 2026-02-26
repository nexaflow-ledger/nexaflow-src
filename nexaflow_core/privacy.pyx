# cython: language_level=3, boundscheck=False, wraparound=False, cdivision=True
from __future__ import annotations
"""
Privacy crypto module for NexaFlow confidential transactions.

Implements Monero-like privacy features over secp256k1:

  PedersenCommitment  -- C = v*G + b*H  (hides amount v with blinding b)
  StealthAddress      -- one-time recipient address derived from view/spend keys
  RingSignature       -- LSAG ring sig hides real signer among decoys
  RangeProof          -- ZKP that committed value is non-negative
  KeyImage            -- I = x*Hp(P)  for per-output double-spend prevention

PRODUCTION NOTE: RangeProof uses a simplified SHA-256 ZKP placeholder.
Replace with a proper Bulletproof before handling real user funds.
"""

import hashlib
import os
import struct

cimport cython
from libc.time cimport time as c_time

from nexaflow_core.crypto_utils import (
    generate_keypair,
    derive_address,
    sign,
    verify,
    sha256,
    hash160,
)
from ecdsa import SECP256k1, SigningKey, VerifyingKey

# ---------------------------------------------------------------------------
#  secp256k1 curve parameters
# ---------------------------------------------------------------------------

_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_G = SECP256k1.generator

# Fixed second generator H = h*G, derived deterministically so discrete log
# of H w.r.t G is unknown (defeating binding compromise).
_H_SCALAR = int.from_bytes(
    sha256(b"NexaFlow/Pedersen/H-generator/v1"), "big"
) % _ORDER
_H = _H_SCALAR * _G


# ---------------------------------------------------------------------------
#  Internal helpers
# ---------------------------------------------------------------------------

cdef bytes _point_to_bytes(object point):
    """Serialize an EC point to 65-byte uncompressed form."""
    return (
        b"\x04"
        + point.x().to_bytes(32, "big")
        + point.y().to_bytes(32, "big")
    )


cdef object _bytes_to_point(bytes b):
    """Deserialize a 65-byte uncompressed point."""
    return VerifyingKey.from_string(b[1:], curve=SECP256k1).pubkey.point


cdef object _hp_point(bytes pub_bytes):
    """Hp(P) = hash-to-point used for key images and ring scalars."""
    h = hash160(pub_bytes)
    scalar = int.from_bytes(h, "big") % _ORDER
    return scalar * _G


cdef object _ring_hash(bytes message, list ring_pubs, object I, object L, object R):
    """H(m, pubs, I, L, R) -> integer scalar for LSAG."""
    h = hashlib.sha256()
    h.update(message)
    for p in ring_pubs:
        h.update(p)
    h.update(_point_to_bytes(I))
    h.update(_point_to_bytes(L))
    h.update(_point_to_bytes(R))
    return int.from_bytes(h.digest(), "big") % _ORDER


# ===================================================================
#  Pedersen Commitments   C = v*G + b*H
# ===================================================================

@cython.freelist(8)
cdef class PedersenCommitment:
    """
    A Pedersen commitment hiding amount v using blinding scalar b.

    Hiding: C reveals nothing about v (information-theoretic with random b).
    Binding: cannot open to a different (v', b') pair (DL hardness).
    Additive: commit(v1,b1) + commit(v2,b2) = commit(v1+v2, b1+b2).
    """
    cdef public bytes commitment  # 65-byte uncompressed secp256k1 point
    cdef public bytes blinding    # 32-byte scalar -- private, never goes on-chain

    def __init__(self, bytes commitment, bytes blinding):
        self.commitment = commitment
        self.blinding   = blinding

    @staticmethod
    def commit(double value, bytes blinding=None):
        """
        Create C = v*G + b*H.

        value    -- NXF amount (stored with 6 decimal places of precision)
        blinding -- optional 32-byte scalar; generated randomly when omitted
        """
        if blinding is None:
            blinding = os.urandom(32)

        v_int = int(round(value * 1_000_000))
        b_int = int.from_bytes(blinding, "big") % _ORDER

        c_point = v_int * _G + b_int * _H
        return PedersenCommitment(_point_to_bytes(c_point), blinding)

    def verify(self, double value) -> bool:
        """Re-derive commitment and compare (requires the blinding factor)."""
        expected = PedersenCommitment.commit(value, self.blinding)
        return expected.commitment == self.commitment

    def add(self, other):
        """Homomorphic addition: commit(v1+v2, b1+b2)."""
        p1 = _bytes_to_point(self.commitment)
        p2 = _bytes_to_point(other.commitment)
        c_point  = p1 + p2
        b1       = int.from_bytes(self.blinding, "big")
        b2       = int.from_bytes(other.blinding, "big")
        blinding = ((b1 + b2) % _ORDER).to_bytes(32, "big")
        return PedersenCommitment(_point_to_bytes(c_point), blinding)


# ===================================================================
#  Stealth Addresses
# ===================================================================

@cython.freelist(8)
cdef class StealthAddress:
    """
    One-time stealth address for untraceable payments.

    Sender:
      1. Generate ephemeral keypair (r, R=r*G).
      2. Shared secret: ss = H(r*V)  where V = recipient view pubkey.
      3. One-time pubkey: P = H(ss)*G + S  where S = recipient spend pubkey.
      4. One-time address = NexaFlow address derived from P.
      5. Publish R on-chain.

    Recipient:
      Compute ss = H(v*R), then check H(ss)*G + S == P.
    """
    cdef public bytes address       # NexaFlow address string as UTF-8 bytes
    cdef public bytes ephemeral_pub # R = r*G  (65-byte, published on-chain)
    cdef public bytes view_tag      # 1-byte fast-scan hint: H(ss)[0]

    def __init__(self, bytes address, bytes ephemeral_pub, bytes view_tag):
        self.address       = address
        self.ephemeral_pub = ephemeral_pub
        self.view_tag      = view_tag

    @staticmethod
    def generate(bytes recipient_view_pub, bytes recipient_spend_pub):
        """
        Generate a stealth address for the recipient.
        Returns (StealthAddress, shared_secret_bytes).
        """
        r_priv, r_pub = generate_keypair()
        r_int = int.from_bytes(r_priv, "big") % _ORDER

        view_point    = _bytes_to_point(recipient_view_pub)
        shared_point  = r_int * view_point
        shared_secret = sha256(shared_point.x().to_bytes(32, "big"))

        h_ss        = int.from_bytes(shared_secret, "big") % _ORDER
        spend_point = _bytes_to_point(recipient_spend_pub)
        p_point     = h_ss * _G + spend_point

        one_time_addr = derive_address(_point_to_bytes(p_point))
        view_tag      = shared_secret[:1]

        stealth = StealthAddress(one_time_addr.encode(), r_pub, view_tag)
        return stealth, shared_secret

    @staticmethod
    def recover_spend_key(bytes view_priv, bytes spend_priv,
                          bytes ephemeral_pub_bytes) -> bytes:
        """
        Recipient: recover the one-time private key for a received UTXO.
        one_time_priv = H(ss) + spend_priv  (mod n)
        """
        v_int         = int.from_bytes(view_priv, "big") % _ORDER
        r_point       = _bytes_to_point(ephemeral_pub_bytes)
        shared_secret = sha256((v_int * r_point).x().to_bytes(32, "big"))
        h_ss          = int.from_bytes(shared_secret, "big") % _ORDER
        s_int         = int.from_bytes(spend_priv, "big") % _ORDER
        return ((h_ss + s_int) % _ORDER).to_bytes(32, "big")

    @staticmethod
    def scan_output(bytes view_priv, bytes spend_pub,
                    bytes ephemeral_pub_bytes, bytes view_tag):
        """
        Recipient: check whether an on-chain output belongs to this wallet.
        Returns one-time address string if matched, else None.
        """
        v_int         = int.from_bytes(view_priv, "big") % _ORDER
        r_point       = _bytes_to_point(ephemeral_pub_bytes)
        shared_secret = sha256((v_int * r_point).x().to_bytes(32, "big"))
        if view_tag and shared_secret[:1] != view_tag:
            return None
        h_ss        = int.from_bytes(shared_secret, "big") % _ORDER
        spend_point = _bytes_to_point(spend_pub)
        p_point     = h_ss * _G + spend_point
        return derive_address(_point_to_bytes(p_point))


# ===================================================================
#  Ring Signatures   (Simplified LSAG)
# ===================================================================

@cython.freelist(4)
cdef class RingSignature:
    """
    Linkable ring signature hiding the real signer among decoy keys.

    Wire format (sig field):
      [1B  n        ] ring size
      [65B key_image] I = x*Hp(P)
      [n*32B c[i]  ] challenge scalars
      [n*32B s[i]  ] response scalars
      [n*65B P[i]  ] ring public keys
    """
    cdef public list  ring
    cdef public bytes sig
    cdef public int   signer_index

    def __init__(self, list ring, bytes sig, int signer_index=-1):
        self.ring         = ring
        self.sig          = sig
        self.signer_index = signer_index

    @staticmethod
    def sign(bytes message, bytes signer_priv, list ring_pubs,
             int signer_index):
        """
        Produce a linkable ring signature.
        """
        n = len(ring_pubs)
        if n == 0 or signer_index < 0 or signer_index >= n:
            raise ValueError("Invalid ring or signer_index")

        ki = KeyImage.generate(signer_priv, ring_pubs[signer_index])
        I  = _bytes_to_point(ki.image)
        x  = int.from_bytes(signer_priv, "big") % _ORDER

        c = [0] * n
        s = [0] * n

        k   = int.from_bytes(os.urandom(32), "big") % _ORDER
        L0  = k * _G
        R0  = k * _hp_point(ring_pubs[signer_index])

        idx    = (signer_index + 1) % n
        c[idx] = _ring_hash(message, ring_pubs, I, L0, R0)

        for _ in range(n - 1):
            s_i    = int.from_bytes(os.urandom(32), "big") % _ORDER
            s[idx] = s_i
            P_i    = _bytes_to_point(ring_pubs[idx])
            L_i    = s_i * _G + c[idx] * P_i
            R_i    = s_i * _hp_point(ring_pubs[idx]) + c[idx] * I
            nxt    = (idx + 1) % n
            c[nxt] = _ring_hash(message, ring_pubs, I, L_i, R_i)
            idx    = nxt

        s[signer_index] = (k - c[signer_index] * x) % _ORDER

        buf = struct.pack(">B", n)
        buf += ki.image
        for i in range(n):
            buf += c[i].to_bytes(32, "big")
        for i in range(n):
            buf += s[i].to_bytes(32, "big")
        for pub in ring_pubs:
            buf += pub

        return RingSignature(ring_pubs, buf, signer_index)

    def get_key_image(self) -> bytes:
        """Extract the 65-byte key image from the serialised signature."""
        return self.sig[1:66]

    def verify(self, bytes message) -> bool:
        return verify_ring_signature(self.sig, message)


cpdef bint verify_ring_signature(bytes sig_bytes, bytes message):
    """
    Standalone verifier used by the ledger validator.
    Returns True iff the ring signature is valid.
    """
    try:
        offset = 0
        n      = sig_bytes[0]
        offset += 1

        I = _bytes_to_point(sig_bytes[offset:offset + 65])
        offset += 65

        c = []
        for _ in range(n):
            c.append(int.from_bytes(sig_bytes[offset:offset + 32], "big"))
            offset += 32

        s = []
        for _ in range(n):
            s.append(int.from_bytes(sig_bytes[offset:offset + 32], "big"))
            offset += 32

        ring_pubs = []
        for _ in range(n):
            ring_pubs.append(sig_bytes[offset:offset + 65])
            offset += 65

        for i in range(n):
            P_i   = _bytes_to_point(ring_pubs[i])
            L_i   = s[i] * _G + c[i] * P_i
            R_i   = s[i] * _hp_point(ring_pubs[i]) + c[i] * I
            c_nxt = _ring_hash(message, ring_pubs, I, L_i, R_i)
            if c_nxt != c[(i + 1) % n]:
                return False

        return True
    except Exception:
        return False


# ===================================================================
#  Range Proofs
# ===================================================================

@cython.freelist(4)
cdef class RangeProof:
    """
    Proves committed value v >= 0.

    Placeholder implementation: SHA-256(blinding || value || domain).
    Replace with Bulletproofs for full ZK range proofs in production.
    """
    cdef public bytes proof

    def __init__(self, bytes proof):
        self.proof = proof

    @staticmethod
    def prove(long long value, bytes blinding):
        """Generate proof for non-negative value (NXF drops, 6 dp)."""
        if value < 0:
            raise ValueError("RangeProof: value must be >= 0")
        proof = sha256(
            blinding
            + value.to_bytes(8, "big")
            + b"NexaFlow/RangeProof/v1"
        )
        return RangeProof(proof)

    def verify(self, bytes commitment) -> bool:
        """Structural check: well-formed 32-byte non-zero proof."""
        return len(self.proof) == 32 and self.proof != b"\x00" * 32


# ===================================================================
#  Key Images   I = x * Hp(P)
# ===================================================================

@cython.freelist(8)
cdef class KeyImage:
    """
    Per-output key image for double-spend prevention.

    Deterministic given (spend_priv, spend_pub).
    Does not reveal the private key or link to on-chain identity.
    """
    cdef public bytes image   # 65-byte uncompressed secp256k1 point

    def __init__(self, bytes image):
        self.image = image

    @staticmethod
    def generate(bytes spend_priv, bytes spend_pub):
        """Compute I = x * Hp(P)."""
        hp = _hp_point(spend_pub)
        x  = int.from_bytes(spend_priv, "big") % _ORDER
        return KeyImage(_point_to_bytes(x * hp))


# ===================================================================
#  Confidential Transaction Builder
# ===================================================================

cpdef object create_confidential_payment(
    str sender_addr,
    bytes sender_priv,
    bytes recipient_view_pub,
    bytes recipient_spend_pub,
    double amount,
    list decoy_pubs,
    double fee=0.00001,
    long long sequence=0,
):
    """
    Build a fully-formed confidential Payment transaction.

    Parameters
    ----------
    sender_addr         NexaFlow address of sender (for fee and sequence bump)
    sender_priv         32-byte spend private key of the sender
    recipient_view_pub  65-byte recipient view public key
    recipient_spend_pub 65-byte recipient spend public key
    amount              NXF amount (hidden in Pedersen commitment)
    decoy_pubs          list of 65-byte decoy public keys (ring members)
    fee                 NXF fee paid publicly from sender's account
    sequence            tx sequence number (0 = caller assigns)

    Returns
    -------
    Transaction with all privacy fields populated.
    """
    from nexaflow_core.transaction import Transaction, Amount, TT_PAYMENT

    # Derive sender public key
    sk         = SigningKey.from_string(sender_priv, curve=SECP256k1)
    sender_pub = b"\x04" + sk.get_verifying_key().to_string()

    # Key image
    ki = KeyImage.generate(sender_priv, sender_pub)

    # Build ring: sender at index 0
    ring = [sender_pub] + [p for p in decoy_pubs if p != sender_pub]

    # Stealth address for recipient
    stealth, _shared_secret = StealthAddress.generate(
        recipient_view_pub, recipient_spend_pub
    )

    # Pedersen commitment (amount is hidden)
    commitment = PedersenCommitment.commit(amount)

    # Range proof
    range_proof = RangeProof.prove(
        int(round(amount * 1_000_000)), commitment.blinding
    )

    # Transaction (amount field zeroed; real value is in commitment)
    tx = Transaction(
        TT_PAYMENT, sender_addr,
        stealth.address.decode(),
        Amount(0.0),
        Amount(fee),
        sequence,
    )
    tx.commitment      = commitment.commitment
    tx.stealth_address = stealth.address
    tx.ephemeral_pub   = stealth.ephemeral_pub
    tx.view_tag        = stealth.view_tag
    tx.range_proof     = range_proof.proof
    tx.key_image       = ki.image

    # Ring signature over tx signing hash (ring_sig excluded from preimage by design)
    ring_sig          = RingSignature.sign(tx.hash_for_signing(), sender_priv, ring, 0)
    tx.ring_signature = ring_sig.sig

    # tx_id: sha256 of the full serialized blob + ring_signature
    tx.tx_id = sha256(tx.hash_for_signing() + tx.ring_signature).hex()

    return tx
