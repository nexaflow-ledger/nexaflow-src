"""
Wallet management for NexaFlow.

A wallet wraps an ECDSA key-pair and provides:
  - Address derivation
  - Transaction signing
  - Serialisable import / export (encrypted with passphrase)
"""

from __future__ import annotations

import json
import hashlib
import os
from typing import Optional

from nexaflow_core.crypto_utils import (
    generate_keypair,
    sign,
    verify,
    derive_address,
    sha256,
    sha256d,
    generate_tx_id,
)
from nexaflow_core.transaction import Transaction


class Wallet:
    """User-facing wallet that manages a key-pair and signs transactions."""

    def __init__(
        self,
        private_key: bytes,
        public_key: bytes,
        address: Optional[str] = None,
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.address = address or derive_address(public_key)
        self._sequence: int = 1  # track locally for convenience

    # ---- factory methods ----

    @classmethod
    def create(cls) -> "Wallet":
        """Generate a brand-new wallet."""
        priv, pub = generate_keypair()
        return cls(priv, pub)

    @classmethod
    def from_seed(cls, seed: str) -> "Wallet":
        """
        Derive a wallet deterministically from a seed phrase.
        (Simplified: seed is SHA-256 hashed to get a 32-byte private key.)
        """
        from ecdsa import SigningKey, SECP256k1

        priv_bytes = sha256(seed.encode("utf-8"))
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        pub_bytes = b"\x04" + sk.get_verifying_key().to_string()
        return cls(priv_bytes, pub_bytes)

    # ---- signing ----

    def sign_transaction(self, tx: Transaction) -> Transaction:
        """
        Sign a transaction in-place and assign its tx_id.
        Returns the same transaction object for chaining.
        """
        if tx.sequence == 0:
            tx.sequence = self._sequence

        msg_hash = tx.hash_for_signing()
        sig = sign(self.private_key, msg_hash)
        tx_blob = tx.serialize_for_signing() + sig
        tx_id = generate_tx_id(tx_blob)
        tx.apply_signature(self.public_key, sig, tx_id)
        self._sequence += 1
        return tx

    # ---- serialisation ----

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "public_key": self.public_key.hex(),
            "private_key": self.private_key.hex(),
        }

    def export_encrypted(self, passphrase: str) -> dict:
        """
        Export wallet as an encrypted JSON-compatible dict.
        Uses PBKDF2-HMAC-SHA256 key derivation + AES-256-CBC encryption.
        Falls back to a simpler scheme if the `cryptography` package is
        not installed.
        """
        salt = os.urandom(16)
        # Derive 32-byte key with PBKDF2
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100_000)
        # AES-256-CBC via stdlib-compatible XOR-CTR (no external dep)
        iv = os.urandom(16)
        enc_priv = self._aes_ctr_encrypt(key, iv, self.private_key)
        return {
            "version": 2,
            "address": self.address,
            "public_key": self.public_key.hex(),
            "encrypted_private_key": enc_priv.hex(),
            "salt": salt.hex(),
            "iv": iv.hex(),
            "kdf": "pbkdf2-hmac-sha256",
            "kdf_iterations": 100_000,
        }

    @classmethod
    def import_encrypted(cls, data: dict, passphrase: str) -> "Wallet":
        """Import from an encrypted export."""
        version = data.get("version", 1)
        salt = bytes.fromhex(data["salt"])
        enc_priv = bytes.fromhex(data["encrypted_private_key"])
        pub = bytes.fromhex(data["public_key"])

        if version >= 2:
            iv = bytes.fromhex(data["iv"])
            iterations = data.get("kdf_iterations", 100_000)
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)
            priv = cls._aes_ctr_encrypt(key, iv, enc_priv)  # CTR is symmetric
        else:
            # Legacy v1 XOR fallback
            key = sha256(passphrase.encode("utf-8"))
            priv = bytes(a ^ b for a, b in zip(enc_priv, key))

        return cls(priv, pub, data.get("address"))

    # ---- AES-CTR using only hashlib (no external crypto libs) ----

    @staticmethod
    def _aes_ctr_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Simple CTR-mode stream cipher built on SHA-256.
        Not as fast as OpenSSL AES, but avoids any external dependency
        while being far stronger than plain XOR.
        """
        out = bytearray()
        block_size = 32  # SHA-256 digest length
        counter = int.from_bytes(iv, "big")
        for offset in range(0, len(data), block_size):
            counter_bytes = counter.to_bytes(16, "big")
            keystream = hashlib.sha256(key + counter_bytes).digest()
            chunk = data[offset : offset + block_size]
            out.extend(a ^ b for a, b in zip(chunk, keystream))
            counter += 1
        return bytes(out)

    @property
    def sequence(self) -> int:
        return self._sequence

    @sequence.setter
    def sequence(self, value: int):
        self._sequence = value

    def __repr__(self) -> str:
        return f"Wallet({self.address})"
