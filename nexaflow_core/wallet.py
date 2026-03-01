"""
Wallet management for NexaFlow.

A wallet wraps an ECDSA key-pair and provides:
  - Address derivation
  - Transaction signing
  - Serialisable import / export (encrypted with passphrase)
"""

from __future__ import annotations

import hashlib
import os
from typing import Any

from nexaflow_core.crypto_utils import (
    derive_address,
    generate_keypair,
    generate_tx_id,
    sha256,
    sign,
)
from nexaflow_core.transaction import Transaction


class Wallet:
    """User-facing wallet that manages key-pairs for signing and stealth addresses."""

    def __init__(
        self,
        private_key: bytes,
        public_key: bytes,
        address: str | None = None,
        view_private_key: bytes | None = None,
        view_public_key: bytes | None = None,
        spend_private_key: bytes | None = None,
        spend_public_key: bytes | None = None,
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.address = address or derive_address(public_key)
        self.view_private_key = view_private_key
        self.view_public_key = view_public_key
        self.spend_private_key = spend_private_key
        self.spend_public_key = spend_public_key
        self._sequence: int = 1  # track locally for convenience

    # ---- factory methods ----

    @classmethod
    def create(cls) -> Wallet:
        """Generate a brand-new wallet with view and spend keypairs."""
        # Main keypair for signing
        priv, pub = generate_keypair()
        # View keypair
        view_priv, view_pub = generate_keypair()
        # Spend keypair
        spend_priv, spend_pub = generate_keypair()
        return cls(priv, pub, view_private_key=view_priv, view_public_key=view_pub,
                   spend_private_key=spend_priv, spend_public_key=spend_pub)

    @classmethod
    def from_seed(cls, seed: str) -> Wallet:
        """
        Derive a wallet deterministically from a seed phrase.
        Generates view and spend keypairs from seed.
        """
        from ecdsa import SECP256k1, SigningKey

        # Main keypair
        priv_bytes = sha256(seed.encode("utf-8"))
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        pub_bytes = b"\x04" + sk.get_verifying_key().to_string()

        # View keypair
        view_priv = sha256((seed + "_view").encode("utf-8"))
        view_sk = SigningKey.from_string(view_priv, curve=SECP256k1)
        view_pub = b"\x04" + view_sk.get_verifying_key().to_string()

        # Spend keypair
        spend_priv = sha256((seed + "_spend").encode("utf-8"))
        spend_sk = SigningKey.from_string(spend_priv, curve=SECP256k1)
        spend_pub = b"\x04" + spend_sk.get_verifying_key().to_string()

        return cls(priv_bytes, pub_bytes, view_private_key=view_priv, view_public_key=view_pub,
                   spend_private_key=spend_priv, spend_public_key=spend_pub)

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

    def sign_confidential_payment(
        self,
        recipient_view_pub: bytes,
        recipient_spend_pub: bytes,
        amount: float,
        decoy_pubs: list[bytes] | None = None,
        fee: float = 0.00001,
    ) -> Transaction:
        """
        Build and return a confidential Payment transaction.

        The amount is hidden inside a Pedersen commitment; the recipient's
        identity is protected by a one-time stealth address; the sender's
        identity is hidden in a LSAG ring signature.

        Parameters
        ----------
        recipient_view_pub   65-byte view public key of the recipient.
        recipient_spend_pub  65-byte spend public key of the recipient.
        amount               NXF amount to send (hidden on-chain).
        decoy_pubs           Optional list of 65-byte decoy public keys.
                             Pass [] for a ring of size 1 (no anonymity).
        fee                  NXF fee deducted from sender's public balance.

        Returns
        -------
        A fully populated Transaction ready for submission.
        """
        if self.spend_private_key is None:
            raise ValueError("Wallet has no spend private key — cannot sign confidential TXs")

        from nexaflow_core.privacy import create_confidential_payment  # type: ignore[import]

        seq = self._sequence
        self._sequence += 1

        return create_confidential_payment(
            sender_addr=self.address,
            sender_priv=self.spend_private_key,
            recipient_view_pub=recipient_view_pub,
            recipient_spend_pub=recipient_spend_pub,
            amount=amount,
            decoy_pubs=list(decoy_pubs or []),
            fee=fee,
            sequence=seq,
        )

    def scan_confidential_outputs(self, ledger: Any) -> list[dict]:
        """
        Scan all confidential UTXOs in *ledger* and return those belonging
        to this wallet.

        For each matched output the dict contains:
          ``stealth_addr``   -- one-time address (hex key in ledger)
          ``commitment``     -- Pedersen commitment bytes (hex str)
          ``ephemeral_pub``  -- ephemeral pubkey needed to recover spend key
          ``view_tag``       -- fast-scan hint byte (hex str)
          ``tx_id``          -- originating transaction ID
          ``one_time_priv``  -- recovered one-time private key (bytes)

        The wallet needs ``view_private_key`` and ``spend_public_key`` for scanning.
        Additionally, ``spend_private_key`` is used to compute ``one_time_priv``.
        """
        if self.view_private_key is None or self.spend_public_key is None:
            raise ValueError("Wallet missing view keys — cannot scan outputs")

        from nexaflow_core.privacy import StealthAddress  # type: ignore[import]

        results: list[dict] = []
        for utxo in ledger.get_all_confidential_outputs():
            ephemeral_pub = bytes.fromhex(utxo["ephemeral_pub"])
            view_tag      = bytes.fromhex(utxo["view_tag"])
            matched_addr  = StealthAddress.scan_output(
                self.view_private_key,
                self.spend_public_key,
                ephemeral_pub,
                view_tag,
            )
            if matched_addr is None:
                continue
            # utxo["stealth_addr"] is the hex encoding of the raw address bytes;
            # matched_addr is the decoded ASCII string — convert before comparing.
            stealth_addr_hex = utxo.get("stealth_addr", "")
            try:
                stealth_addr_str = bytes.fromhex(stealth_addr_hex).decode()
            except (ValueError, UnicodeDecodeError):
                stealth_addr_str = stealth_addr_hex
            if matched_addr != stealth_addr_str:
                # view tag matched but address didn't — rare collision, skip
                continue

            row = dict(utxo)
            if self.spend_private_key is not None:
                row["one_time_priv"] = StealthAddress.recover_spend_key(
                    self.view_private_key,
                    self.spend_private_key,
                    ephemeral_pub,
                ).hex()
            results.append(row)

        return results

    # ---- serialisation ----

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "public_key": self.public_key.hex(),
            "private_key": self.private_key.hex(),
            "view_public_key": self.view_public_key.hex() if self.view_public_key else None,
            "view_private_key": self.view_private_key.hex() if self.view_private_key else None,
            "spend_public_key": self.spend_public_key.hex() if self.spend_public_key else None,
            "spend_private_key": self.spend_private_key.hex() if self.spend_private_key else None,
        }

    def export_encrypted(self, passphrase: str) -> dict:
        """
        Export wallet as an encrypted JSON-compatible dict.
        Uses PBKDF2-HMAC-SHA256 key derivation + BLAKE2b-CTR encryption.
        Falls back to a simpler scheme if the `cryptography` package is
        not installed.
        """
        salt = os.urandom(16)
        # Derive 32-byte key with PBKDF2
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100_000)
        # AES-256-CBC via stdlib-compatible XOR-CTR (no external dep)
        iv = os.urandom(16)
        enc_priv = self._aes_ctr_encrypt(key, iv, self.private_key)
        enc_view_priv = self._aes_ctr_encrypt(key, iv, self.view_private_key) if self.view_private_key else None
        enc_spend_priv = self._aes_ctr_encrypt(key, iv, self.spend_private_key) if self.spend_private_key else None
        return {
            "version": 2,
            "address": self.address,
            "public_key": self.public_key.hex(),
            "encrypted_private_key": enc_priv.hex(),
            "view_public_key": self.view_public_key.hex() if self.view_public_key else None,
            "encrypted_view_private_key": enc_view_priv.hex() if enc_view_priv else None,
            "spend_public_key": self.spend_public_key.hex() if self.spend_public_key else None,
            "encrypted_spend_private_key": enc_spend_priv.hex() if enc_spend_priv else None,
            "salt": salt.hex(),
            "iv": iv.hex(),
            "kdf": "pbkdf2-hmac-sha256",
            "kdf_iterations": 100_000,
        }

    @classmethod
    def import_encrypted(cls, data: dict, passphrase: str) -> Wallet:
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
            view_priv = None
            if data.get("encrypted_view_private_key"):
                enc_view_priv = bytes.fromhex(data["encrypted_view_private_key"])
                view_priv = cls._aes_ctr_encrypt(key, iv, enc_view_priv)
            spend_priv = None
            if data.get("encrypted_spend_private_key"):
                enc_spend_priv = bytes.fromhex(data["encrypted_spend_private_key"])
                spend_priv = cls._aes_ctr_encrypt(key, iv, enc_spend_priv)
        else:
            # Legacy v1 XOR fallback
            key = sha256(passphrase.encode("utf-8"))
            priv = bytes(a ^ b for a, b in zip(enc_priv, key))
            view_priv = None
            spend_priv = None

        view_pub = bytes.fromhex(data["view_public_key"]) if data.get("view_public_key") else None
        spend_pub = bytes.fromhex(data["spend_public_key"]) if data.get("spend_public_key") else None

        return cls(priv, pub, data.get("address"), view_private_key=view_priv, view_public_key=view_pub,
                   spend_private_key=spend_priv, spend_public_key=spend_pub)

    # ---- AES-CTR using only hashlib (no external crypto libs) ----

    @staticmethod
    def _aes_ctr_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Simple CTR-mode stream cipher built on BLAKE2b.
        Not as fast as OpenSSL AES, but avoids any external dependency
        while being far stronger than plain XOR.
        """
        out = bytearray()
        block_size = 32  # BLAKE2b-256 digest length
        counter = int.from_bytes(iv, "big")
        for offset in range(0, len(data), block_size):
            counter_bytes = counter.to_bytes(16, "big")
            keystream = hashlib.blake2b(key + counter_bytes, digest_size=32).digest()
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
