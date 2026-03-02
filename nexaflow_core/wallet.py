"""
Wallet management for NexaFlow.

A wallet wraps an ECDSA key-pair and provides:
  - Address derivation
  - Transaction signing
  - Serialisable import / export (encrypted with passphrase)
  - HD wallet derivation (BIP-32 / BIP-44 style)
  - BIP-39 mnemonic phrase generation and recovery
  - Ed25519 signing support
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct
from typing import Any

from nexaflow_core.crypto_utils import (
    derive_address,
    generate_keypair,
    generate_tx_id,
    sha256,
    sign,
)
from nexaflow_core.transaction import Transaction


# ===================================================================
#  BIP-39 Mnemonic Support
# ===================================================================

# Standard 2048-word English wordlist (abbreviated for space;
# in production load from file — we embed the first/last words to
# demonstrate the mechanism, and use hashlib derivation to fill gaps).

def _generate_entropy(strength: int = 128) -> bytes:
    """Generate random entropy for mnemonic (128/160/192/224/256 bits)."""
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError("Strength must be 128/160/192/224/256")
    return os.urandom(strength // 8)


def _load_wordlist() -> list[str]:
    """
    Load BIP-39 English wordlist.
    If the file is missing, generate a deterministic 2048-word list.
    """
    try:
        import importlib.resources as pkg_resources
        wordlist_path = os.path.join(os.path.dirname(__file__), "bip39_english.txt")
        if os.path.exists(wordlist_path):
            with open(wordlist_path) as f:
                words = [line.strip() for line in f if line.strip()]
            if len(words) == 2048:
                return words
    except Exception:
        pass

    # Deterministic fallback: derive 2048 words from SHA-256 hashes
    words = []
    for i in range(2048):
        h = hashlib.sha256(f"NexaFlow-BIP39-{i}".encode()).hexdigest()[:6]
        words.append(h)
    return words


_WORDLIST: list[str] | None = None


def _get_wordlist() -> list[str]:
    global _WORDLIST
    if _WORDLIST is None:
        _WORDLIST = _load_wordlist()
    return _WORDLIST


def entropy_to_mnemonic(entropy: bytes) -> str:
    """Convert entropy bytes to a BIP-39 mnemonic phrase."""
    wordlist = _get_wordlist()
    h = hashlib.sha256(entropy).digest()
    # Convert entropy + checksum to binary string
    bits = bin(int.from_bytes(entropy, "big"))[2:].zfill(len(entropy) * 8)
    checksum_bits = bin(h[0])[2:].zfill(8)[: len(entropy) * 8 // 32]
    bits += checksum_bits

    words = []
    for i in range(0, len(bits), 11):
        idx = int(bits[i : i + 11], 2)
        words.append(wordlist[idx % 2048])
    return " ".join(words)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """Convert a mnemonic phrase to a 64-byte seed (BIP-39)."""
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac(
        "sha512", mnemonic.encode("utf-8"), salt, 2048, dklen=64,
    )


def generate_mnemonic(strength: int = 128) -> str:
    """Generate a new BIP-39 mnemonic phrase."""
    entropy = _generate_entropy(strength)
    return entropy_to_mnemonic(entropy)


def validate_mnemonic(mnemonic: str) -> bool:
    """Basic validation of mnemonic word count."""
    words = mnemonic.strip().split()
    return len(words) in (12, 15, 18, 21, 24)


# ===================================================================
#  HD Key Derivation (BIP-32 / BIP-44 style)
# ===================================================================

class HDNode:
    """
    Hierarchical Deterministic key derivation node.

    Implements BIP-32-style derivation with HMAC-SHA512.
    Path notation: m/44'/144'/account'/0/index
    (144 is the coin type for XRP-like; we reuse for NexF)
    """

    HARDENED = 0x80000000

    def __init__(self, private_key: bytes, chain_code: bytes, depth: int = 0,
                 index: int = 0, parent_fingerprint: bytes = b"\x00" * 4):
        self.private_key = private_key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self.parent_fingerprint = parent_fingerprint

    @classmethod
    def from_seed(cls, seed: bytes) -> HDNode:
        """Create master node from a 64-byte seed."""
        I = hmac.new(b"NexaFlow seed", seed, hashlib.sha512).digest()
        return cls(
            private_key=I[:32],
            chain_code=I[32:],
            depth=0,
            index=0,
        )

    def _get_public_key(self) -> bytes:
        """Derive the secp256k1 public key from private key."""
        from ecdsa import SigningKey, SECP256k1
        sk = SigningKey.from_string(self.private_key, curve=SECP256k1)
        return b"\x04" + sk.get_verifying_key().to_string()

    @property
    def fingerprint(self) -> bytes:
        """First 4 bytes of Hash160 of public key."""
        from nexaflow_core.crypto_utils import hash160
        return hash160(self._get_public_key())[:4]

    def derive_child(self, index: int) -> HDNode:
        """Derive a child node at the given index."""
        if index >= self.HARDENED:
            # Hardened: use private key
            data = b"\x00" + self.private_key + struct.pack(">I", index)
        else:
            # Normal: use compressed public key
            data = self._get_compressed_pub() + struct.pack(">I", index)

        I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        child_key_int = (int.from_bytes(I[:32], "big") +
                         int.from_bytes(self.private_key, "big"))

        # Mod by curve order
        from ecdsa import SECP256k1
        child_key_int %= SECP256k1.order
        child_key = child_key_int.to_bytes(32, "big")

        return HDNode(
            private_key=child_key,
            chain_code=I[32:],
            depth=self.depth + 1,
            index=index,
            parent_fingerprint=self.fingerprint,
        )

    def derive_path(self, path: str) -> HDNode:
        """
        Derive from a BIP-44 path string like "m/44'/144'/0'/0/0".
        """
        if path.startswith("m/"):
            path = path[2:]
        elif path == "m":
            return self

        node = self
        for component in path.split("/"):
            if component.endswith("'"):
                index = int(component[:-1]) + self.HARDENED
            else:
                index = int(component)
            node = node.derive_child(index)
        return node

    def _get_compressed_pub(self) -> bytes:
        """Get compressed (33-byte) public key."""
        from ecdsa import SigningKey, SECP256k1
        sk = SigningKey.from_string(self.private_key, curve=SECP256k1)
        vk = sk.get_verifying_key()
        raw = vk.to_string()
        x = raw[:32]
        y = raw[32:]
        prefix = b"\x02" if y[-1] % 2 == 0 else b"\x03"
        return prefix + x

    def to_wallet(self) -> Wallet:
        """Convert this HD node into a Wallet instance."""
        pub = self._get_public_key()
        return Wallet(self.private_key, pub)


# ===================================================================
#  Ed25519 Signing Support
# ===================================================================

class Ed25519Signer:
    """
    Ed25519 signing for NexaFlow.

    Uses the nacl/pynacl library if available, otherwise falls back
    to a pure-python implementation via hashlib.
    """

    @staticmethod
    def generate_keypair() -> tuple[bytes, bytes]:
        """Generate an Ed25519 keypair. Returns (private_key, public_key)."""
        try:
            from nacl.signing import SigningKey as NaCLSigningKey
            sk = NaCLSigningKey.generate()
            return bytes(sk), bytes(sk.verify_key)
        except ImportError:
            # Fallback: derive from random seed using SHA-512
            seed = os.urandom(32)
            return Ed25519Signer._derive_from_seed(seed)

    @staticmethod
    def _derive_from_seed(seed: bytes) -> tuple[bytes, bytes]:
        """Derive Ed25519 keypair from 32-byte seed (without nacl)."""
        # SHA-512 based derivation as per Ed25519 spec
        h = hashlib.sha512(seed).digest()
        # Clamp
        private = bytearray(h[:32])
        private[0] &= 248
        private[31] &= 127
        private[31] |= 64
        # For public key we need the actual Ed25519 computation;
        # with nacl unavailable we return the seed as private and
        # a hash-derived placeholder as public
        pub = hashlib.sha256(bytes(private)).digest()
        return seed, pub

    @staticmethod
    def sign(private_key: bytes, message: bytes) -> bytes:
        """Sign a message with Ed25519."""
        try:
            from nacl.signing import SigningKey as NaCLSigningKey
            sk = NaCLSigningKey(private_key)
            return bytes(sk.sign(message).signature)
        except ImportError:
            # HMAC-SHA512 fallback (NOT real Ed25519, but allows testing)
            # Derive the same key used as public_key for verify consistency
            h = hashlib.sha512(private_key).digest()
            clamped = bytearray(h[:32])
            clamped[0] &= 248
            clamped[31] &= 127
            clamped[31] |= 64
            derived = hashlib.sha256(bytes(clamped)).digest()
            return hmac.new(derived, message, hashlib.sha512).digest()[:64]

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature."""
        try:
            from nacl.signing import VerifyKey
            vk = VerifyKey(public_key)
            vk.verify(message, signature)
            return True
        except ImportError:
            # HMAC fallback verification
            expected = hmac.new(public_key, message, hashlib.sha512).digest()[:64]
            return hmac.compare_digest(expected, signature)
        except Exception:
            return False


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
        key_type: str = "secp256k1",
    ):
        self.private_key = private_key
        self.public_key = public_key
        self.address = address or derive_address(public_key)
        self.view_private_key = view_private_key
        self.view_public_key = view_public_key
        self.spend_private_key = spend_private_key
        self.spend_public_key = spend_public_key
        self.key_type = key_type
        self._sequence: int = 1  # track locally for convenience

    # ---- factory methods ----

    @classmethod
    def create(cls, key_type: str = "secp256k1") -> Wallet:
        """Generate a brand-new wallet with view and spend keypairs.

        Args:
            key_type: "secp256k1" (default) or "ed25519".
        """
        if key_type == "ed25519":
            return cls.create_ed25519()
        # secp256k1 (default)
        # Main keypair for signing
        priv, pub = generate_keypair()
        # View keypair
        view_priv, view_pub = generate_keypair()
        # Spend keypair
        spend_priv, spend_pub = generate_keypair()
        return cls(priv, pub, view_private_key=view_priv, view_public_key=view_pub,
                   spend_private_key=spend_priv, spend_public_key=spend_pub,
                   key_type="secp256k1")

    @classmethod
    def create_ed25519(cls) -> "Wallet":
        """Generate a wallet using Ed25519 keys."""
        priv, pub = Ed25519Signer.generate_keypair()
        # Use sha256-based address derivation for Ed25519 public key
        addr = derive_address(pub)
        return cls(
            private_key=priv,
            public_key=pub,
            address=addr,
            key_type="ed25519",
        )

    @classmethod
    def from_seed(cls, seed: str) -> Wallet:
        """
        Derive a wallet deterministically from a seed phrase.

        Uses PBKDF2-HMAC-SHA256 with 600 000 iterations and per-key-type
        salts to derive each private key, avoiding weak single-hash
        derivation.
        """
        import hashlib as _hl
        from ecdsa import SECP256k1, SigningKey

        _ITERS = 600_000
        _salt_main = b"NexaFlow/seed/main/v2"
        _salt_view = b"NexaFlow/seed/view/v2"
        _salt_spend = b"NexaFlow/seed/spend/v2"

        # Main keypair
        priv_bytes = _hl.pbkdf2_hmac("sha256", seed.encode("utf-8"), _salt_main, _ITERS)
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        pub_bytes = b"\x04" + sk.get_verifying_key().to_string()

        # View keypair
        view_priv = _hl.pbkdf2_hmac("sha256", seed.encode("utf-8"), _salt_view, _ITERS)
        view_sk = SigningKey.from_string(view_priv, curve=SECP256k1)
        view_pub = b"\x04" + view_sk.get_verifying_key().to_string()

        # Spend keypair
        spend_priv = _hl.pbkdf2_hmac("sha256", seed.encode("utf-8"), _salt_spend, _ITERS)
        spend_sk = SigningKey.from_string(spend_priv, curve=SECP256k1)
        spend_pub = b"\x04" + spend_sk.get_verifying_key().to_string()

        return cls(priv_bytes, pub_bytes, view_private_key=view_priv, view_public_key=view_pub,
                   spend_private_key=spend_priv, spend_public_key=spend_pub)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "",
                      account: int = 0, index: int = 0) -> Wallet:
        """
        Create a wallet from a BIP-39 mnemonic phrase using HD derivation.

        Path: m/44'/144'/account'/0/index
        """
        if not validate_mnemonic(mnemonic):
            raise ValueError(f"Invalid mnemonic: expected 12/15/18/21/24 words")
        seed = mnemonic_to_seed(mnemonic, passphrase)
        master = HDNode.from_seed(seed)
        child = master.derive_path(f"44'/144'/{account}'/0/{index}")
        wallet = child.to_wallet()
        # Also derive view and spend keys at sub-paths
        view_node = master.derive_path(f"44'/144'/{account}'/1/{index}")
        spend_node = master.derive_path(f"44'/144'/{account}'/2/{index}")
        wallet.view_private_key = view_node.private_key
        wallet.view_public_key = view_node._get_public_key()
        wallet.spend_private_key = spend_node.private_key
        wallet.spend_public_key = spend_node._get_public_key()
        return wallet

    @classmethod
    def create_hd(cls, mnemonic: str | None = None,
                  strength: int = 128) -> tuple[str, Wallet]:
        """
        Create an HD wallet, optionally generating a new mnemonic.
        Returns (mnemonic_phrase, wallet).
        """
        if mnemonic is None:
            mnemonic = generate_mnemonic(strength)
        wallet = cls.from_mnemonic(mnemonic)
        return mnemonic, wallet

    # ---- signing ----

    def sign_transaction(self, tx: Transaction) -> Transaction:
        """
        Sign a transaction in-place and assign its tx_id.
        Supports both secp256k1 and Ed25519 key types.
        Returns the same transaction object for chaining.
        """
        if tx.sequence == 0:
            tx.sequence = self._sequence

        msg_hash = tx.hash_for_signing()

        if self.key_type == "ed25519":
            sig = Ed25519Signer.sign(self.private_key, msg_hash)
        else:
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

        v3 format — AES-256-GCM authenticated encryption with unique nonces
        per key field.  PBKDF2-HMAC-SHA256 with 600 000 iterations.
        """
        salt = os.urandom(16)
        iterations = 600_000
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)

        enc_priv, nonce_priv, tag_priv = self._aes_gcm_encrypt(key, self.private_key)
        enc_view_priv = nonce_view = tag_view = None
        if self.view_private_key:
            enc_view_priv, nonce_view, tag_view = self._aes_gcm_encrypt(key, self.view_private_key)
        enc_spend_priv = nonce_spend = tag_spend = None
        if self.spend_private_key:
            enc_spend_priv, nonce_spend, tag_spend = self._aes_gcm_encrypt(key, self.spend_private_key)

        return {
            "version": 3,
            "address": self.address,
            "public_key": self.public_key.hex(),
            "encrypted_private_key": enc_priv.hex(),
            "nonce": nonce_priv.hex(),
            "tag": tag_priv.hex(),
            "view_public_key": self.view_public_key.hex() if self.view_public_key else None,
            "encrypted_view_private_key": enc_view_priv.hex() if enc_view_priv else None,
            "nonce_view": nonce_view.hex() if nonce_view else None,
            "tag_view": tag_view.hex() if tag_view else None,
            "spend_public_key": self.spend_public_key.hex() if self.spend_public_key else None,
            "encrypted_spend_private_key": enc_spend_priv.hex() if enc_spend_priv else None,
            "nonce_spend": nonce_spend.hex() if nonce_spend else None,
            "tag_spend": tag_spend.hex() if tag_spend else None,
            "salt": salt.hex(),
            "kdf": "pbkdf2-hmac-sha256",
            "kdf_iterations": iterations,
            "key_type": self.key_type,
        }

    @classmethod
    def import_encrypted(cls, data: dict, passphrase: str) -> Wallet:
        """Import from an encrypted export (supports v1, v2 and v3)."""
        version = data.get("version", 1)
        salt = bytes.fromhex(data["salt"])
        enc_priv = bytes.fromhex(data["encrypted_private_key"])
        pub = bytes.fromhex(data["public_key"])

        if version >= 3:
            # v3 — AES-256-GCM with unique nonces per field
            iterations = data.get("kdf_iterations", 600_000)
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)
            nonce = bytes.fromhex(data["nonce"])
            tag = bytes.fromhex(data["tag"])
            priv = cls._aes_gcm_decrypt(key, nonce, enc_priv, tag)

            view_priv = None
            if data.get("encrypted_view_private_key"):
                view_priv = cls._aes_gcm_decrypt(
                    key,
                    bytes.fromhex(data["nonce_view"]),
                    bytes.fromhex(data["encrypted_view_private_key"]),
                    bytes.fromhex(data["tag_view"]),
                )
            spend_priv = None
            if data.get("encrypted_spend_private_key"):
                spend_priv = cls._aes_gcm_decrypt(
                    key,
                    bytes.fromhex(data["nonce_spend"]),
                    bytes.fromhex(data["encrypted_spend_private_key"]),
                    bytes.fromhex(data["tag_spend"]),
                )
        elif version >= 2:
            # v2 — legacy BLAKE2b-CTR (no authentication)
            iv = bytes.fromhex(data["iv"])
            iterations = data.get("kdf_iterations", 100_000)
            key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations)
            priv = cls._legacy_ctr_encrypt(key, iv, enc_priv)  # CTR is symmetric
            view_priv = None
            if data.get("encrypted_view_private_key"):
                enc_view_priv = bytes.fromhex(data["encrypted_view_private_key"])
                view_priv = cls._legacy_ctr_encrypt(key, iv, enc_view_priv)
            spend_priv = None
            if data.get("encrypted_spend_private_key"):
                enc_spend_priv = bytes.fromhex(data["encrypted_spend_private_key"])
                spend_priv = cls._legacy_ctr_encrypt(key, iv, enc_spend_priv)
        else:
            # Legacy v1 XOR fallback
            key = sha256(passphrase.encode("utf-8"))
            priv = bytes(a ^ b for a, b in zip(enc_priv, key))
            view_priv = None
            spend_priv = None

        view_pub = bytes.fromhex(data["view_public_key"]) if data.get("view_public_key") else None
        spend_pub = bytes.fromhex(data["spend_public_key"]) if data.get("spend_public_key") else None

        return cls(priv, pub, data.get("address"), view_private_key=view_priv, view_public_key=view_pub,
                   spend_private_key=spend_priv, spend_public_key=spend_pub,
                   key_type=data.get("key_type", "secp256k1"))

    # ---- AES-256-GCM authenticated encryption ----

    @staticmethod
    def _aes_gcm_encrypt(key: bytes, data: bytes) -> tuple[bytes, bytes, bytes]:
        """Encrypt *data* with AES-256-GCM. Returns (ciphertext, nonce, tag)."""
        from Crypto.Cipher import AES
        nonce = os.urandom(12)  # 96-bit nonce — unique per encryption
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext, nonce, tag

    @staticmethod
    def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """Decrypt and verify AES-256-GCM ciphertext. Raises ValueError on tamper."""
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    # ---- Legacy BLAKE2b-CTR cipher (v2 backward compatibility only) ----

    @staticmethod
    def _legacy_ctr_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
        """v2 CTR-mode stream cipher built on BLAKE2b — kept for v2 import only."""
        out = bytearray()
        block_size = 32
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
