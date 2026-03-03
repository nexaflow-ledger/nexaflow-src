"""
Validator manifest and UNL publication protocol for NexaFlow.

Mirrors the XRP Ledger's validator manifest system:
  - Validators publish signed manifests binding master → ephemeral keys
  - UNL publishers maintain and sign lists of trusted validators
  - Key rotation: new ephemeral key can be bound without changing identity

Components:
  - ValidatorManifest: signed attestation of key binding
  - ManifestCache: stores and validates received manifests
  - UNLPublisher: manages and publishes trusted validator lists
  - UNLSubscriber: fetches and verifies UNL from publisher sites
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ValidatorManifest:
    """
    Signed attestation binding a master key to an ephemeral signing key.

    Fields mirror rippled's validator manifest:
      - master_public_key: permanent validator identity key
      - ephemeral_public_key: short-lived signing key
      - sequence: monotonically increasing (revokes previous manifests)
      - domain: optional human-readable domain for the validator
      - master_signature: signature over manifest body by master key
      - ephemeral_signature: optional signature by ephemeral key
      - expiration: when this manifest expires (0 = no expiration)
    """
    master_public_key: str
    ephemeral_public_key: str
    sequence: int
    domain: str = ""
    master_signature: str = ""
    ephemeral_signature: str = ""
    expiration: float = 0.0
    created_at: float = field(default_factory=time.time)
    revoked: bool = False

    @property
    def manifest_id(self) -> str:
        """Unique ID derived from master key."""
        return hashlib.sha256(self.master_public_key.encode()).hexdigest()[:40]

    def signing_blob(self) -> bytes:
        """Produce the deterministic blob that gets signed."""
        parts = [
            self.master_public_key,
            self.ephemeral_public_key,
            str(self.sequence),
            self.domain,
        ]
        return "|".join(parts).encode("utf-8")

    def is_expired(self, now: float | None = None) -> bool:
        if self.expiration <= 0:
            return False
        if now is None:
            now = time.time()
        return now >= self.expiration

    def to_dict(self) -> dict:
        return {
            "master_public_key": self.master_public_key,
            "ephemeral_public_key": self.ephemeral_public_key,
            "sequence": self.sequence,
            "domain": self.domain,
            "master_signature": self.master_signature,
            "manifest_id": self.manifest_id,
            "expiration": self.expiration,
            "revoked": self.revoked,
        }


class ManifestCache:
    """
    Stores and validates validator manifests.

    Tracks the highest-sequence manifest per master key; lower-sequence
    manifests are automatically revoked.
    """

    def __init__(self):
        self._manifests: dict[str, ValidatorManifest] = {}  # master_key -> latest
        self._history: dict[str, list[ValidatorManifest]] = {}  # all versions

    def apply(self, manifest: ValidatorManifest) -> tuple[bool, str]:
        """
        Apply a manifest.  Returns (accepted, reason).
        Rejects if sequence is lower than the current manifest.
        Verifies master and ephemeral signatures before accepting.
        """
        # Verify master signature is present and valid
        if not manifest.master_signature:
            return False, "Missing master signature"
        blob = manifest.signing_blob()
        if not self._verify_manifest_signature(
            blob, manifest.master_signature, manifest.master_public_key
        ):
            return False, "Invalid master signature"

        # Verify ephemeral signature if present
        if manifest.ephemeral_signature:
            if not self._verify_manifest_signature(
                blob, manifest.ephemeral_signature, manifest.ephemeral_public_key
            ):
                return False, "Invalid ephemeral signature"

        key = manifest.master_public_key
        existing = self._manifests.get(key)
        if existing is not None:
            if manifest.sequence <= existing.sequence:
                return False, "Sequence too low"
            existing.revoked = True

        self._manifests[key] = manifest
        self._history.setdefault(key, []).append(manifest)
        return True, "OK"

    @staticmethod
    def _verify_manifest_signature(blob: bytes, sig_hex: str, pubkey_hex: str) -> bool:
        """Verify a hex-encoded signature against a hex-encoded public key."""
        try:
            sig_bytes = bytes.fromhex(sig_hex)
            pub_bytes = bytes.fromhex(pubkey_hex)
        except (ValueError, TypeError):
            return False
        # Ed25519 (32-byte pubkey, 64-byte sig)
        if len(pub_bytes) == 32 and len(sig_bytes) == 64:
            try:
                from nacl.signing import VerifyKey
                vk = VerifyKey(pub_bytes)
                vk.verify(blob, sig_bytes)
                return True
            except Exception:
                return False
        # secp256k1 / ECDSA (33 or 65-byte pubkey)
        if len(pub_bytes) in (33, 65):
            try:
                from ecdsa import VerifyingKey, SECP256k1
                msg_hash = hashlib.sha256(blob).digest()
                vk = VerifyingKey.from_string(
                    pub_bytes if len(pub_bytes) == 64 else pub_bytes[1:] if len(pub_bytes) == 65 else pub_bytes,
                    curve=SECP256k1,
                )
                vk.verify_digest(sig_bytes, msg_hash)
                return True
            except Exception:
                return False
        return False

    def get(self, master_key: str) -> ValidatorManifest | None:
        return self._manifests.get(master_key)

    def get_ephemeral_key(self, master_key: str) -> str:
        """Resolve the current ephemeral key for a master key."""
        m = self._manifests.get(master_key)
        if m is None or m.revoked:
            return ""
        return m.ephemeral_public_key

    def get_master_key(self, ephemeral_key: str) -> str:
        """Reverse-lookup: find the master key for an ephemeral key."""
        for m in self._manifests.values():
            if m.ephemeral_public_key == ephemeral_key and not m.revoked:
                return m.master_public_key
        return ""

    def all_active(self) -> list[ValidatorManifest]:
        now = time.time()
        return [m for m in self._manifests.values()
                if not m.revoked and not m.is_expired(now)]

    def to_list(self) -> list[dict]:
        return [m.to_dict() for m in self._manifests.values()]

    @property
    def count(self) -> int:
        return len(self._manifests)


@dataclass
class UNLEntry:
    """A single entry in a Unique Node List."""
    validator_public_key: str
    manifest_hash: str = ""
    last_seen: float = 0.0


@dataclass
class ValidatorList:
    """
    A signed list of trusted validators (UNL).

    Publishers periodically issue signed lists with a sequence number
    and expiration.  Subscribers verify the publisher's signature and
    apply the list.
    """
    publisher_key: str
    sequence: int
    expiration: float
    validators: list[UNLEntry] = field(default_factory=list)
    signature: str = ""
    blob_hash: str = ""

    def signing_blob(self) -> bytes:
        parts = [
            self.publisher_key,
            str(self.sequence),
            str(int(self.expiration)),
        ]
        for v in sorted(self.validators, key=lambda x: x.validator_public_key):
            parts.append(v.validator_public_key)
        return "|".join(parts).encode("utf-8")

    def is_expired(self, now: float | None = None) -> bool:
        if now is None:
            now = time.time()
        return now >= self.expiration

    def to_dict(self) -> dict:
        return {
            "publisher_key": self.publisher_key,
            "sequence": self.sequence,
            "expiration": self.expiration,
            "validators": [
                {"validation_public_key": v.validator_public_key,
                 "manifest_hash": v.manifest_hash}
                for v in self.validators
            ],
            "signature": self.signature,
        }


class UNLPublisher:
    """
    Manages trusted validator lists for publication.

    An operator runs a UNL publisher that curates a list of known-good
    validators and signs the list for distribution.
    """

    def __init__(self, publisher_key: str):
        self.publisher_key = publisher_key
        self._current_list: ValidatorList | None = None
        self._sequence: int = 0

    def publish(self, validator_keys: list[str],
                expiration_hours: float = 168.0,
                signature: str = "") -> ValidatorList:
        """Create a new signed UNL."""
        self._sequence += 1
        entries = [UNLEntry(validator_public_key=k) for k in validator_keys]
        vl = ValidatorList(
            publisher_key=self.publisher_key,
            sequence=self._sequence,
            expiration=time.time() + expiration_hours * 3600,
            validators=entries,
            signature=signature,
        )
        blob = vl.signing_blob()
        vl.blob_hash = hashlib.sha256(blob).hexdigest()
        self._current_list = vl
        return vl

    @property
    def current_list(self) -> ValidatorList | None:
        return self._current_list


class UNLSubscriber:
    """
    Subscribes to UNL publisher sites and maintains the trusted validator set.

    In production this would fetch HTTPS endpoints; here it accepts
    ValidatorList objects directly for local / testing use.
    """

    def __init__(self):
        self._publisher_keys: set[str] = set()
        self._trusted_keys: set[str] = set()
        self._lists: dict[str, ValidatorList] = {}  # publisher_key -> latest

    def add_publisher(self, publisher_key: str) -> None:
        self._publisher_keys.add(publisher_key)

    def remove_publisher(self, publisher_key: str) -> None:
        self._publisher_keys.discard(publisher_key)
        self._lists.pop(publisher_key, None)
        self._recompute_trusted()

    def apply_list(self, vl: ValidatorList) -> tuple[bool, str]:
        """Apply a validator list from a trusted publisher.

        Verifies the publisher's signature before accepting the list.
        """
        if vl.publisher_key not in self._publisher_keys:
            return False, "Unknown publisher"
        # Verify publisher signature
        if not vl.signature:
            return False, "Missing publisher signature"
        blob = vl.signing_blob()
        expected_hash = hashlib.sha256(blob).hexdigest()
        if vl.blob_hash and vl.blob_hash != expected_hash:
            return False, "Blob hash mismatch"
        if not ManifestCache._verify_manifest_signature(
            blob, vl.signature, vl.publisher_key
        ):
            return False, "Invalid publisher signature"
        existing = self._lists.get(vl.publisher_key)
        if existing is not None and vl.sequence <= existing.sequence:
            return False, "Sequence too low"
        if vl.is_expired():
            return False, "List is expired"
        self._lists[vl.publisher_key] = vl
        self._recompute_trusted()
        return True, "OK"

    def _recompute_trusted(self) -> None:
        keys: set[str] = set()
        for vl in self._lists.values():
            if not vl.is_expired():
                for v in vl.validators:
                    keys.add(v.validator_public_key)
        self._trusted_keys = keys

    @property
    def trusted_validators(self) -> set[str]:
        return self._trusted_keys.copy()

    @property
    def publisher_count(self) -> int:
        return len(self._publisher_keys)

    def to_dict(self) -> dict:
        return {
            "publishers": list(self._publisher_keys),
            "trusted_count": len(self._trusted_keys),
            "lists": {pk: vl.to_dict() for pk, vl in self._lists.items()},
        }
