"""
On-ledger Credentials for NexaFlow.

Verifiable credentials stored on the ledger:
  - CredentialCreate: issuer creates a credential for a subject
  - CredentialAccept: subject accepts the credential
  - CredentialDelete: issuer or subject deletes the credential

Credentials can be used with Deposit Authorization and other features
to allow permissioned access.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


@dataclass
class Credential:
    """An on-ledger credential."""
    credential_id: str
    issuer: str
    subject: str
    credential_type: str    # arbitrary type string
    uri: str = ""           # optional link to off-chain data
    expiration: float = 0.0 # 0 = no expiration
    accepted: bool = False
    created_at: float = field(default_factory=time.time)
    accepted_at: float = 0.0

    @property
    def is_valid(self) -> bool:
        if not self.accepted:
            return False
        if self.expiration > 0 and time.time() > self.expiration:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "credential_id": self.credential_id,
            "issuer": self.issuer,
            "subject": self.subject,
            "credential_type": self.credential_type,
            "uri": self.uri,
            "expiration": self.expiration,
            "accepted": self.accepted,
            "is_valid": self.is_valid,
            "created_at": self.created_at,
            "accepted_at": self.accepted_at,
        }


MAX_TYPE_LENGTH = 64
MAX_URI_LENGTH = 256


class CredentialManager:
    """Manages all on-ledger credentials."""

    def __init__(self):
        self.credentials: dict[str, Credential] = {}
        self._issuer_index: dict[str, list[str]] = {}
        self._subject_index: dict[str, list[str]] = {}

    @staticmethod
    def _make_id(issuer: str, subject: str, credential_type: str) -> str:
        raw = f"CRED:{issuer}:{subject}:{credential_type}"
        return hashlib.sha256(raw.encode()).hexdigest()[:40]

    def create(self, issuer: str, subject: str,
               credential_type: str,
               uri: str = "",
               expiration: float = 0.0) -> tuple[bool, str, Credential | None]:
        """Create a credential.  Returns (ok, msg, credential)."""
        if not credential_type or len(credential_type) > MAX_TYPE_LENGTH:
            return False, f"Credential type required, max {MAX_TYPE_LENGTH} chars", None
        if uri and len(uri) > MAX_URI_LENGTH:
            return False, f"URI max {MAX_URI_LENGTH} chars", None
        if issuer == subject:
            return False, "Issuer and subject must differ", None
        if expiration > 0 and expiration < time.time():
            return False, "Expiration must be in the future", None

        cid = self._make_id(issuer, subject, credential_type)
        if cid in self.credentials:
            return False, "Credential already exists", None

        cred = Credential(
            credential_id=cid,
            issuer=issuer,
            subject=subject,
            credential_type=credential_type,
            uri=uri,
            expiration=expiration,
        )
        self.credentials[cid] = cred
        self._issuer_index.setdefault(issuer, []).append(cid)
        self._subject_index.setdefault(subject, []).append(cid)
        return True, "Credential created", cred

    def accept(self, subject: str,
               credential_id: str) -> tuple[bool, str]:
        """Subject accepts a credential."""
        cred = self.credentials.get(credential_id)
        if cred is None:
            return False, "Credential not found"
        if cred.subject != subject:
            return False, "Not the subject"
        if cred.accepted:
            return True, "Already accepted"
        cred.accepted = True
        cred.accepted_at = time.time()
        return True, "Credential accepted"

    def delete(self, account: str,
               credential_id: str) -> tuple[bool, str]:
        """Delete a credential (issuer or subject can delete)."""
        cred = self.credentials.get(credential_id)
        if cred is None:
            return False, "Credential not found"
        if account != cred.issuer and account != cred.subject:
            return False, "Not authorized to delete"
        del self.credentials[credential_id]
        idx = self._issuer_index.get(cred.issuer, [])
        if credential_id in idx:
            idx.remove(credential_id)
        idx = self._subject_index.get(cred.subject, [])
        if credential_id in idx:
            idx.remove(credential_id)
        return True, "Credential deleted"

    def get_credential(self, credential_id: str) -> Credential | None:
        return self.credentials.get(credential_id)

    def get_by_issuer(self, issuer: str) -> list[Credential]:
        cids = self._issuer_index.get(issuer, [])
        return [self.credentials[c] for c in cids if c in self.credentials]

    def get_by_subject(self, subject: str) -> list[Credential]:
        cids = self._subject_index.get(subject, [])
        return [self.credentials[c] for c in cids if c in self.credentials]

    def check_credential(self, issuer: str, subject: str,
                         credential_type: str) -> bool:
        """Check if a valid credential exists."""
        cid = self._make_id(issuer, subject, credential_type)
        cred = self.credentials.get(cid)
        if cred is None:
            return False
        return cred.is_valid

    def get_all_credentials(self) -> list[dict]:
        return [c.to_dict() for c in self.credentials.values()]
