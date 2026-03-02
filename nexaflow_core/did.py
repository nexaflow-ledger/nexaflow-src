"""
Decentralized Identifier (DID) support for NexaFlow — XLS-40 equivalent.

On-ledger DID documents linked to NexaFlow accounts:
  - DIDSet: create or update a DID document
  - DIDDelete: remove a DID document

Each account can have at most one DID.  The DID document can include
a URI, arbitrary data payload, and optional attestations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class DIDDocument:
    """An on-ledger DID document."""
    account: str                   # owning account
    did_id: str = ""               # derived from account: "did:nxf:<address>"
    uri: str = ""                  # URI pointing to off-chain document
    data: str = ""                 # hex-encoded on-chain data (max 256 bytes)
    attestations: list[dict] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "did_id": self.did_id,
            "account": self.account,
            "uri": self.uri,
            "data": self.data,
            "attestations": self.attestations,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


MAX_DATA_LENGTH = 512  # hex chars = 256 bytes
MAX_URI_LENGTH = 256
MAX_ATTESTATIONS = 10


class DIDManager:
    """Manages all on-ledger DID documents."""

    def __init__(self):
        self.dids: dict[str, DIDDocument] = {}  # account -> DIDDocument

    def set_did(self, account: str,
                uri: str = "",
                data: str = "",
                attestations: list[dict] | None = None) -> tuple[bool, str, DIDDocument | None]:
        """Create or update a DID document.  Returns (ok, msg, did)."""
        if uri and len(uri) > MAX_URI_LENGTH:
            return False, f"URI exceeds {MAX_URI_LENGTH} characters", None
        if data and len(data) > MAX_DATA_LENGTH:
            return False, f"Data exceeds {MAX_DATA_LENGTH} hex characters", None
        if attestations and len(attestations) > MAX_ATTESTATIONS:
            return False, f"Max {MAX_ATTESTATIONS} attestations", None

        existing = self.dids.get(account)
        if existing:
            # Update
            if uri:
                existing.uri = uri
            if data:
                existing.data = data
            if attestations is not None:
                existing.attestations = attestations
            existing.updated_at = time.time()
            return True, "DID updated", existing

        # Create new
        did_id = f"did:nxf:{account}"
        doc = DIDDocument(
            account=account,
            did_id=did_id,
            uri=uri,
            data=data,
            attestations=attestations or [],
        )
        self.dids[account] = doc
        return True, "DID created", doc

    def delete_did(self, account: str) -> tuple[bool, str]:
        """Delete a DID document."""
        if account not in self.dids:
            return False, "No DID found for account"
        del self.dids[account]
        return True, "DID deleted"

    def get_did(self, account: str) -> DIDDocument | None:
        return self.dids.get(account)

    def resolve(self, did_id: str) -> DIDDocument | None:
        """Resolve a did:nxf: URI to a document."""
        if did_id.startswith("did:nxf:"):
            account = did_id[8:]
            return self.dids.get(account)
        return None

    def get_all_dids(self) -> list[dict]:
        return [d.to_dict() for d in self.dids.values()]
