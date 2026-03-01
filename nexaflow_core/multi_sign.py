"""
Multi-signing and regular key management for NexaFlow.

Provides:
  - Regular key assignment (sign with a secondary key)
  - M-of-N multi-signing with weighted signer lists
  - Signature verification that respects regular keys and signer lists

Mirrors the XRP Ledger's SetRegularKey and SignerListSet features.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SignerEntry:
    """A signer in a multi-sign signer list."""
    account: str    # signer's address
    weight: int     # signer's weight toward the quorum


@dataclass
class SignerList:
    """An M-of-N signer list for an account."""
    signer_quorum: int             # total weight required
    signers: list[SignerEntry] = field(default_factory=list)

    def total_weight(self) -> int:
        return sum(s.weight for s in self.signers)

    def validate_quorum(self, signing_accounts: set[str]) -> tuple[bool, int]:
        """
        Check if the set of signing accounts meets the quorum.
        Returns (met, achieved_weight).
        """
        achieved = sum(s.weight for s in self.signers if s.account in signing_accounts)
        return achieved >= self.signer_quorum, achieved

    def to_dict(self) -> dict:
        return {
            "signer_quorum": self.signer_quorum,
            "signers": [{"account": s.account, "weight": s.weight} for s in self.signers],
        }

    @classmethod
    def from_entries(cls, quorum: int, entries: list[dict]) -> SignerList:
        """Build from list of {"account": str, "weight": int} dicts."""
        signers = [SignerEntry(e["account"], e["weight"]) for e in entries]
        return cls(signer_quorum=quorum, signers=signers)


class MultiSignManager:
    """Tracks regular keys and signer lists for accounts."""

    def __init__(self):
        # address -> regular_key_address
        self.regular_keys: dict[str, str] = {}
        # address -> SignerList
        self.signer_lists: dict[str, SignerList] = {}

    def set_regular_key(self, account: str, regular_key: str) -> None:
        """Assign or update the regular key for an account."""
        if regular_key:
            self.regular_keys[account] = regular_key
        else:
            # Empty regular_key removes it
            self.regular_keys.pop(account, None)

    def get_regular_key(self, account: str) -> str | None:
        """Get the regular key for an account, or None."""
        return self.regular_keys.get(account)

    def set_signer_list(
        self, account: str, signer_quorum: int, signer_entries: list[dict],
    ) -> SignerList:
        """Set or update the signer list for an account."""
        if signer_quorum == 0 and not signer_entries:
            # Delete the signer list
            self.signer_lists.pop(account, None)
            return SignerList(0, [])
        signer_list = SignerList.from_entries(signer_quorum, signer_entries)
        if signer_list.total_weight() < signer_quorum:
            raise ValueError(
                f"Total signer weight ({signer_list.total_weight()}) "
                f"is less than quorum ({signer_quorum})"
            )
        # Ensure no duplicate signers
        addrs = [s.account for s in signer_list.signers]
        if len(addrs) != len(set(addrs)):
            raise ValueError("Duplicate signer accounts")
        # Signer cannot be the account itself
        if account in addrs:
            raise ValueError("Account cannot be in its own signer list")
        self.signer_lists[account] = signer_list
        return signer_list

    def get_signer_list(self, account: str) -> SignerList | None:
        return self.signer_lists.get(account)

    def is_authorized_signer(
        self, account: str, signer_address: str,
    ) -> bool:
        """Check if signer_address is authorised to sign for account."""
        # Master key is always authorised
        if signer_address == account:
            return True
        # Regular key
        if self.regular_keys.get(account) == signer_address:
            return True
        # Multi-sign member
        sl = self.signer_lists.get(account)
        if sl:
            return any(s.account == signer_address for s in sl.signers)
        return False

    def validate_multi_sig(
        self, account: str, signing_accounts: set[str],
    ) -> tuple[bool, str]:
        """Validate a multi-signed transaction."""
        sl = self.signer_lists.get(account)
        if sl is None:
            return False, "No signer list configured"
        met, achieved = sl.validate_quorum(signing_accounts)
        if not met:
            return False, f"Quorum not met: {achieved}/{sl.signer_quorum}"
        return True, "OK"
