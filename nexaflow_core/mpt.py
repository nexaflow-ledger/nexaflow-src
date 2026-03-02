"""
Multi-Purpose Token (MPT) support for NexaFlow — XLS-33 equivalent.

MPT allows creating fungible token issuances independent of trust lines:
  - MPTokenIssuanceCreate: create a new MPT issuance
  - MPTokenIssuanceDestroy: destroy an issuance (if supply == 0)
  - MPTokenAuthorize: authorize a holder / opt-in to hold
  - MPTokenIssuanceSet: update issuance settings (lock, unlock)

Unlike trust lines, MPT balances are stored directly on the holder
and the issuance tracks global metadata.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field


# Issuance flags
MPT_CAN_LOCK = 0x0001
MPT_REQUIRE_AUTH = 0x0002
MPT_CAN_ESCROW = 0x0004
MPT_CAN_TRADE = 0x0008
MPT_CAN_TRANSFER = 0x0010
MPT_CAN_CLAWBACK = 0x0020

# Holder flags
MPT_AUTHORIZED = 0x0001
MPT_FROZEN = 0x0002


@dataclass
class MPTIssuance:
    """A multi-purpose token issuance."""
    issuance_id: str
    issuer: str
    max_supply: float = 0.0    # 0 = unlimited
    outstanding: float = 0.0
    transfer_fee: int = 0      # basis points
    metadata: str = ""
    flags: int = 0
    locked: bool = False
    sequence: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "issuance_id": self.issuance_id,
            "issuer": self.issuer,
            "max_supply": self.max_supply,
            "outstanding": self.outstanding,
            "transfer_fee": self.transfer_fee,
            "metadata": self.metadata,
            "flags": self.flags,
            "locked": self.locked,
        }


@dataclass
class MPTHolder:
    """A holder's balance for a specific MPT issuance."""
    account: str
    issuance_id: str
    balance: float = 0.0
    flags: int = 0  # MPT_AUTHORIZED, MPT_FROZEN, etc.
    locked_balance: float = 0.0

    @property
    def authorized(self) -> bool:
        return bool(self.flags & MPT_AUTHORIZED)

    @property
    def frozen(self) -> bool:
        return bool(self.flags & MPT_FROZEN)

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "issuance_id": self.issuance_id,
            "balance": self.balance,
            "flags": self.flags,
            "locked_balance": self.locked_balance,
            "authorized": self.authorized,
            "frozen": self.frozen,
        }


MAX_METADATA_LENGTH = 1024
MAX_TRANSFER_FEE = 5000  # 50%


class MPTManager:
    """Manages all multi-purpose token issuances and holdings."""

    def __init__(self):
        self.issuances: dict[str, MPTIssuance] = {}
        self._holders: dict[str, dict[str, MPTHolder]] = {}  # issuance_id -> {account: holder}
        self._issuer_index: dict[str, list[str]] = {}  # issuer -> [issuance_id]
        self._seq: dict[str, int] = {}

    def _make_id(self, issuer: str, seq: int) -> str:
        raw = f"MPT:{issuer}:{seq}"
        return hashlib.sha256(raw.encode()).hexdigest()[:40]

    def create_issuance(self, issuer: str,
                        max_supply: float = 0.0,
                        transfer_fee: int = 0,
                        metadata: str = "",
                        flags: int = 0) -> tuple[bool, str, MPTIssuance | None]:
        """Create a new MPT issuance."""
        if transfer_fee < 0 or transfer_fee > MAX_TRANSFER_FEE:
            return False, f"Transfer fee must be 0-{MAX_TRANSFER_FEE}", None
        if metadata and len(metadata) > MAX_METADATA_LENGTH:
            return False, f"Metadata exceeds {MAX_METADATA_LENGTH} chars", None

        seq = self._seq.get(issuer, 0)
        iid = self._make_id(issuer, seq)
        self._seq[issuer] = seq + 1

        issuance = MPTIssuance(
            issuance_id=iid,
            issuer=issuer,
            max_supply=max_supply,
            transfer_fee=transfer_fee,
            metadata=metadata,
            flags=flags,
            sequence=seq,
        )
        self.issuances[iid] = issuance
        self._issuer_index.setdefault(issuer, []).append(iid)
        return True, "Issuance created", issuance

    def destroy_issuance(self, issuer: str,
                         issuance_id: str) -> tuple[bool, str]:
        """Destroy an issuance if outstanding supply is zero."""
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"
        if iss.issuer != issuer:
            return False, "Not the issuer"
        if iss.outstanding > 0:
            return False, "Outstanding supply must be zero"
        del self.issuances[issuance_id]
        self._holders.pop(issuance_id, None)
        idx = self._issuer_index.get(issuer, [])
        if issuance_id in idx:
            idx.remove(issuance_id)
        return True, "Issuance destroyed"

    def authorize(self, issuance_id: str, account: str,
                  issuer_action: bool = False,
                  issuer: str = "") -> tuple[bool, str]:
        """
        Authorize a holder for an MPT issuance.
        If issuer_action=True, the issuer grants authorization.
        Otherwise, the account opts in.
        """
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"

        holders = self._holders.setdefault(issuance_id, {})

        if issuer_action:
            if issuer != iss.issuer:
                return False, "Not the issuer"
            holder = holders.get(account)
            if holder is None:
                holder = MPTHolder(account=account, issuance_id=issuance_id)
                holders[account] = holder
            holder.flags |= MPT_AUTHORIZED
            return True, "Holder authorized"

        # Account self-opt-in
        if account in holders:
            return True, "Already opted in"
        holder = MPTHolder(account=account, issuance_id=issuance_id)
        if not (iss.flags & MPT_REQUIRE_AUTH):
            holder.flags |= MPT_AUTHORIZED
        holders[account] = holder
        return True, "Opted in"

    def set_issuance(self, issuer: str, issuance_id: str,
                     lock: bool | None = None) -> tuple[bool, str]:
        """Update issuance settings (lock/unlock)."""
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"
        if iss.issuer != issuer:
            return False, "Not the issuer"
        if not (iss.flags & MPT_CAN_LOCK):
            return False, "Issuance does not allow locking"
        if lock is not None:
            iss.locked = lock
        return True, "Issuance updated"

    def mint(self, issuer: str, issuance_id: str,
             holder: str, amount: float) -> tuple[bool, str]:
        """Mint tokens to a holder."""
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"
        if iss.issuer != issuer:
            return False, "Not the issuer"
        if iss.locked:
            return False, "Issuance is locked"
        if amount <= 0:
            return False, "Amount must be positive"
        if iss.max_supply > 0 and iss.outstanding + amount > iss.max_supply:
            return False, "Would exceed max supply"

        holders = self._holders.setdefault(issuance_id, {})
        h = holders.get(holder)
        if h is None:
            return False, "Holder not opted in"
        if (iss.flags & MPT_REQUIRE_AUTH) and not h.authorized:
            return False, "Holder not authorized"

        h.balance += amount
        iss.outstanding += amount
        return True, "Minted"

    def transfer(self, issuance_id: str, sender: str,
                 recipient: str, amount: float) -> tuple[bool, str, float]:
        """
        Transfer tokens between holders.  Returns (ok, msg, fee_charged).
        """
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found", 0.0
        if not (iss.flags & MPT_CAN_TRANSFER):
            return False, "Transfers not allowed", 0.0
        if iss.locked:
            return False, "Issuance is locked", 0.0
        if amount <= 0:
            return False, "Amount must be positive", 0.0

        holders = self._holders.setdefault(issuance_id, {})
        s = holders.get(sender)
        r = holders.get(recipient)
        if s is None:
            return False, "Sender not opted in", 0.0
        if r is None:
            return False, "Recipient not opted in", 0.0
        if s.frozen:
            return False, "Sender is frozen", 0.0
        if r.frozen:
            return False, "Recipient is frozen", 0.0
        if s.balance < amount:
            return False, "Insufficient balance", 0.0
        if (iss.flags & MPT_REQUIRE_AUTH) and not r.authorized:
            return False, "Recipient not authorized", 0.0

        # Transfer fee
        fee = 0.0
        if iss.transfer_fee > 0 and sender != iss.issuer and recipient != iss.issuer:
            fee = amount * iss.transfer_fee / 10000.0

        s.balance -= amount
        r.balance += (amount - fee)
        # Fee goes to issuer
        if fee > 0:
            issuer_h = holders.get(iss.issuer)
            if issuer_h:
                issuer_h.balance += fee
        return True, "Transferred", fee

    def burn(self, issuance_id: str, account: str,
             amount: float) -> tuple[bool, str]:
        """Burn (redeem) tokens from a holder."""
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"
        if amount <= 0:
            return False, "Amount must be positive"

        holders = self._holders.setdefault(issuance_id, {})
        h = holders.get(account)
        if h is None:
            return False, "Holder not found"
        if h.balance < amount:
            return False, "Insufficient balance"

        h.balance -= amount
        iss.outstanding -= amount
        return True, "Burned"

    def clawback(self, issuer: str, issuance_id: str,
                 holder: str, amount: float) -> tuple[bool, str]:
        """Issuer claws back tokens from a holder."""
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"
        if iss.issuer != issuer:
            return False, "Not the issuer"
        if not (iss.flags & MPT_CAN_CLAWBACK):
            return False, "Clawback not enabled"

        holders = self._holders.get(issuance_id, {})
        h = holders.get(holder)
        if h is None:
            return False, "Holder not found"
        actual = min(amount, h.balance)
        h.balance -= actual
        iss.outstanding -= actual
        return True, f"Clawed back {actual}"

    def freeze_holder(self, issuer: str, issuance_id: str,
                      holder: str) -> tuple[bool, str]:
        """Freeze a specific holder."""
        iss = self.issuances.get(issuance_id)
        if iss is None:
            return False, "Issuance not found"
        if iss.issuer != issuer:
            return False, "Not the issuer"
        holders = self._holders.get(issuance_id, {})
        h = holders.get(holder)
        if h is None:
            return False, "Holder not found"
        h.flags |= MPT_FROZEN
        return True, "Holder frozen"

    def get_issuance(self, issuance_id: str) -> MPTIssuance | None:
        return self.issuances.get(issuance_id)

    def get_holder(self, issuance_id: str, account: str) -> MPTHolder | None:
        return self._holders.get(issuance_id, {}).get(account)

    def get_holders(self, issuance_id: str) -> list[dict]:
        return [h.to_dict() for h in self._holders.get(issuance_id, {}).values()]

    def get_issuances_by_issuer(self, issuer: str) -> list[dict]:
        ids = self._issuer_index.get(issuer, [])
        return [self.issuances[i].to_dict() for i in ids if i in self.issuances]

    def get_account_mpt_balances(self, account: str) -> list[dict]:
        result = []
        for iid, holders in self._holders.items():
            h = holders.get(account)
            if h and h.balance > 0:
                result.append(h.to_dict())
        return result
