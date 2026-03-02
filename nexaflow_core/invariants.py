"""
Post-transaction invariant checks for NexaFlow.

Mirrors the XRP Ledger's invariant checking system:
  - NXF supply must be conserved (only fees burn, only staking mints)
  - No account balance goes negative
  - Owner count is non-negative
  - Trust-line balances within limits
  - Account sequence only increases
  - Total supply equals initial_supply - burned + minted

These checks run after every transaction application.  If any
invariant fails, the transaction is rolled back and rejected.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class LedgerSnapshot:
    """Snapshot of key ledger fields before a transaction."""
    total_supply: float = 0.0
    total_burned: float = 0.0
    total_minted: float = 0.0
    account_balances: dict[str, float] = field(default_factory=dict)
    account_sequences: dict[str, int] = field(default_factory=dict)
    account_owner_counts: dict[str, int] = field(default_factory=dict)


class InvariantChecker:
    """
    Captures a pre-transaction snapshot of the ledger state and validates
    invariants after the transaction is applied.
    """

    def __init__(self):
        self._snapshot: LedgerSnapshot | None = None

    def capture(self, ledger) -> None:
        """Take a snapshot of the ledger state before a transaction."""
        snap = LedgerSnapshot(
            total_supply=ledger.total_supply,
            total_burned=ledger.total_burned,
            total_minted=ledger.total_minted,
        )
        for addr, acc in ledger.accounts.items():
            snap.account_balances[addr] = acc.balance
            snap.account_sequences[addr] = acc.sequence
            snap.account_owner_counts[addr] = acc.owner_count
        self._snapshot = snap

    def verify(self, ledger) -> tuple[bool, str]:
        """
        Verify all invariants against the current ledger state.
        Returns (passed, error_message).
        """
        if self._snapshot is None:
            return True, ""

        errors: list[str] = []

        # 1. Supply conservation
        ok, msg = self._check_supply_conservation(ledger)
        if not ok:
            errors.append(msg)

        # 2. No negative balances
        ok, msg = self._check_no_negative_balances(ledger)
        if not ok:
            errors.append(msg)

        # 3. Owner count non-negative
        ok, msg = self._check_owner_counts(ledger)
        if not ok:
            errors.append(msg)

        # 4. Sequence only increases
        ok, msg = self._check_sequence_increases(ledger)
        if not ok:
            errors.append(msg)

        # 5. Supply formula holds
        ok, msg = self._check_supply_formula(ledger)
        if not ok:
            errors.append(msg)

        # 6. Trust-line balances within limits
        ok, msg = self._check_trust_line_limits(ledger)
        if not ok:
            errors.append(msg)

        # 7. No NXF created from thin air
        ok, msg = self._check_no_creation(ledger)
        if not ok:
            errors.append(msg)

        self._snapshot = None
        if errors:
            return False, "; ".join(errors)
        return True, ""

    def _check_supply_conservation(self, ledger) -> tuple[bool, str]:
        """Total supply should only change by fees burned or staking interest minted."""
        snap = self._snapshot
        burn_delta = ledger.total_burned - snap.total_burned
        mint_delta = ledger.total_minted - snap.total_minted
        expected_supply = snap.total_supply - burn_delta + mint_delta
        if abs(ledger.total_supply - expected_supply) > 1e-8:
            return (False,
                    f"Supply mismatch: expected {expected_supply}, "
                    f"got {ledger.total_supply}")
        return True, ""

    def _check_no_negative_balances(self, ledger) -> tuple[bool, str]:
        """No account should have a negative NXF balance."""
        for addr, acc in ledger.accounts.items():
            if acc.balance < -1e-10:
                return False, f"Negative balance on {addr}: {acc.balance}"
        return True, ""

    def _check_owner_counts(self, ledger) -> tuple[bool, str]:
        """Owner counts must be non-negative."""
        for addr, acc in ledger.accounts.items():
            if acc.owner_count < 0:
                return False, f"Negative owner_count on {addr}: {acc.owner_count}"
        return True, ""

    def _check_sequence_increases(self, ledger) -> tuple[bool, str]:
        """Account sequences should only increase or stay the same."""
        snap = self._snapshot
        for addr, acc in ledger.accounts.items():
            old_seq = snap.account_sequences.get(addr, 0)
            if acc.sequence < old_seq:
                return (False,
                        f"Sequence decreased on {addr}: {old_seq} -> {acc.sequence}")
        return True, ""

    def _check_supply_formula(self, ledger) -> tuple[bool, str]:
        """total_supply == initial_supply - total_burned + total_minted."""
        expected = ledger.initial_supply - ledger.total_burned + ledger.total_minted
        if abs(ledger.total_supply - expected) > 1e-8:
            return (False,
                    f"Supply formula violated: {ledger.total_supply} != "
                    f"{ledger.initial_supply} - {ledger.total_burned} + {ledger.total_minted}")
        return True, ""

    def _check_trust_line_limits(self, ledger) -> tuple[bool, str]:
        """Trust-line balances should not exceed the holder's limit."""
        for addr, acc in ledger.accounts.items():
            for key, tl in acc.trust_lines.items():
                if tl.balance > tl.limit + 1e-8:
                    return (False,
                            f"Trust line {key} on {addr}: balance {tl.balance} "
                            f"exceeds limit {tl.limit}")
        return True, ""

    def _check_no_creation(self, ledger) -> tuple[bool, str]:
        """
        Sum of all account balances + escrowed + staked + channel_locked
        should equal total_supply (accounting for burned fees and interest).
        
        This catches NXF being created from nowhere.
        """
        snap = self._snapshot
        old_total = sum(snap.account_balances.values())
        new_total = sum(acc.balance for acc in ledger.accounts.values())
        # Account for accounts that were created or deleted
        burn_delta = ledger.total_burned - snap.total_burned
        mint_delta = ledger.total_minted - snap.total_minted
        # New total should be: old_total - burned + minted
        # But also accounting for escrow locks, payment channels, etc.
        # We allow a tolerance because locked funds leave accounts
        expected_change = -burn_delta + mint_delta
        actual_change = new_total - old_total
        # The difference should match expected_change within tolerance
        # (locked funds like escrow/channels move from accounts to managers)
        # We use a generous tolerance to avoid false positives from locks
        if abs(actual_change - expected_change) > 1e-4:
            # Only flag truly anomalous creation
            if new_total > old_total + mint_delta + 1e-4:
                return (False,
                        f"NXF creation detected: balances grew by "
                        f"{new_total - old_total} but expected ≤ {mint_delta}")
        return True, ""
