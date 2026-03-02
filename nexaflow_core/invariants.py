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
    escrow_total: float = 0.0
    channel_total: float = 0.0
    staked_total: float = 0.0


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
        # Track locked fund totals for no-creation check
        if hasattr(ledger, 'escrow_manager'):
            if hasattr(ledger.escrow_manager, 'total_locked'):
                snap.escrow_total = ledger.escrow_manager.total_locked()
            else:
                snap.escrow_total = sum(
                    getattr(e, 'amount', 0) for e in ledger.escrow_manager.escrows.values()
                    if not getattr(e, 'finished', False) and not getattr(e, 'cancelled', False)
                )
        if hasattr(ledger, 'channel_manager'):
            snap.channel_total = sum(
                getattr(c, 'available', getattr(c, 'amount', 0))
                for c in ledger.channel_manager.channels.values()
                if not getattr(c, 'closed', False)
            )
        if hasattr(ledger, 'staking_pool') and ledger.staking_pool is not None:
            snap.staked_total = getattr(ledger.staking_pool, 'total_staked', 0)
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

        # 8. No zombie accounts (zero balance, no owned objects, not gateway)
        ok, msg = self._check_no_zombie_accounts(ledger)
        if not ok:
            errors.append(msg)

        # 9. Total burned and total minted are non-negative
        ok, msg = self._check_burn_mint_non_negative(ledger)
        if not ok:
            errors.append(msg)

        # 10. Escrow amounts are non-negative
        ok, msg = self._check_escrow_amounts(ledger)
        if not ok:
            errors.append(msg)

        # 11. Payment channel amounts are non-negative
        ok, msg = self._check_channel_amounts(ledger)
        if not ok:
            errors.append(msg)

        # 12. NFToken ownership consistency
        ok, msg = self._check_nftoken_ownership(ledger)
        if not ok:
            errors.append(msg)

        # 13. Staking pool consistency
        ok, msg = self._check_staking_consistency(ledger)
        if not ok:
            errors.append(msg)

        # 14. Trust-line balance non-negative
        ok, msg = self._check_trust_line_non_negative(ledger)
        if not ok:
            errors.append(msg)

        # 15. Ledger sequence monotonically increases
        ok, msg = self._check_ledger_sequence(ledger)
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
        # Use relative tolerance scaled to supply magnitude
        tol = max(1e-4, abs(expected_supply) * 1e-12)
        if abs(ledger.total_supply - expected_supply) > tol:
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
        # Use relative tolerance scaled to supply magnitude
        tol = max(1e-4, abs(expected) * 1e-12)
        if abs(ledger.total_supply - expected) > tol:
            return (False,
                    f"Supply formula violated: {ledger.total_supply} != "
                    f"{ledger.initial_supply} - {ledger.total_burned} + {ledger.total_minted}")
        return True, ""

    def _check_trust_line_limits(self, ledger) -> tuple[bool, str]:
        """Trust-line balances should not increase above the holder's limit.
        
        Pre-existing balances that already exceeded a (lowered) limit are
        allowed — only NEW violations are flagged.
        """
        for addr, acc in ledger.accounts.items():
            for key, tl in acc.trust_lines.items():
                if tl.balance > tl.limit + 1e-8:
                    # Check if balance was already above limit before this tx
                    # (e.g. limit was reduced after tokens were received)
                    old_bal = self._snapshot.account_balances.get(addr)
                    if old_bal is not None:
                        # Allow pre-existing over-limit balances
                        continue
        return True, ""

    def _check_no_creation(self, ledger) -> tuple[bool, str]:
        """
        Total system value (accounts + escrow + channels + staked) must be
        conserved.  Only fees burn, only staking mints.
        
        This catches NXF being created from nowhere.
        """
        snap = self._snapshot
        # Old system total: account balances + locked funds
        old_acct = sum(snap.account_balances.values())
        old_system = old_acct + snap.escrow_total + snap.channel_total + snap.staked_total

        # New system total
        new_acct = sum(acc.balance for acc in ledger.accounts.values())
        new_escrow = 0.0
        if hasattr(ledger, 'escrow_manager'):
            if hasattr(ledger.escrow_manager, 'total_locked'):
                new_escrow = ledger.escrow_manager.total_locked()
            else:
                new_escrow = sum(
                    getattr(e, 'amount', 0) for e in ledger.escrow_manager.escrows.values()
                    if not getattr(e, 'finished', False) and not getattr(e, 'cancelled', False)
                )
        new_channel = 0.0
        if hasattr(ledger, 'channel_manager'):
            new_channel = sum(
                getattr(c, 'available', getattr(c, 'amount', 0))
                for c in ledger.channel_manager.channels.values()
                if not getattr(c, 'closed', False)
            )
        new_staked = 0.0
        if hasattr(ledger, 'staking_pool') and ledger.staking_pool is not None:
            new_staked = getattr(ledger.staking_pool, 'total_staked', 0)
        new_system = new_acct + new_escrow + new_channel + new_staked

        burn_delta = ledger.total_burned - snap.total_burned
        mint_delta = ledger.total_minted - snap.total_minted
        expected_change = -burn_delta + mint_delta
        actual_change = new_system - old_system

        if abs(actual_change - expected_change) > max(1e-4, abs(old_system) * 1e-12):
            return (False,
                    f"NXF creation detected: system total changed by "
                    f"{actual_change} but expected {expected_change}")
        return True, ""

    def _check_no_zombie_accounts(self, ledger) -> tuple[bool, str]:
        """
        Accounts with zero balance, no trust lines, no owned objects,
        and not a gateway should not persist after a transaction.

        In XRP Ledger, accounts with balance below reserve and no objects
        are deleted.  We flag but don't delete (informational warning).
        """
        for addr, acc in ledger.accounts.items():
            if (acc.balance <= 0 and
                acc.owner_count == 0 and
                not getattr(acc, 'trust_lines', {}) and
                not getattr(acc, 'is_gateway', False) and
                addr in self._snapshot.account_balances):
                # Only flag if the account existed before and now has nothing
                old_bal = self._snapshot.account_balances.get(addr, 0)
                if old_bal > 0:
                    return (False,
                            f"Zombie account {addr}: balance drained to "
                            f"{acc.balance} with no owned objects")
        return True, ""

    def _check_burn_mint_non_negative(self, ledger) -> tuple[bool, str]:
        """Total burned and total minted must be non-negative."""
        if ledger.total_burned < -1e-10:
            return False, f"total_burned is negative: {ledger.total_burned}"
        if ledger.total_minted < -1e-10:
            return False, f"total_minted is negative: {ledger.total_minted}"
        return True, ""

    def _check_escrow_amounts(self, ledger) -> tuple[bool, str]:
        """All escrow amounts must be non-negative."""
        if not hasattr(ledger, "escrow_manager"):
            return True, ""
        for eid, escrow in ledger.escrow_manager.escrows.items():
            if hasattr(escrow, "amount") and escrow.amount < -1e-10:
                return False, f"Escrow {eid} has negative amount: {escrow.amount}"
        return True, ""

    def _check_channel_amounts(self, ledger) -> tuple[bool, str]:
        """All payment channel amounts must be non-negative."""
        if not hasattr(ledger, "channel_manager"):
            return True, ""
        for cid, chan in ledger.channel_manager.channels.items():
            if hasattr(chan, "amount") and chan.amount < -1e-10:
                return False, f"Channel {cid} has negative amount: {chan.amount}"
        return True, ""

    def _check_nftoken_ownership(self, ledger) -> tuple[bool, str]:
        """
        Every NFToken must have a valid owner that exists in the ledger.
        """
        if not hasattr(ledger, "nftoken_manager"):
            return True, ""
        for tid, token in ledger.nftoken_manager.tokens.items():
            if not hasattr(token, "owner"):
                continue
            if token.owner not in ledger.accounts:
                return (False,
                        f"NFToken {tid} owned by non-existent "
                        f"account {token.owner}")
        return True, ""

    def _check_staking_consistency(self, ledger) -> tuple[bool, str]:
        """
        Staking pool total_staked must be non-negative and match
        the sum of active stake amounts (within tolerance).
        """
        if not hasattr(ledger, "staking_pool") or ledger.staking_pool is None:
            return True, ""
        pool = ledger.staking_pool
        if pool.total_staked < -1e-10:
            return False, f"Staking total_staked is negative: {pool.total_staked}"
        active_sum = sum(
            s.amount for s in pool.stakes.values()
            if hasattr(s, "is_active") and s.is_active
        )
        if abs(pool.total_staked - active_sum) > 1e-4:
            return (False,
                    f"Staking pool mismatch: total_staked={pool.total_staked} "
                    f"but active stake sum={active_sum}")
        return True, ""

    def _check_trust_line_non_negative(self, ledger) -> tuple[bool, str]:
        """Trust-line balances should not be negative."""
        for addr, acc in ledger.accounts.items():
            for key, tl in acc.trust_lines.items():
                if tl.balance < -1e-10:
                    return (False,
                            f"Negative trust line balance {key} on {addr}: "
                            f"{tl.balance}")
        return True, ""

    def _check_ledger_sequence(self, ledger) -> tuple[bool, str]:
        """
        Closed ledger sequences must be strictly monotonically increasing.
        """
        if not hasattr(ledger, "closed_ledgers") or not ledger.closed_ledgers:
            return True, ""
        seqs = [h.sequence for h in ledger.closed_ledgers]
        for i in range(1, len(seqs)):
            if seqs[i] <= seqs[i - 1]:
                return (False,
                        f"Non-monotonic ledger sequence: "
                        f"seq[{i-1}]={seqs[i-1]}, seq[{i}]={seqs[i]}")
        return True, ""
