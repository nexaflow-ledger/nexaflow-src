"""
Economic integrity tests for NexaFlow tokenomics.

Validates the core invariant: **all circulating NXF must originate from
the genesis account distribution or from staking-interest minting**.

Covers:
  - Accounts start with zero balance (no free money)
  - Payments from unfunded accounts are rejected
  - Users cannot spend more than they have
  - Only the genesis account can bootstrap funds into the economy
  - Staking interest is the only mechanism that increases total supply
  - create_account with nonzero initial_nxf cannot mint money out of thin air
  - Supply conservation: total_supply == initial_supply - burned + minted
  - Double-funding prevention
"""

import time
import unittest

from nexaflow_core.ledger import Ledger
from nexaflow_core.staking import StakeTier
from nexaflow_core.transaction import (
    create_payment,
    create_stake,
)


# ═══════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════

def _pay(src, dst, amount, fee=0.00001, seq=0, tx_id=None):
    tx = create_payment(src, dst, amount, fee=fee, sequence=seq)
    if tx_id:
        tx.tx_id = tx_id
    return tx


def _stake(account, amount, tier, tx_id="stk1", seq=0, ts=None):
    tx = create_stake(account, amount, tier, sequence=seq)
    tx.tx_id = tx_id
    if ts is not None:
        tx.timestamp = int(ts)
    return tx


# ═══════════════════════════════════════════════════════════════════
#  New accounts start empty
# ═══════════════════════════════════════════════════════════════════

class TestAccountsStartEmpty(unittest.TestCase):
    """Wallets created through normal flows must have zero balance."""

    def setUp(self):
        self.ledger = Ledger(total_supply=100_000.0, genesis_account="rGen")

    def test_create_account_defaults_to_zero(self):
        self.ledger.create_account("rNew")
        self.assertEqual(self.ledger.get_balance("rNew"), 0.0)

    def test_create_account_explicit_zero(self):
        self.ledger.create_account("rNew", 0.0)
        self.assertEqual(self.ledger.get_balance("rNew"), 0.0)

    def test_genesis_holds_full_supply(self):
        self.assertAlmostEqual(
            self.ledger.get_balance("rGen"),
            100_000.0,
            places=3,
        )


# ═══════════════════════════════════════════════════════════════════
#  Unfunded accounts cannot transact
# ═══════════════════════════════════════════════════════════════════

class TestUnfundedAccountsCannotTransact(unittest.TestCase):
    """An account with 0 balance must be rejected for any debit."""

    def setUp(self):
        self.ledger = Ledger(total_supply=50_000.0, genesis_account="rGen")
        self.ledger.create_account("rEmpty", 0.0)
        self.ledger.create_account("rAlice", 0.0)

    def test_payment_from_unfunded_rejected(self):
        tx = _pay("rEmpty", "rAlice", 1.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_payment_from_nonexistent_rejected(self):
        tx = _pay("rGhost", "rAlice", 1.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_stake_from_unfunded_rejected(self):
        tx = _stake("rEmpty", 100.0, int(StakeTier.DAYS_30))
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_unfunded_cannot_even_pay_fee(self):
        """Zero balance cannot cover even the minimum fee."""
        tx = _pay("rEmpty", "rAlice", 0.0)  # zero amount, but fee applies
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_balance_stays_zero_after_rejected_tx(self):
        tx = _pay("rEmpty", "rAlice", 100.0)
        self.ledger.apply_payment(tx)
        self.assertEqual(self.ledger.get_balance("rEmpty"), 0.0)
        self.assertEqual(self.ledger.get_balance("rAlice"), 0.0)


# ═══════════════════════════════════════════════════════════════════
#  Only genesis can bootstrap funds
# ═══════════════════════════════════════════════════════════════════

class TestGenesisDistribution(unittest.TestCase):
    """Funds flow into the economy exclusively from the genesis account."""

    def setUp(self):
        self.initial = 100_000.0
        self.ledger = Ledger(total_supply=self.initial, genesis_account="rGen")
        self.ledger.create_account("rAlice", 0.0)
        self.ledger.create_account("rBob", 0.0)

    def test_genesis_can_pay_alice(self):
        tx = _pay("rGen", "rAlice", 1000.0, tx_id="gen_pay1")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        self.assertAlmostEqual(self.ledger.get_balance("rAlice"), 1000.0, places=3)

    def test_alice_can_forward_genesis_funds_to_bob(self):
        """Money from genesis → Alice → Bob is legitimate."""
        tx1 = _pay("rGen", "rAlice", 500.0, tx_id="gen_a")
        self.ledger.apply_payment(tx1)
        acc = self.ledger.get_account("rAlice")
        tx2 = _pay("rAlice", "rBob", 200.0, seq=acc.sequence, tx_id="a_b")
        result = self.ledger.apply_payment(tx2)
        self.assertEqual(result, 0)
        self.assertAlmostEqual(self.ledger.get_balance("rBob"), 200.0, places=3)

    def test_alice_cannot_send_more_than_received(self):
        """Alice got 500 from genesis — cannot send 600."""
        tx1 = _pay("rGen", "rAlice", 500.0, tx_id="gen_a2")
        self.ledger.apply_payment(tx1)
        acc = self.ledger.get_account("rAlice")
        tx2 = _pay("rAlice", "rBob", 600.0, seq=acc.sequence, tx_id="a_b2")
        result = self.ledger.apply_payment(tx2)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_genesis_balance_decreases_after_distribution(self):
        before = self.ledger.get_balance("rGen")
        tx = _pay("rGen", "rAlice", 2000.0, tx_id="gen_pay3")
        self.ledger.apply_payment(tx)
        after = self.ledger.get_balance("rGen")
        self.assertAlmostEqual(after, before - 2000.0 - 0.00001, places=4)

    def test_total_supply_decreases_by_fee_only(self):
        """A payment should burn fees only — total supply decreases by fee."""
        before_supply = self.ledger.total_supply
        tx = _pay("rGen", "rAlice", 5000.0, fee=1.0, tx_id="gen_pay4")
        self.ledger.apply_payment(tx)
        self.assertAlmostEqual(
            self.ledger.total_supply,
            before_supply - 1.0,
            places=6,
        )


# ═══════════════════════════════════════════════════════════════════
#  Supply conservation invariant
# ═══════════════════════════════════════════════════════════════════

class TestSupplyConservation(unittest.TestCase):
    """
    At all times: total_supply == initial_supply - total_burned + total_minted.
    """

    def setUp(self):
        self.initial = 50_000.0
        self.ledger = Ledger(total_supply=self.initial, genesis_account="rGen")
        self.ledger.create_account("rAlice", 0.0)

    def _check_invariant(self):
        expected = self.initial - self.ledger.total_burned + self.ledger.total_minted
        self.assertAlmostEqual(self.ledger.total_supply, expected, places=6)

    def test_invariant_at_genesis(self):
        self._check_invariant()
        self.assertEqual(self.ledger.total_burned, 0.0)
        self.assertEqual(self.ledger.total_minted, 0.0)

    def test_invariant_after_payment(self):
        tx = _pay("rGen", "rAlice", 100.0, fee=0.5, tx_id="inv1")
        self.ledger.apply_payment(tx)
        self._check_invariant()

    def test_invariant_after_multiple_payments(self):
        tx1 = _pay("rGen", "rAlice", 1000.0, fee=1.0, tx_id="inv2")
        self.ledger.apply_payment(tx1)
        acc = self.ledger.get_account("rAlice")
        tx2 = _pay("rAlice", "rGen", 500.0, fee=0.5, seq=acc.sequence, tx_id="inv3")
        self.ledger.apply_payment(tx2)
        self._check_invariant()

    def test_invariant_after_stake_and_maturity(self):
        # Fund Alice from genesis
        tx_fund = _pay("rGen", "rAlice", 5000.0, tx_id="inv4")
        self.ledger.apply_payment(tx_fund)
        self._check_invariant()

        # Stake
        now = time.time()
        acc = self.ledger.get_account("rAlice")
        tx_stake = _stake("rAlice", 2000.0, int(StakeTier.DAYS_30),
                          tx_id="inv_stk", seq=acc.sequence, ts=now)
        self.ledger.apply_transaction(tx_stake)
        self._check_invariant()

        # Fast-forward maturity
        record = self.ledger.staking_pool.stakes["inv_stk"]
        record.maturity_time = now - 1
        record.matured = False
        self.ledger.close_ledger()
        self._check_invariant()

        # After minting, total_minted should be > 0 and supply > initial - burned
        self.assertGreater(self.ledger.total_minted, 0.0)

    def test_invariant_after_early_cancel(self):
        tx_fund = _pay("rGen", "rAlice", 5000.0, tx_id="inv5")
        self.ledger.apply_payment(tx_fund)

        now = time.time()
        acc = self.ledger.get_account("rAlice")
        tx_stake = _stake("rAlice", 2000.0, int(StakeTier.DAYS_365),
                          tx_id="inv_stk2", seq=acc.sequence, ts=now)
        self.ledger.apply_transaction(tx_stake)
        self._check_invariant()

        # Early cancel — penalty gets burned
        from nexaflow_core.transaction import create_unstake
        acc2 = self.ledger.get_account("rAlice")
        tx_cancel = create_unstake("rAlice", "inv_stk2", sequence=acc2.sequence)
        tx_cancel.tx_id = "inv_ustk2"
        tx_cancel.timestamp = int(now + 86400)  # 1 day later
        self.ledger.apply_transaction(tx_cancel)
        self._check_invariant()


# ═══════════════════════════════════════════════════════════════════
#  No money from thin air
# ═══════════════════════════════════════════════════════════════════

class TestNoMoneyFromThinAir(unittest.TestCase):
    """
    Verify that create_account with nonzero initial_nxf does not
    increase total_supply — the money must already exist somewhere
    (i.e., only genesis legitimately starts with supply).
    """

    def test_create_account_nonzero_does_not_change_supply(self):
        """
        create_account gives an account a balance, but total_supply is
        unchanged — the caller is responsible for debiting a source.
        This means create_account(addr, X) with X>0 is only valid
        internally (genesis init).
        """
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        supply_before = ledger.total_supply
        ledger.create_account("rSneaky", 999.0)
        # total_supply should NOT have increased
        self.assertEqual(ledger.total_supply, supply_before)

    def test_sum_of_balances_cannot_exceed_supply(self):
        """
        With legitimate genesis + distribution, sum of all balances
        plus total_burned must equal initial_supply + total_minted.
        """
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account("rA", 0.0)
        ledger.create_account("rB", 0.0)

        # Distribute from genesis
        tx1 = _pay("rGen", "rA", 3000.0, fee=1.0, tx_id="eco1")
        ledger.apply_payment(tx1)
        acc_a = ledger.get_account("rA")
        tx2 = _pay("rA", "rB", 1000.0, fee=0.5, seq=acc_a.sequence, tx_id="eco2")
        ledger.apply_payment(tx2)

        # Sum all balances
        total_bal = sum(
            ledger.get_balance(addr)
            for addr in ["rGen", "rA", "rB"]
        )
        # balance_sum + burned == initial_supply (no interest minted yet)
        self.assertAlmostEqual(
            total_bal + ledger.total_burned,
            ledger.initial_supply + ledger.total_minted,
            places=6,
        )

    def test_circular_payments_do_not_create_money(self):
        """A -> B -> A cycle only loses fees, never gains balance."""
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account("rA", 0.0)
        ledger.create_account("rB", 0.0)

        tx0 = _pay("rGen", "rA", 1000.0, fee=0.01, tx_id="circ0")
        ledger.apply_payment(tx0)

        for i in range(5):
            acc_a = ledger.get_account("rA")
            bal_a = ledger.get_balance("rA")
            send_amt = bal_a - 1.0  # keep 1 NXF reserve
            if send_amt <= 0:
                break
            tx_ab = _pay("rA", "rB", send_amt, fee=0.01,
                         seq=acc_a.sequence, tx_id=f"circ_ab{i}")
            ledger.apply_payment(tx_ab)

            acc_b = ledger.get_account("rB")
            bal_b = ledger.get_balance("rB")
            send_back = bal_b - 1.0
            if send_back <= 0:
                break
            tx_ba = _pay("rB", "rA", send_back, fee=0.01,
                         seq=acc_b.sequence, tx_id=f"circ_ba{i}")
            ledger.apply_payment(tx_ba)

        # Total in A + B should be less than 1000 (lost fees)
        total = ledger.get_balance("rA") + ledger.get_balance("rB")
        self.assertLess(total, 1000.0)

        # Supply invariant still holds
        expected_supply = ledger.initial_supply - ledger.total_burned + ledger.total_minted
        self.assertAlmostEqual(ledger.total_supply, expected_supply, places=6)


# ═══════════════════════════════════════════════════════════════════
#  Overspending protection
# ═══════════════════════════════════════════════════════════════════

class TestOverspendingProtection(unittest.TestCase):
    """Cannot spend funds that were not legitimately distributed."""

    def setUp(self):
        self.ledger = Ledger(total_supply=50_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 0.0)

        # Give Alice exactly 100 from genesis
        tx = _pay("rGen", "rAlice", 100.0, fee=0.01, tx_id="setup_pay")
        self.ledger.apply_payment(tx)

    def test_spend_exactly_balance_minus_fee(self):
        """Alice can spend her entire balance minus fee."""
        acc = self.ledger.get_account("rAlice")
        bal = self.ledger.get_balance("rAlice")
        # Spend almost everything, leaving just enough for fee
        send = bal - 0.01
        tx = _pay("rAlice", "rGen", send, fee=0.01,
                   seq=acc.sequence, tx_id="exact1")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        self.assertAlmostEqual(self.ledger.get_balance("rAlice"), 0.0, places=4)

    def test_spend_one_unit_over_balance_rejected(self):
        """Alice cannot spend even 1 NXF more than she has."""
        acc = self.ledger.get_account("rAlice")
        tx = _pay("rAlice", "rGen", 101.0, fee=0.01,
                   seq=acc.sequence, tx_id="over1")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_double_spend_same_funds(self):
        """Cannot spend the same funds twice."""
        acc = self.ledger.get_account("rAlice")
        tx1 = _pay("rAlice", "rGen", 80.0, fee=0.01,
                    seq=acc.sequence, tx_id="ds1")
        result1 = self.ledger.apply_payment(tx1)
        self.assertEqual(result1, 0)

        acc2 = self.ledger.get_account("rAlice")
        tx2 = _pay("rAlice", "rGen", 80.0, fee=0.01,
                    seq=acc2.sequence, tx_id="ds2")
        result2 = self.ledger.apply_payment(tx2)
        self.assertEqual(result2, 101)  # tecUNFUNDED — already spent

    def test_stake_more_than_balance_rejected(self):
        """Cannot stake more NXF than the wallet holds."""
        acc = self.ledger.get_account("rAlice")
        tx = _stake("rAlice", 5000.0, int(StakeTier.DAYS_365),
                     tx_id="over_stk", seq=acc.sequence)
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED


# ═══════════════════════════════════════════════════════════════════
#  Initial supply immutability
# ═══════════════════════════════════════════════════════════════════

class TestInitialSupplyImmutable(unittest.TestCase):
    """initial_supply must never change, regardless of operations."""

    def test_initial_supply_unchanged_after_payments(self):
        ledger = Ledger(total_supply=75_000.0, genesis_account="rGen")
        ledger.create_account("rA", 0.0)
        initial = ledger.initial_supply

        for i in range(10):
            tx = _pay("rGen", "rA", 100.0, tx_id=f"is_{i}")
            ledger.apply_payment(tx)

        self.assertEqual(ledger.initial_supply, initial)

    def test_initial_supply_unchanged_after_staking(self):
        ledger = Ledger(total_supply=75_000.0, genesis_account="rGen")
        ledger.create_account("rA", 0.0)
        initial = ledger.initial_supply

        tx_fund = _pay("rGen", "rA", 5000.0, tx_id="is_fund")
        ledger.apply_payment(tx_fund)

        now = time.time()
        acc = ledger.get_account("rA")
        tx_stk = _stake("rA", 2000.0, int(StakeTier.DAYS_30),
                         tx_id="is_stk", seq=acc.sequence, ts=now)
        ledger.apply_transaction(tx_stk)

        record = ledger.staking_pool.stakes["is_stk"]
        record.maturity_time = now - 1
        record.matured = False
        ledger.close_ledger()

        self.assertEqual(ledger.initial_supply, initial)
        self.assertGreater(ledger.total_minted, 0.0)


if __name__ == "__main__":
    unittest.main()
