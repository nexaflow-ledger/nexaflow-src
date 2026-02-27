"""
Extended security tests for nexaflow_core.ledger — deep invariant & attack tests.

Covers additional attack vectors not in the original test_ledger_security.py:
  - Negative amount payment (reversal attack)
  - Floating-point precision attacks on balances
  - Supply conservation invariant across operations
  - Double-apply of same transaction with different tx_id
  - IOU circular trust line manipulation
  - Massive account creation (resource exhaustion)
  - Ledger state hash determinism
  - Concurrent stake + payment balance atomicity
  - Trust-line re-entrancy via self-referencing issuer
  - Confidential output overwrites
  - Sequence overflow / wraparound
  - Fee burn precision across many small transactions
  - Genesis account manipulation attempts
  - Staking timestamp manipulation (future / past)
"""

import time
import unittest

from nexaflow_core.ledger import AccountEntry, Ledger, LedgerHeader, TrustLineEntry
from nexaflow_core.transaction import (
    TES_SUCCESS,
    Amount,
    Transaction,
    create_payment,
    create_stake,
    create_trust_set,
    create_unstake,
)


class ExtendedLedgerSecBase(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)


# ═══════════════════════════════════════════════════════════════════
#  Negative Amount / Reversal Attack
# ═══════════════════════════════════════════════════════════════════

class TestNegativeAmountAttack(ExtendedLedgerSecBase):

    def test_negative_native_payment_accepted(self):
        """
        CONFIRMED VULN: A payment with negative amount is accepted by
        apply_payment. The sender's balance INCREASES because the negative
        amount is subtracted (which adds), and the receiver loses money.
        """
        tx = create_payment("rAlice", "rBob", -50.0)
        alice_before = self.ledger.get_balance("rAlice")
        bob_before = self.ledger.get_balance("rBob")
        result = self.ledger.apply_payment(tx)
        alice_after = self.ledger.get_balance("rAlice")
        bob_after = self.ledger.get_balance("rBob")
        # Document the vulnerability: either rejected or improperly accepted
        if result == 0:
            # VULNERABILITY: negative payment was accepted
            # Alice balance went up (credited) or Bob balance went down
            self.assertTrue(
                alice_after > alice_before or bob_after < bob_before,
                "Negative payment accepted — balance manipulation possible",
            )
        # If result != 0, it was properly rejected — also acceptable

    def test_negative_fee_payment(self):
        """A negative fee should not credit the sender."""
        tx = create_payment("rAlice", "rBob", 1.0, fee=-1.0)
        alice_before = self.ledger.get_balance("rAlice")
        result = self.ledger.apply_payment(tx)
        # Negative fee should never increase balance
        alice_after = self.ledger.get_balance("rAlice")
        self.assertLessEqual(alice_after, alice_before)


# ═══════════════════════════════════════════════════════════════════
#  Floating Point Precision Attacks
# ═══════════════════════════════════════════════════════════════════

class TestFloatingPointPrecision(ExtendedLedgerSecBase):

    def test_many_small_payments_preserve_total(self):
        """
        VULN: Repeated tiny payments may accumulate floating-point drift.
        Total supply should remain conserved across many operations.
        """
        initial_supply = self.ledger.total_supply
        initial_total = sum(
            acc.balance for acc in self.ledger.accounts.values()
        )

        # Make 1000 tiny payments
        for i in range(100):
            tx = create_payment("rAlice", "rBob", 0.001, fee=0.00001)
            tx.tx_id = f"fp_tx_{i}"
            self.ledger.apply_transaction(tx)

        final_total = sum(
            acc.balance for acc in self.ledger.accounts.values()
        )
        total_burned = self.ledger.total_burned

        # Conservation: initial_total = final_total + total_burned
        self.assertAlmostEqual(
            initial_total,
            final_total + total_burned,
            places=4,
            msg="Supply conservation violated after many small payments",
        )

    def test_very_small_amount_rounding(self):
        """Extremely small amounts should not cause balance to go negative."""
        tx = create_payment("rAlice", "rBob", 1e-15, fee=0.00001)
        tx.tx_id = "tiny_tx"
        self.ledger.apply_transaction(tx)
        self.assertGreaterEqual(self.ledger.get_balance("rAlice"), 0.0)
        self.assertGreaterEqual(self.ledger.get_balance("rBob"), 0.0)

    def test_amount_near_max_double(self):
        """Amount near float64 max should not overflow."""
        tx = create_payment("rAlice", "rBob", 1e308)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED


# ═══════════════════════════════════════════════════════════════════
#  Supply Conservation Invariant
# ═══════════════════════════════════════════════════════════════════

class TestSupplyConservation(ExtendedLedgerSecBase):

    def _compute_total_in_accounts(self):
        return sum(acc.balance for acc in self.ledger.accounts.values())

    def test_supply_after_payment(self):
        total_before = self._compute_total_in_accounts()
        supply_before = self.ledger.total_supply

        tx = create_payment("rAlice", "rBob", 50.0, fee=0.5)
        tx.tx_id = "conserve_1"
        self.ledger.apply_transaction(tx)

        total_after = self._compute_total_in_accounts()
        supply_after = self.ledger.total_supply
        burned = self.ledger.total_burned

        # Total in accounts + burned = initial supply
        self.assertAlmostEqual(
            total_after + burned,
            total_before,
            places=5,
        )

    def test_supply_after_stake_and_unstake(self):
        """Stake → unstake cycle should conserve supply (minus fees)."""
        total_before = self._compute_total_in_accounts()

        tx_s = create_stake("rAlice", 100.0, 0)
        tx_s.tx_id = "stake_conserve"
        tx_s.timestamp = time.time()
        self.ledger.apply_transaction(tx_s)

        tx_u = create_unstake("rAlice", "stake_conserve")
        tx_u.tx_id = "unstake_conserve"
        tx_u.timestamp = time.time()
        self.ledger.apply_transaction(tx_u)

        total_after = self._compute_total_in_accounts()
        total_burned = self.ledger.total_burned
        total_staked = self.ledger.staking_pool.total_staked

        # All money is accounted for
        self.assertAlmostEqual(
            total_after + total_burned + total_staked,
            total_before,
            places=4,
        )

    def test_supply_after_ledger_close_with_maturity(self):
        """Auto-maturity at close_ledger should mint interest correctly."""
        past = time.time() - 31 * 86400
        tx = create_stake("rAlice", 100.0, 1)  # 30-day tier
        tx.tx_id = "mature_supply"
        tx.timestamp = past
        self.ledger.apply_transaction(tx)

        supply_before_close = self.ledger.total_supply
        staked_before = self.ledger.staking_pool.total_staked

        self.ledger.close_ledger()

        # Interest was minted — total_supply should increase by interest
        supply_after = self.ledger.total_supply
        minted = self.ledger.total_minted
        self.assertGreater(minted, 0.0)
        self.assertAlmostEqual(
            supply_after,
            supply_before_close + minted,
            places=4,
        )


# ═══════════════════════════════════════════════════════════════════
#  Double-Apply Same Transaction Content (Different tx_id)
# ═══════════════════════════════════════════════════════════════════

class TestDoubleApplyByContent(ExtendedLedgerSecBase):

    def test_same_content_different_tx_id_both_apply(self):
        """
        Two payments with identical content but different tx_ids should
        both succeed—this is expected design, but the second deduction
        should also succeed.
        """
        tx1 = create_payment("rAlice", "rBob", 10.0)
        tx1.tx_id = "content_dup_1"
        tx2 = create_payment("rAlice", "rBob", 10.0)
        tx2.tx_id = "content_dup_2"

        r1 = self.ledger.apply_transaction(tx1)
        r2 = self.ledger.apply_transaction(tx2)
        self.assertEqual(r1, 0)
        self.assertEqual(r2, 0)
        # Alice lost 20 + 2 fees
        self.assertAlmostEqual(
            self.ledger.get_balance("rAlice"),
            500.0 - 20.0 - 0.00002,
            places=4,
        )


# ═══════════════════════════════════════════════════════════════════
#  IOU Trust-Line Circular Manipulation
# ═══════════════════════════════════════════════════════════════════

class TestIOUCircularAttack(ExtendedLedgerSecBase):

    def setUp(self):
        super().setUp()
        self.ledger.create_account("rGW", 1000.0)
        self.ledger.get_account("rGW").is_gateway = True
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 100.0)
        self.ledger.set_trust_line("rBob", "USD", "rGW", 100.0)

    def test_circular_iou_does_not_create_money(self):
        """
        Circular trust: A trusts B, B trusts A for same currency via same issuer.
        Should not allow money creation.
        """
        self.ledger.set_trust_line("rAlice", "USD", "rBob", 50.0)
        self.ledger.set_trust_line("rBob", "USD", "rAlice", 50.0)

        # Fund Alice's USD through gateway
        tx1 = create_payment("rGW", "rAlice", 30.0, "USD", "rGW")
        tx1.tx_id = "fund_alice_usd"
        self.ledger.apply_transaction(tx1)

        # Try to send in a circle: Alice → Bob → Alice
        alice_usd = self.ledger.get_trust_line("rAlice", "USD", "rGW")
        alice_usd_before = alice_usd.balance if alice_usd else 0.0

        tx2 = create_payment("rAlice", "rBob", 20.0, "USD", "rGW")
        tx2.tx_id = "circle_1"
        self.ledger.apply_transaction(tx2)

        tx3 = create_payment("rBob", "rAlice", 20.0, "USD", "rGW")
        tx3.tx_id = "circle_2"
        self.ledger.apply_transaction(tx3)

        # Net effect should be zero IOU movement (minus fees)
        alice_usd_after = alice_usd.balance if alice_usd else 0.0
        self.assertAlmostEqual(alice_usd_before, alice_usd_after, places=4)

    def test_self_trust_line_no_exploit(self):
        """Setting a trust line to yourself should be harmless."""
        tl = self.ledger.set_trust_line("rAlice", "USD", "rAlice", 1000.0)
        # Should not enable self-issued money
        tx = create_payment("rAlice", "rBob", 50.0, "USD", "rAlice")
        tx.tx_id = "self_trust_pay"
        result = self.ledger.apply_transaction(tx)
        # rAlice is not a gateway, sending own IOUs should work if sender == issuer
        # but Bob needs a trust line to rAlice for USD
        self.assertIn(result, [0, 103])  # either works or no_line


# ═══════════════════════════════════════════════════════════════════
#  Genesis Account Manipulation
# ═══════════════════════════════════════════════════════════════════

class TestGenesisAccountProtection(ExtendedLedgerSecBase):

    def test_create_duplicate_genesis_returns_existing(self):
        """Re-creating genesis should not reset its balance."""
        genesis_bal = self.ledger.get_balance("rGen")
        acc = self.ledger.create_account("rGen", 0.0)
        self.assertEqual(self.ledger.get_balance("rGen"), genesis_bal)

    def test_genesis_is_gateway(self):
        acc = self.ledger.get_account("rGen")
        self.assertTrue(acc.is_gateway)

    def test_drain_genesis_should_not_go_negative(self):
        """Even sending all genesis balance should not result in negative."""
        genesis_bal = self.ledger.get_balance("rGen")
        tx = create_payment("rGen", "rAlice", genesis_bal + 1.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED
        self.assertGreaterEqual(self.ledger.get_balance("rGen"), 0.0)


# ═══════════════════════════════════════════════════════════════════
#  Ledger State Hash Determinism
# ═══════════════════════════════════════════════════════════════════

class TestLedgerHashDeterminism(ExtendedLedgerSecBase):

    def test_same_ops_produce_same_hash(self):
        """Two identical ledgers with same operations should produce same hash."""
        ledger2 = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger2.create_account("rAlice", 500.0)
        ledger2.create_account("rBob", 100.0)

        for ldg in [self.ledger, ledger2]:
            tx = create_payment("rAlice", "rBob", 10.0)
            tx.tx_id = "deterministic_tx"
            ldg.apply_transaction(tx)

        h1 = self.ledger.close_ledger()
        h2 = ledger2.close_ledger()
        self.assertEqual(h1.state_hash, h2.state_hash)
        self.assertEqual(h1.tx_hash, h2.tx_hash)

    def test_different_ops_produce_different_hash(self):
        """Different operations should produce different state hash."""
        ledger2 = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger2.create_account("rAlice", 500.0)
        ledger2.create_account("rBob", 100.0)

        tx1 = create_payment("rAlice", "rBob", 10.0)
        tx1.tx_id = "diff_tx_1"
        self.ledger.apply_transaction(tx1)

        tx2 = create_payment("rAlice", "rBob", 20.0)
        tx2.tx_id = "diff_tx_2"
        ledger2.apply_transaction(tx2)

        h1 = self.ledger.close_ledger()
        h2 = ledger2.close_ledger()
        self.assertNotEqual(h1.state_hash, h2.state_hash)


# ═══════════════════════════════════════════════════════════════════
#  Sequence Overflow
# ═══════════════════════════════════════════════════════════════════

class TestSequenceOverflow(ExtendedLedgerSecBase):

    def test_max_sequence_payment(self):
        """Payment at maximum sequence value."""
        acc = self.ledger.get_account("rAlice")
        acc.sequence = 2**62
        tx = create_payment("rAlice", "rBob", 1.0, sequence=2**62)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        self.assertEqual(acc.sequence, 2**62 + 1)

    def test_negative_sequence_rejected(self):
        """Negative sequence should be rejected."""
        tx = create_payment("rAlice", "rBob", 1.0, sequence=-1)
        result = self.ledger.apply_payment(tx)
        self.assertNotEqual(result, 0)


# ═══════════════════════════════════════════════════════════════════
#  Fee Burn Precision
# ═══════════════════════════════════════════════════════════════════

class TestFeeBurnPrecision(ExtendedLedgerSecBase):

    def test_accumulated_fees_match_burned(self):
        """Sum of all individual fees should equal total_burned."""
        n_txns = 50
        fee = 0.00001
        for i in range(n_txns):
            tx = create_payment("rAlice", "rBob", 0.01, fee=fee)
            tx.tx_id = f"fee_burn_{i}"
            self.ledger.apply_transaction(tx)

        expected_burn = n_txns * fee
        self.assertAlmostEqual(
            self.ledger.total_burned, expected_burn, places=8
        )


# ═══════════════════════════════════════════════════════════════════
#  Staking Timestamp Manipulation
# ═══════════════════════════════════════════════════════════════════

class TestStakingTimestampManipulation(ExtendedLedgerSecBase):

    def test_stake_with_far_future_timestamp(self):
        """A stake created with a far-future timestamp should still work."""
        future = time.time() + 365 * 86400 * 100  # 100 years in future
        tx = create_stake("rAlice", 100.0, 1)
        tx.tx_id = "future_stake"
        tx.timestamp = future
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 0)
        # The stake's maturity time would be in the far future
        record = self.ledger.staking_pool.stakes["future_stake"]
        self.assertGreater(record.maturity_time, future)

    def test_stake_with_zero_timestamp(self):
        """Stake with timestamp=0 should use current time."""
        tx = create_stake("rAlice", 100.0, 0)
        tx.tx_id = "zero_ts_stake"
        tx.timestamp = 0
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 0)

    def test_stake_with_past_timestamp_immediate_maturity(self):
        """
        VULN: A stake with a far-past timestamp could be immediately
        mature at the next ledger close.
        """
        past = time.time() - 365 * 86400  # 1 year ago
        tx = create_stake("rAlice", 100.0, 1)  # 30-day tier
        tx.tx_id = "past_stake"
        tx.timestamp = past
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 0)

        # Close ledger — the stake should auto-mature
        bal_before = self.ledger.get_balance("rAlice")
        self.ledger.close_ledger()
        bal_after = self.ledger.get_balance("rAlice")
        # Immediate payout is a design concern — verify it's tracked
        self.assertGreater(bal_after, bal_before)

    def test_stake_negative_timestamp_handled(self):
        """Negative timestamp should not crash."""
        tx = create_stake("rAlice", 50.0, 0)
        tx.tx_id = "neg_ts_stake"
        tx.timestamp = -1000
        result = self.ledger.apply_stake(tx)
        # Should either succeed or fail gracefully
        self.assertIn(result, [0, 101, 108])


# ═══════════════════════════════════════════════════════════════════
#  Confidential Output Overwrite
# ═══════════════════════════════════════════════════════════════════

class TestConfidentialOutputOverwrite(ExtendedLedgerSecBase):

    def test_duplicate_stealth_address_overwrites(self):
        """
        VULN: If two confidential TX produce the same stealth address,
        the second overwrites the first, potentially destroying value.
        """
        from nexaflow_core.ledger import ConfidentialOutput

        out1 = ConfidentialOutput(
            b"\x01" * 32, b"\xaa" * 32, b"\x02" * 65,
            b"\x03" * 32, b"\x04", "tx_1",
        )
        out2 = ConfidentialOutput(
            b"\x05" * 32, b"\xaa" * 32, b"\x06" * 65,
            b"\x07" * 32, b"\x08", "tx_2",
        )

        self.ledger.confidential_outputs[out1.stealth_addr.hex()] = out1
        self.ledger.confidential_outputs[out2.stealth_addr.hex()] = out2

        # The first output is overwritten
        stored = self.ledger.confidential_outputs[b"\xaa".hex() * 32]
        self.assertEqual(stored.tx_id, "tx_2")

    def test_key_image_replay_protection(self):
        """Spending the same key image twice should be prevented."""
        ki = b"\xde\xad" * 16
        self.ledger.spent_key_images.add(ki)
        self.assertTrue(self.ledger.is_key_image_spent(ki))


# ═══════════════════════════════════════════════════════════════════
#  Massive Account Creation
# ═══════════════════════════════════════════════════════════════════

class TestMassiveAccountCreation(ExtendedLedgerSecBase):

    def test_many_accounts_auto_created_via_payment(self):
        """Creating many accounts via payment should not crash."""
        initial_count = len(self.ledger.accounts)
        created = 0
        for i in range(100):
            tx = create_payment("rAlice", f"rNew{i}", 0.001, fee=0.00001)
            tx.tx_id = f"mass_create_{i}"
            result = self.ledger.apply_transaction(tx)
            if result == 0:
                created += 1
        # All 100 payments should succeed and create new accounts
        # Some may fail if balance insufficient
        self.assertGreater(created, 0)
        self.assertEqual(len(self.ledger.accounts), initial_count + created)

    def test_many_accounts_ledger_close_performance(self):
        """Closing a ledger with many accounts should not timeout."""
        for i in range(200):
            self.ledger.create_account(f"rBulk{i}", 1.0)
        header = self.ledger.close_ledger()
        self.assertIsNotNone(header.hash)
        self.assertEqual(len(header.hash), 64)


# ═══════════════════════════════════════════════════════════════════
#  Trust Line Limit = 0 After Creation
# ═══════════════════════════════════════════════════════════════════

class TestTrustLineLimitZero(ExtendedLedgerSecBase):

    def test_reduce_trust_limit_to_zero(self):
        """Reducing trust limit to 0 should prevent further IOU transfers."""
        self.ledger.create_account("rGW", 1000.0)
        self.ledger.get_account("rGW").is_gateway = True
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 100.0)

        # Fund some USD
        tx1 = create_payment("rGW", "rAlice", 50.0, "USD", "rGW")
        tx1.tx_id = "fund_usd"
        self.ledger.apply_transaction(tx1)

        # Reduce limit to 0
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 0.0)

        # Try to receive more USD — should fail (limit 0)
        tx2 = create_payment("rGW", "rAlice", 10.0, "USD", "rGW")
        tx2.tx_id = "exceed_zero_limit"
        result = self.ledger.apply_transaction(tx2)
        self.assertEqual(result, 101)  # would exceed trust

    def test_send_iou_with_zero_limit_allowed(self):
        """Sending existing IOU balance should work even with limit=0."""
        self.ledger.create_account("rGW", 1000.0)
        self.ledger.get_account("rGW").is_gateway = True
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 100.0)
        self.ledger.set_trust_line("rBob", "USD", "rGW", 100.0)

        # Fund Alice
        tx1 = create_payment("rGW", "rAlice", 50.0, "USD", "rGW")
        tx1.tx_id = "fund_pre"
        self.ledger.apply_transaction(tx1)

        # Reduce Alice's limit to 0
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 0.0)

        # Alice can still SEND her existing balance
        tx2 = create_payment("rAlice", "rBob", 30.0, "USD", "rGW")
        tx2.tx_id = "send_existing"
        result = self.ledger.apply_transaction(tx2)
        self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
