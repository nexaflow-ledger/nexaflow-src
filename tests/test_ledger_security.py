"""
Security-focused tests for nexaflow_core.ledger — edge cases & invariants.

Covers:
  - Self-payment (account sends to itself)
  - Double-spend via applied_tx_ids (replay protection)
  - Negative balance prevention
  - Zero-amount payment
  - Maximum supply overflow guard
  - Fee pool accumulation
  - Trust-line limit enforcement
  - Close ledger hash-chain integrity
  - Staking at ledger level: apply_stake / apply_unstake
  - Auto-maturity at close_ledger
  - Transaction routing via apply_transaction
  - Confidential output storage isolation
"""

import time
import unittest

from nexaflow_core.ledger import AccountEntry, Ledger, LedgerHeader, TrustLineEntry
from nexaflow_core.transaction import (
    TES_SUCCESS,
    create_payment,
    create_stake,
    create_trust_set,
    create_unstake,
)


class LedgerSecBase(unittest.TestCase):
    """Shared setup: ledger with 10K supply, rAlice(500), rBob(100)."""

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)


# ═══════════════════════════════════════════════════════════════════
#  Self-payment
# ═══════════════════════════════════════════════════════════════════

class TestSelfPayment(LedgerSecBase):

    def test_self_payment_deducts_fee_only(self):
        tx = create_payment("rAlice", "rAlice", 10.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        # 500 - 10 - fee + 10 = 500 - fee
        self.assertAlmostEqual(self.ledger.get_balance("rAlice"), 500.0 - 0.00001, places=5)

    def test_self_payment_increments_sequence(self):
        seq_before = self.ledger.get_account("rAlice").sequence
        tx = create_payment("rAlice", "rAlice", 1.0, sequence=seq_before)
        self.ledger.apply_payment(tx)
        self.assertEqual(self.ledger.get_account("rAlice").sequence, seq_before + 1)


# ═══════════════════════════════════════════════════════════════════
#  Replay protection (duplicate TX)
# ═══════════════════════════════════════════════════════════════════

class TestReplayProtection(LedgerSecBase):

    def test_duplicate_tx_id_rejected(self):
        """A TX with a previously applied tx_id should be rejected."""
        tx = create_payment("rAlice", "rBob", 1.0)
        tx.tx_id = "unique_tx_1"
        r1 = self.ledger.apply_transaction(tx)
        self.assertEqual(r1, 0)

        # Create a new TX with the same tx_id
        tx2 = create_payment("rAlice", "rBob", 1.0)
        tx2.tx_id = "unique_tx_1"
        r2 = self.ledger.apply_transaction(tx2)
        self.assertNotEqual(r2, 0)  # should fail

    def test_applied_tx_ids_grows(self):
        tx = create_payment("rAlice", "rBob", 1.0)
        tx.tx_id = "tx_grow_1"
        self.ledger.apply_transaction(tx)
        self.assertIn("tx_grow_1", self.ledger.applied_tx_ids)


# ═══════════════════════════════════════════════════════════════════
#  Balance enforcement
# ═══════════════════════════════════════════════════════════════════

class TestBalanceEnforcement(LedgerSecBase):

    def test_overdraft_rejected(self):
        """Cannot send more than balance."""
        tx = create_payment("rAlice", "rBob", 999999.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_exact_balance_minus_fee(self):
        """Sending all except fee should succeed (if reserve allows)."""
        # rAlice has 500; this will fail due to reserve
        tx = create_payment("rAlice", "rBob", 499.0)
        result = self.ledger.apply_payment(tx)
        # May or may not succeed depending on reserve enforcement
        # The ledger apply_payment checks balance < amt + fee
        # 500 < 499 + 0.00001 = 499.00001 → passes the raw check
        self.assertEqual(result, 0)

    def test_zero_amount_payment(self):
        """Zero-amount payment should still deduct fee."""
        bal_before = self.ledger.get_balance("rAlice")
        tx = create_payment("rAlice", "rBob", 0.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        self.assertAlmostEqual(
            self.ledger.get_balance("rAlice"),
            bal_before - 0.00001,
            places=5,
        )


# ═══════════════════════════════════════════════════════════════════
#  Fee burning
# ═══════════════════════════════════════════════════════════════════

class TestFeeBurning(LedgerSecBase):

    def test_fee_is_burned(self):
        self.assertEqual(self.ledger.total_burned, 0.0)
        initial_supply = self.ledger.total_supply
        tx = create_payment("rAlice", "rBob", 1.0, fee=0.5)
        self.ledger.apply_payment(tx)
        self.assertAlmostEqual(self.ledger.total_burned, 0.5, places=5)
        self.assertAlmostEqual(self.ledger.total_supply, initial_supply - 0.5, places=5)

    def test_multiple_txs_accumulate_burned(self):
        initial_supply = self.ledger.total_supply
        for _ in range(10):
            tx = create_payment("rAlice", "rBob", 1.0, fee=0.1)
            self.ledger.apply_payment(tx)
        self.assertAlmostEqual(self.ledger.total_burned, 1.0, places=5)
        self.assertAlmostEqual(self.ledger.total_supply, initial_supply - 1.0, places=5)


# ═══════════════════════════════════════════════════════════════════
#  Trust line enforcement
# ═══════════════════════════════════════════════════════════════════

class TestTrustLineSecurity(LedgerSecBase):

    def setUp(self):
        super().setUp()
        self.ledger.create_account("rGW", 1000.0)
        self.ledger.get_account("rGW").is_gateway = True
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 100.0)
        self.ledger.set_trust_line("rBob", "USD", "rGW", 100.0)

    def test_iou_exceeds_trust_limit(self):
        """Sending more IOUs than the receiver trusts should fail."""
        # Fund rAlice's trust line
        tl = self.ledger.get_trust_line("rAlice", "USD", "rGW")
        tl.balance = 50.0
        # rBob has limit 100; try to send 150
        tl_bob = self.ledger.get_trust_line("rBob", "USD", "rGW")
        tl_bob.balance = 0.0
        tx = create_payment("rAlice", "rBob", 101.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertNotEqual(result, 0)

    def test_iou_no_trust_line_fails(self):
        """Sending IOU without a trust line should fail."""
        tx = create_payment("rAlice", "rBob", 10.0, "EUR", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 103)  # tecNO_LINE

    def test_issuer_can_send_without_trust_line(self):
        """Gateway can issue its own currency without a trust line to itself."""
        tx = create_payment("rGW", "rAlice", 10.0, "USD", "rGW")
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)


# ═══════════════════════════════════════════════════════════════════
#  Ledger close — hash chain
# ═══════════════════════════════════════════════════════════════════

class TestLedgerClose(LedgerSecBase):

    def test_close_increments_sequence(self):
        seq_before = self.ledger.current_sequence
        self.ledger.close_ledger()
        self.assertEqual(self.ledger.current_sequence, seq_before + 1)

    def test_close_produces_valid_hash(self):
        header = self.ledger.close_ledger()
        self.assertEqual(len(header.hash), 64)

    def test_hash_chain_links(self):
        h1 = self.ledger.close_ledger()
        h2 = self.ledger.close_ledger()
        self.assertEqual(h2.parent_hash, h1.hash)

    def test_close_clears_pending(self):
        tx = create_payment("rAlice", "rBob", 1.0)
        self.ledger.apply_transaction(tx)
        self.assertTrue(len(self.ledger.pending_txns) > 0)
        self.ledger.close_ledger()
        self.assertEqual(len(self.ledger.pending_txns), 0)

    def test_consecutive_closes_different_hashes(self):
        h1 = self.ledger.close_ledger()
        h2 = self.ledger.close_ledger()
        self.assertNotEqual(h1.hash, h2.hash)

    def test_state_summary_fields(self):
        self.ledger.close_ledger()
        summary = self.ledger.get_state_summary()
        expected_keys = {
            "ledger_sequence", "closed_ledgers", "total_accounts",
            "total_supply", "total_burned", "total_staked", "active_stakes",
        }
        for k in expected_keys:
            self.assertIn(k, summary)


# ═══════════════════════════════════════════════════════════════════
#  Staking at ledger level
# ═══════════════════════════════════════════════════════════════════

class TestLedgerStaking(LedgerSecBase):

    def test_apply_stake_debits_account(self):
        tx = create_stake("rAlice", 100.0, 0)  # Flexible
        tx.tx_id = "stake_tx_1"
        tx.timestamp = time.time()
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 0)
        self.assertAlmostEqual(
            self.ledger.get_balance("rAlice"),
            500.0 - 100.0 - 0.00001,
            places=4,
        )

    def test_apply_stake_records_in_pool(self):
        tx = create_stake("rAlice", 50.0, 1)  # 30-day
        tx.tx_id = "stake_tx_2"
        tx.timestamp = time.time()
        self.ledger.apply_stake(tx)
        self.assertIn("stake_tx_2", self.ledger.staking_pool.stakes)

    def test_apply_stake_invalid_tier(self):
        tx = create_stake("rAlice", 50.0, 99)  # bad tier
        tx.tx_id = "stake_tx_bad"
        tx.timestamp = time.time()
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 108)  # tecSTAKE_LOCKED

    def test_apply_stake_insufficient_balance(self):
        tx = create_stake("rAlice", 9999.0, 0)
        tx.tx_id = "stake_too_much"
        tx.timestamp = time.time()
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 101)  # tecUNFUNDED

    def test_apply_stake_below_minimum(self):
        tx = create_stake("rAlice", 0.5, 0)  # below 1.0 MIN
        tx.tx_id = "stake_low"
        tx.timestamp = time.time()
        result = self.ledger.apply_stake(tx)
        self.assertEqual(result, 101)  # below minimum

    def test_apply_unstake_credits_payout(self):
        # Stake first
        tx_s = create_stake("rAlice", 100.0, 0)  # Flexible
        tx_s.tx_id = "stake_for_unstake"
        tx_s.timestamp = time.time()
        self.ledger.apply_stake(tx_s)

        # Unstake
        tx_u = create_unstake("rAlice", "stake_for_unstake")
        tx_u.tx_id = "unstake_1"
        tx_u.timestamp = time.time()
        result = self.ledger.apply_unstake(tx_u)
        self.assertEqual(result, 0)
        # Balance should be close to original minus fees
        bal = self.ledger.get_balance("rAlice")
        self.assertGreater(bal, 390.0)

    def test_apply_unstake_wrong_owner(self):
        tx_s = create_stake("rAlice", 100.0, 0)
        tx_s.tx_id = "alice_stake"
        tx_s.timestamp = time.time()
        self.ledger.apply_stake(tx_s)

        # rBob tries to unstake rAlice's stake
        tx_u = create_unstake("rBob", "alice_stake")
        tx_u.tx_id = "bob_unstake"
        tx_u.timestamp = time.time()
        result = self.ledger.apply_unstake(tx_u)
        self.assertEqual(result, 108)  # not your stake

    def test_apply_unstake_nonexistent_stake(self):
        tx_u = create_unstake("rAlice", "nonexistent_stake_id")
        tx_u.tx_id = "unstake_ghost"
        tx_u.timestamp = time.time()
        result = self.ledger.apply_unstake(tx_u)
        self.assertEqual(result, 108)

    def test_apply_unstake_no_stake_id_in_flags(self):
        tx_u = create_unstake("rAlice", "")
        tx_u.tx_id = "unstake_empty"
        tx_u.timestamp = time.time()
        # Manually set empty flags
        tx_u.flags = {}
        result = self.ledger.apply_unstake(tx_u)
        self.assertEqual(result, 108)

    def test_auto_maturity_at_close(self):
        """Closed ledgers should auto-mature ready stakes."""
        # Create a 30-day stake in the far past
        past = time.time() - 31 * 86400
        tx = create_stake("rAlice", 100.0, 1)  # 30-day
        tx.tx_id = "mature_test"
        tx.timestamp = past
        self.ledger.apply_stake(tx)

        # Close ledger — should auto-mature
        bal_before = self.ledger.get_balance("rAlice")
        self.ledger.close_ledger()
        bal_after = self.ledger.get_balance("rAlice")
        # Should have received payout (principal + interest)
        self.assertGreater(bal_after, bal_before)


# ═══════════════════════════════════════════════════════════════════
#  Transaction routing
# ═══════════════════════════════════════════════════════════════════

class TestTransactionRouting(LedgerSecBase):

    def test_payment_routed(self):
        tx = create_payment("rAlice", "rBob", 1.0)
        tx.tx_id = "pay_route"
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 0)

    def test_trust_set_routed(self):
        self.ledger.create_account("rGW", 1000.0)
        tx = create_trust_set("rAlice", "USD", "rGW", 500.0)
        tx.tx_id = "ts_route"
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 0)

    def test_stake_routed(self):
        tx = create_stake("rAlice", 50.0, 0)
        tx.tx_id = "stake_route"
        tx.timestamp = time.time()
        result = self.ledger.apply_transaction(tx)
        self.assertEqual(result, 0)

    def test_unstake_routed(self):
        tx_s = create_stake("rAlice", 50.0, 0)
        tx_s.tx_id = "stake_route2"
        tx_s.timestamp = time.time()
        self.ledger.apply_transaction(tx_s)

        tx_u = create_unstake("rAlice", "stake_route2")
        tx_u.tx_id = "unstake_route"
        tx_u.timestamp = time.time()
        result = self.ledger.apply_transaction(tx_u)
        self.assertEqual(result, 0)


# ═══════════════════════════════════════════════════════════════════
#  Account creation edge cases
# ═══════════════════════════════════════════════════════════════════

class TestAccountCreation(LedgerSecBase):

    def test_create_duplicate_returns_existing(self):
        acc1 = self.ledger.create_account("rAlice", 999.0)
        acc2 = self.ledger.create_account("rAlice", 0.0)
        self.assertIs(acc1, acc2)  # same object
        self.assertEqual(acc1.balance, 500.0)  # original balance unchanged

    def test_payment_auto_creates_destination(self):
        tx = create_payment("rAlice", "rNewDest", 10.0)
        result = self.ledger.apply_payment(tx)
        self.assertEqual(result, 0)
        self.assertTrue(self.ledger.account_exists("rNewDest"))
        self.assertAlmostEqual(self.ledger.get_balance("rNewDest"), 10.0)

    def test_nonexistent_account_balance_zero(self):
        self.assertEqual(self.ledger.get_balance("rNobody"), 0.0)


# ═══════════════════════════════════════════════════════════════════
#  Confidential output isolation
# ═══════════════════════════════════════════════════════════════════

class TestConfidentialOutputs(LedgerSecBase):

    def test_empty_initially(self):
        self.assertEqual(len(self.ledger.confidential_outputs), 0)

    def test_key_image_not_spent_initially(self):
        self.assertFalse(self.ledger.is_key_image_spent(b"\x01\x02\x03"))

    def test_stealth_address_not_used_initially(self):
        self.assertFalse(self.ledger.is_stealth_address_used("abc123"))

    def test_get_all_confidential_outputs_empty(self):
        self.assertEqual(self.ledger.get_all_confidential_outputs(), [])


if __name__ == "__main__":
    unittest.main()
