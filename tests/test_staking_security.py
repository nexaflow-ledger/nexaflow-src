"""
Security-focused tests for nexaflow_core.staking — edge cases & invariants.

Covers:
  - StakingPool: record_stake, mature_stakes, cancel_stake
  - Duplicate stake rejection
  - Below-minimum stake rejection
  - Invalid tier rejection
  - Concurrent stakes by same address
  - Cancel already-matured / already-cancelled
  - Cancel nonexistent stake
  - Flexible-tier zero-penalty invariant
  - Locked-tier penalty correctness
  - Demand multiplier boundary conditions
  - StakeRecord.to_dict status labels
  - Pool summary / tier info
  - Total staked accounting
  - Interest accounting after cancel & maturity
"""

import time
import unittest

from nexaflow_core.staking import (
    BASE_INTEREST_PENALTY,
    BASE_PRINCIPAL_PENALTY,
    INTEREST_PENALTY_SCALE,
    MIN_STAKE_AMOUNT,
    PRINCIPAL_PENALTY_SCALE,
    SECONDS_PER_YEAR,
    StakeRecord,
    StakeTier,
    StakingPool,
    TIER_CONFIG,
    TIER_NAMES,
    _interest_penalty_rate,
    _principal_penalty_rate,
    _time_decay,
    compute_demand_multiplier,
    effective_apy,
)


# ═══════════════════════════════════════════════════════════════════
#  StakingPool.record_stake
# ═══════════════════════════════════════════════════════════════════

class TestRecordStake(unittest.TestCase):

    def setUp(self):
        self.pool = StakingPool()
        self.now = time.time()

    def test_basic_record(self):
        rec = self.pool.record_stake("tx1", "rAlice", 100.0, 0, 10000.0, self.now)
        self.assertEqual(rec.stake_id, "tx1")
        self.assertEqual(rec.address, "rAlice")
        self.assertEqual(rec.amount, 100.0)
        self.assertEqual(rec.tier, StakeTier.FLEXIBLE)
        self.assertTrue(rec.is_active)

    def test_total_staked_increments(self):
        self.pool.record_stake("tx1", "rA", 50.0, 0, 10000.0, self.now)
        self.assertEqual(self.pool.total_staked, 50.0)
        self.pool.record_stake("tx2", "rB", 30.0, 1, 10000.0, self.now)
        self.assertEqual(self.pool.total_staked, 80.0)

    def test_duplicate_stake_raises(self):
        self.pool.record_stake("tx1", "rA", 50.0, 0, 10000.0, self.now)
        with self.assertRaises(ValueError):
            self.pool.record_stake("tx1", "rA", 50.0, 0, 10000.0, self.now)

    def test_below_minimum_raises(self):
        with self.assertRaises(ValueError):
            self.pool.record_stake("tx1", "rA", 0.5, 0, 10000.0, self.now)

    def test_exactly_minimum(self):
        rec = self.pool.record_stake("tx1", "rA", MIN_STAKE_AMOUNT, 0, 10000.0, self.now)
        self.assertEqual(rec.amount, MIN_STAKE_AMOUNT)

    def test_invalid_tier_raises(self):
        with self.assertRaises(ValueError):
            self.pool.record_stake("tx1", "rA", 50.0, 99, 10000.0, self.now)

    def test_all_valid_tiers(self):
        for tier in StakeTier:
            rec = self.pool.record_stake(
                f"tx_{tier}", "rA", 10.0, int(tier), 10000.0, self.now,
            )
            self.assertEqual(rec.tier, tier)

    def test_multiple_stakes_same_address(self):
        self.pool.record_stake("tx1", "rA", 10.0, 0, 10000.0, self.now)
        self.pool.record_stake("tx2", "rA", 20.0, 1, 10000.0, self.now)
        active = self.pool.get_active_stakes("rA")
        self.assertEqual(len(active), 2)
        self.assertEqual(self.pool.get_total_staked_for_address("rA"), 30.0)

    def test_stakes_by_address_updated(self):
        self.pool.record_stake("tx1", "rA", 10.0, 0, 10000.0, self.now)
        self.assertIn("tx1", self.pool.stakes_by_address["rA"])


# ═══════════════════════════════════════════════════════════════════
#  StakingPool.mature_stakes
# ═══════════════════════════════════════════════════════════════════

class TestMatureStakes(unittest.TestCase):

    def setUp(self):
        self.pool = StakingPool()

    def test_maturity_payout(self):
        past = time.time() - 31 * 86400  # 31 days ago
        self.pool.record_stake("tx1", "rA", 1000.0, 1, 100000.0, past)  # 30-day tier
        payouts = self.pool.mature_stakes(now=time.time())
        self.assertEqual(len(payouts), 1)
        addr, principal, interest = payouts[0]
        self.assertEqual(addr, "rA")
        self.assertEqual(principal, 1000.0)
        self.assertGreater(interest, 0.0)

    def test_not_yet_mature(self):
        now = time.time()
        self.pool.record_stake("tx1", "rA", 1000.0, 4, 100000.0, now)  # 365-day
        payouts = self.pool.mature_stakes(now=now + 1)
        self.assertEqual(len(payouts), 0)

    def test_flexible_never_matures(self):
        past = time.time() - 365 * 86400
        self.pool.record_stake("tx1", "rA", 100.0, 0, 100000.0, past)
        payouts = self.pool.mature_stakes(now=time.time())
        self.assertEqual(len(payouts), 0)

    def test_already_matured_not_processed_again(self):
        past = time.time() - 31 * 86400
        self.pool.record_stake("tx1", "rA", 100.0, 1, 100000.0, past)
        p1 = self.pool.mature_stakes(now=time.time())
        p2 = self.pool.mature_stakes(now=time.time())
        self.assertEqual(len(p1), 1)
        self.assertEqual(len(p2), 0)  # already matured

    def test_total_staked_decreases_on_maturity(self):
        past = time.time() - 31 * 86400
        self.pool.record_stake("tx1", "rA", 100.0, 1, 100000.0, past)
        self.assertEqual(self.pool.total_staked, 100.0)
        self.pool.mature_stakes(now=time.time())
        self.assertEqual(self.pool.total_staked, 0.0)

    def test_interest_paid_tracks(self):
        past = time.time() - 31 * 86400
        self.pool.record_stake("tx1", "rA", 1000.0, 1, 100000.0, past)
        self.pool.mature_stakes(now=time.time())
        self.assertGreater(self.pool.total_interest_paid, 0.0)


# ═══════════════════════════════════════════════════════════════════
#  StakingPool.cancel_stake
# ═══════════════════════════════════════════════════════════════════

class TestCancelStake(unittest.TestCase):

    def setUp(self):
        self.pool = StakingPool()
        self.now = time.time()

    def test_cancel_flexible_no_penalty(self):
        self.pool.record_stake("tx1", "rA", 100.0, 0, 10000.0, self.now)
        addr, payout, int_forfeited, prin_penalty = self.pool.cancel_stake("tx1", self.now + 1)
        self.assertEqual(addr, "rA")
        # Flexible has zero time_decay → zero penalty
        self.assertAlmostEqual(prin_penalty, 0.0, places=8)
        self.assertAlmostEqual(int_forfeited, 0.0, places=4)
        self.assertGreater(payout, 99.0)

    def test_cancel_locked_has_penalty(self):
        self.pool.record_stake("tx1", "rA", 1000.0, 2, 10000.0, self.now)  # 90-day
        # Cancel immediately → maximum penalty
        addr, payout, int_forfeited, prin_penalty = self.pool.cancel_stake("tx1", self.now + 1)
        self.assertGreater(prin_penalty, 0.0)
        self.assertLess(payout, 1000.0)

    def test_cancel_near_maturity_low_penalty(self):
        # 30-day tier, cancel 29 days in (1 day left)
        self.pool.record_stake("tx1", "rA", 1000.0, 1, 10000.0, self.now)
        cancel_time = self.now + 29 * 86400
        addr, payout, int_forfeited, prin_penalty = self.pool.cancel_stake("tx1", cancel_time)
        # Penalty should be very small (time_decay ≈ 1/30)
        self.assertLess(prin_penalty, 5.0)  # much less than full penalty

    def test_cancel_nonexistent_raises(self):
        with self.assertRaises(ValueError):
            self.pool.cancel_stake("ghost")

    def test_cancel_already_matured_raises(self):
        past = time.time() - 31 * 86400
        self.pool.record_stake("tx1", "rA", 100.0, 1, 10000.0, past)
        self.pool.mature_stakes(now=time.time())
        with self.assertRaises(ValueError):
            self.pool.cancel_stake("tx1")

    def test_cancel_already_cancelled_raises(self):
        self.pool.record_stake("tx1", "rA", 100.0, 0, 10000.0, self.now)
        self.pool.cancel_stake("tx1", self.now + 1)
        with self.assertRaises(ValueError):
            self.pool.cancel_stake("tx1", self.now + 2)

    def test_total_staked_decreases_on_cancel(self):
        self.pool.record_stake("tx1", "rA", 200.0, 0, 10000.0, self.now)
        self.assertEqual(self.pool.total_staked, 200.0)
        self.pool.cancel_stake("tx1", self.now + 1)
        self.assertEqual(self.pool.total_staked, 0.0)


# ═══════════════════════════════════════════════════════════════════
#  StakeRecord helpers
# ═══════════════════════════════════════════════════════════════════

class TestStakeRecordHelpers(unittest.TestCase):

    def _make_record(self, tier=StakeTier.DAYS_90, now=None):
        if now is None:
            now = time.time()
        lock_dur, base = TIER_CONFIG[tier]
        eff = effective_apy(base, 0.0, 100000.0)
        mat = now + lock_dur if lock_dur > 0 else 0.0
        return StakeRecord(
            stake_id="s1", tx_id="s1", address="rA",
            amount=1000.0, tier=tier, base_apy=base,
            effective_apy=eff, lock_duration=lock_dur,
            start_time=now, maturity_time=mat,
        )

    def test_accrued_interest_grows(self):
        now = time.time()
        rec = self._make_record(now=now)
        i1 = rec.accrued_interest(now + 3600)         # 1 hour
        i2 = rec.accrued_interest(now + 2 * 3600)     # 2 hours
        self.assertGreater(i2, i1)

    def test_maturity_interest_positive(self):
        rec = self._make_record()
        self.assertGreater(rec.maturity_interest(), 0.0)

    def test_expected_payout(self):
        rec = self._make_record()
        self.assertEqual(rec.expected_payout(), rec.amount + rec.maturity_interest())

    def test_is_mature_false_at_start(self):
        now = time.time()
        rec = self._make_record(now=now)
        self.assertFalse(rec.is_mature(now))

    def test_is_mature_true_after_lock(self):
        now = time.time()
        rec = self._make_record(StakeTier.DAYS_30, now=now)
        self.assertTrue(rec.is_mature(now + 31 * 86400))

    def test_flexible_never_mature(self):
        now = time.time()
        rec = self._make_record(StakeTier.FLEXIBLE, now=now)
        self.assertFalse(rec.is_mature(now + 999 * 86400))

    def test_to_dict_active_status(self):
        now = time.time()
        rec = self._make_record(now=now)
        d = rec.to_dict(now)
        self.assertEqual(d["status"], "Active")

    def test_to_dict_matured_status(self):
        rec = self._make_record()
        rec.matured = True
        d = rec.to_dict()
        self.assertEqual(d["status"], "Matured")

    def test_to_dict_cancelled_status(self):
        rec = self._make_record()
        rec.cancelled = True
        d = rec.to_dict()
        self.assertEqual(d["status"], "Cancelled")

    def test_to_dict_ready_status(self):
        now = time.time()
        rec = self._make_record(StakeTier.DAYS_30, now=now - 31 * 86400)
        d = rec.to_dict(now)
        self.assertEqual(d["status"], "Ready")

    def test_to_dict_has_all_keys(self):
        rec = self._make_record()
        d = rec.to_dict()
        expected_keys = {
            "stake_id", "tx_id", "address", "amount", "tier", "tier_name",
            "base_apy", "effective_apy", "effective_apy_pct", "lock_duration",
            "start_time", "maturity_time", "accrued_interest", "maturity_interest",
            "expected_payout", "payout_amount", "est_cancel_penalty",
            "matured", "cancelled", "status",
        }
        self.assertEqual(set(d.keys()), expected_keys)


# ═══════════════════════════════════════════════════════════════════
#  Penalty helpers
# ═══════════════════════════════════════════════════════════════════

class TestPenaltyHelpers(unittest.TestCase):

    def test_interest_penalty_monotonic(self):
        """Higher tier APY → higher interest penalty rate."""
        rates = [_interest_penalty_rate(TIER_CONFIG[t][1]) for t in StakeTier]
        for i in range(len(rates) - 1):
            self.assertLessEqual(rates[i], rates[i + 1])

    def test_principal_penalty_monotonic(self):
        rates = [_principal_penalty_rate(TIER_CONFIG[t][1]) for t in StakeTier]
        for i in range(len(rates) - 1):
            self.assertLessEqual(rates[i], rates[i + 1])

    def test_interest_penalty_range(self):
        """Should be between BASE and BASE+SCALE."""
        for tier in StakeTier:
            rate = _interest_penalty_rate(TIER_CONFIG[tier][1])
            self.assertGreaterEqual(rate, BASE_INTEREST_PENALTY - 0.001)
            self.assertLessEqual(rate, BASE_INTEREST_PENALTY + INTEREST_PENALTY_SCALE + 0.001)

    def test_principal_penalty_range(self):
        for tier in StakeTier:
            rate = _principal_penalty_rate(TIER_CONFIG[tier][1])
            self.assertGreaterEqual(rate, BASE_PRINCIPAL_PENALTY - 0.001)
            self.assertLessEqual(rate, BASE_PRINCIPAL_PENALTY + PRINCIPAL_PENALTY_SCALE + 0.001)

    def test_time_decay_at_start(self):
        self.assertAlmostEqual(_time_decay(0, 86400), 1.0)

    def test_time_decay_at_maturity(self):
        self.assertAlmostEqual(_time_decay(86400, 86400), 0.0)

    def test_time_decay_halfway(self):
        self.assertAlmostEqual(_time_decay(43200, 86400), 0.5)

    def test_time_decay_beyond_maturity(self):
        """Past maturity, time_decay should clamp to 0."""
        self.assertAlmostEqual(_time_decay(100000, 86400), 0.0)

    def test_time_decay_flexible_zero(self):
        self.assertAlmostEqual(_time_decay(9999, 0), 0.0)


# ═══════════════════════════════════════════════════════════════════
#  Demand multiplier boundary
# ═══════════════════════════════════════════════════════════════════

class TestDemandMultiplier(unittest.TestCase):

    def test_at_target_ratio(self):
        mult = compute_demand_multiplier(30_000, 100_000)
        self.assertAlmostEqual(mult, 1.0, places=2)

    def test_zero_staked(self):
        mult = compute_demand_multiplier(0, 100_000)
        self.assertGreater(mult, 1.0)
        self.assertLessEqual(mult, 2.0)

    def test_all_staked(self):
        mult = compute_demand_multiplier(100_000, 100_000)
        self.assertGreaterEqual(mult, 0.5)
        self.assertLess(mult, 1.0)

    def test_zero_supply(self):
        mult = compute_demand_multiplier(0, 0)
        self.assertEqual(mult, 1.0)

    def test_negative_supply(self):
        mult = compute_demand_multiplier(0, -100)
        self.assertEqual(mult, 1.0)

    def test_clamped_max(self):
        mult = compute_demand_multiplier(0, 1_000_000_000)
        self.assertLessEqual(mult, 2.0)

    def test_clamped_min(self):
        mult = compute_demand_multiplier(1_000_000_000, 1_000_000_000)
        self.assertGreaterEqual(mult, 0.5)


# ═══════════════════════════════════════════════════════════════════
#  Pool queries
# ═══════════════════════════════════════════════════════════════════

class TestPoolQueries(unittest.TestCase):

    def setUp(self):
        self.pool = StakingPool()
        self.now = time.time()

    def test_get_active_stakes_only_active(self):
        self.pool.record_stake("tx1", "rA", 10.0, 0, 10000.0, self.now)
        self.pool.record_stake("tx2", "rA", 20.0, 0, 10000.0, self.now)
        self.pool.cancel_stake("tx1", self.now + 1)
        active = self.pool.get_active_stakes("rA")
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].stake_id, "tx2")

    def test_get_all_stakes_includes_cancelled(self):
        self.pool.record_stake("tx1", "rA", 10.0, 0, 10000.0, self.now)
        self.pool.cancel_stake("tx1", self.now + 1)
        all_stakes = self.pool.get_all_stakes("rA")
        self.assertEqual(len(all_stakes), 1)

    def test_pool_summary(self):
        self.pool.record_stake("tx1", "rA", 100.0, 0, 10000.0, self.now)
        summary = self.pool.get_pool_summary(self.now)
        self.assertEqual(summary["total_staked"], 100.0)
        self.assertEqual(summary["active_stakes"], 1)
        self.assertEqual(summary["total_stakes"], 1)

    def test_tier_info(self):
        info = self.pool.get_tier_info(100000.0)
        self.assertEqual(len(info), 5)  # 5 tiers
        for tier_info in info:
            self.assertIn("name", tier_info)
            self.assertIn("base_apy", tier_info)
            self.assertIn("effective_apy", tier_info)
            self.assertIn("demand_multiplier", tier_info)

    def test_no_stakes_for_address(self):
        self.assertEqual(self.pool.get_active_stakes("rNobody"), [])
        self.assertEqual(self.pool.get_total_staked_for_address("rNobody"), 0.0)

    def test_demand_multiplier_from_pool(self):
        mult = self.pool.get_demand_multiplier(100000.0)
        self.assertGreater(mult, 0)
        self.assertLessEqual(mult, 2.0)


if __name__ == "__main__":
    unittest.main()
