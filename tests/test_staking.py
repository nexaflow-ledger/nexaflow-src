"""
Tests for the NexaFlow transaction-based staking system.

Covers:
  - StakeRecord interest computation & penalty algorithm
  - StakingPool record / mature / cancel lifecycle
  - Dynamic interest (demand multiplier)
  - Tier-scaled, time-decayed early-cancellation penalties
  - Ledger-level apply_stake / apply_unstake integration
  - Double-spend prevention
  - Maturity auto-return in close_ledger
"""

import time

import pytest

from nexaflow_core.staking import (
    BASE_INTEREST_PENALTY,
    BASE_PRINCIPAL_PENALTY,
    INTEREST_PENALTY_SCALE,
    MIN_STAKE_AMOUNT,
    PRINCIPAL_PENALTY_SCALE,
    SECONDS_PER_YEAR,
    TIER_CONFIG,
    StakeRecord,
    StakeTier,
    StakingPool,
    compute_demand_multiplier,
    effective_apy,
    _interest_penalty_rate,
    _principal_penalty_rate,
    _time_decay,
)


# Fixtures

@pytest.fixture
def pool():
    return StakingPool()


@pytest.fixture
def staking_ledger():
    from nexaflow_core.ledger import Ledger
    ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
    ledger.create_account("rStaker", 5000.0)
    ledger.fee_pool = 1000.0
    return ledger


def _make_stake_tx(account, amount, tier, tx_id="tx_test_1", seq=0, ts=None):
    from nexaflow_core.transaction import create_stake
    tx = create_stake(account, amount, tier, sequence=seq)
    tx.tx_id = tx_id
    if ts is not None:
        tx.timestamp = int(ts)
    return tx


def _make_unstake_tx(account, stake_id, tx_id="utx_test_1", seq=0, ts=None):
    from nexaflow_core.transaction import create_unstake
    tx = create_unstake(account, stake_id, sequence=seq)
    tx.tx_id = tx_id
    if ts is not None:
        tx.timestamp = int(ts)
    return tx


# Dynamic interest tests

class TestDynamicInterest:
    def test_demand_multiplier_at_target(self):
        m = compute_demand_multiplier(3000, 10000)
        assert m == pytest.approx(1.0, abs=0.01)

    def test_demand_multiplier_low_stake_ratio(self):
        m = compute_demand_multiplier(0, 10000)
        assert m > 1.0
        assert m <= 2.0

    def test_demand_multiplier_high_stake_ratio(self):
        m = compute_demand_multiplier(8000, 10000)
        assert m < 1.0
        assert m >= 0.5

    def test_demand_multiplier_zero_supply(self):
        m = compute_demand_multiplier(100, 0)
        assert m == 1.0

    def test_effective_apy_uses_multiplier(self):
        base = 0.10
        eff = effective_apy(base, 0, 10000)
        assert eff > base


# Penalty algorithm tests

class TestPenaltyAlgorithm:
    def test_interest_penalty_rate_flexible(self):
        rate = _interest_penalty_rate(0.02)
        assert rate == pytest.approx(
            BASE_INTEREST_PENALTY + (0.02 / 0.15) * INTEREST_PENALTY_SCALE,
            rel=1e-4,
        )
        assert rate < 0.60

    def test_interest_penalty_rate_365(self):
        rate = _interest_penalty_rate(0.15)
        assert rate == pytest.approx(
            BASE_INTEREST_PENALTY + INTEREST_PENALTY_SCALE, rel=1e-4
        )
        assert rate == pytest.approx(0.90, rel=1e-4)

    def test_principal_penalty_rate_scales_with_apy(self):
        low = _principal_penalty_rate(0.02)
        high = _principal_penalty_rate(0.15)
        assert high > low
        assert high == pytest.approx(
            BASE_PRINCIPAL_PENALTY + PRINCIPAL_PENALTY_SCALE, rel=1e-4
        )

    def test_time_decay_at_start(self):
        assert _time_decay(0, 86400) == pytest.approx(1.0)

    def test_time_decay_at_maturity(self):
        assert _time_decay(86400, 86400) == pytest.approx(0.0)

    def test_time_decay_at_halfway(self):
        assert _time_decay(43200, 86400) == pytest.approx(0.5)

    def test_time_decay_flexible_always_zero(self):
        assert _time_decay(999, 0) == 0.0

    def test_higher_tier_larger_penalty(self):
        now = time.time()
        r30 = StakeRecord(
            stake_id="r30", tx_id="r30", address="a", amount=1000,
            tier=StakeTier.DAYS_30, base_apy=0.05, effective_apy=0.05,
            lock_duration=30*86400, start_time=now,
            maturity_time=now + 30*86400,
        )
        r365 = StakeRecord(
            stake_id="r365", tx_id="r365", address="a", amount=1000,
            tier=StakeTier.DAYS_365, base_apy=0.15, effective_apy=0.15,
            lock_duration=365*86400, start_time=now,
            maturity_time=now + 365*86400,
        )
        cancel_time = now + 86400
        _, forfeit_30, prin_pen_30 = r30.early_cancel_payout(cancel_time)
        _, forfeit_365, prin_pen_365 = r365.early_cancel_payout(cancel_time)
        assert prin_pen_365 > prin_pen_30

    def test_longer_held_reduces_penalty(self):
        now = time.time()
        lock = 90 * 86400
        r = StakeRecord(
            stake_id="r1", tx_id="r1", address="a", amount=1000,
            tier=StakeTier.DAYS_90, base_apy=0.08, effective_apy=0.08,
            lock_duration=lock, start_time=now,
            maturity_time=now + lock,
        )
        _, _, pen_early = r.early_cancel_payout(now + 1 * 86400)
        _, _, pen_late  = r.early_cancel_payout(now + 80 * 86400)
        assert pen_early > pen_late

    def test_flexible_no_penalty(self):
        now = time.time()
        r = StakeRecord(
            stake_id="rf", tx_id="rf", address="a", amount=1000,
            tier=StakeTier.FLEXIBLE, base_apy=0.02, effective_apy=0.02,
            lock_duration=0, start_time=now, maturity_time=0.0,
        )
        payout, forfeit, prin_pen = r.early_cancel_payout(now + 86400)
        assert forfeit == pytest.approx(0.0)
        assert prin_pen == pytest.approx(0.0)
        expected = 1000 + r.accrued_interest(now + 86400)
        assert payout == pytest.approx(expected, rel=1e-6)


# StakeRecord unit tests

class TestStakeRecord:
    def test_accrued_interest_zero_at_start(self):
        now = time.time()
        r = StakeRecord(
            stake_id="s1", tx_id="s1", address="a", amount=1000,
            tier=StakeTier.FLEXIBLE, base_apy=0.02, effective_apy=0.02,
            lock_duration=0, start_time=now, maturity_time=0.0,
        )
        assert r.accrued_interest(now) == pytest.approx(0.0, abs=1e-9)

    def test_accrued_interest_after_one_year(self):
        now = time.time()
        r = StakeRecord(
            stake_id="s2", tx_id="s2", address="a", amount=1000,
            tier=StakeTier.FLEXIBLE, base_apy=0.10, effective_apy=0.10,
            lock_duration=0, start_time=now, maturity_time=0.0,
        )
        assert r.accrued_interest(now + SECONDS_PER_YEAR) == pytest.approx(100.0, rel=1e-6)

    def test_maturity_interest_locked(self):
        r = StakeRecord(
            stake_id="s3", tx_id="s3", address="a", amount=2000,
            tier=StakeTier.DAYS_180, base_apy=0.12, effective_apy=0.12,
            lock_duration=180*86400, start_time=0, maturity_time=180*86400,
        )
        expected = 2000 * 0.12 * (180 * 86400 / SECONDS_PER_YEAR)
        assert r.maturity_interest() == pytest.approx(expected, rel=1e-4)

    def test_maturity_interest_flexible_is_zero(self):
        r = StakeRecord(
            stake_id="s4", tx_id="s4", address="a", amount=1000,
            tier=StakeTier.FLEXIBLE, base_apy=0.02, effective_apy=0.02,
            lock_duration=0, start_time=0, maturity_time=0.0,
        )
        assert r.maturity_interest() == 0.0

    def test_is_mature(self):
        now = time.time()
        r = StakeRecord(
            stake_id="m1", tx_id="m1", address="a", amount=100,
            tier=StakeTier.DAYS_30, base_apy=0.05, effective_apy=0.05,
            lock_duration=30*86400, start_time=now,
            maturity_time=now + 30*86400,
        )
        assert r.is_mature(now) is False
        assert r.is_mature(now + 31*86400) is True

    def test_is_active_property(self):
        r = StakeRecord(
            stake_id="a1", tx_id="a1", address="a", amount=100,
            tier=StakeTier.FLEXIBLE, base_apy=0.02, effective_apy=0.02,
            lock_duration=0, start_time=0, maturity_time=0.0,
        )
        assert r.is_active is True
        r.cancelled = True
        assert r.is_active is False

    def test_to_dict_includes_all_fields(self):
        now = time.time()
        r = StakeRecord(
            stake_id="d1", tx_id="d1", address="rAlice", amount=500,
            tier=StakeTier.DAYS_90, base_apy=0.08, effective_apy=0.08,
            lock_duration=90*86400, start_time=now,
            maturity_time=now + 90*86400,
        )
        d = r.to_dict(now)
        assert d["stake_id"] == "d1"
        assert d["amount"] == 500.0
        assert d["tier_name"] == "90 Days"
        assert d["status"] == "Active"
        assert "est_cancel_penalty" in d
        assert "effective_apy_pct" in d


# StakingPool tests

class TestStakingPool:
    def test_record_stake(self, pool):
        r = pool.record_stake("tx1", "rAlice", 100, StakeTier.FLEXIBLE)
        assert r.is_active
        assert r.amount == 100.0
        assert r.stake_id == "tx1"
        assert pool.total_staked == 100.0

    def test_record_stake_below_minimum_raises(self, pool):
        with pytest.raises(ValueError, match="Minimum"):
            pool.record_stake("tx2", "rAlice", 0.5, StakeTier.FLEXIBLE)

    def test_record_stake_invalid_tier_raises(self, pool):
        with pytest.raises(ValueError):
            pool.record_stake("tx3", "rAlice", 100, 99)

    def test_record_stake_duplicate_tx_raises(self, pool):
        pool.record_stake("tx4", "rAlice", 100, StakeTier.FLEXIBLE)
        with pytest.raises(ValueError, match="already recorded"):
            pool.record_stake("tx4", "rAlice", 200, StakeTier.FLEXIBLE)

    def test_cancel_stake_flexible(self, pool):
        now = time.time()
        pool.record_stake("tx5", "rAlice", 1000, StakeTier.FLEXIBLE, now=now)
        addr, payout, forfeit, prin_pen = pool.cancel_stake("tx5", now=now + 30*86400)
        assert addr == "rAlice"
        assert forfeit == pytest.approx(0.0)
        assert prin_pen == pytest.approx(0.0)
        assert payout > 1000
        assert pool.total_staked == 0.0

    def test_cancel_stake_locked_with_penalty(self, pool):
        now = time.time()
        pool.record_stake("tx6", "rAlice", 1000, StakeTier.DAYS_90, now=now)
        addr, payout, forfeit, prin_pen = pool.cancel_stake("tx6", now=now + 10*86400)
        assert forfeit > 0
        assert prin_pen > 0
        assert payout < 1000

    def test_cancel_matured_raises(self, pool):
        now = time.time()
        pool.record_stake("tx7", "rAlice", 1000, StakeTier.DAYS_30, now=now)
        pool.mature_stakes(now=now + 31*86400)
        with pytest.raises(ValueError, match="already matured"):
            pool.cancel_stake("tx7", now=now + 32*86400)

    def test_mature_stakes(self, pool):
        now = time.time()
        pool.record_stake("tx8", "rAlice", 500, StakeTier.DAYS_30, now=now)
        payouts = pool.mature_stakes(now=now + 31*86400)
        assert len(payouts) == 1
        addr, principal, interest = payouts[0]
        assert addr == "rAlice"
        assert principal == 500.0
        assert interest > 0
        assert pool.total_staked == 0.0

    def test_mature_stakes_flexible_not_auto_matured(self, pool):
        now = time.time()
        pool.record_stake("tx9", "rAlice", 500, StakeTier.FLEXIBLE, now=now)
        payouts = pool.mature_stakes(now=now + 365*86400)
        assert len(payouts) == 0
        assert pool.total_staked == 500.0

    def test_multiple_stakes_same_address(self, pool):
        pool.record_stake("txa", "rAlice", 100, StakeTier.FLEXIBLE)
        pool.record_stake("txb", "rAlice", 200, StakeTier.DAYS_30)
        assert pool.get_total_staked_for_address("rAlice") == 300.0
        assert len(pool.get_active_stakes("rAlice")) == 2

    def test_pool_summary(self, pool):
        now = time.time()
        pool.record_stake("txc", "rAlice", 500, StakeTier.FLEXIBLE, now=now)
        pool.record_stake("txd", "rBob", 1000, StakeTier.DAYS_90, now=now)
        summary = pool.get_pool_summary(now)
        assert summary["total_staked"] == 1500.0
        assert summary["active_stakes"] == 2

    def test_tier_info(self, pool):
        tiers = pool.get_tier_info(10000.0)
        assert len(tiers) == 5
        assert tiers[0]["name"] == "Flexible"
        assert "effective_apy_pct" in tiers[0]
        assert "demand_multiplier" in tiers[0]

    def test_effective_apy_varies_with_staking(self, pool):
        now = time.time()
        supply = 10_000.0
        r1 = pool.record_stake("txe", "a", 100, StakeTier.DAYS_90,
                               circulating_supply=supply, now=now)
        eff1 = r1.effective_apy
        pool.record_stake("txf", "b", 4000, StakeTier.DAYS_30,
                          circulating_supply=supply, now=now)
        r3 = pool.record_stake("txg", "c", 100, StakeTier.DAYS_90,
                               circulating_supply=supply, now=now)
        assert r3.effective_apy < eff1

    def test_demand_multiplier_method(self, pool):
        m = pool.get_demand_multiplier(10000.0)
        assert 0.5 <= m <= 2.0


# Ledger integration tests

class TestLedgerStaking:
    def test_apply_stake_debits_balance(self, staking_ledger):
        ledger = staking_ledger
        initial = ledger.get_balance("rStaker")
        now = time.time()
        tx = _make_stake_tx("rStaker", 1000, int(StakeTier.FLEXIBLE),
                            tx_id="stk1", ts=now)
        result = ledger.apply_transaction(tx)
        assert result == 0
        expected = initial - 1000 - tx.fee.value
        assert ledger.get_balance("rStaker") == pytest.approx(expected, rel=1e-6)

    def test_apply_stake_records_in_pool(self, staking_ledger):
        ledger = staking_ledger
        tx = _make_stake_tx("rStaker", 500, int(StakeTier.DAYS_30), tx_id="stk2")
        ledger.apply_transaction(tx)
        assert "stk2" in ledger.staking_pool.stakes
        record = ledger.staking_pool.stakes["stk2"]
        assert record.amount == 500.0
        assert record.tier == StakeTier.DAYS_30

    def test_apply_stake_insufficient_balance(self, staking_ledger):
        ledger = staking_ledger
        tx = _make_stake_tx("rStaker", 99999, int(StakeTier.FLEXIBLE), tx_id="stk3")
        result = ledger.apply_transaction(tx)
        assert result == 101

    def test_apply_stake_invalid_tier(self, staking_ledger):
        ledger = staking_ledger
        tx = _make_stake_tx("rStaker", 100, 99, tx_id="stk4")
        result = ledger.apply_transaction(tx)
        assert result == 108

    def test_apply_stake_below_minimum(self, staking_ledger):
        ledger = staking_ledger
        tx = _make_stake_tx("rStaker", 0.5, int(StakeTier.FLEXIBLE), tx_id="stk5")
        result = ledger.apply_transaction(tx)
        assert result == 101

    def test_apply_stake_duplicate_tx_rejected(self, staking_ledger):
        ledger = staking_ledger
        tx1 = _make_stake_tx("rStaker", 100, int(StakeTier.FLEXIBLE), tx_id="stk6")
        assert ledger.apply_transaction(tx1) == 0
        tx2 = _make_stake_tx("rStaker", 100, int(StakeTier.FLEXIBLE), tx_id="stk6")
        assert ledger.apply_transaction(tx2) == 109

    def test_apply_unstake_flexible_no_penalty(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx_stake = _make_stake_tx("rStaker", 1000, int(StakeTier.FLEXIBLE),
                                  tx_id="stk7", seq=0, ts=now)
        ledger.apply_transaction(tx_stake)
        bal_after_stake = ledger.get_balance("rStaker")
        tx_unstake = _make_unstake_tx("rStaker", "stk7",
                                      tx_id="ustk7", seq=0, ts=now + 86400)
        result = ledger.apply_transaction(tx_unstake)
        assert result == 0
        final = ledger.get_balance("rStaker")
        assert final > bal_after_stake

    def test_apply_unstake_locked_with_penalty(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx_stake = _make_stake_tx("rStaker", 1000, int(StakeTier.DAYS_90),
                                  tx_id="stk8", seq=0, ts=now)
        ledger.apply_transaction(tx_stake)
        bal_after_stake = ledger.get_balance("rStaker")
        tx_unstake = _make_unstake_tx("rStaker", "stk8",
                                      tx_id="ustk8", seq=0, ts=now + 5*86400)
        result = ledger.apply_transaction(tx_unstake)
        assert result == 0
        final = ledger.get_balance("rStaker")
        returned = final - bal_after_stake + tx_unstake.fee.value
        assert returned < 1000

    def test_apply_unstake_nonexistent_stake(self, staking_ledger):
        ledger = staking_ledger
        tx = _make_unstake_tx("rStaker", "ghost", tx_id="ustk9")
        result = ledger.apply_transaction(tx)
        assert result == 108

    def test_apply_unstake_wrong_owner(self, staking_ledger):
        ledger = staking_ledger
        ledger.create_account("rOther", 1000.0)
        tx_stake = _make_stake_tx("rStaker", 100, int(StakeTier.FLEXIBLE),
                                  tx_id="stk10")
        ledger.apply_transaction(tx_stake)
        tx_unstake = _make_unstake_tx("rOther", "stk10", tx_id="ustk10")
        result = ledger.apply_transaction(tx_unstake)
        assert result == 108

    def test_maturity_auto_return_in_close_ledger(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx = _make_stake_tx("rStaker", 1000, int(StakeTier.DAYS_30),
                            tx_id="stk11", ts=now)
        ledger.apply_transaction(tx)
        bal_after_stake = ledger.get_balance("rStaker")
        record = ledger.staking_pool.stakes["stk11"]
        record.maturity_time = now - 1
        record.matured = False
        header = ledger.close_ledger()
        final = ledger.get_balance("rStaker")
        assert final > bal_after_stake
        assert record.matured is True

    def test_state_summary_includes_staking(self, staking_ledger):
        ledger = staking_ledger
        tx = _make_stake_tx("rStaker", 100, int(StakeTier.FLEXIBLE), tx_id="stk12")
        ledger.apply_transaction(tx)
        summary = ledger.get_state_summary()
        assert "total_staked" in summary
        assert "active_stakes" in summary
        assert summary["total_staked"] == 100.0
        assert summary["active_stakes"] == 1

    def test_staking_summary_for_address(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx1 = _make_stake_tx("rStaker", 500, int(StakeTier.DAYS_30),
                             tx_id="stk13", ts=now)
        tx2 = _make_stake_tx("rStaker", 300, int(StakeTier.FLEXIBLE),
                             tx_id="stk14", ts=now)
        ledger.apply_transaction(tx1)
        ledger.apply_transaction(tx2)
        summary = ledger.get_staking_summary("rStaker", now=now)
        assert summary["total_staked"] == 800.0
        assert len(summary["stakes"]) == 2
        assert "demand_multiplier" in summary

    def test_interest_increases_with_higher_tier(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx_flex = _make_stake_tx("rStaker", 500, int(StakeTier.FLEXIBLE),
                                 tx_id="stk15", ts=now)
        tx_365 = _make_stake_tx("rStaker", 500, int(StakeTier.DAYS_365),
                                tx_id="stk16", ts=now)
        ledger.apply_transaction(tx_flex)
        ledger.apply_transaction(tx_365)
        pool = ledger.staking_pool
        future = now + 365 * 86400
        i_flex = pool.stakes["stk15"].accrued_interest(future)
        i_365 = pool.stakes["stk16"].accrued_interest(future)
        assert i_365 > i_flex

    def test_penalty_burns_into_fee_pool(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx = _make_stake_tx("rStaker", 1000, int(StakeTier.DAYS_365),
                            tx_id="stk17", ts=now)
        ledger.apply_transaction(tx)
        fee_after_stake = ledger.fee_pool
        tx_u = _make_unstake_tx("rStaker", "stk17",
                                tx_id="ustk17", ts=now + 86400)
        ledger.apply_transaction(tx_u)
        fee_after_cancel = ledger.fee_pool
        assert fee_after_cancel > fee_after_stake

    def test_longer_held_reduces_penalty_integration(self, staking_ledger):
        ledger = staking_ledger
        now = time.time()
        tx1 = _make_stake_tx("rStaker", 500, int(StakeTier.DAYS_90),
                             tx_id="stk18", ts=now)
        ledger.apply_transaction(tx1)
        bal1 = ledger.get_balance("rStaker")
        tx_u1 = _make_unstake_tx("rStaker", "stk18",
                                 tx_id="ustk18", ts=now + 86400)
        ledger.apply_transaction(tx_u1)
        returned_early = ledger.get_balance("rStaker") - bal1
        tx2 = _make_stake_tx("rStaker", 500, int(StakeTier.DAYS_90),
                             tx_id="stk19", ts=now)
        ledger.apply_transaction(tx2)
        bal2 = ledger.get_balance("rStaker")
        tx_u2 = _make_unstake_tx("rStaker", "stk19",
                                 tx_id="ustk19", ts=now + 80*86400)
        ledger.apply_transaction(tx_u2)
        returned_late = ledger.get_balance("rStaker") - bal2
        assert returned_late > returned_early
