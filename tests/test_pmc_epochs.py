"""
Tests for PMC difficulty-epoch retargeting and reward halvings.

Covers:
  - Difficulty increase when blocks come too fast
  - Difficulty decrease when blocks come too slow
  - ×4 / ÷4 clamp enforcement
  - Epoch boundary triggers (epoch_length mints)
  - Halving at halving_interval boundary
  - Multiple missed halvings catch-up
  - MIN_BASE_REWARD floor enforcement
  - Disabled retarget (epoch_length=0)
  - Disabled halving (halving_interval=0)
  - Epoch history audit trail (DifficultyEpoch records)
  - Query helpers: get_current_epoch_info, get_epoch_history, list_epochs
  - Integration: mine through full epochs and halvings
  - Combined retarget + halving at same boundary
"""

import math

import pytest

from nexaflow_core.pmc import (
    DEFAULT_BASE_REWARD,
    DEFAULT_EPOCH_LENGTH,
    DEFAULT_HALVING_INTERVAL,
    DEFAULT_TARGET_BLOCK_TIME,
    MAX_RETARGET_FACTOR,
    MIN_BASE_REWARD,
    MIN_RETARGET_FACTOR,
    PMCManager,
    calculate_halving,
    calculate_retarget,
    compute_pow_hash,
    verify_pow,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _mine_n(mgr, coin_id, miner, n, start_time, block_interval):
    """Mine *n* blocks with a fixed time interval between them.

    Returns the new time after the last mint.
    """
    t = start_time
    for _ in range(n):
        prev = mgr._last_pow_hash.get(coin_id, coin_id)
        coin = mgr.coins[coin_id]
        nonce = 0
        while not verify_pow(coin_id, miner, nonce, coin.pow_difficulty, prev):
            nonce += 1
        ok, msg, _ = mgr.mint(coin_id, miner, nonce, now=t)
        assert ok, msg
        t += block_interval
    return t


def _create_coin(mgr, *, pow_difficulty=1, epoch_length=10,
                 target_block_time=60.0, halving_interval=100,
                 base_reward=50.0, max_supply=0.0):
    """Create a simple coin with specified epoch/halving params."""
    ok, msg, coin = mgr.create_coin(
        issuer="rIssuer", symbol="EPOC", name="EpochTestCoin",
        max_supply=max_supply, pow_difficulty=pow_difficulty,
        base_reward=base_reward,
        epoch_length=epoch_length,
        target_block_time=target_block_time,
        halving_interval=halving_interval,
        now=1000.0,
    )
    assert ok, msg
    return coin


# ═════════════════════════════════════════════════════════════════════════
#  Pure algorithm tests
# ═════════════════════════════════════════════════════════════════════════


class TestCalculateRetarget:
    def test_blocks_too_fast_increases_difficulty(self):
        """Blocks arriving 2× faster than target → difficulty should increase."""
        # 10 blocks in 300s (30s avg) vs 60s target → too fast
        new_diff, factor = calculate_retarget(4, 300.0, 10, 60.0)
        assert new_diff > 4
        assert factor > 1.0

    def test_blocks_too_slow_decreases_difficulty(self):
        """Blocks arriving 2× slower than target → difficulty should decrease."""
        # 10 blocks in 1200s (120s avg) vs 60s target → too slow
        new_diff, factor = calculate_retarget(4, 1200.0, 10, 60.0)
        assert new_diff < 4
        assert factor < 1.0

    def test_blocks_on_time_no_change(self):
        """Blocks arriving exactly at target → difficulty unchanged."""
        # 10 blocks in 600s (60s avg) vs 60s target → perfect
        new_diff, factor = calculate_retarget(4, 600.0, 10, 60.0)
        assert new_diff == 4
        assert factor == 1.0

    def test_clamp_max_increase(self):
        """Extremely fast blocks → clamped to ×4 adjustment."""
        # 10 blocks in 1s → insanely fast
        new_diff, factor = calculate_retarget(4, 1.0, 10, 60.0)
        # factor should be capped at MAX_RETARGET_FACTOR (4.0)
        assert factor <= MAX_RETARGET_FACTOR

    def test_clamp_max_decrease(self):
        """Extremely slow blocks → clamped to ÷4 adjustment."""
        # 10 blocks in 1_000_000s
        new_diff, factor = calculate_retarget(4, 1_000_000.0, 10, 60.0)
        assert factor >= MIN_RETARGET_FACTOR

    def test_difficulty_cannot_go_below_1(self):
        """Difficulty 1 with slow blocks should stay at 1 (minimum)."""
        new_diff, _ = calculate_retarget(1, 100_000.0, 10, 60.0)
        assert new_diff >= 1

    def test_zero_mints_no_change(self):
        """Zero mints → no retarget."""
        new_diff, factor = calculate_retarget(4, 0.0, 0, 60.0)
        assert new_diff == 4
        assert factor == 1.0

    def test_zero_time_no_change(self):
        """Zero elapsed time → no retarget."""
        new_diff, factor = calculate_retarget(4, 0.0, 10, 60.0)
        assert new_diff == 4
        assert factor == 1.0


class TestCalculateHalving:
    def test_halving_at_boundary(self):
        """Exactly at halving_interval → halves."""
        new_reward, new_halvings, occurred = calculate_halving(50.0, 100, 100, 0)
        assert occurred is True
        assert new_reward == 25.0
        assert new_halvings == 1

    def test_no_halving_before_boundary(self):
        """Before halving_interval → no change."""
        new_reward, new_halvings, occurred = calculate_halving(50.0, 99, 100, 0)
        assert occurred is False
        assert new_reward == 50.0

    def test_second_halving(self):
        """Second halving at 200 mints with interval=100."""
        new_reward, new_halvings, occurred = calculate_halving(25.0, 200, 100, 1)
        assert occurred is True
        assert new_reward == 12.5
        assert new_halvings == 2

    def test_multiple_missed_halvings(self):
        """If 3 halvings were missed, catch them all up."""
        # 300 mints, interval=100, 0 halvings completed → should apply 3
        new_reward, new_halvings, occurred = calculate_halving(50.0, 300, 100, 0)
        assert occurred is True
        assert new_halvings == 3
        assert new_reward == pytest.approx(50.0 / 8)  # 50 / 2^3

    def test_min_base_reward_floor(self):
        """Halving cannot push reward below MIN_BASE_REWARD."""
        # Many halvings from a tiny reward
        new_reward, _, occurred = calculate_halving(
            MIN_BASE_REWARD * 2, 1000, 10, 99,
        )
        assert new_reward >= MIN_BASE_REWARD

    def test_disabled_halving_interval_zero(self):
        """halving_interval=0 disables halvings."""
        new_reward, new_halvings, occurred = calculate_halving(50.0, 1000, 0, 0)
        assert occurred is False
        assert new_reward == 50.0


# ═════════════════════════════════════════════════════════════════════════
#  Integrated epoch tests via PMCManager.mint()
# ═════════════════════════════════════════════════════════════════════════


class TestEpochRetarget:
    def test_retarget_triggers_at_epoch_boundary(self):
        """After epoch_length mints, a retarget occurs."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        # Mine 10 blocks at 30s intervals (too fast → difficulty should increase)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=30.0)
        assert coin.current_epoch == 1
        # Epoch history should have one record
        epochs = mgr.list_epochs(coin.coin_id)
        assert len(epochs) == 1
        assert epochs[0].epoch_number == 0

    def test_retarget_increases_difficulty_fast_blocks(self):
        """Fast blocks → difficulty increases on retarget."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=1, epoch_length=10,
                            target_block_time=60.0)
        original_diff = coin.pow_difficulty
        # Mine at 1s intervals (way faster than 60s target)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=1.0)
        assert coin.pow_difficulty >= original_diff
        # Epoch record should show the increase
        e = mgr.get_epoch(coin.coin_id, 0)
        assert e is not None
        assert e.new_difficulty >= e.old_difficulty

    def test_retarget_decreases_difficulty_slow_blocks(self):
        """Slow blocks → difficulty decreases on retarget."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=4, epoch_length=10,
                            target_block_time=60.0)
        original_diff = coin.pow_difficulty
        # Mine at 300s intervals (5× slower than 60s target)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=300.0)
        assert coin.pow_difficulty <= original_diff
        e = mgr.get_epoch(coin.coin_id, 0)
        assert e is not None
        assert e.new_difficulty <= e.old_difficulty

    def test_no_retarget_before_epoch_boundary(self):
        """Mining fewer than epoch_length blocks doesn't trigger retarget."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=2, epoch_length=10,
                            target_block_time=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 9, start_time=1100.0, block_interval=1.0)
        assert coin.current_epoch == 0
        assert coin.pow_difficulty == 2
        assert len(mgr.list_epochs(coin.coin_id)) == 0

    def test_epoch_start_resets_after_retarget(self):
        """After retarget, epoch_start_mint and epoch_start_time reset."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        assert coin.epoch_start_mint == 10
        assert coin.epoch_start_time > 0
        assert coin.current_epoch == 1

    def test_two_epochs(self):
        """Mining through two full epochs creates two epoch records."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=1, epoch_length=10,
                            target_block_time=60.0)
        t = _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        t = _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=t, block_interval=60.0)
        assert coin.current_epoch == 2
        assert len(mgr.list_epochs(coin.coin_id)) == 2

    def test_disabled_retarget_epoch_length_zero(self):
        """epoch_length=0 disables retarget — difficulty never changes."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=2, epoch_length=0,
                            target_block_time=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 20, start_time=1100.0, block_interval=1.0)
        assert coin.pow_difficulty == 2
        assert coin.current_epoch == 0
        assert len(mgr.list_epochs(coin.coin_id)) == 0

    def test_mints_until_retarget_property(self):
        """The mints_until_retarget property counts down correctly."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10)
        assert coin.mints_until_retarget == 10
        _mine_n(mgr, coin.coin_id, "rMiner", 3, start_time=1100.0, block_interval=60.0)
        assert coin.mints_until_retarget == 7
        _mine_n(mgr, coin.coin_id, "rMiner", 7, start_time=1400.0, block_interval=60.0)
        # After retarget, resets to epoch_length
        assert coin.mints_until_retarget == 10

    def test_mints_until_retarget_disabled(self):
        """mints_until_retarget returns -1 when disabled."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=0)
        assert coin.mints_until_retarget == -1


# ═════════════════════════════════════════════════════════════════════════
#  Integrated halving tests via PMCManager.mint()
# ═════════════════════════════════════════════════════════════════════════


class TestRewardHalving:
    def test_halving_triggers_at_interval(self):
        """base_reward halves after halving_interval mints."""
        mgr = PMCManager()
        coin = _create_coin(mgr, halving_interval=10, epoch_length=0,
                            base_reward=100.0)
        original_reward = coin.base_reward
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        assert coin.base_reward == original_reward / 2
        assert coin.halvings_completed == 1

    def test_second_halving(self):
        """Two halvings at 10 and 20 mints."""
        mgr = PMCManager()
        coin = _create_coin(mgr, halving_interval=10, epoch_length=0,
                            base_reward=100.0)
        t = _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        assert coin.base_reward == 50.0
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=t, block_interval=60.0)
        assert coin.base_reward == 25.0
        assert coin.halvings_completed == 2

    def test_no_halving_before_interval(self):
        """Before halving_interval mints → no halving."""
        mgr = PMCManager()
        coin = _create_coin(mgr, halving_interval=100, epoch_length=0,
                            base_reward=100.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 99, start_time=1100.0, block_interval=1.0)
        assert coin.base_reward == 100.0
        assert coin.halvings_completed == 0

    def test_disabled_halving_interval_zero(self):
        """halving_interval=0 disables halvings."""
        mgr = PMCManager()
        coin = _create_coin(mgr, halving_interval=0, epoch_length=0,
                            base_reward=100.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 50, start_time=1100.0, block_interval=1.0)
        assert coin.base_reward == 100.0

    def test_mints_until_halving_property(self):
        """The mints_until_halving property counts down correctly."""
        mgr = PMCManager()
        coin = _create_coin(mgr, halving_interval=10, epoch_length=0)
        assert coin.mints_until_halving == 10
        _mine_n(mgr, coin.coin_id, "rMiner", 4, start_time=1100.0, block_interval=60.0)
        assert coin.mints_until_halving == 6

    def test_mints_until_halving_disabled(self):
        """mints_until_halving returns -1 when disabled."""
        mgr = PMCManager()
        coin = _create_coin(mgr, halving_interval=0, epoch_length=0)
        assert coin.mints_until_halving == -1

    def test_halving_with_epoch_retarget(self):
        """Halving and retarget at the same boundary both fire."""
        mgr = PMCManager()
        # Both fire at 10 mints
        coin = _create_coin(mgr, halving_interval=10, epoch_length=10,
                            target_block_time=60.0, base_reward=100.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        # Halving occurred
        assert coin.halvings_completed == 1
        assert coin.base_reward == 50.0
        # Retarget occurred
        assert coin.current_epoch == 1
        epochs = mgr.list_epochs(coin.coin_id)
        assert len(epochs) == 1
        assert epochs[0].halving_occurred is True


# ═════════════════════════════════════════════════════════════════════════
#  Epoch query helpers
# ═════════════════════════════════════════════════════════════════════════


class TestEpochQueries:
    def test_get_current_epoch_info(self):
        """get_current_epoch_info returns in-progress epoch data."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0,
                            halving_interval=100)
        _mine_n(mgr, coin.coin_id, "rMiner", 5, start_time=1100.0, block_interval=60.0)
        info = mgr.get_current_epoch_info(coin.coin_id)
        assert info["epoch_number"] == 0
        assert info["mints_in_epoch"] == 5
        assert info["epoch_length"] == 10
        assert info["mints_remaining"] == 5
        assert info["target_block_time"] == 60.0
        assert info["current_difficulty"] == coin.pow_difficulty
        assert info["halvings_completed"] == 0

    def test_get_current_epoch_info_unknown_coin(self):
        """Unknown coin_id → empty dict."""
        mgr = PMCManager()
        assert mgr.get_current_epoch_info("nonexistent") == {}

    def test_get_epoch_history(self):
        """get_epoch_history returns dicts in creation order."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        t = _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=t, block_interval=60.0)
        history = mgr.get_epoch_history(coin.coin_id)
        assert len(history) == 2
        assert history[0]["epoch_number"] == 0
        assert history[1]["epoch_number"] == 1

    def test_list_epochs_newest_first(self):
        """list_epochs returns epochs newest-first."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        t = _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=t, block_interval=60.0)
        epochs = mgr.list_epochs(coin.coin_id)
        assert epochs[0].epoch_number == 1  # newest
        assert epochs[1].epoch_number == 0

    def test_list_epochs_pagination(self):
        """list_epochs supports limit and offset."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        t = 1100.0
        for _ in range(3):
            t = _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=t, block_interval=60.0)
        all_epochs = mgr.list_epochs(coin.coin_id, limit=50)
        assert len(all_epochs) == 3
        page = mgr.list_epochs(coin.coin_id, limit=1, offset=1)
        assert len(page) == 1
        assert page[0].epoch_number == all_epochs[1].epoch_number

    def test_get_epoch_by_number(self):
        """get_epoch returns a specific epoch record."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        e = mgr.get_epoch(coin.coin_id, 0)
        assert e is not None
        assert e.epoch_number == 0
        assert e.mints_in_epoch == 10

    def test_get_epoch_nonexistent(self):
        """get_epoch returns None for unknown epoch number."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10)
        assert mgr.get_epoch(coin.coin_id, 99) is None


# ═════════════════════════════════════════════════════════════════════════
#  DifficultyEpoch record integrity
# ═════════════════════════════════════════════════════════════════════════


class TestEpochRecordIntegrity:
    def test_epoch_record_fields(self):
        """Epoch record captures all expected fields."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=2, epoch_length=10,
                            target_block_time=60.0, base_reward=100.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        e = mgr.get_epoch(coin.coin_id, 0)
        assert e is not None
        assert e.coin_id == coin.coin_id
        assert e.start_mint == 0
        assert e.end_mint == 10
        assert e.start_time == 1000.0  # epoch_start_time set at coin creation
        assert e.mints_in_epoch == 10
        assert e.target_block_time == 60.0
        assert e.old_difficulty == 2
        assert isinstance(e.new_difficulty, int)
        assert isinstance(e.adjustment_factor, float)

    def test_epoch_to_dict_roundtrip(self):
        """Epoch to_dict produces a proper dict."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, target_block_time=60.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        e = mgr.get_epoch(coin.coin_id, 0)
        d = e.to_dict()
        assert d["epoch_number"] == 0
        assert "old_difficulty" in d
        assert "new_difficulty" in d
        assert "halving_occurred" in d

    def test_halving_epoch_record_has_reward_info(self):
        """When halving occurs at epoch boundary, record has reward detail."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=10, halving_interval=10,
                            target_block_time=60.0, base_reward=100.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=60.0)
        e = mgr.get_epoch(coin.coin_id, 0)
        assert e.halving_occurred is True
        assert e.old_base_reward == 100.0
        assert e.new_base_reward == 50.0


# ═════════════════════════════════════════════════════════════════════════
#  Edge cases
# ═════════════════════════════════════════════════════════════════════════


class TestEpochEdgeCases:
    def test_coin_creation_defaults(self):
        """Default epoch/halving params set correctly on new coin."""
        mgr = PMCManager()
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="DFLT", name="Default",
            max_supply=1_000_000.0, pow_difficulty=4, now=1000.0,
        )
        assert ok
        assert coin.epoch_length == DEFAULT_EPOCH_LENGTH
        assert coin.target_block_time == DEFAULT_TARGET_BLOCK_TIME
        assert coin.halving_interval == DEFAULT_HALVING_INTERVAL
        assert coin.halvings_completed == 0
        assert coin.current_epoch == 0
        assert coin.epoch_start_mint == 0

    def test_reward_scales_with_difficulty(self):
        """Block reward = base_reward × 2^(difficulty-1)."""
        mgr = PMCManager()
        coin = _create_coin(mgr, pow_difficulty=1, base_reward=10.0)
        assert coin.block_reward == 10.0  # 10 × 2^0

        # After retarget increases difficulty, reward should scale
        # Let's verify the property directly for different difficulties
        coin.pow_difficulty = 3
        assert coin.block_reward == 40.0  # 10 × 2^2

    def test_halving_without_retarget(self):
        """epoch_length=0 but halving_interval>0: halvings still fire."""
        mgr = PMCManager()
        coin = _create_coin(mgr, epoch_length=0, halving_interval=10,
                            base_reward=100.0)
        _mine_n(mgr, coin.coin_id, "rMiner", 10, start_time=1100.0, block_interval=1.0)
        assert coin.base_reward == 50.0
        assert coin.halvings_completed == 1
        # No epoch retarget should have occurred
        assert coin.current_epoch == 0
        assert len(mgr.list_epochs(coin.coin_id)) == 0
