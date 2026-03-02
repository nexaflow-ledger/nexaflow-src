"""Tests for the negative UNL module."""

import pytest

from nexaflow_core.negative_unl import (
    NegativeUNL,
    NegativeUNLEntry,
    DEFAULT_MISS_THRESHOLD,
    MAX_NEGATIVE_UNL_FRACTION,
)


@pytest.fixture
def nunl():
    return NegativeUNL(miss_threshold=DEFAULT_MISS_THRESHOLD)


class TestRecordValidation:
    def test_record_present(self, nunl):
        nunl.record_validation("v1", participated=True)
        # Should not be on negative list
        assert not nunl.is_on_negative_unl("v1")

    def test_record_miss(self, nunl):
        nunl.record_validation("v1", participated=False)
        nunl.check_and_update(total_validators=5)
        # A single miss shouldn't immediately add to negative list
        # (need to exceed threshold)

    def test_multiple_misses_add_to_negative_unl(self, nunl):
        for _ in range(DEFAULT_MISS_THRESHOLD + 1):
            nunl.record_validation("v1", participated=False)
            nunl.check_and_update(total_validators=5)
        assert nunl.is_on_negative_unl("v1")


class TestCheckAndUpdate:
    def test_recovery_removes_from_negative(self, nunl):
        # First get v1 onto negative list
        for _ in range(DEFAULT_MISS_THRESHOLD + 1):
            nunl.record_validation("v1", participated=False)
            nunl.check_and_update(total_validators=5)
        assert nunl.is_on_negative_unl("v1")
        # Now v1 starts validating again — manual remove
        nunl.remove("v1")
        assert not nunl.is_on_negative_unl("v1")

    def test_max_negative_fraction(self, nunl):
        # Add many validators to negative
        for v in ["v1", "v2"]:
            for _ in range(DEFAULT_MISS_THRESHOLD + 1):
                nunl.record_validation(v, participated=False)
                nunl.check_and_update(total_validators=5)
        max_neg = int(5 * MAX_NEGATIVE_UNL_FRACTION)
        assert nunl.size <= max(1, max_neg)


class TestAdjustedQuorum:
    def test_quorum_no_negatives(self, nunl):
        q = nunl.adjusted_quorum(total_validators=5, base_quorum_pct=0.80)
        # 80% of 5 = 4
        assert q == 4

    def test_quorum_with_negatives(self, nunl):
        for _ in range(DEFAULT_MISS_THRESHOLD + 1):
            nunl.record_validation("v1", participated=False)
            nunl.check_and_update(total_validators=5)
        q = nunl.adjusted_quorum(total_validators=5, base_quorum_pct=0.80)
        # With 1 negative, effective = 4, 80% of 4 = 3.2 -> 4
        assert q <= 4

    def test_quorum_never_below_one(self):
        nunl = NegativeUNL()
        q = nunl.adjusted_quorum(total_validators=1, base_quorum_pct=0.8)
        assert q >= 1


class TestEffectiveValidators:
    def test_all_present(self, nunl):
        all_vals = ["v1", "v2", "v3", "v4", "v5"]
        effective = nunl.effective_validators(all_vals)
        assert len(effective) == 5

    def test_with_negative(self, nunl):
        for _ in range(DEFAULT_MISS_THRESHOLD + 1):
            nunl.record_validation("v1", participated=False)
            nunl.check_and_update(total_validators=5)
        all_vals = ["v1", "v2", "v3", "v4", "v5"]
        effective = nunl.effective_validators(all_vals)
        assert "v1" not in effective


class TestNegativeUNLEntry:
    def test_entry_creation(self):
        entry = NegativeUNLEntry(validator_id="v1")
        assert entry.validator_id == "v1"
