"""Tests for the oracle module."""

import pytest

from nexaflow_core.oracle import (
    OracleManager,
    Oracle,
    PriceEntry,
    MAX_PRICE_ENTRIES,
    MAX_ORACLES_PER_ACCOUNT,
)


@pytest.fixture
def oracles():
    return OracleManager()


class TestOracleCreation:
    def test_set_oracle(self, oracles):
        prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.23, "scale": 1}]
        ok, msg, oracle = oracles.set_oracle("rAlice", prices=prices)
        assert ok is True
        assert oracle is not None
        assert oracle.owner == "rAlice"
        assert len(oracle.prices) == 1

    def test_set_oracle_multi_prices(self, oracles):
        prices = [
            {"base_asset": "NXF", "quote_asset": "USD", "price": 1.0, "scale": 1},
            {"base_asset": "NXF", "quote_asset": "EUR", "price": 1.1, "scale": 1},
        ]
        ok, msg, oracle = oracles.set_oracle("rAlice", prices=prices)
        assert ok is True
        assert len(oracle.prices) == 2

    def test_set_oracle_with_provider(self, oracles):
        prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.0, "scale": 1}]
        ok, msg, oracle = oracles.set_oracle("rAlice", provider="MyProvider", prices=prices)
        assert ok is True
        assert oracle.provider == "MyProvider"

    def test_update_oracle(self, oracles):
        prices1 = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.0, "scale": 1}]
        ok1, msg1, o1 = oracles.set_oracle("rAlice", document_id=1, prices=prices1)
        prices2 = [{"base_asset": "NXF", "quote_asset": "USD", "price": 2.0, "scale": 1}]
        ok2, msg2, o2 = oracles.set_oracle("rAlice", document_id=1, prices=prices2)
        assert ok2 is True
        # Same oracle, updated
        assert o1.oracle_id == o2.oracle_id


class TestOracleDelete:
    def test_delete_oracle(self, oracles):
        prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.0, "scale": 1}]
        ok, msg, oracle = oracles.set_oracle("rAlice", prices=prices)
        ok2, msg2 = oracles.delete_oracle("rAlice", oracle.document_id)
        assert ok2 is True
        assert oracles.get_oracle("rAlice", oracle.document_id) is None

    def test_delete_nonexistent(self, oracles):
        ok, msg = oracles.delete_oracle("rAlice", 999)
        assert ok is False


class TestOracleAggregation:
    def test_aggregate_single_oracle(self, oracles):
        prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 2.5, "scale": 0}]
        oracles.set_oracle("rAlice", prices=prices)
        result = oracles.get_aggregate_price("NXF", "USD")
        assert result is not None
        assert abs(result["mean"] - 2.5) < 0.01

    def test_aggregate_multiple_oracles(self, oracles):
        for i, name in enumerate(["rAlice", "rBob", "rCharlie"]):
            prices = [{"base_asset": "NXF", "quote_asset": "USD",
                        "price": float(1 + i), "scale": 0}]
            oracles.set_oracle(name, prices=prices)
        result = oracles.get_aggregate_price("NXF", "USD", trim=0)
        assert result is not None
        # mean of 1, 2, 3 = 2.0
        assert abs(result["mean"] - 2.0) < 0.01

    def test_aggregate_no_data(self, oracles):
        result = oracles.get_aggregate_price("NXF", "EUR")
        assert result is None


class TestOracleQuery:
    def test_get_oracle(self, oracles):
        prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.0, "scale": 1}]
        ok, msg, oracle = oracles.set_oracle("rAlice", prices=prices)
        fetched = oracles.get_oracle("rAlice", oracle.document_id)
        assert fetched is not None
        assert fetched.oracle_id == oracle.oracle_id

    def test_get_all_oracles(self, oracles):
        for name in ["rAlice", "rBob"]:
            prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.0, "scale": 1}]
            oracles.set_oracle(name, prices=prices)
        all_o = oracles.get_all_oracles()
        assert len(all_o) == 2

    def test_oracle_to_dict(self, oracles):
        prices = [{"base_asset": "NXF", "quote_asset": "USD", "price": 1.5, "scale": 1}]
        ok, msg, oracle = oracles.set_oracle("rAlice", prices=prices)
        d = oracle.to_dict()
        assert d["owner"] == "rAlice"
        assert "oracle_id" in d
