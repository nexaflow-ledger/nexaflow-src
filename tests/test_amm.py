"""Tests for the AMM (Automated Market Maker) module."""

import math
import pytest

from nexaflow_core.amm import (
    AMMManager,
    AMMPool,
    MAX_TRADING_FEE,
    MAX_VOTES,
    AUCTION_SLOT_DURATION,
)


@pytest.fixture
def amm():
    return AMMManager()


class TestAMMPoolCreation:
    def test_create_pool_basic(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        assert ok is True
        assert pool is not None
        assert pool.asset1_currency == "NXF"
        assert pool.asset2_currency == "USD"
        assert pool.balance1 == 1000.0
        assert pool.balance2 == 500.0
        assert pool.trading_fee == 100
        assert pool.creator == "rAlice"

    def test_create_pool_returns_lp_tokens(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        lp_list = amm.get_account_lp("rAlice")
        assert len(lp_list) > 0
        lp = lp_list[0]
        assert lp["amount"] > 0
        expected = math.sqrt(1000.0 * 500.0)
        assert abs(lp["amount"] - expected) < 0.01

    def test_create_pool_zero_amount_fails(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 0, 100.0, 100)
        assert ok is False

    def test_create_pool_excessive_fee_fails(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 100.0, 100.0, MAX_TRADING_FEE + 1)
        assert ok is False

    def test_get_pools(self, amm):
        amm.create_pool("rAlice", "NXF", "", "USD", "", 100.0, 50.0, 100)
        amm.create_pool("rBob", "NXF", "", "EUR", "", 200.0, 100.0, 50)
        pools = amm.get_pools()
        assert len(pools) == 2


class TestAMMDeposit:
    def test_dual_deposit(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        before1 = pool.balance1
        before2 = pool.balance2
        ok2, msg2, lp_minted = amm.deposit(pool.pool_id, "rBob", amount1=100.0, amount2=50.0)
        assert ok2 is True
        assert pool.balance1 == before1 + 100.0
        assert pool.balance2 == before2 + 50.0
        assert lp_minted > 0

    def test_single_asset_deposit(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2, lp = amm.deposit(pool.pool_id, "rBob", amount1=100.0, amount2=0)
        assert ok2 is True
        assert pool.balance1 == 1100.0

    def test_deposit_nonexistent_pool(self, amm):
        ok, msg, lp = amm.deposit("bad-id", "rBob", 100.0, 50.0)
        assert ok is False


class TestAMMWithdraw:
    def test_withdraw_by_lp_tokens(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        lp_list = amm.get_account_lp("rAlice")
        half = lp_list[0]["amount"] / 2
        ok2, msg2, out1, out2 = amm.withdraw(pool.pool_id, "rAlice", lp_tokens=half)
        assert ok2 is True
        assert out1 > 0
        assert out2 > 0
        assert pool.balance1 < 1000.0
        assert pool.balance2 < 500.0

    def test_withdraw_all(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 100.0, 50.0, 100)
        lp_list = amm.get_account_lp("rAlice")
        total_lp = lp_list[0]["amount"]
        ok2, msg2, out1, out2 = amm.withdraw(pool.pool_id, "rAlice", lp_tokens=total_lp)
        assert ok2 is True

    def test_withdraw_more_than_owned_fails(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 100.0, 50.0, 100)
        lp_list = amm.get_account_lp("rAlice")
        total_lp = lp_list[0]["amount"]
        ok2, msg2, out1, out2 = amm.withdraw(pool.pool_id, "rAlice", lp_tokens=total_lp + 1)
        assert ok2 is False


class TestAMMSwap:
    def test_swap_a_for_b(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2, out_amount = amm.swap(pool.pool_id, "rBob", True, 10.0)
        assert ok2 is True
        assert out_amount > 0
        assert pool.balance1 == 1010.0

    def test_swap_b_for_a(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2, out_amount = amm.swap(pool.pool_id, "rBob", False, 10.0)
        assert ok2 is True
        assert out_amount > 0

    def test_swap_zero_fails(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2, out_amount = amm.swap(pool.pool_id, "rBob", True, 0)
        assert ok2 is False

    def test_swap_nonexistent_pool_fails(self, amm):
        ok2, msg2, out_amount = amm.swap("bad-pool", "rBob", True, 10.0)
        assert ok2 is False


class TestAMMVote:
    def test_vote_trading_fee(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2 = amm.vote(pool.pool_id, "rAlice", 200)
        assert ok2 is True
        assert len(pool.votes) > 0

    def test_vote_excessive_fee_fails(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2 = amm.vote(pool.pool_id, "rAlice", MAX_TRADING_FEE + 1)
        assert ok2 is False


class TestAMMBid:
    def test_bid_for_auction_slot(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        ok2, msg2 = amm.bid(pool.pool_id, "rAlice", 10.0)
        assert ok2 is True
        assert pool.auction_slot is not None
        assert pool.auction_slot.account == "rAlice"


class TestAMMDelete:
    def test_delete_empty_pool(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 100.0, 50.0, 100)
        # Withdraw everything first
        lp_list = amm.get_account_lp("rAlice")
        lp_amount = lp_list[0]["amount"] if lp_list else 0
        amm.withdraw(pool.pool_id, "rAlice", lp_tokens=lp_amount)
        ok2, msg2 = amm.delete_pool(pool.pool_id, "rAlice")
        assert ok2 is True
        assert amm.get_pool(pool.pool_id) is None

    def test_delete_nonempty_pool_fails(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 100.0, 50.0, 100)
        ok2, msg2 = amm.delete_pool(pool.pool_id, "rAlice")
        assert ok2 is False


class TestAMMPoolDict:
    def test_to_dict(self, amm):
        ok, msg, pool = amm.create_pool("rAlice", "NXF", "", "USD", "", 1000.0, 500.0, 100)
        d = pool.to_dict()
        assert d["asset1"]["currency"] == "NXF"
        assert d["asset2"]["currency"] == "USD"
        assert "pool_id" in d
        assert "lp_token_supply" in d
