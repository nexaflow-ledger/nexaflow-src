"""Tests for the MPT (Multi-Purpose Tokens) module."""

import pytest

from nexaflow_core.mpt import (
    MPTManager,
    MPTIssuance,
    MPTHolder,
    MPT_CAN_TRANSFER,
    MPT_CAN_CLAWBACK,
    MPT_REQUIRE_AUTH,
    MPT_CAN_LOCK,
)


@pytest.fixture
def mpt():
    return MPTManager()


class TestMPTIssuanceCreate:
    def test_create_issuance(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1_000_000,
                                             flags=MPT_CAN_TRANSFER, metadata="test")
        assert ok is True
        assert iss is not None
        assert iss.issuer == "rAlice"
        assert iss.max_supply == 1_000_000
        assert iss.flags & MPT_CAN_TRANSFER

    def test_create_issuance_zero_max(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=0, flags=0, metadata="")
        assert ok is True
        assert iss.max_supply == 0  # unlimited

    def test_create_multiple(self, mpt):
        mpt.create_issuance("rAlice", max_supply=100, metadata="a")
        mpt.create_issuance("rAlice", max_supply=200, metadata="b")
        all_iss = [v for v in mpt.issuances.values() if v.issuer == "rAlice"]
        assert len(all_iss) == 2


class TestMPTIssuanceDestroy:
    def test_destroy_issuance(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=100)
        ok2, msg2 = mpt.destroy_issuance("rAlice", iss.issuance_id)
        assert ok2 is True
        assert mpt.issuances.get(iss.issuance_id) is None

    def test_destroy_wrong_owner(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=100)
        ok2, msg2 = mpt.destroy_issuance("rBob", iss.issuance_id)
        assert ok2 is False


class TestMPTAuthorize:
    def test_authorize_holder(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=100,
                                             flags=MPT_REQUIRE_AUTH)
        ok2, msg2 = mpt.authorize(iss.issuance_id, "rBob",
                                   issuer_action=True, issuer="rAlice")
        assert ok2 is True
        holder = mpt.get_holder(iss.issuance_id, "rBob")
        assert holder is not None
        assert holder.authorized is True


class TestMPTMintTransferBurn:
    def test_mint(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        ok2, msg2 = mpt.mint("rAlice", iss.issuance_id, "rBob", 100)
        assert ok2 is True
        holder = mpt.get_holder(iss.issuance_id, "rBob")
        assert holder.balance == 100
        assert iss.outstanding == 100

    def test_mint_exceed_max_supply(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=50,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        ok2, msg2 = mpt.mint("rAlice", iss.issuance_id, "rBob", 51)
        assert ok2 is False

    def test_transfer(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        mpt.authorize(iss.issuance_id, "rCharlie")
        mpt.mint("rAlice", iss.issuance_id, "rBob", 100)
        ok2, msg2, fee = mpt.transfer(iss.issuance_id, "rBob", "rCharlie", 30)
        assert ok2 is True
        bob = mpt.get_holder(iss.issuance_id, "rBob")
        charlie = mpt.get_holder(iss.issuance_id, "rCharlie")
        assert bob.balance == 70
        assert charlie.balance == 30

    def test_transfer_insufficient_balance(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        mpt.authorize(iss.issuance_id, "rCharlie")
        mpt.mint("rAlice", iss.issuance_id, "rBob", 10)
        ok2, msg2, fee = mpt.transfer(iss.issuance_id, "rBob", "rCharlie", 20)
        assert ok2 is False

    def test_burn(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        mpt.mint("rAlice", iss.issuance_id, "rBob", 100)
        ok2, msg2 = mpt.burn(iss.issuance_id, "rBob", 40)
        assert ok2 is True
        holder = mpt.get_holder(iss.issuance_id, "rBob")
        assert holder.balance == 60
        assert iss.outstanding == 60


class TestMPTClawback:
    def test_clawback(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_CLAWBACK | MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        mpt.mint("rAlice", iss.issuance_id, "rBob", 100)
        ok2, msg2 = mpt.clawback("rAlice", iss.issuance_id, "rBob", 50)
        assert ok2 is True
        holder = mpt.get_holder(iss.issuance_id, "rBob")
        assert holder.balance == 50

    def test_clawback_disabled(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        mpt.mint("rAlice", iss.issuance_id, "rBob", 100)
        ok2, msg2 = mpt.clawback("rAlice", iss.issuance_id, "rBob", 50)
        assert ok2 is False


class TestMPTFreeze:
    def test_freeze_holder(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_LOCK | MPT_CAN_TRANSFER)
        mpt.authorize(iss.issuance_id, "rBob")
        ok2, msg2 = mpt.freeze_holder("rAlice", iss.issuance_id, "rBob")
        assert ok2 is True
        holder = mpt.get_holder(iss.issuance_id, "rBob")
        assert holder.frozen is True


class TestMPTAccountBalances:
    def test_get_account_mpt_balances(self, mpt):
        ok1, _, iss1 = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER)
        ok2, _, iss2 = mpt.create_issuance("rAlice", max_supply=2000,
                                             flags=MPT_CAN_TRANSFER)
        mpt.authorize(iss1.issuance_id, "rBob")
        mpt.authorize(iss2.issuance_id, "rBob")
        mpt.mint("rAlice", iss1.issuance_id, "rBob", 10)
        mpt.mint("rAlice", iss2.issuance_id, "rBob", 20)
        balances = mpt.get_account_mpt_balances("rBob")
        assert len(balances) == 2


class TestMPTIssuanceDict:
    def test_to_dict(self, mpt):
        ok, msg, iss = mpt.create_issuance("rAlice", max_supply=1000,
                                             flags=MPT_CAN_TRANSFER, metadata="meta")
        d = iss.to_dict()
        assert d["issuer"] == "rAlice"
        assert d["max_supply"] == 1000
        assert "issuance_id" in d
