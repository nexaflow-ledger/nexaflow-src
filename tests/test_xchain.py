"""Tests for the cross-chain bridge module."""

import pytest

from nexaflow_core.xchain import (
    XChainManager,
    BridgeDefinition,
    ClaimID,
    MIN_WITNESSES,
)


@pytest.fixture
def xchain():
    return XChainManager()


NXF_ISSUE = {"currency": "NXF", "issuer": ""}


class TestBridgeCreation:
    def test_create_bridge(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            locking_chain_door="rDoor",
            issuing_chain_door="rIssueDoor",
            locking_chain_issue=NXF_ISSUE,
            issuing_chain_issue=NXF_ISSUE,
            min_account_create_amount=10.0,
            signal_reward=0.01,
        )
        assert ok is True
        assert bridge is not None
        assert bridge.locking_chain_door == "rDoor"
        assert bridge.issuing_chain_door == "rIssueDoor"

    def test_create_duplicate_bridge_fails(self, xchain):
        xchain.create_bridge("rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        ok, msg, bridge = xchain.create_bridge("rDoor", "rIssueDoor",
                                                NXF_ISSUE, NXF_ISSUE)
        assert ok is False


class TestClaimIDCreation:
    def test_create_claim_id(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        ok2, msg2, claim_id = xchain.create_claim_id(bridge.bridge_id, "rSender")
        assert ok2 is True
        assert isinstance(claim_id, int)

    def test_multiple_claim_ids(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        _, _, c1 = xchain.create_claim_id(bridge.bridge_id, "rS1")
        _, _, c2 = xchain.create_claim_id(bridge.bridge_id, "rS2")
        assert c1 != c2


class TestXChainCommit:
    def test_commit(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        _, _, claim_id = xchain.create_claim_id(bridge.bridge_id, "rSender")
        ok2, msg2 = xchain.commit(bridge.bridge_id, "rSender", 100.0,
                                   claim_id, "rDest")
        assert ok2 is True

    def test_commit_invalid_bridge(self, xchain):
        ok, msg = xchain.commit("bad-bridge", "rSender", 100.0, 1, "rDest")
        assert ok is False


class TestXChainAttestation:
    def test_add_attestation(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        _, _, claim_id = xchain.create_claim_id(bridge.bridge_id, "rSender")
        xchain.commit(bridge.bridge_id, "rSender", 100.0, claim_id, "rDest")
        ok2, msg2 = xchain.add_attestation(bridge.bridge_id, claim_id,
                                            "rW1", "sig1")
        assert ok2 is True

    def test_duplicate_attestation_fails(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        _, _, claim_id = xchain.create_claim_id(bridge.bridge_id, "rSender")
        xchain.commit(bridge.bridge_id, "rSender", 100.0, claim_id, "rDest")
        xchain.add_attestation(bridge.bridge_id, claim_id, "rW1", "sig1")
        ok2, msg2 = xchain.add_attestation(bridge.bridge_id, claim_id,
                                            "rW1", "sig1")
        assert ok2 is False


class TestXChainClaim:
    def test_claim_with_quorum(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        _, _, claim_id = xchain.create_claim_id(bridge.bridge_id, "rSender")
        xchain.commit(bridge.bridge_id, "rSender", 100.0, claim_id, "rDest")
        xchain.add_attestation(bridge.bridge_id, claim_id, "rW1", "sig1")
        ok2, msg2, amount = xchain.claim(bridge.bridge_id, claim_id, "rDest")
        assert ok2 is True
        assert amount > 0

    def test_claim_without_quorum_fails(self, xchain):
        xm = XChainManager(min_witnesses=2)
        ok, msg, bridge = xm.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        _, _, claim_id = xm.create_claim_id(bridge.bridge_id, "rSender")
        xm.commit(bridge.bridge_id, "rSender", 100.0, claim_id, "rDest")
        xm.add_attestation(bridge.bridge_id, claim_id, "rW1", "sig1")
        # Need 2 witnesses, only 1 attested
        ok2, msg2, amount = xm.claim(bridge.bridge_id, claim_id, "rDest")
        assert ok2 is False


class TestXChainAccountCreate:
    def test_account_create_commit(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE,
            min_account_create_amount=10.0)
        ok2, msg2 = xchain.account_create_commit(
            bridge.bridge_id, "rSender", 50.0, "rNewAccount")
        assert ok2 is True

    def test_account_create_below_minimum(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE,
            min_account_create_amount=10.0)
        ok2, msg2 = xchain.account_create_commit(
            bridge.bridge_id, "rSender", 5.0, "rNew")
        assert ok2 is False


class TestBridgeDict:
    def test_to_dict(self, xchain):
        ok, msg, bridge = xchain.create_bridge(
            "rDoor", "rIssueDoor", NXF_ISSUE, NXF_ISSUE)
        d = bridge.to_dict()
        assert d["locking_chain_door"] == "rDoor"
        assert d["issuing_chain_door"] == "rIssueDoor"
        assert "bridge_id" in d
