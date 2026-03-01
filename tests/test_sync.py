"""
Tests for the NexaFlow ledger synchronisation protocol.

Covers:
  - Full snapshot serialisation / deserialisation roundtrip
  - Delta snapshot (incremental) roundtrip
  - Hash-chain verification (accept valid, reject tampered)
  - apply_snapshot correctly updates all ledger state
    (accounts, trust lines, staking, confidential outputs,
     monetary aggregates, applied tx IDs, spent key images)
  - LedgerSyncManager peer selection logic
  - Backward-compatible LEDGER_REQ/RES handling
"""

import asyncio
import copy
import time

import pytest

from nexaflow_core.ledger import (
    Ledger, LedgerHeader, AccountEntry, TrustLineEntry, ConfidentialOutput,
)
from nexaflow_core.staking import StakeRecord, StakeTier, StakingPool
from nexaflow_core.sync import (
    build_full_snapshot,
    build_delta_snapshot,
    apply_snapshot,
    _verify_header_chain,
    _serialise_account,
    _serialise_header,
    _serialise_stake,
    LedgerSyncManager,
    PeerSyncStatus,
    DELTA_THRESHOLD,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def source_ledger():
    """A populated ledger that acts as the 'ahead' peer."""
    ledger = Ledger(total_supply=100_000.0, genesis_account="rGenesis")
    ledger.create_account("rAlice", 5000.0)
    ledger.create_account("rBob", 3000.0)
    ledger.create_account("rGateway", 10000.0)
    ledger.accounts["rGateway"].is_gateway = True

    # Trust lines
    ledger.set_trust_line("rAlice", "USD", "rGateway", 10000.0)
    tl = ledger.get_trust_line("rAlice", "USD", "rGateway")
    tl.balance = 250.0

    ledger.set_trust_line("rBob", "EUR", "rGateway", 5000.0)
    tl2 = ledger.get_trust_line("rBob", "EUR", "rGateway")
    tl2.balance = 100.0

    # Close a few ledgers to build a hash chain
    ledger.close_ledger()
    ledger.close_ledger()
    ledger.close_ledger()

    # Add some applied tx ids
    ledger.applied_tx_ids.add("tx_001")
    ledger.applied_tx_ids.add("tx_002")

    # Monetary tracking
    ledger.total_burned = 0.5
    ledger.total_minted = 10.0

    return ledger


@pytest.fixture
def empty_ledger():
    """A brand-new ledger (the 'behind' peer)."""
    return Ledger(total_supply=100_000.0, genesis_account="rGenesis")


# ── Full snapshot roundtrip ──────────────────────────────────────────


class TestFullSnapshot:
    def test_build_snapshot_has_all_fields(self, source_ledger):
        snap = build_full_snapshot(source_ledger)
        assert snap["type"] == "full"
        assert snap["current_sequence"] == source_ledger.current_sequence
        assert snap["total_supply"] == source_ledger.total_supply
        assert snap["total_burned"] == source_ledger.total_burned
        assert snap["total_minted"] == source_ledger.total_minted
        assert "rAlice" in snap["accounts"]
        assert "rBob" in snap["accounts"]
        assert "rGenesis" in snap["accounts"]
        assert len(snap["closed_ledgers"]) == 3
        assert "tx_001" in snap["applied_tx_ids"]

    def test_full_snapshot_roundtrip(self, source_ledger, empty_ledger):
        """Full snapshot → apply → state matches source."""
        snap = build_full_snapshot(source_ledger)
        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True

        # Sequence
        assert empty_ledger.current_sequence == source_ledger.current_sequence

        # Accounts
        for addr in ("rAlice", "rBob", "rGateway", "rGenesis"):
            src_acc = source_ledger.get_account(addr)
            dst_acc = empty_ledger.get_account(addr)
            assert dst_acc is not None, f"Missing account {addr}"
            assert dst_acc.balance == src_acc.balance
            assert dst_acc.sequence == src_acc.sequence
            assert dst_acc.is_gateway == src_acc.is_gateway

        # Trust lines
        tl = empty_ledger.get_trust_line("rAlice", "USD", "rGateway")
        assert tl is not None
        assert tl.balance == 250.0
        assert tl.limit == 10000.0

        tl2 = empty_ledger.get_trust_line("rBob", "EUR", "rGateway")
        assert tl2 is not None
        assert tl2.balance == 100.0

        # Closed ledgers
        assert len(empty_ledger.closed_ledgers) == 3

        # Monetary aggregates
        assert empty_ledger.total_burned == source_ledger.total_burned
        assert empty_ledger.total_minted == source_ledger.total_minted
        assert empty_ledger.total_supply == source_ledger.total_supply

        # Applied tx IDs
        assert "tx_001" in empty_ledger.applied_tx_ids
        assert "tx_002" in empty_ledger.applied_tx_ids

    def test_snapshot_rejected_when_not_ahead(self, source_ledger):
        """Snapshot with same or lower seq is rejected."""
        snap = build_full_snapshot(source_ledger)
        # Peer that's already at the same sequence
        peer_ledger = Ledger(total_supply=100_000.0)
        peer_ledger.current_sequence = source_ledger.current_sequence + 1
        ok = apply_snapshot(peer_ledger, snap)
        assert ok is False


# ── Delta snapshot ───────────────────────────────────────────────────


class TestDeltaSnapshot:
    def test_delta_contains_only_new_headers(self, source_ledger):
        """Delta since seq 2 should only have headers with seq > 2."""
        delta = build_delta_snapshot(source_ledger, since_seq=2)
        assert delta["type"] == "delta"
        assert delta["since_seq"] == 2
        seqs = [h["sequence"] for h in delta["closed_ledgers"]]
        for s in seqs:
            assert s > 2

    def test_delta_roundtrip(self, source_ledger):
        """Delta snapshot correctly syncs a partially-behind peer."""
        # Create a peer that shares the first closed ledger from the source
        behind = Ledger(total_supply=100_000.0, genesis_account="rGenesis")
        behind.create_account("rAlice", 5000.0)

        # Copy the first closed header from source to simulate shared history
        first_hdr = source_ledger.closed_ledgers[0]
        from nexaflow_core.ledger import LedgerHeader
        hdr_copy = LedgerHeader(first_hdr.sequence, first_hdr.parent_hash)
        hdr_copy.hash = first_hdr.hash
        hdr_copy.tx_hash = first_hdr.tx_hash
        hdr_copy.state_hash = first_hdr.state_hash
        hdr_copy.close_time = first_hdr.close_time
        hdr_copy.tx_count = first_hdr.tx_count
        hdr_copy.total_nxf = first_hdr.total_nxf
        behind.closed_ledgers.append(hdr_copy)
        behind.current_sequence = 2  # just closed seq 1

        delta = build_delta_snapshot(source_ledger, since_seq=1)
        ok = apply_snapshot(behind, delta)
        assert ok is True
        assert behind.current_sequence == source_ledger.current_sequence

        # Should have rBob and rGateway now
        assert behind.get_account("rBob") is not None
        assert behind.get_account("rGateway") is not None


# ── Header chain verification ────────────────────────────────────────


class TestHeaderChainVerification:
    def test_valid_chain_accepted(self, source_ledger):
        snap = build_full_snapshot(source_ledger)
        headers = snap["closed_ledgers"]
        assert _verify_header_chain(headers, "") is True

    def test_empty_chain_accepted(self):
        assert _verify_header_chain([], "anything") is True

    def test_tampered_chain_rejected(self, source_ledger):
        snap = build_full_snapshot(source_ledger)
        headers = snap["closed_ledgers"]
        # Tamper with a hash
        if len(headers) > 1:
            headers[1]["parent_hash"] = "deadbeef" * 8
            assert _verify_header_chain(headers, "") is False

    def test_snapshot_with_bad_chain_rejected(self, source_ledger, empty_ledger):
        """apply_snapshot rejects data with broken hash chain."""
        snap = build_full_snapshot(source_ledger)
        if len(snap["closed_ledgers"]) > 1:
            snap["closed_ledgers"][1]["parent_hash"] = "bad" * 21 + "b"
            ok = apply_snapshot(empty_ledger, snap)
            assert ok is False


# ── Serialisation helpers ────────────────────────────────────────────


class TestSerialisation:
    def test_serialise_account_includes_trust_lines(self, source_ledger):
        acc = source_ledger.get_account("rAlice")
        data = _serialise_account(acc)
        assert data["address"] == "rAlice"
        assert data["balance"] == 5000.0
        assert len(data["trust_lines"]) == 1
        assert data["trust_lines"][0]["currency"] == "USD"
        assert data["trust_lines"][0]["balance"] == 250.0

    def test_serialise_header_roundtrip(self, source_ledger):
        hdr = source_ledger.closed_ledgers[0]
        data = _serialise_header(hdr)
        assert data["sequence"] == hdr.sequence
        assert data["hash"] == hdr.hash
        assert data["parent_hash"] == hdr.parent_hash


# ── Staking sync ─────────────────────────────────────────────────────


class TestStakingSync:
    def test_stakes_synced_in_full_snapshot(self, source_ledger, empty_ledger):
        """Staking records are transferred via full snapshot."""
        pool = source_ledger.staking_pool
        pool.record_stake(
            tx_id="stake_tx_1",
            address="rAlice",
            amount=100.0,
            tier=int(StakeTier.DAYS_30),
            circulating_supply=source_ledger.total_supply,
        )

        snap = build_full_snapshot(source_ledger)
        assert "stake_tx_1" in snap["stakes"]

        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True
        assert "stake_tx_1" in empty_ledger.staking_pool.stakes
        rec = empty_ledger.staking_pool.stakes["stake_tx_1"]
        assert rec.address == "rAlice"
        assert rec.amount == 100.0


# ── Confidential output sync ────────────────────────────────────────


class TestConfidentialSync:
    def test_confidential_outputs_synced(self, source_ledger, empty_ledger):
        """Confidential UTXO outputs are transferred via snapshot."""
        out = ConfidentialOutput(
            b"\x01" * 32,  # commitment
            b"\x02" * 32,  # stealth_addr
            b"\x03" * 33,  # ephemeral_pub
            b"\x04" * 64,  # range_proof
            b"\x05",       # view_tag
            "conf_tx_1",   # tx_id
        )
        sa_hex = out.stealth_addr.hex()
        source_ledger.confidential_outputs[sa_hex] = out

        snap = build_full_snapshot(source_ledger)
        assert sa_hex in snap["confidential_outputs"]

        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True
        assert sa_hex in empty_ledger.confidential_outputs
        restored = empty_ledger.confidential_outputs[sa_hex]
        assert restored.commitment == b"\x01" * 32
        assert restored.tx_id == "conf_tx_1"


# ── Spent key images sync ───────────────────────────────────────────


class TestSpentKeyImagesSync:
    def test_key_images_synced(self, source_ledger, empty_ledger):
        ki = b"\xaa" * 32
        source_ledger.spent_key_images.add(ki)

        snap = build_full_snapshot(source_ledger)
        assert ki.hex() in snap["spent_key_images"]

        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True
        assert ki in empty_ledger.spent_key_images


# ── LedgerSyncManager unit tests ────────────────────────────────────


class TestSyncManagerLogic:
    def test_choose_best_peer_picks_highest_sequence(self):
        """_choose_best_peer picks the peer with highest sequence ahead of local."""

        class FakeP2P:
            node_id = "local"
            peers = {}

            async def send_to_peer(self, *a, **kw):
                return True

        p2p = FakeP2P()
        ledger = Ledger(total_supply=1000.0)
        mgr = LedgerSyncManager(p2p, ledger)

        mgr._peer_statuses = {
            "peer_a": PeerSyncStatus("peer_a", sequence=3, last_hash="aaa"),
            "peer_b": PeerSyncStatus("peer_b", sequence=7, last_hash="bbb"),
            "peer_c": PeerSyncStatus("peer_c", sequence=1, last_hash="ccc"),
        }
        best = mgr._choose_best_peer()
        assert best is not None
        assert best.peer_id == "peer_b"

    def test_choose_best_peer_none_when_not_ahead(self):
        class FakeP2P:
            node_id = "local"
            peers = {}

        p2p = FakeP2P()
        ledger = Ledger(total_supply=1000.0)
        ledger.close_ledger()
        ledger.close_ledger()  # sequence now 3

        mgr = LedgerSyncManager(p2p, ledger)
        mgr._peer_statuses = {
            "peer_a": PeerSyncStatus("peer_a", sequence=2),
            "peer_b": PeerSyncStatus("peer_b", sequence=1),
        }
        assert mgr._choose_best_peer() is None

    def test_handle_sync_status_req_returns_correct_data(self):
        class FakeP2P:
            node_id = "node-1"
            peers = {}

        p2p = FakeP2P()
        ledger = Ledger(total_supply=1000.0)
        ledger.close_ledger()
        mgr = LedgerSyncManager(p2p, ledger)

        result = mgr.handle_sync_status_req({}, "peer_x")
        assert result["node_id"] == "node-1"
        assert result["sequence"] == ledger.current_sequence
        assert result["closed_count"] == 1
        assert len(result["last_hash"]) == 64  # blake2b hex

    def test_handle_sync_delta_req_builds_delta(self, source_ledger):
        class FakeP2P:
            node_id = "node-1"
            peers = {}

        mgr = LedgerSyncManager(FakeP2P(), source_ledger)
        delta = mgr.handle_sync_delta_req({"since_seq": 1}, "peer_x")
        assert delta["type"] == "delta"
        assert delta["current_sequence"] == source_ledger.current_sequence
        # Should have headers with seq > 1
        for h in delta["closed_ledgers"]:
            assert h["sequence"] > 1

    def test_handle_sync_snap_req_builds_full(self, source_ledger):
        class FakeP2P:
            node_id = "node-1"
            peers = {}

        mgr = LedgerSyncManager(FakeP2P(), source_ledger)
        snap = mgr.handle_sync_snap_req({}, "peer_x")
        assert snap["type"] == "full"
        assert "rAlice" in snap["accounts"]

    def test_backward_compat_ledger_request(self, source_ledger, empty_ledger):
        """Legacy LEDGER_REQ/RES works through the sync manager."""

        class FakeP2P:
            node_id = "node-1"
            peers = {}

        mgr_source = LedgerSyncManager(FakeP2P(), source_ledger)
        mgr_dest = LedgerSyncManager(FakeP2P(), empty_ledger)

        # Simulate LEDGER_REQ → LEDGER_RES flow
        response = mgr_source.handle_ledger_request("peer_x")
        mgr_dest.handle_ledger_response(response, "peer_y")

        assert empty_ledger.current_sequence == source_ledger.current_sequence
        assert empty_ledger.get_account("rAlice") is not None

    def test_status_output(self, source_ledger):
        class FakeP2P:
            node_id = "node-1"
            peers = {}

        mgr = LedgerSyncManager(FakeP2P(), source_ledger)
        s = mgr.status()
        assert "syncing" in s
        assert "local_sequence" in s
        assert s["local_sequence"] == source_ledger.current_sequence
