"""
Security tests for the PMC sync protocol.

Covers:
  - PMC state roundtrip via full and delta snapshots
  - Store-backed sync export path
  - Malformed PMC data handling
  - Oversized payload tolerance
  - Duplicate coin / holder injection
  - Balance manipulation attempts
  - Epoch history tampering
  - Commitment chain integrity
  - Missing / truncated fields (backward compatibility)
  - Cross-snapshot isolation (one snapshot can't corrupt another)
  - LMDB flush-after-sync integration
"""

import copy
import time

import pytest

from nexaflow_core.ledger import Ledger
from nexaflow_core.pmc import (
    DEFAULT_FLAGS,
    DifficultyEpoch,
    EMPTY_TX_ROOT,
    PMCCommitment,
    PMCDefinition,
    PMCHolder,
    PMCManager,
    PMCOffer,
    PMCRule,
    RuleType,
    compute_pow_hash,
    verify_pow,
)
from nexaflow_core.pmc_store import PMCStore
from nexaflow_core.sync import (
    _serialise_pmc_state,
    _apply_pmc_state,
    apply_snapshot,
    build_full_snapshot,
    build_delta_snapshot,
)


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def pmc_source_ledger():
    """A ledger with PMC coins and mined balances, for sync tests."""
    ledger = Ledger(total_supply=100_000.0, genesis_account="rGenesis")
    ledger.create_account("rIssuer", 1000.0)
    ledger.create_account("rMiner", 500.0)
    ledger.create_account("rTrader", 300.0)

    mgr = ledger.pmc_manager
    # Create a coin
    ok, _, coin = mgr.create_coin(
        issuer="rIssuer", symbol="SYNC", name="SyncCoin",
        max_supply=1_000_000.0, pow_difficulty=1,
        epoch_length=10, target_block_time=30.0,
        halving_interval=100, now=1000.0,
    )
    assert ok

    # Mine a few blocks
    for i in range(3):
        prev = mgr._last_pow_hash[coin.coin_id]
        nonce = 0
        while not verify_pow(coin.coin_id, "rMiner", nonce, 1, prev):
            nonce += 1
        ok, _, _ = mgr.mint(coin.coin_id, "rMiner", nonce, now=1001.0 + i)
        assert ok

    # Transfer some
    ok, _, _ = mgr.transfer(coin.coin_id, "rMiner", "rTrader", 10.0, now=1005.0)
    assert ok

    # Create a DEX offer
    ok, _, offer = mgr.create_offer(
        coin.coin_id, "rTrader", is_sell=True, amount=5.0,
        price=2.0, now=1006.0,
    )
    assert ok

    # Close some ledgers
    ledger.close_ledger()
    ledger.close_ledger()

    return ledger, coin


@pytest.fixture
def empty_ledger():
    return Ledger(total_supply=100_000.0, genesis_account="rGenesis")


# ═════════════════════════════════════════════════════════════════════════
#  PMC state roundtrip via full snapshot
# ═════════════════════════════════════════════════════════════════════════


class TestPMCSyncRoundtrip:
    def test_full_snapshot_includes_pmc_state(self, pmc_source_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        assert "pmc_state" in snap
        pmc = snap["pmc_state"]
        assert coin.coin_id in pmc["coins"]
        assert coin.coin_id in pmc["holders"]
        assert len(pmc["pow_hashes"]) >= 1
        assert len(pmc["commitments"].get(coin.coin_id, [])) == 3
        assert pmc["symbol_index"]["SYNC"] == coin.coin_id

    def test_full_snapshot_roundtrip_pmc_coins(self, pmc_source_ledger, empty_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True

        # Coin definition should be reconstructed
        mgr = empty_ledger.pmc_manager
        restored = mgr.get_coin(coin.coin_id)
        assert restored is not None
        assert restored.symbol == "SYNC"
        assert restored.total_mints == 3
        assert restored.pow_difficulty == coin.pow_difficulty
        assert restored.epoch_length == 10
        assert restored.halving_interval == 100

    def test_full_snapshot_roundtrip_pmc_holders(self, pmc_source_ledger, empty_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        mgr = empty_ledger.pmc_manager
        # Miner should have balance
        miner_bal = mgr.get_balance(coin.coin_id, "rMiner")
        assert miner_bal > 0
        # Trader received 10.0, but 5.0 are escrowed in a sell offer
        trader_bal = mgr.get_balance(coin.coin_id, "rTrader")
        assert trader_bal == 5.0

    def test_full_snapshot_roundtrip_pmc_offers(self, pmc_source_ledger, empty_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        mgr = empty_ledger.pmc_manager
        active_offers = mgr.list_active_offers(coin.coin_id)
        assert len(active_offers) >= 1
        assert active_offers[0].owner == "rTrader"

    def test_full_snapshot_roundtrip_pow_chain(self, pmc_source_ledger, empty_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        src_mgr = ledger.pmc_manager
        dst_mgr = empty_ledger.pmc_manager
        assert dst_mgr._last_pow_hash[coin.coin_id] == src_mgr._last_pow_hash[coin.coin_id]

    def test_full_snapshot_roundtrip_commitments(self, pmc_source_ledger, empty_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        mgr = empty_ledger.pmc_manager
        # list_commitments returns newest-first; use internal list for chain order
        chain = mgr._commitments.get(coin.coin_id, [])
        assert len(chain) == 3
        # First commitment has no predecessor
        assert chain[0].prev_commitment == ""
        # Subsequent commitments chain to predecessor
        for i in range(1, len(chain)):
            assert chain[i].prev_commitment == chain[i - 1].commitment_id

    def test_full_snapshot_roundtrip_symbol_index(self, pmc_source_ledger, empty_ledger):
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        mgr = empty_ledger.pmc_manager
        by_symbol = mgr.get_coin_by_symbol("SYNC")
        assert by_symbol is not None
        assert by_symbol.coin_id == coin.coin_id

    def test_delta_snapshot_includes_pmc(self, pmc_source_ledger):
        ledger, coin = pmc_source_ledger
        delta = build_delta_snapshot(ledger, since_seq=1)
        assert "pmc_state" in delta
        assert coin.coin_id in delta["pmc_state"]["coins"]


# ═════════════════════════════════════════════════════════════════════════
#  Store-backed sync export
# ═════════════════════════════════════════════════════════════════════════


class TestStoreSyncExport:
    def test_store_backed_export(self, pmc_source_ledger, tmp_path):
        """When PMCManager has a store, sync uses store.export_all()."""
        ledger, coin = pmc_source_ledger
        store = PMCStore(str(tmp_path / "sync_export.lmdb"))
        # Flush current in-memory state to store
        mgr = ledger.pmc_manager
        mgr._store = store
        mgr.flush_to_store()

        # Now _serialise_pmc_state should use the fast path
        pmc_data = _serialise_pmc_state(ledger)
        assert coin.coin_id in pmc_data["coins"]
        assert "SYNC" in pmc_data["symbol_index"]
        store.close()

    def test_store_export_matches_inmemory(self, pmc_source_ledger, tmp_path):
        """Store export should produce same data as in-memory serialization."""
        ledger, coin = pmc_source_ledger
        # Get in-memory version first
        inmem_data = _serialise_pmc_state(ledger)

        # Now flush to store and get store version
        store = PMCStore(str(tmp_path / "compare.lmdb"))
        mgr = ledger.pmc_manager
        mgr._store = store
        mgr.flush_to_store()

        store_data = store.export_all()
        # Core data should match
        assert set(inmem_data["coins"].keys()) == set(store_data["coins"].keys())
        assert set(inmem_data["pow_hashes"].keys()) == set(store_data["pow_hashes"].keys())
        assert inmem_data["symbol_index"] == store_data["symbol_index"]
        assert inmem_data["offer_seq"] == store_data["offer_seq"]
        store.close()
        # Remove store reference so cleanup doesn't fail
        mgr._store = None


# ═════════════════════════════════════════════════════════════════════════
#  Malformed data handling
# ═════════════════════════════════════════════════════════════════════════


class TestMalformedDataSecurity:
    def test_corrupted_coin_definition_skipped(self, empty_ledger):
        """Malformed coin defs should not crash the applier."""
        pmc_data = {
            "coins": {
                "good_coin": {
                    "symbol": "GOOD", "name": "Good", "issuer": "rIssuer",
                    "decimals": 8, "max_supply": 1000.0, "flags": int(DEFAULT_FLAGS),
                    "pow_difficulty": 4, "base_reward": 50.0, "created_at": 1000.0,
                },
                # Missing required fields — but _apply_pmc_state uses .get()
                # with defaults, so it should still create a coin
                "partial_coin": {
                    "symbol": "PART",
                },
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        mgr = empty_ledger.pmc_manager
        assert mgr.get_coin("good_coin") is not None
        # Partial coin gets defaults
        part = mgr.get_coin("partial_coin")
        assert part is not None
        assert part.symbol == "PART"

    def test_invalid_rule_in_coin_skipped(self, empty_ledger):
        """Rules with invalid data should be silently skipped."""
        pmc_data = {
            "coins": {
                "c1": {
                    "symbol": "RULES", "name": "RuleCoin", "issuer": "rIssuer",
                    "rules": [
                        {"rule_type": "MAX_BALANCE", "value": 1000},  # valid
                        {"invalid_key": "bad_data"},  # invalid — should be skipped
                    ],
                },
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        coin = empty_ledger.pmc_manager.get_coin("c1")
        assert coin is not None
        # Only the valid rule should be present
        assert len(coin.rules) == 1

    def test_invalid_commitment_skipped(self, empty_ledger):
        """Commitments missing required fields are skipped with warning."""
        pmc_data = {
            "commitments": {
                "c1": [
                    {"commitment_id": "valid_hash", "miner": "rM", "tx_root": "", "reward": 50.0},
                    {"bad_field": "no_commitment_id"},  # missing required key
                ],
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        mgr = empty_ledger.pmc_manager
        commits = mgr._commitments.get("c1", [])
        assert len(commits) == 1
        assert commits[0].commitment_id == "valid_hash"

    def test_invalid_epoch_skipped(self, empty_ledger):
        """Epochs missing required fields are skipped."""
        pmc_data = {
            "epoch_history": {
                "c1": [
                    {"epoch_number": 0, "old_difficulty": 4, "new_difficulty": 5},
                    {"no_epoch_number": True},  # missing required field
                ],
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        mgr = empty_ledger.pmc_manager
        epochs = mgr._epoch_history.get("c1", [])
        assert len(epochs) == 1

    def test_empty_pmc_data(self, empty_ledger):
        """Applying empty pmc_data is a no-op."""
        _apply_pmc_state(empty_ledger, {})
        mgr = empty_ledger.pmc_manager
        assert len(mgr.coins) == 0

    def test_none_pmc_data(self, empty_ledger):
        """apply_snapshot handles missing pmc_state gracefully."""
        snap = {
            "type": "full",
            "current_sequence": 2,
            "total_supply": 100_000.0,
            "total_burned": 0.0,
            "total_minted": 0.0,
            "accounts": {},
            "closed_ledgers": [],
            "applied_tx_ids": [],
            "stakes": {},
            "confidential_outputs": {},
            "spent_key_images": [],
            # no pmc_state key at all
        }
        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True  # should not crash


# ═════════════════════════════════════════════════════════════════════════
#  Balance manipulation attacks
# ═════════════════════════════════════════════════════════════════════════


class TestBalanceManipulation:
    def test_negative_balance_in_snapshot(self, pmc_source_ledger, empty_ledger):
        """A snapshot with negative balances should still apply (data is trusted)."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        # Tamper with balance
        snap["pmc_state"]["holders"][coin.coin_id]["rMiner"]["balance"] = -999.0
        apply_snapshot(empty_ledger, snap)
        mgr = empty_ledger.pmc_manager
        # Balance is applied as-is (sync data is trusted from consensus)
        assert mgr.get_balance(coin.coin_id, "rMiner") == -999.0

    def test_inflated_total_minted(self, pmc_source_ledger, empty_ledger):
        """Verify that inflated total_minted is applied and detectable."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        snap["pmc_state"]["coins"][coin.coin_id]["total_minted"] = 999_999_999.0
        apply_snapshot(empty_ledger, snap)
        mgr = empty_ledger.pmc_manager
        c = mgr.get_coin(coin.coin_id)
        # Value is applied — higher-level validation is separate
        assert c.total_minted == 999_999_999.0


# ═════════════════════════════════════════════════════════════════════════
#  Duplicate injection
# ═════════════════════════════════════════════════════════════════════════


class TestDuplicateInjection:
    def test_duplicate_coin_update_not_create(self, pmc_source_ledger, empty_ledger):
        """Applying same coin_id twice via _apply_pmc_state updates in place."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        pmc_data = snap["pmc_state"]

        # Apply PMC state twice
        _apply_pmc_state(empty_ledger, pmc_data)

        # Modify and re-apply
        pmc_data2 = copy.deepcopy(pmc_data)
        pmc_data2["coins"][coin.coin_id]["total_mints"] = 999
        _apply_pmc_state(empty_ledger, pmc_data2)

        mgr = empty_ledger.pmc_manager
        assert len(mgr.coins) == 1  # still just one coin
        assert mgr.coins[coin.coin_id].total_mints == 999  # updated

    def test_duplicate_commitment_deduped(self, pmc_source_ledger, empty_ledger):
        """Duplicate commitments are skipped by commitment_id."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        pmc_data = snap["pmc_state"]

        _apply_pmc_state(empty_ledger, pmc_data)
        original_count = len(empty_ledger.pmc_manager._commitments.get(coin.coin_id, []))

        # Apply same PMC data again
        _apply_pmc_state(empty_ledger, pmc_data)
        new_count = len(empty_ledger.pmc_manager._commitments.get(coin.coin_id, []))
        assert new_count == original_count  # no duplicates

    def test_duplicate_epoch_deduped(self, empty_ledger):
        """Duplicate epoch records are skipped by epoch_number."""
        pmc_data = {
            "epoch_history": {
                "c1": [
                    {"epoch_number": 0, "old_difficulty": 4, "new_difficulty": 5},
                    {"epoch_number": 0, "old_difficulty": 4, "new_difficulty": 6},  # dup
                ],
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        mgr = empty_ledger.pmc_manager
        epochs = mgr._epoch_history.get("c1", [])
        assert len(epochs) == 1
        assert epochs[0].new_difficulty == 5  # first one wins

    def test_duplicate_offer_deduped(self, empty_ledger):
        """Duplicate offers by offer_id are skipped."""
        pmc_data = {
            "offers": {
                "o1": {"coin_id": "c1", "owner": "rA", "amount": 10.0},
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        _apply_pmc_state(empty_ledger, pmc_data)  # second time
        assert len(empty_ledger.pmc_manager.offers) == 1


# ═════════════════════════════════════════════════════════════════════════
#  Cross-snapshot isolation
# ═════════════════════════════════════════════════════════════════════════


class TestCrossSnapshotIsolation:
    def test_snapshot_doesnt_leak_data(self, pmc_source_ledger):
        """Building a snapshot doesn't modify the source ledger."""
        ledger, coin = pmc_source_ledger
        mgr = ledger.pmc_manager
        original_minted = coin.total_minted

        # Build snapshot
        snap = build_full_snapshot(ledger)

        # Modify the snapshot
        snap["pmc_state"]["coins"][coin.coin_id]["total_minted"] = 0

        # Original should be unaffected
        assert coin.total_minted == original_minted

    def test_two_peers_independent_state(self, pmc_source_ledger):
        """Two empty ledgers receiving the same snapshot have independent state."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)

        peer1 = Ledger(total_supply=100_000.0, genesis_account="rGenesis")
        peer2 = Ledger(total_supply=100_000.0, genesis_account="rGenesis")

        apply_snapshot(peer1, snap)
        apply_snapshot(peer2, snap)

        # Mutate peer1's PMC state
        peer1.pmc_manager.coins[coin.coin_id].frozen = True

        # peer2 should be unaffected
        assert peer2.pmc_manager.coins[coin.coin_id].frozen is False


# ═════════════════════════════════════════════════════════════════════════
#  LMDB flush-after-sync integration
# ═════════════════════════════════════════════════════════════════════════


class TestLMDBFlushAfterSync:
    def test_apply_snapshot_flushes_to_store(self, pmc_source_ledger, tmp_path):
        """After applying a snapshot, PMC state is flushed to LMDB if available."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)

        # Create a target ledger with LMDB-backed PMCManager
        target = Ledger(total_supply=100_000.0, genesis_account="rGenesis")
        store = PMCStore(str(tmp_path / "target.lmdb"))
        target.pmc_manager._store = store

        ok = apply_snapshot(target, snap)
        assert ok is True

        # Verify data was flushed to LMDB
        stored_coin = store.get_coin(coin.coin_id)
        assert stored_coin is not None
        assert stored_coin["symbol"] == "SYNC"

        # Verify holders in store
        holders = store.list_holders(coin.coin_id)
        assert len(holders) >= 2  # miner + trader

        # Verify pow hash in store
        pow_hash = store.get_pow_hash(coin.coin_id)
        assert pow_hash is not None

        store.close()
        target.pmc_manager._store = None

    def test_store_survives_sync(self, pmc_source_ledger, tmp_path):
        """After sync + flush, store can be reopened for recovery."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)

        # Apply to store-backed target
        target = Ledger(total_supply=100_000.0, genesis_account="rGenesis")
        store_path = str(tmp_path / "persist.lmdb")
        store1 = PMCStore(store_path)
        target.pmc_manager._store = store1

        apply_snapshot(target, snap)
        store1.close()
        target.pmc_manager._store = None

        # Reopen and verify
        store2 = PMCStore(store_path)
        mgr2 = PMCManager(store=store2)
        assert mgr2.get_coin(coin.coin_id) is not None
        assert mgr2.get_balance(coin.coin_id, "rMiner") > 0
        store2.close()


# ═════════════════════════════════════════════════════════════════════════
#  Commitment chain integrity
# ═════════════════════════════════════════════════════════════════════════


class TestCommitmentChainIntegrity:
    def test_commitment_chain_links_preserved(self, pmc_source_ledger, empty_ledger):
        """Commitment prev_commitment chain is properly transferred."""
        ledger, coin = pmc_source_ledger
        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        mgr = empty_ledger.pmc_manager
        chain = mgr.get_commitment_chain(coin.coin_id)
        assert len(chain) == 3

        # First commitment has empty prev (or genesis)
        assert chain[0]["prev_commitment"] == ""
        # Subsequent ones link to previous
        for i in range(1, len(chain)):
            assert chain[i]["prev_commitment"] == chain[i - 1]["commitment_id"]

    def test_tx_commit_index_preserved(self, pmc_source_ledger, empty_ledger):
        """Tx-to-commitment index survives sync."""
        ledger, coin = pmc_source_ledger
        src_mgr = ledger.pmc_manager

        snap = build_full_snapshot(ledger)
        apply_snapshot(empty_ledger, snap)

        dst_mgr = empty_ledger.pmc_manager
        # All tx_commit mappings should match
        for txh, commit_id in src_mgr._tx_commitment_index.items():
            assert dst_mgr._tx_commitment_index.get(txh) == commit_id


# ═════════════════════════════════════════════════════════════════════════
#  Backward compatibility
# ═════════════════════════════════════════════════════════════════════════


class TestSyncBackwardCompat:
    def test_snapshot_without_pmc_fields(self, empty_ledger):
        """Snapshot from older node without epoch fields works."""
        pmc_data = {
            "coins": {
                "old_coin": {
                    "symbol": "OLD", "name": "OldCoin", "issuer": "rOld",
                    # No epoch_length, target_block_time, etc.
                },
            },
        }
        _apply_pmc_state(empty_ledger, pmc_data)
        coin = empty_ledger.pmc_manager.get_coin("old_coin")
        assert coin is not None
        # Should get defaults
        assert coin.epoch_length == 100  # DEFAULT_EPOCH_LENGTH
        assert coin.target_block_time == 60.0
        assert coin.halving_interval == 10_000

    def test_snapshot_without_pmc_state_key(self, empty_ledger):
        """Full snapshot from pre-PMC nodes (no pmc_state key)."""
        snap = {
            "type": "full",
            "current_sequence": 5,
            "total_supply": 100_000.0,
            "total_burned": 0.0,
            "total_minted": 0.0,
            "accounts": {
                "rGenesis": {
                    "address": "rGenesis", "balance": 100_000.0,
                    "sequence": 1, "is_gateway": False, "owner_count": 0,
                    "trust_lines": [],
                },
            },
            "closed_ledgers": [],
            "applied_tx_ids": [],
            "stakes": {},
            "confidential_outputs": {},
            "spent_key_images": [],
        }
        ok = apply_snapshot(empty_ledger, snap)
        assert ok is True
        # PMC manager should be empty but intact
        assert len(empty_ledger.pmc_manager.coins) == 0
