"""
Tests for the LMDB-backed PMC persistent storage layer.

Covers:
  - Basic CRUD for every data category (coins, holders, offers, etc.)
  - Composite-key iteration and prefix queries
  - Batch atomic writes
  - Bulk import / export roundtrip
  - PMCManager store integration (write-through and startup recovery)
  - Crash-recovery simulation (close + reopen)
  - Concurrent reader safety
  - Edge cases: empty store, missing keys, unicode, large payloads
  - Store stats / diagnostics
  - Security: malformed data rejection, oversized value handling
"""

import json
import os
import tempfile
import time

import pytest

from nexaflow_core.pmc import (
    DEFAULT_BASE_REWARD,
    DEFAULT_EPOCH_LENGTH,
    DEFAULT_FLAGS,
    DEFAULT_POW_DIFFICULTY,
    DEFAULT_TARGET_BLOCK_TIME,
    DEFAULT_HALVING_INTERVAL,
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


# ── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def store_dir(tmp_path):
    """Provide a temporary directory for the LMDB store."""
    return str(tmp_path / "test_pmc.lmdb")


@pytest.fixture
def store(store_dir):
    """A fresh PMCStore instance."""
    s = PMCStore(store_dir)
    yield s
    s.close()


@pytest.fixture
def sample_coin_dict():
    """A realistic PMCDefinition as a dict."""
    return {
        "coin_id": "abc123def456",
        "symbol": "ZETA",
        "name": "Zeta Coin",
        "issuer": "rIssuer1",
        "decimals": 8,
        "max_supply": 1_000_000.0,
        "total_minted": 500.0,
        "total_burned": 10.0,
        "circulating": 490.0,
        "flags": int(DEFAULT_FLAGS),
        "pow_difficulty": 4,
        "base_reward": 50.0,
        "block_reward": 400.0,
        "total_mints": 10,
        "metadata": "",
        "rules": [],
        "created_at": 1700000000.0,
        "frozen": False,
        "epoch_length": 100,
        "target_block_time": 60.0,
        "halving_interval": 10000,
        "halvings_completed": 0,
        "current_epoch": 0,
        "epoch_start_mint": 0,
        "epoch_start_time": 1700000000.0,
        "mints_until_retarget": 90,
        "mints_until_halving": 9990,
    }


@pytest.fixture
def sample_holder_dict():
    return {
        "account": "rMiner1",
        "coin_id": "abc123def456",
        "balance": 250.0,
        "frozen": False,
        "last_transfer_at": 0.0,
        "last_mint_at": 1700001000.0,
    }


# ═════════════════════════════════════════════════════════════════════════
#  Basic CRUD — Coins
# ═════════════════════════════════════════════════════════════════════════


class TestCoinCRUD:
    def test_put_get_coin(self, store, sample_coin_dict):
        store.put_coin("abc123", sample_coin_dict)
        result = store.get_coin("abc123")
        assert result is not None
        assert result["symbol"] == "ZETA"
        assert result["total_minted"] == 500.0

    def test_get_missing_coin(self, store):
        assert store.get_coin("nonexistent") is None

    def test_delete_coin(self, store, sample_coin_dict):
        store.put_coin("abc123", sample_coin_dict)
        assert store.delete_coin("abc123") is True
        assert store.get_coin("abc123") is None

    def test_delete_missing_coin(self, store):
        assert store.delete_coin("nonexistent") is False

    def test_list_coins(self, store, sample_coin_dict):
        store.put_coin("coin1", sample_coin_dict)
        d2 = dict(sample_coin_dict)
        d2["symbol"] = "BETA"
        store.put_coin("coin2", d2)
        coins = store.list_coins()
        assert len(coins) == 2
        symbols = {c[1]["symbol"] for c in coins}
        assert symbols == {"ZETA", "BETA"}

    def test_coin_count(self, store, sample_coin_dict):
        assert store.coin_count() == 0
        store.put_coin("c1", sample_coin_dict)
        store.put_coin("c2", sample_coin_dict)
        assert store.coin_count() == 2

    def test_overwrite_coin(self, store, sample_coin_dict):
        store.put_coin("c1", sample_coin_dict)
        updated = dict(sample_coin_dict)
        updated["total_minted"] = 999.0
        store.put_coin("c1", updated)
        result = store.get_coin("c1")
        assert result["total_minted"] == 999.0
        assert store.coin_count() == 1


# ═════════════════════════════════════════════════════════════════════════
#  Holders — composite keys
# ═════════════════════════════════════════════════════════════════════════


class TestHolderCRUD:
    def test_put_get_holder(self, store, sample_holder_dict):
        store.put_holder("coin1", "rAlice", sample_holder_dict)
        result = store.get_holder("coin1", "rAlice")
        assert result is not None
        assert result["balance"] == 250.0

    def test_get_missing_holder(self, store):
        assert store.get_holder("coin1", "rAlice") is None

    def test_list_holders_by_coin(self, store):
        store.put_holder("coin1", "rAlice", {"balance": 100.0})
        store.put_holder("coin1", "rBob", {"balance": 200.0})
        store.put_holder("coin2", "rAlice", {"balance": 50.0})

        holders = store.list_holders("coin1")
        assert len(holders) == 2
        accounts = {h[0] for h in holders}
        assert accounts == {"rAlice", "rBob"}

        holders2 = store.list_holders("coin2")
        assert len(holders2) == 1

    def test_delete_holder(self, store):
        store.put_holder("coin1", "rAlice", {"balance": 100.0})
        assert store.delete_holder("coin1", "rAlice") is True
        assert store.get_holder("coin1", "rAlice") is None

    def test_holder_count(self, store):
        store.put_holder("coin1", "rA", {"balance": 1.0})
        store.put_holder("coin1", "rB", {"balance": 2.0})
        assert store.holder_count("coin1") == 2
        assert store.holder_count() == 2


# ═════════════════════════════════════════════════════════════════════════
#  Offers
# ═════════════════════════════════════════════════════════════════════════


class TestOfferCRUD:
    def test_put_get_offer(self, store):
        offer = {"offer_id": "o1", "coin_id": "c1", "amount": 10.0}
        store.put_offer("o1", offer)
        result = store.get_offer("o1")
        assert result["amount"] == 10.0

    def test_list_offers(self, store):
        store.put_offer("o1", {"amount": 10.0})
        store.put_offer("o2", {"amount": 20.0})
        offers = store.list_offers()
        assert len(offers) == 2


# ═════════════════════════════════════════════════════════════════════════
#  PoW hashes
# ═════════════════════════════════════════════════════════════════════════


class TestPoWHashes:
    def test_put_get_pow_hash(self, store):
        store.put_pow_hash("coin1", "0000abcd1234")
        assert store.get_pow_hash("coin1") == "0000abcd1234"

    def test_list_pow_hashes(self, store):
        store.put_pow_hash("c1", "hash1")
        store.put_pow_hash("c2", "hash2")
        hashes = store.list_pow_hashes()
        assert len(hashes) == 2
        assert hashes["c1"] == "hash1"


# ═════════════════════════════════════════════════════════════════════════
#  Pending transactions
# ═════════════════════════════════════════════════════════════════════════


class TestPendingTxs:
    def test_put_get_pending(self, store):
        pool = [{"type": "transfer", "amount": 10.0}, {"type": "burn", "amount": 5.0}]
        store.put_pending_txs("coin1", pool)
        result = store.get_pending_txs("coin1")
        assert len(result) == 2
        assert result[0]["type"] == "transfer"

    def test_empty_pending(self, store):
        assert store.get_pending_txs("nonexistent") == []

    def test_clear_pending(self, store):
        store.put_pending_txs("coin1", [{"a": 1}])
        store.clear_pending_txs("coin1")
        assert store.get_pending_txs("coin1") == []


# ═════════════════════════════════════════════════════════════════════════
#  Commitments
# ═════════════════════════════════════════════════════════════════════════


class TestCommitments:
    def test_put_get_commitment(self, store):
        commit = {"commitment_id": "h1", "miner": "rM", "reward": 400.0}
        store.put_commitment("coin1", 0, commit)
        result = store.get_commitment("coin1", 0)
        assert result["commitment_id"] == "h1"

    def test_list_commitments_ordered(self, store):
        for i in range(5):
            store.put_commitment("coin1", i, {"commitment_id": f"h{i}", "idx": i})
        commits = store.list_commitments("coin1")
        assert len(commits) == 5
        assert commits[0]["idx"] == 0
        assert commits[4]["idx"] == 4

    def test_commitment_count(self, store):
        store.put_commitment("c1", 0, {"x": 1})
        store.put_commitment("c1", 1, {"x": 2})
        store.put_commitment("c2", 0, {"x": 3})
        assert store.commitment_count("c1") == 2
        assert store.commitment_count() == 3


# ═════════════════════════════════════════════════════════════════════════
#  Tx commit index
# ═════════════════════════════════════════════════════════════════════════


class TestTxCommitIdx:
    def test_put_get(self, store):
        store.put_tx_commit_idx("tx_hash_1", "commit_id_1")
        assert store.get_tx_commit_idx("tx_hash_1") == "commit_id_1"

    def test_missing(self, store):
        assert store.get_tx_commit_idx("missing") is None


# ═════════════════════════════════════════════════════════════════════════
#  Epoch history
# ═════════════════════════════════════════════════════════════════════════


class TestEpochHistory:
    def test_put_get_epoch(self, store):
        epoch = {"epoch_number": 0, "old_difficulty": 4, "new_difficulty": 5}
        store.put_epoch("coin1", 0, epoch)
        result = store.get_epoch("coin1", 0)
        assert result["new_difficulty"] == 5

    def test_list_epochs(self, store):
        for i in range(3):
            store.put_epoch("coin1", i, {"epoch_number": i})
        epochs = store.list_epochs("coin1")
        assert len(epochs) == 3
        assert epochs[0]["epoch_number"] == 0
        assert epochs[2]["epoch_number"] == 2


# ═════════════════════════════════════════════════════════════════════════
#  Symbol / Issuer / Offer indices
# ═════════════════════════════════════════════════════════════════════════


class TestIndices:
    def test_symbol_index(self, store):
        store.put_symbol("ZETA", "coin_id_1")
        assert store.get_symbol("ZETA") == "coin_id_1"
        assert store.get_symbol("BETA") is None

    def test_issuer_index(self, store):
        store.put_issuer_coins("rIssuer", ["c1", "c2"])
        result = store.get_issuer_coins("rIssuer")
        assert result == ["c1", "c2"]

    def test_offer_index(self, store):
        store.put_offer_index("coin1", ["o1", "o2"])
        assert store.get_offer_index("coin1") == ["o1", "o2"]
        assert store.get_offer_index("other") == []

    def test_meta(self, store):
        store.put_meta("offer_seq", 42)
        assert store.get_meta("offer_seq") == 42
        assert store.get_meta("missing", 0) == 0


# ═════════════════════════════════════════════════════════════════════════
#  Batch write (atomic)
# ═════════════════════════════════════════════════════════════════════════


class TestBatchWrite:
    def test_atomic_multi_db_write(self, store):
        ops = [
            (b"coins", "c1", {"symbol": "ALPHA"}),
            (b"coins", "c2", {"symbol": "BETA"}),
            (b"pow_hashes", "c1", "hash_alpha"),
            (b"symbol_idx", "ALPHA", "c1"),
        ]
        store.batch_write(ops)
        assert store.get_coin("c1")["symbol"] == "ALPHA"
        assert store.get_coin("c2")["symbol"] == "BETA"
        assert store.get_pow_hash("c1") == "hash_alpha"
        assert store.get_symbol("ALPHA") == "c1"

    def test_batch_with_delete(self, store):
        store.put_coin("c1", {"symbol": "OLD"})
        ops = [
            (b"coins", "c1", None),  # delete
            (b"coins", "c2", {"symbol": "NEW"}),
        ]
        store.batch_write(ops)
        assert store.get_coin("c1") is None
        assert store.get_coin("c2")["symbol"] == "NEW"


# ═════════════════════════════════════════════════════════════════════════
#  Bulk import / export roundtrip
# ═════════════════════════════════════════════════════════════════════════


class TestBulkImportExport:
    def test_roundtrip(self, store, sample_coin_dict):
        # Build a realistic dataset
        data = {
            "coins": {"c1": sample_coin_dict},
            "holders": {"c1": {"rAlice": {"balance": 100.0}, "rBob": {"balance": 200.0}}},
            "offers": {"o1": {"coin_id": "c1", "amount": 50.0}},
            "pow_hashes": {"c1": "0000abcd"},
            "pending_txs": {"c1": [{"type": "transfer"}]},
            "commitments": {"c1": [{"commitment_id": "h1", "reward": 400.0}]},
            "tx_commit_index": {"tx1": "h1"},
            "epoch_history": {"c1": [{"epoch_number": 0, "old_difficulty": 4}]},
            "symbol_index": {"ZETA": "c1"},
            "issuer_index": {"rIssuer1": ["c1"]},
            "offer_index": {"c1": ["o1"]},
            "seq": {"rIssuer1": 1},
            "offer_seq": 1,
        }
        store.import_all(data)

        # Export and verify
        exported = store.export_all()
        assert "c1" in exported["coins"]
        assert exported["coins"]["c1"]["symbol"] == "ZETA"
        assert len(exported["holders"]["c1"]) == 2
        assert exported["pow_hashes"]["c1"] == "0000abcd"
        assert len(exported["commitments"]["c1"]) == 1
        assert exported["symbol_index"]["ZETA"] == "c1"
        assert exported["seq"]["rIssuer1"] == 1
        assert exported["offer_seq"] == 1

    def test_import_overwrites(self, store, sample_coin_dict):
        # First import
        store.import_all({"coins": {"c1": sample_coin_dict}})
        assert store.coin_count() == 1

        # Second import adds more (doesn't clear in this path)
        d2 = dict(sample_coin_dict)
        d2["symbol"] = "BETA"
        store.import_all({"coins": {"c2": d2}})
        # Both coins exist
        assert store.coin_count() == 2

    def test_clear_all(self, store, sample_coin_dict):
        store.put_coin("c1", sample_coin_dict)
        store.put_holder("c1", "rA", {"balance": 1.0})
        store.clear_all()
        assert store.coin_count() == 0
        assert store.holder_count() == 0


# ═════════════════════════════════════════════════════════════════════════
#  PMCManager store integration
# ═════════════════════════════════════════════════════════════════════════


class TestPMCManagerStoreIntegration:
    """Test that PMCManager write-through persistence works."""

    @pytest.fixture
    def managed_store(self, store_dir):
        """A PMCStore and manager pair."""
        s = PMCStore(store_dir)
        mgr = PMCManager(store=s)
        yield mgr, s
        s.close()

    def test_create_coin_persists(self, managed_store):
        mgr, store = managed_store
        ok, msg, coin = mgr.create_coin(
            issuer="rAlice", symbol="ZETA", name="Zeta",
            max_supply=1_000_000.0, pow_difficulty=3, now=1000.0,
        )
        assert ok
        # Verify persisted to LMDB
        stored = store.get_coin(coin.coin_id)
        assert stored is not None
        assert stored["symbol"] == "ZETA"
        # Check symbol index
        assert store.get_symbol("ZETA") == coin.coin_id
        # Check PoW hash
        assert store.get_pow_hash(coin.coin_id) is not None

    def test_mint_persists(self, managed_store):
        mgr, store = managed_store
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="MINT", name="MintCoin",
            pow_difficulty=1, now=1000.0,
        )
        assert ok
        # Find a valid nonce
        prev_hash = mgr._last_pow_hash[coin.coin_id]
        nonce = 0
        while not verify_pow(coin.coin_id, "rMiner", nonce, 1, prev_hash):
            nonce += 1

        ok, msg, reward = mgr.mint(
            coin.coin_id, "rMiner", nonce, now=1001.0,
        )
        assert ok
        assert reward > 0

        # Verify holder persisted
        h = store.get_holder(coin.coin_id, "rMiner")
        assert h is not None
        assert h["balance"] == reward

        # Verify coin state persisted
        c = store.get_coin(coin.coin_id)
        assert c["total_minted"] == reward
        assert c["total_mints"] == 1

        # Verify commitment persisted
        commits = store.list_commitments(coin.coin_id)
        assert len(commits) == 1

    def test_transfer_persists(self, managed_store):
        mgr, store = managed_store
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="XFER", name="TransferCoin",
            pow_difficulty=1, now=1000.0,
        )
        assert ok
        # Mine some coins
        prev_hash = mgr._last_pow_hash[coin.coin_id]
        nonce = 0
        while not verify_pow(coin.coin_id, "rMiner", nonce, 1, prev_hash):
            nonce += 1
        mgr.mint(coin.coin_id, "rMiner", nonce, now=1001.0)

        # Transfer
        ok, msg, royalty = mgr.transfer(
            coin.coin_id, "rMiner", "rBob", 10.0, now=1002.0,
        )
        assert ok

        # Both sender and receiver persisted
        sender_h = store.get_holder(coin.coin_id, "rMiner")
        receiver_h = store.get_holder(coin.coin_id, "rBob")
        assert sender_h is not None
        assert receiver_h is not None
        assert receiver_h["balance"] == 10.0

    def test_burn_persists(self, managed_store):
        mgr, store = managed_store
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="BURN", name="BurnCoin",
            pow_difficulty=1, now=1000.0,
        )
        prev_hash = mgr._last_pow_hash[coin.coin_id]
        nonce = 0
        while not verify_pow(coin.coin_id, "rMiner", nonce, 1, prev_hash):
            nonce += 1
        mgr.mint(coin.coin_id, "rMiner", nonce, now=1001.0)

        ok, msg = mgr.burn(coin.coin_id, "rMiner", 5.0, now=1002.0)
        assert ok

        c = store.get_coin(coin.coin_id)
        assert c["total_burned"] == 5.0

    def test_crash_recovery(self, store_dir):
        """Simulate crash: create store, write data, close, reopen."""
        # Phase 1: create coins and mine
        store1 = PMCStore(store_dir)
        mgr1 = PMCManager(store=store1)
        ok, _, coin = mgr1.create_coin(
            issuer="rIssuer", symbol="CRASH", name="CrashTest",
            pow_difficulty=1, now=1000.0,
        )
        assert ok
        coin_id = coin.coin_id

        # Mine a block
        prev = mgr1._last_pow_hash[coin_id]
        nonce = 0
        while not verify_pow(coin_id, "rM", nonce, 1, prev):
            nonce += 1
        ok, _, reward = mgr1.mint(coin_id, "rM", nonce, now=1001.0)
        assert ok

        # Close (simulate crash)
        store1.close()

        # Phase 2: reopen and verify recovery
        store2 = PMCStore(store_dir)
        mgr2 = PMCManager(store=store2)

        # Coin should be recovered
        recovered_coin = mgr2.get_coin(coin_id)
        assert recovered_coin is not None
        assert recovered_coin.symbol == "CRASH"
        assert recovered_coin.total_minted == reward
        assert recovered_coin.total_mints == 1

        # Holder should be recovered
        assert mgr2.get_balance(coin_id, "rM") == reward

        # Symbol index should work
        by_symbol = mgr2.get_coin_by_symbol("CRASH")
        assert by_symbol is not None
        assert by_symbol.coin_id == coin_id

        # PoW chain should be recovered
        assert mgr2._last_pow_hash.get(coin_id) is not None

        # Commitments should be recovered
        commits = mgr2.list_commitments(coin_id)
        assert len(commits) == 1

        store2.close()

    def test_offer_persist_and_cancel(self, managed_store):
        mgr, store = managed_store
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="DEX", name="DEX Coin",
            pow_difficulty=1, now=1000.0,
        )
        # Mine
        prev = mgr._last_pow_hash[coin.coin_id]
        nonce = 0
        while not verify_pow(coin.coin_id, "rSeller", nonce, 1, prev):
            nonce += 1
        mgr.mint(coin.coin_id, "rSeller", nonce, now=1001.0)

        # Create offer
        ok, _, offer = mgr.create_offer(
            coin.coin_id, "rSeller", is_sell=True, amount=10.0,
            price=1.0, now=1002.0,
        )
        assert ok
        stored = store.get_offer(offer.offer_id)
        assert stored is not None
        assert stored["amount"] == 10.0

        # Cancel
        ok, _ = mgr.cancel_offer(offer.offer_id, "rSeller")
        assert ok
        stored = store.get_offer(offer.offer_id)
        assert stored["cancelled"] is True

    def test_freeze_unfreeze_persist(self, managed_store):
        mgr, store = managed_store
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="FRZ", name="Freeze Coin",
            pow_difficulty=1,
            flags=int(DEFAULT_FLAGS) | 0x0008,  # FREEZABLE
            now=1000.0,
        )
        # Mine to create a holder
        prev = mgr._last_pow_hash[coin.coin_id]
        nonce = 0
        while not verify_pow(coin.coin_id, "rHolder", nonce, 1, prev):
            nonce += 1
        mgr.mint(coin.coin_id, "rHolder", nonce, now=1001.0)

        # Freeze holder
        ok, _ = mgr.freeze_holder(coin.coin_id, "rIssuer", "rHolder")
        assert ok
        h = store.get_holder(coin.coin_id, "rHolder")
        assert h["frozen"] is True

        # Unfreeze
        ok, _ = mgr.unfreeze_holder(coin.coin_id, "rIssuer", "rHolder")
        assert ok
        h = store.get_holder(coin.coin_id, "rHolder")
        assert h["frozen"] is False

        # Freeze coin globally
        ok, _ = mgr.freeze_coin(coin.coin_id, "rIssuer")
        assert ok
        c = store.get_coin(coin.coin_id)
        assert c["frozen"] is True


# ═════════════════════════════════════════════════════════════════════════
#  Edge cases & security
# ═════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_empty_store_operations(self, store):
        assert store.list_coins() == []
        assert store.list_holders("nonexistent") == []
        assert store.list_commitments("x") == []
        assert store.export_all()["coins"] == {}

    def test_unicode_keys(self, store):
        store.put_coin("coin_日本語", {"symbol": "NIHON"})
        result = store.get_coin("coin_日本語")
        assert result["symbol"] == "NIHON"

    def test_large_value(self, store):
        """Store a large metadata blob."""
        big_data = {"data": "x" * 100_000}
        store.put_coin("big", big_data)
        result = store.get_coin("big")
        assert len(result["data"]) == 100_000

    def test_store_stats(self, store, sample_coin_dict):
        store.put_coin("c1", sample_coin_dict)
        store.put_holder("c1", "rA", {"balance": 1.0})
        stats = store.stats()
        assert stats["databases"]["coins"] == 1
        assert stats["databases"]["holders"] == 1
        assert stats["entries_total"] >= 2

    def test_store_repr(self, store, sample_coin_dict):
        store.put_coin("c1", sample_coin_dict)
        r = repr(store)
        assert "PMCStore" in r
        assert "entries=" in r

    def test_close_and_reopen(self, store_dir, sample_coin_dict):
        s1 = PMCStore(store_dir)
        s1.put_coin("c1", sample_coin_dict)
        s1.close()

        s2 = PMCStore(store_dir)
        assert s2.get_coin("c1") is not None
        s2.close()

    def test_sync_flush(self, store):
        store.put_coin("c1", {"symbol": "TEST"})
        store.sync()
        assert store.get_coin("c1") is not None


class TestStoreSecurityEdges:
    """Test that the store handles adversarial / malformed data safely."""

    def test_empty_key_rejected(self, store):
        """LMDB rejects empty keys — verify clean error."""
        import lmdb
        with pytest.raises(lmdb.BadValsizeError):
            store.put_coin("", {"symbol": "EMPTY"})

    def test_special_chars_in_key(self, store):
        store.put_coin("coin:with:colons", {"symbol": "COLON"})
        result = store.get_coin("coin:with:colons")
        assert result["symbol"] == "COLON"

    def test_null_bytes_in_data(self, store):
        """JSON doesn't support null bytes in strings — verify handling."""
        try:
            store.put_coin("c1", {"data": "hello\x00world"})
            result = store.get_coin("c1")
            # JSON may or may not round-trip null bytes
            assert result is not None
        except (ValueError, json.JSONDecodeError):
            pass  # acceptable to reject

    def test_concurrent_readers(self, store_dir, sample_coin_dict):
        """LMDB supports multiple concurrent readers."""
        s1 = PMCStore(store_dir)
        s1.put_coin("c1", sample_coin_dict)

        # Open second reader (readonly)
        s2 = PMCStore(store_dir, readonly=True)
        result = s2.get_coin("c1")
        assert result is not None
        assert result["symbol"] == "ZETA"
        s2.close()
        s1.close()


# ═════════════════════════════════════════════════════════════════════════
#  PMCManager without store (backward compatibility)
# ═════════════════════════════════════════════════════════════════════════


class TestPMCManagerNoStore:
    def test_no_store_default(self):
        """PMCManager works without a store (pure in-memory)."""
        mgr = PMCManager()
        assert mgr._store is None
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="TEST", name="Test",
            pow_difficulty=1, now=1000.0,
        )
        assert ok
        assert coin.symbol == "TEST"

    def test_persist_methods_noop_without_store(self):
        """Persistence methods are no-ops when no store is set."""
        mgr = PMCManager()
        ok, _, coin = mgr.create_coin(
            issuer="rIssuer", symbol="NOOP", name="NoOp",
            pow_difficulty=1, now=1000.0,
        )
        assert ok
        # These should not raise
        mgr._persist_coin(coin.coin_id)
        mgr._persist_holder(coin.coin_id, "rSomeone")
        mgr._persist_pow_hash(coin.coin_id)
        mgr._persist_indices(coin.coin_id)


# ═════════════════════════════════════════════════════════════════════════
#  flush_to_store full roundtrip
# ═════════════════════════════════════════════════════════════════════════


class TestFlushToStore:
    def test_flush_roundtrip(self, store_dir):
        """Build state in-memory, flush to store, reopen and verify."""
        store1 = PMCStore(store_dir)
        mgr1 = PMCManager(store=store1)

        # Create two coins
        ok, _, c1 = mgr1.create_coin(
            issuer="rA", symbol="ALPHA", name="Alpha", pow_difficulty=1, now=1000.0,
        )
        ok2, _, c2 = mgr1.create_coin(
            issuer="rA", symbol="BETA", name="Beta", pow_difficulty=1, now=1000.0,
        )
        assert ok and ok2

        # Mine on both
        for coin in [c1, c2]:
            prev = mgr1._last_pow_hash[coin.coin_id]
            nonce = 0
            while not verify_pow(coin.coin_id, "rM", nonce, 1, prev):
                nonce += 1
            mgr1.mint(coin.coin_id, "rM", nonce, now=1001.0)

        # Flush and close
        mgr1.flush_to_store()
        store1.close()

        # Reopen
        store2 = PMCStore(store_dir)
        mgr2 = PMCManager(store=store2)

        assert len(mgr2.coins) == 2
        assert mgr2.get_coin_by_symbol("ALPHA") is not None
        assert mgr2.get_coin_by_symbol("BETA") is not None
        assert mgr2.get_balance(c1.coin_id, "rM") > 0
        assert mgr2.get_balance(c2.coin_id, "rM") > 0

        store2.close()
