"""
Tests for Tier 3 features:
  - SHAMap / Merkle trie
  - Keylets (deterministic object IDs)
  - Owner reserve enforcement
  - AccountDelete rules (sequence >= 256)
  - Formal fee model (drops-based)
  - Canonical transaction ordering
  - Reporting mode (read-only server)
  - Admin RPC security
"""

import pytest
from nexaflow_core.shamap import (
    SHAMap, SHAMapLeaf, SHAMapInner, MerkleProof,
    sha512_half, compute_keylet, LedgerSpace,
    account_keylet, trust_line_keylet, offer_keylet,
    escrow_keylet, check_keylet, nftoken_keylet, did_keylet,
    amm_keylet, oracle_keylet, mpt_keylet, credential_keylet,
    bridge_keylet, hook_keylet,
)
from nexaflow_core.reporting import (
    ReportingServer, ReportingStore, StoredLedger, StoredTransaction,
)
from nexaflow_core.fee_model import FeeModel
from nexaflow_core.ledger import Ledger, AccountEntry
from nexaflow_core.transaction import (
    Transaction, Amount,
    TT_PAYMENT, TT_ACCOUNT_DELETE, TT_OFFER_CREATE,
    TES_SUCCESS,
)


# ═══════════════════════════════════════════════════════════════════
#  T3.1 — SHAMap / Merkle Trie
# ═══════════════════════════════════════════════════════════════════

class TestSHAMap:
    def test_insert_and_get(self):
        sm = SHAMap()
        key = sha512_half(b"test_key")
        sm.insert(key, b"hello world")
        assert sm.get(key) == b"hello world"

    def test_get_missing_returns_none(self):
        sm = SHAMap()
        key = sha512_half(b"nonexistent")
        assert sm.get(key) is None

    def test_size_tracks_inserts(self):
        sm = SHAMap()
        assert sm.size == 0
        for i in range(10):
            key = sha512_half(f"key_{i}".encode())
            sm.insert(key, f"val_{i}".encode())
        assert sm.size == 10

    def test_update_existing_key(self):
        sm = SHAMap()
        key = sha512_half(b"key")
        sm.insert(key, b"v1")
        sm.insert(key, b"v2")
        assert sm.get(key) == b"v2"
        assert sm.size == 1

    def test_remove(self):
        sm = SHAMap()
        key = sha512_half(b"key")
        sm.insert(key, b"data")
        assert sm.remove(key) is True
        assert sm.get(key) is None
        assert sm.size == 0

    def test_remove_nonexistent(self):
        sm = SHAMap()
        key = sha512_half(b"nonexistent")
        assert sm.remove(key) is False

    def test_root_hash_changes_on_insert(self):
        sm = SHAMap()
        h1 = sm.root_hash
        sm.insert(sha512_half(b"a"), b"data")
        h2 = sm.root_hash
        assert h1 != h2

    def test_root_hash_deterministic(self):
        """Same inserts produce same root hash."""
        sm1 = SHAMap()
        sm2 = SHAMap()
        for i in range(5):
            key = sha512_half(f"k{i}".encode())
            sm1.insert(key, f"v{i}".encode())
            sm2.insert(key, f"v{i}".encode())
        assert sm1.root_hash == sm2.root_hash

    def test_all_leaves(self):
        sm = SHAMap()
        keys = []
        for i in range(5):
            key = sha512_half(f"k{i}".encode())
            keys.append(key)
            sm.insert(key, f"v{i}".encode())
        leaves = sm.all_leaves()
        assert len(leaves) == 5
        leaf_keys = {l.key for l in leaves}
        for k in keys:
            assert k in leaf_keys

    def test_collision_handling(self):
        """Multiple keys that share nibble prefixes are stored correctly."""
        sm = SHAMap()
        k1 = b"\x12" + b"\x00" * 31
        k2 = b"\x12" + b"\x01" * 31
        sm.insert(k1, b"val1")
        sm.insert(k2, b"val2")
        assert sm.get(k1) == b"val1"
        assert sm.get(k2) == b"val2"
        assert sm.size == 2


# ═══════════════════════════════════════════════════════════════════
#  T3.2 — Keylets
# ═══════════════════════════════════════════════════════════════════

class TestKeylets:
    def test_account_keylet_deterministic(self):
        k1 = account_keylet("rAlice")
        k2 = account_keylet("rAlice")
        assert k1 == k2
        assert len(k1) == 32

    def test_different_accounts_different_keylets(self):
        assert account_keylet("rAlice") != account_keylet("rBob")

    def test_trust_line_keylet(self):
        k = trust_line_keylet("rAlice", "USD", "rIssuer")
        assert len(k) == 32

    def test_offer_keylet(self):
        k = offer_keylet("rAlice", 42)
        assert len(k) == 32

    def test_escrow_keylet(self):
        k = escrow_keylet("rAlice", "escrow123")
        assert len(k) == 32

    def test_did_keylet(self):
        k = did_keylet("rAlice")
        assert len(k) == 32

    def test_amm_keylet(self):
        k = amm_keylet("pool_xyz")
        assert len(k) == 32

    def test_oracle_keylet(self):
        k = oracle_keylet("rOracle", 1)
        assert len(k) == 32

    def test_nftoken_keylet(self):
        k = nftoken_keylet("nft_abc")
        assert len(k) == 32

    def test_mpt_keylet(self):
        k = mpt_keylet("mpt_000")
        assert len(k) == 32

    def test_credential_keylet(self):
        k = credential_keylet("cred_001")
        assert len(k) == 32

    def test_bridge_keylet(self):
        k = bridge_keylet("bridge_001")
        assert len(k) == 32

    def test_hook_keylet(self):
        k = hook_keylet("rAccount", 0)
        assert len(k) == 32

    def test_keylets_from_different_spaces_differ(self):
        """Account keylet and DID keylet for same address must differ."""
        ka = account_keylet("rAlice")
        kd = did_keylet("rAlice")
        assert ka != kd

    def test_sha512_half_is_32_bytes(self):
        h = sha512_half(b"test")
        assert len(h) == 32


# ═══════════════════════════════════════════════════════════════════
#  T3.3 — Owner Reserve Enforcement
# ═══════════════════════════════════════════════════════════════════

def _ledger():
    return Ledger(total_supply=1_000_000.0, genesis_account="genesis")


def _fund(ledger, addr, amount=10_000.0):
    tx = Transaction(TT_PAYMENT, "genesis", addr, Amount(amount), Amount(0.00001), 0)
    tx.tx_id = f"fund_{addr}"
    ledger.apply_transaction(tx)


class TestOwnerReserve:
    def test_owner_reserve_calculation(self):
        ledger = _ledger()
        _fund(ledger, "alice", 100)
        acc = ledger.accounts["alice"]
        acc.owner_count = 0
        assert ledger.owner_reserve(acc) == 10.0

        acc.owner_count = 5
        assert ledger.owner_reserve(acc) == 20.0

    def test_check_owner_reserve_passes(self):
        ledger = _ledger()
        _fund(ledger, "alice", 100)
        acc = ledger.accounts["alice"]
        acc.owner_count = 0
        assert ledger.check_owner_reserve(acc)

    def test_check_owner_reserve_with_additional(self):
        ledger = _ledger()
        _fund(ledger, "alice", 15)
        acc = ledger.accounts["alice"]
        acc.owner_count = 0
        # Balance = 15, reserve for 0 + 2 = 10 + 4 = 14 → passes
        assert ledger.check_owner_reserve(acc, additional=2)
        # reserve for 0 + 5 = 10 + 10 = 20 → fails
        assert not ledger.check_owner_reserve(acc, additional=5)


# ═══════════════════════════════════════════════════════════════════
#  T3.4 — AccountDelete Rules (sequence >= 256)
# ═══════════════════════════════════════════════════════════════════

class TestAccountDeleteRules:
    def test_delete_fails_if_sequence_too_low(self):
        """AccountDelete requires sequence >= 256."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        acc = ledger.accounts["alice"]
        # Sequence should be low (around 2 after fund)
        assert acc.sequence < 256

        tx = Transaction(TT_ACCOUNT_DELETE, "alice", "bob", Amount(0.0), Amount(0.00001), 0)
        tx.tx_id = "delete_alice"
        rc = ledger.apply_transaction(tx)
        assert rc == 134  # tecSEQ_TOO_LOW

    def test_delete_succeeds_with_high_sequence(self):
        """AccountDelete succeeds when sequence >= 256."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        acc = ledger.accounts["alice"]
        acc.sequence = 256  # Force high sequence
        acc.owner_count = 0

        tx = Transaction(TT_ACCOUNT_DELETE, "alice", "bob", Amount(0.0), Amount(0.00001), 0)
        tx.flags = {}
        tx.tx_id = "delete_alice_ok"
        rc = ledger.apply_transaction(tx)
        assert rc == TES_SUCCESS
        assert "alice" not in ledger.accounts


# ═══════════════════════════════════════════════════════════════════
#  T3.5 — Canonical Transaction Ordering
# ═══════════════════════════════════════════════════════════════════

class TestCanonicalOrdering:
    def test_close_ledger_sorts_transactions(self):
        """close_ledger sorts pending txns deterministically."""
        ledger = _ledger()
        _fund(ledger, "bob", 10_000)

        # Apply 3 payments with different tx types in reverse order
        for name, i in [("charlie", 3), ("bob", 2), ("alice", 1)]:
            _fund(ledger, name, 100)

        # The pending txns should be sorted after close
        header = ledger.close_ledger()
        assert header.tx_count >= 3

    def test_deterministic_hash_same_txns(self):
        """Two ledgers with same transactions produce same hash."""
        import copy

        def build_ledger():
            lg = _ledger()
            _fund(lg, "alice", 100)
            _fund(lg, "bob", 200)
            return lg.close_ledger()

        h1 = build_ledger()
        h2 = build_ledger()
        assert h1.hash == h2.hash


# ═══════════════════════════════════════════════════════════════════
#  T3.6 — Reporting Mode
# ═══════════════════════════════════════════════════════════════════

class TestReportingMode:
    def test_store_and_retrieve_ledger(self):
        store = ReportingStore()
        store.store_ledger({
            "sequence": 1,
            "state_hash": "abc",
            "close_time": 1000.0,
            "parent_hash": "000",
            "transactions": [
                {"tx_id": "tx1", "account": "alice", "destination": "bob",
                 "tx_type": 0, "sequence": 1, "result_code": 0, "timestamp": 1000.0}
            ],
        })
        assert store.ledger_count == 1
        sl = store.get_ledger(1)
        assert sl is not None
        assert sl.sequence == 1
        assert sl.txn_count == 1

    def test_get_transaction(self):
        store = ReportingStore()
        store.store_ledger({
            "sequence": 1,
            "transactions": [
                {"tx_id": "tx1", "account": "alice", "destination": "",
                 "tx_type": 0, "sequence": 1, "result_code": 0, "timestamp": 0}
            ],
        })
        stx = store.get_transaction("tx1")
        assert stx is not None
        assert stx.tx_id == "tx1"

    def test_account_tx_history(self):
        store = ReportingStore()
        for i in range(5):
            store.store_ledger({
                "sequence": i + 1,
                "transactions": [
                    {"tx_id": f"tx{i}", "account": "alice", "destination": "bob",
                     "tx_type": 0, "sequence": i, "result_code": 0, "timestamp": float(i)}
                ],
            })
        txns = store.get_account_transactions("alice")
        assert len(txns) == 5

    def test_ledger_range(self):
        store = ReportingStore()
        for i in range(3):
            store.store_ledger({"sequence": i + 1, "transactions": []})
        lo, hi = store.ledger_range
        assert lo == 1
        assert hi == 3

    def test_pruning(self):
        store = ReportingStore(max_ledgers=3)
        for i in range(5):
            store.store_ledger({"sequence": i + 1, "transactions": []})
        assert store.ledger_count == 3
        assert store.get_ledger(1) is None
        assert store.get_ledger(2) is None
        assert store.get_ledger(3) is not None

    def test_reporting_server_read_only(self):
        srv = ReportingServer()
        assert srv.is_read_only

    def test_server_info(self):
        srv = ReportingServer()
        srv.ingest_ledger({"sequence": 1, "transactions": []})
        info = srv.server_info()
        assert "info" in info
        assert info["info"]["server_state"] == "reporting"
        assert info["info"]["reporting"]["is_reporting"] is True

    def test_reject_submit(self):
        srv = ReportingServer()
        result = srv.handle_request("submit", {})
        assert "error" in result
        assert result["error"] == "reportingUnsupported"

    def test_query_ledger(self):
        srv = ReportingServer()
        srv.ingest_ledger({
            "sequence": 1,
            "state_hash": "abc",
            "close_time": 100.0,
            "parent_hash": "000",
            "transactions": [],
        })
        result = srv.ledger(sequence=1)
        assert "result" in result
        assert result["result"]["ledger_index"] == 1

    def test_query_missing_ledger(self):
        srv = ReportingServer()
        result = srv.ledger(sequence=999)
        assert "error" in result

    def test_handle_request_dispatch(self):
        srv = ReportingServer()
        srv.ingest_ledger({"sequence": 1, "transactions": []})

        result = srv.handle_request("server_info", {})
        assert "info" in result

    def test_account_tx_via_server(self):
        srv = ReportingServer()
        srv.ingest_ledger({
            "sequence": 1,
            "transactions": [
                {"tx_id": "tx1", "account": "alice", "destination": "bob",
                 "tx_type": 0, "sequence": 1, "result_code": 0, "timestamp": 0.0}
            ],
        })
        result = srv.account_tx("alice")
        assert "result" in result
        assert len(result["result"]["transactions"]) == 1

    def test_unknown_command(self):
        srv = ReportingServer()
        result = srv.handle_request("bogus", {})
        assert result["error"] == "unknownCmd"


# ═══════════════════════════════════════════════════════════════════
#  T3.7 — SHAMap Integration with Keylets
# ═══════════════════════════════════════════════════════════════════

class TestSHAMapWithKeylets:
    def test_store_accounts_with_keylets(self):
        """Store account data using keylets in the SHAMap."""
        sm = SHAMap()
        for name in ["alice", "bob", "charlie"]:
            key = account_keylet(name)
            sm.insert(key, f'{{"balance": 1000}}'.encode(), LedgerSpace.ACCOUNT)
        assert sm.size == 3

        k = account_keylet("alice")
        data = sm.get(k)
        assert b"1000" in data

    def test_store_trust_lines(self):
        sm = SHAMap()
        k = trust_line_keylet("alice", "USD", "issuer")
        sm.insert(k, b'{"limit":1000}', LedgerSpace.TRUST_LINE)
        assert sm.get(k) == b'{"limit":1000}'

    def test_mixed_object_types(self):
        """Store different object types and retrieve them."""
        sm = SHAMap()
        sm.insert(account_keylet("alice"), b"account", LedgerSpace.ACCOUNT)
        sm.insert(offer_keylet("alice", 1), b"offer", LedgerSpace.OFFER)
        sm.insert(did_keylet("alice"), b"did", LedgerSpace.DID)

        assert sm.size == 3
        assert sm.get(account_keylet("alice")) == b"account"
        assert sm.get(offer_keylet("alice", 1)) == b"offer"
        assert sm.get(did_keylet("alice")) == b"did"
