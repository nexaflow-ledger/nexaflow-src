"""
Tests for Tier 2 features:
  - WebSocket subscriptions (SubscriptionManager)
  - server_info handler (rich response)
  - Fee RPC (/fee)
  - book_offers RPC
  - account_tx pagination
  - ledger_data endpoint
"""

import asyncio
import json
import pytest

from nexaflow_core.websocket import SubscriptionManager, ClientSubscription
from nexaflow_core.fee_model import FeeModel, FeeLevel, QueuedTransaction


# ═══════════════════════════════════════════════════════════════════
#  T2.1 — WebSocket SubscriptionManager
# ═══════════════════════════════════════════════════════════════════

class _FakeWS:
    """Minimal mock for an aiohttp WebSocketResponse."""
    def __init__(self):
        self.sent: list[dict] = []
        self.closed = False

    async def send_json(self, data, **kw):
        self.sent.append(data)

    async def send_str(self, data):
        self.sent.append(json.loads(data))


@pytest.mark.asyncio
class TestSubscriptionManager:
    async def test_add_remove_client(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        assert mgr.client_count == 1
        await mgr.remove_client(ws_id)
        assert mgr.client_count == 0

    async def test_subscribe_streams(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)

        result = await mgr.subscribe(ws_id, streams=["ledger", "transactions"])
        assert result["status"] == "success"

        sub = mgr._clients[ws_id]
        assert "ledger" in sub.streams
        assert "transactions" in sub.streams

    async def test_subscribe_invalid_stream_warns(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)

        result = await mgr.subscribe(ws_id, streams=["invalid_stream"])
        assert "warnings" in result

    async def test_subscribe_accounts(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)

        result = await mgr.subscribe(ws_id, accounts=["rAlice", "rBob"])
        assert result["status"] == "success"

        sub = mgr._clients[ws_id]
        assert "rAlice" in sub.accounts
        assert "rBob" in sub.accounts

    async def test_unsubscribe(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        await mgr.subscribe(ws_id, streams=["ledger", "transactions"])
        
        result = await mgr.unsubscribe(ws_id, streams=["ledger"])
        assert result["status"] == "success"
        assert "ledger" not in mgr._clients[ws_id].streams
        assert "transactions" in mgr._clients[ws_id].streams

    async def test_broadcast_ledger(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        await mgr.subscribe(ws_id, streams=["ledger"])

        await mgr.broadcast_ledger({
            "sequence": 42,
            "hash": "abc123",
            "close_time": 1000,
            "txn_count": 5,
        })
        assert len(ws.sent) == 1
        assert ws.sent[0]["type"] == "ledgerClosed"
        assert ws.sent[0]["ledger_index"] == 42

    async def test_broadcast_transaction_to_stream(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        await mgr.subscribe(ws_id, streams=["transactions"])

        await mgr.broadcast_transaction({
            "account": "alice",
            "destination": "bob",
            "amount": 100,
        })
        assert len(ws.sent) == 1
        assert ws.sent[0]["type"] == "transaction"

    async def test_broadcast_transaction_to_account_sub(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        await mgr.subscribe(ws_id, accounts=["alice"])

        await mgr.broadcast_transaction({
            "account": "alice",
            "destination": "bob",
            "amount": 100,
        })
        # Should get the tx because alice is subscribed
        assert len(ws.sent) == 1

    async def test_no_broadcast_to_unsubscribed(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        # Don't subscribe to anything

        await mgr.broadcast_ledger({"sequence": 1})
        assert len(ws.sent) == 0

    async def test_subscribe_unknown_client(self):
        mgr = SubscriptionManager()
        result = await mgr.subscribe("nonexistent", streams=["ledger"])
        assert "error" in result

    async def test_subscribe_books(self):
        mgr = SubscriptionManager()
        ws = _FakeWS()
        ws_id = await mgr.add_client(ws)
        result = await mgr.subscribe(ws_id, books=[
            {"taker_pays": {"currency": "USD"}, "taker_gets": {"currency": "NXF"}}
        ])
        assert result["status"] == "success"
        assert "USD/NXF" in mgr._clients[ws_id].books


# ═══════════════════════════════════════════════════════════════════
#  T2.2 — Fee Model
# ═══════════════════════════════════════════════════════════════════

class TestFeeModel:
    def test_minimum_fee(self):
        fm = FeeModel(base_fee=10)
        assert fm.minimum_fee() == 10

    def test_account_reserve(self):
        fm = FeeModel()
        # 0 objects: base reserve only
        assert fm.account_reserve(0) == 10_000_000
        # 5 objects
        assert fm.account_reserve(5) == 10_000_000 + 5 * 2_000_000

    def test_validate_fee_ok(self):
        fm = FeeModel(base_fee=10)
        ok, msg = fm.validate_fee(10)
        assert ok

    def test_validate_fee_too_low(self):
        fm = FeeModel(base_fee=10)
        ok, msg = fm.validate_fee(5)
        assert not ok
        assert "below minimum" in msg

    def test_enqueue_and_dequeue(self):
        fm = FeeModel(base_fee=10)
        assert fm.enqueue("tx1", "alice", 20, 1)
        assert fm.enqueue("tx2", "bob", 50, 2)
        assert fm.fee_level.queue_size == 2

        result = fm.dequeue_for_ledger(max_txns=1)
        assert len(result) == 1
        assert result[0].tx_id == "tx2"  # highest fee first

    def test_queue_full_rejects(self):
        fm = FeeModel(base_fee=10, queue_max=2)
        fm.enqueue("tx1", "a", 20, 1)
        fm.enqueue("tx2", "b", 30, 2)
        assert not fm.enqueue("tx3", "c", 40, 3)

    def test_load_escalation(self):
        fm = FeeModel(base_fee=10)
        fm.fee_level.expected_ledger_size = 10

        # Simulate 20 txns (2x expected)  
        for i in range(20):
            fm.record_transaction(10)
        fm.on_ledger_close()

        # Open ledger fee should be escalated (2^2 = 4x)
        assert fm.fee_level.open_ledger_fee_level > 10

    def test_to_dict(self):
        fm = FeeModel(base_fee=10)
        d = fm.to_dict()
        assert "base_fee" in d
        assert "drops" in d
        assert "expected_ledger_size" in d

    def test_queue_contents(self):
        fm = FeeModel(base_fee=10)
        fm.enqueue("tx1", "alice", 20, 1)
        contents = fm.queue_contents()
        assert len(contents) == 1
        assert contents[0]["tx_id"] == "tx1"

    def test_should_queue(self):
        fm = FeeModel(base_fee=10)
        fm.fee_level.open_ledger_fee_level = 100
        # Fee is above minimum but below open ledger fee — should queue
        assert fm.should_queue(50)
        # Fee is above open ledger fee — should not queue
        assert not fm.should_queue(200)


# ═══════════════════════════════════════════════════════════════════
#  T2.3 — Fee Level
# ═══════════════════════════════════════════════════════════════════

class TestFeeLevel:
    def test_load_factor_ratio_normal(self):
        fl = FeeLevel()
        assert fl.load_factor_ratio == pytest.approx(1.0)

    def test_current_base_fee_under_load(self):
        fl = FeeLevel(base_fee_drops=10, load_factor=512, load_base=256)
        assert fl.current_base_fee == 20  # 2x load

    def test_to_dict_structure(self):
        fl = FeeLevel()
        d = fl.to_dict()
        assert "base_fee" in d
        assert "drops" in d
        assert "levels" in d
