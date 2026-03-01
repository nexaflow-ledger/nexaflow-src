"""
Security tests for the REST API layer.

Covers:
  - API key authentication enforcement
  - Rate limiting (token bucket)
  - CORS middleware
  - Request body size limits
  - Input validation (malformed JSON, type coercion, injection)
  - Deep health check
  - Edge-case route handling
"""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from nexaflow_core.api import (
    APIServer,
    _make_api_key_middleware,
    _make_cors_middleware,
    _make_rate_limit_middleware,
    _TokenBucket,
)

# ─── Helpers ────────────────────────────────────────────────────────

@dataclass
class _FakePeer:
    peer_id: str = "peer-1"
    remote_addr: str = "127.0.0.1:9002"
    direction: str = "outbound"
    messages_sent: int = 0
    messages_received: int = 0


class _FakeP2P:
    def __init__(self):
        self.peers: dict[str, _FakePeer] = {}
        self.broadcasted: list = []

    @property
    def peer_count(self):
        return len(self.peers)

    def peer_ids(self):
        return list(self.peers.keys())

    def status(self):
        return {"node_id": "test", "peers": self.peer_count}

    async def broadcast_transaction(self, tx_dict):
        self.broadcasted.append(tx_dict)


class _FakeStakingPool:
    def __init__(self):
        self.stakes = {}
        self.total_staked = 0.0
        self.total_interest_paid = 0.0

    def get_pool_summary(self, now=None):
        return {
            "total_staked": self.total_staked,
            "total_interest_paid": self.total_interest_paid,
            "total_pending_interest": 0.0,
            "active_stakes": 0,
            "total_stakes": 0,
        }

    def get_tier_info(self, supply):
        return []

    def get_demand_multiplier(self, supply):
        return 1.0


class _FakeLedger:
    def __init__(self):
        self.current_sequence = 1
        self.closed_ledgers = []
        self.accounts = {}
        self.staking_pool = _FakeStakingPool()

    def get_balance(self, addr):
        return 100.0

    def get_state_summary(self):
        return {
            "ledger_sequence": self.current_sequence,
            "total_accounts": len(self.accounts),
        }

    def get_staking_summary(self, addr):
        return {"address": addr, "stakes": []}


class _FakeNode:
    def __init__(self):
        self.node_id = "test-node"
        self.p2p = _FakeP2P()
        self.ledger = _FakeLedger()
        self.wallet = MagicMock()
        self.wallet.address = "rTestAddr"
        self.validator = MagicMock()
        self.tx_pool = {}
        self.tx_objects = {}
        self.peers_to_connect = []

    def status(self):
        return {"node_id": self.node_id, "port": 9001}

    async def send_payment(self, dest, amount, currency, memo):
        return None

    async def run_consensus(self):
        pass


def _build_api_config(**overrides):
    """Build an APIConfig dataclass for testing."""
    from nexaflow_core.config import APIConfig
    defaults = {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8080,
        "api_key": "",
        "rate_limit_rpm": 0,
        "cors_origins": [],
        "max_body_bytes": 1_048_576,
    }
    defaults.update(overrides)
    return APIConfig(**defaults)


async def _make_test_client(api_config=None, node=None):
    """Create an aiohttp TestClient from an APIServer."""
    node = node or _FakeNode()
    api = APIServer(node, host="127.0.0.1", port=0, api_config=api_config)

    middlewares = []
    max_body = 1_048_576
    if api_config:
        max_body = api_config.max_body_bytes
        if api_config.rate_limit_rpm > 0:
            bucket = _TokenBucket(api_config.rate_limit_rpm)
            middlewares.append(_make_rate_limit_middleware(bucket))
        if api_config.cors_origins:
            middlewares.append(_make_cors_middleware(api_config.cors_origins))
        if api_config.api_key:
            middlewares.append(_make_api_key_middleware(api_config.api_key))

    app = web.Application(middlewares=middlewares, client_max_size=max_body)
    api._register_routes(app)
    api._app = app
    return TestClient(TestServer(app)), node


# ═══════════════════════════════════════════════════════════════════
#  Token Bucket Rate Limiter
# ═══════════════════════════════════════════════════════════════════

class TestTokenBucket:
    def test_unlimited_always_allows(self):
        bucket = _TokenBucket(0)
        for _ in range(1000):
            assert bucket.allow("1.2.3.4")

    def test_allows_up_to_limit(self):
        bucket = _TokenBucket(5)
        for _ in range(5):
            assert bucket.allow("1.2.3.4")
        assert not bucket.allow("1.2.3.4")

    def test_different_ips_independent(self):
        bucket = _TokenBucket(2)
        assert bucket.allow("1.1.1.1")
        assert bucket.allow("1.1.1.1")
        assert not bucket.allow("1.1.1.1")
        # Different IP still has full allocation
        assert bucket.allow("2.2.2.2")
        assert bucket.allow("2.2.2.2")
        assert not bucket.allow("2.2.2.2")

    def test_tokens_refill_over_time(self):
        bucket = _TokenBucket(60)  # 1 per second
        # Drain all
        for _ in range(60):
            bucket.allow("x")
        assert not bucket.allow("x")
        # Manually advance the bucket's timestamp
        bucket._buckets["x"][1] -= 2.0  # pretend 2 secs passed
        assert bucket.allow("x")
        assert bucket.allow("x")

    def test_negative_rpm_treated_as_unlimited(self):
        bucket = _TokenBucket(-1)
        for _ in range(100):
            assert bucket.allow("any")

    def test_tokens_capped_at_rpm(self):
        bucket = _TokenBucket(10)
        # Advance time a LOT — tokens should cap at 10
        bucket._buckets["ip"][1] -= 10000
        for _ in range(10):
            assert bucket.allow("ip")
        assert not bucket.allow("ip")


# ═══════════════════════════════════════════════════════════════════
#  API Key Authentication
# ═══════════════════════════════════════════════════════════════════

class TestAPIKeyAuth:
    @pytest.mark.asyncio
    async def test_get_requests_allowed_without_key(self):
        cfg = _build_api_config(api_key="secret123")
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.get("/health")
            assert resp.status == 200

    @pytest.mark.asyncio
    async def test_post_rejected_without_key(self):
        cfg = _build_api_config(api_key="secret123")
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.post("/tx/payment", json={"destination": "x", "amount": 1})
            assert resp.status == 401

    @pytest.mark.asyncio
    async def test_post_rejected_with_wrong_key(self):
        cfg = _build_api_config(api_key="secret123")
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.post(
                "/tx/payment",
                json={"destination": "x", "amount": 1},
                headers={"X-API-Key": "wrong"},
            )
            assert resp.status == 401

    @pytest.mark.asyncio
    async def test_post_allowed_with_correct_header_key(self):
        cfg = _build_api_config(api_key="secret123")
        client, _node = await _make_test_client(cfg)
        async with client:
            resp = await client.post(
                "/tx/payment",
                json={"destination": "rDest", "amount": 10},
                headers={"X-API-Key": "secret123"},
            )
            # 400 because send_payment returns None, but NOT 401
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_post_allowed_with_query_param_key(self):
        cfg = _build_api_config(api_key="secret123")
        client, _node = await _make_test_client(cfg)
        async with client:
            resp = await client.post(
                "/tx/payment?api_key=secret123",
                json={"destination": "rDest", "amount": 10},
            )
            assert resp.status == 400  # not 401

    @pytest.mark.asyncio
    async def test_no_auth_when_key_empty(self):
        cfg = _build_api_config(api_key="")
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.post("/tx/payment", json={"destination": "rDest", "amount": 10})
            # Should not 401 — api_key is empty so no auth enforced
            assert resp.status != 401


# ═══════════════════════════════════════════════════════════════════
#  CORS Middleware
# ═══════════════════════════════════════════════════════════════════

class TestCORSMiddleware:
    @pytest.mark.asyncio
    async def test_allowed_origin_gets_cors_headers(self):
        cfg = _build_api_config(cors_origins=["https://dashboard.nexaflow.io"])
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.get(
                "/health",
                headers={"Origin": "https://dashboard.nexaflow.io"},
            )
            assert resp.status == 200
            assert "Access-Control-Allow-Origin" in resp.headers

    @pytest.mark.asyncio
    async def test_disallowed_origin_no_cors_headers(self):
        cfg = _build_api_config(cors_origins=["https://dashboard.nexaflow.io"])
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.get(
                "/health",
                headers={"Origin": "https://evil.com"},
            )
            assert resp.status == 200
            assert "Access-Control-Allow-Origin" not in resp.headers

    @pytest.mark.asyncio
    async def test_wildcard_allows_any_origin(self):
        cfg = _build_api_config(cors_origins=["*"])
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.get(
                "/health",
                headers={"Origin": "https://anything.com"},
            )
            assert "Access-Control-Allow-Origin" in resp.headers

    @pytest.mark.asyncio
    async def test_preflight_options_returns_204(self):
        cfg = _build_api_config(cors_origins=["https://app.example.com"])
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.options(
                "/tx/payment",
                headers={"Origin": "https://app.example.com"},
            )
            assert resp.status == 204


# ═══════════════════════════════════════════════════════════════════
#  Rate Limiting Middleware
# ═══════════════════════════════════════════════════════════════════

class TestRateLimitMiddleware:
    @pytest.mark.asyncio
    async def test_rate_limit_returns_429(self):
        cfg = _build_api_config(rate_limit_rpm=3)
        client, _ = await _make_test_client(cfg)
        async with client:
            for _ in range(3):
                resp = await client.get("/health")
                assert resp.status == 200
            resp = await client.get("/health")
            assert resp.status == 429

    @pytest.mark.asyncio
    async def test_429_has_retry_after_header(self):
        cfg = _build_api_config(rate_limit_rpm=1)
        client, _ = await _make_test_client(cfg)
        async with client:
            await client.get("/health")
            resp = await client.get("/health")
            assert resp.status == 429
            assert "Retry-After" in resp.headers


# ═══════════════════════════════════════════════════════════════════
#  Input Validation & Injection
# ═══════════════════════════════════════════════════════════════════

class TestInputValidation:
    @pytest.mark.asyncio
    async def test_payment_non_json_body(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/payment",
                data=b"not json",
                headers={"Content-Type": "application/json"},
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_payment_missing_destination(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post("/tx/payment", json={"amount": 100})
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_payment_zero_amount(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/payment", json={"destination": "rDest", "amount": 0}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_payment_negative_amount(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/payment", json={"destination": "rDest", "amount": -50}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_stake_zero_amount(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/stake", json={"amount": 0, "tier": 1}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_stake_negative_amount(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/stake", json={"amount": -100, "tier": 0}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_unstake_missing_stake_id(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post("/tx/unstake", json={})
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_trust_missing_fields(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post("/tx/trust", json={"currency": "USD"})
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_trust_zero_limit(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/trust", json={"currency": "USD", "issuer": "rGW", "limit": 0}
            )
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_extremely_long_memo_accepted(self):
        """Memos aren't dangerous — just ensure no crash."""
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/payment",
                json={"destination": "rDest", "amount": 1, "memo": "x" * 10_000},
            )
            # 400 because send_payment returns None, but no crash
            assert resp.status == 400

    @pytest.mark.asyncio
    async def test_sql_injection_in_address(self):
        """Ensure address passed to ledger is harmless."""
        client, _ = await _make_test_client()
        async with client:
            resp = await client.get("/balance/'; DROP TABLE accounts; --")
            assert resp.status == 200
            body = await resp.json()
            assert body["balance"] == 100.0  # fake ledger returns 100.0

    @pytest.mark.asyncio
    async def test_xss_in_destination(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.post(
                "/tx/payment",
                json={"destination": "<script>alert(1)</script>", "amount": 10},
            )
            assert resp.status == 400
            text = await resp.text()
            assert "<script>" not in text


# ═══════════════════════════════════════════════════════════════════
#  Deep Health Check
# ═══════════════════════════════════════════════════════════════════

class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_healthy_no_peers_no_seed(self):
        """Node with no peers_to_connect is healthy even alone."""
        client, node = await _make_test_client()
        node.peers_to_connect = []
        async with client:
            resp = await client.get("/health")
            data = await resp.json()
            assert resp.status == 200
            assert data["ok"] is True
            assert data["checks"]["peers"] == "ok"

    @pytest.mark.asyncio
    async def test_degraded_when_expecting_peers(self):
        """Node that expects peers but has none should be degraded."""
        client, node = await _make_test_client()
        node.peers_to_connect = ["127.0.0.1:9002"]
        async with client:
            resp = await client.get("/health")
            data = await resp.json()
            assert resp.status == 503
            assert data["ok"] is False
            assert data["checks"]["peers"] == "degraded"

    @pytest.mark.asyncio
    async def test_health_has_expected_fields(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.get("/health")
            data = await resp.json()
            assert "node_id" in data
            assert "peers" in data
            assert "ledger_sequence" in data
            assert "closed_ledgers" in data
            assert "tx_pool_size" in data
            assert "checks" in data


# ═══════════════════════════════════════════════════════════════════
#  Orderbook Endpoint
# ═══════════════════════════════════════════════════════════════════

class TestOrderbookEndpoint:
    @pytest.mark.asyncio
    async def test_orderbook_returns_404_when_dex_disabled(self):
        client, _ = await _make_test_client()
        async with client:
            resp = await client.get("/orderbook/NXF/USD")
            assert resp.status == 404


# ═══════════════════════════════════════════════════════════════════
#  Request Body Size Limit
# ═══════════════════════════════════════════════════════════════════

class TestBodySizeLimit:
    @pytest.mark.asyncio
    async def test_oversized_body_rejected(self):
        cfg = _build_api_config(max_body_bytes=256)
        client, _ = await _make_test_client(cfg)
        async with client:
            resp = await client.post(
                "/tx/payment",
                data=b"x" * 512,
                headers={"Content-Type": "application/json"},
            )
            assert resp.status in (400, 413)
