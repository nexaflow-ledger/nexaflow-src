"""
REST / HTTP API server for NexaFlow nodes.

Built on ``aiohttp`` and designed to be started alongside the P2P layer.

Endpoints
---------
GET  /status                  Node & ledger summary
GET  /balance/<address>       Account balance
POST /tx/payment              Submit a payment
POST /tx/trust                Set a trust line
GET  /peers                   Connected peers
GET  /ledger                  Latest closed ledger info
POST /consensus               Trigger a consensus round
GET  /orderbook/<base>/<counter>  Order-book snapshot (if DEX enabled)
GET  /health                  Deep health check
POST /tx/stake                Submit a stake
POST /tx/unstake              Cancel a stake
GET  /staking/{address}       Staking info for address
GET  /staking                 Global staking pool stats

Security
--------
- API-key authentication on POST endpoints (``X-API-Key`` header or
  ``api_key`` query param).  Disabled when ``api_key`` config is empty.
- Per-IP token-bucket rate limiter (configurable RPM).
- CORS middleware (origins configurable via ``cors_origins``).
- Request body size cap (``max_body_bytes``, default 1 MiB).

Usage:
    api = APIServer(node, host="127.0.0.1", port=8080)
    await api.start()    # call inside existing event loop
    ...
    await api.stop()
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from aiohttp import web

if TYPE_CHECKING:
    from nexaflow_core.config import APIConfig

logger = logging.getLogger("nexaflow_api")


# ═══════════════════════════════════════════════════════════════════
#  Rate Limiter (per-IP token bucket)
# ═══════════════════════════════════════════════════════════════════

class _TokenBucket:
    """Simple per-IP token-bucket rate limiter."""

    __slots__ = ("_buckets", "_rpm")

    def __init__(self, rpm: int):
        self._rpm = rpm  # 0 = unlimited
        # ip -> (tokens, last_refill_timestamp)
        self._buckets: dict[str, list[float]] = defaultdict(lambda: [float(rpm), time.monotonic()])

    def allow(self, ip: str) -> bool:
        if self._rpm <= 0:
            return True
        bucket = self._buckets[ip]
        now = time.monotonic()
        elapsed = now - bucket[1]
        # refill tokens
        bucket[0] = min(float(self._rpm), bucket[0] + elapsed * (self._rpm / 60.0))
        bucket[1] = now
        if bucket[0] >= 1.0:
            bucket[0] -= 1.0
            return True
        return False


# ═══════════════════════════════════════════════════════════════════
#  Middleware factories
# ═══════════════════════════════════════════════════════════════════

def _make_rate_limit_middleware(bucket: _TokenBucket):
    """aiohttp middleware that enforces per-IP rate limits."""

    @web.middleware
    async def rate_limit_middleware(request: web.Request, handler):
        ip = request.remote or "unknown"
        if not bucket.allow(ip):
            raise web.HTTPTooManyRequests(
                text="Rate limit exceeded. Try again later.",
                headers={"Retry-After": "5"},
            )
        return await handler(request)

    return rate_limit_middleware


def _make_api_key_middleware(api_key: str):
    """aiohttp middleware that requires an API key on POST/PUT/DELETE."""

    @web.middleware
    async def api_key_middleware(request: web.Request, handler):
        if request.method in ("POST", "PUT", "DELETE"):
            key = request.headers.get("X-API-Key") or request.query.get("api_key")
            if key != api_key:
                raise web.HTTPUnauthorized(text="Invalid or missing API key")
        return await handler(request)

    return api_key_middleware


def _make_cors_middleware(origins: list[str]):
    """aiohttp middleware that adds CORS headers."""

    allowed = set(origins) if origins else set()

    @web.middleware
    async def cors_middleware(request: web.Request, handler):
        # Handle preflight
        origin = request.headers.get("Origin", "")
        if request.method == "OPTIONS":
            resp = web.Response(status=204)
        else:
            resp = await handler(request)

        if "*" in allowed or origin in allowed:
            resp.headers["Access-Control-Allow-Origin"] = origin or "*"
            resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-API-Key"
            resp.headers["Access-Control-Max-Age"] = "3600"
        return resp

    return cors_middleware


class APIServer:
    """Thin aiohttp wrapper around a running NexaFlowNode."""

    def __init__(
        self,
        node: Any,
        host: str = "127.0.0.1",
        port: int = 8080,
        *,
        api_config: APIConfig | None = None,
    ):
        self.node = node
        self.host = host
        self.port = port
        self._api_config = api_config
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None

    # ── lifecycle ────────────────────────────────────────────────

    async def start(self) -> None:
        middlewares: list = []
        max_body = 1_048_576  # default 1 MiB

        if self._api_config is not None:
            cfg = self._api_config
            max_body = cfg.max_body_bytes

            # Rate limiter
            if cfg.rate_limit_rpm > 0:
                self._rate_limiter = _TokenBucket(cfg.rate_limit_rpm)
                middlewares.append(_make_rate_limit_middleware(self._rate_limiter))

            # CORS
            if cfg.cors_origins:
                middlewares.append(_make_cors_middleware(cfg.cors_origins))

            # API key auth
            if cfg.api_key:
                middlewares.append(_make_api_key_middleware(cfg.api_key))

        self._app = web.Application(
            middlewares=middlewares,
            client_max_size=max_body,
        )
        self._register_routes(self._app)
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port)
        await site.start()
        logger.info(f"API listening on http://{self.host}:{self.port}")

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    # ── routes ───────────────────────────────────────────────────

    def _register_routes(self, app: web.Application) -> None:
        app.router.add_get("/health", self._health)
        app.router.add_get("/status", self._status)
        app.router.add_get("/balance/{address}", self._balance)
        app.router.add_post("/tx/payment", self._submit_payment)
        app.router.add_post("/tx/trust", self._submit_trust)
        app.router.add_get("/peers", self._peers)
        app.router.add_get("/ledger", self._ledger)
        app.router.add_post("/consensus", self._trigger_consensus)
        app.router.add_get("/orderbook/{base}/{counter}", self._orderbook)
        # Staking
        app.router.add_post("/tx/stake", self._submit_stake)
        app.router.add_post("/tx/unstake", self._submit_unstake)
        app.router.add_get("/staking/{address}", self._staking_info)
        app.router.add_get("/staking", self._staking_pool)

    # ── handlers ─────────────────────────────────────────────────

    async def _health(self, _request: web.Request) -> web.Response:
        """Deep health check — reports overall status and sub-system health."""
        peer_count = self.node.p2p.peer_count
        ledger_seq = self.node.ledger.current_sequence
        closed = len(self.node.ledger.closed_ledgers)
        # Heuristic: healthy if we have peers or are the only node
        peers_ok = peer_count > 0 or not self.node.peers_to_connect
        ledger_ok = ledger_seq >= 1
        healthy = peers_ok and ledger_ok
        return web.json_response({
            "ok": healthy,
            "node_id": self.node.node_id,
            "peers": peer_count,
            "ledger_sequence": ledger_seq,
            "closed_ledgers": closed,
            "tx_pool_size": len(self.node.tx_pool),
            "checks": {
                "peers": "ok" if peers_ok else "degraded",
                "ledger": "ok" if ledger_ok else "degraded",
            },
        }, status=200 if healthy else 503)

    async def _status(self, _request: web.Request) -> web.Response:
        return web.json_response(self.node.status(), dumps=_json_dumps)

    async def _balance(self, request: web.Request) -> web.Response:
        address = request.match_info["address"]
        bal = self.node.ledger.get_balance(address)
        return web.json_response({"address": address, "balance": bal})

    async def _submit_payment(self, request: web.Request) -> web.Response:
        """
        POST /tx/payment
        Body: {"destination": "rXXX", "amount": 100.0, "currency": "NXF", "memo": ""}
        """
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc

        dest = body.get("destination", "")
        amount = float(body.get("amount", 0))
        currency = body.get("currency", "NXF")
        memo = body.get("memo", "")

        if not dest or amount <= 0:
            raise web.HTTPBadRequest(text="destination and positive amount required")

        tx = await self.node.send_payment(dest, amount, currency, memo)
        if tx is None:
            raise web.HTTPBadRequest(text="Transaction validation failed")

        return web.json_response({
            "status": "submitted",
            "tx_id": tx.tx_id,
        })

    async def _submit_trust(self, request: web.Request) -> web.Response:
        """
        POST /tx/trust
        Body: {"currency": "USD", "issuer": "rGateway", "limit": 1000.0}
        """
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc

        currency = body.get("currency", "")
        issuer = body.get("issuer", "")
        limit = float(body.get("limit", 0))

        if not currency or not issuer or limit <= 0:
            raise web.HTTPBadRequest(text="currency, issuer, and positive limit required")

        from nexaflow_core.transaction import create_trust_set
        tx = create_trust_set(self.node.wallet.address, currency, issuer, limit)
        self.node.wallet.sign_transaction(tx)

        valid, _code, msg = self.node.validator.validate(tx)
        if not valid:
            raise web.HTTPBadRequest(text=f"Validation failed: {msg}")

        tx_dict = tx.to_dict()
        tx_dict["tx_id"] = tx.tx_id
        tx_dict["signing_pub_key"] = tx.signing_pub_key.hex()
        tx_dict["signature"] = tx.signature.hex()
        self.node.tx_pool[tx.tx_id] = tx_dict
        self.node.tx_objects[tx.tx_id] = tx
        await self.node.p2p.broadcast_transaction(tx_dict)

        return web.json_response({"status": "submitted", "tx_id": tx.tx_id})

    async def _peers(self, _request: web.Request) -> web.Response:
        peers = []
        for p in self.node.p2p.peers.values():
            peers.append({
                "peer_id": p.peer_id,
                "remote_addr": p.remote_addr,
                "direction": p.direction,
                "messages_sent": p.messages_sent,
                "messages_received": p.messages_received,
            })
        return web.json_response({"peers": peers, "count": len(peers)})

    async def _ledger(self, _request: web.Request) -> web.Response:
        summary = self.node.ledger.get_state_summary()
        result = dict(summary)
        if self.node.ledger.closed_ledgers:
            last = self.node.ledger.closed_ledgers[-1]
            result["last_closed"] = {
                "sequence": last.sequence,
                "hash": last.hash,
                "tx_count": last.transaction_count,
                "timestamp": last.timestamp,
            }
        return web.json_response(result, dumps=_json_dumps)

    async def _trigger_consensus(self, _request: web.Request) -> web.Response:
        await self.node.run_consensus()
        return web.json_response({"status": "consensus_triggered"})

    async def _orderbook(self, request: web.Request) -> web.Response:
        base = request.match_info["base"]
        counter = request.match_info["counter"]
        # If the node has an order_book attribute use it
        ob = getattr(self.node, "order_book", None)
        if ob is None:
            return web.json_response({"error": "DEX not enabled"}, status=404)
        pair = f"{base}/{counter}"
        snapshot = ob.get_book_snapshot(pair)
        return web.json_response(snapshot, dumps=_json_dumps)

    # ── staking handlers ─────────────────────────────────────────────

    async def _submit_stake(self, request: web.Request) -> web.Response:
        """
        POST /tx/stake
        Body: {"amount": 100.0, "tier": 1, "memo": ""}

        Builds, signs, validates, and applies a Stake transaction.
        """
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc

        amount = float(body.get("amount", 0))
        tier = int(body.get("tier", 0))
        memo = body.get("memo", "")

        if amount <= 0:
            raise web.HTTPBadRequest(text="positive amount required")

        from nexaflow_core.transaction import create_stake
        tx = create_stake(self.node.wallet.address, amount, tier, memo=memo)
        self.node.wallet.sign_transaction(tx)

        valid, _code, msg = self.node.validator.validate(tx)
        if not valid:
            raise web.HTTPBadRequest(text=f"Validation failed: {msg}")

        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(
                text=f"Apply failed: {RESULT_NAMES.get(result, result)}"
            )

        # Broadcast
        tx_dict = tx.to_dict()
        tx_dict["tx_id"] = tx.tx_id
        tx_dict["signing_pub_key"] = tx.signing_pub_key.hex()
        tx_dict["signature"] = tx.signature.hex()
        self.node.tx_pool[tx.tx_id] = tx_dict
        self.node.tx_objects[tx.tx_id] = tx
        await self.node.p2p.broadcast_transaction(tx_dict)

        return web.json_response({
            "status": "staked",
            "tx_id": tx.tx_id,
            "amount": amount,
            "tier": tier,
        }, dumps=_json_dumps)

    async def _submit_unstake(self, request: web.Request) -> web.Response:
        """
        POST /tx/unstake
        Body: {"stake_id": "abc123", "memo": ""}

        Early cancellation.  Locked-tier stakes suffer a large penalty.
        """
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc

        stake_id = body.get("stake_id", "")
        memo = body.get("memo", "")
        if not stake_id:
            raise web.HTTPBadRequest(text="stake_id required")

        from nexaflow_core.transaction import create_unstake
        tx = create_unstake(self.node.wallet.address, stake_id, memo=memo)
        self.node.wallet.sign_transaction(tx)

        valid, _code, msg = self.node.validator.validate(tx)
        if not valid:
            raise web.HTTPBadRequest(text=f"Validation failed: {msg}")

        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(
                text=f"Apply failed: {RESULT_NAMES.get(result, result)}"
            )

        tx_dict = tx.to_dict()
        tx_dict["tx_id"] = tx.tx_id
        tx_dict["signing_pub_key"] = tx.signing_pub_key.hex()
        tx_dict["signature"] = tx.signature.hex()
        self.node.tx_pool[tx.tx_id] = tx_dict
        self.node.tx_objects[tx.tx_id] = tx
        await self.node.p2p.broadcast_transaction(tx_dict)

        return web.json_response({
            "status": "unstaked",
            "tx_id": tx.tx_id,
            "stake_id": stake_id,
        }, dumps=_json_dumps)

    async def _staking_info(self, request: web.Request) -> web.Response:
        """GET /staking/{address}"""
        address = request.match_info["address"]
        info = self.node.ledger.get_staking_summary(address)
        return web.json_response(info, dumps=_json_dumps)

    async def _staking_pool(self, _request: web.Request) -> web.Response:
        """GET /staking — global pool stats + tier info with effective APYs."""
        pool = self.node.ledger.staking_pool.get_pool_summary()
        pool["tiers"] = self.node.ledger.staking_pool.get_tier_info(
            self.node.ledger.total_supply
        )
        pool["demand_multiplier"] = self.node.ledger.staking_pool.get_demand_multiplier(
            self.node.ledger.total_supply
        )
        return web.json_response(pool, dumps=_json_dumps)


def _json_dumps(obj: Any) -> str:
    """JSON serialiser that handles non-standard types."""
    return json.dumps(obj, default=str)
