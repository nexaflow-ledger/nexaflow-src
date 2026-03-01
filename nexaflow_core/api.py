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
POST /consensus               Trigger a consensus round (admin)
GET  /orderbook/<base>/<counter>  Order-book snapshot (if DEX enabled)
GET  /health                  Deep health check
POST /tx/stake                Submit a stake
POST /tx/unstake              Cancel a stake
GET  /staking/{address}       Staking info for address
GET  /staking                 Global staking pool stats

Security
--------
- API-key authentication on POST endpoints via ``X-API-Key`` header only.
  Timing-safe comparison via ``hmac.compare_digest``.
- Per-IP token-bucket rate limiter (configurable RPM).
- CORS middleware (origins configurable via ``cors_origins``).
- Request body size cap (``max_body_bytes``, default 1 MiB).
- Optional TLS for the HTTP listener (``api_tls_cert`` / ``api_tls_key``).
- Numeric inputs validated and clamped (NaN / Inf rejected).

Usage:
    api = APIServer(node, host="127.0.0.1", port=8080)
    await api.start()    # call inside existing event loop
    ...
    await api.stop()
"""

from __future__ import annotations

import hmac
import json
import logging
import math
import ssl as _ssl
import time
from collections import defaultdict
from typing import TYPE_CHECKING, Any

from aiohttp import web

if TYPE_CHECKING:
    from nexaflow_core.config import APIConfig

logger = logging.getLogger("nexaflow_api")


# ═══════════════════════════════════════════════════════════════════
#  Input helpers
# ═══════════════════════════════════════════════════════════════════

def _safe_float(value: Any, name: str = "value") -> float:
    """Convert *value* to float, rejecting NaN, Inf, and non-numeric."""
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise web.HTTPBadRequest(text=f"{name} must be a number")
    if math.isnan(f) or math.isinf(f):
        raise web.HTTPBadRequest(text=f"{name} must be a finite number")
    return f


def _safe_int(value: Any, name: str = "value") -> int:
    """Convert *value* to int, rejecting non-integer input."""
    try:
        return int(value)
    except (TypeError, ValueError):
        raise web.HTTPBadRequest(text=f"{name} must be an integer")


def _sanitize_validation_msg(msg: str) -> str:
    """Strip internal state (balances, sequences) from validation messages."""
    # Allow only the error class prefix, trim after the first colon + space
    # Examples:  "Insufficient balance: have 1234" → "Insufficient balance"
    if ":" in msg:
        return msg.split(":", 1)[0]
    return msg


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
    """aiohttp middleware that requires an API key on POST/PUT/DELETE.

    Uses ``hmac.compare_digest`` for timing-safe comparison and only
    reads the key from the ``X-API-Key`` header (never from query params
    to avoid credential leakage in logs / Referer headers).
    """

    @web.middleware
    async def api_key_middleware(request: web.Request, handler):
        if request.method in ("POST", "PUT", "DELETE"):
            key = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(key, api_key):
                raise web.HTTPUnauthorized(text="Invalid or missing API key")
        return await handler(request)

    return api_key_middleware


def _make_cors_middleware(origins: list[str]):
    """aiohttp middleware that adds CORS headers.

    The ``*`` wildcard is **not** supported — operators must list concrete
    origins to prevent credential-bearing cross-origin requests from
    untrusted sites.
    """

    allowed = set(origins) if origins else set()
    # Discard wildcard silently — explicit origins only
    allowed.discard("*")

    @web.middleware
    async def cors_middleware(request: web.Request, handler):
        origin = request.headers.get("Origin", "")
        if request.method == "OPTIONS":
            resp = web.Response(status=204)
        else:
            resp = await handler(request)

        if origin in allowed:
            resp.headers["Access-Control-Allow-Origin"] = origin
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
        ssl_ctx = None

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

            # Optional TLS for the API listener
            cert = getattr(cfg, "tls_cert", "") or ""
            key = getattr(cfg, "tls_key", "") or ""
            if cert and key:
                ssl_ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
                ssl_ctx.minimum_version = _ssl.TLSVersion.TLSv1_2
                ssl_ctx.load_cert_chain(cert, key)

        self._app = web.Application(
            middlewares=middlewares,
            client_max_size=max_body,
        )
        self._register_routes(self._app)
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self.host, self.port, ssl_context=ssl_ctx)
        await site.start()
        scheme = "https" if ssl_ctx else "http"
        logger.info(f"API listening on {scheme}://{self.host}:{self.port}")

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
        # ── New endpoints ──
        app.router.add_get("/account/{address}", self._account_info)
        app.router.add_get("/account/{address}/lines", self._account_lines)
        app.router.add_get("/account/{address}/offers", self._account_offers)
        app.router.add_get("/account/{address}/nftokens", self._account_nftokens)
        app.router.add_get("/account/{address}/escrows", self._account_escrows)
        app.router.add_get("/account/{address}/channels", self._account_channels)
        app.router.add_get("/account/{address}/checks", self._account_checks)
        app.router.add_get("/tx/{tx_id}", self._get_transaction)
        # New tx submission endpoints
        app.router.add_post("/tx/escrow/create", self._submit_escrow_create)
        app.router.add_post("/tx/escrow/finish", self._submit_escrow_finish)
        app.router.add_post("/tx/escrow/cancel", self._submit_escrow_cancel)
        app.router.add_post("/tx/check/create", self._submit_check_create)
        app.router.add_post("/tx/check/cash", self._submit_check_cash)
        app.router.add_post("/tx/check/cancel", self._submit_check_cancel)
        app.router.add_post("/tx/account_set", self._submit_account_set)
        app.router.add_post("/tx/nftoken/mint", self._submit_nftoken_mint)
        # Amendments
        app.router.add_get("/amendments", self._amendments)
        # WebSocket
        app.router.add_get("/ws", self._websocket_handler)

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
        amount = _safe_float(body.get("amount", 0), "amount")
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
        limit = _safe_float(body.get("limit", 0), "limit")

        if not currency or not issuer or limit <= 0:
            raise web.HTTPBadRequest(text="currency, issuer, and positive limit required")

        from nexaflow_core.transaction import create_trust_set
        tx = create_trust_set(self.node.wallet.address, currency, issuer, limit)
        self.node.wallet.sign_transaction(tx)

        valid, _code, msg = self.node.validator.validate(tx)
        if not valid:
            raise web.HTTPBadRequest(text=f"Validation failed: {_sanitize_validation_msg(msg)}")

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
        """POST /consensus — admin-only consensus trigger.

        This endpoint is gated behind API-key auth like all POST endpoints.
        Operators should use a strong API key to prevent abuse.
        """
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

        amount = _safe_float(body.get("amount", 0), "amount")
        tier = _safe_int(body.get("tier", 0), "tier")
        memo = body.get("memo", "")

        if amount <= 0:
            raise web.HTTPBadRequest(text="positive amount required")

        from nexaflow_core.transaction import create_stake
        tx = create_stake(self.node.wallet.address, amount, tier, memo=memo)
        self.node.wallet.sign_transaction(tx)

        valid, _code, msg = self.node.validator.validate(tx)
        if not valid:
            raise web.HTTPBadRequest(text=f"Validation failed: {_sanitize_validation_msg(msg)}")

        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(
                text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}"
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
            raise web.HTTPBadRequest(text=f"Validation failed: {_sanitize_validation_msg(msg)}")

        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(
                text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}"
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

    # ── account info endpoints ───────────────────────────────────

    async def _account_info(self, request: web.Request) -> web.Response:
        """GET /account/{address} — full account state."""
        address = request.match_info["address"]
        acc = self.node.ledger.get_account(address)
        if acc is None:
            raise web.HTTPNotFound(text=f"Account {address} not found")
        info = acc.to_dict()
        info["transfer_rate"] = acc.transfer_rate
        info["require_dest"] = acc.require_dest
        info["deposit_auth"] = acc.deposit_auth
        info["default_ripple"] = acc.default_ripple
        info["global_freeze"] = acc.global_freeze
        info["disable_master"] = acc.disable_master
        info["regular_key"] = acc.regular_key
        info["domain"] = acc.domain
        info["deposit_preauth"] = list(acc.deposit_preauth)
        info["tickets"] = acc.tickets
        # Signer list
        sl = self.node.ledger.multi_sign_manager.get_signer_list(address)
        info["signer_list"] = sl.to_dict() if sl else None
        return web.json_response(info, dumps=_json_dumps)

    async def _account_lines(self, request: web.Request) -> web.Response:
        """GET /account/{address}/lines — trust lines with pagination."""
        address = request.match_info["address"]
        acc = self.node.ledger.get_account(address)
        if acc is None:
            raise web.HTTPNotFound(text=f"Account {address} not found")
        limit = _safe_int(request.query.get("limit", "200"), "limit")
        marker = _safe_int(request.query.get("marker", "0"), "marker")
        lines = []
        all_tl = list(acc.trust_lines.values())
        page = all_tl[marker : marker + limit]
        for tl in page:
            lines.append({
                "currency": tl.currency,
                "issuer": tl.issuer,
                "balance": tl.balance,
                "limit": tl.limit,
                "limit_peer": tl.limit_peer,
                "no_ripple": tl.no_ripple,
                "frozen": tl.frozen,
                "authorized": tl.authorized,
                "quality_in": tl.quality_in,
                "quality_out": tl.quality_out,
            })
        result = {"account": address, "lines": lines}
        if marker + limit < len(all_tl):
            result["marker"] = marker + limit
        return web.json_response(result, dumps=_json_dumps)

    async def _account_offers(self, request: web.Request) -> web.Response:
        """GET /account/{address}/offers — open DEX offers."""
        address = request.match_info["address"]
        acc = self.node.ledger.get_account(address)
        if acc is None:
            raise web.HTTPNotFound(text=f"Account {address} not found")
        offers = acc.open_offers
        return web.json_response(
            {"account": address, "offers": offers, "count": len(offers)},
            dumps=_json_dumps,
        )

    async def _account_nftokens(self, request: web.Request) -> web.Response:
        """GET /account/{address}/nftokens — owned NFTokens."""
        address = request.match_info["address"]
        tokens = self.node.ledger.nftoken_manager.get_tokens_for_account(address)
        return web.json_response(
            {"account": address, "nftokens": [t.to_dict() for t in tokens]},
            dumps=_json_dumps,
        )

    async def _account_escrows(self, request: web.Request) -> web.Response:
        """GET /account/{address}/escrows — active escrows."""
        address = request.match_info["address"]
        escrows = self.node.ledger.escrow_manager.get_escrows_for_account(address)
        return web.json_response(
            {"account": address, "escrows": [e.to_dict() for e in escrows]},
            dumps=_json_dumps,
        )

    async def _account_channels(self, request: web.Request) -> web.Response:
        """GET /account/{address}/channels — active payment channels."""
        address = request.match_info["address"]
        channels = self.node.ledger.channel_manager.get_channels_for_account(address)
        return web.json_response(
            {"account": address, "channels": [c.to_dict() for c in channels]},
            dumps=_json_dumps,
        )

    async def _account_checks(self, request: web.Request) -> web.Response:
        """GET /account/{address}/checks — pending checks."""
        address = request.match_info["address"]
        checks = self.node.ledger.check_manager.get_checks_for_account(address)
        return web.json_response(
            {"account": address, "checks": [c.to_dict() for c in checks]},
            dumps=_json_dumps,
        )

    async def _get_transaction(self, request: web.Request) -> web.Response:
        """GET /tx/{tx_id} — lookup transaction by ID."""
        tx_id = request.match_info["tx_id"]
        tx_obj = getattr(self.node, "tx_objects", {}).get(tx_id)
        if tx_obj is not None:
            return web.json_response(tx_obj.to_dict(), dumps=_json_dumps)
        tx_dict = self.node.tx_pool.get(tx_id)
        if tx_dict is not None:
            return web.json_response(tx_dict, dumps=_json_dumps)
        raise web.HTTPNotFound(text=f"Transaction {tx_id} not found")

    # ── new transaction submission handlers ──────────────────────

    async def _submit_escrow_create(self, request: web.Request) -> web.Response:
        """POST /tx/escrow/create"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        dest = body.get("destination", "")
        amount = _safe_float(body.get("amount", 0), "amount")
        finish_after = _safe_int(body.get("finish_after", 0), "finish_after")
        cancel_after = _safe_int(body.get("cancel_after", 0), "cancel_after")
        condition = body.get("condition", "")
        if not dest or amount <= 0:
            raise web.HTTPBadRequest(text="destination and positive amount required")
        from nexaflow_core.transaction import create_escrow_create
        tx = create_escrow_create(self.node.wallet.address, dest, amount,
                                  finish_after, cancel_after, condition)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "escrow_created", "tx_id": tx.tx_id})

    async def _submit_escrow_finish(self, request: web.Request) -> web.Response:
        """POST /tx/escrow/finish"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        escrow_id = body.get("escrow_id", "")
        owner = body.get("owner", "")
        fulfillment = body.get("fulfillment", "")
        from nexaflow_core.transaction import create_escrow_finish
        tx = create_escrow_finish(self.node.wallet.address, owner, escrow_id, fulfillment)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "escrow_finished", "tx_id": tx.tx_id})

    async def _submit_escrow_cancel(self, request: web.Request) -> web.Response:
        """POST /tx/escrow/cancel"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        escrow_id = body.get("escrow_id", "")
        owner = body.get("owner", "")
        from nexaflow_core.transaction import create_escrow_cancel
        tx = create_escrow_cancel(self.node.wallet.address, owner, escrow_id)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "escrow_cancelled", "tx_id": tx.tx_id})

    async def _submit_check_create(self, request: web.Request) -> web.Response:
        """POST /tx/check/create"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        dest = body.get("destination", "")
        send_max = _safe_float(body.get("send_max", 0), "send_max")
        currency = body.get("currency", "NXF")
        issuer = body.get("issuer", "")
        expiration = _safe_int(body.get("expiration", 0), "expiration")
        from nexaflow_core.transaction import create_check_create
        tx = create_check_create(self.node.wallet.address, dest, send_max,
                                 currency, issuer, expiration)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "check_created", "tx_id": tx.tx_id})

    async def _submit_check_cash(self, request: web.Request) -> web.Response:
        """POST /tx/check/cash"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        check_id = body.get("check_id", "")
        amount = _safe_float(body.get("amount", 0), "amount")
        deliver_min = _safe_float(body.get("deliver_min", 0), "deliver_min")
        from nexaflow_core.transaction import create_check_cash
        tx = create_check_cash(self.node.wallet.address, check_id, amount, deliver_min)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "check_cashed", "tx_id": tx.tx_id})

    async def _submit_check_cancel(self, request: web.Request) -> web.Response:
        """POST /tx/check/cancel"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        check_id = body.get("check_id", "")
        from nexaflow_core.transaction import create_check_cancel
        tx = create_check_cancel(self.node.wallet.address, check_id)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "check_cancelled", "tx_id": tx.tx_id})

    async def _submit_account_set(self, request: web.Request) -> web.Response:
        """POST /tx/account_set"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        set_flags = body.get("set_flags", {})
        clear_flags = body.get("clear_flags", {})
        transfer_rate = _safe_float(body.get("transfer_rate", 0), "transfer_rate")
        domain = body.get("domain", "")
        from nexaflow_core.transaction import create_account_set
        tx = create_account_set(self.node.wallet.address, set_flags, clear_flags,
                                transfer_rate, domain)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "account_set", "tx_id": tx.tx_id})

    async def _submit_nftoken_mint(self, request: web.Request) -> web.Response:
        """POST /tx/nftoken/mint"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        uri = body.get("uri", "")
        transfer_fee = _safe_int(body.get("transfer_fee", 0), "transfer_fee")
        taxon = _safe_int(body.get("nftoken_taxon", 0), "nftoken_taxon")
        transferable = body.get("transferable", True)
        burnable = body.get("burnable", True)
        from nexaflow_core.transaction import create_nftoken_mint
        tx = create_nftoken_mint(self.node.wallet.address, uri=uri,
                                 transfer_fee=transfer_fee, nftoken_taxon=taxon,
                                 transferable=transferable, burnable=burnable)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "nftoken_minted", "tx_id": tx.tx_id})

    # ── amendments ────────────────────────────────────────────────

    async def _amendments(self, _request: web.Request) -> web.Response:
        """GET /amendments — list all amendments and their status."""
        amendments = self.node.ledger.amendment_manager.get_all_amendments()
        enabled = self.node.ledger.amendment_manager.get_enabled()
        return web.json_response(
            {"amendments": amendments, "enabled": enabled},
            dumps=_json_dumps,
        )

    # ── WebSocket subscription ───────────────────────────────────

    async def _websocket_handler(self, request: web.Request) -> web.WebSocketResponse:
        """
        WebSocket /ws — subscribe to ledger events.

        Client sends JSON messages to subscribe:
          {"command": "subscribe", "streams": ["ledger", "transactions"]}
          {"command": "subscribe", "accounts": ["rXXX"]}
          {"command": "unsubscribe", "streams": ["ledger"]}

        Server pushes events matching subscriptions.
        """
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        subscriptions: dict[str, bool] = {}
        account_subs: set[str] = set()

        # Register this WebSocket for event broadcasting
        ws_id = id(ws)
        if not hasattr(self, "_ws_clients"):
            self._ws_clients = {}
        self._ws_clients[ws_id] = {
            "ws": ws,
            "streams": subscriptions,
            "accounts": account_subs,
        }

        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.JSONDecodeError:
                        await ws.send_json({"error": "Invalid JSON"})
                        continue

                    cmd = data.get("command", "")
                    if cmd == "subscribe":
                        for stream in data.get("streams", []):
                            subscriptions[stream] = True
                        for acct in data.get("accounts", []):
                            account_subs.add(acct)
                        await ws.send_json({"status": "subscribed",
                                            "streams": list(subscriptions.keys()),
                                            "accounts": list(account_subs)})
                    elif cmd == "unsubscribe":
                        for stream in data.get("streams", []):
                            subscriptions.pop(stream, None)
                        for acct in data.get("accounts", []):
                            account_subs.discard(acct)
                        await ws.send_json({"status": "unsubscribed"})
                    elif cmd == "ping":
                        await ws.send_json({"type": "pong"})
                    else:
                        await ws.send_json({"error": f"Unknown command: {cmd}"})
                elif msg.type == web.WSMsgType.ERROR:
                    logger.error(f"WebSocket error: {ws.exception()}")
        finally:
            self._ws_clients.pop(ws_id, None)

        return ws

    async def broadcast_ws_event(self, event_type: str, data: dict) -> None:
        """Broadcast an event to all WebSocket clients subscribed to the stream."""
        if not hasattr(self, "_ws_clients"):
            return
        for ws_info in list(self._ws_clients.values()):
            ws = ws_info["ws"]
            if ws.closed:
                continue
            # Check stream subscription
            if event_type in ws_info["streams"]:
                try:
                    await ws.send_json({"type": event_type, **data})
                except Exception:
                    pass
            # Check account subscription
            if event_type == "transaction":
                acct = data.get("account", "")
                dest = data.get("destination", "")
                if acct in ws_info["accounts"] or dest in ws_info["accounts"]:
                    try:
                        await ws.send_json({"type": "account_transaction", **data})
                    except Exception:
                        pass


def _json_dumps(obj: Any) -> str:
    """JSON serialiser that handles non-standard types."""
    return json.dumps(obj, default=str)
