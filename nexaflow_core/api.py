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
        # ── Tier 1-3 endpoints ──
        app.router.add_get("/server_info", self._server_info)
        app.router.add_get("/account/{address}/tx", self._account_tx)
        app.router.add_get("/ledger/data", self._ledger_data)
        # AMM
        app.router.add_get("/amm/{pool_id}", self._amm_info)
        app.router.add_get("/amm", self._amm_list)
        app.router.add_post("/tx/amm/create", self._submit_amm_create)
        app.router.add_post("/tx/amm/deposit", self._submit_amm_deposit)
        app.router.add_post("/tx/amm/withdraw", self._submit_amm_withdraw)
        app.router.add_post("/tx/amm/swap", self._submit_amm_swap)
        # Oracles
        app.router.add_get("/oracle/{oracle_id}", self._oracle_info)
        app.router.add_get("/oracle/price/{base}/{quote}", self._oracle_price)
        app.router.add_post("/tx/oracle/set", self._submit_oracle_set)
        app.router.add_post("/tx/oracle/delete", self._submit_oracle_delete)
        # DID
        app.router.add_get("/did/{address}", self._did_info)
        app.router.add_post("/tx/did/set", self._submit_did_set)
        app.router.add_post("/tx/did/delete", self._submit_did_delete)
        # MPT
        app.router.add_get("/mpt/{mpt_id}", self._mpt_info)
        app.router.add_post("/tx/mpt/create", self._submit_mpt_create)
        # Credentials
        app.router.add_get("/credential/{credential_id}", self._credential_info)
        app.router.add_post("/tx/credential/create", self._submit_credential_create)
        # Cross-chain
        app.router.add_get("/bridge/{bridge_id}", self._bridge_info)
        app.router.add_post("/tx/xchain/create_bridge", self._submit_xchain_create_bridge)
        # Hooks
        app.router.add_get("/hooks/{address}", self._hooks_info)
        app.router.add_post("/tx/hook/set", self._submit_set_hook)
        # WebSocket
        app.router.add_get("/ws", self._websocket_handler)
        # ── Tier 2: additional query endpoints ──
        app.router.add_get("/book_offers/{base}/{counter}", self._book_offers)
        app.router.add_get("/fee", self._fee_info)
        # ── Tier 3: admin-only endpoint (requires X-Admin-Key) ──
        app.router.add_post("/admin/stop", self._admin_stop)
        app.router.add_get("/admin/peers", self._admin_peers)
        app.router.add_post("/admin/log_level", self._admin_log_level)
        # ── Pathfinding ──
        app.router.add_post("/path_find", self._path_find)

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

    # ── Tier 1-3 handlers ────────────────────────────────────────

    async def _server_info(self, _request: web.Request) -> web.Response:
        """GET /server_info — build version, uptime, state, features."""
        import time as _time
        uptime = _time.time() - getattr(self.node, "_start_time", _time.time())
        ledger = self.node.ledger
        closed_count = len(ledger.closed_ledgers)
        validated_range = f"1-{closed_count}" if closed_count > 0 else "empty"
        # Load factor
        load_factor = 1
        if hasattr(ledger, "fee_escalation"):
            stats = ledger.fee_escalation.get_stats()
            load_factor = stats.get("load_factor", 1)
        info = {
            "build_version": "0.9.0",
            "server_state": "full",
            "uptime": int(uptime),
            "node_id": self.node.node_id,
            "complete_ledgers": validated_range,
            "peers": self.node.p2p.peer_count,
            "ledger_sequence": ledger.current_sequence,
            "validated_ledger": {
                "seq": closed_count,
                "hash": ledger.closed_ledgers[-1].hash if closed_count > 0 else "",
                "close_time": ledger.closed_ledgers[-1].close_time if closed_count > 0 else 0,
            },
            "load_factor": load_factor,
            "total_supply": ledger.total_supply,
            "total_burned": ledger.total_burned,
            "total_minted": ledger.total_minted,
            "account_count": len(ledger.accounts),
            "tx_pool_size": len(self.node.tx_pool),
            "reserve_base": getattr(ledger, "BASE_RESERVE", 10.0),
            "reserve_inc": getattr(ledger, "OWNER_RESERVE_INC", 2.0),
            "fee_base": 10,
            "amendments_enabled": (
                len(ledger.amendment_manager.get_enabled())
                if hasattr(ledger, "amendment_manager") else 0
            ),
            "state_accounting": {
                "full": {"duration_us": int(uptime * 1_000_000)},
            },
        }
        return web.json_response({"result": {"info": info}}, dumps=_json_dumps)

    async def _account_tx(self, request: web.Request) -> web.Response:
        """GET /account/{address}/tx — paginated transaction history."""
        address = request.match_info["address"]
        limit = _safe_int(request.query.get("limit", "20"), "limit")
        marker = _safe_int(request.query.get("marker", "0"), "marker")
        # Collect from tx_objects
        txns = []
        all_tx = list(getattr(self.node, "tx_objects", {}).values())
        matching = [t for t in all_tx
                    if t.account == address or getattr(t, "destination", "") == address]
        page = matching[marker:marker + limit]
        for t in page:
            txns.append(t.to_dict())
        result = {"account": address, "transactions": txns}
        if marker + limit < len(matching):
            result["marker"] = marker + limit
        return web.json_response(result, dumps=_json_dumps)

    async def _ledger_data(self, _request: web.Request) -> web.Response:
        """GET /ledger/data — all ledger objects summary."""
        ledger = self.node.ledger
        data = {
            "accounts": len(ledger.accounts),
            "trust_lines": sum(len(a.trust_lines) for a in ledger.accounts.values()),
            "amm_pools": len(ledger.amm_manager.pools) if hasattr(ledger, "amm_manager") else 0,
            "oracles": len(ledger.oracle_manager.oracles) if hasattr(ledger, "oracle_manager") else 0,
            "dids": len(ledger.did_manager.dids) if hasattr(ledger, "did_manager") else 0,
            "mpt_issuances": len(ledger.mpt_manager.issuances) if hasattr(ledger, "mpt_manager") else 0,
            "credentials": len(ledger.credential_manager.credentials) if hasattr(ledger, "credential_manager") else 0,
            "bridges": len(ledger.xchain_manager.bridges) if hasattr(ledger, "xchain_manager") else 0,
            "hooks": len(ledger.hooks_manager.definitions) if hasattr(ledger, "hooks_manager") else 0,
        }
        return web.json_response(data, dumps=_json_dumps)

    # ── AMM handlers ─────────────────────────────────────────────

    async def _amm_info(self, request: web.Request) -> web.Response:
        """GET /amm/{pool_id}"""
        pool_id = request.match_info["pool_id"]
        pool = self.node.ledger.amm_manager.get_pool(pool_id)
        if pool is None:
            raise web.HTTPNotFound(text=f"AMM pool {pool_id} not found")
        return web.json_response(pool.to_dict(), dumps=_json_dumps)

    async def _amm_list(self, _request: web.Request) -> web.Response:
        """GET /amm — list all AMM pools."""
        pools = self.node.ledger.amm_manager.get_pools()
        return web.json_response(
            {"pools": [p.to_dict() for p in pools]}, dumps=_json_dumps)

    async def _submit_amm_create(self, request: web.Request) -> web.Response:
        """POST /tx/amm/create"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_amm_create
        tx = create_amm_create(
            self.node.wallet.address,
            body.get("asset_a", ""), body.get("asset_b", ""),
            _safe_float(body.get("amount_a", 0), "amount_a"),
            _safe_float(body.get("amount_b", 0), "amount_b"),
            _safe_int(body.get("trading_fee", 100), "trading_fee"),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "amm_created", "tx_id": tx.tx_id})

    async def _submit_amm_deposit(self, request: web.Request) -> web.Response:
        """POST /tx/amm/deposit"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_amm_deposit
        tx = create_amm_deposit(
            self.node.wallet.address,
            body.get("pool_id", ""),
            _safe_float(body.get("amount_a", 0), "amount_a"),
            _safe_float(body.get("amount_b", 0), "amount_b"),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "amm_deposited", "tx_id": tx.tx_id})

    async def _submit_amm_withdraw(self, request: web.Request) -> web.Response:
        """POST /tx/amm/withdraw"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_amm_withdraw
        tx = create_amm_withdraw(
            self.node.wallet.address,
            body.get("pool_id", ""),
            _safe_float(body.get("lp_tokens", 0), "lp_tokens"),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "amm_withdrawn", "tx_id": tx.tx_id})

    async def _submit_amm_swap(self, request: web.Request) -> web.Response:
        """POST /tx/amm/swap — convenience endpoint wrapping AMMDeposit-style swap."""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        pool_id = body.get("pool_id", "")
        asset_in = body.get("asset_in", "")
        amount_in = _safe_float(body.get("amount_in", 0), "amount_in")
        pool = self.node.ledger.amm_manager.get_pool(pool_id)
        if pool is None:
            raise web.HTTPNotFound(text=f"AMM pool {pool_id} not found")
        try:
            out_amount, out_asset = self.node.ledger.amm_manager.swap(
                pool_id, self.node.wallet.address, asset_in, amount_in)
        except Exception as e:
            raise web.HTTPBadRequest(text=str(e))
        return web.json_response({
            "status": "swapped",
            "asset_out": out_asset,
            "amount_out": out_amount,
        }, dumps=_json_dumps)

    # ── Oracle handlers ──────────────────────────────────────────

    async def _oracle_info(self, request: web.Request) -> web.Response:
        """GET /oracle/{oracle_id}"""
        oracle_id = request.match_info["oracle_id"]
        oracle = self.node.ledger.oracle_manager.get_oracle(oracle_id)
        if oracle is None:
            raise web.HTTPNotFound(text=f"Oracle {oracle_id} not found")
        return web.json_response(oracle.to_dict(), dumps=_json_dumps)

    async def _oracle_price(self, request: web.Request) -> web.Response:
        """GET /oracle/price/{base}/{quote} — aggregated trimmed-mean price."""
        base = request.match_info["base"]
        quote = request.match_info["quote"]
        trim_pct = _safe_float(request.query.get("trim", "20"), "trim")
        try:
            price = self.node.ledger.oracle_manager.get_aggregate_price(
                base, quote, trim_pct)
        except ValueError as e:
            raise web.HTTPNotFound(text=str(e))
        return web.json_response({
            "base_asset": base, "quote_asset": quote,
            "price": price, "trim_pct": trim_pct,
        }, dumps=_json_dumps)

    async def _submit_oracle_set(self, request: web.Request) -> web.Response:
        """POST /tx/oracle/set"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_oracle_set
        tx = create_oracle_set(
            self.node.wallet.address,
            body.get("base_asset", ""), body.get("quote_asset", ""),
            body.get("prices", []),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "oracle_set", "tx_id": tx.tx_id})

    async def _submit_oracle_delete(self, request: web.Request) -> web.Response:
        """POST /tx/oracle/delete"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_oracle_delete
        tx = create_oracle_delete(self.node.wallet.address, body.get("oracle_id", ""))
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "oracle_deleted", "tx_id": tx.tx_id})

    # ── DID handlers ─────────────────────────────────────────────

    async def _did_info(self, request: web.Request) -> web.Response:
        """GET /did/{address}"""
        address = request.match_info["address"]
        did = self.node.ledger.did_manager.get_did(address)
        if did is None:
            raise web.HTTPNotFound(text=f"DID for {address} not found")
        return web.json_response(did.to_dict(), dumps=_json_dumps)

    async def _submit_did_set(self, request: web.Request) -> web.Response:
        """POST /tx/did/set"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_did_set
        tx = create_did_set(
            self.node.wallet.address,
            body.get("document", ""), body.get("uri", ""), body.get("data", ""),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "did_set", "tx_id": tx.tx_id})

    async def _submit_did_delete(self, request: web.Request) -> web.Response:
        """POST /tx/did/delete"""
        from nexaflow_core.transaction import create_did_delete
        tx = create_did_delete(self.node.wallet.address)
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "did_deleted", "tx_id": tx.tx_id})

    # ── MPT handlers ─────────────────────────────────────────────

    async def _mpt_info(self, request: web.Request) -> web.Response:
        """GET /mpt/{mpt_id}"""
        mpt_id = request.match_info["mpt_id"]
        issuance = self.node.ledger.mpt_manager.issuances.get(mpt_id)
        if issuance is None:
            raise web.HTTPNotFound(text=f"MPT issuance {mpt_id} not found")
        return web.json_response(issuance.to_dict(), dumps=_json_dumps)

    async def _submit_mpt_create(self, request: web.Request) -> web.Response:
        """POST /tx/mpt/create"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_mpt_issuance_create
        tx = create_mpt_issuance_create(
            self.node.wallet.address,
            _safe_int(body.get("max_supply", 0), "max_supply"),
            _safe_int(body.get("flags", 0), "flags"),
            body.get("metadata", ""),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "mpt_created", "tx_id": tx.tx_id})

    # ── Credential handlers ──────────────────────────────────────

    async def _credential_info(self, request: web.Request) -> web.Response:
        """GET /credential/{credential_id}"""
        cred_id = request.match_info["credential_id"]
        cred = self.node.ledger.credential_manager.credentials.get(cred_id)
        if cred is None:
            raise web.HTTPNotFound(text=f"Credential {cred_id} not found")
        return web.json_response(cred.to_dict(), dumps=_json_dumps)

    async def _submit_credential_create(self, request: web.Request) -> web.Response:
        """POST /tx/credential/create"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_credential_create
        tx = create_credential_create(
            self.node.wallet.address,
            body.get("subject", ""),
            body.get("credential_type", ""),
            body.get("uri", ""),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "credential_created", "tx_id": tx.tx_id})

    # ── Cross-chain handlers ─────────────────────────────────────

    async def _bridge_info(self, request: web.Request) -> web.Response:
        """GET /bridge/{bridge_id}"""
        bridge_id = request.match_info["bridge_id"]
        bridge = self.node.ledger.xchain_manager.bridges.get(bridge_id)
        if bridge is None:
            raise web.HTTPNotFound(text=f"Bridge {bridge_id} not found")
        return web.json_response(bridge.to_dict(), dumps=_json_dumps)

    async def _submit_xchain_create_bridge(self, request: web.Request) -> web.Response:
        """POST /tx/xchain/create_bridge"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_xchain_create_bridge
        tx = create_xchain_create_bridge(
            self.node.wallet.address,
            body.get("locking_chain_door", ""),
            body.get("issuing_chain_door", ""),
            body.get("locking_chain_issue", "NXF"),
            body.get("issuing_chain_issue", "NXF"),
            _safe_float(body.get("min_create_amount", 10.0), "min_create_amount"),
            _safe_float(body.get("signature_reward", 0.01), "signature_reward"),
            body.get("witness_accounts", []),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "bridge_created", "tx_id": tx.tx_id})

    # ── Hooks handlers ───────────────────────────────────────────

    async def _hooks_info(self, request: web.Request) -> web.Response:
        """GET /hooks/{address} — installed hooks for an account."""
        address = request.match_info["address"]
        hooks = self.node.ledger.hooks_manager.get_hooks(address)
        return web.json_response(
            {"account": address, "hooks": [h.to_dict() for h in hooks]},
            dumps=_json_dumps)

    async def _submit_set_hook(self, request: web.Request) -> web.Response:
        """POST /tx/hook/set"""
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc
        from nexaflow_core.transaction import create_set_hook
        tx = create_set_hook(
            self.node.wallet.address,
            body.get("hook_hash", ""),
            body.get("hook_on", []),
            body.get("hook_namespace", ""),
            body.get("hook_parameters", {}),
        )
        self.node.wallet.sign_transaction(tx)
        result = self.node.ledger.apply_transaction(tx)
        if result != 0:
            from nexaflow_core.transaction import RESULT_NAMES
            raise web.HTTPBadRequest(text=f"Apply failed: {RESULT_NAMES.get(result, 'unknown')}")
        return web.json_response({"status": "hook_set", "tx_id": tx.tx_id})

    # ── Tier 2: book_offers + fee RPCs ───────────────────────────

    async def _book_offers(self, request: web.Request) -> web.Response:
        """
        GET /book_offers/{base}/{counter}
        Returns the current order book for a given currency pair.
        Optional query params: limit (default 200)
        """
        base = request.match_info["base"]
        counter = request.match_info["counter"]
        limit = _safe_int(request.query.get("limit", "200"), "limit")

        # Gather offers from all accounts
        bids: list[dict] = []
        asks: list[dict] = []
        for acc in self.node.ledger.accounts.values():
            for offer in acc.open_offers:
                tp = offer.get("taker_pays")
                tg = offer.get("taker_gets")
                if tp is None or tg is None:
                    continue
                tp_cur = tp.currency if hasattr(tp, "currency") else "NXF"
                tg_cur = tg.currency if hasattr(tg, "currency") else "NXF"
                entry = {
                    "account": acc.address,
                    "taker_pays": tp.to_dict() if hasattr(tp, "to_dict") else str(tp),
                    "taker_gets": tg.to_dict() if hasattr(tg, "to_dict") else str(tg),
                    "tx_id": offer.get("tx_id", ""),
                    "time_in_force": offer.get("time_in_force", "GTC"),
                }
                if tp_cur == base and tg_cur == counter:
                    asks.append(entry)
                elif tp_cur == counter and tg_cur == base:
                    bids.append(entry)

        return web.json_response({
            "book": f"{base}/{counter}",
            "asks": asks[:limit],
            "bids": bids[:limit],
        }, dumps=_json_dumps)

    async def _fee_info(self, _request: web.Request) -> web.Response:
        """
        GET /fee
        Returns current transaction fee levels, queue stats, and reserve info.
        """
        ledger = self.node.ledger
        # Build fee data from whatever is available
        fee_data: dict = {
            "current_ledger_size": len(ledger.pending_txns),
            "expected_ledger_size": 100,
        }
        # If fee_model is available, use it
        if hasattr(ledger, "fee_model"):
            fee_data.update(ledger.fee_model.to_dict())
        elif hasattr(ledger, "fee_escalation"):
            fee_data["fee_escalation"] = ledger.fee_escalation.get_stats()

        # Reserve info
        base_reserve = getattr(ledger, "BASE_RESERVE", 10.0)
        inc_reserve = getattr(ledger, "OWNER_RESERVE_INC", 2.0)
        fee_data["drops"] = fee_data.get("drops", {
            "base_fee": "10",
            "median_fee": "10",
            "minimum_fee": "10",
            "open_ledger_fee": "10",
        })
        fee_data["reserve_base"] = base_reserve
        fee_data["reserve_inc"] = inc_reserve
        return web.json_response(fee_data, dumps=_json_dumps)

    # ── Tier 3: Admin RPC endpoints ──────────────────────────────

    def _check_admin_key(self, request: web.Request) -> None:
        """Validate admin API key. Raises HTTPForbidden if invalid."""
        admin_key = ""
        if self._api_config is not None:
            admin_key = getattr(self._api_config, "admin_key", "") or ""
        if not admin_key:
            # No admin key configured — admin endpoints disabled
            raise web.HTTPForbidden(text="Admin endpoints not configured")
        provided = request.headers.get("X-Admin-Key", "")
        if not hmac.compare_digest(provided, admin_key):
            raise web.HTTPForbidden(text="Invalid admin key")

    async def _admin_stop(self, request: web.Request) -> web.Response:
        """POST /admin/stop — gracefully shut down the node."""
        self._check_admin_key(request)
        logger.warning("Admin-initiated shutdown requested")
        return web.json_response({"status": "shutting_down"})

    async def _admin_peers(self, request: web.Request) -> web.Response:
        """GET /admin/peers — detailed peer info (admin only)."""
        self._check_admin_key(request)
        peers = []
        for p in self.node.p2p.connected_peers:
            peers.append({
                "node_id": getattr(p, "node_id", str(p)),
                "address": getattr(p, "address", ""),
                "latency_ms": getattr(p, "latency_ms", 0),
                "uptime": getattr(p, "uptime", 0),
            })
        return web.json_response({"peers": peers}, dumps=_json_dumps)

    async def _admin_log_level(self, request: web.Request) -> web.Response:
        """POST /admin/log_level — change logging level at runtime."""
        self._check_admin_key(request)
        try:
            body = await request.json()
        except Exception:
            raise web.HTTPBadRequest(text="Invalid JSON body")
        level = body.get("level", "INFO").upper()
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if level not in valid_levels:
            raise web.HTTPBadRequest(text=f"Invalid level. Use one of: {valid_levels}")
        logging.getLogger("nexaflow").setLevel(getattr(logging, level))
        logging.getLogger("nexaflow_api").setLevel(getattr(logging, level))
        return web.json_response({"status": "ok", "level": level})

    # ── Pathfinding ──────────────────────────────────────────────

    async def _path_find(self, request: web.Request) -> web.Response:
        """
        POST /path_find  (ripple_path_find equivalent)
        Body: {
          "source": "rSrc",
          "destination": "rDst",
          "currency": "USD",
          "amount": 100.0,
          "source_currency": "",  // optional, for cross-currency
          "max_paths": 5          // optional
        }
        Returns discovered payment paths with hops and max amounts.
        """
        try:
            body = await request.json()
        except Exception as exc:
            raise web.HTTPBadRequest(text="Invalid JSON body") from exc

        source = body.get("source", "")
        destination = body.get("destination", "")
        currency = body.get("currency", "NXF")
        amount = _safe_float(body.get("amount", 0), "amount")
        source_currency = body.get("source_currency", "")
        max_paths = int(body.get("max_paths", 5))

        if not source or not destination or amount <= 0:
            raise web.HTTPBadRequest(
                text="source, destination, and positive amount required"
            )

        from nexaflow_core.payment_path import PathFinder
        from nexaflow_core.trust_line import TrustGraph

        ledger = self.node.ledger
        tg = TrustGraph()
        tg.build_from_ledger(ledger)
        pf = PathFinder(tg, ledger, getattr(ledger, "order_book", None))

        paths = pf.find_paths(
            source=source,
            destination=destination,
            currency=currency,
            amount=amount,
            max_paths=max_paths,
            source_currency=source_currency,
        )

        return web.json_response({
            "source": source,
            "destination": destination,
            "currency": currency,
            "amount": amount,
            "alternatives": [p.to_dict() for p in paths],
        })


def _json_dumps(obj: Any) -> str:
    """JSON serialiser that handles non-standard types."""
    return json.dumps(obj, default=str)
