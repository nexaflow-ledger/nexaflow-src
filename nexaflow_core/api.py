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
GET  /health                  Liveness probe (always 200)

Usage:
    api = APIServer(node, host="127.0.0.1", port=8080)
    await api.start()    # call inside existing event loop
    ...
    await api.stop()
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from aiohttp import web

if TYPE_CHECKING:
    pass  # avoid circular imports; NexaFlowNode injected at runtime

logger = logging.getLogger("nexaflow_api")


class APIServer:
    """Thin aiohttp wrapper around a running NexaFlowNode."""

    def __init__(self, node: Any, host: str = "127.0.0.1", port: int = 8080):
        self.node = node
        self.host = host
        self.port = port
        self._app: web.Application | None = None
        self._runner: web.AppRunner | None = None

    # ── lifecycle ────────────────────────────────────────────────

    async def start(self) -> None:
        self._app = web.Application()
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

    # ── handlers ─────────────────────────────────────────────────

    async def _health(self, _request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

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


def _json_dumps(obj: Any) -> str:
    """JSON serialiser that handles non-standard types."""
    return json.dumps(obj, default=str)
