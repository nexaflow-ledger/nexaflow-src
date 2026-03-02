"""
WebSocket API & Subscriptions (Tier 2).

Provides real-time streaming of ledger events via aiohttp WebSocket
connections, mirroring the XRPL WebSocket API:

Subscription streams
--------------------
* ``ledger``       — emitted on each validated ledger close
* ``transactions`` — emitted for every applied transaction
* ``accounts``     — emitted when a subscribed account's state changes
* ``book``         — emitted when orders change for a given book
* ``peer_status``  — emitted on peer connect/disconnect events

Clients send JSON commands:

    { "command": "subscribe", "streams": ["ledger", "transactions"] }
    { "command": "subscribe", "accounts": ["rAddr1"] }
    { "command": "unsubscribe", "streams": ["ledger"] }
    { "command": "ping" }
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

try:
    import aiohttp
    from aiohttp import web
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

log = logging.getLogger("nexaflow.websocket")


# ── Subscription manager ────────────────────────────────────────

@dataclass
class ClientSubscription:
    """Tracks what a single WebSocket client is subscribed to."""
    ws_id: str
    ws: Any  # aiohttp.web.WebSocketResponse (or None for testing)
    streams: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    books: set[str] = field(default_factory=set)  # "base/counter"


class SubscriptionManager:
    """
    Manages all active WebSocket clients and their subscriptions.
    Provides broadcast helpers that the core ledger calls when
    state changes occur.
    """

    VALID_STREAMS = {"ledger", "transactions", "peer_status",
                     "consensus", "server", "validations"}

    def __init__(self):
        self._clients: dict[str, ClientSubscription] = {}
        self._lock = asyncio.Lock()
        self._broadcast_queue: asyncio.Queue[dict] = asyncio.Queue(maxsize=10_000)
        self._running = False
        self._task: Optional[asyncio.Task] = None

    # ── Client lifecycle ────────────────────────────────────────

    async def add_client(self, ws: Any) -> str:
        ws_id = str(uuid.uuid4())
        async with self._lock:
            self._clients[ws_id] = ClientSubscription(ws_id=ws_id, ws=ws)
        return ws_id

    async def remove_client(self, ws_id: str) -> None:
        async with self._lock:
            self._clients.pop(ws_id, None)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    # ── Subscription commands ───────────────────────────────────

    async def subscribe(self, ws_id: str, streams: list[str] | None = None,
                        accounts: list[str] | None = None,
                        books: list[dict] | None = None) -> dict:
        async with self._lock:
            sub = self._clients.get(ws_id)
            if not sub:
                return {"error": "unknown_client"}

            result: dict[str, Any] = {"status": "success"}
            if streams:
                valid = set(streams) & self.VALID_STREAMS
                sub.streams |= valid
                invalid = set(streams) - self.VALID_STREAMS
                if invalid:
                    result["warnings"] = [f"Unknown stream: {s}" for s in invalid]
            if accounts:
                sub.accounts |= set(accounts)
            if books:
                for b in books:
                    key = f"{b.get('taker_pays', {}).get('currency', 'NXF')}/{b.get('taker_gets', {}).get('currency', 'NXF')}"
                    sub.books.add(key)
            return result

    async def unsubscribe(self, ws_id: str, streams: list[str] | None = None,
                          accounts: list[str] | None = None,
                          books: list[dict] | None = None) -> dict:
        async with self._lock:
            sub = self._clients.get(ws_id)
            if not sub:
                return {"error": "unknown_client"}
            if streams:
                sub.streams -= set(streams)
            if accounts:
                sub.accounts -= set(accounts)
            if books:
                for b in books:
                    key = f"{b.get('taker_pays', {}).get('currency', 'NXF')}/{b.get('taker_gets', {}).get('currency', 'NXF')}"
                    sub.books.discard(key)
            return {"status": "success"}

    # ── Broadcast helpers (called by core) ──────────────────────

    async def broadcast_ledger(self, ledger_data: dict) -> None:
        """Broadcast ledger close event to subscribers."""
        msg = {
            "type": "ledgerClosed",
            "ledger_index": ledger_data.get("sequence", 0),
            "ledger_hash": ledger_data.get("hash", ""),
            "ledger_time": ledger_data.get("close_time", 0),
            "txn_count": ledger_data.get("txn_count", 0),
            "reserve_base": ledger_data.get("reserve_base", 10000000),
            "reserve_inc": ledger_data.get("reserve_inc", 2000000),
            "fee_base": ledger_data.get("fee_base", 10),
        }
        await self._send_to_stream("ledger", msg)

    async def broadcast_transaction(self, tx_data: dict) -> None:
        """Broadcast a transaction to relevant subscribers."""
        msg = {
            "type": "transaction",
            "transaction": tx_data,
            "status": "closed",
            "validated": True,
        }
        await self._send_to_stream("transactions", msg)

        # Also notify account-specific subscribers
        accounts_involved = set()
        if tx_data.get("account"):
            accounts_involved.add(tx_data["account"])
        if tx_data.get("destination"):
            accounts_involved.add(tx_data["destination"])

        if accounts_involved:
            await self._send_to_accounts(accounts_involved, msg)

    async def broadcast_peer_status(self, peer_data: dict) -> None:
        msg = {"type": "peerStatusChange", **peer_data}
        await self._send_to_stream("peer_status", msg)

    async def broadcast_book_change(self, base_currency: str,
                                    counter_currency: str,
                                    offers: list[dict]) -> None:
        book_key = f"{base_currency}/{counter_currency}"
        msg = {
            "type": "bookChanges",
            "book": book_key,
            "offers": offers,
        }
        async with self._lock:
            for sub in self._clients.values():
                if book_key in sub.books:
                    await self._safe_send(sub.ws, msg)

    async def broadcast_server_status(self, status_data: dict) -> None:
        msg = {"type": "serverStatus", **status_data}
        await self._send_to_stream("server", msg)

    async def broadcast_validation(self, validation_data: dict) -> None:
        msg = {"type": "validationReceived", **validation_data}
        await self._send_to_stream("validations", msg)

    async def broadcast_consensus(self, consensus_data: dict) -> None:
        msg = {"type": "consensusPhase", **consensus_data}
        await self._send_to_stream("consensus", msg)

    # ── Internal ────────────────────────────────────────────────

    async def _send_to_stream(self, stream: str, msg: dict) -> None:
        async with self._lock:
            for sub in self._clients.values():
                if stream in sub.streams:
                    await self._safe_send(sub.ws, msg)

    async def _send_to_accounts(self, accounts: set[str], msg: dict) -> None:
        async with self._lock:
            for sub in self._clients.values():
                if sub.accounts & accounts:
                    await self._safe_send(sub.ws, msg)

    @staticmethod
    async def _safe_send(ws: Any, msg: dict) -> None:
        try:
            if ws is not None and not getattr(ws, 'closed', True) if not HAS_AIOHTTP else True:
                data = json.dumps(msg, default=str)
                if HAS_AIOHTTP and hasattr(ws, 'send_json'):
                    await ws.send_json(msg, dumps=lambda o: json.dumps(o, default=str))
                elif hasattr(ws, 'send_str'):
                    await ws.send_str(data)
        except Exception as exc:
            log.debug("WS send error: %s", exc)


# ── WebSocket handler for aiohttp ───────────────────────────────

async def websocket_handler(request: Any, manager: SubscriptionManager,
                            server_info_fn=None) -> Any:
    """
    aiohttp WebSocket handler.

    Use as::

        app.router.add_get('/ws', lambda r: websocket_handler(r, mgr))
    """
    if not HAS_AIOHTTP:
        raise RuntimeError("aiohttp is required for WebSocket support")

    ws = web.WebSocketResponse(heartbeat=30.0)
    await ws.prepare(request)

    ws_id = await manager.add_client(ws)
    log.info("WS client connected: %s", ws_id)

    try:
        async for msg in ws:
            if msg.type == aiohttp.WSMsgType.TEXT:
                try:
                    data = json.loads(msg.data)
                except json.JSONDecodeError:
                    await ws.send_json({"error": "invalid_json"})
                    continue

                command = data.get("command", data.get("method", ""))
                response = await _handle_ws_command(
                    manager, ws_id, command, data, server_info_fn
                )
                response["id"] = data.get("id")
                await ws.send_json(response, dumps=lambda o: json.dumps(o, default=str))

            elif msg.type in (aiohttp.WSMsgType.ERROR,
                              aiohttp.WSMsgType.CLOSE):
                break
    finally:
        await manager.remove_client(ws_id)
        log.info("WS client disconnected: %s", ws_id)

    return ws


async def _handle_ws_command(manager: SubscriptionManager, ws_id: str,
                             command: str, data: dict,
                             server_info_fn=None) -> dict:
    """Route a WebSocket command to the appropriate handler."""
    if command == "subscribe":
        return await manager.subscribe(
            ws_id,
            streams=data.get("streams"),
            accounts=data.get("accounts"),
            books=data.get("books"),
        )
    elif command == "unsubscribe":
        return await manager.unsubscribe(
            ws_id,
            streams=data.get("streams"),
            accounts=data.get("accounts"),
            books=data.get("books"),
        )
    elif command == "ping":
        return {"status": "success", "type": "pong", "time": int(time.time())}
    elif command == "server_info":
        if server_info_fn:
            info = server_info_fn()
            return {"status": "success", "result": {"info": info}}
        return {"status": "success", "result": {"info": {}}}
    else:
        return {"error": "unknownCmd", "error_message": f"Unknown command: {command}"}
