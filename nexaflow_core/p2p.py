"""
Real TCP-based P2P networking layer for NexaFlow.

Implements an async peer-to-peer protocol where nodes:
  - Discover and connect to peers
  - Broadcast transactions
  - Exchange consensus proposals
  - Synchronise ledger state

Protocol is JSON-over-TCP with newline-delimited messages.

Message types:
  HELLO        - handshake with node identity
  TX           - broadcast a signed transaction
  PROPOSAL     - consensus proposal for a ledger round
  CONSENSUS_OK - agreed transaction set after consensus
  LEDGER_REQ   - request ledger state
  LEDGER_RES   - ledger state response
  PING / PONG  - keepalive
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Callable

logger = logging.getLogger("nexaflow_p2p")


# =====================================================================
# Message helpers
# =====================================================================

def encode_message(msg_type: str, payload: dict) -> bytes:
    """Encode a message as a newline-terminated JSON blob."""
    msg = {"type": msg_type, "payload": payload, "ts": time.time()}
    return (json.dumps(msg, default=str) + "\n").encode("utf-8")


def decode_message(data: bytes) -> dict | None:
    """Decode a newline-terminated JSON message."""
    try:
        return json.loads(data.strip())
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


# =====================================================================
# Peer connection
# =====================================================================

class PeerConnection:
    """Represents a single TCP connection to a peer."""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer_id: str = "",
        direction: str = "outbound",
    ):
        self.reader = reader
        self.writer = writer
        self.peer_id = peer_id
        self.direction = direction
        self.connected_at = time.time()
        self.last_seen = time.time()
        self.messages_sent = 0
        self.messages_received = 0
        addr = writer.get_extra_info("peername")
        self.remote_addr: str = f"{addr[0]}:{addr[1]}" if addr else "unknown"

    async def send(self, msg_type: str, payload: dict) -> bool:
        """Send a message to this peer. Returns False if the write fails."""
        try:
            self.writer.write(encode_message(msg_type, payload))
            await self.writer.drain()
            self.messages_sent += 1
            return True
        except (ConnectionError, OSError):
            return False

    async def readline(self) -> dict | None:
        """Read one newline-delimited JSON message."""
        try:
            data = await asyncio.wait_for(self.reader.readline(), timeout=60.0)
            if not data:
                return None
            self.last_seen = time.time()
            self.messages_received += 1
            return decode_message(data)
        except (asyncio.TimeoutError, ConnectionError, OSError):
            return None

    async def close(self):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

    def info(self) -> dict:
        return {
            "peer_id": self.peer_id,
            "remote_addr": self.remote_addr,
            "direction": self.direction,
            "uptime": round(time.time() - self.connected_at, 1),
            "msgs_sent": self.messages_sent,
            "msgs_recv": self.messages_received,
        }


# =====================================================================
# P2P Node
# =====================================================================

class P2PNode:
    """
    Async TCP server + client that forms the P2P overlay.

    Usage:
        node = P2PNode(node_id="validator-1", host="0.0.0.0", port=9001)
        node.on_transaction = my_tx_handler
        node.on_proposal = my_proposal_handler
        await node.start()
        await node.connect_to_peer("127.0.0.1", 9002)
        await node.broadcast_transaction(tx_dict)
    """

    def __init__(
        self,
        node_id: str,
        host: str = "0.0.0.0",
        port: int = 9001,
    ):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.peers: dict[str, PeerConnection] = {}   # peer_id -> connection
        self._server: asyncio.AbstractServer | None = None
        self._running = False
        self._tasks: list[asyncio.Task] = []

        # Callbacks - set by the node runner
        self.on_transaction: Callable | None = None
        self.on_proposal: Callable | None = None
        self.on_consensus_result: Callable | None = None
        self.on_peer_connected: Callable | None = None
        self.on_peer_disconnected: Callable | None = None

        # Dedup - track seen message hashes to avoid rebroadcasts
        self._seen_ids: set[str] = set()
        self._max_seen = 10_000

    # ---- lifecycle ----

    async def start(self):
        """Start the TCP server and begin accepting connections."""
        self._server = await asyncio.start_server(
            self._handle_inbound, self.host, self.port
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        logger.info(f"[{self.node_id}] Listening on {addr[0]}:{addr[1]}")
        # Start keepalive loop
        self._tasks.append(asyncio.create_task(self._keepalive_loop()))

    async def stop(self):
        """Shut down the server and disconnect all peers."""
        self._running = False
        for task in self._tasks:
            task.cancel()
        for peer in list(self.peers.values()):
            await peer.close()
        self.peers.clear()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        logger.info(f"[{self.node_id}] Stopped")

    # ---- connecting ----

    async def connect_to_peer(self, host: str, port: int) -> bool:
        """Initiate an outbound connection to a peer."""
        try:
            reader, writer = await asyncio.open_connection(host, port)
            peer = PeerConnection(reader, writer, direction="outbound")
            # Send handshake
            await peer.send("HELLO", {
                "node_id": self.node_id,
                "port": self.port,
            })
            # Read handshake response
            msg = await peer.readline()
            if msg and msg.get("type") == "HELLO":
                peer.peer_id = msg["payload"]["node_id"]
                self.peers[peer.peer_id] = peer
                logger.info(
                    f"[{self.node_id}] Connected to {peer.peer_id} "
                    f"at {host}:{port}"
                )
                if self.on_peer_connected:
                    self.on_peer_connected(peer.peer_id)
                # Start reading loop
                task = asyncio.create_task(self._read_loop(peer))
                self._tasks.append(task)
                return True
            else:
                await peer.close()
                return False
        except (ConnectionError, OSError) as e:
            logger.warning(f"[{self.node_id}] Failed to connect to {host}:{port}: {e}")
            return False

    async def _handle_inbound(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a new inbound connection."""
        peer = PeerConnection(reader, writer, direction="inbound")
        # Wait for HELLO
        msg = await peer.readline()
        if not msg or msg.get("type") != "HELLO":
            await peer.close()
            return

        peer.peer_id = msg["payload"]["node_id"]
        # Send our HELLO back
        await peer.send("HELLO", {
            "node_id": self.node_id,
            "port": self.port,
        })

        self.peers[peer.peer_id] = peer
        logger.info(
            f"[{self.node_id}] Inbound connection from {peer.peer_id} "
            f"({peer.remote_addr})"
        )
        if self.on_peer_connected:
            self.on_peer_connected(peer.peer_id)

        await self._read_loop(peer)

    # ---- message loop ----

    async def _read_loop(self, peer: PeerConnection):
        """Continuously read messages from a peer."""
        while self._running:
            msg = await peer.readline()
            if msg is None:
                break
            await self._dispatch(peer, msg)

        # Peer disconnected
        self.peers.pop(peer.peer_id, None)
        await peer.close()
        logger.info(f"[{self.node_id}] Peer {peer.peer_id} disconnected")
        if self.on_peer_disconnected:
            self.on_peer_disconnected(peer.peer_id)

    async def _dispatch(self, peer: PeerConnection, msg: dict):
        """Route an incoming message to the right handler."""
        msg_type = msg.get("type", "")
        payload = msg.get("payload", {})

        if msg_type == "PING":
            await peer.send("PONG", {"node_id": self.node_id})

        elif msg_type == "PONG":
            pass  # keepalive ack

        elif msg_type == "TX":
            tx_id = payload.get("tx_id", "")
            if tx_id and tx_id not in self._seen_ids:
                self._mark_seen(tx_id)
                if self.on_transaction:
                    self.on_transaction(payload, peer.peer_id)
                # Rebroadcast to other peers
                await self._relay(peer.peer_id, "TX", payload)

        elif msg_type == "PROPOSAL":
            prop_id = payload.get("validator_id", "") + str(payload.get("ledger_seq", ""))
            if prop_id not in self._seen_ids:
                self._mark_seen(prop_id)
                if self.on_proposal:
                    self.on_proposal(payload, peer.peer_id)
                await self._relay(peer.peer_id, "PROPOSAL", payload)

        elif msg_type == "CONSENSUS_OK":
            if self.on_consensus_result:
                self.on_consensus_result(payload, peer.peer_id)

        elif msg_type == "LEDGER_REQ":
            # Respond with our ledger state (handled externally)
            pass

        elif msg_type == "LEDGER_RES":
            pass

    # ---- broadcasting ----

    async def broadcast_transaction(self, tx_dict: dict):
        """Broadcast a transaction to all connected peers."""
        tx_id = tx_dict.get("tx_id", "")
        self._mark_seen(tx_id)
        for peer in list(self.peers.values()):
            await peer.send("TX", tx_dict)

    async def broadcast_proposal(self, proposal_dict: dict):
        """Broadcast a consensus proposal to all peers."""
        for peer in list(self.peers.values()):
            await peer.send("PROPOSAL", proposal_dict)

    async def broadcast_consensus_result(self, result_dict: dict):
        """Broadcast consensus result to all peers."""
        for peer in list(self.peers.values()):
            await peer.send("CONSENSUS_OK", result_dict)

    async def send_to_peer(self, peer_id: str, msg_type: str, payload: dict) -> bool:
        """Send a message to a specific peer."""
        peer = self.peers.get(peer_id)
        if peer:
            return await peer.send(msg_type, payload)
        return False

    async def _relay(self, origin_peer: str, msg_type: str, payload: dict):
        """Relay a message to all peers except the origin."""
        for pid, peer in list(self.peers.items()):
            if pid != origin_peer:
                await peer.send(msg_type, payload)

    # ---- keepalive ----

    async def _keepalive_loop(self):
        """Ping all peers every 30 seconds."""
        while self._running:
            await asyncio.sleep(30)
            for peer in list(self.peers.values()):
                ok = await peer.send("PING", {"node_id": self.node_id})
                if not ok:
                    self.peers.pop(peer.peer_id, None)
                    await peer.close()

    # ---- helpers ----

    def _mark_seen(self, msg_id: str):
        if len(self._seen_ids) > self._max_seen:
            # Evict oldest half
            to_remove = list(self._seen_ids)[: self._max_seen // 2]
            for k in to_remove:
                self._seen_ids.discard(k)
        self._seen_ids.add(msg_id)

    @property
    def peer_count(self) -> int:
        return len(self.peers)

    def peer_ids(self) -> list[str]:
        return list(self.peers.keys())

    def status(self) -> dict:
        return {
            "node_id": self.node_id,
            "listen": f"{self.host}:{self.port}",
            "peers": len(self.peers),
            "peer_list": [p.info() for p in self.peers.values()],
            "running": self._running,
        }
