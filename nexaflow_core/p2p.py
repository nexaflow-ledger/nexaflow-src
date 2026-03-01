"""
Real TCP-based P2P networking layer for NexaFlow.

Implements an async peer-to-peer protocol where nodes:
  - Discover and connect to peers
  - Broadcast transactions
  - Exchange consensus proposals
  - Synchronise ledger state

Protocol is JSON-over-TCP with newline-delimited messages.  All connections
are optionally wrapped in TLS (including mutual TLS for validator identity
verification).

Message types:
  HELLO        - handshake with node identity and optional public key
  TX           - broadcast a signed transaction
  PROPOSAL     - consensus proposal for a ledger round
  CONSENSUS_OK - agreed transaction set after consensus
  LEDGER_REQ   - request ledger state
  LEDGER_RES   - ledger state response
  PING / PONG  - keepalive

TLS / mTLS:
  Build SSLContexts with :func:`build_tls_context` and pass them to
  :class:`P2PNode` as ``ssl_context`` (server-side) and
  ``client_ssl_context`` (outbound connections).  When both sides present
  certificates signed by the same CA the connection is mutually
  authenticated before the HELLO handshake begins.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
import time
from typing import Callable

logger = logging.getLogger("nexaflow_p2p")


# =====================================================================
# TLS helpers
# =====================================================================

def build_tls_context(
    cert_file: str,
    key_file: str,
    ca_file: str = "",
    verify_peer: bool = True,
    server_side: bool = True,
) -> ssl.SSLContext:
    """
    Build an :class:`ssl.SSLContext` for encrypted P2P connections.

    Parameters
    ----------
    cert_file   Path to the node's PEM-encoded X.509 certificate.
    key_file    Path to the node's PEM-encoded private key.
    ca_file     Path to the CA bundle used to verify peer certificates.
                Required when *verify_peer* is True.
    verify_peer Require a valid peer certificate (mutual TLS).  Set to
                False for one-way TLS (server-only authentication).
    server_side True when building the context for the listening server;
                False when building the context for outbound connections.

    Returns
    -------
    ssl.SSLContext ready to be passed to :func:`asyncio.start_server`
    or :func:`asyncio.open_connection`.
    """
    if server_side:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False  # hostname check is not meaningful for P2P IPs

    # Require TLS 1.3 minimum; reject older protocol versions.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    # Load node certificate and private key
    if cert_file and key_file:
        ctx.load_cert_chain(cert_file, key_file)

    # Peer verification (mutual TLS)
    if verify_peer:
        if ca_file:
            ctx.load_verify_locations(ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


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
        result: dict = json.loads(data.strip())
        return result
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

    TLS / mutual TLS
    ----------------
    Pass pre-built :class:`ssl.SSLContext` objects created with
    :func:`build_tls_context` to enable encrypted connections.  When
    both ``ssl_context`` (server) and ``client_ssl_context`` (client)
    are provided every byte on the wire is encrypted.  Mutual TLS
    (mTLS) additionally authenticates each peer's certificate before
    the HELLO handshake even begins.

    Peer public keys
    ----------------
    If ``node_pubkey`` (65-byte uncompressed secp256k1 public key) is
    set it will be advertised in the HELLO message so peers can use it
    for consensus proposal signature verification.  Received pubkeys
    are stored in :attr:`peer_pubkeys`.

    Usage::

        ctx_srv = build_tls_context(cert, key, ca, server_side=True)
        ctx_cli = build_tls_context(cert, key, ca, server_side=False)
        node = P2PNode("v1", ssl_context=ctx_srv, client_ssl_context=ctx_cli)
        node.on_transaction = my_tx_handler
        await node.start()
        await node.connect_to_peer("127.0.0.1", 9002)
    """

    def __init__(
        self,
        node_id: str,
        host: str = "0.0.0.0",
        port: int = 9001,
        ssl_context: ssl.SSLContext | None = None,
        client_ssl_context: ssl.SSLContext | None = None,
        node_pubkey: bytes | None = None,
    ):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.peers: dict[str, PeerConnection] = {}   # peer_id -> connection
        self._server: asyncio.AbstractServer | None = None
        self._running = False
        self._tasks: list[asyncio.Task] = []

        # TLS contexts — None means plaintext (backward-compatible default)
        self._ssl_context: ssl.SSLContext | None = ssl_context
        self._client_ssl_context: ssl.SSLContext | None = client_ssl_context

        # This node's 65-byte uncompressed secp256k1 public key (optional).
        # Advertised in HELLO so peers can verify signed consensus proposals.
        self.node_pubkey: bytes | None = node_pubkey
        # Map peer_id -> their 65-byte public key (populated from HELLO)
        self.peer_pubkeys: dict[str, bytes] = {}

        # Callbacks - set by the node runner
        self.on_transaction: Callable | None = None
        self.on_proposal: Callable | None = None
        self.on_consensus_result: Callable | None = None
        self.on_peer_connected: Callable | None = None
        self.on_peer_disconnected: Callable | None = None
        self.on_ledger_request: Callable | None = None   # (peer_id) -> dict
        self.on_ledger_response: Callable | None = None  # (payload, peer_id) -> None

        # Efficient sync callbacks (used by LedgerSyncManager)
        self.on_sync_status_req: Callable | None = None   # (payload, peer_id) -> dict
        self.on_sync_status_res: Callable | None = None   # (payload, peer_id) -> None
        self.on_sync_delta_req: Callable | None = None    # (payload, peer_id) -> dict
        self.on_sync_snap_req: Callable | None = None     # (payload, peer_id) -> dict
        self.on_sync_data_res: Callable | None = None     # (payload, peer_id) -> None

        # Known peer addresses for gossip-based discovery
        # {  "host:port": last_seen_timestamp  }
        self._known_addrs: dict[str, float] = {}

        # Dedup - track seen message hashes to avoid rebroadcasts
        self._seen_ids: set[str] = set()
        self._max_seen = 10_000

    # ---- lifecycle ----

    async def start(self):
        """Start the TCP server and begin accepting connections.

        When an :attr:`_ssl_context` is configured the server accepts only
        TLS-encrypted connections.  All existing callers that don't set
        an SSL context continue to get plain TCP (backward-compatible).
        """
        self._server = await asyncio.start_server(
            self._handle_inbound, self.host, self.port,
            ssl=self._ssl_context,
        )
        self._running = True
        addr = self._server.sockets[0].getsockname()
        tls_tag = " [TLS]" if self._ssl_context else ""
        logger.info(f"[{self.node_id}] Listening on {addr[0]}:{addr[1]}{tls_tag}")
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
        """Initiate an outbound connection to a peer.

        When :attr:`_client_ssl_context` is set the connection is TLS-
        encrypted.  This is backward-compatible: without an SSL context
        a plain TCP connection is made exactly as before.
        """
        try:
            reader, writer = await asyncio.open_connection(
                host, port, ssl=self._client_ssl_context
            )
            peer = PeerConnection(reader, writer, direction="outbound")
            # Send handshake — include our public key so the peer can verify
            # our consensus proposal signatures.
            await peer.send("HELLO", {
                "node_id": self.node_id,
                "port": self.port,
                "pubkey": self.node_pubkey.hex() if self.node_pubkey else "",
            })
            # Read handshake response
            msg = await peer.readline()
            if msg and msg.get("type") == "HELLO":
                peer.peer_id = msg["payload"]["node_id"]
                # Store peer's advertised public key
                pubkey_hex = msg["payload"].get("pubkey", "")
                if pubkey_hex:
                    with contextlib.suppress(ValueError):
                        self.peer_pubkeys[peer.peer_id] = bytes.fromhex(pubkey_hex)
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
        except (ConnectionError, OSError, ssl.SSLError) as e:
            logger.warning(f"[{self.node_id}] Failed to connect to {host}:{port}: {e}")
            return False

    async def _handle_inbound(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a new inbound connection.

        When TLS is active the SSL handshake has already completed by the
        time this callback fires, so the peer is already authenticated at
        the transport layer.  The HELLO application-layer handshake then
        exchanges node IDs and public keys.
        """
        peer = PeerConnection(reader, writer, direction="inbound")
        # Wait for HELLO
        msg = await peer.readline()
        if not msg or msg.get("type") != "HELLO":
            await peer.close()
            return

        peer.peer_id = msg["payload"]["node_id"]
        # Store peer's advertised public key
        pubkey_hex = msg["payload"].get("pubkey", "")
        if pubkey_hex:
            with contextlib.suppress(ValueError):
                self.peer_pubkeys[peer.peer_id] = bytes.fromhex(pubkey_hex)

        # Send our HELLO back — include our public key
        await peer.send("HELLO", {
            "node_id": self.node_id,
            "port": self.port,
            "pubkey": self.node_pubkey.hex() if self.node_pubkey else "",
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

        elif msg_type == "PEERS":
            # Gossip: peer shares known addresses
            addrs = payload.get("addresses", [])
            for addr in addrs:
                if isinstance(addr, str) and addr not in self._known_addrs:
                    self._known_addrs[addr] = time.time()

        elif msg_type == "LEDGER_REQ":
            # Peer is requesting our ledger state (legacy)
            if self.on_ledger_request:
                state = self.on_ledger_request(peer.peer_id)
                if state:
                    await peer.send("LEDGER_RES", state)

        elif msg_type == "LEDGER_RES":
            if self.on_ledger_response:
                self.on_ledger_response(payload, peer.peer_id)

        # ── Efficient sync protocol messages ──────────────────────
        elif msg_type == "SYNC_STATUS_REQ":
            if self.on_sync_status_req:
                response = self.on_sync_status_req(payload, peer.peer_id)
                if response:
                    await peer.send("SYNC_STATUS_RES", response)

        elif msg_type == "SYNC_STATUS_RES":
            if self.on_sync_status_res:
                self.on_sync_status_res(payload, peer.peer_id)

        elif msg_type == "SYNC_DELTA_REQ":
            if self.on_sync_delta_req:
                delta = self.on_sync_delta_req(payload, peer.peer_id)
                if delta:
                    await peer.send("SYNC_DELTA_RES", delta)

        elif msg_type == "SYNC_SNAP_REQ":
            if self.on_sync_snap_req:
                snap = self.on_sync_snap_req(payload, peer.peer_id)
                if snap:
                    await peer.send("SYNC_SNAP_RES", snap)

        elif msg_type in ("SYNC_DELTA_RES", "SYNC_SNAP_RES") and self.on_sync_data_res:
            self.on_sync_data_res(payload, peer.peer_id)

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

    async def broadcast_peers(self):
        """Share our known peer addresses with all connected peers (gossip)."""
        my_addr = f"{self.host}:{self.port}"
        addrs = [my_addr, *list(self._known_addrs.keys())]
        # Include currently connected peers
        for peer in self.peers.values():
            if peer.remote_addr not in addrs:
                addrs.append(peer.remote_addr)
        for peer in list(self.peers.values()):
            await peer.send("PEERS", {"addresses": addrs})

    async def request_ledger(self, peer_id: str) -> bool:
        """Send a LEDGER_REQ to a specific peer to sync state."""
        return await self.send_to_peer(peer_id, "LEDGER_REQ", {
            "node_id": self.node_id,
        })

    def register_address(self, addr: str) -> None:
        """Register a known peer address for gossip discovery."""
        self._known_addrs[addr] = time.time()

    async def _relay(self, origin_peer: str, msg_type: str, payload: dict):
        """Relay a message to all peers except the origin."""
        for pid, peer in list(self.peers.items()):
            if pid != origin_peer:
                await peer.send(msg_type, payload)

    # ---- keepalive ----

    async def _keepalive_loop(self):
        """Ping all peers every 30 seconds; gossip peer addresses every 60s."""
        cycle = 0
        while self._running:
            await asyncio.sleep(30)
            cycle += 1

            # Ping
            for peer in list(self.peers.values()):
                ok = await peer.send("PING", {"node_id": self.node_id})
                if not ok:
                    self.peers.pop(peer.peer_id, None)
                    await peer.close()

            # Every other cycle (~60s) share known addresses
            if cycle % 2 == 0:
                await self.broadcast_peers()
                # Try connecting to any discovered addresses we aren't connected to
                connected_addrs = {p.remote_addr for p in self.peers.values()}
                my_addr = f"{self.host}:{self.port}"
                for addr in list(self._known_addrs.keys()):
                    if addr == my_addr or addr in connected_addrs:
                        continue
                    if ":" in addr:
                        try:
                            host, port_str = addr.rsplit(":", 1)
                            port = int(port_str)
                            task = asyncio.create_task(self.connect_to_peer(host, port))
                            task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
                        except (ValueError, OSError):
                            pass

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
            "tls": self._ssl_context is not None,
            "peers": len(self.peers),
            "peer_list": [p.info() for p in self.peers.values()],
            "running": self._running,
        }
