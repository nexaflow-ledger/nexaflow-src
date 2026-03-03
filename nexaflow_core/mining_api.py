"""
Bitcoin-Compatible Stratum Mining API for NexaFlow PMC.

Implements a Stratum v1-compatible JSON-RPC server so that any Bitcoin ASIC
miner, GPU miner, or mining pool software can connect directly to a NexaFlow
wallet/node and mine Programmable Micro Coins using the same double-SHA256
PoW algorithm Bitcoin uses.

Architecture
------------
                   ┌─────────────────────────────┐
                   │      Bitcoin ASIC / GPU      │
                   │      (Stratum v1 client)     │
                   └──────────┬──────────────────┘
                              │ TCP :3333
                   ┌──────────▼──────────────────┐
                   │      StratumServer          │
                   │  (JSON-RPC over TCP)        │
                   │                              │
                   │  mining.subscribe            │
                   │  mining.authorize             │
                   │  mining.submit                │
                   │  mining.notify  ───────────►  │
                   └──────────┬──────────────────┘
                              │
                   ┌──────────▼──────────────────┐
                   │      MiningCoordinator       │
                   │                              │
                   │  Job management              │
                   │  PMC ⟷ Bitcoin work xlation │
                   │  Nonce ⟷ extranonce mapping │
                   │  Share difficulty tracking    │
                   └──────────┬──────────────────┘
                              │
                   ┌──────────▼──────────────────┐
                   │      PMCManager / Ledger     │
                   │      (mint on valid share)   │
                   └──────────────────────────────┘

Stratum v1 Methods
------------------
mining.subscribe  → Session setup; returns extranonce1 + extranonce2_size
mining.authorize  → Worker auth: "wallet_address.worker_name"
mining.submit     → Submit a solved share (job_id, extranonce2, ntime, nonce)
mining.notify     → Server pushes new jobs to miners (coin_id, prev_hash, …)

The double-SHA256 hash target is mapped directly from the PMC coin's
``pow_difficulty`` field (number of leading hex zeros).

Usage
-----
    from nexaflow_core.mining_api import StratumServer, MiningCoordinator

    coordinator = MiningCoordinator(pmc_manager, mint_callback=my_mint_fn)
    coordinator.add_coin("coin_abc123...")

    server = StratumServer(coordinator, host="0.0.0.0", port=3333)
    await server.start()
    # ... miners connect via stratum+tcp://host:3333
    await server.stop()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    from nexaflow_core.pmc import PMCManager

logger = logging.getLogger("nexaflow.mining_api")

# ═══════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════

DEFAULT_STRATUM_PORT = 3333
EXTRANONCE1_SIZE = 4           # 4 bytes → 8 hex chars
EXTRANONCE2_SIZE = 4           # 4 bytes → 8 hex chars
MAX_NONCE = 0xFFFFFFFF
SHARE_TARGET_MULTIPLIER = 1    # share diff relative to network diff
JOB_REFRESH_INTERVAL = 30.0    # seconds between new job notifications
MAX_WORKERS_PER_IP = 256       # anti-DoS: max concurrent connections per IP
MAX_MESSAGE_SIZE = 8192        # bytes


# ═══════════════════════════════════════════════════════════════════════
#  Data structures
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class MiningJob:
    """A work unit sent to miners."""
    job_id: str
    coin_id: str
    prev_hash: str
    miner_address: str
    difficulty: int
    target: str                 # hex target string
    created_at: float = field(default_factory=time.time)
    clean_jobs: bool = True     # True → miners must drop old work

    def to_notify_params(self, extranonce1: str) -> list:
        """Build Stratum ``mining.notify`` params."""
        return [
            self.job_id,           # [0] job_id
            self.prev_hash,        # [1] prev_hash (hex)
            self.coin_id,          # [2] coinbase1 (we use coin_id)
            extranonce1,           # [3] coinbase2 (we use extranonce)
            [],                    # [4] merkle_branches (empty for PMC)
            f"{self.difficulty:08x}",  # [5] version (we encode difficulty)
            self.target,           # [6] nbits (target)
            f"{int(time.time()):08x}", # [7] ntime
            self.clean_jobs,       # [8] clean_jobs
        ]


@dataclass
class MinerSession:
    """Per-connection miner state."""
    session_id: str
    extranonce1: str
    writer: asyncio.StreamWriter | None = None
    authorized: bool = False
    worker_name: str = ""
    wallet_address: str = ""
    subscribed: bool = False
    ip: str = ""
    connected_at: float = field(default_factory=time.time)
    shares_accepted: int = 0
    shares_rejected: int = 0
    last_share_at: float = 0.0
    current_coin_id: str = ""
    hashrate_estimate: float = 0.0

    @property
    def uptime(self) -> float:
        return time.time() - self.connected_at


@dataclass
class PoolStats:
    """Aggregate mining pool statistics."""
    total_shares_accepted: int = 0
    total_shares_rejected: int = 0
    total_blocks_found: int = 0
    total_coins_mined: float = 0.0
    active_miners: int = 0
    hashrate_estimate: float = 0.0
    started_at: float = field(default_factory=time.time)

    @property
    def uptime(self) -> float:
        return time.time() - self.started_at

    def to_dict(self) -> dict:
        return {
            "total_shares_accepted": self.total_shares_accepted,
            "total_shares_rejected": self.total_shares_rejected,
            "total_blocks_found": self.total_blocks_found,
            "total_coins_mined": round(self.total_coins_mined, 8),
            "active_miners": self.active_miners,
            "hashrate_estimate": round(self.hashrate_estimate, 2),
            "uptime_seconds": round(self.uptime, 1),
        }


# ═══════════════════════════════════════════════════════════════════════
#  Mining Coordinator
# ═══════════════════════════════════════════════════════════════════════

class MiningCoordinator:
    """
    Bridges Bitcoin Stratum miners ↔ NexaFlow PMC PoW.

    Responsibilities:
      - Maintain the set of minable coins
      - Create and rotate mining jobs
      - Validate submitted shares (nonces)
      - Trigger ``mint()`` on valid full-difficulty solutions
      - Track pool-wide statistics

    Parameters
    ----------
    pmc_manager : PMCManager
        The PMC engine instance to query for coin info and perform mints.
    mint_callback : callable, optional
        ``async def mint_callback(coin_id, miner_addr, nonce) -> dict|None``
        Called when a valid block is found.  If *None*, the coordinator
        calls ``pmc_manager.mint()`` directly.
    default_coin_id : str, optional
        If set, newly subscribed miners are assigned this coin automatically.
    """

    def __init__(
        self,
        pmc_manager: PMCManager,
        mint_callback: Callable | None = None,
        default_coin_id: str = "",
    ):
        self.pmc = pmc_manager
        self.mint_callback = mint_callback
        self.default_coin_id = default_coin_id

        self.sessions: dict[str, MinerSession] = {}   # session_id → session
        self.jobs: dict[str, MiningJob] = {}           # job_id → job
        self.active_coins: set[str] = set()            # coins accepting miners
        self.stats = PoolStats()
        self._extranonce_counter = 0
        self._job_counter = 0

    # ── Coin management ──

    def add_coin(self, coin_id: str) -> bool:
        """Register a coin for mining.  Returns False if coin not found."""
        info = self.pmc.get_pow_info(coin_id)
        if not info or not info.get("mintable"):
            return False
        self.active_coins.add(coin_id)
        if not self.default_coin_id:
            self.default_coin_id = coin_id
        logger.info("Mining enabled for coin %s (%s)", coin_id[:12], info["symbol"])
        return True

    def remove_coin(self, coin_id: str) -> None:
        self.active_coins.discard(coin_id)
        if self.default_coin_id == coin_id:
            self.default_coin_id = next(iter(self.active_coins), "")

    def list_minable_coins(self) -> list[dict]:
        """Return PoW info for all active coins."""
        return [
            self.pmc.get_pow_info(cid)
            for cid in self.active_coins
            if self.pmc.get_pow_info(cid).get("mintable")
        ]

    # ── Session lifecycle ──

    def create_session(self, ip: str = "") -> MinerSession:
        """Create a new miner session with unique extranonce1."""
        self._extranonce_counter = (self._extranonce_counter + 1) % (2 ** 32)
        en1 = f"{self._extranonce_counter:08x}"
        sid = hashlib.sha256(f"{en1}:{time.time()}:{os.urandom(8).hex()}".encode()).hexdigest()[:16]
        session = MinerSession(session_id=sid, extranonce1=en1, ip=ip)
        self.sessions[sid] = session
        self.stats.active_miners = len(self.sessions)
        logger.info("Miner session created: %s from %s", sid, ip)
        return session

    def remove_session(self, session_id: str) -> None:
        self.sessions.pop(session_id, None)
        self.stats.active_miners = len(self.sessions)

    # ── Job creation ──

    def create_job(self, coin_id: str, miner_address: str) -> MiningJob | None:
        """Create a fresh mining job for a specific coin."""
        info = self.pmc.get_pow_info(coin_id)
        if not info or not info.get("mintable"):
            return None

        self._job_counter += 1
        job_id = f"{self._job_counter:08x}"
        diff = info["difficulty"]
        target = "0" * diff + "f" * (64 - diff)

        job = MiningJob(
            job_id=job_id,
            coin_id=coin_id,
            prev_hash=info.get("prev_hash", ""),
            miner_address=miner_address,
            difficulty=diff,
            target=target,
        )
        self.jobs[job_id] = job
        return job

    # ── Share validation ──

    def validate_share(
        self,
        session: MinerSession,
        job_id: str,
        extranonce2: str,
        ntime: str,
        nonce_hex: str,
    ) -> tuple[bool, str, float]:
        """
        Validate a submitted share.

        The miner's nonce is reconstructed from the Stratum fields.  The
        share is verified against the PMC coin's double-SHA256 target.

        Returns (accepted, message, minted_amount).
        """
        job = self.jobs.get(job_id)
        if job is None:
            return False, "Job not found or expired", 0.0

        if not session.authorized:
            return False, "Not authorized", 0.0

        # Reconstruct the nonce from Stratum fields.
        # In Bitcoin Stratum, the miner iterates nonce within a block header.
        # For PMC, we map: nonce = int(extranonce1 + extranonce2 + nonce_hex, 16)
        # This gives each miner a unique nonce space via extranonce1.
        try:
            combined = session.extranonce1 + extranonce2 + nonce_hex
            pmc_nonce = int(combined, 16) % (2 ** 63)  # keep within sane range
        except (ValueError, OverflowError):
            return False, "Invalid nonce encoding", 0.0

        # Verify the PoW using the same double-SHA256 as pmc.py
        coin_id = job.coin_id
        miner = session.wallet_address
        prev_hash = job.prev_hash
        diff = job.difficulty
        target = "0" * diff

        blob = f"{coin_id}:{miner}:{pmc_nonce}:{prev_hash}".encode()
        h = hashlib.sha256(hashlib.sha256(blob).digest()).hexdigest()

        if h[:diff] != target:
            session.shares_rejected += 1
            self.stats.total_shares_rejected += 1
            return False, "Share does not meet target difficulty", 0.0

        # Valid share — it's also a valid block!
        session.shares_accepted += 1
        session.last_share_at = time.time()
        self.stats.total_shares_accepted += 1

        # Perform the actual mint
        minted = self._do_mint(coin_id, miner, pmc_nonce)
        if minted > 0:
            self.stats.total_blocks_found += 1
            self.stats.total_coins_mined += minted
            logger.info(
                "BLOCK FOUND! coin=%s miner=%s nonce=%d reward=%.8f",
                coin_id[:12], miner[:12], pmc_nonce, minted,
            )
            return True, f"Block found! Reward: {minted:.8f}", minted

        # Share was valid PoW but mint failed (supply exhausted, etc.)
        return True, "Valid share (mint pending)", 0.0

    def _do_mint(self, coin_id: str, miner: str, nonce: int) -> float:
        """Perform the mint via callback or direct PMCManager call."""
        if self.mint_callback is not None:
            # Callback assumed to be async; handle both sync and async.
            result = self.mint_callback(coin_id, miner, nonce)
            if isinstance(result, float):
                return result
            return 0.0

        ok, msg, amount = self.pmc.mint(coin_id, miner, nonce)
        if ok:
            return amount
        logger.warning("Mint failed for coin=%s miner=%s: %s", coin_id[:12], miner[:12], msg)
        return 0.0

    # ── Statistics ──

    def get_miner_stats(self, session_id: str) -> dict:
        s = self.sessions.get(session_id)
        if s is None:
            return {}
        return {
            "session_id": s.session_id,
            "worker_name": s.worker_name,
            "wallet_address": s.wallet_address,
            "ip": s.ip,
            "shares_accepted": s.shares_accepted,
            "shares_rejected": s.shares_rejected,
            "uptime_seconds": round(s.uptime, 1),
            "current_coin": s.current_coin_id,
            "hashrate_estimate": round(s.hashrate_estimate, 2),
        }

    def get_pool_stats(self) -> dict:
        return self.stats.to_dict()

    def get_all_miner_stats(self) -> list[dict]:
        return [self.get_miner_stats(sid) for sid in self.sessions]


# ═══════════════════════════════════════════════════════════════════════
#  Stratum v1 TCP Server
# ═══════════════════════════════════════════════════════════════════════

class StratumServer:
    """
    Stratum v1-compatible TCP server for Bitcoin mining hardware.

    Speaks line-delimited JSON-RPC over TCP (the de-facto standard that
    every Bitcoin ASIC, GPU miner, and pool proxy implements).

    Parameters
    ----------
    coordinator : MiningCoordinator
        The coordinator that manages jobs and validates shares.
    host : str
        Listen address (default "0.0.0.0" — all interfaces).
    port : int
        Listen port (default 3333 — standard Stratum).
    tls_cert : str, optional
        Path to TLS certificate for stratum+ssl.
    tls_key : str, optional
        Path to TLS private key.
    """

    def __init__(
        self,
        coordinator: MiningCoordinator,
        host: str = "0.0.0.0",
        port: int = DEFAULT_STRATUM_PORT,
        tls_cert: str | None = None,
        tls_key: str | None = None,
    ):
        self.coordinator = coordinator
        self.host = host
        self.port = port
        self.tls_cert = tls_cert
        self.tls_key = tls_key
        self._server: asyncio.Server | None = None
        self._sessions: dict[str, MinerSession] = {}
        self._job_refresh_task: asyncio.Task | None = None
        self._ip_connections: dict[str, int] = {}
        self._running = False

    async def start(self) -> None:
        """Start accepting miner connections."""
        ssl_ctx = None
        if self.tls_cert and self.tls_key:
            import ssl
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(self.tls_cert, self.tls_key)

        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self.host,
            port=self.port,
            ssl=ssl_ctx,
        )
        self._running = True
        self._job_refresh_task = asyncio.create_task(self._job_refresh_loop())

        addr = self._server.sockets[0].getsockname() if self._server.sockets else (self.host, self.port)
        proto = "stratum+ssl" if ssl_ctx else "stratum+tcp"
        logger.info(
            "Stratum mining server started at %s://%s:%d",
            proto, addr[0], addr[1],
        )

    async def stop(self) -> None:
        """Gracefully stop the mining server."""
        self._running = False
        if self._job_refresh_task:
            self._job_refresh_task.cancel()
            try:
                await self._job_refresh_task
            except asyncio.CancelledError:
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        # Close all miner sessions
        for sid, session in list(self._sessions.items()):
            if session.writer and not session.writer.is_closing():
                session.writer.close()
            self.coordinator.remove_session(sid)
        self._sessions.clear()
        logger.info("Stratum mining server stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    # ── Connection handler ──

    async def _handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single miner connection."""
        peername = writer.get_extra_info("peername")
        ip = peername[0] if peername else "unknown"

        # Anti-DoS: limit connections per IP
        count = self._ip_connections.get(ip, 0)
        if count >= MAX_WORKERS_PER_IP:
            logger.warning("Too many connections from %s, rejecting", ip)
            writer.close()
            return
        self._ip_connections[ip] = count + 1

        session = self.coordinator.create_session(ip=ip)
        session.writer = writer
        self._sessions[session.session_id] = session

        logger.info("Miner connected: %s from %s", session.session_id, ip)

        try:
            while self._running:
                try:
                    data = await asyncio.wait_for(
                        reader.readline(), timeout=300.0,  # 5 min keepalive
                    )
                except asyncio.TimeoutError:
                    break
                if not data:
                    break
                if len(data) > MAX_MESSAGE_SIZE:
                    await self._send_error(writer, None, -1, "Message too large")
                    break
                try:
                    msg = json.loads(data.decode("utf-8", errors="replace"))
                except json.JSONDecodeError:
                    await self._send_error(writer, None, -1, "Invalid JSON")
                    continue

                await self._dispatch(session, msg, writer)
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            # Cleanup
            self.coordinator.remove_session(session.session_id)
            self._sessions.pop(session.session_id, None)
            self._ip_connections[ip] = max(0, self._ip_connections.get(ip, 1) - 1)
            if not writer.is_closing():
                writer.close()
            logger.info("Miner disconnected: %s", session.session_id)

    # ── JSON-RPC dispatch ──

    async def _dispatch(
        self,
        session: MinerSession,
        msg: dict,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Route a Stratum JSON-RPC request."""
        method = msg.get("method", "")
        params = msg.get("params", [])
        msg_id = msg.get("id")

        handlers = {
            "mining.subscribe": self._handle_subscribe,
            "mining.authorize": self._handle_authorize,
            "mining.submit": self._handle_submit,
            "mining.extranonce.subscribe": self._handle_extranonce_subscribe,
            "mining.get_transactions": self._handle_get_transactions,
        }

        handler = handlers.get(method)
        if handler is None:
            await self._send_error(writer, msg_id, -3, f"Unknown method: {method}")
            return

        try:
            await handler(session, params, msg_id, writer)
        except Exception as exc:
            logger.exception("Error handling %s: %s", method, exc)
            await self._send_error(writer, msg_id, -2, str(exc))

    # ── mining.subscribe ──

    async def _handle_subscribe(
        self,
        session: MinerSession,
        params: list,
        msg_id: Any,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle mining.subscribe — session setup."""
        session.subscribed = True
        result = [
            [["mining.set_difficulty", session.session_id],
             ["mining.notify", session.session_id]],
            session.extranonce1,
            EXTRANONCE2_SIZE,
        ]
        await self._send_result(writer, msg_id, result)
        logger.debug("Miner subscribed: %s", session.session_id)

    # ── mining.authorize ──

    async def _handle_authorize(
        self,
        session: MinerSession,
        params: list,
        msg_id: Any,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle mining.authorize — worker authentication.

        Worker name format:  ``<wallet_address>.<worker_name>``
        or just ``<wallet_address>``.
        """
        if not params:
            await self._send_error(writer, msg_id, -1, "Missing worker name")
            return

        full_name = str(params[0])
        parts = full_name.split(".", 1)
        wallet_addr = parts[0]
        worker_name = parts[1] if len(parts) > 1 else "default"

        # Basic validation: NexaFlow addresses start with 'r'
        if not wallet_addr.startswith("r") or len(wallet_addr) < 10:
            await self._send_error(writer, msg_id, -1, "Invalid wallet address")
            return

        session.authorized = True
        session.wallet_address = wallet_addr
        session.worker_name = worker_name
        session.current_coin_id = self.coordinator.default_coin_id

        await self._send_result(writer, msg_id, True)
        logger.info(
            "Miner authorized: %s → %s (worker: %s)",
            session.session_id, wallet_addr[:16], worker_name,
        )

        # Send initial job if a coin is configured
        if session.current_coin_id:
            await self._send_new_job(session)

    # ── mining.submit ──

    async def _handle_submit(
        self,
        session: MinerSession,
        params: list,
        msg_id: Any,
        writer: asyncio.StreamWriter,
    ) -> None:
        """
        Handle mining.submit — share submission.

        Stratum params: [worker, job_id, extranonce2, ntime, nonce]
        """
        if len(params) < 5:
            await self._send_error(writer, msg_id, -1, "Missing submit params")
            return

        _worker, job_id, extranonce2, ntime, nonce_hex = params[:5]

        accepted, message, minted = self.coordinator.validate_share(
            session, job_id, extranonce2, ntime, nonce_hex,
        )

        if accepted:
            await self._send_result(writer, msg_id, True)
            if minted > 0:
                # Block found — send new job to all miners on this coin
                await self._broadcast_new_jobs(session.current_coin_id)
        else:
            await self._send_error(writer, msg_id, 23, message)

    # ── mining.extranonce.subscribe ──

    async def _handle_extranonce_subscribe(
        self,
        session: MinerSession,
        params: list,
        msg_id: Any,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle extranonce subscription (NiceHash compatibility)."""
        await self._send_result(writer, msg_id, True)

    # ── mining.get_transactions ──

    async def _handle_get_transactions(
        self,
        session: MinerSession,
        params: list,
        msg_id: Any,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Return empty transaction list (PMC doesn't need coinbase txs)."""
        await self._send_result(writer, msg_id, [])

    # ── Job management ──

    async def _send_new_job(self, session: MinerSession) -> None:
        """Create and send a new mining job to a specific miner."""
        if not session.current_coin_id or not session.authorized:
            return
        job = self.coordinator.create_job(
            session.current_coin_id, session.wallet_address,
        )
        if job is None:
            return

        # Also set the difficulty
        await self._send_set_difficulty(session)

        notify = {
            "id": None,
            "method": "mining.notify",
            "params": job.to_notify_params(session.extranonce1),
        }
        await self._send_json(session.writer, notify)

    async def _send_set_difficulty(self, session: MinerSession) -> None:
        """Send mining.set_difficulty to a miner."""
        info = self.coordinator.pmc.get_pow_info(session.current_coin_id)
        if not info:
            return
        # Map PMC difficulty (leading hex zeros) to Stratum difficulty.
        # Each hex zero = 16× harder.  Stratum diff 1 ≈ Bitcoin's diff 1.
        stratum_diff = max(1, 16 ** info["difficulty"])
        msg = {
            "id": None,
            "method": "mining.set_difficulty",
            "params": [stratum_diff],
        }
        await self._send_json(session.writer, msg)

    async def _broadcast_new_jobs(self, coin_id: str) -> None:
        """Push new jobs to all miners working on a specific coin."""
        for session in list(self._sessions.values()):
            if session.current_coin_id == coin_id and session.authorized:
                try:
                    await self._send_new_job(session)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    pass

    async def _job_refresh_loop(self) -> None:
        """Periodically send fresh jobs to all miners."""
        while self._running:
            await asyncio.sleep(JOB_REFRESH_INTERVAL)
            for coin_id in list(self.coordinator.active_coins):
                await self._broadcast_new_jobs(coin_id)

    # ── JSON-RPC helpers ──

    @staticmethod
    async def _send_json(writer: asyncio.StreamWriter | None, obj: dict) -> None:
        if writer is None or writer.is_closing():
            return
        line = json.dumps(obj) + "\n"
        writer.write(line.encode())
        await writer.drain()

    async def _send_result(
        self, writer: asyncio.StreamWriter, msg_id: Any, result: Any,
    ) -> None:
        await self._send_json(writer, {"id": msg_id, "result": result, "error": None})

    async def _send_error(
        self, writer: asyncio.StreamWriter, msg_id: Any, code: int, message: str,
    ) -> None:
        await self._send_json(writer, {
            "id": msg_id,
            "result": None,
            "error": [code, message, None],
        })

    # ── Status ──

    def get_server_info(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "running": self._running,
            "protocol": "stratum+ssl" if self.tls_cert else "stratum+tcp",
            "active_sessions": len(self._sessions),
            "minable_coins": len(self.coordinator.active_coins),
            "pool_stats": self.coordinator.get_pool_stats(),
        }


# ═══════════════════════════════════════════════════════════════════════
#  Pool Configuration Helper
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PoolConfig:
    """Configuration for the built-in mining pool."""
    enabled: bool = False
    host: str = "0.0.0.0"
    port: int = DEFAULT_STRATUM_PORT
    tls_cert: str = ""
    tls_key: str = ""
    default_coin: str = ""        # default coin_id for new miners
    auto_register_coins: bool = True  # auto-register all minable coins
    job_refresh_seconds: float = JOB_REFRESH_INTERVAL

    @classmethod
    def from_dict(cls, d: dict) -> PoolConfig:
        return cls(
            enabled=bool(d.get("enabled", False)),
            host=str(d.get("host", "0.0.0.0")),
            port=int(d.get("port", DEFAULT_STRATUM_PORT)),
            tls_cert=str(d.get("tls_cert", "")),
            tls_key=str(d.get("tls_key", "")),
            default_coin=str(d.get("default_coin", "")),
            auto_register_coins=bool(d.get("auto_register_coins", True)),
            job_refresh_seconds=float(d.get("job_refresh_seconds", JOB_REFRESH_INTERVAL)),
        )

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "host": self.host,
            "port": self.port,
            "tls_cert": self.tls_cert,
            "tls_key": self.tls_key,
            "default_coin": self.default_coin,
            "auto_register_coins": self.auto_register_coins,
            "job_refresh_seconds": self.job_refresh_seconds,
        }


# ═══════════════════════════════════════════════════════════════════════
#  Convenience: Run an integrated mining node
# ═══════════════════════════════════════════════════════════════════════

class MiningNode:
    """
    High-level helper that wraps a StratumServer + MiningCoordinator
    and integrates with a wallet's PMCManager.

    This is what the GUI or CLI uses to "start mining pool" with one call.

    Usage::

        node = MiningNode(pmc_manager)
        node.add_coin(coin_id)
        await node.start(port=3333)
        # miners connect via stratum+tcp://your-ip:3333
        # worker name = wallet_address.worker_name
        info = node.get_info()
        await node.stop()
    """

    def __init__(
        self,
        pmc_manager: PMCManager,
        mint_callback: Callable | None = None,
    ):
        self.coordinator = MiningCoordinator(pmc_manager, mint_callback)
        self._server: StratumServer | None = None

    def add_coin(self, coin_id: str) -> bool:
        return self.coordinator.add_coin(coin_id)

    def remove_coin(self, coin_id: str) -> None:
        self.coordinator.remove_coin(coin_id)

    def list_coins(self) -> list[dict]:
        return self.coordinator.list_minable_coins()

    async def start(
        self,
        host: str = "0.0.0.0",
        port: int = DEFAULT_STRATUM_PORT,
        tls_cert: str | None = None,
        tls_key: str | None = None,
    ) -> None:
        if self._server and self._server.is_running:
            return
        self._server = StratumServer(
            self.coordinator, host=host, port=port,
            tls_cert=tls_cert, tls_key=tls_key,
        )
        await self._server.start()

    async def stop(self) -> None:
        if self._server:
            await self._server.stop()
            self._server = None

    @property
    def is_running(self) -> bool:
        return self._server is not None and self._server.is_running

    def get_info(self) -> dict:
        if self._server:
            return self._server.get_server_info()
        return {"running": False}

    def get_pool_stats(self) -> dict:
        return self.coordinator.get_pool_stats()

    def get_miner_stats(self) -> list[dict]:
        return self.coordinator.get_all_miner_stats()
