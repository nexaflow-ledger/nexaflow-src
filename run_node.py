#!/usr/bin/env python3
"""
NexaFlow Node Runner — starts a full validator node with:
  - P2P TCP networking
  - Ledger & consensus engine
  - Interactive CLI for sending transactions
  - Automatic consensus rounds on a timer

Usage:
    python run_node.py --node-id validator-1 --port 9001 \\
                       --peers 127.0.0.1:9002 \\
                       --fund-address rMyWallet --fund-amount 10000

Environment variables (alternative to flags):
    NEXAFLOW_NODE_ID, NEXAFLOW_PORT, NEXAFLOW_PEERS, NEXAFLOW_FUND_ADDR, NEXAFLOW_FUND_AMT
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import sys

# ---------------------------------------------------------------------------
# Ensure the project root is in sys.path so imports work before pip install
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from nexaflow_core.consensus import ConsensusEngine, Proposal  # noqa: E402
from nexaflow_core.config import load_config  # noqa: E402
from nexaflow_core.ledger import Ledger  # noqa: E402
from nexaflow_core.p2p import P2PNode  # noqa: E402
from nexaflow_core.storage import LedgerStore  # noqa: E402
from nexaflow_core.sync import LedgerSyncManager, STATUS_TIMEOUT, DATA_TIMEOUT  # noqa: E402
from nexaflow_core.transaction import Amount, Transaction, create_payment  # noqa: E402
from nexaflow_core.trust_line import TrustGraph  # noqa: E402
from nexaflow_core.validator import TransactionValidator  # noqa: E402
from nexaflow_core.wallet import Wallet  # noqa: E402

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("node")

# Consensus round interval (seconds)
CONSENSUS_INTERVAL = 10


# ===================================================================
#  NexaFlow Full Node
# ===================================================================

class NexaFlowNode:
    """
    Combines P2P networking, ledger, consensus, and wallet
    into a single runnable node.
    """

    def __init__(
        self,
        node_id: str,
        host: str = "0.0.0.0",
        port: int = 9001,
        peers: list[str] | None = None,
        config=None,
    ):
        self.node_id = node_id
        self.port = port
        self.peers_to_connect = peers or []
        self.config = config

        # Core components
        self.ledger = Ledger()
        self.p2p = P2PNode(node_id, host, port)
        self.wallet = Wallet.from_seed(node_id)
        self.validator = TransactionValidator(self.ledger)
        self.trust_graph = TrustGraph()

        # Persistence
        self.store: LedgerStore | None = None

        # Efficient ledger sync manager
        self.sync_manager = LedgerSyncManager(self.p2p, self.ledger)

        # Transaction pool (tx_id -> tx dict from network, or Transaction obj)
        self.tx_pool: dict[str, dict] = {}
        self.tx_objects: dict[str, Transaction] = {}

        # Consensus state
        self.peer_proposals: dict[str, dict] = {}

        # Background task references (prevent GC)
        self._bg_tasks: list[asyncio.Task] = []

        # API server reference
        self._api = None

        # Wire up P2P callbacks
        self.p2p.on_transaction = self._on_tx_received
        self.p2p.on_proposal = self._on_proposal_received
        self.p2p.on_consensus_result = self._on_consensus_result
        self.p2p.on_peer_connected = self._on_peer_connected
        self.p2p.on_peer_disconnected = self._on_peer_disconnected
        self.p2p.on_ledger_request = self.sync_manager.handle_ledger_request
        self.p2p.on_ledger_response = self.sync_manager.handle_ledger_response

        # Efficient sync protocol callbacks
        self.p2p.on_sync_status_req = self.sync_manager.handle_sync_status_req
        self.p2p.on_sync_status_res = self.sync_manager.handle_sync_status_res
        self.p2p.on_sync_delta_req = self.sync_manager.handle_sync_delta_req
        self.p2p.on_sync_snap_req = self.sync_manager.handle_sync_snap_req
        self.p2p.on_sync_data_res = self.sync_manager.handle_sync_data_res

    # ---- lifecycle ----

    async def start(self):
        """Start networking, persistence, API, and periodic consensus."""
        # ── Deterministic genesis ────────────────────────────────
        if self.config and self.config.genesis.accounts:
            genesis_accounts = self.config.genesis.accounts
            logger.info(f"Applying deterministic genesis ({len(genesis_accounts)} accounts)")
            for addr, balance in genesis_accounts.items():
                if not self.ledger.account_exists(addr):
                    self.ledger.create_account(addr, balance)
                else:
                    acc = self.ledger.get_account(addr)
                    if acc:
                        acc.balance = balance

        # ── Persistence: restore from SQLite ─────────────────────
        if self.config and self.config.storage.enabled:
            self.store = LedgerStore(self.config.storage.path)
            if self.store.latest_ledger_seq() > 0:
                logger.info("Restoring ledger state from database...")
                self.store.restore_ledger(self.ledger)
                logger.info(
                    f"Restored: seq={self.ledger.current_sequence}, "
                    f"{len(self.ledger.accounts)} accounts, "
                    f"{len(self.ledger.closed_ledgers)} closed ledgers, "
                    f"{len(self.ledger.applied_tx_ids)} applied tx IDs, "
                    f"{len(self.ledger.staking_pool.stakes)} stakes"
                )

        # Fund our own wallet on the ledger
        if not self.ledger.account_exists(self.wallet.address):
            self.ledger.create_account(self.wallet.address, 0.0)

        await self.p2p.start()

        # Connect to seed peers (with retry)
        for peer_addr in self.peers_to_connect:
            self._bg_tasks.append(asyncio.create_task(self._connect_with_retry(peer_addr)))

        # Start consensus timer
        self._bg_tasks.append(asyncio.create_task(self._consensus_loop()))
        # Start the ledger sync manager
        await self.sync_manager.start()
        # ── API server ───────────────────────────────────────────
        if self.config and self.config.api.enabled:
            from nexaflow_core.api import APIServer
            self._api = APIServer(
                self,
                host=self.config.api.host,
                port=self.config.api.port,
                api_config=self.config.api,
            )
            await self._api.start()

        logger.info(
            f"Node {self.node_id} started | addr={self.wallet.address} | port={self.port}"
        )

    async def stop(self):
        # Persist state before shutting down
        if self.store is not None:
            logger.info("Saving ledger state to database...")
            self.store.snapshot_ledger(self.ledger)
            self.store.close()
        await self.sync_manager.stop()
        if self._api is not None:
            await self._api.stop()
        await self.p2p.stop()

    async def _connect_with_retry(self, addr: str, max_retries: int = 30):
        """Try connecting to a peer with exponential back-off."""
        host, port_str = addr.rsplit(":", 1)
        port = int(port_str)
        delay = 1.0
        for attempt in range(max_retries):
            if await self.p2p.connect_to_peer(host, port):
                return
            logger.info(f"Retry connecting to {addr} in {delay:.0f}s (attempt {attempt+1})")
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 15.0)
        logger.error(f"Could not connect to {addr} after {max_retries} attempts")

    # ---- P2P callbacks ----

    def _on_peer_connected(self, peer_id: str):
        logger.info(f"Peer connected: {peer_id}")
        # Trigger an efficient sync cycle (status → delta/snap as needed)
        asyncio.ensure_future(self.sync_manager.request_sync())

    def _on_peer_disconnected(self, peer_id: str):
        logger.info(f"Peer disconnected: {peer_id}")

    def _on_tx_received(self, tx_data: dict, from_peer: str):
        """Handle a transaction received from the network."""
        tx_id = tx_data.get("tx_id", "")
        if tx_id in self.tx_pool:
            return  # already have it

        logger.info(f"Received TX {tx_id[:12]}... from {from_peer}")

        # Reconstruct a Transaction object for local application
        try:
            tx = self._reconstruct_tx(tx_data)
            # Validate
            valid, _code, msg = self.validator.validate(tx)
            if valid:
                self.tx_pool[tx_id] = tx_data
                self.tx_objects[tx_id] = tx
                logger.info(f"TX {tx_id[:12]}... accepted")
            else:
                logger.warning(f"TX {tx_id[:12]}... rejected: {msg}")
        except Exception as e:
            logger.warning(f"Failed to process TX: {e}")

    def _on_proposal_received(self, prop_data: dict, from_peer: str):
        """Handle a consensus proposal from a peer."""
        vid = prop_data.get("validator_id", "")
        logger.info(
            f"Received proposal from {vid} with "
            f"{len(prop_data.get('tx_ids', []))} txns"
        )
        self.peer_proposals[vid] = prop_data

    def _on_consensus_result(self, result_data: dict, from_peer: str):
        """Handle a consensus result from a peer (for catch-up)."""
        logger.info(f"Received consensus result from {from_peer}")

    # ---- transaction creation ----

    async def send_payment(
        self,
        destination: str,
        amount: float,
        currency: str = "NXF",
        memo: str = "",
    ):
        """Create, sign, validate, pool, and broadcast a payment."""
        # Ensure destination account exists locally
        if not self.ledger.account_exists(destination):
            self.ledger.create_account(destination, 0.0)

        tx = create_payment(
            self.wallet.address,
            destination,
            amount,
            currency,
            "",
            0.00001,
            0,
            memo,
        )
        self.wallet.sign_transaction(tx)

        # Validate locally
        valid, _code, msg = self.validator.validate(tx)
        if not valid:
            logger.error(f"Local validation failed: {msg}")
            return None

        # Add to pool
        tx_dict = tx.to_dict()
        tx_dict["tx_id"] = tx.tx_id
        tx_dict["signing_pub_key"] = tx.signing_pub_key.hex()
        tx_dict["signature"] = tx.signature.hex()
        self.tx_pool[tx.tx_id] = tx_dict
        self.tx_objects[tx.tx_id] = tx

        # Broadcast
        await self.p2p.broadcast_transaction(tx_dict)
        logger.info(f"Broadcast TX {tx.tx_id[:12]}... ({amount} {currency} -> {destination[:12]}...)")
        return tx

    # ---- consensus ----

    async def _consensus_loop(self):
        """Run consensus rounds periodically."""
        while self.p2p._running:
            await asyncio.sleep(CONSENSUS_INTERVAL)
            if self.tx_pool or self.peer_proposals:
                await self.run_consensus()

    async def run_consensus(self):
        """Execute a single consensus round."""
        logger.info(
            f"=== Consensus round for ledger {self.ledger.current_sequence} "
            f"({len(self.tx_pool)} candidate txns) ==="
        )

        # Build UNL from connected peers
        unl = self.p2p.peer_ids()

        # Create our proposal
        my_tx_ids = list(self.tx_pool.keys())
        engine = ConsensusEngine(
            unl, self.node_id, self.ledger.current_sequence
        )
        engine.submit_transactions(my_tx_ids)

        # Broadcast our proposal
        my_proposal = {
            "validator_id": self.node_id,
            "ledger_seq": self.ledger.current_sequence,
            "tx_ids": my_tx_ids,
        }
        await self.p2p.broadcast_proposal(my_proposal)

        # Wait briefly for peer proposals to arrive
        await asyncio.sleep(2.0)

        # Add peer proposals to engine
        for vid, prop_data in self.peer_proposals.items():
            tx_ids_set = set(prop_data.get("tx_ids", []))
            prop = Proposal(vid, prop_data.get("ledger_seq", 0), tx_ids_set)
            engine.add_proposal(prop)

        # Run consensus
        result = engine.run_rounds()

        if result is not None:
            agreed_ids = result.agreed_tx_ids
            logger.info(
                f"Consensus reached: {len(agreed_ids)} txns agreed "
                f"in {result.rounds_taken} rounds"
            )

            # Apply agreed transactions
            applied = 0
            for tx_id in agreed_ids:
                tx_obj = self.tx_objects.get(tx_id)
                if tx_obj is not None:
                    res_code = self.ledger.apply_transaction(tx_obj)
                    if res_code == 0:
                        applied += 1
                        logger.info(f"  Applied TX {tx_id[:12]}...")
                    else:
                        logger.warning(f"  TX {tx_id[:12]}... failed to apply (code={res_code})")

            # Close ledger
            header = self.ledger.close_ledger()
            logger.info(
                f"Ledger {header.sequence} closed | hash={header.hash[:16]}... | "
                f"{applied} txns applied"
            )

            # Broadcast result
            await self.p2p.broadcast_consensus_result({
                "ledger_seq": header.sequence,
                "hash": header.hash,
                "agreed_tx_ids": list(agreed_ids),
                "applied": applied,
            })

            # Persist to SQLite after each consensus round
            if self.store is not None:
                self.store.snapshot_ledger(self.ledger)

            # Clear pools
            for tx_id in agreed_ids:
                self.tx_pool.pop(tx_id, None)
                self.tx_objects.pop(tx_id, None)
            self.peer_proposals.clear()
        else:
            logger.warning("No consensus reached this round")

    # ---- helpers ----

    def _reconstruct_tx(self, tx_data: dict) -> Transaction:
        """Rebuild a Transaction object from a network dict."""
        amount_d = tx_data.get("amount", {"value": 0, "currency": "NXF"})
        fee_d = tx_data.get("fee", {"value": 0.00001, "currency": "NXF"})
        tx = Transaction(
            tx_data.get("tx_type", 0),
            tx_data.get("account", ""),
            tx_data.get("destination", ""),
            Amount(float(amount_d["value"]), amount_d.get("currency", "NXF"), amount_d.get("issuer", "")),
            Amount(float(fee_d["value"])),
            tx_data.get("sequence", 0),
            tx_data.get("memo", ""),
        )
        tx.tx_id = tx_data.get("tx_id", "")
        if "signing_pub_key" in tx_data:
            tx.signing_pub_key = bytes.fromhex(tx_data["signing_pub_key"])
        if "signature" in tx_data:
            tx.signature = bytes.fromhex(tx_data["signature"])
        return tx

    def fund_local(self, address: str, amount: float):
        """Fund an address from genesis (local helper for testing)."""
        if not self.ledger.account_exists(address):
            self.ledger.create_account(address, 0.0)
        genesis = self.ledger.get_account(self.ledger.genesis_account)
        dest = self.ledger.get_account(address)
        if genesis and dest and genesis.balance >= amount:
            genesis.balance -= amount
            dest.balance += amount
            logger.info(f"Funded {address[:16]}... with {amount} NXF")

    def status(self) -> dict:
        return {
            "node_id": self.node_id,
            "address": self.wallet.address,
            "port": self.port,
            "peers": self.p2p.peer_count,
            "ledger": self.ledger.get_state_summary(),
            "balance": self.ledger.get_balance(self.wallet.address),
            "tx_pool": len(self.tx_pool),
            "sync": self.sync_manager.status(),
            "p2p": self.p2p.status(),
        }


# ===================================================================
#  Interactive CLI
# ===================================================================

async def interactive_cli(node: NexaFlowNode):
    """Simple async CLI for interacting with the running node."""
    loop = asyncio.get_event_loop()

    def print_help():
        print("""
╔══════════════════════════════════════════════════════════════╗
║  NexaFlow Node CLI                                            ║
╠══════════════════════════════════════════════════════════════╣
║  status          - Show node status                          ║
║  balance [addr]  - Check balance                             ║
║  send <to> <amt> - Send NXF payment                          ║
║  peers           - List connected peers                      ║
║  ledger          - Show ledger info                           ║
║  sync            - Trigger ledger sync with peers             ║
║  consensus       - Trigger consensus now                      ║
║  fund <addr> <n> - Fund address from genesis (test)           ║
║  help            - Show this help                             ║
║  quit            - Shutdown node                              ║
╚══════════════════════════════════════════════════════════════╝
""")

    print_help()

    while True:
        try:
            line = await loop.run_in_executor(None, lambda: input(f"\n[{node.node_id}] > "))
            parts = line.strip().split()
            if not parts:
                continue

            cmd = parts[0].lower()

            if cmd == "help":
                print_help()

            elif cmd == "status":
                s = node.status()
                print(json.dumps(s, indent=2, default=str))

            elif cmd == "balance":
                addr = parts[1] if len(parts) > 1 else node.wallet.address
                bal = node.ledger.get_balance(addr)
                print(f"  {addr}: {bal:.6f} NXF")

            elif cmd == "send":
                if len(parts) < 3:
                    print("  Usage: send <destination_address> <amount>")
                    continue
                dest = parts[1]
                amt = float(parts[2])
                memo = " ".join(parts[3:]) if len(parts) > 3 else ""
                tx = await node.send_payment(dest, amt, "NXF", memo)
                if tx:
                    print(f"  TX submitted: {tx.tx_id[:16]}...")
                else:
                    print("  TX failed — check logs")

            elif cmd == "peers":
                for p in node.p2p.peers.values():
                    print(f"  {p.peer_id} | {p.remote_addr} | "
                          f"{p.direction} | msgs: {p.messages_sent}/{p.messages_received}")
                if not node.p2p.peers:
                    print("  No peers connected")

            elif cmd == "ledger":
                summary = node.ledger.get_state_summary()
                print(json.dumps(summary, indent=2))
                if node.ledger.closed_ledgers:
                    last = node.ledger.closed_ledgers[-1]
                    print(f"  Last closed: seq={last.sequence} hash={last.hash[:16]}...")

            elif cmd == "sync":
                print("  Triggering ledger sync...")
                ok = await node.sync_manager.request_sync()
                if ok:
                    # Give it a moment to complete
                    await asyncio.sleep(DATA_TIMEOUT + STATUS_TIMEOUT + 1)
                    ss = node.sync_manager.status()
                    print(f"  Sync complete. Ledger seq={ss['local_sequence']}")
                    print(json.dumps(ss, indent=2, default=str))
                else:
                    print("  Sync already in progress or on cooldown")

            elif cmd == "consensus":
                await node.run_consensus()

            elif cmd == "fund":
                if len(parts) < 3:
                    print("  Usage: fund <address> <amount>")
                    continue
                node.fund_local(parts[1], float(parts[2]))

            elif cmd in ("quit", "exit", "q"):
                print("Shutting down...")
                await node.stop()
                break

            else:
                print(f"  Unknown command: {cmd}. Type 'help'.")

        except (EOFError, KeyboardInterrupt):
            print("\nShutting down...")
            await node.stop()
            break
        except Exception as e:
            print(f"  Error: {e}")


# ===================================================================
#  Main entry point
# ===================================================================

def parse_args():
    p = argparse.ArgumentParser(description="NexaFlow Validator Node")
    p.add_argument("--config", default=None, help="Path to nexaflow.toml config file")
    p.add_argument("--node-id", default=os.environ.get("NEXAFLOW_NODE_ID", "validator-1"),
                    help="Unique node identifier")
    p.add_argument("--host", default="0.0.0.0", help="Listen host")
    p.add_argument("--port", type=int,
                    default=int(os.environ.get("NEXAFLOW_PORT", "9001")),
                    help="Listen port")
    p.add_argument("--peers", nargs="*",
                    default=(os.environ.get("NEXAFLOW_PEERS", "").split(",")
                             if os.environ.get("NEXAFLOW_PEERS") else []),
                    help="Seed peers as host:port")
    p.add_argument("--fund-address",
                    default=os.environ.get("NEXAFLOW_FUND_ADDR", ""),
                    help="Fund this address on startup")
    p.add_argument("--fund-amount", type=float,
                    default=float(os.environ.get("NEXAFLOW_FUND_AMT", "0")),
                    help="Amount to fund")
    p.add_argument("--no-cli", action="store_true",
                    help="Run without interactive CLI")
    return p.parse_args()


async def main():
    args = parse_args()

    # Load config (TOML + env overrides)
    cfg = load_config(args.config)

    # CLI flags override config
    if args.node_id != "validator-1" or not cfg.node.node_id:
        cfg.node.node_id = args.node_id
    if args.host != "0.0.0.0":
        cfg.node.host = args.host
    if args.port != 9001:
        cfg.node.port = args.port
    if args.peers:
        cfg.node.peers = [p for p in args.peers if p]

    node = NexaFlowNode(
        node_id=cfg.node.node_id,
        host=cfg.node.host,
        port=cfg.node.port,
        peers=cfg.node.peers or [p for p in args.peers if p],
        config=cfg,
    )
    await node.start()

    # ── BFT safety warning ───────────────────────────────────────
    if not cfg.consensus.validator_key_file or not cfg.consensus.validator_pubkeys_dir:
        logger.warning(
            "⚠  Running in NON-BFT mode — consensus proposals are unsigned. "
            "Set [consensus] validator_key_file and validator_pubkeys_dir "
            "in nexaflow.toml for Byzantine fault tolerance."
        )

    # Optional: fund an address from genesis for testing
    if args.fund_address:
        node.fund_local(args.fund_address, args.fund_amount or 10000.0)

    # Always fund own wallet for testing (only in dev mode / no genesis config)
    if not cfg.genesis.accounts:
        node.fund_local(node.wallet.address, 50000.0)

    if args.no_cli:
        # Run forever without CLI
        try:
            while True:
                await asyncio.sleep(1)
        except (KeyboardInterrupt, asyncio.CancelledError):
            await node.stop()
    else:
        await interactive_cli(node)


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())


def main_sync():
    """Synchronous entry point for console_scripts."""
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
