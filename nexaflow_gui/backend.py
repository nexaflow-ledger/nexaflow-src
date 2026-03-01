"""
Async backend bridge — runs a NexaFlow node on a background thread and
exposes a signal-based API that Qt widgets can safely connect to.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

# ── NexaFlow imports ────────────────────────────────────────────────────
from nexaflow_core.config import load_config
from nexaflow_core.network import Network, ValidatorNode
from nexaflow_core.order_book import OrderBook
from nexaflow_core.staking import TIER_NAMES, StakeTier
from nexaflow_core.transaction import (
    Amount,
    create_offer,
    create_payment,
    create_stake,
    create_trust_set,
    create_unstake,
)
from nexaflow_core.wallet import Wallet

logger = logging.getLogger("nexaflow_gui.backend")


class NodeBackend(QObject):
    """
    In-process NexaFlow node that runs a *local simulation network*
    (no real TCP) so the GUI works instantly without Docker.

    All mutations happen on the main thread (Qt) — no async loop needed
    for the local-simulation path.
    """

    # ── Signals (thread-safe updates to the GUI) ────────────────────────
    status_updated = pyqtSignal(dict)             # full status snapshot
    balance_updated = pyqtSignal(str, float)       # (address, balance)
    tx_submitted = pyqtSignal(dict)                # tx dict
    tx_applied = pyqtSignal(dict)                  # tx dict after consensus
    consensus_completed = pyqtSignal(dict)         # consensus result
    ledger_closed = pyqtSignal(dict)               # ledger header
    log_message = pyqtSignal(str)                  # log line
    error_occurred = pyqtSignal(str)               # error message
    accounts_changed = pyqtSignal()                # any account created/changed
    trust_lines_changed = pyqtSignal()             # trust lines altered
    peers_changed = pyqtSignal()                   # network topology changed
    order_book_changed = pyqtSignal()              # DEX state changed
    wallet_created = pyqtSignal(dict)              # wallet info
    staking_changed = pyqtSignal()                 # any staking state change
    p2p_status_updated = pyqtSignal(dict)            # real-time P2P snapshot
    ledger_reset = pyqtSignal()                      # ledger data wiped

    # Dev mode: enabled via NEXAFLOW_DEV_MODE=1 env var
    DEV_MODE: bool = os.environ.get("NEXAFLOW_DEV_MODE", "0") == "1"

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)

        # ── Load configuration ──────────────────────────────────────────
        self.config = load_config("nexaflow.toml")

        # ── Core objects ────────────────────────────────────────────────
        genesis_accounts = self.config.genesis.accounts or None
        self.network = Network(
            total_supply=self.config.ledger.total_supply,
            genesis_accounts=genesis_accounts,
        )
        self.order_book = OrderBook()
        self.wallets: dict[str, Wallet] = {}       # address → Wallet
        self.wallet_names: dict[str, str] = {}     # address → friendly name
        self.tx_history: list[dict] = []

        # Derive validator set: this node + one per peer
        self._validators = self._build_validator_list()
        for vid in self._validators:
            self.network.add_validator(vid)

        # Primary node reference (this node is first)
        self._primary_node: ValidatorNode = self.network.nodes[self._validators[0]]

        # Poll timer for periodic status refresh
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(3000)
        self._poll_timer.timeout.connect(self._emit_status)

        # Fast P2P status timer (1 s)
        self._p2p_timer = QTimer(self)
        self._p2p_timer.setInterval(1000)
        self._p2p_timer.timeout.connect(self._emit_p2p_status)

        self._log(f"Backend initialised with {len(self._validators)} validator(s): {', '.join(self._validators)}")
    def _build_validator_list(self) -> list[str]:
        """Derive the validator set from config: this node + one per peer."""
        validators = [self.config.node.node_id]
        for i, peer in enumerate(self.config.node.peers, start=2):
            # Use hostname from peer address as ID, fallback to peer-N
            host = peer.rsplit(":", 1)[0] if ":" in peer else peer
            # If it looks like a raw IP or generic hostname, generate a name
            if host.replace(".", "").isdigit() or host in ("localhost", "127.0.0.1", "0.0.0.0"):
                vid = f"validator-{i}"
            else:
                vid = host
            validators.append(vid)
        return validators
    # ── Lifecycle ───────────────────────────────────────────────────────

    def start(self) -> None:
        self._poll_timer.start()
        self._p2p_timer.start()
        self._emit_status()
        self._emit_p2p_status()
        self._log("Node network started")

    def stop(self) -> None:
        self._poll_timer.stop()
        self._p2p_timer.stop()
        self._log("Node network stopped")

    # ── Wallet operations ───────────────────────────────────────────────

    def create_wallet(self, name: str = "") -> dict:
        """Create a new wallet with zero balance.

        The wallet must receive funds through a legitimate payment
        from the genesis account or another funded account.
        """
        wallet = Wallet.create()
        self.wallets[wallet.address] = wallet
        self.wallet_names[wallet.address] = name or f"Wallet-{len(self.wallets)}"
        # Register the address on every validator ledger with 0 balance
        for node in self.network.nodes.values():
            if not node.ledger.account_exists(wallet.address):
                node.ledger.create_account(wallet.address, 0.0)
        bal = self._primary_node.ledger.get_balance(wallet.address)
        info = {
            "address": wallet.address,
            "name": self.wallet_names[wallet.address],
            "balance": bal,
            "public_key": wallet.public_key.hex(),
        }
        self.wallet_created.emit(info)
        self.accounts_changed.emit()
        self._log(f"Created wallet '{info['name']}' → {wallet.address[:16]}…")
        return info

    def import_wallet_from_seed(self, seed: str, name: str = "") -> dict:
        """Import a wallet from a deterministic seed.

        The wallet is registered with zero balance.  Funds must come
        from a legitimate payment originating at the genesis account.
        """
        wallet = Wallet.from_seed(seed)
        self.wallets[wallet.address] = wallet
        self.wallet_names[wallet.address] = name or f"Seed-{seed[:8]}"
        # Register with 0 balance if new
        for node in self.network.nodes.values():
            if not node.ledger.account_exists(wallet.address):
                node.ledger.create_account(wallet.address, 0.0)
        bal = self._primary_node.ledger.get_balance(wallet.address)
        info = {
            "address": wallet.address,
            "name": self.wallet_names[wallet.address],
            "balance": bal,
            "public_key": wallet.public_key.hex(),
        }
        self.wallet_created.emit(info)
        self.accounts_changed.emit()
        self._log(f"Imported wallet from seed → {wallet.address[:16]}…")
        return info

    def get_wallets(self) -> list[dict]:
        """Return a list of all known wallets with balances."""
        result = []
        for addr, w in self.wallets.items():
            bal = self._primary_node.ledger.get_balance(addr)
            result.append({
                "address": addr,
                "name": self.wallet_names.get(addr, ""),
                "balance": bal,
                "public_key": w.public_key.hex(),
            })
        return result

    def export_wallet(self, address: str, passphrase: str) -> str:
        """Export wallet as encrypted JSON string."""
        wallet = self.wallets.get(address)
        if not wallet:
            raise ValueError(f"No wallet found for {address}")
        data = wallet.export_encrypted(passphrase)
        data["name"] = self.wallet_names.get(address, "")
        return json.dumps(data, indent=2)

    def get_wallet_keys(self, address: str) -> dict:
        """Return raw key material for a wallet (DANGEROUS — guard in UI)."""
        wallet = self.wallets.get(address)
        if not wallet:
            raise ValueError(f"No wallet found for {address}")
        return wallet.to_dict()

    def recover_wallet_from_keys(
        self,
        public_key: str,
        private_key: str,
        address: str | None = None,
        name: str = "",
        view_public_key: str | None = None,
        view_private_key: str | None = None,
        spend_public_key: str | None = None,
        spend_private_key: str | None = None,
    ) -> dict:
        """Recover a wallet from raw hex key material.

        Parameters
        ----------
        public_key       130-char hex uncompressed secp256k1 public key.
        private_key      64-char hex secp256k1 private key.
        address          Optional address; derived from public key if omitted.
        name             Optional friendly name.
        view_public_key  Optional 130-char hex view public key (privacy/stealth).
        view_private_key Optional 64-char hex view private key.
        spend_public_key Optional 130-char hex spend public key.
        spend_private_key Optional 64-char hex spend private key.
        """
        pub = bytes.fromhex(public_key)
        priv = bytes.fromhex(private_key)

        # Validate key pairing — derive public key from private and compare
        try:
            from ecdsa import SECP256k1, SigningKey
            sk = SigningKey.from_string(priv, curve=SECP256k1)
            derived_pub = b"\x04" + sk.get_verifying_key().to_string()
            if derived_pub != pub:
                raise ValueError(
                    "Public key does not match the provided private key. "
                    "Please double-check both values."
                )
        except ImportError:
            pass  # ecdsa not installed — skip verification

        v_pub = bytes.fromhex(view_public_key) if view_public_key else None
        v_priv = bytes.fromhex(view_private_key) if view_private_key else None
        s_pub = bytes.fromhex(spend_public_key) if spend_public_key else None
        s_priv = bytes.fromhex(spend_private_key) if spend_private_key else None

        # Validate view key pairing if both provided
        if v_priv and v_pub:
            try:
                from ecdsa import SECP256k1, SigningKey
                vk = SigningKey.from_string(v_priv, curve=SECP256k1)
                derived_v_pub = b"\x04" + vk.get_verifying_key().to_string()
                if derived_v_pub != v_pub:
                    raise ValueError(
                        "View public key does not match view private key."
                    )
            except ImportError:
                pass

        # Validate spend key pairing if both provided
        if s_priv and s_pub:
            try:
                from ecdsa import SECP256k1, SigningKey
                sk2 = SigningKey.from_string(s_priv, curve=SECP256k1)
                derived_s_pub = b"\x04" + sk2.get_verifying_key().to_string()
                if derived_s_pub != s_pub:
                    raise ValueError(
                        "Spend public key does not match spend private key."
                    )
            except ImportError:
                pass

        wallet = Wallet(
            priv, pub, address,
            view_private_key=v_priv, view_public_key=v_pub,
            spend_private_key=s_priv, spend_public_key=s_pub,
        )

        self.wallets[wallet.address] = wallet
        self.wallet_names[wallet.address] = (
            name or f"Recovered-{wallet.address[:8]}"
        )

        # Register on all validator ledgers
        for node in self.network.nodes.values():
            if not node.ledger.account_exists(wallet.address):
                node.ledger.create_account(wallet.address, 0.0)

        bal = self._primary_node.ledger.get_balance(wallet.address)
        info = {
            "address": wallet.address,
            "name": self.wallet_names[wallet.address],
            "balance": bal,
            "public_key": wallet.public_key.hex(),
        }
        self.wallet_created.emit(info)
        self.accounts_changed.emit()

        has_privacy = bool(v_priv and s_priv)
        self._log(
            f"Recovered wallet → {wallet.address[:16]}… "
            f"({'with' if has_privacy else 'without'} untraceable keys)"
        )
        return info

    def import_wallet_from_file(self, data_str: str, passphrase: str) -> dict:
        """Import a wallet from an encrypted JSON export."""
        data = json.loads(data_str)
        wallet = Wallet.import_encrypted(data, passphrase)
        name = data.get("name", "")
        self.wallets[wallet.address] = wallet
        self.wallet_names[wallet.address] = name or f"Import-{wallet.address[:8]}"
        for node in self.network.nodes.values():
            if not node.ledger.account_exists(wallet.address):
                node.ledger.create_account(wallet.address, 0.0)
        bal = self._primary_node.ledger.get_balance(wallet.address)
        info = {
            "address": wallet.address,
            "name": self.wallet_names[wallet.address],
            "balance": bal,
            "public_key": wallet.public_key.hex(),
        }
        self.wallet_created.emit(info)
        self.accounts_changed.emit()
        self._log(f"Imported wallet from file → {wallet.address[:16]}…")
        return info

    # ── Transaction operations ──────────────────────────────────────────

    def _account_seq(self, address: str) -> int:
        """Return the current sequence number for *address* from the ledger."""
        acc = self._primary_node.ledger.get_account(address)
        return acc.sequence if acc is not None else 1

    def _apply_immediately(self) -> None:
        """Run a consensus round so that pending TXs are applied right away.

        In the GUI simulation there is no async consensus loop, so we
        trigger it after every broadcast to keep the ledger up-to-date.
        """
        self.run_consensus()

    def send_payment(
        self,
        from_address: str,
        destination: str,
        amount: float,
        currency: str = "NXF",
        issuer: str = "",
        memo: str = "",
    ) -> dict | None:
        """Build, sign, broadcast a payment."""
        wallet = self.wallets.get(from_address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {from_address}")
            return None

        try:
            seq = self._account_seq(from_address)
            tx = create_payment(
                account=from_address,
                destination=destination,
                amount=amount,
                currency=currency,
                issuer=issuer,
                memo=memo,
                sequence=seq,
            )
            wallet.sign_transaction(tx)

            # Broadcast to all validators
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _code, _msg in results.values())

            # Apply immediately so the ledger sequence stays in sync
            if accepted:
                self._apply_immediately()

            tx_dict = tx.to_dict()
            tx_dict["_accepted"] = accepted
            self.tx_history.append(tx_dict)
            self.tx_submitted.emit(tx_dict)

            if accepted:
                self._log(
                    f"Payment {tx.tx_id[:12]}… | {from_address[:10]}… → "
                    f"{destination[:10]}… | {amount:,.8f} {currency}"
                )
            else:
                msgs = [msg for _ok, _code, msg in results.values()]
                self.error_occurred.emit(f"TX rejected: {msgs[0]}")

            return tx_dict

        except Exception as exc:
            self.error_occurred.emit(f"Payment failed: {exc}")
            logger.exception("Payment error")
            return None

    def set_trust_line(
        self,
        from_address: str,
        currency: str,
        issuer: str,
        limit: float,
    ) -> dict | None:
        """Create / update a trust line."""
        wallet = self.wallets.get(from_address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {from_address}")
            return None

        try:
            seq = self._account_seq(from_address)
            tx = create_trust_set(
                account=from_address,
                currency=currency,
                issuer=issuer,
                limit=limit,
                sequence=seq,
            )
            wallet.sign_transaction(tx)

            self.network.broadcast_transaction(tx)
            self._apply_immediately()
            tx_dict = tx.to_dict()
            self.tx_history.append(tx_dict)
            self.tx_submitted.emit(tx_dict)
            self.trust_lines_changed.emit()
            self._log(f"TrustSet {currency}/{issuer[:10]}… limit={limit:,.8f}")
            return tx_dict

        except Exception as exc:
            self.error_occurred.emit(f"TrustSet failed: {exc}")
            return None

    def create_dex_offer(
        self,
        from_address: str,
        pays_amount: float,
        pays_currency: str,
        pays_issuer: str,
        gets_amount: float,
        gets_currency: str,
        gets_issuer: str,
    ) -> dict | None:
        """Create a DEX order (OfferCreate)."""
        wallet = self.wallets.get(from_address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {from_address}")
            return None

        try:
            taker_pays = Amount(pays_amount, pays_currency, pays_issuer)
            taker_gets = Amount(gets_amount, gets_currency, gets_issuer)
            seq = self._account_seq(from_address)
            tx = create_offer(
                account=from_address,
                taker_pays=taker_pays,
                taker_gets=taker_gets,
                sequence=seq,
            )
            wallet.sign_transaction(tx)

            self.network.broadcast_transaction(tx)
            self._apply_immediately()
            fills = self.order_book.process_offer_create(tx)

            tx_dict = tx.to_dict()
            tx_dict["_fills"] = [f.to_dict() for f in fills]
            self.tx_history.append(tx_dict)
            self.tx_submitted.emit(tx_dict)
            self.order_book_changed.emit()
            self._log(f"OfferCreate {pays_currency}/{gets_currency} — {len(fills)} fill(s)")
            return tx_dict

        except Exception as exc:
            self.error_occurred.emit(f"Offer failed: {exc}")
            return None

    # ── Consensus ───────────────────────────────────────────────────────

    def run_consensus(self) -> dict | None:
        """Execute a consensus round across all validators."""
        try:
            result = self.network.run_consensus_round()
            self.consensus_completed.emit(result)
            self.accounts_changed.emit()
            self.trust_lines_changed.emit()

            agreed = result.get("agreed", 0)
            status = result.get("status", "unknown")
            self._log(f"Consensus round → {status} | {agreed} tx(s) applied")

            # Emit updated balances for tracked wallets
            for addr in self.wallets:
                bal = self._primary_node.ledger.get_balance(addr)
                self.balance_updated.emit(addr, bal)

            return result

        except Exception as exc:
            self.error_occurred.emit(f"Consensus failed: {exc}")
            logger.exception("Consensus error")
            return None

    # ── Queries ─────────────────────────────────────────────────────────

    def get_balance(self, address: str) -> float:
        return self._primary_node.ledger.get_balance(address)

    def get_account_info(self, address: str) -> dict | None:
        acct = self._primary_node.ledger.get_account(address)
        return acct.to_dict() if acct else None

    def get_all_accounts(self) -> list[dict]:
        ledger = self._primary_node.ledger
        return [
            acct.to_dict()
            for acct in ledger.accounts.values()
        ]

    def get_ledger_summary(self) -> dict:
        return self._primary_node.ledger.get_state_summary()

    def get_closed_ledgers(self) -> list[dict]:
        return [lh.to_dict() for lh in self._primary_node.ledger.closed_ledgers]

    def get_trust_lines(self) -> list[dict]:
        """Gather trust lines from the primary ledger."""
        lines = []
        for acct in self._primary_node.ledger.accounts.values():
            for _key, tl in acct.trust_lines.items():
                lines.append(tl.to_dict())
        return lines

    def get_network_status(self) -> dict:
        return self.network.network_status()

    def get_order_book_snapshot(self, pair: str, depth: int = 20) -> dict:
        return self.order_book.get_book_snapshot(pair, depth)

    def get_order_book_pairs(self) -> list[str]:
        return self.order_book.pairs

    def get_recent_fills(self, limit: int = 50) -> list[dict]:
        return self.order_book.get_fills(limit)

    # ── Staking operations ──────────────────────────────────────────────

    def stake_nxf(
        self, address: str, amount: float, tier: int
    ) -> dict | None:
        """
        Build, sign, and apply a Stake transaction.

        Returns the tx dict on success, None on failure.
        """
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None

        try:
            seq = self._account_seq(address)
            tx = create_stake(
                account=address,
                amount=amount,
                stake_tier=tier,
                sequence=seq,
            )
            wallet.sign_transaction(tx)

            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _code, _msg in results.values())

            if accepted:
                self._apply_immediately()
                tier_name = TIER_NAMES.get(StakeTier(tier), "Unknown")
                self.staking_changed.emit()
                self.accounts_changed.emit()
                bal = self._primary_node.ledger.get_balance(address)
                self.balance_updated.emit(address, bal)
                self._log(
                    f"Staked {amount:,.8f} NXF | {address[:16]}… | "
                    f"tier={tier_name} | tx={tx.tx_id[:12]}…"
                )
            else:
                msgs = [msg for _ok, _code, msg in results.values()]
                self.error_occurred.emit(f"Stake rejected: {msgs[0]}")
                return None

            return tx.to_dict()

        except Exception as exc:
            self.error_occurred.emit(f"Staking failed: {exc}")
            return None

    def cancel_stake(self, stake_id: str) -> dict | None:
        """
        Build, sign, and apply an Unstake (early cancellation) transaction.

        Locked-tier stakes will incur a penalty.
        Returns the tx dict on success, None on failure.
        """
        # Find which wallet owns this stake
        record = self._primary_node.ledger.staking_pool.stakes.get(stake_id)
        if record is None:
            self.error_occurred.emit(f"Stake {stake_id} not found")
            return None

        address = record.address
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None

        try:
            seq = self._account_seq(address)
            tx = create_unstake(
                account=address,
                stake_id=stake_id,
                sequence=seq,
            )
            wallet.sign_transaction(tx)

            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _code, _msg in results.values())

            if accepted:
                self._apply_immediately()
                self.staking_changed.emit()
                self.accounts_changed.emit()
                bal = self._primary_node.ledger.get_balance(address)
                self.balance_updated.emit(address, bal)
                self._log(
                    f"Cancelled stake {stake_id[:12]}… | "
                    f"payout={record.payout_amount:,.8f} NXF"
                )
            else:
                msgs = [msg for _ok, _code, msg in results.values()]
                self.error_occurred.emit(f"Unstake rejected: {msgs[0]}")
                return None

            return tx.to_dict()

        except Exception as exc:
            self.error_occurred.emit(f"Unstake failed: {exc}")
            return None

    def get_stakes_for_address(
        self, address: str, active_only: bool = True
    ) -> list[dict]:
        """Return all stakes for an address."""
        if active_only:
            stakes = self._primary_node.ledger.staking_pool.get_active_stakes(address)
        else:
            stakes = self._primary_node.ledger.staking_pool.get_all_stakes(address)
        return [s.to_dict() for s in stakes]

    def get_all_active_stakes(self) -> list[dict]:
        """Return all active stakes across all tracked wallets."""
        result = []
        for addr in self.wallets:
            stakes = self._primary_node.ledger.staking_pool.get_active_stakes(addr)
            result.extend(s.to_dict() for s in stakes)
        return result

    def get_staking_summary(self, address: str) -> dict:
        """Return staking summary for an address."""
        return self._primary_node.ledger.get_staking_summary(address)

    def get_staking_pool_summary(self) -> dict:
        """Return global staking pool stats."""
        return self._primary_node.ledger.staking_pool.get_pool_summary()

    def get_staking_tiers(self) -> list[dict]:
        """Return available staking tier info with current effective APYs."""
        return self._primary_node.ledger.staking_pool.get_tier_info(
            self._primary_node.ledger.total_supply
        )

    def get_demand_multiplier(self) -> float:
        """Return the current demand multiplier for dynamic APY."""
        return self._primary_node.ledger.staking_pool.get_demand_multiplier(
            self._primary_node.ledger.total_supply
        )

    def find_payment_paths(
        self,
        source: str,
        destination: str,
        currency: str,
        amount: float,
    ) -> list[dict]:
        pf = self._primary_node.get_path_finder()
        paths = pf.find_paths(source, destination, currency, amount)
        return [p.to_dict() for p in paths]

    def get_tx_history(self) -> list[dict]:
        return list(reversed(self.tx_history))

    def get_validator_statuses(self) -> list[dict]:
        return [
            node.status()
            for node in self.network.nodes.values()
        ]

    # ── Cache management ────────────────────────────────────────────

    def clear_cache(self) -> str:
        """Remove on-disk caches and in-memory transient state.

        Clears:
          - __pycache__ directories
          - .pytest_cache / .mypy_cache directories
          - In-memory transaction history
          - In-memory order book

        Does NOT touch wallet keys, ledger state, or balances.
        Returns a human-readable summary.
        """
        import shutil
        from pathlib import Path

        project_root = Path(__file__).resolve().parent.parent
        removed: list[str] = []

        # Disk caches
        for pattern, label in [
            ("**/__pycache__", "__pycache__"),
            (".pytest_cache", ".pytest_cache"),
            (".mypy_cache", ".mypy_cache"),
        ]:
            for p in project_root.glob(pattern):
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                    removed.append(str(p.relative_to(project_root)))

        # In-memory caches
        mem_cleared: list[str] = []
        if self.tx_history:
            count = len(self.tx_history)
            self.tx_history.clear()
            mem_cleared.append(f"{count} transaction(s) from history")

        if self.order_book._orders:
            self.order_book = OrderBook()
            self.order_book_changed.emit()
            mem_cleared.append("order book")

        self._log(
            f"Cache cleared: {len(removed)} dir(s) on disk, "
            f"{len(mem_cleared)} in-memory cache(s)"
        )

        lines = []
        if removed:
            lines.append(f"Removed {len(removed)} cache director{'y' if len(removed) == 1 else 'ies'}:")
            for r in removed[:15]:
                lines.append(f"  • {r}")
            if len(removed) > 15:
                lines.append(f"  … and {len(removed) - 15} more")
        else:
            lines.append("No on-disk caches found.")
        if mem_cleared:
            lines.append("")
            lines.append("Cleared in-memory:")
            for m in mem_cleared:
                lines.append(f"  • {m}")
        else:
            lines.append("No in-memory caches to clear.")

        return "\n".join(lines)

    # ── Full data wipe ──────────────────────────────────────────────────

    def clear_all_data(self) -> str:
        """Wipe ALL data: ledger, wallets, tx history, caches, on-disk files.

        Returns a human-readable summary.
        """
        import shutil
        from pathlib import Path

        project_root = Path(__file__).resolve().parent.parent
        removed_dirs: list[str] = []
        removed_files: list[str] = []

        # 1. On-disk caches
        for pattern in ["**/__pycache__", ".pytest_cache", ".mypy_cache"]:
            for p in project_root.glob(pattern):
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                    removed_dirs.append(str(p.relative_to(project_root)))

        # 2. On-disk data directory (wallet.json, SQLite DB)
        data_dir = project_root / "data"
        if data_dir.is_dir():
            for f in data_dir.iterdir():
                if f.is_file():
                    removed_files.append(str(f.relative_to(project_root)))
                    f.unlink()
            removed_dirs.append("data/ (contents)")

        # 3. On-disk certs directory (auto-generated keys)
        certs_dir = project_root / "certs"
        if certs_dir.is_dir():
            shutil.rmtree(certs_dir, ignore_errors=True)
            removed_dirs.append("certs/")

        # 4. Rebuild network from scratch
        old_supply = self.network.total_supply
        genesis_accounts = self.config.genesis.accounts or None
        self.network = Network(old_supply, genesis_accounts=genesis_accounts)
        for vid in self._validators:
            self.network.add_validator(vid)
        self._primary_node = self.network.nodes[self._validators[0]]

        # 5. Clear all in-memory state
        self.wallets.clear()
        self.wallet_names.clear()
        self.tx_history.clear()
        self.order_book = OrderBook()

        # 6. Emit signals so every tab refreshes
        self.ledger_reset.emit()
        self.accounts_changed.emit()
        self.staking_changed.emit()
        self.trust_lines_changed.emit()
        self.order_book_changed.emit()
        self._emit_status()

        self._log("\u26a0 ALL data cleared (wallets, ledger, caches, keys)")

        lines = ["All data has been cleared:\n"]
        lines.append(f"  \u2022  {len(self.wallets)} wallets remaining (was purged)")
        lines.append("  \u2022  Ledger reset to empty")
        lines.append("  \u2022  Transaction history cleared")
        lines.append("  \u2022  Order book cleared")
        if removed_files:
            lines.append(f"  \u2022  {len(removed_files)} file(s) deleted from disk")
        if removed_dirs:
            lines.append(f"  \u2022  {len(removed_dirs)} director(ies) removed")
        lines.append("\nYou will need to create a new wallet to continue.")
        return "\n".join(lines)

    # ── Ledger reset (dev mode only) ─────────────────────────────────

    def reset_ledger(self) -> None:
        """Wipe all ledger state and reinitialise.  DEV MODE ONLY."""
        if not self.DEV_MODE:
            self.error_occurred.emit("Ledger reset is only available in dev mode")
            return
        # Rebuild network from scratch
        old_supply = self.network.total_supply
        genesis_accounts = self.config.genesis.accounts or None
        self.network = Network(old_supply, genesis_accounts=genesis_accounts)
        for vid in self._validators:
            self.network.add_validator(vid)
        self._primary_node = self.network.nodes[self._validators[0]]
        # Re-register existing wallets with 0 balance
        for addr in self.wallets:
            for node in self.network.nodes.values():
                if not node.ledger.account_exists(addr):
                    node.ledger.create_account(addr, 0.0)
        self.tx_history.clear()
        self.order_book = OrderBook()
        self.ledger_reset.emit()
        self.accounts_changed.emit()
        self.staking_changed.emit()
        self.trust_lines_changed.emit()
        self.order_book_changed.emit()
        self._emit_status()
        self._log("⚠ Ledger data reset (dev mode)")

    # ── P2P status ──────────────────────────────────────────────────────

    def get_p2p_status(self) -> dict:
        """Build a snapshot of the P2P / network simulation state."""
        nodes = self.network.nodes
        total_tx_pool = sum(len(n.tx_pool) for n in nodes.values())
        per_node = []
        for nid, node in nodes.items():
            per_node.append({
                "node_id": nid,
                "accounts": len(node.ledger.accounts),
                "tx_pool": len(node.tx_pool),
                "ledger_seq": node.ledger.current_sequence,
                "closed_ledgers": len(node.ledger.closed_ledgers),
                "unl_size": len(node.unl),
                "peers": node.unl,  # in simulation, UNL = peers
            })
        return {
            "mode": "local_simulation",
            "validator_count": len(nodes),
            "total_tx_pool": total_tx_pool,
            "nodes": per_node,
            "dev_mode": self.DEV_MODE,
        }

    # ── Internal ────────────────────────────────────────────────────────

    def _emit_status(self) -> None:
        """Periodic status snapshot pushed to the GUI."""
        try:
            summary = self.get_ledger_summary()
            summary["wallet_count"] = len(self.wallets)
            summary["tx_pool"] = sum(
                len(n.tx_pool) for n in self.network.nodes.values()
            )
            summary["validator_count"] = len(self.network.nodes)
            self.status_updated.emit(summary)
        except Exception:
            pass

    def _emit_p2p_status(self) -> None:
        """Push a P2P status snapshot every second."""
        with contextlib.suppress(Exception):
            self.p2p_status_updated.emit(self.get_p2p_status())

    def _log(self, msg: str) -> None:
        logger.info(msg)
        self.log_message.emit(msg)
