"""
Async backend bridge — runs a NexaFlow node on a background thread and
exposes a signal-based API that Qt widgets can safely connect to.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QObject, QTimer, pyqtSignal

# ── NexaFlow imports ────────────────────────────────────────────────────
from nexaflow_core.network import Network, ValidatorNode
from nexaflow_core.order_book import OrderBook
from nexaflow_core.transaction import (
    Amount,
    create_offer,
    create_payment,
    create_stake,
    create_trust_set,
    create_unstake,
)
from nexaflow_core.wallet import Wallet
from nexaflow_core.staking import StakeTier, TIER_NAMES, TIER_CONFIG

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

    def __init__(self, parent: QObject | None = None):
        super().__init__(parent)

        # ── Core objects ────────────────────────────────────────────────
        self.network = Network()
        self.order_book = OrderBook()
        self.wallets: dict[str, Wallet] = {}       # address → Wallet
        self.wallet_names: dict[str, str] = {}     # address → friendly name
        self.tx_history: list[dict] = []

        # Add a default validator so consensus works
        self.network.add_validator("validator-1")
        self.network.add_validator("validator-2")
        self.network.add_validator("validator-3")

        # Primary node reference
        self._primary_node: ValidatorNode = self.network.nodes["validator-1"]

        # Poll timer for periodic status refresh
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(3000)
        self._poll_timer.timeout.connect(self._emit_status)

        self._log("Backend initialised with 3 validators")

    # ── Lifecycle ───────────────────────────────────────────────────────

    def start(self) -> None:
        self._poll_timer.start()
        self._emit_status()
        self._log("Node network started")

    def stop(self) -> None:
        self._poll_timer.stop()
        self._log("Node network stopped")

    # ── Wallet operations ───────────────────────────────────────────────

    def create_wallet(self, name: str = "") -> dict:
        """Create a new wallet and fund it from genesis."""
        wallet = Wallet.create()
        self.wallets[wallet.address] = wallet
        self.wallet_names[wallet.address] = name or f"Wallet-{len(self.wallets)}"
        # Fund on all nodes
        self.network.fund_account(wallet.address, 1000.0)
        info = {
            "address": wallet.address,
            "name": self.wallet_names[wallet.address],
            "balance": 1000.0,
            "public_key": wallet.public_key.hex(),
        }
        self.wallet_created.emit(info)
        self.accounts_changed.emit()
        self._log(f"Created wallet '{info['name']}' → {wallet.address[:16]}…")
        return info

    def import_wallet_from_seed(self, seed: str, name: str = "") -> dict:
        """Import a wallet from a deterministic seed."""
        wallet = Wallet.from_seed(seed)
        self.wallets[wallet.address] = wallet
        self.wallet_names[wallet.address] = name or f"Seed-{seed[:8]}"
        if not self._primary_node.ledger.account_exists(wallet.address):
            self.network.fund_account(wallet.address, 1000.0)
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

    def fund_wallet(self, address: str, amount: float) -> None:
        """Fund a wallet from genesis."""
        self.network.fund_account(address, amount)
        bal = self._primary_node.ledger.get_balance(address)
        self.balance_updated.emit(address, bal)
        self.accounts_changed.emit()
        self._log(f"Funded {address[:16]}… with {amount:,.2f} NXF")

    # ── Transaction operations ──────────────────────────────────────────

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
            tx = create_payment(
                account=from_address,
                destination=destination,
                amount=amount,
                currency=currency,
                issuer=issuer,
                memo=memo,
                sequence=wallet.sequence,
            )
            wallet.sign_transaction(tx)
            wallet.sequence += 1  # type: ignore[operator]

            # Broadcast to all validators
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _code, _msg in results.values())

            tx_dict = tx.to_dict()
            tx_dict["_accepted"] = accepted
            self.tx_history.append(tx_dict)
            self.tx_submitted.emit(tx_dict)

            if accepted:
                self._log(
                    f"Payment {tx.tx_id[:12]}… | {from_address[:10]}… → "
                    f"{destination[:10]}… | {amount:,.4f} {currency}"
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
            tx = create_trust_set(
                account=from_address,
                currency=currency,
                issuer=issuer,
                limit=limit,
                sequence=wallet.sequence,
            )
            wallet.sign_transaction(tx)
            wallet.sequence += 1  # type: ignore[operator]

            self.network.broadcast_transaction(tx)
            tx_dict = tx.to_dict()
            self.tx_history.append(tx_dict)
            self.tx_submitted.emit(tx_dict)
            self.trust_lines_changed.emit()
            self._log(f"TrustSet {currency}/{issuer[:10]}… limit={limit:,.2f}")
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
            tx = create_offer(
                account=from_address,
                taker_pays=taker_pays,
                taker_gets=taker_gets,
                sequence=wallet.sequence,
            )
            wallet.sign_transaction(tx)
            wallet.sequence += 1  # type: ignore[operator]

            self.network.broadcast_transaction(tx)
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
            tx = create_stake(
                account=address,
                amount=amount,
                stake_tier=tier,
                sequence=wallet.sequence,
            )
            wallet.sign_transaction(tx)
            wallet.sequence += 1

            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _code, _msg in results.values())

            if accepted:
                tier_name = TIER_NAMES.get(StakeTier(tier), "Unknown")
                self.staking_changed.emit()
                self.accounts_changed.emit()
                bal = self._primary_node.ledger.get_balance(address)
                self.balance_updated.emit(address, bal)
                self._log(
                    f"Staked {amount:,.2f} NXF | {address[:16]}… | "
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
            tx = create_unstake(
                account=address,
                stake_id=stake_id,
                sequence=wallet.sequence,
            )
            wallet.sign_transaction(tx)
            wallet.sequence += 1

            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _code, _msg in results.values())

            if accepted:
                self.staking_changed.emit()
                self.accounts_changed.emit()
                bal = self._primary_node.ledger.get_balance(address)
                self.balance_updated.emit(address, bal)
                self._log(
                    f"Cancelled stake {stake_id[:12]}… | "
                    f"payout={record.payout_amount:,.4f} NXF"
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

    def _log(self, msg: str) -> None:
        logger.info(msg)
        self.log_message.emit(msg)
