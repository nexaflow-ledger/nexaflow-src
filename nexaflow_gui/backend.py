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
    create_pmc_create,
    create_pmc_mint,
    create_pmc_transfer,
    create_pmc_burn,
    create_pmc_set_rules,
    create_pmc_offer_create,
    create_pmc_offer_accept,
    create_pmc_offer_cancel,
)
from nexaflow_core.wallet import Wallet
from nexaflow_core.mining_api import MiningNode, MiningCoordinator, PoolConfig

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
    pmc_changed = pyqtSignal()                       # PMC state change
    mining_pool_changed = pyqtSignal()               # mining pool state change
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

        # ── Mining pool (Stratum server for Bitcoin hardware) ───────────
        self.mining_node: MiningNode | None = None

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

    # ── PMC operations ──────────────────────────────────────────────────

    def pmc_create_coin(
        self,
        address: str,
        symbol: str,
        name: str,
        max_supply: float = 0.0,
        decimals: int = 8,
        pow_difficulty: int = 4,
        base_reward: float = 50.0,
        pmc_flags: int = 0x004F,
        metadata: str = "",
        rules: list | None = None,
    ) -> dict | None:
        """Create a new Programmable Micro Coin."""
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_create(
                account=address, symbol=symbol, name=name,
                max_supply=max_supply, decimals=decimals,
                pow_difficulty=pow_difficulty, base_reward=base_reward,
                pmc_flags=pmc_flags,
                metadata=metadata, rules=rules or [],
                sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                self.accounts_changed.emit()
                self._log(f"PMC Created: {symbol} | issuer={address[:16]}…")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCCreate rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCCreate failed: {exc}")
            return None

    def pmc_mint(
        self, address: str, coin_id: str, nonce: int,
    ) -> dict | None:
        """Mint new PMC supply via Proof-of-Work.

        The reward amount is computed automatically from the coin's
        difficulty and base_reward — miners do not choose it.
        """
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_mint(
                account=address, coin_id=coin_id,
                nonce=nonce, sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                self._log(f"PMC Mined: coin={coin_id[:12]}… | miner={address[:12]}…")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCMint rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCMint failed: {exc}")
            return None

    def pmc_transfer(
        self, address: str, destination: str, coin_id: str,
        amount: float, memo: str = ""
    ) -> dict | None:
        """Transfer PMC tokens."""
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_transfer(
                account=address, destination=destination,
                coin_id=coin_id, amount=amount, memo=memo,
                sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                self.accounts_changed.emit()
                self._log(f"PMC Transfer: {amount} | {address[:12]}… → {destination[:12]}…")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCTransfer rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCTransfer failed: {exc}")
            return None

    def pmc_burn(
        self, address: str, coin_id: str, amount: float
    ) -> dict | None:
        """Burn PMC tokens."""
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_burn(
                account=address, coin_id=coin_id, amount=amount,
                sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                self._log(f"PMC Burned: {amount} | coin={coin_id[:12]}…")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCBurn rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCBurn failed: {exc}")
            return None

    def pmc_offer_create(
        self, address: str, coin_id: str, is_sell: bool,
        amount: float, price: float, counter_coin_id: str = "",
        destination: str = "", expiration: float = 0.0,
    ) -> dict | None:
        """Post a PMC DEX offer."""
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_offer_create(
                account=address, coin_id=coin_id, is_sell=is_sell,
                amount=amount, price=price,
                counter_coin_id=counter_coin_id,
                destination=destination, expiration=expiration,
                sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                side = "SELL" if is_sell else "BUY"
                self._log(f"PMC Offer: {side} {amount} @ {price} NXF")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCOffer rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCOffer failed: {exc}")
            return None

    def pmc_offer_accept(
        self, address: str, offer_id: str, fill_amount: float = 0.0,
    ) -> dict | None:
        """Accept (fill) a PMC DEX offer."""
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_offer_accept(
                account=address, offer_id=offer_id,
                fill_amount=fill_amount, sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                self.accounts_changed.emit()
                self._log(f"PMC Offer accepted: {offer_id[:12]}…")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCOfferAccept rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCOfferAccept failed: {exc}")
            return None

    def pmc_offer_cancel(
        self, address: str, offer_id: str,
    ) -> dict | None:
        """Cancel an open PMC DEX offer."""
        wallet = self.wallets.get(address)
        if not wallet:
            self.error_occurred.emit(f"No wallet found for {address}")
            return None
        try:
            seq = self._account_seq(address)
            tx = create_pmc_offer_cancel(
                account=address, offer_id=offer_id, sequence=seq,
            )
            wallet.sign_transaction(tx)
            results = self.network.broadcast_transaction(tx)
            accepted = any(ok for ok, _c, _m in results.values())
            if accepted:
                self._apply_immediately()
                self.pmc_changed.emit()
                self._log(f"PMC Offer cancelled: {offer_id[:12]}…")
            else:
                msgs = [m for _, _, m in results.values()]
                self.error_occurred.emit(f"PMCOfferCancel rejected: {msgs[0]}")
                return None
            return tx.to_dict()
        except Exception as exc:
            self.error_occurred.emit(f"PMCOfferCancel failed: {exc}")
            return None

    def pmc_list_coins(self) -> list[dict]:
        """Return all registered PMC coins."""
        mgr = self._primary_node.ledger.pmc_manager
        return [c.to_dict() for c in mgr.list_coins()]

    def pmc_get_coin(self, coin_id: str) -> dict | None:
        """Return details for a single coin."""
        mgr = self._primary_node.ledger.pmc_manager
        c = mgr.get_coin(coin_id)
        return c.to_dict() if c else None

    def pmc_get_portfolio(self, address: str) -> list[dict]:
        """Return all PMC holdings for an address."""
        mgr = self._primary_node.ledger.pmc_manager
        return mgr.get_portfolio(address)

    def pmc_get_order_book(self, coin_id: str, counter: str = "") -> dict:
        """Return the PMC order book for a trading pair."""
        mgr = self._primary_node.ledger.pmc_manager
        return mgr.get_order_book(coin_id, counter)

    def pmc_list_active_offers(self, coin_id: str = "") -> list[dict]:
        """Return active PMC offers (optionally filtered by coin)."""
        mgr = self._primary_node.ledger.pmc_manager
        if coin_id:
            return [o.to_dict() for o in mgr.list_active_offers(coin_id)]
        return [o.to_dict() for o in mgr.list_all_active_offers()]

    def pmc_get_pow_info(self, coin_id: str) -> dict:
        """Return PoW mining info for a coin."""
        mgr = self._primary_node.ledger.pmc_manager
        return mgr.get_pow_info(coin_id)

    # ── Mining Pool (Bitcoin Stratum API) ───────────────────────────────

    def mining_pool_start(
        self,
        host: str = "0.0.0.0",
        port: int = 3333,
        coin_ids: list[str] | None = None,
    ) -> bool:
        """
        Start the built-in Stratum mining server.

        Once running, Bitcoin miners can connect via:
            stratum+tcp://<your-ip>:<port>
        with worker name: ``<wallet_address>.<worker_name>``

        Parameters
        ----------
        host : str
            Interface to bind (default all interfaces).
        port : int
            TCP port (default 3333 — standard Stratum).
        coin_ids : list[str], optional
            Coins to enable for mining.  If empty, registers all mintable coins.
        """
        import asyncio

        if self.mining_node and self.mining_node.is_running:
            self.error_occurred.emit("Mining pool is already running")
            return False

        mgr = self._primary_node.ledger.pmc_manager

        # Create a mint callback that routes through the ledger properly
        def _sync_mint(coin_id: str, miner: str, nonce: int) -> float:
            ok, msg, amount = mgr.mint(coin_id, miner, nonce)
            if ok:
                self.pmc_changed.emit()
                self.mining_pool_changed.emit()
                return amount
            return 0.0

        self.mining_node = MiningNode(mgr, mint_callback=_sync_mint)

        # Register coins
        registered = 0
        if coin_ids:
            for cid in coin_ids:
                if self.mining_node.add_coin(cid):
                    registered += 1
        else:
            # Auto-register all mintable coins
            for coin in mgr.list_coins():
                if coin.has_flag(coin.__class__.flags.__class__(0x0004)):
                    pass  # flag check below
                info = mgr.get_pow_info(coin.coin_id)
                if info.get("mintable"):
                    if self.mining_node.add_coin(coin.coin_id):
                        registered += 1

        if registered == 0:
            self.error_occurred.emit("No minable coins found. Create a coin first.")
            self.mining_node = None
            return False

        # Start the async server in a background thread event loop
        import threading

        def _run_server():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    self.mining_node.start(host=host, port=port)
                )
                loop.run_forever()
            except Exception as exc:
                logger.error("Mining pool error: %s", exc)
            finally:
                loop.close()

        self._mining_thread = threading.Thread(
            target=_run_server, daemon=True, name="mining-pool",
        )
        self._mining_thread.start()

        self._log(
            f"Mining pool started on {host}:{port} | "
            f"{registered} coin(s) registered | "
            f"Connect miners via stratum+tcp://{host}:{port}"
        )
        self.mining_pool_changed.emit()
        return True

    def mining_pool_stop(self) -> None:
        """Stop the mining pool server."""
        import asyncio

        if not self.mining_node or not self.mining_node.is_running:
            return
        # Stop the server from the mining thread's event loop
        try:
            loop = asyncio.new_event_loop()
            loop.run_until_complete(self.mining_node.stop())
            loop.close()
        except Exception as exc:
            logger.warning("Error stopping mining pool: %s", exc)
        self.mining_node = None
        self._log("Mining pool stopped")
        self.mining_pool_changed.emit()

    def mining_pool_add_coin(self, coin_id: str) -> bool:
        """Register an additional coin for mining."""
        if not self.mining_node:
            return False
        ok = self.mining_node.add_coin(coin_id)
        if ok:
            self.mining_pool_changed.emit()
        return ok

    def mining_pool_remove_coin(self, coin_id: str) -> None:
        """Remove a coin from the mining pool."""
        if self.mining_node:
            self.mining_node.remove_coin(coin_id)
            self.mining_pool_changed.emit()

    def mining_pool_get_info(self) -> dict:
        """Return current mining pool server status."""
        if self.mining_node:
            return self.mining_node.get_info()
        return {"running": False}

    def mining_pool_get_stats(self) -> dict:
        """Return pool-wide mining statistics."""
        if self.mining_node:
            return self.mining_node.get_pool_stats()
        return {}

    def mining_pool_get_miners(self) -> list[dict]:
        """Return per-miner statistics."""
        if self.mining_node:
            return self.mining_node.get_miner_stats()
        return []

    def mining_pool_list_coins(self) -> list[dict]:
        """Return info for all coins being mined."""
        if self.mining_node:
            return self.mining_node.list_coins()
        return []

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
