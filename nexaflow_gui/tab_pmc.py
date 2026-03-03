"""
Programmable Micro Coin (PMC) tab — create, mine, trade, and manage
programmable tokens on the NexaFlow network.

Sections:
  1. My Coins / Portfolio — overview of coins created and held
  2. Create Coin — form to define a new PMC
  3. Mine — PoW mining interface
  4. Transfer / Burn
  5. Cross-Trade DEX — order book, post offers, accept offers
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import make_primary_button, make_stat_card

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


# ═══════════════════════════════════════════════════════════════════════
#  Dialogs
# ═══════════════════════════════════════════════════════════════════════

class _CreateCoinDialog(QDialog):
    """Dialog for creating a new Programmable Micro Coin."""

    def __init__(self, wallets: list[dict], parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Create Programmable Micro Coin")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        form = QFormLayout()

        # Wallet selector
        self.wallet_combo = QComboBox()
        for w in wallets:
            name = w.get("name", "")
            addr = w["address"]
            bal = w.get("balance", 0.0)
            self.wallet_combo.addItem(
                f"{name}  ({addr[:12]}…)  —  {bal:,.8f} NXF", addr
            )
        form.addRow("Issuer Wallet:", self.wallet_combo)

        # Symbol
        self.symbol_edit = QLineEdit()
        self.symbol_edit.setPlaceholderText("TICKER (3–12 chars, e.g. ZETA)")
        self.symbol_edit.setMaxLength(12)
        form.addRow("Symbol:", self.symbol_edit)

        # Name
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Coin name (e.g. Zeta Coin)")
        form.addRow("Name:", self.name_edit)

        # Max Supply
        self.supply_edit = QLineEdit()
        self.supply_edit.setPlaceholderText("0 = unlimited")
        form.addRow("Max Supply:", self.supply_edit)

        # PoW Difficulty
        self.diff_edit = QLineEdit("4")
        self.diff_edit.setPlaceholderText("1–32 (leading hex zeros)")
        form.addRow("PoW Difficulty:", self.diff_edit)

        # Decimals
        self.decimals_edit = QLineEdit("8")
        form.addRow("Decimals:", self.decimals_edit)

        # Flags
        self.chk_transferable = QCheckBox("Transferable")
        self.chk_transferable.setChecked(True)
        self.chk_burnable = QCheckBox("Burnable")
        self.chk_burnable.setChecked(True)
        self.chk_mintable = QCheckBox("PoW Mintable")
        self.chk_mintable.setChecked(True)
        self.chk_tradeable = QCheckBox("Cross-Tradeable")
        self.chk_tradeable.setChecked(True)
        self.chk_freezable = QCheckBox("Freezable")
        flags_lay = QHBoxLayout()
        for cb in (self.chk_transferable, self.chk_burnable,
                   self.chk_mintable, self.chk_tradeable, self.chk_freezable):
            flags_lay.addWidget(cb)
        form.addRow("Flags:", flags_lay)

        # Metadata
        self.metadata_edit = QLineEdit()
        self.metadata_edit.setPlaceholderText("Optional JSON or URI")
        form.addRow("Metadata:", self.metadata_edit)

        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def get_flags(self) -> int:
        f = 0
        if self.chk_transferable.isChecked():
            f |= 0x0001
        if self.chk_burnable.isChecked():
            f |= 0x0002
        if self.chk_mintable.isChecked():
            f |= 0x0004
        if self.chk_freezable.isChecked():
            f |= 0x0008
        if self.chk_tradeable.isChecked():
            f |= 0x0040
        return f


class _TransferDialog(QDialog):
    """Dialog for transferring PMC tokens."""

    def __init__(
        self,
        wallets: list[dict],
        coins: list[dict],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Transfer Micro Coin")
        self.setMinimumWidth(480)
        lay = QVBoxLayout(self)
        form = QFormLayout()

        self.wallet_combo = QComboBox()
        for w in wallets:
            addr = w["address"]
            name = w.get("name", "")
            self.wallet_combo.addItem(f"{name}  ({addr[:12]}…)", addr)
        form.addRow("From:", self.wallet_combo)

        self.coin_combo = QComboBox()
        for c in coins:
            self.coin_combo.addItem(
                f"{c['symbol']} — {c['name']}", c["coin_id"]
            )
        form.addRow("Coin:", self.coin_combo)

        self.dest_edit = QLineEdit()
        self.dest_edit.setPlaceholderText("Destination address")
        form.addRow("To:", self.dest_edit)

        self.amount_edit = QLineEdit()
        self.amount_edit.setPlaceholderText("Amount")
        form.addRow("Amount:", self.amount_edit)

        self.memo_edit = QLineEdit()
        self.memo_edit.setPlaceholderText("Optional memo")
        form.addRow("Memo:", self.memo_edit)

        lay.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


class _TradeDialog(QDialog):
    """Dialog for creating a PMC DEX offer."""

    def __init__(
        self,
        wallets: list[dict],
        coins: list[dict],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Create Trade Offer")
        self.setMinimumWidth(500)
        lay = QVBoxLayout(self)
        form = QFormLayout()

        self.wallet_combo = QComboBox()
        for w in wallets:
            addr = w["address"]
            name = w.get("name", "")
            bal = w.get("balance", 0.0)
            self.wallet_combo.addItem(
                f"{name}  ({addr[:12]}…)  —  {bal:,.8f} NXF", addr
            )
        form.addRow("Wallet:", self.wallet_combo)

        self.coin_combo = QComboBox()
        for c in coins:
            self.coin_combo.addItem(
                f"{c['symbol']} — {c['name']}", c["coin_id"]
            )
        form.addRow("Coin:", self.coin_combo)

        self.side_combo = QComboBox()
        self.side_combo.addItem("Sell", True)
        self.side_combo.addItem("Buy", False)
        form.addRow("Side:", self.side_combo)

        self.amount_edit = QLineEdit()
        self.amount_edit.setPlaceholderText("Quantity of coin")
        form.addRow("Amount:", self.amount_edit)

        self.price_edit = QLineEdit()
        self.price_edit.setPlaceholderText("Price per unit (NXF)")
        form.addRow("Price (NXF):", self.price_edit)

        # Counter coin (optional PMC-to-PMC)
        self.counter_combo = QComboBox()
        self.counter_combo.addItem("NXF (native)", "")
        for c in coins:
            self.counter_combo.addItem(
                f"{c['symbol']}", c["coin_id"]
            )
        form.addRow("Pay with:", self.counter_combo)

        lay.addLayout(form)

        info = QLabel(
            "Sell: you sell the coin and receive NXF (or counter coin).\n"
            "Buy: you pay NXF (or counter coin) to buy the coin."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #8b949e; font-size: 11px; margin-top: 6px;")
        lay.addWidget(info)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


# ═══════════════════════════════════════════════════════════════════════
#  Main PMC Tab
# ═══════════════════════════════════════════════════════════════════════

class PMCTab(QWidget):
    """Programmable Micro Coin management and trading interface."""

    def __init__(self, backend: "NodeBackend", parent: QWidget | None = None):
        super().__init__(parent)
        self.backend = backend
        self._build_ui()
        self._connect_signals()

        # Refresh every 3 seconds
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(3000)

    # ── UI construction ─────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 12)
        root.setSpacing(12)

        # ── Header / stats ──
        header = QLabel("Programmable Micro Coins")
        header.setProperty("class", "heading")
        root.addWidget(header)

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        card, self._lbl_total_coins = make_stat_card("Total Coins")
        stats_row.addWidget(card)
        card, self._lbl_my_holdings = make_stat_card("My Holdings")
        stats_row.addWidget(card)
        card, self._lbl_active_offers = make_stat_card("Active Offers")
        stats_row.addWidget(card)
        card, self._lbl_dex_volume = make_stat_card("DEX Pairs")
        stats_row.addWidget(card)

        root.addLayout(stats_row)

        # ── Action buttons ──
        btn_row = QHBoxLayout()
        self.btn_create = make_primary_button("✦ Create Coin")
        self.btn_transfer = make_primary_button("↗ Transfer")
        self.btn_burn = make_primary_button("🔥 Burn")
        self.btn_trade = make_primary_button("⇄ Trade")
        self.btn_refresh = make_primary_button("↻ Refresh")

        for btn in (self.btn_create, self.btn_transfer, self.btn_burn,
                    self.btn_trade, self.btn_refresh):
            btn_row.addWidget(btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Sub-tabs ──
        self.sub_tabs = QTabWidget()
        self.sub_tabs.setDocumentMode(True)

        # Sub-tab 1: All Coins
        self.coins_table = self._make_table(
            ["Symbol", "Name", "Issuer", "Supply", "Minted",
             "Burned", "PoW Diff", "Flags", "Coin ID"]
        )
        self.sub_tabs.addTab(self.coins_table, "All Coins")

        # Sub-tab 2: My Portfolio
        self.portfolio_table = self._make_table(
            ["Symbol", "Name", "Balance", "Frozen", "Coin ID"]
        )
        self.sub_tabs.addTab(self.portfolio_table, "My Portfolio")

        # Sub-tab 3: DEX / Order Book
        dex_widget = QWidget()
        dex_lay = QVBoxLayout(dex_widget)
        dex_lay.setContentsMargins(0, 6, 0, 0)

        # Pair selector
        pair_row = QHBoxLayout()
        pair_row.addWidget(QLabel("Coin:"))
        self.dex_coin_combo = QComboBox()
        self.dex_coin_combo.setMinimumWidth(200)
        pair_row.addWidget(self.dex_coin_combo)
        pair_row.addWidget(QLabel("vs"))
        self.dex_counter_combo = QComboBox()
        self.dex_counter_combo.addItem("NXF", "")
        self.dex_counter_combo.setMinimumWidth(150)
        pair_row.addWidget(self.dex_counter_combo)
        self.btn_load_book = make_primary_button("Load Book")
        pair_row.addWidget(self.btn_load_book)
        pair_row.addStretch()
        dex_lay.addLayout(pair_row)

        # Bids / asks splitter
        book_splitter = QSplitter(Qt.Orientation.Horizontal)
        # Bids (buy orders)
        bid_box = QGroupBox("Bids (Buy Orders)")
        bid_box.setStyleSheet(
            "QGroupBox { color: #3fb950; font-weight: 700; border: 1px solid #238636; "
            "border-radius: 6px; margin-top: 8px; padding-top: 14px; }"
        )
        bid_lay = QVBoxLayout(bid_box)
        self.bids_table = self._make_table(["Price (NXF)", "Amount"])
        bid_lay.addWidget(self.bids_table)
        book_splitter.addWidget(bid_box)

        # Asks (sell orders)
        ask_box = QGroupBox("Asks (Sell Orders)")
        ask_box.setStyleSheet(
            "QGroupBox { color: #f85149; font-weight: 700; border: 1px solid #da3633; "
            "border-radius: 6px; margin-top: 8px; padding-top: 14px; }"
        )
        ask_lay = QVBoxLayout(ask_box)
        self.asks_table = self._make_table(["Price (NXF)", "Amount"])
        ask_lay.addWidget(self.asks_table)
        book_splitter.addWidget(ask_box)

        dex_lay.addWidget(book_splitter, 1)

        # Active offers (my offers + all)
        self.offers_table = self._make_table(
            ["Offer ID", "Coin", "Side", "Amount", "Price",
             "Remaining", "Owner", "Status"]
        )
        offers_box = QGroupBox("Active Offers")
        offers_lay = QVBoxLayout(offers_box)
        offers_action_row = QHBoxLayout()
        self.btn_accept_offer = make_primary_button("Accept Selected")
        self.btn_cancel_offer = make_primary_button("Cancel Selected")
        offers_action_row.addWidget(self.btn_accept_offer)
        offers_action_row.addWidget(self.btn_cancel_offer)
        offers_action_row.addStretch()
        offers_lay.addLayout(offers_action_row)
        offers_lay.addWidget(self.offers_table)
        dex_lay.addWidget(offers_box)

        self.sub_tabs.addTab(dex_widget, "Cross-Trade DEX")

        # Sub-tab 4: PoW Mining
        mine_widget = QWidget()
        mine_lay = QVBoxLayout(mine_widget)
        mine_lay.setContentsMargins(0, 6, 0, 0)

        mine_form = QFormLayout()
        self.mine_wallet_combo = QComboBox()
        mine_form.addRow("Miner Wallet:", self.mine_wallet_combo)
        self.mine_coin_combo = QComboBox()
        mine_form.addRow("Coin:", self.mine_coin_combo)
        self.mine_amount_edit = QLineEdit("1.0")
        self.mine_amount_edit.setPlaceholderText("Tokens to mint per solve")
        mine_form.addRow("Mint Amount:", self.mine_amount_edit)

        mine_lay.addLayout(mine_form)

        # PoW info
        self.mine_info = QLabel("Select a coin to see mining info.")
        self.mine_info.setWordWrap(True)
        self.mine_info.setStyleSheet("color: #8b949e; font-size: 12px; margin: 8px 0;")
        mine_lay.addWidget(self.mine_info)

        mine_btn_row = QHBoxLayout()
        self.btn_mine = make_primary_button("⛏ Mine (find nonce)")
        mine_btn_row.addWidget(self.btn_mine)
        mine_btn_row.addStretch()
        mine_lay.addLayout(mine_btn_row)

        self.mine_log = QTextEdit()
        self.mine_log.setReadOnly(True)
        self.mine_log.setMaximumHeight(200)
        self.mine_log.setStyleSheet(
            "background: #0d1117; color: #c9d1d9; font-family: monospace; "
            "font-size: 11px; border: 1px solid #30363d; border-radius: 4px;"
        )
        mine_lay.addWidget(self.mine_log)
        mine_lay.addStretch()

        self.sub_tabs.addTab(mine_widget, "PoW Mining")

        root.addWidget(self.sub_tabs, 1)

    # ── Signals ─────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self.btn_create.clicked.connect(self._on_create)
        self.btn_transfer.clicked.connect(self._on_transfer)
        self.btn_burn.clicked.connect(self._on_burn)
        self.btn_trade.clicked.connect(self._on_trade)
        self.btn_refresh.clicked.connect(self._refresh)
        self.btn_load_book.clicked.connect(self._load_order_book)
        self.btn_mine.clicked.connect(self._on_mine)
        self.btn_accept_offer.clicked.connect(self._on_accept_offer)
        self.btn_cancel_offer.clicked.connect(self._on_cancel_offer)
        self.mine_coin_combo.currentIndexChanged.connect(self._update_mine_info)
        self.backend.pmc_changed.connect(self._refresh)
        self.backend.accounts_changed.connect(self._refresh_combos)

    # ── Refresh helpers ─────────────────────────────────────────────

    def _refresh(self) -> None:
        self._refresh_coins_table()
        self._refresh_portfolio()
        self._refresh_offers()
        self._refresh_combos()
        self._refresh_stats()

    def _refresh_stats(self) -> None:
        coins = self.backend.pmc_list_coins()
        self._lbl_total_coins.setText(str(len(coins)))

        total_holdings = 0
        for addr in self.backend.wallets:
            p = self.backend.pmc_get_portfolio(addr)
            total_holdings += len(p)
        self._lbl_my_holdings.setText(str(total_holdings))

        offers = self.backend.pmc_list_active_offers()
        self._lbl_active_offers.setText(str(len(offers)))

        # Count unique coin_ids that have offers
        pairs = set()
        for o in offers:
            pairs.add(o.get("coin_id", ""))
        self._lbl_dex_volume.setText(str(len(pairs)))

    def _refresh_coins_table(self) -> None:
        coins = self.backend.pmc_list_coins()
        t = self.coins_table
        t.setRowCount(len(coins))
        for i, c in enumerate(coins):
            t.setItem(i, 0, QTableWidgetItem(c.get("symbol", "")))
            t.setItem(i, 1, QTableWidgetItem(c.get("name", "")))
            t.setItem(i, 2, QTableWidgetItem(c.get("issuer", "")[:16] + "…"))
            sup = c.get("max_supply", 0)
            t.setItem(i, 3, QTableWidgetItem(
                f"{sup:,.{c.get('decimals', 8)}f}" if sup > 0 else "Unlimited"
            ))
            t.setItem(i, 4, QTableWidgetItem(f"{c.get('total_minted', 0):,.8f}"))
            t.setItem(i, 5, QTableWidgetItem(f"{c.get('total_burned', 0):,.8f}"))
            t.setItem(i, 6, QTableWidgetItem(str(c.get("pow_difficulty", "?"))))
            flag_names = c.get("flag_names", [])
            t.setItem(i, 7, QTableWidgetItem(", ".join(flag_names)))
            t.setItem(i, 8, QTableWidgetItem(c.get("coin_id", "")[:20] + "…"))

    def _refresh_portfolio(self) -> None:
        rows = []
        for addr in self.backend.wallets:
            for h in self.backend.pmc_get_portfolio(addr):
                rows.append(h)
        t = self.portfolio_table
        t.setRowCount(len(rows))
        for i, h in enumerate(rows):
            t.setItem(i, 0, QTableWidgetItem(h.get("symbol", "")))
            t.setItem(i, 1, QTableWidgetItem(h.get("name", "")))
            t.setItem(i, 2, QTableWidgetItem(f"{h.get('balance', 0):,.8f}"))
            t.setItem(i, 3, QTableWidgetItem("Yes" if h.get("frozen") else "No"))
            t.setItem(i, 4, QTableWidgetItem(h.get("coin_id", "")[:20] + "…"))

    def _refresh_offers(self) -> None:
        offers = self.backend.pmc_list_active_offers()
        t = self.offers_table
        t.setRowCount(len(offers))
        coins_cache: dict[str, dict] = {}
        for i, o in enumerate(offers):
            cid = o.get("coin_id", "")
            if cid not in coins_cache:
                info = self.backend.pmc_get_coin(cid)
                coins_cache[cid] = info or {}
            sym = coins_cache[cid].get("symbol", cid[:8])
            t.setItem(i, 0, QTableWidgetItem(o.get("offer_id", "")[:16] + "…"))
            t.setItem(i, 1, QTableWidgetItem(sym))
            t.setItem(i, 2, QTableWidgetItem("SELL" if o.get("is_sell") else "BUY"))
            t.setItem(i, 3, QTableWidgetItem(f"{o.get('amount', 0):,.8f}"))
            t.setItem(i, 4, QTableWidgetItem(f"{o.get('price', 0):,.8f}"))
            t.setItem(i, 5, QTableWidgetItem(f"{o.get('remaining', 0):,.8f}"))
            t.setItem(i, 6, QTableWidgetItem(o.get("owner", "")[:16] + "…"))
            t.setItem(i, 7, QTableWidgetItem(
                "Active" if o.get("is_active") else "Inactive"
            ))

    def _refresh_combos(self) -> None:
        """Refresh all wallet/coin combo boxes."""
        coins = self.backend.pmc_list_coins()
        wallets = self._wallet_list()

        # DEX coin combos
        self.dex_coin_combo.blockSignals(True)
        prev_dex = self.dex_coin_combo.currentData()
        self.dex_coin_combo.clear()
        for c in coins:
            self.dex_coin_combo.addItem(c["symbol"], c["coin_id"])
        if prev_dex:
            idx = self.dex_coin_combo.findData(prev_dex)
            if idx >= 0:
                self.dex_coin_combo.setCurrentIndex(idx)
        self.dex_coin_combo.blockSignals(False)

        # Counter coin combo
        self.dex_counter_combo.blockSignals(True)
        prev_counter = self.dex_counter_combo.currentData()
        self.dex_counter_combo.clear()
        self.dex_counter_combo.addItem("NXF", "")
        for c in coins:
            self.dex_counter_combo.addItem(c["symbol"], c["coin_id"])
        if prev_counter:
            idx = self.dex_counter_combo.findData(prev_counter)
            if idx >= 0:
                self.dex_counter_combo.setCurrentIndex(idx)
        self.dex_counter_combo.blockSignals(False)

        # Mine wallet combo
        self.mine_wallet_combo.blockSignals(True)
        prev_mw = self.mine_wallet_combo.currentData()
        self.mine_wallet_combo.clear()
        for w in wallets:
            addr = w["address"]
            name = w.get("name", "")
            self.mine_wallet_combo.addItem(f"{name}  ({addr[:12]}…)", addr)
        if prev_mw:
            idx = self.mine_wallet_combo.findData(prev_mw)
            if idx >= 0:
                self.mine_wallet_combo.setCurrentIndex(idx)
        self.mine_wallet_combo.blockSignals(False)

        # Mine coin combo
        self.mine_coin_combo.blockSignals(True)
        prev_mc = self.mine_coin_combo.currentData()
        self.mine_coin_combo.clear()
        for c in coins:
            self.mine_coin_combo.addItem(f"{c['symbol']} — {c['name']}", c["coin_id"])
        if prev_mc:
            idx = self.mine_coin_combo.findData(prev_mc)
            if idx >= 0:
                self.mine_coin_combo.setCurrentIndex(idx)
        self.mine_coin_combo.blockSignals(False)

    # ── Wallet helper ───────────────────────────────────────────────

    def _wallet_list(self) -> list[dict]:
        result = []
        for addr, wal in self.backend.wallets.items():
            bal = self.backend.get_balance(addr) if hasattr(self.backend, 'get_balance') else 0.0
            result.append({
                "address": addr,
                "name": self.backend.wallet_names.get(addr, ""),
                "balance": bal,
            })
        return result

    # ── Actions ─────────────────────────────────────────────────────

    def _on_create(self) -> None:
        wallets = self._wallet_list()
        if not wallets:
            QMessageBox.warning(self, "No Wallets", "Create a wallet first.")
            return
        dlg = _CreateCoinDialog(wallets, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        addr = dlg.wallet_combo.currentData()
        symbol = dlg.symbol_edit.text().strip().upper()
        name = dlg.name_edit.text().strip()
        try:
            max_supply = float(dlg.supply_edit.text() or "0")
        except ValueError:
            QMessageBox.warning(self, "Invalid", "Max supply must be a number.")
            return
        try:
            diff = int(dlg.diff_edit.text() or "4")
        except ValueError:
            diff = 4
        try:
            decimals = int(dlg.decimals_edit.text() or "8")
        except ValueError:
            decimals = 8
        flags = dlg.get_flags()
        metadata = dlg.metadata_edit.text().strip()

        result = self.backend.pmc_create_coin(
            address=addr, symbol=symbol, name=name,
            max_supply=max_supply, decimals=decimals,
            pow_difficulty=diff, pmc_flags=flags,
            metadata=metadata,
        )
        if result:
            QMessageBox.information(
                self, "Coin Created",
                f"✦ {symbol} created successfully!\n\nCoin ID: {result.get('tx_id', '?')[:24]}…"
            )
            self._refresh()

    def _on_transfer(self) -> None:
        wallets = self._wallet_list()
        coins = self.backend.pmc_list_coins()
        if not wallets:
            QMessageBox.warning(self, "No Wallets", "Create a wallet first.")
            return
        if not coins:
            QMessageBox.warning(self, "No Coins", "Create a coin first.")
            return
        dlg = _TransferDialog(wallets, coins, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        addr = dlg.wallet_combo.currentData()
        coin_id = dlg.coin_combo.currentData()
        dest = dlg.dest_edit.text().strip()
        memo = dlg.memo_edit.text().strip()
        try:
            amount = float(dlg.amount_edit.text())
        except ValueError:
            QMessageBox.warning(self, "Invalid", "Amount must be a number.")
            return
        result = self.backend.pmc_transfer(
            address=addr, destination=dest, coin_id=coin_id,
            amount=amount, memo=memo,
        )
        if result:
            QMessageBox.information(self, "Transferred", "Transfer successful!")
            self._refresh()

    def _on_burn(self) -> None:
        wallets = self._wallet_list()
        coins = self.backend.pmc_list_coins()
        if not wallets or not coins:
            QMessageBox.warning(self, "Missing", "Need wallet + coins.")
            return
        # Simple burn dialog
        dlg = QDialog(self)
        dlg.setWindowTitle("Burn Micro Coin")
        dlg.setMinimumWidth(400)
        lay = QVBoxLayout(dlg)
        form = QFormLayout()
        w_combo = QComboBox()
        for w in wallets:
            addr = w["address"]
            w_combo.addItem(f"{w.get('name', '')}  ({addr[:12]}…)", addr)
        form.addRow("Wallet:", w_combo)
        c_combo = QComboBox()
        for c in coins:
            c_combo.addItem(f"{c['symbol']}", c["coin_id"])
        form.addRow("Coin:", c_combo)
        amt_edit = QLineEdit()
        amt_edit.setPlaceholderText("Amount to burn")
        form.addRow("Amount:", amt_edit)
        lay.addLayout(form)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            amount = float(amt_edit.text())
        except ValueError:
            return
        result = self.backend.pmc_burn(
            address=w_combo.currentData(),
            coin_id=c_combo.currentData(),
            amount=amount,
        )
        if result:
            QMessageBox.information(self, "Burned", "Tokens burned!")
            self._refresh()

    def _on_trade(self) -> None:
        wallets = self._wallet_list()
        coins = self.backend.pmc_list_coins()
        if not wallets:
            QMessageBox.warning(self, "No Wallets", "Create a wallet first.")
            return
        if not coins:
            QMessageBox.warning(self, "No Coins", "Create a coin first.")
            return
        dlg = _TradeDialog(wallets, coins, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        addr = dlg.wallet_combo.currentData()
        coin_id = dlg.coin_combo.currentData()
        is_sell = dlg.side_combo.currentData()
        counter = dlg.counter_combo.currentData()
        try:
            amount = float(dlg.amount_edit.text())
            price = float(dlg.price_edit.text())
        except ValueError:
            QMessageBox.warning(self, "Invalid", "Amount/price must be numbers.")
            return
        result = self.backend.pmc_offer_create(
            address=addr, coin_id=coin_id, is_sell=is_sell,
            amount=amount, price=price, counter_coin_id=counter,
        )
        if result:
            QMessageBox.information(self, "Offer Posted", "Trade offer created!")
            self._refresh()

    def _on_accept_offer(self) -> None:
        row = self.offers_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Offer", "Select an offer to accept.")
            return
        offer_id_text = self.offers_table.item(row, 0).text().rstrip("…")
        # Find full offer id
        offers = self.backend.pmc_list_active_offers()
        full_id = ""
        for o in offers:
            if o["offer_id"].startswith(offer_id_text):
                full_id = o["offer_id"]
                break
        if not full_id:
            QMessageBox.warning(self, "Not Found", "Could not find that offer.")
            return
        # Pick wallet
        wallets = self._wallet_list()
        if not wallets:
            return
        # Quick wallet picker
        dlg = QDialog(self)
        dlg.setWindowTitle("Accept Offer")
        dlg.setMinimumWidth(380)
        lay = QVBoxLayout(dlg)
        form = QFormLayout()
        w_combo = QComboBox()
        for w in wallets:
            addr = w["address"]
            w_combo.addItem(f"{w.get('name', '')}  ({addr[:12]}…)", addr)
        form.addRow("Your Wallet:", w_combo)
        fill_edit = QLineEdit()
        fill_edit.setPlaceholderText("Leave empty to fill entire offer")
        form.addRow("Fill Amount:", fill_edit)
        lay.addLayout(form)
        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(dlg.accept)
        btns.rejected.connect(dlg.reject)
        lay.addWidget(btns)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        addr = w_combo.currentData()
        fill = 0.0
        if fill_edit.text().strip():
            try:
                fill = float(fill_edit.text())
            except ValueError:
                pass
        result = self.backend.pmc_offer_accept(
            address=addr, offer_id=full_id, fill_amount=fill,
        )
        if result:
            QMessageBox.information(self, "Accepted", "Offer filled!")
            self._refresh()

    def _on_cancel_offer(self) -> None:
        row = self.offers_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "Select Offer", "Select an offer to cancel.")
            return
        offer_id_text = self.offers_table.item(row, 0).text().rstrip("…")
        offers = self.backend.pmc_list_active_offers()
        full_id = ""
        owner = ""
        for o in offers:
            if o["offer_id"].startswith(offer_id_text):
                full_id = o["offer_id"]
                owner = o["owner"]
                break
        if not full_id:
            return
        if owner not in self.backend.wallets:
            QMessageBox.warning(self, "Not Yours", "You can only cancel your own offers.")
            return
        result = self.backend.pmc_offer_cancel(address=owner, offer_id=full_id)
        if result:
            QMessageBox.information(self, "Cancelled", "Offer cancelled.")
            self._refresh()

    def _on_mine(self) -> None:
        """Run PoW mining — brute-force a nonce in a loop."""
        addr = self.mine_wallet_combo.currentData()
        coin_id = self.mine_coin_combo.currentData()
        if not addr or not coin_id:
            QMessageBox.warning(self, "Missing", "Select wallet and coin.")
            return
        try:
            mint_amount = float(self.mine_amount_edit.text() or "1")
        except ValueError:
            mint_amount = 1.0

        # Get PoW info
        pow_info = self.backend.pmc_get_pow_info(coin_id)
        if not pow_info or not pow_info.get("mintable"):
            QMessageBox.warning(self, "Not Mintable", "This coin cannot be mined.")
            return

        difficulty = pow_info["difficulty"]
        prev_hash = pow_info.get("prev_hash", "")
        target = "0" * difficulty

        self.mine_log.append(
            f"⛏ Mining {pow_info['symbol']} | difficulty={difficulty} "
            f"| target={'0'*difficulty}... | est. hashes: {pow_info['estimated_hashes']:,.0f}"
        )

        # Brute-force nonce (limited iterations for GUI responsiveness)
        import hashlib as _hl

        found = False
        nonce = 0
        max_iters = min(10_000_000, int(pow_info["estimated_hashes"] * 4))
        batch = 50_000

        for start in range(0, max_iters, batch):
            for n in range(start, min(start + batch, max_iters)):
                blob = f"{coin_id}:{addr}:{n}:{prev_hash}".encode()
                h = _hl.blake2b(blob, digest_size=32).hexdigest()
                if h[:difficulty] == target:
                    nonce = n
                    found = True
                    break
            if found:
                break
            # Process events to keep UI responsive
            from PyQt6.QtWidgets import QApplication
            QApplication.processEvents()

        if not found:
            self.mine_log.append(
                f"✗ No solution found in {max_iters:,} attempts. Try again."
            )
            return

        self.mine_log.append(f"✓ Found nonce={nonce} — submitting mint transaction…")

        result = self.backend.pmc_mint(
            address=addr, coin_id=coin_id, nonce=nonce, amount=mint_amount,
        )
        if result:
            self.mine_log.append(
                f"✓ Minted {mint_amount} tokens! tx={result.get('tx_id', '?')[:16]}…"
            )
            self._update_mine_info()
            self._refresh()
        else:
            self.mine_log.append("✗ Mint transaction failed.")

    def _update_mine_info(self) -> None:
        coin_id = self.mine_coin_combo.currentData()
        if not coin_id:
            self.mine_info.setText("Select a coin to see mining info.")
            return
        info = self.backend.pmc_get_pow_info(coin_id)
        if not info:
            self.mine_info.setText("Coin not found.")
            return
        remaining = info.get("remaining_supply", "∞")
        if isinstance(remaining, float) and remaining == float("inf"):
            remaining = "∞"
        else:
            remaining = f"{remaining:,.8f}"
        self.mine_info.setText(
            f"<b>{info['symbol']}</b> | "
            f"Difficulty: <b>{info['difficulty']}</b> | "
            f"Est. hashes: <b>{info['estimated_hashes']:,.0f}</b> | "
            f"Minted: <b>{info['total_minted']:,.8f}</b> | "
            f"Remaining: <b>{remaining}</b> | "
            f"Mintable: <b>{'Yes' if info['mintable'] else 'No'}</b>"
        )

    def _load_order_book(self) -> None:
        coin_id = self.dex_coin_combo.currentData()
        counter = self.dex_counter_combo.currentData() or ""
        if not coin_id:
            return
        book = self.backend.pmc_get_order_book(coin_id, counter)
        bids = book.get("bids", [])
        asks = book.get("asks", [])

        self.bids_table.setRowCount(len(bids))
        for i, b in enumerate(bids):
            self.bids_table.setItem(i, 0, QTableWidgetItem(f"{b['price']:,.8f}"))
            self.bids_table.setItem(i, 1, QTableWidgetItem(f"{b['amount']:,.8f}"))

        self.asks_table.setRowCount(len(asks))
        for i, a in enumerate(asks):
            self.asks_table.setItem(i, 0, QTableWidgetItem(f"{a['price']:,.8f}"))
            self.asks_table.setItem(i, 1, QTableWidgetItem(f"{a['amount']:,.8f}"))

    # ── Table factory ───────────────────────────────────────────────

    @staticmethod
    def _make_table(headers: list[str]) -> QTableWidget:
        t = QTableWidget(0, len(headers))
        t.setHorizontalHeaderLabels(headers)
        t.horizontalHeader().setStretchLastSection(True)
        t.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.ResizeToContents
        )
        t.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        t.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        t.verticalHeader().setVisible(False)
        t.setAlternatingRowColors(True)
        return t
