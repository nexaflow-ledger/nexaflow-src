"""
Staking tab — stake NXF tokens and earn interest rewards.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
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
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import make_primary_button, make_stat_card

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


# ── Stake Dialog ────────────────────────────────────────────────────────

class _StakeDialog(QDialog):
    """Dialog for creating a new stake."""

    def __init__(
        self,
        wallets: list[dict],
        tiers: list[dict],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Stake NXF")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)

        form = QFormLayout()

        # Wallet selector
        self.wallet_combo = QComboBox()
        for w in wallets:
            name = w.get("name", "")
            addr = w["address"]
            bal = w.get("balance", 0.0)
            self.wallet_combo.addItem(
                f"{name}  ({addr[:12]}…)  —  {bal:,.2f} NXF", addr
            )
        form.addRow("Wallet:", self.wallet_combo)

        # Amount
        self.amount_edit = QLineEdit()
        self.amount_edit.setPlaceholderText("Amount to stake (NXF)")
        form.addRow("Amount:", self.amount_edit)

        # Tier selector
        self.tier_combo = QComboBox()
        for t in tiers:
            self.tier_combo.addItem(
                f"{t['name']}  —  {t['apy_pct']} APY"
                + (f"  ({t['lock_days']}d lock)" if t["lock_days"] > 0 else "  (no lock)"),
                t["tier"],
            )
        form.addRow("Lock Period:", self.tier_combo)

        lay.addLayout(form)

        # Info label
        self._info = QLabel("")
        self._info.setWordWrap(True)
        self._info.setStyleSheet("color: #8b949e; font-size: 12px; margin-top: 8px;")
        lay.addWidget(self._info)

        self.tier_combo.currentIndexChanged.connect(self._update_info)
        self.amount_edit.textChanged.connect(self._update_info)
        self._update_info()

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _update_info(self) -> None:
        try:
            amount = float(self.amount_edit.text())
        except ValueError:
            amount = 0.0
        idx = self.tier_combo.currentIndex()
        tier_data = self.tier_combo.itemData(idx)
        # Rough estimate
        from nexaflow_core.staking import TIER_CONFIG, StakeTier

        _dur, apy = TIER_CONFIG.get(StakeTier(tier_data), (0, 0.0))
        yearly = amount * apy
        monthly = yearly / 12
        self._info.setText(
            f"Estimated rewards: ~{monthly:,.4f} NXF/month  |  ~{yearly:,.4f} NXF/year"
        )

    def get_values(self) -> tuple[str, float, int]:
        addr = self.wallet_combo.currentData()
        amount = float(self.amount_edit.text() or "0")
        tier = self.tier_combo.currentData()
        return addr, amount, tier


# ── Staking Tab ─────────────────────────────────────────────────────────

class StakingTab(QWidget):
    def __init__(self, backend: NodeBackend, parent: QWidget | None = None):
        super().__init__(parent)
        self.backend = backend
        self._build_ui()
        self._connect_signals()

        # Auto-refresh interest display every 10s
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(10_000)
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh_timer.start()

    # ── UI ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(16)

        # Title
        header = QHBoxLayout()
        title = QLabel("Staking & Interest")
        title.setProperty("class", "heading")
        title.setStyleSheet("font-size: 22px;")
        header.addWidget(title)
        header.addStretch()
        root.addLayout(header)

        # ── Stats row ──────────────────────────────────────────────────
        stats = QHBoxLayout()
        stats.setSpacing(12)

        card, self._lbl_total_staked = make_stat_card("Total Staked (NXF)")
        stats.addWidget(card)
        card, self._lbl_active_stakes = make_stat_card("Active Stakes")
        stats.addWidget(card)
        card, self._lbl_pending_interest = make_stat_card("Pending Interest")
        stats.addWidget(card)
        card, self._lbl_total_paid = make_stat_card("Interest Paid")
        stats.addWidget(card)

        root.addLayout(stats)

        # ── Tier info ──────────────────────────────────────────────────
        tier_box = QGroupBox("Available Staking Tiers")
        tier_lay = QHBoxLayout(tier_box)
        tier_lay.setSpacing(12)

        tier_data = [
            ("Flexible", "2.0%", "No lock"),
            ("30 Days", "5.0%", "30-day lock"),
            ("90 Days", "8.0%", "90-day lock"),
            ("180 Days", "12.0%", "180-day lock"),
            ("365 Days", "15.0%", "365-day lock"),
        ]
        for name, apy, lock in tier_data:
            card = QLabel(
                f"<div style='text-align:center;'>"
                f"<b style='color:#39d2c0;font-size:16px;'>{apy}</b><br>"
                f"<span style='font-size:13px;'>{name}</span><br>"
                f"<span style='color:#8b949e;font-size:11px;'>{lock}</span>"
                f"</div>"
            )
            card.setAlignment(Qt.AlignmentFlag.AlignCenter)
            card.setStyleSheet(
                "background: #1c2128; border: 1px solid #30363d; "
                "border-radius: 8px; padding: 14px 8px;"
            )
            tier_lay.addWidget(card)

        root.addWidget(tier_box)

        # ── Actions + Stakes table ─────────────────────────────────────
        mid = QHBoxLayout()
        mid.setSpacing(16)

        # Actions
        act_box = QGroupBox("Actions")
        act_lay = QVBoxLayout(act_box)

        self._btn_stake = make_primary_button("🔒  Stake NXF")
        act_lay.addWidget(self._btn_stake)

        self._btn_unstake = QPushButton("🔓  Unstake Selected")
        self._btn_unstake.setMinimumHeight(36)
        act_lay.addWidget(self._btn_unstake)

        self._btn_collect = QPushButton("💰  Collect Interest")
        self._btn_collect.setMinimumHeight(36)
        act_lay.addWidget(self._btn_collect)

        self._btn_refresh = QPushButton("🔄  Refresh")
        self._btn_refresh.setMinimumHeight(36)
        act_lay.addWidget(self._btn_refresh)

        act_lay.addStretch()
        mid.addWidget(act_box, 1)

        # Stakes table
        tbl_box = QGroupBox("Your Stakes")
        tbl_lay = QVBoxLayout(tbl_box)

        self._table = QTableWidget()
        self._table.setColumnCount(8)
        self._table.setHorizontalHeaderLabels([
            "Stake ID", "Wallet", "Amount", "Tier",
            "APY", "Interest", "Status", "Unlocks",
        ])
        self._table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        self._table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        tbl_lay.addWidget(self._table)

        mid.addWidget(tbl_box, 3)
        root.addLayout(mid, 1)

    # ── Signals ─────────────────────────────────────────────────────────

    def _connect_signals(self) -> None:
        self._btn_stake.clicked.connect(self._on_stake)
        self._btn_unstake.clicked.connect(self._on_unstake)
        self._btn_collect.clicked.connect(self._on_collect)
        self._btn_refresh.clicked.connect(self._refresh)
        self.backend.staking_changed.connect(self._refresh)
        self.backend.accounts_changed.connect(self._refresh)

    # ── Handlers ────────────────────────────────────────────────────────

    def _on_stake(self) -> None:
        wallets = self.backend.get_wallets()
        if not wallets:
            QMessageBox.warning(self, "No Wallets", "Create a wallet first.")
            return
        tiers = self.backend.get_staking_tiers()
        dlg = _StakeDialog(wallets, tiers, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        addr, amount, tier = dlg.get_values()
        if amount <= 0:
            QMessageBox.warning(self, "Invalid", "Enter a positive amount.")
            return
        self.backend.stake_nxf(addr, amount, tier)

    def _on_unstake(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Select", "Select a stake to unstake.")
            return
        stake_id = self._table.item(row, 0).text()
        status = self._table.item(row, 6).text()
        if "Locked" in status:
            QMessageBox.warning(
                self, "Locked",
                "This stake is still locked. Wait until the unlock time."
            )
            return
        self.backend.unstake_nxf(stake_id)

    def _on_collect(self) -> None:
        row = self._table.currentRow()
        if row < 0:
            QMessageBox.information(
                self, "Select", "Select a Flexible stake to collect interest."
            )
            return
        stake_id = self._table.item(row, 0).text()
        self.backend.collect_staking_interest(stake_id)

    # ── Refresh ─────────────────────────────────────────────────────────

    def _refresh(self) -> None:
        pool = self.backend.get_staking_pool_summary()

        self._lbl_total_staked.setText(f"{pool.get('total_staked', 0):,.2f}")
        self._lbl_active_stakes.setText(str(pool.get("active_stakes", 0)))
        self._lbl_pending_interest.setText(
            f"{pool.get('total_pending_interest', 0):,.4f}"
        )
        self._lbl_total_paid.setText(
            f"{pool.get('total_interest_paid', 0):,.4f}"
        )

        # Populate table with all active stakes from tracked wallets
        stakes = self.backend.get_all_active_stakes()
        self._table.setRowCount(len(stakes))

        for i, s in enumerate(stakes):
            self._table.setItem(i, 0, QTableWidgetItem(s["stake_id"]))

            addr = s["address"]
            name = self.backend.wallet_names.get(addr, addr[:12])
            self._table.setItem(i, 1, QTableWidgetItem(name))

            self._table.setItem(
                i, 2, QTableWidgetItem(f"{s['amount']:,.2f}")
            )
            self._table.setItem(i, 3, QTableWidgetItem(s["tier_name"]))
            self._table.setItem(i, 4, QTableWidgetItem(s["apy_pct"]))
            self._table.setItem(
                i, 5, QTableWidgetItem(f"{s['total_interest']:,.4f}")
            )

            if not s["is_active"]:
                status_text = "Closed"
            elif s["is_unlocked"]:
                status_text = "Unlocked"
            else:
                status_text = "Locked"
            self._table.setItem(i, 6, QTableWidgetItem(status_text))

            if s["unlock_time"] > 0:
                unlock_str = datetime.fromtimestamp(
                    s["unlock_time"]
                ).strftime("%Y-%m-%d %H:%M")
            else:
                unlock_str = "—"
            self._table.setItem(i, 7, QTableWidgetItem(unlock_str))
