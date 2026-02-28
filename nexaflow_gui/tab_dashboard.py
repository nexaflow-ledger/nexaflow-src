"""
Dashboard tab — overview stats, quick actions, and activity log.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import make_primary_button, make_stat_card

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


class DashboardTab(QWidget):
    def __init__(self, backend: NodeBackend, parent: QWidget | None = None):
        super().__init__(parent)
        self.backend = backend
        self._build_ui()
        self._connect_signals()

    # ── UI construction ─────────────────────────────────────────────────

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(16)

        # Header row
        header = QHBoxLayout()
        title = QLabel("NexaFlow Dashboard")
        title.setProperty("class", "heading")
        title.setStyleSheet("font-size: 22px;")
        header.addWidget(title)
        header.addStretch()

        self._status_indicator = QLabel("● RUNNING")
        self._status_indicator.setStyleSheet(
            "color: #3fb950; font-weight: 700; font-size: 13px;"
        )
        header.addWidget(self._status_indicator)
        root.addLayout(header)

        # ── Stat cards row ──────────────────────────────────────────────
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)

        card, self._lbl_balance = make_stat_card("Total Balance (NXF)")
        stats_row.addWidget(card)
        card, self._lbl_wallets = make_stat_card("Wallets")
        stats_row.addWidget(card)
        card, self._lbl_ledger_seq = make_stat_card("Ledger Sequence")
        stats_row.addWidget(card)
        card, self._lbl_tx_pool = make_stat_card("TX Pool")
        stats_row.addWidget(card)
        card, self._lbl_validators = make_stat_card("Validators")
        stats_row.addWidget(card)

        root.addLayout(stats_row)

        # ── Middle row : Quick Actions + Consensus ──────────────────────
        mid = QHBoxLayout()
        mid.setSpacing(16)

        # Quick actions
        qa_box = QGroupBox("Quick Actions")
        qa_lay = QVBoxLayout(qa_box)

        self._btn_new_wallet = make_primary_button("+ Create Wallet")
        qa_lay.addWidget(self._btn_new_wallet)

        self._btn_consensus = make_primary_button("⚡ Run Consensus")
        qa_lay.addWidget(self._btn_consensus)

        qa_lay.addStretch()
        mid.addWidget(qa_box, 1)

        # Network overview
        net_box = QGroupBox("Network Overview")
        net_lay = QVBoxLayout(net_box)
        self._lbl_net_info = QLabel("Loading…")
        self._lbl_net_info.setWordWrap(True)
        self._lbl_net_info.setStyleSheet("font-size: 13px; line-height: 1.6;")
        net_lay.addWidget(self._lbl_net_info)
        net_lay.addStretch()
        mid.addWidget(net_box, 2)

        root.addLayout(mid)

        # ── Activity Log ────────────────────────────────────────────────
        log_box = QGroupBox("Activity Log")
        log_lay = QVBoxLayout(log_box)
        self._log_view = QPlainTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setMaximumBlockCount(500)
        self._log_view.setMinimumHeight(140)
        log_lay.addWidget(self._log_view)
        root.addWidget(log_box, 1)

    # ── Signal wiring ───────────────────────────────────────────────────

    def _connect_signals(self):
        self.backend.status_updated.connect(self._on_status)
        self.backend.log_message.connect(self._on_log)
        self.backend.error_occurred.connect(self._on_error)
        self.backend.consensus_completed.connect(self._on_consensus)

        self._btn_new_wallet.clicked.connect(self._create_wallet)
        self._btn_consensus.clicked.connect(self._run_consensus)

    # ── Slots ───────────────────────────────────────────────────────────

    def _on_status(self, status: dict):
        total_bal = sum(
            self.backend.get_balance(a) for a in self.backend.wallets
        )
        self._lbl_balance.setText(f"{total_bal:,.8f}")
        self._lbl_wallets.setText(str(status.get("wallet_count", 0)))
        self._lbl_ledger_seq.setText(str(status.get("ledger_sequence", 0)))
        self._lbl_tx_pool.setText(str(status.get("tx_pool", 0)))
        self._lbl_validators.setText(str(status.get("validator_count", 0)))

        # Network info text
        self._lbl_net_info.setText(
            f"Validators: {status.get('validator_count', 0)}\n"
            f"Total Accounts: {status.get('total_accounts', 0)}\n"
            f"Closed Ledgers: {status.get('closed_ledgers', 0)}\n"
            f"Total Supply: {status.get('total_supply', 0):,.0f} NXF\n"
            f"Total Burned: {status.get('total_burned', 0):,.8f} NXF\n"
            f"Total Minted (Interest): {status.get('total_minted', 0):,.8f} NXF"
        )

    def _on_log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_view.appendPlainText(f"[{ts}] {msg}")

    def _on_error(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._log_view.appendPlainText(f"[{ts}] ❌ {msg}")

    def _on_consensus(self, result: dict):
        ts = datetime.now().strftime("%H:%M:%S")
        status = result.get("status", "?")
        agreed = result.get("agreed", 0)
        self._log_view.appendPlainText(
            f"[{ts}] ⚡ Consensus: {status} — {agreed} tx(s) finalised"
        )

    def _create_wallet(self):
        self.backend.create_wallet()

    def _run_consensus(self):
        self.backend.run_consensus()
