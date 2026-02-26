"""
Network & Validators tab — view validator nodes, consensus state, P2P info.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import make_primary_button, make_stat_card

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


class NetworkTab(QWidget):
    def __init__(self, backend: NodeBackend, parent: QWidget | None = None):
        super().__init__(parent)
        self.backend = backend
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(16)

        # Header
        header = QHBoxLayout()
        title = QLabel("Network & Validators")
        title.setProperty("class", "heading")
        header.addWidget(title)
        header.addStretch()
        self._btn_refresh = make_primary_button("↻  Refresh")
        header.addWidget(self._btn_refresh)
        root.addLayout(header)

        # Stats
        stats = QHBoxLayout()
        stats.setSpacing(12)
        card, self._lbl_validators = make_stat_card("Validators")
        stats.addWidget(card)
        card, self._lbl_consensus_rounds = make_stat_card("Closed Ledgers")
        stats.addWidget(card)
        card, self._lbl_total_tx = make_stat_card("Total TX Pool")
        stats.addWidget(card)
        root.addLayout(stats)

        # Validator table
        val_box = QGroupBox("Validator Nodes")
        val_lay = QVBoxLayout(val_box)

        self._val_table = QTableWidget()
        self._val_table.setColumnCount(6)
        self._val_table.setHorizontalHeaderLabels([
            "Node ID", "Accounts", "TX Pool", "Closed Ledgers",
            "Ledger Seq", "UNL Size",
        ])
        self._val_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 6):
            self._val_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._val_table.setAlternatingRowColors(True)
        self._val_table.verticalHeader().setVisible(False)
        self._val_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        val_lay.addWidget(self._val_table)
        root.addWidget(val_box, 1)

        # Consensus quick actions
        actions_box = QGroupBox("Consensus")
        actions_lay = QHBoxLayout(actions_box)

        self._btn_consensus = make_primary_button("⚡ Run Consensus Round")
        actions_lay.addWidget(self._btn_consensus)

        self._consensus_status = QLabel("No consensus rounds executed yet.")
        self._consensus_status.setStyleSheet("color: #8b949e; font-size: 13px;")
        actions_lay.addWidget(self._consensus_status, 1)

        root.addWidget(actions_box)

    def _connect_signals(self):
        self.backend.status_updated.connect(self._on_status)
        self.backend.consensus_completed.connect(self._on_consensus)
        self._btn_refresh.clicked.connect(self._refresh)
        self._btn_consensus.clicked.connect(self._run_consensus)

    def _on_status(self, status: dict):
        self._lbl_validators.setText(str(status.get("validator_count", 0)))
        self._lbl_consensus_rounds.setText(str(status.get("closed_ledgers", 0)))
        self._lbl_total_tx.setText(str(status.get("tx_pool", 0)))
        self._refresh()

    def _on_consensus(self, result: dict):
        status = result.get("status", "?")
        agreed = result.get("agreed", 0)
        self._consensus_status.setText(
            f"Last round: {status} — {agreed} transaction(s) applied"
        )
        self._consensus_status.setStyleSheet(
            "color: #3fb950; font-size: 13px; font-weight: 600;"
            if status == "consensus_reached"
            else "color: #d29922; font-size: 13px; font-weight: 600;"
        )
        self._refresh()

    def _refresh(self):
        statuses = self.backend.get_validator_statuses()
        self._val_table.setRowCount(len(statuses))
        for i, s in enumerate(statuses):
            self._val_table.setItem(i, 0, QTableWidgetItem(s.get("node_id", "")))

            acct_count = s.get("total_accounts", 0)
            self._val_table.setItem(i, 1, QTableWidgetItem(str(acct_count)))

            pool = s.get("tx_pool_size", 0)
            self._val_table.setItem(i, 2, QTableWidgetItem(str(pool)))

            closed = s.get("closed_ledgers", 0)
            self._val_table.setItem(i, 3, QTableWidgetItem(str(closed)))

            seq = s.get("ledger_sequence", 0)
            self._val_table.setItem(i, 4, QTableWidgetItem(str(seq)))

            unl = s.get("unl_size", 0)
            self._val_table.setItem(i, 5, QTableWidgetItem(str(unl)))

    def _run_consensus(self):
        self.backend.run_consensus()
