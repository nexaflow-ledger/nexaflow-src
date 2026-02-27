"""
Network & Validators tab — view validator nodes, consensus state, P2P info.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
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
        self._start_time = time.time()
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
        card, self._lbl_uptime = make_stat_card("Uptime")
        stats.addWidget(card)
        root.addLayout(stats)

        # ── Splitter: Validators (left) | P2P Status (right) ───────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Validator table
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
        splitter.addWidget(val_box)

        # Right: Real-time P2P status
        p2p_box = QGroupBox("P2P Status  (live)")
        p2p_lay = QVBoxLayout(p2p_box)

        # Connection indicator
        self._p2p_mode = QLabel("Mode: —")
        self._p2p_mode.setStyleSheet("font-size: 13px; font-weight: 600; color: #39d2c0;")
        p2p_lay.addWidget(self._p2p_mode)

        self._p2p_peers_label = QLabel("Peers: —")
        self._p2p_peers_label.setStyleSheet("font-size: 12px; color: #c9d1d9;")
        p2p_lay.addWidget(self._p2p_peers_label)

        self._p2p_pool_label = QLabel("Global TX Pool: —")
        self._p2p_pool_label.setStyleSheet("font-size: 12px; color: #c9d1d9;")
        p2p_lay.addWidget(self._p2p_pool_label)

        self._p2p_dev_label = QLabel("")
        self._p2p_dev_label.setStyleSheet("font-size: 11px; color: #f85149; font-weight: 700;")
        p2p_lay.addWidget(self._p2p_dev_label)

        # Per-node detail table
        self._p2p_table = QTableWidget()
        self._p2p_table.setColumnCount(5)
        self._p2p_table.setHorizontalHeaderLabels([
            "Node", "Peers", "Ledger Seq", "TX Pool", "Closed",
        ])
        self._p2p_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 5):
            self._p2p_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._p2p_table.setAlternatingRowColors(True)
        self._p2p_table.verticalHeader().setVisible(False)
        self._p2p_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        p2p_lay.addWidget(self._p2p_table, 1)

        self._p2p_last_update = QLabel("Last update: —")
        self._p2p_last_update.setStyleSheet("font-size: 11px; color: #6e7681;")
        p2p_lay.addWidget(self._p2p_last_update)

        splitter.addWidget(p2p_box)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

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
        self.backend.p2p_status_updated.connect(self._on_p2p_status)
        self._btn_refresh.clicked.connect(self._refresh)
        self._btn_consensus.clicked.connect(self._run_consensus)

    def _on_status(self, status: dict):
        self._lbl_validators.setText(str(status.get("validator_count", 0)))
        self._lbl_consensus_rounds.setText(str(status.get("closed_ledgers", 0)))
        self._lbl_total_tx.setText(str(status.get("tx_pool", 0)))
        elapsed = int(time.time() - self._start_time)
        mins, secs = divmod(elapsed, 60)
        hrs, mins = divmod(mins, 60)
        self._lbl_uptime.setText(f"{hrs:02d}:{mins:02d}:{secs:02d}")
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

    def _on_p2p_status(self, p2p: dict):
        """Real-time P2P panel update (fires every ~1 s)."""
        mode = p2p.get("mode", "unknown").replace("_", " ").title()
        val_count = p2p.get("validator_count", 0)
        pool = p2p.get("total_tx_pool", 0)
        dev = p2p.get("dev_mode", False)
        nodes = p2p.get("nodes", [])

        self._p2p_mode.setText(f"●  Mode: {mode}")
        self._p2p_peers_label.setText(f"Validators: {val_count}  |  Peer links (full mesh)")
        self._p2p_pool_label.setText(f"Global TX Pool: {pool}")
        self._p2p_dev_label.setText("DEV MODE ACTIVE" if dev else "")

        self._p2p_table.setRowCount(len(nodes))
        for i, n in enumerate(nodes):
            self._p2p_table.setItem(i, 0, QTableWidgetItem(n.get("node_id", "")))
            peers = n.get("peers", [])
            self._p2p_table.setItem(i, 1, QTableWidgetItem(str(len(peers))))
            self._p2p_table.setItem(i, 2, QTableWidgetItem(str(n.get("ledger_seq", 0))))
            self._p2p_table.setItem(i, 3, QTableWidgetItem(str(n.get("tx_pool", 0))))
            self._p2p_table.setItem(i, 4, QTableWidgetItem(str(n.get("closed_ledgers", 0))))

        import datetime
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self._p2p_last_update.setText(f"Last update: {now}")

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
