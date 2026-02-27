"""
Ledger & Accounts tab — browse accounts, balances, closed ledger history.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import make_primary_button, make_stat_card

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


class LedgerTab(QWidget):
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
        title = QLabel("Ledger Explorer")
        title.setProperty("class", "heading")
        header.addWidget(title)
        header.addStretch()
        self._btn_refresh = make_primary_button("↻  Refresh")
        header.addWidget(self._btn_refresh)
        root.addLayout(header)

        # Stat cards
        stats = QHBoxLayout()
        stats.setSpacing(12)
        card, self._lbl_seq = make_stat_card("Ledger Seq")
        stats.addWidget(card)
        card, self._lbl_accounts = make_stat_card("Total Accounts")
        stats.addWidget(card)
        card, self._lbl_supply = make_stat_card("Total Supply")
        stats.addWidget(card)
        card, self._lbl_fees = make_stat_card("Fee Pool")
        stats.addWidget(card)
        root.addLayout(stats)

        # Splitter: accounts left, closed ledgers right
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Accounts table ──────────────────────────────────────────────
        acct_w = QWidget()
        acct_lay = QVBoxLayout(acct_w)
        acct_lay.setContentsMargins(0, 0, 0, 0)

        acct_box = QGroupBox("Accounts")
        acct_inner = QVBoxLayout(acct_box)

        # Search
        search_row = QHBoxLayout()
        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Search by address…")
        search_row.addWidget(self._search_edit)
        acct_inner.addLayout(search_row)

        self._acct_table = QTableWidget()
        self._acct_table.setColumnCount(5)
        self._acct_table.setHorizontalHeaderLabels([
            "Address", "Balance (NXF)", "Sequence", "Trust Lines", "Gateway",
        ])
        self._acct_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col in range(1, 5):
            self._acct_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._acct_table.setAlternatingRowColors(True)
        self._acct_table.verticalHeader().setVisible(False)
        self._acct_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        acct_inner.addWidget(self._acct_table)
        acct_lay.addWidget(acct_box)
        splitter.addWidget(acct_w)

        # ── Closed ledgers table ────────────────────────────────────────
        ledger_w = QWidget()
        ledger_lay = QVBoxLayout(ledger_w)
        ledger_lay.setContentsMargins(0, 0, 0, 0)

        ledger_box = QGroupBox("Closed Ledgers")
        ledger_inner = QVBoxLayout(ledger_box)

        self._ledger_table = QTableWidget()
        self._ledger_table.setColumnCount(5)
        self._ledger_table.setHorizontalHeaderLabels([
            "Seq", "Hash", "TXs", "Close Time", "Total NXF",
        ])
        self._ledger_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for col in [0, 2, 3, 4]:
            self._ledger_table.horizontalHeader().setSectionResizeMode(
                col, QHeaderView.ResizeMode.ResizeToContents
            )
        self._ledger_table.setAlternatingRowColors(True)
        self._ledger_table.verticalHeader().setVisible(False)
        ledger_inner.addWidget(self._ledger_table)
        ledger_lay.addWidget(ledger_box)
        splitter.addWidget(ledger_w)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    def _connect_signals(self):
        self.backend.accounts_changed.connect(self._refresh)
        self.backend.consensus_completed.connect(lambda _: self._refresh())
        self.backend.status_updated.connect(self._on_status)
        self._btn_refresh.clicked.connect(self._refresh)
        self._search_edit.textChanged.connect(self._filter_accounts)

    def _on_status(self, status: dict):
        self._lbl_seq.setText(str(status.get("ledger_sequence", 0)))
        self._lbl_accounts.setText(str(status.get("total_accounts", 0)))
        supply = status.get("total_supply", 0)
        self._lbl_supply.setText(f"{supply:,.0f}")
        fees = status.get("total_burned", 0)
        self._lbl_fees.setText(f"{fees:,.6f}")

    def _refresh(self):
        self._refresh_accounts()
        self._refresh_ledgers()

    def _refresh_accounts(self):
        accounts = self.backend.get_all_accounts()
        search = self._search_edit.text().strip().lower()
        if search:
            accounts = [a for a in accounts if search in a.get("address", "").lower()]

        self._acct_table.setRowCount(len(accounts))
        for i, acct in enumerate(accounts):
            addr = acct.get("address", "")
            self._acct_table.setItem(i, 0, QTableWidgetItem(addr))

            bal = acct.get("balance", 0)
            bal_item = QTableWidgetItem(f"{bal:,.6f}")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._acct_table.setItem(i, 1, bal_item)

            seq = acct.get("sequence", 0)
            self._acct_table.setItem(i, 2, QTableWidgetItem(str(seq)))

            tl_count = len(acct.get("trust_lines", {}))
            self._acct_table.setItem(i, 3, QTableWidgetItem(str(tl_count)))

            gw = "Yes" if acct.get("is_gateway") else "No"
            self._acct_table.setItem(i, 4, QTableWidgetItem(gw))

    def _refresh_ledgers(self):
        ledgers = self.backend.get_closed_ledgers()
        self._ledger_table.setRowCount(len(ledgers))
        for i, lh in enumerate(reversed(ledgers)):
            self._ledger_table.setItem(i, 0, QTableWidgetItem(str(lh.get("sequence", 0))))

            h = lh.get("hash", "")
            self._ledger_table.setItem(i, 1, QTableWidgetItem(h[:20] + "…" if len(h) > 20 else h))

            self._ledger_table.setItem(i, 2, QTableWidgetItem(str(lh.get("tx_count", 0))))
            self._ledger_table.setItem(i, 3, QTableWidgetItem(str(lh.get("close_time", 0))))

            total = lh.get("total_nxf", 0)
            self._ledger_table.setItem(i, 4, QTableWidgetItem(f"{total:,.0f}"))

    def _filter_accounts(self):
        self._refresh_accounts()
