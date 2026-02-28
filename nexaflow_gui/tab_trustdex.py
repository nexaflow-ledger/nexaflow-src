"""
Trust Lines & DEX Order Book tab.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
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

from nexaflow_gui.widgets import make_primary_button, truncate_addr

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


class TrustDexTab(QWidget):
    def __init__(self, backend: NodeBackend, parent: QWidget | None = None):
        super().__init__(parent)
        self.backend = backend
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(16)

        title = QLabel("Trust Lines & DEX")
        title.setProperty("class", "heading")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Vertical)

        # ── Trust lines table ───────────────────────────────────────────
        tl_widget = QWidget()
        tl_lay = QVBoxLayout(tl_widget)
        tl_lay.setContentsMargins(0, 0, 0, 0)

        tl_header = QHBoxLayout()
        tl_box = QGroupBox("Trust Lines")
        tl_inner = QVBoxLayout(tl_box)

        self._btn_refresh_tl = make_primary_button("↻  Refresh")
        tl_header.addStretch()
        tl_header.addWidget(self._btn_refresh_tl)
        tl_inner.addLayout(tl_header)

        self._tl_table = QTableWidget()
        self._tl_table.setColumnCount(5)
        self._tl_table.setHorizontalHeaderLabels([
            "Holder", "Currency", "Issuer", "Balance", "Limit",
        ])
        self._tl_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._tl_table.setAlternatingRowColors(True)
        self._tl_table.verticalHeader().setVisible(False)
        tl_inner.addWidget(self._tl_table)
        tl_lay.addWidget(tl_box)
        splitter.addWidget(tl_widget)

        # ── Order Book ──────────────────────────────────────────────────
        ob_widget = QWidget()
        ob_lay = QVBoxLayout(ob_widget)
        ob_lay.setContentsMargins(0, 0, 0, 0)

        ob_box = QGroupBox("Order Book (DEX)")
        ob_inner = QVBoxLayout(ob_box)

        pair_row = QHBoxLayout()
        pair_row.addWidget(QLabel("Pair:"))
        self._combo_pair = QComboBox()
        self._combo_pair.setEditable(True)
        self._combo_pair.addItems(["NXF/USD", "NXF/EUR", "NXF/BTC"])
        self._combo_pair.setMinimumWidth(180)
        pair_row.addWidget(self._combo_pair)
        self._btn_refresh_ob = make_primary_button("↻  Load")
        pair_row.addWidget(self._btn_refresh_ob)
        pair_row.addStretch()
        ob_inner.addLayout(pair_row)

        book_row = QHBoxLayout()

        # Bids
        bid_grp = QGroupBox("Bids (Buy)")
        bid_lay = QVBoxLayout(bid_grp)
        self._bid_table = QTableWidget()
        self._bid_table.setColumnCount(3)
        self._bid_table.setHorizontalHeaderLabels(["Price", "Quantity", "Account"])
        self._bid_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._bid_table.setAlternatingRowColors(True)
        self._bid_table.verticalHeader().setVisible(False)
        bid_lay.addWidget(self._bid_table)
        book_row.addWidget(bid_grp)

        # Asks
        ask_grp = QGroupBox("Asks (Sell)")
        ask_lay = QVBoxLayout(ask_grp)
        self._ask_table = QTableWidget()
        self._ask_table.setColumnCount(3)
        self._ask_table.setHorizontalHeaderLabels(["Price", "Quantity", "Account"])
        self._ask_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._ask_table.setAlternatingRowColors(True)
        self._ask_table.verticalHeader().setVisible(False)
        ask_lay.addWidget(self._ask_table)
        book_row.addWidget(ask_grp)

        ob_inner.addLayout(book_row)

        # Recent fills
        fills_box = QGroupBox("Recent Fills")
        fills_lay = QVBoxLayout(fills_box)
        self._fills_table = QTableWidget()
        self._fills_table.setColumnCount(4)
        self._fills_table.setHorizontalHeaderLabels(["Pair", "Price", "Quantity", "Time"])
        self._fills_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._fills_table.setAlternatingRowColors(True)
        self._fills_table.verticalHeader().setVisible(False)
        fills_lay.addWidget(self._fills_table)
        ob_inner.addWidget(fills_box)

        ob_lay.addWidget(ob_box)
        splitter.addWidget(ob_widget)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        root.addWidget(splitter, 1)

    def _connect_signals(self):
        self.backend.trust_lines_changed.connect(self._refresh_trust_lines)
        self.backend.order_book_changed.connect(self._refresh_order_book)
        self.backend.consensus_completed.connect(lambda _: self._refresh_trust_lines())
        self._btn_refresh_tl.clicked.connect(self._refresh_trust_lines)
        self._btn_refresh_ob.clicked.connect(self._refresh_order_book)

    def _refresh_trust_lines(self):
        lines = self.backend.get_trust_lines()
        self._tl_table.setRowCount(len(lines))
        for i, tl in enumerate(lines):
            self._tl_table.setItem(i, 0, QTableWidgetItem(truncate_addr(tl.get("holder", ""))))
            self._tl_table.setItem(i, 1, QTableWidgetItem(tl.get("currency", "")))
            self._tl_table.setItem(i, 2, QTableWidgetItem(truncate_addr(tl.get("issuer", ""))))

            bal = tl.get("balance", 0)
            bal_item = QTableWidgetItem(f"{bal:,.8f}")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._tl_table.setItem(i, 3, bal_item)

            lim = tl.get("limit", 0)
            lim_item = QTableWidgetItem(f"{lim:,.8f}")
            lim_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._tl_table.setItem(i, 4, lim_item)

    def _refresh_order_book(self):
        pair = self._combo_pair.currentText().strip()
        if not pair:
            return

        snap = self.backend.get_order_book_snapshot(pair)

        bids = snap.get("bids", [])
        self._bid_table.setRowCount(len(bids))
        for i, b in enumerate(bids):
            self._bid_table.setItem(i, 0, QTableWidgetItem(f"{b.get('price', 0):,.8f}"))
            self._bid_table.setItem(i, 1, QTableWidgetItem(f"{b.get('remaining', 0):,.8f}"))
            self._bid_table.setItem(i, 2, QTableWidgetItem(truncate_addr(b.get("account", ""))))

        asks = snap.get("asks", [])
        self._ask_table.setRowCount(len(asks))
        for i, a in enumerate(asks):
            self._ask_table.setItem(i, 0, QTableWidgetItem(f"{a.get('price', 0):,.8f}"))
            self._ask_table.setItem(i, 1, QTableWidgetItem(f"{a.get('remaining', 0):,.8f}"))
            self._ask_table.setItem(i, 2, QTableWidgetItem(truncate_addr(a.get("account", ""))))

        fills = self.backend.get_recent_fills()
        self._fills_table.setRowCount(len(fills))
        for i, f in enumerate(fills):
            self._fills_table.setItem(i, 0, QTableWidgetItem(f.get("pair", "")))
            self._fills_table.setItem(i, 1, QTableWidgetItem(f"{f.get('price', 0):,.8f}"))
            self._fills_table.setItem(i, 2, QTableWidgetItem(f"{f.get('quantity', 0):,.8f}"))
            self._fills_table.setItem(i, 3, QTableWidgetItem(str(f.get("timestamp", ""))))
