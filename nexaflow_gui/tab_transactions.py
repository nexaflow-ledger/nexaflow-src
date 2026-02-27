"""
Transaction tab — send payments, set trust lines, view TX history.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import make_primary_button, truncate_addr

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


class TransactionTab(QWidget):
    def __init__(self, backend: NodeBackend, parent: QWidget | None = None):
        super().__init__(parent)
        self.backend = backend
        self._build_ui()
        self._connect_signals()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 16)
        root.setSpacing(16)

        title = QLabel("Transactions")
        title.setProperty("class", "heading")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: Send Payment ──────────────────────────────────────────
        left = QWidget()
        left_lay = QVBoxLayout(left)
        left_lay.setContentsMargins(0, 0, 0, 0)

        pay_box = QGroupBox("Send Payment")
        pay_form = QFormLayout(pay_box)
        pay_form.setSpacing(14)
        pay_form.setContentsMargins(16, 28, 16, 16)

        self._combo_from = QComboBox()
        self._combo_from.setMinimumHeight(34)
        pay_form.addRow("From:", self._combo_from)

        self._edit_to = QLineEdit()
        self._edit_to.setPlaceholderText("Destination address (rXXX…)")
        self._edit_to.setMinimumHeight(36)
        pay_form.addRow("To:", self._edit_to)

        self._spin_amount = QDoubleSpinBox()
        self._spin_amount.setRange(0.000001, 999_999_999.0)
        self._spin_amount.setDecimals(6)
        self._spin_amount.setValue(100.0)
        self._spin_amount.setMinimumHeight(34)
        pay_form.addRow("Amount:", self._spin_amount)

        self._combo_currency = QComboBox()
        self._combo_currency.setEditable(True)
        self._combo_currency.addItems(["NXF", "USD", "EUR", "BTC", "ETH"])
        self._combo_currency.setMinimumHeight(34)
        pay_form.addRow("Currency:", self._combo_currency)

        self._edit_issuer = QLineEdit()
        self._edit_issuer.setPlaceholderText("Issuer address (for IOUs only)")
        self._edit_issuer.setMinimumHeight(36)
        pay_form.addRow("Issuer:", self._edit_issuer)

        self._edit_memo = QLineEdit()
        self._edit_memo.setPlaceholderText("Optional memo")
        self._edit_memo.setMinimumHeight(36)
        pay_form.addRow("Memo:", self._edit_memo)

        self._check_confidential = QCheckBox("Confidential Transaction (shielded on-chain)")
        pay_form.addRow(self._check_confidential)

        self._btn_send = make_primary_button("🚀  Send Payment")
        pay_form.addRow(self._btn_send)

        left_lay.addWidget(pay_box)

        # ── Trust Line ──────────────────────────────────────────────────
        trust_box = QGroupBox("Set Trust Line")
        trust_form = QFormLayout(trust_box)
        trust_form.setSpacing(14)
        trust_form.setContentsMargins(16, 28, 16, 16)

        self._combo_trust_from = QComboBox()
        self._combo_trust_from.setMinimumHeight(34)
        trust_form.addRow("Account:", self._combo_trust_from)

        self._edit_trust_currency = QLineEdit()
        self._edit_trust_currency.setPlaceholderText("e.g. USD")
        self._edit_trust_currency.setMinimumHeight(36)
        trust_form.addRow("Currency:", self._edit_trust_currency)

        self._edit_trust_issuer = QLineEdit()
        self._edit_trust_issuer.setPlaceholderText("Issuer address")
        self._edit_trust_issuer.setMinimumHeight(36)
        trust_form.addRow("Issuer:", self._edit_trust_issuer)

        self._spin_trust_limit = QDoubleSpinBox()
        self._spin_trust_limit.setRange(0, 999_999_999.0)
        self._spin_trust_limit.setDecimals(2)
        self._spin_trust_limit.setValue(1000.0)
        self._spin_trust_limit.setMinimumHeight(34)
        trust_form.addRow("Limit:", self._spin_trust_limit)

        self._btn_trust = make_primary_button("🔗  Set Trust Line")
        trust_form.addRow(self._btn_trust)

        left_lay.addWidget(trust_box)
        left_lay.addStretch()

        # Wrap left panel in a scroll area so forms never compress
        scroll = QScrollArea()
        scroll.setWidget(left)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        splitter.addWidget(scroll)

        # ── Right: TX History ───────────────────────────────────────────
        right = QWidget()
        right_lay = QVBoxLayout(right)
        right_lay.setContentsMargins(0, 0, 0, 0)

        hist_box = QGroupBox("Transaction History")
        hist_lay = QVBoxLayout(hist_box)

        self._tx_table = QTableWidget()
        self._tx_table.setColumnCount(6)
        self._tx_table.setHorizontalHeaderLabels([
            "TX ID", "Type", "From", "To", "Amount", "Status",
        ])
        self._tx_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._tx_table.setAlternatingRowColors(True)
        self._tx_table.verticalHeader().setVisible(False)
        self._tx_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        hist_lay.addWidget(self._tx_table)

        right_lay.addWidget(hist_box, 1)
        splitter.addWidget(right)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        root.addWidget(splitter, 1)

    def _connect_signals(self):
        self.backend.accounts_changed.connect(self._refresh_combos)
        self.backend.wallet_created.connect(lambda _: self._refresh_combos())
        self.backend.tx_submitted.connect(lambda _: self._refresh_history())
        self.backend.consensus_completed.connect(lambda _: self._refresh_history())

        self._btn_send.clicked.connect(self._on_send)
        self._btn_trust.clicked.connect(self._on_trust)

    # ── Combo refresh ───────────────────────────────────────────────────

    def _refresh_combos(self):
        wallets = self.backend.get_wallets()
        for combo in (self._combo_from, self._combo_trust_from):
            prev = combo.currentText()
            combo.clear()
            for w in wallets:
                label = f"{w['name']}  ({truncate_addr(w['address'])})"
                combo.addItem(label, w["address"])
            # Restore selection
            idx = combo.findText(prev)
            if idx >= 0:
                combo.setCurrentIndex(idx)

    # ── Send Payment ────────────────────────────────────────────────────

    def _on_send(self):
        addr = self._combo_from.currentData()
        if not addr:
            QMessageBox.warning(self, "Error", "Select a sender wallet first.")
            return

        dest = self._edit_to.text().strip()
        if not dest:
            QMessageBox.warning(self, "Error", "Enter a destination address.")
            return

        amount = self._spin_amount.value()
        currency = self._combo_currency.currentText().strip() or "NXF"
        issuer = self._edit_issuer.text().strip()
        memo = self._edit_memo.text().strip()

        result = self.backend.send_payment(addr, dest, amount, currency, issuer, memo)
        if result and result.get("_accepted"):
            QMessageBox.information(self, "Success", f"Payment submitted!\nTX: {result.get('tx_id', '?')[:24]}…")
        elif result:
            QMessageBox.warning(self, "Rejected", "Transaction was not accepted by validators.")

    # ── Set Trust Line ──────────────────────────────────────────────────

    def _on_trust(self):
        addr = self._combo_trust_from.currentData()
        if not addr:
            QMessageBox.warning(self, "Error", "Select an account first.")
            return

        currency = self._edit_trust_currency.text().strip()
        issuer = self._edit_trust_issuer.text().strip()
        limit = self._spin_trust_limit.value()

        if not currency or not issuer:
            QMessageBox.warning(self, "Error", "Enter currency and issuer.")
            return

        result = self.backend.set_trust_line(addr, currency, issuer, limit)
        if result:
            QMessageBox.information(self, "Success", f"Trust line set: {currency}/{issuer[:16]}…")

    # ── History refresh ─────────────────────────────────────────────────

    def _refresh_history(self):
        txns = self.backend.get_tx_history()
        self._tx_table.setRowCount(len(txns))
        for i, tx in enumerate(txns):
            tx_id = tx.get("tx_id", "")[:16] + "…" if tx.get("tx_id") else "—"
            self._tx_table.setItem(i, 0, QTableWidgetItem(tx_id))
            self._tx_table.setItem(i, 1, QTableWidgetItem(tx.get("tx_type", "?")))

            acct = tx.get("account", "")
            self._tx_table.setItem(i, 2, QTableWidgetItem(truncate_addr(acct)))

            dest = tx.get("destination", "")
            self._tx_table.setItem(i, 3, QTableWidgetItem(truncate_addr(dest) if dest else "—"))

            amt = tx.get("amount", {})
            if isinstance(amt, dict):
                val = f"{amt.get('value', 0):,.4f} {amt.get('currency', '')}"
            else:
                val = str(amt)
            self._tx_table.setItem(i, 4, QTableWidgetItem(val))

            accepted = tx.get("_accepted", True)
            status_item = QTableWidgetItem("✓ Accepted" if accepted else "✗ Rejected")
            status_item.setForeground(
                Qt.GlobalColor.green if accepted else Qt.GlobalColor.red
            )
            self._tx_table.setItem(i, 5, status_item)
