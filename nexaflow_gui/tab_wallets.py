"""
Wallet management tab — create, import, view wallets and balances.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
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

from nexaflow_gui.widgets import (
    make_primary_button,
    make_success_button,
)

if TYPE_CHECKING:
    from nexaflow_gui.backend import NodeBackend


# ── Dialogs ─────────────────────────────────────────────────────────────

class _CreateWalletDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Create Wallet")
        self.setMinimumWidth(400)
        lay = QVBoxLayout(self)

        form = QFormLayout()
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Optional friendly name")
        form.addRow("Name:", self.name_edit)
        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


class _ImportSeedDialog(QDialog):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Import from Seed")
        self.setMinimumWidth(450)
        lay = QVBoxLayout(self)

        form = QFormLayout()
        self.seed_edit = QLineEdit()
        self.seed_edit.setPlaceholderText("Enter seed phrase or identifier")
        form.addRow("Seed:", self.seed_edit)

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Optional friendly name")
        form.addRow("Name:", self.name_edit)
        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


class _FundDialog(QDialog):
    def __init__(self, address: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Fund Wallet")
        self.setMinimumWidth(400)
        lay = QVBoxLayout(self)

        lay.addWidget(QLabel(f"Address: {address}"))

        form = QFormLayout()
        self.amount_edit = QLineEdit("1000")
        form.addRow("Amount (NXF):", self.amount_edit)
        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


# ── Main Tab ────────────────────────────────────────────────────────────

class WalletTab(QWidget):
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
        title = QLabel("Wallet Manager")
        title.setProperty("class", "heading")
        header.addWidget(title)
        header.addStretch()

        self._btn_create = make_primary_button("+ New Wallet")
        header.addWidget(self._btn_create)

        self._btn_import = QPushButton("📥  Import from Seed")
        self._btn_import.setMinimumHeight(36)
        header.addWidget(self._btn_import)

        root.addLayout(header)

        # Wallet table
        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["Name", "Address", "Balance (NXF)", "Actions"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        root.addWidget(self._table, 1)

        # Detail panel
        detail_box = QGroupBox("Wallet Details")
        detail_lay = QVBoxLayout(detail_box)
        self._detail_label = QLabel("Select a wallet to view details.")
        self._detail_label.setWordWrap(True)
        self._detail_label.setStyleSheet("font-family: 'SF Mono', monospace; font-size: 12px;")
        self._detail_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        detail_lay.addWidget(self._detail_label)
        root.addWidget(detail_box)

    def _connect_signals(self):
        self.backend.accounts_changed.connect(self._refresh_table)
        self.backend.wallet_created.connect(lambda _: self._refresh_table())
        self.backend.balance_updated.connect(lambda _a, _b: self._refresh_table())

        self._btn_create.clicked.connect(self._on_create)
        self._btn_import.clicked.connect(self._on_import)
        self._table.currentCellChanged.connect(self._on_selection)

    # ── Actions ─────────────────────────────────────────────────────────

    def _on_create(self):
        dlg = _CreateWalletDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.backend.create_wallet(dlg.name_edit.text().strip())

    def _on_import(self):
        dlg = _ImportSeedDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            seed = dlg.seed_edit.text().strip()
            if not seed:
                QMessageBox.warning(self, "Error", "Seed cannot be empty.")
                return
            self.backend.import_wallet_from_seed(seed, dlg.name_edit.text().strip())

    def _on_fund(self, address: str):
        dlg = _FundDialog(address, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            try:
                amt = float(dlg.amount_edit.text())
                self.backend.fund_wallet(address, amt)
            except ValueError:
                QMessageBox.warning(self, "Error", "Invalid amount.")

    def _on_selection(self, row: int, _col: int, _prev_row: int, _prev_col: int):
        wallets = self.backend.get_wallets()
        if 0 <= row < len(wallets):
            w = wallets[row]
            acct = self.backend.get_account_info(w["address"])
            detail = (
                f"Name:       {w['name']}\n"
                f"Address:    {w['address']}\n"
                f"Public Key: {w['public_key']}\n"
                f"Balance:    {w['balance']:,.6f} NXF\n"
            )
            if acct:
                detail += (
                    f"Sequence:   {acct.get('sequence', 0)}\n"
                    f"Owner Cnt:  {acct.get('owner_count', 0)}\n"
                    f"Is Gateway: {acct.get('is_gateway', False)}\n"
                )
                tls = acct.get("trust_lines", {})
                if tls:
                    detail += f"Trust Lines: {len(tls)}\n"
            self._detail_label.setText(detail)

    # ── Refresh ─────────────────────────────────────────────────────────

    def _refresh_table(self):
        wallets = self.backend.get_wallets()
        self._table.setRowCount(len(wallets))
        for i, w in enumerate(wallets):
            self._table.setItem(i, 0, QTableWidgetItem(w["name"]))

            addr_item = QTableWidgetItem(w["address"])
            addr_item.setFont(_mono_font())
            self._table.setItem(i, 1, addr_item)

            bal_item = QTableWidgetItem(f"{w['balance']:,.6f}")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(i, 2, bal_item)

            btn = make_success_button("Fund")
            btn.setMinimumHeight(28)
            btn.clicked.connect(lambda checked, a=w["address"]: self._on_fund(a))
            self._table.setCellWidget(i, 3, btn)

    def get_selected_address(self) -> str | None:
        """Return the address of the currently selected wallet, if any."""
        row = self._table.currentRow()
        wallets = self.backend.get_wallets()
        if 0 <= row < len(wallets):
            return wallets[row]["address"]
        return None


def _mono_font():
    f = QLabel().font()
    f.setFamily("SF Mono, Fira Code, Consolas, monospace")
    f.setPointSize(11)
    return f
