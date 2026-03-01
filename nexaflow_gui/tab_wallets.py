"""
Wallet management tab — create, import, export, view keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
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
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.widgets import (
    make_danger_button,
    make_primary_button,
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


class _ExportWalletDialog(QDialog):
    """Ask for a passphrase to encrypt the wallet export."""

    def __init__(self, wallet_name: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Export Wallet — {wallet_name}")
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)

        info = QLabel(
            "Enter a passphrase to encrypt the exported wallet file.\n"
            "You will need this passphrase to import the wallet later."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #8b949e; margin-bottom: 8px;")
        lay.addWidget(info)

        form = QFormLayout()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("Encryption passphrase")
        form.addRow("Passphrase:", self.pass_edit)

        self.confirm_edit = QLineEdit()
        self.confirm_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_edit.setPlaceholderText("Confirm passphrase")
        form.addRow("Confirm:", self.confirm_edit)
        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    def _validate(self):
        if not self.pass_edit.text():
            QMessageBox.warning(self, "Error", "Passphrase cannot be empty.")
            return
        if self.pass_edit.text() != self.confirm_edit.text():
            QMessageBox.warning(self, "Error", "Passphrases do not match.")
            return
        self.accept()


class _RecoverWalletDialog(QDialog):
    """Recover a wallet from raw key material (address + public/private keys)."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Recover Wallet from Keys")
        self.setMinimumWidth(560)
        lay = QVBoxLayout(self)

        info = QLabel(
            "Paste your key material to recover a wallet.\n"
            "Private keys are 64 hex chars, public keys are 130 hex chars "
            "(starting with 04).\nView/spend keys are optional — fill them "
            "in to recover untraceable transaction capability."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #8b949e; margin-bottom: 8px;")
        lay.addWidget(info)

        form = QFormLayout()

        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText("Optional friendly name")
        form.addRow("Name:", self.name_edit)

        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText("e.g. rABC123... (leave blank to derive)")
        form.addRow("Address:", self.address_edit)

        # ── main keys ───────
        self.pub_edit = QLineEdit()
        self.pub_edit.setPlaceholderText("130-char hex (04...)")
        form.addRow("Public Key:", self.pub_edit)

        self.priv_edit = QLineEdit()
        self.priv_edit.setPlaceholderText("64-char hex")
        self.priv_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Private Key:", self.priv_edit)

        # ── separator ───────
        sep = QLabel("── Untraceable / Privacy Keys (optional) ──")
        sep.setStyleSheet("color: #58a6ff; font-weight: 600; margin-top: 8px;")
        form.addRow(sep)

        self.view_pub_edit = QLineEdit()
        self.view_pub_edit.setPlaceholderText("130-char hex (04...)")
        form.addRow("View Public Key:", self.view_pub_edit)

        self.view_priv_edit = QLineEdit()
        self.view_priv_edit.setPlaceholderText("64-char hex")
        self.view_priv_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("View Private Key:", self.view_priv_edit)

        self.spend_pub_edit = QLineEdit()
        self.spend_pub_edit.setPlaceholderText("130-char hex (04...)")
        form.addRow("Spend Public Key:", self.spend_pub_edit)

        self.spend_priv_edit = QLineEdit()
        self.spend_priv_edit.setPlaceholderText("64-char hex")
        self.spend_priv_edit.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Spend Private Key:", self.spend_priv_edit)

        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)

    # ── helpers ──

    @staticmethod
    def _is_valid_hex(text: str, expected_len: int) -> bool:
        if len(text) != expected_len:
            return False
        try:
            bytes.fromhex(text)
            return True
        except ValueError:
            return False

    def _validate(self):
        pub = self.pub_edit.text().strip()
        priv = self.priv_edit.text().strip()

        if not pub or not priv:
            QMessageBox.warning(self, "Error", "Public key and private key are required.")
            return
        if not self._is_valid_hex(priv, 64):
            QMessageBox.warning(
                self, "Error",
                "Private key must be exactly 64 hex characters."
            )
            return
        if not self._is_valid_hex(pub, 130) or not pub.startswith("04"):
            QMessageBox.warning(
                self, "Error",
                "Public key must be 130 hex characters starting with '04'."
            )
            return

        # Validate optional untraceable keys if provided
        for label, edit, length in [
            ("View public key", self.view_pub_edit, 130),
            ("View private key", self.view_priv_edit, 64),
            ("Spend public key", self.spend_pub_edit, 130),
            ("Spend private key", self.spend_priv_edit, 64),
        ]:
            val = edit.text().strip()
            if val and not self._is_valid_hex(val, length):
                QMessageBox.warning(
                    self, "Error",
                    f"{label} must be exactly {length} hex characters."
                )
                return
            if val and length == 130 and not val.startswith("04"):
                QMessageBox.warning(
                    self, "Error",
                    f"{label} must start with '04'."
                )
                return

        self.accept()

    def get_keys(self) -> dict:
        """Return key material entered by the user (hex strings)."""
        result: dict[str, str | None] = {
            "name": self.name_edit.text().strip(),
            "address": self.address_edit.text().strip() or None,
            "public_key": self.pub_edit.text().strip(),
            "private_key": self.priv_edit.text().strip(),
            "view_public_key": self.view_pub_edit.text().strip() or None,
            "view_private_key": self.view_priv_edit.text().strip() or None,
            "spend_public_key": self.spend_pub_edit.text().strip() or None,
            "spend_private_key": self.spend_priv_edit.text().strip() or None,
        }
        return result


class _ImportFileDialog(QDialog):
    """Ask for a passphrase to decrypt an imported wallet file."""

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("Import Wallet from File")
        self.setMinimumWidth(420)
        lay = QVBoxLayout(self)

        info = QLabel("Enter the passphrase used when the wallet was exported.")
        info.setWordWrap(True)
        info.setStyleSheet("color: #8b949e; margin-bottom: 8px;")
        lay.addWidget(info)

        form = QFormLayout()
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("Decryption passphrase")
        form.addRow("Passphrase:", self.pass_edit)
        lay.addLayout(form)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        lay.addWidget(buttons)


class _ViewKeysDialog(QDialog):
    """Display raw private key material (read-only)."""

    def __init__(self, keys: dict, wallet_name: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(f"Private Keys — {wallet_name}")
        self.setMinimumWidth(600)
        self.setMinimumHeight(400)
        lay = QVBoxLayout(self)

        warn = QLabel(
            "⚠  NEVER share your private keys.  Anyone with these keys\n"
            "has full control over this wallet and its funds."
        )
        warn.setStyleSheet(
            "color: #f85149; font-weight: 700; font-size: 13px; margin-bottom: 8px;"
        )
        warn.setWordWrap(True)
        lay.addWidget(warn)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setStyleSheet(
            "font-family: 'SF Mono', 'Fira Code', monospace; font-size: 11px;"
        )

        lines = []
        labels = [
            ("address", "Address"),
            ("public_key", "Public Key"),
            ("private_key", "Private Key"),
            ("view_public_key", "View Public Key"),
            ("view_private_key", "View Private Key"),
            ("spend_public_key", "Spend Public Key"),
            ("spend_private_key", "Spend Private Key"),
        ]
        for key, label in labels:
            val = keys.get(key)
            if val:
                lines.append(f"{label}:\n  {val}\n")
        text.setPlainText("\n".join(lines))
        lay.addWidget(text, 1)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        lay.addWidget(close_btn)


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

        self._btn_import_file = QPushButton("📂  Import from File")
        self._btn_import_file.setMinimumHeight(36)
        header.addWidget(self._btn_import_file)

        self._btn_recover = QPushButton("🔑  Recover Wallet")
        self._btn_recover.setMinimumHeight(36)
        header.addWidget(self._btn_recover)

        root.addLayout(header)

        # Wallet table
        self._table = QTableWidget()
        self._table.setColumnCount(3)
        self._table.setHorizontalHeaderLabels(["Name", "Address", "Balance (NXF)"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        root.addWidget(self._table, 1)

        # Action buttons for selected wallet
        action_row = QHBoxLayout()
        action_row.setSpacing(10)

        self._btn_export = QPushButton("📤  Export Wallet")
        self._btn_export.setMinimumHeight(36)
        self._btn_export.setEnabled(False)
        action_row.addWidget(self._btn_export)

        self._btn_view_keys = make_danger_button("🔑  View Private Keys")
        self._btn_view_keys.setEnabled(False)
        action_row.addWidget(self._btn_view_keys)

        action_row.addStretch()
        root.addLayout(action_row)

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
        self._btn_import_file.clicked.connect(self._on_import_file)
        self._btn_recover.clicked.connect(self._on_recover)
        self._btn_export.clicked.connect(self._on_export)
        self._btn_view_keys.clicked.connect(self._on_view_keys)
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

    def _on_recover(self):
        dlg = _RecoverWalletDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            keys = dlg.get_keys()
            self.backend.recover_wallet_from_keys(
                public_key=keys["public_key"],
                private_key=keys["private_key"],
                address=keys.get("address"),
                name=keys.get("name", ""),
                view_public_key=keys.get("view_public_key"),
                view_private_key=keys.get("view_private_key"),
                spend_public_key=keys.get("spend_public_key"),
                spend_private_key=keys.get("spend_private_key"),
            )
            QMessageBox.information(self, "Success", "Wallet recovered successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Recovery Failed", str(exc))

    def _on_import_file(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Wallet File", "", "JSON files (*.json);;All files (*)"
        )
        if not path:
            return
        dlg = _ImportFileDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            with open(path) as f:
                data_str = f.read()
            self.backend.import_wallet_from_file(data_str, dlg.pass_edit.text())
            QMessageBox.information(self, "Success", "Wallet imported successfully.")
        except Exception as exc:
            QMessageBox.critical(self, "Import Failed", str(exc))

    def _on_export(self):
        addr = self.get_selected_address()
        if not addr:
            return
        name = self.backend.wallet_names.get(addr, "wallet")
        dlg = _ExportWalletDialog(name, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            json_str = self.backend.export_wallet(addr, dlg.pass_edit.text())
        except Exception as exc:
            QMessageBox.critical(self, "Export Failed", str(exc))
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Wallet File", f"{name}.json",
            "JSON files (*.json);;All files (*)",
        )
        if path:
            with open(path, "w") as f:
                f.write(json_str)
            QMessageBox.information(self, "Exported", f"Wallet saved to {path}")

    def _on_view_keys(self):
        addr = self.get_selected_address()
        if not addr:
            return
        confirm = QMessageBox.warning(
            self,
            "View Private Keys",
            "⚠  You are about to reveal the private keys for this wallet.\n\n"
            "Anyone with access to these keys has FULL CONTROL over the\n"
            "wallet and all its funds.\n\n"
            "Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return
        try:
            keys = self.backend.get_wallet_keys(addr)
            name = self.backend.wallet_names.get(addr, "")
            dlg = _ViewKeysDialog(keys, name, self)
            dlg.exec()
        except Exception as exc:
            QMessageBox.critical(self, "Error", str(exc))

    def _on_selection(self, row: int, _col: int, _prev_row: int, _prev_col: int):
        wallets = self.backend.get_wallets()
        has_selection = 0 <= row < len(wallets)
        self._btn_export.setEnabled(has_selection)
        self._btn_view_keys.setEnabled(has_selection)
        if has_selection:
            w = wallets[row]
            acct = self.backend.get_account_info(w["address"])
            detail = (
                f"Name:       {w['name']}\n"
                f"Address:    {w['address']}\n"
                f"Public Key: {w['public_key']}\n"
                f"Balance:    {w['balance']:,.8f} NXF\n"
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

            bal_item = QTableWidgetItem(f"{w['balance']:,.8f}")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            self._table.setItem(i, 2, bal_item)

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
