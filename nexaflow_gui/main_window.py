"""
NexaFlow GUI — Main Window.

Assembles tabs, status bar, menu bar, and the backend bridge.
"""

from __future__ import annotations

import sys

from PyQt6.QtCore import QSize
from PyQt6.QtGui import QAction
from PyQt6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from nexaflow_gui.backend import NodeBackend
from nexaflow_gui.tab_dashboard import DashboardTab
from nexaflow_gui.tab_ledger import LedgerTab
from nexaflow_gui.tab_network import NetworkTab
from nexaflow_gui.tab_staking import StakingTab
from nexaflow_gui.tab_transactions import TransactionTab
from nexaflow_gui.tab_trustdex import TrustDexTab
from nexaflow_gui.tab_wallets import WalletTab
from nexaflow_gui.theme import build_stylesheet


class MainWindow(QMainWindow):
    """Top-level NexaFlow GUI window."""

    def __init__(self):
        super().__init__()

        self.setWindowTitle("NexaFlow — Cryptocurrency Node")
        self.setMinimumSize(QSize(1200, 780))
        self.resize(1440, 900)

        # ── Backend ─────────────────────────────────────────────────────
        self.backend = NodeBackend(self)

        # ── Central widget ──────────────────────────────────────────────
        central = QWidget()
        self.setCentralWidget(central)
        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Top banner ──────────────────────────────────────────────────
        banner = QWidget()
        banner.setStyleSheet(
            "background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "stop:0 #0d1117, stop:0.5 #111d2b, stop:1 #0d1117);"
            "border-bottom: 1px solid #30363d;"
        )
        banner_lay = QHBoxLayout(banner)
        banner_lay.setContentsMargins(24, 10, 24, 10)

        logo_label = QLabel("◆  NexaFlow")
        logo_label.setStyleSheet(
            "font-size: 20px; font-weight: 800; color: #39d2c0;"
            "letter-spacing: 1px;"
        )
        banner_lay.addWidget(logo_label)

        version_label = QLabel("v1.0.0")
        version_label.setStyleSheet(
            "font-size: 11px; color: #6e7681; margin-left: 8px;"
        )
        banner_lay.addWidget(version_label)
        banner_lay.addStretch()

        self._banner_status = QLabel("● Local Simulation")
        self._banner_status.setStyleSheet(
            "font-size: 12px; color: #3fb950; font-weight: 600;"
        )
        banner_lay.addWidget(self._banner_status)

        if self.backend.DEV_MODE:
            dev_badge = QLabel("  DEV MODE")
            dev_badge.setStyleSheet(
                "font-size: 11px; color: #f85149; font-weight: 800;"
                "background: #3d1d20; border-radius: 4px; padding: 2px 8px;"
            )
            banner_lay.addWidget(dev_badge)

        root_layout.addWidget(banner)

        # ── Tab widget ──────────────────────────────────────────────────
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)

        self.tab_dashboard = DashboardTab(self.backend)
        self.tab_wallets = WalletTab(self.backend)
        self.tab_transactions = TransactionTab(self.backend)
        self.tab_ledger = LedgerTab(self.backend)
        self.tab_network = NetworkTab(self.backend)
        self.tab_trustdex = TrustDexTab(self.backend)
        self.tab_staking = StakingTab(self.backend)

        self.tabs.addTab(self.tab_dashboard, "  Dashboard  ")
        self.tabs.addTab(self.tab_wallets, "  Wallets  ")
        self.tabs.addTab(self.tab_transactions, "  Transactions  ")
        self.tabs.addTab(self.tab_ledger, "  Ledger  ")
        self.tabs.addTab(self.tab_network, "  Network  ")
        self.tabs.addTab(self.tab_trustdex, "  Trust / DEX  ")
        self.tabs.addTab(self.tab_staking, "  Staking  ")

        root_layout.addWidget(self.tabs, 1)

        # ── Status bar ──────────────────────────────────────────────────
        self._build_status_bar()

        # ── Menu bar ────────────────────────────────────────────────────
        self._build_menu_bar()

        # ── Start backend ───────────────────────────────────────────────
        self.backend.status_updated.connect(self._on_status)
        self.backend.start()

    # ── Menu bar ────────────────────────────────────────────────────────

    def _build_menu_bar(self):
        menu = self.menuBar()

        # File
        file_menu = menu.addMenu("File")

        new_wallet = QAction("New Wallet", self)
        new_wallet.setShortcut("Ctrl+N")
        new_wallet.triggered.connect(lambda: self.backend.create_wallet())
        file_menu.addAction(new_wallet)

        file_menu.addSeparator()

        quit_action = QAction("Quit", self)
        quit_action.setShortcut("Ctrl+Q")
        quit_action.triggered.connect(self.close)
        file_menu.addAction(quit_action)

        # Node
        node_menu = menu.addMenu("Node")

        consensus = QAction("Run Consensus", self)
        consensus.setShortcut("Ctrl+R")
        consensus.triggered.connect(lambda: self.backend.run_consensus())
        node_menu.addAction(consensus)

        # Dev-mode only: reset ledger
        if self.backend.DEV_MODE:
            node_menu.addSeparator()
            reset_action = QAction("⚠ Reset All Ledger Data", self)
            reset_action.triggered.connect(self._confirm_reset_ledger)
            node_menu.addAction(reset_action)

        # Help
        help_menu = menu.addMenu("Help")
        about = QAction("About NexaFlow", self)
        about.triggered.connect(self._show_about)
        help_menu.addAction(about)

    def _build_status_bar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)

        self._sb_ledger = QLabel("Ledger: 0")
        self._sb_accounts = QLabel("Accounts: 0")
        self._sb_wallets = QLabel("Wallets: 0")
        self._sb_pool = QLabel("TX Pool: 0")

        for lbl in (self._sb_ledger, self._sb_accounts, self._sb_wallets, self._sb_pool):
            lbl.setStyleSheet("margin-right: 16px;")
            sb.addPermanentWidget(lbl)

    def _on_status(self, status: dict):
        self._sb_ledger.setText(f"Ledger: {status.get('ledger_sequence', 0)}")
        self._sb_accounts.setText(f"Accounts: {status.get('total_accounts', 0)}")
        self._sb_wallets.setText(f"Wallets: {status.get('wallet_count', 0)}")
        self._sb_pool.setText(f"TX Pool: {status.get('tx_pool', 0)}")

    def _show_about(self):
        QMessageBox.about(
            self,
            "About NexaFlow",
            "<h2>NexaFlow v1.0.0</h2>"
            "<p>A cryptocurrency implementation with consensus, "
            "trust lines, DEX, and P2P networking.</p>"
            "<p>Built with Python, Cython, and PyQt6.</p>"
            '<p><a href="https://github.com/nexaflow-ledger/nexaflow-src">'
            "github.com/nexaflow-ledger/nexaflow-src</a></p>",
        )

    def _confirm_reset_ledger(self):
        """Prompt for confirmation, then wipe all ledger data."""
        reply = QMessageBox.critical(
            self,
            "Reset All Ledger Data",
            "⚠  This will permanently delete ALL ledger data:\n\n"
            "  •  All account balances\n"
            "  •  All transaction history\n"
            "  •  All trust lines and DEX orders\n"
            "  •  All staking positions\n"
            "  •  All closed ledger headers\n\n"
            "Wallets will be preserved but balances will be zero.\n\n"
            "This cannot be undone.  Continue?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.backend.reset_ledger()

    def closeEvent(self, event):
        self.backend.stop()
        super().closeEvent(event)


def main():
    """Entry point for the NexaFlow GUI application."""
    app = QApplication(sys.argv)
    app.setApplicationName("NexaFlow")
    app.setApplicationVersion("1.0.0")

    # Apply dark theme
    app.setStyleSheet(build_stylesheet())

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
