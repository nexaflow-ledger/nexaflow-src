# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for NexaFlow GUI (PyQt6 desktop application).
Build with:  pyinstaller nexaflow_gui.spec
"""

import sys
from pathlib import Path

block_cipher = None
HERE = Path(SPECPATH)

hidden_imports = [
    # ── Core library ────────────────────────────────────────────
    "nexaflow_core",
    "nexaflow_core.account",
    "nexaflow_core.api",
    "nexaflow_core.config",
    "nexaflow_core.consensus",
    "nexaflow_core.crypto_utils",
    "nexaflow_core.ledger",
    "nexaflow_core.logging_config",
    "nexaflow_core.network",
    "nexaflow_core.order_book",
    "nexaflow_core.p2p",
    "nexaflow_core.payment_path",
    "nexaflow_core.precision",
    "nexaflow_core.privacy",
    "nexaflow_core.staking",
    "nexaflow_core.storage",
    "nexaflow_core.sync",
    "nexaflow_core.transaction",
    "nexaflow_core.trust_line",
    "nexaflow_core.validator",
    "nexaflow_core.wallet",
    # ── GUI modules ─────────────────────────────────────────────
    "nexaflow_gui",
    "nexaflow_gui.backend",
    "nexaflow_gui.main_window",
    "nexaflow_gui.tab_dashboard",
    "nexaflow_gui.tab_ledger",
    "nexaflow_gui.tab_network",
    "nexaflow_gui.tab_staking",
    "nexaflow_gui.tab_transactions",
    "nexaflow_gui.tab_trustdex",
    "nexaflow_gui.tab_wallets",
    "nexaflow_gui.theme",
    "nexaflow_gui.widgets",
    # ── Runtime deps ────────────────────────────────────────────
    "ecdsa",
    "aiohttp",
    "pycryptodome",
    "Crypto",
    "Crypto.Cipher",
    "Crypto.Cipher.AES",
    "Crypto.Random",
    "Crypto.Util",
    "Crypto.Util.Padding",
    "tomli",
    "PyQt6",
    "PyQt6.QtCore",
    "PyQt6.QtGui",
    "PyQt6.QtWidgets",
    "json",
    "ssl",
    "asyncio",
]

# Bundle the example config
datas = []
if (HERE / "nexaflow.example.toml").exists():
    datas.append((str(HERE / "nexaflow.example.toml"), "."))

# Collect compiled Cython extensions
binaries = []
for ext in ("*.so", "*.pyd"):
    for f in (HERE / "nexaflow_core").glob(ext):
        binaries.append((str(f), "nexaflow_core"))

a = Analysis(
    [str(HERE / "nexaflow_gui" / "__main__.py")],
    pathex=[str(HERE)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# ── Determine if windowed (macOS / Windows) or console (Linux) ──
is_windowed = sys.platform in ("darwin", "win32")

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="nexaflow-gui",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=not is_windowed,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

# ── macOS .app bundle ───────────────────────────────────────────
if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="NexaFlow.app",
        icon=None,
        bundle_identifier="com.nexaflow.gui",
        info_plist={
            "CFBundleDisplayName": "NexaFlow",
            "CFBundleShortVersionString": "0.9.0",
            "NSHighResolutionCapable": True,
        },
    )
