# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for NexaFlow Node (CLI validator node).
Build with:  pyinstaller nexaflow_node.spec
"""

import sys
from pathlib import Path

block_cipher = None
HERE = Path(SPECPATH)

# Collect all nexaflow_core modules (including compiled .so/.pyd)
hidden_imports = [
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
    # Runtime deps
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
    "json",
    "ssl",
    "asyncio",
]

# Bundle the example config as a data file
datas = []
if (HERE / "nexaflow.example.toml").exists():
    datas.append((str(HERE / "nexaflow.example.toml"), "."))

# Collect any compiled Cython .so / .pyd in nexaflow_core/
binaries = []
for ext in ("*.so", "*.pyd"):
    for f in (HERE / "nexaflow_core").glob(ext):
        binaries.append((str(f), "nexaflow_core"))

a = Analysis(
    [str(HERE / "run_node.py")],
    pathex=[str(HERE)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt6", "tkinter", "matplotlib", "numpy", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="nexaflow-node",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
