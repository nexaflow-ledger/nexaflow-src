"""
NexaFlow setup.py — build Cython extensions and install the project.

This file is kept alongside pyproject.toml for backwards compatibility
and for ``python setup.py build_ext --inplace`` convenience.

Usage:
    pip install .                          # install everything
    pip install ".[gui]"                   # install with PyQt6 GUI
    pip install ".[dev]"                   # install with dev tools
    python setup.py build_ext --inplace    # compile Cython in-place
"""

import os
from pathlib import Path

from setuptools import Extension, find_packages, setup

HERE = Path(__file__).resolve().parent
long_description = ""
if (HERE / "README.md").exists():
    long_description = (HERE / "README.md").read_text(encoding="utf-8")

# ---------------------------------------------------------------------------
# Cython / C extension setup with graceful fallback
# ---------------------------------------------------------------------------

_PYX_MODULES = [
    ("nexaflow_core.crypto_utils", "nexaflow_core/crypto_utils"),
    ("nexaflow_core.transaction", "nexaflow_core/transaction"),
    ("nexaflow_core.ledger", "nexaflow_core/ledger"),
    ("nexaflow_core.consensus", "nexaflow_core/consensus"),
    ("nexaflow_core.privacy", "nexaflow_core/privacy"),
]

USE_CYTHON = False
try:
    from Cython.Build import cythonize

    if all(os.path.exists(src + ".pyx") for _, src in _PYX_MODULES):
        USE_CYTHON = True
except ImportError:
    cythonize = None  # type: ignore[assignment]

if USE_CYTHON:
    extensions = [Extension(name, [src + ".pyx"]) for name, src in _PYX_MODULES]
    ext_modules = cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",
            "boundscheck": False,
            "wraparound": False,
            "cdivision": True,
        },
    )
else:
    # Try pre-generated .c files
    c_files = [(name, src + ".c") for name, src in _PYX_MODULES]
    if all(os.path.exists(c) for _, c in c_files):
        ext_modules = [Extension(name, [c]) for name, c in c_files]
    else:
        # Pure-Python fallback — no compiled extensions
        ext_modules = []

# ---------------------------------------------------------------------------
# Package setup
# ---------------------------------------------------------------------------

setup(
    name="nexaflow",
    version="0.9.0",
    description="A NexaFlow-like cryptocurrency with Cython optimized consensus",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    author="NexaFlow Contributors",
    python_requires=">=3.10",
    packages=find_packages(exclude=["tests", "tests.*", "scripts", "build"]),
    ext_modules=ext_modules,
    install_requires=[
        "ecdsa>=0.18.0,<0.19",
        "aiohttp>=3.9.0,<3.12",
        "tomli>=2.0.0,<3;python_version<'3.11'",
        "pycryptodome>=3.21.0,<4",
    ],
    extras_require={
        "gui": [
            "PyQt6>=6.5.0",
        ],
        "dev": [
            "cython>=3.0.0",
            "pytest>=7.0",
            "pytest-asyncio>=0.21",
            "pytest-cov>=4.0",
            "mypy>=1.5",
            "ruff>=0.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "nexaflow-node=run_node:main_sync",
        ],
        "gui_scripts": [
            "nexaflow-gui=nexaflow_gui.main_window:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
)
