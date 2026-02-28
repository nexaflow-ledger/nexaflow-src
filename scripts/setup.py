"""
Build configuration for NexaFlow – A NexaFlow-like cryptocurrency with Cython optimization.

Build with:
    python setup.py build_ext --inplace

If Cython is not installed the build falls back to pre-generated .c files
(if present) or skips the extension modules entirely so the package can
still be used in pure-Python mode.
"""

import os
from pathlib import Path
from setuptools import setup, Extension, find_packages

HERE = Path(__file__).resolve().parent
long_description = (HERE / "README.md").read_text(encoding="utf-8") if (HERE / "README.md").exists() else ""

# ---------------------------------------------------------------------------
# Cython / C extension setup with graceful fallback
# ---------------------------------------------------------------------------

_PYX_MODULES = [
    ("nexaflow_core.crypto_utils", "nexaflow_core/crypto_utils"),
    ("nexaflow_core.transaction",  "nexaflow_core/transaction"),
    ("nexaflow_core.ledger",       "nexaflow_core/ledger"),
    ("nexaflow_core.consensus",    "nexaflow_core/consensus"),
    ("nexaflow_core.privacy",      "nexaflow_core/privacy"),
]

USE_CYTHON = False
try:
    from Cython.Build import cythonize
    # Only use Cython if .pyx sources are present
    if all(os.path.exists(src + ".pyx") for _, src in _PYX_MODULES):
        USE_CYTHON = True
except ImportError:
    cythonize = None

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

setup(
    name="nexaflow",
    version="1.0.0",
    description="A NexaFlow-like cryptocurrency implemented in Python with Cython optimization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="NexaFlow Contributors",
    license="MIT",
    url="https://github.com/nexaflow-ledger/nexaflow-src",
    project_urls={
        "Bug Tracker": "https://github.com/nexaflow-ledger/nexaflow-src/issues",
        "Changelog": "https://github.com/nexaflow-ledger/nexaflow-src/blob/main/CHANGELOG.md",
    },
    packages=find_packages(exclude=["tests", "tests.*", "benchmarks", "benchmarks.*"]),
    ext_modules=ext_modules,
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "ecdsa>=0.18.0",
        "aiohttp>=3.9.0",
        "tomli>=2.0.0;python_version<'3.11'",
    ],
    extras_require={
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
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Cython",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
)
