"""
Precision constants and helpers for NexaFlow.

NexaFlow uses 8 decimal places of precision for all currency amounts,
matching Bitcoin's satoshi model:

    1 NXF = 100,000,000 drops (smallest indivisible unit)

All display formatting should use 8 decimal places (``:.8f``).
"""

from __future__ import annotations

# Number of decimal places for all NXF (and IOU) amounts.
NXF_DECIMALS: int = 8

# Smallest representable unit — 1 drop = 0.00000001 NXF.
DROPS_PER_NXF: int = 10 ** NXF_DECIMALS  # 100_000_000

# Format string for display.
AMOUNT_FMT: str = f":.{NXF_DECIMALS}f"  # ":.8f"


def normalize_amount(value: float) -> float:
    """Round *value* to ``NXF_DECIMALS`` decimal places.

    This prevents floating-point dust from propagating through
    arithmetic chains while keeping the C ``double`` representation
    used internally by the Cython layer.

    >>> normalize_amount(1.000000005)
    1.00000001
    >>> normalize_amount(0.123456789)
    0.12345679
    """
    return round(value, NXF_DECIMALS)


def drops_to_nxf(drops: int) -> float:
    """Convert an integer drop count to an NXF float."""
    return drops / DROPS_PER_NXF


def nxf_to_drops(value: float) -> int:
    """Convert an NXF float to the nearest integer drop count."""
    return int(round(value * DROPS_PER_NXF))


def format_amount(value: float, currency: str = "NXF") -> str:
    """Return a human-readable string with 8 decimal places."""
    return f"{value:.{NXF_DECIMALS}f} {currency}"
