"""
NexaFlow - A NexaFlow-like cryptocurrency with Cython-optimized processing.

Key features:
- ECDSA-based cryptographic signing (Cython-optimized)
- Trust lines between accounts for IOU currencies
- Payment path finding across trust networks
- Simplified NexaFlow Protocol Consensus Algorithm (RPCA)
- Native NXF token with configurable supply
- Fast transaction validation and ledger management
"""

__version__ = "1.0.0"
__all__ = [
    "crypto_utils",
    "transaction",
    "ledger",
    "consensus",
    "wallet",
    "account",
    "trust_line",
    "payment_path",
    "network",
    "validator",
]
