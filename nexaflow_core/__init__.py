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
    "account",
    "amendments",
    "amm",
    "check",
    "consensus",
    "credentials",
    "crypto_utils",
    "did",
    "escrow",
    "fee_escalation",
    "fee_model",
    "hooks",
    "invariants",
    "ledger",
    "mpt",
    "multi_sign",
    "negative_unl",
    "network",
    "nftoken",
    "oracle",
    "order_book",
    "payment_channel",
    "payment_path",
    "precision",
    "privacy",
    "reporting",
    "shamap",
    "staking",
    "storage",
    "sync",
    "ticket",
    "transaction",
    "trust_line",
    "tx_metadata",
    "validator",
    "wallet",
    "websocket",
    "xchain",
]
