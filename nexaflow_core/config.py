"""
TOML-based configuration for NexaFlow nodes.

Loads settings from a TOML file and/or environment variables.
Environment variables take precedence over file values.

Usage:
    from nexaflow_core.config import load_config
    cfg = load_config("nexaflow.toml")
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib  # type: ignore[import]
    except ModuleNotFoundError:
        import tomli as tomllib  # type: ignore[import,no-redef]


@dataclass
class NodeConfig:
    """P2P and identity settings."""
    node_id: str = "validator-1"
    host: str = "0.0.0.0"
    port: int = 9001
    peers: list[str] = field(default_factory=list)


@dataclass
class WalletConfig:
    """Node wallet auto-generation and persistence.

    On first run the node automatically generates a secure wallet and saves
    it to ``wallet_file``.  On subsequent runs the wallet is loaded from that
    file.  When ``auto_genesis`` is True *and* ``[genesis.accounts]`` is empty
    the newly-created wallet address receives the full supply.
    """
    wallet_file: str = "data/wallet.json"
    auto_genesis: bool = True


@dataclass
class LedgerConfig:
    """Ledger / economics settings."""
    total_supply: float = 100_000_000_000.0
    account_reserve: float = 20.0
    owner_reserve: float = 5.0
    min_fee: float = 0.00001000


@dataclass
class TLSConfig:
    """TLS / mutual-TLS settings for the P2P layer."""
    enabled: bool = False
    cert_file: str = "certs/node.crt"   # PEM X.509 certificate
    key_file: str = "certs/node.key"    # PEM private key
    ca_file: str = "certs/ca.crt"       # CA bundle used to verify peers
    verify_peer: bool = True             # mutual TLS — require peer certificate
    # When True, automatically generate TLS CA + node cert on first run
    # if the configured cert files don't exist.
    auto_generate: bool = True


@dataclass
class ConsensusConfig:
    """Consensus timing and BFT settings."""
    interval_seconds: int = 10
    proposal_wait_seconds: float = 2.0
    initial_threshold: float = 0.50
    final_threshold: float = 0.80
    # BFT: path to this validator's secp256k1 private key used to sign
    # proposals.  When empty, proposals are sent unsigned (non-BFT mode).
    validator_key_file: str = ""
    # BFT: directory containing <validator_id>.pub files (65-byte hex pubkeys)
    # used to verify peer proposals.  Empty = no signature verification.
    validator_pubkeys_dir: str = ""
    # When True, automatically generate BFT consensus keys on first run
    # if validator_key_file does not exist.
    auto_generate_keys: bool = True
    # Default directory for auto-generated key material.
    certs_dir: str = "certs"


@dataclass
class APIConfig:
    """REST API settings."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080
    api_key: str = ""                 # require this key on POST endpoints (empty = no auth)
    rate_limit_rpm: int = 120          # max requests per minute per IP (0 = unlimited)
    cors_origins: list[str] = field(default_factory=list)  # allowed CORS origins (empty = no CORS)
    max_body_bytes: int = 1_048_576    # 1 MiB max request body


@dataclass
class StorageConfig:
    """Persistence settings."""
    enabled: bool = False
    backend: str = "sqlite"
    path: str = "data/nexaflow.db"


@dataclass
class GenesisConfig:
    """
    Deterministic genesis state.

    ``accounts`` maps address → initial NXF balance.  Every node must use
    identical genesis config to converge on the same ledger hash chain.
    When empty, a single genesis account (``nGenesisNXF``) receives the
    full supply (backward-compatible behaviour).
    """
    accounts: dict[str, float] = field(default_factory=dict)


@dataclass
class LoggingConfig:
    """Logging settings."""
    level: str = "INFO"
    format: str = "human"   # "human" or "json"
    file: str | None = None


@dataclass
class NexaFlowConfig:
    """Top-level configuration container."""
    node: NodeConfig = field(default_factory=NodeConfig)
    wallet: WalletConfig = field(default_factory=WalletConfig)
    ledger: LedgerConfig = field(default_factory=LedgerConfig)
    consensus: ConsensusConfig = field(default_factory=ConsensusConfig)
    tls: TLSConfig = field(default_factory=TLSConfig)
    api: APIConfig = field(default_factory=APIConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    genesis: GenesisConfig = field(default_factory=GenesisConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _merge(dc: Any, raw: dict[str, Any]) -> None:
    """Merge a raw dict into a dataclass instance (in-place)."""
    for key, value in raw.items():
        key_under = key.replace("-", "_")
        if hasattr(dc, key_under):
            setattr(dc, key_under, value)


def load_config(path: str | None = None) -> NexaFlowConfig:
    """
    Load configuration from a TOML file, then overlay environment variables.

    Env-var mapping (selected):
        NEXAFLOW_NODE_ID   -> node.node_id
        NEXAFLOW_HOST      -> node.host
        NEXAFLOW_PORT      -> node.port
        NEXAFLOW_PEERS     -> node.peers   (comma-separated)
        NEXAFLOW_API_PORT  -> api.port
        NEXAFLOW_LOG_LEVEL -> logging.level
        NEXAFLOW_LOG_FMT   -> logging.format
        NEXAFLOW_DB_PATH   -> storage.path
    """
    cfg = NexaFlowConfig()

    # ── TOML file ────────────────────────────────────────────────
    if path is not None:
        p = Path(path)
        if p.exists():
            with open(p, "rb") as f:
                data = tomllib.load(f)
            for section_name, section_dc in [
                ("node", cfg.node),
                ("wallet", cfg.wallet),
                ("ledger", cfg.ledger),
                ("consensus", cfg.consensus),
                ("tls", cfg.tls),
                ("api", cfg.api),
                ("storage", cfg.storage),
                ("genesis", cfg.genesis),
                ("logging", cfg.logging),
            ]:
                if section_name in data:
                    _merge(section_dc, data[section_name])

    # ── Environment variable overrides ───────────────────────────
    if v := os.environ.get("NEXAFLOW_NODE_ID"):
        cfg.node.node_id = v
    if v := os.environ.get("NEXAFLOW_HOST"):
        cfg.node.host = v
    if v := os.environ.get("NEXAFLOW_PORT"):
        cfg.node.port = int(v)
    if v := os.environ.get("NEXAFLOW_PEERS"):
        cfg.node.peers = [p.strip() for p in v.split(",") if p.strip()]
    if v := os.environ.get("NEXAFLOW_API_PORT"):
        cfg.api.port = int(v)
        cfg.api.enabled = True
    if v := os.environ.get("NEXAFLOW_LOG_LEVEL"):
        cfg.logging.level = v.upper()
    if v := os.environ.get("NEXAFLOW_LOG_FMT"):
        cfg.logging.format = v
    if v := os.environ.get("NEXAFLOW_DB_PATH"):
        cfg.storage.path = v
        cfg.storage.enabled = True
    if v := os.environ.get("NEXAFLOW_API_KEY"):
        cfg.api.api_key = v
    if v := os.environ.get("NEXAFLOW_CORS_ORIGINS"):
        cfg.api.cors_origins = [o.strip() for o in v.split(",") if o.strip()]

    return cfg
