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
from typing import Any, Dict, List, Optional

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
    peers: List[str] = field(default_factory=list)


@dataclass
class LedgerConfig:
    """Ledger / economics settings."""
    total_supply: float = 100_000_000_000.0
    account_reserve: float = 20.0
    owner_reserve: float = 5.0
    min_fee: float = 0.000010


@dataclass
class ConsensusConfig:
    """Consensus timing."""
    interval_seconds: int = 10
    proposal_wait_seconds: float = 2.0
    initial_threshold: float = 0.50
    final_threshold: float = 0.80


@dataclass
class APIConfig:
    """REST API settings."""
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8080


@dataclass
class StorageConfig:
    """Persistence settings."""
    enabled: bool = False
    backend: str = "sqlite"
    path: str = "data/nexaflow.db"


@dataclass
class LoggingConfig:
    """Logging settings."""
    level: str = "INFO"
    format: str = "human"   # "human" or "json"
    file: Optional[str] = None


@dataclass
class NexaFlowConfig:
    """Top-level configuration container."""
    node: NodeConfig = field(default_factory=NodeConfig)
    ledger: LedgerConfig = field(default_factory=LedgerConfig)
    consensus: ConsensusConfig = field(default_factory=ConsensusConfig)
    api: APIConfig = field(default_factory=APIConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _merge(dc: Any, raw: Dict[str, Any]) -> None:
    """Merge a raw dict into a dataclass instance (in-place)."""
    for key, value in raw.items():
        key_under = key.replace("-", "_")
        if hasattr(dc, key_under):
            setattr(dc, key_under, value)


def load_config(path: Optional[str] = None) -> NexaFlowConfig:
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
                ("ledger", cfg.ledger),
                ("consensus", cfg.consensus),
                ("api", cfg.api),
                ("storage", cfg.storage),
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

    return cfg
