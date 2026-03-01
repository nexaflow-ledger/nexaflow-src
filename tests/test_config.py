"""
Tests for nexaflow_core.config — TOML configuration and environment overrides.

Covers:
  - Default values for all dataclass sections
  - TOML parsing and section merging
  - Environment variable overrides (precedence over TOML)
  - GenesisConfig
  - APIConfig auth / cors / rate fields
  - _merge helper edge cases
  - Missing / broken TOML files
  - Hyphenated key handling
"""

from __future__ import annotations

import os
import textwrap
import unittest
from unittest.mock import patch

from nexaflow_core.config import (
    APIConfig,
    ConsensusConfig,
    GenesisConfig,
    LedgerConfig,
    LoggingConfig,
    NexaFlowConfig,
    NodeConfig,
    StorageConfig,
    TLSConfig,
    _merge,
    load_config,
)

# ═══════════════════════════════════════════════════════════════════
#  Defaults
# ═══════════════════════════════════════════════════════════════════

class TestDefaults(unittest.TestCase):

    def test_node_defaults(self):
        n = NodeConfig()
        self.assertEqual(n.node_id, "validator-1")
        self.assertEqual(n.host, "0.0.0.0")
        self.assertEqual(n.port, 9001)
        self.assertEqual(n.peers, [])

    def test_ledger_defaults(self):
        ledger_cfg = LedgerConfig()
        self.assertEqual(ledger_cfg.total_supply, 100_000_000_000.0)
        self.assertEqual(ledger_cfg.min_fee, 0.000010)

    def test_api_defaults(self):
        a = APIConfig()
        self.assertFalse(a.enabled)
        self.assertEqual(a.host, "127.0.0.1")
        self.assertEqual(a.port, 8080)
        self.assertEqual(a.api_key, "")
        self.assertEqual(a.rate_limit_rpm, 60)
        self.assertEqual(a.cors_origins, [])
        self.assertEqual(a.max_body_bytes, 1_048_576)

    def test_tls_defaults(self):
        t = TLSConfig()
        self.assertTrue(t.enabled)
        self.assertTrue(t.verify_peer)

    def test_consensus_defaults(self):
        c = ConsensusConfig()
        self.assertEqual(c.interval_seconds, 10)
        self.assertEqual(c.initial_threshold, 0.50)
        self.assertEqual(c.final_threshold, 0.80)
        self.assertEqual(c.validator_key_file, "")

    def test_storage_defaults(self):
        s = StorageConfig()
        self.assertTrue(s.enabled)
        self.assertEqual(s.backend, "sqlite")

    def test_genesis_defaults(self):
        g = GenesisConfig()
        self.assertEqual(g.accounts, {})

    def test_logging_defaults(self):
        log_cfg = LoggingConfig()
        self.assertEqual(log_cfg.level, "INFO")
        self.assertEqual(log_cfg.format, "human")
        self.assertIsNone(log_cfg.file)

    def test_nexaflow_config_defaults(self):
        cfg = NexaFlowConfig()
        self.assertIsInstance(cfg.node, NodeConfig)
        self.assertIsInstance(cfg.api, APIConfig)
        self.assertIsInstance(cfg.genesis, GenesisConfig)


# ═══════════════════════════════════════════════════════════════════
#  _merge helper
# ═══════════════════════════════════════════════════════════════════

class TestMerge(unittest.TestCase):

    def test_merge_updates_fields(self):
        n = NodeConfig()
        _merge(n, {"node_id": "my-node", "port": 5555})
        self.assertEqual(n.node_id, "my-node")
        self.assertEqual(n.port, 5555)

    def test_merge_ignores_unknown_keys(self):
        n = NodeConfig()
        _merge(n, {"unknown_field": 42})
        self.assertFalse(hasattr(n, "unknown_field"))

    def test_merge_hyphenated_keys(self):
        """TOML often uses kebab-case; _merge converts to snake_case."""
        n = NodeConfig()
        _merge(n, {"node-id": "kebab-node"})
        self.assertEqual(n.node_id, "kebab-node")

    def test_merge_empty_dict(self):
        n = NodeConfig()
        _merge(n, {})
        self.assertEqual(n.node_id, "validator-1")  # unchanged


# ═══════════════════════════════════════════════════════════════════
#  TOML loading
# ═══════════════════════════════════════════════════════════════════

class TestLoadConfig(unittest.TestCase):

    def test_load_no_file(self):
        """load_config(None) returns defaults."""
        cfg = load_config(None)
        self.assertEqual(cfg.node.port, 9001)

    def test_load_missing_file(self):
        """Non-existent TOML file returns defaults (no crash)."""
        cfg = load_config("/tmp/__nonexistent_config__.toml")
        self.assertEqual(cfg.node.node_id, "validator-1")

    def test_load_toml_file(self, tmp_path=None):
        """Valid TOML file is parsed correctly."""
        import tempfile
        content = textwrap.dedent("""\
            [node]
            node_id = "test-node"
            port = 7777
            peers = ["127.0.0.1:9002", "127.0.0.1:9003"]

            [api]
            enabled = true
            port = 3000
            api_key = "secret123"
            cors_origins = ["http://localhost:3000"]

            [ledger]
            total_supply = 50000.0

            [genesis]
            accounts = { rAlice = 100.0, rBob = 200.0 }
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)

        self.assertEqual(cfg.node.node_id, "test-node")
        self.assertEqual(cfg.node.port, 7777)
        self.assertEqual(len(cfg.node.peers), 2)
        self.assertTrue(cfg.api.enabled)
        self.assertEqual(cfg.api.port, 3000)
        self.assertEqual(cfg.api.api_key, "secret123")
        self.assertEqual(cfg.api.cors_origins, ["http://localhost:3000"])
        self.assertEqual(cfg.ledger.total_supply, 50000.0)
        self.assertEqual(cfg.genesis.accounts["rAlice"], 100.0)
        self.assertEqual(cfg.genesis.accounts["rBob"], 200.0)


# ═══════════════════════════════════════════════════════════════════
#  Environment variable overrides
# ═══════════════════════════════════════════════════════════════════

class TestEnvOverrides(unittest.TestCase):

    @patch.dict(os.environ, {"NEXAFLOW_NODE_ID": "env-node"}, clear=False)
    def test_env_node_id(self):
        cfg = load_config(None)
        self.assertEqual(cfg.node.node_id, "env-node")

    @patch.dict(os.environ, {"NEXAFLOW_HOST": "10.0.0.1"}, clear=False)
    def test_env_host(self):
        cfg = load_config(None)
        self.assertEqual(cfg.node.host, "10.0.0.1")

    @patch.dict(os.environ, {"NEXAFLOW_PORT": "5555"}, clear=False)
    def test_env_port(self):
        cfg = load_config(None)
        self.assertEqual(cfg.node.port, 5555)

    @patch.dict(os.environ, {"NEXAFLOW_PEERS": "a:1, b:2 , c:3"}, clear=False)
    def test_env_peers(self):
        cfg = load_config(None)
        self.assertEqual(cfg.node.peers, ["a:1", "b:2", "c:3"])

    @patch.dict(os.environ, {"NEXAFLOW_API_PORT": "4444"}, clear=False)
    def test_env_api_port(self):
        cfg = load_config(None)
        self.assertEqual(cfg.api.port, 4444)
        self.assertTrue(cfg.api.enabled)  # auto-enabled

    @patch.dict(os.environ, {"NEXAFLOW_LOG_LEVEL": "debug"}, clear=False)
    def test_env_log_level_uppercased(self):
        cfg = load_config(None)
        self.assertEqual(cfg.logging.level, "DEBUG")

    @patch.dict(os.environ, {"NEXAFLOW_LOG_FMT": "json"}, clear=False)
    def test_env_log_format(self):
        cfg = load_config(None)
        self.assertEqual(cfg.logging.format, "json")

    @patch.dict(os.environ, {"NEXAFLOW_DB_PATH": "/tmp/nf.db"}, clear=False)
    def test_env_db_path(self):
        cfg = load_config(None)
        self.assertEqual(cfg.storage.path, "/tmp/nf.db")
        self.assertTrue(cfg.storage.enabled)  # auto-enabled

    @patch.dict(os.environ, {"NEXAFLOW_API_KEY": "my-key"}, clear=False)
    def test_env_api_key(self):
        cfg = load_config(None)
        self.assertEqual(cfg.api.api_key, "my-key")

    @patch.dict(os.environ, {"NEXAFLOW_CORS_ORIGINS": "http://a.com, http://b.com"}, clear=False)
    def test_env_cors_origins(self):
        cfg = load_config(None)
        self.assertEqual(cfg.api.cors_origins, ["http://a.com", "http://b.com"])

    @patch.dict(os.environ, {"NEXAFLOW_PEERS": ""}, clear=False)
    def test_env_empty_peers(self):
        cfg = load_config(None)
        self.assertEqual(cfg.node.peers, [])

    @patch.dict(os.environ, {"NEXAFLOW_CORS_ORIGINS": ""}, clear=False)
    def test_env_empty_cors(self):
        cfg = load_config(None)
        self.assertEqual(cfg.api.cors_origins, [])


# ═══════════════════════════════════════════════════════════════════
#  Env overrides take precedence over TOML
# ═══════════════════════════════════════════════════════════════════

class TestEnvOverridesToml(unittest.TestCase):

    @patch.dict(os.environ, {"NEXAFLOW_PORT": "8888"}, clear=False)
    def test_env_wins_over_toml(self):
        """Environment variable should override the TOML file value."""
        import tempfile
        content = textwrap.dedent("""\
            [node]
            port = 1111
        """)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(cfg.node.port, 8888)  # env wins
