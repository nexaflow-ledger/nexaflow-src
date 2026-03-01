"""
Extended security tests for Config and Network modules.

Config (nexaflow_core.config):
  - Non-numeric NEXAFLOW_PORT env var causes crash (unhandled ValueError)
  - Environment variable injection / override precedence
  - Malformed TOML file handling
  - Path traversal in file paths
  - Missing TOML file handling
  - Empty / whitespace env var values
  - CORS origins injection

Network (nexaflow_core.network):
  - fund_account bypasses transaction validation
  - fund_account with negative amount (steal from genesis)
  - Consensus with no validators
  - UNL manipulation (full mesh assumption)
  - Transaction pool pollution (invalid txns kept)
  - Double-apply after consensus
  - Network with single validator (centralization)
"""

from __future__ import annotations

import os
import tempfile
import unittest

from nexaflow_core.config import NexaFlowConfig, load_config
from nexaflow_core.ledger import Ledger
from nexaflow_core.network import Network, ValidatorNode

# ═══════════════════════════════════════════════════════════════════
#  Config: Environment Variable Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestConfigEnvVars(unittest.TestCase):

    def setUp(self):
        self._saved = {}
        self._keys = [
            "NEXAFLOW_NODE_ID", "NEXAFLOW_HOST", "NEXAFLOW_PORT",
            "NEXAFLOW_PEERS", "NEXAFLOW_API_PORT", "NEXAFLOW_LOG_LEVEL",
            "NEXAFLOW_LOG_FMT", "NEXAFLOW_DB_PATH", "NEXAFLOW_API_KEY",
            "NEXAFLOW_CORS_ORIGINS",
        ]
        for k in self._keys:
            self._saved[k] = os.environ.pop(k, None)

    def tearDown(self):
        for k in self._keys:
            if self._saved[k] is not None:
                os.environ[k] = self._saved[k]
            else:
                os.environ.pop(k, None)

    def test_non_numeric_port_crashes(self):
        """
        VULN: NEXAFLOW_PORT="abc" causes unhandled ValueError in int().
        """
        os.environ["NEXAFLOW_PORT"] = "abc"
        with self.assertRaises(ValueError):
            load_config()

    def test_negative_port(self):
        """Negative port is accepted without validation."""
        os.environ["NEXAFLOW_PORT"] = "-1"
        cfg = load_config()
        self.assertEqual(cfg.node.port, -1)

    def test_zero_port(self):
        os.environ["NEXAFLOW_PORT"] = "0"
        cfg = load_config()
        self.assertEqual(cfg.node.port, 0)

    def test_huge_port(self):
        os.environ["NEXAFLOW_PORT"] = "99999"
        cfg = load_config()
        self.assertEqual(cfg.node.port, 99999)

    def test_env_overrides_toml(self):
        """Environment variables should override TOML values."""
        toml_content = b'[node]\nnode_id = "from_toml"\nport = 9001\n'
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            os.environ["NEXAFLOW_NODE_ID"] = "from_env"
            cfg = load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(cfg.node.node_id, "from_env")

    def test_empty_peers_string(self):
        os.environ["NEXAFLOW_PEERS"] = ""
        cfg = load_config()
        self.assertEqual(cfg.node.peers, [])

    def test_peers_with_spaces(self):
        os.environ["NEXAFLOW_PEERS"] = "  host1:9001 , host2:9002 , "
        cfg = load_config()
        self.assertEqual(cfg.node.peers, ["host1:9001", "host2:9002"])

    def test_cors_origins_injection(self):
        """
        VULN: CORS origins from env are not validated.
        An attacker controlling the env var can set arbitrary origins.
        """
        os.environ["NEXAFLOW_CORS_ORIGINS"] = "*, http://evil.com"
        cfg = load_config()
        self.assertIn("*", cfg.api.cors_origins)
        self.assertIn("http://evil.com", cfg.api.cors_origins)

    def test_api_key_from_env(self):
        os.environ["NEXAFLOW_API_KEY"] = "secret_key_123"
        cfg = load_config()
        self.assertEqual(cfg.api.api_key, "secret_key_123")

    def test_db_path_with_path_traversal(self):
        """
        VULN: DB path from env is not sanitized.
        Could write to arbitrary filesystem location.
        """
        os.environ["NEXAFLOW_DB_PATH"] = "/tmp/../../../etc/evil.db"
        cfg = load_config()
        self.assertEqual(cfg.storage.path, "/tmp/../../../etc/evil.db")
        self.assertTrue(cfg.storage.enabled)


# ═══════════════════════════════════════════════════════════════════
#  Config: TOML File Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestConfigTOML(unittest.TestCase):

    def setUp(self):
        # Clear env vars
        for k in ["NEXAFLOW_NODE_ID", "NEXAFLOW_PORT", "NEXAFLOW_PEERS",
                   "NEXAFLOW_API_PORT", "NEXAFLOW_LOG_LEVEL", "NEXAFLOW_HOST",
                   "NEXAFLOW_LOG_FMT", "NEXAFLOW_DB_PATH", "NEXAFLOW_API_KEY",
                   "NEXAFLOW_CORS_ORIGINS"]:
            os.environ.pop(k, None)

    def test_nonexistent_file(self):
        """Non-existent TOML file should return defaults."""
        cfg = load_config("/nonexistent/path/config.toml")
        self.assertEqual(cfg.node.node_id, "validator-1")
        self.assertEqual(cfg.node.port, 9001)

    def test_empty_toml(self):
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            f.write(b"")
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(cfg.node.node_id, "validator-1")

    def test_malformed_toml(self):
        """Malformed TOML should raise an error."""
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            f.write(b"this is not valid TOML {{{{ garbage")
            f.flush()
            with self.assertRaises(Exception):  # noqa: B017
                load_config(f.name)
        os.unlink(f.name)

    def test_extra_unknown_keys_ignored(self):
        toml_content = b'[node]\nnode_id = "v1"\nunknown_key = "value"\n'
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        self.assertEqual(cfg.node.node_id, "v1")

    def test_wrong_type_in_toml(self):
        """String where int expected — _merge just sets it."""
        toml_content = b'[node]\nport = "not_a_number"\n'
        with tempfile.NamedTemporaryFile(suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()
            cfg = load_config(f.name)
        os.unlink(f.name)
        # Port is now a string, not validated
        self.assertEqual(cfg.node.port, "not_a_number")

    def test_none_path(self):
        cfg = load_config(None)
        self.assertIsInstance(cfg, NexaFlowConfig)


# ═══════════════════════════════════════════════════════════════════
#  Config: Default Values
# ═══════════════════════════════════════════════════════════════════

class TestConfigDefaults(unittest.TestCase):

    def setUp(self):
        for k in ["NEXAFLOW_NODE_ID", "NEXAFLOW_PORT", "NEXAFLOW_PEERS",
                   "NEXAFLOW_API_PORT", "NEXAFLOW_LOG_LEVEL", "NEXAFLOW_HOST",
                   "NEXAFLOW_LOG_FMT", "NEXAFLOW_DB_PATH", "NEXAFLOW_API_KEY",
                   "NEXAFLOW_CORS_ORIGINS"]:
            os.environ.pop(k, None)

    def test_defaults(self):
        cfg = load_config()
        self.assertEqual(cfg.node.port, 9001)
        self.assertEqual(cfg.ledger.total_supply, 100_000_000_000.0)
        self.assertEqual(cfg.consensus.initial_threshold, 0.50)
        self.assertEqual(cfg.consensus.final_threshold, 0.80)
        self.assertFalse(cfg.api.enabled)
        self.assertFalse(cfg.storage.enabled)
        self.assertFalse(cfg.tls.enabled)


# ═══════════════════════════════════════════════════════════════════
#  Network: fund_account Bypass
# ═══════════════════════════════════════════════════════════════════

class TestNetworkFundAccountBypass(unittest.TestCase):

    def setUp(self):
        self.network = Network()
        self.network.add_validator("v1")

    def test_fund_account_bypasses_validation(self):
        """
        VULN: fund_account directly manipulates balances without
        creating a transaction. No signatures, no fees, no validation.
        """
        self.network.fund_account("alice", 1000.0)
        node = self.network.nodes["v1"]
        alice = node.ledger.get_account("alice")
        self.assertIsNotNone(alice)
        self.assertEqual(alice.balance, 1000.0)

    def test_fund_negative_amount_steals_from_genesis(self):
        """
        VULN: fund_account with negative amount increases genesis balance
        and decreases target balance.
        """
        self.network.fund_account("alice", 1000.0)
        node = self.network.nodes["v1"]
        genesis_before = node.ledger.get_account(node.ledger.genesis_account).balance

        self.network.fund_account("alice", -500.0)
        genesis_after = node.ledger.get_account(node.ledger.genesis_account).balance
        alice_after = node.ledger.get_account("alice").balance

        self.assertEqual(alice_after, 500.0)
        self.assertEqual(genesis_after, genesis_before + 500.0)

    def test_fund_zero_amount(self):
        """Fund with zero is a no-op but creates the account."""
        self.network.fund_account("alice", 0.0)
        node = self.network.nodes["v1"]
        alice = node.ledger.get_account("alice")
        self.assertIsNotNone(alice)
        self.assertEqual(alice.balance, 0.0)

    def test_fund_more_than_genesis_balance(self):
        """
        Test: Funding more than genesis has — fund_account checks
        genesis.balance >= amount, so excess funding is silently skipped.
        This is safe but may confuse callers expecting the funds to arrive.
        """
        node = self.network.nodes["v1"]
        genesis = node.ledger.get_account(node.ledger.genesis_account)
        total = genesis.balance

        self.network.fund_account("alice", total + 1000)
        alice = node.ledger.get_account("alice")
        # fund_account has a guard: genesis.balance >= amount
        # So either alice got nothing (guard triggered) or genesis went negative
        genesis_after = node.ledger.get_account(node.ledger.genesis_account).balance
        self.assertTrue(
            genesis_after >= 0 or alice.balance == 0,
            "fund_account should guard against over-funding"
        )


# ═══════════════════════════════════════════════════════════════════
#  Network: Consensus Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestNetworkConsensus(unittest.TestCase):

    def test_consensus_no_validators(self):
        network = Network()
        result = network.run_consensus_round()
        self.assertEqual(result["error"], "No validators")

    def test_consensus_single_validator(self):
        """Single validator always achieves consensus."""
        network = Network()
        network.add_validator("v1")
        result = network.run_consensus_round()
        # No pending txns → nothing to agree on
        self.assertEqual(result.get("agreed_transactions", 0), 0)

    def test_consensus_with_empty_tx_pool(self):
        """Consensus on empty transaction pools."""
        network = Network()
        network.add_validator("v1")
        network.add_validator("v2")
        result = network.run_consensus_round()
        # No transactions to agree on
        self.assertIn(result.get("status"), ["no_consensus", "consensus_reached"])


# ═══════════════════════════════════════════════════════════════════
#  Network: UNL Manipulation
# ═══════════════════════════════════════════════════════════════════

class TestUNLManipulation(unittest.TestCase):

    def test_full_mesh_unl(self):
        """Adding validators creates full-mesh UNL."""
        network = Network()
        network.add_validator("v1")
        network.add_validator("v2")
        network.add_validator("v3")
        self.assertEqual(set(network.nodes["v1"].unl), {"v2", "v3"})
        self.assertEqual(set(network.nodes["v2"].unl), {"v1", "v3"})
        self.assertEqual(set(network.nodes["v3"].unl), {"v1", "v2"})

    def test_unl_modification(self):
        """
        VULN: UNL is a plain list — can be modified externally
        to exclude validators and influence consensus.
        """
        network = Network()
        network.add_validator("v1")
        network.add_validator("v2")
        network.add_validator("v3")

        # Malicious modification: v1 only trusts itself
        network.nodes["v1"].unl = []
        self.assertEqual(len(network.nodes["v1"].unl), 0)


# ═══════════════════════════════════════════════════════════════════
#  Network: ValidatorNode Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestValidatorNode(unittest.TestCase):

    def test_status_format(self):
        ledger = Ledger()
        node = ValidatorNode("v1", ledger, ["v2"])
        status = node.status()
        self.assertEqual(status["node_id"], "v1")
        self.assertEqual(status["pending_txns"], 0)
        self.assertEqual(status["unl_size"], 1)

    def test_create_proposal_empty_pool(self):
        ledger = Ledger()
        node = ValidatorNode("v1", ledger)
        prop = node.create_proposal()
        self.assertEqual(prop.tx_ids, set())
        self.assertEqual(prop.validator_id, "v1")

    def test_apply_consensus_unknown_tx_id(self):
        """Applying tx_ids not in the pool should be silently skipped."""
        ledger = Ledger()
        node = ValidatorNode("v1", ledger)
        applied = node.apply_consensus_result({"nonexistent_tx"})
        self.assertEqual(len(applied), 0)


# ═══════════════════════════════════════════════════════════════════
#  Network: Multi-Node State Divergence
# ═══════════════════════════════════════════════════════════════════

class TestStateDivergence(unittest.TestCase):

    def test_fund_account_syncs_all_nodes(self):
        """fund_account should apply to all nodes."""
        network = Network()
        network.add_validator("v1")
        network.add_validator("v2")
        network.fund_account("alice", 1000.0)

        for nid, node in network.nodes.items():
            alice = node.ledger.get_account("alice")
            self.assertIsNotNone(alice, f"alice missing on {nid}")
            self.assertEqual(alice.balance, 1000.0, f"wrong balance on {nid}")


if __name__ == "__main__":
    unittest.main()
