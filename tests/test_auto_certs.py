#!/usr/bin/env python3
"""Quick integration test: auto-generation of BFT consensus keys."""
import os
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from nexaflow_core.config import (
    NexaFlowConfig, ConsensusConfig, WalletConfig, GenesisConfig,
)
from run_node import NexaFlowNode

TEST_DIR = Path("/tmp/nf_cert_test")


@pytest.fixture(autouse=True)
def _clean_test_dir():
    """Ensure a clean temp directory for every test."""
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
    TEST_DIR.mkdir(parents=True)
    yield
    # cleanup handled by next test or OS


def make_cfg():
    cfg = NexaFlowConfig()
    cfg.wallet = WalletConfig(wallet_file=str(TEST_DIR / "wallet.json"))
    cfg.genesis = GenesisConfig(accounts={})
    cfg.consensus = ConsensusConfig(
        auto_generate_keys=True,
        certs_dir=str(TEST_DIR / "certs"),
    )
    return cfg


def test_auto_generate():
    """First run: no keys exist -> they are generated."""
    cfg = make_cfg()
    node = NexaFlowNode("test-validator", "127.0.0.1", 19990, config=cfg)

    key_file = TEST_DIR / "certs" / "test-validator.key"
    pub_file = TEST_DIR / "certs" / "pubkeys" / "test-validator.pub"

    assert key_file.exists(), "private key file not created"
    assert pub_file.exists(), "public key file not created"
    assert len(node._validator_privkey) == 32, f"privkey wrong length: {len(node._validator_privkey)}"
    assert "test-validator" in node._unl_pubkeys, "own pubkey not loaded"

    priv_hex = key_file.read_text().strip()
    pub_hex = pub_file.read_text().strip()
    assert len(priv_hex) == 64, f"priv hex wrong length: {len(priv_hex)}"
    assert len(pub_hex) == 130, f"pub hex wrong length: {len(pub_hex)}"
    assert pub_hex.startswith("04"), "pub key must start with 04"

    # Permissions (Unix only)
    if os.name != "nt":
        assert oct(key_file.stat().st_mode & 0o777) == "0o600"

    # Config auto-populated
    assert cfg.consensus.validator_key_file == str(key_file)
    assert cfg.consensus.validator_pubkeys_dir == str(TEST_DIR / "certs" / "pubkeys")


def test_load_on_restart():
    """Second run: keys exist -> loaded from disk, same key."""
    cfg = make_cfg()
    # First run generates
    node1 = NexaFlowNode("test-validator", "127.0.0.1", 19990, config=cfg)
    expected = node1._validator_privkey

    # Second run loads
    cfg2 = make_cfg()
    node2 = NexaFlowNode("test-validator", "127.0.0.1", 19991, config=cfg2)
    assert node2._validator_privkey == expected, "key changed on restart!"


def test_skip_when_disabled():
    """auto_generate_keys=False and no key file -> no generation."""
    cfg = make_cfg()
    cfg.consensus.auto_generate_keys = False
    cfg.consensus.validator_key_file = ""
    cfg.consensus.validator_pubkeys_dir = ""
    cfg.consensus.certs_dir = str(TEST_DIR / "certs_disabled")

    node = NexaFlowNode("disabled-node", "127.0.0.1", 19992, config=cfg)
    assert node._validator_privkey == b"", "should have empty key when disabled"
    assert not (TEST_DIR / "certs_disabled").exists(), "should not create dir"
