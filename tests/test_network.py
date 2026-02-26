"""
Test suite for nexaflow_core.network — Simulated network & validator nodes.

Covers:
  - ValidatorNode: receive_transaction, create_proposal, apply_consensus_result, status
  - Network: add_validator, broadcast_transaction, run_consensus_round
"""

import unittest

from nexaflow_core.network import ValidatorNode, Network
from nexaflow_core.ledger import Ledger
from nexaflow_core.transaction import create_payment, create_trust_set, Amount
from nexaflow_core.wallet import Wallet


class TestValidatorNode(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.node = ValidatorNode("node1", self.ledger, unl=["node2"])

    def test_status(self):
        s = self.node.status()
        self.assertEqual(s["node_id"], "node1")
        self.assertIn("ledger_seq", s)
        self.assertIn("pending_txns", s)

    def test_receive_valid_transaction(self):
        w = Wallet.from_seed("alice-seed")
        self.ledger.create_account(w.address, 500.0)
        tx = create_payment(w.address, "rBob", 10.0)
        w.sign_transaction(tx)
        accepted, code, msg = self.node.receive_transaction(tx)
        self.assertTrue(accepted)
        self.assertIn(tx.tx_id, self.node.tx_pool)

    def test_receive_invalid_transaction(self):
        tx = create_payment("rGhost", "rBob", 10.0)
        accepted, code, msg = self.node.receive_transaction(tx)
        self.assertFalse(accepted)
        self.assertEqual(len(self.node.tx_pool), 0)

    def test_create_proposal(self):
        w = Wallet.from_seed("alice-seed")
        self.ledger.create_account(w.address, 500.0)
        tx = create_payment(w.address, "rBob", 5.0)
        w.sign_transaction(tx)
        self.node.receive_transaction(tx)
        prop = self.node.create_proposal()
        self.assertEqual(prop.validator_id, "node1")
        self.assertIn(tx.tx_id, prop.tx_ids)

    def test_apply_consensus_result(self):
        w = Wallet.from_seed("alice-seed")
        self.ledger.create_account(w.address, 500.0)
        tx = create_payment(w.address, "rBob", 10.0)
        w.sign_transaction(tx)
        self.node.receive_transaction(tx)
        applied = self.node.apply_consensus_result({tx.tx_id})
        self.assertEqual(len(applied), 1)
        self.assertEqual(self.node.closed_count, 1)
        # tx should be removed from pool
        self.assertNotIn(tx.tx_id, self.node.tx_pool)

    def test_get_path_finder(self):
        pf = self.node.get_path_finder()
        self.assertIsNotNone(pf)


class TestNetwork(unittest.TestCase):

    def setUp(self):
        self.net = Network(total_supply=10000.0)

    def test_add_validator(self):
        node = self.net.add_validator("v1")
        self.assertEqual(node.node_id, "v1")
        self.assertIn("v1", self.net.nodes)

    def test_add_multiple_validators_unl(self):
        self.net.add_validator("v1")
        self.net.add_validator("v2")
        self.net.add_validator("v3")
        # Each should have the others in UNL
        self.assertIn("v2", self.net.nodes["v1"].unl)
        self.assertIn("v1", self.net.nodes["v2"].unl)
        self.assertNotIn("v1", self.net.nodes["v1"].unl)

    def test_broadcast_transaction(self):
        n1 = self.net.add_validator("v1")
        n2 = self.net.add_validator("v2")
        # Fund sender
        for n in [n1, n2]:
            n.ledger.create_account("rAlice", 500.0)
        w = Wallet.from_seed("alice-net")
        for n in [n1, n2]:
            n.ledger.create_account(w.address, 500.0)
        tx = create_payment(w.address, "rBob", 10.0)
        w.sign_transaction(tx)
        results = self.net.broadcast_transaction(tx)
        self.assertEqual(len(results), 2)
        # Both should accept
        for nid, (accepted, code, msg) in results.items():
            self.assertTrue(accepted)

    def test_run_consensus_round_empty(self):
        self.net.add_validator("v1")
        result = self.net.run_consensus_round()
        # No transactions — consensus returns no_consensus
        self.assertIn(result.get("status", result.get("agreed", "")),
                      ["no_consensus", 0])

    def test_run_consensus_with_transaction(self):
        n1 = self.net.add_validator("v1")
        n2 = self.net.add_validator("v2")
        # Create matching accounts on both nodes
        w = Wallet.from_seed("consensus-test")
        for n in [n1, n2]:
            n.ledger.create_account(w.address, 1000.0)
            n.ledger.create_account("rBob", 100.0)
        # Create and broadcast a transaction
        tx = create_payment(w.address, "rBob", 10.0)
        w.sign_transaction(tx)
        self.net.broadcast_transaction(tx)
        # Run consensus
        result = self.net.run_consensus_round()
        # Should apply at least one transaction
        self.assertIn("applied_transactions", result)
        self.assertGreater(result.get("applied_transactions", 0), 0)

    def test_run_consensus_no_validators(self):
        result = self.net.run_consensus_round()
        self.assertIn("error", result)


class TestNetworkLedgerIntegrity(unittest.TestCase):
    """Verify all nodes end up with consistent state after consensus."""

    def test_ledger_consistency(self):
        net = Network(total_supply=10000.0)
        n1 = net.add_validator("v1")
        n2 = net.add_validator("v2")
        n3 = net.add_validator("v3")

        w = Wallet.from_seed("integrity-test")
        for n in [n1, n2, n3]:
            n.ledger.create_account(w.address, 1000.0)
            n.ledger.create_account("rRecv", 0.0)

        tx = create_payment(w.address, "rRecv", 50.0)
        w.sign_transaction(tx)
        net.broadcast_transaction(tx)
        net.run_consensus_round()

        # All nodes should have same ledger sequence
        seqs = {n.ledger.current_sequence for n in [n1, n2, n3]}
        self.assertEqual(len(seqs), 1)


if __name__ == "__main__":
    unittest.main()
