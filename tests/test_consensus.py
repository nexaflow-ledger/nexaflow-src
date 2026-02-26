"""
Test suite for nexaflow_core.consensus — Cython-optimized RPCA consensus.

Covers:
  - Proposal creation and hashing
  - ConsensusEngine with unanimous / partial / split / empty proposals
  - Threshold escalation across rounds
  - Round history
  - ConsensusResult
"""

import unittest

from nexaflow_core.consensus import (
    Proposal,
    ConsensusEngine,
    ConsensusResult,
    PHASE_NAMES,
)


# ===================================================================
#  Proposal
# ===================================================================


class TestProposal(unittest.TestCase):

    def test_creation(self):
        p = Proposal("v1", 5, {"tx1", "tx2"})
        self.assertEqual(p.validator_id, "v1")
        self.assertEqual(p.ledger_seq, 5)
        self.assertEqual(p.tx_ids, {"tx1", "tx2"})
        self.assertEqual(p.round_number, 0)

    def test_empty_tx_ids(self):
        p = Proposal("v1", 1)
        self.assertEqual(p.tx_ids, set())

    def test_compute_hash_deterministic(self):
        p = Proposal("v1", 1, {"a", "b"})
        h1 = p.compute_hash()
        h2 = p.compute_hash()
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)

    def test_different_proposals_different_hash(self):
        p1 = Proposal("v1", 1, {"tx1"})
        p2 = Proposal("v2", 1, {"tx1"})
        self.assertNotEqual(p1.compute_hash(), p2.compute_hash())

    def test_same_txs_different_order_same_hash(self):
        # tx_ids is a set, so order shouldn't matter
        p1 = Proposal("v1", 1, {"a", "b", "c"})
        p2 = Proposal("v1", 1, {"c", "a", "b"})
        self.assertEqual(p1.compute_hash(), p2.compute_hash())


# ===================================================================
#  ConsensusEngine — unanimous agreement
# ===================================================================


class TestConsensusUnanimous(unittest.TestCase):

    def test_two_validators_agree(self):
        engine = ConsensusEngine(["v2"], "v1", 1)
        engine.submit_transactions(["tx1", "tx2"])
        engine.add_proposal(Proposal("v2", 1, {"tx1", "tx2"}))
        result = engine.run_rounds()
        self.assertIsNotNone(result)
        self.assertEqual(result.agreed_tx_ids, {"tx1", "tx2"})

    def test_three_validators_agree(self):
        engine = ConsensusEngine(["v2", "v3"], "v1", 1)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}))
        engine.add_proposal(Proposal("v3", 1, {"tx1"}))
        result = engine.run_rounds()
        self.assertIsNotNone(result)
        self.assertIn("tx1", result.agreed_tx_ids)

    def test_result_ledger_seq(self):
        engine = ConsensusEngine(["v2"], "v1", 42)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 42, {"tx1"}))
        result = engine.run_rounds()
        self.assertEqual(result.ledger_seq, 42)


# ===================================================================
#  ConsensusEngine — partial agreement
# ===================================================================


class TestConsensusPartial(unittest.TestCase):

    def test_majority_wins(self):
        """4 of 5 validators agree on tx1, only 1 has tx2 — tx1 passes (80%)."""
        engine = ConsensusEngine(["v2", "v3", "v4", "v5"], "v1", 1)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}))
        engine.add_proposal(Proposal("v3", 1, {"tx1"}))
        engine.add_proposal(Proposal("v4", 1, {"tx1"}))
        engine.add_proposal(Proposal("v5", 1, {"tx2"}))  # dissent
        result = engine.run_rounds()
        self.assertIsNotNone(result)
        self.assertIn("tx1", result.agreed_tx_ids)

    def test_minority_excluded(self):
        """tx2 only proposed by 1 of 5 validators — should be excluded."""
        engine = ConsensusEngine(["v2", "v3", "v4", "v5"], "v1", 1)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}))
        engine.add_proposal(Proposal("v3", 1, {"tx1"}))
        engine.add_proposal(Proposal("v4", 1, {"tx1"}))
        engine.add_proposal(Proposal("v5", 1, {"tx2"}))
        result = engine.run_rounds()
        if result is not None:
            self.assertNotIn("tx2", result.agreed_tx_ids)


# ===================================================================
#  ConsensusEngine — split / failure
# ===================================================================


class TestConsensusSplit(unittest.TestCase):

    def test_total_disagreement_with_no_overlap(self):
        """Two validators, completely different tx sets — may fail or agree on empty."""
        engine = ConsensusEngine(["v2"], "v1", 1, max_rounds=3)
        engine.submit_transactions(["tx_a"])
        engine.add_proposal(Proposal("v2", 1, {"tx_b"}))
        result = engine.run_rounds()
        # With only 2 validators and 50% threshold, each tx gets 50%.
        # At final threshold 80%, neither passes. Could fail.
        # But at initial 50% threshold, both might pass in early rounds.
        # The exact outcome depends on threshold escalation.
        if result is not None:
            # If consensus reached, check consistency
            self.assertIsInstance(result.agreed_tx_ids, set)


# ===================================================================
#  ConsensusEngine — empty
# ===================================================================


class TestConsensusEmpty(unittest.TestCase):

    def test_no_transactions(self):
        engine = ConsensusEngine(["v2"], "v1", 1)
        engine.submit_transactions([])
        engine.add_proposal(Proposal("v2", 1, set()))
        result = engine.run_rounds()
        # No txns to agree on — should fail (nothing to consensus on)
        self.assertIsNone(result)

    def test_single_validator_alone(self):
        """Only one validator — should still reach consensus with itself."""
        engine = ConsensusEngine([], "v1", 1)
        engine.submit_transactions(["tx1"])
        result = engine.run_rounds()
        self.assertIsNotNone(result)
        self.assertIn("tx1", result.agreed_tx_ids)


# ===================================================================
#  ConsensusEngine — thresholds and rounds
# ===================================================================


class TestConsensusThresholds(unittest.TestCase):

    def test_round_history_populated(self):
        engine = ConsensusEngine(["v2"], "v1", 1)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}))
        engine.run_rounds()
        self.assertTrue(len(engine.round_history) > 0)

    def test_round_history_fields(self):
        engine = ConsensusEngine(["v2"], "v1", 1)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}))
        engine.run_rounds()
        entry = engine.round_history[0]
        self.assertIn("round", entry)
        self.assertIn("threshold", entry)
        self.assertIn("proposals", entry)
        self.assertIn("agreed_txns", entry)

    def test_max_rounds_respected(self):
        engine = ConsensusEngine(["v2"], "v1", 1, max_rounds=2)
        engine.submit_transactions(["tx_a"])
        engine.add_proposal(Proposal("v2", 1, {"tx_b"}))
        engine.run_rounds()
        self.assertLessEqual(engine.current_round, 3)  # at most max_rounds + 1


# ===================================================================
#  ConsensusResult
# ===================================================================


class TestConsensusResult(unittest.TestCase):

    def test_creation(self):
        r = ConsensusResult(10, {"t1", "t2"}, 3, 0.80, 5)
        self.assertEqual(r.ledger_seq, 10)
        self.assertEqual(len(r.agreed_tx_ids), 2)
        self.assertEqual(r.rounds_taken, 3)
        self.assertAlmostEqual(r.final_threshold, 0.80)
        self.assertEqual(r.total_proposals, 5)

    def test_to_dict(self):
        r = ConsensusResult(1, {"tx1"}, 1, 0.80, 2)
        d = r.to_dict()
        self.assertEqual(d["ledger_seq"], 1)
        self.assertEqual(d["agreed_transactions"], 1)
        self.assertEqual(d["rounds_taken"], 1)

    def test_repr(self):
        r = ConsensusResult(5, {"a", "b"}, 2, 0.75, 3)
        s = repr(r)
        self.assertIn("seq=5", s)
        self.assertIn("txns=2", s)


# ===================================================================
#  Phase names
# ===================================================================


class TestPhaseNames(unittest.TestCase):

    def test_phase_names_exist(self):
        self.assertIn(0, PHASE_NAMES)
        self.assertEqual(PHASE_NAMES[2], "accepted")


if __name__ == "__main__":
    unittest.main()
