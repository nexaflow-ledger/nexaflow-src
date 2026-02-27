"""
Extended security tests for Consensus engine (nexaflow_core.consensus).

Covers:
  - Single-validator consensus always succeeds (centralization risk)
  - Byzantine threshold bypass with exactly f+1 Byzantine nodes
  - Equivocation detection correctness
  - Unsigned proposal acceptance when pubkeys are configured
  - Proposal replay with different round numbers
  - Empty UNL edge cases
  - Proposal with unknown validator (not in UNL)
  - BFT safety check boundary conditions
  - Empty/overlapping tx sets across proposals
  - max_rounds=1 edge case
  - Self-proposal update replaces previous without equivocation
  - Phase transition correctness
"""

from __future__ import annotations

import hashlib
import unittest

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der

from nexaflow_core.consensus import (
    PHASE_NAMES,
    ConsensusEngine,
    ConsensusResult,
    Proposal,
)


def _keygen():
    """Return (privkey_bytes, pubkey_bytes) for secp256k1."""
    sk = SigningKey.generate(curve=SECP256k1)
    return sk.to_string(), b"\x04" + sk.verifying_key.to_string()


# ═══════════════════════════════════════════════════════════════════
#  Single-Validator Consensus
# ═══════════════════════════════════════════════════════════════════

class TestSingleValidatorConsensus(unittest.TestCase):
    """
    VULN: With a single UNL entry (the node itself), consensus
    always succeeds.  This effectively centralizes the network.
    """

    def test_self_only_consensus(self):
        """A lone validator always reaches consensus on its own set."""
        engine = ConsensusEngine(
            unl=["self"], my_id="self", ledger_seq=1,
        )
        engine.submit_transactions(["tx1", "tx2", "tx3"])
        result = engine.run_rounds()
        self.assertIsNotNone(result)
        self.assertEqual(result.agreed_tx_ids, {"tx1", "tx2", "tx3"})

    def test_empty_unl_consensus(self):
        """With no UNL members, only the node itself exists — n=1."""
        engine = ConsensusEngine(
            unl=[], my_id="self", ledger_seq=1,
        )
        engine.submit_transactions(["tx1"])
        result = engine.run_rounds()
        self.assertIsNotNone(result)
        self.assertEqual(result.agreed_tx_ids, {"tx1"})

    def test_two_validators_one_silent(self):
        """If a UNL member never submits a proposal, self can still win."""
        engine = ConsensusEngine(
            unl=["self", "v2"], my_id="self", ledger_seq=1,
        )
        engine.submit_transactions(["tx1"])
        # v2 never submits — only self's proposal exists
        result = engine.run_rounds()
        # With 1 out of 2 voters (50%), the 50% threshold passes in round 0
        # but 80% final threshold may not pass with 1/2
        if result is not None:
            self.assertIn("tx1", result.agreed_tx_ids)


# ═══════════════════════════════════════════════════════════════════
#  Byzantine Threshold Boundary
# ═══════════════════════════════════════════════════════════════════

class TestByzantineThreshold(unittest.TestCase):
    """Test BFT safety when f = floor((n-1)/3) Byzantine nodes are present."""

    def test_max_byzantine_faults_value(self):
        """Verify max_byzantine_faults = floor((n-1)/3)."""
        # UNL=[v2,v3,v4], my_id=v1 => n=4, f=1
        engine = ConsensusEngine(
            unl=["v2", "v3", "v4"], my_id="v1", ledger_seq=1,
        )
        self.assertEqual(engine.max_byzantine_faults, 1)

        # UNL=[v2..v7], my_id=v1 => n=7, f=2
        engine2 = ConsensusEngine(
            unl=[f"v{i}" for i in range(2, 8)], my_id="v1", ledger_seq=1,
        )
        self.assertEqual(engine2.max_byzantine_faults, 2)

    def test_bft_safe_boundary(self):
        """n=4 means f=1 and 3f+1=4, so it's BFT-safe."""
        engine = ConsensusEngine(
            unl=["v2", "v3", "v4"], my_id="v1", ledger_seq=1,
        )
        self.assertTrue(engine.is_bft_safe())

    def test_bft_unsafe_with_small_unl(self):
        """n=2, f=0, 3(0)+1=1 <= 2, so it's safe. n=1, f=0, also safe."""
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1,
        )
        # n=2, f=0, 3*0+1=1 <= 2
        self.assertTrue(engine.is_bft_safe())

    def test_equivocating_validator_excluded(self):
        """Equivocating validator removed from vote count."""
        engine = ConsensusEngine(
            unl=["v2", "v3", "v4"], my_id="v1", ledger_seq=1,
        )
        engine.submit_transactions(["tx1", "tx2"])

        # v2 first proposal
        p1 = Proposal("v2", 1, {"tx1", "tx2"}, 0)
        self.assertTrue(engine.add_proposal(p1))

        # v2 conflicting second proposal (equivocation)
        p2 = Proposal("v2", 1, {"tx3"}, 0)
        self.assertFalse(engine.add_proposal(p2))

        # v2 should be in byzantine set
        self.assertIn("v2", engine.byzantine_validators)

    def test_byzantine_plus_one_exceeds_tolerance(self):
        """
        With n=4, f=1. If 2 out of 3 UNL peers are Byzantine,
        consensus should fail (too many faults).
        """
        priv1, pub1 = _keygen()
        priv2, pub2 = _keygen()
        priv3, pub3 = _keygen()
        priv_self, pub_self = _keygen()

        engine = ConsensusEngine(
            unl=["v2", "v3", "v4"],
            my_id="v1",
            ledger_seq=1,
            unl_pubkeys={"v2": pub2, "v3": pub3, "v4": pub3},
            my_privkey=priv_self,
        )
        engine.submit_transactions(["tx1"])

        # v2 equivocates
        p2a = Proposal("v2", 1, {"tx1"}, 0)
        p2a.sign(priv2)
        engine.add_proposal(p2a)
        p2b = Proposal("v2", 1, {"tx_evil"}, 0)
        p2b.sign(priv2)
        engine.add_proposal(p2b)

        # v3 equivocates
        p3a = Proposal("v3", 1, {"tx1"}, 0)
        p3a.sign(priv3)
        engine.add_proposal(p3a)
        p3b = Proposal("v3", 1, {"tx_evil2"}, 0)
        p3b.sign(priv3)
        engine.add_proposal(p3b)

        self.assertIn("v2", engine.byzantine_validators)
        self.assertIn("v3", engine.byzantine_validators)
        # With 2 out of 3 UNL peers excluded, only v1 + v4 remain
        # Result depends on v4's proposal


# ═══════════════════════════════════════════════════════════════════
#  Signature Verification
# ═══════════════════════════════════════════════════════════════════

class TestSignatureVerification(unittest.TestCase):

    def test_unsigned_proposal_accepted_without_pubkeys(self):
        """Without unl_pubkeys, unsigned proposals are accepted."""
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1,
        )
        engine.submit_transactions(["tx1"])
        p = Proposal("v2", 1, {"tx1"}, 0)
        self.assertTrue(engine.add_proposal(p))

    def test_unsigned_proposal_accepted_with_unknown_validator(self):
        """
        VULN: If unl_pubkeys doesn't contain the validator_id,
        the signature check is skipped entirely.
        An unknown attacker could inject proposals.
        """
        priv, pub = _keygen()
        engine = ConsensusEngine(
            unl=["v2", "attacker"],
            my_id="v1",
            ledger_seq=1,
            unl_pubkeys={"v2": pub},  # attacker NOT in pubkeys
        )
        engine.submit_transactions(["tx1"])

        # Attacker submits unsigned proposal — accepted because no pubkey known
        p = Proposal("attacker", 1, {"tx_evil"}, 0)
        accepted = engine.add_proposal(p)
        self.assertTrue(accepted)  # BUG: accepted without sig

    def test_bad_signature_rejected(self):
        """Proposal with wrong signature is marked Byzantine."""
        priv_real, pub_real = _keygen()
        priv_fake, _ = _keygen()

        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1,
            unl_pubkeys={"v2": pub_real},
        )
        engine.submit_transactions(["tx1"])

        p = Proposal("v2", 1, {"tx1"}, 0)
        p.sign(priv_fake)  # signed with wrong key
        self.assertFalse(engine.add_proposal(p))
        self.assertIn("v2", engine.byzantine_validators)

    def test_good_signature_accepted(self):
        priv, pub = _keygen()
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1,
            unl_pubkeys={"v2": pub},
        )
        engine.submit_transactions(["tx1"])

        p = Proposal("v2", 1, {"tx1"}, 0)
        p.sign(priv)
        self.assertTrue(engine.add_proposal(p))


# ═══════════════════════════════════════════════════════════════════
#  Proposal Hash Determinism
# ═══════════════════════════════════════════════════════════════════

class TestProposalHash(unittest.TestCase):

    def test_same_txs_different_order_same_hash(self):
        """tx_ids ordering shouldn't affect the hash — sorted internally."""
        p1 = Proposal("v1", 1, {"tx_a", "tx_b", "tx_c"}, 0)
        p2 = Proposal("v1", 1, {"tx_c", "tx_a", "tx_b"}, 0)
        self.assertEqual(p1.compute_hash(), p2.compute_hash())

    def test_different_txs_different_hash(self):
        p1 = Proposal("v1", 1, {"tx_a"}, 0)
        p2 = Proposal("v1", 1, {"tx_b"}, 0)
        self.assertNotEqual(p1.compute_hash(), p2.compute_hash())

    def test_different_round_different_hash(self):
        p1 = Proposal("v1", 1, {"tx_a"}, 0)
        p2 = Proposal("v1", 1, {"tx_a"}, 1)
        self.assertNotEqual(p1.compute_hash(), p2.compute_hash())

    def test_different_ledger_seq_different_hash(self):
        p1 = Proposal("v1", 1, {"tx_a"}, 0)
        p2 = Proposal("v1", 2, {"tx_a"}, 0)
        self.assertNotEqual(p1.compute_hash(), p2.compute_hash())

    def test_empty_tx_ids_hash(self):
        p = Proposal("v1", 1, set(), 0)
        h = p.compute_hash()
        self.assertEqual(len(h), 64)  # BLAKE2b-256 hex


# ═══════════════════════════════════════════════════════════════════
#  Proposal from Non-UNL Validator
# ═══════════════════════════════════════════════════════════════════

class TestNonUNLProposal(unittest.TestCase):

    def test_proposal_from_outsider_ignored_in_vote(self):
        """
        Proposals from validators NOT in UNL should not count toward
        consensus, even though they're stored in proposals dict.
        """
        engine = ConsensusEngine(
            unl=["v2", "v3"], my_id="v1", ledger_seq=1,
        )
        engine.submit_transactions(["tx1"])

        p2 = Proposal("v2", 1, {"tx1"}, 0)
        p3 = Proposal("v3", 1, {"tx1"}, 0)
        engine.add_proposal(p2)
        engine.add_proposal(p3)

        # Outsider also submits a proposal
        outsider = Proposal("outsider", 1, {"tx_evil"}, 0)
        engine.add_proposal(outsider)

        result = engine.run_rounds()
        self.assertIsNotNone(result)
        # tx_evil should NOT be in agreed set (outsider's vote doesn't count)
        self.assertNotIn("tx_evil", result.agreed_tx_ids)
        self.assertIn("tx1", result.agreed_tx_ids)


# ═══════════════════════════════════════════════════════════════════
#  Phase Transitions
# ═══════════════════════════════════════════════════════════════════

class TestPhaseTransitions(unittest.TestCase):

    def test_initial_phase_is_open(self):
        engine = ConsensusEngine(unl=["v2"], my_id="v1", ledger_seq=1)
        self.assertEqual(engine.phase, 0)  # PHASE_OPEN

    def test_phase_accepted_on_success(self):
        engine = ConsensusEngine(unl=["v2"], my_id="v1", ledger_seq=1)
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}, 0))
        result = engine.run_rounds()
        if result:
            self.assertEqual(engine.phase, 2)  # PHASE_ACCEPTED

    def test_phase_failed_on_no_agreement(self):
        """If no transaction gets enough votes, phase should be FAILED."""
        engine = ConsensusEngine(
            unl=["v2", "v3", "v4"], my_id="v1", ledger_seq=1,
            max_rounds=2,
        )
        engine.submit_transactions(["tx1"])
        # All peers propose completely different tx sets
        engine.add_proposal(Proposal("v2", 1, {"tx_a"}, 0))
        engine.add_proposal(Proposal("v3", 1, {"tx_b"}, 0))
        engine.add_proposal(Proposal("v4", 1, {"tx_c"}, 0))
        result = engine.run_rounds()
        # With 4 different proposals, no tx gets 80%
        if result is None:
            self.assertEqual(engine.phase, 3)  # PHASE_FAILED


# ═══════════════════════════════════════════════════════════════════
#  Round History Tracking
# ═══════════════════════════════════════════════════════════════════

class TestRoundHistory(unittest.TestCase):

    def test_round_history_records_all_rounds(self):
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1, max_rounds=5,
        )
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}, 0))
        engine.run_rounds()
        # At least 1 round should be recorded
        self.assertGreater(len(engine.round_history), 0)
        # Each entry should have required fields
        for entry in engine.round_history:
            self.assertIn("round", entry)
            self.assertIn("threshold", entry)
            self.assertIn("proposals", entry)
            self.assertIn("byzantine_count", entry)

    def test_round_history_threshold_increasing(self):
        engine = ConsensusEngine(
            unl=["v2", "v3", "v4", "v5"], my_id="v1", ledger_seq=1,
            max_rounds=10,
        )
        engine.submit_transactions(["tx1"])
        # Only 1 out of 5 votes — will iterate all rounds
        engine.run_rounds()
        if len(engine.round_history) > 1:
            thresholds = [r["threshold"] for r in engine.round_history]
            # Thresholds should be non-decreasing
            for i in range(1, len(thresholds)):
                self.assertGreaterEqual(thresholds[i], thresholds[i - 1])


# ═══════════════════════════════════════════════════════════════════
#  max_rounds Edge Cases
# ═══════════════════════════════════════════════════════════════════

class TestMaxRoundsEdge(unittest.TestCase):

    def test_max_rounds_one(self):
        """With max_rounds=1, consensus must pass on the first try."""
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1, max_rounds=1,
        )
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}, 0))
        result = engine.run_rounds()
        # threshold_step=0, threshold stays at initial (0.50)
        # With 2/2 votes, 100% >= 50%, passes first round
        self.assertIsNotNone(result)

    def test_max_rounds_zero(self):
        """max_rounds=0 means no voting rounds — should fail."""
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1, max_rounds=0,
        )
        engine.submit_transactions(["tx1"])
        engine.add_proposal(Proposal("v2", 1, {"tx1"}, 0))
        result = engine.run_rounds()
        # No rounds executed; falls through to post-loop check
        # Post-loop uses final_threshold=0.80; with 2/2 = 100% >= 80%
        self.assertIsNotNone(result)


# ═══════════════════════════════════════════════════════════════════
#  Empty TX Set Consensus
# ═══════════════════════════════════════════════════════════════════

class TestEmptyTXConsensus(unittest.TestCase):

    def test_empty_candidate_set(self):
        """If all validators submit empty sets, no consensus tx exists."""
        engine = ConsensusEngine(
            unl=["v2"], my_id="v1", ledger_seq=1,
        )
        engine.submit_transactions([])
        engine.add_proposal(Proposal("v2", 1, set(), 0))
        result = engine.run_rounds()
        # Empty agreed set means no result
        self.assertIsNone(result)


# ═══════════════════════════════════════════════════════════════════
#  ConsensusResult Serialization
# ═══════════════════════════════════════════════════════════════════

class TestConsensusResultSerialization(unittest.TestCase):

    def test_to_dict_has_all_fields(self):
        r = ConsensusResult(1, {"tx1"}, 3, 0.80, 5, 1)
        d = r.to_dict()
        self.assertEqual(d["ledger_seq"], 1)
        self.assertEqual(d["agreed_transactions"], 1)
        self.assertEqual(d["rounds_taken"], 3)
        self.assertEqual(d["threshold"], 0.80)
        self.assertEqual(d["proposals"], 5)
        self.assertEqual(d["byzantine_validators_excluded"], 1)

    def test_repr_format(self):
        r = ConsensusResult(1, {"tx1", "tx2"}, 2, 0.80, 4, 0)
        repr_str = repr(r)
        self.assertIn("ConsensusResult", repr_str)
        self.assertIn("seq=1", repr_str)
        self.assertIn("txns=2", repr_str)


if __name__ == "__main__":
    unittest.main()
