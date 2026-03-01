"""
Test suite for nexaflow_core.amendments — network-voted feature flags.

Covers:
  - Amendment creation, status transitions, and serialization
  - AmendmentManager propose / vote / process_voting_round
  - 80% threshold, sustained majority (configurable voting period)
  - Veto mechanism
  - Lost majority resets timer
  - is_enabled (by name and by ID)
  - Edge cases: double enable, vote on enabled/vetoed
"""

import unittest

from nexaflow_core.amendments import (
    Amendment,
    AmendmentManager,
    AmendmentStatus,
)


class TestAmendment(unittest.TestCase):

    def test_defaults(self):
        a = Amendment(amendment_id="abc", name="FeatureX", description="desc")
        self.assertEqual(a.status, AmendmentStatus.PROPOSED)
        self.assertEqual(len(a.votes_for), 0)

    def test_to_dict(self):
        a = Amendment(amendment_id="abc", name="FeatureX", description="cool")
        d = a.to_dict()
        self.assertEqual(d["name"], "FeatureX")
        self.assertEqual(d["status"], "proposed")


class TestAmendmentManager(unittest.TestCase):

    def setUp(self):
        # Use a short voting period (10 seconds) for tests
        self.mgr = AmendmentManager(voting_period=10.0, threshold=0.80)

    def test_compute_amendment_id_deterministic(self):
        id1 = AmendmentManager.compute_amendment_id("TestFeature")
        id2 = AmendmentManager.compute_amendment_id("TestFeature")
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 64)

    def test_propose(self):
        a = self.mgr.propose("FeatureA", "My feature")
        self.assertEqual(a.status, AmendmentStatus.VOTING)
        self.assertIn(a.amendment_id, self.mgr.amendments)

    def test_propose_idempotent(self):
        a1 = self.mgr.propose("FeatureA")
        a2 = self.mgr.propose("FeatureA")
        self.assertIs(a1, a2)

    def test_vote_for(self):
        a = self.mgr.propose("F")
        accepted = self.mgr.vote(a.amendment_id, "v1", support=True)
        self.assertTrue(accepted)
        self.assertIn("v1", a.votes_for)

    def test_vote_against(self):
        a = self.mgr.propose("F")
        self.mgr.vote(a.amendment_id, "v1", support=False)
        self.assertIn("v1", a.votes_against)

    def test_vote_switch(self):
        a = self.mgr.propose("F")
        self.mgr.vote(a.amendment_id, "v1", support=True)
        self.mgr.vote(a.amendment_id, "v1", support=False)
        self.assertNotIn("v1", a.votes_for)
        self.assertIn("v1", a.votes_against)

    def test_vote_on_nonexistent(self):
        self.assertFalse(self.mgr.vote("fakeid", "v1", True))

    # ── process_voting_round ─────────────────────────────────────

    def test_enable_after_sustained_majority(self):
        a = self.mgr.propose("BigFeature")
        aid = a.amendment_id
        # 10 validators; need 80% = 8
        for i in range(8):
            self.mgr.vote(aid, f"v{i}", True)
        # First round: starts timer
        newly = self.mgr.process_voting_round(10, now=1000.0)
        self.assertEqual(len(newly), 0)
        self.assertGreater(a.first_majority_time, 0)
        # Second round: not enough time
        newly = self.mgr.process_voting_round(10, now=1005.0)
        self.assertEqual(len(newly), 0)
        # Third round: over voting period
        newly = self.mgr.process_voting_round(10, now=1011.0)
        self.assertEqual(len(newly), 1)
        self.assertEqual(a.status, AmendmentStatus.ENABLED)
        self.assertTrue(self.mgr.is_enabled(aid))

    def test_lost_majority_resets_timer(self):
        a = self.mgr.propose("FlipFlop")
        aid = a.amendment_id
        for i in range(8):
            self.mgr.vote(aid, f"v{i}", True)
        self.mgr.process_voting_round(10, now=1000.0)
        self.assertGreater(a.first_majority_time, 0)
        # Remove a vote to go below 80%
        self.mgr.vote(aid, "v0", False)
        self.mgr.process_voting_round(10, now=1005.0)
        self.assertEqual(a.first_majority_time, 0.0)
        # Re-add vote
        self.mgr.vote(aid, "v0", True)
        self.mgr.process_voting_round(10, now=1020.0)
        self.assertEqual(a.first_majority_time, 1020.0)

    def test_below_threshold_never_enables(self):
        a = self.mgr.propose("Unpopular")
        aid = a.amendment_id
        for i in range(5):  # only 50%
            self.mgr.vote(aid, f"v{i}", True)
        self.mgr.process_voting_round(10, now=1000.0)
        self.mgr.process_voting_round(10, now=9999.0)
        self.assertNotEqual(a.status, AmendmentStatus.ENABLED)

    def test_zero_validators(self):
        self.mgr.propose("NoValidators")
        newly = self.mgr.process_voting_round(0, now=1000.0)
        self.assertEqual(len(newly), 0)

    # ── is_enabled ───────────────────────────────────────────────

    def test_is_enabled_by_name(self):
        a = self.mgr.propose("ByName")
        aid = a.amendment_id
        for i in range(10):
            self.mgr.vote(aid, f"v{i}", True)
        self.mgr.process_voting_round(10, now=1000.0)
        self.mgr.process_voting_round(10, now=1011.0)
        self.assertTrue(self.mgr.is_enabled("ByName"))

    def test_is_enabled_false(self):
        self.assertFalse(self.mgr.is_enabled("NonexistentFeature"))

    # ── veto ─────────────────────────────────────────────────────

    def test_veto(self):
        a = self.mgr.propose("VetoMe")
        ok = self.mgr.veto(a.amendment_id)
        self.assertTrue(ok)
        self.assertEqual(a.status, AmendmentStatus.VETOED)

    def test_veto_enabled_fails(self):
        a = self.mgr.propose("AlreadyEnabled")
        a.status = AmendmentStatus.ENABLED
        self.mgr.enabled_amendments.add(a.amendment_id)
        ok = self.mgr.veto(a.amendment_id)
        self.assertFalse(ok)

    def test_vote_on_vetoed_ignored(self):
        a = self.mgr.propose("VetoedFeature")
        self.mgr.veto(a.amendment_id)
        accepted = self.mgr.vote(a.amendment_id, "v1", True)
        self.assertFalse(accepted)

    def test_vote_on_enabled_ignored(self):
        a = self.mgr.propose("EnabledFeature")
        a.status = AmendmentStatus.ENABLED
        accepted = self.mgr.vote(a.amendment_id, "v1", True)
        self.assertFalse(accepted)

    # ── get_all / get_enabled ────────────────────────────────────

    def test_get_all_amendments(self):
        self.mgr.propose("A")
        self.mgr.propose("B")
        all_ = self.mgr.get_all_amendments()
        self.assertEqual(len(all_), 2)

    def test_get_enabled_empty(self):
        self.assertEqual(self.mgr.get_enabled(), [])


if __name__ == "__main__":
    unittest.main()
