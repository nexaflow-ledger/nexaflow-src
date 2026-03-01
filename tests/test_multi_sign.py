"""
Test suite for nexaflow_core.multi_sign — regular keys and M-of-N multi-signing.

Covers:
  - SignerEntry and SignerList basics
  - SignerList.validate_quorum
  - SignerList.from_entries
  - MultiSignManager regular key CRUD
  - Signer list management (set, get, delete)
  - is_authorized_signer logic (master, regular, multi-sign)
  - validate_multi_sig quorum checks
  - Edge cases: duplicate signers, self in signer list, weight < quorum
"""

import unittest

from nexaflow_core.multi_sign import (
    MultiSignManager,
    SignerEntry,
    SignerList,
)


class TestSignerEntry(unittest.TestCase):

    def test_basic(self):
        se = SignerEntry(account="rSigner1", weight=3)
        self.assertEqual(se.account, "rSigner1")
        self.assertEqual(se.weight, 3)


class TestSignerList(unittest.TestCase):

    def test_total_weight(self):
        sl = SignerList(
            signer_quorum=5,
            signers=[
                SignerEntry("rA", 3),
                SignerEntry("rB", 2),
                SignerEntry("rC", 1),
            ],
        )
        self.assertEqual(sl.total_weight(), 6)

    def test_validate_quorum_met(self):
        sl = SignerList(
            signer_quorum=4,
            signers=[SignerEntry("rA", 3), SignerEntry("rB", 2)],
        )
        met, achieved = sl.validate_quorum({"rA", "rB"})
        self.assertTrue(met)
        self.assertEqual(achieved, 5)

    def test_validate_quorum_not_met(self):
        sl = SignerList(
            signer_quorum=4,
            signers=[SignerEntry("rA", 2), SignerEntry("rB", 1)],
        )
        met, achieved = sl.validate_quorum({"rA"})
        self.assertFalse(met)
        self.assertEqual(achieved, 2)

    def test_validate_quorum_subset(self):
        sl = SignerList(
            signer_quorum=3,
            signers=[SignerEntry("rA", 2), SignerEntry("rB", 2), SignerEntry("rC", 2)],
        )
        met, achieved = sl.validate_quorum({"rA", "rC"})
        self.assertTrue(met)
        self.assertEqual(achieved, 4)

    def test_validate_quorum_unknown_signer(self):
        sl = SignerList(
            signer_quorum=3,
            signers=[SignerEntry("rA", 2), SignerEntry("rB", 2)],
        )
        met, achieved = sl.validate_quorum({"rX", "rY"})
        self.assertFalse(met)
        self.assertEqual(achieved, 0)

    def test_from_entries(self):
        sl = SignerList.from_entries(3, [
            {"account": "rA", "weight": 2},
            {"account": "rB", "weight": 2},
        ])
        self.assertEqual(sl.signer_quorum, 3)
        self.assertEqual(len(sl.signers), 2)

    def test_to_dict(self):
        sl = SignerList(signer_quorum=3, signers=[SignerEntry("rA", 3)])
        d = sl.to_dict()
        self.assertEqual(d["signer_quorum"], 3)
        self.assertEqual(len(d["signers"]), 1)


class TestMultiSignManager(unittest.TestCase):

    def setUp(self):
        self.mgr = MultiSignManager()

    # ── Regular key ──────────────────────────────────────────────

    def test_set_and_get_regular_key(self):
        self.mgr.set_regular_key("rAlice", "rRegular")
        self.assertEqual(self.mgr.get_regular_key("rAlice"), "rRegular")

    def test_remove_regular_key(self):
        self.mgr.set_regular_key("rAlice", "rRegular")
        self.mgr.set_regular_key("rAlice", "")
        self.assertIsNone(self.mgr.get_regular_key("rAlice"))

    def test_get_regular_key_none(self):
        self.assertIsNone(self.mgr.get_regular_key("rNoone"))

    # ── Signer list ──────────────────────────────────────────────

    def test_set_signer_list(self):
        sl = self.mgr.set_signer_list("rAlice", 3, [
            {"account": "rBob", "weight": 2},
            {"account": "rCharlie", "weight": 2},
        ])
        self.assertEqual(sl.signer_quorum, 3)
        self.assertIs(self.mgr.get_signer_list("rAlice"), sl)

    def test_delete_signer_list(self):
        self.mgr.set_signer_list("rAlice", 3, [
            {"account": "rBob", "weight": 3},
        ])
        self.mgr.set_signer_list("rAlice", 0, [])
        self.assertIsNone(self.mgr.get_signer_list("rAlice"))

    def test_weight_less_than_quorum(self):
        with self.assertRaises(ValueError):
            self.mgr.set_signer_list("rAlice", 10, [
                {"account": "rBob", "weight": 2},
            ])

    def test_duplicate_signers(self):
        with self.assertRaises(ValueError):
            self.mgr.set_signer_list("rAlice", 2, [
                {"account": "rBob", "weight": 1},
                {"account": "rBob", "weight": 1},
            ])

    def test_self_in_signer_list(self):
        with self.assertRaises(ValueError):
            self.mgr.set_signer_list("rAlice", 1, [
                {"account": "rAlice", "weight": 1},
            ])

    # ── is_authorized_signer ─────────────────────────────────────

    def test_master_key_always_authorized(self):
        self.assertTrue(self.mgr.is_authorized_signer("rAlice", "rAlice"))

    def test_regular_key_authorized(self):
        self.mgr.set_regular_key("rAlice", "rRegular")
        self.assertTrue(self.mgr.is_authorized_signer("rAlice", "rRegular"))

    def test_multi_sign_member_authorized(self):
        self.mgr.set_signer_list("rAlice", 2, [
            {"account": "rBob", "weight": 2},
        ])
        self.assertTrue(self.mgr.is_authorized_signer("rAlice", "rBob"))

    def test_unauthorized_signer(self):
        self.assertFalse(self.mgr.is_authorized_signer("rAlice", "rStranger"))

    # ── validate_multi_sig ───────────────────────────────────────

    def test_validate_multi_sig_success(self):
        self.mgr.set_signer_list("rAlice", 3, [
            {"account": "rBob", "weight": 2},
            {"account": "rCharlie", "weight": 2},
        ])
        ok, msg = self.mgr.validate_multi_sig("rAlice", {"rBob", "rCharlie"})
        self.assertTrue(ok)

    def test_validate_multi_sig_insufficient(self):
        self.mgr.set_signer_list("rAlice", 2, [
            {"account": "rBob", "weight": 1},
            {"account": "rCharlie", "weight": 1},
        ])
        # Only one signer (weight 1), but quorum requires 2
        ok, msg = self.mgr.validate_multi_sig("rAlice", {"rBob"})
        self.assertFalse(ok)
        self.assertIn("Quorum not met", msg)

    def test_validate_multi_sig_no_list(self):
        ok, msg = self.mgr.validate_multi_sig("rAlice", {"rBob"})
        self.assertFalse(ok)
        self.assertIn("No signer list", msg)


if __name__ == "__main__":
    unittest.main()
