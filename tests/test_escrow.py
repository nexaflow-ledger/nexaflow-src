"""
Test suite for nexaflow_core.escrow — time-locked and condition-locked NXF escrows.

Covers:
  - EscrowEntry creation, defaults, and serialization
  - can_finish with timing, conditions, and fulfillment
  - can_cancel with timing and ownership rules
  - EscrowManager CRUD
  - SHA-256 condition/fulfillment verification
  - Edge cases: double finish/cancel, invalid escrow IDs
"""

import hashlib
import time
import unittest

from nexaflow_core.escrow import EscrowEntry, EscrowManager


class TestEscrowEntry(unittest.TestCase):
    """Tests for the EscrowEntry dataclass."""

    def _make_entry(self, **kwargs):
        defaults = dict(
            escrow_id="esc1", account="rAlice", destination="rBob",
            amount=100.0, condition="", finish_after=0, cancel_after=0,
            create_time=1_000_000.0,
        )
        defaults.update(kwargs)
        return EscrowEntry(**defaults)

    # ── Defaults & serialization ─────────────────────────────────

    def test_defaults(self):
        e = self._make_entry()
        self.assertEqual(e.escrow_id, "esc1")
        self.assertFalse(e.finished)
        self.assertFalse(e.cancelled)

    def test_to_dict(self):
        d = self._make_entry().to_dict()
        self.assertEqual(d["escrow_id"], "esc1")
        self.assertEqual(d["amount"], 100.0)
        self.assertIn("create_time", d)

    # ── can_finish ───────────────────────────────────────────────

    def test_finish_no_conditions(self):
        """Escrow with no time/condition can be finished immediately."""
        e = self._make_entry()
        ok, msg = e.can_finish(now=1_000_001.0)
        self.assertTrue(ok)

    def test_finish_before_finish_after(self):
        e = self._make_entry(finish_after=2_000_000)
        ok, msg = e.can_finish(now=1_500_000.0)
        self.assertFalse(ok)
        self.assertIn("Cannot finish before", msg)

    def test_finish_after_cancel_after(self):
        e = self._make_entry(cancel_after=1_500_000)
        ok, msg = e.can_finish(now=2_000_000.0)
        self.assertFalse(ok)
        self.assertIn("expired", msg)

    def test_finish_with_valid_fulfillment(self):
        secret = "my-secret"
        condition = hashlib.sha256(secret.encode()).hexdigest()
        e = self._make_entry(condition=condition)
        ok, msg = e.can_finish(fulfillment=secret, now=1_000_001.0)
        self.assertTrue(ok)

    def test_finish_with_wrong_fulfillment(self):
        secret = "my-secret"
        condition = hashlib.sha256(secret.encode()).hexdigest()
        e = self._make_entry(condition=condition)
        ok, msg = e.can_finish(fulfillment="wrong-secret", now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn("does not match", msg)

    def test_finish_condition_without_fulfillment(self):
        condition = hashlib.sha256(b"secret").hexdigest()
        e = self._make_entry(condition=condition)
        ok, msg = e.can_finish(now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn("requires fulfillment", msg)

    def test_finish_already_finished(self):
        e = self._make_entry()
        e.finished = True
        ok, msg = e.can_finish(now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn("already resolved", msg)

    def test_finish_already_cancelled(self):
        e = self._make_entry()
        e.cancelled = True
        ok, msg = e.can_finish(now=1_000_001.0)
        self.assertFalse(ok)

    # ── can_cancel ───────────────────────────────────────────────

    def test_cancel_after_cancel_after(self):
        e = self._make_entry(cancel_after=1_500_000)
        ok, msg = e.can_cancel("rAlice", now=1_600_000.0)
        self.assertTrue(ok)

    def test_cancel_before_cancel_after(self):
        e = self._make_entry(cancel_after=1_500_000)
        ok, msg = e.can_cancel("rAlice", now=1_400_000.0)
        self.assertFalse(ok)
        self.assertIn("Cannot cancel before", msg)

    def test_cancel_no_cancel_after(self):
        e = self._make_entry(cancel_after=0)
        ok, msg = e.can_cancel("rAlice", now=9_999_999.0)
        self.assertFalse(ok)
        self.assertIn("cannot be cancelled", msg)


class TestEscrowManager(unittest.TestCase):
    """Tests for EscrowManager."""

    def setUp(self):
        self.mgr = EscrowManager()

    def test_create_and_get(self):
        e = self.mgr.create_escrow("e1", "rAlice", "rBob", 50.0, now=1000.0)
        self.assertEqual(e.amount, 50.0)
        self.assertIs(self.mgr.get_escrow("e1"), e)

    def test_create_invalid_timing(self):
        with self.assertRaises(ValueError):
            self.mgr.create_escrow(
                "e1", "rAlice", "rBob", 10.0,
                finish_after=2000, cancel_after=1000,
            )

    def test_finish_success(self):
        self.mgr.create_escrow("e1", "rAlice", "rBob", 50.0, now=1000.0)
        entry, err = self.mgr.finish_escrow("e1", now=1001.0)
        self.assertEqual(err, "")
        self.assertTrue(entry.finished)

    def test_finish_with_condition(self):
        secret = "payment-proof"
        condition = hashlib.sha256(secret.encode()).hexdigest()
        self.mgr.create_escrow("e2", "rAlice", "rBob", 100.0,
                               condition=condition, now=1000.0)
        entry, err = self.mgr.finish_escrow("e2", fulfillment=secret, now=1001.0)
        self.assertEqual(err, "")
        self.assertTrue(entry.finished)

    def test_finish_nonexistent(self):
        with self.assertRaises(KeyError):
            self.mgr.finish_escrow("nope")

    def test_cancel_success(self):
        self.mgr.create_escrow("e3", "rAlice", "rBob", 25.0,
                               cancel_after=2000, now=1000.0)
        entry, err = self.mgr.cancel_escrow("e3", "rAlice", now=2001.0)
        self.assertEqual(err, "")
        self.assertTrue(entry.cancelled)

    def test_cancel_too_early(self):
        self.mgr.create_escrow("e4", "rAlice", "rBob", 25.0,
                               cancel_after=5000, now=1000.0)
        entry, err = self.mgr.cancel_escrow("e4", "rAlice", now=3000.0)
        self.assertNotEqual(err, "")
        self.assertFalse(entry.cancelled)

    def test_get_escrows_for_account(self):
        self.mgr.create_escrow("e1", "rAlice", "rBob", 10.0, now=100.0)
        self.mgr.create_escrow("e2", "rAlice", "rCharlie", 20.0, now=200.0)
        self.mgr.create_escrow("e3", "rBob", "rAlice", 30.0, now=300.0)
        result = self.mgr.get_escrows_for_account("rAlice")
        self.assertEqual(len(result), 2)

    def test_pending_count_and_total_locked(self):
        self.mgr.create_escrow("e1", "rA", "rB", 100.0, now=100.0)
        self.mgr.create_escrow("e2", "rA", "rC", 200.0, now=200.0)
        self.assertEqual(self.mgr.get_pending_count(), 2)
        self.assertEqual(self.mgr.total_locked(), 300.0)
        self.mgr.finish_escrow("e1", now=300.0)
        self.assertEqual(self.mgr.get_pending_count(), 1)
        self.assertEqual(self.mgr.total_locked(), 200.0)

    def test_double_finish(self):
        self.mgr.create_escrow("e1", "rA", "rB", 50.0, now=100.0)
        self.mgr.finish_escrow("e1", now=200.0)
        entry, err = self.mgr.finish_escrow("e1", now=300.0)
        self.assertNotEqual(err, "")

    def test_cancel_after_finish(self):
        self.mgr.create_escrow("e1", "rA", "rB", 50.0,
                               cancel_after=5000, now=100.0)
        self.mgr.finish_escrow("e1", now=200.0)
        entry, err = self.mgr.cancel_escrow("e1", "rA", now=6000.0)
        self.assertNotEqual(err, "")


if __name__ == "__main__":
    unittest.main()
