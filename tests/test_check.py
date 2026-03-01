"""
Test suite for nexaflow_core.check — deferred pull-payment Checks.

Covers:
  - CheckEntry creation, defaults, and serialization
  - can_cash with amount limits, deliver_min, and expiration
  - can_cancel (sender, destination, third-party, expired)
  - CheckManager CRUD
  - Cash and cancel workflows
  - Edge cases: double cash, double cancel, expired check
"""

import unittest

from nexaflow_core.check import CheckEntry, CheckManager


class TestCheckEntry(unittest.TestCase):
    """Tests for the CheckEntry dataclass."""

    def _make(self, **kwargs):
        defaults = dict(
            check_id="chk1", account="rAlice", destination="rBob",
            send_max=100.0, currency="NXF", issuer="", expiration=0,
            create_time=1_000_000.0,
        )
        defaults.update(kwargs)
        return CheckEntry(**defaults)

    def test_defaults(self):
        c = self._make()
        self.assertFalse(c.cashed)
        self.assertFalse(c.cancelled)
        self.assertEqual(c.cashed_amount, 0.0)

    def test_to_dict(self):
        d = self._make().to_dict()
        self.assertEqual(d["check_id"], "chk1")
        self.assertEqual(d["send_max"], 100.0)

    # ── can_cash ─────────────────────────────────────────────────

    def test_cash_full_amount(self):
        c = self._make()
        ok, msg = c.can_cash(100.0, now=1_000_001.0)
        self.assertTrue(ok)

    def test_cash_partial(self):
        c = self._make(send_max=100.0)
        ok, msg = c.can_cash(50.0, now=1_000_001.0)
        self.assertTrue(ok)

    def test_cash_exceeds_send_max(self):
        c = self._make(send_max=100.0)
        ok, msg = c.can_cash(150.0, now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn("exceeds", msg)

    def test_cash_deliver_min_met(self):
        c = self._make(send_max=100.0)
        ok, msg = c.can_cash(50.0, deliver_min=40.0, now=1_000_001.0)
        self.assertTrue(ok)

    def test_cash_deliver_min_not_met(self):
        c = self._make(send_max=100.0)
        ok, msg = c.can_cash(30.0, deliver_min=50.0, now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn("deliver_min", msg)

    def test_cash_expired(self):
        c = self._make(expiration=1_500_000)
        ok, msg = c.can_cash(50.0, now=1_600_000.0)
        self.assertFalse(ok)
        self.assertIn("expired", msg)

    def test_cash_already_cashed(self):
        c = self._make()
        c.cashed = True
        ok, msg = c.can_cash(50.0)
        self.assertFalse(ok)

    def test_cash_zero_amount_uses_send_max(self):
        c = self._make(send_max=100.0)
        ok, msg = c.can_cash(0, now=1_000_001.0)
        self.assertTrue(ok)

    # ── can_cancel ───────────────────────────────────────────────

    def test_cancel_by_sender(self):
        c = self._make()
        ok, msg = c.can_cancel("rAlice", now=1_000_001.0)
        self.assertTrue(ok)

    def test_cancel_by_destination(self):
        c = self._make()
        ok, msg = c.can_cancel("rBob", now=1_000_001.0)
        self.assertTrue(ok)

    def test_cancel_by_third_party_rejected(self):
        c = self._make()
        ok, msg = c.can_cancel("rCharlie", now=1_000_001.0)
        self.assertFalse(ok)

    def test_cancel_by_third_party_if_expired(self):
        c = self._make(expiration=1_500_000)
        ok, msg = c.can_cancel("rCharlie", now=1_600_000.0)
        self.assertTrue(ok)


class TestCheckManager(unittest.TestCase):
    """Tests for CheckManager."""

    def setUp(self):
        self.mgr = CheckManager()

    def test_create_and_get(self):
        c = self.mgr.create_check("c1", "rAlice", "rBob", 200.0, now=1000.0)
        self.assertEqual(c.send_max, 200.0)
        self.assertIs(self.mgr.get_check("c1"), c)

    def test_cash_success_full(self):
        self.mgr.create_check("c1", "rAlice", "rBob", 200.0, now=1000.0)
        entry, amount, err = self.mgr.cash_check("c1", 200.0, now=1001.0)
        self.assertEqual(err, "")
        self.assertEqual(amount, 200.0)
        self.assertTrue(entry.cashed)

    def test_cash_success_partial(self):
        self.mgr.create_check("c1", "rAlice", "rBob", 200.0, now=1000.0)
        entry, amount, err = self.mgr.cash_check("c1", 50.0, now=1001.0)
        self.assertEqual(amount, 50.0)

    def test_cash_zero_amount_gets_send_max(self):
        self.mgr.create_check("c1", "rAlice", "rBob", 200.0, now=1000.0)
        entry, amount, err = self.mgr.cash_check("c1", 0.0, now=1001.0)
        self.assertEqual(amount, 200.0)

    def test_cash_nonexistent(self):
        with self.assertRaises(KeyError):
            self.mgr.cash_check("nope")

    def test_double_cash(self):
        self.mgr.create_check("c1", "rAlice", "rBob", 100.0, now=1000.0)
        self.mgr.cash_check("c1", 80.0, now=1001.0)
        entry, amount, err = self.mgr.cash_check("c1", 10.0, now=1002.0)
        self.assertNotEqual(err, "")
        self.assertEqual(amount, 0.0)

    def test_cancel_success(self):
        self.mgr.create_check("c1", "rAlice", "rBob", 100.0, now=1000.0)
        entry, err = self.mgr.cancel_check("c1", "rAlice", now=1001.0)
        self.assertEqual(err, "")
        self.assertTrue(entry.cancelled)

    def test_cancel_nonexistent(self):
        with self.assertRaises(KeyError):
            self.mgr.cancel_check("nope", "rAlice")

    def test_get_checks_for_account(self):
        self.mgr.create_check("c1", "rAlice", "rBob", 50.0, now=100.0)
        self.mgr.create_check("c2", "rBob", "rAlice", 80.0, now=200.0)
        self.mgr.create_check("c3", "rCharlie", "rDave", 90.0, now=300.0)
        result = self.mgr.get_checks_for_account("rAlice")
        self.assertEqual(len(result), 2)

    def test_pending_count(self):
        self.mgr.create_check("c1", "rA", "rB", 50.0, now=100.0)
        self.mgr.create_check("c2", "rA", "rC", 60.0, now=200.0)
        self.assertEqual(self.mgr.get_pending_count(), 2)
        self.mgr.cash_check("c1", 50.0, now=300.0)
        self.assertEqual(self.mgr.get_pending_count(), 1)

    def test_iou_check(self):
        c = self.mgr.create_check("c1", "rAlice", "rBob", 100.0,
                                  currency="USD", issuer="rGateway", now=1000.0)
        self.assertEqual(c.currency, "USD")
        self.assertEqual(c.issuer, "rGateway")


if __name__ == "__main__":
    unittest.main()
