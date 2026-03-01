"""
Test suite for nexaflow_core.payment_channel — off-ledger micropayment channels.

Covers:
  - PaymentChannel creation, defaults, and serialization
  - can_claim validation (balance monotonicity, expiration)
  - can_close (destination immediate, creator settle delay)
  - PaymentChannelManager CRUD
  - fund_channel
  - Claim workflow with payouts
  - Close request workflow with settle delay
  - Edge cases: double close, expired channel, closed channel
"""

import unittest

from nexaflow_core.payment_channel import PaymentChannel, PaymentChannelManager


class TestPaymentChannel(unittest.TestCase):
    """Tests for the PaymentChannel dataclass."""

    def _make_channel(self, **kwargs):
        defaults = dict(
            channel_id="ch1", account="rAlice", destination="rBob",
            amount=1000.0, balance=0.0, settle_delay=3600,
            public_key="", cancel_after=0, create_time=1_000_000.0,
        )
        defaults.update(kwargs)
        return PaymentChannel(**defaults)

    def test_available(self):
        ch = self._make_channel(amount=500.0, balance=200.0)
        self.assertAlmostEqual(ch.available, 300.0)

    def test_available_capped_at_zero(self):
        ch = self._make_channel(amount=100.0, balance=150.0)
        self.assertEqual(ch.available, 0.0)

    def test_can_claim_valid(self):
        ch = self._make_channel(amount=500.0, balance=100.0)
        ok, msg = ch.can_claim(200.0, now=1_000_001.0)
        self.assertTrue(ok)

    def test_can_claim_less_than_balance(self):
        ch = self._make_channel(amount=500.0, balance=200.0)
        ok, msg = ch.can_claim(100.0, now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn(">=", msg)

    def test_can_claim_exceeds_amount(self):
        ch = self._make_channel(amount=500.0, balance=0.0)
        ok, msg = ch.can_claim(600.0, now=1_000_001.0)
        self.assertFalse(ok)
        self.assertIn("exceeds", msg)

    def test_can_claim_expired(self):
        ch = self._make_channel(cancel_after=1_500_000)
        ok, msg = ch.can_claim(100.0, now=1_600_000.0)
        self.assertFalse(ok)
        self.assertIn("expired", msg)

    def test_can_claim_closed(self):
        ch = self._make_channel()
        ch.closed = True
        ok, msg = ch.can_claim(100.0)
        self.assertFalse(ok)

    def test_can_close_destination_immediate(self):
        ch = self._make_channel()
        ok, msg = ch.can_close("rBob", now=1_000_001.0)
        self.assertTrue(ok)

    def test_can_close_creator_first_request(self):
        ch = self._make_channel(settle_delay=3600)
        ok, msg = ch.can_close("rAlice", now=1_000_001.0)
        self.assertTrue(ok)  # sets close_requested

    def test_can_close_creator_settle_delay_not_elapsed(self):
        ch = self._make_channel(settle_delay=3600)
        ch.close_requested = True
        ch.close_request_time = 1_000_000.0
        ok, msg = ch.can_close("rAlice", now=1_001_000.0)
        self.assertFalse(ok)
        self.assertIn("Settle delay", msg)

    def test_can_close_creator_after_settle_delay(self):
        ch = self._make_channel(settle_delay=3600)
        ch.close_requested = True
        ch.close_request_time = 1_000_000.0
        ok, msg = ch.can_close("rAlice", now=1_003_601.0)
        self.assertTrue(ok)

    def test_can_close_third_party_rejected(self):
        ch = self._make_channel()
        ok, msg = ch.can_close("rCharlie", now=1_000_001.0)
        self.assertFalse(ok)

    def test_to_dict(self):
        d = self._make_channel().to_dict()
        self.assertEqual(d["channel_id"], "ch1")
        self.assertIn("available", d)


class TestPaymentChannelManager(unittest.TestCase):
    """Tests for PaymentChannelManager."""

    def setUp(self):
        self.mgr = PaymentChannelManager()

    def test_create_and_get(self):
        ch = self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        self.assertEqual(ch.amount, 500.0)
        self.assertIs(self.mgr.get_channel("ch1"), ch)

    def test_fund_channel(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        ch = self.mgr.fund_channel("ch1", 200.0)
        self.assertEqual(ch.amount, 700.0)

    def test_fund_closed_channel(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        ch = self.mgr.get_channel("ch1")
        ch.closed = True
        with self.assertRaises(ValueError):
            self.mgr.fund_channel("ch1", 100.0)

    def test_fund_nonexistent(self):
        with self.assertRaises(KeyError):
            self.mgr.fund_channel("nope", 100.0)

    def test_claim_success(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        ch, payout, err = self.mgr.claim("ch1", 200.0, now=1001.0)
        self.assertEqual(err, "")
        self.assertEqual(payout, 200.0)
        self.assertEqual(ch.balance, 200.0)

    def test_claim_incremental(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        self.mgr.claim("ch1", 100.0, now=1001.0)
        ch, payout, err = self.mgr.claim("ch1", 300.0, now=1002.0)
        self.assertEqual(payout, 200.0)
        self.assertEqual(ch.balance, 300.0)

    def test_claim_nonexistent(self):
        with self.assertRaises(KeyError):
            self.mgr.claim("nope", 100.0)

    def test_request_close_destination(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        ch, closed, err = self.mgr.request_close("ch1", "rBob", now=1001.0)
        self.assertTrue(closed)
        self.assertTrue(ch.closed)

    def test_request_close_creator_two_phase(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 500.0, 3600, now=1000.0)
        # Phase 1: request
        ch, closed, err = self.mgr.request_close("ch1", "rAlice", now=1001.0)
        self.assertFalse(closed)
        self.assertTrue(ch.close_requested)
        # Phase 2: early attempt fails
        ch, closed, err = self.mgr.request_close("ch1", "rAlice", now=2000.0)
        self.assertFalse(closed)
        # Phase 3: after settle delay
        ch, closed, err = self.mgr.request_close("ch1", "rAlice", now=4602.0)
        self.assertTrue(closed)

    def test_get_channels_for_account(self):
        self.mgr.create_channel("ch1", "rAlice", "rBob", 100.0, 60, now=100.0)
        self.mgr.create_channel("ch2", "rBob", "rAlice", 200.0, 60, now=200.0)
        self.mgr.create_channel("ch3", "rCharlie", "rDave", 300.0, 60, now=300.0)
        result = self.mgr.get_channels_for_account("rAlice")
        self.assertEqual(len(result), 2)

    def test_total_locked(self):
        self.mgr.create_channel("ch1", "rA", "rB", 500.0, 60, now=100.0)
        self.mgr.claim("ch1", 200.0, now=200.0)
        self.mgr.create_channel("ch2", "rA", "rC", 300.0, 60, now=300.0)
        # ch1: 500-200=300, ch2: 300-0=300
        self.assertAlmostEqual(self.mgr.total_locked(), 600.0)


if __name__ == "__main__":
    unittest.main()
