"""
Test suite for nexaflow_core.validator — Transaction validation.

Covers:
  - Signature verification (valid + invalid)
  - Account existence
  - Fee checks (below minimum)
  - Sequence checks
  - Balance / reserve checks (native NXF payment)
  - IOU trust-line checks
  - TrustSet validation
  - validate_batch
"""

import unittest

from nexaflow_core.validator import TransactionValidator, MIN_FEE, ACCOUNT_RESERVE, OWNER_RESERVE
from nexaflow_core.ledger import Ledger
from nexaflow_core.transaction import (
    Amount,
    Transaction,
    create_payment,
    create_trust_set,
    TT_PAYMENT,
    TT_TRUST_SET,
    TES_SUCCESS,
    TEC_UNFUNDED,
    TEC_NO_LINE,
    TEC_INSUF_FEE,
    TEC_BAD_SEQ,
    TEC_BAD_SIG,
)
from nexaflow_core.wallet import Wallet


class ValidatorTestBase(unittest.TestCase):
    """Base class that provides a ledger and validator."""

    def setUp(self):
        self.ledger = Ledger(total_supply=100_000.0, genesis_account="rGen")
        # rAlice has enough for reserves + payments
        self.ledger.create_account("rAlice", 1000.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)
        self.wallet = Wallet.from_seed("alice-seed")


class TestValidatorSignature(ValidatorTestBase):

    def test_valid_signature_passes(self):
        tx = create_payment(self.wallet.address, "rBob", 1.0)
        self.wallet.sign_transaction(tx)
        # Need the wallet address to exist in ledger
        self.ledger.create_account(self.wallet.address, 1000.0)
        ok, code, msg = self.validator.validate(tx)
        self.assertTrue(ok)
        self.assertEqual(code, TES_SUCCESS)

    def test_invalid_signature_fails(self):
        # Sign with one key, then swap the pubkey to a different valid key
        w1 = Wallet.from_seed("key1")
        w2 = Wallet.from_seed("key2")
        self.ledger.create_account(w1.address, 1000.0)
        tx = create_payment(w1.address, "rBob", 1.0)
        w1.sign_transaction(tx)
        # Replace the pubkey with w2's key — signature won't match
        tx.signing_pub_key = w2.public_key
        ok, code, msg = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SIG)

    def test_no_signature_skips_check(self):
        """Without signature/pubkey, the check is skipped — not a failure."""
        tx = create_payment("rAlice", "rBob", 1.0)
        ok, code, msg = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorAccountExists(ValidatorTestBase):

    def test_nonexistent_source_fails(self):
        tx = create_payment("rGhost", "rBob", 1.0)
        ok, code, msg = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_existing_source_passes(self):
        tx = create_payment("rAlice", "rBob", 1.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorFee(ValidatorTestBase):

    def test_fee_below_minimum_fails(self):
        tx = create_payment("rAlice", "rBob", 1.0, fee=0.000001)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_fee_at_minimum_passes(self):
        tx = create_payment("rAlice", "rBob", 1.0, fee=MIN_FEE)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_fee_above_minimum_passes(self):
        tx = create_payment("rAlice", "rBob", 1.0, fee=1.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorSequence(ValidatorTestBase):

    def test_correct_sequence_passes(self):
        acc = self.ledger.get_account("rAlice")
        tx = create_payment("rAlice", "rBob", 1.0, sequence=acc.sequence)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_zero_sequence_skips_check(self):
        tx = create_payment("rAlice", "rBob", 1.0, sequence=0)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_wrong_sequence_fails(self):
        tx = create_payment("rAlice", "rBob", 1.0, sequence=999)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SEQ)


class TestValidatorBalance(ValidatorTestBase):

    def test_sufficient_balance_passes(self):
        # rAlice has 1000, reserve = 20 + 0*5 = 20, payment 1 + fee 0.00001
        tx = create_payment("rAlice", "rBob", 1.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_insufficient_balance_after_reserve_fails(self):
        # rAlice has 1000, reserve=20, try to send 981 (1000 - 981 - 0.00001 < 20)
        tx = create_payment("rAlice", "rBob", 981.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_balance_exactly_at_reserve(self):
        # Send exactly what would leave balance at reserve
        # balance = 1000, reserve = 20, max_send = 1000 - 20 - fee
        max_send = 1000.0 - ACCOUNT_RESERVE - 0.00001
        tx = create_payment("rAlice", "rBob", max_send)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorIOU(ValidatorTestBase):

    def setUp(self):
        super().setUp()
        self.ledger.create_account("rGW", 1000.0)
        self.ledger.set_trust_line("rAlice", "USD", "rGW", 500.0)

    def test_iou_with_trust_line_passes(self):
        tx = create_payment("rAlice", "rBob", 10.0, "USD", "rGW")
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_iou_without_trust_line_fails(self):
        tx = create_payment("rBob", "rAlice", 10.0, "USD", "rGW")
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_NO_LINE)

    def test_iou_issuer_can_send_without_trust_line(self):
        tx = create_payment("rGW", "rAlice", 10.0, "USD", "rGW")
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_iou_no_native_for_fee(self):
        # Create account with 0 native balance
        self.ledger.create_account("rBroke", 0.0)
        self.ledger.set_trust_line("rBroke", "USD", "rGW", 100.0)
        tx = create_payment("rBroke", "rAlice", 10.0, "USD", "rGW")
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)


class TestValidatorTrustSet(ValidatorTestBase):

    def test_trust_set_valid(self):
        tx = create_trust_set("rAlice", "EUR", "rBank", 500.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_trust_set_no_balance_for_fee(self):
        self.ledger.create_account("rPoor", 0.0)
        tx = create_trust_set("rPoor", "EUR", "rBank", 500.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)


class TestValidateBatch(ValidatorTestBase):

    def test_batch_returns_list(self):
        tx1 = create_payment("rAlice", "rBob", 1.0)
        tx2 = create_payment("rGhost", "rBob", 1.0)
        results = self.validator.validate_batch([tx1, tx2])
        self.assertEqual(len(results), 2)
        # First should pass, second should fail
        self.assertTrue(results[0][1])   # valid
        self.assertFalse(results[1][1])  # invalid

    def test_batch_empty(self):
        results = self.validator.validate_batch([])
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
