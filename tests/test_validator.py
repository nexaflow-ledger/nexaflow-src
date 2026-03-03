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

from nexaflow_core.ledger import Ledger
from nexaflow_core.transaction import (
    TEC_BAD_SEQ,
    TEC_BAD_SIG,
    TEC_INSUF_FEE,
    TEC_NO_LINE,
    TEC_UNFUNDED,
    TES_SUCCESS,
    create_payment,
    create_trust_set,
)
from nexaflow_core.validator import ACCOUNT_RESERVE, MIN_FEE, TransactionValidator
from nexaflow_core.wallet import Wallet


class ValidatorTestBase(unittest.TestCase):
    """Base class that provides a ledger and validator."""

    def setUp(self):
        self.ledger = Ledger(total_supply=100_000.0, genesis_account="rGen")
        # Create wallets for signing
        self.wallet_alice = Wallet.from_seed("alice-seed")
        self.wallet_bob = Wallet.from_seed("bob-seed")
        self.addr_alice = self.wallet_alice.address
        self.addr_bob = self.wallet_bob.address
        # Fund accounts using the wallet addresses
        self.ledger.create_account(self.addr_alice, 1000.0)
        self.ledger.create_account(self.addr_bob, 100.0)
        self.validator = TransactionValidator(self.ledger)
        self.wallet = self.wallet_alice  # alias for compat

    def _signed_payment(self, src_addr, dst_addr, amount, currency=None,
                        issuer=None, fee=None, sequence=None):
        """Create and sign a payment transaction."""
        args = [src_addr, dst_addr, amount]
        if currency is not None:
            args.append(currency)
            if issuer is not None:
                args.append(issuer)
        kwargs = {}
        if fee is not None:
            kwargs["fee"] = fee
        if sequence is not None:
            kwargs["sequence"] = sequence
        tx = create_payment(*args, **kwargs)
        # Find the matching wallet to sign
        wallets = {
            self.addr_alice: self.wallet_alice,
            self.addr_bob: self.wallet_bob,
        }
        for extra_name in ("wallet_gw", "wallet_broke", "wallet_poor", "wallet_ghost"):
            w = getattr(self, extra_name, None)
            if w:
                wallets[w.address] = w
        w = wallets.get(src_addr)
        if w:
            w.sign_transaction(tx)
        return tx

    def _signed_trust_set(self, account, currency, issuer, limit):
        """Create and sign a TrustSet transaction."""
        tx = create_trust_set(account, currency, issuer, limit)
        wallets = {
            self.addr_alice: self.wallet_alice,
            self.addr_bob: self.wallet_bob,
        }
        for extra_name in ("wallet_gw", "wallet_broke", "wallet_poor"):
            w = getattr(self, extra_name, None)
            if w:
                wallets[w.address] = w
        w = wallets.get(account)
        if w:
            w.sign_transaction(tx)
        return tx


class TestValidatorSignature(ValidatorTestBase):

    def test_valid_signature_passes(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0)
        ok, code, _msg = self.validator.validate(tx)
        self.assertTrue(ok)
        self.assertEqual(code, TES_SUCCESS)

    def test_invalid_signature_fails(self):
        # Sign with one key, then swap the pubkey to a different valid key
        w1 = Wallet.from_seed("key1")
        w2 = Wallet.from_seed("key2")
        self.ledger.create_account(w1.address, 1000.0)
        tx = create_payment(w1.address, self.addr_bob, 1.0)
        w1.sign_transaction(tx)
        # Replace the pubkey with w2's key — signature won't match
        tx.signing_pub_key = w2.public_key
        ok, code, _msg = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SIG)

    def test_no_signature_rejected(self):
        """Without signature/pubkey, the transaction is now rejected (CR-1 fix)."""
        tx = create_payment(self.addr_alice, self.addr_bob, 1.0)
        ok, code, _msg = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SIG)


class TestValidatorAccountExists(ValidatorTestBase):

    def test_nonexistent_source_fails(self):
        self.wallet_ghost = Wallet.from_seed("ghost-seed")
        tx = self._signed_payment(self.wallet_ghost.address, self.addr_bob, 1.0)
        ok, code, _msg = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_existing_source_passes(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorFee(ValidatorTestBase):

    def test_fee_below_minimum_fails(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0, fee=0.000001)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_fee_at_minimum_passes(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0, fee=MIN_FEE)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_fee_above_minimum_passes(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0, fee=1.0)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorSequence(ValidatorTestBase):

    def test_correct_sequence_passes(self):
        acc = self.ledger.get_account(self.addr_alice)
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0, sequence=acc.sequence)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_zero_sequence_skips_check(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0, sequence=0)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_wrong_sequence_fails(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0, sequence=999)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SEQ)


class TestValidatorBalance(ValidatorTestBase):

    def test_sufficient_balance_passes(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 1.0)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_insufficient_balance_after_reserve_fails(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 981.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_balance_exactly_at_reserve(self):
        max_send = 1000.0 - ACCOUNT_RESERVE - 0.00001
        tx = self._signed_payment(self.addr_alice, self.addr_bob, max_send)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


class TestValidatorIOU(ValidatorTestBase):

    def setUp(self):
        super().setUp()
        self.wallet_gw = Wallet.from_seed("gw-seed")
        self.addr_gw = self.wallet_gw.address
        self.ledger.create_account(self.addr_gw, 1000.0)
        self.ledger.set_trust_line(self.addr_alice, "USD", self.addr_gw, 500.0)

    def test_iou_with_trust_line_passes(self):
        tx = self._signed_payment(self.addr_alice, self.addr_bob, 10.0, "USD", self.addr_gw)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_iou_without_trust_line_fails(self):
        tx = self._signed_payment(self.addr_bob, self.addr_alice, 10.0, "USD", self.addr_gw)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_NO_LINE)

    def test_iou_issuer_can_send_without_trust_line(self):
        tx = self._signed_payment(self.addr_gw, self.addr_alice, 10.0, "USD", self.addr_gw)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_iou_no_native_for_fee(self):
        self.wallet_broke = Wallet.from_seed("broke-seed")
        self.ledger.create_account(self.wallet_broke.address, 0.0)
        self.ledger.set_trust_line(self.wallet_broke.address, "USD", self.addr_gw, 100.0)
        tx = self._signed_payment(self.wallet_broke.address, self.addr_alice, 10.0, "USD", self.addr_gw)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)


class TestValidatorTrustSet(ValidatorTestBase):

    def test_trust_set_valid(self):
        tx = self._signed_trust_set(self.addr_alice, "EUR", "rBank", 500.0)
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_trust_set_no_balance_for_fee(self):
        self.wallet_poor = Wallet.from_seed("poor-seed")
        self.ledger.create_account(self.wallet_poor.address, 0.0)
        tx = self._signed_trust_set(self.wallet_poor.address, "EUR", "rBank", 500.0)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)


class TestValidateBatch(ValidatorTestBase):

    def test_batch_returns_list(self):
        self.wallet_ghost = Wallet.from_seed("ghost-seed")
        tx1 = self._signed_payment(self.addr_alice, self.addr_bob, 1.0)
        tx2 = self._signed_payment(self.wallet_ghost.address, self.addr_bob, 1.0)
        results = self.validator.validate_batch([tx1, tx2])
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0][1])   # valid
        self.assertFalse(results[1][1])  # invalid (unfunded)

    def test_batch_empty(self):
        results = self.validator.validate_batch([])
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
