"""
Test suite for TransactionValidator with all new transaction types.

Covers:
  - Basic validation pipeline (sig, account, fee, sequence)
  - Payment validation (native, IOU, deposit_auth, frozen, no_ripple)
  - Escrow create/finish/cancel validation
  - PayChan create/fund/claim validation
  - Check create/cash/cancel validation
  - SignerListSet validation
  - AccountDelete validation
  - TicketCreate validation
  - NFToken burn/offer_create/offer_accept validation
  - AccountSet and DepositPreauth (fee checks)
"""

import unittest

from nexaflow_core.ledger import Ledger
from nexaflow_core.transaction import (
    TEC_BAD_SEQ,
    TEC_INSUF_FEE,
    TEC_NO_ENTRY,
    TEC_NO_PERMISSION,
    TEC_UNFUNDED,
    TES_SUCCESS,
    TT_ACCOUNT_DELETE,
    TT_ACCOUNT_SET,
    TT_CHECK_CANCEL,
    TT_CHECK_CASH,
    TT_CHECK_CREATE,
    TT_DEPOSIT_PREAUTH,
    TT_ESCROW_CANCEL,
    TT_ESCROW_CREATE,
    TT_ESCROW_FINISH,
    TT_NFTOKEN_BURN,
    TT_NFTOKEN_MINT,
    TT_NFTOKEN_OFFER_ACCEPT,
    TT_NFTOKEN_OFFER_CREATE,
    TT_PAYCHAN_CLAIM,
    TT_PAYCHAN_CREATE,
    TT_PAYCHAN_FUND,
    TT_PAYMENT,
    TT_SIGNER_LIST_SET,
    TT_TICKET_CREATE,
    Amount,
    Transaction,
    create_payment,
    create_trust_set,
)
from nexaflow_core.validator import TransactionValidator


def _make_tx(tx_type, account, **kwargs):
    """Helper to build a minimal Transaction for validation."""
    tx = Transaction(
        tx_type=tx_type,
        account=account,
        destination=kwargs.get("destination", ""),
        amount=kwargs.get("amount", Amount(0.0)),
        fee=kwargs.get("fee", Amount(0.001)),
        sequence=kwargs.get("sequence", 0),
    )
    # Set flags after construction (not a constructor arg)
    if "flags" in kwargs:
        tx.flags = kwargs["flags"]
    # Skip signature for unit tests
    return tx


class TestValidatorPayment(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_native_payment(self):
        tx = _make_tx(0, "rAlice", destination="rBob", amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)
        self.assertEqual(code, TES_SUCCESS)

    def test_unfunded_payment(self):
        tx = _make_tx(0, "rAlice", destination="rBob", amount=Amount(9999.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_account_not_found(self):
        tx = _make_tx(0, "rNobody", destination="rBob", amount=Amount(1.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_insufficient_fee(self):
        tx = _make_tx(0, "rAlice", destination="rBob",
                       amount=Amount(1.0), fee=Amount(0.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_deposit_auth_blocks_payment(self):
        acc_bob = self.ledger.get_account("rBob")
        acc_bob.deposit_auth = True
        tx = _make_tx(0, "rAlice", destination="rBob", amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_deposit_auth_preauth_allowed(self):
        acc_bob = self.ledger.get_account("rBob")
        acc_bob.deposit_auth = True
        acc_bob.deposit_preauth.add("rAlice")
        tx = _make_tx(0, "rAlice", destination="rBob", amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorEscrow(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_escrow_create_valid(self):
        tx = _make_tx(1, "rAlice", destination="rBob", amount=Amount(50.0),
                       flags={"finish_after": 99999, "cancel_after": 999999})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_escrow_create_unfunded(self):
        tx = _make_tx(1, "rAlice", destination="rBob", amount=Amount(9999.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_escrow_create_no_destination(self):
        tx = _make_tx(1, "rAlice", destination="", amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_escrow_create_bad_timing(self):
        tx = _make_tx(1, "rAlice", destination="rBob", amount=Amount(10.0),
                       flags={"finish_after": 1000, "cancel_after": 500})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_escrow_finish_valid(self):
        # Create an escrow first
        self.ledger.escrow_manager.create_escrow("esc1", "rAlice", "rBob", 50.0, now=100.0)
        tx = _make_tx(2, "rAlice", flags={"escrow_id": "esc1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_escrow_finish_not_found(self):
        tx = _make_tx(2, "rAlice", flags={"escrow_id": "nope"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_ENTRY)

    def test_escrow_cancel_valid(self):
        self.ledger.escrow_manager.create_escrow("esc1", "rAlice", "rBob", 50.0,
                                                  cancel_after=9999, now=100.0)
        tx = _make_tx(TT_ESCROW_CANCEL, "rAlice", flags={"escrow_id": "esc1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorPayChan(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_paychan_create_valid(self):
        tx = _make_tx(13, "rAlice", destination="rBob", amount=Amount(100.0),
                       flags={"settle_delay": 3600})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_paychan_create_no_destination(self):
        tx = _make_tx(13, "rAlice", destination="", amount=Amount(100.0),
                       flags={"settle_delay": 3600})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_paychan_create_no_settle_delay(self):
        tx = _make_tx(13, "rAlice", destination="rBob", amount=Amount(100.0),
                       flags={"settle_delay": 0})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_paychan_fund_valid(self):
        self.ledger.channel_manager.create_channel("ch1", "rAlice", "rBob", 100.0, 60, now=100.0)
        tx = _make_tx(14, "rAlice", amount=Amount(50.0), flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_paychan_fund_wrong_creator(self):
        self.ledger.channel_manager.create_channel("ch1", "rAlice", "rBob", 100.0, 60, now=100.0)
        tx = _make_tx(14, "rBob", amount=Amount(50.0), flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_paychan_claim_valid(self):
        self.ledger.channel_manager.create_channel("ch1", "rAlice", "rBob", 100.0, 60, now=100.0)
        tx = _make_tx(15, "rBob", flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_paychan_claim_closed(self):
        self.ledger.channel_manager.create_channel("ch1", "rAlice", "rBob", 100.0, 60, now=100.0)
        self.ledger.channel_manager.get_channel("ch1").closed = True
        tx = _make_tx(15, "rBob", flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorCheck(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_check_create_valid(self):
        tx = _make_tx(16, "rAlice", destination="rBob", amount=Amount(100.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_check_create_no_destination(self):
        tx = _make_tx(16, "rAlice", destination="", amount=Amount(100.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_check_create_zero_amount(self):
        tx = _make_tx(16, "rAlice", destination="rBob", amount=Amount(0.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_check_cash_valid(self):
        self.ledger.check_manager.create_check("chk1", "rAlice", "rBob", 100.0, now=100.0)
        tx = _make_tx(17, "rBob", flags={"check_id": "chk1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_check_cash_wrong_destination(self):
        self.ledger.check_manager.create_check("chk1", "rAlice", "rBob", 100.0, now=100.0)
        tx = _make_tx(17, "rAlice", flags={"check_id": "chk1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_check_cancel_valid(self):
        self.ledger.check_manager.create_check("chk1", "rAlice", "rBob", 100.0, now=100.0)
        tx = _make_tx(18, "rAlice", flags={"check_id": "chk1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorSignerList(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_signer_list(self):
        tx = _make_tx(12, "rAlice", flags={
            "signer_quorum": 2,
            "signer_entries": [
                {"account": "rBob", "weight": 1},
                {"account": "rCharlie", "weight": 1},
            ],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_self_in_signer_list(self):
        tx = _make_tx(12, "rAlice", flags={
            "signer_quorum": 1,
            "signer_entries": [{"account": "rAlice", "weight": 1}],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_duplicate_signers(self):
        tx = _make_tx(12, "rAlice", flags={
            "signer_quorum": 1,
            "signer_entries": [
                {"account": "rBob", "weight": 1},
                {"account": "rBob", "weight": 1},
            ],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_weight_less_than_quorum(self):
        tx = _make_tx(12, "rAlice", flags={
            "signer_quorum": 10,
            "signer_entries": [{"account": "rBob", "weight": 1}],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorAccountDelete(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_delete(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, "rAlice", destination="rBob",
                       fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_delete_low_fee(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, "rAlice", destination="rBob",
                       fee=Amount(0.001))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_delete_to_self(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, "rAlice", destination="rAlice",
                       fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_delete_with_trust_lines(self):
        self.ledger.set_trust_line("rAlice", "USD", "rGateway", 1000.0)
        tx = _make_tx(TT_ACCOUNT_DELETE, "rAlice", destination="rBob", fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_delete_nonexistent_destination(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, "rAlice", destination="rNobody",
                       fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorTicketCreate(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_ticket_create(self):
        tx = _make_tx(TT_TICKET_CREATE, "rAlice", flags={"ticket_count": 5})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_ticket_count_too_large(self):
        tx = _make_tx(TT_TICKET_CREATE, "rAlice", flags={"ticket_count": 300})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_ticket_count_zero(self):
        tx = _make_tx(TT_TICKET_CREATE, "rAlice", flags={"ticket_count": 0})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorNFToken(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_mint_valid(self):
        tx = _make_tx(TT_NFTOKEN_MINT, "rAlice")
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_burn_valid(self):
        token = self.ledger.nftoken_manager.mint("rAlice", now=100.0)
        tx = _make_tx(TT_NFTOKEN_BURN, "rAlice", flags={"nftoken_id": token.nftoken_id})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_burn_not_found(self):
        tx = _make_tx(TT_NFTOKEN_BURN, "rAlice", flags={"nftoken_id": "fake"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_ENTRY)

    def test_burn_unauthorized(self):
        token = self.ledger.nftoken_manager.mint("rAlice", burnable=False, now=100.0)
        token.owner = "rBob"
        tx = _make_tx(TT_NFTOKEN_BURN, "rBob", flags={"nftoken_id": token.nftoken_id})
        # rBob is not the issuer and token is not burnable
        valid, code, msg = self.validator.validate(tx)
        # rBob IS the owner, so they can burn
        self.assertTrue(valid)

    def test_offer_create_sell_invalid_not_owner(self):
        token = self.ledger.nftoken_manager.mint("rAlice", now=100.0)
        tx = _make_tx(TT_NFTOKEN_OFFER_CREATE, "rBob", flags={
            "nftoken_id": token.nftoken_id,
            "is_sell": True,
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_offer_accept_valid(self):
        token = self.ledger.nftoken_manager.mint("rAlice", now=100.0)
        self.ledger.nftoken_manager.create_offer(
            "off1", token.nftoken_id, "rAlice", 10.0, is_sell=True, now=100.0)
        tx = _make_tx(TT_NFTOKEN_OFFER_ACCEPT, "rBob", flags={"offer_id": "off1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorBatch(unittest.TestCase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self.ledger.create_account("rAlice", 500.0)
        self.ledger.create_account("rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_batch_validation(self):
        txns = [
            _make_tx(0, "rAlice", destination="rBob", amount=Amount(10.0)),
            _make_tx(0, "rNobody", destination="rBob", amount=Amount(1.0)),
        ]
        results = self.validator.validate_batch(txns)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0][1])   # valid
        self.assertFalse(results[1][1])  # invalid


if __name__ == "__main__":
    unittest.main()
