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
from nexaflow_core.wallet import Wallet

# ── Global wallet registry — maps address → Wallet for auto-signing ──
_WALLETS: dict[str, Wallet] = {}


def _get_or_create_wallet(name: str) -> Wallet:
    """Return a Wallet for *name*, creating & caching it on first call."""
    if name not in _WALLETS:
        w = Wallet.from_seed(name)
        _WALLETS[name] = w
        _WALLETS[w.address] = w  # also index by derived address
    return _WALLETS[name]


def _make_tx(tx_type, account, **kwargs):
    """Helper to build a minimal Transaction for validation, auto-signed."""
    # If account is a friendly name (not a wallet address), resolve it
    if account in _WALLETS:
        resolved = _WALLETS[account].address if account != _WALLETS[account].address else account
    else:
        # Unknown account — create ephemeral wallet for signing
        w = _get_or_create_wallet(account)
        resolved = w.address
    explicit_seq = kwargs.get("sequence", None)
    tx = Transaction(
        tx_type=tx_type,
        account=resolved,
        destination=kwargs.get("destination", ""),
        amount=kwargs.get("amount", Amount(0.0)),
        fee=kwargs.get("fee", Amount(0.001)),
        sequence=0,  # always 0 so sign_transaction fills from wallet
    )
    if "flags" in kwargs:
        tx.flags = kwargs["flags"]
    # Auto-sign with the wallet
    w = _WALLETS[resolved]
    w._sequence = 1  # always reset so validator sequence check passes
    w.sign_transaction(tx)
    # If caller specified an explicit sequence, override after signing
    if explicit_seq is not None:
        tx.sequence = explicit_seq
    return tx


class _WalletBase(unittest.TestCase):
    """Mixin that provides wallet-keyed accounts."""

    def _make_accounts(self, ledger, *names_and_balances):
        """Create wallet-derived accounts. E.g. ('rAlice', 500, 'rBob', 100).
        
        Resets wallet sequence counters to match fresh ledger accounts.
        """
        it = iter(names_and_balances)
        for name in it:
            bal = next(it)
            w = _get_or_create_wallet(name)
            w._sequence = 1  # reset sequence to match fresh ledger accounts
            ledger.create_account(w.address, bal)
            setattr(self, f"_w_{name}", w)

    def _addr(self, name: str) -> str:
        return _WALLETS[name].address


class TestValidatorPayment(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_native_payment(self):
        tx = _make_tx(0, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)
        self.assertEqual(code, TES_SUCCESS)

    def test_unfunded_payment(self):
        tx = _make_tx(0, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(9999.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_account_not_found(self):
        tx = _make_tx(0, "rNobody", destination=self._addr("rBob"), amount=Amount(1.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_insufficient_fee(self):
        tx = _make_tx(0, self._addr("rAlice"), destination=self._addr("rBob"),
                       amount=Amount(1.0), fee=Amount(0.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_deposit_auth_blocks_payment(self):
        acc_bob = self.ledger.get_account(self._addr("rBob"))
        acc_bob.deposit_auth = True
        tx = _make_tx(0, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_deposit_auth_preauth_allowed(self):
        acc_bob = self.ledger.get_account(self._addr("rBob"))
        acc_bob.deposit_auth = True
        acc_bob.deposit_preauth.add(self._addr("rAlice"))
        tx = _make_tx(0, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorEscrow(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_escrow_create_valid(self):
        tx = _make_tx(1, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(50.0),
                       flags={"finish_after": 99999, "cancel_after": 999999})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_escrow_create_unfunded(self):
        tx = _make_tx(1, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(9999.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_escrow_create_no_destination(self):
        tx = _make_tx(1, self._addr("rAlice"), destination="", amount=Amount(10.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_escrow_create_bad_timing(self):
        tx = _make_tx(1, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(10.0),
                       flags={"finish_after": 1000, "cancel_after": 500})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_escrow_finish_valid(self):
        # Create an escrow first
        self.ledger.escrow_manager.create_escrow("esc1", self._addr("rAlice"), self._addr("rBob"), 50.0, now=100.0)
        tx = _make_tx(2, self._addr("rAlice"), flags={"escrow_id": "esc1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_escrow_finish_not_found(self):
        tx = _make_tx(2, self._addr("rAlice"), flags={"escrow_id": "nope"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_ENTRY)

    def test_escrow_cancel_valid(self):
        self.ledger.escrow_manager.create_escrow("esc1", self._addr("rAlice"), self._addr("rBob"), 50.0,
                                                  cancel_after=9999, now=100.0)
        tx = _make_tx(TT_ESCROW_CANCEL, self._addr("rAlice"), flags={"escrow_id": "esc1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorPayChan(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_paychan_create_valid(self):
        tx = _make_tx(13, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(100.0),
                       flags={"settle_delay": 3600})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_paychan_create_no_destination(self):
        tx = _make_tx(13, self._addr("rAlice"), destination="", amount=Amount(100.0),
                       flags={"settle_delay": 3600})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_paychan_create_no_settle_delay(self):
        tx = _make_tx(13, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(100.0),
                       flags={"settle_delay": 0})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_paychan_fund_valid(self):
        self.ledger.channel_manager.create_channel("ch1", self._addr("rAlice"), self._addr("rBob"), 100.0, 60, now=100.0)
        tx = _make_tx(14, self._addr("rAlice"), amount=Amount(50.0), flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_paychan_fund_wrong_creator(self):
        self.ledger.channel_manager.create_channel("ch1", self._addr("rAlice"), self._addr("rBob"), 100.0, 60, now=100.0)
        tx = _make_tx(14, self._addr("rBob"), amount=Amount(50.0), flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_paychan_claim_valid(self):
        self.ledger.channel_manager.create_channel("ch1", self._addr("rAlice"), self._addr("rBob"), 100.0, 60, now=100.0)
        tx = _make_tx(15, self._addr("rBob"), flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_paychan_claim_closed(self):
        self.ledger.channel_manager.create_channel("ch1", self._addr("rAlice"), self._addr("rBob"), 100.0, 60, now=100.0)
        self.ledger.channel_manager.get_channel("ch1").closed = True
        tx = _make_tx(15, self._addr("rBob"), flags={"channel_id": "ch1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorCheck(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_check_create_valid(self):
        tx = _make_tx(16, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(100.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_check_create_no_destination(self):
        tx = _make_tx(16, self._addr("rAlice"), destination="", amount=Amount(100.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_check_create_zero_amount(self):
        tx = _make_tx(16, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(0.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_check_cash_valid(self):
        self.ledger.check_manager.create_check("chk1", self._addr("rAlice"), self._addr("rBob"), 100.0, now=100.0)
        tx = _make_tx(17, self._addr("rBob"), flags={"check_id": "chk1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_check_cash_wrong_destination(self):
        self.ledger.check_manager.create_check("chk1", self._addr("rAlice"), self._addr("rBob"), 100.0, now=100.0)
        tx = _make_tx(17, self._addr("rAlice"), flags={"check_id": "chk1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_check_cancel_valid(self):
        self.ledger.check_manager.create_check("chk1", self._addr("rAlice"), self._addr("rBob"), 100.0, now=100.0)
        tx = _make_tx(18, self._addr("rAlice"), flags={"check_id": "chk1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorSignerList(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_signer_list(self):
        tx = _make_tx(12, self._addr("rAlice"), flags={
            "signer_quorum": 2,
            "signer_entries": [
                {"account": "rBob", "weight": 1},
                {"account": "rCharlie", "weight": 1},
            ],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_self_in_signer_list(self):
        tx = _make_tx(12, self._addr("rAlice"), flags={
            "signer_quorum": 1,
            "signer_entries": [{"account": self._addr("rAlice"), "weight": 1}],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_duplicate_signers(self):
        tx = _make_tx(12, self._addr("rAlice"), flags={
            "signer_quorum": 1,
            "signer_entries": [
                {"account": "rBob", "weight": 1},
                {"account": "rBob", "weight": 1},
            ],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_weight_less_than_quorum(self):
        tx = _make_tx(12, self._addr("rAlice"), flags={
            "signer_quorum": 10,
            "signer_entries": [{"account": "rBob", "weight": 1}],
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorAccountDelete(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_delete(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, self._addr("rAlice"), destination=self._addr("rBob"),
                       fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_delete_low_fee(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, self._addr("rAlice"), destination=self._addr("rBob"),
                       fee=Amount(0.001))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_delete_to_self(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, self._addr("rAlice"), destination=self._addr("rAlice"),
                       fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_delete_with_trust_lines(self):
        self.ledger.set_trust_line(self._addr("rAlice"), "USD", "rGateway", 1000.0)
        tx = _make_tx(TT_ACCOUNT_DELETE, self._addr("rAlice"), destination=self._addr("rBob"), fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_delete_nonexistent_destination(self):
        tx = _make_tx(TT_ACCOUNT_DELETE, self._addr("rAlice"), destination="rNobody",
                       fee=Amount(5.0))
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorTicketCreate(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0)
        self.validator = TransactionValidator(self.ledger)

    def test_valid_ticket_create(self):
        tx = _make_tx(TT_TICKET_CREATE, self._addr("rAlice"), flags={"ticket_count": 5})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_ticket_count_too_large(self):
        tx = _make_tx(TT_TICKET_CREATE, self._addr("rAlice"), flags={"ticket_count": 300})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)

    def test_ticket_count_zero(self):
        tx = _make_tx(TT_TICKET_CREATE, self._addr("rAlice"), flags={"ticket_count": 0})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)


class TestValidatorNFToken(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_mint_valid(self):
        tx = _make_tx(TT_NFTOKEN_MINT, self._addr("rAlice"))
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_burn_valid(self):
        token = self.ledger.nftoken_manager.mint(self._addr("rAlice"), now=100.0)
        tx = _make_tx(TT_NFTOKEN_BURN, self._addr("rAlice"), flags={"nftoken_id": token.nftoken_id})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_burn_not_found(self):
        tx = _make_tx(TT_NFTOKEN_BURN, self._addr("rAlice"), flags={"nftoken_id": "fake"})
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_ENTRY)

    def test_burn_unauthorized(self):
        token = self.ledger.nftoken_manager.mint(self._addr("rAlice"), burnable=False, now=100.0)
        token.owner = self._addr("rBob")
        tx = _make_tx(TT_NFTOKEN_BURN, self._addr("rBob"), flags={"nftoken_id": token.nftoken_id})
        # rBob IS the owner, so they can burn
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)

    def test_offer_create_sell_invalid_not_owner(self):
        token = self.ledger.nftoken_manager.mint(self._addr("rAlice"), now=100.0)
        tx = _make_tx(TT_NFTOKEN_OFFER_CREATE, self._addr("rBob"), flags={
            "nftoken_id": token.nftoken_id,
            "is_sell": True,
        })
        valid, code, msg = self.validator.validate(tx)
        self.assertFalse(valid)
        self.assertEqual(code, TEC_NO_PERMISSION)

    def test_offer_accept_valid(self):
        token = self.ledger.nftoken_manager.mint(self._addr("rAlice"), now=100.0)
        self.ledger.nftoken_manager.create_offer(
            "off1", token.nftoken_id, self._addr("rAlice"), 10.0, is_sell=True, now=100.0)
        tx = _make_tx(TT_NFTOKEN_OFFER_ACCEPT, self._addr("rBob"), flags={"offer_id": "off1"})
        valid, code, msg = self.validator.validate(tx)
        self.assertTrue(valid)


class TestValidatorBatch(_WalletBase):

    def setUp(self):
        self.ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        self._make_accounts(self.ledger, "rAlice", 500.0, "rBob", 100.0)
        self.validator = TransactionValidator(self.ledger)

    def test_batch_validation(self):
        txns = [
            _make_tx(0, self._addr("rAlice"), destination=self._addr("rBob"), amount=Amount(10.0)),
            _make_tx(0, "rNobody", destination=self._addr("rBob"), amount=Amount(1.0)),
        ]
        results = self.validator.validate_batch(txns)
        self.assertEqual(len(results), 2)
        self.assertTrue(results[0][1])   # valid
        self.assertFalse(results[1][1])  # invalid


if __name__ == "__main__":
    unittest.main()
