"""
Integration tests for all new transaction types applied through Ledger.

Covers every new apply_* handler in ledger.pyx:
  - Escrow (create / finish / cancel)
  - AccountSet (flags, transfer_rate, domain)
  - SetRegularKey
  - SignerListSet
  - PaymentChannel (create / fund / claim)
  - Check (create / cash / cancel)
  - DepositPreauth
  - AccountDelete
  - TicketCreate
  - NFToken (mint / burn / offer_create / offer_accept)
  - Payment enhancements (no_ripple, frozen, transfer_rate)
"""

import unittest

from nexaflow_core.ledger import AccountEntry, Ledger, TrustLineEntry
from nexaflow_core.transaction import (
    Amount,
    create_account_delete,
    create_account_set,
    create_check_cancel,
    create_check_cash,
    create_check_create,
    create_deposit_preauth,
    create_escrow_cancel,
    create_escrow_create,
    create_escrow_finish,
    create_nftoken_burn,
    create_nftoken_mint,
    create_nftoken_offer_accept,
    create_nftoken_offer_create,
    create_paychan_claim,
    create_paychan_create,
    create_paychan_fund,
    create_payment,
    create_set_regular_key,
    create_signer_list_set,
    create_ticket_create,
    create_trust_set,
)


def _ledger_with_funded(address="rAlice", balance=10000.0):
    """Return a fresh Ledger with a funded test account."""
    ledger = Ledger()
    acc = ledger.create_account(address, balance)
    return ledger, acc


def _apply(ledger, tx):
    """Shortcut: apply_transaction and return the result code."""
    return ledger.apply_transaction(tx)


# ===================================================================
#  Escrow handlers
# ===================================================================


class TestEscrowCreateHandler(unittest.TestCase):
    """apply_escrow_create: lock NXF, create escrow entry."""

    def test_success(self):
        ledger, acc = _ledger_with_funded()
        tx = create_escrow_create("rAlice", "rBob", 500.0,
                                  finish_after=9999, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertAlmostEqual(acc.balance, 10000.0 - 500.0 - 0.00001, places=5)
        self.assertEqual(acc.owner_count, 1)
        self.assertEqual(acc.sequence, 2)
        # Destination created lazily
        self.assertTrue(ledger.account_exists("rBob"))

    def test_insufficient_balance(self):
        ledger, acc = _ledger_with_funded(balance=100.0)
        tx = create_escrow_create("rAlice", "rBob", 200.0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 101)  # tecUNFUNDED

    def test_bad_sequence(self):
        ledger, acc = _ledger_with_funded()
        tx = create_escrow_create("rAlice", "rBob", 100.0, sequence=99)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 105)  # tecBAD_SEQ

    def test_unknown_account(self):
        ledger = Ledger()
        tx = create_escrow_create("rGhost", "rBob", 100.0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 101)


class TestEscrowFinishHandler(unittest.TestCase):
    """apply_escrow_finish: release escrowed NXF to destination."""

    def _create_escrow(self, ledger, acc):
        tx = create_escrow_create("rAlice", "rBob", 500.0, sequence=1)
        _apply(ledger, tx)
        return tx.tx_id

    def test_finish_success(self):
        ledger, acc = _ledger_with_funded()
        ledger.create_account("rBob", 0.0)
        eid = self._create_escrow(ledger, acc)
        tx = create_escrow_finish("rAlice", "rAlice", eid, sequence=2)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        bob = ledger.get_account("rBob")
        self.assertAlmostEqual(bob.balance, 500.0, places=2)

    def test_finish_wrong_id(self):
        ledger, acc = _ledger_with_funded()
        self._create_escrow(ledger, acc)
        tx = create_escrow_finish("rAlice", "rAlice", "bad_id", sequence=2)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 117)  # tecNO_ENTRY

    def test_finish_decrements_owner_count(self):
        ledger, acc = _ledger_with_funded()
        ledger.create_account("rBob", 0.0)
        eid = self._create_escrow(ledger, acc)
        self.assertEqual(acc.owner_count, 1)
        tx = create_escrow_finish("rAlice", "rAlice", eid, sequence=2)
        _apply(ledger, tx)
        self.assertEqual(acc.owner_count, 0)


class TestEscrowCancelHandler(unittest.TestCase):
    """apply_escrow_cancel: return NXF to creator."""

    def test_cancel_refunds_creator(self):
        ledger, acc = _ledger_with_funded()
        tx_create = create_escrow_create("rAlice", "rBob", 500.0,
                                         cancel_after=1, sequence=1)
        _apply(ledger, tx_create)
        bal_after_create = acc.balance
        tx_cancel = create_escrow_cancel("rAlice", "rAlice",
                                         tx_create.tx_id, sequence=2)
        rc = _apply(ledger, tx_cancel)
        self.assertEqual(rc, 0)
        # Balance should be restored (minus two fees)
        self.assertGreater(acc.balance, bal_after_create)
        self.assertEqual(acc.owner_count, 0)


# ===================================================================
#  AccountSet handler
# ===================================================================


class TestAccountSetHandler(unittest.TestCase):
    """apply_account_set: configure account flags."""

    def test_set_require_dest(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice",
                                set_flags={"asfRequireDest": True},
                                sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertTrue(acc.require_dest)

    def test_clear_require_dest(self):
        ledger, acc = _ledger_with_funded()
        acc.require_dest = True
        tx = create_account_set("rAlice",
                                clear_flags={"asfRequireDest": True},
                                sequence=1)
        _apply(ledger, tx)
        self.assertFalse(acc.require_dest)

    def test_set_deposit_auth(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice",
                                set_flags={"asfDepositAuth": True},
                                sequence=1)
        _apply(ledger, tx)
        self.assertTrue(acc.deposit_auth)

    def test_set_disable_master(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice",
                                set_flags={"asfDisableMaster": True},
                                sequence=1)
        _apply(ledger, tx)
        self.assertTrue(acc.disable_master)

    def test_set_default_ripple(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice",
                                set_flags={"asfDefaultRipple": True},
                                sequence=1)
        _apply(ledger, tx)
        self.assertTrue(acc.default_ripple)

    def test_set_global_freeze(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice",
                                set_flags={"asfGlobalFreeze": True},
                                sequence=1)
        _apply(ledger, tx)
        self.assertTrue(acc.global_freeze)

    def test_set_transfer_rate(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice", transfer_rate=1.005, sequence=1)
        _apply(ledger, tx)
        self.assertAlmostEqual(acc.transfer_rate, 1.005)

    def test_invalid_transfer_rate_below(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice", transfer_rate=0.5, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)  # tecNO_PERMISSION

    def test_invalid_transfer_rate_above(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice", transfer_rate=2.5, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)

    def test_set_domain(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice", domain="example.com", sequence=1)
        _apply(ledger, tx)
        self.assertEqual(acc.domain, "example.com")

    def test_multiple_flags_at_once(self):
        ledger, acc = _ledger_with_funded()
        tx = create_account_set("rAlice",
                                set_flags={"asfRequireDest": True,
                                           "asfDepositAuth": True},
                                transfer_rate=1.1, domain="multi.test",
                                sequence=1)
        _apply(ledger, tx)
        self.assertTrue(acc.require_dest)
        self.assertTrue(acc.deposit_auth)
        self.assertAlmostEqual(acc.transfer_rate, 1.1)
        self.assertEqual(acc.domain, "multi.test")


# ===================================================================
#  SetRegularKey handler
# ===================================================================


class TestSetRegularKeyHandler(unittest.TestCase):

    def test_set_key(self):
        ledger, acc = _ledger_with_funded()
        tx = create_set_regular_key("rAlice", "rRegKey1", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.regular_key, "rRegKey1")
        self.assertEqual(acc.sequence, 2)

    def test_remove_key(self):
        ledger, acc = _ledger_with_funded()
        acc.regular_key = "rOldKey"
        tx = create_set_regular_key("rAlice", "", sequence=1)
        _apply(ledger, tx)
        self.assertEqual(acc.regular_key, "")


# ===================================================================
#  SignerListSet handler
# ===================================================================


class TestSignerListSetHandler(unittest.TestCase):

    def test_set_signer_list(self):
        ledger, acc = _ledger_with_funded()
        entries = [
            {"account": "rSig1", "weight": 1},
            {"account": "rSig2", "weight": 1},
        ]
        tx = create_signer_list_set("rAlice", 2, entries, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 1)
        self.assertEqual(acc.sequence, 2)

    def test_unknown_account(self):
        ledger = Ledger()
        entries = [{"account": "rSig1", "weight": 1}]
        tx = create_signer_list_set("rGhost", 1, entries, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 101)


# ===================================================================
#  PaymentChannel handlers
# ===================================================================


class TestPayChanCreateHandler(unittest.TestCase):

    def test_create_channel(self):
        ledger, acc = _ledger_with_funded()
        tx = create_paychan_create("rAlice", "rBob", 1000.0,
                                   settle_delay=3600, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        # Balance debited: amount + fee
        self.assertAlmostEqual(acc.balance, 10000.0 - 1000.0 - 0.00001, places=4)
        self.assertEqual(acc.owner_count, 1)
        self.assertTrue(ledger.account_exists("rBob"))

    def test_insufficient_balance(self):
        ledger, acc = _ledger_with_funded(balance=500.0)
        tx = create_paychan_create("rAlice", "rBob", 1000.0,
                                   settle_delay=3600, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 101)


class TestPayChanFundHandler(unittest.TestCase):

    def _create_channel(self, ledger):
        tx = create_paychan_create("rAlice", "rBob", 500.0,
                                   settle_delay=3600, sequence=1)
        _apply(ledger, tx)
        return tx.tx_id

    def test_fund_success(self):
        ledger, acc = _ledger_with_funded()
        cid = self._create_channel(ledger)
        bal_before = acc.balance
        tx = create_paychan_fund("rAlice", cid, 200.0, sequence=2)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertAlmostEqual(acc.balance, bal_before - 200.0 - 0.00001, places=4)

    def test_fund_bad_channel(self):
        ledger, acc = _ledger_with_funded()
        tx = create_paychan_fund("rAlice", "nonexistent", 100.0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 117)  # tecNO_ENTRY


class TestPayChanClaimHandler(unittest.TestCase):

    def _setup_channel(self, ledger, acc):
        ledger.create_account("rBob", 0.0)
        tx = create_paychan_create("rAlice", "rBob", 500.0,
                                   settle_delay=3600, sequence=1)
        _apply(ledger, tx)
        return tx.tx_id

    def test_claim_credits_destination(self):
        ledger, acc = _ledger_with_funded()
        cid = self._setup_channel(ledger, acc)
        tx = create_paychan_claim("rAlice", cid, balance=100.0, sequence=2)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        bob = ledger.get_account("rBob")
        self.assertAlmostEqual(bob.balance, 100.0, places=2)

    def test_claim_with_close(self):
        ledger, acc = _ledger_with_funded()
        cid = self._setup_channel(ledger, acc)
        tx = create_paychan_claim("rAlice", cid, balance=0.0,
                                  close=True, sequence=2)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)


# ===================================================================
#  Check handlers
# ===================================================================


class TestCheckCreateHandler(unittest.TestCase):

    def test_create_check(self):
        ledger, acc = _ledger_with_funded()
        tx = create_check_create("rAlice", "rBob", 200.0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 1)
        self.assertEqual(acc.sequence, 2)


class TestCheckCashHandler(unittest.TestCase):

    def _create_check(self, ledger):
        tx = create_check_create("rAlice", "rBob", 200.0, sequence=1)
        _apply(ledger, tx)
        return tx.tx_id

    def test_cash_native_check(self):
        ledger, alice = _ledger_with_funded()
        ledger.create_account("rBob", 10.0)
        check_id = self._create_check(ledger)
        bob = ledger.get_account("rBob")
        bal_before = bob.balance
        tx = create_check_cash("rBob", check_id, amount=200.0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertAlmostEqual(bob.balance, bal_before + 200.0 - 0.00001, places=4)
        # Alice debited
        self.assertAlmostEqual(alice.balance, 10000.0 - 200.0 - 0.00002, places=4)

    def test_cash_wrong_destination(self):
        """Only the designated destination can cash the check."""
        ledger, alice = _ledger_with_funded()
        ledger.create_account("rBob", 10.0)
        ledger.create_account("rEve", 10.0)
        check_id = self._create_check(ledger)
        tx = create_check_cash("rEve", check_id, amount=200.0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)  # tecNO_PERMISSION


class TestCheckCancelHandler(unittest.TestCase):

    def test_cancel_check(self):
        ledger, acc = _ledger_with_funded()
        tx_create = create_check_create("rAlice", "rBob", 200.0, sequence=1)
        _apply(ledger, tx_create)
        self.assertEqual(acc.owner_count, 1)
        tx_cancel = create_check_cancel("rAlice", tx_create.tx_id, sequence=2)
        rc = _apply(ledger, tx_cancel)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 0)

    def test_cancel_bad_id(self):
        ledger, acc = _ledger_with_funded()
        tx = create_check_cancel("rAlice", "nonexistent", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 117)


# ===================================================================
#  DepositPreauth handler
# ===================================================================


class TestDepositPreauthHandler(unittest.TestCase):

    def test_authorize(self):
        ledger, acc = _ledger_with_funded()
        tx = create_deposit_preauth("rAlice", authorize="rBob", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertIn("rBob", acc.deposit_preauth)

    def test_unauthorize(self):
        ledger, acc = _ledger_with_funded()
        acc.deposit_preauth.add("rBob")
        tx = create_deposit_preauth("rAlice", unauthorize="rBob", sequence=1)
        _apply(ledger, tx)
        self.assertNotIn("rBob", acc.deposit_preauth)


# ===================================================================
#  AccountDelete handler
# ===================================================================


class TestAccountDeleteHandler(unittest.TestCase):

    def test_delete_transfers_balance(self):
        ledger, acc = _ledger_with_funded()
        acc.sequence = 256  # must have consumed 256+ seqs to delete
        ledger.create_account("rBob", 50.0)
        tx = create_account_delete("rAlice", "rBob", fee=5.0, sequence=256)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertFalse(ledger.account_exists("rAlice"))
        bob = ledger.get_account("rBob")
        # Bob gets Alice's remaining balance (after fee deduction)
        self.assertAlmostEqual(bob.balance, 50.0 + 10000.0 - 5.0, places=2)

    def test_delete_with_owned_objects_fails(self):
        ledger, acc = _ledger_with_funded()
        acc.sequence = 256
        acc.owner_count = 1  # simulate owned object
        ledger.create_account("rBob", 0.0)
        tx = create_account_delete("rAlice", "rBob", fee=5.0, sequence=256)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)  # tecNO_PERMISSION

    def test_delete_with_trust_lines_fails(self):
        ledger, acc = _ledger_with_funded()
        acc.sequence = 256
        # Set up a trust line
        ledger.set_trust_line("rAlice", "USD", "rIssuer", 1000.0)
        ledger.create_account("rBob", 0.0)
        tx = create_account_delete("rAlice", "rBob", fee=5.0, sequence=256)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)

    def test_delete_to_nonexistent_destination(self):
        ledger, acc = _ledger_with_funded()
        acc.sequence = 256
        tx = create_account_delete("rAlice", "rNonExist", fee=5.0, sequence=256)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 101)


# ===================================================================
#  TicketCreate handler
# ===================================================================


class TestTicketCreateHandler(unittest.TestCase):

    def test_create_single_ticket(self):
        ledger, acc = _ledger_with_funded()
        tx = create_ticket_create("rAlice", ticket_count=1, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 1)
        self.assertEqual(len(acc.tickets), 1)
        # Sequence jumps: 1 (base) + 1 (consumed) + 1 (ticket) = 3
        self.assertEqual(acc.sequence, 3)

    def test_create_multiple_tickets(self):
        ledger, acc = _ledger_with_funded()
        tx = create_ticket_create("rAlice", ticket_count=5, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 5)
        self.assertEqual(len(acc.tickets), 5)

    def test_invalid_ticket_count_zero(self):
        ledger, acc = _ledger_with_funded()
        tx = create_ticket_create("rAlice", ticket_count=0, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)

    def test_invalid_ticket_count_over_250(self):
        ledger, acc = _ledger_with_funded()
        tx = create_ticket_create("rAlice", ticket_count=251, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)


# ===================================================================
#  NFToken handlers
# ===================================================================


class TestNFTokenMintHandler(unittest.TestCase):

    def test_mint_success(self):
        ledger, acc = _ledger_with_funded()
        tx = create_nftoken_mint("rAlice", uri="ipfs://abc",
                                 transfer_fee=500, sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 1)
        self.assertEqual(acc.sequence, 2)

    def test_mint_multiple(self):
        ledger, acc = _ledger_with_funded()
        for i in range(3):
            tx = create_nftoken_mint("rAlice", uri=f"ipfs://nft{i}",
                                     sequence=i + 1)
            _apply(ledger, tx)
        self.assertEqual(acc.owner_count, 3)


class TestNFTokenBurnHandler(unittest.TestCase):

    def test_burn_success(self):
        ledger, acc = _ledger_with_funded()
        tx_mint = create_nftoken_mint("rAlice", uri="ipfs://burn_me",
                                      sequence=1)
        _apply(ledger, tx_mint)
        # Get minted token ID from nftoken_manager
        tokens = ledger.nftoken_manager.get_tokens_for_account("rAlice")
        self.assertEqual(len(tokens), 1)
        token_id = tokens[0].nftoken_id
        tx_burn = create_nftoken_burn("rAlice", token_id, sequence=2)
        rc = _apply(ledger, tx_burn)
        self.assertEqual(rc, 0)
        self.assertEqual(acc.owner_count, 0)

    def test_burn_nonexistent(self):
        ledger, acc = _ledger_with_funded()
        tx = create_nftoken_burn("rAlice", "fake_token_id", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 117)  # tecNO_ENTRY


class TestNFTokenOfferCreateHandler(unittest.TestCase):

    def test_create_sell_offer(self):
        ledger, acc = _ledger_with_funded()
        # Mint first
        tx_mint = create_nftoken_mint("rAlice", uri="ipfs://sell",
                                      sequence=1)
        _apply(ledger, tx_mint)
        tokens = ledger.nftoken_manager.get_tokens_for_account("rAlice")
        token_id = tokens[0].nftoken_id
        tx_offer = create_nftoken_offer_create(
            "rAlice", token_id, amount=100.0, is_sell=True, sequence=2,
        )
        rc = _apply(ledger, tx_offer)
        self.assertEqual(rc, 0)
        # owner_count: 1 (token) + 1 (offer)
        self.assertEqual(acc.owner_count, 2)


class TestNFTokenOfferAcceptHandler(unittest.TestCase):

    def test_buy_nft(self):
        """Buyer accepts a sell offer; NXF moves from buyer to seller."""
        ledger, alice = _ledger_with_funded("rAlice", 10000.0)
        bob = ledger.create_account("rBob", 5000.0)
        # Alice mints
        tx_mint = create_nftoken_mint("rAlice", uri="ipfs://buyable",
                                      sequence=1)
        _apply(ledger, tx_mint)
        tokens = ledger.nftoken_manager.get_tokens_for_account("rAlice")
        token_id = tokens[0].nftoken_id
        # Alice creates sell offer
        tx_offer = create_nftoken_offer_create(
            "rAlice", token_id, amount=200.0, is_sell=True, sequence=2,
        )
        _apply(ledger, tx_offer)
        offer_id = tx_offer.tx_id
        alice_bal_before = alice.balance
        bob_bal_before = bob.balance
        # Bob accepts the sell offer
        tx_accept = create_nftoken_offer_accept("rBob", offer_id, sequence=1)
        rc = _apply(ledger, tx_accept)
        self.assertEqual(rc, 0)
        # Bob paid 200 NXF + fee
        self.assertAlmostEqual(bob.balance,
                               bob_bal_before - 200.0 - 0.00001, places=4)
        # Alice received 200 NXF
        self.assertAlmostEqual(alice.balance,
                               alice_bal_before + 200.0, places=4)

    def test_accept_nonexistent_offer(self):
        ledger, acc = _ledger_with_funded()
        tx = create_nftoken_offer_accept("rAlice", "bad_offer", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 117)


# ===================================================================
#  Payment enhancements: no_ripple, frozen, transfer_rate
# ===================================================================


class TestPaymentNoRipple(unittest.TestCase):
    """IOU payment fails when sender's trust line has no_ripple set."""

    def _setup_iou(self, ledger):
        """Create issuer + holder accounts + trust line with IOU balance."""
        issuer = ledger.create_account("rIssuer", 10000.0)
        issuer.is_gateway = True
        holder = ledger.create_account("rHolder", 100.0)
        dest = ledger.create_account("rDest", 100.0)
        # Holder trusts issuer for USD
        tl_hold = ledger.set_trust_line("rHolder", "USD", "rIssuer", 5000.0)
        tl_hold.balance = 1000.0
        # Dest trusts issuer for USD
        tl_dest = ledger.set_trust_line("rDest", "USD", "rIssuer", 5000.0)
        return holder, tl_hold, dest, tl_dest

    def test_payment_blocked_by_no_ripple(self):
        ledger = Ledger()
        holder, tl_hold, dest, tl_dest = self._setup_iou(ledger)
        tl_hold.no_ripple = True
        tx = create_payment("rHolder", "rDest", 50.0,
                            currency="USD", issuer="rIssuer", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 115)  # tecNO_RIPPLE

    def test_payment_ok_without_no_ripple(self):
        ledger = Ledger()
        holder, tl_hold, dest, tl_dest = self._setup_iou(ledger)
        tx = create_payment("rHolder", "rDest", 50.0,
                            currency="USD", issuer="rIssuer", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)


class TestPaymentFrozenTrustLine(unittest.TestCase):
    """IOU payment fails when either trust line is frozen."""

    def _setup_iou(self, ledger):
        ledger.create_account("rIssuer", 10000.0)
        ledger.create_account("rHolder", 100.0)
        ledger.create_account("rDest", 100.0)
        tl_h = ledger.set_trust_line("rHolder", "USD", "rIssuer", 5000.0)
        tl_h.balance = 1000.0
        tl_d = ledger.set_trust_line("rDest", "USD", "rIssuer", 5000.0)
        return tl_h, tl_d

    def test_sender_frozen(self):
        ledger = Ledger()
        tl_h, tl_d = self._setup_iou(ledger)
        tl_h.frozen = True
        tx = create_payment("rHolder", "rDest", 50.0,
                            currency="USD", issuer="rIssuer", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 116)  # tecFROZEN

    def test_dest_frozen(self):
        ledger = Ledger()
        tl_h, tl_d = self._setup_iou(ledger)
        tl_d.frozen = True
        tx = create_payment("rHolder", "rDest", 50.0,
                            currency="USD", issuer="rIssuer", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 116)


class TestPaymentTransferRate(unittest.TestCase):
    """IOU payment applies transfer_rate from issuer."""

    def test_transfer_rate_applied(self):
        ledger = Ledger()
        issuer = ledger.create_account("rIssuer", 10000.0)
        issuer.transfer_rate = 1.002  # 0.2% fee
        ledger.create_account("rHolder", 100.0)
        ledger.create_account("rDest", 100.0)
        tl_h = ledger.set_trust_line("rHolder", "USD", "rIssuer", 5000.0)
        tl_h.balance = 1000.0
        tl_d = ledger.set_trust_line("rDest", "USD", "rIssuer", 5000.0)

        tx = create_payment("rHolder", "rDest", 100.0,
                            currency="USD", issuer="rIssuer", sequence=1)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        # Sender debited 100 * 1.002 = 100.2
        self.assertAlmostEqual(tl_h.balance, 1000.0 - 100.2, places=4)
        # Destination credited 100
        self.assertAlmostEqual(tl_d.balance, 100.0, places=4)


# ===================================================================
#  apply_transaction routing (verify all new types dispatch)
# ===================================================================


class TestTransactionRouting(unittest.TestCase):
    """Verify that apply_transaction correctly routes all new tx types."""

    def test_escrow_create_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_escrow_create("rAlice", "rBob", 100.0, sequence=1)
        self.assertEqual(tx.tx_type, 1)  # TT_ESCROW_CREATE
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_account_set_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_account_set("rAlice", domain="test.com", sequence=1)
        self.assertEqual(tx.tx_type, 3)  # TT_ACCOUNT_SET
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_set_regular_key_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_set_regular_key("rAlice", "rKey", sequence=1)
        self.assertEqual(tx.tx_type, 5)  # TT_SET_REGULAR_KEY
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_signer_list_set_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_signer_list_set("rAlice", 1,
                                    [{"account": "rS", "weight": 1}],
                                    sequence=1)
        self.assertEqual(tx.tx_type, 12)  # TT_SIGNER_LIST_SET
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_paychan_create_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_paychan_create("rAlice", "rBob", 100.0,
                                   settle_delay=60, sequence=1)
        self.assertEqual(tx.tx_type, 13)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_check_create_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_check_create("rAlice", "rBob", 100.0, sequence=1)
        self.assertEqual(tx.tx_type, 16)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_deposit_preauth_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_deposit_preauth("rAlice", authorize="rBob", sequence=1)
        self.assertEqual(tx.tx_type, 19)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_ticket_create_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_ticket_create("rAlice", ticket_count=1, sequence=1)
        self.assertEqual(tx.tx_type, 22)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_nftoken_mint_routes(self):
        ledger, _ = _ledger_with_funded()
        tx = create_nftoken_mint("rAlice", uri="ipfs://test", sequence=1)
        self.assertEqual(tx.tx_type, 25)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_duplicate_tx_rejected(self):
        ledger, _ = _ledger_with_funded()
        tx = create_account_set("rAlice", domain="dup.test", sequence=0)
        # Give tx a non-empty tx_id so the duplicate check fires
        tx.tx_id = "dup_test_tx_001"
        _apply(ledger, tx)
        # Second apply with same tx_id should be 109
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 109)


# ===================================================================
#  Close ledger with new transactions
# ===================================================================


class TestCloseLedgerWithNewTxns(unittest.TestCase):
    """Verify close_ledger works after applying new transaction types."""

    def test_close_with_escrow(self):
        ledger, _ = _ledger_with_funded()
        _apply(ledger, create_escrow_create("rAlice", "rBob", 100.0,
                                            sequence=1))
        header = ledger.close_ledger()
        self.assertEqual(header.tx_count, 1)
        self.assertEqual(header.sequence, 1)
        self.assertTrue(header.hash)

    def test_close_with_mixed_types(self):
        ledger, _ = _ledger_with_funded()
        _apply(ledger, create_account_set("rAlice", domain="test.com",
                                          sequence=1))
        _apply(ledger, create_ticket_create("rAlice", ticket_count=2,
                                            sequence=2))
        # Sequence jumped after ticket create
        header = ledger.close_ledger()
        self.assertEqual(header.tx_count, 2)


if __name__ == "__main__":
    unittest.main()
