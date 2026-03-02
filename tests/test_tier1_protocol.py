"""
Tests for Tier 1 protocol mechanics:
  - Authorized trust lines (RequireAuth + tfSetfAuth)
  - Global & individual freeze enforcement
  - Transfer rate on IOUs
  - Destination / Source tags + RequireDest
  - Partial payments (tfPartialPayment)
  - Quality In / Quality Out
  - Offer execution flags (IOC / FOK / tfSell)
"""

import pytest
from nexaflow_core.ledger import Ledger, AccountEntry, TrustLineEntry
from nexaflow_core.transaction import (
    Transaction, Amount,
    TT_PAYMENT, TT_TRUST_SET, TT_OFFER_CREATE, TT_ACCOUNT_SET,
    TES_SUCCESS, TEC_UNFUNDED, TEC_NO_LINE, TEC_FROZEN,
    TEC_REQUIRE_AUTH, TEC_PARTIAL_PAYMENT,
)


# ── helpers ──────────────────────────────────────────────────────

def _ledger():
    return Ledger(total_supply=1_000_000.0, genesis_account="genesis")


_fund_counter = 0

def _fund(ledger, addr, amount=10_000.0):
    """Send native NXF from genesis to addr."""
    global _fund_counter
    _fund_counter += 1
    tx = Transaction(TT_PAYMENT, "genesis", addr, Amount(amount), Amount(0.00001), 0)
    tx.tx_id = f"fund_{addr}_{_fund_counter}"
    ledger.apply_transaction(tx)


_trust_counter = 0

def _set_trust(ledger, holder, currency, issuer, limit, flags=None):
    global _trust_counter
    _trust_counter += 1
    tx = Transaction(TT_TRUST_SET, holder, "", Amount(0.0), Amount(0.00001), 0)
    tx.limit_amount = Amount(limit, currency, issuer)
    tx.flags = flags or {}
    tx.tx_id = f"trust_{holder}_{currency}_{issuer}_{_trust_counter}"
    return ledger.apply_transaction(tx)


_iou_counter = 0

def _iou_payment(ledger, src, dst, amount, currency, issuer, flags=None, tag=0):
    global _iou_counter
    _iou_counter += 1
    tx = Transaction(TT_PAYMENT, src, dst, Amount(amount, currency, issuer), Amount(0.00001), 0)
    tx.flags = flags or {}
    tx.destination_tag = tag
    tx.tx_id = f"iou_{src}_{dst}_{amount}_{currency}_{_iou_counter}"
    return ledger.apply_transaction(tx), tx


_acctset_counter = 0

def _account_set(ledger, account, set_flag=None, clear_flag=None, transfer_rate=None):
    global _acctset_counter
    _acctset_counter += 1
    tx = Transaction(TT_ACCOUNT_SET, account, "", Amount(0.0), Amount(0.00001), 0)
    flags = {}
    if set_flag:
        flags["set_flags"] = {set_flag: True}
    if clear_flag:
        flags["clear_flags"] = {clear_flag: True}
    if transfer_rate is not None:
        flags["transfer_rate"] = transfer_rate
    tx.flags = flags
    tx.tx_id = f"acctset_{account}_{set_flag}_{_acctset_counter}"
    return ledger.apply_transaction(tx)


# ═══════════════════════════════════════════════════════════════════
#  T1.1 — Authorized Trust Lines (RequireAuth)
# ═══════════════════════════════════════════════════════════════════

class TestAuthorizedTrustLines:
    def test_require_auth_blocks_unauthorized_payment(self):
        """Issuer sets asfRequireAuth; unauthorized trust line rejects IOU."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        # Issuer enables RequireAuth
        _account_set(ledger, "issuer", set_flag="asfRequireAuth")
        assert ledger.accounts["issuer"].require_auth

        # Alice sets trust line but does NOT get authorized
        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        _set_trust(ledger, "bob", "USD", "issuer", 1000.0)

        # Issuer sends USD to alice — should fail (trust line not authorized)
        rc, _ = _iou_payment(ledger, "issuer", "alice", 100, "USD", "issuer")
        assert rc == TEC_REQUIRE_AUTH
    
    def test_authorized_trust_line_allows_payment(self):
        """After issuer authorizes the trust line, payments succeed."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)

        _account_set(ledger, "issuer", set_flag="asfRequireAuth")
        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)

        # Issuer authorizes alice's trust line
        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"tfSetfAuth": True})

        tl = ledger.get_trust_line("alice", "USD", "issuer")
        assert tl.authorized

        # Now issuer → alice should succeed
        rc, _ = _iou_payment(ledger, "issuer", "alice", 100, "USD", "issuer")
        assert rc == TES_SUCCESS

    def test_clear_auth(self):
        """tfClearfAuth revokes authorization."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"tfSetfAuth": True})
        tl = ledger.get_trust_line("alice", "USD", "issuer")
        assert tl.authorized

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"tfClearfAuth": True})
        assert not tl.authorized


# ═══════════════════════════════════════════════════════════════════
#  T1.2 — Global & Individual Freeze
# ═══════════════════════════════════════════════════════════════════

class TestFreezeEnforcement:
    def test_global_freeze_blocks_iou_payment(self):
        """Issuer's global_freeze blocks all IOU movement except back to issuer."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        _set_trust(ledger, "bob", "USD", "issuer", 1000.0)

        # Fund alice with some USD
        rc, _ = _iou_payment(ledger, "issuer", "alice", 100, "USD", "issuer")
        assert rc == TES_SUCCESS

        # Issuer enables global freeze
        _account_set(ledger, "issuer", set_flag="asfGlobalFreeze")
        assert ledger.accounts["issuer"].global_freeze

        # alice → bob should fail (global freeze)
        rc, _ = _iou_payment(ledger, "alice", "bob", 50, "USD", "issuer")
        assert rc == 132  # tecGLOBAL_FREEZE

    def test_global_freeze_allows_return_to_issuer(self):
        """Under global freeze, tokens can still flow back to issuer."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        rc, _ = _iou_payment(ledger, "issuer", "alice", 100, "USD", "issuer")
        assert rc == TES_SUCCESS

        _account_set(ledger, "issuer", set_flag="asfGlobalFreeze")

        # alice → issuer should succeed
        rc, _ = _iou_payment(ledger, "alice", "issuer", 50, "USD", "issuer")
        assert rc == TES_SUCCESS

    def test_individual_freeze(self):
        """tfSetFreeze on a trust line blocks that line's payments."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        rc, _ = _iou_payment(ledger, "issuer", "alice", 100, "USD", "issuer")
        assert rc == TES_SUCCESS

        # Freeze alice's trust line
        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"tfSetFreeze": True})
        tl = ledger.get_trust_line("alice", "USD", "issuer")
        assert tl.frozen

        # Payment from alice should fail
        _fund(ledger, "bob", 10_000)
        _set_trust(ledger, "bob", "USD", "issuer", 1000.0)
        rc, _ = _iou_payment(ledger, "alice", "bob", 10, "USD", "issuer")
        assert rc == TEC_FROZEN


# ═══════════════════════════════════════════════════════════════════
#  T1.3 — Transfer Rate
# ═══════════════════════════════════════════════════════════════════

class TestTransferRate:
    def test_transfer_rate_deducts_extra(self):
        """Issuer's transfer_rate > 1.0 deducts extra from sender."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        # Set transfer rate to 1.02 (2% fee)
        _account_set(ledger, "issuer", transfer_rate=1.02)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        _set_trust(ledger, "bob", "USD", "issuer", 1000.0)

        rc, _ = _iou_payment(ledger, "issuer", "alice", 200, "USD", "issuer")
        assert rc == TES_SUCCESS

        # alice → bob, 100 USD. With 2% rate, alice pays 102
        rc, _ = _iou_payment(ledger, "alice", "bob", 100, "USD", "issuer")
        assert rc == TES_SUCCESS

        tl_alice = ledger.get_trust_line("alice", "USD", "issuer")
        # alice started with 200, paid 102 for a 100 delivery
        assert tl_alice.balance == pytest.approx(98.0, abs=0.01)


# ═══════════════════════════════════════════════════════════════════
#  T1.4 — Destination / Source Tags + RequireDest
# ═══════════════════════════════════════════════════════════════════

class TestDestinationTags:
    def test_destination_tag_on_transaction(self):
        """Transaction can carry destination_tag and source_tag."""
        tx = Transaction(TT_PAYMENT, "alice", "bob", Amount(100), Amount(0.00001), 1)
        tx.destination_tag = 42
        tx.source_tag = 7
        assert tx.destination_tag == 42
        assert tx.source_tag == 7

        d = tx.to_dict()
        assert d["destination_tag"] == 42
        assert d["source_tag"] == 7

    def test_require_dest_rejects_no_tag(self):
        """Account with require_dest rejects payments without destination_tag."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        # Bob requires destination tag
        _account_set(ledger, "bob", set_flag="asfRequireDest")
        assert ledger.accounts["bob"].require_dest

        # Payment without tag should fail
        rc, _ = _iou_payment(ledger, "alice", "bob", 100, "NXF", "", tag=0)
        # For native payments, use regular Payment:
        tx = Transaction(TT_PAYMENT, "alice", "bob", Amount(100), Amount(0.00001), 0)
        tx.tx_id = "require_dest_test"
        tx.destination_tag = 0
        rc = ledger.apply_transaction(tx)
        assert rc == 131  # tecDST_TAG_NEEDED

    def test_require_dest_accepts_with_tag(self):
        """Payment with destination_tag succeeds when require_dest is set."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        _account_set(ledger, "bob", set_flag="asfRequireDest")

        tx = Transaction(TT_PAYMENT, "alice", "bob", Amount(100), Amount(0.00001), 0)
        tx.tx_id = "require_dest_pass"
        tx.destination_tag = 42
        rc = ledger.apply_transaction(tx)
        assert rc == TES_SUCCESS

    def test_tags_included_in_serialization(self):
        """Tags are included in serialize_for_signing."""
        tx1 = Transaction(TT_PAYMENT, "a", "b", Amount(1), Amount(0.00001), 1)
        tx1.destination_tag = 0
        tx1.source_tag = 0
        blob1 = tx1.serialize_for_signing()

        tx2 = Transaction(TT_PAYMENT, "a", "b", Amount(1), Amount(0.00001), 1)
        tx2.destination_tag = 42
        tx2.source_tag = 0
        blob2 = tx2.serialize_for_signing()

        assert blob1 != blob2  # tag changes the blob

    def test_delivered_amount_field(self):
        """delivered_amount field starts at -1 (unset) and can be set."""
        tx = Transaction(TT_PAYMENT, "a", "b", Amount(100), Amount(0.00001), 1)
        assert tx.delivered_amount == -1.0
        tx.delivered_amount = 50.0
        d = tx.to_dict()
        assert d["delivered_amount"] == 50.0


# ═══════════════════════════════════════════════════════════════════
#  T1.5 — Partial Payments
# ═══════════════════════════════════════════════════════════════════

class TestPartialPayments:
    def test_partial_payment_delivers_available_amount(self):
        """tfPartialPayment flag delivers as much as possible."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        _set_trust(ledger, "bob", "USD", "issuer", 1000.0)

        # Give alice 50 USD
        rc, _ = _iou_payment(ledger, "issuer", "alice", 50, "USD", "issuer")
        assert rc == TES_SUCCESS

        # alice tries to send 100 USD with partial flag — only 50 available
        rc, tx = _iou_payment(ledger, "alice", "bob", 100, "USD", "issuer",
                              flags={"tfPartialPayment": True})
        assert rc == TES_SUCCESS
        assert tx.delivered_amount == pytest.approx(50.0, abs=0.01)

    def test_no_partial_flag_fails_on_insufficient(self):
        """Without tfPartialPayment, insufficient balance fails."""
        ledger = _ledger()
        _fund(ledger, "issuer", 10_000)
        _fund(ledger, "alice", 10_000)
        _fund(ledger, "bob", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0)
        _set_trust(ledger, "bob", "USD", "issuer", 1000.0)

        rc, _ = _iou_payment(ledger, "issuer", "alice", 50, "USD", "issuer")
        assert rc == TES_SUCCESS

        rc, _ = _iou_payment(ledger, "alice", "bob", 100, "USD", "issuer")
        assert rc == TEC_UNFUNDED


# ═══════════════════════════════════════════════════════════════════
#  T1.6 — Quality In / Quality Out
# ═══════════════════════════════════════════════════════════════════

class TestQualityInOut:
    def test_set_quality_via_trust_set(self):
        """TrustSet with quality_in/quality_out flags sets the fields."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"quality_in": 0.9, "quality_out": 1.1})

        tl = ledger.get_trust_line("alice", "USD", "issuer")
        assert tl.quality_in == pytest.approx(0.9)
        assert tl.quality_out == pytest.approx(1.1)

    def test_no_ripple_flag(self):
        """tfSetNoRipple / tfClearNoRipple toggles the no_ripple field."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"tfSetNoRipple": True})
        tl = ledger.get_trust_line("alice", "USD", "issuer")
        assert tl.no_ripple

        _set_trust(ledger, "alice", "USD", "issuer", 1000.0,
                   flags={"tfClearNoRipple": True})
        assert not tl.no_ripple


# ═══════════════════════════════════════════════════════════════════
#  T1.7 — Offer Execution Flags
# ═══════════════════════════════════════════════════════════════════

class TestOfferFlags:
    def test_offer_ioc_flag(self):
        """OfferCreate with tfImmediateOrCancel records IOC."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)

        tx = Transaction(TT_OFFER_CREATE, "alice", "", Amount(0.0), Amount(0.00001), 0)
        tx.taker_pays = Amount(100, "USD", "issuer")
        tx.taker_gets = Amount(50)
        tx.flags = {"tfImmediateOrCancel": True}
        tx.tx_id = "offer_ioc"
        rc = ledger.apply_transaction(tx)
        assert rc == TES_SUCCESS

        offer = ledger.accounts["alice"].open_offers[-1]
        assert offer["time_in_force"] == "IOC"

    def test_offer_fok_flag(self):
        """OfferCreate with tfFillOrKill records FOK."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)

        tx = Transaction(TT_OFFER_CREATE, "alice", "", Amount(0.0), Amount(0.00001), 0)
        tx.taker_pays = Amount(100, "USD", "issuer")
        tx.taker_gets = Amount(50)
        tx.flags = {"tfFillOrKill": True}
        tx.tx_id = "offer_fok"
        rc = ledger.apply_transaction(tx)
        assert rc == TES_SUCCESS

        offer = ledger.accounts["alice"].open_offers[-1]
        assert offer["time_in_force"] == "FOK"

    def test_offer_sell_flag(self):
        """OfferCreate with tfSell records sell priority."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)

        tx = Transaction(TT_OFFER_CREATE, "alice", "", Amount(0.0), Amount(0.00001), 0)
        tx.taker_pays = Amount(100, "USD", "issuer")
        tx.taker_gets = Amount(50)
        tx.flags = {"tfSell": True}
        tx.tx_id = "offer_sell"
        rc = ledger.apply_transaction(tx)
        assert rc == TES_SUCCESS

        offer = ledger.accounts["alice"].open_offers[-1]
        assert offer["tf_sell"] is True

    def test_default_offer_is_gtc(self):
        """Default offer (no flags) is GTC."""
        ledger = _ledger()
        _fund(ledger, "alice", 10_000)

        tx = Transaction(TT_OFFER_CREATE, "alice", "", Amount(0.0), Amount(0.00001), 0)
        tx.taker_pays = Amount(100, "USD", "issuer")
        tx.taker_gets = Amount(50)
        tx.flags = {}
        tx.tx_id = "offer_gtc"
        rc = ledger.apply_transaction(tx)
        assert rc == TES_SUCCESS

        offer = ledger.accounts["alice"].open_offers[-1]
        assert offer["time_in_force"] == "GTC"
        assert offer["tf_sell"] is False
