"""
Transaction validator for NexaFlow.

Validates transactions before they enter the consensus pool:
  - Signature verification
  - Account existence / funding
  - Sequence number checks
  - Fee sufficiency
  - Trust-line existence (IOU payments)
  - Amount sanity checks
  - Escrow / PayChan / Check / NFToken / Ticket validation
"""

from __future__ import annotations

from nexaflow_core.staking import MIN_STAKE_AMOUNT, StakeTier
from nexaflow_core.transaction import (
    TEC_AMENDMENT_BLOCKED,
    TEC_BAD_SEQ,
    TEC_BAD_SIG,
    TEC_CHECK_EXPIRED,
    TEC_ESCROW_BAD_CONDITION,
    TEC_ESCROW_NOT_READY,
    TEC_FROZEN,
    TEC_INSUF_FEE,
    TEC_KEY_IMAGE_SPENT,
    TEC_NFTOKEN_EXISTS,
    TEC_NO_ENTRY,
    TEC_NO_LINE,
    TEC_NO_PERMISSION,
    TEC_NO_RIPPLE,
    TEC_PAYCHAN_EXPIRED,
    TEC_STAKE_DUPLICATE,
    TEC_STAKE_LOCKED,
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
    TT_OFFER_CREATE,
    TT_OFFER_CANCEL,
    TT_PAYCHAN_CLAIM,
    TT_PAYCHAN_CREATE,
    TT_PAYCHAN_FUND,
    TT_SET_REGULAR_KEY,
    TT_SIGNER_LIST_SET,
    TT_STAKE,
    TT_TICKET_CREATE,
    TT_TRUST_SET,
    TT_UNSTAKE,
    Transaction,
)

# Minimum fee in NXF (8 decimal places)
MIN_FEE = 0.00001000
# Minimum reserve to keep an account alive
ACCOUNT_RESERVE = 20.0
OWNER_RESERVE = 5.0
# Account delete fee is higher
ACCOUNT_DELETE_FEE = 5.0


class TransactionValidator:
    """Stateless validator — checks a transaction against a ledger snapshot."""

    def __init__(self, ledger):
        self.ledger = ledger

    def validate(self, tx: Transaction) -> tuple[bool, int, str]:
        """
        Full validation pipeline.
        Returns (is_valid, result_code, human_message).
        """
        # 1. Signature
        if tx.signature and tx.signing_pub_key and not tx.verify_signature():
            return False, TEC_BAD_SIG, "Invalid signature"

        # 1.5. Privacy checks for confidential transactions
        if tx.commitment:
            from nexaflow_core.privacy import (  # type: ignore[import]
                RangeProof,
                verify_ring_signature,
            )

            # Key image double-spend check against ledger
            if tx.key_image and self.ledger.is_key_image_spent(tx.key_image):
                return False, TEC_KEY_IMAGE_SPENT, "Key image already spent (double-spend attempt)"

            # Range proof structural check
            if tx.range_proof and not RangeProof(tx.range_proof).verify(tx.commitment):
                return False, TEC_BAD_SIG, "Invalid range proof"

            # Ring signature verification
            if tx.ring_signature and not verify_ring_signature(
                tx.ring_signature, tx.hash_for_signing()
            ):
                return False, TEC_BAD_SIG, "Invalid ring signature"

        # 2. Source account exists
        src_acc = self.ledger.get_account(tx.account)
        if src_acc is None:
            return False, TEC_UNFUNDED, f"Account {tx.account} does not exist"

        # 3. Fee check
        fee_val = tx.fee.value if hasattr(tx.fee, 'value') else float(tx.fee)
        if fee_val < MIN_FEE:
            return False, TEC_INSUF_FEE, f"Fee {fee_val} below minimum {MIN_FEE}"

        # 4. Sequence check (if non-zero)
        if tx.sequence != 0 and tx.sequence != src_acc.sequence:
            return (
                False,
                TEC_BAD_SEQ,
                f"Expected seq {src_acc.sequence}, got {tx.sequence}",
            )

        # 5. Balance check — must cover fee + reserve (skip for confidential)
        if not tx.commitment:
            required_reserve = ACCOUNT_RESERVE + OWNER_RESERVE * src_acc.owner_count
            if tx.tx_type == 0:  # Payment
                return self._validate_payment(tx, src_acc, fee_val, required_reserve)
            elif tx.tx_type == TT_TRUST_SET:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            elif tx.tx_type == TT_STAKE:
                return self._validate_stake(tx, src_acc, fee_val, required_reserve)
            elif tx.tx_type == TT_UNSTAKE:
                return self._validate_unstake(tx, src_acc, fee_val)
            elif tx.tx_type == TT_ESCROW_CREATE:
                return self._validate_escrow_create(tx, src_acc, fee_val, required_reserve)
            elif tx.tx_type == TT_ESCROW_FINISH:
                return self._validate_escrow_finish(tx, src_acc, fee_val)
            elif tx.tx_type == TT_ESCROW_CANCEL:
                return self._validate_escrow_cancel(tx, src_acc, fee_val)
            elif tx.tx_type == TT_PAYCHAN_CREATE:
                return self._validate_paychan_create(tx, src_acc, fee_val, required_reserve)
            elif tx.tx_type == TT_PAYCHAN_FUND:
                return self._validate_paychan_fund(tx, src_acc, fee_val)
            elif tx.tx_type == TT_PAYCHAN_CLAIM:
                return self._validate_paychan_claim(tx, src_acc, fee_val)
            elif tx.tx_type == TT_CHECK_CREATE:
                return self._validate_check_create(tx, src_acc, fee_val)
            elif tx.tx_type == TT_CHECK_CASH:
                return self._validate_check_cash(tx, src_acc, fee_val)
            elif tx.tx_type == TT_CHECK_CANCEL:
                return self._validate_check_cancel(tx, src_acc, fee_val)
            elif tx.tx_type == TT_SET_REGULAR_KEY:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            elif tx.tx_type == TT_SIGNER_LIST_SET:
                return self._validate_signer_list_set(tx, src_acc, fee_val)
            elif tx.tx_type == TT_ACCOUNT_SET:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            elif tx.tx_type == TT_ACCOUNT_DELETE:
                return self._validate_account_delete(tx, src_acc, fee_val)
            elif tx.tx_type == TT_DEPOSIT_PREAUTH:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            elif tx.tx_type == TT_TICKET_CREATE:
                return self._validate_ticket_create(tx, src_acc, fee_val)
            elif tx.tx_type == TT_NFTOKEN_MINT:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            elif tx.tx_type == TT_NFTOKEN_BURN:
                return self._validate_nftoken_burn(tx, src_acc, fee_val)
            elif tx.tx_type == TT_NFTOKEN_OFFER_CREATE:
                return self._validate_nftoken_offer_create(tx, src_acc, fee_val)
            elif tx.tx_type == TT_NFTOKEN_OFFER_ACCEPT:
                return self._validate_nftoken_offer_accept(tx, src_acc, fee_val)
            elif tx.tx_type in (TT_OFFER_CREATE, TT_OFFER_CANCEL):
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            else:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"

        return True, TES_SUCCESS, "Valid"

    # ---- per-type validators ----

    def _validate_payment(self, tx, src_acc, fee_val, required_reserve):
        amt = tx.amount
        if amt.is_native():
            needed = amt.value + fee_val
            if src_acc.balance - needed < required_reserve:
                return (
                    False, TEC_UNFUNDED,
                    f"Insufficient balance: have {src_acc.balance}, "
                    f"need {needed} + reserve {required_reserve}",
                )
            # Check deposit_auth on destination
            dst_acc = self.ledger.get_account(tx.destination)
            if dst_acc is not None and dst_acc.deposit_auth:
                if tx.account not in dst_acc.deposit_preauth:
                    return False, TEC_NO_PERMISSION, "Destination requires deposit preauthorization"
        else:
            if src_acc.balance < fee_val:
                return False, TEC_INSUF_FEE, "Cannot cover fee"
            tl = self.ledger.get_trust_line(tx.account, amt.currency, amt.issuer)
            if tl is None and tx.account != amt.issuer:
                return False, TEC_NO_LINE, f"No trust line for {amt.currency}/{amt.issuer}"
            if tl is not None:
                if tl.frozen:
                    return False, TEC_FROZEN, "Trust line is frozen"
                if tl.no_ripple:
                    return False, TEC_NO_RIPPLE, "Trust line has noRipple flag set"
        return True, TES_SUCCESS, "Valid"

    def _validate_stake(self, tx, src_acc, fee_val, required_reserve):
        amt_val = tx.amount.value if hasattr(tx.amount, 'value') else float(tx.amount)
        if amt_val < MIN_STAKE_AMOUNT:
            return False, TEC_UNFUNDED, f"Minimum stake is {MIN_STAKE_AMOUNT} NXF"
        tier_val = tx.flags.get("stake_tier", -1) if tx.flags else -1
        try:
            StakeTier(tier_val)
        except (ValueError, KeyError):
            return False, TEC_STAKE_LOCKED, f"Invalid staking tier: {tier_val}"
        needed = amt_val + fee_val
        if src_acc.balance - needed < required_reserve:
            return (
                False, TEC_UNFUNDED,
                f"Insufficient balance: have {src_acc.balance}, "
                f"need {needed} + reserve {required_reserve}",
            )
        return True, TES_SUCCESS, "Valid"

    def _validate_unstake(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        stake_id = tx.flags.get("stake_id", "") if tx.flags else ""
        if not stake_id:
            return False, TEC_STAKE_LOCKED, "Missing stake_id in flags"
        record = self.ledger.staking_pool.stakes.get(stake_id)
        if record is None:
            return False, TEC_STAKE_LOCKED, f"Stake {stake_id} not found"
        if record.address != tx.account:
            return False, TEC_STAKE_LOCKED, "Cannot cancel another account's stake"
        if record.matured or record.cancelled:
            return False, TEC_STAKE_DUPLICATE, "Stake already resolved"
        return True, TES_SUCCESS, "Valid"

    def _validate_escrow_create(self, tx, src_acc, fee_val, required_reserve):
        amt_val = tx.amount.value
        needed = amt_val + fee_val
        if src_acc.balance - needed < required_reserve:
            return False, TEC_UNFUNDED, f"Cannot afford escrow of {amt_val} NXF"
        if not tx.destination:
            return False, TEC_NO_PERMISSION, "Escrow requires a destination"
        finish_after = tx.flags.get("finish_after", 0) if tx.flags else 0
        cancel_after = tx.flags.get("cancel_after", 0) if tx.flags else 0
        if cancel_after > 0 and finish_after > 0 and finish_after >= cancel_after:
            return False, TEC_ESCROW_BAD_CONDITION, "finish_after must be before cancel_after"
        return True, TES_SUCCESS, "Valid"

    def _validate_escrow_finish(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        escrow_id = tx.flags.get("escrow_id", "") if tx.flags else ""
        if not escrow_id:
            return False, TEC_NO_ENTRY, "Missing escrow_id"
        entry = self.ledger.escrow_manager.get_escrow(escrow_id)
        if entry is None:
            return False, TEC_NO_ENTRY, f"Escrow {escrow_id} not found"
        if entry.finished or entry.cancelled:
            return False, TEC_NO_PERMISSION, "Escrow already resolved"
        return True, TES_SUCCESS, "Valid"

    def _validate_escrow_cancel(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        escrow_id = tx.flags.get("escrow_id", "") if tx.flags else ""
        if not escrow_id:
            return False, TEC_NO_ENTRY, "Missing escrow_id"
        entry = self.ledger.escrow_manager.get_escrow(escrow_id)
        if entry is None:
            return False, TEC_NO_ENTRY, f"Escrow {escrow_id} not found"
        return True, TES_SUCCESS, "Valid"

    def _validate_paychan_create(self, tx, src_acc, fee_val, required_reserve):
        amt_val = tx.amount.value
        needed = amt_val + fee_val
        if src_acc.balance - needed < required_reserve:
            return False, TEC_UNFUNDED, f"Cannot afford channel of {amt_val} NXF"
        if not tx.destination:
            return False, TEC_NO_PERMISSION, "Channel requires a destination"
        settle_delay = tx.flags.get("settle_delay", 0) if tx.flags else 0
        if settle_delay <= 0:
            return False, TEC_NO_PERMISSION, "settle_delay must be positive"
        return True, TES_SUCCESS, "Valid"

    def _validate_paychan_fund(self, tx, src_acc, fee_val):
        amt_val = tx.amount.value
        if src_acc.balance < amt_val + fee_val:
            return False, TEC_UNFUNDED, "Insufficient balance to fund channel"
        channel_id = tx.flags.get("channel_id", "") if tx.flags else ""
        if not channel_id:
            return False, TEC_NO_ENTRY, "Missing channel_id"
        ch = self.ledger.channel_manager.get_channel(channel_id)
        if ch is None:
            return False, TEC_NO_ENTRY, f"Channel {channel_id} not found"
        if ch.account != tx.account:
            return False, TEC_NO_PERMISSION, "Only channel creator can fund"
        return True, TES_SUCCESS, "Valid"

    def _validate_paychan_claim(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        channel_id = tx.flags.get("channel_id", "") if tx.flags else ""
        if not channel_id:
            return False, TEC_NO_ENTRY, "Missing channel_id"
        ch = self.ledger.channel_manager.get_channel(channel_id)
        if ch is None:
            return False, TEC_NO_ENTRY, f"Channel {channel_id} not found"
        if ch.closed:
            return False, TEC_PAYCHAN_EXPIRED, "Channel is closed"
        return True, TES_SUCCESS, "Valid"

    def _validate_check_create(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        if not tx.destination:
            return False, TEC_NO_PERMISSION, "Check requires a destination"
        send_max = tx.amount.value
        if send_max <= 0:
            return False, TEC_NO_PERMISSION, "send_max must be positive"
        return True, TES_SUCCESS, "Valid"

    def _validate_check_cash(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        check_id = tx.flags.get("check_id", "") if tx.flags else ""
        if not check_id:
            return False, TEC_NO_ENTRY, "Missing check_id"
        entry = self.ledger.check_manager.get_check(check_id)
        if entry is None:
            return False, TEC_NO_ENTRY, f"Check {check_id} not found"
        if entry.destination != tx.account:
            return False, TEC_NO_PERMISSION, "Only destination can cash a check"
        if entry.cashed or entry.cancelled:
            return False, TEC_CHECK_EXPIRED, "Check already resolved"
        return True, TES_SUCCESS, "Valid"

    def _validate_check_cancel(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        check_id = tx.flags.get("check_id", "") if tx.flags else ""
        if not check_id:
            return False, TEC_NO_ENTRY, "Missing check_id"
        entry = self.ledger.check_manager.get_check(check_id)
        if entry is None:
            return False, TEC_NO_ENTRY, f"Check {check_id} not found"
        return True, TES_SUCCESS, "Valid"

    def _validate_signer_list_set(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        quorum = tx.flags.get("signer_quorum", 0) if tx.flags else 0
        entries = tx.flags.get("signer_entries", []) if tx.flags else []
        if quorum > 0 and not entries:
            return False, TEC_NO_PERMISSION, "Quorum set but no signers provided"
        if entries:
            addrs = [e.get("account", "") for e in entries]
            if tx.account in addrs:
                return False, TEC_NO_PERMISSION, "Account cannot be in its own signer list"
            if len(addrs) != len(set(addrs)):
                return False, TEC_NO_PERMISSION, "Duplicate signer accounts"
            total_w = sum(e.get("weight", 0) for e in entries)
            if total_w < quorum:
                return False, TEC_NO_PERMISSION, f"Total weight {total_w} < quorum {quorum}"
        return True, TES_SUCCESS, "Valid"

    def _validate_account_delete(self, tx, src_acc, fee_val):
        if fee_val < ACCOUNT_DELETE_FEE:
            return False, TEC_INSUF_FEE, f"Account deletion requires fee >= {ACCOUNT_DELETE_FEE}"
        if src_acc.owner_count > 0:
            return False, TEC_NO_PERMISSION, "Cannot delete account with owned objects"
        if len(src_acc.trust_lines) > 0:
            return False, TEC_NO_PERMISSION, "Cannot delete account with trust lines"
        if not tx.destination:
            return False, TEC_NO_PERMISSION, "Must specify destination for remaining balance"
        if tx.destination == tx.account:
            return False, TEC_NO_PERMISSION, "Cannot delete to self"
        dst = self.ledger.get_account(tx.destination)
        if dst is None:
            return False, TEC_UNFUNDED, "Destination account does not exist"
        return True, TES_SUCCESS, "Valid"

    def _validate_ticket_create(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        count = tx.flags.get("ticket_count", 1) if tx.flags else 1
        if count < 1 or count > 250:
            return False, TEC_NO_PERMISSION, "ticket_count must be 1-250"
        return True, TES_SUCCESS, "Valid"

    def _validate_nftoken_burn(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        nftoken_id = tx.flags.get("nftoken_id", "") if tx.flags else ""
        if not nftoken_id:
            return False, TEC_NO_ENTRY, "Missing nftoken_id"
        token = self.ledger.nftoken_manager.get_token(nftoken_id)
        if token is None:
            return False, TEC_NO_ENTRY, f"NFToken {nftoken_id} not found"
        if token.burned:
            return False, TEC_NFTOKEN_EXISTS, "NFToken already burned"
        if token.owner != tx.account and not (token.burnable and token.issuer == tx.account):
            return False, TEC_NO_PERMISSION, "Not authorized to burn"
        return True, TES_SUCCESS, "Valid"

    def _validate_nftoken_offer_create(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        nftoken_id = tx.flags.get("nftoken_id", "") if tx.flags else ""
        if not nftoken_id:
            return False, TEC_NO_ENTRY, "Missing nftoken_id"
        token = self.ledger.nftoken_manager.get_token(nftoken_id)
        if token is None or token.burned:
            return False, TEC_NO_ENTRY, "NFToken not found or burned"
        is_sell = tx.flags.get("is_sell", False)
        if is_sell and token.owner != tx.account:
            return False, TEC_NO_PERMISSION, "Only owner can create sell offers"
        if not is_sell and token.owner == tx.account:
            return False, TEC_NO_PERMISSION, "Cannot buy your own token"
        if not token.transferable and tx.account != token.issuer and not is_sell:
            return False, TEC_NO_PERMISSION, "Token is not transferable"
        return True, TES_SUCCESS, "Valid"

    def _validate_nftoken_offer_accept(self, tx, src_acc, fee_val):
        if src_acc.balance < fee_val:
            return False, TEC_INSUF_FEE, "Cannot cover fee"
        offer_id = tx.flags.get("offer_id", "") if tx.flags else ""
        if not offer_id:
            return False, TEC_NO_ENTRY, "Missing offer_id"
        offer = self.ledger.nftoken_manager.offers.get(offer_id)
        if offer is None:
            return False, TEC_NO_ENTRY, "Offer not found"
        if offer.accepted or offer.cancelled:
            return False, TEC_NO_PERMISSION, "Offer already resolved"
        if offer.destination and offer.destination != tx.account:
            return False, TEC_NO_PERMISSION, "Offer restricted to specific account"
        # Check buyer has funds
        if offer.is_sell and offer.amount > 0:
            if src_acc.balance < offer.amount + fee_val:
                return False, TEC_UNFUNDED, "Insufficient balance to accept sell offer"
        return True, TES_SUCCESS, "Valid"

    def validate_batch(self, txns: list) -> list:
        """Validate a list of transactions. Returns list of (tx, valid, code, msg)."""
        return [(tx, *self.validate(tx)) for tx in txns]
