"""
Transaction validator for NexaFlow.

Validates transactions before they enter the consensus pool:
  - Signature verification
  - Account existence / funding
  - Sequence number checks
  - Fee sufficiency
  - Trust-line existence (IOU payments)
  - Amount sanity checks
"""

from __future__ import annotations

from nexaflow_core.staking import MIN_STAKE_AMOUNT, StakeTier
from nexaflow_core.transaction import (
    TEC_BAD_SEQ,
    TEC_BAD_SIG,
    TEC_INSUF_FEE,
    TEC_KEY_IMAGE_SPENT,
    TEC_NO_LINE,
    TEC_STAKE_DUPLICATE,
    TEC_STAKE_LOCKED,
    TEC_UNFUNDED,
    TES_SUCCESS,
    TT_STAKE,
    TT_UNSTAKE,
    Transaction,
)

# Minimum fee in NXF (8 decimal places)
MIN_FEE = 0.00001000
# Minimum reserve to keep an account alive
ACCOUNT_RESERVE = 20.0
OWNER_RESERVE = 5.0


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
                amt = tx.amount
                if amt.is_native():
                    needed = amt.value + fee_val
                    if src_acc.balance - needed < required_reserve:
                        return (
                            False,
                            TEC_UNFUNDED,
                            f"Insufficient balance: have {src_acc.balance}, "
                            f"need {needed} + reserve {required_reserve}",
                        )
                else:
                    # IOU — just check fee
                    if src_acc.balance < fee_val:
                        return False, TEC_INSUF_FEE, "Cannot cover fee"
                    # Check trust line
                    tl = self.ledger.get_trust_line(
                        tx.account, amt.currency, amt.issuer
                    )
                    if tl is None and tx.account != amt.issuer:
                        return (
                            False,
                            TEC_NO_LINE,
                            f"No trust line for {amt.currency}/{amt.issuer}",
                        )
            elif tx.tx_type == 20:  # TrustSet
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"
            elif tx.tx_type == TT_STAKE:  # Stake
                amt_val = tx.amount.value if hasattr(tx.amount, 'value') else float(tx.amount)
                if amt_val < MIN_STAKE_AMOUNT:
                    return (
                        False,
                        TEC_UNFUNDED,
                        f"Minimum stake is {MIN_STAKE_AMOUNT} NXF",
                    )
                tier_val = tx.flags.get("stake_tier", -1) if tx.flags else -1
                try:
                    StakeTier(tier_val)
                except (ValueError, KeyError):
                    return False, TEC_STAKE_LOCKED, f"Invalid staking tier: {tier_val}"
                needed = amt_val + fee_val
                if src_acc.balance - needed < required_reserve:
                    return (
                        False,
                        TEC_UNFUNDED,
                        f"Insufficient balance: have {src_acc.balance}, "
                        f"need {needed} + reserve {required_reserve}",
                    )
            elif tx.tx_type == TT_UNSTAKE:  # Unstake (early cancel)
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
            else:
                if src_acc.balance < fee_val:
                    return False, TEC_INSUF_FEE, "Cannot cover fee"

        return True, TES_SUCCESS, "Valid"

    def validate_batch(self, txns: list) -> list:
        """Validate a list of transactions. Returns list of (tx, valid, code, msg)."""
        return [(tx, *self.validate(tx)) for tx in txns]
