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

from typing import Tuple

from nexaflow_core.transaction import (
    Transaction,
    Amount,
    TEC_UNFUNDED,
    TEC_NO_LINE,
    TEC_INSUF_FEE,
    TEC_BAD_SEQ,
    TEC_BAD_SIG,
    TES_SUCCESS,
    RESULT_NAMES,
)

# Minimum fee in NXF
MIN_FEE = 0.000010
# Minimum reserve to keep an account alive
ACCOUNT_RESERVE = 20.0
OWNER_RESERVE = 5.0


class TransactionValidator:
    """Stateless validator — checks a transaction against a ledger snapshot."""

    def __init__(self, ledger):
        self.ledger = ledger

    def validate(self, tx: Transaction) -> Tuple[bool, int, str]:
        """
        Full validation pipeline.
        Returns (is_valid, result_code, human_message).
        """
        # 1. Signature
        if tx.signature and tx.signing_pub_key:
            if not tx.verify_signature():
                return False, TEC_BAD_SIG, "Invalid signature"

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

        # 5. Balance check — must cover fee + reserve
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
        else:
            if src_acc.balance < fee_val:
                return False, TEC_INSUF_FEE, "Cannot cover fee"

        return True, TES_SUCCESS, "Valid"

    def validate_batch(self, txns: list) -> list:
        """Validate a list of transactions. Returns list of (tx, valid, code, msg)."""
        return [(tx, *self.validate(tx)) for tx in txns]
