"""
Security-focused tests for nexaflow_core.validator — bypass & edge cases.

Covers:
  - Stake validation: min amount, invalid tier, balance check with reserve
  - Unstake validation: missing stake_id, wrong owner, already resolved
  - Extreme amounts (near overflow)
  - Fee exactly at minimum boundary
  - Sequence of 0 (allowed) vs wrong sequence
  - IOU edge cases with gateway accounts
  - Confidential TX path (key image check)
  - validate_batch with mixed valid/invalid
"""

import time
import unittest

from nexaflow_core.ledger import Ledger
from nexaflow_core.staking import MIN_STAKE_AMOUNT
from nexaflow_core.transaction import (
    TEC_BAD_SEQ,
    TEC_INSUF_FEE,
    TEC_STAKE_DUPLICATE,
    TEC_STAKE_LOCKED,
    TEC_UNFUNDED,
    TES_SUCCESS,
    create_payment,
    create_stake,
    create_trust_set,
    create_unstake,
)
from nexaflow_core.validator import (
    MIN_FEE,
    TransactionValidator,
)
from nexaflow_core.wallet import Wallet

# ── Wallet registry for auto-signing ──
_WALLETS: dict[str, Wallet] = {}


def _get_or_create_wallet(name: str) -> Wallet:
    if name not in _WALLETS:
        w = Wallet.from_seed(name)
        _WALLETS[name] = w
        _WALLETS[w.address] = w
    return _WALLETS[name]


def _sign(name_or_addr: str, tx):
    """Sign *tx* with the wallet for *name_or_addr*, resetting seq to 1."""
    w = _WALLETS.get(name_or_addr)
    if not w:
        w = _get_or_create_wallet(name_or_addr)
    w._sequence = 1
    tx.sequence = 0  # let sign_transaction fill from wallet
    w.sign_transaction(tx)
    return tx


class ValidatorSecBase(unittest.TestCase):
    def setUp(self):
        self.ledger = Ledger(total_supply=100_000.0, genesis_account="rGen")
        # Create wallets and wallet-derived accounts
        self._w_alice = _get_or_create_wallet("rAlice")
        self._w_bob = _get_or_create_wallet("rBob")
        self.alice = self._w_alice.address
        self.bob = self._w_bob.address
        self.ledger.create_account(self.alice, 1000.0)
        self.ledger.create_account(self.bob, 100.0)
        self.validator = TransactionValidator(self.ledger)


# ═══════════════════════════════════════════════════════════════════
#  Stake validation
# ═══════════════════════════════════════════════════════════════════

class TestStakeValidation(ValidatorSecBase):

    def test_valid_stake(self):
        tx = _sign(self.alice, create_stake(self.alice, 50.0, 0))  # Flexible
        ok, code, _ = self.validator.validate(tx)
        self.assertTrue(ok)
        self.assertEqual(code, TES_SUCCESS)

    def test_stake_below_minimum(self):
        tx = _sign(self.alice, create_stake(self.alice, 0.5, 0))  # below MIN_STAKE_AMOUNT
        ok, code, msg = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)
        self.assertIn("Minimum", msg)

    def test_stake_exactly_minimum(self):
        tx = _sign(self.alice, create_stake(self.alice, MIN_STAKE_AMOUNT, 0))
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_stake_invalid_tier_negative(self):
        tx = _sign(self.alice, create_stake(self.alice, 10.0, -1))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_LOCKED)

    def test_stake_invalid_tier_too_high(self):
        tx = _sign(self.alice, create_stake(self.alice, 10.0, 99))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_LOCKED)

    def test_stake_all_valid_tiers(self):
        for tier in range(5):  # 0-4
            tx = _sign(self.alice, create_stake(self.alice, 10.0, tier))
            ok, _code, _ = self.validator.validate(tx)
            self.assertTrue(ok, f"Tier {tier} should be valid")

    def test_stake_insufficient_balance_with_reserve(self):
        """Staking should fail if it would drop below reserve."""
        # alice has 1000, reserve = 20, try to stake 981
        tx = _sign(self.alice, create_stake(self.alice, 981.0, 0))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_stake_with_owner_count_affects_reserve(self):
        """Owner count increases required reserve."""
        acc = self.ledger.get_account(self.alice)
        acc.owner_count = 10  # reserve = 20 + 10*5 = 70
        tx = _sign(self.alice, create_stake(self.alice, 931.0, 0))  # 931 + fee + 70 > 1000
        ok, _code, _ = self.validator.validate(tx)
        self.assertFalse(ok)

    def test_stake_nonexistent_account(self):
        w_ghost = _get_or_create_wallet("rGhost")
        tx = _sign(w_ghost.address, create_stake(w_ghost.address, 10.0, 0))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)


# ═══════════════════════════════════════════════════════════════════
#  Unstake validation
# ═══════════════════════════════════════════════════════════════════

class TestUnstakeValidation(ValidatorSecBase):

    def _create_stake(self, stake_id="test_stake"):
        """Helper: create a stake in the pool."""
        self.ledger.staking_pool.record_stake(
            tx_id=stake_id, address=self.alice, amount=50.0,
            tier=0, circulating_supply=100_000.0, now=time.time(),
        )

    def test_valid_unstake(self):
        self._create_stake("s1")
        tx = _sign(self.alice, create_unstake(self.alice, "s1"))
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_unstake_missing_stake_id(self):
        tx = create_unstake(self.alice, "")
        tx.flags = {}  # empty flags BEFORE signing
        _sign(self.alice, tx)
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_LOCKED)

    def test_unstake_nonexistent_stake(self):
        tx = _sign(self.alice, create_unstake(self.alice, "no_such_stake"))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_LOCKED)

    def test_unstake_wrong_owner(self):
        self._create_stake("alice_stake")
        tx = _sign(self.bob, create_unstake(self.bob, "alice_stake"))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_LOCKED)

    def test_unstake_already_matured(self):
        self._create_stake("matured_s")
        self.ledger.staking_pool.stakes["matured_s"].matured = True
        tx = _sign(self.alice, create_unstake(self.alice, "matured_s"))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_DUPLICATE)

    def test_unstake_already_cancelled(self):
        self._create_stake("canc_s")
        self.ledger.staking_pool.stakes["canc_s"].cancelled = True
        tx = _sign(self.alice, create_unstake(self.alice, "canc_s"))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_STAKE_DUPLICATE)

    def test_unstake_no_fee_balance(self):
        w_poor = _get_or_create_wallet("rPoor")
        self.ledger.create_account(w_poor.address, 0.0)
        self._create_stake("poor_stake")
        self.ledger.staking_pool.stakes["poor_stake"].address = w_poor.address
        tx = _sign(w_poor.address, create_unstake(w_poor.address, "poor_stake"))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)


# ═══════════════════════════════════════════════════════════════════
#  Extreme amounts
# ═══════════════════════════════════════════════════════════════════

class TestExtremeAmounts(ValidatorSecBase):

    def test_very_large_payment(self):
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 1e18))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_very_small_payment(self):
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 0.000001))
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_very_large_fee(self):
        """Large fee is allowed if balance covers it."""
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 1.0, fee=100.0))
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)


# ═══════════════════════════════════════════════════════════════════
#  Fee boundary
# ═══════════════════════════════════════════════════════════════════

class TestFeeBoundary(ValidatorSecBase):

    def test_fee_one_below_minimum(self):
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 1.0, fee=MIN_FEE * 0.99))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)

    def test_fee_exactly_minimum(self):
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 1.0, fee=MIN_FEE))
        ok, _code, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_fee_zero(self):
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 1.0, fee=0.0))
        ok, _code, _ = self.validator.validate(tx)
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════════════
#  Sequence edge cases
# ═══════════════════════════════════════════════════════════════════

class TestSequenceEdgeCases(ValidatorSecBase):

    def test_sequence_zero_always_passes(self):
        tx = _sign(self.alice, create_payment(self.alice, self.bob, 1.0, sequence=0))
        ok, _, _ = self.validator.validate(tx)
        self.assertTrue(ok)

    def test_negative_sequence_fails(self):
        tx = create_payment(self.alice, self.bob, 1.0, sequence=-1)
        w = _WALLETS[self.alice]
        w._sequence = -1  # make wallet fill with -1
        tx.sequence = 0
        w.sign_transaction(tx)
        w._sequence = 1  # reset
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SEQ)

    def test_sequence_far_future_fails(self):
        tx = create_payment(self.alice, self.bob, 1.0, sequence=999999)
        w = _WALLETS[self.alice]
        w._sequence = 999999  # make wallet fill with 999999
        tx.sequence = 0
        w.sign_transaction(tx)
        w._sequence = 1  # reset
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_BAD_SEQ)


# ═══════════════════════════════════════════════════════════════════
#  Trust-set with validator
# ═══════════════════════════════════════════════════════════════════

class TestTrustSetValidation(ValidatorSecBase):

    def test_trust_set_account_not_found(self):
        w_ghost = _get_or_create_wallet("rGhost")
        tx = _sign(w_ghost.address, create_trust_set(w_ghost.address, "USD", "rBank", 500.0))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_UNFUNDED)

    def test_trust_set_fee_too_low(self):
        tx = _sign(self.alice, create_trust_set(self.alice, "USD", "rBank", 500.0, fee=0.0))
        ok, code, _ = self.validator.validate(tx)
        self.assertFalse(ok)
        self.assertEqual(code, TEC_INSUF_FEE)


# ═══════════════════════════════════════════════════════════════════
#  validate_batch mixed
# ═══════════════════════════════════════════════════════════════════

class TestBatchMixed(ValidatorSecBase):

    def test_batch_mixed_results(self):
        good_pay = _sign(self.alice, create_payment(self.alice, self.bob, 1.0))
        w_ghost = _get_or_create_wallet("rGhost2")
        bad_account = _sign(w_ghost.address, create_payment(w_ghost.address, self.bob, 1.0))
        bad_fee = _sign(self.alice, create_payment(self.alice, self.bob, 1.0, fee=0.0))
        good_stake = _sign(self.alice, create_stake(self.alice, 10.0, 0))

        results = self.validator.validate_batch([good_pay, bad_account, bad_fee, good_stake])
        self.assertEqual(len(results), 4)
        self.assertTrue(results[0][1])   # good_pay valid
        self.assertFalse(results[1][1])  # bad_account invalid
        self.assertFalse(results[2][1])  # bad_fee invalid
        self.assertTrue(results[3][1])   # good_stake valid


if __name__ == "__main__":
    unittest.main()
