"""
Automated Market Maker (AMM) for NexaFlow — XLS-30 equivalent.

Implements constant-product (x * y = k) liquidity pools with:
  - AMMCreate: deploy a new pool for a token pair
  - AMMDeposit: add liquidity (single-sided or dual)
  - AMMWithdraw: remove liquidity (single-sided or dual)
  - AMMVote: vote on the trading fee for a pool
  - AMMBid: bid LP tokens to become the auction slot holder
  - AMMDelete: remove an empty pool

LP tokens are minted/burned proportional to liquidity provided.
The trading fee is determined by a weighted median of votes.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field


@dataclass
class LPToken:
    """LP token balance held by an account."""
    pool_id: str
    amount: float


@dataclass
class AMMVoteEntry:
    """An account's vote on the trading fee."""
    account: str
    fee_val: int  # in basis points (1 = 0.01%)
    weight: float  # proportional to LP tokens held


@dataclass
class AuctionSlot:
    """The current auction-slot holder who gets discounted trading."""
    account: str
    price: float  # LP tokens paid
    expiration: float  # epoch
    discount_pct: float = 0.0  # 0-100


@dataclass
class AMMPool:
    """A single AMM liquidity pool."""
    pool_id: str
    asset1_currency: str
    asset1_issuer: str
    asset2_currency: str
    asset2_issuer: str
    balance1: float = 0.0
    balance2: float = 0.0
    lp_token_supply: float = 0.0
    lp_token_currency: str = ""
    trading_fee: int = 0  # basis points (max 1000 = 10%)
    lp_balances: dict[str, float] = field(default_factory=dict)
    votes: list[AMMVoteEntry] = field(default_factory=list)
    auction_slot: AuctionSlot | None = None
    creator: str = ""
    created_at: float = field(default_factory=time.time)

    @property
    def invariant(self) -> float:
        """Return the constant product k = x * y."""
        return self.balance1 * self.balance2

    def pair_key(self) -> str:
        return f"{self.asset1_currency}:{self.asset1_issuer}/" \
               f"{self.asset2_currency}:{self.asset2_issuer}"

    def to_dict(self) -> dict:
        d = {
            "pool_id": self.pool_id,
            "asset1": {"currency": self.asset1_currency, "issuer": self.asset1_issuer},
            "asset2": {"currency": self.asset2_currency, "issuer": self.asset2_issuer},
            "balance1": self.balance1,
            "balance2": self.balance2,
            "lp_token_supply": self.lp_token_supply,
            "lp_token_currency": self.lp_token_currency,
            "trading_fee": self.trading_fee,
            "creator": self.creator,
        }
        if self.auction_slot:
            d["auction_slot"] = {
                "account": self.auction_slot.account,
                "price": self.auction_slot.price,
                "expiration": self.auction_slot.expiration,
                "discount_pct": self.auction_slot.discount_pct,
            }
        return d


MAX_TRADING_FEE = 1000  # 10% in basis points
MAX_VOTES = 8
AUCTION_SLOT_DURATION = 86400.0  # 24 hours


class AMMManager:
    """Manages all AMM pools."""

    def __init__(self):
        self.pools: dict[str, AMMPool] = {}
        self._pair_index: dict[str, str] = {}  # pair_key -> pool_id

    @staticmethod
    def _pool_id(asset1_currency: str, asset1_issuer: str,
                 asset2_currency: str, asset2_issuer: str) -> str:
        raw = f"{asset1_currency}:{asset1_issuer}/{asset2_currency}:{asset2_issuer}"
        return hashlib.sha256(raw.encode()).hexdigest()[:40]

    def get_pool(self, pool_id: str) -> AMMPool | None:
        return self.pools.get(pool_id)

    def get_pool_by_pair(self, currency1: str, issuer1: str,
                         currency2: str, issuer2: str) -> AMMPool | None:
        pid = self._pool_id(currency1, issuer1, currency2, issuer2)
        pool = self.pools.get(pid)
        if pool:
            return pool
        pid = self._pool_id(currency2, issuer2, currency1, issuer1)
        return self.pools.get(pid)

    def create_pool(self, creator: str,
                    asset1_currency: str, asset1_issuer: str,
                    asset2_currency: str, asset2_issuer: str,
                    amount1: float, amount2: float,
                    trading_fee: int = 0) -> tuple[bool, str, AMMPool | None]:
        """
        Create a new AMM pool.  Returns (success, message, pool).
        """
        if amount1 <= 0 or amount2 <= 0:
            return False, "Amounts must be positive", None
        if trading_fee < 0 or trading_fee > MAX_TRADING_FEE:
            return False, f"Trading fee must be 0-{MAX_TRADING_FEE} basis points", None

        pid = self._pool_id(asset1_currency, asset1_issuer,
                            asset2_currency, asset2_issuer)
        if pid in self.pools:
            return False, "Pool already exists", None

        # Also check reversed pair
        rpid = self._pool_id(asset2_currency, asset2_issuer,
                             asset1_currency, asset1_issuer)
        if rpid in self.pools:
            return False, "Pool already exists (reversed pair)", None

        lp_currency = f"LP-{pid[:8]}"
        initial_lp = math.sqrt(amount1 * amount2)

        pool = AMMPool(
            pool_id=pid,
            asset1_currency=asset1_currency,
            asset1_issuer=asset1_issuer,
            asset2_currency=asset2_currency,
            asset2_issuer=asset2_issuer,
            balance1=amount1,
            balance2=amount2,
            lp_token_supply=initial_lp,
            lp_token_currency=lp_currency,
            trading_fee=trading_fee,
            creator=creator,
        )
        pool.lp_balances[creator] = initial_lp

        self.pools[pid] = pool
        self._pair_index[pool.pair_key()] = pid
        return True, "Pool created", pool

    def deposit(self, pool_id: str, account: str,
                amount1: float | None = None,
                amount2: float | None = None,
                lp_token_out: float | None = None) -> tuple[bool, str, float]:
        """
        Deposit liquidity.  Supports:
          - Dual-asset deposit (both amounts provided)
          - Single-asset deposit (one amount provided)
          - LP-token targeted deposit (lp_token_out specified)
        Returns (success, message, lp_tokens_minted).
        """
        pool = self.pools.get(pool_id)
        if pool is None:
            return False, "Pool not found", 0.0

        if lp_token_out is not None and lp_token_out <= 0:
            return False, "LP token amount must be positive", 0.0

        if amount1 is not None and amount1 < 0:
            return False, "Amount1 cannot be negative", 0.0
        if amount2 is not None and amount2 < 0:
            return False, "Amount2 cannot be negative", 0.0

        if pool.lp_token_supply == 0:
            # Empty pool — treat as initial deposit
            if amount1 is None or amount2 is None or amount1 <= 0 or amount2 <= 0:
                return False, "Both amounts required for empty pool", 0.0
            lp_minted = math.sqrt(amount1 * amount2)
            pool.balance1 += amount1
            pool.balance2 += amount2
            pool.lp_token_supply += lp_minted
            pool.lp_balances[account] = pool.lp_balances.get(account, 0) + lp_minted
            return True, "Deposited", lp_minted

        if lp_token_out is not None:
            # Target a specific LP token amount
            ratio = lp_token_out / pool.lp_token_supply
            need1 = pool.balance1 * ratio
            need2 = pool.balance2 * ratio
            pool.balance1 += need1
            pool.balance2 += need2
            pool.lp_token_supply += lp_token_out
            pool.lp_balances[account] = pool.lp_balances.get(account, 0) + lp_token_out
            return True, "Deposited (LP target)", lp_token_out

        if amount1 is not None and amount2 is not None:
            # Dual-asset: mint proportional to smaller ratio
            ratio1 = amount1 / pool.balance1 if pool.balance1 > 0 else 0
            ratio2 = amount2 / pool.balance2 if pool.balance2 > 0 else 0
            ratio = min(ratio1, ratio2)
            lp_minted = pool.lp_token_supply * ratio
            pool.balance1 += amount1
            pool.balance2 += amount2
            pool.lp_token_supply += lp_minted
            pool.lp_balances[account] = pool.lp_balances.get(account, 0) + lp_minted
            return True, "Deposited (dual)", lp_minted

        if amount1 is not None and amount1 > 0:
            # Single-asset deposit (asset1)
            lp_minted = self._single_side_deposit(pool, amount1, is_asset1=True)
            pool.lp_balances[account] = pool.lp_balances.get(account, 0) + lp_minted
            return True, "Deposited (single, asset1)", lp_minted

        if amount2 is not None and amount2 > 0:
            lp_minted = self._single_side_deposit(pool, amount2, is_asset1=False)
            pool.lp_balances[account] = pool.lp_balances.get(account, 0) + lp_minted
            return True, "Deposited (single, asset2)", lp_minted

        return False, "No valid deposit amounts provided", 0.0

    @staticmethod
    def _single_side_deposit(pool: AMMPool, amount: float,
                             is_asset1: bool) -> float:
        """
        Single-sided deposit using constant-product math.
        Fee is applied to the implicit swap portion.
        """
        if is_asset1:
            reserve = pool.balance1
        else:
            reserve = pool.balance2

        fee_fraction = pool.trading_fee / 10000.0
        # Half is "swapped" — apply fee to the swap half
        swap_half = amount / 2
        effective = swap_half * (1 - fee_fraction)
        # New reserve after deposit
        new_reserve = reserve + amount
        # LP minted proportional to sqrt of product increase
        old_k = pool.balance1 * pool.balance2
        if is_asset1:
            pool.balance1 = new_reserve
            new_k = pool.balance1 * pool.balance2
        else:
            pool.balance2 = new_reserve
            new_k = pool.balance1 * pool.balance2

        if old_k == 0:
            return amount
        lp_minted = pool.lp_token_supply * (math.sqrt(new_k / old_k) - 1)
        pool.lp_token_supply += lp_minted
        return lp_minted

    def withdraw(self, pool_id: str, account: str,
                 lp_tokens: float | None = None,
                 amount1: float | None = None,
                 amount2: float | None = None) -> tuple[bool, str, float, float]:
        """
        Withdraw liquidity.  Returns (success, msg, withdrawn1, withdrawn2).
        """
        pool = self.pools.get(pool_id)
        if pool is None:
            return False, "Pool not found", 0.0, 0.0

        lp_held = pool.lp_balances.get(account, 0)

        if lp_tokens is not None:
            if lp_tokens <= 0:
                return False, "LP amount must be positive", 0.0, 0.0
            if lp_tokens > lp_held:
                return False, "Insufficient LP tokens", 0.0, 0.0

            ratio = lp_tokens / pool.lp_token_supply
            out1 = pool.balance1 * ratio
            out2 = pool.balance2 * ratio
            pool.balance1 -= out1
            pool.balance2 -= out2
            pool.lp_token_supply -= lp_tokens
            pool.lp_balances[account] -= lp_tokens
            if pool.lp_balances[account] <= 1e-10:
                del pool.lp_balances[account]
            return True, "Withdrawn", out1, out2

        # Single-asset withdrawal
        if amount1 is not None and amount1 > 0:
            return self._single_side_withdraw(pool, account, amount1, is_asset1=True)
        if amount2 is not None and amount2 > 0:
            return self._single_side_withdraw(pool, account, amount2, is_asset1=False)

        return False, "No valid withdrawal specified", 0.0, 0.0

    def _single_side_withdraw(self, pool: AMMPool, account: str,
                              amount: float, is_asset1: bool
                              ) -> tuple[bool, str, float, float]:
        """Single-sided withdrawal with fee."""
        bal = pool.balance1 if is_asset1 else pool.balance2
        if amount > bal:
            return False, "Exceeds pool balance", 0.0, 0.0

        old_k = pool.balance1 * pool.balance2
        if is_asset1:
            pool.balance1 -= amount
            new_k = pool.balance1 * pool.balance2
        else:
            pool.balance2 -= amount
            new_k = pool.balance1 * pool.balance2

        if old_k == 0:
            return False, "Pool is empty", 0.0, 0.0

        lp_burned = pool.lp_token_supply * (1 - math.sqrt(new_k / old_k))
        lp_held = pool.lp_balances.get(account, 0)
        if lp_burned > lp_held:
            # Revert
            if is_asset1:
                pool.balance1 += amount
            else:
                pool.balance2 += amount
            return False, "Insufficient LP tokens", 0.0, 0.0

        pool.lp_token_supply -= lp_burned
        pool.lp_balances[account] -= lp_burned
        if pool.lp_balances[account] <= 1e-10:
            del pool.lp_balances[account]

        if is_asset1:
            return True, "Withdrawn (single, asset1)", amount, 0.0
        return True, "Withdrawn (single, asset2)", 0.0, amount

    def swap(self, pool_id: str, account: str,
             sell_asset1: bool, sell_amount: float) -> tuple[bool, str, float]:
        """
        Execute a swap through the AMM.
        Returns (success, message, amount_received).
        """
        pool = self.pools.get(pool_id)
        if pool is None:
            return False, "Pool not found", 0.0
        if sell_amount <= 0:
            return False, "Amount must be positive", 0.0

        fee_fraction = pool.trading_fee / 10000.0

        # Check if account holds the auction slot for discounted fee
        discount = 0.0
        if pool.auction_slot and pool.auction_slot.account == account:
            if time.time() < pool.auction_slot.expiration:
                discount = pool.auction_slot.discount_pct / 100.0
        effective_fee = fee_fraction * (1 - discount)
        amount_after_fee = sell_amount * (1 - effective_fee)

        if sell_asset1:
            # Sell asset1 for asset2
            new_bal1 = pool.balance1 + amount_after_fee
            out = pool.balance2 - (pool.invariant / new_bal1)
            if out <= 0 or out > pool.balance2:
                return False, "Insufficient liquidity", 0.0
            pool.balance1 += sell_amount  # full amount goes to pool
            pool.balance2 -= out
        else:
            new_bal2 = pool.balance2 + amount_after_fee
            out = pool.balance1 - (pool.invariant / new_bal2)
            if out <= 0 or out > pool.balance1:
                return False, "Insufficient liquidity", 0.0
            pool.balance2 += sell_amount
            pool.balance1 -= out

        return True, "Swap executed", out

    def vote(self, pool_id: str, account: str,
             fee_val: int) -> tuple[bool, str]:
        """
        Submit a trading fee vote.  The pool's fee is recomputed as the
        weighted median of all active votes.
        """
        pool = self.pools.get(pool_id)
        if pool is None:
            return False, "Pool not found"
        if fee_val < 0 or fee_val > MAX_TRADING_FEE:
            return False, f"Fee must be 0-{MAX_TRADING_FEE}"

        lp_held = pool.lp_balances.get(account, 0)
        if lp_held <= 0:
            return False, "Must hold LP tokens to vote"

        # Upsert
        existing = None
        for v in pool.votes:
            if v.account == account:
                existing = v
                break
        if existing:
            existing.fee_val = fee_val
            existing.weight = lp_held
        else:
            if len(pool.votes) >= MAX_VOTES:
                # Replace lowest-weight vote
                pool.votes.sort(key=lambda v: v.weight)
                if lp_held > pool.votes[0].weight:
                    pool.votes[0] = AMMVoteEntry(
                        account=account, fee_val=fee_val, weight=lp_held)
                else:
                    return False, "Vote slots full and your weight is too low"
            else:
                pool.votes.append(AMMVoteEntry(
                    account=account, fee_val=fee_val, weight=lp_held))

        # Recompute weighted median
        self._recompute_fee(pool)
        return True, "Vote recorded"

    @staticmethod
    def _recompute_fee(pool: AMMPool) -> None:
        """Compute weighted median of votes."""
        if not pool.votes:
            return
        total_weight = sum(v.weight for v in pool.votes)
        if total_weight == 0:
            return
        sorted_votes = sorted(pool.votes, key=lambda v: v.fee_val)
        cumulative = 0.0
        for v in sorted_votes:
            cumulative += v.weight
            if cumulative >= total_weight / 2:
                pool.trading_fee = v.fee_val
                return
        pool.trading_fee = sorted_votes[-1].fee_val

    def bid(self, pool_id: str, account: str,
            bid_amount: float) -> tuple[bool, str]:
        """
        Bid LP tokens for the auction slot (discounted trading).
        """
        pool = self.pools.get(pool_id)
        if pool is None:
            return False, "Pool not found"
        if bid_amount <= 0:
            return False, "Bid must be positive"

        lp_held = pool.lp_balances.get(account, 0)
        if bid_amount > lp_held:
            return False, "Insufficient LP tokens"

        # Must outbid current holder
        if pool.auction_slot and time.time() < pool.auction_slot.expiration:
            if bid_amount <= pool.auction_slot.price:
                return False, "Must outbid current holder"

        # Burn LP tokens as bid
        pool.lp_balances[account] -= bid_amount
        pool.lp_token_supply -= bid_amount
        if pool.lp_balances[account] <= 1e-10:
            del pool.lp_balances[account]

        pool.auction_slot = AuctionSlot(
            account=account,
            price=bid_amount,
            expiration=time.time() + AUCTION_SLOT_DURATION,
            discount_pct=50.0,  # 50% fee discount
        )
        return True, "Auction slot won"

    def delete_pool(self, pool_id: str, account: str) -> tuple[bool, str]:
        """Delete an empty pool (only creator can delete)."""
        pool = self.pools.get(pool_id)
        if pool is None:
            return False, "Pool not found"
        if pool.lp_token_supply > 1e-10:
            return False, "Pool still has liquidity"
        pair_key = pool.pair_key()
        del self.pools[pool_id]
        self._pair_index.pop(pair_key, None)
        return True, "Pool deleted"

    def get_pools(self) -> list[dict]:
        return [p.to_dict() for p in self.pools.values()]

    def get_account_lp(self, account: str) -> list[dict]:
        """Get all LP token balances for an account."""
        result = []
        for pid, pool in self.pools.items():
            bal = pool.lp_balances.get(account, 0)
            if bal > 0:
                result.append({
                    "pool_id": pid,
                    "lp_currency": pool.lp_token_currency,
                    "amount": bal,
                    "pair": pool.pair_key(),
                })
        return result
