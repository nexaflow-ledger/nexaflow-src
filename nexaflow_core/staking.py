"""
Transaction-based staking with dynamic interest for NexaFlow.

Stakes are created as Stake transactions.  At maturity the ledger
automatically returns principal + interest to the staker.  Early
cancellation via an Unstake transaction is possible but incurs a
penalty that scales with two factors:

  1. **Tier APY** — higher-yield tiers carry a larger base penalty.
  2. **Time served** — the longer the stake has been held, the more
     the penalty is reduced (linearly toward zero at maturity).

Dynamic Interest Algorithm
──────────────────────────
Base APY per tier is adjusted by a *demand multiplier* derived from
the network staking ratio (total_staked / circulating_supply):

    effective_apy = base_apy × demand_multiplier
    demand_multiplier = clamp(0.5, 2.0, 1 + (target − ratio) × k)

When fewer tokens are staked the multiplier rises (up to 2×) to
attract capital.  When too many tokens are staked it drops (to 0.5×)
to release liquidity.  Target ratio = 30 %, k = 3.

Early-Cancellation Penalty (tier-scaled, time-decayed)
──────────────────────────────────────────────────────
  interest_penalty_rate = BASE_INTEREST_PENALTY
                        + (tier_apy / MAX_BASE_APY) × INTEREST_PENALTY_SCALE
     → ranges  50 %  (Flexible/lowest)  …  90 %  (365-day/highest)

  principal_penalty_rate = BASE_PRINCIPAL_PENALTY
                         + (tier_apy / MAX_BASE_APY) × PRINCIPAL_PENALTY_SCALE
     → ranges  2 %  (Flexible)  …  10 %  (365-day)

  time_decay = 1 − (elapsed / lock_duration)   (0 at maturity)

  actual_interest_forfeited = accrued × interest_penalty_rate × time_decay
  actual_principal_penalty  = principal × principal_penalty_rate × time_decay

Flexible-tier stakes have lock_duration = 0 → time_decay = 0 → zero penalty.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import IntEnum
from typing import Optional


# ── Tier definitions ────────────────────────────────────────────────────

class StakeTier(IntEnum):
    FLEXIBLE = 0
    DAYS_30  = 1
    DAYS_90  = 2
    DAYS_180 = 3
    DAYS_365 = 4


# Maps tier → (lock_duration_seconds, base_annual_percentage_yield)
TIER_CONFIG: dict[StakeTier, tuple[int, float]] = {
    StakeTier.FLEXIBLE: (0,            0.02),
    StakeTier.DAYS_30:  (30  * 86_400, 0.05),
    StakeTier.DAYS_90:  (90  * 86_400, 0.08),
    StakeTier.DAYS_180: (180 * 86_400, 0.12),
    StakeTier.DAYS_365: (365 * 86_400, 0.15),
}

TIER_NAMES: dict[StakeTier, str] = {
    StakeTier.FLEXIBLE: "Flexible",
    StakeTier.DAYS_30:  "30 Days",
    StakeTier.DAYS_90:  "90 Days",
    StakeTier.DAYS_180: "180 Days",
    StakeTier.DAYS_365: "365 Days",
}

SECONDS_PER_YEAR: float = 365.25 * 86_400
MIN_STAKE_AMOUNT: float = 1.0

# ── Dynamic interest parameters ────────────────────────────────────────

TARGET_STAKE_RATIO: float = 0.30
DEMAND_SENSITIVITY: float = 3.0
MIN_MULTIPLIER: float = 0.5
MAX_MULTIPLIER: float = 2.0

# ── Penalty parameters (tier-scaled, time-decayed) ─────────────────────

# Highest base APY across all tiers — used to normalise tier scaling
MAX_BASE_APY: float = max(apy for _, apy in TIER_CONFIG.values())  # 0.15

# Interest penalty: forfeit 50 %–90 % of accrued interest
BASE_INTEREST_PENALTY: float  = 0.50
INTEREST_PENALTY_SCALE: float = 0.40   # adds up to 40 pp for highest tier

# Principal penalty: burn 2 %–10 % of principal
BASE_PRINCIPAL_PENALTY: float  = 0.02
PRINCIPAL_PENALTY_SCALE: float = 0.08  # adds up to 8 pp for highest tier

# Legacy constants exported for ledger.pyx backward-compat import
EARLY_INTEREST_PENALTY: float  = BASE_INTEREST_PENALTY + INTEREST_PENALTY_SCALE
EARLY_PRINCIPAL_PENALTY: float = BASE_PRINCIPAL_PENALTY + PRINCIPAL_PENALTY_SCALE


# ── Dynamic interest helpers ────────────────────────────────────────────

def compute_demand_multiplier(
    total_staked: float,
    circulating_supply: float,
) -> float:
    """
    Demand multiplier for APY adjustment.

    ratio < target → multiplier > 1 (incentivise staking).
    ratio > target → multiplier < 1 (release liquidity).
    """
    if circulating_supply <= 0:
        return 1.0
    ratio = total_staked / circulating_supply
    raw = 1.0 + (TARGET_STAKE_RATIO - ratio) * DEMAND_SENSITIVITY
    return max(MIN_MULTIPLIER, min(MAX_MULTIPLIER, raw))


def effective_apy(
    base_apy: float,
    total_staked: float,
    circulating_supply: float,
) -> float:
    """Return the effective APY after applying the demand multiplier."""
    return base_apy * compute_demand_multiplier(total_staked, circulating_supply)


# ── Penalty helpers ─────────────────────────────────────────────────────

def _interest_penalty_rate(tier_apy: float) -> float:
    """Interest penalty rate scaled by tier APY (0.50 … 0.90)."""
    ratio = tier_apy / MAX_BASE_APY if MAX_BASE_APY > 0 else 0.0
    return BASE_INTEREST_PENALTY + ratio * INTEREST_PENALTY_SCALE


def _principal_penalty_rate(tier_apy: float) -> float:
    """Principal penalty rate scaled by tier APY (0.02 … 0.10)."""
    ratio = tier_apy / MAX_BASE_APY if MAX_BASE_APY > 0 else 0.0
    return BASE_PRINCIPAL_PENALTY + ratio * PRINCIPAL_PENALTY_SCALE


def _time_decay(elapsed: float, lock_duration: float) -> float:
    """
    Fraction of penalty remaining — 1.0 at start, 0.0 at maturity.

    Flexible stakes (lock_duration == 0) always return 0.0 → no penalty.
    """
    if lock_duration <= 0:
        return 0.0
    served = min(elapsed / lock_duration, 1.0)
    return 1.0 - served


# ── StakeRecord ─────────────────────────────────────────────────────────

@dataclass
class StakeRecord:
    """
    A stake tied to a specific Stake transaction.

    ``stake_id == tx_id`` — guarantees one tx → one stake (double-spend
    prevention).
    """
    stake_id: str           # == tx_id
    tx_id: str
    address: str
    amount: float           # principal locked
    tier: StakeTier
    base_apy: float         # base rate at creation
    effective_apy: float    # base × demand multiplier at creation
    lock_duration: int      # seconds
    start_time: float       # epoch
    maturity_time: float    # epoch (0.0 for Flexible)
    matured: bool = False
    cancelled: bool = False
    payout_amount: float = 0.0

    # ── interest helpers ────────────────────────────────────────────

    def accrued_interest(self, now: Optional[float] = None) -> float:
        """Interest accrued so far using the effective APY."""
        if now is None:
            now = time.time()
        elapsed = max(0.0, now - self.start_time)
        return self.amount * self.effective_apy * (elapsed / SECONDS_PER_YEAR)

    def maturity_interest(self) -> float:
        """Full interest earned at maturity (locked tiers only)."""
        if self.lock_duration <= 0:
            return 0.0
        return self.amount * self.effective_apy * (self.lock_duration / SECONDS_PER_YEAR)

    def expected_payout(self) -> float:
        """Principal + full interest at maturity."""
        return self.amount + self.maturity_interest()

    def early_cancel_payout(
        self, now: Optional[float] = None,
    ) -> tuple[float, float, float]:
        """
        Compute the payout if cancelled before maturity.

        Penalty is **scaled by tier APY** and **reduced by time served**.

        Returns ``(payout, interest_forfeited, principal_penalty)``.
        Flexible-tier stakes incur no penalty (time_decay = 0).
        """
        if now is None:
            now = time.time()

        interest = self.accrued_interest(now)
        elapsed = max(0.0, now - self.start_time)

        # Time decay: 1 at start → 0 at maturity
        decay = _time_decay(elapsed, self.lock_duration)

        # Tier-scaled penalty rates
        ip_rate = _interest_penalty_rate(self.effective_apy)
        pp_rate = _principal_penalty_rate(self.effective_apy)

        interest_forfeited = interest * ip_rate * decay
        principal_penalty  = self.amount * pp_rate * decay

        interest_kept = interest - interest_forfeited
        payout = (self.amount - principal_penalty) + interest_kept
        return payout, interest_forfeited, principal_penalty

    def is_mature(self, now: Optional[float] = None) -> bool:
        """True when the lock period has expired (never for Flexible)."""
        if self.tier == StakeTier.FLEXIBLE:
            return False
        if now is None:
            now = time.time()
        return now >= self.maturity_time

    @property
    def is_active(self) -> bool:
        return not self.matured and not self.cancelled

    def to_dict(self, now: Optional[float] = None) -> dict:
        if now is None:
            now = time.time()
        if self.cancelled:
            status = "Cancelled"
        elif self.matured:
            status = "Matured"
        elif self.is_mature(now):
            status = "Ready"
        else:
            status = "Active"

        # Compute estimated penalty if user were to cancel right now
        _pay, est_int_penalty, est_prin_penalty = self.early_cancel_payout(now)

        return {
            "stake_id": self.stake_id,
            "tx_id": self.tx_id,
            "address": self.address,
            "amount": self.amount,
            "tier": int(self.tier),
            "tier_name": TIER_NAMES[self.tier],
            "base_apy": self.base_apy,
            "effective_apy": self.effective_apy,
            "effective_apy_pct": f"{self.effective_apy * 100:.2f}%",
            "lock_duration": self.lock_duration,
            "start_time": self.start_time,
            "maturity_time": self.maturity_time,
            "accrued_interest": self.accrued_interest(now),
            "maturity_interest": self.maturity_interest(),
            "expected_payout": self.expected_payout(),
            "payout_amount": self.payout_amount,
            "est_cancel_penalty": est_int_penalty + est_prin_penalty,
            "matured": self.matured,
            "cancelled": self.cancelled,
            "status": status,
        }


# ── StakingPool ─────────────────────────────────────────────────────────

class StakingPool:
    """
    Manages all StakeRecords network-wide.

    Entry points called from the Ledger:
      ``record_stake()``   — on Stake tx application
      ``mature_stakes()``  — during ``close_ledger()``
      ``cancel_stake()``   — on Unstake tx application
    """

    def __init__(self) -> None:
        self.stakes: dict[str, StakeRecord] = {}
        self.stakes_by_address: dict[str, list[str]] = {}
        self.total_staked: float = 0.0
        self.total_interest_paid: float = 0.0

    # ── core operations ─────────────────────────────────────────────

    def record_stake(
        self,
        tx_id: str,
        address: str,
        amount: float,
        tier: StakeTier | int,
        circulating_supply: float = 100_000_000_000.0,
        now: Optional[float] = None,
    ) -> StakeRecord:
        """
        Record a new stake from an applied Stake transaction.

        ``tx_id`` IS the ``stake_id`` — one tx → one stake.
        """
        if tx_id in self.stakes:
            raise ValueError(f"Stake for tx {tx_id} already recorded")

        tier = StakeTier(tier)
        if amount < MIN_STAKE_AMOUNT:
            raise ValueError(f"Minimum stake is {MIN_STAKE_AMOUNT} NXF")
        if tier not in TIER_CONFIG:
            raise ValueError(f"Unknown tier: {tier}")

        lock_duration, base = TIER_CONFIG[tier]
        if now is None:
            now = time.time()

        eff = effective_apy(base, self.total_staked, circulating_supply)
        maturity = now + lock_duration if lock_duration > 0 else 0.0

        record = StakeRecord(
            stake_id=tx_id,
            tx_id=tx_id,
            address=address,
            amount=amount,
            tier=tier,
            base_apy=base,
            effective_apy=eff,
            lock_duration=lock_duration,
            start_time=now,
            maturity_time=maturity,
        )
        self.stakes[tx_id] = record
        self.stakes_by_address.setdefault(address, []).append(tx_id)
        self.total_staked += amount
        return record

    def mature_stakes(
        self, now: Optional[float] = None,
    ) -> list[tuple[str, float, float]]:
        """
        Process all stakes that have reached maturity.

        Returns ``[(address, principal, interest), …]`` so the ledger
        can credit each account automatically.
        """
        if now is None:
            now = time.time()

        payouts: list[tuple[str, float, float]] = []
        for record in list(self.stakes.values()):
            if record.matured or record.cancelled:
                continue
            if record.tier == StakeTier.FLEXIBLE:
                continue  # Flexible must be manually cancelled
            if now >= record.maturity_time:
                interest = record.maturity_interest()
                record.matured = True
                record.payout_amount = record.amount + interest
                self.total_staked -= record.amount
                self.total_interest_paid += interest
                payouts.append((record.address, record.amount, interest))
        return payouts

    def cancel_stake(
        self,
        stake_id: str,
        now: Optional[float] = None,
    ) -> tuple[str, float, float, float]:
        """
        Cancel a stake early.

        Returns ``(address, payout, interest_forfeited, principal_penalty)``.
        Penalty is tier-scaled and time-decayed.
        """
        record = self.stakes.get(stake_id)
        if record is None:
            raise ValueError(f"Stake {stake_id} not found")
        if record.matured:
            raise ValueError(f"Stake {stake_id} already matured")
        if record.cancelled:
            raise ValueError(f"Stake {stake_id} already cancelled")

        payout, interest_forfeited, principal_penalty = \
            record.early_cancel_payout(now)

        record.cancelled = True
        record.payout_amount = payout
        self.total_staked -= record.amount

        interest_paid_out = record.accrued_interest(now) - interest_forfeited
        if interest_paid_out > 0:
            self.total_interest_paid += interest_paid_out

        return record.address, payout, interest_forfeited, principal_penalty

    # ── queries ─────────────────────────────────────────────────────

    def get_active_stakes(self, address: str) -> list[StakeRecord]:
        ids = self.stakes_by_address.get(address, [])
        return [
            self.stakes[sid] for sid in ids
            if sid in self.stakes and self.stakes[sid].is_active
        ]

    def get_all_stakes(self, address: str) -> list[StakeRecord]:
        ids = self.stakes_by_address.get(address, [])
        return [self.stakes[sid] for sid in ids if sid in self.stakes]

    def get_total_staked_for_address(self, address: str) -> float:
        return sum(s.amount for s in self.get_active_stakes(address))

    def get_pool_summary(self, now: Optional[float] = None) -> dict:
        active = [s for s in self.stakes.values() if s.is_active]
        total_pending = sum(s.accrued_interest(now) for s in active)
        return {
            "total_staked": self.total_staked,
            "total_interest_paid": self.total_interest_paid,
            "total_pending_interest": total_pending,
            "active_stakes": len(active),
            "total_stakes": len(self.stakes),
        }

    def get_demand_multiplier(
        self, circulating_supply: float = 100_000_000_000.0,
    ) -> float:
        return compute_demand_multiplier(self.total_staked, circulating_supply)

    def get_tier_info(
        self, circulating_supply: float = 100_000_000_000.0,
    ) -> list[dict]:
        """Tier info including current effective APYs."""
        mult = self.get_demand_multiplier(circulating_supply)
        return [
            {
                "tier": int(tier),
                "name": TIER_NAMES[tier],
                "lock_days": duration // 86_400,
                "base_apy": apy,
                "effective_apy": apy * mult,
                "effective_apy_pct": f"{apy * mult * 100:.2f}%",
                "demand_multiplier": mult,
            }
            for tier, (duration, apy) in TIER_CONFIG.items()
        ]
