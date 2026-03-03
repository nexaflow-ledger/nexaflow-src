"""
Programmable Micro Coin (PMC) engine for NexaFlow.

PMC enables anyone to create lightweight, programmable tokens that live
on the NexaFlow ledger.  Each micro coin has:

  - **Proof-of-Work minting**: new supply is mined by solving a
    Bitcoin-compatible double-SHA256 hash puzzle.  The coin creator
    sets a fixed difficulty; miners are rewarded proportionally to
    the work performed — higher difficulty yields exponentially
    larger block rewards.  Uses the same hash algorithm as Bitcoin
    so existing ASIC / GPU mining hardware works out of the box.
  - **Programmable rules**: the issuer attaches rules that govern
    transfers, burns, and minting behaviour (max per-mint, cooldowns,
    whitelist/blacklist, royalty-on-transfer, expiry, etc.).
  - **Cross-trading / DEX**: holders can post buy/sell offers against
    NXF or other PMC coins.  Offers match on acceptance, settling
    atomically on-ledger.
  - **Micro-transaction optimized**: 8-decimal precision, sub-cent
    denominations, batched transfers.

Transaction types (codes 60-67):
  60  PMCCreate        – define a new micro coin
  61  PMCMint          – submit PoW nonce to mint new supply
  62  PMCTransfer      – send coins between accounts
  63  PMCBurn          – destroy supply (holder)
  64  PMCSetRules      – update programmable rules (issuer only)
  65  PMCOfferCreate   – post a buy/sell offer on the DEX
  66  PMCOfferAccept   – accept (fill) an existing offer
  67  PMCOfferCancel   – cancel own open offer

Architecture mirrors NexaFlow's NFTokenManager / MPTManager pattern:
a single ``PMCManager`` instance is held by the Ledger and called from
``apply_transaction`` for each PMC tx type.
"""

from __future__ import annotations

import hashlib
import math
import time
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Any


# ═══════════════════════════════════════════════════════════════════════
#  Constants
# ═══════════════════════════════════════════════════════════════════════

MAX_COIN_SYMBOL_LEN = 12
MAX_COIN_NAME_LEN = 64
MAX_METADATA_LEN = 2048
MAX_RULES = 32
MAX_DECIMALS = 8
DEFAULT_DECIMALS = 8
MIN_POW_DIFFICULTY = 1          # at least 1 leading hex zero
MAX_POW_DIFFICULTY = 32         # 32 hex zeros ≈ 128-bit security
DEFAULT_POW_DIFFICULTY = 4      # 4 leading hex zeros (~65 k hashes)
MAX_SUPPLY_CAP = 1_000_000_000_000_000.0  # absolute ceiling

# ── Reward scaling ───────────────────────────────────────────────────
# Reward formula:  reward = base_reward * 2^(difficulty - 1)
# Difficulty 1 → 1× base_reward, Difficulty 2 → 2×, 3 → 4×, 4 → 8×, …
# This gives coins mined at higher difficulty exponentially more value,
# making the coin creator's difficulty choice a core economic lever.
DEFAULT_BASE_REWARD = 50.0     # default tokens per PoW solve at diff=1
MIN_BASE_REWARD = 0.00000001   # 1 satoshi-equivalent
MAX_BASE_REWARD = 1_000_000_000.0


# ═══════════════════════════════════════════════════════════════════════
#  Enums & Flags
# ═══════════════════════════════════════════════════════════════════════

class PMCFlag(IntFlag):
    """Bit-flags stored on a coin definition."""
    TRANSFERABLE     = 0x0001
    BURNABLE         = 0x0002
    MINTABLE         = 0x0004   # PoW minting enabled
    FREEZABLE        = 0x0008   # issuer can freeze holders
    ROYALTY_ON_XFER  = 0x0010   # % royalty to issuer on every transfer
    WHITELIST_ONLY   = 0x0020   # only whitelisted accounts may hold
    CROSS_TRADEABLE  = 0x0040   # may be listed on the PMC DEX
    EXPIRABLE        = 0x0080   # coin balances expire after TTL


DEFAULT_FLAGS = (
    PMCFlag.TRANSFERABLE
    | PMCFlag.BURNABLE
    | PMCFlag.MINTABLE
    | PMCFlag.CROSS_TRADEABLE
)


class RuleType(IntEnum):
    """Types of programmable rules attachable to a coin."""
    MAX_BALANCE      = 1    # cap per-account balance
    MIN_TRANSFER     = 2    # minimum transfer amount
    MAX_TRANSFER     = 3    # maximum transfer amount
    COOLDOWN         = 4    # seconds between transfers per account
    ROYALTY_PCT      = 5    # percentage of transfer sent to issuer
    WHITELIST        = 6    # list of allowed holder addresses
    BLACKLIST        = 7    # list of banned addresses
    EXPIRY_TTL       = 8    # seconds after which balance expires
    MAX_PER_MINT     = 9    # cap tokens minted per PoW solution
    MINT_COOLDOWN    = 10   # seconds between mints per account
    REQUIRE_MEMO     = 11   # transfers must include a memo
    TIME_LOCK        = 12   # balance locked until Unix timestamp


# ═══════════════════════════════════════════════════════════════════════
#  Data classes
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class PMCRule:
    """A single programmable rule attached to a coin."""
    rule_type: RuleType
    value: Any = None           # interpretation depends on rule_type
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "rule_type": self.rule_type.name,
            "value": self.value,
            "enabled": self.enabled,
        }

    @staticmethod
    def from_dict(d: dict) -> "PMCRule":
        return PMCRule(
            rule_type=RuleType[d["rule_type"]],
            value=d.get("value"),
            enabled=d.get("enabled", True),
        )


@dataclass
class PMCDefinition:
    """On-ledger definition of a Programmable Micro Coin."""
    coin_id: str                          # deterministic BLAKE2b hash
    symbol: str                           # ticker, e.g. "ZETA"
    name: str                             # human-readable name
    issuer: str                           # creator account address
    decimals: int = DEFAULT_DECIMALS
    max_supply: float = 0.0               # 0 = unlimited
    total_minted: float = 0.0
    total_burned: float = 0.0
    flags: int = int(DEFAULT_FLAGS)
    pow_difficulty: int = DEFAULT_POW_DIFFICULTY
    base_reward: float = DEFAULT_BASE_REWARD   # tokens per PoW at diff=1
    metadata: str = ""                    # JSON / URI
    rules: list[PMCRule] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    frozen: bool = False
    total_mints: int = 0                  # number of successful PoW solves

    @property
    def circulating(self) -> float:
        return self.total_minted - self.total_burned

    @property
    def block_reward(self) -> float:
        """Current reward per PoW solve: base_reward * 2^(difficulty-1)."""
        return self.base_reward * (2 ** (self.pow_difficulty - 1))

    def has_flag(self, flag: PMCFlag) -> bool:
        return bool(self.flags & flag)

    def get_rule(self, rt: RuleType) -> PMCRule | None:
        for r in self.rules:
            if r.rule_type == rt and r.enabled:
                return r
        return None

    def to_dict(self) -> dict:
        return {
            "coin_id": self.coin_id,
            "symbol": self.symbol,
            "name": self.name,
            "issuer": self.issuer,
            "decimals": self.decimals,
            "max_supply": self.max_supply,
            "total_minted": self.total_minted,
            "total_burned": self.total_burned,
            "circulating": self.circulating,
            "flags": self.flags,
            "flag_names": [f.name for f in PMCFlag if self.flags & f],
            "pow_difficulty": self.pow_difficulty,
            "base_reward": self.base_reward,
            "block_reward": self.block_reward,
            "total_mints": self.total_mints,
            "metadata": self.metadata,
            "rules": [r.to_dict() for r in self.rules],
            "created_at": self.created_at,
            "frozen": self.frozen,
        }


@dataclass
class PMCHolder:
    """A single account's balance for a specific PMC."""
    account: str
    coin_id: str
    balance: float = 0.0
    frozen: bool = False
    last_transfer_at: float = 0.0
    last_mint_at: float = 0.0
    acquired_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "account": self.account,
            "coin_id": self.coin_id,
            "balance": self.balance,
            "frozen": self.frozen,
            "last_transfer_at": self.last_transfer_at,
            "last_mint_at": self.last_mint_at,
        }


@dataclass
class PMCOffer:
    """A buy or sell offer on the PMC cross-trade DEX."""
    offer_id: str
    coin_id: str                  # the PMC being traded
    owner: str                    # offer creator
    is_sell: bool                 # True = selling coin_id, False = buying
    amount: float                 # quantity of coin_id
    price: float                  # price per unit in NXF (or counter_coin)
    counter_coin_id: str = ""     # empty = NXF, otherwise another PMC
    filled: float = 0.0           # amount already filled
    destination: str = ""         # restrict to specific taker (empty = open)
    expiration: float = 0.0       # 0 = no expiry
    created_at: float = field(default_factory=time.time)
    cancelled: bool = False

    @property
    def remaining(self) -> float:
        return self.amount - self.filled

    @property
    def is_active(self) -> bool:
        if self.cancelled:
            return False
        if self.remaining <= 0:
            return False
        if self.expiration > 0 and time.time() >= self.expiration:
            return False
        return True

    @property
    def total_cost(self) -> float:
        """Total NXF (or counter-coin) cost for the full offer."""
        return self.amount * self.price

    def to_dict(self) -> dict:
        return {
            "offer_id": self.offer_id,
            "coin_id": self.coin_id,
            "owner": self.owner,
            "is_sell": self.is_sell,
            "amount": self.amount,
            "price": self.price,
            "counter_coin_id": self.counter_coin_id,
            "filled": self.filled,
            "remaining": self.remaining,
            "destination": self.destination,
            "expiration": self.expiration,
            "created_at": self.created_at,
            "cancelled": self.cancelled,
            "is_active": self.is_active,
        }


# ═══════════════════════════════════════════════════════════════════════
#  Transaction commitment — Merkle tree helpers
# ═══════════════════════════════════════════════════════════════════════

EMPTY_TX_ROOT = "0" * 64  # sentinel when no transactions are committed


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def compute_merkle_root(tx_hashes: list[str]) -> str:
    """
    Compute the Merkle root of a list of transaction hashes (hex strings).

    Uses the same double-SHA256 algorithm as Bitcoin's Merkle tree so that
    the commitment structure is familiar to existing tooling.  If the list
    has an odd number of entries the last hash is duplicated (Bitcoin rule).

    Returns EMPTY_TX_ROOT when *tx_hashes* is empty.
    """
    if not tx_hashes:
        return EMPTY_TX_ROOT

    # Leaf layer: double-SHA256 of each tx hash
    layer: list[bytes] = [
        _sha256(_sha256(h.encode("utf-8"))) for h in tx_hashes
    ]

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])          # duplicate last (Bitcoin rule)
        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            combined = layer[i] + layer[i + 1]
            next_layer.append(_sha256(_sha256(combined)))
        layer = next_layer

    return layer[0].hex()


def hash_pending_tx(tx_dict: dict) -> str:
    """Compute a deterministic double-SHA256 hash of a pending tx dict.

    Fields are sorted alphabetically so that any miner independently
    building the same tx set arrives at the same Merkle root.
    """
    import json
    canonical = json.dumps(tx_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(
        hashlib.sha256(canonical.encode("utf-8")).digest()
    ).hexdigest()


@dataclass
class PMCCommitment:
    """A PoW-validated transaction commitment.

    Each successful mint anchors a batch of PMC transactions into the
    coin's PoW chain.  The *tx_root* Merkle root cryptographically binds
    the mined hash to real transaction data — the miner simultaneously
    earns a reward *and* validates the included transactions.
    """
    commitment_id: str          # = the PoW hash that sealed this commitment
    coin_id: str
    miner: str
    tx_root: str                # Merkle root of committed transactions
    tx_hashes: list[str]        # individual tx hashes included
    tx_count: int               # len(tx_hashes)
    pow_hash: str               # the winning PoW hash (== commitment_id)
    difficulty: int
    reward: float
    timestamp: float
    prev_commitment: str = ""   # chain to previous commitment

    def to_dict(self) -> dict:
        return {
            "commitment_id": self.commitment_id,
            "coin_id": self.coin_id,
            "miner": self.miner,
            "tx_root": self.tx_root,
            "tx_hashes": self.tx_hashes,
            "tx_count": self.tx_count,
            "pow_hash": self.pow_hash,
            "difficulty": self.difficulty,
            "reward": self.reward,
            "timestamp": self.timestamp,
            "prev_commitment": self.prev_commitment,
        }


# ═══════════════════════════════════════════════════════════════════════
#  Proof-of-Work helpers
# ═══════════════════════════════════════════════════════════════════════

def compute_pow_hash(
    coin_id: str,
    miner: str,
    nonce: int,
    prev_hash: str = "",
    tx_root: str = EMPTY_TX_ROOT,
) -> str:
    """
    Compute the PoW hash for a mint attempt using **Bitcoin-style
    double-SHA256** so that existing Bitcoin ASIC / GPU mining
    hardware can be used directly.

    hash = SHA256( SHA256( coin_id || miner || nonce || prev_hash || tx_root ) )

    The *tx_root* is the Merkle root of the transactions the miner is
    committing to validate.  This binds the PoW to real data — the same
    hash cannot be reused with a different transaction set.

    Returns the hex digest (64 hex chars, 256-bit).
    """
    blob = f"{coin_id}:{miner}:{nonce}:{prev_hash}:{tx_root}".encode("utf-8")
    first = hashlib.sha256(blob).digest()
    return hashlib.sha256(first).hexdigest()


def verify_pow(
    coin_id: str,
    miner: str,
    nonce: int,
    difficulty: int,
    prev_hash: str = "",
    tx_root: str = EMPTY_TX_ROOT,
) -> bool:
    """
    Verify that the nonce produces a double-SHA256 hash with at least
    ``difficulty`` leading hex zeros.
    """
    h = compute_pow_hash(coin_id, miner, nonce, prev_hash, tx_root)
    return h[:difficulty] == "0" * difficulty


def estimate_hashrate_to_difficulty(difficulty: int) -> float:
    """Approx hashes needed: 16^difficulty."""
    return 16.0 ** difficulty


def compute_block_reward(base_reward: float, difficulty: int) -> float:
    """Reward = base_reward * 2^(difficulty - 1).

    Higher difficulty exponentially increases the reward, reflecting
    the greater computational work required.  This makes the coin
    creator's difficulty choice the primary economic lever — a coin
    with difficulty 8 pays 128× the base reward per solve.
    """
    return base_reward * (2 ** (difficulty - 1))


# ═══════════════════════════════════════════════════════════════════════
#  Rule engine — evaluate programmable rules
# ═══════════════════════════════════════════════════════════════════════

class RuleViolation(Exception):
    """Raised when a programmable rule blocks an operation."""
    def __init__(self, rule_type: RuleType, message: str):
        self.rule_type = rule_type
        self.message = message
        super().__init__(f"[{rule_type.name}] {message}")


def evaluate_transfer_rules(
    coin: PMCDefinition,
    sender: PMCHolder,
    receiver: PMCHolder | None,
    amount: float,
    now: float | None = None,
    memo: str = "",
) -> float:
    """
    Evaluate all transfer rules for a coin.  Returns the royalty amount
    (may be 0).  Raises ``RuleViolation`` on failure.
    """
    if now is None:
        now = time.time()
    royalty = 0.0

    for rule in coin.rules:
        if not rule.enabled:
            continue
        rt = rule.rule_type
        val = rule.value

        if rt == RuleType.MIN_TRANSFER:
            if amount < float(val):
                raise RuleViolation(rt, f"Amount {amount} below minimum {val}")

        elif rt == RuleType.MAX_TRANSFER:
            if amount > float(val):
                raise RuleViolation(rt, f"Amount {amount} exceeds maximum {val}")

        elif rt == RuleType.MAX_BALANCE and receiver is not None:
            cap = float(val)
            if receiver.balance + amount > cap:
                raise RuleViolation(
                    rt, f"Receiver balance would exceed cap {cap}"
                )

        elif rt == RuleType.COOLDOWN:
            cd = float(val)
            if sender.last_transfer_at > 0 and (now - sender.last_transfer_at) < cd:
                raise RuleViolation(
                    rt,
                    f"Cooldown active: {cd - (now - sender.last_transfer_at):.0f}s remaining",
                )

        elif rt == RuleType.ROYALTY_PCT:
            pct = float(val)
            royalty = amount * (pct / 100.0)

        elif rt == RuleType.WHITELIST:
            allowed = set(val) if isinstance(val, list) else set()
            if receiver is not None and receiver.account not in allowed:
                raise RuleViolation(rt, "Receiver not whitelisted")
            if sender.account not in allowed and sender.account != coin.issuer:
                raise RuleViolation(rt, "Sender not whitelisted")

        elif rt == RuleType.BLACKLIST:
            banned = set(val) if isinstance(val, list) else set()
            if sender.account in banned:
                raise RuleViolation(rt, "Sender is blacklisted")
            if receiver is not None and receiver.account in banned:
                raise RuleViolation(rt, "Receiver is blacklisted")

        elif rt == RuleType.EXPIRY_TTL:
            ttl = float(val)
            if sender.acquired_at > 0 and (now - sender.acquired_at) > ttl:
                raise RuleViolation(rt, "Sender balance has expired")

        elif rt == RuleType.REQUIRE_MEMO:
            if bool(val) and not memo:
                raise RuleViolation(rt, "Memo is required for transfers")

        elif rt == RuleType.TIME_LOCK:
            unlock_at = float(val)
            if now < unlock_at:
                raise RuleViolation(
                    rt, f"Balance locked until {unlock_at}"
                )

    return royalty


def evaluate_mint_rules(
    coin: PMCDefinition,
    miner_holder: PMCHolder,
    mint_amount: float,
    now: float | None = None,
) -> None:
    """Evaluate minting-related rules.  Raises ``RuleViolation`` on failure."""
    if now is None:
        now = time.time()

    for rule in coin.rules:
        if not rule.enabled:
            continue
        rt = rule.rule_type
        val = rule.value

        if rt == RuleType.MAX_PER_MINT:
            cap = float(val)
            if mint_amount > cap:
                raise RuleViolation(rt, f"Mint amount {mint_amount} exceeds cap {cap}")

        elif rt == RuleType.MINT_COOLDOWN:
            cd = float(val)
            if miner_holder.last_mint_at > 0 and (now - miner_holder.last_mint_at) < cd:
                raise RuleViolation(
                    rt,
                    f"Mint cooldown: {cd - (now - miner_holder.last_mint_at):.0f}s remaining",
                )

        elif rt == RuleType.MAX_BALANCE:
            cap = float(val)
            if miner_holder.balance + mint_amount > cap:
                raise RuleViolation(
                    rt, f"Post-mint balance would exceed cap {cap}"
                )


# ═══════════════════════════════════════════════════════════════════════
#  PMC Manager — central state and operations
# ═══════════════════════════════════════════════════════════════════════

class PMCManager:
    """
    Manages all Programmable Micro Coins, holder balances, and offers.

    Instantiated once per Ledger, similar to NFTokenManager / MPTManager.
    """

    def __init__(self) -> None:
        # coin_id → PMCDefinition
        self.coins: dict[str, PMCDefinition] = {}
        # coin_id → { account → PMCHolder }
        self._holders: dict[str, dict[str, PMCHolder]] = {}
        # symbol → coin_id (for quick lookup by ticker)
        self._symbol_index: dict[str, str] = {}
        # issuer → [coin_id]
        self._issuer_index: dict[str, list[str]] = {}
        # offer_id → PMCOffer
        self.offers: dict[str, PMCOffer] = {}
        # coin_id → [offer_id] (active offers index)
        self._offer_index: dict[str, list[str]] = {}
        # issuer → running sequence for deterministic IDs
        self._seq: dict[str, int] = {}
        # Global offer sequence
        self._offer_seq: int = 0
        # last PoW hash per coin (chain the PoW)
        self._last_pow_hash: dict[str, str] = {}
        # ── Transaction commitment pool ─────────────────────────────
        # coin_id → [pending tx dicts] awaiting PoW commitment
        self._pending_txs: dict[str, list[dict]] = {}
        # coin_id → [PMCCommitment] history of PoW-validated commits
        self._commitments: dict[str, list[PMCCommitment]] = {}
        # tx_hash → commitment_id (index: which commitment includes a tx)
        self._tx_commitment_index: dict[str, str] = {}

    # ── ID generation ───────────────────────────────────────────────

    def _make_coin_id(self, issuer: str, symbol: str, seq: int) -> str:
        raw = f"PMC:{issuer}:{symbol}:{seq}".encode("utf-8")
        return hashlib.blake2b(raw, digest_size=32).hexdigest()[:40]

    def _make_offer_id(self, owner: str) -> str:
        self._offer_seq += 1
        raw = f"PMCO:{owner}:{self._offer_seq}:{time.time()}".encode("utf-8")
        return hashlib.blake2b(raw, digest_size=20).hexdigest()

    # ── Coin creation ───────────────────────────────────────────────

    def create_coin(
        self,
        issuer: str,
        symbol: str,
        name: str,
        max_supply: float = 0.0,
        decimals: int = DEFAULT_DECIMALS,
        pow_difficulty: int = DEFAULT_POW_DIFFICULTY,
        base_reward: float = DEFAULT_BASE_REWARD,
        flags: int = int(DEFAULT_FLAGS),
        metadata: str = "",
        rules: list[dict] | None = None,
        now: float | None = None,
    ) -> tuple[bool, str, PMCDefinition | None]:
        """
        Create a new Programmable Micro Coin definition.

        Returns (success, message, definition_or_None).
        """
        # Validate symbol
        if not symbol or len(symbol) > MAX_COIN_SYMBOL_LEN:
            return False, f"Symbol must be 1-{MAX_COIN_SYMBOL_LEN} chars", None
        symbol = symbol.upper()
        if symbol == "NXF":
            return False, "Cannot use reserved symbol NXF", None
        if symbol in self._symbol_index:
            return False, f"Symbol '{symbol}' already exists", None

        # Validate name
        if not name or len(name) > MAX_COIN_NAME_LEN:
            return False, f"Name must be 1-{MAX_COIN_NAME_LEN} chars", None

        # Validate supply
        if max_supply < 0 or max_supply > MAX_SUPPLY_CAP:
            return False, f"Max supply must be 0 (unlimited) to {MAX_SUPPLY_CAP}", None

        # Validate decimals
        if decimals < 0 or decimals > MAX_DECIMALS:
            return False, f"Decimals must be 0-{MAX_DECIMALS}", None

        # Validate PoW difficulty
        if pow_difficulty < MIN_POW_DIFFICULTY or pow_difficulty > MAX_POW_DIFFICULTY:
            return False, f"Difficulty must be {MIN_POW_DIFFICULTY}-{MAX_POW_DIFFICULTY}", None

        # Validate base reward
        if base_reward < MIN_BASE_REWARD or base_reward > MAX_BASE_REWARD:
            return False, f"Base reward must be {MIN_BASE_REWARD}-{MAX_BASE_REWARD}", None

        # Validate metadata length
        if metadata and len(metadata) > MAX_METADATA_LEN:
            return False, f"Metadata exceeds {MAX_METADATA_LEN} chars", None

        # Parse rules
        parsed_rules: list[PMCRule] = []
        if rules:
            if len(rules) > MAX_RULES:
                return False, f"Too many rules (max {MAX_RULES})", None
            for rd in rules:
                try:
                    parsed_rules.append(PMCRule.from_dict(rd))
                except (KeyError, ValueError) as exc:
                    return False, f"Invalid rule: {exc}", None

        seq = self._seq.get(issuer, 0)
        coin_id = self._make_coin_id(issuer, symbol, seq)
        self._seq[issuer] = seq + 1

        coin = PMCDefinition(
            coin_id=coin_id,
            symbol=symbol,
            name=name,
            issuer=issuer,
            decimals=decimals,
            max_supply=max_supply,
            flags=flags,
            pow_difficulty=pow_difficulty,
            base_reward=base_reward,
            metadata=metadata,
            rules=parsed_rules,
            created_at=now if now is not None else time.time(),
        )

        self.coins[coin_id] = coin
        self._symbol_index[symbol] = coin_id
        self._issuer_index.setdefault(issuer, []).append(coin_id)
        self._holders[coin_id] = {}
        self._offer_index[coin_id] = []
        self._last_pow_hash[coin_id] = coin_id  # genesis PoW seed
        self._pending_txs[coin_id] = []
        self._commitments[coin_id] = []

        return True, "Coin created", coin

    # ── PoW minting ─────────────────────────────────────────────────

    # ── Pending transaction pool ──────────────────────────────────

    def submit_pending_tx(self, coin_id: str, tx_dict: dict) -> tuple[bool, str, str]:
        """
        Submit a PMC transaction (transfer, burn, DEX settlement, etc.)
        to the pending pool for a coin, awaiting PoW commitment.

        Returns (success, message, tx_hash).
        """
        if coin_id not in self.coins:
            return False, "Coin not found", ""
        tx_hash = hash_pending_tx(tx_dict)
        tx_dict["_tx_hash"] = tx_hash
        tx_dict["_submitted_at"] = time.time()
        self._pending_txs.setdefault(coin_id, []).append(tx_dict)
        return True, "Transaction submitted to pending pool", tx_hash

    def get_pending_txs(self, coin_id: str) -> list[dict]:
        """Return the current pending transaction pool for a coin."""
        return list(self._pending_txs.get(coin_id, []))

    def get_pending_tx_root(self, coin_id: str) -> tuple[str, list[str]]:
        """
        Compute the Merkle root of pending transactions for a coin.

        Miners call this to get the *tx_root* they must include in their
        PoW hash.  Returns (merkle_root, [tx_hashes]).
        """
        pending = self._pending_txs.get(coin_id, [])
        tx_hashes = [tx["_tx_hash"] for tx in pending if "_tx_hash" in tx]
        root = compute_merkle_root(tx_hashes)
        return root, tx_hashes

    # ── PoW minting (with transaction commitment) ───────────────────

    def mint(
        self,
        coin_id: str,
        miner: str,
        nonce: int,
        tx_root: str = EMPTY_TX_ROOT,
        committed_tx_hashes: list[str] | None = None,
        now: float | None = None,
    ) -> tuple[bool, str, float]:
        """
        Attempt to mint new supply via Proof-of-Work.

        The minter does **not** choose the reward amount — it is computed
        automatically from the coin's difficulty and base_reward:

            reward = base_reward * 2^(difficulty - 1)

        This means harder PoW puzzles pay exponentially more, making
        difficulty the economic backbone of each micro coin.

        **Transaction commitment** (new):
        Miners may include a *tx_root* — the Merkle root of pending PMC
        transactions they are committing to validate.  When present the
        PoW simultaneously mints new supply **and** anchors a batch of
        transactions into the coin's PoW chain, giving them
        cryptographic finality.  The PoW hash itself is bound to the
        tx_root so it cannot be re-used for a different transaction set.

        If *tx_root* is EMPTY_TX_ROOT (default) the mint proceeds as a
        "coinbase-only" block — backward-compatible with existing miners.

        Returns (success, message, minted_amount).
        """
        if now is None:
            now = time.time()

        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found", 0.0

        if not coin.has_flag(PMCFlag.MINTABLE):
            return False, "Minting is disabled for this coin", 0.0

        if coin.frozen:
            return False, "Coin is frozen", 0.0

        # Compute reward from difficulty
        reward = compute_block_reward(coin.base_reward, coin.pow_difficulty)

        # Check supply cap
        if coin.max_supply > 0:
            remaining = coin.max_supply - coin.total_minted
            if remaining <= 0:
                return False, "Max supply reached", 0.0
            reward = min(reward, remaining)

        if reward <= 0:
            return False, "Max supply reached", 0.0

        # Get/create holder
        holder = self._get_or_create_holder(coin_id, miner, now)

        # Evaluate mint rules
        try:
            evaluate_mint_rules(coin, holder, reward, now)
        except RuleViolation as exc:
            return False, str(exc), 0.0

        # ── Validate transaction commitment ───────────────────────
        # If miner supplied committed_tx_hashes, verify that the
        # tx_root they mined against actually matches.  This prevents
        # a miner from claiming they validated transactions they did
        # not actually include in their PoW hash.
        if committed_tx_hashes:
            expected_root = compute_merkle_root(committed_tx_hashes)
            if tx_root != expected_root:
                return False, "tx_root does not match committed transactions", 0.0
            # Verify each claimed tx exists in the pending pool
            pending_hashes = {
                tx["_tx_hash"] for tx in self._pending_txs.get(coin_id, [])
                if "_tx_hash" in tx
            }
            for txh in committed_tx_hashes:
                if txh not in pending_hashes:
                    return False, f"Committed tx {txh[:16]}… not in pending pool", 0.0

        # Verify Proof-of-Work (Bitcoin-style double-SHA256)
        # The tx_root is now part of the hash input — PoW is bound to
        # the exact set of transactions the miner is validating.
        prev_hash = self._last_pow_hash.get(coin_id, coin_id)
        if not verify_pow(coin_id, miner, nonce, coin.pow_difficulty,
                          prev_hash, tx_root):
            return False, "Invalid Proof-of-Work", 0.0

        # Round to coin decimals
        factor = 10 ** coin.decimals
        reward = math.floor(reward * factor) / factor

        # Apply mint
        holder.balance += reward
        holder.last_mint_at = now
        coin.total_minted += reward
        coin.total_mints += 1

        # Update PoW chain hash
        new_pow_hash = compute_pow_hash(
            coin_id, miner, nonce, prev_hash, tx_root
        )
        self._last_pow_hash[coin_id] = new_pow_hash

        # ── Record commitment & drain committed txs from pool ─────
        final_tx_hashes = committed_tx_hashes or []
        prev_commitment_id = (
            self._commitments[coin_id][-1].commitment_id
            if self._commitments.get(coin_id)
            else ""
        )
        commitment = PMCCommitment(
            commitment_id=new_pow_hash,
            coin_id=coin_id,
            miner=miner,
            tx_root=tx_root,
            tx_hashes=final_tx_hashes,
            tx_count=len(final_tx_hashes),
            pow_hash=new_pow_hash,
            difficulty=coin.pow_difficulty,
            reward=reward,
            timestamp=now,
            prev_commitment=prev_commitment_id,
        )
        self._commitments.setdefault(coin_id, []).append(commitment)

        # Index each committed tx and remove from pending pool
        if final_tx_hashes:
            committed_set = set(final_tx_hashes)
            for txh in final_tx_hashes:
                self._tx_commitment_index[txh] = new_pow_hash
            self._pending_txs[coin_id] = [
                tx for tx in self._pending_txs.get(coin_id, [])
                if tx.get("_tx_hash") not in committed_set
            ]

        committed_count = len(final_tx_hashes)
        if committed_count > 0:
            return (
                True,
                f"Minted {reward} {coin.symbol} (difficulty {coin.pow_difficulty}, "
                f"committed {committed_count} txs)",
                reward,
            )
        return True, f"Minted {reward} {coin.symbol} (difficulty {coin.pow_difficulty})", reward

    # ── Transfer ────────────────────────────────────────────────────

    def transfer(
        self,
        coin_id: str,
        sender: str,
        receiver: str,
        amount: float,
        memo: str = "",
        now: float | None = None,
    ) -> tuple[bool, str, float]:
        """
        Transfer PMC tokens.  Returns (success, msg, royalty_paid).
        """
        if now is None:
            now = time.time()

        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found", 0.0

        if not coin.has_flag(PMCFlag.TRANSFERABLE):
            return False, "Transfers disabled for this coin", 0.0

        if coin.frozen:
            return False, "Coin is frozen", 0.0

        if amount <= 0:
            return False, "Amount must be positive", 0.0

        if sender == receiver:
            return False, "Cannot transfer to self", 0.0

        s_holder = self._holders.get(coin_id, {}).get(sender)
        if s_holder is None or s_holder.balance < amount:
            return False, "Insufficient balance", 0.0

        if s_holder.frozen:
            return False, "Sender account frozen", 0.0

        r_holder = self._get_or_create_holder(coin_id, receiver, now)
        if r_holder.frozen:
            return False, "Receiver account frozen", 0.0

        # Evaluate programmable rules
        try:
            royalty = evaluate_transfer_rules(
                coin, s_holder, r_holder, amount, now, memo
            )
        except RuleViolation as exc:
            return False, str(exc), 0.0

        # Round
        factor = 10 ** coin.decimals
        amount = math.floor(amount * factor) / factor
        royalty = math.floor(royalty * factor) / factor

        net_amount = amount - royalty

        # Debit sender
        s_holder.balance -= amount
        s_holder.last_transfer_at = now

        # Credit receiver
        r_holder.balance += net_amount

        # Credit royalty to issuer
        if royalty > 0 and coin.issuer != sender:
            issuer_holder = self._get_or_create_holder(coin_id, coin.issuer, now)
            issuer_holder.balance += royalty

        # Submit to pending pool for PoW commitment
        self.submit_pending_tx(coin_id, {
            "type": "transfer",
            "coin_id": coin_id,
            "sender": sender,
            "receiver": receiver,
            "amount": net_amount,
            "royalty": royalty,
            "timestamp": now,
        })

        return True, f"Transferred {net_amount} {coin.symbol}", royalty

    # ── Burn ────────────────────────────────────────────────────────

    def burn(
        self,
        coin_id: str,
        account: str,
        amount: float,
        now: float | None = None,
    ) -> tuple[bool, str]:
        """Burn (destroy) tokens from an account."""
        if now is None:
            now = time.time()

        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found"

        if not coin.has_flag(PMCFlag.BURNABLE):
            return False, "Burning disabled for this coin"

        holder = self._holders.get(coin_id, {}).get(account)
        if holder is None or holder.balance < amount:
            return False, "Insufficient balance"

        if amount <= 0:
            return False, "Amount must be positive"

        factor = 10 ** coin.decimals
        amount = math.floor(amount * factor) / factor

        holder.balance -= amount
        coin.total_burned += amount

        # Submit to pending pool for PoW commitment
        self.submit_pending_tx(coin_id, {
            "type": "burn",
            "coin_id": coin_id,
            "account": account,
            "amount": amount,
            "timestamp": now,
        })

        return True, f"Burned {amount} {coin.symbol}"

    # ── Set rules (issuer only) ─────────────────────────────────────

    def set_rules(
        self,
        coin_id: str,
        issuer: str,
        rules: list[dict],
    ) -> tuple[bool, str]:
        """Update the programmable rules on a coin (issuer only)."""
        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found"
        if coin.issuer != issuer:
            return False, "Only the issuer can update rules"
        if len(rules) > MAX_RULES:
            return False, f"Too many rules (max {MAX_RULES})"

        parsed: list[PMCRule] = []
        for rd in rules:
            try:
                parsed.append(PMCRule.from_dict(rd))
            except (KeyError, ValueError) as exc:
                return False, f"Invalid rule: {exc}"

        coin.rules = parsed
        return True, "Rules updated"

    # ── DEX: create offer ───────────────────────────────────────────

    def create_offer(
        self,
        coin_id: str,
        owner: str,
        is_sell: bool,
        amount: float,
        price: float,
        counter_coin_id: str = "",
        destination: str = "",
        expiration: float = 0.0,
        now: float | None = None,
    ) -> tuple[bool, str, PMCOffer | None]:
        """
        Post a buy/sell offer on the PMC DEX.

        For sell offers the owner must hold sufficient balance.
        For buy offers against NXF, the NXF reservation is handled by
        the ledger layer (caller).

        ``counter_coin_id`` empty means NXF; otherwise it's a PMC-to-PMC
        cross-trade.
        """
        if now is None:
            now = time.time()

        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found", None

        if not coin.has_flag(PMCFlag.CROSS_TRADEABLE):
            return False, "Cross-trading disabled for this coin", None

        if coin.frozen:
            return False, "Coin is frozen", None

        if amount <= 0 or price <= 0:
            return False, "Amount and price must be positive", None

        # Validate counter coin if PMC-to-PMC
        if counter_coin_id:
            counter = self.coins.get(counter_coin_id)
            if counter is None:
                return False, "Counter coin not found", None
            if not counter.has_flag(PMCFlag.CROSS_TRADEABLE):
                return False, "Counter coin is not cross-tradeable", None

        # Sell: check seller has enough
        if is_sell:
            holder = self._holders.get(coin_id, {}).get(owner)
            if holder is None or holder.balance < amount:
                return False, "Insufficient balance to sell", None

        # Buy with another PMC: check buyer has enough counter-coin
        if not is_sell and counter_coin_id:
            total_cost = amount * price
            c_holder = self._holders.get(counter_coin_id, {}).get(owner)
            if c_holder is None or c_holder.balance < total_cost:
                return False, "Insufficient counter-coin balance", None

        offer_id = self._make_offer_id(owner)
        offer = PMCOffer(
            offer_id=offer_id,
            coin_id=coin_id,
            owner=owner,
            is_sell=is_sell,
            amount=amount,
            price=price,
            counter_coin_id=counter_coin_id,
            destination=destination,
            expiration=expiration,
            created_at=now,
        )

        self.offers[offer_id] = offer
        self._offer_index.setdefault(coin_id, []).append(offer_id)

        return True, "Offer created", offer

    # ── DEX: accept offer ───────────────────────────────────────────

    def accept_offer(
        self,
        offer_id: str,
        taker: str,
        fill_amount: float | None = None,
        now: float | None = None,
    ) -> tuple[bool, str, dict]:
        """
        Accept (fill) an existing PMC DEX offer.

        Returns (success, msg, settlement_info).

        Settlement info dict keys:
          coin_amount, price, total_cost, counter_coin_id,
          seller, buyer, royalty
        """
        if now is None:
            now = time.time()

        offer = self.offers.get(offer_id)
        if offer is None:
            return False, "Offer not found", {}

        if not offer.is_active:
            return False, "Offer is no longer active", {}

        if offer.destination and offer.destination != taker:
            return False, "Offer restricted to another account", {}

        if offer.owner == taker:
            return False, "Cannot accept own offer", {}

        coin = self.coins.get(offer.coin_id)
        if coin is None:
            return False, "Coin not found", {}

        # Determine fill quantity
        qty = offer.remaining
        if fill_amount is not None:
            qty = min(qty, fill_amount)
        if qty <= 0:
            return False, "Nothing to fill", {}

        total_cost = qty * offer.price

        # Determine seller and buyer
        if offer.is_sell:
            seller = offer.owner
            buyer = taker
        else:
            seller = taker
            buyer = offer.owner

        # Validate seller has coins
        s_holder = self._holders.get(offer.coin_id, {}).get(seller)
        if s_holder is None or s_holder.balance < qty:
            return False, "Seller has insufficient coin balance", {}

        # For PMC-to-PMC cross-trade
        counter_coin_id = offer.counter_coin_id

        if counter_coin_id:
            # Buyer pays with counter coin
            b_counter = self._holders.get(counter_coin_id, {}).get(buyer)
            if b_counter is None or b_counter.balance < total_cost:
                return False, "Buyer has insufficient counter-coin balance", {}

        # Evaluate transfer rules on the coin being traded
        royalty = 0.0
        try:
            r_holder = self._get_or_create_holder(offer.coin_id, buyer, now)
            royalty = evaluate_transfer_rules(
                coin, s_holder, r_holder, qty, now
            )
        except RuleViolation as exc:
            return False, str(exc), {}

        factor = 10 ** coin.decimals
        royalty = math.floor(royalty * factor) / factor
        net_qty = qty - royalty

        # ── Execute settlement atomically ──

        # 1. Move coins: seller → buyer
        s_holder.balance -= qty
        s_holder.last_transfer_at = now
        r_holder.balance += net_qty

        # Royalty to issuer
        if royalty > 0:
            issuer_h = self._get_or_create_holder(offer.coin_id, coin.issuer, now)
            issuer_h.balance += royalty

        # 2. Move payment: buyer → seller
        if counter_coin_id:
            b_counter = self._holders[counter_coin_id][buyer]
            b_counter.balance -= total_cost
            s_counter = self._get_or_create_holder(counter_coin_id, seller, now)
            s_counter.balance += total_cost
        # If NXF-based, the ledger layer handles NXF balance moves

        # 3. Update offer fill
        offer.filled += qty

        settlement = {
            "coin_id": offer.coin_id,
            "coin_symbol": coin.symbol,
            "coin_amount": net_qty,
            "price": offer.price,
            "total_cost": total_cost,
            "counter_coin_id": counter_coin_id or "NXF",
            "seller": seller,
            "buyer": buyer,
            "royalty": royalty,
        }

        # Submit DEX settlement to pending pool for PoW commitment
        self.submit_pending_tx(offer.coin_id, {
            "type": "dex_settlement",
            "offer_id": offer_id,
            "coin_id": offer.coin_id,
            "seller": seller,
            "buyer": buyer,
            "coin_amount": net_qty,
            "price": offer.price,
            "total_cost": total_cost,
            "counter_coin_id": counter_coin_id or "NXF",
            "timestamp": now,
        })

        return True, "Offer filled", settlement

    # ── DEX: cancel offer ───────────────────────────────────────────

    def cancel_offer(
        self,
        offer_id: str,
        account: str,
    ) -> tuple[bool, str]:
        """Cancel an open offer (owner only)."""
        offer = self.offers.get(offer_id)
        if offer is None:
            return False, "Offer not found"
        if offer.owner != account:
            return False, "Only the offer owner can cancel"
        if offer.cancelled:
            return False, "Offer already cancelled"
        offer.cancelled = True
        return True, "Offer cancelled"

    # ── Freeze / unfreeze (issuer only) ─────────────────────────────

    def freeze_holder(self, coin_id: str, issuer: str, account: str) -> tuple[bool, str]:
        """Freeze a specific holder's balance."""
        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found"
        if coin.issuer != issuer:
            return False, "Not the issuer"
        if not coin.has_flag(PMCFlag.FREEZABLE):
            return False, "Freezing not enabled"
        holder = self._holders.get(coin_id, {}).get(account)
        if holder is None:
            return False, "Holder not found"
        holder.frozen = True
        return True, f"Frozen {account}"

    def unfreeze_holder(self, coin_id: str, issuer: str, account: str) -> tuple[bool, str]:
        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found"
        if coin.issuer != issuer:
            return False, "Not the issuer"
        holder = self._holders.get(coin_id, {}).get(account)
        if holder is None:
            return False, "Holder not found"
        holder.frozen = False
        return True, f"Unfrozen {account}"

    def freeze_coin(self, coin_id: str, issuer: str) -> tuple[bool, str]:
        """Global freeze — halts all operations on the coin."""
        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found"
        if coin.issuer != issuer:
            return False, "Not the issuer"
        coin.frozen = True
        return True, "Coin frozen"

    def unfreeze_coin(self, coin_id: str, issuer: str) -> tuple[bool, str]:
        coin = self.coins.get(coin_id)
        if coin is None:
            return False, "Coin not found"
        if coin.issuer != issuer:
            return False, "Not the issuer"
        coin.frozen = False
        return True, "Coin unfrozen"

    # ── Query helpers ───────────────────────────────────────────────

    def get_coin(self, coin_id: str) -> PMCDefinition | None:
        return self.coins.get(coin_id)

    def get_coin_by_symbol(self, symbol: str) -> PMCDefinition | None:
        cid = self._symbol_index.get(symbol.upper())
        return self.coins.get(cid) if cid else None

    def get_holder(self, coin_id: str, account: str) -> PMCHolder | None:
        return self._holders.get(coin_id, {}).get(account)

    def get_balance(self, coin_id: str, account: str) -> float:
        h = self._holders.get(coin_id, {}).get(account)
        return h.balance if h else 0.0

    def list_coins(self) -> list[PMCDefinition]:
        return list(self.coins.values())

    def list_coins_by_issuer(self, issuer: str) -> list[PMCDefinition]:
        ids = self._issuer_index.get(issuer, [])
        return [self.coins[cid] for cid in ids if cid in self.coins]

    def list_holders(self, coin_id: str) -> list[PMCHolder]:
        return list(self._holders.get(coin_id, {}).values())

    def list_active_offers(self, coin_id: str) -> list[PMCOffer]:
        ids = self._offer_index.get(coin_id, [])
        return [self.offers[oid] for oid in ids
                if oid in self.offers and self.offers[oid].is_active]

    def list_all_active_offers(self) -> list[PMCOffer]:
        return [o for o in self.offers.values() if o.is_active]

    def list_offers_by_account(self, account: str) -> list[PMCOffer]:
        return [o for o in self.offers.values() if o.owner == account]

    def get_order_book(
        self, coin_id: str, counter_coin_id: str = ""
    ) -> dict[str, list[dict]]:
        """
        Return structured buy/sell order book for a trading pair.
        Groups by price level, sorted best-first.
        """
        bids: dict[float, float] = {}   # price → total amount
        asks: dict[float, float] = {}

        for offer in self.list_active_offers(coin_id):
            if offer.counter_coin_id != counter_coin_id:
                continue
            bucket = asks if offer.is_sell else bids
            bucket[offer.price] = bucket.get(offer.price, 0.0) + offer.remaining

        bid_list = sorted(
            [{"price": p, "amount": a} for p, a in bids.items()],
            key=lambda x: -x["price"],
        )
        ask_list = sorted(
            [{"price": p, "amount": a} for p, a in asks.items()],
            key=lambda x: x["price"],
        )

        return {"bids": bid_list, "asks": ask_list}

    def get_portfolio(self, account: str) -> list[dict]:
        """Return all PMC holdings for an account."""
        result = []
        for coin_id, holders in self._holders.items():
            h = holders.get(account)
            if h and h.balance > 0:
                coin = self.coins.get(coin_id)
                result.append({
                    "coin_id": coin_id,
                    "symbol": coin.symbol if coin else "?",
                    "name": coin.name if coin else "?",
                    "balance": h.balance,
                    "frozen": h.frozen,
                })
        return result

    def get_pow_info(self, coin_id: str) -> dict:
        """Return current PoW mining info for a coin."""
        coin = self.coins.get(coin_id)
        if coin is None:
            return {}
        remaining = (coin.max_supply - coin.total_minted) if coin.max_supply > 0 else float("inf")
        reward = compute_block_reward(coin.base_reward, coin.pow_difficulty)
        if coin.max_supply > 0:
            reward = min(reward, max(0.0, coin.max_supply - coin.total_minted))
        # Compute current pending tx root for miners
        pending_root, pending_hashes = self.get_pending_tx_root(coin_id)
        return {
            "coin_id": coin_id,
            "symbol": coin.symbol,
            "difficulty": coin.pow_difficulty,
            "base_reward": coin.base_reward,
            "block_reward": reward,
            "estimated_hashes": estimate_hashrate_to_difficulty(coin.pow_difficulty),
            "total_minted": coin.total_minted,
            "total_mints": coin.total_mints,
            "max_supply": coin.max_supply,
            "remaining_supply": remaining,
            "prev_hash": self._last_pow_hash.get(coin_id, ""),
            "mintable": coin.has_flag(PMCFlag.MINTABLE) and not coin.frozen,
            "algorithm": "double-SHA256",
            "pending_tx_count": len(pending_hashes),
            "pending_tx_root": pending_root,
            "total_commitments": len(self._commitments.get(coin_id, [])),
        }

    # ── Commitment query helpers ─────────────────────────────────

    def get_commitment(self, commitment_id: str, coin_id: str) -> PMCCommitment | None:
        """Look up a specific commitment by its ID."""
        for c in self._commitments.get(coin_id, []):
            if c.commitment_id == commitment_id:
                return c
        return None

    def list_commitments(
        self, coin_id: str, limit: int = 50, offset: int = 0,
    ) -> list[PMCCommitment]:
        """Return the commitment history for a coin (newest first)."""
        chain = self._commitments.get(coin_id, [])
        return list(reversed(chain))[offset : offset + limit]

    def get_tx_commitment(self, tx_hash: str) -> str:
        """Return the commitment_id that includes a given tx hash, or ''."""
        return self._tx_commitment_index.get(tx_hash, "")

    def is_tx_committed(self, tx_hash: str) -> bool:
        """Check whether a transaction has been PoW-committed."""
        return tx_hash in self._tx_commitment_index

    def get_commitment_chain(self, coin_id: str) -> list[dict]:
        """Return the full commitment chain for a coin as dicts."""
        return [c.to_dict() for c in self._commitments.get(coin_id, [])]

    # ── Internal helpers ────────────────────────────────────────────

    def _get_or_create_holder(
        self, coin_id: str, account: str, now: float | None = None,
    ) -> PMCHolder:
        holders = self._holders.setdefault(coin_id, {})
        h = holders.get(account)
        if h is None:
            h = PMCHolder(
                account=account,
                coin_id=coin_id,
                acquired_at=now if now is not None else time.time(),
            )
            holders[account] = h
        return h
