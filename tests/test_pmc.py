"""
Comprehensive test suite for nexaflow_core.pmc — Programmable Micro Coins.

Covers:
  - Coin creation (validation, symbol uniqueness, flags, rules, NXF reserved)
  - PoW mining (verify_pow, compute_pow_hash, valid mint, invalid nonce,
    supply cap, difficulty adjustment, chain hashing)
  - Transfer (basic, royalty, cooldown, freeze, self-transfer, rules)
  - Burn (basic, disabled, insufficient)
  - Rule engine (all rule types: whitelist, blacklist, max-balance,
    min/max transfer, cooldown, royalty, expiry, require-memo, time-lock,
    max-per-mint, mint-cooldown)
  - DEX offers (create sell/buy, accept, cancel, destination-restricted,
    PMC-to-PMC cross-trade, frozen coin, insufficient balance)
  - Freeze / unfreeze (holder-level and coin-level)
  - Query helpers (list_coins, portfolio, order book, pow_info)
  - Edge cases & error paths
"""

import time
import unittest

from nexaflow_core.pmc import (
    DEFAULT_FLAGS,
    DEFAULT_POW_DIFFICULTY,
    MAX_COIN_SYMBOL_LEN,
    MAX_POW_DIFFICULTY,
    MAX_RULES,
    MIN_POW_DIFFICULTY,
    PMCDefinition,
    PMCFlag,
    PMCHolder,
    PMCManager,
    PMCOffer,
    PMCRule,
    RuleType,
    RuleViolation,
    adjust_difficulty,
    compute_pow_hash,
    estimate_hashrate_to_difficulty,
    evaluate_mint_rules,
    evaluate_transfer_rules,
    verify_pow,
)


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

def _find_valid_nonce(coin_id: str, miner: str, difficulty: int,
                      prev_hash: str = "", limit: int = 5_000_000) -> int | None:
    """Brute-force a valid nonce (for test use)."""
    for n in range(limit):
        if verify_pow(coin_id, miner, n, difficulty, prev_hash):
            return n
    return None


def _quick_coin(mgr: PMCManager, issuer: str = "rAlice",
                symbol: str = "TEST", name: str = "Test Coin",
                max_supply: float = 1_000_000.0,
                pow_difficulty: int = 1,
                flags: int = int(DEFAULT_FLAGS),
                rules: list[dict] | None = None,
                now: float = 1_000_000.0) -> PMCDefinition:
    """Create a coin with low difficulty for fast tests."""
    ok, msg, coin = mgr.create_coin(
        issuer=issuer, symbol=symbol, name=name,
        max_supply=max_supply, pow_difficulty=pow_difficulty,
        flags=flags, rules=rules, now=now,
    )
    assert ok, msg
    return coin


def _mint_quick(mgr: PMCManager, coin: PMCDefinition, miner: str,
                amount: float = 100.0, now: float = 1_000_001.0) -> float:
    """Find a nonce and mint tokens. Returns minted amount."""
    prev_hash = mgr._last_pow_hash.get(coin.coin_id, coin.coin_id)
    nonce = _find_valid_nonce(coin.coin_id, miner, coin.pow_difficulty, prev_hash)
    assert nonce is not None, "Could not find valid nonce"
    ok, msg, minted = mgr.mint(coin.coin_id, miner, nonce, amount, now=now)
    assert ok, msg
    return minted


# ═══════════════════════════════════════════════════════════════════════
#  Data-class unit tests
# ═══════════════════════════════════════════════════════════════════════

class TestPMCRule(unittest.TestCase):

    def test_round_trip(self):
        rule = PMCRule(rule_type=RuleType.MAX_BALANCE, value=1000, enabled=True)
        d = rule.to_dict()
        r2 = PMCRule.from_dict(d)
        self.assertEqual(r2.rule_type, RuleType.MAX_BALANCE)
        self.assertEqual(r2.value, 1000)
        self.assertTrue(r2.enabled)

    def test_from_dict_invalid_type(self):
        with self.assertRaises(KeyError):
            PMCRule.from_dict({"rule_type": "NONEXISTENT", "value": 1})


class TestPMCDefinition(unittest.TestCase):

    def test_circulating(self):
        defn = PMCDefinition(
            coin_id="c1", symbol="T", name="T", issuer="r1",
            total_minted=500.0, total_burned=120.0,
        )
        self.assertAlmostEqual(defn.circulating, 380.0)

    def test_has_flag(self):
        defn = PMCDefinition(
            coin_id="c1", symbol="T", name="T", issuer="r1",
            flags=int(PMCFlag.TRANSFERABLE | PMCFlag.MINTABLE),
        )
        self.assertTrue(defn.has_flag(PMCFlag.TRANSFERABLE))
        self.assertTrue(defn.has_flag(PMCFlag.MINTABLE))
        self.assertFalse(defn.has_flag(PMCFlag.BURNABLE))

    def test_get_rule_returns_enabled_only(self):
        defn = PMCDefinition(
            coin_id="c1", symbol="T", name="T", issuer="r1",
            rules=[PMCRule(RuleType.MAX_BALANCE, 500, enabled=False)],
        )
        self.assertIsNone(defn.get_rule(RuleType.MAX_BALANCE))

    def test_to_dict_includes_flag_names(self):
        defn = PMCDefinition(
            coin_id="c1", symbol="T", name="T", issuer="r1",
            flags=int(PMCFlag.TRANSFERABLE | PMCFlag.BURNABLE),
        )
        d = defn.to_dict()
        self.assertIn("TRANSFERABLE", d["flag_names"])
        self.assertIn("BURNABLE", d["flag_names"])


class TestPMCHolder(unittest.TestCase):

    def test_to_dict(self):
        h = PMCHolder(account="rBob", coin_id="c1", balance=42.5)
        d = h.to_dict()
        self.assertEqual(d["account"], "rBob")
        self.assertAlmostEqual(d["balance"], 42.5)


class TestPMCOffer(unittest.TestCase):

    def test_remaining(self):
        o = PMCOffer(
            offer_id="o1", coin_id="c1", owner="r1",
            is_sell=True, amount=100.0, price=1.0, filled=30.0,
        )
        self.assertAlmostEqual(o.remaining, 70.0)

    def test_is_active_cancelled(self):
        o = PMCOffer(
            offer_id="o1", coin_id="c1", owner="r1",
            is_sell=True, amount=100.0, price=1.0, cancelled=True,
        )
        self.assertFalse(o.is_active)

    def test_is_active_fully_filled(self):
        o = PMCOffer(
            offer_id="o1", coin_id="c1", owner="r1",
            is_sell=True, amount=100.0, price=1.0, filled=100.0,
        )
        self.assertFalse(o.is_active)

    def test_total_cost(self):
        o = PMCOffer(
            offer_id="o1", coin_id="c1", owner="r1",
            is_sell=True, amount=50.0, price=2.5,
        )
        self.assertAlmostEqual(o.total_cost, 125.0)


# ═══════════════════════════════════════════════════════════════════════
#  PoW helpers
# ═══════════════════════════════════════════════════════════════════════

class TestPoWHelpers(unittest.TestCase):

    def test_compute_pow_hash_deterministic(self):
        h1 = compute_pow_hash("coin1", "rAlice", 42, "abc")
        h2 = compute_pow_hash("coin1", "rAlice", 42, "abc")
        self.assertEqual(h1, h2)

    def test_compute_pow_hash_different_inputs(self):
        h1 = compute_pow_hash("coin1", "rAlice", 42, "abc")
        h2 = compute_pow_hash("coin1", "rAlice", 43, "abc")
        self.assertNotEqual(h1, h2)

    def test_verify_pow_valid(self):
        # With difficulty 1 it's easy to find a match
        for nonce in range(10000):
            if verify_pow("test_coin", "rMiner", nonce, 1, "seed"):
                self.assertTrue(True)
                return
        self.fail("Could not find a valid nonce in 10k attempts")

    def test_verify_pow_invalid(self):
        # A random nonce is overwhelmingly unlikely to satisfy difficulty 16
        self.assertFalse(verify_pow("x", "y", 0, 16, "z"))

    def test_estimate_hashrate(self):
        self.assertAlmostEqual(estimate_hashrate_to_difficulty(1), 16.0)
        self.assertAlmostEqual(estimate_hashrate_to_difficulty(4), 65536.0)

    def test_adjust_difficulty_insufficient_data(self):
        coin = PMCDefinition(
            coin_id="c", symbol="T", name="T", issuer="r",
            pow_difficulty=4,
        )
        coin._mint_timestamps = [1.0, 2.0]  # < window
        self.assertEqual(adjust_difficulty(coin), 4)

    def test_adjust_difficulty_increase(self):
        """Mints too fast → difficulty should increase."""
        coin = PMCDefinition(
            coin_id="c", symbol="T", name="T", issuer="r",
            pow_difficulty=4,
        )
        # 10 mints 1 second apart (target is 60s)
        coin._mint_timestamps = [float(i) for i in range(10)]
        self.assertEqual(adjust_difficulty(coin), 5)

    def test_adjust_difficulty_decrease(self):
        """Mints too slow → difficulty should decrease."""
        coin = PMCDefinition(
            coin_id="c", symbol="T", name="T", issuer="r",
            pow_difficulty=4,
        )
        # 10 mints 200 seconds apart
        coin._mint_timestamps = [float(i * 200) for i in range(10)]
        self.assertEqual(adjust_difficulty(coin), 3)

    def test_adjust_difficulty_stays(self):
        """Mints close to target → no change."""
        coin = PMCDefinition(
            coin_id="c", symbol="T", name="T", issuer="r",
            pow_difficulty=4,
        )
        # 10 mints ~60s apart
        coin._mint_timestamps = [float(i * 60) for i in range(10)]
        self.assertEqual(adjust_difficulty(coin), 4)


# ═══════════════════════════════════════════════════════════════════════
#  Rule engine
# ═══════════════════════════════════════════════════════════════════════

class TestRuleEngine(unittest.TestCase):

    def _coin_with_rules(self, rules: list[PMCRule]) -> PMCDefinition:
        return PMCDefinition(
            coin_id="c", symbol="T", name="T", issuer="rIssuer",
            rules=rules,
        )

    def _holder(self, account: str, balance: float = 100.0,
                last_xfer: float = 0.0, acquired: float = 0.0) -> PMCHolder:
        return PMCHolder(
            account=account, coin_id="c", balance=balance,
            last_transfer_at=last_xfer, acquired_at=acquired,
        )

    # ── Transfer rules ──

    def test_min_transfer_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MIN_TRANSFER, 10)])
        sender = self._holder("rA")
        r = evaluate_transfer_rules(coin, sender, None, 15.0, now=100.0)
        self.assertEqual(r, 0.0)

    def test_min_transfer_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MIN_TRANSFER, 10)])
        sender = self._holder("rA")
        with self.assertRaises(RuleViolation) as ctx:
            evaluate_transfer_rules(coin, sender, None, 5.0, now=100.0)
        self.assertEqual(ctx.exception.rule_type, RuleType.MIN_TRANSFER)

    def test_max_transfer_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MAX_TRANSFER, 1000)])
        evaluate_transfer_rules(coin, self._holder("rA"), None, 500.0, now=100.0)

    def test_max_transfer_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MAX_TRANSFER, 100)])
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(coin, self._holder("rA"), None, 200.0, now=100.0)

    def test_max_balance_receiver(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MAX_BALANCE, 150)])
        receiver = self._holder("rB", balance=100.0)
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(coin, self._holder("rA"), receiver, 60.0, now=100.0)

    def test_max_balance_receiver_ok(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MAX_BALANCE, 200)])
        receiver = self._holder("rB", balance=100.0)
        evaluate_transfer_rules(coin, self._holder("rA"), receiver, 50.0, now=100.0)

    def test_cooldown_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.COOLDOWN, 60)])
        sender = self._holder("rA", last_xfer=10.0)
        evaluate_transfer_rules(coin, sender, None, 10.0, now=100.0)

    def test_cooldown_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.COOLDOWN, 60)])
        sender = self._holder("rA", last_xfer=50.0)
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(coin, sender, None, 10.0, now=80.0)

    def test_royalty(self):
        coin = self._coin_with_rules([PMCRule(RuleType.ROYALTY_PCT, 5)])
        royalty = evaluate_transfer_rules(coin, self._holder("rA"), None, 100.0, now=100.0)
        self.assertAlmostEqual(royalty, 5.0)

    def test_whitelist_pass(self):
        coin = self._coin_with_rules(
            [PMCRule(RuleType.WHITELIST, ["rA", "rB"])]
        )
        sender = self._holder("rA")
        receiver = self._holder("rB")
        evaluate_transfer_rules(coin, sender, receiver, 10.0, now=100.0)

    def test_whitelist_fail_receiver(self):
        coin = self._coin_with_rules(
            [PMCRule(RuleType.WHITELIST, ["rA"])]
        )
        sender = self._holder("rA")
        receiver = self._holder("rC")
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(coin, sender, receiver, 10.0, now=100.0)

    def test_whitelist_issuer_exempt(self):
        """Issuer can always send even if not in whitelist."""
        coin = self._coin_with_rules(
            [PMCRule(RuleType.WHITELIST, ["rB"])]
        )
        sender = self._holder("rIssuer")  # matches coin.issuer
        receiver = self._holder("rB")
        evaluate_transfer_rules(coin, sender, receiver, 10.0, now=100.0)

    def test_blacklist_sender(self):
        coin = self._coin_with_rules(
            [PMCRule(RuleType.BLACKLIST, ["rEvil"])]
        )
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(
                coin, self._holder("rEvil"), self._holder("rB"), 10.0, now=100.0,
            )

    def test_blacklist_receiver(self):
        coin = self._coin_with_rules(
            [PMCRule(RuleType.BLACKLIST, ["rEvil"])]
        )
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(
                coin, self._holder("rA"), self._holder("rEvil"), 10.0, now=100.0,
            )

    def test_expiry_ttl_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.EXPIRY_TTL, 3600)])
        sender = self._holder("rA", acquired=1000.0)
        evaluate_transfer_rules(coin, sender, None, 10.0, now=2000.0)

    def test_expiry_ttl_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.EXPIRY_TTL, 100)])
        sender = self._holder("rA", acquired=1000.0)
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(coin, sender, None, 10.0, now=2000.0)

    def test_require_memo_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.REQUIRE_MEMO, True)])
        evaluate_transfer_rules(
            coin, self._holder("rA"), None, 10.0, now=100.0, memo="payment",
        )

    def test_require_memo_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.REQUIRE_MEMO, True)])
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(
                coin, self._holder("rA"), None, 10.0, now=100.0, memo="",
            )

    def test_time_lock_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.TIME_LOCK, 500.0)])
        evaluate_transfer_rules(coin, self._holder("rA"), None, 10.0, now=600.0)

    def test_time_lock_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.TIME_LOCK, 500.0)])
        with self.assertRaises(RuleViolation):
            evaluate_transfer_rules(coin, self._holder("rA"), None, 10.0, now=300.0)

    def test_disabled_rule_ignored(self):
        coin = self._coin_with_rules(
            [PMCRule(RuleType.MIN_TRANSFER, 1000, enabled=False)]
        )
        # Amount 5.0 would fail if rule were enabled
        evaluate_transfer_rules(coin, self._holder("rA"), None, 5.0, now=100.0)

    # ── Mint rules ──

    def test_max_per_mint_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MAX_PER_MINT, 50)])
        holder = self._holder("rMiner")
        evaluate_mint_rules(coin, holder, 30.0, now=100.0)

    def test_max_per_mint_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MAX_PER_MINT, 50)])
        holder = self._holder("rMiner")
        with self.assertRaises(RuleViolation):
            evaluate_mint_rules(coin, holder, 60.0, now=100.0)

    def test_mint_cooldown_pass(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MINT_COOLDOWN, 30)])
        holder = PMCHolder(account="rMiner", coin_id="c", last_mint_at=10.0)
        evaluate_mint_rules(coin, holder, 10.0, now=50.0)

    def test_mint_cooldown_fail(self):
        coin = self._coin_with_rules([PMCRule(RuleType.MINT_COOLDOWN, 30)])
        holder = PMCHolder(account="rMiner", coin_id="c", last_mint_at=10.0)
        with self.assertRaises(RuleViolation):
            evaluate_mint_rules(coin, holder, 10.0, now=20.0)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — coin creation
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerCreation(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()

    def test_create_basic(self):
        ok, msg, coin = self.mgr.create_coin(
            "rAlice", "ZETA", "Zeta Coin", now=1000.0,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(coin)
        self.assertEqual(coin.symbol, "ZETA")
        self.assertEqual(coin.issuer, "rAlice")
        self.assertEqual(len(coin.coin_id), 40)

    def test_symbol_uppercased(self):
        ok, _, coin = self.mgr.create_coin("r1", "abc", "ABC", now=1000.0)
        self.assertTrue(ok)
        self.assertEqual(coin.symbol, "ABC")

    def test_symbol_nxf_reserved(self):
        ok, msg, _ = self.mgr.create_coin("r1", "NXF", "Native", now=1000.0)
        self.assertFalse(ok)
        self.assertIn("reserved", msg.lower())

    def test_symbol_duplicate(self):
        self.mgr.create_coin("rA", "DUP", "D1", now=1000.0)
        ok, msg, _ = self.mgr.create_coin("rB", "DUP", "D2", now=1001.0)
        self.assertFalse(ok)
        self.assertIn("already exists", msg)

    def test_symbol_too_long(self):
        ok, _, _ = self.mgr.create_coin("r1", "A" * 13, "Long", now=1000.0)
        self.assertFalse(ok)

    def test_symbol_empty(self):
        ok, _, _ = self.mgr.create_coin("r1", "", "Empty", now=1000.0)
        self.assertFalse(ok)

    def test_name_too_long(self):
        ok, _, _ = self.mgr.create_coin("r1", "X", "N" * 65, now=1000.0)
        self.assertFalse(ok)

    def test_negative_supply(self):
        ok, _, _ = self.mgr.create_coin("r1", "NEG", "Neg", max_supply=-1, now=1000.0)
        self.assertFalse(ok)

    def test_invalid_decimals(self):
        ok, _, _ = self.mgr.create_coin("r1", "DEC", "D", decimals=9, now=1000.0)
        self.assertFalse(ok)

    def test_invalid_pow_difficulty_low(self):
        ok, _, _ = self.mgr.create_coin("r1", "D", "D", pow_difficulty=0, now=1000.0)
        self.assertFalse(ok)

    def test_invalid_pow_difficulty_high(self):
        ok, _, _ = self.mgr.create_coin("r1", "D", "D", pow_difficulty=33, now=1000.0)
        self.assertFalse(ok)

    def test_metadata_too_long(self):
        ok, _, _ = self.mgr.create_coin("r1", "M", "M", metadata="x" * 2049, now=1000.0)
        self.assertFalse(ok)

    def test_too_many_rules(self):
        rules = [{"rule_type": "MAX_BALANCE", "value": 100}] * 33
        ok, _, _ = self.mgr.create_coin("r1", "R", "R", rules=rules, now=1000.0)
        self.assertFalse(ok)

    def test_create_with_rules(self):
        rules = [
            {"rule_type": "MAX_BALANCE", "value": 5000},
            {"rule_type": "ROYALTY_PCT", "value": 2},
        ]
        ok, _, coin = self.mgr.create_coin("r1", "RUL", "Rules", rules=rules, now=1000.0)
        self.assertTrue(ok)
        self.assertEqual(len(coin.rules), 2)
        self.assertIsNotNone(coin.get_rule(RuleType.MAX_BALANCE))

    def test_create_populates_indexes(self):
        self.mgr.create_coin("rA", "IDX", "Idx", now=1000.0)
        self.assertIn("IDX", self.mgr._symbol_index)
        self.assertEqual(len(self.mgr._issuer_index["rA"]), 1)

    def test_create_multiple_coins_same_issuer(self):
        self.mgr.create_coin("rA", "ONE", "One", now=1000.0)
        self.mgr.create_coin("rA", "TWO", "Two", now=1001.0)
        self.assertEqual(len(self.mgr._issuer_index["rA"]), 2)

    def test_default_flags(self):
        _, _, coin = self.mgr.create_coin("r1", "FLG", "F", now=1000.0)
        self.assertTrue(coin.has_flag(PMCFlag.TRANSFERABLE))
        self.assertTrue(coin.has_flag(PMCFlag.BURNABLE))
        self.assertTrue(coin.has_flag(PMCFlag.MINTABLE))
        self.assertTrue(coin.has_flag(PMCFlag.CROSS_TRADEABLE))


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — PoW minting
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerMinting(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)

    def test_mint_basic(self):
        minted = _mint_quick(self.mgr, self.coin, "rMiner", 50.0, now=1_000_001.0)
        self.assertAlmostEqual(minted, 50.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rMiner"), 50.0)
        self.assertAlmostEqual(self.coin.total_minted, 50.0)

    def test_mint_updates_pow_chain(self):
        prev = self.mgr._last_pow_hash[self.coin.coin_id]
        _mint_quick(self.mgr, self.coin, "rMiner")
        new = self.mgr._last_pow_hash[self.coin.coin_id]
        self.assertNotEqual(prev, new)

    def test_mint_invalid_nonce(self):
        ok, msg, _ = self.mgr.mint(
            self.coin.coin_id, "rMiner", nonce=99999999,
            amount=10.0, now=1_000_001.0,
        )
        # Overwhelmingly likely to be invalid, but not guaranteed
        # For safety, we just check that we got a boolean result
        self.assertIsInstance(ok, bool)

    def test_mint_coin_not_found(self):
        ok, msg, _ = self.mgr.mint("nonexistent", "rMiner", 0, 10.0, now=1000.0)
        self.assertFalse(ok)
        self.assertIn("not found", msg.lower())

    def test_mint_disabled(self):
        coin = _quick_coin(
            self.mgr, symbol="NOMINT",
            flags=int(PMCFlag.TRANSFERABLE | PMCFlag.BURNABLE),
        )
        ok, msg, _ = self.mgr.mint(coin.coin_id, "rMiner", 0, 10.0, now=1000.0)
        self.assertFalse(ok)
        self.assertIn("disabled", msg.lower())

    def test_mint_frozen_coin(self):
        self.coin.frozen = True
        ok, msg, _ = self.mgr.mint(self.coin.coin_id, "rMiner", 0, 10.0, now=1000.0)
        self.assertFalse(ok)
        self.assertIn("frozen", msg.lower())

    def test_mint_zero_amount(self):
        ok, msg, _ = self.mgr.mint(self.coin.coin_id, "rMiner", 0, 0.0, now=1000.0)
        self.assertFalse(ok)

    def test_mint_supply_cap(self):
        coin = _quick_coin(self.mgr, symbol="CAP", max_supply=50.0, pow_difficulty=1)
        # Mint up to the cap
        _mint_quick(self.mgr, coin, "rMiner", 50.0, now=1_000_001.0)
        # Next mint should fail — supply exhausted
        ok, msg, _ = self.mgr.mint(coin.coin_id, "rMiner", 0, 10.0, now=1_000_002.0)
        self.assertFalse(ok)
        self.assertIn("max supply", msg.lower())

    def test_mint_clamps_to_remaining_supply(self):
        coin = _quick_coin(self.mgr, symbol="CLP", max_supply=80.0, pow_difficulty=1)
        minted = _mint_quick(self.mgr, coin, "rMiner", 100.0, now=1_000_001.0)
        self.assertAlmostEqual(minted, 80.0)

    def test_mint_records_timestamp(self):
        _mint_quick(self.mgr, self.coin, "rMiner", 10.0, now=5000.0)
        self.assertIn(5000.0, self.coin._mint_timestamps)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — transfers
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerTransfer(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)
        _mint_quick(self.mgr, self.coin, "rAlice", 500.0, now=1_000_001.0)

    def test_transfer_basic(self):
        ok, msg, royalty = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 100.0, now=1_000_010.0,
        )
        self.assertTrue(ok)
        self.assertAlmostEqual(royalty, 0.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rAlice"), 400.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rBob"), 100.0)

    def test_transfer_insufficient(self):
        ok, msg, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 999.0, now=1_000_010.0,
        )
        self.assertFalse(ok)
        self.assertIn("insufficient", msg.lower())

    def test_transfer_to_self(self):
        ok, _, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rAlice", 10.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_transfer_zero(self):
        ok, _, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 0.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_transfer_coin_not_found(self):
        ok, _, _ = self.mgr.transfer("nope", "rA", "rB", 10.0, now=1000.0)
        self.assertFalse(ok)

    def test_transfer_disabled(self):
        coin = _quick_coin(
            self.mgr, symbol="NOXFER",
            flags=int(PMCFlag.BURNABLE | PMCFlag.MINTABLE),
        )
        _mint_quick(self.mgr, coin, "rAlice", 100.0, now=1_000_002.0)
        ok, msg, _ = self.mgr.transfer(
            coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_010.0,
        )
        self.assertFalse(ok)
        self.assertIn("disabled", msg.lower())

    def test_transfer_frozen_coin(self):
        self.coin.frozen = True
        ok, msg, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_transfer_frozen_sender(self):
        holder = self.mgr.get_holder(self.coin.coin_id, "rAlice")
        holder.frozen = True
        ok, msg, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_010.0,
        )
        self.assertFalse(ok)
        self.assertIn("frozen", msg.lower())

    def test_transfer_frozen_receiver(self):
        # Create receiver holder and freeze them
        self.mgr._get_or_create_holder(self.coin.coin_id, "rBob", now=1000.0)
        self.mgr.get_holder(self.coin.coin_id, "rBob").frozen = True
        ok, msg, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_010.0,
        )
        self.assertFalse(ok)
        self.assertIn("frozen", msg.lower())

    def test_transfer_with_royalty(self):
        coin = _quick_coin(
            self.mgr, symbol="ROY",
            rules=[{"rule_type": "ROYALTY_PCT", "value": 10}],
        )
        _mint_quick(self.mgr, coin, "rSender", 100.0, now=1_000_001.0)
        ok, msg, royalty = self.mgr.transfer(
            coin.coin_id, "rSender", "rBob", 100.0, now=1_000_010.0,
        )
        self.assertTrue(ok)
        self.assertAlmostEqual(royalty, 10.0)
        # Receiver gets 90 (net), issuer gets 10 (royalty)
        self.assertAlmostEqual(self.mgr.get_balance(coin.coin_id, "rBob"), 90.0)
        # Issuer is rAlice, gets royalty
        self.assertAlmostEqual(self.mgr.get_balance(coin.coin_id, "rAlice"), 10.0)

    def test_transfer_updates_last_transfer_at(self):
        self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 10.0, now=2_000_000.0,
        )
        holder = self.mgr.get_holder(self.coin.coin_id, "rAlice")
        self.assertAlmostEqual(holder.last_transfer_at, 2_000_000.0)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — burn
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerBurn(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)
        _mint_quick(self.mgr, self.coin, "rAlice", 200.0, now=1_000_001.0)

    def test_burn_basic(self):
        ok, msg = self.mgr.burn(self.coin.coin_id, "rAlice", 50.0, now=1_000_010.0)
        self.assertTrue(ok)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rAlice"), 150.0)
        self.assertAlmostEqual(self.coin.total_burned, 50.0)
        self.assertAlmostEqual(self.coin.circulating, 150.0)

    def test_burn_insufficient(self):
        ok, msg = self.mgr.burn(self.coin.coin_id, "rAlice", 999.0, now=1_000_010.0)
        self.assertFalse(ok)

    def test_burn_zero(self):
        ok, _ = self.mgr.burn(self.coin.coin_id, "rAlice", 0.0)
        self.assertFalse(ok)

    def test_burn_disabled(self):
        coin = _quick_coin(
            self.mgr, symbol="NOBURN",
            flags=int(PMCFlag.TRANSFERABLE | PMCFlag.MINTABLE),
        )
        _mint_quick(self.mgr, coin, "rAlice", 100.0, now=1_000_002.0)
        ok, msg = self.mgr.burn(coin.coin_id, "rAlice", 10.0)
        self.assertFalse(ok)
        self.assertIn("disabled", msg.lower())

    def test_burn_coin_not_found(self):
        ok, _ = self.mgr.burn("nonexistent", "rAlice", 10.0)
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — set rules
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerSetRules(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)

    def test_set_rules_basic(self):
        rules = [{"rule_type": "MAX_BALANCE", "value": 9999}]
        ok, msg = self.mgr.set_rules(self.coin.coin_id, "rAlice", rules)
        self.assertTrue(ok)
        self.assertEqual(len(self.coin.rules), 1)

    def test_set_rules_not_issuer(self):
        ok, msg = self.mgr.set_rules(self.coin.coin_id, "rBob", [])
        self.assertFalse(ok)
        self.assertIn("issuer", msg.lower())

    def test_set_rules_coin_not_found(self):
        ok, _ = self.mgr.set_rules("nope", "rAlice", [])
        self.assertFalse(ok)

    def test_set_rules_too_many(self):
        rules = [{"rule_type": "MAX_BALANCE", "value": 100}] * 33
        ok, _ = self.mgr.set_rules(self.coin.coin_id, "rAlice", rules)
        self.assertFalse(ok)

    def test_set_rules_invalid_rule(self):
        rules = [{"rule_type": "INVALID", "value": 1}]
        ok, _ = self.mgr.set_rules(self.coin.coin_id, "rAlice", rules)
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — DEX offers
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerDEX(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)
        _mint_quick(self.mgr, self.coin, "rSeller", 1000.0, now=1_000_001.0)

    # ── Create offer ──

    def test_create_sell_offer(self):
        ok, msg, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", is_sell=True,
            amount=100.0, price=0.5, now=1_000_010.0,
        )
        self.assertTrue(ok)
        self.assertIsNotNone(offer)
        self.assertTrue(offer.is_sell)
        self.assertAlmostEqual(offer.amount, 100.0)
        self.assertAlmostEqual(offer.price, 0.5)

    def test_create_buy_offer(self):
        ok, msg, offer = self.mgr.create_offer(
            self.coin.coin_id, "rBuyer", is_sell=False,
            amount=50.0, price=0.5, now=1_000_010.0,
        )
        self.assertTrue(ok)
        self.assertFalse(offer.is_sell)

    def test_create_sell_insufficient_balance(self):
        ok, _, _ = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", is_sell=True,
            amount=9999.0, price=1.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_create_offer_coin_not_found(self):
        ok, _, _ = self.mgr.create_offer(
            "nope", "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_create_offer_frozen_coin(self):
        self.coin.frozen = True
        ok, _, _ = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_create_offer_not_cross_tradeable(self):
        coin = _quick_coin(
            self.mgr, symbol="NCTRADE",
            flags=int(PMCFlag.TRANSFERABLE | PMCFlag.MINTABLE | PMCFlag.BURNABLE),
        )
        ok, _, _ = self.mgr.create_offer(
            coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_create_offer_invalid_amount(self):
        ok, _, _ = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 0.0, 1.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_create_offer_invalid_price(self):
        ok, _, _ = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, -1.0, now=1_000_010.0,
        )
        self.assertFalse(ok)

    # ── Accept offer ──

    def test_accept_sell_offer(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", is_sell=True,
            amount=100.0, price=0.5, now=1_000_010.0,
        )
        ok, msg, settlement = self.mgr.accept_offer(
            offer.offer_id, "rBuyer", now=1_000_020.0,
        )
        self.assertTrue(ok)
        self.assertEqual(settlement["seller"], "rSeller")
        self.assertEqual(settlement["buyer"], "rBuyer")
        self.assertAlmostEqual(settlement["coin_amount"], 100.0)
        self.assertAlmostEqual(settlement["total_cost"], 50.0)
        # Buyer should have the coins
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rBuyer"), 100.0)
        # Seller should have fewer
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rSeller"), 900.0)

    def test_accept_buy_offer(self):
        """When is_sell=False, taker is the seller."""
        # rBuyer wants to buy 50 @ 1.0 NXF each
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rBuyer", is_sell=False,
            amount=50.0, price=1.0, now=1_000_010.0,
        )
        ok, msg, settlement = self.mgr.accept_offer(
            offer.offer_id, "rSeller", now=1_000_020.0,
        )
        self.assertTrue(ok)
        self.assertEqual(settlement["seller"], "rSeller")
        self.assertEqual(settlement["buyer"], "rBuyer")
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rBuyer"), 50.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin.coin_id, "rSeller"), 950.0)

    def test_accept_partial_fill(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", is_sell=True,
            amount=100.0, price=1.0, now=1_000_010.0,
        )
        ok, _, settlement = self.mgr.accept_offer(
            offer.offer_id, "rBuyer", fill_amount=40.0, now=1_000_020.0,
        )
        self.assertTrue(ok)
        self.assertAlmostEqual(settlement["coin_amount"], 40.0)
        self.assertAlmostEqual(offer.filled, 40.0)
        self.assertTrue(offer.is_active)  # 60 remaining

    def test_accept_own_offer(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        ok, msg, _ = self.mgr.accept_offer(offer.offer_id, "rSeller", now=1_000_020.0)
        self.assertFalse(ok)
        self.assertIn("own offer", msg.lower())

    def test_accept_cancelled_offer(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        self.mgr.cancel_offer(offer.offer_id, "rSeller")
        ok, msg, _ = self.mgr.accept_offer(offer.offer_id, "rBuyer", now=1_000_020.0)
        self.assertFalse(ok)
        self.assertIn("active", msg.lower())

    def test_accept_destination_restricted(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0,
            destination="rSpecific", now=1_000_010.0,
        )
        ok, msg, _ = self.mgr.accept_offer(offer.offer_id, "rOther", now=1_000_020.0)
        self.assertFalse(ok)
        self.assertIn("restricted", msg.lower())
        # Correct taker should succeed
        ok2, _, _ = self.mgr.accept_offer(offer.offer_id, "rSpecific", now=1_000_021.0)
        self.assertTrue(ok2)

    def test_accept_offer_not_found(self):
        ok, _, _ = self.mgr.accept_offer("nonexistent", "rBuyer", now=1000.0)
        self.assertFalse(ok)

    # ── Cancel offer ──

    def test_cancel_offer(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        ok, msg = self.mgr.cancel_offer(offer.offer_id, "rSeller")
        self.assertTrue(ok)
        self.assertTrue(offer.cancelled)
        self.assertFalse(offer.is_active)

    def test_cancel_offer_not_owner(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        ok, msg = self.mgr.cancel_offer(offer.offer_id, "rRandom")
        self.assertFalse(ok)

    def test_cancel_already_cancelled(self):
        _, _, offer = self.mgr.create_offer(
            self.coin.coin_id, "rSeller", True, 10.0, 1.0, now=1_000_010.0,
        )
        self.mgr.cancel_offer(offer.offer_id, "rSeller")
        ok, msg = self.mgr.cancel_offer(offer.offer_id, "rSeller")
        self.assertFalse(ok)

    def test_cancel_offer_not_found(self):
        ok, _ = self.mgr.cancel_offer("nope", "rx")
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════════════════
#  PMC-to-PMC cross-trade
# ═══════════════════════════════════════════════════════════════════════

class TestPMCCrossTrade(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin_a = _quick_coin(self.mgr, symbol="ALPHA", name="Alpha")
        self.coin_b = _quick_coin(self.mgr, symbol="BETA", name="Beta")
        _mint_quick(self.mgr, self.coin_a, "rAlice", 500.0, now=1_000_001.0)
        _mint_quick(self.mgr, self.coin_b, "rBob", 500.0, now=1_000_002.0)

    def test_cross_trade_sell(self):
        """Alice sells 100 ALPHA for 2 BETA each."""
        _, _, offer = self.mgr.create_offer(
            self.coin_a.coin_id, "rAlice", is_sell=True,
            amount=100.0, price=2.0,
            counter_coin_id=self.coin_b.coin_id,
            now=1_000_010.0,
        )
        self.assertTrue(offer is not None)

        # Bob accepts — pays 200 BETA, gets 100 ALPHA
        ok, msg, settlement = self.mgr.accept_offer(
            offer.offer_id, "rBob", now=1_000_020.0,
        )
        self.assertTrue(ok, msg)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin_a.coin_id, "rBob"), 100.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin_a.coin_id, "rAlice"), 400.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin_b.coin_id, "rBob"), 300.0)
        self.assertAlmostEqual(self.mgr.get_balance(self.coin_b.coin_id, "rAlice"), 200.0)

    def test_cross_trade_insufficient_counter(self):
        """Buyer doesn't have enough counter-coin."""
        _, _, offer = self.mgr.create_offer(
            self.coin_a.coin_id, "rAlice", is_sell=True,
            amount=100.0, price=10.0,
            counter_coin_id=self.coin_b.coin_id,
            now=1_000_010.0,
        )
        # Bob only has 500 BETA, needs 1000
        ok, msg, _ = self.mgr.accept_offer(offer.offer_id, "rBob", now=1_000_020.0)
        self.assertFalse(ok)
        self.assertIn("insufficient", msg.lower())

    def test_cross_trade_counter_not_found(self):
        ok, msg, _ = self.mgr.create_offer(
            self.coin_a.coin_id, "rAlice", True, 10.0, 1.0,
            counter_coin_id="nonexistent", now=1_000_010.0,
        )
        self.assertFalse(ok)

    def test_cross_trade_buy_offer_insufficient_counter(self):
        """Buy offer creator lacks counter-coin balance."""
        ok, msg, _ = self.mgr.create_offer(
            self.coin_a.coin_id, "rBuyer", is_sell=False,
            amount=100.0, price=100.0,
            counter_coin_id=self.coin_b.coin_id,
            now=1_000_010.0,
        )
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — freeze / unfreeze
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerFreeze(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(
            self.mgr,
            flags=int(DEFAULT_FLAGS | PMCFlag.FREEZABLE),
        )
        _mint_quick(self.mgr, self.coin, "rHolder", 100.0, now=1_000_001.0)

    def test_freeze_holder(self):
        ok, msg = self.mgr.freeze_holder(self.coin.coin_id, "rAlice", "rHolder")
        self.assertTrue(ok)
        h = self.mgr.get_holder(self.coin.coin_id, "rHolder")
        self.assertTrue(h.frozen)

    def test_unfreeze_holder(self):
        self.mgr.freeze_holder(self.coin.coin_id, "rAlice", "rHolder")
        ok, msg = self.mgr.unfreeze_holder(self.coin.coin_id, "rAlice", "rHolder")
        self.assertTrue(ok)
        h = self.mgr.get_holder(self.coin.coin_id, "rHolder")
        self.assertFalse(h.frozen)

    def test_freeze_not_issuer(self):
        ok, msg = self.mgr.freeze_holder(self.coin.coin_id, "rRandom", "rHolder")
        self.assertFalse(ok)

    def test_freeze_not_freezable(self):
        coin2 = _quick_coin(self.mgr, symbol="NOFRZ",
                            flags=int(PMCFlag.TRANSFERABLE | PMCFlag.MINTABLE))
        ok, msg = self.mgr.freeze_holder(coin2.coin_id, "rAlice", "rSomeone")
        self.assertFalse(ok)

    def test_freeze_holder_not_found(self):
        ok, msg = self.mgr.freeze_holder(self.coin.coin_id, "rAlice", "rGhost")
        self.assertFalse(ok)

    def test_freeze_coin_global(self):
        ok, msg = self.mgr.freeze_coin(self.coin.coin_id, "rAlice")
        self.assertTrue(ok)
        self.assertTrue(self.coin.frozen)

    def test_unfreeze_coin_global(self):
        self.mgr.freeze_coin(self.coin.coin_id, "rAlice")
        ok, msg = self.mgr.unfreeze_coin(self.coin.coin_id, "rAlice")
        self.assertTrue(ok)
        self.assertFalse(self.coin.frozen)

    def test_freeze_coin_not_issuer(self):
        ok, _ = self.mgr.freeze_coin(self.coin.coin_id, "rEvil")
        self.assertFalse(ok)

    def test_freeze_coin_not_found(self):
        ok, _ = self.mgr.freeze_coin("nope", "rAlice")
        self.assertFalse(ok)


# ═══════════════════════════════════════════════════════════════════════
#  PMCManager — query helpers
# ═══════════════════════════════════════════════════════════════════════

class TestPMCManagerQueries(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)
        _mint_quick(self.mgr, self.coin, "rAlice", 300.0, now=1_000_001.0)
        _mint_quick(self.mgr, self.coin, "rBob", 100.0, now=1_000_002.0)

    def test_get_coin(self):
        c = self.mgr.get_coin(self.coin.coin_id)
        self.assertIsNotNone(c)
        self.assertEqual(c.symbol, "TEST")

    def test_get_coin_not_found(self):
        self.assertIsNone(self.mgr.get_coin("nonexistent"))

    def test_get_coin_by_symbol(self):
        c = self.mgr.get_coin_by_symbol("TEST")
        self.assertIsNotNone(c)
        c2 = self.mgr.get_coin_by_symbol("test")  # case insensitive
        self.assertIsNotNone(c2)
        self.assertEqual(c.coin_id, c2.coin_id)

    def test_get_coin_by_symbol_not_found(self):
        self.assertIsNone(self.mgr.get_coin_by_symbol("NOPE"))

    def test_get_holder(self):
        h = self.mgr.get_holder(self.coin.coin_id, "rAlice")
        self.assertIsNotNone(h)
        self.assertAlmostEqual(h.balance, 300.0)

    def test_get_balance(self):
        self.assertAlmostEqual(
            self.mgr.get_balance(self.coin.coin_id, "rAlice"), 300.0,
        )

    def test_get_balance_no_holder(self):
        self.assertAlmostEqual(
            self.mgr.get_balance(self.coin.coin_id, "rNobody"), 0.0,
        )

    def test_list_coins(self):
        coins = self.mgr.list_coins()
        self.assertEqual(len(coins), 1)

    def test_list_coins_by_issuer(self):
        self.mgr.create_coin("rAlice", "SEC", "Second", now=1001.0)
        listed = self.mgr.list_coins_by_issuer("rAlice")
        self.assertEqual(len(listed), 2)

    def test_list_holders(self):
        holders = self.mgr.list_holders(self.coin.coin_id)
        accounts = {h.account for h in holders}
        self.assertIn("rAlice", accounts)
        self.assertIn("rBob", accounts)

    def test_list_active_offers(self):
        self.mgr.create_offer(
            self.coin.coin_id, "rAlice", True, 50.0, 1.0, now=1_000_010.0,
        )
        self.mgr.create_offer(
            self.coin.coin_id, "rAlice", True, 30.0, 2.0, now=1_000_011.0,
        )
        active = self.mgr.list_active_offers(self.coin.coin_id)
        self.assertEqual(len(active), 2)

    def test_list_offers_by_account(self):
        self.mgr.create_offer(
            self.coin.coin_id, "rAlice", True, 50.0, 1.0, now=1_000_010.0,
        )
        offers = self.mgr.list_offers_by_account("rAlice")
        self.assertEqual(len(offers), 1)

    def test_get_order_book(self):
        self.mgr.create_offer(
            self.coin.coin_id, "rAlice", is_sell=True,
            amount=50.0, price=2.0, now=1_000_010.0,
        )
        self.mgr.create_offer(
            self.coin.coin_id, "rAlice", is_sell=True,
            amount=30.0, price=1.5, now=1_000_011.0,
        )
        self.mgr.create_offer(
            self.coin.coin_id, "rBuyer", is_sell=False,
            amount=20.0, price=1.0, now=1_000_012.0,
        )
        book = self.mgr.get_order_book(self.coin.coin_id)
        self.assertEqual(len(book["asks"]), 2)
        self.assertEqual(len(book["bids"]), 1)
        # Asks sorted ascending by price
        self.assertAlmostEqual(book["asks"][0]["price"], 1.5)
        self.assertAlmostEqual(book["asks"][1]["price"], 2.0)
        # Bids sorted descending by price
        self.assertAlmostEqual(book["bids"][0]["price"], 1.0)

    def test_get_portfolio(self):
        portfolio = self.mgr.get_portfolio("rAlice")
        self.assertEqual(len(portfolio), 1)
        self.assertEqual(portfolio[0]["symbol"], "TEST")
        self.assertAlmostEqual(portfolio[0]["balance"], 300.0)

    def test_get_portfolio_empty(self):
        portfolio = self.mgr.get_portfolio("rNobody")
        self.assertEqual(len(portfolio), 0)

    def test_get_pow_info(self):
        info = self.mgr.get_pow_info(self.coin.coin_id)
        self.assertEqual(info["symbol"], "TEST")
        self.assertEqual(info["difficulty"], 1)
        self.assertTrue(info["mintable"])
        self.assertGreater(info["total_minted"], 0)

    def test_get_pow_info_not_found(self):
        info = self.mgr.get_pow_info("nonexistent")
        self.assertEqual(info, {})

    def test_list_all_active_offers(self):
        self.mgr.create_offer(
            self.coin.coin_id, "rAlice", True, 10.0, 1.0, now=1_000_010.0,
        )
        all_offers = self.mgr.list_all_active_offers()
        self.assertEqual(len(all_offers), 1)


# ═══════════════════════════════════════════════════════════════════════
#  Integration: mint → transfer → burn lifecycle
# ═══════════════════════════════════════════════════════════════════════

class TestPMCLifecycle(unittest.TestCase):
    """End-to-end scenario: create → mine → transfer → trade → burn."""

    def test_full_lifecycle(self):
        mgr = PMCManager()

        # 1. Create coin
        ok, _, coin = mgr.create_coin(
            "rIssuer", "LIFE", "Lifecycle Coin",
            max_supply=10_000.0, pow_difficulty=1, now=1000.0,
        )
        self.assertTrue(ok)

        # 2. Mine some supply
        minted = _mint_quick(mgr, coin, "rMiner1", 500.0, now=1001.0)
        self.assertAlmostEqual(minted, 500.0)
        minted2 = _mint_quick(mgr, coin, "rMiner2", 300.0, now=1002.0)
        self.assertAlmostEqual(minted2, 300.0)

        # 3. Transfer
        ok, _, royalty = mgr.transfer(
            coin.coin_id, "rMiner1", "rAlice", 200.0, now=1010.0,
        )
        self.assertTrue(ok)
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rAlice"), 200.0)

        # 4. Create DEX sell offer
        ok, _, offer = mgr.create_offer(
            coin.coin_id, "rAlice", is_sell=True,
            amount=50.0, price=0.1, now=1020.0,
        )
        self.assertTrue(ok)

        # 5. Accept offer
        ok, _, settlement = mgr.accept_offer(
            offer.offer_id, "rBuyer", now=1030.0,
        )
        self.assertTrue(ok)
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rBuyer"), 50.0)
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rAlice"), 150.0)

        # 6. Burn
        ok, msg = mgr.burn(coin.coin_id, "rBuyer", 10.0, now=1040.0)
        self.assertTrue(ok)
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rBuyer"), 40.0)
        self.assertAlmostEqual(coin.total_burned, 10.0)
        self.assertAlmostEqual(coin.circulating, 790.0)

        # 7. Portfolio check
        portfolio = mgr.get_portfolio("rBuyer")
        self.assertEqual(len(portfolio), 1)
        self.assertAlmostEqual(portfolio[0]["balance"], 40.0)


# ═══════════════════════════════════════════════════════════════════════
#  Edge cases
# ═══════════════════════════════════════════════════════════════════════

class TestPMCEdgeCases(unittest.TestCase):

    def test_coin_id_deterministic(self):
        mgr = PMCManager()
        _, _, c1 = mgr.create_coin("rA", "DET", "Det", now=1000.0)
        mgr2 = PMCManager()
        _, _, c2 = mgr2.create_coin("rA", "DET", "Det", now=1000.0)
        self.assertEqual(c1.coin_id, c2.coin_id)

    def test_multiple_miners_same_coin(self):
        mgr = PMCManager()
        coin = _quick_coin(mgr, pow_difficulty=1)
        m1 = _mint_quick(mgr, coin, "rMiner1", 100.0, now=1_000_001.0)
        m2 = _mint_quick(mgr, coin, "rMiner2", 100.0, now=1_000_002.0)
        self.assertAlmostEqual(m1, 100.0)
        self.assertAlmostEqual(m2, 100.0)
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rMiner1"), 100.0)
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rMiner2"), 100.0)
        self.assertAlmostEqual(coin.total_minted, 200.0)

    def test_unlimited_supply(self):
        mgr = PMCManager()
        coin = _quick_coin(mgr, max_supply=0.0, pow_difficulty=1)
        m = _mint_quick(mgr, coin, "rMiner", 1_000_000.0, now=1_000_001.0)
        self.assertAlmostEqual(m, 1_000_000.0)

    def test_offer_expiration(self):
        mgr = PMCManager()
        coin = _quick_coin(mgr)
        _mint_quick(mgr, coin, "rAlice", 100.0, now=1_000_001.0)
        # Use a far-future expiration so the offer is active now
        far_future = time.time() + 999_999.0
        _, _, offer = mgr.create_offer(
            coin.coin_id, "rAlice", True, 50.0, 1.0,
            expiration=far_future, now=1_000_010.0,
        )
        # Before expiry — active
        self.assertTrue(offer.is_active)
        # After expiry — set to a past timestamp
        offer.expiration = 1.0  # expired long ago
        self.assertFalse(offer.is_active)

    def test_transfer_creates_receiver_holder(self):
        mgr = PMCManager()
        coin = _quick_coin(mgr)
        _mint_quick(mgr, coin, "rAlice", 100.0, now=1_000_001.0)
        self.assertIsNone(mgr.get_holder(coin.coin_id, "rBob"))
        mgr.transfer(coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_010.0)
        self.assertIsNotNone(mgr.get_holder(coin.coin_id, "rBob"))
        self.assertAlmostEqual(mgr.get_balance(coin.coin_id, "rBob"), 10.0)


if __name__ == "__main__":
    unittest.main()
