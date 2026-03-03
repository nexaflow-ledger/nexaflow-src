"""
Test suite for PMC PoW-Validated Transaction Commitments.

Verifies that PoW mining now goes beyond simple mint distribution and
actually validates / commits pending PMC transactions:

  - Merkle root computation (empty, single, multiple, odd leaf count)
  - Pending tx pool (submit, retrieve, compute root)
  - Mint with tx commitment (binds PoW to real tx data)
  - Commitment chain integrity (prev_commitment links)
  - Bad commitment rejection (wrong root, missing tx)
  - Backward compatibility (mint without commitment still works)
  - Commitment query helpers (lookup, is_committed, chain)
  - DEX / transfer / burn auto-submission to pending pool
  - get_pow_info includes commitment data
"""

import time
import unittest

from nexaflow_core.pmc import (
    DEFAULT_BASE_REWARD,
    DEFAULT_FLAGS,
    EMPTY_TX_ROOT,
    PMCCommitment,
    PMCDefinition,
    PMCFlag,
    PMCManager,
    RuleType,
    compute_block_reward,
    compute_merkle_root,
    compute_pow_hash,
    hash_pending_tx,
    verify_pow,
)


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

def _find_valid_nonce(
    coin_id: str, miner: str, difficulty: int,
    prev_hash: str = "", tx_root: str = EMPTY_TX_ROOT,
    limit: int = 5_000_000,
) -> int | None:
    """Brute-force a valid nonce for the given tx_root."""
    for n in range(limit):
        if verify_pow(coin_id, miner, n, difficulty, prev_hash, tx_root):
            return n
    return None


def _quick_coin(
    mgr: PMCManager, issuer: str = "rAlice",
    symbol: str = "COMMIT", name: str = "Commit Coin",
    max_supply: float = 1_000_000.0,
    pow_difficulty: int = 1,
    base_reward: float = DEFAULT_BASE_REWARD,
    flags: int = int(DEFAULT_FLAGS),
    rules: list[dict] | None = None,
    now: float = 1_000_000.0,
) -> PMCDefinition:
    ok, msg, coin = mgr.create_coin(
        issuer=issuer, symbol=symbol, name=name,
        max_supply=max_supply, pow_difficulty=pow_difficulty,
        base_reward=base_reward, flags=flags, rules=rules, now=now,
    )
    assert ok, msg
    return coin


def _mint_quick(
    mgr: PMCManager, coin: PMCDefinition, miner: str,
    tx_root: str = EMPTY_TX_ROOT,
    committed_tx_hashes: list[str] | None = None,
    now: float = 1_000_001.0,
) -> float:
    """Find nonce and mint, optionally with tx commitment."""
    prev_hash = mgr._last_pow_hash.get(coin.coin_id, coin.coin_id)
    nonce = _find_valid_nonce(
        coin.coin_id, miner, coin.pow_difficulty, prev_hash, tx_root,
    )
    assert nonce is not None, "Could not find valid nonce"
    ok, msg, minted = mgr.mint(
        coin.coin_id, miner, nonce,
        tx_root=tx_root,
        committed_tx_hashes=committed_tx_hashes,
        now=now,
    )
    assert ok, msg
    return minted


# ═══════════════════════════════════════════════════════════════════════
#  Merkle tree tests
# ═══════════════════════════════════════════════════════════════════════

class TestMerkleRoot(unittest.TestCase):

    def test_empty_returns_sentinel(self):
        self.assertEqual(compute_merkle_root([]), EMPTY_TX_ROOT)

    def test_single_leaf(self):
        root = compute_merkle_root(["aabbcc"])
        self.assertIsInstance(root, str)
        self.assertEqual(len(root), 64)
        self.assertNotEqual(root, EMPTY_TX_ROOT)

    def test_two_leaves(self):
        root = compute_merkle_root(["aabb", "ccdd"])
        self.assertEqual(len(root), 64)

    def test_odd_leaf_count_duplicates_last(self):
        root3 = compute_merkle_root(["a", "b", "c"])
        # 3 leaves → "c" is duplicated → same as 4 leaves [a, b, c, c]
        root4 = compute_merkle_root(["a", "b", "c", "c"])
        self.assertEqual(root3, root4)

    def test_deterministic(self):
        hashes = ["tx1", "tx2", "tx3", "tx4"]
        self.assertEqual(compute_merkle_root(hashes), compute_merkle_root(hashes))

    def test_order_matters(self):
        a = compute_merkle_root(["tx1", "tx2"])
        b = compute_merkle_root(["tx2", "tx1"])
        self.assertNotEqual(a, b)


class TestHashPendingTx(unittest.TestCase):

    def test_deterministic(self):
        tx = {"type": "transfer", "sender": "rAlice", "amount": 100}
        self.assertEqual(hash_pending_tx(tx), hash_pending_tx(tx))

    def test_different_txs_differ(self):
        tx1 = {"type": "transfer", "sender": "rAlice", "amount": 100}
        tx2 = {"type": "transfer", "sender": "rAlice", "amount": 200}
        self.assertNotEqual(hash_pending_tx(tx1), hash_pending_tx(tx2))

    def test_key_order_irrelevant(self):
        tx1 = {"b": 2, "a": 1}
        tx2 = {"a": 1, "b": 2}
        self.assertEqual(hash_pending_tx(tx1), hash_pending_tx(tx2))


# ═══════════════════════════════════════════════════════════════════════
#  PoW hash with tx_root
# ═══════════════════════════════════════════════════════════════════════

class TestPoWWithTxRoot(unittest.TestCase):

    def test_tx_root_changes_hash(self):
        """PoW hash must differ when tx_root differs."""
        h1 = compute_pow_hash("coin", "miner", 0, "prev", EMPTY_TX_ROOT)
        h2 = compute_pow_hash("coin", "miner", 0, "prev", "deadbeef" * 8)
        self.assertNotEqual(h1, h2)

    def test_backward_compat_empty_root(self):
        """Empty tx_root should still produce a valid hash."""
        h = compute_pow_hash("coin", "miner", 42, "prev", EMPTY_TX_ROOT)
        self.assertEqual(len(h), 64)

    def test_verify_pow_with_root(self):
        """verify_pow must check against the correct tx_root."""
        coin_id = "verifytest"
        miner = "rMiner"
        prev = "seed"
        root = compute_merkle_root(["tx_a", "tx_b"])

        nonce = _find_valid_nonce(coin_id, miner, 1, prev, root)
        self.assertIsNotNone(nonce)

        # Correct root succeeds
        self.assertTrue(verify_pow(coin_id, miner, nonce, 1, prev, root))

        # Wrong root fails
        self.assertFalse(verify_pow(coin_id, miner, nonce, 1, prev, EMPTY_TX_ROOT))

        # No root fails (default is EMPTY_TX_ROOT which differs)
        self.assertFalse(verify_pow(coin_id, miner, nonce, 1, prev))


# ═══════════════════════════════════════════════════════════════════════
#  Pending tx pool
# ═══════════════════════════════════════════════════════════════════════

class TestPendingTxPool(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr)

    def test_submit_and_retrieve(self):
        ok, msg, tx_hash = self.mgr.submit_pending_tx(
            self.coin.coin_id, {"type": "transfer", "amount": 50}
        )
        self.assertTrue(ok)
        self.assertEqual(len(tx_hash), 64)
        pending = self.mgr.get_pending_txs(self.coin.coin_id)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["_tx_hash"], tx_hash)

    def test_submit_unknown_coin_fails(self):
        ok, msg, tx_hash = self.mgr.submit_pending_tx(
            "nonexistent", {"type": "transfer"}
        )
        self.assertFalse(ok)

    def test_pending_tx_root_empty(self):
        root, hashes = self.mgr.get_pending_tx_root(self.coin.coin_id)
        self.assertEqual(root, EMPTY_TX_ROOT)
        self.assertEqual(hashes, [])

    def test_pending_tx_root_with_txs(self):
        self.mgr.submit_pending_tx(self.coin.coin_id, {"type": "burn", "amount": 10})
        self.mgr.submit_pending_tx(self.coin.coin_id, {"type": "burn", "amount": 20})
        root, hashes = self.mgr.get_pending_tx_root(self.coin.coin_id)
        self.assertNotEqual(root, EMPTY_TX_ROOT)
        self.assertEqual(len(hashes), 2)
        self.assertEqual(root, compute_merkle_root(hashes))


# ═══════════════════════════════════════════════════════════════════════
#  Mint with transaction commitment
# ═══════════════════════════════════════════════════════════════════════

class TestMintWithCommitment(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr, pow_difficulty=1)

    def test_backward_compat_no_commitment(self):
        """Minting without any commitment still works (coinbase-only)."""
        minted = _mint_quick(self.mgr, self.coin, "rMiner")
        self.assertGreater(minted, 0)
        # A commitment record is still created (with empty tx list)
        commits = self.mgr.list_commitments(self.coin.coin_id)
        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0].tx_count, 0)
        self.assertEqual(commits[0].tx_root, EMPTY_TX_ROOT)

    def test_mint_with_valid_commitment(self):
        """Miner includes pending txs in PoW and they get committed."""
        # Seed the pending pool
        self.mgr.submit_pending_tx(self.coin.coin_id, {"type": "transfer", "a": 1})
        self.mgr.submit_pending_tx(self.coin.coin_id, {"type": "burn", "a": 2})

        root, tx_hashes = self.mgr.get_pending_tx_root(self.coin.coin_id)
        self.assertEqual(len(tx_hashes), 2)

        # Mine with the commitment
        minted = _mint_quick(
            self.mgr, self.coin, "rMiner",
            tx_root=root,
            committed_tx_hashes=tx_hashes,
            now=1_000_001.0,
        )
        self.assertGreater(minted, 0)

        # Pending pool should be drained
        self.assertEqual(len(self.mgr.get_pending_txs(self.coin.coin_id)), 0)

        # Commitment should be recorded
        commits = self.mgr.list_commitments(self.coin.coin_id)
        self.assertEqual(len(commits), 1)
        self.assertEqual(commits[0].tx_count, 2)
        self.assertEqual(commits[0].tx_root, root)
        self.assertEqual(commits[0].tx_hashes, tx_hashes)
        self.assertEqual(commits[0].miner, "rMiner")

        # Each tx should be indexed
        for txh in tx_hashes:
            self.assertTrue(self.mgr.is_tx_committed(txh))
            self.assertEqual(self.mgr.get_tx_commitment(txh), commits[0].commitment_id)

    def test_wrong_tx_root_rejected(self):
        """If tx_root doesn't match committed_tx_hashes, mint fails."""
        self.mgr.submit_pending_tx(self.coin.coin_id, {"type": "transfer", "x": 1})
        root, tx_hashes = self.mgr.get_pending_tx_root(self.coin.coin_id)

        # Try to mine with a bogus root
        prev_hash = self.mgr._last_pow_hash.get(self.coin.coin_id, self.coin.coin_id)
        bogus_root = "dead" * 16
        nonce = _find_valid_nonce(
            self.coin.coin_id, "rMiner", 1, prev_hash, bogus_root,
        )
        assert nonce is not None
        ok, msg, _ = self.mgr.mint(
            self.coin.coin_id, "rMiner", nonce,
            tx_root=bogus_root,
            committed_tx_hashes=tx_hashes,
        )
        self.assertFalse(ok)
        self.assertIn("tx_root", msg)

    def test_committed_tx_not_in_pool_rejected(self):
        """Claiming a tx that's not in the pending pool fails."""
        fake_hash = "f" * 64
        root = compute_merkle_root([fake_hash])

        prev_hash = self.mgr._last_pow_hash.get(self.coin.coin_id, self.coin.coin_id)
        nonce = _find_valid_nonce(
            self.coin.coin_id, "rMiner", 1, prev_hash, root,
        )
        assert nonce is not None
        ok, msg, _ = self.mgr.mint(
            self.coin.coin_id, "rMiner", nonce,
            tx_root=root,
            committed_tx_hashes=[fake_hash],
        )
        self.assertFalse(ok)
        self.assertIn("not in pending pool", msg)

    def test_pow_bound_to_tx_root(self):
        """A nonce valid for one tx_root is invalid for another."""
        self.mgr.submit_pending_tx(self.coin.coin_id, {"type": "burn", "v": 1})
        root, tx_hashes = self.mgr.get_pending_tx_root(self.coin.coin_id)

        prev_hash = self.mgr._last_pow_hash.get(self.coin.coin_id, self.coin.coin_id)
        nonce = _find_valid_nonce(
            self.coin.coin_id, "rMiner", 1, prev_hash, root,
        )
        assert nonce is not None

        # Valid with the correct root
        self.assertTrue(verify_pow(
            self.coin.coin_id, "rMiner", nonce, 1, prev_hash, root
        ))

        # Invalid with EMPTY_TX_ROOT (different data ⇒ different hash)
        self.assertFalse(verify_pow(
            self.coin.coin_id, "rMiner", nonce, 1, prev_hash, EMPTY_TX_ROOT
        ))


# ═══════════════════════════════════════════════════════════════════════
#  Commitment chain integrity
# ═══════════════════════════════════════════════════════════════════════

class TestCommitmentChain(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr, pow_difficulty=1)

    def test_chain_links(self):
        """Each commitment's prev_commitment points to the prior one."""
        # 3 sequential mints
        _mint_quick(self.mgr, self.coin, "rMiner", now=1_000_001.0)
        _mint_quick(self.mgr, self.coin, "rMiner", now=1_000_002.0)
        _mint_quick(self.mgr, self.coin, "rMiner", now=1_000_003.0)

        chain = self.mgr.list_commitments(self.coin.coin_id, limit=10)
        # newest first
        self.assertEqual(len(chain), 3)
        # Latest points to middle
        self.assertEqual(chain[0].prev_commitment, chain[1].commitment_id)
        # Middle points to first
        self.assertEqual(chain[1].prev_commitment, chain[2].commitment_id)
        # First has empty prev
        self.assertEqual(chain[2].prev_commitment, "")

    def test_get_commitment_chain_as_dicts(self):
        _mint_quick(self.mgr, self.coin, "rMiner", now=1_000_001.0)
        chain_dicts = self.mgr.get_commitment_chain(self.coin.coin_id)
        self.assertIsInstance(chain_dicts, list)
        self.assertEqual(len(chain_dicts), 1)
        self.assertIn("commitment_id", chain_dicts[0])
        self.assertIn("tx_root", chain_dicts[0])


# ═══════════════════════════════════════════════════════════════════════
#  Auto-submission from transfer / burn / DEX
# ═══════════════════════════════════════════════════════════════════════

class TestAutoSubmitToPendingPool(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr, pow_difficulty=1)
        # Give rAlice some tokens to transfer/burn
        _mint_quick(self.mgr, self.coin, "rAlice", now=1_000_001.0)

    def test_transfer_creates_pending_tx(self):
        bal = self.mgr.get_balance(self.coin.coin_id, "rAlice")
        self.assertGreater(bal, 0)

        ok, msg, _ = self.mgr.transfer(
            self.coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_002.0,
        )
        self.assertTrue(ok)

        pending = self.mgr.get_pending_txs(self.coin.coin_id)
        # Should have at least 1 pending tx from the transfer
        transfer_txs = [p for p in pending if p.get("type") == "transfer"]
        self.assertGreaterEqual(len(transfer_txs), 1)
        self.assertEqual(transfer_txs[0]["sender"], "rAlice")
        self.assertEqual(transfer_txs[0]["receiver"], "rBob")

    def test_burn_creates_pending_tx(self):
        ok, msg = self.mgr.burn(
            self.coin.coin_id, "rAlice", 5.0, now=1_000_002.0,
        )
        self.assertTrue(ok)

        pending = self.mgr.get_pending_txs(self.coin.coin_id)
        burn_txs = [p for p in pending if p.get("type") == "burn"]
        self.assertGreaterEqual(len(burn_txs), 1)
        self.assertEqual(burn_txs[0]["account"], "rAlice")

    def test_dex_settlement_creates_pending_tx(self):
        """Accepting a DEX offer should submit a settlement tx."""
        # Give rBob tokens too
        _mint_quick(self.mgr, self.coin, "rBob", now=1_000_002.0)

        # rBob creates a sell offer
        ok, msg, offer = self.mgr.create_offer(
            self.coin.coin_id, "rBob", is_sell=True,
            amount=5.0, price=1.0, now=1_000_003.0,
        )
        self.assertTrue(ok)

        # rAlice accepts
        ok, msg, settlement = self.mgr.accept_offer(
            offer.offer_id, "rAlice", now=1_000_004.0,
        )
        self.assertTrue(ok)

        pending = self.mgr.get_pending_txs(self.coin.coin_id)
        dex_txs = [p for p in pending if p.get("type") == "dex_settlement"]
        self.assertGreaterEqual(len(dex_txs), 1)
        self.assertEqual(dex_txs[0]["seller"], "rBob")
        self.assertEqual(dex_txs[0]["buyer"], "rAlice")


# ═══════════════════════════════════════════════════════════════════════
#  get_pow_info includes commitment data
# ═══════════════════════════════════════════════════════════════════════

class TestPowInfoCommitmentData(unittest.TestCase):

    def setUp(self):
        self.mgr = PMCManager()
        self.coin = _quick_coin(self.mgr, pow_difficulty=1)

    def test_pow_info_has_commitment_fields(self):
        info = self.mgr.get_pow_info(self.coin.coin_id)
        self.assertIn("pending_tx_count", info)
        self.assertIn("pending_tx_root", info)
        self.assertIn("total_commitments", info)
        self.assertEqual(info["pending_tx_count"], 0)
        self.assertEqual(info["pending_tx_root"], EMPTY_TX_ROOT)
        self.assertEqual(info["total_commitments"], 0)

    def test_pow_info_updates_after_activity(self):
        # Mint once (generates a commitment)
        _mint_quick(self.mgr, self.coin, "rMiner", now=1_000_001.0)

        # Transfer to create a pending tx
        self.mgr.transfer(
            self.coin.coin_id, "rMiner", "rBob", 10.0, now=1_000_002.0,
        )

        info = self.mgr.get_pow_info(self.coin.coin_id)
        self.assertEqual(info["total_commitments"], 1)
        self.assertGreaterEqual(info["pending_tx_count"], 1)
        self.assertNotEqual(info["pending_tx_root"], EMPTY_TX_ROOT)


# ═══════════════════════════════════════════════════════════════════════
#  End-to-end: full cycle
# ═══════════════════════════════════════════════════════════════════════

class TestFullCommitmentCycle(unittest.TestCase):
    """
    End-to-end test: create coin → mint → transfer → submit pending →
    mine with commitment → verify committed.
    """

    def test_full_cycle(self):
        mgr = PMCManager()
        coin = _quick_coin(mgr, pow_difficulty=1)

        # 1. Coinbase-only first mint
        _mint_quick(mgr, coin, "rAlice", now=1_000_001.0)
        self.assertGreater(mgr.get_balance(coin.coin_id, "rAlice"), 0)

        # 2. rAlice transfers to rBob (auto-added to pending pool)
        mgr.transfer(coin.coin_id, "rAlice", "rBob", 10.0, now=1_000_002.0)

        # 3. rBob burns some (auto-added to pending pool)
        mgr.burn(coin.coin_id, "rBob", 2.0, now=1_000_003.0)

        # 4. Miner collects pending txs and computes root
        root, tx_hashes = mgr.get_pending_tx_root(coin.coin_id)
        self.assertEqual(len(tx_hashes), 2)  # transfer + burn
        self.assertNotEqual(root, EMPTY_TX_ROOT)

        # 5. Mine with commitment
        minted = _mint_quick(
            mgr, coin, "rMiner",
            tx_root=root,
            committed_tx_hashes=tx_hashes,
            now=1_000_004.0,
        )
        self.assertGreater(minted, 0)

        # 6. Verify: pending pool drained, txs committed
        self.assertEqual(len(mgr.get_pending_txs(coin.coin_id)), 0)
        for txh in tx_hashes:
            self.assertTrue(mgr.is_tx_committed(txh))

        # 7. Commitment chain has 2 entries (coinbase + committed)
        chain = mgr.list_commitments(coin.coin_id)
        self.assertEqual(len(chain), 2)
        self.assertEqual(chain[0].tx_count, 2)   # latest
        self.assertEqual(chain[1].tx_count, 0)    # coinbase-only

        # 8. Chain link integrity
        self.assertEqual(chain[0].prev_commitment, chain[1].commitment_id)


if __name__ == "__main__":
    unittest.main()
