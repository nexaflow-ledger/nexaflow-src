"""
Test suite for nexaflow_core.mining_api — Bitcoin Stratum Mining API.

Covers:
  - MiningCoordinator: session management, job creation, share validation
  - MiningNode: high-level start/stop lifecycle
  - StratumServer: JSON-RPC dispatch (subscribe, authorize, submit)
  - Pool statistics tracking
  - Edge cases: invalid nonce, unauthorized, expired jobs
"""

import asyncio
import json
import time
import unittest

from nexaflow_core.pmc import (
    DEFAULT_BASE_REWARD,
    PMCManager,
    compute_pow_hash,
    verify_pow,
)
from nexaflow_core.mining_api import (
    DEFAULT_STRATUM_PORT,
    EXTRANONCE2_SIZE,
    MinerSession,
    MiningCoordinator,
    MiningJob,
    MiningNode,
    PoolConfig,
    PoolStats,
    StratumServer,
)


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

def _setup_manager_with_coin(
    symbol: str = "TEST",
    difficulty: int = 1,
    base_reward: float = 50.0,
    max_supply: float = 1_000_000.0,
) -> tuple[PMCManager, str]:
    """Create a PMCManager with one minable coin. Returns (mgr, coin_id)."""
    mgr = PMCManager()
    ok, msg, coin = mgr.create_coin(
        issuer="rIssuer", symbol=symbol, name=f"{symbol} Coin",
        max_supply=max_supply, pow_difficulty=difficulty,
        base_reward=base_reward, now=1_000_000.0,
    )
    assert ok, msg
    return mgr, coin.coin_id


def _find_valid_nonce_for_miner(
    coin_id: str, miner: str, difficulty: int, prev_hash: str,
    limit: int = 5_000_000,
) -> int | None:
    """Brute-force a valid nonce."""
    for n in range(limit):
        if verify_pow(coin_id, miner, n, difficulty, prev_hash):
            return n
    return None


# ═══════════════════════════════════════════════════════════════════════
#  PoolStats
# ═══════════════════════════════════════════════════════════════════════

class TestPoolStats(unittest.TestCase):

    def test_to_dict(self):
        s = PoolStats()
        d = s.to_dict()
        self.assertIn("total_shares_accepted", d)
        self.assertIn("active_miners", d)
        self.assertIn("uptime_seconds", d)

    def test_uptime_positive(self):
        s = PoolStats(started_at=time.time() - 10.0)
        self.assertGreaterEqual(s.uptime, 9.0)


# ═══════════════════════════════════════════════════════════════════════
#  PoolConfig
# ═══════════════════════════════════════════════════════════════════════

class TestPoolConfig(unittest.TestCase):

    def test_from_dict_defaults(self):
        cfg = PoolConfig.from_dict({})
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.port, DEFAULT_STRATUM_PORT)

    def test_round_trip(self):
        cfg = PoolConfig(enabled=True, port=4444, host="127.0.0.1")
        d = cfg.to_dict()
        cfg2 = PoolConfig.from_dict(d)
        self.assertEqual(cfg2.port, 4444)
        self.assertTrue(cfg2.enabled)
        self.assertEqual(cfg2.host, "127.0.0.1")


# ═══════════════════════════════════════════════════════════════════════
#  MiningJob
# ═══════════════════════════════════════════════════════════════════════

class TestMiningJob(unittest.TestCase):

    def test_to_notify_params(self):
        job = MiningJob(
            job_id="00000001",
            coin_id="abc123",
            prev_hash="def456",
            miner_address="rMiner",
            difficulty=2,
            target="00" + "f" * 62,
        )
        params = job.to_notify_params("deadbeef")
        self.assertEqual(params[0], "00000001")      # job_id
        self.assertEqual(params[1], "def456")          # prev_hash
        self.assertEqual(params[2], "abc123")          # coin_id
        self.assertEqual(params[3], "deadbeef")        # extranonce1
        self.assertIsInstance(params[4], list)          # merkle (empty)
        self.assertIsInstance(params[8], bool)          # clean_jobs


# ═══════════════════════════════════════════════════════════════════════
#  MinerSession
# ═══════════════════════════════════════════════════════════════════════

class TestMinerSession(unittest.TestCase):

    def test_uptime(self):
        s = MinerSession(
            session_id="s1", extranonce1="00000001",
            connected_at=time.time() - 60.0,
        )
        self.assertGreaterEqual(s.uptime, 59.0)


# ═══════════════════════════════════════════════════════════════════════
#  MiningCoordinator
# ═══════════════════════════════════════════════════════════════════════

class TestMiningCoordinator(unittest.TestCase):

    def setUp(self):
        self.mgr, self.coin_id = _setup_manager_with_coin(difficulty=1)
        self.coord = MiningCoordinator(self.mgr)

    def test_add_coin(self):
        ok = self.coord.add_coin(self.coin_id)
        self.assertTrue(ok)
        self.assertIn(self.coin_id, self.coord.active_coins)
        self.assertEqual(self.coord.default_coin_id, self.coin_id)

    def test_add_coin_not_found(self):
        ok = self.coord.add_coin("nonexistent_coin_id")
        self.assertFalse(ok)

    def test_remove_coin(self):
        self.coord.add_coin(self.coin_id)
        self.coord.remove_coin(self.coin_id)
        self.assertNotIn(self.coin_id, self.coord.active_coins)

    def test_list_minable_coins(self):
        self.coord.add_coin(self.coin_id)
        coins = self.coord.list_minable_coins()
        self.assertEqual(len(coins), 1)
        self.assertEqual(coins[0]["coin_id"], self.coin_id)
        self.assertEqual(coins[0]["algorithm"], "double-SHA256")

    def test_create_session(self):
        session = self.coord.create_session(ip="192.168.1.1")
        self.assertIsNotNone(session)
        self.assertEqual(len(session.extranonce1), 8)  # 4 bytes hex
        self.assertIn(session.session_id, self.coord.sessions)
        self.assertEqual(self.coord.stats.active_miners, 1)

    def test_remove_session(self):
        session = self.coord.create_session()
        self.coord.remove_session(session.session_id)
        self.assertNotIn(session.session_id, self.coord.sessions)

    def test_unique_extranonces(self):
        s1 = self.coord.create_session()
        s2 = self.coord.create_session()
        self.assertNotEqual(s1.extranonce1, s2.extranonce1)

    def test_create_job(self):
        self.coord.add_coin(self.coin_id)
        job = self.coord.create_job(self.coin_id, "rMiner")
        self.assertIsNotNone(job)
        self.assertEqual(job.coin_id, self.coin_id)
        self.assertEqual(job.miner_address, "rMiner")
        self.assertEqual(job.difficulty, 1)
        self.assertIn(job.job_id, self.coord.jobs)

    def test_create_job_coin_not_registered(self):
        job = self.coord.create_job("nonexistent", "rMiner")
        self.assertIsNone(job)

    def test_validate_share_valid(self):
        """Find a real valid nonce and submit it through the coordinator."""
        self.coord.add_coin(self.coin_id)
        session = self.coord.create_session(ip="127.0.0.1")
        session.authorized = True
        session.wallet_address = "rTestMiner"
        session.current_coin_id = self.coin_id

        job = self.coord.create_job(self.coin_id, "rTestMiner")
        self.assertIsNotNone(job)

        # Find a valid nonce the miner's way:
        # The coordinator maps: pmc_nonce = int(extranonce1 + extranonce2 + nonce_hex, 16) % 2^63
        # We need to find a valid pmc_nonce, then decompose it back.
        info = self.mgr.get_pow_info(self.coin_id)
        prev_hash = info["prev_hash"]

        valid_nonce = _find_valid_nonce_for_miner(
            self.coin_id, "rTestMiner", 1, prev_hash,
        )
        self.assertIsNotNone(valid_nonce, "Could not find valid nonce")

        # Now we need extranonce1 + extranonce2 + nonce_hex to map to valid_nonce
        # We can't easily decompose, so let's test validity directly through the coordinator.
        # Instead, find a nonce where the combined value produces valid PoW.
        import hashlib

        found = False
        for n in range(500_000):
            # Build combined nonce the same way the coordinator does
            en2 = f"{n:08x}"
            nonce_hex = "00000000"
            combined = session.extranonce1 + en2 + nonce_hex
            pmc_nonce = int(combined, 16) % (2 ** 63)

            blob = f"{self.coin_id}:rTestMiner:{pmc_nonce}:{prev_hash}".encode()
            h = hashlib.sha256(hashlib.sha256(blob).digest()).hexdigest()
            if h[0] == "0":  # difficulty=1 means first hex char is 0
                accepted, message, minted = self.coord.validate_share(
                    session, job.job_id, en2, "00000000", nonce_hex,
                )
                self.assertTrue(accepted, message)
                self.assertGreater(minted, 0)
                found = True
                break

        self.assertTrue(found, "Could not find valid share in 500k attempts")
        self.assertEqual(session.shares_accepted, 1)
        self.assertEqual(self.coord.stats.total_blocks_found, 1)

    def test_validate_share_invalid_nonce(self):
        self.coord.add_coin(self.coin_id)
        session = self.coord.create_session()
        session.authorized = True
        session.wallet_address = "rMiner"

        # Create a job with very high difficulty so nonce 0 won't solve it
        mgr2, cid2 = _setup_manager_with_coin(symbol="HARD", difficulty=8)
        coord2 = MiningCoordinator(mgr2)
        coord2.add_coin(cid2)
        session2 = coord2.create_session()
        session2.authorized = True
        session2.wallet_address = "rMiner"
        job = coord2.create_job(cid2, "rMiner")

        accepted, msg, minted = coord2.validate_share(
            session2, job.job_id, "00000000", "00000000", "00000000",
        )
        self.assertFalse(accepted)
        self.assertAlmostEqual(minted, 0.0)

    def test_validate_share_job_not_found(self):
        session = self.coord.create_session()
        session.authorized = True
        accepted, msg, _ = self.coord.validate_share(
            session, "nonexistent_job", "00", "00", "00",
        )
        self.assertFalse(accepted)
        self.assertIn("not found", msg.lower())

    def test_validate_share_unauthorized(self):
        self.coord.add_coin(self.coin_id)
        session = self.coord.create_session()
        # Not authorized
        job = self.coord.create_job(self.coin_id, "rMiner")
        accepted, msg, _ = self.coord.validate_share(
            session, job.job_id, "00", "00", "00",
        )
        self.assertFalse(accepted)
        self.assertIn("not authorized", msg.lower())

    def test_get_pool_stats(self):
        stats = self.coord.get_pool_stats()
        self.assertIn("total_shares_accepted", stats)
        self.assertEqual(stats["active_miners"], 0)

    def test_get_miner_stats(self):
        session = self.coord.create_session(ip="10.0.0.1")
        session.wallet_address = "rTestWallet"
        session.worker_name = "rig1"
        stats = self.coord.get_miner_stats(session.session_id)
        self.assertEqual(stats["wallet_address"], "rTestWallet")
        self.assertEqual(stats["worker_name"], "rig1")
        self.assertEqual(stats["ip"], "10.0.0.1")

    def test_get_all_miner_stats(self):
        self.coord.create_session()
        self.coord.create_session()
        all_stats = self.coord.get_all_miner_stats()
        self.assertEqual(len(all_stats), 2)

    def test_get_miner_stats_not_found(self):
        stats = self.coord.get_miner_stats("nonexistent")
        self.assertEqual(stats, {})


# ═══════════════════════════════════════════════════════════════════════
#  MiningNode (high-level wrapper)
# ═══════════════════════════════════════════════════════════════════════

class TestMiningNode(unittest.TestCase):

    def setUp(self):
        self.mgr, self.coin_id = _setup_manager_with_coin()

    def test_add_coin(self):
        node = MiningNode(self.mgr)
        ok = node.add_coin(self.coin_id)
        self.assertTrue(ok)
        coins = node.list_coins()
        self.assertEqual(len(coins), 1)

    def test_remove_coin(self):
        node = MiningNode(self.mgr)
        node.add_coin(self.coin_id)
        node.remove_coin(self.coin_id)
        self.assertEqual(len(node.list_coins()), 0)

    def test_not_running_by_default(self):
        node = MiningNode(self.mgr)
        self.assertFalse(node.is_running)
        info = node.get_info()
        self.assertFalse(info["running"])

    def test_pool_stats_empty(self):
        node = MiningNode(self.mgr)
        stats = node.get_pool_stats()
        self.assertEqual(stats["total_blocks_found"], 0)

    def test_start_stop(self):
        """Test start/stop lifecycle using asyncio."""
        node = MiningNode(self.mgr)
        node.add_coin(self.coin_id)

        async def _lifecycle():
            await node.start(host="127.0.0.1", port=0)  # port 0 = OS assigns
            self.assertTrue(node.is_running)
            info = node.get_info()
            self.assertTrue(info["running"])
            await node.stop()
            self.assertFalse(node.is_running)

        asyncio.run(_lifecycle())


# ═══════════════════════════════════════════════════════════════════════
#  Stratum Server — JSON-RPC protocol
# ═══════════════════════════════════════════════════════════════════════

class TestStratumProtocol(unittest.TestCase):
    """Test the Stratum JSON-RPC protocol handling end-to-end."""

    def setUp(self):
        self.mgr, self.coin_id = _setup_manager_with_coin()
        self.coord = MiningCoordinator(self.mgr, default_coin_id=self.coin_id)
        self.coord.add_coin(self.coin_id)

    def test_subscribe_authorize_flow(self):
        """Simulate a full miner session via JSON-RPC messages."""
        responses = []

        async def _test():
            server = StratumServer(self.coord, host="127.0.0.1", port=0)
            await server.start()
            actual_port = server._server.sockets[0].getsockname()[1]

            reader, writer = await asyncio.open_connection("127.0.0.1", actual_port)

            # 1. mining.subscribe
            subscribe = json.dumps({
                "id": 1, "method": "mining.subscribe", "params": [],
            }) + "\n"
            writer.write(subscribe.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5.0)
            data = json.loads(resp)
            responses.append(data)
            self.assertEqual(data["id"], 1)
            self.assertIsNotNone(data["result"])
            extranonce1 = data["result"][1]
            self.assertEqual(len(extranonce1), 8)

            # 2. mining.authorize
            authorize = json.dumps({
                "id": 2,
                "method": "mining.authorize",
                "params": ["rTestWallet.rig1", "x"],
            }) + "\n"
            writer.write(authorize.encode())
            await writer.drain()

            # Read authorize response + any set_difficulty/notify messages
            for _ in range(5):
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                    if line:
                        data = json.loads(line)
                        responses.append(data)
                except asyncio.TimeoutError:
                    break

            # Check authorize was successful
            auth_resp = [r for r in responses if r.get("id") == 2]
            self.assertTrue(len(auth_resp) > 0)
            self.assertTrue(auth_resp[0]["result"])

            # Check we got a mining.notify job
            notify_msgs = [r for r in responses if r.get("method") == "mining.notify"]
            self.assertTrue(len(notify_msgs) > 0)

            writer.close()
            await server.stop()

        asyncio.run(_test())

    def test_authorize_invalid_address(self):
        """Reject authorization with invalid wallet address."""
        async def _test():
            server = StratumServer(self.coord, host="127.0.0.1", port=0)
            await server.start()
            actual_port = server._server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", actual_port)

            # Subscribe first
            writer.write((json.dumps({
                "id": 1, "method": "mining.subscribe", "params": [],
            }) + "\n").encode())
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=5.0)

            # Authorize with bad address
            writer.write((json.dumps({
                "id": 2, "method": "mining.authorize", "params": ["badaddr"],
            }) + "\n").encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5.0)
            data = json.loads(resp)
            self.assertIsNone(data["result"])
            self.assertIsNotNone(data["error"])

            writer.close()
            await server.stop()

        asyncio.run(_test())

    def test_unknown_method(self):
        """Unknown Stratum methods return an error."""
        async def _test():
            server = StratumServer(self.coord, host="127.0.0.1", port=0)
            await server.start()
            actual_port = server._server.sockets[0].getsockname()[1]
            reader, writer = await asyncio.open_connection("127.0.0.1", actual_port)

            writer.write((json.dumps({
                "id": 1, "method": "mining.bogus", "params": [],
            }) + "\n").encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5.0)
            data = json.loads(resp)
            self.assertIsNotNone(data["error"])

            writer.close()
            await server.stop()

        asyncio.run(_test())

    def test_server_info(self):
        """get_server_info returns correct structure."""
        server = StratumServer(self.coord, host="127.0.0.1", port=3333)
        info = server.get_server_info()
        self.assertEqual(info["host"], "127.0.0.1")
        self.assertEqual(info["port"], 3333)
        self.assertFalse(info["running"])
        self.assertEqual(info["protocol"], "stratum+tcp")


# ═══════════════════════════════════════════════════════════════════════
#  Integration: coordinator + actual PoW
# ═══════════════════════════════════════════════════════════════════════

class TestMiningIntegration(unittest.TestCase):
    """Integration tests: mine a block through the coordinator."""

    def test_mint_via_coordinator(self):
        """Create a coin, find a valid share, and mint through coordinator."""
        mgr, coin_id = _setup_manager_with_coin(difficulty=1, base_reward=100.0)
        coord = MiningCoordinator(mgr)
        coord.add_coin(coin_id)

        session = coord.create_session()
        session.authorized = True
        session.wallet_address = "rMiner"
        session.current_coin_id = coin_id

        job = coord.create_job(coin_id, "rMiner")

        # Brute-force from coordinator's perspective
        import hashlib
        info = mgr.get_pow_info(coin_id)
        prev_hash = info["prev_hash"]
        found = False

        for n in range(1_000_000):
            en2 = f"{n:08x}"
            combined = session.extranonce1 + en2 + "00000000"
            pmc_nonce = int(combined, 16) % (2 ** 63)
            blob = f"{coin_id}:rMiner:{pmc_nonce}:{prev_hash}".encode()
            h = hashlib.sha256(hashlib.sha256(blob).digest()).hexdigest()
            if h[0] == "0":
                ok, msg, minted = coord.validate_share(
                    session, job.job_id, en2, "00000000", "00000000",
                )
                if ok and minted > 0:
                    found = True
                    # Verify the mined amount
                    self.assertAlmostEqual(minted, 100.0)  # base_reward=100, diff=1
                    # Verify the balance was updated
                    bal = mgr.get_balance(coin_id, "rMiner")
                    self.assertAlmostEqual(bal, 100.0)
                    # Verify pool stats
                    self.assertEqual(coord.stats.total_blocks_found, 1)
                    self.assertAlmostEqual(coord.stats.total_coins_mined, 100.0)
                    break

        self.assertTrue(found, "Could not mine a block in 1M attempts")

    def test_multiple_coins(self):
        """Register multiple coins and mine each one."""
        mgr = PMCManager()
        _, _, c1 = mgr.create_coin(
            "rIssuer", "COIN1", "First", pow_difficulty=1,
            base_reward=10.0, now=1000.0,
        )
        _, _, c2 = mgr.create_coin(
            "rIssuer", "COIN2", "Second", pow_difficulty=1,
            base_reward=20.0, now=1001.0,
        )

        coord = MiningCoordinator(mgr)
        self.assertTrue(coord.add_coin(c1.coin_id))
        self.assertTrue(coord.add_coin(c2.coin_id))
        self.assertEqual(len(coord.active_coins), 2)
        coins = coord.list_minable_coins()
        symbols = {c["symbol"] for c in coins}
        self.assertIn("COIN1", symbols)
        self.assertIn("COIN2", symbols)


if __name__ == "__main__":
    unittest.main()
