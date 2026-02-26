"""
Test suite for nexaflow_core.p2p — Real async TCP P2P layer.

Covers:
  - Message encode / decode helpers
  - P2PNode start / stop lifecycle
  - Two-node connection and message exchange
"""

import asyncio
import unittest

from nexaflow_core.p2p import P2PNode, encode_message, decode_message


class TestMessageEncoding(unittest.TestCase):
    """Test JSON-over-TCP message helpers."""

    def test_encode_returns_bytes(self):
        data = encode_message("HELLO", {"node_id": "n1"})
        self.assertIsInstance(data, bytes)
        self.assertTrue(data.endswith(b"\n"))

    def test_decode_roundtrip(self):
        encoded = encode_message("TX", {"amount": 42})
        decoded = decode_message(encoded)
        self.assertEqual(decoded["type"], "TX")
        self.assertEqual(decoded["payload"]["amount"], 42)

    def test_decode_invalid_json(self):
        result = decode_message(b"not json at all")
        self.assertIsNone(result)

    def test_encode_various_types(self):
        data = encode_message("PROPOSAL", {
            "tx_ids": ["a", "b"],
            "ledger_seq": 5,
            "threshold": 0.8,
        })
        decoded = decode_message(data)
        self.assertEqual(decoded["payload"]["tx_ids"], ["a", "b"])


class TestP2PNodeLifecycle(unittest.TestCase):
    """Test starting and stopping a P2P node."""

    def test_node_creation(self):
        node = P2PNode("test-node", "127.0.0.1", 19001)
        self.assertEqual(node.node_id, "test-node")
        self.assertEqual(node.host, "127.0.0.1")
        self.assertEqual(node.port, 19001)

    def test_start_and_stop(self):
        """Start a node, verify it's listening, then stop."""
        async def _test():
            node = P2PNode("n1", "127.0.0.1", 19002)
            await node.start()
            self.assertIsNotNone(node._server)
            await node.stop()

        asyncio.run(_test())


class TestP2PConnection(unittest.TestCase):
    """Test two nodes connecting and exchanging messages."""

    def test_two_nodes_connect(self):
        async def _test():
            n1 = P2PNode("node1", "127.0.0.1", 19003)
            n2 = P2PNode("node2", "127.0.0.1", 19004)

            await n1.start()
            await n2.start()

            # n1 connects to n2
            await n1.connect_to_peer("127.0.0.1", 19004)
            # Give a moment for HELLO exchange
            await asyncio.sleep(0.3)

            # Both should know about each other
            self.assertGreaterEqual(len(n1.peers), 1)

            await n1.stop()
            await n2.stop()

        asyncio.run(_test())

    def test_broadcast_transaction(self):
        async def _test():
            n1 = P2PNode("node1", "127.0.0.1", 19005)
            n2 = P2PNode("node2", "127.0.0.1", 19006)

            received = []

            def on_tx(payload, peer_id):
                received.append(payload)

            n2.on_transaction = on_tx

            await n1.start()
            await n2.start()

            await n1.connect_to_peer("127.0.0.1", 19006)
            await asyncio.sleep(0.3)

            # Broadcast a TX message from n1
            await n1.broadcast_transaction({"tx_id": "test123", "amount": 10.0})
            await asyncio.sleep(0.3)

            # n2 should have received the TX via on_transaction callback
            self.assertTrue(len(received) > 0)
            self.assertEqual(received[0]["tx_id"], "test123")

            await n1.stop()
            await n2.stop()

        asyncio.run(_test())


if __name__ == "__main__":
    unittest.main()
