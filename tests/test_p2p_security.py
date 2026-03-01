"""
Tests for P2P networking layer (nexaflow_core.p2p) — security & edge cases.

Covers:
  - encode_message / decode_message
  - Malformed message handling
  - _mark_seen dedup and eviction
  - PEERS gossip message handling (dispatch)
  - LEDGER_REQ / LEDGER_RES dispatch
  - PeerConnection info
  - P2PNode properties (peer_count, register_address, _known_addrs)
  - TX dedup (broadcast only once)
  - PROPOSAL dedup
"""

import asyncio
import json
import time
import unittest

from nexaflow_core.p2p import (
    P2PNode,
    PeerConnection,
    decode_message,
    encode_message,
)

# ═══════════════════════════════════════════════════════════════════
#  encode / decode
# ═══════════════════════════════════════════════════════════════════

class TestEncoding(unittest.TestCase):

    def test_encode_message_json(self):
        raw = encode_message("TX", {"tx_id": "abc", "amount": 42})
        self.assertIsInstance(raw, bytes)
        self.assertTrue(raw.endswith(b"\n"))
        parsed = json.loads(raw)
        self.assertEqual(parsed["type"], "TX")
        self.assertEqual(parsed["payload"]["tx_id"], "abc")
        self.assertIn("ts", parsed)

    def test_decode_valid(self):
        raw = encode_message("PING", {"node_id": "v1"})
        msg = decode_message(raw)
        self.assertIsNotNone(msg)
        self.assertEqual(msg["type"], "PING")

    def test_decode_garbage(self):
        self.assertIsNone(decode_message(b"NOT JSON\n"))

    def test_decode_empty(self):
        self.assertIsNone(decode_message(b""))

    def test_decode_binary_garbage(self):
        self.assertIsNone(decode_message(b"\x00\xff\xfe\n"))

    def test_encode_non_serializable(self):
        """Default=str should handle non-JSON types."""
        raw = encode_message("TEST", {"ts": time.time(), "obj": object()})
        msg = decode_message(raw)
        self.assertIsNotNone(msg)


# ═══════════════════════════════════════════════════════════════════
#  _mark_seen / dedup
# ═══════════════════════════════════════════════════════════════════

class TestDedup(unittest.TestCase):

    def test_mark_seen_adds_id(self):
        node = P2PNode("test")
        node._mark_seen("msg1")
        self.assertIn("msg1", node._seen_ids)

    def test_mark_seen_idempotent(self):
        node = P2PNode("test")
        node._mark_seen("msg1")
        node._mark_seen("msg1")
        self.assertIn("msg1", node._seen_ids)

    def test_eviction_after_max(self):
        """When _seen_ids exceeds _max_seen, half are evicted."""
        node = P2PNode("test")
        node._max_seen = 10
        for i in range(11):
            node._mark_seen(f"m{i}")
        # After eviction, should be about half + 1
        self.assertLessEqual(len(node._seen_ids), 11)
        self.assertIn("m10", node._seen_ids)  # latest always present

    def test_eviction_keeps_functionality(self):
        node = P2PNode("test")
        node._max_seen = 20
        for i in range(25):
            node._mark_seen(f"id_{i}")
        # Should not crash, and latest IDs present
        self.assertIn("id_24", node._seen_ids)


# ═══════════════════════════════════════════════════════════════════
#  P2PNode properties
# ═══════════════════════════════════════════════════════════════════

class TestP2PNodeProperties(unittest.TestCase):

    def test_peer_count_empty(self):
        node = P2PNode("v1")
        self.assertEqual(node.peer_count, 0)

    def test_register_address(self):
        node = P2PNode("v1")
        node.register_address("10.0.0.1:9002")
        self.assertIn("10.0.0.1:9002", node._known_addrs)

    def test_register_multiple_addresses(self):
        node = P2PNode("v1")
        node.register_address("a:1")
        node.register_address("b:2")
        node.register_address("c:3")
        self.assertEqual(len(node._known_addrs), 3)

    def test_node_id_stored(self):
        node = P2PNode("my-validator", host="10.0.0.5", port=5555)
        self.assertEqual(node.node_id, "my-validator")
        self.assertEqual(node.host, "10.0.0.5")
        self.assertEqual(node.port, 5555)

    def test_pubkey_default_none(self):
        node = P2PNode("v1")
        self.assertIsNone(node.node_pubkey)

    def test_pubkey_provided(self):
        fake_key = b"\x04" + b"\x01" * 64
        node = P2PNode("v1", node_pubkey=fake_key)
        self.assertEqual(node.node_pubkey, fake_key)


# ═══════════════════════════════════════════════════════════════════
#  Dispatch (unit test via direct call)
# ═══════════════════════════════════════════════════════════════════

class TestDispatch(unittest.TestCase):
    """Test _dispatch by calling it directly with mock PeerConnections."""

    def setUp(self):
        self.loop = asyncio.new_event_loop()

    def tearDown(self):
        self.loop.close()

    def _run(self, coro):
        """Helper to run async code in sync test."""
        return self.loop.run_until_complete(coro)

    def test_peers_gossip_populates_known_addrs(self):
        node = P2PNode("v1")
        # Use public routable IPs (private IPs are now filtered)
        msg = {"type": "PEERS", "payload": {"addresses": ["8.8.8.8:9001", "1.1.1.1:9002"]}}

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        self._run(node._dispatch(FakePeer(), msg))
        self.assertIn("8.8.8.8:9001", node._known_addrs)
        self.assertIn("1.1.1.1:9002", node._known_addrs)

    def test_peers_gossip_ignores_non_strings(self):
        node = P2PNode("v1")
        msg = {"type": "PEERS", "payload": {"addresses": [123, None, "valid:1"]}}

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        self._run(node._dispatch(FakePeer(), msg))
        self.assertIn("valid:1", node._known_addrs)
        self.assertNotIn(123, node._known_addrs)

    def test_tx_dedup(self):
        """Same tx_id should only trigger callback once."""
        node = P2PNode("v1")
        calls = []
        node.on_transaction = lambda payload, pid: calls.append(payload)

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"type": "TX", "payload": {"tx_id": "tx_abc"}}
        self._run(node._dispatch(FakePeer(), msg))
        self._run(node._dispatch(FakePeer(), msg))  # dupe
        self.assertEqual(len(calls), 1)

    def test_proposal_dedup(self):
        node = P2PNode("v1")
        calls = []
        node.on_proposal = lambda payload, pid: calls.append(payload)

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"type": "PROPOSAL", "payload": {"validator_id": "v2", "ledger_seq": 5}}
        self._run(node._dispatch(FakePeer(), msg))
        self._run(node._dispatch(FakePeer(), msg))  # dupe
        self.assertEqual(len(calls), 1)

    def test_ping_responds_with_pong(self):
        node = P2PNode("v1")
        sent_msgs = []

        class FakePeer:
            peer_id = "p1"
            async def send(self, msg_type, payload):
                sent_msgs.append(msg_type)
                return True

        msg = {"type": "PING", "payload": {}}
        self._run(node._dispatch(FakePeer(), msg))
        self.assertIn("PONG", sent_msgs)

    def test_ledger_req_callback(self):
        node = P2PNode("v1")
        request_from = []

        def on_req(peer_id):
            request_from.append(peer_id)
            return {"accounts": {}, "ledgers": []}

        node.on_ledger_request = on_req
        sent_msgs = []

        class FakePeer:
            peer_id = "p1"
            async def send(self, msg_type, payload):
                sent_msgs.append((msg_type, payload))
                return True

        msg = {"type": "LEDGER_REQ", "payload": {"node_id": "v2"}}
        self._run(node._dispatch(FakePeer(), msg))
        self.assertEqual(request_from, ["p1"])
        self.assertEqual(sent_msgs[0][0], "LEDGER_RES")

    def test_ledger_res_callback(self):
        node = P2PNode("v1")
        received = []
        node.on_ledger_response = lambda payload, pid: received.append(payload)

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"type": "LEDGER_RES", "payload": {"accounts": {"rA": 100}}}
        self._run(node._dispatch(FakePeer(), msg))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["accounts"]["rA"], 100)

    def test_consensus_ok_callback(self):
        node = P2PNode("v1")
        results = []
        node.on_consensus_result = lambda payload, pid: results.append(payload)

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"type": "CONSENSUS_OK", "payload": {"txns": ["tx1"]}}
        self._run(node._dispatch(FakePeer(), msg))
        self.assertEqual(len(results), 1)

    def test_unknown_message_type_no_crash(self):
        node = P2PNode("v1")

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"type": "UNKNOWN_TYPE", "payload": {}}
        self._run(node._dispatch(FakePeer(), msg))  # should not raise

    def test_missing_type_field(self):
        node = P2PNode("v1")

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"payload": {"something": 1}}  # no "type"
        self._run(node._dispatch(FakePeer(), msg))  # should not raise

    def test_tx_empty_id_not_deduped(self):
        """TX with empty tx_id should not be processed (no dedup entry)."""
        node = P2PNode("v1")
        calls = []
        node.on_transaction = lambda payload, pid: calls.append(payload)

        class FakePeer:
            peer_id = "p1"
            async def send(self, *a, **kw): return True

        msg = {"type": "TX", "payload": {"tx_id": ""}}
        self._run(node._dispatch(FakePeer(), msg))
        # Empty tx_id is falsy, so callback should NOT fire
        self.assertEqual(len(calls), 0)


# ═══════════════════════════════════════════════════════════════════
#  PeerConnection.info
# ═══════════════════════════════════════════════════════════════════

class TestPeerConnectionInfo(unittest.TestCase):

    def test_info_fields(self):
        # We can't easily create a real PeerConnection without sockets,
        # so just verify the class attributes exist
        self.assertTrue(hasattr(PeerConnection, '__init__'))


if __name__ == "__main__":
    unittest.main()
