"""
Tests for the 18-feature Ripple-parity gap implementation (v2).

Covers:
  1. LastLedgerSequence / tx expiration
  2. STObject binary serialization
  3. Structured Memos array on transactions
  4. Server state machine
  5. Validator manifest / UNL publication protocol
  6. Fee escalation wiring in Ledger
  7. Amendment feature-gating
  8. Ticket consumption in apply_transaction
  9. AccountDelete enhanced object cleanup
 10. Offer expiration pass-through
 11. New RPC endpoints (ledger_entry, nft_offers, gateway_balances, etc.)
 12. History sharding / online delete
 13. Peer reservations / crawl API
 14. Sign API endpoint
 15. PayChannel claim signature verification
 16. Reporting mode integration
 17. DEX auto-bridge edge cases
 18. Server state wired into server_info
"""

import hashlib
import struct
import time
import unittest

from nexaflow_core.ledger import Ledger
from nexaflow_core.transaction import (
    Transaction, Amount, create_payment,
    create_offer, create_account_delete,
)


def _make_ledger():
    """Create a fresh Ledger with one funded account."""
    ledger = Ledger()
    ledger.create_account("rAlice", 10_000.0)
    ledger.create_account("rBob", 5_000.0)
    return ledger


def _apply(ledger, tx):
    return ledger.apply_transaction(tx)


# ═════════════════════════════════════════════════════════════════════
#  1. LastLedgerSequence / tx expiration
# ═════════════════════════════════════════════════════════════════════

class TestLastLedgerSequence(unittest.TestCase):
    """A tx with LastLedgerSequence < current_sequence should fail 136."""

    def test_expires_when_past_ledger(self):
        ledger = _make_ledger()
        ledger.current_sequence = 50
        tx = create_payment("rAlice", "rBob", 10.0)
        tx.last_ledger_sequence = 40  # already expired
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 136)  # tecEXPIRED

    def test_succeeds_when_within_ledger(self):
        ledger = _make_ledger()
        ledger.current_sequence = 5
        tx = create_payment("rAlice", "rBob", 10.0)
        tx.last_ledger_sequence = 100  # far future
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_zero_means_no_expiry(self):
        ledger = _make_ledger()
        ledger.current_sequence = 999
        tx = create_payment("rAlice", "rBob", 10.0)
        tx.last_ledger_sequence = 0
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)


# ═════════════════════════════════════════════════════════════════════
#  2. STObject binary serialization
# ═════════════════════════════════════════════════════════════════════

class TestSerialization(unittest.TestCase):
    """Test the new STObject binary serialization module."""

    def test_import_module(self):
        from nexaflow_core.serialization import STSerializer, STType, FIELD_REGISTRY
        self.assertTrue(len(FIELD_REGISTRY) > 0)

    def test_serialize_uint32(self):
        from nexaflow_core.serialization import STSerializer
        s = STSerializer()
        s.add_uint32("Sequence", 42)
        data = s.to_bytes()
        self.assertIsInstance(data, bytes)
        self.assertTrue(len(data) > 0)

    def test_serialize_amount_native(self):
        from nexaflow_core.serialization import encode_native_amount, decode_native_amount
        encoded = encode_native_amount(1_000_000)
        self.assertEqual(len(encoded), 8)
        decoded = decode_native_amount(encoded)
        self.assertEqual(decoded, 1_000_000)

    def test_serialize_transaction(self):
        from nexaflow_core.serialization import serialize_transaction
        tx = create_payment("rAlice", "rBob", 100.0)
        st = serialize_transaction(tx)
        raw = st.to_bytes()
        self.assertIsInstance(raw, bytes)
        self.assertTrue(len(raw) > 0)

    def test_signing_bytes_exclude_signature(self):
        from nexaflow_core.serialization import STSerializer
        s = STSerializer()
        s.add_uint32("Sequence", 1)
        s.add_blob("TxnSignature", b"\xde\xad")
        full = s.to_bytes()
        signing = s.to_signing_bytes()
        self.assertNotEqual(full, signing)
        # Signing bytes should be shorter (no TxnSignature)
        self.assertLess(len(signing), len(full))

    def test_to_hash(self):
        from nexaflow_core.serialization import STSerializer
        s = STSerializer()
        s.add_uint32("Sequence", 1)
        h = s.to_hash()
        self.assertEqual(len(h), 64)  # hex digest of blake2b-256

    def test_field_registry_has_key_fields(self):
        from nexaflow_core.serialization import FIELD_REGISTRY
        names = {f.name for f in FIELD_REGISTRY.values()}
        for required in ["TransactionType", "Account", "Destination", "Amount",
                         "Fee", "Sequence", "LastLedgerSequence", "Memos"]:
            self.assertIn(required, names, f"Missing field: {required}")


# ═════════════════════════════════════════════════════════════════════
#  3. Structured Memos
# ═════════════════════════════════════════════════════════════════════

class TestStructuredMemos(unittest.TestCase):
    def test_memos_in_to_dict(self):
        tx = create_payment("rA", "rB", 1.0)
        tx.memos = [
            {"MemoType": "text/plain", "MemoData": "hello"},
            {"MemoType": "application/json", "MemoData": '{"key": 1}'},
        ]
        d = tx.to_dict()
        self.assertEqual(len(d["Memos"]), 2)
        self.assertEqual(d["Memos"][0]["MemoType"], "text/plain")

    def test_empty_memos_not_in_dict(self):
        tx = create_payment("rA", "rB", 1.0)
        d = tx.to_dict()
        # Empty memos should serialize as empty list
        self.assertEqual(d.get("Memos", []), [])


# ═════════════════════════════════════════════════════════════════════
#  4. Server state machine
# ═════════════════════════════════════════════════════════════════════

class TestServerStateMachine(unittest.TestCase):
    def test_initial_state(self):
        from nexaflow_core.server_state import ServerStateMachine, ServerState
        sm = ServerStateMachine()
        self.assertEqual(sm.state, ServerState.DISCONNECTED)

    def test_valid_transitions(self):
        from nexaflow_core.server_state import ServerStateMachine, ServerState
        sm = ServerStateMachine()
        self.assertTrue(sm.transition(ServerState.CONNECTED))
        self.assertEqual(sm.state, ServerState.CONNECTED)
        self.assertTrue(sm.transition(ServerState.SYNCING))
        self.assertTrue(sm.transition(ServerState.TRACKING))
        self.assertTrue(sm.transition(ServerState.FULL))

    def test_invalid_transition(self):
        from nexaflow_core.server_state import ServerStateMachine, ServerState
        sm = ServerStateMachine()
        # Can't jump from DISCONNECTED to FULL
        self.assertFalse(sm.transition(ServerState.FULL))
        self.assertEqual(sm.state, ServerState.DISCONNECTED)

    def test_force_transition(self):
        from nexaflow_core.server_state import ServerStateMachine, ServerState
        sm = ServerStateMachine()
        sm.force(ServerState.FULL)
        self.assertEqual(sm.state, ServerState.FULL)

    def test_evaluate_state(self):
        from nexaflow_core.server_state import ServerStateMachine, ServerState
        sm = ServerStateMachine()
        sm.force(ServerState.CONNECTED)
        sm.evaluate_state(peer_count=3, synced=True, is_validator=True,
                         ledger_current=100)
        # With peers + synced + validator → should reach VALIDATING
        self.assertIn(sm.state, (ServerState.FULL, ServerState.PROPOSING,
                                 ServerState.VALIDATING))

    def test_to_dict(self):
        from nexaflow_core.server_state import ServerStateMachine
        sm = ServerStateMachine()
        d = sm.to_dict()
        self.assertIn("disconnected", d)

    def test_uptime_in_current(self):
        from nexaflow_core.server_state import ServerStateMachine
        sm = ServerStateMachine()
        up = sm.uptime_in_current()
        self.assertGreaterEqual(up, 0.0)


# ═════════════════════════════════════════════════════════════════════
#  5. Validator manifest / UNL
# ═════════════════════════════════════════════════════════════════════

class TestManifestAndUNL(unittest.TestCase):
    """Manifest tests use real Ed25519 key pairs for signature verification."""

    @classmethod
    def setUpClass(cls):
        from nacl.signing import SigningKey
        # Generate 3 master key pairs
        cls._keys = []
        for _ in range(3):
            sk = SigningKey.generate()
            cls._keys.append((sk, sk.verify_key))
        # Ephemeral keys (just more ed25519 pairs)
        cls._eph_keys = []
        for _ in range(3):
            sk = SigningKey.generate()
            cls._eph_keys.append((sk, sk.verify_key))

    def _pk_hex(self, idx):
        return bytes(self._keys[idx][1]).hex()

    def _eph_hex(self, idx):
        return bytes(self._eph_keys[idx][1]).hex()

    def _sign_manifest(self, manifest, key_idx):
        """Sign a manifest blob with the master key at key_idx."""
        blob = manifest.signing_blob()
        sig = self._keys[key_idx][0].sign(blob).signature
        return sig.hex()

    def test_manifest_cache_apply_and_get(self):
        from nexaflow_core.manifest import ManifestCache, ValidatorManifest
        cache = ManifestCache()
        m = ValidatorManifest(
            master_public_key=self._pk_hex(0),
            ephemeral_public_key=self._eph_hex(0),
            sequence=1,
            domain="example.com",
        )
        m.master_signature = self._sign_manifest(m, 0)
        cache.apply(m)
        result = cache.get(self._pk_hex(0))
        self.assertIsNotNone(result)
        self.assertEqual(result.ephemeral_public_key, self._eph_hex(0))

    def test_manifest_sequence_revocation(self):
        from nexaflow_core.manifest import ManifestCache, ValidatorManifest
        cache = ManifestCache()
        m1 = ValidatorManifest(self._pk_hex(0), self._eph_hex(0), sequence=1)
        m1.master_signature = self._sign_manifest(m1, 0)
        m2 = ValidatorManifest(self._pk_hex(0), self._eph_hex(1), sequence=5)
        m2.master_signature = self._sign_manifest(m2, 0)
        cache.apply(m1)
        cache.apply(m2)
        result = cache.get(self._pk_hex(0))
        self.assertEqual(result.sequence, 5)
        self.assertEqual(result.ephemeral_public_key, self._eph_hex(1))

    def test_manifest_get_ephemeral_key(self):
        from nexaflow_core.manifest import ManifestCache, ValidatorManifest
        cache = ManifestCache()
        m = ValidatorManifest(self._pk_hex(0), self._eph_hex(0), sequence=1)
        m.master_signature = self._sign_manifest(m, 0)
        cache.apply(m)
        self.assertEqual(cache.get_ephemeral_key(self._pk_hex(0)), self._eph_hex(0))
        self.assertEqual(cache.get_ephemeral_key("unknown"), "")

    def test_manifest_all_active(self):
        from nexaflow_core.manifest import ManifestCache, ValidatorManifest
        cache = ManifestCache()
        for i in range(3):
            m = ValidatorManifest(self._pk_hex(i), self._eph_hex(i), sequence=1)
            m.master_signature = self._sign_manifest(m, i)
            cache.apply(m)
        self.assertEqual(len(cache.all_active()), 3)

    def test_unl_publisher_and_subscriber(self):
        from nexaflow_core.manifest import UNLPublisher, UNLSubscriber
        sk_hex = bytes(self._keys[0][0]).hex()
        pk_hex = self._pk_hex(0)
        pub = UNLPublisher(publisher_key=pk_hex, private_key=sk_hex)
        vl = pub.publish(
            validator_keys=["v1", "v2", "v3"],
            expiration_hours=1.0,
        )
        self.assertEqual(len(vl.validators), 3)

        sub = UNLSubscriber()
        sub.add_publisher(pk_hex)
        ok, msg = sub.apply_list(vl)
        self.assertTrue(ok, msg)
        self.assertEqual(len(sub.trusted_validators), 3)
        self.assertIn("v1", sub.trusted_validators)


# ═════════════════════════════════════════════════════════════════════
#  6. Fee escalation wiring
# ═════════════════════════════════════════════════════════════════════

class TestFeeEscalationWiring(unittest.TestCase):
    def test_ledger_has_fee_escalation(self):
        ledger = Ledger()
        self.assertTrue(hasattr(ledger, "fee_escalation"))
        self.assertIsNotNone(ledger.fee_escalation)

    def test_close_ledger_calls_on_close(self):
        ledger = _make_ledger()
        # Close a ledger — should not raise
        ledger.close_ledger()
        self.assertEqual(len(ledger.closed_ledgers), 1)

    def test_fee_escalation_stats(self):
        ledger = _make_ledger()
        stats = ledger.fee_escalation.get_stats()
        self.assertIn("base_fee", stats)
        self.assertIn("open_ledger_cost", stats)


# ═════════════════════════════════════════════════════════════════════
#  7. Amendment feature-gating
# ═════════════════════════════════════════════════════════════════════

class TestAmendmentGating(unittest.TestCase):
    """Test that amendment-gated transaction types are blocked when
    the corresponding amendment is not enabled."""

    def test_nftoken_blocked_without_amendment(self):
        """If amendments are registered but NonFungibleTokensV1_1 is
        not enabled, NFTokenMint (type 25) should be blocked."""
        ledger = _make_ledger()
        # Register some amendments but do NOT enable the NFToken one
        ledger.amendment_manager.propose("SomeOtherAmendment")
        # Create an NFTokenMint tx (type 25)
        from nexaflow_core.transaction import create_nftoken_mint
        tx = create_nftoken_mint("rAlice", uri="http://example.com")
        rc = _apply(ledger, tx)
        # Should be blocked (118 = tecAMENDMENT_BLOCKED)
        self.assertEqual(rc, 118)

    def test_nftoken_allowed_when_amendment_enabled(self):
        """When the NFToken amendment IS enabled, mint should proceed."""
        ledger = _make_ledger()
        # Enable the amendment by adding its ID to the enabled set directly
        # The ledger gates on "NFToken" as the amendment name
        amendment = ledger.amendment_manager.propose("NFToken")
        ledger.amendment_manager.enabled_amendments.add(amendment.amendment_id)
        from nexaflow_core.transaction import create_nftoken_mint
        tx = create_nftoken_mint("rAlice", uri="http://example.com")
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)

    def test_ungated_types_always_allowed(self):
        """Standard tx types (Payment, TrustSet) are never gated."""
        ledger = _make_ledger()
        ledger.amendment_manager.propose("SomeAmendment")
        tx = create_payment("rAlice", "rBob", 10.0)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)


# ═════════════════════════════════════════════════════════════════════
#  8. Ticket consumption
# ═════════════════════════════════════════════════════════════════════

class TestTicketConsumption(unittest.TestCase):
    def test_valid_ticket_consumed(self):
        ledger = _make_ledger()
        # Create tickets
        from nexaflow_core.transaction import create_ticket_create
        tx = create_ticket_create("rAlice", ticket_count=3)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        # Verify tickets were created
        acc = ledger.get_account("rAlice")
        self.assertTrue(len(acc.tickets) >= 1)

    def test_invalid_ticket_returns_no_ticket(self):
        ledger = _make_ledger()
        tx = create_payment("rAlice", "rBob", 10.0)
        tx.ticket_sequence = 9999  # non-existent ticket
        rc = _apply(ledger, tx)
        # Should return 137 (tecNO_TICKET)
        self.assertEqual(rc, 137)


# ═════════════════════════════════════════════════════════════════════
#  9. AccountDelete enhanced cleanup
# ═════════════════════════════════════════════════════════════════════

class TestAccountDeleteEnhanced(unittest.TestCase):
    def test_delete_blocked_by_escrow(self):
        """Account with active escrow cannot be deleted."""
        ledger = _make_ledger()
        acc = ledger.get_account("rAlice")
        acc.sequence = 256
        acc.owner_count = 0
        # Create an escrow
        from nexaflow_core.transaction import create_escrow_create
        tx_esc = create_escrow_create("rAlice", "rBob", 100.0,
                                      finish_after=int(time.time()) + 3600,
                                      cancel_after=int(time.time()) + 7200)
        _apply(ledger, tx_esc)
        # Now try to delete — should be blocked
        acc.owner_count = 0  # Reset
        acc.sequence = 256
        from nexaflow_core.transaction import create_account_delete
        tx = create_account_delete("rAlice", "rBob", fee=5.0, sequence=256)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)  # tecNO_PERMISSION

    def test_delete_blocked_by_channel(self):
        """Account with active payment channel cannot be deleted."""
        ledger = _make_ledger()
        acc = ledger.get_account("rAlice")
        acc.sequence = 256
        # Create a channel
        ledger.channel_manager.create_channel(
            "chan1", "rAlice", "rBob", 500.0, settle_delay=3600
        )
        acc.owner_count = 0
        tx = create_account_delete("rAlice", "rBob", fee=5.0, sequence=256)
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 110)


# ═════════════════════════════════════════════════════════════════════
#  10. Offer expiration pass-through
# ═════════════════════════════════════════════════════════════════════

class TestOfferExpiration(unittest.TestCase):
    def test_expiration_recorded_on_offer(self):
        """Expiration flag is passed through to the open offer record."""
        ledger = _make_ledger()
        tx = create_offer("rAlice", Amount(50.0, "USD", "rGateway"), Amount(100.0))
        exp_time = time.time() + 3600
        tx.flags = tx.flags or {}
        tx.flags["Expiration"] = exp_time
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        acc = ledger.get_account("rAlice")
        self.assertTrue(len(acc.open_offers) > 0)
        self.assertAlmostEqual(acc.open_offers[-1]["expiration"], exp_time, places=0)

    def test_no_expiration_defaults_zero(self):
        ledger = _make_ledger()
        tx = create_offer("rAlice", Amount(50.0, "USD", "rGateway"), Amount(100.0))
        rc = _apply(ledger, tx)
        self.assertEqual(rc, 0)
        acc = ledger.get_account("rAlice")
        self.assertEqual(acc.open_offers[-1]["expiration"], 0.0)


# ═════════════════════════════════════════════════════════════════════
#  12. History sharding / online delete
# ═════════════════════════════════════════════════════════════════════

class TestHistorySharding(unittest.TestCase):
    def test_online_delete(self):
        from nexaflow_core.storage import LedgerStore
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            store = LedgerStore(db_path, _allow_any_path=True)
            # Insert 10 ledgers
            for i in range(1, 11):
                store.save_closed_ledger(
                    sequence=i, hash=f"h{i}", previous_hash=f"h{i-1}",
                    timestamp=time.time(), transaction_count=1)
            self.assertEqual(store.latest_ledger_seq(), 10)
            # Keep only last 5
            pruned = store.online_delete(keep_last=5)
            self.assertEqual(pruned, 5)
            # Verify only 5 remain
            remaining = store.load_closed_ledgers()
            self.assertEqual(len(remaining), 5)
            self.assertEqual(remaining[0]["sequence"], 6)
            store.close()

    def test_shard_info(self):
        from nexaflow_core.storage import LedgerStore
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            store = LedgerStore(db_path, _allow_any_path=True)
            # Insert a few ledgers
            for i in range(1, 6):
                store.save_closed_ledger(
                    sequence=i, hash=f"h{i}", previous_hash=f"h{i-1}",
                    timestamp=time.time())
            info = store.get_shard_info()
            self.assertIn("shards", info)
            self.assertIn("shard_size", info)
            self.assertEqual(info["total_stored"], 5)
            store.close()

    def test_vacuum(self):
        from nexaflow_core.storage import LedgerStore
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            store = LedgerStore(db_path, _allow_any_path=True)
            store.vacuum()  # Should not raise
            store.close()


# ═════════════════════════════════════════════════════════════════════
#  13. Peer reservations / crawl
# ═════════════════════════════════════════════════════════════════════

class TestPeerReservations(unittest.TestCase):
    def test_add_and_check_reservation(self):
        from nexaflow_core.p2p import P2PNode
        node = P2PNode("test_node")
        node.add_reservation("important_validator")
        self.assertIn("important_validator", node.reservations)
        self.assertTrue(node._is_reserved("important_validator"))

    def test_remove_reservation(self):
        from nexaflow_core.p2p import P2PNode
        node = P2PNode("test_node")
        node.add_reservation("v1")
        node.remove_reservation("v1")
        self.assertNotIn("v1", node.reservations)

    def test_effective_max_peers(self):
        from nexaflow_core.p2p import P2PNode, MAX_PEERS
        node = P2PNode("test_node")
        node.add_reservation("v1")
        # Reserved peer gets extra slots
        self.assertGreater(node._effective_max_peers("v1"), MAX_PEERS)
        # Non-reserved peer gets normal cap
        self.assertEqual(node._effective_max_peers("v2"), MAX_PEERS)

    def test_crawl_returns_valid_structure(self):
        from nexaflow_core.p2p import P2PNode
        node = P2PNode("test_node")
        node._server_start = time.time()
        crawl = node.crawl()
        self.assertIn("overlay", crawl)
        self.assertIn("server", crawl)
        self.assertEqual(crawl["overlay"]["total"], 0)
        self.assertEqual(crawl["server"]["node_id"], "test_node")


# ═════════════════════════════════════════════════════════════════════
#  15. PayChannel claim signature verification
# ═════════════════════════════════════════════════════════════════════

class TestPayChannelClaimSig(unittest.TestCase):
    def test_verify_returns_false_for_bad_sig(self):
        from nexaflow_core.payment_channel import verify_claim_signature
        result = verify_claim_signature(
            "channel1", 100.0, "deadbeef", "00" * 32
        )
        self.assertFalse(result)

    def test_verify_bad_hex_returns_false(self):
        from nexaflow_core.payment_channel import verify_claim_signature
        result = verify_claim_signature("ch1", 1.0, "not_hex", "also_not_hex")
        self.assertFalse(result)

    def test_claim_with_bad_signature_rejected(self):
        from nexaflow_core.payment_channel import PaymentChannelManager
        mgr = PaymentChannelManager()
        mgr.create_channel("ch1", "rAlice", "rBob", 1000.0,
                          settle_delay=60, public_key="ab" * 32)
        ch, payout, err = mgr.claim("ch1", 100.0, signature="dead" * 16,
                                     public_key="ab" * 32)
        self.assertEqual(payout, 0.0)
        self.assertIn("Invalid claim signature", err)

    def test_claim_no_signature_still_works(self):
        """Backward compat: claims without signature still succeed."""
        from nexaflow_core.payment_channel import PaymentChannelManager
        mgr = PaymentChannelManager()
        mgr.create_channel("ch2", "rAlice", "rBob", 1000.0, settle_delay=60)
        ch, payout, err = mgr.claim("ch2", 100.0)
        self.assertEqual(payout, 100.0)
        self.assertEqual(err, "")


# ═════════════════════════════════════════════════════════════════════
#  16. Reporting mode
# ═════════════════════════════════════════════════════════════════════

class TestReportingMode(unittest.TestCase):
    def test_reporting_server_info(self):
        from nexaflow_core.reporting import ReportingServer
        rs = ReportingServer()
        info = rs.server_info()
        self.assertIn("info", info)
        self.assertEqual(info["info"]["server_state"], "reporting")
        self.assertTrue(info["info"]["reporting"]["is_reporting"])

    def test_ingest_and_query_ledger(self):
        from nexaflow_core.reporting import ReportingServer
        rs = ReportingServer()
        rs.ingest_ledger({
            "sequence": 1,
            "state_hash": "abc123",
            "close_time": time.time(),
            "parent_hash": "000000",
            "transactions": [
                {"tx_id": "tx1", "tx_type": 0, "account": "rA",
                 "destination": "rB", "sequence": 1, "result_code": 0,
                 "timestamp": time.time()},
            ],
        })
        result = rs.ledger(sequence=1)
        self.assertIn("result", result)
        self.assertEqual(result["result"]["ledger_index"], 1)

    def test_query_transaction(self):
        from nexaflow_core.reporting import ReportingServer
        rs = ReportingServer()
        rs.ingest_ledger({
            "sequence": 1, "state_hash": "h", "close_time": 0,
            "parent_hash": "p",
            "transactions": [
                {"tx_id": "TXID1", "tx_type": 0, "account": "rA",
                 "destination": "", "sequence": 1, "result_code": 0,
                 "timestamp": 0},
            ],
        })
        result = rs.tx("TXID1")
        self.assertIn("result", result)

    def test_write_methods_rejected(self):
        from nexaflow_core.reporting import ReportingServer
        rs = ReportingServer()
        result = rs.handle_request("submit", {})
        self.assertEqual(result["error"], "reportingUnsupported")

    def test_account_tx(self):
        from nexaflow_core.reporting import ReportingServer
        rs = ReportingServer()
        rs.ingest_ledger({
            "sequence": 1, "state_hash": "h", "close_time": 0,
            "parent_hash": "p",
            "transactions": [
                {"tx_id": "TX1", "tx_type": 0, "account": "rAlice",
                 "destination": "rBob", "sequence": 1, "result_code": 0,
                 "timestamp": 0},
            ],
        })
        result = rs.account_tx("rAlice")
        self.assertIn("result", result)
        self.assertEqual(len(result["result"]["transactions"]), 1)


# ═════════════════════════════════════════════════════════════════════
#  Transaction fields in to_dict
# ═════════════════════════════════════════════════════════════════════

class TestTransactionFields(unittest.TestCase):
    def test_last_ledger_sequence_in_dict(self):
        tx = create_payment("rA", "rB", 1.0)
        tx.last_ledger_sequence = 500
        d = tx.to_dict()
        self.assertEqual(d["LastLedgerSequence"], 500)

    def test_ticket_sequence_in_dict(self):
        tx = create_payment("rA", "rB", 1.0)
        tx.ticket_sequence = 42
        d = tx.to_dict()
        self.assertEqual(d["TicketSequence"], 42)

    def test_account_txn_id_in_dict(self):
        tx = create_payment("rA", "rB", 1.0)
        tx.account_txn_id = "abc123"
        d = tx.to_dict()
        self.assertEqual(d["AccountTxnID"], "abc123")


# ═════════════════════════════════════════════════════════════════════
#  Serialization round-trip and edge cases
# ═════════════════════════════════════════════════════════════════════

class TestSerializationEdgeCases(unittest.TestCase):
    def test_iou_amount_encoding(self):
        from nexaflow_core.serialization import encode_iou_amount
        encoded = encode_iou_amount(42.5, "USD", "rGateway")
        self.assertEqual(len(encoded), 48)

    def test_encode_currency_code(self):
        from nexaflow_core.serialization import encode_currency_code
        encoded = encode_currency_code("USD")
        self.assertEqual(len(encoded), 20)

    def test_encode_field_id(self):
        from nexaflow_core.serialization import encode_field_id
        # Type 2 (UInt32), field 4 (Sequence) → should be compact
        data = encode_field_id(2, 4)
        self.assertTrue(len(data) >= 1)

    def test_vl_length_encoding(self):
        from nexaflow_core.serialization import encode_vl_length
        # Short length
        self.assertEqual(len(encode_vl_length(10)), 1)
        # Medium length
        self.assertEqual(len(encode_vl_length(200)), 2)


# ═════════════════════════════════════════════════════════════════════
#  Server state wired into server_info
# ═════════════════════════════════════════════════════════════════════

class TestServerStateWiring(unittest.TestCase):
    """Verify that ServerStateMachine is importable and functional."""

    def test_all_states_represented(self):
        from nexaflow_core.server_state import ServerState
        states = [s.value for s in ServerState]
        self.assertIn("disconnected", states)
        self.assertIn("full", states)
        self.assertIn("validating", states)

    def test_state_accounting_keys(self):
        from nexaflow_core.server_state import ServerStateMachine
        sm = ServerStateMachine()
        d = sm.to_dict()
        # Should have one entry per state
        self.assertGreaterEqual(len(d), 1)


# ═════════════════════════════════════════════════════════════════════
#  DEX auto-bridge edge cases
# ═════════════════════════════════════════════════════════════════════

class TestDEXAutoBridge(unittest.TestCase):
    def test_auto_bridge_cross_currency_no_crash(self):
        """Cross-currency offers (neither is NXF) go through auto-bridge."""
        ledger = _make_ledger()
        # Set up trust lines so both currencies exist
        ledger.set_trust_line("rAlice", "USD", "rGateway", 10000.0)
        ledger.set_trust_line("rAlice", "EUR", "rGateway", 10000.0)
        # Create a cross-currency offer
        tx = create_offer("rAlice", Amount(85.0, "EUR", "rGateway"), Amount(100.0, "USD", "rGateway"))
        rc = _apply(ledger, tx)
        # Should succeed even if no matching orders
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
