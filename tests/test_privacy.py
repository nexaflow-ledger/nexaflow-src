"""
Test suite for nexaflow_core.privacy — Confidential transaction primitives.

Covers:
  - PedersenCommitment: commit, verify, homomorphic addition, deterministic
  - StealthAddress: generate, scan_output (hit/miss), recover_spend_key,
                    view_tag fast-scan, cross-wallet isolation
  - KeyImage: generation, determinism, uniqueness per key, length
  - RangeProof: prove, verify, negative value rejection
  - RingSignature / verify_ring_signature: sign/verify (n=1,3,5), all
    signer positions, tamper detection, key-image linkability, wrong message
  - create_confidential_payment: full TX field population, ring sig validity,
    key image consistency, distinct outputs per call
  - Integration: ledger apply + double-spend prevention, validator checks,
    wallet.sign_confidential_payment + scan_confidential_outputs round-trip
"""

import os
import unittest

# Enable confidential transactions for testing
os.environ.setdefault("NEXAFLOW_ALLOW_CONFIDENTIAL", "1")

from nexaflow_core.crypto_utils import derive_address, generate_keypair
from nexaflow_core.ledger import Ledger
from nexaflow_core.privacy import (
    KeyImage,
    PedersenCommitment,
    RangeProof,
    RingSignature,
    StealthAddress,
    create_confidential_payment,
    verify_ring_signature,
)
from nexaflow_core.validator import TransactionValidator
from nexaflow_core.wallet import Wallet

# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def _keypair():
    """Return (priv_bytes, pub_bytes) — 32-byte + 65-byte."""
    return generate_keypair()


# ===================================================================
#  PedersenCommitment
# ===================================================================

class TestPedersenCommitment(unittest.TestCase):

    def test_commit_returns_object(self):
        c = PedersenCommitment.commit(10.0)
        self.assertIsInstance(c, PedersenCommitment)

    def test_commitment_is_65_bytes(self):
        c = PedersenCommitment.commit(1.0)
        self.assertEqual(len(c.commitment), 65)
        self.assertEqual(c.commitment[0], 0x04)  # uncompressed point prefix

    def test_blinding_is_32_bytes(self):
        c = PedersenCommitment.commit(5.0)
        self.assertEqual(len(c.blinding), 32)

    def test_verify_correct_value(self):
        c = PedersenCommitment.commit(42.5)
        self.assertTrue(c.verify(42.5))

    def test_verify_wrong_value(self):
        c = PedersenCommitment.commit(42.5)
        self.assertFalse(c.verify(42.6))
        self.assertFalse(c.verify(0.0))

    def test_deterministic_with_explicit_blinding(self):
        blinding = b"\xab" * 32
        c1 = PedersenCommitment.commit(7.0, blinding)
        c2 = PedersenCommitment.commit(7.0, blinding)
        self.assertEqual(c1.commitment, c2.commitment)

    def test_random_blinding_produces_distinct_commitments(self):
        c1 = PedersenCommitment.commit(7.0)
        c2 = PedersenCommitment.commit(7.0)
        # Negligible collision probability
        self.assertNotEqual(c1.commitment, c2.commitment)

    def test_zero_value(self):
        c = PedersenCommitment.commit(0.0)
        self.assertTrue(c.verify(0.0))
        self.assertFalse(c.verify(1.0))

    def test_large_value(self):
        c = PedersenCommitment.commit(999_999.999999)
        self.assertTrue(c.verify(999_999.999999))

    def test_homomorphic_add(self):
        c1 = PedersenCommitment.commit(3.0)
        c2 = PedersenCommitment.commit(7.0)
        c_sum = c1.add(c2)
        self.assertTrue(c_sum.verify(10.0))

    def test_homomorphic_add_three(self):
        c1 = PedersenCommitment.commit(1.0)
        c2 = PedersenCommitment.commit(2.0)
        c3 = PedersenCommitment.commit(3.0)
        c_total = c1.add(c2).add(c3)
        self.assertTrue(c_total.verify(6.0))

    def test_homomorphic_add_wrong_total(self):
        c1 = PedersenCommitment.commit(3.0)
        c2 = PedersenCommitment.commit(7.0)
        self.assertFalse(c1.add(c2).verify(11.0))

    def test_commitment_bytes_differ_for_different_values(self):
        b = b"\x11" * 32
        c1 = PedersenCommitment.commit(1.0, b)
        c2 = PedersenCommitment.commit(2.0, b)
        self.assertNotEqual(c1.commitment, c2.commitment)


# ===================================================================
#  StealthAddress
# ===================================================================

class TestStealthAddress(unittest.TestCase):

    def setUp(self):
        self.v_priv, self.v_pub   = _keypair()   # view keypair
        self.sp_priv, self.sp_pub = _keypair()   # spend keypair

    def test_generate_returns_tuple(self):
        result = StealthAddress.generate(self.v_pub, self.sp_pub)
        self.assertEqual(len(result), 2)

    def test_address_is_bytes(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        self.assertIsInstance(stealth.address, bytes)

    def test_address_starts_with_r(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        self.assertTrue(stealth.address.startswith(b"r"))

    def test_ephemeral_pub_is_65_bytes(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        self.assertEqual(len(stealth.ephemeral_pub), 65)

    def test_view_tag_is_1_byte(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        self.assertEqual(len(stealth.view_tag), 1)

    def test_scan_output_matches(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        matched = StealthAddress.scan_output(
            self.v_priv, self.sp_pub, stealth.ephemeral_pub, stealth.view_tag
        )
        self.assertEqual(matched, stealth.address.decode())

    def test_scan_output_wrong_view_key(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        other_v_priv, _ = _keypair()
        matched = StealthAddress.scan_output(
            other_v_priv, self.sp_pub, stealth.ephemeral_pub, stealth.view_tag
        )
        # View tag will not match → None
        self.assertIsNone(matched)

    def test_scan_output_wrong_spend_key(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        _, other_sp_pub = _keypair()
        matched = StealthAddress.scan_output(
            self.v_priv, other_sp_pub, stealth.ephemeral_pub, stealth.view_tag
        )
        # View tag may match, but derived address differs
        if matched is not None:
            self.assertNotEqual(matched, stealth.address.decode())

    def test_distinct_outputs_per_call(self):
        s1, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        s2, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        self.assertNotEqual(s1.address, s2.address)
        self.assertNotEqual(s1.ephemeral_pub, s2.ephemeral_pub)

    def test_recover_spend_key_is_32_bytes(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        key = StealthAddress.recover_spend_key(
            self.v_priv, self.sp_priv, stealth.ephemeral_pub
        )
        self.assertEqual(len(key), 32)

    def test_recover_spend_key_deterministic(self):
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        k1 = StealthAddress.recover_spend_key(self.v_priv, self.sp_priv, stealth.ephemeral_pub)
        k2 = StealthAddress.recover_spend_key(self.v_priv, self.sp_priv, stealth.ephemeral_pub)
        self.assertEqual(k1, k2)

    def test_recover_spend_key_different_outputs(self):
        s1, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        s2, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        k1 = StealthAddress.recover_spend_key(self.v_priv, self.sp_priv, s1.ephemeral_pub)
        k2 = StealthAddress.recover_spend_key(self.v_priv, self.sp_priv, s2.ephemeral_pub)
        self.assertNotEqual(k1, k2)

    def test_cross_wallet_isolation(self):
        """Output generated for wallet A is not scanned by wallet B."""
        v2_priv, _v2_pub = _keypair()
        _sp2_priv, sp2_pub = _keypair()
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        matched = StealthAddress.scan_output(
            v2_priv, sp2_pub, stealth.ephemeral_pub, stealth.view_tag
        )
        self.assertIsNone(matched)

    def test_scan_without_view_tag_still_works(self):
        """Passing empty view_tag disables fast-scan but still works."""
        stealth, _ = StealthAddress.generate(self.v_pub, self.sp_pub)
        matched = StealthAddress.scan_output(
            self.v_priv, self.sp_pub, stealth.ephemeral_pub, b""
        )
        self.assertEqual(matched, stealth.address.decode())


# ===================================================================
#  KeyImage
# ===================================================================

class TestKeyImage(unittest.TestCase):

    def test_image_is_65_bytes(self):
        priv, pub = _keypair()
        ki = KeyImage.generate(priv, pub)
        self.assertEqual(len(ki.image), 65)

    def test_image_uncompressed_prefix(self):
        priv, pub = _keypair()
        ki = KeyImage.generate(priv, pub)
        self.assertEqual(ki.image[0], 0x04)

    def test_deterministic(self):
        priv, pub = _keypair()
        ki1 = KeyImage.generate(priv, pub)
        ki2 = KeyImage.generate(priv, pub)
        self.assertEqual(ki1.image, ki2.image)

    def test_different_keys_produce_different_images(self):
        p1, pub1 = _keypair()
        p2, pub2 = _keypair()
        ki1 = KeyImage.generate(p1, pub1)
        ki2 = KeyImage.generate(p2, pub2)
        self.assertNotEqual(ki1.image, ki2.image)

    def test_image_not_equal_to_public_key(self):
        priv, pub = _keypair()
        ki = KeyImage.generate(priv, pub)
        self.assertNotEqual(ki.image, pub)


# ===================================================================
#  RangeProof
# ===================================================================

class TestRangeProof(unittest.TestCase):

    def _blinding(self):
        import os
        return os.urandom(32)

    def test_prove_returns_object(self):
        rp = RangeProof.prove(1_000_000, self._blinding())
        self.assertIsInstance(rp, RangeProof)

    def test_proof_is_32_bytes(self):
        rp = RangeProof.prove(500_000, self._blinding())
        self.assertEqual(len(rp.proof), 32)

    def test_verify_valid_proof(self):
        blinding = self._blinding()
        c = PedersenCommitment.commit(0.5, blinding)
        rp = RangeProof.prove(500_000, blinding, c.commitment)
        self.assertTrue(rp.verify(c.commitment))

    def test_verify_zero_value(self):
        blinding = self._blinding()
        c = PedersenCommitment.commit(0.0, blinding)
        rp = RangeProof.prove(0, blinding, c.commitment)
        self.assertTrue(rp.verify(c.commitment))

    def test_negative_value_raises(self):
        with self.assertRaises((ValueError, OverflowError)):
            RangeProof.prove(-1, self._blinding())

    def test_deterministic_proof(self):
        blinding = self._blinding()
        rp1 = RangeProof.prove(100, blinding)
        rp2 = RangeProof.prove(100, blinding)
        self.assertEqual(rp1.proof, rp2.proof)

    def test_different_blindings_produce_different_proofs(self):
        rp1 = RangeProof.prove(100, self._blinding())
        rp2 = RangeProof.prove(100, self._blinding())
        self.assertNotEqual(rp1.proof, rp2.proof)

    def test_zero_proof_rejected(self):
        rp = RangeProof(b"\x00" * 32)
        self.assertFalse(rp.verify(b"\x04" + b"\x00" * 64))

    def test_short_proof_rejected(self):
        rp = RangeProof(b"\xab" * 16)
        self.assertFalse(rp.verify(b"\x04" + b"\x00" * 64))


# ===================================================================
#  RingSignature / verify_ring_signature
# ===================================================================

class TestRingSignature(unittest.TestCase):

    def setUp(self):
        self.priv, self.pub = _keypair()
        self.msg = b"NexaFlow test message"

    # ---- basic sign/verify ----

    def test_sign_returns_object(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        self.assertIsInstance(sig, RingSignature)

    def test_sig_bytes_non_empty(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        self.assertGreater(len(sig.sig), 0)

    def test_verify_n1(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        self.assertTrue(verify_ring_signature(sig.sig, self.msg))

    def test_verify_n3(self):
        _d1_priv, d1_pub = _keypair()
        _d2_priv, d2_pub = _keypair()
        ring = [self.pub, d1_pub, d2_pub]
        sig = RingSignature.sign(self.msg, self.priv, ring, 0)
        self.assertTrue(verify_ring_signature(sig.sig, self.msg))

    def test_verify_n5(self):
        decoys = [_keypair()[1] for _ in range(4)]
        ring = [self.pub, *decoys]
        sig = RingSignature.sign(self.msg, self.priv, ring, 0)
        self.assertTrue(verify_ring_signature(sig.sig, self.msg))

    def test_signer_at_last_position(self):
        _d1_priv, d1_pub = _keypair()
        _d2_priv, d2_pub = _keypair()
        ring = [d1_pub, d2_pub, self.pub]
        sig = RingSignature.sign(self.msg, self.priv, ring, 2)
        self.assertTrue(verify_ring_signature(sig.sig, self.msg))

    def test_signer_at_middle_position(self):
        _d1_priv, d1_pub = _keypair()
        _d2_priv, d2_pub = _keypair()
        ring = [d1_pub, self.pub, d2_pub]
        sig = RingSignature.sign(self.msg, self.priv, ring, 1)
        self.assertTrue(verify_ring_signature(sig.sig, self.msg))

    def test_instance_verify_method(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        self.assertTrue(sig.verify(self.msg))

    # ---- key image ----

    def test_get_key_image_is_65_bytes(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        ki = sig.get_key_image()
        self.assertEqual(len(ki), 65)

    def test_key_image_consistent_with_keygen(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        expected_ki = KeyImage.generate(self.priv, self.pub).image
        self.assertEqual(sig.get_key_image(), expected_ki)

    def test_key_image_same_across_messages(self):
        sig1 = RingSignature.sign(b"msg1", self.priv, [self.pub], 0)
        sig2 = RingSignature.sign(b"msg2", self.priv, [self.pub], 0)
        self.assertEqual(sig1.get_key_image(), sig2.get_key_image())

    def test_key_image_differs_between_wallets(self):
        p2, pub2 = _keypair()
        sig1 = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        sig2 = RingSignature.sign(self.msg, p2, [pub2], 0)
        self.assertNotEqual(sig1.get_key_image(), sig2.get_key_image())

    # ---- tamper / rejection ----

    def test_wrong_message_rejected(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        self.assertFalse(verify_ring_signature(sig.sig, b"different message"))

    def test_flipped_challenge_bit_rejected(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        bad = bytearray(sig.sig)
        bad[70] ^= 0xFF  # inside c[0]
        self.assertFalse(verify_ring_signature(bytes(bad), self.msg))

    def test_flipped_response_bit_rejected(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        bad = bytearray(sig.sig)
        # n=1: offset 1(n) + 65(I) + 32(c0) = 98, inside s[0]
        bad[100] ^= 0x01
        self.assertFalse(verify_ring_signature(bytes(bad), self.msg))

    def test_truncated_sig_rejected(self):
        sig = RingSignature.sign(self.msg, self.priv, [self.pub], 0)
        self.assertFalse(verify_ring_signature(sig.sig[:30], self.msg))

    def test_empty_sig_rejected(self):
        self.assertFalse(verify_ring_signature(b"", self.msg))

    # ---- invalid arguments ----

    def test_empty_ring_raises(self):
        with self.assertRaises((ValueError, Exception)):
            RingSignature.sign(self.msg, self.priv, [], 0)

    def test_signer_index_out_of_range_raises(self):
        with self.assertRaises((ValueError, Exception)):
            RingSignature.sign(self.msg, self.priv, [self.pub], 1)

    def test_negative_signer_index_raises(self):
        with self.assertRaises((ValueError, Exception)):
            RingSignature.sign(self.msg, self.priv, [self.pub], -1)


# ===================================================================
#  create_confidential_payment
# ===================================================================

class TestCreateConfidentialPayment(unittest.TestCase):

    def setUp(self):
        self.s_priv, self.s_pub = _keypair()
        self.v_priv, self.v_pub = _keypair()
        self.sp_priv, self.sp_pub = _keypair()
        self.sender_addr = derive_address(self.s_pub)

    def _make_tx(self, amount=5.0, decoys=None, fee=0.0001, sequence=1):
        return create_confidential_payment(
            self.sender_addr, self.s_priv,
            self.v_pub, self.sp_pub,
            amount, list(decoys or []),
            fee=fee, sequence=sequence,
        )

    def test_commitment_populated(self):
        tx = self._make_tx()
        self.assertIsNotNone(tx.commitment)
        self.assertGreater(len(tx.commitment), 0)

    def test_commitment_is_65_bytes(self):
        tx = self._make_tx()
        self.assertEqual(len(tx.commitment), 65)

    def test_stealth_address_populated(self):
        tx = self._make_tx()
        self.assertIsNotNone(tx.stealth_address)
        self.assertGreater(len(tx.stealth_address), 0)

    def test_range_proof_populated(self):
        tx = self._make_tx()
        self.assertIsNotNone(tx.range_proof)
        self.assertEqual(len(tx.range_proof), 32)

    def test_key_image_populated(self):
        tx = self._make_tx()
        self.assertIsNotNone(tx.key_image)
        self.assertEqual(len(tx.key_image), 65)

    def test_ring_signature_populated(self):
        tx = self._make_tx()
        self.assertIsNotNone(tx.ring_signature)
        self.assertGreater(len(tx.ring_signature), 0)

    def test_ring_signature_valid(self):
        tx = self._make_tx()
        self.assertTrue(verify_ring_signature(tx.ring_signature, tx.hash_for_signing()))

    def test_key_image_matches_sender(self):
        tx = self._make_tx()
        expected_ki = KeyImage.generate(self.s_priv, self.s_pub).image
        self.assertEqual(tx.key_image, expected_ki)

    def test_amount_field_zeroed(self):
        tx = self._make_tx(amount=99.0)
        self.assertEqual(tx.amount.value, 0.0)

    def test_tx_id_generated(self):
        tx = self._make_tx()
        self.assertIsNotNone(tx.tx_id)
        self.assertGreater(len(tx.tx_id), 0)

    def test_distinct_outputs_per_call(self):
        tx1 = self._make_tx()
        tx2 = self._make_tx()
        self.assertNotEqual(tx1.stealth_address, tx2.stealth_address)
        self.assertNotEqual(tx1.commitment, tx2.commitment)

    def test_with_decoy_ring_sig_valid(self):
        _d1_priv, d1_pub = _keypair()
        _d2_priv, d2_pub = _keypair()
        tx = self._make_tx(decoys=[d1_pub, d2_pub])
        self.assertTrue(verify_ring_signature(tx.ring_signature, tx.hash_for_signing()))

    def test_sequence_applied(self):
        tx = self._make_tx(sequence=7)
        self.assertEqual(tx.sequence, 7)

    def test_fee_applied(self):
        tx = self._make_tx(fee=0.005)
        self.assertAlmostEqual(tx.fee.value, 0.005, places=6)


# ===================================================================
#  Ledger integration: apply_payment with confidential TX
# ===================================================================

class TestLedgerConfidentialPayment(unittest.TestCase):

    def _setup(self):
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account("rAlice", 500.0)
        s_priv, s_pub = _keypair()
        v_priv, v_pub = _keypair()
        sp_priv, sp_pub = _keypair()
        return ledger, s_priv, s_pub, v_priv, v_pub, sp_priv, sp_pub

    def test_apply_confidential_payment_success(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        result = ledger.apply_payment(tx)
        self.assertEqual(result, 0)  # tesSUCCESS

    def test_spent_key_image_recorded(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        ledger.apply_payment(tx)
        self.assertTrue(ledger.is_key_image_spent(tx.key_image))

    def test_double_spend_rejected(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        ledger.apply_payment(tx)
        result = ledger.apply_payment(tx)
        self.assertEqual(result, 107)  # tecKEY_IMAGE_SPENT

    def test_confidential_output_recorded(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        ledger.apply_payment(tx)
        utxos = ledger.get_all_confidential_outputs()
        self.assertEqual(len(utxos), 1)

    def test_fee_deducted_from_sender(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        before = ledger.get_account("rAlice").balance
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.5, sequence=1
        )
        ledger.apply_payment(tx)
        after = ledger.get_account("rAlice").balance
        self.assertAlmostEqual(after, before - 0.5, places=5)

    def test_multiple_outputs_accumulate(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        ledger.create_account("rBob", 500.0)
        s2_priv, _s2_pub = _keypair()

        tx1 = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 1.0, [], fee=0.0001, sequence=1
        )
        tx2 = create_confidential_payment(
            "rBob", s2_priv, v_pub, sp_pub, 2.0, [], fee=0.0001, sequence=1
        )
        ledger.apply_payment(tx1)
        ledger.apply_payment(tx2)
        self.assertEqual(len(ledger.get_all_confidential_outputs()), 2)

    def test_is_key_image_spent_false_before_apply(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 1.0, [], fee=0.0001, sequence=1
        )
        self.assertFalse(ledger.is_key_image_spent(tx.key_image))

    def test_stealth_address_used_after_apply(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 1.0, [], fee=0.0001, sequence=1
        )
        sa_hex = tx.stealth_address.hex()
        ledger.apply_payment(tx)
        self.assertTrue(ledger.is_stealth_address_used(sa_hex))

    def test_state_summary_includes_confidential_counts(self):
        ledger, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 1.0, [], fee=0.0001, sequence=1
        )
        ledger.apply_payment(tx)
        summary = ledger.get_state_summary()
        self.assertIn("confidential_outputs", summary)
        self.assertEqual(summary["confidential_outputs"], 1)


# ===================================================================
#  Validator: privacy field checks
# ===================================================================

class TestValidatorPrivacy(unittest.TestCase):

    def _setup(self):
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account("rAlice", 500.0)
        validator = TransactionValidator(ledger)
        s_priv, s_pub = _keypair()
        v_priv, v_pub = _keypair()
        sp_priv, sp_pub = _keypair()
        return ledger, validator, s_priv, s_pub, v_priv, v_pub, sp_priv, sp_pub

    def test_valid_confidential_tx_passes(self):
        _ledger, validator, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        valid, _code, msg = validator.validate(tx)
        self.assertTrue(valid, msg)

    def test_double_spend_fails_validation(self):
        ledger, validator, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        ledger.apply_payment(tx)  # mark key image spent in ledger
        valid, code, _msg = validator.validate(tx)
        self.assertFalse(valid)
        from nexaflow_core.transaction import TEC_KEY_IMAGE_SPENT
        self.assertEqual(code, TEC_KEY_IMAGE_SPENT)

    def test_invalid_ring_sig_fails_validation(self):
        _ledger, validator, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        # Corrupt ring signature
        bad_sig = bytearray(tx.ring_signature)
        bad_sig[70] ^= 0xFF
        tx.ring_signature = bytes(bad_sig)
        valid, _code, _msg = validator.validate(tx)
        self.assertFalse(valid)

    def test_invalid_range_proof_fails_validation(self):
        _ledger, validator, s_priv, _s_pub, _v_priv, v_pub, _sp_priv, sp_pub = self._setup()
        tx = create_confidential_payment(
            "rAlice", s_priv, v_pub, sp_pub, 5.0, [], fee=0.0001, sequence=1
        )
        tx.range_proof = b"\x00" * 32  # zero proof → rejected
        valid, _code, _msg = validator.validate(tx)
        self.assertFalse(valid)


# ===================================================================
#  Wallet integration: sign_confidential_payment + scan
# ===================================================================

class TestWalletPrivacy(unittest.TestCase):

    def _make_wallets(self):
        sender = Wallet.create()
        recipient = Wallet.create()
        return sender, recipient

    def test_sign_confidential_payment_returns_tx(self):
        sender, recipient = self._make_wallets()
        tx = sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            10.0,
        )
        self.assertIsNotNone(tx)

    def test_sign_confidential_payment_all_fields(self):
        sender, recipient = self._make_wallets()
        tx = sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            10.0,
        )
        self.assertIsNotNone(tx.commitment)
        self.assertIsNotNone(tx.ring_signature)
        self.assertIsNotNone(tx.key_image)
        self.assertIsNotNone(tx.stealth_address)
        self.assertIsNotNone(tx.range_proof)

    def test_sign_confidential_payment_ring_sig_valid(self):
        sender, recipient = self._make_wallets()
        tx = sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            10.0,
        )
        self.assertTrue(verify_ring_signature(tx.ring_signature, tx.hash_for_signing()))

    def test_sign_increments_sequence(self):
        sender, recipient = self._make_wallets()
        seq_before = sender.sequence
        sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            1.0,
        )
        self.assertEqual(sender.sequence, seq_before + 1)

    def test_scan_finds_own_output(self):
        sender = Wallet.create()
        recipient = Wallet.create()
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account(sender.address, 500.0)

        tx = sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            5.0,
            fee=0.0001,
        )
        ledger.apply_payment(tx)

        found = recipient.scan_confidential_outputs(ledger)
        self.assertEqual(len(found), 1)

    def test_scan_does_not_find_others_output(self):
        sender = Wallet.create()
        recipient = Wallet.create()
        bystander = Wallet.create()
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account(sender.address, 500.0)

        tx = sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            5.0,
            fee=0.0001,
        )
        ledger.apply_payment(tx)

        found = bystander.scan_confidential_outputs(ledger)
        self.assertEqual(len(found), 0)

    def test_scan_multiple_outputs(self):
        sender = Wallet.create()
        recipient = Wallet.create()
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account(sender.address, 500.0)

        for amount in [1.0, 2.0, 3.0]:
            tx = sender.sign_confidential_payment(
                recipient.view_public_key,
                recipient.spend_public_key,
                amount,
                fee=0.0001,
            )
            ledger.apply_payment(tx)

        found = recipient.scan_confidential_outputs(ledger)
        self.assertEqual(len(found), 3)

    def test_scan_result_contains_one_time_priv(self):
        sender = Wallet.create()
        recipient = Wallet.create()
        ledger = Ledger(total_supply=10_000.0, genesis_account="rGen")
        ledger.create_account(sender.address, 500.0)

        tx = sender.sign_confidential_payment(
            recipient.view_public_key,
            recipient.spend_public_key,
            5.0,
            fee=0.0001,
        )
        ledger.apply_payment(tx)

        found = recipient.scan_confidential_outputs(ledger)
        self.assertIn("one_time_priv", found[0])
        self.assertEqual(len(found[0]["one_time_priv"]), 64)  # 32 bytes hex


if __name__ == "__main__":
    unittest.main()
