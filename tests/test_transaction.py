"""
Test suite for nexaflow_core.transaction — Cython-optimized transaction processing.

Covers:
  - Amount (native vs IOU, serialization, to_dict, from_dict)
  - Transaction creation, serialization, signing, to_dict
  - create_payment, create_trust_set, create_offer builders
  - Constants visibility (TT_*, TES_*, TEC_*)
"""

import unittest

from nexaflow_core.crypto_utils import generate_keypair, generate_tx_id, sign
from nexaflow_core.transaction import (
    RESULT_NAMES,
    TEC_BAD_SIG,
    TEC_UNFUNDED,
    TES_SUCCESS,
    TT_ACCOUNT_SET,
    TT_OFFER_CANCEL,
    TT_OFFER_CREATE,
    TT_PAYMENT,
    TT_TRUST_SET,
    TX_TYPE_NAMES,
    Amount,
    Transaction,
    create_offer,
    create_payment,
    create_trust_set,
)

# ===================================================================
#  Amount
# ===================================================================


class TestAmount(unittest.TestCase):

    def test_native_default(self):
        a = Amount(100.0)
        self.assertTrue(a.is_native())
        self.assertEqual(a.currency, "NXF")
        self.assertEqual(a.issuer, "")

    def test_iou(self):
        a = Amount(50.0, "USD", "rIssuer123")
        self.assertFalse(a.is_native())
        self.assertEqual(a.currency, "USD")
        self.assertEqual(a.issuer, "rIssuer123")

    def test_serialize_returns_bytes(self):
        a = Amount(1.5, "USD", "rIssuer")
        blob = a.serialize()
        self.assertIsInstance(blob, bytes)
        # 8 (double) + 3 (currency) + 40 (issuer) = 51
        self.assertEqual(len(blob), 51)

    def test_serialize_deterministic(self):
        a = Amount(99.0, "EUR", "rBank")
        self.assertEqual(a.serialize(), a.serialize())

    def test_to_dict_native(self):
        d = Amount(42.0).to_dict()
        self.assertEqual(d["value"], 42.0)
        self.assertEqual(d["currency"], "NXF")
        self.assertNotIn("issuer", d)

    def test_to_dict_iou(self):
        d = Amount(10.0, "BTC", "rSatoshi").to_dict()
        self.assertEqual(d["currency"], "BTC")
        self.assertEqual(d["issuer"], "rSatoshi")

    def test_from_dict_roundtrip_native(self):
        orig = Amount(7.77)
        rebuilt = Amount.from_dict(orig.to_dict())
        self.assertAlmostEqual(rebuilt.value, 7.77, places=5)
        self.assertTrue(rebuilt.is_native())

    def test_from_dict_roundtrip_iou(self):
        orig = Amount(3.14, "JPY", "rTokyo")
        rebuilt = Amount.from_dict(orig.to_dict())
        self.assertEqual(rebuilt.currency, "JPY")
        self.assertEqual(rebuilt.issuer, "rTokyo")

    def test_repr_native(self):
        self.assertIn("NXF", repr(Amount(1.0)))

    def test_repr_iou(self):
        r = repr(Amount(5.0, "USD", "rIssuerAbcdef"))
        self.assertIn("USD", r)


# ===================================================================
#  Transaction
# ===================================================================


class TestTransaction(unittest.TestCase):

    def test_creation_defaults(self):
        tx = Transaction(TT_PAYMENT, "rSender")
        self.assertEqual(tx.tx_type, TT_PAYMENT)
        self.assertEqual(tx.account, "rSender")
        self.assertEqual(tx.destination, "")
        self.assertEqual(tx.result_code, -1)
        self.assertTrue(tx.amount.is_native())

    def test_serialize_for_signing_deterministic(self):
        tx = Transaction(TT_PAYMENT, "rA", "rB", Amount(100.0))
        blob1 = tx.serialize_for_signing()
        blob2 = tx.serialize_for_signing()
        self.assertEqual(blob1, blob2)

    def test_serialize_for_signing_changes_with_fields(self):
        tx1 = Transaction(TT_PAYMENT, "rA", "rB", Amount(1.0))
        tx2 = Transaction(TT_PAYMENT, "rA", "rB", Amount(2.0))
        self.assertNotEqual(tx1.serialize_for_signing(), tx2.serialize_for_signing())

    def test_hash_for_signing_returns_32_bytes(self):
        tx = Transaction(TT_PAYMENT, "rSrc", "rDst", Amount(10.0))
        h = tx.hash_for_signing()
        self.assertEqual(len(h), 32)

    def test_apply_signature(self):
        tx = Transaction(TT_PAYMENT, "rSrc", "rDst")
        tx.apply_signature(b"pubkey", b"sig", "abc123")
        self.assertEqual(tx.signing_pub_key, b"pubkey")
        self.assertEqual(tx.signature, b"sig")
        self.assertEqual(tx.tx_id, "abc123")

    def test_verify_signature_no_sig(self):
        tx = Transaction(TT_PAYMENT, "rSrc")
        self.assertFalse(tx.verify_signature())

    def test_sign_and_verify(self):
        priv, pub = generate_keypair()
        tx = Transaction(TT_PAYMENT, "rA", "rB", Amount(50.0))
        msg_hash = tx.hash_for_signing()
        sig = sign(priv, msg_hash)
        tx_id = generate_tx_id(tx.serialize_for_signing() + sig)
        tx.apply_signature(pub, sig, tx_id)
        self.assertTrue(tx.verify_signature())

    def test_to_dict(self):
        tx = Transaction(TT_PAYMENT, "rSender", "rReceiver", Amount(100.0))
        tx.tx_id = "txid123"
        d = tx.to_dict()
        self.assertEqual(d["tx_type"], TT_PAYMENT)
        self.assertEqual(d["account"], "rSender")
        self.assertEqual(d["destination"], "rReceiver")
        self.assertIn("amount", d)
        self.assertIn("fee", d)
        self.assertIn("tx_id", d)

    def test_to_dict_type_name(self):
        tx = Transaction(TT_TRUST_SET, "rAcc")
        d = tx.to_dict()
        self.assertEqual(d["tx_type_name"], "TrustSet")


# ===================================================================
#  Transaction builders
# ===================================================================


class TestTransactionBuilders(unittest.TestCase):

    def test_create_payment_native(self):
        tx = create_payment("rAlice", "rBob", 25.0)
        self.assertEqual(tx.tx_type, TT_PAYMENT)
        self.assertEqual(tx.account, "rAlice")
        self.assertEqual(tx.destination, "rBob")
        self.assertAlmostEqual(tx.amount.value, 25.0)
        self.assertTrue(tx.amount.is_native())

    def test_create_payment_iou(self):
        tx = create_payment("rA", "rB", 10.0, "USD", "rIssuer")
        self.assertEqual(tx.amount.currency, "USD")
        self.assertEqual(tx.amount.issuer, "rIssuer")

    def test_create_payment_custom_fee(self):
        tx = create_payment("rA", "rB", 5.0, fee=0.001)
        self.assertAlmostEqual(tx.fee.value, 0.001)

    def test_create_payment_memo(self):
        tx = create_payment("rA", "rB", 1.0, memo="hello")
        self.assertEqual(tx.memo, "hello")

    def test_create_trust_set(self):
        tx = create_trust_set("rHolder", "USD", "rIssuer", 1000.0)
        self.assertEqual(tx.tx_type, TT_TRUST_SET)
        self.assertEqual(tx.account, "rHolder")
        self.assertIsNotNone(tx.limit_amount)
        self.assertAlmostEqual(tx.limit_amount.value, 1000.0)
        self.assertEqual(tx.limit_amount.currency, "USD")
        self.assertEqual(tx.limit_amount.issuer, "rIssuer")

    def test_create_offer(self):
        pays = Amount(100.0, "USD", "rGW")
        gets = Amount(5.0)
        tx = create_offer("rTrader", pays, gets)
        self.assertEqual(tx.tx_type, TT_OFFER_CREATE)
        self.assertEqual(tx.account, "rTrader")
        self.assertEqual(tx.taker_pays.currency, "USD")
        self.assertTrue(tx.taker_gets.is_native())


# ===================================================================
#  Constants visibility
# ===================================================================


class TestConstants(unittest.TestCase):

    def test_tx_type_values(self):
        self.assertEqual(TT_PAYMENT, 0)
        self.assertEqual(TT_TRUST_SET, 20)
        self.assertEqual(TT_OFFER_CREATE, 7)
        self.assertEqual(TT_OFFER_CANCEL, 8)
        self.assertEqual(TT_ACCOUNT_SET, 3)

    def test_result_codes(self):
        self.assertEqual(TES_SUCCESS, 0)
        self.assertEqual(TEC_UNFUNDED, 101)
        self.assertEqual(TEC_BAD_SIG, 106)

    def test_tx_type_names_mapping(self):
        self.assertEqual(TX_TYPE_NAMES["Payment"], TT_PAYMENT)
        self.assertEqual(TX_TYPE_NAMES["TrustSet"], TT_TRUST_SET)

    def test_result_names_mapping(self):
        self.assertEqual(RESULT_NAMES[TES_SUCCESS], "tesSUCCESS")
        self.assertIn(TEC_UNFUNDED, RESULT_NAMES)


if __name__ == "__main__":
    unittest.main()
