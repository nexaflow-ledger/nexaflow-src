"""
Test suite for nexaflow_core.wallet — Wallet management.

Covers:
  - Wallet.create() and Wallet.from_seed()
  - Transaction signing and verification
  - Sequence tracking
  - to_dict, export_encrypted, import_encrypted round-trips
"""

import unittest

from nexaflow_core.wallet import Wallet
from nexaflow_core.transaction import create_payment, Amount


class TestWalletCreate(unittest.TestCase):

    def test_create_generates_keys(self):
        w = Wallet.create()
        self.assertEqual(len(w.private_key), 32)
        self.assertEqual(len(w.public_key), 65)

    def test_create_derives_address(self):
        w = Wallet.create()
        self.assertTrue(w.address.startswith("r"))
        self.assertTrue(len(w.address) > 20)

    def test_create_unique(self):
        w1 = Wallet.create()
        w2 = Wallet.create()
        self.assertNotEqual(w1.address, w2.address)

    def test_initial_sequence(self):
        w = Wallet.create()
        self.assertEqual(w.sequence, 1)


class TestWalletFromSeed(unittest.TestCase):

    def test_deterministic(self):
        w1 = Wallet.from_seed("test-seed-123")
        w2 = Wallet.from_seed("test-seed-123")
        self.assertEqual(w1.address, w2.address)
        self.assertEqual(w1.private_key, w2.private_key)

    def test_different_seeds(self):
        w1 = Wallet.from_seed("seed_a")
        w2 = Wallet.from_seed("seed_b")
        self.assertNotEqual(w1.address, w2.address)

    def test_address_format(self):
        w = Wallet.from_seed("my_seed")
        self.assertTrue(w.address.startswith("r"))


class TestWalletSigning(unittest.TestCase):

    def test_sign_transaction(self):
        w = Wallet.create()
        tx = create_payment(w.address, "rDest", 10.0)
        signed = w.sign_transaction(tx)
        self.assertIs(signed, tx)
        self.assertTrue(len(tx.signature) > 0)
        self.assertTrue(len(tx.tx_id) > 0)
        self.assertEqual(tx.signing_pub_key, w.public_key)

    def test_signed_tx_verifies(self):
        w = Wallet.create()
        tx = create_payment(w.address, "rDest", 25.0)
        w.sign_transaction(tx)
        self.assertTrue(tx.verify_signature())

    def test_sequence_increments(self):
        w = Wallet.create()
        self.assertEqual(w.sequence, 1)
        tx1 = create_payment(w.address, "rA", 1.0)
        w.sign_transaction(tx1)
        self.assertEqual(w.sequence, 2)
        tx2 = create_payment(w.address, "rB", 2.0)
        w.sign_transaction(tx2)
        self.assertEqual(w.sequence, 3)

    def test_sequence_assigned_to_tx(self):
        w = Wallet.create()
        tx = create_payment(w.address, "rX", 5.0)
        w.sign_transaction(tx)
        self.assertEqual(tx.sequence, 1)

    def test_sequence_setter(self):
        w = Wallet.create()
        w.sequence = 42
        self.assertEqual(w.sequence, 42)


class TestWalletSerialization(unittest.TestCase):

    def test_to_dict(self):
        w = Wallet.create()
        d = w.to_dict()
        self.assertIn("address", d)
        self.assertIn("public_key", d)
        self.assertIn("private_key", d)
        self.assertEqual(d["address"], w.address)

    def test_export_encrypted_has_fields(self):
        w = Wallet.create()
        data = w.export_encrypted("password123")
        self.assertIn("address", data)
        self.assertIn("public_key", data)
        self.assertIn("encrypted_private_key", data)
        self.assertIn("salt", data)

    def test_encrypted_key_differs_from_plain(self):
        w = Wallet.create()
        data = w.export_encrypted("secret")
        self.assertNotEqual(data["encrypted_private_key"], w.private_key.hex())

    def test_import_encrypted_roundtrip(self):
        w = Wallet.create()
        passphrase = "my-strong-password"
        exported = w.export_encrypted(passphrase)
        w2 = Wallet.import_encrypted(exported, passphrase)
        self.assertEqual(w2.private_key, w.private_key)
        self.assertEqual(w2.public_key, w.public_key)
        self.assertEqual(w2.address, w.address)

    def test_import_wrong_passphrase(self):
        w = Wallet.create()
        exported = w.export_encrypted("correct")
        w2 = Wallet.import_encrypted(exported, "wrong")
        # Wrong passphrase → different private key
        self.assertNotEqual(w2.private_key, w.private_key)


if __name__ == "__main__":
    unittest.main()
