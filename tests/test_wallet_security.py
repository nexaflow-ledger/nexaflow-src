"""
Security-focused tests for nexaflow_core.wallet — key management & crypto.

Covers:
  - View / spend keypair generation
  - Deterministic seed derivation (from_seed edge cases)
  - Empty and special-character passphrases
  - AES-CTR encryption round-trip
  - Encrypted export/import with view/spend keys (v2 format)
  - Wrong passphrase detection
  - Corrupted export data
  - Wallet repr
  - sign_confidential_payment guard
  - Sequence management and edge cases
"""

import unittest

from nexaflow_core.transaction import create_payment
from nexaflow_core.wallet import Wallet

# ═══════════════════════════════════════════════════════════════════
#  View / Spend key generation
# ═══════════════════════════════════════════════════════════════════

class TestViewSpendKeys(unittest.TestCase):

    def test_create_generates_view_keys(self):
        w = Wallet.create()
        self.assertIsNotNone(w.view_private_key)
        self.assertIsNotNone(w.view_public_key)
        self.assertEqual(len(w.view_private_key), 32)
        self.assertEqual(len(w.view_public_key), 65)

    def test_create_generates_spend_keys(self):
        w = Wallet.create()
        self.assertIsNotNone(w.spend_private_key)
        self.assertIsNotNone(w.spend_public_key)
        self.assertEqual(len(w.spend_private_key), 32)
        self.assertEqual(len(w.spend_public_key), 65)

    def test_from_seed_generates_view_keys(self):
        w = Wallet.from_seed("test-seed")
        self.assertIsNotNone(w.view_private_key)
        self.assertIsNotNone(w.view_public_key)

    def test_from_seed_generates_spend_keys(self):
        w = Wallet.from_seed("test-seed")
        self.assertIsNotNone(w.spend_private_key)
        self.assertIsNotNone(w.spend_public_key)

    def test_view_key_deterministic_from_seed(self):
        w1 = Wallet.from_seed("abc")
        w2 = Wallet.from_seed("abc")
        self.assertEqual(w1.view_private_key, w2.view_private_key)
        self.assertEqual(w1.view_public_key, w2.view_public_key)

    def test_spend_key_deterministic_from_seed(self):
        w1 = Wallet.from_seed("abc")
        w2 = Wallet.from_seed("abc")
        self.assertEqual(w1.spend_private_key, w2.spend_private_key)

    def test_different_seeds_different_view_keys(self):
        w1 = Wallet.from_seed("seed-a")
        w2 = Wallet.from_seed("seed-b")
        self.assertNotEqual(w1.view_private_key, w2.view_private_key)

    def test_main_key_differs_from_view_and_spend(self):
        w = Wallet.from_seed("separation-test")
        self.assertNotEqual(w.private_key, w.view_private_key)
        self.assertNotEqual(w.private_key, w.spend_private_key)
        self.assertNotEqual(w.view_private_key, w.spend_private_key)


# ═══════════════════════════════════════════════════════════════════
#  Seed edge cases
# ═══════════════════════════════════════════════════════════════════

class TestSeedEdgeCases(unittest.TestCase):

    def test_empty_seed(self):
        """Empty string seed should still produce a valid wallet."""
        w = Wallet.from_seed("")
        self.assertTrue(w.address.startswith("r"))
        self.assertEqual(len(w.private_key), 32)

    def test_very_long_seed(self):
        w = Wallet.from_seed("a" * 10_000)
        self.assertTrue(len(w.address) > 20)

    def test_unicode_seed(self):
        w = Wallet.from_seed("日本語シード🚀")
        self.assertTrue(w.address.startswith("r"))

    def test_whitespace_seed(self):
        w1 = Wallet.from_seed(" seed ")
        w2 = Wallet.from_seed("seed")
        # These should be different (whitespace matters)
        self.assertNotEqual(w1.address, w2.address)


# ═══════════════════════════════════════════════════════════════════
#  AES-CTR encryption
# ═══════════════════════════════════════════════════════════════════

class TestAESCTR(unittest.TestCase):

    def test_roundtrip(self):
        key = b"\x00" * 32
        iv = b"\x01" * 16
        data = b"hello world 1234"
        encrypted = Wallet._aes_ctr_encrypt(key, iv, data)
        decrypted = Wallet._aes_ctr_encrypt(key, iv, encrypted)
        self.assertEqual(decrypted, data)

    def test_different_key_different_output(self):
        iv = b"\x00" * 16
        data = b"test data"
        enc1 = Wallet._aes_ctr_encrypt(b"\x01" * 32, iv, data)
        enc2 = Wallet._aes_ctr_encrypt(b"\x02" * 32, iv, data)
        self.assertNotEqual(enc1, enc2)

    def test_different_iv_different_output(self):
        key = b"\x00" * 32
        data = b"test data"
        enc1 = Wallet._aes_ctr_encrypt(key, b"\x01" * 16, data)
        enc2 = Wallet._aes_ctr_encrypt(key, b"\x02" * 16, data)
        self.assertNotEqual(enc1, enc2)

    def test_empty_data(self):
        key = b"\x00" * 32
        iv = b"\x00" * 16
        result = Wallet._aes_ctr_encrypt(key, iv, b"")
        self.assertEqual(result, b"")

    def test_large_data(self):
        key = b"\xab" * 32
        iv = b"\xcd" * 16
        data = b"\xff" * 1000
        encrypted = Wallet._aes_ctr_encrypt(key, iv, data)
        decrypted = Wallet._aes_ctr_encrypt(key, iv, encrypted)
        self.assertEqual(decrypted, data)


# ═══════════════════════════════════════════════════════════════════
#  Encrypted export/import round-trips (v2)
# ═══════════════════════════════════════════════════════════════════

class TestEncryptedExportV2(unittest.TestCase):

    def test_roundtrip_with_all_keys(self):
        w = Wallet.create()
        exported = w.export_encrypted("pass123")
        w2 = Wallet.import_encrypted(exported, "pass123")
        self.assertEqual(w2.private_key, w.private_key)
        self.assertEqual(w2.view_private_key, w.view_private_key)
        self.assertEqual(w2.spend_private_key, w.spend_private_key)
        self.assertEqual(w2.address, w.address)

    def test_view_pub_preserved(self):
        w = Wallet.create()
        exported = w.export_encrypted("pw")
        w2 = Wallet.import_encrypted(exported, "pw")
        self.assertEqual(w2.view_public_key, w.view_public_key)
        self.assertEqual(w2.spend_public_key, w.spend_public_key)

    def test_wrong_passphrase_corrupts_keys(self):
        w = Wallet.create()
        exported = w.export_encrypted("correct")
        w2 = Wallet.import_encrypted(exported, "wrong")
        self.assertNotEqual(w2.private_key, w.private_key)

    def test_version_2_tag(self):
        w = Wallet.create()
        exported = w.export_encrypted("pw")
        self.assertEqual(exported["version"], 2)

    def test_export_has_kdf_fields(self):
        w = Wallet.create()
        exported = w.export_encrypted("pw")
        self.assertEqual(exported["kdf"], "pbkdf2-hmac-sha256")
        self.assertEqual(exported["kdf_iterations"], 100_000)
        self.assertIn("salt", exported)
        self.assertIn("iv", exported)


# ═══════════════════════════════════════════════════════════════════
#  Passphrase edge cases
# ═══════════════════════════════════════════════════════════════════

class TestPassphraseEdgeCases(unittest.TestCase):

    def test_empty_passphrase(self):
        w = Wallet.create()
        exported = w.export_encrypted("")
        w2 = Wallet.import_encrypted(exported, "")
        self.assertEqual(w2.private_key, w.private_key)

    def test_unicode_passphrase(self):
        w = Wallet.create()
        exported = w.export_encrypted("пароль🔑")
        w2 = Wallet.import_encrypted(exported, "пароль🔑")
        self.assertEqual(w2.private_key, w.private_key)

    def test_very_long_passphrase(self):
        w = Wallet.create()
        long_pw = "x" * 10_000
        exported = w.export_encrypted(long_pw)
        w2 = Wallet.import_encrypted(exported, long_pw)
        self.assertEqual(w2.private_key, w.private_key)


# ═══════════════════════════════════════════════════════════════════
#  Wallet without optional keys
# ═══════════════════════════════════════════════════════════════════

class TestWalletWithoutOptionalKeys(unittest.TestCase):

    def test_wallet_without_view_keys(self):
        from nexaflow_core.crypto_utils import generate_keypair
        priv, pub = generate_keypair()
        w = Wallet(priv, pub)
        self.assertIsNone(w.view_private_key)
        self.assertIsNone(w.view_public_key)

    def test_sign_confidential_without_spend_key_raises(self):
        from nexaflow_core.crypto_utils import generate_keypair
        priv, pub = generate_keypair()
        w = Wallet(priv, pub)  # no spend_private_key
        with self.assertRaises(ValueError):
            w.sign_confidential_payment(
                recipient_view_pub=b"\x04" + b"\x01" * 64,
                recipient_spend_pub=b"\x04" + b"\x02" * 64,
                amount=10.0,
            )

    def test_scan_without_view_keys_raises(self):
        from nexaflow_core.crypto_utils import generate_keypair
        priv, pub = generate_keypair()
        w = Wallet(priv, pub)
        with self.assertRaises(ValueError):
            w.scan_confidential_outputs(object())

    def test_to_dict_without_view_keys(self):
        from nexaflow_core.crypto_utils import generate_keypair
        priv, pub = generate_keypair()
        w = Wallet(priv, pub)
        d = w.to_dict()
        self.assertIsNone(d["view_public_key"])
        self.assertIsNone(d["spend_public_key"])

    def test_export_without_view_keys(self):
        from nexaflow_core.crypto_utils import generate_keypair
        priv, pub = generate_keypair()
        w = Wallet(priv, pub)
        exported = w.export_encrypted("pw")
        self.assertIsNone(exported["encrypted_view_private_key"])
        self.assertIsNone(exported["encrypted_spend_private_key"])


# ═══════════════════════════════════════════════════════════════════
#  Sequence management
# ═══════════════════════════════════════════════════════════════════

class TestSequenceManagement(unittest.TestCase):

    def test_initial_sequence_is_one(self):
        w = Wallet.create()
        self.assertEqual(w.sequence, 1)

    def test_signing_increments(self):
        w = Wallet.create()
        for _i in range(5):
            tx = create_payment(w.address, "rDest", 1.0)
            w.sign_transaction(tx)
        self.assertEqual(w.sequence, 6)

    def test_manual_sequence_set(self):
        w = Wallet.create()
        w.sequence = 100
        tx = create_payment(w.address, "rDest", 1.0)
        w.sign_transaction(tx)
        self.assertEqual(tx.sequence, 100)
        self.assertEqual(w.sequence, 101)

    def test_repr(self):
        w = Wallet.create()
        r = repr(w)
        self.assertIn("Wallet(", r)
        self.assertIn(w.address, r)


if __name__ == "__main__":
    unittest.main()
