"""
Test suite for HD wallet, BIP-39 mnemonics, and Ed25519 signing.

Covers:
  - BIP-39 mnemonic generation and validation
  - entropy_to_mnemonic determinism
  - mnemonic_to_seed derivation
  - HDNode from_seed, derive_child (normal + hardened), derive_path
  - HDNode.to_wallet integration
  - Wallet.from_mnemonic, Wallet.create_hd
  - Ed25519Signer.generate_keypair, sign, verify
  - Ed25519 sign/verify roundtrip
  - Edge cases: invalid mnemonic, invalid entropy strength
"""

import unittest

from nexaflow_core.wallet import (
    Ed25519Signer,
    HDNode,
    Wallet,
    entropy_to_mnemonic,
    generate_mnemonic,
    mnemonic_to_seed,
    validate_mnemonic,
)


class TestBIP39Mnemonic(unittest.TestCase):

    def test_generate_mnemonic_12_words(self):
        m = generate_mnemonic(128)
        words = m.split()
        self.assertEqual(len(words), 12)

    def test_generate_mnemonic_24_words(self):
        m = generate_mnemonic(256)
        words = m.split()
        self.assertEqual(len(words), 24)

    def test_invalid_entropy_strength(self):
        with self.assertRaises(ValueError):
            generate_mnemonic(100)

    def test_validate_mnemonic_12(self):
        m = generate_mnemonic(128)
        self.assertTrue(validate_mnemonic(m))

    def test_validate_mnemonic_24(self):
        m = generate_mnemonic(256)
        self.assertTrue(validate_mnemonic(m))

    def test_validate_invalid_word_count(self):
        self.assertFalse(validate_mnemonic("one two three"))

    def test_entropy_to_mnemonic_deterministic(self):
        ent = b"\x00" * 16  # 128 bits
        m1 = entropy_to_mnemonic(ent)
        m2 = entropy_to_mnemonic(ent)
        self.assertEqual(m1, m2)

    def test_mnemonic_to_seed_deterministic(self):
        m = generate_mnemonic(128)
        s1 = mnemonic_to_seed(m, "pass1")
        s2 = mnemonic_to_seed(m, "pass1")
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1), 64)

    def test_mnemonic_to_seed_passphrase_changes_seed(self):
        m = generate_mnemonic(128)
        s1 = mnemonic_to_seed(m, "")
        s2 = mnemonic_to_seed(m, "different")
        self.assertNotEqual(s1, s2)


class TestHDNode(unittest.TestCase):

    def setUp(self):
        seed = mnemonic_to_seed("abandon " * 11 + "about")
        self.master = HDNode.from_seed(seed)

    def test_from_seed(self):
        self.assertEqual(self.master.depth, 0)
        self.assertEqual(len(self.master.private_key), 32)
        self.assertEqual(len(self.master.chain_code), 32)

    def test_derive_child_normal(self):
        child = self.master.derive_child(0)
        self.assertEqual(child.depth, 1)
        self.assertNotEqual(child.private_key, self.master.private_key)

    def test_derive_child_hardened(self):
        child = self.master.derive_child(HDNode.HARDENED + 44)
        self.assertEqual(child.depth, 1)

    def test_derive_path(self):
        child = self.master.derive_path("44'/144'/0'/0/0")
        self.assertEqual(child.depth, 5)

    def test_derive_path_m_prefix(self):
        child = self.master.derive_path("m/44'/144'/0'/0/0")
        self.assertEqual(child.depth, 5)

    def test_derive_path_m_only(self):
        node = self.master.derive_path("m")
        self.assertIs(node, self.master)

    def test_to_wallet(self):
        child = self.master.derive_path("44'/144'/0'/0/0")
        wallet = child.to_wallet()
        self.assertIsInstance(wallet, Wallet)
        self.assertTrue(len(wallet.address) > 0)

    def test_different_indices_different_keys(self):
        c0 = self.master.derive_child(0)
        c1 = self.master.derive_child(1)
        self.assertNotEqual(c0.private_key, c1.private_key)

    def test_fingerprint(self):
        fp = self.master.fingerprint
        self.assertEqual(len(fp), 4)


class TestWalletFromMnemonic(unittest.TestCase):

    def test_from_mnemonic_roundtrip(self):
        m = generate_mnemonic(128)
        w1 = Wallet.from_mnemonic(m)
        w2 = Wallet.from_mnemonic(m)
        self.assertEqual(w1.address, w2.address)
        self.assertEqual(w1.private_key, w2.private_key)

    def test_from_mnemonic_different_passphrases(self):
        m = generate_mnemonic(128)
        w1 = Wallet.from_mnemonic(m, passphrase="")
        w2 = Wallet.from_mnemonic(m, passphrase="secure")
        self.assertNotEqual(w1.address, w2.address)

    def test_from_mnemonic_different_accounts(self):
        m = generate_mnemonic(128)
        w0 = Wallet.from_mnemonic(m, account=0)
        w1 = Wallet.from_mnemonic(m, account=1)
        self.assertNotEqual(w0.address, w1.address)

    def test_from_mnemonic_different_indices(self):
        m = generate_mnemonic(128)
        w0 = Wallet.from_mnemonic(m, index=0)
        w1 = Wallet.from_mnemonic(m, index=1)
        self.assertNotEqual(w0.address, w1.address)

    def test_from_mnemonic_invalid_raises(self):
        with self.assertRaises(ValueError):
            Wallet.from_mnemonic("one two three")

    def test_from_mnemonic_has_view_spend_keys(self):
        m = generate_mnemonic(128)
        w = Wallet.from_mnemonic(m)
        self.assertIsNotNone(w.view_private_key)
        self.assertIsNotNone(w.view_public_key)
        self.assertIsNotNone(w.spend_private_key)
        self.assertIsNotNone(w.spend_public_key)


class TestWalletCreateHD(unittest.TestCase):

    def test_create_hd_new_mnemonic(self):
        mnemonic, wallet = Wallet.create_hd()
        self.assertTrue(validate_mnemonic(mnemonic))
        self.assertIsInstance(wallet, Wallet)
        self.assertTrue(len(wallet.address) > 0)

    def test_create_hd_existing_mnemonic(self):
        m = generate_mnemonic(128)
        mnemonic, wallet = Wallet.create_hd(mnemonic=m)
        self.assertEqual(mnemonic, m)
        # Deterministic
        _, w2 = Wallet.create_hd(mnemonic=m)
        self.assertEqual(wallet.address, w2.address)


class TestEd25519Signer(unittest.TestCase):

    def test_generate_keypair(self):
        priv, pub = Ed25519Signer.generate_keypair()
        self.assertEqual(len(priv), 32)
        self.assertEqual(len(pub), 32)

    def test_sign_returns_64_bytes(self):
        priv, pub = Ed25519Signer.generate_keypair()
        sig = Ed25519Signer.sign(priv, b"hello world")
        self.assertEqual(len(sig), 64)

    def test_sign_deterministic(self):
        priv, pub = Ed25519Signer.generate_keypair()
        s1 = Ed25519Signer.sign(priv, b"msg")
        s2 = Ed25519Signer.sign(priv, b"msg")
        self.assertEqual(s1, s2)

    def test_verify_valid(self):
        priv, pub = Ed25519Signer.generate_keypair()
        sig = Ed25519Signer.sign(priv, b"test message")
        self.assertTrue(Ed25519Signer.verify(pub, b"test message", sig))

    def test_verify_wrong_message(self):
        priv, pub = Ed25519Signer.generate_keypair()
        sig = Ed25519Signer.sign(priv, b"correct")
        self.assertFalse(Ed25519Signer.verify(pub, b"wrong", sig))

    def test_verify_wrong_key(self):
        priv1, pub1 = Ed25519Signer.generate_keypair()
        priv2, pub2 = Ed25519Signer.generate_keypair()
        sig = Ed25519Signer.sign(priv1, b"msg")
        self.assertFalse(Ed25519Signer.verify(pub2, b"msg", sig))

    def test_sign_different_messages_differ(self):
        priv, pub = Ed25519Signer.generate_keypair()
        s1 = Ed25519Signer.sign(priv, b"msg1")
        s2 = Ed25519Signer.sign(priv, b"msg2")
        self.assertNotEqual(s1, s2)


if __name__ == "__main__":
    unittest.main()
