"""
Test suite for nexaflow_core.crypto_utils — Cython-optimized cryptographic utilities.

Covers:
  - SHA-256 / double-SHA-256 / SHA-512-half / RIPEMD-160 / Hash160
  - Base58 encode / decode (NexaFlow alphabet)
  - Base58Check encode / decode with checksum verification
  - ECDSA key-pair generation
  - ECDSA signing and verification
  - Address derivation
  - Nonce / TX-ID generation
  - NexaFlow timestamp helpers
"""

import hashlib
import time
import unittest

from nexaflow_core.crypto_utils import (
    base58_decode,
    base58_encode,
    base58check_decode,
    base58check_encode,
    derive_address,
    generate_keypair,
    generate_nonce,
    generate_tx_id,
    hash160,
    nexaflow_timestamp,
    ripemd160,
    sha256,
    sha256d,
    sha512_half,
    sign,
    unix_from_nexaflow,
    verify,
)


class TestHashFunctions(unittest.TestCase):
    """Tests for hashing primitives."""

    def test_sha256_known_vector(self):
        expected = hashlib.sha256(b"hello").digest()
        self.assertEqual(sha256(b"hello"), expected)

    def test_sha256_empty(self):
        expected = hashlib.sha256(b"").digest()
        self.assertEqual(sha256(b""), expected)

    def test_sha256_returns_32_bytes(self):
        self.assertEqual(len(sha256(b"test")), 32)

    def test_sha256d_double_hash(self):
        single = hashlib.sha256(b"data").digest()
        expected = hashlib.sha256(single).digest()
        self.assertEqual(sha256d(b"data"), expected)

    def test_sha256d_differs_from_single(self):
        self.assertNotEqual(sha256(b"data"), sha256d(b"data"))

    def test_sha512_half_returns_32_bytes(self):
        result = sha512_half(b"test data")
        self.assertEqual(len(result), 32)

    def test_sha512_half_is_first_half(self):
        full = hashlib.sha512(b"payload").digest()
        self.assertEqual(sha512_half(b"payload"), full[:32])

    def test_ripemd160_returns_20_bytes(self):
        result = ripemd160(b"hello")
        self.assertEqual(len(result), 20)

    def test_ripemd160_known_value(self):
        expected = hashlib.new("ripemd160", b"hello").digest()
        self.assertEqual(ripemd160(b"hello"), expected)

    def test_hash160_composition(self):
        data = b"public_key_bytes"
        expected = hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()
        self.assertEqual(hash160(data), expected)

    def test_hash160_returns_20_bytes(self):
        self.assertEqual(len(hash160(b"key")), 20)


class TestBase58(unittest.TestCase):
    """Tests for Base58 encoding / decoding with NexaFlow alphabet."""

    def test_roundtrip_simple(self):
        payload = b"\x01\x02\x03\x04"
        encoded = base58_encode(payload)
        decoded = base58_decode(encoded)
        # Decoded may have different leading zeros; check value equivalence
        self.assertEqual(int.from_bytes(decoded, "big"),
                         int.from_bytes(payload, "big"))

    def test_encode_single_zero(self):
        # A single zero byte should encode to the first alphabet char
        encoded = base58_encode(b"\x00")
        self.assertTrue(len(encoded) >= 1)
        # First char should be 'r' (NexaFlow alphabet[0])
        self.assertEqual(encoded[0], "r")

    def test_encode_preserves_leading_zeros(self):
        payload = b"\x00\x00\x01"
        encoded = base58_encode(payload)
        # Should start with two 'r's for the two leading zero bytes
        self.assertTrue(encoded.startswith("rr"))

    def test_decode_then_encode_roundtrip(self):
        original = b"\x00\x05\x10\x20\x40"
        encoded = base58_encode(original)
        decoded = base58_decode(encoded)
        self.assertEqual(decoded, original)

    def test_encode_large_payload(self):
        payload = bytes(range(256)) * 2
        encoded = base58_encode(payload)
        self.assertIsInstance(encoded, str)
        self.assertTrue(len(encoded) > 0)

    def test_base58check_roundtrip(self):
        payload = b"\xab\xcd\xef" * 5
        encoded = base58check_encode(0, payload)
        decoded = base58check_decode(encoded)
        self.assertEqual(decoded, payload)

    def test_base58check_bad_checksum_raises(self):
        payload = b"\x01\x02\x03"
        encoded = base58check_encode(0, payload)
        # Corrupt last character
        chars = list(encoded)
        chars[-1] = "r" if chars[-1] != "r" else "p"
        corrupted = "".join(chars)
        with self.assertRaises(ValueError):
            base58check_decode(corrupted)

    def test_base58check_version_byte_stripped(self):
        payload = hash160(b"some public key")
        encoded = base58check_encode(0, payload)
        decoded = base58check_decode(encoded)
        self.assertEqual(decoded, payload)


class TestECDSA(unittest.TestCase):
    """Tests for ECDSA key generation, signing, and verification."""

    def test_generate_keypair_lengths(self):
        priv, pub = generate_keypair()
        self.assertEqual(len(priv), 32)  # secp256k1 private key
        self.assertEqual(len(pub), 65)   # 0x04 + 64 bytes uncompressed

    def test_generate_keypair_prefix(self):
        _, pub = generate_keypair()
        self.assertEqual(pub[0:1], b"\x04")

    def test_generate_keypair_uniqueness(self):
        pair1 = generate_keypair()
        pair2 = generate_keypair()
        self.assertNotEqual(pair1[0], pair2[0])

    def test_sign_returns_bytes(self):
        priv, _ = generate_keypair()
        msg_hash = sha256(b"message")
        sig = sign(priv, msg_hash)
        self.assertIsInstance(sig, bytes)
        self.assertTrue(len(sig) > 0)

    def test_sign_and_verify_valid(self):
        priv, pub = generate_keypair()
        msg_hash = sha256(b"transaction data")
        sig = sign(priv, msg_hash)
        self.assertTrue(verify(pub, msg_hash, sig))

    def test_verify_wrong_message_fails(self):
        priv, pub = generate_keypair()
        msg_hash = sha256(b"correct message")
        wrong_hash = sha256(b"wrong message")
        sig = sign(priv, msg_hash)
        self.assertFalse(verify(pub, wrong_hash, sig))

    def test_verify_wrong_key_fails(self):
        priv1, _ = generate_keypair()
        _, pub2 = generate_keypair()
        msg_hash = sha256(b"message")
        sig = sign(priv1, msg_hash)
        self.assertFalse(verify(pub2, msg_hash, sig))

    def test_sign_different_messages_different_sigs(self):
        priv, _ = generate_keypair()
        sig1 = sign(priv, sha256(b"msg1"))
        sig2 = sign(priv, sha256(b"msg2"))
        self.assertNotEqual(sig1, sig2)

    def test_sign_deterministic_message_verifiable(self):
        """Sign the same hash twice — both signatures should verify."""
        priv, pub = generate_keypair()
        msg = sha256(b"deterministic")
        sig1 = sign(priv, msg)
        sig2 = sign(priv, msg)
        self.assertTrue(verify(pub, msg, sig1))
        self.assertTrue(verify(pub, msg, sig2))


class TestAddressDerivation(unittest.TestCase):
    """Tests for NexaFlow-style address derivation."""

    def test_derive_address_starts_with_r(self):
        _, pub = generate_keypair()
        addr = derive_address(pub)
        self.assertTrue(addr.startswith("r"))

    def test_derive_address_deterministic(self):
        _, pub = generate_keypair()
        addr1 = derive_address(pub)
        addr2 = derive_address(pub)
        self.assertEqual(addr1, addr2)

    def test_derive_address_different_keys_different_addrs(self):
        _, pub1 = generate_keypair()
        _, pub2 = generate_keypair()
        self.assertNotEqual(derive_address(pub1), derive_address(pub2))

    def test_derive_address_reasonable_length(self):
        _, pub = generate_keypair()
        addr = derive_address(pub)
        # NexaFlow addresses are typically 25-35 chars
        self.assertGreater(len(addr), 20)
        self.assertLess(len(addr), 40)


class TestNonceAndTxId(unittest.TestCase):
    """Tests for nonce and tx-id generation."""

    def test_generate_nonce_default_length(self):
        nonce = generate_nonce()
        self.assertEqual(len(nonce), 32)

    def test_generate_nonce_custom_length(self):
        nonce = generate_nonce(16)
        self.assertEqual(len(nonce), 16)

    def test_generate_nonce_uniqueness(self):
        n1 = generate_nonce()
        n2 = generate_nonce()
        self.assertNotEqual(n1, n2)

    def test_generate_tx_id_hex_string(self):
        tx_id = generate_tx_id(b"some transaction blob")
        self.assertEqual(len(tx_id), 64)  # 32 bytes hex
        int(tx_id, 16)  # should parse as hex

    def test_generate_tx_id_deterministic(self):
        blob = b"same blob"
        self.assertEqual(generate_tx_id(blob), generate_tx_id(blob))

    def test_generate_tx_id_different_inputs(self):
        self.assertNotEqual(generate_tx_id(b"a"), generate_tx_id(b"b"))


class TestTimestampHelpers(unittest.TestCase):
    """Tests for NexaFlow epoch timestamp helpers."""

    NEXAFLOW_EPOCH = 946684800  # 2000-01-01 UTC

    def test_nexaflow_timestamp_positive(self):
        ts = nexaflow_timestamp()
        self.assertGreater(ts, 0)

    def test_nexaflow_timestamp_reasonable(self):
        # Should be roughly (now - 2000-01-01) in seconds
        ts = nexaflow_timestamp()
        expected_approx = int(time.time()) - self.NEXAFLOW_EPOCH
        self.assertAlmostEqual(ts, expected_approx, delta=2)

    def test_unix_from_nexaflow_roundtrip(self):
        rts = nexaflow_timestamp()
        unix_ts = unix_from_nexaflow(rts)
        self.assertAlmostEqual(unix_ts, time.time(), delta=2)

    def test_unix_from_nexaflow_epoch_zero(self):
        unix_ts = unix_from_nexaflow(0)
        self.assertAlmostEqual(unix_ts, self.NEXAFLOW_EPOCH, delta=1)


if __name__ == "__main__":
    unittest.main()
