import unittest

from src.crypto import (
    CryptoError, DecryptionError, KdfParams, decrypt, derive_key, encrypt, new_salt, zero,
)

FAST = KdfParams(memory_kib=19_456, iterations=2, parallelism=1)


class CryptoTests(unittest.TestCase):
    def test_derive_key_is_deterministic_and_salt_dependent(self):
        salt = new_salt()
        k1 = derive_key(b"pw", salt, FAST)
        self.assertEqual(k1, derive_key(b"pw", salt, FAST))
        self.assertNotEqual(k1, derive_key(b"pw", new_salt(), FAST))
        self.assertNotEqual(k1, derive_key(b"other", salt, FAST))
        self.assertEqual(len(k1), 32)

    def test_roundtrip(self):
        key = derive_key(b"pw", new_salt(), FAST)
        nonce, ct = encrypt(key, b"secret data", b"aad")
        self.assertNotIn(b"secret data", ct)
        self.assertEqual(decrypt(key, nonce, ct, b"aad"), b"secret data")

    def test_nonce_is_fresh_every_time(self):
        key = derive_key(b"pw", new_salt(), FAST)
        nonces = {encrypt(key, b"x")[0] for _ in range(50)}
        self.assertEqual(len(nonces), 50)

    def test_wrong_key_tamper_and_aad_fail_closed(self):
        key = derive_key(b"pw", new_salt(), FAST)
        nonce, ct = encrypt(key, b"data", b"aad")
        with self.assertRaises(DecryptionError):
            decrypt(derive_key(b"bad", new_salt(), FAST), nonce, ct, b"aad")
        flipped = bytes([ct[0] ^ 1]) + ct[1:]
        with self.assertRaises(DecryptionError):
            decrypt(key, nonce, flipped, b"aad")
        with self.assertRaises(DecryptionError):
            decrypt(key, nonce, ct, b"different-aad")

    def test_kdf_bounds_enforced(self):
        with self.assertRaises(CryptoError):
            KdfParams(memory_kib=1024, iterations=1, parallelism=1).validate()
        with self.assertRaises(CryptoError):
            KdfParams.from_dict({"memory_kib": 10**9, "iterations": 3, "parallelism": 4})
        with self.assertRaises(CryptoError):
            KdfParams.from_dict({"memory_kib": "big"})

    def test_zero(self):
        buf = bytearray(b"abc")
        zero(buf)
        self.assertEqual(buf, bytearray(3))


if __name__ == "__main__":
    unittest.main()
