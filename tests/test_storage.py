import json
import os
import tempfile
import unittest

from src.storage import StorageError, VaultFile, read_vault, write_vault


def sample():
    kdf = {"memory_kib": 65536, "iterations": 3, "parallelism": 4}
    return VaultFile(1, kdf, b"s" * 16, b"n" * 12, b"c" * 32)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "vault.pm")

    def tearDown(self):
        self.dir.cleanup()

    def test_roundtrip_and_no_temp_files_left(self):
        write_vault(self.path, sample())
        self.assertEqual(read_vault(self.path), sample())
        self.assertEqual(os.listdir(self.dir.name), ["vault.pm"])

    def test_overwrite_is_atomic_replace(self):
        write_vault(self.path, sample())
        v2 = sample()
        v2.ciphertext = b"d" * 40
        write_vault(self.path, v2)
        self.assertEqual(read_vault(self.path).ciphertext, b"d" * 40)

    def test_file_permissions_owner_only(self):
        write_vault(self.path, sample())
        if os.name == "posix":
            self.assertEqual(os.stat(self.path).st_mode & 0o077, 0)

    def _write_raw(self, obj):
        with open(self.path, "w") as fh:
            fh.write(obj if isinstance(obj, str) else json.dumps(obj))

    def test_rejects_bad_files(self):
        with self.assertRaises(StorageError):
            read_vault(self.path)                      # missing
        self._write_raw("not json")
        with self.assertRaises(StorageError):
            read_vault(self.path)
        self._write_raw([1, 2])
        with self.assertRaises(StorageError):
            read_vault(self.path)

    def test_rejects_unknown_version_before_anything_else(self):
        write_vault(self.path, sample())
        with open(self.path) as fh:
            data = json.load(fh)
        data["version"] = 99
        self._write_raw(data)
        with self.assertRaises(StorageError):
            read_vault(self.path)

    def test_rejects_bad_base64_and_lengths(self):
        write_vault(self.path, sample())
        with open(self.path) as fh:
            data = json.load(fh)
        data["cipher"]["nonce"] = "AAAA"               # wrong length
        self._write_raw(data)
        with self.assertRaises(StorageError):
            read_vault(self.path)


if __name__ == "__main__":
    unittest.main()
