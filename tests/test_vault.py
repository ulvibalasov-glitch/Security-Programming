import base64
import json
import os
import tempfile
import unittest

from src.crypto import KdfParams
from src.user import (
    EntryError, Vault, VaultError, VaultLockedError, WeakPasswordError, WrongPasswordError,
)

FAST = KdfParams(memory_kib=19_456, iterations=2, parallelism=1)
MASTER = "correct horse battery staple"


def load(path):
    with open(path) as fh:
        return json.load(fh)


def dump(obj, path):
    with open(path, "w") as fh:
        json.dump(obj, fh)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "vault.pm")

    def tearDown(self):
        self.dir.cleanup()

    def make(self):
        return Vault.create(self.path, MASTER, FAST)

    def reopen(self, password=MASTER):
        v = Vault(self.path)
        v.unlock(password)
        return v

    def test_weak_master_password_rejected(self):
        for bad in ("short", "aaaaaaaaaaaaaaaa"):
            with self.assertRaises(WeakPasswordError):
                Vault.create(self.path, bad, FAST)
        self.assertFalse(os.path.exists(self.path))

    def test_create_refuses_to_overwrite(self):
        self.make().lock()
        with self.assertRaises(VaultError):
            Vault.create(self.path, MASTER, FAST)

    def test_unlock_only_with_correct_password(self):
        self.make().lock()
        with self.assertRaises(WrongPasswordError):
            self.reopen("wrong password entirely")
        self.assertTrue(self.reopen().is_unlocked)

    def test_locked_vault_gives_no_access(self):
        v = self.make()
        v.lock()
        with self.assertRaises(VaultLockedError):
            v.titles()

    def test_entries_persist_and_file_has_no_plaintext(self):
        v = self.make()
        v.add(title="example.com", username="ulvi", password="S3cretPassw0rd!",
              url="https://example.com", notes="my note")
        v.lock()
        with open(self.path, "rb") as fh:
            raw = fh.read()
        for needle in (b"example.com", b"ulvi", b"S3cretPassw0rd", b"my note"):
            self.assertNotIn(needle, raw)
        entry = self.reopen().get("EXAMPLE.com")        # case-insensitive lookup
        self.assertEqual(entry["password"], "S3cretPassw0rd!")

    def test_fresh_nonce_on_every_save(self):
        v = self.make()
        n1 = load(self.path)["cipher"]["nonce"]
        v.add(title="a", username="u", password="p")
        n2 = load(self.path)["cipher"]["nonce"]
        v.add(title="b", username="u", password="p")
        n3 = load(self.path)["cipher"]["nonce"]
        self.assertEqual(len({n1, n2, n3}), 3)

    def test_update_and_remove(self):
        v = self.make()
        v.add(title="a", username="u", password="p1")
        v.update("a", password="p2", title="a2")
        self.assertEqual(self.reopen().get("a2")["password"], "p2")
        v = self.reopen()
        v.remove("a2")
        self.assertEqual(self.reopen().titles(), [])

    def test_duplicates_and_missing_entries(self):
        v = self.make()
        v.add(title="a", username="u", password="p")
        with self.assertRaises(EntryError):
            v.add(title="A", username="u", password="p")
        with self.assertRaises(EntryError):
            v.get("nope")
        with self.assertRaises(EntryError):
            v.remove("nope")

    def test_input_validation(self):
        v = self.make()
        bad = [
            dict(title="", username="u", password="p"),
            dict(title="t\x1b[31m", username="u", password="p"),
            dict(title="t", username="u", password=""),
            dict(title="t", username="u" * 201, password="p"),
            dict(title="t", username="u", password="p", notes="x" * 2001),
        ]
        for fields in bad:
            with self.assertRaises(EntryError, msg=str(fields)[:40]):
                v.add(**fields)

    def test_tampered_ciphertext_and_header_fail_closed(self):
        self.make().lock()
        data = load(self.path)

        tampered = json.loads(json.dumps(data))
        ct = bytearray(base64.b64decode(tampered["ciphertext"]))
        ct[0] ^= 1
        tampered["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        dump(tampered, self.path)
        with self.assertRaises(WrongPasswordError):
            self.reopen()

        # header (KDF params) is authenticated as AAD: changing it must fail
        header_tamper = json.loads(json.dumps(data))
        header_tamper["kdf"]["iterations"] = 5
        dump(header_tamper, self.path)
        with self.assertRaises(WrongPasswordError):
            self.reopen()

    def test_downgraded_kdf_params_rejected(self):
        self.make().lock()
        data = load(self.path)
        data["kdf"]["memory_kib"] = 8
        dump(data, self.path)
        with self.assertRaises(VaultError):
            self.reopen()


if __name__ == "__main__":
    unittest.main()
