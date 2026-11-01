import contextlib
import io
import os
import tempfile
import unittest
from unittest import mock

from src.crypto import KdfParams
from src.interface import cli
from src.user import Vault

FAST = KdfParams(memory_kib=19_456, iterations=2, parallelism=1)
MASTER = "correct horse battery staple"


def run(vault_path, argv, secrets=(), texts=()):
    """Run the CLI with scripted getpass()/input() answers; return (code, out, err)."""
    out, err = io.StringIO(), io.StringIO()
    with mock.patch("getpass.getpass", side_effect=list(secrets)), \
         mock.patch("builtins.input", side_effect=list(texts)), \
         mock.patch("time.sleep"), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(["--vault", vault_path, *argv])
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.dir.name, "vault.pm")
        patcher = mock.patch.object(cli.Vault, "create", side_effect=self._fast_create)
        self._real_create = Vault.create
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self.dir.cleanup()

    def _fast_create(self, path, password, kdf=None):
        return self._real_create(path, password, FAST)

    def test_full_flow_never_prints_password_unless_revealed(self):
        code, out, _ = run(self.path, ["init"], secrets=[MASTER, MASTER])
        self.assertEqual(code, 0)

        code, out, _ = run(self.path, ["add", "example.com"],
                           secrets=[MASTER, "HunterPass#1", "HunterPass#1"],
                           texts=["ulvi", "https://example.com", "note"])
        self.assertEqual(code, 0)
        self.assertNotIn("HunterPass#1", out)

        code, out, _ = run(self.path, ["list"], secrets=[MASTER])
        self.assertIn("example.com", out)
        self.assertNotIn("HunterPass#1", out)

        code, out, _ = run(self.path, ["get", "example.com"], secrets=[MASTER])
        self.assertNotIn("HunterPass#1", out)
        self.assertIn(cli.MASK, out)

        code, out, _ = run(self.path, ["get", "example.com", "--reveal"], secrets=[MASTER])
        self.assertIn("HunterPass#1", out)

        code, out, _ = run(self.path, ["remove", "example.com"], secrets=[MASTER], texts=["y"])
        self.assertEqual(code, 0)
        code, out, _ = run(self.path, ["list"], secrets=[MASTER])
        self.assertIn("(vault is empty)", out)

    def test_wrong_master_password_three_times_fails(self):
        run(self.path, ["init"], secrets=[MASTER, MASTER])
        code, out, err = run(self.path, ["list"], secrets=["bad1", "bad2", "bad3"])
        self.assertEqual(code, 1)
        self.assertIn("too many failed attempts", err)
        self.assertEqual(out, "")

    def test_init_rejects_weak_then_accepts_strong(self):
        code, _, err = run(self.path, ["init"], secrets=["short", "short", MASTER, MASTER])
        self.assertEqual(code, 0)
        self.assertIn("at least 12", err)

    def test_missing_vault_and_bad_arguments(self):
        code, _, err = run(self.path, ["list"], secrets=[MASTER])
        self.assertEqual(code, 1)
        with self.assertRaises(SystemExit):
            run(self.path, ["get", "bad\x00title"])
        with self.assertRaises(SystemExit):
            run(os.path.join(self.dir.name, "nodir", "v.pm"), ["list"])
        with self.assertRaises(SystemExit):
            run(self.dir.name, ["list"])                # path is a directory


if __name__ == "__main__":
    unittest.main()
