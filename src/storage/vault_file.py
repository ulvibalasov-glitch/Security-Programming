"""Storage layer: the ONLY place that touches the filesystem.

Reads/writes the versioned JSON container from DESIGN.md section 3.
Never sees plaintext or the master password.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from dataclasses import dataclass

FORMAT_VERSION = 1
MAX_VAULT_BYTES = 10 * 1024 * 1024   # refuse absurdly large files
_SALT_LEN = 16
_NONCE_LEN = 12
_TAG_LEN = 16


class StorageError(Exception):
    """The vault file is missing, unreadable, malformed or unsupported."""


@dataclass
class VaultFile:
    version: int
    kdf: dict          # memory_kib / iterations / parallelism (ints)
    salt: bytes
    nonce: bytes
    ciphertext: bytes  # AES-GCM ciphertext + tag


def vault_exists(path: str) -> bool:
    return os.path.isfile(path)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value, expected_len: int | None, field: str) -> bytes:
    if not isinstance(value, str):
        raise StorageError(f"vault field '{field}' must be a string")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise StorageError(f"vault field '{field}' is not valid base64") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise StorageError(f"vault field '{field}' has the wrong length")
    return raw


def read_vault(path: str) -> VaultFile:
    if not os.path.isfile(path):
        raise StorageError(f"no vault file at '{path}'")
    try:
        if os.path.getsize(path) > MAX_VAULT_BYTES:
            raise StorageError("vault file is unreasonably large")
        with open(path, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StorageError(f"cannot read vault file: {exc}") from exc

    if not isinstance(data, dict):
        raise StorageError("vault file is malformed")
    # Version is checked BEFORE any decryption is attempted (T5).
    if data.get("version") != FORMAT_VERSION or isinstance(data.get("version"), bool):
        raise StorageError(f"unsupported vault format version: {data.get('version')!r}")

    kdf = data.get("kdf")
    cipher = data.get("cipher")
    if not isinstance(kdf, dict) or not isinstance(cipher, dict):
        raise StorageError("vault file is malformed")
    if kdf.get("algorithm") != "argon2id" or cipher.get("algorithm") != "AES-256-GCM":
        raise StorageError("unsupported algorithm in vault file")

    salt = _unb64(kdf.get("salt"), _SALT_LEN, "kdf.salt")
    nonce = _unb64(cipher.get("nonce"), _NONCE_LEN, "cipher.nonce")
    ciphertext = _unb64(data.get("ciphertext"), None, "ciphertext")
    if len(ciphertext) < _TAG_LEN:
        raise StorageError("vault ciphertext is too short")

    params = {k: kdf.get(k) for k in ("memory_kib", "iterations", "parallelism")}
    return VaultFile(FORMAT_VERSION, params, salt, nonce, ciphertext)


def write_vault(path: str, vault: VaultFile) -> None:
    """Atomic write: temp file in same dir -> fsync -> rename over original."""
    document = {
        "version": vault.version,
        "kdf": {"algorithm": "argon2id", "salt": _b64(vault.salt), **vault.kdf},
        "cipher": {"algorithm": "AES-256-GCM", "nonce": _b64(vault.nonce)},
        "ciphertext": _b64(vault.ciphertext),
    }
    payload = json.dumps(document, indent=2).encode("utf-8")

    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".vault-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:      # mkstemp creates the file as 0600
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    if hasattr(os, "O_DIRECTORY"):           # make the rename itself durable (POSIX)
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
