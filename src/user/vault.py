"""User management module: master-password auth + unlocked-vault state.

Password verification has no stored hash: if the AES-GCM tag verifies, the
password was correct (DESIGN.md section 3).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

from ..crypto import (
    CryptoError,
    DecryptionError,
    KdfParams,
    decrypt,
    derive_key,
    encrypt,
    new_salt,
    zero,
)
from ..storage import (
    FORMAT_VERSION,
    StorageError,
    VaultFile,
    read_vault,
    vault_exists,
    write_vault,
)

MIN_PASSWORD_LEN = 12

# Field length limits (T14: strict validation before an entry is accepted).
FIELD_LIMITS = {
    "title": 100,
    "username": 200,
    "password": 1024,
    "url": 500,
    "notes": 2000,
}
ENTRY_FIELDS = tuple(FIELD_LIMITS)


class VaultError(Exception):
    """Generic vault failure (corrupt file, already exists, ...)."""


class WeakPasswordError(VaultError):
    pass


class WrongPasswordError(VaultError):
    """GCM tag failed: wrong master password OR tampered vault."""


class VaultLockedError(VaultError):
    pass


class EntryError(VaultError):
    pass


def check_master_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise WeakPasswordError(
            f"master password must be at least {MIN_PASSWORD_LEN} characters "
            "(a passphrase of several words works well)"
        )
    if len(set(password)) < 5:
        raise WeakPasswordError("master password is too repetitive")


def validate_field(name: str, value) -> str:
    if not isinstance(value, str):
        raise EntryError(f"{name} must be text")
    if name == "title":
        value = value.strip()
        if not value:
            raise EntryError("title must not be empty")
    if name == "password" and not value:
        raise EntryError("password must not be empty")
    if len(value) > FIELD_LIMITS[name]:
        raise EntryError(f"{name} is too long (max {FIELD_LIMITS[name]} characters)")
    allowed = "\n" if name == "notes" else ""
    for ch in value:
        if (ord(ch) < 32 and ch not in allowed) or ord(ch) == 127:
            raise EntryError(f"{name} contains control characters")
    return value


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _aad(version: int, kdf: dict, salt: bytes) -> bytes:
    """Bind the plaintext header to the ciphertext so KDF params/version
    cannot be altered without making decryption fail."""
    header = {"version": version, "kdf": kdf, "salt": salt.hex()}
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")


class Vault:
    def __init__(self, path: str):
        self._path = path
        self._key: bytearray | None = None
        self._entries: list[dict] | None = None
        self._header: VaultFile | None = None

    # ---- lifecycle -------------------------------------------------------
    @classmethod
    def create(cls, path: str, password: str, kdf: KdfParams | None = None) -> "Vault":
        check_master_password(password)
        if vault_exists(path):
            raise VaultError(f"a vault already exists at '{path}' (refusing to overwrite)")
        params = kdf or KdfParams()
        params.validate()
        vault = cls(path)
        salt = new_salt()
        vault._key = derive_key(password.encode("utf-8"), salt, params)
        vault._entries = []
        vault._header = VaultFile(FORMAT_VERSION, params.to_dict(), salt, b"", b"")
        vault._save()
        return vault

    def unlock(self, password: str) -> None:
        try:
            header = read_vault(self._path)
            params = KdfParams.from_dict(header.kdf)
        except (StorageError, CryptoError) as exc:
            raise VaultError(f"vault cannot be opened: {exc}") from exc

        key = derive_key(password.encode("utf-8"), header.salt, params)
        try:
            plaintext = decrypt(
                key, header.nonce, header.ciphertext,
                _aad(header.version, header.kdf, header.salt),
            )
        except DecryptionError as exc:
            zero(key)
            raise WrongPasswordError("wrong master password (or vault was modified)") from exc

        try:
            entries = json.loads(plaintext.decode("utf-8"))
            if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
                raise ValueError
        except (UnicodeDecodeError, ValueError) as exc:
            zero(key)
            raise VaultError("vault contents are malformed") from exc

        self._key, self._entries, self._header = key, entries, header

    def lock(self) -> None:
        zero(self._key)
        self._key = None
        if self._entries is not None:
            for entry in self._entries:
                entry.clear()
            self._entries.clear()
        self._entries = None

    @property
    def is_unlocked(self) -> bool:
        return self._key is not None and self._entries is not None

    def _require_unlocked(self) -> list[dict]:
        if not self.is_unlocked:
            raise VaultLockedError("vault is locked")
        return self._entries  # type: ignore[return-value]

    # ---- persistence -----------------------------------------------------
    def _save(self) -> None:
        """Re-encrypt the WHOLE entry list with a fresh nonce, then write atomically."""
        assert self._key is not None and self._entries is not None and self._header is not None
        h = self._header
        plaintext = json.dumps(self._entries, sort_keys=True).encode("utf-8")
        nonce, ciphertext = encrypt(self._key, plaintext, _aad(h.version, h.kdf, h.salt))
        new_header = VaultFile(h.version, h.kdf, h.salt, nonce, ciphertext)
        write_vault(self._path, new_header)
        self._header = new_header

    # ---- entries ---------------------------------------------------------
    def _find(self, title: str) -> dict | None:
        wanted = title.strip().casefold()
        for entry in self._require_unlocked():
            if entry["title"].casefold() == wanted:
                return entry
        return None

    def has(self, title: str) -> bool:
        return self._find(title) is not None

    def titles(self) -> list[str]:
        return sorted((e["title"] for e in self._require_unlocked()), key=str.casefold)

    def get(self, title: str) -> dict:
        entry = self._find(title)
        if entry is None:
            raise EntryError(f"no entry titled '{title}'")
        return dict(entry)

    def add(self, **fields: str) -> None:
        entries = self._require_unlocked()
        clean = {name: validate_field(name, fields.get(name, "")) for name in ENTRY_FIELDS}
        if self._find(clean["title"]) is not None:
            raise EntryError(f"an entry titled '{clean['title']}' already exists")
        clean["modified"] = _now()
        entries.append(clean)
        self._save()

    def update(self, current_title: str, /, **changes: str) -> None:
        entry = self._find(current_title)
        if entry is None:
            raise EntryError(f"no entry titled '{current_title}'")
        unknown = set(changes) - set(ENTRY_FIELDS)
        if unknown:
            raise EntryError(f"unknown field(s): {', '.join(sorted(unknown))}")
        clean = {name: validate_field(name, value) for name, value in changes.items()}
        new_title = clean.get("title")
        if new_title is not None:
            other = self._find(new_title)
            if other is not None and other is not entry:
                raise EntryError(f"an entry titled '{new_title}' already exists")
        entry.update(clean)
        entry["modified"] = _now()
        self._save()

    def remove(self, title: str) -> None:
        entry = self._find(title)
        if entry is None:
            raise EntryError(f"no entry titled '{title}'")
        self._require_unlocked().remove(entry)
        self._save()
