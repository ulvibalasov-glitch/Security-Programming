"""Encryption module: the ONLY place that touches cryptographic primitives.

- Key derivation: Argon2id (argon2-cffi low-level API)
- Encryption: AES-256-GCM (cryptography)

It never touches the filesystem and never knows where a password came from.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32     # AES-256
SALT_LEN = 16
NONCE_LEN = 12   # 96-bit nonce, as recommended for GCM


class CryptoError(Exception):
    """Base class for crypto failures."""


class DecryptionError(CryptoError):
    """AEAD authentication failed: wrong key (password) or tampered data."""


# Accepted KDF parameter range. The floor stops a tampered vault header from
# silently downgrading the KDF; the ceiling stops a hostile header from
# making us allocate gigabytes (denial of service).
_BOUNDS = {
    "memory_kib": (19_456, 1_048_576),   # 19 MiB (OWASP minimum) .. 1 GiB
    "iterations": (2, 10),
    "parallelism": (1, 16),
}


@dataclass(frozen=True)
class KdfParams:
    memory_kib: int = 65_536   # 64 MiB, per DESIGN.md section 3
    iterations: int = 3
    parallelism: int = 4

    def validate(self) -> None:
        for name, (low, high) in _BOUNDS.items():
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool):
                raise CryptoError(f"KDF parameter {name} must be an integer")
            if not low <= value <= high:
                raise CryptoError(
                    f"KDF parameter {name}={value} outside allowed range "
                    f"{low}..{high}"
                )

    def to_dict(self) -> dict:
        return {
            "memory_kib": self.memory_kib,
            "iterations": self.iterations,
            "parallelism": self.parallelism,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "KdfParams":
        try:
            params = cls(
                memory_kib=data["memory_kib"],
                iterations=data["iterations"],
                parallelism=data["parallelism"],
            )
        except (KeyError, TypeError) as exc:
            raise CryptoError("missing or malformed KDF parameters") from exc
        params.validate()
        return params


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def derive_key(password: bytes, salt: bytes, params: KdfParams) -> bytearray:
    """Derive a 32-byte key. Returned as a bytearray so it can be zeroed."""
    params.validate()
    if len(salt) != SALT_LEN:
        raise CryptoError("salt must be 16 bytes")
    raw = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=params.iterations,
        memory_cost=params.memory_kib,
        parallelism=params.parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def encrypt(key: bytearray, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt with a fresh random nonce on EVERY call.

    Returns (nonce, ciphertext_with_16_byte_tag).
    """
    if len(key) != KEY_LEN:
        raise CryptoError("key must be 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(bytes(key)).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(key: bytearray, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """AES-256-GCM decrypt. Fails closed with DecryptionError."""
    if len(key) != KEY_LEN:
        raise CryptoError("key must be 32 bytes")
    if len(nonce) != NONCE_LEN:
        raise CryptoError("nonce must be 12 bytes")
    try:
        return AESGCM(bytes(key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc


def zero(buf: bytearray | None) -> None:
    """Best-effort overwrite of a mutable buffer (see T7 residual risk)."""
    if buf:
        buf[:] = bytes(len(buf))
