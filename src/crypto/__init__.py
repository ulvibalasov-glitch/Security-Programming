"""
Encryption module.

Owns all cryptographic primitives: Argon2id key derivation and
AES-256-GCM authenticated encryption/decryption. Never touches the
filesystem and never sees where the master password came from.

Planned interface:
    derive_key(password: bytes, salt: bytes, params: dict) -> bytes
    encrypt(key: bytes, plaintext: bytes) -> tuple[nonce, ciphertext, tag]
    decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes
"""
