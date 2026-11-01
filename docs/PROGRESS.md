# Checkpoint 2 — Progress Note (Password Manager)

## Implemented
| Requirement | Where | How |
|---|---|---|
| Basic vault storage | `src/storage/vault_file.py` | Versioned JSON container (DESIGN.md §3); atomic write (temp file → fsync → rename); owner-only file mode; size/format/version validation on load |
| Credentials encrypted at rest | `src/crypto/engine.py`, `src/user/vault.py` | Argon2id (64 MiB, t=3, p=4) → AES-256-GCM over the whole entry list; fresh random 96-bit nonce on every save |
| Master password authentication | `src/user/vault.py`, `src/interface/cli.py` | Vault unlocks only if the GCM tag verifies (no stored hash); min. length check at `init`; 3 attempts per run with 1 s/2 s backoff |
| Interface never prints passwords | `src/interface/cli.py` | `getpass` for all secrets, never CLI args; `get` masks the password unless `--reveal`; entry fields validated (length, control characters) |
| Build/run instructions | `README.md` | Tested from a clean venv |
| Tests | `tests/` | 27 unit tests: crypto, storage, vault logic, tamper cases, CLI flow |

## Changes versus the Checkpoint 1 design
- **Header authenticated as AAD.** DESIGN.md noted that the GCM tag did not cover the header. The version, KDF parameters and salt are now passed to AES-GCM as associated data, so altering them makes decryption fail.
- **KDF parameter bounds.** Vault headers outside a safe range (memory 19 MiB–1 GiB, iterations 2–10, parallelism 1–16) are rejected, which prevents downgrade and resource-exhaustion via a tampered file.
- **Per-command unlock instead of a persistent session.** Each CLI invocation is a separate process, so `unlock`/`lock` as session commands would need a background process or a session file holding key material. For now every command prompts for the master password and locks (zeroes) on exit; `unlock` only verifies the password.
- `encrypt` returns `(nonce, ciphertext+tag)` as produced by the library rather than a separate tag.

## Known limitations / next steps
- Python cannot guarantee memory zeroing (immutable `str`/`bytes` copies); documented under T7.
- Attempt counter is per process, not persisted (a persisted counter in the vault file would be attacker-editable).
- Not yet done: clipboard copy with auto-clear (T10), `mlock` (T8), password generator, interactive session mode, automated CI.
