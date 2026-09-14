# Password Manager — Secure Programming Course Project

A local, single-user password manager. One master password unlocks a single
encrypted vault file stored on disk. Built as coursework for the Secure
Programming module — Checkpoint 1 covers architecture, threat model, and
initial cryptographic design decisions (see `docs/DESIGN.md`).

## Scope (Checkpoint 1)

In scope:
- Single local user, single vault file, no network component, no sync.
- CLI interface only (no GUI, no browser extension).
- One master password protecting one vault.
- Storing arbitrary credential entries: title, username, password, optional
  notes/URL.

Out of scope for now (may be revisited in later checkpoints):
- Multi-user / multi-vault support.
- Cloud sync or remote storage backends.
- Browser integration / autofill.
- Defenses against a compromised endpoint (keyloggers, malware with
  ptrace/debugger access, OS-level memory forensics). These are noted as
  accepted risks in the threat model, not silently ignored.

## Planned commands

| Command | Description |
|---|---|
| `pm init` | Create a new vault: set master password, generate salt + KDF params, write empty encrypted vault. |
| `pm unlock` | Prompt for master password, derive key, decrypt vault into memory for the session. |
| `pm list` | List entry titles in the unlocked vault (no secrets shown). |
| `pm get <title>` | Show a single entry's username/password (password masked by default, `--reveal` to print). |
| `pm add <title>` | Add a new entry (prompts for username/password/notes). |
| `pm edit <title>` | Modify an existing entry. |
| `pm remove <title>` | Delete an entry. |
| `pm lock` | Zero the in-memory key/vault and end the session. |

## Vault file

A single file (default `vault.pm`) containing a version tag, KDF parameters,
salt, nonce, and the AEAD ciphertext of the serialized entry list. Format
details and the cryptographic rationale are in `docs/DESIGN.md`.

## Build & run

Requirements: Python 3.11+ (reference implementation), `pip`.

```bash
git clone <this-repo-url>
cd password-manager
python -m venv .venv
source .venv/bin/activate        # .venv\Scripts\activate on Windows
pip install -r requirements.txt  # argon2-cffi, cryptography

# first run
python -m src init
python -m src unlock
python -m src add "example.com"
python -m src list
python -m src lock
```

## Project layout

```
src/
  crypto/      # key derivation (Argon2id) + AEAD encrypt/decrypt (AES-256-GCM)
  user/        # master password setup/verification, session/lock state
  storage/     # reads/writes the vault file, atomic writes, format versioning
  interface/   # CLI command handlers
docs/
  DESIGN.md    # architecture diagram, threat model, crypto/format decisions
tests/
```

## Status

Checkpoint 1: design document + repository skeleton. No functional crypto
code yet — module boundaries and interfaces are being fixed first so the
threat model and the code stay consistent.
