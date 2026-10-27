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

## Commands

Passwords are never passed as arguments; they are always prompted (no echo).
Each command unlocks the vault for its own duration and locks it again on exit.

| Command | Description |
|---|---|
| `init` | Create a new vault: choose a master password (min. 12 chars), generate salt + KDF params, write an empty encrypted vault. Refuses to overwrite an existing vault. |
| `unlock` | Verify the master password (3 attempts, 1 s / 2 s backoff). |
| `list` | List entry titles (no secrets shown). |
| `get <title>` | Show an entry. Password is masked unless `--reveal` is given. |
| `add <title>` | Add an entry (prompts for username / password / URL / notes). |
| `edit <title>` | Modify an entry (Enter keeps the current value). |
| `remove <title>` | Delete an entry after confirmation. |

Use `--vault PATH` (before the command) to choose another vault file; default `vault.pm`.

## Vault file

A single file (default `vault.pm`) containing a version tag, KDF parameters,
salt, nonce, and the AEAD ciphertext of the serialized entry list. Format
details and the cryptographic rationale are in `docs/DESIGN.md`.

## Build & run

Requirements: Python 3.11+, `pip`, git.

```bash
git clone <this-repo-url>
cd Security-Programming
python3 -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate
pip install -r requirements.txt   # argon2-cffi, cryptography

# first run
python -m src init
python -m src add "example.com"
python -m src list
python -m src get "example.com"            # password masked
python -m src get "example.com" --reveal   # password shown
python -m src edit "example.com"
python -m src remove "example.com"

# tests (no extra dependencies)
python -m unittest discover -v
```

## Project layout

```
src/
  crypto/      # Argon2id key derivation + AES-256-GCM encrypt/decrypt (engine.py)
  user/        # master password policy, unlock/lock state, entry validation (vault.py)
  storage/     # vault file read/write, atomic writes, format version checks (vault_file.py)
  interface/   # argparse CLI command handlers (cli.py)
docs/
  DESIGN.md    # architecture diagram, threat model, crypto/format decisions
  PROGRESS.md  # Checkpoint 2 progress note
tests/         # unittest suites for every module
```

## Status

Checkpoint 2: core requirements implemented (encrypted vault storage, master
password authentication, CLI that never prints passwords unless `--reveal`).
See `docs/PROGRESS.md`.
