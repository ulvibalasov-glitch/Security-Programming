# Design Document — Checkpoint 1

## 1. Architecture

Three modules, each with a narrow responsibility, so that a compromise or bug
in one has a bounded blast radius:

```
                    +-------------------+
                    |     Interface     |   (CLI commands)
                    |  init/unlock/get/ |
                    |  add/edit/remove  |
                    +---------+---------+
                              |
                              v
                    +-------------------+
                    |  User Management  |
                    |-------------------|
                    | - master password |
                    |   setup/verify    |
                    | - session state   |
                    |   (locked/        |
                    |    unlocked)      |
                    | - failed-attempt  |
                    |   counter         |
                    +----+---------+----+
                         |         |
              derive_key |         | decrypted entries
              (password, |         | (in-memory only,
               salt)     |         |  while unlocked)
                         v         ^
                 +-------------------+
                 |    Encryption      |
                 |--------------------|
                 | - Argon2id KDF     |
                 | - AES-256-GCM      |
                 |   encrypt/decrypt  |
                 | - CSPRNG salt/     |
                 |   nonce generation |
                 +----+----------+----+
                      |          ^
        ciphertext +  |          | ciphertext + header
        header to     |          | read from disk
        write         v          |
                 +-------------------+
                 |     Storage        |
                 |--------------------|
                 | - read/write vault |
                 |   file             |
                 | - atomic write     |
                 |   (temp + rename)  |
                 | - format version   |
                 |   checks           |
                 +--------------------+
                          |
                          v
                     vault.pm (disk)
```

**Encryption module** — the only place that touches cryptographic primitives.
Exposes `derive_key(password, salt, params) -> key`, `encrypt(key, plaintext)
-> (nonce, ciphertext, tag)`, `decrypt(key, nonce, ciphertext, tag) ->
plaintext`. Never touches the filesystem and never sees the master password's
origin (interface vs. test harness) — it just takes bytes in and returns
bytes out.

**User management module** — owns the notion of "is the vault currently
unlocked." Handles first-run setup (generate salt + KDF params, call
Encryption to produce the initial empty encrypted vault), unlock (take the
typed password, ask Encryption to derive a key and decrypt, treat successful
AEAD decryption as proof of a correct password rather than storing a separate
password hash), session lifetime, lock (tell Encryption module to zero the
key), and a failed-attempt counter for lockout/backoff.

**Storage layer** — the only place that touches the filesystem. Reads the
vault file into a header (version, KDF params, salt, nonce) plus a ciphertext
blob, and writes updated versions atomically (write to a temp file, `fsync`,
rename over the original) so a crash mid-write can't corrupt or truncate the
vault. It never sees plaintext and never sees the master password.

### Data flow

1. **Startup / unlock**: Interface → Storage reads `vault.pm` off disk →
   returns header + ciphertext to User Management. User types master
   password → User Management → Encryption `derive_key(password, salt)` →
   Encryption `decrypt(key, ciphertext, nonce, tag)`. If the AEAD tag
   verifies, the plaintext entry list is held in memory by User Management
   for the session; if it fails, nothing is decrypted and the failed-attempt
   counter increments.
2. **Read (`get`/`list`)**: Interface asks User Management for the in-memory
   entries (only while unlocked); nothing touches Encryption or Storage.
3. **Write (`add`/`edit`/`remove`)**: Interface updates the in-memory entry
   list via User Management → User Management asks Encryption to serialize
   and re-encrypt the *entire* entry list with a fresh random nonce →
   Storage writes the new header + ciphertext atomically to disk.
4. **Lock/exit**: User Management tells Encryption to zero the derived key
   and zeroes the in-memory plaintext entry list.

## 2. Threat model

Assets: the master password, the vault file at rest, the decrypted vault
while the program is running, and the CLI surface the user interacts with.
Attacker is assumed to *not* currently control the running process (no
active malware with code-execution rights) — that's an accepted-risk boundary
stated explicitly below, since defending against a fully compromised endpoint
is out of scope for this project.

| # | Threat | Asset | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | Offline brute-force / dictionary attack on a stolen vault, guessing the master password | Master password | Argon2id KDF with memory-hard parameters (target ≥64 MiB memory, tuned so derivation takes ~300–500 ms on reference hardware) makes each guess expensive | Still feasible against very weak passwords; no KDF fixes a 4-digit PIN |
| T2 | User chooses a weak/guessable master password | Master password | Minimum length/entropy check at `init` time; recommend a passphrase | Can't force good judgment; user can bypass advisory checks |
| T3 | Keylogger or screen-scraping malware captures the password as it's typed | Master password | Out of scope — requires a trusted endpoint; documented as an accepted risk | Full compromise of the master password if the endpoint is malicious |
| T4 | Theft or copy of the vault file (stolen laptop, leaked backup, synced cloud folder) | Vault at rest | AES-256-GCM: without the key, ciphertext is semantically secure — no entry data leaks | Metadata (vault exists, its size, last-modified time) still leaks |
| T5 | Tampering with the vault file (bit flip, malicious edit, downgrade to an older/weaker format) | Vault at rest | GCM authentication tag: any modification causes decryption to fail closed, so a tampered vault is never silently accepted; format version is checked before decrypt | A rejected vault is unusable until restored from backup — no partial recovery |
| T6 | Nonce reuse under AES-GCM (catastrophic: breaks confidentiality and authenticity) | Vault at rest | A fresh CSPRNG-generated 96-bit nonce is generated on every full-vault re-encryption; whole-vault re-encryption (rather than incremental per-field updates) keeps nonce management simple and avoids counter-reuse bugs | Relies on the CSPRNG; extremely low practical risk |
| T7 | Decrypted vault or derived key exposed via memory dump, core dump, or crash report | Vault in memory | Explicit zeroing of key/plaintext buffers after use and on lock; disable core dumps for the process where the OS allows it; keep plaintext lifetime as short as possible | Language/runtime limits (e.g., garbage-collected copies, string interning) mean zeroing isn't always guaranteed — documented limitation |
| T8 | Decrypted data swapped to disk by the OS | Vault in memory | Attempt to lock sensitive memory pages (e.g., `mlock`/`VirtualLock`) where the platform and runtime support it | Not guaranteed on all platforms/runtimes; treated as defense-in-depth, not a hard guarantee |
| T9 | Debugger or `ptrace` attached to the running process reads memory directly | Vault in memory | Out of scope for Checkpoint 1 — requires OS-level process protections beyond this project's scope; documented as accepted risk | Full exposure of in-memory secrets if this occurs |
| T10 | Clipboard sniffing after copying a password out of the manager | Interface | Auto-clear the clipboard after a short timeout (~20–30 s) following a copy | A fast attacker or clipboard-monitoring malware within the window still succeeds |
| T11 | Shoulder-surfing or screen capture while a password is displayed | Interface | Passwords masked by default; explicit `--reveal` flag required to print in plaintext | User can still choose to reveal in an unsafe environment |
| T12 | Secrets passed as CLI arguments, visible to any local user via the process list (`ps`) | Interface | Never accept passwords/master password as command-line arguments; always prompt interactively (stdin, not echoed) | None significant if enforced consistently across all commands |
| T13 | Secrets leaked into shell history or application logs | Interface | No logging of plaintext secrets at any log level; document that users should be aware of shell history when scripting around the tool | Shell history risk remains if a user manually types a secret into an unrelated command |
| T14 | Malformed/adversarial input in an entry field (e.g., a note breaking the serialization format) | Interface | Strict, well-defined serialization (JSON with proper escaping, explicit field length limits) and input validation before an entry is accepted | Standard input-validation risk if a new field type is added without the same care |

## 3. Vault format and cryptographic scheme (initial decision)

**Format** — a single versioned container, e.g.:

```json
{
  "version": 1,
  "kdf": {
    "algorithm": "argon2id",
    "salt": "<base64, 16 bytes>",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 4
  },
  "cipher": {
    "algorithm": "AES-256-GCM",
    "nonce": "<base64, 12 bytes>"
  },
  "ciphertext": "<base64>"
}
```

`ciphertext` is the AES-256-GCM encryption (ciphertext + 16-byte auth tag) of
the JSON-serialized entry list. Header fields (`kdf`, `cipher.nonce`,
`version`) are stored in the clear alongside the ciphertext — they're
parameters, not secrets, and GCM's tag covers the ciphertext they were used
to produce, not the header itself, so `version` is checked by the loader
before any decryption is attempted.

**Why whole-vault AEAD rather than per-entry encryption**: at this project's
scale (a personal vault, dozens to low hundreds of entries), re-encrypting
the entire serialized entry list on every change is cheap, and it keeps
nonce management trivial — one fresh random nonce per save, no per-entry
nonce bookkeeping to get wrong. Per-entry encryption would reduce how much
ciphertext needs re-writing per change and could support partial/streaming
reads, but adds real complexity (a nonce per entry, more surface for reuse
bugs) that isn't justified yet. Documented here as a candidate for revisit if
a later checkpoint needs large-vault performance or partial updates.

**Why Argon2id**: memory-hard, resistant to GPU/ASIC parallelization, and the
"id" variant mixes data-dependent and data-independent access patterns,
which is the current recommended default for password hashing/KDF use
(over PBKDF2 or scrypt) per OWASP guidance.

**Why AES-256-GCM**: authenticated encryption in one primitive — confidentiality
and integrity/tamper-detection together (T4 and T5 above), widely available
in standard libraries, and fast enough that whole-vault re-encryption on
every save is not a noticeable delay for this project's scale.

**Password verification**: no separate password hash/verifier is stored.
Successful AEAD decryption (i.e., the GCM tag verifies) *is* the check that
the entered password was correct. This avoids keeping a second, potentially
weaker, verification artifact next to the vault.
