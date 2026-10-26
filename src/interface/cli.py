"""Interface module: CLI command handlers.

Rules (DESIGN.md T11-T13):
- passwords are NEVER accepted as command-line arguments; always prompted
  with getpass (no echo)
- passwords are masked unless `get --reveal` is used
- nothing secret is logged
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

from ..user import (
    EntryError,
    Vault,
    VaultError,
    WeakPasswordError,
    WrongPasswordError,
)
from ..user.vault import FIELD_LIMITS, validate_field

DEFAULT_VAULT = "vault.pm"
MAX_ATTEMPTS = 3          # per invocation; delay doubles after each failure
MASK = "********"


class CliError(Exception):
    pass


# ---- argument validation (first-level input validation) -----------------
def _title_arg(value: str) -> str:
    try:
        return validate_field("title", value)
    except EntryError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def _path_arg(value: str) -> str:
    if not value or "\x00" in value:
        raise argparse.ArgumentTypeError("invalid vault path")
    if os.path.isdir(value):
        raise argparse.ArgumentTypeError("vault path is a directory")
    parent = os.path.dirname(os.path.abspath(value))
    if not os.path.isdir(parent):
        raise argparse.ArgumentTypeError(f"directory does not exist: {parent}")
    return value


# ---- prompting -----------------------------------------------------------
def _ask_secret(label: str, confirm: bool = False) -> str:
    first = getpass.getpass(f"{label}: ")
    if confirm and getpass.getpass(f"Confirm {label.lower()}: ") != first:
        raise CliError(f"{label} entries did not match")
    return first


def _open_vault(path: str) -> Vault:
    vault = Vault(path)
    for attempt in range(MAX_ATTEMPTS):
        password = _ask_secret("Master password")
        try:
            vault.unlock(password)
            return vault
        except WrongPasswordError:
            print("Wrong master password.", file=sys.stderr)
            if attempt < MAX_ATTEMPTS - 1:
                time.sleep(2 ** attempt)     # 1s, 2s backoff
    raise CliError("too many failed attempts")


# ---- commands --------------------------------------------------------------
def cmd_init(args) -> None:
    while True:
        password = _ask_secret("New master password", confirm=True)
        try:
            Vault.create(args.vault, password).lock()
            break
        except WeakPasswordError as exc:
            print(f"Rejected: {exc}", file=sys.stderr)
    print(f"Vault created at {args.vault}")


def cmd_unlock(args) -> None:
    """Verify the master password (each command unlocks for its own duration)."""
    _open_vault(args.vault).lock()
    print("Master password verified.")


def cmd_list(args) -> None:
    vault = _open_vault(args.vault)
    try:
        titles = vault.titles()
    finally:
        vault.lock()
    if not titles:
        print("(vault is empty)")
    for title in titles:
        print(title)


def cmd_get(args) -> None:
    vault = _open_vault(args.vault)
    try:
        entry = vault.get(args.title)
    finally:
        vault.lock()
    print(f"Title:    {entry['title']}")
    print(f"Username: {entry['username']}")
    if args.reveal:
        print(f"Password: {entry['password']}")
    else:
        print(f"Password: {MASK}  (use --reveal to show)")
    print(f"URL:      {entry['url']}")
    print(f"Notes:    {entry['notes']}")


def _ask_text(label: str, current: str | None = None) -> str:
    suffix = f" [{current}]" if current else ""
    value = input(f"{label}{suffix}: ")
    return value if value or current is None else current


def cmd_add(args) -> None:
    vault = _open_vault(args.vault)
    try:
        if vault.has(args.title):
            raise CliError(f"an entry titled '{args.title}' already exists")
        username = _ask_text("Username")
        password = _ask_secret("Entry password", confirm=True)
        url = _ask_text("URL (optional)")
        notes = _ask_text("Notes (optional, single line)")
        vault.add(title=args.title, username=username, password=password,
                  url=url, notes=notes)
    finally:
        vault.lock()
    print(f"Added '{args.title}'.")


def cmd_edit(args) -> None:
    vault = _open_vault(args.vault)
    try:
        current = vault.get(args.title)
        print("Press Enter to keep the current value.")
        changes = {
            "username": _ask_text("Username", current["username"]),
            "url": _ask_text("URL", current["url"]),
            "notes": _ask_text("Notes", current["notes"]),
        }
        new_password = getpass.getpass("New entry password (Enter to keep): ")
        if new_password:
            if getpass.getpass("Confirm new entry password: ") != new_password:
                raise CliError("entry passwords did not match")
            changes["password"] = new_password
        vault.update(args.title, **changes)
    finally:
        vault.lock()
    print(f"Updated '{args.title}'.")


def cmd_remove(args) -> None:
    vault = _open_vault(args.vault)
    try:
        vault.get(args.title)                      # existence check first
        answer = input(f"Delete '{args.title}'? [y/N]: ").strip().lower()
        if answer != "y":
            print("Cancelled.")
            return
        vault.remove(args.title)
    finally:
        vault.lock()
    print(f"Removed '{args.title}'.")


# ---- parser / main ---------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pm", description="Local password manager")
    parser.add_argument("--vault", type=_path_arg, default=DEFAULT_VAULT,
                        help=f"vault file (default: {DEFAULT_VAULT})")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault").set_defaults(func=cmd_init)
    sub.add_parser("unlock", help="verify the master password").set_defaults(func=cmd_unlock)
    sub.add_parser("list", help="list entry titles").set_defaults(func=cmd_list)

    p = sub.add_parser("get", help="show an entry (password masked)")
    p.add_argument("title", type=_title_arg)
    p.add_argument("--reveal", action="store_true", help="print the password in cleartext")
    p.set_defaults(func=cmd_get)

    for name, func, text in (("add", cmd_add, "add an entry"),
                             ("edit", cmd_edit, "edit an entry"),
                             ("remove", cmd_remove, "delete an entry")):
        p = sub.add_parser(name, help=text)
        p.add_argument("title", type=_title_arg)
        p.set_defaults(func=func)
    return parser


def _disable_core_dumps() -> None:           # T7, POSIX only
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    _disable_core_dumps()
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
    except (CliError, VaultError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nAborted.", file=sys.stderr)
        return 130
    return 0
