"""
User management module.

Owns master-password setup/verification and session state
(locked/unlocked), including the failed-attempt counter. Calls into
the crypto module to derive keys and decrypt/encrypt; never touches
the filesystem directly.
"""
