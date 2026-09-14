"""
Storage layer.

The only module that touches the filesystem. Reads and writes the
vault file (header + ciphertext), using atomic writes (temp file +
rename) so a crash mid-write can't corrupt the vault. Never sees
plaintext or the master password.
"""
