"""Encrypted-secret accessor.

Sensitive settings (router password, future API keys) are stored in the
``settings`` table encrypted with Fernet. The encryption key lives outside
the database, in a small file with 0600 permissions next to the SQLite DB.

Why this matters:
- A leaked DB backup alone won't expose router credentials.
- The dashboard service can read its own secrets without prompting because
  the key file is readable by the service user (and only the service user).

This is *not* a substitute for OS-level filesystem permissions, just a
thin defence-in-depth layer.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .store import Store

log = logging.getLogger("dns-dashboard.secrets")


class SecretStore:
    def __init__(self, store: Store, key_path: str | Path) -> None:
        self._store = store
        self._key_path = Path(key_path)
        self._fernet: Fernet | None = None

    @property
    def _f(self) -> Fernet:
        if self._fernet is None:
            self._fernet = Fernet(self._load_or_create_key())
        return self._fernet

    def _load_or_create_key(self) -> bytes:
        if self._key_path.exists():
            return self._key_path.read_bytes().strip()
        self._key_path.parent.mkdir(parents=True, exist_ok=True)
        key = Fernet.generate_key()
        # Write atomically with restrictive permissions.
        tmp = self._key_path.with_suffix(self._key_path.suffix + ".tmp")
        tmp.write_bytes(key)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self._key_path)
        log.info("generated new secret key at %s", self._key_path)
        return key

    def get(self, key: str) -> str | None:
        ciphertext = self._store.get_setting(key)
        if not ciphertext:
            return None
        try:
            return self._f.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            log.warning("secret %s is unreadable (key rotated?)", key)
            return None

    def set(self, key: str, value: str | None) -> None:
        if value is None or value == "":
            self._store.set_setting(key, None)
            return
        ciphertext = self._f.encrypt(value.encode()).decode()
        self._store.set_setting(key, ciphertext)
