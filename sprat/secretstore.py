"""Per-project secrets (login passwords, API keys), encrypted at rest.

Projects refer to them as ${NAME} (e.g. in the login body). Values are encrypted with Fernet
(AES-128-CBC + HMAC-SHA256) and stored in <data dir>/secrets.json. They are never returned by the
API, never included in exports, reports or logs, and deleted with their project.

Key: SPRAT_SECRET_KEY if set (a Fernet key, or any passphrase, which is hashed into one),
otherwise a key generated once into <data dir>/.secret.key. Anyone who can read both that key file
and secrets.json can decrypt, so on a shared server set SPRAT_SECRET_KEY instead of relying on
the key file.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def check_name(name: str) -> None:
    if not NAME.fullmatch(name or ""):  # not match(...$): `$` also matches before a trailing newline
        raise ValueError("Use letters, digits and _ only, starting with a letter (e.g. NTT_PASSWORD)")


def _fernet_from(value: str) -> Fernet:
    try:
        return Fernet(value.encode())
    except (ValueError, TypeError):  # a passphrase, not a Fernet key
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()))


class SecretStore:
    def __init__(self, data_dir: Path):
        self.dir = Path(data_dir)
        self.file = self.dir / "secrets.json"
        self._lock = threading.Lock()
        self._key_lock = threading.Lock()
        self._fernet = None

    # ---------- key ----------
    def _f(self) -> Fernet:
        with self._key_lock:
            if self._fernet is None:
                env = os.environ.get("SPRAT_SECRET_KEY")
                self._fernet = _fernet_from(env) if env else Fernet(self._key_file())
            return self._fernet

    def _key_file(self) -> bytes:
        """The key in .secret.key, created once. Create-exclusive, so when several processes start on a
        fresh data dir at once they all end up with the one key that reached the disk."""
        kf = self.dir / ".secret.key"
        if not kf.is_file():
            self.dir.mkdir(parents=True, exist_ok=True)
            key = Fernet.generate_key()
            try:
                with open(kf, "xb") as f:
                    f.write(key)
            except FileExistsError:  # another process won; it may not have written the key yet
                for _ in range(100):
                    if kf.read_bytes().strip():
                        break
                    time.sleep(0.02)
            else:
                try:
                    os.chmod(kf, 0o600)
                except OSError:
                    pass
        return kf.read_bytes().strip()

    @property
    def key_source(self) -> str:
        return "SPRAT_SECRET_KEY" if os.environ.get("SPRAT_SECRET_KEY") else str(self.dir / ".secret.key")

    # ---------- storage ----------
    def _read(self) -> dict:
        if not self.file.is_file():
            return {}
        return json.loads(self.file.read_text(encoding="utf-8"))

    def _write(self, data: dict) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        tmp = self.file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(self.file)
        try:
            os.chmod(self.file, 0o600)
        except OSError:
            pass

    def names(self, pid: str) -> list[dict]:
        """Names and when they were saved. Never values."""
        with self._lock:
            entries = self._read().get(pid, {})
        return [{"name": n, "updated": e.get("updated")} for n, e in sorted(entries.items())]

    def set(self, pid: str, name: str, value: str) -> None:
        check_name(name)
        if not value:
            raise ValueError(f"{name}: enter a value")
        token = self._f().encrypt(value.encode()).decode()
        with self._lock:
            data = self._read()
            data.setdefault(pid, {})[name] = {"value": token, "updated": time.time()}
            self._write(data)

    def delete(self, pid: str, name: str) -> None:
        with self._lock:
            data = self._read()
            if data.get(pid, {}).pop(name, None) is not None:
                if not data[pid]:
                    data.pop(pid)
                self._write(data)

    def drop_project(self, pid: str) -> None:
        with self._lock:
            data = self._read()
            if data.pop(pid, None) is not None:
                self._write(data)

    def values(self, pid: str) -> dict[str, str]:
        """Decrypted values, for building a run's requests. Never send these to the browser."""
        with self._lock:
            entries = self._read().get(pid, {})
        out = {}
        for n, e in entries.items():
            try:
                out[n] = self._f().decrypt(e["value"].encode()).decode()
            except InvalidToken:
                raise ValueError(f"Secret {n} can't be decrypted: the encryption key changed. Enter it again.")
        return out
