"""Almacenamiento del servidor: blobs cifrados en disco + metadatos en SQLite.

Lo que el servidor guarda (y por lo tanto lo único que un atacante que lo
comprometa puede ver):
  * blobs/<file_id>.bin  -> ciphertext AES-256-GCM (bytes ilegibles)
  * metadata.sqlite3     -> usuarios y CLAVES PÚBLICAS, nonce, tag, AAD (metadatos
                            autenticados en claro), firma, claves de sesión
                            ENVUELTAS con RSA-OAEP (una por destinatario),
                            challenges pendientes y hashes de tokens de sesión.

NUNCA guarda: claves privadas, claves de sesión en claro, texto claro,
passphrases ni los tokens de sesión en claro (solo su SHA-256).
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from ..crypto.sha256 import sha256

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    public_key_pem  TEXT NOT NULL,
    fingerprint     TEXT NOT NULL UNIQUE,
    created_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    nonce_hex   TEXT PRIMARY KEY,
    username    TEXT NOT NULL REFERENCES users(username),
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,         -- SHA-256 del token (nunca el token)
    username    TEXT NOT NULL REFERENCES users(username),
    expires_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS files (
    file_id     TEXT PRIMARY KEY,
    owner       TEXT NOT NULL REFERENCES users(username),
    nonce       BLOB NOT NULL,
    tag         BLOB NOT NULL,
    aad         BLOB NOT NULL,
    signature   BLOB NOT NULL,
    signer_fp   TEXT NOT NULL,
    size        INTEGER NOT NULL,         -- tamaño del ciphertext
    created_at  REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS file_keys (
    file_id       TEXT NOT NULL REFERENCES files(file_id),
    recipient     TEXT NOT NULL REFERENCES users(username),
    recipient_fp  TEXT NOT NULL,
    wrapped_key   BLOB NOT NULL,          -- clave de sesión cifrada con RSA-OAEP
    added_at      REAL NOT NULL,
    PRIMARY KEY (file_id, recipient)
);
"""


@dataclass(frozen=True)
class UserRecord:
    username: str
    public_key_pem: str
    fingerprint: str
    created_at: float


@dataclass(frozen=True)
class FileRecord:
    file_id: str
    owner: str
    nonce: bytes
    tag: bytes
    aad: bytes
    signature: bytes
    signer_fp: str
    size: int
    created_at: float


def token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hex()


class Storage:
    def __init__(self, data_dir: Path | str, clock: Callable[[], float] = time.time) -> None:
        self.data_dir = Path(data_dir)
        self.blob_dir = self.data_dir / "blobs"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.data_dir / "metadata.sqlite3"
        self.clock = clock
        self._lock = threading.Lock()
        with self._conn() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        # Una conexión por operación + lock: simple y seguro con el servidor multihilo de Flask.
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute("PRAGMA foreign_keys = ON")
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    # ------------------------------------------------------------------ usuarios
    def add_user(self, username: str, public_key_pem: str, fingerprint: str) -> bool:
        try:
            with self._conn() as c:
                c.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                          (username, public_key_pem, fingerprint, self.clock()))
            return True
        except sqlite3.IntegrityError:
            return False

    def get_user(self, username: str) -> UserRecord | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return UserRecord(*row) if row else None

    def list_users(self) -> list[UserRecord]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [UserRecord(*r) for r in rows]

    # ---------------------------------------------------------------- challenges
    def add_challenge(self, nonce_hex: str, username: str, ttl: float, max_pending: int = 5) -> None:
        now = self.clock()
        with self._conn() as c:
            c.execute("DELETE FROM challenges WHERE expires_at < ?", (now,))
            pending = c.execute("SELECT COUNT(*) FROM challenges WHERE username = ?", (username,)).fetchone()[0]
            if pending >= max_pending:  # limita challenges acumulados por usuario
                c.execute("DELETE FROM challenges WHERE nonce_hex IN (SELECT nonce_hex FROM challenges "
                          "WHERE username = ? ORDER BY expires_at LIMIT ?)", (username, pending - max_pending + 1))
            c.execute("INSERT INTO challenges VALUES (?, ?, ?)", (nonce_hex, username, now + ttl))

    def consume_challenge(self, nonce_hex: str, username: str) -> bool:
        """Borra el challenge (USO ÚNICO) y devuelve True si existía y no había expirado.

        Se borra SIEMPRE antes de verificar la firma: aunque la verificación falle,
        el nonce ya no se puede volver a usar (anti-replay).
        """
        with self._conn() as c:
            row = c.execute("DELETE FROM challenges WHERE nonce_hex = ? AND username = ? RETURNING expires_at",
                            (nonce_hex, username)).fetchone()
        return row is not None and row[0] >= self.clock()

    # ------------------------------------------------------------------ sesiones
    def add_session(self, token: str, username: str, ttl: float) -> None:
        now = self.clock()
        with self._conn() as c:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            c.execute("INSERT INTO sessions VALUES (?, ?, ?)", (token_hash(token), username, now + ttl))

    def session_user(self, token: str) -> str | None:
        with self._conn() as c:
            row = c.execute("SELECT username, expires_at FROM sessions WHERE token_hash = ?",
                            (token_hash(token),)).fetchone()
        if row is None or row[1] < self.clock():
            return None
        return row[0]

    # ------------------------------------------------------------------ archivos
    def _blob_path(self, file_id: str) -> Path:
        return self.blob_dir / f"{file_id}.bin"

    def add_file(self, rec: FileRecord, ciphertext: bytes, keys: list[tuple[str, str, bytes]]) -> bool:
        """Guarda el blob (escritura atómica) y los metadatos. keys = [(recipient, fp, wrapped)]."""
        path = self._blob_path(rec.file_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(ciphertext)
        try:
            with self._conn() as c:
                c.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                          (rec.file_id, rec.owner, rec.nonce, rec.tag, rec.aad, rec.signature,
                           rec.signer_fp, rec.size, rec.created_at))
                c.executemany("INSERT INTO file_keys VALUES (?, ?, ?, ?, ?)",
                              [(rec.file_id, r, fp, w, rec.created_at) for r, fp, w in keys])
        except sqlite3.IntegrityError:
            tmp.unlink(missing_ok=True)
            return False
        os.replace(tmp, path)
        return True

    def get_file(self, file_id: str) -> FileRecord | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM files WHERE file_id = ?", (file_id,)).fetchone()
        return FileRecord(*row) if row else None

    def read_blob(self, file_id: str) -> bytes:
        return self._blob_path(file_id).read_bytes()

    def get_wrapped_key(self, file_id: str, recipient: str) -> tuple[str, bytes] | None:
        with self._conn() as c:
            row = c.execute("SELECT recipient_fp, wrapped_key FROM file_keys WHERE file_id = ? AND recipient = ?",
                            (file_id, recipient)).fetchone()
        return (row[0], row[1]) if row else None

    def add_wrapped_key(self, file_id: str, recipient: str, recipient_fp: str, wrapped: bytes) -> None:
        """Agrega o reemplaza la clave envuelta para un destinatario."""
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO file_keys VALUES (?, ?, ?, ?, ?)",
                      (file_id, recipient, recipient_fp, wrapped, self.clock()))

    def recipients(self, file_id: str) -> list[str]:
        with self._conn() as c:
            rows = c.execute("SELECT recipient FROM file_keys WHERE file_id = ? ORDER BY recipient",
                             (file_id,)).fetchall()
        return [r[0] for r in rows]

    def files_for(self, username: str) -> list[FileRecord]:
        """Archivos a los que `username` tiene acceso (tiene una clave envuelta)."""
        with self._conn() as c:
            rows = c.execute("SELECT f.* FROM files f JOIN file_keys k ON f.file_id = k.file_id "
                             "WHERE k.recipient = ? ORDER BY f.created_at", (username,)).fetchall()
        return [FileRecord(*r) for r in rows]

    def all_files(self) -> list[FileRecord]:
        with self._conn() as c:
            rows = c.execute("SELECT * FROM files ORDER BY created_at").fetchall()
        return [FileRecord(*r) for r in rows]

    def all_wrapped_keys(self) -> list[tuple[str, str, bytes]]:
        with self._conn() as c:
            return c.execute("SELECT file_id, recipient, wrapped_key FROM file_keys").fetchall()
