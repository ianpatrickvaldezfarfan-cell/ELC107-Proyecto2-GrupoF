"""Keystore local del cliente: clave privada cifrada, sesión, contactos y archivos conocidos.

Carpeta por usuario (permite simular varios usuarios en la misma PC):
    <home>/<usuario>/
        private_key.enc.json   clave privada CIFRADA (ver abajo)
        public_key.pem         clave pública propia (formato GRUPOF)
        session.json           token de sesión del último login (sin la clave privada)
        contacts.json          huellas de claves públicas de otros usuarios (pinning)
        files_index.json       file_id -> nombre real (los nombres van cifrados en el servidor)
    <home> = --home, o la variable GRUPOF_HOME, o ~/.grupof

Cifrado de la clave privada:
    salt  = 16 bytes aleatorios
    K     = PBKDF2-HMAC-SHA256(passphrase, salt, iteraciones, 32 bytes)
    (C,T) = AES-256-GCM(K, nonce aleatorio de 96 bits, TLV(clave privada), AAD = encabezado)
El encabezado (usuario, parámetros del KDF, huella pública, versión) va como AAD:
si alguien altera, por ejemplo, el número de iteraciones guardado, el tag falla.
El número de iteraciones se guarda en el archivo, así que puede cambiarse el valor
por defecto sin romper keystores existentes.

Material sensible: la passphrase, la clave derivada K y la clave privada serializada
se manejan como bytearray y se sobreescriben con ceros tras usarse. LIMITACIÓN: los
enteros de la clave RSA (d, p, q, ...) son `int` inmutables de Python y el recolector
de basura decide cuándo libera su memoria; no pueden borrarse de forma fiable
(ver src/crypto/utils.py).

session.json guarda el token en claro: es de corta duración (15 min), solo sirve ante
ese servidor y NO permite descifrar nada (para eso hace falta la clave privada).
"""

from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

from .. import protocol as P
from ..crypto.encoding import (decode_private_key, encode_private_key, fingerprint,
                               public_key_from_pem, public_key_to_pem)
from ..crypto.errors import InvalidTag
from ..crypto.gcm import AESGCM
from ..crypto.kdf import MIN_ITERATIONS, default_iterations, pbkdf2_hmac_sha256
from ..crypto.rsa_core import RSAPrivateKey, RSAPublicKey
from ..crypto.utils import zeroize

KEYSTORE_FORMAT = "grupof-keystore"
KEYSTORE_VERSION = 1
SALT_BYTES = 16


class KeystoreError(Exception):
    """Errores del keystore local (no existe, passphrase incorrecta, alterado...)."""


def default_home() -> Path:
    env = os.environ.get("GRUPOF_HOME")
    return Path(env) if env else Path.home() / ".grupof"


def _write_json(path: Path, data: Any) -> None:
    """Escritura atómica de JSON en UTF-8 (archivo temporal + reemplazo)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)


def _read_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise KeystoreError(f"archivo dañado: {path}") from exc


class Keystore:
    def __init__(self, username: str, home: Path | str | None = None) -> None:
        self.username = P.validate_username(username)
        self.dir = Path(home) / username if home is not None else default_home() / username
        self.private_path = self.dir / "private_key.enc.json"
        self.public_path = self.dir / "public_key.pem"
        self.session_path = self.dir / "session.json"
        self.contacts_path = self.dir / "contacts.json"
        self.index_path = self.dir / "files_index.json"

    # ----------------------------------------------------------- clave privada
    def exists(self) -> bool:
        return self.private_path.exists() and self.public_path.exists()

    @staticmethod
    def _header_aad(header: dict[str, Any]) -> bytes:
        return P.canonical_json(header)

    def create(self, priv: RSAPrivateKey, passphrase: bytearray, iterations: int | None = None,
               overwrite: bool = False) -> str:
        """Cifra y guarda la clave privada. Devuelve la huella de la clave pública."""
        if self.exists() and not overwrite:
            raise KeystoreError(f"ya existe un keystore para '{self.username}' en {self.dir}")
        iterations = iterations if iterations is not None else default_iterations()
        if iterations < MIN_ITERATIONS:
            raise KeystoreError(f"se requieren al menos {MIN_ITERATIONS} iteraciones de PBKDF2")
        self.dir.mkdir(parents=True, exist_ok=True)
        pub = priv.public_key()
        fp = fingerprint(pub)
        salt = secrets.token_bytes(SALT_BYTES)
        nonce = secrets.token_bytes(12)
        header = {
            "format": KEYSTORE_FORMAT, "version": KEYSTORE_VERSION, "username": self.username,
            "kdf": {"name": "PBKDF2-HMAC-SHA256", "iterations": iterations, "salt": P.b64e(salt), "dklen": 32},
            "cipher": {"name": "AES-256-GCM", "nonce": P.b64e(nonce)},
            "public_key_fingerprint": fp,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        key = pbkdf2_hmac_sha256(passphrase, salt, iterations, 32)
        secret = encode_private_key(priv)
        gcm = AESGCM(key)
        try:
            ct, tag = gcm.encrypt(nonce, secret, self._header_aad(header))
        finally:
            gcm.wipe()
            zeroize(key)
            zeroize(secret)
        _write_json(self.private_path, {"header": header, "ciphertext": P.b64e(ct), "tag": P.b64e(tag)})
        self.public_path.write_text(public_key_to_pem(pub), encoding="utf-8")
        return fp

    def kdf_iterations(self) -> int:
        return int(self._load_private_file()["header"]["kdf"]["iterations"])

    def _load_private_file(self) -> dict[str, Any]:
        data = _read_json(self.private_path)
        if data is None:
            raise KeystoreError(f"no existe keystore para '{self.username}' (ejecute keygen) en {self.dir}")
        try:
            header = data["header"]
            if header["format"] != KEYSTORE_FORMAT or header["version"] != KEYSTORE_VERSION:
                raise KeystoreError("formato de keystore no soportado")
            if header["username"] != self.username:
                raise KeystoreError("el keystore pertenece a otro usuario")
        except (KeyError, TypeError) as exc:
            raise KeystoreError("keystore dañado") from exc
        return data

    def unlock(self, passphrase: bytearray) -> RSAPrivateKey:
        """Deriva la clave con PBKDF2 (iteraciones leídas del archivo) y descifra la clave privada."""
        data = self._load_private_file()
        header = data["header"]
        try:
            iterations = int(header["kdf"]["iterations"])
            salt = P.b64d(header["kdf"]["salt"])
            nonce = P.b64d(header["cipher"]["nonce"])
            ct, tag = P.b64d(data["ciphertext"]), P.b64d(data["tag"])
        except (KeyError, TypeError, ValueError) as exc:
            raise KeystoreError("keystore dañado") from exc
        if iterations < MIN_ITERATIONS:
            raise KeystoreError("parámetros de KDF inseguros en el keystore")
        key = pbkdf2_hmac_sha256(passphrase, salt, iterations, 32)
        gcm = AESGCM(key)
        try:
            secret = bytearray(gcm.decrypt(nonce, ct, tag, self._header_aad(header)))
        except InvalidTag as exc:
            raise KeystoreError("passphrase incorrecta o keystore alterado") from exc
        finally:
            gcm.wipe()
            zeroize(key)
        try:
            priv = decode_private_key(secret)
        finally:
            zeroize(secret)
        if fingerprint(priv.public_key()) != header["public_key_fingerprint"]:
            raise KeystoreError("la clave privada no corresponde a la huella guardada")
        return priv

    def public_key(self) -> RSAPublicKey:
        if not self.public_path.exists():
            raise KeystoreError(f"no existe keystore para '{self.username}' (ejecute keygen) en {self.dir}")
        return public_key_from_pem(self.public_path.read_text(encoding="utf-8"))

    def fingerprint(self) -> str:
        return fingerprint(self.public_key())

    # ----------------------------------------------------------------- sesión
    def save_session(self, server: str, token: str, expires_at: float) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        _write_json(self.session_path, {"server": server, "token": token, "expires_at": expires_at})

    def load_session(self, server: str, now: float | None = None) -> str | None:
        """Token vigente para ese servidor, o None (no hay login, expiró o es de otro servidor)."""
        data = _read_json(self.session_path)
        if not data or data.get("server") != server:
            return None
        if data.get("expires_at", 0) <= (now if now is not None else time.time()):
            return None
        return data.get("token")

    def clear_session(self) -> None:
        self.session_path.unlink(missing_ok=True)

    # -------------------------------------------------------------- contactos
    def contacts(self) -> dict[str, Any]:
        return _read_json(self.contacts_path, {})

    def pinned_fingerprint(self, username: str) -> str | None:
        entry = self.contacts().get(username)
        return entry["fingerprint"] if entry else None

    def pin(self, username: str, fp: str, verified: bool) -> None:
        contacts = self.contacts()
        contacts[username] = {"fingerprint": fp, "verified_out_of_band": verified,
                              "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        self.dir.mkdir(parents=True, exist_ok=True)
        _write_json(self.contacts_path, contacts)

    # ------------------------------------------------- índice local de archivos
    def remember_file(self, file_id: str, filename: str) -> None:
        index = _read_json(self.index_path, {})
        index[file_id] = filename
        self.dir.mkdir(parents=True, exist_ok=True)
        _write_json(self.index_path, index)

    def known_filename(self, file_id: str) -> str | None:
        return _read_json(self.index_path, {}).get(file_id)
