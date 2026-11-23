"""Cifrado híbrido del archivo en el CLIENTE (sellar / abrir / re-envolver).

SELLAR (subida):
  1. clave de sesión K_s = 32 bytes aleatorios, nonce = 12 bytes aleatorios
  2. texto claro interno = encabezado {nombre real, tamaño} || datos   (el nombre queda CIFRADO)
  3. AAD = {file_id, owner, timestamp, tamaño del ciphertext}
  4. (C, T) = AES-256-GCM(K_s, nonce, texto claro interno, AAD)
  5. para cada destinatario i:  W_i = RSA-OAEP(pub_i, K_s)
  6. σ = RSA-PSS(priv_dueño, SHA-256(C || nonce || T || AAD))   (con prefijos de longitud)
  7. al servidor solo viaja: C, nonce, T, AAD, {W_i}, σ, huella del firmante

ABRIR (descarga) — el orden importa y CUALQUIER fallo aborta sin entregar datos:
  1. la huella del firmante coincide con la clave pública (fijada) del dueño
  2. verificar σ con la clave pública del dueño
  3. validar la AAD (dueño, file_id, tamaño)
  4. desenvolver K_s con la clave privada propia (RSA-OAEP)
  5. AES-GCM: verificar el tag y descifrar (GCM verifica ANTES de producir texto claro)
  6. separar el encabezado interno (nombre real) de los datos

RE-ENVOLVER (compartir): el dueño desenvuelve K_s localmente, comprueba con el tag
GCM que es la clave correcta y la cifra con la clave pública del destinatario.
El servidor nunca ve K_s.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any

from .. import protocol as P
from ..crypto.encoding import fingerprint
from ..crypto.errors import DecryptionError, InvalidSignature, InvalidTag
from ..crypto.gcm import NONCE_SIZE, AESGCM
from ..crypto.oaep import oaep_decrypt, oaep_encrypt
from ..crypto.pss import pss_sign_digest, pss_verify_digest
from ..crypto.rsa_core import RSAPrivateKey, RSAPublicKey
from ..crypto.utils import zeroize

SESSION_KEY_BYTES = 32


class PackageError(Exception):
    """El paquete no supera alguna verificación. `step` indica cuál (para mostrarlo en la CLI)."""

    def __init__(self, step: str, message: str) -> None:
        super().__init__(f"{step}: {message}")
        self.step = step
        self.message = message


@dataclass(frozen=True)
class Recipient:
    username: str
    public_key: RSAPublicKey
    fingerprint: str


@dataclass(frozen=True)
class OpenedFile:
    file_id: str
    owner: str
    filename: str
    data: bytes
    meta: dict[str, Any]


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def seal(owner: str, owner_priv: RSAPrivateKey, recipients: list[Recipient], filename: str, data: bytes,
         *, file_id: str | None = None, timestamp: str | None = None) -> dict[str, Any]:
    """Cifra el archivo y devuelve el cuerpo JSON listo para POST /api/files."""
    if owner not in {r.username for r in recipients}:
        raise ValueError("el dueño debe estar entre los destinatarios")
    file_id = file_id or secrets.token_hex(16)
    session_key = bytearray(secrets.token_bytes(SESSION_KEY_BYTES))
    nonce = secrets.token_bytes(NONCE_SIZE)
    gcm = AESGCM(session_key)
    try:
        inner = P.pack_plaintext(filename, data)
        aad = P.build_aad(file_id, owner, timestamp or utc_timestamp(), len(inner))
        ciphertext, tag = gcm.encrypt(nonce, inner, aad)
        wrapped = [{"recipient": r.username, "recipient_fp": r.fingerprint,
                    "wrapped_key": P.b64e(oaep_encrypt(r.public_key, session_key))} for r in recipients]
    finally:
        gcm.wipe()
        zeroize(session_key)
    signature = pss_sign_digest(owner_priv, P.file_signature_digest(ciphertext, nonce, tag, aad))
    return {
        "file_id": file_id, "aad": P.b64e(aad), "nonce": P.b64e(nonce), "tag": P.b64e(tag),
        "ciphertext": P.b64e(ciphertext), "signature": P.b64e(signature),
        "signer_fp": fingerprint(owner_priv.public_key()), "wrapped_keys": wrapped,
    }


def _decode(pkg: dict[str, Any]) -> dict[str, Any]:
    try:
        return {k: P.b64d(pkg[k]) for k in ("aad", "nonce", "tag", "ciphertext", "signature", "wrapped_key")}
    except (KeyError, P.ProtocolError) as exc:
        raise PackageError("formato", "paquete incompleto o mal codificado") from exc


def verify_signature(pkg: dict[str, Any], owner_pub: RSAPublicKey) -> dict[str, Any]:
    """Pasos 1-3 de ABRIR: firma del dueño y coherencia de la AAD. Devuelve los metadatos."""
    raw = _decode(pkg)
    if pkg.get("signer_fp") != fingerprint(owner_pub):
        raise PackageError("firma", "la huella del firmante no coincide con la clave pública del dueño")
    try:
        digest = P.file_signature_digest(raw["ciphertext"], raw["nonce"], raw["tag"], raw["aad"])
        pss_verify_digest(owner_pub, digest, raw["signature"])
    except InvalidSignature as exc:
        raise PackageError("firma", "firma RSA-PSS inválida: el archivo o sus metadatos fueron alterados") from exc
    try:
        meta = P.parse_aad(raw["aad"])
    except P.ProtocolError as exc:
        raise PackageError("metadatos", str(exc)) from exc
    if meta["owner"] != pkg.get("owner") or meta["file_id"] != pkg.get("file_id"):
        raise PackageError("metadatos", "la AAD no corresponde al archivo solicitado")
    if meta["size"] != len(raw["ciphertext"]):
        raise PackageError("metadatos", "el tamaño del ciphertext no coincide con la AAD")
    return meta


def unwrap_session_key(pkg: dict[str, Any], my_priv: RSAPrivateKey) -> bytearray:
    """Paso 4: K_s = RSA-OAEP-Dec(priv, W). Devuelve un bytearray que el llamador debe borrar."""
    try:
        key = oaep_decrypt(my_priv, _decode(pkg)["wrapped_key"])
    except DecryptionError as exc:
        raise PackageError("clave de sesión", "no se pudo desenvolver con su clave privada (no autorizado)") from exc
    if len(key) != SESSION_KEY_BYTES:
        zeroize(key)
        raise PackageError("clave de sesión", "longitud de clave de sesión inválida")
    return key


def open_package(pkg: dict[str, Any], my_priv: RSAPrivateKey, owner_pub: RSAPublicKey) -> OpenedFile:
    """Verifica y descifra un paquete descargado. Lanza PackageError ante cualquier fallo."""
    meta = verify_signature(pkg, owner_pub)
    raw = _decode(pkg)
    session_key = unwrap_session_key(pkg, my_priv)
    gcm = AESGCM(session_key)
    try:
        inner = gcm.decrypt(raw["nonce"], raw["ciphertext"], raw["tag"], raw["aad"])
    except InvalidTag as exc:
        raise PackageError("integridad", "tag AES-GCM inválido: ciphertext o AAD alterados") from exc
    finally:
        gcm.wipe()
        zeroize(session_key)
    try:
        filename, data = P.unpack_plaintext(inner)
    except P.ProtocolError as exc:
        raise PackageError("contenido", str(exc)) from exc
    return OpenedFile(meta["file_id"], meta["owner"], filename, data, meta)


def check_integrity(pkg: dict[str, Any], my_priv: RSAPrivateKey, owner_pub: RSAPublicKey) -> dict[str, Any]:
    """Verificación completa (firma + clave + tag GCM) sin descifrar el contenido."""
    meta = verify_signature(pkg, owner_pub)
    raw = _decode(pkg)
    session_key = unwrap_session_key(pkg, my_priv)
    gcm = AESGCM(session_key)
    try:
        if not gcm.verify(raw["nonce"], raw["ciphertext"], raw["tag"], raw["aad"]):
            raise PackageError("integridad", "tag AES-GCM inválido: ciphertext o AAD alterados")
    finally:
        gcm.wipe()
        zeroize(session_key)
    return meta


def rewrap_for(pkg: dict[str, Any], my_priv: RSAPrivateKey, owner_pub: RSAPublicKey,
               recipient_pub: RSAPublicKey) -> bytes:
    """Compartir: desenvuelve K_s localmente, confirma que es correcta (tag GCM) y la envuelve
    con la clave pública del destinatario."""
    verify_signature(pkg, owner_pub)
    raw = _decode(pkg)
    session_key = unwrap_session_key(pkg, my_priv)
    gcm = AESGCM(session_key)
    try:
        if not gcm.verify(raw["nonce"], raw["ciphertext"], raw["tag"], raw["aad"]):
            raise PackageError("integridad", "la clave de sesión no autentica el archivo")
        return oaep_encrypt(recipient_pub, session_key)
    finally:
        gcm.wipe()
        zeroize(session_key)
