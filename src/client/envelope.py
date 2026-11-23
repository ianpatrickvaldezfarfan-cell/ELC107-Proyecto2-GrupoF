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

Parámetro opcional `trace`: función que recibe una descripción de cada paso
criptográfico (la usa el registro de operaciones de la GUI). Nunca recibe
secretos: solo prefijos de datos públicos (tag, firma, claves ENVUELTAS, huellas).
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable

from .. import protocol as P
from ..crypto.encoding import fingerprint
from ..crypto.errors import DecryptionError, InvalidSignature, InvalidTag
from ..crypto.gcm import NONCE_SIZE, AESGCM
from ..crypto.oaep import oaep_decrypt, oaep_encrypt
from ..crypto.pss import pss_sign_digest, pss_verify_digest
from ..crypto.rsa_core import RSAPrivateKey, RSAPublicKey
from ..crypto.utils import zeroize

SESSION_KEY_BYTES = 32

Trace = Callable[[str], None]


def _no_trace(_msg: str) -> None:
    pass


def _short(data: bytes, n: int = 8) -> str:
    return data[:n].hex() + "..."


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
         *, file_id: str | None = None, timestamp: str | None = None, trace: Trace | None = None) -> dict[str, Any]:
    """Cifra el archivo y devuelve el cuerpo JSON listo para POST /api/files."""
    t = trace or _no_trace
    if owner not in {r.username for r in recipients}:
        raise ValueError("el dueño debe estar entre los destinatarios")
    file_id = file_id or secrets.token_hex(16)
    session_key = bytearray(secrets.token_bytes(SESSION_KEY_BYTES))
    nonce = secrets.token_bytes(NONCE_SIZE)
    t("Clave de sesión AES-256 generada (256 bits del CSPRNG del sistema operativo)")
    t(f"Nonce GCM de 96 bits generado: {nonce.hex()}")
    gcm = AESGCM(session_key)
    try:
        inner = P.pack_plaintext(filename, data)
        t(f"Encabezado interno con el nombre real ('{filename}') y el tamaño original: irá CIFRADO")
        aad = P.build_aad(file_id, owner, timestamp or utc_timestamp(), len(inner))
        t(f"AAD (autenticada, no cifrada): {aad.decode('utf-8')}")
        ciphertext, tag = gcm.encrypt(nonce, inner, aad)
        t(f"Contenido cifrado con AES-256-GCM: {len(ciphertext):,} bytes (tag: {tag.hex()[:16]}...)"
          .replace(",", "."))
        wrapped = []
        for r in recipients:
            w = oaep_encrypt(r.public_key, session_key)
            t(f"Clave de sesión envuelta con RSA-OAEP-SHA256 para {r.username} "
              f"(huella {r.fingerprint[:8].upper()}...): {_short(w)}")
            wrapped.append({"recipient": r.username, "recipient_fp": r.fingerprint, "wrapped_key": P.b64e(w)})
    finally:
        gcm.wipe()
        zeroize(session_key)
    t("Clave de sesión en claro borrada de la memoria (sobrescrita con ceros)")
    digest = P.file_signature_digest(ciphertext, nonce, tag, aad)
    signature = pss_sign_digest(owner_priv, digest)
    t(f"Firma RSA-PSS creada sobre SHA-256(ciphertext‖nonce‖tag‖AAD) = {digest.hex()[:16]}...: {_short(signature)}")
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


def verify_signature(pkg: dict[str, Any], owner_pub: RSAPublicKey, trace: Trace | None = None) -> dict[str, Any]:
    """Pasos 1-3 de ABRIR: firma del dueño y coherencia de la AAD. Devuelve los metadatos."""
    t = trace or _no_trace
    raw = _decode(pkg)
    owner_fp = fingerprint(owner_pub)
    if pkg.get("signer_fp") != owner_fp:
        raise PackageError("firma", "la huella del firmante no coincide con la clave pública del dueño")
    t(f"Huella del firmante ({owner_fp[:8].upper()}...) coincide con la clave pública de {pkg.get('owner')}")
    try:
        digest = P.file_signature_digest(raw["ciphertext"], raw["nonce"], raw["tag"], raw["aad"])
        t(f"SHA-256(ciphertext‖nonce‖tag‖AAD) recalculado: {digest.hex()[:16]}...")
        pss_verify_digest(owner_pub, digest, raw["signature"])
    except InvalidSignature as exc:
        raise PackageError("firma", "firma RSA-PSS inválida: el archivo o sus metadatos fueron alterados") from exc
    t(f"Firma RSA-PSS VÁLIDA (firmada por {pkg.get('owner')})")
    try:
        meta = P.parse_aad(raw["aad"])
    except P.ProtocolError as exc:
        raise PackageError("metadatos", str(exc)) from exc
    if meta["owner"] != pkg.get("owner") or meta["file_id"] != pkg.get("file_id"):
        raise PackageError("metadatos", "la AAD no corresponde al archivo solicitado")
    if meta["size"] != len(raw["ciphertext"]):
        raise PackageError("metadatos", "el tamaño del ciphertext no coincide con la AAD")
    t(f"AAD coherente: dueño={meta['owner']}, fecha={meta['timestamp']}, {meta['size']} bytes")
    return meta


def unwrap_session_key(pkg: dict[str, Any], my_priv: RSAPrivateKey, trace: Trace | None = None) -> bytearray:
    """Paso 4: K_s = RSA-OAEP-Dec(priv, W). Devuelve un bytearray que el llamador debe borrar."""
    t = trace or _no_trace
    wrapped = _decode(pkg)["wrapped_key"]
    try:
        key = oaep_decrypt(my_priv, wrapped)
    except DecryptionError as exc:
        raise PackageError("clave de sesión", "no se pudo desenvolver con su clave privada (no autorizado)") from exc
    if len(key) != SESSION_KEY_BYTES:
        zeroize(key)
        raise PackageError("clave de sesión", "longitud de clave de sesión inválida")
    t(f"Clave de sesión desenvuelta con RSA-OAEP usando mi clave privada (envuelta: {_short(wrapped)})")
    return key


def open_package(pkg: dict[str, Any], my_priv: RSAPrivateKey, owner_pub: RSAPublicKey,
                 trace: Trace | None = None) -> OpenedFile:
    """Verifica y descifra un paquete descargado. Lanza PackageError ante cualquier fallo."""
    t = trace or _no_trace
    meta = verify_signature(pkg, owner_pub, t)
    raw = _decode(pkg)
    session_key = unwrap_session_key(pkg, my_priv, t)
    gcm = AESGCM(session_key)
    try:
        inner = gcm.decrypt(raw["nonce"], raw["ciphertext"], raw["tag"], raw["aad"])
    except InvalidTag as exc:
        raise PackageError("integridad", "tag AES-GCM inválido: ciphertext o AAD alterados") from exc
    finally:
        gcm.wipe()
        zeroize(session_key)
    t(f"Tag AES-GCM verificado ({raw['tag'].hex()[:16]}...) y contenido descifrado")
    t("Clave de sesión en claro borrada de la memoria")
    try:
        filename, data = P.unpack_plaintext(inner)
    except P.ProtocolError as exc:
        raise PackageError("contenido", str(exc)) from exc
    t(f"Encabezado interno descifrado: nombre real '{filename}', {len(data):,} bytes".replace(",", "."))
    return OpenedFile(meta["file_id"], meta["owner"], filename, data, meta)


def check_integrity(pkg: dict[str, Any], my_priv: RSAPrivateKey, owner_pub: RSAPublicKey,
                    trace: Trace | None = None) -> dict[str, Any]:
    """Verificación completa (firma + clave + tag GCM) sin descifrar el contenido."""
    t = trace or _no_trace
    meta = verify_signature(pkg, owner_pub, t)
    raw = _decode(pkg)
    session_key = unwrap_session_key(pkg, my_priv, t)
    gcm = AESGCM(session_key)
    try:
        if not gcm.verify(raw["nonce"], raw["ciphertext"], raw["tag"], raw["aad"]):
            raise PackageError("integridad", "tag AES-GCM inválido: ciphertext o AAD alterados")
    finally:
        gcm.wipe()
        zeroize(session_key)
    t(f"Tag AES-GCM VÁLIDO ({raw['tag'].hex()[:16]}...): contenido íntegro (sin descifrarlo)")
    return meta


def rewrap_for(pkg: dict[str, Any], my_priv: RSAPrivateKey, owner_pub: RSAPublicKey,
               recipient_pub: RSAPublicKey, trace: Trace | None = None, recipient_name: str = "") -> bytes:
    """Compartir: desenvuelve K_s localmente, confirma que es correcta (tag GCM) y la envuelve
    con la clave pública del destinatario."""
    t = trace or _no_trace
    verify_signature(pkg, owner_pub, t)
    raw = _decode(pkg)
    session_key = unwrap_session_key(pkg, my_priv, t)
    gcm = AESGCM(session_key)
    try:
        if not gcm.verify(raw["nonce"], raw["ciphertext"], raw["tag"], raw["aad"]):
            raise PackageError("integridad", "la clave de sesión no autentica el archivo")
        t("Tag AES-GCM confirma que la clave de sesión es la correcta")
        wrapped = oaep_encrypt(recipient_pub, session_key)
    finally:
        gcm.wipe()
        zeroize(session_key)
    t(f"Clave de sesión re-envuelta con RSA-OAEP para {recipient_name or 'el destinatario'}: {_short(wrapped)}")
    t("Clave de sesión en claro borrada de la memoria")
    return wrapped
