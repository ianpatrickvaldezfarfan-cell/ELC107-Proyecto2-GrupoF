"""Definiciones del protocolo compartidas por cliente y servidor.

Aquí se fijan EXACTAMENTE los bytes que se firman y autentican, para que
cliente y servidor calculen lo mismo:

  * Mensaje de registro (prueba de posesión de la clave privada).
  * Mensaje de login challenge-response.
  * AAD del archivo (JSON canónico) y digest que se firma con RSA-PSS.

Separación de dominios: cada mensaje firmado empieza con una etiqueta distinta
("GRUPOF-v1/REGISTER", "GRUPOF-v1/LOGIN", "GRUPOF-v1/FILE"), de modo que una
firma obtenida en un contexto no sirve en otro (p. ej. una firma de login no
puede presentarse como firma de un archivo).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

from .crypto.sha256 import SHA256

PROTOCOL_VERSION = 1
USERNAME_RE = re.compile(r"^[a-z0-9_-]{3,32}$")
FILE_ID_RE = re.compile(r"^[0-9a-f]{32}$")

_TAG_REGISTER = b"GRUPOF-v1/REGISTER\x00"
_TAG_LOGIN = b"GRUPOF-v1/LOGIN\x00"
_TAG_FILE = b"GRUPOF-v1/FILE\x00"


class ProtocolError(ValueError):
    """Datos mal formados según el protocolo."""


# ---------------------------------------------------------------------------
# Codificación
# ---------------------------------------------------------------------------
def b64e(data: bytes) -> str:
    return base64.b64encode(bytes(data)).decode("ascii")


def b64d(text: str) -> bytes:
    if not isinstance(text, str):
        raise ProtocolError("se esperaba texto base64")
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError("base64 inválido") from exc


def canonical_json(obj: Any) -> bytes:
    """JSON canónico: claves ordenadas, sin espacios, UTF-8. Mismo objeto -> mismos bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def validate_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        raise ProtocolError("nombre de usuario inválido (3-32 caracteres: a-z, 0-9, _ o -)")
    return username


def _lp(data: bytes) -> bytes:
    """Prefijo de longitud de 8 bytes (big-endian) + datos: evita ambigüedades al concatenar."""
    return len(data).to_bytes(8, "big") + data


# ---------------------------------------------------------------------------
# Mensajes firmados
# ---------------------------------------------------------------------------
def register_message(username: str, fingerprint_hex: str) -> bytes:
    """Lo que el usuario firma al registrarse: prueba que posee la clave privada."""
    return _TAG_REGISTER + _lp(username.encode("utf-8")) + _lp(fingerprint_hex.encode("ascii"))


def login_message(username: str, nonce: bytes) -> bytes:
    """Lo que el usuario firma para responder al challenge del servidor."""
    return _TAG_LOGIN + _lp(username.encode("utf-8")) + _lp(nonce)


def build_aad(file_id: str, owner: str, timestamp: str, ciphertext_size: int) -> bytes:
    """AAD del archivo: metadatos autenticados (NO cifrados) por AES-GCM y cubiertos por la firma.

    Contiene SOLO lo que el servidor necesita para el control de acceso. El nombre
    real del archivo y su tamaño original van CIFRADOS en el encabezado interno
    (ver pack_plaintext), así que el servidor no los conoce.
    """
    return canonical_json({
        "v": PROTOCOL_VERSION,
        "alg": "AES-256-GCM",
        "file_id": file_id,
        "owner": owner,
        "timestamp": timestamp,
        "size": ciphertext_size,
    })


_AAD_KEYS = {"v", "alg", "file_id", "owner", "timestamp", "size"}


def parse_aad(aad: bytes) -> dict[str, Any]:
    try:
        meta = json.loads(aad.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("AAD no es JSON válido") from exc
    if not isinstance(meta, dict) or set(meta) != _AAD_KEYS:
        raise ProtocolError("AAD incompleta o con campos inesperados")
    if canonical_json(meta) != aad:
        raise ProtocolError("AAD no canónica")
    if meta["v"] != PROTOCOL_VERSION or meta["alg"] != "AES-256-GCM":
        raise ProtocolError("versión/algoritmo de AAD no soportado")
    if not isinstance(meta["file_id"], str) or not FILE_ID_RE.match(meta["file_id"]):
        raise ProtocolError("file_id inválido")
    if not isinstance(meta["size"], int) or meta["size"] < 0:
        raise ProtocolError("tamaño inválido en la AAD")
    return meta


# ---------------------------------------------------------------------------
# Encabezado interno (va DENTRO del texto claro, por lo tanto se cifra)
# ---------------------------------------------------------------------------
#   texto claro = "GFPT" || 0x01 || LEN_HEADER (4 B) || header_json || datos
#   header_json = {"filename": <nombre real>, "size": <tamaño original>}
_PT_MAGIC = b"GFPT\x01"
_MAX_HEADER = 4096
MAX_FILENAME_LEN = 255


def pack_plaintext(filename: str, data: bytes) -> bytes:
    """Antepone a los datos el encabezado con el nombre y tamaño reales (se cifrará todo junto)."""
    if not filename or len(filename) > MAX_FILENAME_LEN:
        raise ProtocolError("nombre de archivo vacío o demasiado largo")
    header = canonical_json({"filename": filename, "size": len(data)})
    return _PT_MAGIC + len(header).to_bytes(4, "big") + header + bytes(data)


def unpack_plaintext(plaintext: bytes) -> tuple[str, bytes]:
    """Separa el encabezado interno y valida que el tamaño declarado coincida."""
    if plaintext[:5] != _PT_MAGIC or len(plaintext) < 9:
        raise ProtocolError("encabezado interno ausente o con versión desconocida")
    hlen = int.from_bytes(plaintext[5:9], "big")
    if hlen > _MAX_HEADER or 9 + hlen > len(plaintext):
        raise ProtocolError("encabezado interno con longitud inválida")
    try:
        header = json.loads(plaintext[9:9 + hlen].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("encabezado interno inválido") from exc
    if not isinstance(header, dict) or not isinstance(header.get("filename"), str) \
            or not isinstance(header.get("size"), int):
        raise ProtocolError("encabezado interno incompleto")
    data = plaintext[9 + hlen:]
    if header["size"] != len(data):
        raise ProtocolError("el tamaño original no coincide con los datos")
    return header["filename"], data


def file_signature_digest(ciphertext: bytes, nonce: bytes, tag: bytes, aad: bytes) -> bytes:
    """Digest que se firma con RSA-PSS (variante prehashed):

        SHA-256( "GRUPOF-v1/FILE" || LP(ciphertext) || LP(nonce) || LP(tag) || LP(AAD) )

    Es el "SHA-256 de (ciphertext || nonce || tag || AAD)" del enunciado, reforzado
    con prefijos de longitud (LP): sin ellos, bytes del final de un campo podrían
    "moverse" al siguiente y producir otra tupla distinta con el mismo digest.
    """
    h = SHA256(_TAG_FILE)
    h.update(len(ciphertext).to_bytes(8, "big"))
    h.update(ciphertext)          # SHA256.update procesa por bloques: sirve para archivos grandes
    h.update(_lp(nonce))
    h.update(_lp(tag))
    h.update(_lp(aad))
    return h.digest()
