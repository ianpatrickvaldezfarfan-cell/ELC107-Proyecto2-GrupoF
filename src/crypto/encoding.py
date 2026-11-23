"""Formato propio de serialización de claves ("PEM-like" del Grupo F) y huellas.

No usamos ASN.1/DER ni librerías externas: definimos un formato TLV simple.

Binario (TLV):
    MAGIC  = b"GRPF"           (4 bytes)
    VER    = 0x01              (1 byte)
    TYPE   = 0x01 pública | 0x02 privada   (1 byte)
    luego una secuencia de campos:
        TAG (1 byte) || LEN (4 bytes, big-endian) || VALOR (entero big-endian sin signo)
    Pública: n(0x01), e(0x02)
    Privada: n, e, d(0x03), p(0x04), q(0x05), dP(0x06), dQ(0x07), qInv(0x08)

Armadura de texto (estilo PEM, RFC 7468 pero con etiquetas propias):
    -----BEGIN GRUPOF RSA PUBLIC KEY-----
    <base64 en líneas de 64 caracteres>
    -----END GRUPOF RSA PUBLIC KEY-----

Huella (fingerprint): SHA-256 de la codificación binaria de la clave PÚBLICA.
Se muestra en grupos de 4 hex para comparar fuera de banda (en persona,
por teléfono, etc.) y detectar que el servidor no sustituyó la clave
(ataque man-in-the-middle sobre el directorio de claves).

(`base64` es solo codificación de texto, no criptografía.)
"""

from __future__ import annotations

import base64
import binascii
import re

from .errors import CryptoError
from .rsa_core import RSAPrivateKey, RSAPublicKey, validate_private_key, validate_public_key
from .sha256 import sha256

MAGIC = b"GRPF"
VERSION = 0x01
TYPE_PUBLIC = 0x01
TYPE_PRIVATE = 0x02

_PUB_FIELDS = ("n", "e")
_PRIV_FIELDS = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")
_TAGS = {name: i + 1 for i, name in enumerate(_PRIV_FIELDS)}

PUBLIC_LABEL = "GRUPOF RSA PUBLIC KEY"
PRIVATE_LABEL = "GRUPOF RSA PRIVATE KEY"
_MAX_FIELD = 4096  # bytes; ninguna componente de una clave de hasta 4096 bits lo supera


# ---------------------------------------------------------------------------
# TLV
# ---------------------------------------------------------------------------
def _int_to_bytes(x: int) -> bytes:
    return x.to_bytes(max(1, (x.bit_length() + 7) // 8), "big")


def _encode_tlv(key_type: int, fields: list[tuple[str, int]]) -> bytearray:
    out = bytearray(MAGIC + bytes([VERSION, key_type]))
    for name, value in fields:
        raw = _int_to_bytes(value)
        out += bytes([_TAGS[name]]) + len(raw).to_bytes(4, "big") + raw
    return out


def _decode_tlv(data: bytes, expected_type: int, names: tuple[str, ...]) -> dict[str, int]:
    if len(data) < 6 or data[:4] != MAGIC:
        raise CryptoError("formato de clave desconocido (magic)")
    if data[4] != VERSION:
        raise CryptoError("versión de formato de clave no soportada")
    if data[5] != expected_type:
        raise CryptoError("tipo de clave inesperado")
    pos, values = 6, {}
    inv_tags = {v: k for k, v in _TAGS.items()}
    while pos < len(data):
        if pos + 5 > len(data):
            raise CryptoError("clave truncada")
        tag = data[pos]
        length = int.from_bytes(data[pos + 1: pos + 5], "big")
        pos += 5
        if length == 0 or length > _MAX_FIELD or pos + length > len(data):
            raise CryptoError("longitud de campo inválida")
        name = inv_tags.get(tag)
        if name is None or name not in names or name in values:
            raise CryptoError("campo de clave inesperado o repetido")
        values[name] = int.from_bytes(data[pos: pos + length], "big")
        pos += length
    if set(values) != set(names):
        raise CryptoError("faltan campos en la clave")
    return values


def encode_public_key(pub: RSAPublicKey) -> bytes:
    return bytes(_encode_tlv(TYPE_PUBLIC, [("n", pub.n), ("e", pub.e)]))


def decode_public_key(data: bytes) -> RSAPublicKey:
    v = _decode_tlv(data, TYPE_PUBLIC, _PUB_FIELDS)
    pub = RSAPublicKey(v["n"], v["e"])
    validate_public_key(pub)
    return pub


def encode_private_key(priv: RSAPrivateKey) -> bytearray:
    """Codificación binaria de la clave privada (bytearray para poder borrarla)."""
    return _encode_tlv(TYPE_PRIVATE, [(f, getattr(priv, f)) for f in _PRIV_FIELDS])


def decode_private_key(data: bytes | bytearray) -> RSAPrivateKey:
    v = _decode_tlv(bytes(data), TYPE_PRIVATE, _PRIV_FIELDS)
    priv = RSAPrivateKey(**v)
    validate_private_key(priv)
    return priv


# ---------------------------------------------------------------------------
# Armadura de texto (PEM-like)
# ---------------------------------------------------------------------------
def armor(label: str, data: bytes) -> str:
    b64 = base64.b64encode(bytes(data)).decode("ascii")
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def dearmor(label: str, text: str) -> bytes:
    pattern = rf"-----BEGIN {re.escape(label)}-----\s*(.*?)\s*-----END {re.escape(label)}-----"
    m = re.search(pattern, text, re.DOTALL)
    if not m:
        raise CryptoError(f"no se encontró un bloque '{label}'")
    try:
        return base64.b64decode("".join(m.group(1).split()), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CryptoError("base64 inválido en la clave") from exc


def public_key_to_pem(pub: RSAPublicKey) -> str:
    return armor(PUBLIC_LABEL, encode_public_key(pub))


def public_key_from_pem(text: str) -> RSAPublicKey:
    return decode_public_key(dearmor(PUBLIC_LABEL, text))


def private_key_to_pem(priv: RSAPrivateKey) -> str:
    """¡Clave privada en CLARO! Solo para pruebas; el keystore la guarda cifrada."""
    return armor(PRIVATE_LABEL, encode_private_key(priv))


def private_key_from_pem(text: str) -> RSAPrivateKey:
    return decode_private_key(dearmor(PRIVATE_LABEL, text))


# ---------------------------------------------------------------------------
# Huellas
# ---------------------------------------------------------------------------
def fingerprint(pub: RSAPublicKey) -> str:
    """Huella = SHA-256(codificación binaria de la clave pública), en hex (64 caracteres)."""
    return sha256(encode_public_key(pub)).hex()


def format_fingerprint(fp_hex: str) -> str:
    """'ab12cd34...' -> 'AB12 CD34 ...' (16 grupos de 4) para leerla en voz alta."""
    fp_hex = fp_hex.upper()
    return " ".join(fp_hex[i:i + 4] for i in range(0, len(fp_hex), 4))
