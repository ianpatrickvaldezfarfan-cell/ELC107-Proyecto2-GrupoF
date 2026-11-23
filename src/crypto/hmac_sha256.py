"""HMAC-SHA256 implementado desde cero según RFC 2104 (y FIPS 198-1).

Definición (RFC 2104 §2), con B = 64 bytes (tamaño de bloque de SHA-256):

    K0   = K                     si |K| = B
         = H(K) || 0x00...       si |K| > B   (se hashea y se rellena con ceros)
         = K || 0x00...          si |K| < B   (se rellena con ceros hasta B)
    ipad = 0x36 repetido B veces
    opad = 0x5C repetido B veces

    HMAC(K, m) = H( (K0 ⊕ opad) || H( (K0 ⊕ ipad) || m ) )

Optimización usada por PBKDF2: los bloques (K0 ⊕ ipad) y (K0 ⊕ opad) ocupan
exactamente un bloque de SHA-256, así que el estado tras comprimirlos puede
precalcularse UNA vez por clave. Cada HMAC posterior cuesta solo las
compresiones del mensaje (RFC 2104 §4, "Implementation Note").
"""

from __future__ import annotations

from .sha256 import BLOCK_SIZE, DIGEST_SIZE, SHA256, compress, sha256, state_to_bytes
from .utils import constant_time_equal, zeroize

_IPAD = 0x36
_OPAD = 0x5C


def _normalize_key(key: bytes | bytearray) -> bytearray:
    """Calcula K0 (RFC 2104 §2, pasos 1-3) como bytearray de 64 bytes."""
    if len(key) > BLOCK_SIZE:
        k0 = bytearray(sha256(key))
    else:
        k0 = bytearray(key)
    k0.extend(b"\x00" * (BLOCK_SIZE - len(k0)))
    return k0


class HMAC_SHA256:
    """HMAC-SHA256 incremental. Los estados interno/externo se precalculan en __init__."""

    digest_size = DIGEST_SIZE
    block_size = BLOCK_SIZE

    __slots__ = ("_inner", "_outer")

    def __init__(self, key: bytes | bytearray, msg: bytes | bytearray = b"") -> None:
        k0 = _normalize_key(key)
        ipad_block = bytearray(b ^ _IPAD for b in k0)   # K0 ⊕ ipad
        opad_block = bytearray(b ^ _OPAD for b in k0)   # K0 ⊕ opad
        self._inner = SHA256(ipad_block)
        self._outer = SHA256(opad_block)
        # Borrar copias de la clave que controlamos
        zeroize(k0)
        zeroize(ipad_block)
        zeroize(opad_block)
        if msg:
            self.update(msg)

    def update(self, msg: bytes | bytearray | memoryview) -> "HMAC_SHA256":
        self._inner.update(msg)
        return self

    def digest(self) -> bytes:
        inner_hash = self._inner.digest()            # H((K0 ⊕ ipad) || m)
        outer = self._outer.copy()
        outer.update(inner_hash)                     # H((K0 ⊕ opad) || inner_hash)
        return outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "HMAC_SHA256":
        other = HMAC_SHA256.__new__(HMAC_SHA256)
        other._inner = self._inner.copy()
        other._outer = self._outer.copy()
        return other

    # --- Acceso a los estados precalculados (lo usa PBKDF2) -------------------
    def _precomputed_states(self) -> tuple[tuple[int, ...], tuple[int, ...]]:
        """Estados SHA-256 tras absorber (K0⊕ipad) y (K0⊕opad). Solo válido sin mensaje previo."""
        if self._inner._length != BLOCK_SIZE or self._inner._buffer:
            raise RuntimeError("los estados precalculados solo existen antes de update()")
        return self._inner._state, self._outer._state


def hmac_sha256(key: bytes | bytearray, msg: bytes | bytearray | memoryview) -> bytes:
    """HMAC-SHA256(key, msg) en una sola llamada (32 bytes)."""
    return HMAC_SHA256(key, msg).digest()


def verify_hmac_sha256(key: bytes | bytearray, msg: bytes, tag: bytes) -> bool:
    """Verifica un tag HMAC en tiempo constante."""
    return constant_time_equal(hmac_sha256(key, msg), tag)


# ---------------------------------------------------------------------------
# Camino rápido para mensajes de exactamente 32 bytes (iteraciones de PBKDF2)
# ---------------------------------------------------------------------------
# Tras el bloque de pad (64 B), un mensaje de 32 B más su relleno SHA-256 cabe en
# un único bloque: 32 B de datos || 0x80 || 23 ceros || longitud total en bits
# (64 + 32) * 8 = 768 = 0x300. Así cada HMAC cuesta exactamente 2 compresiones.
_PAD_32_AFTER_BLOCK = b"\x80" + b"\x00" * 23 + (768).to_bytes(8, "big")


def hmac_sha256_32_fast(inner_state: tuple[int, ...], outer_state: tuple[int, ...], msg32: bytes) -> bytes:
    """HMAC de un mensaje de 32 bytes usando estados precalculados (2 compresiones)."""
    inner = state_to_bytes(compress(inner_state, msg32 + _PAD_32_AFTER_BLOCK))
    return state_to_bytes(compress(outer_state, inner + _PAD_32_AFTER_BLOCK))
