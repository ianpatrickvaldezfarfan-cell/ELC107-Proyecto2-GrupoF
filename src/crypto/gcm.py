"""AES-GCM implementado desde cero según NIST SP 800-38D (Galois/Counter Mode).

Notación (SP 800-38D §6 y §7):
    H   = CIPH_K(0^128)                                   subclave de hash
    J0  = IV || 0^31 || 1                                  si len(IV) = 96 bits
        = GHASH_H(IV || 0^{s+64} || [len(IV)]_64)          en otro caso
    C   = GCTR_K(inc32(J0), P)                             cifrado tipo contador
    S   = GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)
    T   = MSB_t(GCTR_K(J0, S))                             tag (t = 128 bits aquí)

GHASH (§6.4):  X_0 = 0,   X_i = (X_{i-1} ⊕ B_i) · H,   GHASH = X_m
Multiplicación en GF(2^128) (§6.3, Algoritmo 1), con el polinomio
    f(x) = x^128 + x^7 + x^2 + x + 1
y la convención "reflejada" de GCM: el bit MÁS a la izquierda del bloque es el
coeficiente de x^0. Multiplicar por x equivale a desplazar a la DERECHA y, si
se cae un 1 por el extremo, reducir con R = 11100001 || 0^120 (0xE1 << 120).

Se implementan dos multiplicaciones:
  * `gf128_mul`: Algoritmo 1 literal, bit a bit (128 iteraciones). Didáctica.
  * `GHashTable`: tablas de 8 bits precalculadas por clave H. Como la
    multiplicación es LINEAL sobre GF(2), X·H = ⊕_{i=0}^{15} (byte_i(X) en posición i)·H,
    así que se precalculan 16 tablas de 256 entradas (M_i[b] = b·x^{8i}·H) y cada
    multiplicación se reduce a 16 consultas y 15 XOR. Los tests comprueban
    que coincide con `gf128_mul`.

Decisiones de seguridad:
  - Nonce de 96 bits (recomendado por §8.2; con nonces aleatorios el límite es
    2^32 mensajes por clave). En este sistema cada archivo usa una clave de
    sesión NUEVA, así que la reutilización de (clave, nonce) es prácticamente imposible.
  - Tag fijo de 128 bits (no se aceptan tags truncados).
  - Al descifrar se verifica el tag ANTES de producir el texto claro y la
    comparación es en tiempo constante; si falla no se devuelve nada (§7.2 paso 8).
"""

from __future__ import annotations

from .aes import AES
from .errors import InvalidTag
from .utils import constant_time_equal

NONCE_SIZE = 12   # 96 bits
TAG_SIZE = 16     # 128 bits
_MASK128 = (1 << 128) - 1
_R = 0xE1 << 120  # R = 11100001 || 0^120

# Límites de SP 800-38D §5.2.1.1
_MAX_PLAINTEXT_BYTES = ((1 << 39) - 256) // 8
_MAX_AAD_BYTES = ((1 << 64) - 1) // 8


# ---------------------------------------------------------------------------
# Multiplicación en GF(2^128)
# ---------------------------------------------------------------------------
def gf128_mul(x: int, y: int) -> int:
    """Z = X · Y en GF(2^128), Algoritmo 1 de SP 800-38D §6.3 (bit a bit).

        Z_0 = 0, V_0 = Y
        para i = 0..127:
            Z_{i+1} = Z_i            si x_i = 0
                    = Z_i ⊕ V_i      si x_i = 1
            V_{i+1} = V_i >> 1        si LSB_1(V_i) = 0
                    = (V_i >> 1) ⊕ R  si LSB_1(V_i) = 1
    (x_i es el i-ésimo bit de X contando desde la IZQUIERDA.)
    """
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _mul_x(v: int) -> int:
    """V · x en GF(2^128) (un paso de V del Algoritmo 1)."""
    return (v >> 1) ^ _R if v & 1 else v >> 1


class GHashTable:
    """Multiplicación rápida por una H fija mediante 16 tablas de 256 entradas."""

    __slots__ = ("_tables",)

    def __init__(self, h: int) -> None:
        # basis[k] = H · x^k   (k = 0..127). El bit (127-k) de un bloque representa x^k.
        basis = []
        v = h
        for _ in range(128):
            basis.append(v)
            v = _mul_x(v)
        tables = []
        for i in range(16):                       # posición del byte (0 = más a la izquierda)
            t = [0] * 256
            for b in range(1, 256):
                low = b & -b                      # bit menos significativo encendido de b
                j = 8 - low.bit_length()          # su índice contando desde el MSB (0x80 -> 0)
                # Por linealidad: M_i[b] = M_i[b sin ese bit] ⊕ H·x^{8i+j}
                t[b] = t[b ^ low] ^ basis[8 * i + j]
            tables.append(tuple(t))
        self._tables = tuple(tables)

    def mul(self, x: int) -> int:
        """Devuelve X · H."""
        t = self._tables
        b = x.to_bytes(16, "big")
        return (t[0][b[0]] ^ t[1][b[1]] ^ t[2][b[2]] ^ t[3][b[3]]
                ^ t[4][b[4]] ^ t[5][b[5]] ^ t[6][b[6]] ^ t[7][b[7]]
                ^ t[8][b[8]] ^ t[9][b[9]] ^ t[10][b[10]] ^ t[11][b[11]]
                ^ t[12][b[12]] ^ t[13][b[13]] ^ t[14][b[14]] ^ t[15][b[15]])


# ---------------------------------------------------------------------------
# GHASH y GCTR
# ---------------------------------------------------------------------------
def _ghash_update(table: GHashTable, x: int, data: bytes) -> int:
    """Absorbe `data` en GHASH, rellenando con ceros el último bloque parcial (0^v / 0^u)."""
    mul = table.mul
    n = len(data)
    full = n - (n % 16)
    for i in range(0, full, 16):
        x = mul(x ^ int.from_bytes(data[i:i + 16], "big"))
    if full < n:
        last = data[full:] + b"\x00" * (16 - (n - full))
        x = mul(x ^ int.from_bytes(last, "big"))
    return x


def ghash(h: int, aad: bytes, ciphertext: bytes) -> int:
    """GHASH_H(A || 0^v || C || 0^u || [len(A)]_64 || [len(C)]_64)  (SP 800-38D §7.1 paso 5)."""
    table = GHashTable(h)
    return _ghash_with_table(table, aad, ciphertext)


def _ghash_with_table(table: GHashTable, aad: bytes, ciphertext: bytes) -> int:
    x = _ghash_update(table, 0, aad)
    x = _ghash_update(table, x, ciphertext)
    length_block = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    return table.mul(x ^ length_block)


def inc32(block: int) -> int:
    """inc_32 (§6.2): incrementa módulo 2^32 los 32 bits menos significativos."""
    return (block & ~0xFFFFFFFF & _MASK128) | ((block + 1) & 0xFFFFFFFF)


def gctr(cipher: AES, icb: int, data: bytes) -> bytes:
    """GCTR_K(ICB, X) (§6.5): Y_i = X_i ⊕ CIPH_K(CB_i), CB_{i+1} = inc32(CB_i).

    Implementación: se genera todo el flujo de clave y se hace un único XOR entre
    enteros grandes (mucho más rápido en Python que XOR byte a byte).
    """
    n = len(data)
    if n == 0:
        return b""
    n_blocks = -(-n // 16)
    high = icb & ~0xFFFFFFFF & _MASK128
    low = icb & 0xFFFFFFFF
    enc = cipher.encrypt_int
    keystream = b"".join(
        enc(high | ((low + i) & 0xFFFFFFFF)).to_bytes(16, "big") for i in range(n_blocks)
    )[:n]
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(n, "big")


# ---------------------------------------------------------------------------
# API de alto nivel
# ---------------------------------------------------------------------------
class AESGCM:
    """AES-GCM con una clave fija (se reutiliza la expansión de clave y las tablas de H)."""

    __slots__ = ("_cipher", "_table")

    def __init__(self, key: bytes | bytearray) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("la clave debe tener 16, 24 o 32 bytes (el proyecto usa 32 = AES-256)")
        self._cipher = AES(key)
        h = self._cipher.encrypt_int(0)                   # H = CIPH_K(0^128)
        self._table = GHashTable(h)

    def _j0(self, nonce: bytes) -> int:
        if len(nonce) == 0:
            raise ValueError("el nonce no puede estar vacío")
        if len(nonce) == NONCE_SIZE:
            return (int.from_bytes(nonce, "big") << 32) | 1     # IV || 0^31 || 1
        # IV de otra longitud: J0 = GHASH(IV || 0^{s+64} || [len(IV)]_64)
        x = _ghash_update(self._table, 0, nonce)
        return self._table.mul(x ^ (len(nonce) * 8))

    def _tag(self, j0: int, aad: bytes, ciphertext: bytes) -> bytes:
        s = _ghash_with_table(self._table, aad, ciphertext)
        return (self._cipher.encrypt_int(j0) ^ s).to_bytes(16, "big")  # T = GCTR(J0, S)

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        """Cifrado autenticado (SP 800-38D §7.1). Devuelve (ciphertext, tag de 16 bytes)."""
        if len(plaintext) > _MAX_PLAINTEXT_BYTES or len(aad) > _MAX_AAD_BYTES:
            raise ValueError("datos demasiado largos para GCM")
        j0 = self._j0(nonce)
        ciphertext = gctr(self._cipher, inc32(j0), bytes(plaintext))
        return ciphertext, self._tag(j0, bytes(aad), ciphertext)

    def decrypt(self, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
        """Descifrado autenticado (SP 800-38D §7.2).

        Calcula el tag esperado y lo compara en tiempo constante ANTES de
        descifrar. Si no coincide lanza InvalidTag y no se produce texto claro.
        """
        if len(tag) != TAG_SIZE:
            raise InvalidTag()
        if len(ciphertext) > _MAX_PLAINTEXT_BYTES or len(aad) > _MAX_AAD_BYTES:
            raise InvalidTag()
        j0 = self._j0(nonce)
        expected = self._tag(j0, bytes(aad), bytes(ciphertext))
        if not constant_time_equal(expected, bytes(tag)):
            raise InvalidTag()
        return gctr(self._cipher, inc32(j0), bytes(ciphertext))

    def wipe(self) -> None:
        self._cipher.wipe()


def aes_gcm_encrypt(key: bytes | bytearray, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Atajo: (ciphertext, tag) = AES-GCM-Enc(key, nonce, plaintext, aad)."""
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(key: bytes | bytearray, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    """Atajo: plaintext = AES-GCM-Dec(...) o InvalidTag."""
    return AESGCM(key).decrypt(nonce, ciphertext, tag, aad)
