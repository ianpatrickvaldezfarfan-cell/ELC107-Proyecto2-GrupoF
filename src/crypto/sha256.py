"""SHA-256 implementado desde cero según FIPS 180-4 (Secure Hash Standard).

Estructura (Merkle–Damgård):
    1. Relleno (FIPS 180-4 §5.1.1): M || 1 || 0^k || len(M) en 64 bits,
       con k mínimo tal que (ℓ + 1 + k) ≡ 448 (mod 512).
    2. División en bloques de 512 bits (§5.2.1).
    3. Valor inicial H(0) (§5.3.3): primeros 32 bits de la parte fraccionaria
       de las raíces cuadradas de los 8 primeros primos.
    4. Para cada bloque, función de compresión (§6.2.2):
         - Programa de mensaje: W_t = M_t                       (0 <= t <= 15)
                                W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}
         - 64 rondas con las constantes K_t (§4.2.2): primeros 32 bits de la
           parte fraccionaria de las raíces cúbicas de los 64 primeros primos.
         - H(i) = H(i-1) + (a, b, ..., h)   (suma mod 2^32 palabra a palabra)

Todas las sumas son módulo 2^32. Las funciones lógicas (§4.1.2) son:
    Ch(x,y,z)  = (x ∧ y) ⊕ (¬x ∧ z)
    Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)
    Σ0(x) = ROTR^2(x)  ⊕ ROTR^13(x) ⊕ ROTR^22(x)
    Σ1(x) = ROTR^6(x)  ⊕ ROTR^11(x) ⊕ ROTR^25(x)
    σ0(x) = ROTR^7(x)  ⊕ ROTR^18(x) ⊕ SHR^3(x)
    σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)
"""

from __future__ import annotations

import struct

_MASK32 = 0xFFFFFFFF

BLOCK_SIZE = 64   # bytes (512 bits)
DIGEST_SIZE = 32  # bytes (256 bits)

# FIPS 180-4 §4.2.2 — constantes K_t (raíces cúbicas de los 64 primeros primos).
# tests/test_sha256.py las recalcula a partir de los primos para demostrar su origen.
K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)

# FIPS 180-4 §5.3.3 — valor hash inicial H(0) (raíces cuadradas de los 8 primeros primos).
H0 = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)


# ---------------------------------------------------------------------------
# Funciones lógicas de FIPS 180-4 §4.1.2 (versión didáctica, una por ecuación)
# ---------------------------------------------------------------------------
def rotr(x: int, n: int) -> int:
    """ROTR^n(x) = (x >> n) ∨ (x << (32 - n))   — FIPS 180-4 §3.2."""
    return ((x >> n) | (x << (32 - n))) & _MASK32


def ch(x: int, y: int, z: int) -> int:
    """Ch(x,y,z) = (x ∧ y) ⊕ (¬x ∧ z)   — "elige" y o z según cada bit de x."""
    return (x & y) ^ (~x & z & _MASK32)


def maj(x: int, y: int, z: int) -> int:
    """Maj(x,y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ (y ∧ z)   — voto mayoritario bit a bit."""
    return (x & y) ^ (x & z) ^ (y & z)


def big_sigma0(x: int) -> int:
    """Σ0(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)."""
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def big_sigma1(x: int) -> int:
    """Σ1(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)."""
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def small_sigma0(x: int) -> int:
    """σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)."""
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def small_sigma1(x: int) -> int:
    """σ1(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)."""
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def compress_reference(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """Función de compresión (FIPS 180-4 §6.2.2) escrita literalmente con las
    funciones anteriores. Es lenta pero fácil de seguir; `compress` es la
    versión optimizada y los tests comprueban que ambas coinciden."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("el bloque debe tener 64 bytes")
    # Paso 1: programa de mensaje W_0..W_63
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        w.append((small_sigma1(w[t - 2]) + w[t - 7] + small_sigma0(w[t - 15]) + w[t - 16]) & _MASK32)
    # Paso 2: inicializar las 8 variables de trabajo con H(i-1)
    a, b, c, d, e, f, g, h = state
    # Paso 3: 64 rondas
    for t in range(64):
        t1 = (h + big_sigma1(e) + ch(e, f, g) + K[t] + w[t]) & _MASK32
        t2 = (big_sigma0(a) + maj(a, b, c)) & _MASK32
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & _MASK32, c, b, a, (t1 + t2) & _MASK32
    # Paso 4: H(i) = H(i-1) + variables de trabajo
    return tuple((x + y) & _MASK32 for x, y in zip(state, (a, b, c, d, e, f, g, h)))


def compress(state: tuple[int, ...], block: bytes) -> tuple[int, ...]:
    """Función de compresión optimizada (mismas ecuaciones, operaciones en línea).

    Optimizaciones (equivalentes algebraicamente):
      - Las rotaciones se escriben en línea y se enmascara a 32 bits una sola
        vez tras los XOR (los bits por encima de 32 se descartan igual).
      - Ch(e,f,g) = g ⊕ (e ∧ (f ⊕ g))       (evita el ¬ sobre enteros de Python)
      - Maj(a,b,c) = (a ∧ b) ∨ (c ∧ (a ∨ b))
    """
    M = _MASK32
    w = list(struct.unpack(">16I", block))
    for t in range(16, 64):
        x = w[t - 15]
        s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
        x = w[t - 2]
        s1 = ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10)
        w.append((w[t - 16] + (s0 & M) + w[t - 7] + (s1 & M)) & M)

    a, b, c, d, e, f, g, h = state
    for t in range(64):
        S1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) & M
        t1 = (h + S1 + (g ^ (e & (f ^ g))) + K[t] + w[t]) & M
        S0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) & M
        t2 = S0 + ((a & b) | (c & (a | b)))
        h = g
        g = f
        f = e
        e = (d + t1) & M
        d = c
        c = b
        b = a
        a = (t1 + t2) & M

    s = state
    return (
        (s[0] + a) & M, (s[1] + b) & M, (s[2] + c) & M, (s[3] + d) & M,
        (s[4] + e) & M, (s[5] + f) & M, (s[6] + g) & M, (s[7] + h) & M,
    )


def state_to_bytes(state: tuple[int, ...]) -> bytes:
    """Serializa las 8 palabras de 32 bits del estado en big-endian (el digest)."""
    return struct.pack(">8I", *state)


def pad_message_length(total_len: int) -> bytes:
    """Relleno de FIPS 180-4 §5.1.1 para un mensaje de `total_len` bytes:
    0x80, ceros hasta que len ≡ 56 (mod 64), y la longitud en bits (64 bits BE)."""
    zeros = (55 - total_len) % BLOCK_SIZE
    return b"\x80" + b"\x00" * zeros + struct.pack(">Q", (total_len * 8) & 0xFFFFFFFFFFFFFFFF)


class SHA256:
    """Objeto hash incremental con interfaz similar a hashlib (update/digest/copy).

    Permite hashear archivos grandes por partes sin cargarlos completos.
    """

    name = "sha256"
    block_size = BLOCK_SIZE
    digest_size = DIGEST_SIZE

    __slots__ = ("_state", "_buffer", "_length")

    def __init__(self, data: bytes | bytearray | memoryview = b"") -> None:
        self._state: tuple[int, ...] = H0
        self._buffer = bytearray()
        self._length = 0  # bytes procesados en total
        if data:
            self.update(data)

    def update(self, data: bytes | bytearray | memoryview) -> "SHA256":
        data = memoryview(data).cast("B")
        self._length += len(data)
        buf = self._buffer
        pos = 0
        # Completar el bloque pendiente, si lo hay
        if buf:
            need = BLOCK_SIZE - len(buf)
            buf += data[:need]
            pos = need
            if len(buf) < BLOCK_SIZE:
                return self
            self._state = compress(self._state, bytes(buf))
            buf.clear()
        # Procesar bloques completos directamente desde la entrada
        state = self._state
        n = len(data)
        while pos + BLOCK_SIZE <= n:
            state = compress(state, bytes(data[pos:pos + BLOCK_SIZE]))
            pos += BLOCK_SIZE
        self._state = state
        buf += data[pos:]
        return self

    def digest(self) -> bytes:
        """Devuelve el hash de 32 bytes sin alterar el estado (se puede seguir actualizando)."""
        tail = bytes(self._buffer) + pad_message_length(self._length)
        state = self._state
        for i in range(0, len(tail), BLOCK_SIZE):
            state = compress(state, tail[i:i + BLOCK_SIZE])
        return state_to_bytes(state)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> "SHA256":
        other = SHA256.__new__(SHA256)
        other._state = self._state
        other._buffer = bytearray(self._buffer)
        other._length = self._length
        return other


def sha256(data: bytes | bytearray | memoryview = b"") -> bytes:
    """Atajo: SHA-256(data) como 32 bytes."""
    return SHA256(data).digest()


def sha256_hex(data: bytes | bytearray | memoryview = b"") -> str:
    return SHA256(data).hexdigest()
