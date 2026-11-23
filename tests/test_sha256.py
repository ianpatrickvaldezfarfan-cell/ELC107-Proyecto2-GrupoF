"""Pruebas de SHA-256: vectores NIST (FIPS 180-4 / CAVP), validación cruzada y origen de constantes."""

import math
import secrets

import pytest
from cryptography.hazmat.primitives import hashes

from src.crypto import sha256 as S
from src.crypto.sha256 import SHA256, sha256, sha256_hex

# Vectores de ejemplo de NIST ("SHA256.pdf", Cryptographic Standards and Guidelines).
NIST_VECTORS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",  # 448 bits
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        b"ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",  # 896 bits
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
]


def _ref(data: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


@pytest.mark.parametrize("msg,expected", NIST_VECTORS)
def test_vectores_nist(msg, expected):
    assert sha256_hex(msg) == expected


def test_millon_de_a():
    # Vector NIST: 1.000.000 repeticiones de 'a' (15.625 bloques)
    assert sha256(b"a" * 1_000_000).hex() == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"


def test_bordes_de_relleno_contra_cryptography():
    # Longitudes alrededor de los límites de bloque: 55/56 bytes es donde el relleno
    # pasa a necesitar un bloque extra (FIPS 180-4 §5.1.1).
    for n in list(range(0, 130)) + [255, 256, 1000, 4097]:
        msg = secrets.token_bytes(n)
        assert sha256(msg) == _ref(msg), f"falló con longitud {n}"


def test_actualizacion_incremental_equivale_a_un_solo_bloque():
    data = secrets.token_bytes(1000)
    h = SHA256()
    for chunk in (data[:1], data[1:63], data[63:64], data[64:200], data[200:]):
        h.update(chunk)
    assert h.digest() == sha256(data)
    # digest() no altera el estado; copy() es independiente
    c = h.copy()
    c.update(b"x")
    assert h.digest() == sha256(data)
    assert c.digest() == sha256(data + b"x")


def test_compresion_optimizada_igual_a_la_didactica():
    for _ in range(20):
        block = secrets.token_bytes(64)
        assert S.compress(S.H0, block) == S.compress_reference(S.H0, block)


def _first_primes(n):
    primes, k = [], 2
    while len(primes) < n:
        if all(k % p for p in primes if p * p <= k):
            primes.append(k)
        k += 1
    return primes


def _icbrt(n):
    """Raíz cúbica entera (Newton)."""
    x = 1 << ((n.bit_length() + 2) // 3)
    while True:
        y = (2 * x + n // (x * x)) // 3
        if y >= x:
            return x
        x = y


def test_constantes_derivadas_de_primos():
    """K_t = 32 bits fraccionarios de cbrt(primo_t); H0 = de sqrt(primo) (FIPS 180-4 §4.2.2, §5.3.3)."""
    primes = _first_primes(64)
    k = tuple(_icbrt(p << 96) & 0xFFFFFFFF for p in primes)
    h0 = tuple(math.isqrt(p << 64) & 0xFFFFFFFF for p in primes[:8])
    assert k == S.K
    assert h0 == S.H0
