"""Pruebas del núcleo RSA: generación de claves, CRT, cegado y contramedida de Bellcore."""

import dataclasses
import secrets

import pytest

from src.crypto import rsa_core as R
from src.crypto.arith import gcd, lcm
from src.crypto.errors import CryptoError
from tests.rsa_helpers import to_cryptography_private


def _check_key(k: R.RSAPrivateKey, bits: int):
    assert k.n.bit_length() == bits
    assert k.p * k.q == k.n and k.p != k.q
    assert abs(k.p - k.q) > 1 << (bits // 2 - 100)
    assert k.e == 65537
    assert (k.e * k.d) % lcm(k.p - 1, k.q - 1) == 1
    assert k.dp == k.d % (k.p - 1) and k.dq == k.d % (k.q - 1)
    assert (k.qinv * k.q) % k.p == 1
    R.validate_private_key(k)


def test_clave_2048(our_key):
    _check_key(our_key, 2048)
    # `cryptography` acepta nuestros números (valida su consistencia internamente)
    to_cryptography_private(our_key)


def test_clave_1024_con_estadisticas():
    st = R.KeyGenStats()
    k = R.generate_keypair(1024, stats=st)
    _check_key(k, 1024)
    assert st.prime_stats.primes_found >= 2 and st.prime_stats.candidates >= 2


@pytest.mark.slow
def test_clave_3072():
    _check_key(R.generate_keypair(3072), 3072)


def test_tamano_no_soportado():
    with pytest.raises(ValueError):
        R.generate_keypair(512)


def test_ida_y_vuelta_crt_cegado_y_sin_crt(our_key):
    pub = our_key.public_key()
    for _ in range(5):
        m = secrets.randbelow(our_key.n)
        c = R.rsaep(pub, m)
        assert c == pow(m, our_key.e, our_key.n)          # pow nativo solo en tests
        assert R.rsadp(our_key, c) == m                    # CRT + cegado
        assert R.rsadp(our_key, c, blinding=False) == m    # CRT sin cegado
        assert R.rsadp_no_crt(our_key, c) == m             # c^d mod n directo


def test_firma_cruda(our_key):
    m = secrets.randbelow(our_key.n)
    s = R.rsasp1(our_key, m)
    assert R.rsavp1(our_key.public_key(), s) == m


def test_rangos(our_key):
    with pytest.raises(CryptoError):
        R.rsaep(our_key.public_key(), our_key.n)
    with pytest.raises(CryptoError):
        R.rsadp(our_key, our_key.n)


def test_contramedida_bellcore(our_key):
    """Una firma CRT con un fallo en m1 permite factorizar n: gcd(s^e − m, n) = q.
    Por eso rsasp1 verifica la firma antes de devolverla."""
    faulty = dataclasses.replace(our_key, dp=our_key.dp ^ 1)   # simula un fallo de hardware
    m = secrets.randbelow(our_key.n)
    s_bad = R._crt_exp(faulty, m)
    # El atacante recupera un factor con una sola firma defectuosa:
    assert gcd(pow(s_bad, our_key.e, our_key.n) - m, our_key.n) == our_key.q
    # Nuestra implementación detecta el fallo y no entrega la firma:
    with pytest.raises(CryptoError):
        R.rsasp1(faulty, m)


def test_validacion_detecta_inconsistencias(our_key):
    with pytest.raises(CryptoError):
        R.validate_private_key(dataclasses.replace(our_key, d=our_key.d + 2))
    with pytest.raises(CryptoError):
        R.validate_private_key(dataclasses.replace(our_key, qinv=our_key.qinv + 1))


def test_repr_no_filtra_secretos(our_key):
    assert str(our_key.d) not in repr(our_key)
