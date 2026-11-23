"""Pruebas de PBKDF2-HMAC-SHA256 (RFC 8018).

Vectores: los publicados para PBKDF2-HMAC-SHA256 (RFC 7914 §11 y los vectores
de uso común con P="password", S="salt"), más validación cruzada con `cryptography`.
"""

import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.crypto import kdf
from src.crypto.kdf import pbkdf2_hmac_sha256

VECTORS = [
    (b"password", b"salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"),
    (b"password", b"salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"),
    (b"password", b"salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"),
    # RFC 7914 §11 (dkLen = 64 -> dos bloques T_1 || T_2)
    (b"passwd", b"salt", 1, 64,
     "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
     "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
]


@pytest.mark.parametrize("p,s,c,dklen,expected", VECTORS)
def test_vectores(p, s, c, dklen, expected):
    assert pbkdf2_hmac_sha256(p, s, c, dklen).hex() == expected


@pytest.mark.slow
def test_rfc7914_80000_iteraciones():
    expected = ("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d")
    assert pbkdf2_hmac_sha256(b"Password", b"NaCl", 80000, 64).hex() == expected


def test_validacion_cruzada_cryptography():
    for dklen in (1, 16, 32, 33, 64, 100):
        pw, salt = secrets.token_bytes(20), secrets.token_bytes(16)
        ref = PBKDF2HMAC(algorithm=hashes.SHA256(), length=dklen, salt=salt, iterations=50).derive(pw)
        assert bytes(pbkdf2_hmac_sha256(pw, salt, 50, dklen)) == ref


def test_devuelve_bytearray_borrable():
    dk = pbkdf2_hmac_sha256(bytearray(b"pw"), b"salt", 10)
    assert isinstance(dk, bytearray)


def test_parametros_invalidos():
    with pytest.raises(ValueError):
        pbkdf2_hmac_sha256(b"p", b"s", 0)
    with pytest.raises(ValueError):
        pbkdf2_hmac_sha256(b"p", b"s", 1, 0)


def test_iteraciones_por_defecto(monkeypatch):
    monkeypatch.delenv("GRUPOF_KDF_ITERS", raising=False)
    assert kdf.default_iterations() == 100_000
    monkeypatch.setenv("GRUPOF_KDF_ITERS", "1234")
    assert kdf.default_iterations() == 1234
