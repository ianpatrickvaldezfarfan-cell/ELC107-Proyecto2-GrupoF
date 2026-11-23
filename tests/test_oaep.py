"""Pruebas de RSA-OAEP (SHA-256, MGF1-SHA256) con validación cruzada contra `cryptography`."""

import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from src.crypto.errors import DecryptionError
from src.crypto.mgf import mgf1_sha256
from src.crypto.oaep import max_message_length, oaep_decrypt, oaep_encrypt
from tests.rsa_helpers import to_cryptography_private, to_cryptography_public

_C_OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def test_mgf1_longitudes():
    assert len(mgf1_sha256(b"seed", 0)) == 0
    assert len(mgf1_sha256(b"seed", 223)) == 223
    assert mgf1_sha256(b"seed", 40)[:32] == mgf1_sha256(b"seed", 32)


def test_ida_y_vuelta(our_key):
    pub = our_key.public_key()
    session_key = secrets.token_bytes(32)
    c = oaep_encrypt(pub, session_key)
    assert len(c) == 256
    assert oaep_decrypt(our_key, c) == session_key
    # Probabilístico: dos cifrados del mismo mensaje son distintos
    assert oaep_encrypt(pub, session_key) != c


def test_longitud_maxima(our_key):
    pub = our_key.public_key()
    assert max_message_length(pub) == 256 - 2 * 32 - 2 == 190
    m = secrets.token_bytes(190)
    assert oaep_decrypt(our_key, oaep_encrypt(pub, m)) == m
    assert oaep_decrypt(our_key, oaep_encrypt(pub, b"")) == b""
    with pytest.raises(ValueError):
        oaep_encrypt(pub, secrets.token_bytes(191))


def test_nosotros_cifra_cryptography_descifra(our_key):
    m = secrets.token_bytes(32)
    c = oaep_encrypt(our_key.public_key(), m)
    assert to_cryptography_private(our_key).decrypt(c, _C_OAEP) == m


def test_cryptography_cifra_nosotros_desciframos(their_key):
    m = secrets.token_bytes(32)
    c = to_cryptography_public(their_key.public_key()).encrypt(m, _C_OAEP)
    assert oaep_decrypt(their_key, c) == m


def test_etiqueta(our_key):
    pub = our_key.public_key()
    c = oaep_encrypt(pub, b"k" * 32, label=b"archivo-123")
    assert oaep_decrypt(our_key, c, label=b"archivo-123") == b"k" * 32
    with pytest.raises(DecryptionError):
        oaep_decrypt(our_key, c, label=b"otro")


def test_alteraciones_y_clave_incorrecta(our_key, their_key):
    c = bytearray(oaep_encrypt(our_key.public_key(), secrets.token_bytes(32)))
    with pytest.raises(DecryptionError):
        oaep_decrypt(their_key, bytes(c))          # otro usuario no puede desenvolver
    c[100] ^= 0x01
    with pytest.raises(DecryptionError):
        oaep_decrypt(our_key, bytes(c))            # 1 bit alterado
    with pytest.raises(DecryptionError):
        oaep_decrypt(our_key, bytes(c[:-1]))       # longitud incorrecta
    with pytest.raises(DecryptionError):
        oaep_decrypt(our_key, b"\xff" * 256)       # c >= n
