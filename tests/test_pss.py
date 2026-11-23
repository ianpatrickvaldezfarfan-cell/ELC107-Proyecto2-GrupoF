"""Pruebas de RSA-PSS (SHA-256, MGF1-SHA256, sLen = 32) con validación cruzada contra `cryptography`."""

import secrets

import pytest
from cryptography.exceptions import InvalidSignature as CInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from src.crypto.errors import InvalidSignature
from src.crypto.pss import pss_is_valid, pss_sign, pss_sign_digest, pss_verify, pss_verify_digest
from src.crypto.sha256 import sha256
from tests.rsa_helpers import from_cryptography_private, to_cryptography_private, to_cryptography_public

_C_PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
MSG = b"ciphertext||nonce||tag||AAD de ejemplo"


def test_firma_y_verificacion(our_key):
    pub = our_key.public_key()
    sig = pss_sign(our_key, MSG)
    assert len(sig) == 256
    pss_verify(pub, MSG, sig)
    assert pss_sign(our_key, MSG) != sig          # probabilística (sal aleatoria)


def test_rechazos(our_key, their_key):
    pub = our_key.public_key()
    sig = pss_sign(our_key, MSG)
    assert not pss_is_valid(pub, MSG + b"!", sig)                       # mensaje alterado
    assert not pss_is_valid(their_key.public_key(), MSG, sig)          # otra clave pública
    assert not pss_is_valid(pub, MSG, pss_sign(their_key, MSG))        # firmada por otro
    bad = bytearray(sig)
    bad[10] ^= 0x40
    assert not pss_is_valid(pub, MSG, bytes(bad))                      # firma alterada
    assert not pss_is_valid(pub, MSG, sig[:-1])                        # longitud incorrecta
    assert not pss_is_valid(pub, MSG, b"\x00" * 256)                   # firma trivial
    with pytest.raises(InvalidSignature):
        pss_verify(pub, MSG, b"\xff" * 256)                            # s >= n


def test_nuestra_firma_verificada_por_cryptography(our_key):
    sig = pss_sign(our_key, MSG)
    to_cryptography_public(our_key.public_key()).verify(sig, MSG, _C_PSS, hashes.SHA256())
    with pytest.raises(CInvalidSignature):
        to_cryptography_public(our_key.public_key()).verify(sig, MSG + b"x", _C_PSS, hashes.SHA256())


def test_firma_de_cryptography_verificada_por_nosotros(their_key):
    sig = to_cryptography_private(their_key).sign(MSG, _C_PSS, hashes.SHA256())
    pss_verify(their_key.public_key(), MSG, sig)


def test_variante_prehashed_cruzada(our_key):
    digest = sha256(MSG)
    sig = pss_sign_digest(our_key, digest)
    to_cryptography_public(our_key.public_key()).verify(sig, digest, _C_PSS, Prehashed(hashes.SHA256()))
    sig2 = to_cryptography_private(our_key).sign(digest, _C_PSS, Prehashed(hashes.SHA256()))
    pss_verify_digest(our_key.public_key(), digest, sig2)


@pytest.mark.parametrize("bits", [2049, 3072])
def test_otros_tamanos_de_modulo(bits):
    # 2049 bits: emBits = 2048 es múltiplo de 8 -> emLen = k − 1 (caso borde de RFC 8017)
    c_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    k = from_cryptography_private(c_key)
    m = secrets.token_bytes(100)
    sig = pss_sign(k, m)
    c_key.public_key().verify(sig, m, _C_PSS, hashes.SHA256())
    pss_verify(k.public_key(), m, c_key.sign(m, _C_PSS, hashes.SHA256()))
