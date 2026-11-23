"""Pruebas de HMAC-SHA256: los 7 casos de prueba de RFC 4231 + validación cruzada."""

import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as c_hmac

from src.crypto.hmac_sha256 import HMAC_SHA256, hmac_sha256, verify_hmac_sha256

# RFC 4231 §4.2 - §4.8 (HMAC-SHA-256). El caso 5 se trunca a 128 bits.
RFC4231 = [
    (b"\x0b" * 20, b"Hi There",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
    (b"Jefe", b"what do ya want for nothing?",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
    (b"\xaa" * 20, b"\xdd" * 50,
     "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
    (bytes(range(1, 26)), b"\xcd" * 50,
     "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
    (b"\x0c" * 20, b"Test With Truncation",
     "a3b6167473100ee06e0c796c2955552b"),
    (b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First",
     "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
    (b"\xaa" * 131,
     b"This is a test using a larger than block-size key and a larger than block-size data. "
     b"The key needs to be hashed before being used by the HMAC algorithm.",
     "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
]


@pytest.mark.parametrize("caso", range(1, 8))
def test_rfc4231(caso):
    key, data, expected = RFC4231[caso - 1]
    tag = hmac_sha256(key, data).hex()
    assert tag[: len(expected)] == expected


def test_validacion_cruzada_cryptography():
    for klen in (0, 1, 32, 63, 64, 65, 200):
        for mlen in (0, 1, 55, 64, 100, 1000):
            key, msg = secrets.token_bytes(klen), secrets.token_bytes(mlen)
            ref = c_hmac.HMAC(key, hashes.SHA256())
            ref.update(msg)
            assert hmac_sha256(key, msg) == ref.finalize()


def test_incremental_y_verificacion():
    key, msg = b"clave", b"mensaje dividido en partes"
    h = HMAC_SHA256(key)
    h.update(msg[:7]).update(msg[7:])
    tag = h.digest()
    assert tag == hmac_sha256(key, msg)
    assert verify_hmac_sha256(key, msg, tag)
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    assert not verify_hmac_sha256(key, msg, bad)
