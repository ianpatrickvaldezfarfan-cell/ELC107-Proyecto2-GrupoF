"""Pruebas del formato de claves propio (TLV + armadura PEM-like) y de las huellas."""

import pytest

from src.crypto import encoding as E
from src.crypto.errors import CryptoError


def test_publica_ida_y_vuelta(our_key):
    pub = our_key.public_key()
    pem = E.public_key_to_pem(pub)
    assert pem.startswith("-----BEGIN GRUPOF RSA PUBLIC KEY-----\n")
    assert all(len(line) <= 64 for line in pem.splitlines())
    assert E.public_key_from_pem(pem) == pub
    assert E.decode_public_key(E.encode_public_key(pub)) == pub


def test_privada_ida_y_vuelta(our_key):
    pem = E.private_key_to_pem(our_key)
    assert E.private_key_from_pem(pem) == our_key
    raw = E.encode_private_key(our_key)
    assert isinstance(raw, bytearray)
    assert E.decode_private_key(raw) == our_key


def test_huella(our_key, their_key):
    fp = E.fingerprint(our_key.public_key())
    assert len(fp) == 64 and all(c in "0123456789abcdef" for c in fp)
    assert fp == E.fingerprint(E.public_key_from_pem(E.public_key_to_pem(our_key.public_key())))
    assert fp != E.fingerprint(their_key.public_key())
    pretty = E.format_fingerprint(fp)
    assert len(pretty.split()) == 16 and pretty.replace(" ", "") == fp.upper()


def test_errores_de_formato(our_key):
    pub_pem = E.public_key_to_pem(our_key.public_key())
    with pytest.raises(CryptoError):
        E.private_key_from_pem(pub_pem)                       # etiqueta equivocada
    with pytest.raises(CryptoError):
        E.public_key_from_pem(pub_pem.replace("A", "*", 1))   # base64 inválido
    raw = E.encode_public_key(our_key.public_key())
    with pytest.raises(CryptoError):
        E.decode_public_key(b"XXXX" + raw[4:])                # magic
    with pytest.raises(CryptoError):
        E.decode_public_key(raw[:-3])                         # truncada
    with pytest.raises(CryptoError):
        E.decode_private_key(raw)                             # tipo equivocado
    priv_raw = E.encode_private_key(our_key)
    priv_raw[-1] ^= 1                                         # qInv alterado
    with pytest.raises(CryptoError):
        E.decode_private_key(priv_raw)
