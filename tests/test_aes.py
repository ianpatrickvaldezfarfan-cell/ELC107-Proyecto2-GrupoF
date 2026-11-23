"""Pruebas de AES: vectores de FIPS 197 (Apéndices A, B y C) y validación cruzada."""

import secrets

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from src.crypto import aes as A

PT = bytes.fromhex("00112233445566778899aabbccddeeff")

# FIPS 197 Apéndice C: ejemplos de AES-128 (C.1), AES-192 (C.2) y AES-256 (C.3)
APPENDIX_C = [
    (bytes(range(16)), "69c4e0d86a7b0430d8cdb78070b4c55a"),
    (bytes(range(24)), "dda97ca4864cdfe06eaf70a0ec0d7191"),
    (bytes(range(32)), "8ea2b7ca516745bfeafc49904b496089"),
]


def _ref_ecb(key, block):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block) + enc.finalize()


@pytest.mark.parametrize("key,expected", APPENDIX_C, ids=["C.1-AES128", "C.2-AES192", "C.3-AES256"])
def test_apendice_c(key, expected):
    assert A.AES(key).encrypt_block(PT).hex() == expected
    assert A.encrypt_block_reference(key, PT).hex() == expected
    assert A.decrypt_block_reference(key, bytes.fromhex(expected)) == PT


def test_apendice_b_aes128():
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    assert A.encrypt_block(key, pt).hex() == "3925841d02dc09fbdc118597196a0b32"


def test_key_expansion_apendice_a():
    # A.1 (AES-128): última palabra w[43]
    w = A.key_expansion(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert len(w) == 44 and w[43] == 0xB6630CA6
    # A.3 (AES-256): 60 palabras; w[8] y w[59]
    w = A.key_expansion(bytes.fromhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"))
    assert len(w) == 60
    assert w[8] == 0x9BA35411
    assert w[59] == 0x706C631E


def test_sbox_calculada():
    # Valores conocidos de la S-box (FIPS 197 Figura 7) y propiedades
    assert A.SBOX[0x00] == 0x63
    assert A.SBOX[0x53] == 0xED   # ejemplo de §5.1.1
    assert A.SBOX[0xFF] == 0x16
    assert sorted(A.SBOX) == list(range(256))          # es una permutación
    assert all(A.INV_SBOX[A.SBOX[x]] == x for x in range(256))
    assert all(A.SBOX[x] != x and A.SBOX[x] != x ^ 0xFF for x in range(256))  # sin puntos fijos


def test_aritmetica_gf256():
    assert A.gmul(0x57, 0x83) == 0xC1        # ejemplo de FIPS 197 §4.2
    assert A.gmul(0x57, 0x13) == 0xFE        # ejemplo de §4.2.1
    assert A.xtime(0x57) == 0xAE
    for a in range(1, 256):
        assert A.gmul(a, A.ginv(a)) == 1


def test_mix_columns_ejemplo():
    # Columna de ejemplo clásica: db 13 53 45 -> 8e 4d a1 bc
    state = [0xDB, 0x13, 0x53, 0x45] + [0] * 12
    A.mix_columns(state)
    assert state[:4] == [0x8E, 0x4D, 0xA1, 0xBC]
    A.inv_mix_columns(state)
    assert state[:4] == [0xDB, 0x13, 0x53, 0x45]


def test_shift_rows_inversa():
    state = list(range(16))
    A.shift_rows(state)
    assert state == [0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11]
    A.inv_shift_rows(state)
    assert state == list(range(16))


def test_optimizada_igual_a_didactica_y_a_cryptography():
    for _ in range(30):
        key, block = secrets.token_bytes(32), secrets.token_bytes(16)
        fast = A.AES(key).encrypt_block(block)
        assert fast == A.encrypt_block_reference(key, block)
        assert fast == _ref_ecb(key, block)
        assert A.decrypt_block_reference(key, fast) == block


def test_clave_invalida():
    with pytest.raises(ValueError):
        A.AES(b"corta")
