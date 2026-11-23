"""Pruebas de AES-GCM: vectores de McGrew-Viega ("The Galois/Counter Mode of Operation",
Apéndice B, reproducidos en las pruebas de NIST) y validación cruzada con `cryptography`."""

import secrets

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as RefAESGCM

from src.crypto import gcm as G
from src.crypto.errors import InvalidTag
from src.crypto.gcm import AESGCM, aes_gcm_decrypt, aes_gcm_encrypt

K_TC3 = "feffe9928665731c6d6a8f9467308308"
P_64 = ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
P_60 = P_64[:120]
AAD_20 = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
IV_96 = "cafebabefacedbaddecaf888"
IV_64 = "cafebabefacedbad"
IV_480 = ("9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
          "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b")

# (caso, clave, iv, texto claro, aad, ciphertext, tag)
VECTORS = [
    # --- AES-128 ---
    (1, "00" * 16, "00" * 12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
    (2, "00" * 16, "00" * 12, "00" * 16, "", "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf"),
    (3, K_TC3, IV_96, P_64, "",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4"),
    (4, K_TC3, IV_96, P_60, AAD_20,
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
     "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47"),
    # --- AES-256 (los que usa el proyecto) ---
    (13, "00" * 32, "00" * 12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"),
    (14, "00" * 32, "00" * 12, "00" * 16, "", "cea7403d4d606b6e074ec5d3baf39d18",
     "d0d1c8a799996bf0265b98b5d48ab919"),
    (15, K_TC3 * 2, IV_96, P_64, "",
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
     "b094dac5d93471bdec1a502270e3cc6c"),
    (16, K_TC3 * 2, IV_96, P_60, AAD_20,
     "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
     "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
     "76fc6ece0f4e1768cddf8853bb2d551b"),
    # IV distinto de 96 bits (J0 calculado con GHASH)
    (17, K_TC3 * 2, IV_64, P_60, AAD_20,
     "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
     "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
     "3a337dbf46a792c45e454913fe2ea8f2"),
    (18, K_TC3 * 2, IV_480, P_60, AAD_20,
     "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
     "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
     "a44a8266ee1c8eb0c8b5d4cf5ae9f19a"),
]


@pytest.mark.parametrize("v", VECTORS, ids=[f"TC{v[0]}" for v in VECTORS])
def test_vectores_mcgrew_viega(v):
    _, k, iv, p, a, c, t = (bytes.fromhex(x) if isinstance(x, str) else x for x in v)
    ct, tag = aes_gcm_encrypt(k, iv, p, a)
    assert ct.hex() == c.hex()
    assert tag.hex() == t.hex()
    assert aes_gcm_decrypt(k, iv, c, t, a) == p


def test_subclave_h():
    # TC2: H = E_K(0^128) con K = 0^128
    from src.crypto.aes import AES
    assert AES(bytes(16)).encrypt_int(0) == 0x66E94BD4EF8A2C3B884CFA59CA342B2E


def test_multiplicacion_tabla_igual_a_algoritmo_1():
    for _ in range(50):
        h = secrets.randbits(128)
        x = secrets.randbits(128)
        assert G.GHashTable(h).mul(x) == G.gf128_mul(x, h)
    # Propiedades: el uno de GF(2^128) en notación GCM es 0x80...0 (coeficiente de x^0)
    one = 1 << 127
    h = secrets.randbits(128)
    assert G.gf128_mul(one, h) == h
    assert G.gf128_mul(h, 0) == 0


def test_inc32_envuelve_mod_2_32():
    assert G.inc32(0xFFFFFFFF) == 0
    assert G.inc32((5 << 32) | 0xFFFFFFFF) == 5 << 32
    assert G.inc32(7) == 8


def test_validacion_cruzada_ambas_direcciones():
    for n in (0, 1, 15, 16, 17, 100, 1000, 4099):
        key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        pt, aad = secrets.token_bytes(n), secrets.token_bytes(n % 40)
        ref = RefAESGCM(key)
        ct, tag = aes_gcm_encrypt(key, nonce, pt, aad)
        # nosotros -> cryptography
        assert ref.decrypt(nonce, ct + tag, aad) == pt
        # cryptography -> nosotros
        blob = ref.encrypt(nonce, pt, aad)
        assert aes_gcm_decrypt(key, nonce, blob[:-16], blob[-16:], aad) == pt


def _flip(data: bytes, bit: int) -> bytes:
    b = bytearray(data)
    b[bit // 8] ^= 0x80 >> (bit % 8)
    return bytes(b)


def test_alteraciones_detectadas():
    key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
    pt, aad = b"documento confidencial" * 10, b'{"filename":"a.txt"}'
    g = AESGCM(key)
    ct, tag = g.encrypt(nonce, pt, aad)
    assert g.decrypt(nonce, ct, tag, aad) == pt
    with pytest.raises(InvalidTag):
        g.decrypt(nonce, _flip(ct, 37), tag, aad)               # 1 bit del ciphertext
    with pytest.raises(InvalidTag):
        g.decrypt(nonce, ct, tag, _flip(aad, 3))                # AAD alterada
    with pytest.raises(InvalidTag):
        g.decrypt(nonce, ct, _flip(tag, 127), aad)              # tag alterado
    with pytest.raises(InvalidTag):
        g.decrypt(_flip(nonce, 0), ct, tag, aad)                # nonce alterado
    with pytest.raises(InvalidTag):
        AESGCM(secrets.token_bytes(32)).decrypt(nonce, ct, tag, aad)  # otra clave
    with pytest.raises(InvalidTag):
        g.decrypt(nonce, ct, tag[:12], aad)                     # tag truncado no aceptado
    with pytest.raises(InvalidTag):
        g.decrypt(nonce, ct[:-1], tag, aad)                     # ciphertext truncado


def test_nonce_vacio_rechazado():
    with pytest.raises(ValueError):
        aes_gcm_encrypt(bytes(32), b"", b"x")
