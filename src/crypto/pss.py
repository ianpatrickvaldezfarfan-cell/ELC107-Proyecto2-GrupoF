"""Firma RSASSA-PSS con SHA-256 y MGF1-SHA256 (RFC 8017 §8.1 y §9.1).

Codificación EMSA-PSS (§9.1.1), con hLen = sLen = 32, emBits = modBits − 1:
    mHash  = SHA-256(M)
    salt   = sLen octetos aleatorios
    M'     = 0x00 × 8 || mHash || salt
    H      = SHA-256(M')
    PS     = 0x00 × (emLen − sLen − hLen − 2)
    DB     = PS || 0x01 || salt
    dbMask = MGF1(H, emLen − hLen − 1);   maskedDB = DB ⊕ dbMask
    (se ponen a 0 los 8·emLen − emBits bits más a la izquierda de maskedDB)
    EM     = maskedDB || H || 0xBC
    S      = I2OSP(RSASP1(K, OS2IP(EM)), k)

La sal aleatoria hace la firma PROBABILÍSTICA (dos firmas del mismo mensaje
son distintas) y PSS tiene prueba de seguridad en el modelo de oráculo
aleatorio (Bellare-Rogaway 1996), a diferencia de PKCS#1 v1.5.

Se ofrecen dos variantes:
  * pss_sign / pss_verify: reciben el mensaje M y calculan mHash = SHA-256(M).
  * pss_sign_digest / pss_verify_digest: reciben directamente mHash (32 bytes).
    Así se firma "el SHA-256 de (ciphertext || nonce || tag || AAD)" calculado
    por partes sobre archivos grandes, sin volver a hashearlo.
"""

from __future__ import annotations

import secrets

from .errors import CryptoError, InvalidSignature
from .mgf import mgf1_sha256
from .rsa_core import RSAPrivateKey, RSAPublicKey, rsasp1, rsavp1
from .sha256 import DIGEST_SIZE as HLEN
from .sha256 import sha256
from .utils import constant_time_equal, i2osp, os2ip, xor_bytes

DEFAULT_SALT_LEN = HLEN  # sLen = hLen = 32 (recomendación habitual)


def _emsa_pss_encode(m_hash: bytes, em_bits: int, salt_len: int) -> bytes:
    """EMSA-PSS-ENCODE (§9.1.1) a partir de mHash."""
    em_len = (em_bits + 7) // 8
    if em_len < HLEN + salt_len + 2:
        raise CryptoError("encoding error: módulo demasiado pequeño para PSS")
    salt = secrets.token_bytes(salt_len)
    m_prime = b"\x00" * 8 + m_hash + salt
    h = sha256(m_prime)
    ps = b"\x00" * (em_len - salt_len - HLEN - 2)
    db = ps + b"\x01" + salt
    masked_db = bytearray(xor_bytes(db, mgf1_sha256(h, em_len - HLEN - 1)))
    masked_db[0] &= 0xFF >> (8 * em_len - em_bits)
    return bytes(masked_db) + h + b"\xbc"


def _emsa_pss_verify(m_hash: bytes, em: bytes, em_bits: int, salt_len: int) -> bool:
    """EMSA-PSS-VERIFY (§9.1.2). True = "consistent"."""
    em_len = (em_bits + 7) // 8
    if len(em) != em_len or em_len < HLEN + salt_len + 2:
        return False
    if em[-1] != 0xBC:                                             # paso 4
        return False
    masked_db = em[: em_len - HLEN - 1]                            # paso 5
    h = em[em_len - HLEN - 1: -1]
    unused_bits = 8 * em_len - em_bits
    if masked_db[0] & (0xFF << (8 - unused_bits)) & 0xFF:          # paso 6
        return False
    db = bytearray(xor_bytes(masked_db, mgf1_sha256(h, em_len - HLEN - 1)))  # pasos 7-8
    db[0] &= 0xFF >> unused_bits                                   # paso 9
    ps_len = em_len - HLEN - salt_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:                     # paso 10
        return False
    salt = bytes(db[-salt_len:]) if salt_len else b""              # paso 11
    h_prime = sha256(b"\x00" * 8 + m_hash + salt)                  # pasos 12-13
    return constant_time_equal(h, h_prime)                         # paso 14


def pss_sign_digest(priv: RSAPrivateKey, m_hash: bytes, salt_len: int = DEFAULT_SALT_LEN) -> bytes:
    """RSASSA-PSS-SIGN (§8.1.1) sobre un hash SHA-256 ya calculado."""
    if len(m_hash) != HLEN:
        raise ValueError("mHash debe tener 32 bytes (SHA-256)")
    mod_bits = priv.n.bit_length()
    em = _emsa_pss_encode(m_hash, mod_bits - 1, salt_len)
    s = rsasp1(priv, os2ip(em))
    return i2osp(s, priv.size_bytes)


def pss_verify_digest(pub: RSAPublicKey, m_hash: bytes, signature: bytes,
                      salt_len: int = DEFAULT_SALT_LEN) -> None:
    """RSASSA-PSS-VERIFY (§8.1.2). Lanza InvalidSignature si la firma no es válida."""
    k = pub.size_bytes
    if len(m_hash) != HLEN or len(signature) != k:                  # paso 1
        raise InvalidSignature()
    s = os2ip(signature)
    if s >= pub.n:
        raise InvalidSignature()
    m = rsavp1(pub, s)                                             # paso 2
    mod_bits = pub.n.bit_length()
    em_len = (mod_bits - 1 + 7) // 8
    if m >= 1 << (8 * em_len):                                     # I2OSP "integer too large"
        raise InvalidSignature()
    em = i2osp(m, em_len)
    if not _emsa_pss_verify(m_hash, em, mod_bits - 1, salt_len):   # paso 3
        raise InvalidSignature()


def pss_sign(priv: RSAPrivateKey, message: bytes, salt_len: int = DEFAULT_SALT_LEN) -> bytes:
    return pss_sign_digest(priv, sha256(message), salt_len)


def pss_verify(pub: RSAPublicKey, message: bytes, signature: bytes, salt_len: int = DEFAULT_SALT_LEN) -> None:
    pss_verify_digest(pub, sha256(message), signature, salt_len)


def pss_is_valid(pub: RSAPublicKey, message: bytes, signature: bytes) -> bool:
    """Variante booleana de pss_verify (cómoda para la demo)."""
    try:
        pss_verify(pub, message, signature)
        return True
    except InvalidSignature:
        return False
