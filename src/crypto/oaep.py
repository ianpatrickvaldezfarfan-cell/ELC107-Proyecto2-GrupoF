"""RSAES-OAEP con SHA-256 y MGF1-SHA256 (RFC 8017 §7.1).

Se usa para ENVOLVER la clave de sesión AES-256 de cada archivo con la clave
pública de cada destinatario.

Codificación EME-OAEP (§7.1.1 paso 2), con k = longitud del módulo, hLen = 32:
    lHash     = SHA-256(L)                                   (L = etiqueta, vacía por defecto)
    PS        = 0x00 repetido (k − mLen − 2·hLen − 2) veces
    DB        = lHash || PS || 0x01 || M                      (k − hLen − 1 octetos)
    seed      = hLen octetos aleatorios
    dbMask    = MGF1(seed, k − hLen − 1);   maskedDB   = DB ⊕ dbMask
    seedMask  = MGF1(maskedDB, hLen);       maskedSeed = seed ⊕ seedMask
    EM        = 0x00 || maskedSeed || maskedDB
    C         = I2OSP(RSAEP(n, e, OS2IP(EM)), k)

Longitud máxima del mensaje: mLen ≤ k − 2·hLen − 2 (190 octetos con RSA-2048).

Al descifrar, TODOS los fallos de formato producen el mismo error y se
evalúan sin salir antes de tiempo, para no dar un oráculo de relleno
(ataque de Manger, 2001).
"""

from __future__ import annotations

import secrets

from .errors import DecryptionError
from .mgf import mgf1_sha256
from .rsa_core import RSAPrivateKey, RSAPublicKey, rsadp, rsaep
from .sha256 import DIGEST_SIZE as HLEN
from .sha256 import sha256
from .utils import constant_time_equal, i2osp, os2ip, xor_bytes


def max_message_length(pub: RSAPublicKey) -> int:
    return pub.size_bytes - 2 * HLEN - 2


def oaep_encrypt(pub: RSAPublicKey, message: bytes | bytearray, label: bytes = b"") -> bytes:
    """RSAES-OAEP-ENCRYPT (§7.1.1)."""
    k = pub.size_bytes
    m_len = len(message)
    if m_len > k - 2 * HLEN - 2:
        raise ValueError("mensaje demasiado largo para RSA-OAEP")
    l_hash = sha256(label)
    ps = b"\x00" * (k - m_len - 2 * HLEN - 2)
    db = l_hash + ps + b"\x01" + bytes(message)
    seed = secrets.token_bytes(HLEN)
    masked_db = xor_bytes(db, mgf1_sha256(seed, k - HLEN - 1))
    masked_seed = xor_bytes(seed, mgf1_sha256(masked_db, HLEN))
    em = b"\x00" + masked_seed + masked_db
    c = rsaep(pub, os2ip(em))
    return i2osp(c, k)


def oaep_decrypt(priv: RSAPrivateKey, ciphertext: bytes, label: bytes = b"") -> bytearray:
    """RSAES-OAEP-DECRYPT (§7.1.2). Devuelve un bytearray (borrable con zeroize)."""
    k = priv.size_bytes
    # Paso 1: comprobaciones de longitud
    if len(ciphertext) != k or k < 2 * HLEN + 2:
        raise DecryptionError()
    # Paso 2: RSADP
    c = os2ip(ciphertext)
    if c >= priv.n:
        raise DecryptionError()
    em = bytearray(i2osp(rsadp(priv, c), k))
    # Paso 3: decodificación EME-OAEP
    l_hash = sha256(label)
    y = em[0]
    masked_seed = bytes(em[1:1 + HLEN])
    masked_db = bytes(em[1 + HLEN:])
    seed = xor_bytes(masked_seed, mgf1_sha256(masked_db, HLEN))
    db = bytearray(xor_bytes(masked_db, mgf1_sha256(seed, k - HLEN - 1)))
    l_hash_prime = bytes(db[:HLEN])

    # Buscar el separador 0x01 recorriendo SIEMPRE todo el bloque (sin cortar el bucle)
    rest = db[HLEN:]
    found = 0            # 1 cuando ya se encontró el 0x01
    index = 0            # posición del 0x01 dentro de `rest`
    bad_padding = 0      # 1 si apareció un byte distinto de 0x00 antes del 0x01
    for i, b in enumerate(rest):
        is_one = int(b == 1)
        is_zero = int(b == 0)
        take = is_one & (1 - found)
        index = index * (1 - take) + i * take
        bad_padding |= (1 - found) & (1 - is_one) & (1 - is_zero)
        found |= is_one
    ok = (constant_time_equal(l_hash, l_hash_prime) & (y == 0) & (found == 1) & (bad_padding == 0))
    if not ok:
        em[:] = bytes(len(em))
        db[:] = bytes(len(db))
        raise DecryptionError()
    message = bytearray(rest[index + 1:])
    em[:] = bytes(len(em))
    db[:] = bytes(len(db))
    return message
