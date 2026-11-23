"""PBKDF2-HMAC-SHA256 implementado desde cero según RFC 8018 §5.2.

    DK = T_1 || T_2 || ... || T_l      (truncado a dkLen bytes)
    l  = ceil(dkLen / hLen),  hLen = 32

    T_i = F(P, S, c, i) = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
        U_1 = PRF(P, S || INT_32_BE(i))
        U_j = PRF(P, U_{j-1})                 para j = 2..c

con PRF = HMAC-SHA256 y la contraseña P como clave del HMAC.

Costo: 2·c compresiones SHA-256 por bloque de salida gracias a que los
estados (P⊕ipad) y (P⊕opad) se precalculan una sola vez (ver hmac_sha256.py).

ITERACIONES POR DEFECTO — DECISIÓN DE DISEÑO DOCUMENTADA:
    OWASP (Password Storage Cheat Sheet, 2023+) recomienda 600.000 iteraciones
    para PBKDF2-HMAC-SHA256. Este proyecto usa 100.000 por defecto porque
    nuestro SHA-256 es Python puro (unas 50-100 veces más lento que una
    implementación en C), y 600.000 iteraciones harían que desbloquear el
    keystore tarde decenas de segundos en la demo en vivo. El número de
    iteraciones se guarda DENTRO de cada keystore, de modo que puede subirse
    (p. ej. a 600.000) sin romper los keystores existentes.
    La variable de entorno GRUPOF_KDF_ITERS permite cambiar el valor por
    defecto (los tests la fijan en un valor bajo para ejecutarse rápido).
"""

from __future__ import annotations

import os

from .hmac_sha256 import HMAC_SHA256, hmac_sha256_32_fast
from .sha256 import DIGEST_SIZE
from .utils import zeroize

DEFAULT_ITERATIONS = 100_000
OWASP_RECOMMENDED_ITERATIONS = 600_000
MIN_ITERATIONS = 1_000  # límite inferior de seguridad al leer el valor de un keystore/env


def default_iterations() -> int:
    """Iteraciones por defecto: GRUPOF_KDF_ITERS si está definida, si no 100.000."""
    raw = os.environ.get("GRUPOF_KDF_ITERS")
    if raw:
        value = int(raw)
        if value < 1:
            raise ValueError("GRUPOF_KDF_ITERS debe ser >= 1")
        return value
    return DEFAULT_ITERATIONS


def pbkdf2_hmac_sha256(
    password: bytes | bytearray,
    salt: bytes,
    iterations: int,
    dklen: int = 32,
) -> bytearray:
    """Deriva `dklen` bytes con PBKDF2-HMAC-SHA256 (RFC 8018 §5.2).

    Devuelve un bytearray para que el llamador pueda borrarlo con zeroize().
    """
    if iterations < 1:
        raise ValueError("iterations debe ser >= 1")
    if dklen < 1:
        raise ValueError("dklen debe ser >= 1")
    if dklen > (2**32 - 1) * DIGEST_SIZE:  # RFC 8018 §5.2 paso 1: "derived key too long"
        raise ValueError("clave derivada demasiado larga")

    prf = HMAC_SHA256(password)                       # precalcula P⊕ipad, P⊕opad
    inner_state, outer_state = prf._precomputed_states()

    n_blocks = -(-dklen // DIGEST_SIZE)               # l = ceil(dkLen / hLen)
    dk = bytearray()
    for i in range(1, n_blocks + 1):
        # U_1 = PRF(P, S || INT(i))  (mensaje de longitud arbitraria -> camino general)
        u = prf.copy().update(salt + i.to_bytes(4, "big")).digest()
        t = int.from_bytes(u, "big")                  # acumulador T_i como entero (XOR rápido)
        # U_j = PRF(P, U_{j-1}), j = 2..c  (mensajes de 32 B -> camino rápido)
        for _ in range(iterations - 1):
            u = hmac_sha256_32_fast(inner_state, outer_state, u)
            t ^= int.from_bytes(u, "big")
        block = bytearray(t.to_bytes(DIGEST_SIZE, "big"))
        dk.extend(block)
        zeroize(block)

    result = bytearray(dk[:dklen])
    zeroize(dk)
    return result
