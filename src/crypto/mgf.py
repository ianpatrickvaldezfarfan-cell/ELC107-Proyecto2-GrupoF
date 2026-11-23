"""MGF1 con SHA-256 (RFC 8017 Apéndice B.2.1), usada por OAEP y PSS.

    T = H(seed || I2OSP(0, 4)) || H(seed || I2OSP(1, 4)) || ...
    MGF1(seed, maskLen) = primeros maskLen octetos de T
"""

from __future__ import annotations

from .sha256 import DIGEST_SIZE, SHA256


def mgf1_sha256(seed: bytes, mask_len: int) -> bytes:
    if mask_len > (1 << 32) * DIGEST_SIZE:
        raise ValueError("mask too long")
    base = SHA256(seed)              # se reutiliza el estado tras absorber la semilla
    out = bytearray()
    counter = 0
    while len(out) < mask_len:
        h = base.copy()
        h.update(counter.to_bytes(4, "big"))
        out += h.digest()
        counter += 1
    return bytes(out[:mask_len])
