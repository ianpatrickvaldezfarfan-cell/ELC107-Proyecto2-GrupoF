"""Conversión entre nuestras claves y las de `cryptography` (solo para validación cruzada)."""

from cryptography.hazmat.primitives.asymmetric import rsa

from src.crypto.rsa_core import RSAPrivateKey, RSAPublicKey


def to_cryptography_private(k: RSAPrivateKey) -> rsa.RSAPrivateKey:
    pub = rsa.RSAPublicNumbers(k.e, k.n)
    return rsa.RSAPrivateNumbers(k.p, k.q, k.d, k.dp, k.dq, k.qinv, pub).private_key()


def to_cryptography_public(k: RSAPublicKey) -> rsa.RSAPublicKey:
    return rsa.RSAPublicNumbers(k.e, k.n).public_key()


def from_cryptography_private(k: rsa.RSAPrivateKey) -> RSAPrivateKey:
    nums = k.private_numbers()
    pub = nums.public_numbers
    return RSAPrivateKey(n=pub.n, e=pub.e, d=nums.d, p=nums.p, q=nums.q,
                         dp=nums.dmp1, dq=nums.dmq1, qinv=nums.iqmp)
