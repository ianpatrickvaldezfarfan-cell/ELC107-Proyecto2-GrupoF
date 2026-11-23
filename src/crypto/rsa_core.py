"""Núcleo RSA: generación de claves y primitivas RSAEP/RSADP/RSASP1/RSAVP1 (RFC 8017 §5).

Generación del par de claves (en línea con FIPS 186-5 Apéndice A.1.3):
    p, q primos de nlen/2 bits, con los 2 bits altos en 1  ⇒  n = p·q tiene nlen bits
    |p − q| > 2^{nlen/2 − 100}                     (evita factorizar por Fermat)
    e = 65537 = 2^16 + 1
    λ(n) = lcm(p − 1, q − 1)                       (función de Carmichael)
    d = e^{-1} mod λ(n)                            (Euclides extendido)
    dP = d mod (p − 1),  dQ = d mod (q − 1),  qInv = q^{-1} mod p   (parámetros CRT)

Descifrado / firma con el Teorema Chino del Resto (RFC 8017 §5.1.2, paso 2.b):
    m1 = c^{dP} mod p
    m2 = c^{dQ} mod q
    h  = qInv · (m1 − m2) mod p
    m  = m2 + q · h                    (recombinación de Garner)
Es ~3-4 veces más rápido que c^d mod n: dos exponenciaciones con la mitad de bits
(el costo de square-and-multiply crece ~ cúbicamente con el tamaño).

Contramedidas incluidas:
  * Cegado (blinding) de RSADP: c' = c · r^e mod n con r aleatorio; se descifra c'
    y se multiplica por r^{-1}. El tiempo deja de depender directamente de c (Kocher 1996).
  * Verificación tras firmar con CRT: si un fallo de hardware corrompe m1 o m2, la
    firma defectuosa permitiría factorizar n con gcd(s^e − m, n) (ataque de Bellcore,
    Boneh-DeMillo-Lipton 1997). Por eso se comprueba s^e ≡ m (mod n) antes de devolverla.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from .arith import gcd, int_byte_len, lcm, mod_exp, mod_inv
from .errors import CryptoError
from .primes import DEFAULT_MR_ROUNDS, PrimeGenStats, generate_prime

DEFAULT_E = 65537
SUPPORTED_BITS = (1024, 2048, 3072, 4096)  # 1024 solo para benchmark/tests: INSEGURO hoy
DEFAULT_BITS = 2048


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def size_bytes(self) -> int:
        """k = longitud en octetos del módulo (RFC 8017)."""
        return int_byte_len(self.n)


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def size_bytes(self) -> int:
        return int_byte_len(self.n)

    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(self.n, self.e)

    def __repr__(self) -> str:  # nunca imprimir los secretos por accidente
        return f"RSAPrivateKey(bits={self.bits}, e={self.e}, <secretos ocultos>)"


@dataclass
class KeyGenStats:
    """Estadísticas de la generación del par (para benchmarks)."""
    bits: int = 0
    prime_stats: PrimeGenStats = field(default_factory=PrimeGenStats)
    attempts: int = 0  # intentos de par (p, q) (se reintenta si |p−q| es pequeño, etc.)


def generate_keypair(
    bits: int = DEFAULT_BITS,
    e: int = DEFAULT_E,
    rounds: int = DEFAULT_MR_ROUNDS,
    stats: KeyGenStats | None = None,
) -> RSAPrivateKey:
    """Genera un par de claves RSA de `bits` bits. Devuelve la clave privada (contiene la pública)."""
    if bits not in SUPPORTED_BITS:
        raise ValueError(f"tamaño no soportado: {bits} (use {SUPPORTED_BITS})")
    if e < 3 or e % 2 == 0:
        raise ValueError("e debe ser impar y >= 3")
    st = stats if stats is not None else KeyGenStats()
    st.bits = bits
    half = bits // 2
    while True:
        st.attempts += 1
        p = generate_prime(half, e, rounds, st.prime_stats)
        q = generate_prime(bits - half, e, rounds, st.prime_stats)
        if p == q or abs(p - q) <= (1 << (half - 100)):
            continue
        if p < q:                      # convención: p > q (no es obligatoria, simplifica qInv)
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = lcm(p - 1, q - 1)
        d = mod_inv(e, lam)
        if d <= (1 << half):           # FIPS 186-5: d > 2^{nlen/2}
            continue
        return RSAPrivateKey(
            n=n, e=e, d=d, p=p, q=q,
            dp=d % (p - 1), dq=d % (q - 1), qinv=mod_inv(q, p),
        )


def private_key_from_components(n: int, e: int, d: int, p: int, q: int) -> RSAPrivateKey:
    """Reconstruye la clave privada (calcula los parámetros CRT) y valida su consistencia."""
    key = RSAPrivateKey(n=n, e=e, d=d, p=p, q=q, dp=d % (p - 1), dq=d % (q - 1), qinv=mod_inv(q, p))
    validate_private_key(key)
    return key


def validate_private_key(key: RSAPrivateKey) -> None:
    """Comprobaciones de consistencia (se usan al cargar una clave desde disco)."""
    if key.p * key.q != key.n:
        raise CryptoError("clave privada inconsistente: p·q ≠ n")
    if (key.e * key.d) % lcm(key.p - 1, key.q - 1) != 1:
        raise CryptoError("clave privada inconsistente: e·d ≢ 1 (mod λ(n))")
    if key.dp != key.d % (key.p - 1) or key.dq != key.d % (key.q - 1):
        raise CryptoError("parámetros CRT inconsistentes")
    if (key.qinv * key.q) % key.p != 1:
        raise CryptoError("qInv inconsistente")


def validate_public_key(key: RSAPublicKey) -> None:
    if key.n.bit_length() < 1024 or key.n % 2 == 0:
        raise CryptoError("módulo RSA inválido")
    if key.e < 3 or key.e % 2 == 0 or key.e >= key.n:
        raise CryptoError("exponente público inválido")


# ---------------------------------------------------------------------------
# Primitivas RFC 8017 §5
# ---------------------------------------------------------------------------
def rsaep(pub: RSAPublicKey, m: int) -> int:
    """RSAEP (§5.1.1): c = m^e mod n, exige 0 ≤ m < n."""
    if not 0 <= m < pub.n:
        raise CryptoError("representante del mensaje fuera de rango")
    return mod_exp(m, pub.e, pub.n)


def _crt_exp(priv: RSAPrivateKey, c: int) -> int:
    """c^d mod n mediante CRT (RFC 8017 §5.1.2, 2.b)."""
    m1 = mod_exp(c % priv.p, priv.dp, priv.p)
    m2 = mod_exp(c % priv.q, priv.dq, priv.q)
    h = (priv.qinv * (m1 - m2)) % priv.p
    return m2 + priv.q * h


def rsadp(priv: RSAPrivateKey, c: int, blinding: bool = True) -> int:
    """RSADP (§5.1.2): m = c^d mod n usando CRT (y cegado opcional)."""
    n = priv.n
    if not 0 <= c < n:
        raise CryptoError("representante del ciphertext fuera de rango")
    if not blinding:
        return _crt_exp(priv, c)
    # Cegado: elegir r ∈ Z_n* aleatorio; c' = c·r^e  ⇒  (c')^d = m·r  ⇒  m = (c')^d · r^{-1}
    while True:
        r = secrets.randbelow(n - 2) + 2
        if gcd(r, n) == 1:
            break
    c_blind = (c * mod_exp(r, priv.e, n)) % n
    m_blind = _crt_exp(priv, c_blind)
    return (m_blind * mod_inv(r, n)) % n


def rsadp_no_crt(priv: RSAPrivateKey, c: int) -> int:
    """m = c^d mod n directo (sin CRT). Solo para comparar en tests/benchmark."""
    if not 0 <= c < priv.n:
        raise CryptoError("representante del ciphertext fuera de rango")
    return mod_exp(c, priv.d, priv.n)


def rsasp1(priv: RSAPrivateKey, m: int) -> int:
    """RSASP1 (§5.2.1): s = m^d mod n (CRT + cegado) con verificación anti-Bellcore."""
    s = rsadp(priv, m)
    if mod_exp(s, priv.e, priv.n) != m:
        raise CryptoError("fallo interno al firmar (verificación CRT)")
    return s


def rsavp1(pub: RSAPublicKey, s: int) -> int:
    """RSAVP1 (§5.2.2): m = s^e mod n, exige 0 ≤ s < n."""
    if not 0 <= s < pub.n:
        raise CryptoError("representante de la firma fuera de rango")
    return mod_exp(s, pub.e, pub.n)
