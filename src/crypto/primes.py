"""Generación de primos: criba por primos pequeños + test de Miller-Rabin.

Miller-Rabin (Miller 1976, Rabin 1980). Sea n impar, n − 1 = 2^s · d con d impar.
Para una base a ∈ [2, n−2], n "pasa" la ronda si
        a^d ≡ 1 (mod n)    o    a^{2^r · d} ≡ −1 (mod n) para algún 0 ≤ r < s.
Si n es primo, todas las bases pasan (pequeño teorema de Fermat + en Z_p las
únicas raíces cuadradas de 1 son ±1). Si n es compuesto, a lo sumo 1/4 de
las bases pasan (teorema de Rabin), así que con t bases aleatorias la
probabilidad de aceptar un compuesto es ≤ 4^{-t}.

A diferencia del test de Fermat (a^{n−1} ≡ 1), Miller-Rabin NO se deja engañar
por los números de Carmichael (561, 1105, 1729, ...), que satisfacen
a^{n−1} ≡ 1 para toda base coprima con n. Ver `fermat_test` y los tests.

Generación (en línea con FIPS 186-5 Apéndice A.1.3 / B.3.3):
  1. candidato aleatorio de `bits` bits con el CSPRNG (`secrets`), forzando
     los 2 bits más altos a 1 (así p·q tiene exactamente 2·bits bits) y el bit
     más bajo a 1 (impar);
  2. criba: se descarta si es divisible por algún primo < 2000 (elimina ~85 %
     de los candidatos sin hacer ninguna exponenciación);
  3. se exige gcd(p − 1, e) = 1 para que exista d = e^{-1};
  4. Miller-Rabin con `rounds` bases aleatorias.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .arith import gcd, mod_exp

SIEVE_LIMIT = 2000
DEFAULT_MR_ROUNDS = 40   # probabilidad de error ≤ 4^-40 = 2^-80 (cota del peor caso)


def _sieve(limit: int) -> tuple[int, ...]:
    """Criba de Eratóstenes: todos los primos < limit."""
    is_p = bytearray([1]) * limit
    is_p[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if is_p[i]:
            is_p[i * i::i] = bytearray(len(range(i * i, limit, i)))
    return tuple(i for i in range(limit) if is_p[i])


SMALL_PRIMES: tuple[int, ...] = _sieve(SIEVE_LIMIT)

# Para n < 3.317.044.064.679.887.385.961.981 basta con estas 13 bases para que
# Miller-Rabin sea DETERMINISTA (Sorenson & Webster, 2015).
_DETERMINISTIC_LIMIT = 3_317_044_064_679_887_385_961_981
_DETERMINISTIC_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)


def fermat_test(n: int, a: int) -> bool:
    """Test de Fermat: True si a^{n−1} ≡ 1 (mod n). Solo con fines comparativos."""
    return mod_exp(a, n - 1, n) == 1


def _decompose(n: int) -> tuple[int, int]:
    """Escribe n − 1 = 2^s · d con d impar."""
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    return s, d


def miller_rabin_round(n: int, a: int, s: int | None = None, d: int | None = None) -> bool:
    """Una ronda de Miller-Rabin con base a. True = "probablemente primo" para esa base,
    False = a es un TESTIGO de que n es compuesto."""
    if s is None or d is None:
        s, d = _decompose(n)
    x = mod_exp(a, d, n)                 # a^d mod n
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):               # a^{2d}, a^{4d}, ..., a^{2^{s-1} d}
        x = x * x % n
        if x == n - 1:
            return True
        if x == 1:                       # raíz cuadrada no trivial de 1 -> compuesto
            return False
    return False


def miller_rabin(n: int, rounds: int = DEFAULT_MR_ROUNDS, bases: tuple[int, ...] | None = None) -> bool:
    """Miller-Rabin "puro" (sin criba previa). Útil para mostrar que detecta Carmichael."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False
    s, d = _decompose(n)
    if bases is None:
        if n < _DETERMINISTIC_LIMIT:
            bases = tuple(a for a in _DETERMINISTIC_BASES if a < n - 1)
        else:
            bases = tuple(secrets.randbelow(n - 3) + 2 for _ in range(rounds))  # a ∈ [2, n−2]
    return all(miller_rabin_round(n, a, s, d) for a in bases)


def trial_division(n: int) -> bool:
    """Criba: False si n es divisible por algún primo pequeño (y distinto de él)."""
    for p in SMALL_PRIMES:
        if n % p == 0:
            return n == p
    return True


def is_probable_prime(n: int, rounds: int = DEFAULT_MR_ROUNDS) -> bool:
    """Test de primalidad completo: criba por primos < 2000 y luego Miller-Rabin."""
    if n < 2:
        return False
    if n < SIEVE_LIMIT:
        return n in SMALL_PRIMES
    if not trial_division(n):
        return False
    return miller_rabin(n, rounds)


@dataclass
class PrimeGenStats:
    """Estadísticas de generación (para el benchmark)."""
    candidates: int = 0          # candidatos aleatorios generados
    sieved_out: int = 0          # descartados por la criba de primos pequeños
    gcd_rejected: int = 0        # descartados por gcd(p−1, e) ≠ 1
    mr_tested: int = 0           # candidatos que llegaron a Miller-Rabin
    primes_found: int = 0

    def merge(self, other: "PrimeGenStats") -> None:
        for f in ("candidates", "sieved_out", "gcd_rejected", "mr_tested", "primes_found"):
            setattr(self, f, getattr(self, f) + getattr(other, f))


def random_odd_candidate(bits: int) -> int:
    """Entero aleatorio de exactamente `bits` bits, con los 2 bits altos y el bit 0 en 1."""
    if bits < 16:
        raise ValueError("tamaño de primo demasiado pequeño")
    return secrets.randbits(bits) | (0b11 << (bits - 2)) | 1


def generate_prime(
    bits: int,
    e: int = 65537,
    rounds: int = DEFAULT_MR_ROUNDS,
    stats: PrimeGenStats | None = None,
) -> int:
    """Genera un primo probable de `bits` bits con gcd(p − 1, e) = 1."""
    st = stats if stats is not None else PrimeGenStats()
    while True:
        candidate = random_odd_candidate(bits)
        st.candidates += 1
        if not trial_division(candidate):
            st.sieved_out += 1
            continue
        if gcd(candidate - 1, e) != 1:
            st.gcd_rejected += 1
            continue
        st.mr_tested += 1
        if miller_rabin(candidate, rounds):
            st.primes_found += 1
            return candidate
