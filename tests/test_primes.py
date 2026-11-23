"""Pruebas de aritmética modular y primalidad (Miller-Rabin con criba)."""

import secrets

import pytest

from src.crypto import arith, primes

# Números de Carmichael: compuestos que engañan al test de Fermat para toda base coprima.
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911, 10585, 15841, 29341, 41041,
              46657, 52633, 62745, 63973, 75361, 101101, 825265, 321197185]

# Primos conocidos, incluidos primos de Mersenne 2^p − 1
KNOWN_PRIMES = [2, 3, 5, 7, 97, 1999, 2003, 7919, 104729, 2**31 - 1, 2**61 - 1,
                2**89 - 1, 2**107 - 1, 2**127 - 1, 2**521 - 1, 2**607 - 1]


# --- aritmética -------------------------------------------------------------
def test_mod_exp_contra_pow_nativo():
    for _ in range(200):
        m = secrets.randbits(512) | 1
        b, e = secrets.randbits(600), secrets.randbits(300)
        assert arith.mod_exp(b, e, m) == pow(b, e, m)   # pow solo se usa aquí, en tests
    assert arith.mod_exp(5, 0, 7) == 1
    assert arith.mod_exp(5, 3, 1) == 0
    with pytest.raises(ValueError):
        arith.mod_exp(2, -1, 7)


def test_egcd_identidad_de_bezout():
    for _ in range(200):
        a, b = secrets.randbits(256), secrets.randbits(256) + 1
        g, x, y = arith.egcd(a, b)
        assert a * x + b * y == g == arith.gcd(a, b)


def test_mod_inv():
    assert arith.mod_inv(3, 11) == 4            # 3·4 = 12 ≡ 1 (mod 11)
    assert arith.mod_inv(65537, 3120) == pow(65537, -1, 3120)
    for _ in range(100):
        m = secrets.randbits(512) | 1
        a = secrets.randbits(500)
        if arith.gcd(a, m) == 1:
            assert a * arith.mod_inv(a, m) % m == 1
    with pytest.raises(ValueError):
        arith.mod_inv(6, 9)                     # gcd = 3: no hay inverso


# --- primalidad ---------------------------------------------------------------
def test_criba():
    assert len(primes.SMALL_PRIMES) == 303      # π(2000) = 303
    assert primes.SMALL_PRIMES[:6] == (2, 3, 5, 7, 11, 13)
    assert primes.SMALL_PRIMES[-1] == 1999


@pytest.mark.parametrize("p", KNOWN_PRIMES)
def test_primos_conocidos(p):
    assert primes.is_probable_prime(p)
    assert primes.miller_rabin(p)


def test_compuestos():
    for n in [0, 1, 4, 9, 2001, 7917, 2**61 + 1, (2**61 - 1) * (2**89 - 1), (2**127 - 1) ** 2]:
        assert not primes.is_probable_prime(n)


@pytest.mark.parametrize("n", CARMICHAEL)
def test_carmichael_engana_a_fermat_pero_no_a_miller_rabin(n):
    # Fermat dice "primo" para cualquier base coprima con n...
    base = next(a for a in range(2, n) if arith.gcd(a, n) == 1)
    assert primes.fermat_test(n, base)
    # ...pero Miller-Rabin (SIN la criba previa) lo detecta como compuesto
    assert not primes.miller_rabin(n)
    assert not primes.miller_rabin(n, bases=tuple(secrets.randbelow(n - 3) + 2 for _ in range(20)))
    assert not primes.is_probable_prime(n)


def test_testigo_explicito_561():
    # 560 = 2^4 · 35; 2^35 ≡ 263, 263^2 ≡ 166, 166^2 ≡ 67, 67^2 ≡ 1 (raíz no trivial) -> compuesto
    assert not primes.miller_rabin_round(561, 2)


def test_pseudoprimo_fuerte_detectado():
    # 3825123056546413051 es pseudoprimo fuerte para las bases 2,3,5,...,23;
    # las 13 bases deterministas (hasta 41) lo detectan.
    n = 3825123056546413051
    assert all(primes.miller_rabin_round(n, a) for a in (2, 3, 5, 7, 11, 13, 17, 19, 23))
    assert not primes.miller_rabin(n)


@pytest.mark.parametrize("bits", [256, 512, 1024])
def test_generar_primo(bits):
    st = primes.PrimeGenStats()
    p = primes.generate_prime(bits, stats=st)
    assert p.bit_length() == bits
    assert p >> (bits - 2) == 0b11              # 2 bits altos en 1
    assert primes.is_probable_prime(p)
    assert arith.gcd(p - 1, 65537) == 1
    assert st.candidates >= 1 and st.primes_found == 1
    assert st.candidates == st.sieved_out + st.gcd_rejected + st.mr_tested
