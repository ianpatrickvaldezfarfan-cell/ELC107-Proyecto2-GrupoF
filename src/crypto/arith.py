"""Aritmética modular implementada desde cero para RSA y Miller-Rabin.

Por la restricción del proyecto NO se usa `pow(b, e, m)` ni `pow(a, -1, m)`
de Python: estas funciones las reemplazan. Solo se usan las operaciones
básicas de los enteros de precisión arbitraria (+, -, *, //, %).
"""

from __future__ import annotations


def mod_exp(base: int, exponent: int, modulus: int) -> int:
    """Exponenciación modular base^exponent mod modulus por "square-and-multiply"
    de izquierda a derecha (binario).

    Si exponent = (e_{k-1} ... e_1 e_0)_2, se recorre desde el bit más
    significativo manteniendo r = base^{(e_{k-1}...e_i)_2} mod n:
        r ← r² mod n                (square, en cada bit)
        r ← r · base mod n          (multiply, solo si e_i = 1)
    Costo: k elevaciones al cuadrado y (peso de Hamming de e) multiplicaciones,
    cada una reducida módulo n para que los números no crezcan.
    """
    if modulus <= 0:
        raise ValueError("el módulo debe ser positivo")
    if exponent < 0:
        raise ValueError("exponente negativo: use mod_inv")
    if modulus == 1:
        return 0
    base %= modulus
    result = 1
    for bit in bin(exponent)[2:]:          # bits de izquierda a derecha
        result = result * result % modulus  # square
        if bit == "1":
            result = result * base % modulus  # multiply
    return result


def gcd(a: int, b: int) -> int:
    """Máximo común divisor por el algoritmo de Euclides: gcd(a, b) = gcd(b, a mod b)."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    return a // gcd(a, b) * b


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Algoritmo de Euclides EXTENDIDO (versión iterativa).

    Devuelve (g, x, y) tales que a·x + b·y = g = gcd(a, b) (identidad de Bézout).
    Invariantes en cada paso:  old_r = a·old_s + b·old_t   y   r = a·s + b·t
    con  q = old_r // r,  (old_r, r) ← (r, old_r − q·r)  y análogo para s, t.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inv(a: int, m: int) -> int:
    """Inverso modular a^{-1} mod m usando Euclides extendido.

    Si gcd(a, m) = 1, entonces a·x + m·y = 1  ⇒  a·x ≡ 1 (mod m), y el inverso es x mod m.
    """
    if m <= 1:
        raise ValueError("el módulo debe ser > 1")
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError("no existe inverso: a y m no son coprimos")
    return x % m


def int_byte_len(n: int) -> int:
    """Longitud en bytes de n (k en RFC 8017)."""
    return (n.bit_length() + 7) // 8
