"""Utilidades comunes para las primitivas criptográficas.

- Conversión entero <-> bytes (I2OSP / OS2IP, RFC 8017 §4.1 y §4.2).
- Comparación en tiempo constante (evita ataques de temporización al comparar
  tags MAC, hashes o firmas).
- Borrado (zeroize) de material sensible guardado en `bytearray`.

LIMITACIÓN DEL BORRADO EN PYTHON (documentada a propósito):
    Python no ofrece control sobre la memoria. Los objetos `bytes` e `int` son
    inmutables: no se pueden sobreescribir, y el recolector de basura decide
    cuándo libera (y si reutiliza o no) la memoria donde vivían. Además el
    intérprete puede haber creado copias intermedias (slices, conversiones,
    concatenaciones). Por eso usamos `bytearray` para el material sensible que
    controlamos directamente (claves de sesión, claves derivadas, passphrase)
    y lo sobreescribimos con ceros tras usarlo; esto REDUCE la ventana de
    exposición pero NO garantiza que no queden copias en memoria. Los enteros
    grandes de RSA (d, p, q, ...) no pueden borrarse de forma fiable.
"""

from __future__ import annotations


def i2osp(x: int, length: int) -> bytes:
    """Integer-to-Octet-String Primitive (RFC 8017 §4.1).

    Convierte el entero no negativo x en una cadena big-endian de `length`
    octetos. Lanza ValueError si x >= 256^length ("integer too large").
    """
    if x < 0 or x >= 1 << (8 * length):
        raise ValueError("entero demasiado grande para la longitud indicada")
    return x.to_bytes(length, "big")


def os2ip(data: bytes) -> int:
    """Octet-String-to-Integer Primitive (RFC 8017 §4.2): big-endian -> entero."""
    return int.from_bytes(data, "big")


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compara dos cadenas en tiempo independiente de su contenido.

    Acumula con OR el XOR de todos los bytes: el bucle siempre recorre la
    longitud completa, sin cortar en el primer byte distinto (a diferencia de
    `==`), de modo que el tiempo no revela cuántos bytes iniciales coinciden.
    La longitud sí puede filtrarse, pero en nuestros usos es pública (tags de
    16 bytes, hashes de 32 bytes).
    """
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de dos cadenas de igual longitud."""
    if len(a) != len(b):
        raise ValueError("xor_bytes: longitudes distintas")
    n = len(a)
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(n, "big")


def zeroize(buf: bytearray | memoryview | None) -> None:
    """Sobreescribe con ceros un búfer mutable (ver limitación en el docstring del módulo)."""
    if buf is None:
        return
    if isinstance(buf, (bytes, str)):
        raise TypeError("zeroize requiere un búfer mutable (bytearray), no bytes/str")
    for i in range(len(buf)):
        buf[i] = 0
