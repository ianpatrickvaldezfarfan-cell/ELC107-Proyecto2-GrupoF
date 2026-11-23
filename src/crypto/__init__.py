"""Primitivas criptográficas implementadas desde cero en Python puro.

Restricción del proyecto: este paquete NO importa hashlib, hmac, ni ninguna
librería criptográfica externa. La única fuente de aleatoriedad permitida es
`secrets` / `os.urandom` (CSPRNG del sistema operativo).
"""
