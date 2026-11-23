"""Configuración común de pytest.

GRUPOF_KDF_ITERS se reduce SOLO en los tests para que la derivación de claves
del keystore no tarde segundos en cada prueba. El valor real por defecto
(100.000) se define en src/crypto/kdf.py.
"""

import os

import pytest

os.environ.setdefault("GRUPOF_KDF_ITERS", "1000")


@pytest.fixture(scope="session")
def our_key():
    """Par RSA-2048 generado con NUESTRA implementación (una vez por sesión)."""
    from src.crypto.rsa_core import generate_keypair
    return generate_keypair(2048)


@pytest.fixture(scope="session")
def key_pool():
    """Claves RSA-2048 pregeneradas (con nuestra implementación) para reutilizar en tests de cliente."""
    from src.crypto.rsa_core import generate_keypair
    return [generate_keypair(2048) for _ in range(3)]


@pytest.fixture
def fast_keygen(monkeypatch, key_pool):
    """Hace que ClientService.keygen use claves pregeneradas (los tests de RSA ya prueban la generación)."""
    import itertools

    from src.client import service
    pool = itertools.cycle(key_pool)
    monkeypatch.setattr(service, "generate_keypair", lambda bits=2048, stats=None, **kw: next(pool))


@pytest.fixture(scope="session")
def their_key():
    """Par RSA-2048 generado por la librería `cryptography`, convertido a nuestras clases."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from tests.rsa_helpers import from_cryptography_private
    return from_cryptography_private(rsa.generate_private_key(public_exponent=65537, key_size=2048))
