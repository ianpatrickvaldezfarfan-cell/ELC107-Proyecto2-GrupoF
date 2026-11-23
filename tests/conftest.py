"""Configuración común de pytest.

GRUPOF_KDF_ITERS se reduce SOLO en los tests para que la derivación de claves
del keystore no tarde segundos en cada prueba. El valor real por defecto
(100.000) se define en src/crypto/kdf.py.
"""

import os

os.environ.setdefault("GRUPOF_KDF_ITERS", "1000")
