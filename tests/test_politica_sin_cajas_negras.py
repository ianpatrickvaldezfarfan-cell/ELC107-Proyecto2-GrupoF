"""Verifica la restricción del proyecto: src/ no usa librerías criptográficas de caja negra.

- Prohibido importar hashlib, hmac, cryptography, Crypto/Cryptodome, nacl, ssl, rsa, etc. en src/.
- Prohibido usar pow() de 3 argumentos (exponenciación/inverso modular nativo) en src/crypto/.
"""

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
FORBIDDEN_MODULES = {"hashlib", "hmac", "cryptography", "Crypto", "Cryptodome", "nacl", "ssl", "rsa", "ecdsa", "_hashlib"}


def _python_files(root: Path):
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


def test_src_no_importa_librerias_criptograficas():
    offenders = []
    for path in _python_files(SRC):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                names = [node.module]
            for n in names:
                if n.split(".")[0] in FORBIDDEN_MODULES:
                    offenders.append(f"{path.relative_to(SRC)}: import {n}")
    assert not offenders, "Importaciones prohibidas en src/:\n" + "\n".join(offenders)


def test_crypto_no_usa_pow_modular_nativo():
    offenders = []
    for path in _python_files(SRC / "crypto"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "pow" and len(node.args) >= 3):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert not offenders, "pow(b, e, m) nativo en src/crypto/:\n" + "\n".join(offenders)
