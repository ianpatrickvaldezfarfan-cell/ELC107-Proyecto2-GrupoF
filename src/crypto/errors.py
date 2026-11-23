"""Excepciones del núcleo criptográfico.

Los mensajes son deliberadamente genéricos: no revelan en qué paso exacto
falló una verificación (p. ej. OAEP no distingue "relleno inválido" de
"hash de etiqueta incorrecto", para no crear un oráculo tipo Manger).
"""


class CryptoError(Exception):
    """Error criptográfico genérico."""


class InvalidTag(CryptoError):
    """El tag de autenticación GCM no coincide: datos o AAD alterados, o clave/nonce incorrectos."""

    def __init__(self, msg: str = "tag de autenticación inválido") -> None:
        super().__init__(msg)


class DecryptionError(CryptoError):
    """Fallo al descifrar (p. ej. RSA-OAEP)."""

    def __init__(self, msg: str = "error de descifrado") -> None:
        super().__init__(msg)


class InvalidSignature(CryptoError):
    """La firma digital no es válida para el mensaje y la clave pública dados."""

    def __init__(self, msg: str = "firma inválida") -> None:
        super().__init__(msg)
