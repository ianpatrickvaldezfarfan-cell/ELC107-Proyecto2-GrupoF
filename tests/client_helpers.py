"""Utilidades para probar el cliente contra el servidor sin red (test client de Flask)."""

from src.client.api_client import ApiClient
from src.client.api_client import InProcessTransport as FlaskTransport
from src.client.keystore import Keystore
from src.client.service import ClientService

SERVER = "http://test-server"


def passphrase_for(user: str) -> bytes:
    return f"passphrase-de-{user}".encode()


def make_service(flask_client, home, user, confirm=lambda _q: True, passphrase=None):
    pw = passphrase if passphrase is not None else passphrase_for(user)
    calls = {"n": 0}

    def provider(_prompt):
        calls["n"] += 1
        return bytearray(pw)  # bytearray nuevo cada vez (el servicio lo borra tras usarlo)

    svc = ClientService(Keystore(user, home), ApiClient(FlaskTransport(flask_client)), SERVER, provider, confirm)
    svc.passphrase_calls = calls
    return svc
