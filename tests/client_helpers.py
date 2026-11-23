"""Utilidades para probar el cliente contra el servidor sin red (test client de Flask)."""

from src.client.api_client import ApiClient
from src.client.keystore import Keystore
from src.client.service import ClientService

SERVER = "http://test-server"


class FlaskTransport:
    def __init__(self, flask_client):
        self.c = flask_client

    def request(self, method, path, json, headers):
        r = self.c.open(path, method=method, json=json, headers=headers)
        return r.status_code, r.get_json(silent=True)


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
