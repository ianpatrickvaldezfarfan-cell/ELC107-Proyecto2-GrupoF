"""Cliente HTTP del servidor (requests). Solo transporta datos YA cifrados.

El transporte es intercambiable: en los tests se usa el test client de Flask
(sin red) y en uso real `RequestsTransport`.
"""

from __future__ import annotations

from typing import Any, Protocol


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"[{status}] {message}")
        self.status = status
        self.message = message


class Transport(Protocol):
    def request(self, method: str, path: str, json: Any | None, headers: dict[str, str]) -> tuple[int, Any]: ...


class RequestsTransport:
    def __init__(self, base_url: str, timeout: float = 120.0) -> None:
        import requests  # importación diferida: los tests no la necesitan
        self._requests = requests
        self._session = requests.Session()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def request(self, method, path, json, headers):
        try:
            r = self._session.request(method, self.base_url + path, json=json, headers=headers, timeout=self.timeout)
        except self._requests.ConnectionError as exc:
            raise ApiError(0, f"no se pudo conectar con el servidor {self.base_url} (¿está iniciado?)") from exc
        except self._requests.Timeout as exc:
            raise ApiError(0, "tiempo de espera agotado al contactar al servidor") from exc
        try:
            body = r.json()
        except ValueError:
            body = {"error": r.text[:200]}
        return r.status_code, body


class InProcessTransport:
    """Transporte sobre el test client de Flask (servidor en el mismo proceso, sin red).
    Lo usan los tests y la demo de ataques en su modo por defecto."""

    def __init__(self, flask_test_client) -> None:
        self.c = flask_test_client

    def request(self, method, path, json, headers):
        r = self.c.open(path, method=method, json=json, headers=headers)
        return r.status_code, r.get_json(silent=True)


class ApiClient:
    def __init__(self, transport: Transport, token: str | None = None) -> None:
        self.transport = transport
        self.token = token

    def _call(self, method: str, path: str, json: Any | None = None, auth: bool = False) -> Any:
        headers = {}
        if auth:
            if not self.token:
                raise ApiError(401, "no hay sesión activa: ejecute 'login'")
            headers["Authorization"] = f"Bearer {self.token}"
        status, body = self.transport.request(method, path, json, headers)
        if status >= 400:
            msg = body.get("error", "error desconocido") if isinstance(body, dict) else str(body)
            raise ApiError(status, msg)
        return body

    # públicos
    def health(self):
        return self._call("GET", "/api/health")

    def register(self, username: str, public_key_pem: str, signature_b64: str):
        return self._call("POST", "/api/register", {"username": username, "public_key_pem": public_key_pem,
                                                    "signature": signature_b64})

    def challenge(self, username: str):
        return self._call("POST", "/api/auth/challenge", {"username": username})

    def respond(self, username: str, nonce_b64: str, signature_b64: str):
        return self._call("POST", "/api/auth/response", {"username": username, "nonce": nonce_b64,
                                                         "signature": signature_b64})

    def get_key(self, username: str):
        return self._call("GET", f"/api/keys/{username}")

    def list_keys(self):
        return self._call("GET", "/api/keys")

    # con sesión
    def upload(self, body: dict[str, Any]):
        return self._call("POST", "/api/files", body, auth=True)

    def list_files(self):
        return self._call("GET", "/api/files", auth=True)

    def download(self, file_id: str):
        return self._call("GET", f"/api/files/{file_id}", auth=True)

    def share(self, file_id: str, recipient: str, recipient_fp: str, wrapped_b64: str):
        return self._call("POST", f"/api/files/{file_id}/share",
                          {"recipient": recipient, "recipient_fp": recipient_fp, "wrapped_key": wrapped_b64}, auth=True)

    def compromised_view(self):
        return self._call("GET", "/api/admin/compromised-view")
