"""Servidor Flask de almacenamiento Zero-Trust.

El servidor es NO CONFIABLE por diseño: guarda y entrega bytes cifrados, pero
no posee ninguna clave privada ni de sesión. Aun así aplica controles propios
(defensa en profundidad):

  * Autenticación SIN contraseñas por challenge-response (RSA-PSS):
      1. POST /api/auth/challenge {username}           -> nonce aleatorio de 32 B (expira en 60 s)
      2. El cliente firma login_message(username, nonce) con su clave privada
      3. POST /api/auth/response {username, nonce, signature}
         El servidor BORRA el nonce (uso único, anti-replay), comprueba que no
         expiró y verifica la firma con la clave pública registrada.
         Si todo es correcto emite un token de sesión aleatorio (15 min).
  * Registro con prueba de posesión: el usuario firma register_message().
  * Al subir un archivo verifica la firma PSS del dueño y la coherencia de la AAD,
    y solo entrega a cada usuario SU clave envuelta.

Endpoints:
  GET  /api/health
  POST /api/register
  POST /api/auth/challenge
  POST /api/auth/response
  GET  /api/keys                       directorio de claves públicas + huellas
  GET  /api/keys/<username>
  POST /api/files                      (auth) subir paquete cifrado
  GET  /api/files                      (auth) listar archivos accesibles
  GET  /api/files/<file_id>            (auth) descargar paquete (solo con acceso)
  POST /api/files/<file_id>/share      (auth, solo dueño) agregar clave envuelta
  GET  /api/admin/compromised-view     vista del atacante (demo)

Ejecutar:  python -m src.server.app [--host 127.0.0.1] [--port 5000] [--data-dir server_data]
"""

from __future__ import annotations

import argparse
import secrets
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

from .. import protocol as P
from ..crypto.encoding import fingerprint, public_key_from_pem, public_key_to_pem
from ..crypto.errors import CryptoError, InvalidSignature
from ..crypto.gcm import NONCE_SIZE, TAG_SIZE
from ..crypto.pss import pss_verify, pss_verify_digest
from .compromised_view import compromised_report
from .storage import FileRecord, Storage

CHALLENGE_TTL = 60          # segundos
SESSION_TTL = 15 * 60       # segundos
CHALLENGE_NONCE_BYTES = 32
MAX_UPLOAD_BYTES = 64 * 1024 * 1024


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _json_body() -> dict[str, Any]:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "se esperaba un cuerpo JSON")
    return data


def _field(data: dict[str, Any], name: str, kind: type = str) -> Any:
    value = data.get(name)
    if not isinstance(value, kind):
        raise ApiError(400, f"campo '{name}' ausente o inválido")
    return value


def _b64_field(data: dict[str, Any], name: str) -> bytes:
    try:
        return P.b64d(_field(data, name))
    except P.ProtocolError as exc:
        raise ApiError(400, f"campo '{name}': {exc}") from exc


def create_app(
    data_dir: Path | str = "server_data",
    clock: Callable[[], float] = time.time,
    challenge_ttl: float = CHALLENGE_TTL,
    session_ttl: float = SESSION_TTL,
    enable_compromised_view: bool = True,
) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.json.ensure_ascii = False
    storage = Storage(data_dir, clock=clock)
    app.extensions["grupof_storage"] = storage

    # ------------------------------------------------------------------ helpers
    def load_public_key(username: str):
        user = storage.get_user(username)
        if user is None:
            raise ApiError(404, "usuario no encontrado")
        return user, public_key_from_pem(user.public_key_pem)

    def require_auth(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                raise ApiError(401, "falta el token de sesión (haga login)")
            user = storage.session_user(header[7:].strip())
            if user is None:
                raise ApiError(401, "token inválido o expirado (haga login de nuevo)")
            g.user = user
            return fn(*args, **kwargs)
        return wrapper

    @app.errorhandler(ApiError)
    def _api_error(exc: ApiError):
        return jsonify(error=exc.message), exc.status

    @app.errorhandler(HTTPException)
    def _http_error(exc: HTTPException):
        return jsonify(error=exc.description or exc.name), exc.code

    # ------------------------------------------------------------------ rutas
    @app.get("/api/health")
    def health():
        return jsonify(status="ok", server="GrupoF Zero-Trust Storage", holds_private_keys=False)

    @app.post("/api/register")
    def register():
        data = _json_body()
        try:
            username = P.validate_username(_field(data, "username"))
            pub = public_key_from_pem(_field(data, "public_key_pem"))
        except (P.ProtocolError, CryptoError) as exc:
            raise ApiError(400, str(exc)) from exc
        if pub.bits < 2048:
            raise ApiError(400, "la clave RSA debe tener al menos 2048 bits")
        fp = fingerprint(pub)
        signature = _b64_field(data, "signature")
        try:
            pss_verify(pub, P.register_message(username, fp), signature)
        except InvalidSignature as exc:
            raise ApiError(400, "prueba de posesión inválida: la firma no corresponde a la clave") from exc
        if not storage.add_user(username, public_key_to_pem(pub), fp):
            raise ApiError(409, "el usuario o la clave pública ya están registrados")
        return jsonify(username=username, fingerprint=fp), 201

    @app.post("/api/auth/challenge")
    def auth_challenge():
        data = _json_body()
        username = _field(data, "username")
        if storage.get_user(username) is None:
            raise ApiError(404, "usuario no encontrado")
        nonce = secrets.token_bytes(CHALLENGE_NONCE_BYTES)
        storage.add_challenge(nonce.hex(), username, challenge_ttl)
        return jsonify(nonce=P.b64e(nonce), expires_in=challenge_ttl)

    @app.post("/api/auth/response")
    def auth_response():
        data = _json_body()
        username = _field(data, "username")
        nonce = _b64_field(data, "nonce")
        signature = _b64_field(data, "signature")
        # 1) Consumir el challenge ANTES de verificar: uso único aunque la firma falle.
        if not storage.consume_challenge(nonce.hex(), username):
            raise ApiError(401, "challenge inválido, ya usado o expirado")
        # 2) Verificar la firma con la clave pública REGISTRADA del usuario.
        _, pub = load_public_key(username)
        try:
            pss_verify(pub, P.login_message(username, nonce), signature)
        except InvalidSignature as exc:
            raise ApiError(401, "firma del challenge inválida") from exc
        token = secrets.token_urlsafe(32)
        storage.add_session(token, username, session_ttl)
        return jsonify(token=token, expires_in=session_ttl, username=username)

    @app.get("/api/keys")
    def list_keys():
        return jsonify(users=[{"username": u.username, "fingerprint": u.fingerprint}
                              for u in storage.list_users()])

    @app.get("/api/keys/<username>")
    def get_key(username: str):
        user = storage.get_user(username)
        if user is None:
            raise ApiError(404, "usuario no encontrado")
        return jsonify(username=user.username, public_key_pem=user.public_key_pem, fingerprint=user.fingerprint)

    @app.post("/api/files")
    @require_auth
    def upload():
        data = _json_body()
        file_id = _field(data, "file_id")
        aad = _b64_field(data, "aad")
        nonce = _b64_field(data, "nonce")
        tag = _b64_field(data, "tag")
        ciphertext = _b64_field(data, "ciphertext")
        signature = _b64_field(data, "signature")
        wrapped_keys = _field(data, "wrapped_keys", list)

        if len(nonce) != NONCE_SIZE or len(tag) != TAG_SIZE:
            raise ApiError(400, "nonce (96 bits) o tag (128 bits) con longitud inválida")
        try:
            meta = P.parse_aad(aad)
        except P.ProtocolError as exc:
            raise ApiError(400, str(exc)) from exc
        if meta["file_id"] != file_id:
            raise ApiError(400, "file_id no coincide con la AAD")
        if meta["owner"] != g.user:
            raise ApiError(400, "el dueño de la AAD no es el usuario autenticado")
        if meta["size"] != len(ciphertext):
            raise ApiError(400, "el tamaño de la AAD no coincide con el ciphertext")

        owner, owner_pub = load_public_key(g.user)
        signer_fp = _field(data, "signer_fp")
        if signer_fp != owner.fingerprint:
            raise ApiError(400, "la huella del firmante no es la del dueño")
        try:
            pss_verify_digest(owner_pub, P.file_signature_digest(ciphertext, nonce, tag, aad), signature)
        except InvalidSignature as exc:
            raise ApiError(400, "firma del archivo inválida") from exc

        keys: list[tuple[str, str, bytes]] = []
        for entry in wrapped_keys:
            if not isinstance(entry, dict):
                raise ApiError(400, "entrada de wrapped_keys inválida")
            recipient = _field(entry, "recipient")
            rec_fp = _field(entry, "recipient_fp")
            wrapped = _b64_field(entry, "wrapped_key")
            r_user, r_pub = load_public_key(recipient)
            if rec_fp != r_user.fingerprint:
                raise ApiError(400, f"la huella indicada para '{recipient}' no coincide con la registrada")
            if len(wrapped) != r_pub.size_bytes:
                raise ApiError(400, f"clave envuelta para '{recipient}' con longitud inválida")
            keys.append((recipient, rec_fp, wrapped))
        if g.user not in {k[0] for k in keys}:
            raise ApiError(400, "falta la clave envuelta para el propio dueño")
        if len({k[0] for k in keys}) != len(keys):
            raise ApiError(400, "destinatarios repetidos")

        rec = FileRecord(file_id, g.user, nonce, tag, aad, signature, signer_fp, len(ciphertext), clock())
        if not storage.add_file(rec, ciphertext, keys):
            raise ApiError(409, "ya existe un archivo con ese file_id")
        return jsonify(file_id=file_id, recipients=sorted(k[0] for k in keys)), 201

    @app.get("/api/files")
    @require_auth
    def list_files():
        out = []
        for rec in storage.files_for(g.user):
            out.append({
                "file_id": rec.file_id, "owner": rec.owner, "aad": P.b64e(rec.aad),
                "size": rec.size, "created_at": rec.created_at, "is_owner": rec.owner == g.user,
                "recipients": storage.recipients(rec.file_id) if rec.owner == g.user else None,
            })
        return jsonify(files=out)

    @app.get("/api/files/<file_id>")
    @require_auth
    def download(file_id: str):
        rec = storage.get_file(file_id)
        key = storage.get_wrapped_key(file_id, g.user) if rec else None
        if rec is None or key is None:
            # Misma respuesta si no existe o si no hay acceso: no revela existencia.
            raise ApiError(404, "archivo no encontrado o sin acceso")
        owner = storage.get_user(rec.owner)
        return jsonify(
            file_id=rec.file_id, owner=rec.owner, owner_fp=owner.fingerprint,
            aad=P.b64e(rec.aad), nonce=P.b64e(rec.nonce), tag=P.b64e(rec.tag),
            ciphertext=P.b64e(storage.read_blob(file_id)), signature=P.b64e(rec.signature),
            signer_fp=rec.signer_fp, recipient=g.user, recipient_fp=key[0], wrapped_key=P.b64e(key[1]),
        )

    @app.post("/api/files/<file_id>/share")
    @require_auth
    def share(file_id: str):
        rec = storage.get_file(file_id)
        if rec is None or storage.get_wrapped_key(file_id, g.user) is None:
            raise ApiError(404, "archivo no encontrado o sin acceso")
        if rec.owner != g.user:
            raise ApiError(403, "solo el dueño puede compartir el archivo")
        data = _json_body()
        recipient = _field(data, "recipient")
        rec_fp = _field(data, "recipient_fp")
        wrapped = _b64_field(data, "wrapped_key")
        r_user, r_pub = load_public_key(recipient)
        if rec_fp != r_user.fingerprint:
            raise ApiError(400, "la huella del destinatario no coincide con la registrada")
        if len(wrapped) != r_pub.size_bytes:
            raise ApiError(400, "clave envuelta con longitud inválida")
        storage.add_wrapped_key(file_id, recipient, rec_fp, wrapped)
        return jsonify(file_id=file_id, recipients=storage.recipients(file_id))

    @app.get("/api/admin/compromised-view")
    def compromised_view():
        if not enable_compromised_view:
            raise ApiError(404, "deshabilitado")
        return jsonify(compromised_report(storage))

    return app


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Servidor de almacenamiento Zero-Trust (Grupo F)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--data-dir", type=Path, default=Path("server_data"))
    parser.add_argument("--no-compromised-view", action="store_true",
                        help="deshabilita el endpoint de demostración /api/admin/compromised-view")
    args = parser.parse_args(argv)
    app = create_app(args.data_dir, enable_compromised_view=not args.no_compromised_view)
    print("=" * 64)
    print("  Servidor Zero-Trust - Grupo F (ELC107)")
    print(f"  Datos en: {args.data_dir.resolve()}")
    print(f"  Escuchando en http://{args.host}:{args.port}")
    print("  Este servidor NO posee claves privadas ni claves de sesión.")
    print("=" * 64)
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()
