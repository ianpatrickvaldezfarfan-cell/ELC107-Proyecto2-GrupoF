"""Pruebas del servidor Flask: registro, challenge-response (anti-replay), subida,
control de acceso, compartir y vista del servidor comprometido.

Los paquetes cifrados se construyen aquí "a mano" con las primitivas, de modo
que el servidor se prueba independientemente del cliente (Fase 5).
"""

import secrets

import pytest

from src import protocol as P
from src.crypto.encoding import fingerprint, public_key_to_pem
from src.crypto.gcm import aes_gcm_decrypt, aes_gcm_encrypt
from src.crypto.oaep import oaep_decrypt, oaep_encrypt
from src.crypto.pss import pss_sign, pss_sign_digest
from src.crypto.rsa_core import generate_keypair
from src.server.app import create_app
from src.server.compromised_view import shannon_entropy

SECRET_TEXT = b"Informe confidencial del Grupo F: la clave de la boveda es 4471. " * 40


class FakeClock:
    def __init__(self):
        self.now = 1_700_000_000.0

    def __call__(self):
        return self.now


@pytest.fixture(scope="module")
def keys():
    return {name: generate_keypair(2048) for name in ("alice", "bob", "carol", "mallory")}


@pytest.fixture
def env(tmp_path):
    clock = FakeClock()
    app = create_app(tmp_path / "server_data", clock=clock)
    app.testing = True
    return app, app.test_client(), clock


def register(client, name, key):
    pub = key.public_key()
    sig = pss_sign(key, P.register_message(name, fingerprint(pub)))
    return client.post("/api/register", json={
        "username": name, "public_key_pem": public_key_to_pem(pub), "signature": P.b64e(sig)})


def login(client, name, key):
    r = client.post("/api/auth/challenge", json={"username": name})
    assert r.status_code == 200
    nonce = P.b64d(r.json["nonce"])
    sig = pss_sign(key, P.login_message(name, nonce))
    r = client.post("/api/auth/response", json={"username": name, "nonce": P.b64e(nonce), "signature": P.b64e(sig)})
    assert r.status_code == 200, r.json
    return r.json["token"]


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def make_package(owner, owner_key, recipients, plaintext=SECRET_TEXT, filename="informe.txt"):
    """Construye el paquete como lo hará el cliente: AES-GCM + OAEP por destinatario + PSS."""
    session_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    file_id = secrets.token_hex(16)
    aad = P.build_aad(file_id, filename, owner, "2026-11-23T12:00:00Z", len(plaintext))
    ct, tag = aes_gcm_encrypt(session_key, nonce, plaintext, aad)
    sig = pss_sign_digest(owner_key, P.file_signature_digest(ct, nonce, tag, aad))
    wrapped = [{"recipient": name, "recipient_fp": fingerprint(k.public_key()),
                "wrapped_key": P.b64e(oaep_encrypt(k.public_key(), session_key))}
               for name, k in recipients.items()]
    body = {"file_id": file_id, "aad": P.b64e(aad), "nonce": P.b64e(nonce), "tag": P.b64e(tag),
            "ciphertext": P.b64e(ct), "signature": P.b64e(sig),
            "signer_fp": fingerprint(owner_key.public_key()), "wrapped_keys": wrapped}
    return body, session_key


# --------------------------------------------------------------------------- registro
def test_registro(env, keys):
    _, c, _ = env
    r = register(c, "alice", keys["alice"])
    assert r.status_code == 201
    assert r.json["fingerprint"] == fingerprint(keys["alice"].public_key())
    assert register(c, "alice", keys["alice"]).status_code == 409          # duplicado
    assert register(c, "x", keys["bob"]).status_code == 400                # nombre inválido
    d = c.get("/api/keys/alice").json
    assert d["fingerprint"] == fingerprint(keys["alice"].public_key())
    assert [u["username"] for u in c.get("/api/keys").json["users"]] == ["alice"]


def test_registro_sin_prueba_de_posesion(env, keys):
    _, c, _ = env
    # Mallory intenta registrar la clave pública de Bob a su nombre: no puede firmar con la privada de Bob
    pub = keys["bob"].public_key()
    sig = pss_sign(keys["mallory"], P.register_message("mallory", fingerprint(pub)))
    r = c.post("/api/register", json={"username": "mallory", "public_key_pem": public_key_to_pem(pub),
                                      "signature": P.b64e(sig)})
    assert r.status_code == 400


# --------------------------------------------------------------------------- login
def test_login_challenge_response(env, keys):
    _, c, _ = env
    register(c, "alice", keys["alice"])
    token = login(c, "alice", keys["alice"])
    assert c.get("/api/files", headers=auth(token)).status_code == 200
    assert c.get("/api/files").status_code == 401
    assert c.get("/api/files", headers=auth("token-falso")).status_code == 401


def test_replay_del_challenge_rechazado(env, keys):
    _, c, _ = env
    register(c, "alice", keys["alice"])
    nonce = P.b64d(c.post("/api/auth/challenge", json={"username": "alice"}).json["nonce"])
    body = {"username": "alice", "nonce": P.b64e(nonce),
            "signature": P.b64e(pss_sign(keys["alice"], P.login_message("alice", nonce)))}
    assert c.post("/api/auth/response", json=body).status_code == 200
    r = c.post("/api/auth/response", json=body)                            # replay exacto
    assert r.status_code == 401 and "ya usado" in r.json["error"]


def test_challenge_expirado(env, keys):
    _, c, clock = env
    register(c, "alice", keys["alice"])
    nonce = P.b64d(c.post("/api/auth/challenge", json={"username": "alice"}).json["nonce"])
    clock.now += 61
    sig = pss_sign(keys["alice"], P.login_message("alice", nonce))
    r = c.post("/api/auth/response", json={"username": "alice", "nonce": P.b64e(nonce), "signature": P.b64e(sig)})
    assert r.status_code == 401


def test_firma_de_otro_usuario_rechazada_y_consume_el_nonce(env, keys):
    _, c, _ = env
    register(c, "alice", keys["alice"])
    nonce = P.b64d(c.post("/api/auth/challenge", json={"username": "alice"}).json["nonce"])
    bad = pss_sign(keys["mallory"], P.login_message("alice", nonce))
    r = c.post("/api/auth/response", json={"username": "alice", "nonce": P.b64e(nonce), "signature": P.b64e(bad)})
    assert r.status_code == 401
    good = pss_sign(keys["alice"], P.login_message("alice", nonce))       # el nonce ya se consumió
    r = c.post("/api/auth/response", json={"username": "alice", "nonce": P.b64e(nonce), "signature": P.b64e(good)})
    assert r.status_code == 401


def test_challenge_de_otro_usuario_no_sirve(env, keys):
    _, c, _ = env
    register(c, "alice", keys["alice"])
    register(c, "mallory", keys["mallory"])
    nonce = P.b64d(c.post("/api/auth/challenge", json={"username": "alice"}).json["nonce"])
    sig = pss_sign(keys["mallory"], P.login_message("mallory", nonce))
    r = c.post("/api/auth/response", json={"username": "mallory", "nonce": P.b64e(nonce), "signature": P.b64e(sig)})
    assert r.status_code == 401


def test_token_expira(env, keys):
    _, c, clock = env
    register(c, "alice", keys["alice"])
    token = login(c, "alice", keys["alice"])
    clock.now += 15 * 60 + 1
    assert c.get("/api/files", headers=auth(token)).status_code == 401


# --------------------------------------------------------------------------- archivos
@pytest.fixture
def three_users(env, keys):
    app, c, clock = env
    tokens = {}
    for name in ("alice", "bob", "carol"):
        register(c, name, keys[name])
        tokens[name] = login(c, name, keys[name])
    return app, c, tokens


def test_subir_listar_descargar(three_users, keys):
    _, c, tokens = three_users
    body, session_key = make_package("alice", keys["alice"], {"alice": keys["alice"]})
    r = c.post("/api/files", json=body, headers=auth(tokens["alice"]))
    assert r.status_code == 201, r.json
    files = c.get("/api/files", headers=auth(tokens["alice"])).json["files"]
    assert [f["file_id"] for f in files] == [body["file_id"]] and files[0]["is_owner"]
    pkg = c.get(f"/api/files/{body['file_id']}", headers=auth(tokens["alice"])).json
    # Alice puede desenvolver y descifrar
    k = oaep_decrypt(keys["alice"], P.b64d(pkg["wrapped_key"]))
    assert bytes(k) == session_key
    pt = aes_gcm_decrypt(k, P.b64d(pkg["nonce"]), P.b64d(pkg["ciphertext"]), P.b64d(pkg["tag"]), P.b64d(pkg["aad"]))
    assert pt == SECRET_TEXT


def test_validaciones_de_subida(three_users, keys):
    _, c, tokens = three_users
    h = auth(tokens["alice"])
    body, _ = make_package("alice", keys["alice"], {"alice": keys["alice"]})
    bad = dict(body, signature=P.b64e(pss_sign(keys["bob"], b"otra cosa")))
    assert c.post("/api/files", json=bad, headers=h).status_code == 400            # firma inválida
    body_bob, _ = make_package("bob", keys["bob"], {"bob": keys["bob"]})
    assert c.post("/api/files", json=body_bob, headers=h).status_code == 400       # dueño != usuario
    no_owner, _ = make_package("alice", keys["alice"], {"bob": keys["bob"]})
    assert c.post("/api/files", json=no_owner, headers=h).status_code == 400       # sin clave del dueño
    wrong_fp = dict(body, wrapped_keys=[dict(body["wrapped_keys"][0], recipient_fp="00" * 32)])
    assert c.post("/api/files", json=wrong_fp, headers=h).status_code == 400       # huella falsa
    assert c.post("/api/files", json=body, headers=h).status_code == 201
    assert c.post("/api/files", json=body, headers=h).status_code == 409           # file_id repetido


def test_control_de_acceso_y_compartir(three_users, keys):
    _, c, tokens = three_users
    body, session_key = make_package("alice", keys["alice"], {"alice": keys["alice"]})
    fid = body["file_id"]
    c.post("/api/files", json=body, headers=auth(tokens["alice"]))
    # Bob y Carol no ven ni pueden descargar el archivo
    assert c.get("/api/files", headers=auth(tokens["bob"])).json["files"] == []
    assert c.get(f"/api/files/{fid}", headers=auth(tokens["bob"])).status_code == 404
    # Alice comparte con Bob: re-envuelve LOCALMENTE la clave de sesión con la pública de Bob
    share = {"recipient": "bob", "recipient_fp": fingerprint(keys["bob"].public_key()),
             "wrapped_key": P.b64e(oaep_encrypt(keys["bob"].public_key(), session_key))}
    r = c.post(f"/api/files/{fid}/share", json=share, headers=auth(tokens["alice"]))
    assert r.status_code == 200 and r.json["recipients"] == ["alice", "bob"]
    pkg = c.get(f"/api/files/{fid}", headers=auth(tokens["bob"])).json
    assert pkg["recipient"] == "bob"
    assert bytes(oaep_decrypt(keys["bob"], P.b64d(pkg["wrapped_key"]))) == session_key
    # Bob (no dueño) no puede compartir con Carol; Carol sigue sin acceso
    share_c = {"recipient": "carol", "recipient_fp": fingerprint(keys["carol"].public_key()),
               "wrapped_key": P.b64e(oaep_encrypt(keys["carol"].public_key(), session_key))}
    assert c.post(f"/api/files/{fid}/share", json=share_c, headers=auth(tokens["bob"])).status_code == 403
    assert c.get(f"/api/files/{fid}", headers=auth(tokens["carol"])).status_code == 404


def test_cada_usuario_recibe_solo_su_clave_envuelta(three_users, keys):
    _, c, tokens = three_users
    body, _ = make_package("alice", keys["alice"], {"alice": keys["alice"], "bob": keys["bob"]})
    c.post("/api/files", json=body, headers=auth(tokens["alice"]))
    pkg_a = c.get(f"/api/files/{body['file_id']}", headers=auth(tokens["alice"])).json
    pkg_b = c.get(f"/api/files/{body['file_id']}", headers=auth(tokens["bob"])).json
    assert pkg_a["wrapped_key"] != pkg_b["wrapped_key"]
    assert "wrapped_keys" not in pkg_b


# --------------------------------------------------------------------------- zero-trust
def test_servidor_comprometido_solo_ve_bytes_cifrados(three_users, keys):
    app, c, tokens = three_users
    body, session_key = make_package("alice", keys["alice"], {"alice": keys["alice"], "bob": keys["bob"]})
    c.post("/api/files", json=body, headers=auth(tokens["alice"]))
    storage = app.extensions["grupof_storage"]
    everything = storage.db_path.read_bytes() + b"".join(p.read_bytes() for p in storage.blob_dir.iterdir())
    assert b"boveda" not in everything                       # el texto claro no está
    assert session_key not in everything                     # la clave de sesión no está
    for t in tokens.values():
        assert t.encode() not in everything                  # los tokens no están (solo su hash)
    report = c.get("/api/admin/compromised-view").json
    assert report["secret_material_found"] == []
    f = report["files"][0]
    assert f["entropy_bits_per_byte"] > 7.5 and f["printable_ratio"] < 0.5
    assert shannon_entropy(SECRET_TEXT) < 5.0                # el texto claro tiene entropía baja


def test_vista_comprometida_deshabilitable(tmp_path):
    app = create_app(tmp_path / "d", enable_compromised_view=False)
    assert app.test_client().get("/api/admin/compromised-view").status_code == 404


def test_health(env):
    _, c, _ = env
    assert c.get("/api/health").json["holds_private_keys"] is False
