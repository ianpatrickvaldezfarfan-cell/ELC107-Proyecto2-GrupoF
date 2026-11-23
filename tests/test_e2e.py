"""Flujo completo end-to-end: alice sube, comparte con bob, bob descarga; carol no puede.
Incluye ataques: alteración en el servidor, clave sustituida (MITM), paquete robado."""

import sqlite3

import pytest

from src import protocol as P
from src.client import envelope as E
from src.client.service import ClientError, TrustError, safe_filename
from src.crypto.encoding import public_key_to_pem
from src.crypto.rsa_core import generate_keypair
from src.server.app import create_app
from tests.client_helpers import make_service

CONTENT = "Acta de la reunión: presupuesto 2027 = Bs 1.250.000 (confidencial). ñandú áéíóú\n".encode() * 50


@pytest.fixture
def world(tmp_path, fast_keygen):
    app = create_app(tmp_path / "server_data")
    client = app.test_client()
    home = tmp_path / "homes"
    users = {}
    for name in ("alice", "bob", "carol"):
        svc = make_service(client, home, name)
        svc.keygen(bytearray(f"passphrase-de-{name}".encode()), bits=2048, iterations=1000)
        svc.register()
        svc.login()
        svc.close()
        users[name] = svc
    src = tmp_path / "acta_reunion.txt"
    src.write_bytes(CONTENT)
    return app, client, home, users, src


def _storage(app):
    return app.extensions["grupof_storage"]


def test_flujo_completo(world, tmp_path):
    app, client, home, u, src = world
    alice, bob, carol = u["alice"], u["bob"], u["carol"]

    file_id = alice.upload(src)
    # alice ve su archivo (con el nombre real gracias al índice local)
    rows = alice.list_files()
    assert [(r.file_id, r.filename, r.is_owner) for r in rows] == [(file_id, "acta_reunion.txt", True)]

    # bob todavía no tiene acceso
    assert bob.list_files() == []

    # alice comparte con bob (re-envoltura local)
    assert alice.share(file_id, "bob") == ["alice", "bob"]
    rows = bob.list_files()
    assert rows[0].file_id == file_id and rows[0].filename is None   # nombre cifrado hasta descargar

    opened = bob.download(file_id)
    assert opened.filename == "acta_reunion.txt" and opened.data == CONTENT and opened.owner == "alice"
    out = bob.save(opened, tmp_path / "descargas_bob")
    assert out.name == "acta_reunion.txt" and out.read_bytes() == CONTENT
    assert bob.list_files()[0].filename == "acta_reunion.txt"

    # verify completo
    res = bob.verify(file_id)
    assert res["signature"] and res["gcm_tag"] and res["owner"] == "alice"

    # carol no puede ni listar ni descargar
    assert carol.list_files() == []
    from src.client.api_client import ApiError
    with pytest.raises(ApiError) as exc:
        carol.download(file_id)
    assert exc.value.status == 404


def test_compartir_al_subir(world):
    _, _, _, u, src = world
    fid = u["alice"].upload(src, share_with=["bob", "carol"])
    assert u["bob"].download(fid).data == CONTENT
    assert u["carol"].download(fid).data == CONTENT


def test_list_no_pide_passphrase(world):
    _, _, _, u, src = world
    u["alice"].upload(src)
    alice = u["alice"]
    alice.close()
    before = alice.passphrase_calls["n"]
    alice.list_files()
    alice.verify(alice.list_files()[0].file_id, signature_only=True)
    assert alice.passphrase_calls["n"] == before


def test_sin_login(world, tmp_path):
    app, client, home, u, src = world
    u["alice"].ks.clear_session()
    fresh = make_service(client, home, "alice")
    with pytest.raises(ClientError, match="login"):
        fresh.list_files()


def test_alteracion_en_el_servidor_detectada(world):
    app, _, _, u, src = world
    fid = u["alice"].upload(src, share_with=["bob"])
    blob = _storage(app).blob_dir / f"{fid}.bin"
    data = bytearray(blob.read_bytes())
    data[10] ^= 0x01                                 # el servidor (o un atacante) altera 1 bit
    blob.write_bytes(bytes(data))
    with pytest.raises(E.PackageError) as exc:
        u["bob"].download(fid)
    assert exc.value.step == "firma"


def test_aad_alterada_detectada(world):
    app, _, _, u, src = world
    fid = u["alice"].upload(src, share_with=["bob"])
    st = _storage(app)
    with sqlite3.connect(st.db_path) as c:
        aad = c.execute("SELECT aad FROM files WHERE file_id=?", (fid,)).fetchone()[0]
        c.execute("UPDATE files SET aad=? WHERE file_id=?", (aad.replace(b'"alice"', b'"carol"'), fid))
    with pytest.raises(E.PackageError):
        u["bob"].download(fid)


def test_clave_sustituida_en_el_directorio_mitm(world):
    """Alice ya fijó la clave de bob; el servidor la reemplaza por la de un atacante."""
    app, _, _, u, src = world
    fid = u["alice"].upload(src, share_with=["bob"])          # aquí alice fija la huella de bob
    evil = generate_keypair(2048)
    with sqlite3.connect(_storage(app).db_path) as c:
        c.execute("UPDATE users SET public_key_pem=? WHERE username='bob'", (public_key_to_pem(evil.public_key()),))
    with pytest.raises(TrustError, match="CAMBIÓ"):
        u["alice"].upload(src, share_with=["bob"])
    fid2 = u["alice"].upload(src)
    with pytest.raises(TrustError):
        u["alice"].share(fid2, "bob")
    assert fid


def test_huella_no_confirmada_cancela(world, tmp_path):
    app, client, home, u, src = world
    alice_cautious = make_service(client, home, "alice", confirm=lambda _q: False)
    with pytest.raises(TrustError, match="no se confirmó"):
        alice_cautious.upload(src, share_with=["carol"])


def test_paquete_robado_no_sirve_a_carol(world):
    """Carol obtiene (fuera del control de acceso) el paquete de bob: no puede desenvolver la clave."""
    app, client, _, u, src = world
    fid = u["alice"].upload(src, share_with=["bob"])
    pkg_bob = u["bob"].api.download(fid)
    carol_priv = u["carol"]._unlock()
    alice_pub = u["alice"].ks.public_key()
    with pytest.raises(E.PackageError) as exc:
        E.open_package(pkg_bob, carol_priv, alice_pub)
    assert exc.value.step == "clave de sesión"


def test_solo_el_duenio_comparte(world):
    _, _, _, u, src = world
    fid = u["alice"].upload(src, share_with=["bob"])
    with pytest.raises(ClientError, match="dueño"):
        u["bob"].share(fid, "carol")


def test_nombre_malicioso_saneado(world, tmp_path):
    app, client, home, u, src = world
    alice = u["alice"]
    body = E.seal("alice", alice._unlock(), [alice._trusted_key("alice", confirm_new=False),
                                             alice._trusted_key("bob", confirm_new=True)],
                  "..\\..\\Windows\\System32\\evil.dll", b"MZ")
    alice.api.upload(body)
    opened = u["bob"].download(body["file_id"])
    target = u["bob"].save(opened, tmp_path / "dl")
    assert target.parent == tmp_path / "dl" and target.name == "evil.dll"


def test_safe_filename():
    assert safe_filename("../../etc/passwd", "x") == "passwd"
    assert safe_filename("C:\\a\\b.txt", "x") == "b.txt"
    assert safe_filename("con.txt", "x") == "_con.txt"
    assert safe_filename("a<b>:c?.txt", "x") == "a_b__c_.txt"
    assert safe_filename("..", "fallback") == "fallback"


def test_servidor_no_conoce_nombre_ni_contenido(world):
    app, _, _, u, src = world
    u["alice"].upload(src, share_with=["bob"])
    st = _storage(app)
    everything = st.db_path.read_bytes() + b"".join(p.read_bytes() for p in st.blob_dir.iterdir())
    assert b"acta_reunion" not in everything
    assert b"presupuesto" not in everything
    aad = P.parse_aad(st.all_files()[0].aad)
    assert set(aad) == {"v", "alg", "file_id", "owner", "timestamp", "size"}
