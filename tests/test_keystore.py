"""Pruebas del keystore: clave privada cifrada con PBKDF2 + AES-256-GCM, sesión y contactos."""

import json

import pytest

from src.client.keystore import Keystore, KeystoreError
from src.crypto.encoding import encode_private_key, fingerprint

PW = b"una passphrase larga"


@pytest.fixture
def ks(tmp_path, our_key):
    k = Keystore("alice", tmp_path)
    k.create(our_key, bytearray(PW), iterations=1500)
    return k


def test_ida_y_vuelta(ks, our_key):
    assert ks.exists()
    assert ks.unlock(bytearray(PW)) == our_key
    assert ks.fingerprint() == fingerprint(our_key.public_key())


def test_iteraciones_guardadas_en_el_keystore(ks, monkeypatch):
    assert ks.kdf_iterations() == 1500
    # Cambiar el valor por defecto NO rompe keystores existentes: se usa el guardado
    monkeypatch.setenv("GRUPOF_KDF_ITERS", "5000")
    assert ks.unlock(bytearray(PW)).bits == 2048


def test_iteraciones_por_defecto(tmp_path, our_key, monkeypatch):
    monkeypatch.setenv("GRUPOF_KDF_ITERS", "1234")
    k = Keystore("bob", tmp_path)
    k.create(our_key, bytearray(PW))
    assert k.kdf_iterations() == 1234


def test_passphrase_incorrecta(ks):
    with pytest.raises(KeystoreError, match="passphrase incorrecta"):
        ks.unlock(bytearray(b"otra passphrase"))


def test_encabezado_autenticado(ks):
    # Bajar las iteraciones o cambiar la sal en el archivo invalida el tag (el encabezado es la AAD)
    data = json.loads(ks.private_path.read_text(encoding="utf-8"))
    data["header"]["kdf"]["iterations"] = 1000
    ks.private_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KeystoreError):
        ks.unlock(bytearray(PW))


def test_ciphertext_alterado(ks):
    data = json.loads(ks.private_path.read_text(encoding="utf-8"))
    ct = bytearray(__import__("base64").b64decode(data["ciphertext"]))
    ct[0] ^= 1
    data["ciphertext"] = __import__("base64").b64encode(bytes(ct)).decode()
    ks.private_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KeystoreError):
        ks.unlock(bytearray(PW))


def test_la_clave_privada_no_esta_en_claro_en_disco(ks, our_key):
    raw = ks.private_path.read_bytes()
    assert b"PRIVATE" not in raw
    secret = bytes(encode_private_key(our_key))
    d_bytes = our_key.d.to_bytes((our_key.d.bit_length() + 7) // 8, "big")
    assert secret[:40] not in raw and d_bytes[:32] not in raw


def test_no_sobrescribe_y_minimo_de_iteraciones(ks, our_key, tmp_path):
    with pytest.raises(KeystoreError):
        ks.create(our_key, bytearray(PW))
    with pytest.raises(KeystoreError):
        Keystore("carol", tmp_path).create(our_key, bytearray(PW), iterations=10)


def test_keystore_de_otro_usuario(ks, tmp_path):
    (tmp_path / "mallory").mkdir()
    (tmp_path / "mallory" / "private_key.enc.json").write_bytes(ks.private_path.read_bytes())
    with pytest.raises(KeystoreError, match="otro usuario"):
        Keystore("mallory", tmp_path).unlock(bytearray(PW))


def test_sesion(ks):
    ks.save_session("http://srv", "tok123", expires_at=2_000.0)
    assert ks.load_session("http://srv", now=1_000.0) == "tok123"
    assert ks.load_session("http://srv", now=3_000.0) is None       # expirado
    assert ks.load_session("http://otro", now=1_000.0) is None      # otro servidor
    ks.clear_session()
    assert ks.load_session("http://srv", now=1_000.0) is None


def test_contactos_e_indice(ks):
    assert ks.pinned_fingerprint("bob") is None
    ks.pin("bob", "ab" * 32, verified=True)
    assert ks.pinned_fingerprint("bob") == "ab" * 32
    assert ks.contacts()["bob"]["verified_out_of_band"] is True
    ks.remember_file("f" * 32, "informe.pdf")
    assert ks.known_filename("f" * 32) == "informe.pdf"
