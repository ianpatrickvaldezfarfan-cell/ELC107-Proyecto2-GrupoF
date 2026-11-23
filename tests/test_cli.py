"""Pruebas de la CLI (argparse + salida + códigos de salida) contra el servidor en memoria."""

import pytest

from src.client import cli
from src.server.app import create_app
from tests.client_helpers import FlaskTransport


@pytest.fixture
def run(tmp_path, monkeypatch, fast_keygen):
    app = create_app(tmp_path / "server_data")
    flask_client = app.test_client()
    monkeypatch.setattr(cli, "make_transport", lambda server: FlaskTransport(flask_client))
    home = tmp_path / "homes"

    def _run(user, *args, passphrase=None):
        if passphrase is None:
            passphrase = f"pass-{user}-123"
        monkeypatch.setenv("GRUPOF_PASSPHRASE", passphrase)
        return cli.main(["--user", user, "--home", str(home), "--no-color", *args])

    _run.app = app
    return _run


def test_keygen_con_iteraciones_de_demo(run, capsys):
    assert run("dave", "keygen", "--kdf-iters", "20000") == 0
    out = capsys.readouterr().out
    assert "20.000 iteraciones" in out and "SOLO para demostraciones" in out
    assert "OWASP recomienda 600.000" in out


def test_flujo_cli(run, tmp_path, capsys):
    for u in ("alice", "bob"):
        assert run(u, "keygen", "--kdf-iters", "1000") == 0
        assert run(u, "register") == 0
        assert run(u, "login") == 0
    capsys.readouterr()

    f = tmp_path / "nota.txt"
    f.write_text("hola bob, esto es secreto", encoding="utf-8")
    assert run("alice", "upload", str(f), "--share-with", "bob", "--yes") == 0
    out = capsys.readouterr().out
    file_id = out.split("file_id: ")[1].split()[0]

    # list sin passphrase (si se pidiera, la variable vacía haría fallar el keystore)
    assert run("alice", "list", passphrase="") == 0
    assert "nota.txt" in capsys.readouterr().out

    dest = tmp_path / "dl"
    dest.mkdir()
    assert run("bob", "download", file_id[:8], "--out", str(dest)) == 0      # prefijo del file_id
    assert (dest / "nota.txt").read_text(encoding="utf-8") == "hola bob, esto es secreto"
    assert run("bob", "verify", file_id) == 0
    assert run("bob", "fingerprint", "alice") == 0
    assert "TOFU" in capsys.readouterr().out
    assert run("bob", "fingerprint", "alice", "--trust") == 0


def test_comando_parametros_globales_despues(run, capsys):
    assert run("alice", "keygen", "--kdf-iters", "1000") == 0
    # --no-color también funciona después del subcomando
    from src.client.cli import main
    assert main(["fingerprint", "--user", "alice", "--home", str(run.app.extensions["grupof_storage"].data_dir.parent / "homes"),
                 "--no-color"]) == 0


def test_errores_y_fallo_de_seguridad(run, tmp_path, capsys):
    assert run("alice", "keygen", "--kdf-iters", "1000") == 0
    assert run("alice", "register") == 0
    assert run("alice", "list") == 1                          # sin login
    assert "login" in capsys.readouterr().err
    assert run("alice", "login", passphrase="incorrecta!!") == 1
    assert "passphrase incorrecta" in capsys.readouterr().err
    assert run("alice", "login") == 0
    f = tmp_path / "a.bin"
    f.write_bytes(b"\x00" * 100)
    assert run("alice", "upload", str(f)) == 0
    file_id = capsys.readouterr().out.split("file_id: ")[1].split()[0]
    st = run.app.extensions["grupof_storage"]
    blob = st.blob_dir / f"{file_id}.bin"
    data = bytearray(blob.read_bytes())
    data[0] ^= 0x80
    blob.write_bytes(bytes(data))
    assert run("alice", "download", file_id, "--out", str(tmp_path / "x.bin")) == cli.EXIT_SECURITY
    assert "FALLO DE SEGURIDAD" in capsys.readouterr().err
    assert not (tmp_path / "x.bin").exists()                  # no se entregaron datos parciales


def test_passphrase_corta_rechazada(run, capsys):
    assert run("carol", "keygen", passphrase="corta") == 1
