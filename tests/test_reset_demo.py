"""Pruebas del script de limpieza scripts/reset_demo.py (siempre sobre carpetas temporales)."""

import importlib.util
from pathlib import Path

import pytest

from src.server.storage import Storage

ROOT = Path(__file__).resolve().parent.parent
CLOSED = "http://127.0.0.1:1"   # puerto cerrado: nunca consulta un servidor real


@pytest.fixture
def reset():
    spec = importlib.util.spec_from_file_location("reset_demo", ROOT / "scripts" / "reset_demo.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "server_data"
    st = Storage(data)
    st.add_user("alice_7d42", "pem", "fp1")
    home = tmp_path / "homes"
    for u in ("alice", "bob", "dave"):
        (home / u).mkdir(parents=True)
        (home / u / "private_key.enc.json").write_text("{}")
    return data, home


def _args(data, home, *extra):
    return ["--data-dir", str(data), "--home", str(home), "--server", CLOSED, *extra]


def test_dry_run_no_borra(reset, env, capsys):
    data, home = env
    assert reset.main(_args(data, home, "--dry-run")) == 0
    out = capsys.readouterr().out
    assert "alice_7d42" in out and "No se borró nada" in out
    assert data.exists() and (home / "alice").exists()


def test_borra_con_yes(reset, env):
    data, home = env
    assert reset.main(_args(data, home, "--yes", "--users", "alice,bob")) == 0
    assert not data.exists()
    assert not (home / "alice").exists() and not (home / "bob").exists()
    assert (home / "dave").exists()          # no indicado: se conserva


def test_cancelar(reset, env, monkeypatch):
    data, home = env
    monkeypatch.setattr("builtins.input", lambda _p: "no")
    assert reset.main(_args(data, home)) == 0
    assert data.exists() and (home / "alice").exists()


def test_rechaza_carpeta_que_no_es_del_servidor(reset, tmp_path):
    other = tmp_path / "mis_documentos"
    other.mkdir()
    (other / "tesis.docx").write_text("importante")
    assert reset.main(["--data-dir", str(other), "--home", str(tmp_path), "--server", CLOSED, "--yes"]) == 2
    assert (other / "tesis.docx").exists()


def test_rechaza_nombres_peligrosos(reset, env):
    data, home = env
    assert reset.main(_args(data, home, "--yes", "--users", "..,alice")) == 2
    assert (home / "alice").exists() and data.exists()


def test_aborta_si_el_servidor_esta_en_ejecucion(reset, env, monkeypatch):
    data, home = env
    monkeypatch.setattr(reset, "server_running", lambda _url: True)
    assert reset.main(_args(data, home, "--yes")) == 1
    assert data.exists()


def test_solo_keystores(reset, env):
    data, home = env
    assert reset.main(_args(data, home, "--yes", "--solo-keystores", "--users", "dave")) == 0
    assert data.exists() and not (home / "dave").exists()
