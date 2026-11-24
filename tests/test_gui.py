"""Pruebas de la GUI Tkinter conducida programáticamente (servidor en el mismo proceso).

Los diálogos modales se reemplazan por respuestas automáticas; se verifica que
la GUI usa la misma lógica (service/envelope), que el registro de operaciones
muestra los pasos criptográficos y que los fallos de seguridad abren el diálogo rojo.
Se omiten si no hay entorno gráfico disponible.
"""

import time
from pathlib import Path

import pytest

tk = pytest.importorskip("tkinter")

from src.client import gui  # noqa: E402
from src.client.api_client import InProcessTransport  # noqa: E402
from src.server.app import create_app  # noqa: E402
from tests.client_helpers import make_service  # noqa: E402


@pytest.fixture
def tk_root():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"sin entorno gráfico: {exc}")
    root.withdraw()
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass
    # Liberar AQUÍ (hilo principal) los ciclos de referencias que contienen objetos de Tk;
    # si no, el recolector podría hacerlo desde el hilo de trabajo de otra prueba (gh-83274).
    import gc
    gc.collect()


@pytest.fixture
def setup(tmp_path, fast_keygen, monkeypatch):
    server = create_app(tmp_path / "server_data")
    client = server.test_client()
    home = tmp_path / "homes"
    for name in ("alice", "bob", "carol"):
        svc = make_service(client, home, name)
        svc.keygen(bytearray(f"passphrase-de-{name}".encode()), iterations=1000)
        svc.register()
        svc.login()
    # Respuestas automáticas a los diálogos
    record = {"security": [], "errors": [], "info": []}

    class FakeSecurityDialog:
        def __init__(self, parent, heading, message, footer):
            record["security"].append((heading, message, footer))

        def show(self):
            return None

    monkeypatch.setattr(gui, "SecurityErrorDialog", FakeSecurityDialog)
    monkeypatch.setattr(gui.messagebox, "showerror", lambda *a, **k: record["errors"].append(a))
    monkeypatch.setattr(gui.messagebox, "showinfo", lambda *a, **k: record["info"].append(a))
    monkeypatch.setattr(gui.messagebox, "showwarning", lambda *a, **k: record["errors"].append(a))
    monkeypatch.setattr(gui.messagebox, "askyesno", lambda *a, **k: True)   # confirma huellas
    return server, client, home, record, tmp_path


def make_app(root, client, home, user, monkeypatch):
    monkeypatch.setenv("GRUPOF_PASSPHRASE", f"passphrase-de-{user}")
    app = gui.App(root, "http://test-server", home, transport_factory=lambda _s: InProcessTransport(client),
                  custom_home=True)
    app.open_user(user)
    wait_idle(root, app)
    return app


def wait_idle(root, app, timeout=60):
    # procesar eventos un momento: algunas acciones se programan con after(...)
    settle = time.time() + 0.15
    while time.time() < settle:
        root.update()
        time.sleep(0.01)
    end = time.time() + timeout
    while time.time() < end:
        root.update()
        if not app.busy and app.bridge.q.empty():
            root.update()
            if not app.busy:
                _join_workers()
                return
        time.sleep(0.01)
    raise TimeoutError("la tarea de la GUI no terminó")


def _join_workers():
    """Espera a que terminen los hilos de tarea: así ningún objeto de Tk se libera fuera del hilo principal."""
    import threading
    for t in threading.enumerate():
        if t.name.startswith("tarea:"):
            t.join(timeout=5)


def log_text(app) -> str:
    return app.log.text.get("1.0", "end")


def test_subir_compartir_y_descargar_desde_la_gui(tk_root, setup, monkeypatch):
    server, client, home, record, tmp = setup
    alice = make_app(tk_root, client, home, "alice", monkeypatch)
    assert alice.svc.is_unlocked
    assert alice.tree.get_children() == ()

    src = tmp / "acta.txt"
    src.write_text("acta secreta de la reunión", encoding="utf-8")
    monkeypatch.setattr(gui.ChooseUsersDialog, "show", lambda self: ["bob"])
    alice._upload_choose(src, ["alice", "bob", "carol"])
    tk_root.after(20, lambda: None)
    wait_idle(tk_root, alice)
    wait_idle(tk_root, alice)   # el refresco de la lista se encadena después de subir

    text = log_text(alice)
    for expected in ("Clave de sesión AES-256 generada", "Contenido cifrado con AES-256-GCM", "(tag: ",
                     "Clave de sesión envuelta con RSA-OAEP-SHA256 para bob", "Firma RSA-PSS creada",
                     "Enviado al servidor: solo datos cifrados"):
        assert expected in text, expected
    rows = [alice.tree.item(i, "values") for i in alice.tree.get_children()]
    assert len(rows) == 1 and rows[0][0] == "acta.txt" and rows[0][5] == "bob"
    file_id = alice.tree.get_children()[0]

    # bob descarga: el nombre aparece cifrado hasta descargar
    tk_root2 = tk.Toplevel(tk_root)   # segunda "ventana" en la misma prueba
    bob = make_app(tk_root2, client, home, "bob", monkeypatch)
    assert bob.tree.item(file_id, "values")[0].startswith("(nombre cifrado")
    out = tmp / "descargado.txt"
    monkeypatch.setattr(gui.filedialog, "asksaveasfilename", lambda **k: str(out))
    bob.tree.selection_set(file_id)
    bob.act_download()
    wait_idle(tk_root, bob)
    wait_idle(tk_root, bob)
    assert out.read_text(encoding="utf-8") == "acta secreta de la reunión"
    text = log_text(bob)
    for expected in ("Firma RSA-PSS VÁLIDA", "Clave de sesión desenvuelta con RSA-OAEP",
                     "Tag AES-GCM verificado", "nombre real 'acta.txt'"):
        assert expected in text, expected
    assert record["security"] == [] and record["errors"] == []


def test_fallo_de_seguridad_muestra_dialogo_rojo(tk_root, setup, monkeypatch):
    server, client, home, record, tmp = setup
    alice = make_app(tk_root, client, home, "alice", monkeypatch)
    src = tmp / "a.txt"
    src.write_text("hola", encoding="utf-8")
    alice.run_task("subir", lambda: alice.svc.upload(src), on_done=alice._uploaded)
    wait_idle(tk_root, alice)
    wait_idle(tk_root, alice)
    blob = next((tmp / "server_data" / "blobs").glob("*.bin"))
    data = bytearray(blob.read_bytes())
    data[0] ^= 1
    blob.write_bytes(bytes(data))
    alice.tree.selection_set(blob.stem)
    alice.act_verify()
    wait_idle(tk_root, alice)
    assert len(record["security"]) == 1
    heading, message, footer = record["security"][0]
    assert heading == "FALLO DE SEGURIDAD" and "firma" in message and "no se entregó" in footer
    assert "FALLO DE SEGURIDAD" in log_text(alice)


def test_alerta_mitm_en_dialogo(tk_root, setup, monkeypatch):
    import sqlite3

    from src.crypto.encoding import public_key_to_pem
    from src.crypto.rsa_core import generate_keypair
    server, client, home, record, tmp = setup
    alice = make_app(tk_root, client, home, "alice", monkeypatch)
    alice.svc.trust("bob")                                   # alice fija la huella de bob
    with sqlite3.connect(tmp / "server_data" / "metadata.sqlite3") as c:
        c.execute("UPDATE users SET public_key_pem=? WHERE username='bob'",
                  (public_key_to_pem(generate_keypair(2048).public_key()),))
    src = tmp / "b.txt"
    src.write_text("x", encoding="utf-8")
    alice.run_task("subir", lambda: alice.svc.upload(src, ["bob"]))
    wait_idle(tk_root, alice)
    assert record["security"] and record["security"][0][0] == "¡POSIBLE ATAQUE MITM!"


def test_bridge_call_desde_hilo(tk_root):
    import threading
    bridge = gui.UiBridge(tk_root)
    box = {}
    t = threading.Thread(target=lambda: box.setdefault("r", bridge.call(lambda: threading.current_thread().name)))
    t.start()
    end = time.time() + 5
    while t.is_alive() and time.time() < end:
        tk_root.update()
        time.sleep(0.01)
    assert box["r"] == threading.main_thread().name   # el diálogo se ejecutó en el hilo de Tk


def test_verificar_registra_cada_paso_una_sola_vez(tk_root, setup, monkeypatch):
    server, client, home, record, tmp = setup
    alice = make_app(tk_root, client, home, "alice", monkeypatch)
    src = tmp / "v.txt"
    src.write_text("verificar", encoding="utf-8")
    alice.run_task("subir", lambda: alice.svc.upload(src), on_done=alice._uploaded)
    wait_idle(tk_root, alice)
    wait_idle(tk_root, alice)
    alice.log.clear()
    alice.tree.selection_set(alice.tree.get_children()[0])
    alice.act_verify()
    wait_idle(tk_root, alice)
    text = log_text(alice)
    assert text.count("Firma RSA-PSS VÁLIDA") == 1
    assert text.count("Huella del firmante") == 1
    assert text.count("AAD coherente") == 1
    assert text.count("Tag AES-GCM VÁLIDO") == 1
    assert record["info"] and "Verificación correcta" in record["info"][0][0]


@pytest.mark.parametrize("target,original,expected", [
    ("C:/x/informe", "presupuesto.pdf", "C:/x/informe.pdf"),        # quitó la extensión: se conserva
    ("C:/x/informe.txt", "presupuesto.pdf", "C:/x/informe.txt"),    # eligió otra: se respeta
    ("C:/x/notas", "LEEME", "C:/x/notas"),                          # el original no tenía extensión
    ("C:/x/copia.v2", "datos.tar.gz", "C:/x/copia.v2"),
])
def test_conserva_extension_original(target, original, expected):
    assert gui.keep_original_extension(Path(target), original) == Path(expected)


def test_usuarios_locales(tmp_path):
    (tmp_path / "alice").mkdir()
    (tmp_path / "alice" / "private_key.enc.json").write_text("{}")
    (tmp_path / "vacio").mkdir()
    assert gui.list_local_users(tmp_path) == ["alice"]
    assert gui.list_local_users(Path(tmp_path / "no-existe")) == []
