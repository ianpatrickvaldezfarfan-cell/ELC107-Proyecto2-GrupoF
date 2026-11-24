"""Interfaz gráfica de escritorio (Tkinter) del cliente Zero-Trust - Grupo F.

No contiene criptografía propia: usa exactamente la misma lógica que la CLI
(service.py / envelope.py). Lo que agrega es:
  * ventanas y diálogos (usuario, passphrase, huellas, errores de seguridad);
  * un REGISTRO DE OPERACIONES que muestra paso a paso lo que ocurre
    criptográficamente (lo alimenta el parámetro `trace` de envelope/service);
  * ejecución de las operaciones lentas (PBKDF2, generación de claves, cifrado)
    en un hilo aparte, con indicador de progreso, para que la ventana no se congele.

Hilos: Tkinter NO es seguro entre hilos. El hilo de trabajo nunca toca widgets:
envía funciones a una cola que el hilo de la interfaz ejecuta cada 50 ms
(UiBridge.post). Cuando el hilo de trabajo necesita una respuesta del usuario
(passphrase, confirmar una huella) usa UiBridge.call, que muestra el diálogo en
el hilo de la interfaz y espera el resultado.

Clave privada: se desbloquea una vez al abrir el usuario y queda en memoria
mientras la ventana está abierta (botón "Bloquear" para descartarla). La
passphrase se lee de un Entry de Tk: Tk guarda el texto como str inmutable que
no puede borrarse de forma fiable (misma limitación documentada en utils.py).

Varias ventanas: cada ventana es un proceso independiente
("Abrir otra ventana" lanza otro), así alice y bob pueden usarse a la vez.

Uso:  python grupof_gui.py [--user alice] [--server http://127.0.0.1:5000] [--home DIR]
"""

from __future__ import annotations

import argparse
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable

from ..crypto.encoding import format_fingerprint
from ..crypto.kdf import DEFAULT_ITERATIONS
from .api_client import ApiClient, ApiError, RequestsTransport
from .envelope import OpenedFile, PackageError
from .keystore import Keystore, KeystoreError, default_home
from .service import ClientError, ClientService, FileRow, Reporter, TrustError, fmt_int, safe_filename

ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_SERVER = "http://127.0.0.1:5000"
MIN_PASSPHRASE = 8
ITERATION_CHOICES = [
    ("10.000 (SOLO demostración)", 10_000),
    ("20.000", 20_000),
    ("100.000 (por defecto)", 100_000),
    ("600.000 (recomendado OWASP, muy lento)", 600_000),
]

COLORS = {
    "bg": "#f6f6f4", "panel": "#ffffff", "text": "#1b1b1b", "muted": "#5f5e5a",
    "accent": "#2a78d6", "ok": "#1e7d32", "warn": "#a86100", "error": "#b3261e",
    "trace": "#5b3fb5", "title": "#0b0b0b", "danger_bg": "#b3261e", "danger_soft": "#fdecea",
}
LOG_STYLES = {  # tipo -> (prefijo, color)
    "title": ("══", COLORS["title"]),
    "step": ("→ ", COLORS["accent"]),
    "trace": ("  ▸", COLORS["trace"]),
    "info": ("ℹ ", COLORS["muted"]),
    "ok": ("✓ ", COLORS["ok"]),
    "warn": ("! ", COLORS["warn"]),
    "error": ("✗ ", COLORS["error"]),
}


def keep_original_extension(target: Path, original_name: str) -> Path:
    """Si el usuario cambió el nombre en el diálogo Guardar y quitó la extensión,
    se conserva la extensión original del archivo ('informe' -> 'informe.pdf')."""
    original_ext = Path(original_name).suffix
    if original_ext and not target.suffix:
        return target.with_name(target.name + original_ext)
    return target


def list_local_users(home: Path) -> list[str]:
    if not home.exists():
        return []
    return sorted(p.name for p in home.iterdir() if (p / "private_key.enc.json").exists())


# ---------------------------------------------------------------------------
# Comunicación entre hilos
# ---------------------------------------------------------------------------
class UiBridge:
    """Ejecuta funciones en el hilo de Tk a pedido de los hilos de trabajo."""

    def __init__(self, root: tk.Misc) -> None:
        self.root = root
        self.q: queue.Queue = queue.Queue()
        self._poll()

    def post(self, fn: Callable, *args) -> None:
        """Encola fn(*args) para el hilo de la interfaz (no espera)."""
        self.q.put((fn, args))

    def call(self, fn: Callable[[], Any]) -> Any:
        """Ejecuta fn() en el hilo de la interfaz y espera su resultado (para diálogos)."""
        if threading.current_thread() is threading.main_thread():
            return fn()
        done, box = threading.Event(), {}

        def wrapper():
            try:
                box["result"] = fn()
            except BaseException as exc:  # se relanza en el hilo de trabajo
                box["error"] = exc
            finally:
                done.set()

        self.q.put((wrapper, ()))
        done.wait()
        if "error" in box:
            raise box["error"]
        return box.get("result")

    def _poll(self) -> None:
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        try:
            self.root.after(50, self._poll)
        except tk.TclError:
            pass  # la ventana se cerró


# ---------------------------------------------------------------------------
# Registro de operaciones
# ---------------------------------------------------------------------------
class LogPanel(ttk.Frame):
    def __init__(self, parent) -> None:
        super().__init__(parent)
        self.text = ScrolledText(self, height=14, wrap="word", font=("Consolas", 9), bg=COLORS["panel"],
                                 fg=COLORS["text"], relief="flat", borderwidth=1, state="disabled")
        self.text.pack(fill="both", expand=True)
        for kind, (_, color) in LOG_STYLES.items():
            self.text.tag_configure(kind, foreground=color)
        self.text.tag_configure("title", font=("Consolas", 9, "bold"), spacing1=6)
        self.text.tag_configure("time", foreground="#9a9994")

    def append(self, kind: str, msg: str) -> None:
        prefix, _ = LOG_STYLES.get(kind, ("", COLORS["text"]))
        self.text.configure(state="normal")
        self.text.insert("end", time.strftime("%H:%M:%S "), "time")
        if kind == "title":
            self.text.insert("end", f"{prefix} {msg} {prefix}\n", kind)
        else:
            self.text.insert("end", f"{prefix} {msg}\n", kind)
        self.text.configure(state="disabled")
        self.text.see("end")

    def clear(self) -> None:
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")


class GuiReporter(Reporter):
    """Envía los mensajes del servicio (que corre en otro hilo) al registro de operaciones."""

    def __init__(self, bridge: UiBridge, log: LogPanel) -> None:
        self.bridge, self.log = bridge, log

    def _send(self, kind, msg):
        self.bridge.post(self.log.append, kind, msg)

    def step(self, msg):
        self._send("step", msg)

    def info(self, msg):
        self._send("info", msg)

    def ok(self, msg):
        self._send("ok", msg)

    def warn(self, msg):
        self._send("warn", msg)

    def trace(self, msg):
        self._send("trace", msg)


# ---------------------------------------------------------------------------
# Diálogos
# ---------------------------------------------------------------------------
class _Modal(tk.Toplevel):
    def __init__(self, parent, title: str) -> None:
        super().__init__(parent)
        self.withdraw()
        self.title(title)
        self.transient(parent.winfo_toplevel())
        self.resizable(False, False)
        self.configure(bg=COLORS["bg"])
        self.result: Any = None
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.bind("<Escape>", lambda _e: self.cancel())

    def show(self) -> Any:
        self.update_idletasks()
        parent = self.master.winfo_toplevel()
        x = parent.winfo_rootx() + max(0, (parent.winfo_width() - self.winfo_reqwidth()) // 2)
        y = parent.winfo_rooty() + max(0, (parent.winfo_height() - self.winfo_reqheight()) // 3)
        self.geometry(f"+{x}+{y}")
        self.deiconify()
        try:
            self.grab_set()
        except tk.TclError:
            pass  # otra ventana tiene el grab; el diálogo sigue siendo usable
        self.focus_force()
        self.wait_window()
        return self.result

    def cancel(self) -> None:
        self.result = None
        self.destroy()


class PassphraseDialog(_Modal):
    def __init__(self, parent, prompt: str) -> None:
        super().__init__(parent, "Passphrase del keystore")
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        ttk.Label(frm, text=prompt, wraplength=360).pack(anchor="w")
        self.var = tk.StringVar()
        self.entry = ttk.Entry(frm, textvariable=self.var, show="•", width=40)
        self.entry.pack(fill="x", pady=(8, 4))
        ttk.Label(frm, text="Se derivará la clave con PBKDF2; puede tardar unos segundos.",
                  foreground=COLORS["muted"]).pack(anchor="w")
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Cancelar", command=self.cancel).pack(side="right")
        ttk.Button(btns, text="Desbloquear", command=self.accept).pack(side="right", padx=6)
        self.bind("<Return>", lambda _e: self.accept())
        self.after(50, self.entry.focus_set)

    def accept(self) -> None:
        value = self.var.get()
        self.result = bytearray(value.encode("utf-8"))
        self.var.set("")
        self.destroy()


class NewIdentityDialog(_Modal):
    """Usuario (si es nuevo), passphrase dos veces, iteraciones de PBKDF2 y tamaño RSA."""

    def __init__(self, parent, username: str | None = None) -> None:
        super().__init__(parent, "Generar claves")
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        frm.columnconfigure(1, weight=1)
        row = 0
        self.user_var = tk.StringVar(value=username or "")
        ttk.Label(frm, text="Usuario:").grid(row=row, column=0, sticky="w", pady=3)
        e = ttk.Entry(frm, textvariable=self.user_var, width=32)
        e.grid(row=row, column=1, sticky="ew", pady=3)
        if username:
            e.configure(state="disabled")
        row += 1
        self.pw1, self.pw2 = tk.StringVar(), tk.StringVar()
        ttk.Label(frm, text="Passphrase:").grid(row=row, column=0, sticky="w", pady=3)
        self.first = ttk.Entry(frm, textvariable=self.pw1, show="•")
        self.first.grid(row=row, column=1, sticky="ew", pady=3)
        row += 1
        ttk.Label(frm, text="Repetir passphrase:").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(frm, textvariable=self.pw2, show="•").grid(row=row, column=1, sticky="ew", pady=3)
        row += 1
        ttk.Label(frm, text="Iteraciones PBKDF2:").grid(row=row, column=0, sticky="w", pady=3)
        self.iter_var = tk.StringVar(value=ITERATION_CHOICES[2][0])
        cb = ttk.Combobox(frm, textvariable=self.iter_var, state="readonly", width=36,
                          values=[label for label, _ in ITERATION_CHOICES])
        cb.grid(row=row, column=1, sticky="ew", pady=3)
        cb.bind("<<ComboboxSelected>>", lambda _e: self._update_hint())
        row += 1
        ttk.Label(frm, text="Tamaño RSA:").grid(row=row, column=0, sticky="w", pady=3)
        self.bits_var = tk.StringVar(value="2048")
        bits = ttk.Frame(frm)
        bits.grid(row=row, column=1, sticky="w")
        for b in ("2048", "3072"):
            ttk.Radiobutton(bits, text=f"{b} bits", value=b, variable=self.bits_var).pack(side="left", padx=(0, 10))
        row += 1
        self.hint = ttk.Label(frm, wraplength=380, foreground=COLORS["muted"])
        self.hint.grid(row=row, column=0, columnspan=2, sticky="w", pady=(8, 0))
        self._update_hint()
        row += 1
        btns = ttk.Frame(frm)
        btns.grid(row=row, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(btns, text="Generar", command=self.accept).pack(side="left", padx=6)
        ttk.Button(btns, text="Cancelar", command=self.cancel).pack(side="left")
        self.bind("<Return>", lambda _e: self.accept())
        self.after(50, (self.first if username else e).focus_set)

    def _iterations(self) -> int:
        return dict(ITERATION_CHOICES)[self.iter_var.get()]

    def _update_hint(self) -> None:
        it = self._iterations()
        if it < DEFAULT_ITERATIONS:
            text = (f"{fmt_int(it)} iteraciones es menos que el valor por defecto ({fmt_int(DEFAULT_ITERATIONS)}): "
                    "úselo SOLO para demostraciones. OWASP recomienda 600.000.")
            self.hint.configure(foreground=COLORS["warn"], text=text)
        else:
            self.hint.configure(foreground=COLORS["muted"],
                                text="OWASP recomienda 600.000; el sistema usa 100.000 por el costo de Python puro.")

    def accept(self) -> None:
        user = self.user_var.get().strip().lower()
        p1, p2 = self.pw1.get(), self.pw2.get()
        if not user:
            messagebox.showwarning("Generar claves", "Indique un nombre de usuario.", parent=self)
            return
        if p1 != p2:
            messagebox.showwarning("Generar claves", "Las passphrases no coinciden.", parent=self)
            return
        if len(p1) < MIN_PASSPHRASE:
            messagebox.showwarning("Generar claves", f"La passphrase debe tener al menos {MIN_PASSPHRASE} caracteres.",
                                   parent=self)
            return
        self.result = {"username": user, "passphrase": bytearray(p1.encode("utf-8")),
                       "iterations": self._iterations(), "bits": int(self.bits_var.get())}
        self.pw1.set("")
        self.pw2.set("")
        self.destroy()


class ChooseUsersDialog(_Modal):
    """Elegir destinatarios (varios, con casillas) o uno solo (lista)."""

    def __init__(self, parent, title: str, prompt: str, users: list[str], multi: bool) -> None:
        super().__init__(parent, title)
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        ttk.Label(frm, text=prompt, wraplength=340).pack(anchor="w", pady=(0, 8))
        self.multi = multi
        self.vars: dict[str, tk.BooleanVar] = {}
        self.single = tk.StringVar(value=users[0] if users else "")
        if not users:
            ttk.Label(frm, text="(no hay otros usuarios registrados)", foreground=COLORS["muted"]).pack(anchor="w")
        for u in users:
            if multi:
                v = tk.BooleanVar(value=False)
                self.vars[u] = v
                ttk.Checkbutton(frm, text=u, variable=v).pack(anchor="w")
            else:
                ttk.Radiobutton(frm, text=u, value=u, variable=self.single).pack(anchor="w")
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(12, 0))
        ttk.Button(btns, text="Cancelar", command=self.cancel).pack(side="right")
        ttk.Button(btns, text="Aceptar", command=self.accept).pack(side="right", padx=6)

    def accept(self) -> None:
        if self.multi:
            self.result = [u for u, v in self.vars.items() if v.get()]
        else:
            self.result = [self.single.get()] if self.single.get() else None
        self.destroy()


class SecurityErrorDialog(_Modal):
    """Diálogo rojo para fallos de seguridad (firma/tag inválidos, clave no autorizada, MITM)."""

    def __init__(self, parent, heading: str, message: str, footer: str) -> None:
        super().__init__(parent, heading)
        self.configure(bg=COLORS["danger_soft"])
        band = tk.Frame(self, bg=COLORS["danger_bg"])
        band.pack(fill="x")
        tk.Label(band, text=f"✖  {heading}", bg=COLORS["danger_bg"], fg="white",
                 font=("Segoe UI", 14, "bold"), padx=18, pady=12).pack(anchor="w")
        tk.Label(self, text=message, bg=COLORS["danger_soft"], fg=COLORS["text"], justify="left",
                 wraplength=520, font=("Segoe UI", 10), padx=18, pady=12).pack(anchor="w")
        tk.Label(self, text=footer, bg=COLORS["danger_soft"], fg=COLORS["error"],
                 font=("Segoe UI", 10, "bold"), padx=18).pack(anchor="w")
        tk.Button(self, text="Entendido", command=self.destroy, bg=COLORS["danger_bg"], fg="white",
                  activebackground="#8c1d18", activeforeground="white", relief="flat",
                  padx=16, pady=4).pack(anchor="e", padx=18, pady=14)
        self.bell()


class FingerprintDialog(_Modal):
    """Mi huella y consulta/verificación de huellas de otros usuarios."""

    def __init__(self, parent, app: "App") -> None:
        super().__init__(parent, "Huellas de claves públicas")
        self.app = app
        svc = app.svc
        frm = ttk.Frame(self, padding=16)
        frm.pack(fill="both")
        ttk.Label(frm, text=f"Mi huella ({svc.user}) - compártala por un canal independiente:",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w")
        own = format_fingerprint(svc.ks.fingerprint())
        box = tk.Text(frm, height=2, width=42, font=("Consolas", 12), relief="flat", bg=COLORS["panel"])
        box.insert("1.0", own[:39] + "\n" + own[40:])
        box.configure(state="disabled")
        box.pack(anchor="w", pady=6)
        ttk.Button(frm, text="Copiar", command=lambda: self._copy(own)).pack(anchor="w")
        ttk.Separator(frm).pack(fill="x", pady=12)
        ttk.Label(frm, text="Verificar la huella de otro usuario:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        row = ttk.Frame(frm)
        row.pack(fill="x", pady=6)
        self.user_var = tk.StringVar()
        self.combo = ttk.Combobox(row, textvariable=self.user_var, width=20)
        self.combo.pack(side="left")
        ttk.Button(row, text="Consultar", command=self.lookup).pack(side="left", padx=6)
        self.trust_btn = ttk.Button(row, text="Marcar como verificada", command=self.trust, state="disabled")
        self.trust_btn.pack(side="left")
        self.result_lbl = tk.Label(frm, text="", justify="left", font=("Consolas", 10), bg=COLORS["bg"],
                                   wraplength=520)
        self.result_lbl.pack(anchor="w", pady=6)
        ttk.Button(frm, text="Cerrar", command=self.destroy).pack(anchor="e")
        app.run_task("Consultar directorio de claves", svc.registered_users,
                     on_done=lambda users: self._fill(users), quiet=True)

    def _fill(self, users: list[str]) -> None:
        if self.winfo_exists():
            self.combo.configure(values=[u for u in users if u != self.app.svc.user])

    def _copy(self, text: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(text)

    def lookup(self) -> None:
        user = self.user_var.get().strip()
        if user:
            self.app.run_task(f"Huella de {user}", lambda: self.app.svc.fingerprint_info(user), on_done=self._show)

    def _show(self, info: dict) -> None:
        if not self.winfo_exists():
            return
        lines = [format_fingerprint(info["fingerprint"])]
        color = COLORS["text"]
        if info.get("pinned") is None:
            lines.append("Aún no fijada. Compárela fuera de banda antes de confiar.")
            color = COLORS["warn"]
        elif info["matches_pinned"]:
            state = "verificada fuera de banda" if info["verified_out_of_band"] else "fijada por TOFU (sin verificar)"
            lines.append(f"✓ Coincide con la huella fijada ({state}).")
            color = COLORS["ok"]
        else:
            lines.append("✗ ¡NO coincide con la huella fijada! Posible ataque MITM.")
            color = COLORS["error"]
        self.result_lbl.configure(text="\n".join(lines), fg=color)
        self.trust_btn.configure(state="normal" if info.get("matches_pinned") is not False else "disabled")

    def trust(self) -> None:
        user = self.user_var.get().strip()
        if not user:
            return
        if messagebox.askyesno("Confirmar", f"¿Comparó la huella de '{user}' por un canal independiente "
                               "(en persona, por teléfono) y coincide?", parent=self, icon="warning"):
            self.app.run_task(f"Confiar en {user}", lambda: self.app.svc.trust(user),
                              on_done=lambda _fp: self.lookup())


# ---------------------------------------------------------------------------
# Aplicación
# ---------------------------------------------------------------------------
class App:
    def __init__(self, root: tk.Tk, server: str, home: Path | None, transport_factory=RequestsTransport,
                 custom_home: bool = False) -> None:
        self.root = root
        self.server = server.rstrip("/")
        self.home = home or default_home()
        self.custom_home = custom_home
        self.transport_factory = transport_factory
        self.bridge = UiBridge(root)
        self.svc: ClientService | None = None
        self.busy = False
        self.rows: dict[str, FileRow] = {}
        self.buttons: list[ttk.Button] = []
        root.title("Zero-Trust Storage - Grupo F")
        scale = max(1.0, root.winfo_fpixels("1i") / 96.0)   # pantallas con escalado (125 %, 150 %...)
        sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()
        w, h = min(int(1120 * scale), int(sw * 0.92)), min(int(740 * scale), int(sh * 0.85))
        root.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h) // 3)}")
        root.minsize(min(int(900 * scale), w), min(int(560 * scale), h))
        root.configure(bg=COLORS["bg"])
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        style = ttk.Style(root)
        style.configure("Header.TLabel", font=("Segoe UI", 13, "bold"))
        style.configure("Muted.TLabel", foreground=COLORS["muted"])
        style.configure("Treeview", rowheight=24)
        self.container = ttk.Frame(root, padding=12)
        self.container.pack(fill="both", expand=True)

    # ------------------------------------------------------------ pantalla inicial
    def show_start(self) -> None:
        for w in self.container.winfo_children():
            w.destroy()
        frm = ttk.Frame(self.container, padding=30)
        frm.place(relx=0.5, rely=0.4, anchor="center")
        ttk.Label(frm, text="Almacenamiento en la nube Zero-Trust", style="Header.TLabel").pack(anchor="w")
        ttk.Label(frm, text="ELC107 Criptografía y Seguridad - Grupo F", style="Muted.TLabel").pack(anchor="w",
                                                                                                    pady=(0, 16))
        grid = ttk.Frame(frm)
        grid.pack(fill="x")
        ttk.Label(grid, text="Servidor:").grid(row=0, column=0, sticky="w", pady=4)
        self.server_var = tk.StringVar(value=self.server)
        ttk.Entry(grid, textvariable=self.server_var, width=36).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(grid, text="Usuario:").grid(row=1, column=0, sticky="w", pady=4)
        users = list_local_users(self.home)
        self.start_user = tk.StringVar(value=users[0] if users else "")
        ttk.Combobox(grid, textvariable=self.start_user, values=users, width=34).grid(row=1, column=1, sticky="ew")
        btns = ttk.Frame(frm)
        btns.pack(fill="x", pady=(16, 0))
        ttk.Button(btns, text="Abrir usuario", command=self._start_open).pack(side="left")
        ttk.Button(btns, text="Crear usuario nuevo…", command=self._start_create).pack(side="left", padx=8)
        ttk.Label(frm, text=f"Keystores en: {self.home}", style="Muted.TLabel").pack(anchor="w", pady=(16, 0))
        self.root.bind("<Return>", lambda _e: self._start_open())

    def _start_open(self) -> None:
        self.server = self.server_var.get().strip().rstrip("/") or DEFAULT_SERVER
        user = self.start_user.get().strip().lower()
        if not user:
            messagebox.showinfo("Abrir usuario", "Elija un usuario o cree uno nuevo.", parent=self.root)
            return
        if not Keystore(user, self.home).exists():
            if messagebox.askyesno("Usuario nuevo", f"No existe un keystore para '{user}'. ¿Crearlo ahora?",
                                   parent=self.root):
                self._start_create(user)
            return
        self.open_user(user)

    def _start_create(self, username: str | None = None) -> None:
        self.server = self.server_var.get().strip().rstrip("/") or DEFAULT_SERVER
        dlg = NewIdentityDialog(self.root)
        if username:
            dlg.user_var.set(username)
        data = dlg.show()
        if not data:
            return
        try:
            ks = Keystore(data["username"], self.home)
        except Exception as exc:
            messagebox.showerror("Usuario inválido", str(exc), parent=self.root)
            return
        if ks.exists():
            messagebox.showerror("Usuario existente", f"Ya existe un keystore para '{data['username']}'.",
                                 parent=self.root)
            return
        self._build_service(data["username"])
        self.build_main()
        self._keygen(data, overwrite=False)

    # ------------------------------------------------------------ servicio
    def _build_service(self, username: str) -> None:
        self.root.unbind("<Return>")
        # El reporter se reemplaza por GuiReporter al construir el registro de operaciones (build_main)
        self.svc = ClientService(Keystore(username, self.home), ApiClient(self.transport_factory(self.server)),
                                 self.server, self._ask_passphrase, self._confirm)

    def open_user(self, username: str) -> None:
        self._build_service(username)
        self.build_main()
        self.log.append("info", f"Usuario '{username}' - servidor {self.server}")
        self.run_task("Desbloquear clave privada", self.svc.unlock, on_done=lambda _r: self.refresh_files())

    def _ask_passphrase(self, prompt: str) -> bytearray:
        """Llamado desde el hilo de trabajo cuando el servicio necesita la clave privada."""
        env = os.environ.get("GRUPOF_PASSPHRASE")
        if env is not None:
            self.bridge.post(self.log.append, "warn", "passphrase tomada de GRUPOF_PASSPHRASE (solo para demostración)")
            return bytearray(env.encode("utf-8"))
        result = self.bridge.call(lambda: PassphraseDialog(self.root, prompt).show())
        if result is None:
            raise ClientError("operación cancelada: no se ingresó la passphrase")
        return result

    def _confirm(self, question: str) -> bool:
        return bool(self.bridge.call(lambda: messagebox.askyesno(
            "Verificar huella", question + "\n\nSi no la verificó, responda No.", icon="warning", parent=self.root)))

    # ------------------------------------------------------------ ventana principal
    def build_main(self) -> None:
        for w in self.container.winfo_children():
            w.destroy()
        svc = self.svc
        self.root.title(f"Zero-Trust Storage - {svc.user} @ {self.server}")

        header = ttk.Frame(self.container)
        header.pack(fill="x")
        ttk.Label(header, text=f"Usuario: {svc.user}", style="Header.TLabel").pack(side="left")
        self.fp_lbl = ttk.Label(header, text="", style="Muted.TLabel")
        self.fp_lbl.pack(side="left", padx=12)
        self.session_lbl = ttk.Label(header, text="")
        self.session_lbl.pack(side="right")
        self.key_lbl = ttk.Label(header, text="")
        self.key_lbl.pack(side="right", padx=12)

        bar1 = ttk.Frame(self.container)
        bar1.pack(fill="x", pady=(10, 2))
        bar2 = ttk.Frame(self.container)
        bar2.pack(fill="x", pady=(2, 8))
        self.buttons = []
        for parent, items in (
            (bar1, [("Generar claves", self.act_keygen), ("Registrar", self.act_register),
                    ("Iniciar sesión", self.act_login), ("⬆ Subir archivo", self.act_upload),
                    ("⬇ Descargar", self.act_download), ("Compartir", self.act_share)]),
            (bar2, [("✔ Verificar firma", self.act_verify), ("Ver mi huella", self.act_fingerprint),
                    ("⟳ Actualizar lista", self.refresh_files), ("Bloquear clave", self.act_lock),
                    ("Abrir otra ventana", self.act_new_window), ("Cambiar usuario", self.act_switch_user)]),
        ):
            for text, cmd in items:
                b = ttk.Button(parent, text=text, command=cmd)
                b.pack(side="left", padx=(0, 6))
                self.buttons.append(b)

        panes = ttk.PanedWindow(self.container, orient="vertical")
        panes.pack(fill="both", expand=True)
        table_frame = ttk.Frame(panes)
        cols = ("nombre", "id", "dueno", "tamano", "fecha", "compartido")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", selectmode="browse")
        for col, text, width, anchor in (("nombre", "Nombre", 260, "w"), ("id", "file_id", 110, "w"),
                                         ("dueno", "Dueño", 90, "w"), ("tamano", "Tamaño", 80, "e"),
                                         ("fecha", "Fecha", 130, "w"), ("compartido", "Compartido con", 200, "w")):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=anchor)
        sb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self.act_download())
        self.tree.tag_configure("unknown", foreground=COLORS["muted"])
        panes.add(table_frame, weight=3)

        log_frame = ttk.Frame(panes)
        ttk.Label(log_frame, text="Registro de operaciones (paso a paso criptográfico)",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(6, 2))
        self.log = LogPanel(log_frame)
        self.log.pack(fill="both", expand=True)
        panes.add(log_frame, weight=2)

        status = ttk.Frame(self.container)
        status.pack(fill="x", pady=(6, 0))
        self.status_lbl = ttk.Label(status, text="Listo", style="Muted.TLabel")
        self.status_lbl.pack(side="left")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=220)
        self.progress.pack(side="right")

        svc.r = GuiReporter(self.bridge, self.log)
        self.update_header()

    def update_header(self) -> None:
        svc = self.svc
        try:
            fp = format_fingerprint(svc.ks.fingerprint())
            self.fp_lbl.configure(text=f"huella {fp[:19]}…")
        except KeystoreError:
            self.fp_lbl.configure(text="(sin claves)")
        exp = svc.session_expires_at()
        if exp:
            self.session_lbl.configure(text=f"● Sesión activa hasta {time.strftime('%H:%M', time.localtime(exp))}",
                                       foreground=COLORS["ok"])
        else:
            self.session_lbl.configure(text="○ Sin sesión (Iniciar sesión)", foreground=COLORS["warn"])
        if svc.is_unlocked:
            self.key_lbl.configure(text="Clave privada: desbloqueada en memoria", foreground=COLORS["ok"])
        else:
            self.key_lbl.configure(text="Clave privada: bloqueada", foreground=COLORS["muted"])

    # ------------------------------------------------------------ tareas en segundo plano
    def run_task(self, title: str, fn: Callable[[], Any], on_done: Callable[[Any], None] | None = None,
                 quiet: bool = False) -> bool:
        if self.busy:
            self.root.bell()
            return False
        self.busy = True
        for b in self.buttons:
            b.state(["disabled"])
        if hasattr(self, "progress"):
            self.progress.start(12)
            self.status_lbl.configure(text=f"{title}…")
        if not quiet and hasattr(self, "log"):
            self.log.append("title", title)

        def worker():
            try:
                result = fn()
            except BaseException as exc:  # noqa: BLE001 - se muestra en un diálogo
                self.bridge.post(self._finish, None, None, exc)
            else:
                self.bridge.post(self._finish, on_done, result, None)

        threading.Thread(target=worker, daemon=True, name=f"tarea: {title}").start()
        return True

    def _finish(self, on_done, result, exc) -> None:
        """Libera la interfaz ANTES de continuar, para que on_done pueda lanzar otra tarea."""
        self._task_finished()
        if exc is not None:
            self._task_failed(exc)
        elif on_done is not None:
            on_done(result)

    def _task_finished(self) -> None:
        self.busy = False
        for b in self.buttons:
            b.state(["!disabled"])
        if hasattr(self, "progress"):
            self.progress.stop()
            self.progress["value"] = 0
            self.status_lbl.configure(text="Listo")
            self.update_header()

    def _task_failed(self, exc: BaseException) -> None:
        log = getattr(self, "log", None)
        if isinstance(exc, PackageError):
            log and log.append("error", f"FALLO DE SEGURIDAD en '{exc.step}': {exc.message}")
            SecurityErrorDialog(self.root, "FALLO DE SEGURIDAD",
                                f"Paso que falló: {exc.step}\n\n{exc.message}",
                                "Operación abortada: no se entregó ningún dato.").show()
        elif isinstance(exc, TrustError):
            log and log.append("error", str(exc))
            if "ALERTA" in str(exc):
                SecurityErrorDialog(self.root, "¡POSIBLE ATAQUE MITM!", str(exc),
                                    "No se cifró nada para la clave sospechosa.").show()
            else:
                messagebox.showwarning("Huella no confirmada", str(exc), parent=self.root)
        elif isinstance(exc, ApiError):
            log and log.append("error", f"servidor: {exc.message}")
            messagebox.showerror("Servidor", exc.message, parent=self.root)
        elif isinstance(exc, (ClientError, KeystoreError)):
            log and log.append("error", str(exc))
            messagebox.showerror("Error", str(exc), parent=self.root)
        else:
            log and log.append("error", "".join(traceback.format_exception_only(type(exc), exc)).strip())
            messagebox.showerror("Error inesperado", repr(exc), parent=self.root)

    # ------------------------------------------------------------ acciones
    def _selected(self) -> FileRow | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Seleccione un archivo", "Seleccione un archivo en la tabla.", parent=self.root)
            return None
        return self.rows.get(sel[0])

    def refresh_files(self) -> None:
        if self.svc.session_expires_at() is None:
            self.tree.delete(*self.tree.get_children())
            self.rows = {}
            self.log.append("info", "Sin sesión activa: pulse «Registrar» (la primera vez) e «Iniciar sesión».")
            self.update_header()
            return
        self.run_task("Listar archivos (sin pedir passphrase: usa el token)", self.svc.list_files,
                      on_done=self._fill_table, quiet=True)

    def _fill_table(self, rows: list[FileRow]) -> None:
        self.tree.delete(*self.tree.get_children())
        self.rows = {r.file_id: r for r in rows}
        for r in rows:
            shared = ", ".join(x for x in (r.recipients or []) if x != self.svc.user) if r.is_owner else "—"
            size = f"{r.size / 1024:.1f} KB" if r.size >= 1024 else f"{r.size} B"
            self.tree.insert("", "end", iid=r.file_id, tags=() if r.filename else ("unknown",), values=(
                r.filename or "(nombre cifrado: descárguelo)", r.file_id[:12] + "…", r.owner, size,
                time.strftime("%Y-%m-%d %H:%M", time.localtime(r.created_at)), shared or "(nadie)"))
        self.log.append("ok", f"{len(rows)} archivo(s) accesibles")

    def act_keygen(self) -> None:
        if self.svc.ks.exists() and not messagebox.askyesno(
                "Reemplazar claves",
                f"Ya existe un keystore para '{self.svc.user}'.\n\nSi lo reemplaza perderá el acceso a sus archivos "
                "y el servidor no aceptará la nueva clave para este usuario.\n\n¿Continuar?",
                icon="warning", parent=self.root):
            return
        data = NewIdentityDialog(self.root, self.svc.user).show()
        if data:
            self._keygen(data, overwrite=True)

    def _keygen(self, data: dict, overwrite: bool) -> None:
        def done(fp: str) -> None:
            self.log.append("ok", f"Huella de su clave pública: {format_fingerprint(fp)}")
            self.log.append("info", "Siguiente paso: «Registrar» y luego «Iniciar sesión».")

        self.run_task(f"Generar claves RSA-{data['bits']} y keystore ({fmt_int(data['iterations'])} iteraciones)",
                      lambda: self.svc.keygen(data["passphrase"], data["bits"], data["iterations"], overwrite),
                      on_done=done)

    def act_register(self) -> None:
        def done(fp: str) -> None:
            messagebox.showinfo("Registrado", f"El servidor guardó SOLO su clave pública.\n\nHuella:\n"
                                f"{format_fingerprint(fp)}", parent=self.root)
        self.run_task("Registrar clave pública (prueba de posesión)", self.svc.register, on_done=done)

    def act_login(self) -> None:
        def done(exp: float) -> None:
            self.log.append("ok", f"Sesión iniciada hasta {time.strftime('%H:%M:%S', time.localtime(exp))}")
            self.root.after(100, self.refresh_files)
        self.run_task("Iniciar sesión (challenge-response RSA-PSS)", self.svc.login, on_done=done)

    def act_upload(self) -> None:
        path = filedialog.askopenfilename(parent=self.root, title="Elegir archivo para cifrar y subir")
        if not path:
            return
        self.run_task("Consultar directorio de usuarios", self.svc.registered_users,
                      on_done=lambda users: self._upload_choose(Path(path), users), quiet=True)

    def _upload_choose(self, path: Path, users: list[str]) -> None:
        others = [u for u in users if u != self.svc.user]
        chosen = ChooseUsersDialog(self.root, "Compartir al subir",
                                   f"¿Con quién compartir «{path.name}»? (puede no elegir a nadie)",
                                   others, multi=True).show()
        if chosen is None:
            return
        self.root.after(10, lambda: self.run_task(
            f"Subir «{path.name}»" + (f" compartido con {', '.join(chosen)}" if chosen else ""),
            lambda: self.svc.upload(path, chosen), on_done=self._uploaded))

    def _uploaded(self, file_id: str) -> None:
        self.log.append("ok", f"Archivo subido: file_id {file_id}")
        self.root.after(100, self.refresh_files)

    def act_download(self) -> None:
        row = self._selected()
        if row:
            self.run_task(f"Descargar {row.file_id[:12]}…", lambda: self.svc.download(row.file_id),
                          on_done=self._save_opened)

    def _save_opened(self, opened: OpenedFile) -> None:
        name = safe_filename(opened.filename, f"{opened.file_id}.bin")
        target = filedialog.asksaveasfilename(parent=self.root, title="Guardar archivo descifrado",
                                              initialfile=name)
        if not target:
            self.log.append("info", "Guardado cancelado (los datos descifrados se descartan)")
            return
        target_path = keep_original_extension(Path(target), opened.filename)
        path = self.svc.save(opened, target_path, force=True, as_file=True)
        self.log.append("ok", f"'{opened.filename}' verificado y guardado en {path}")
        self.refresh_files()

    def act_share(self) -> None:
        row = self._selected()
        if not row:
            return
        if not row.is_owner:
            messagebox.showinfo("Compartir", "Solo el dueño puede compartir el archivo.", parent=self.root)
            return
        already = set(row.recipients or [])
        self.run_task("Consultar directorio de usuarios", self.svc.registered_users,
                      on_done=lambda users: self._share_choose(row, [u for u in users if u not in already]),
                      quiet=True)

    def _share_choose(self, row: FileRow, candidates: list[str]) -> None:
        chosen = ChooseUsersDialog(self.root, "Compartir", f"Compartir «{row.filename or row.file_id[:12]}» con:",
                                   candidates, multi=False).show()
        if chosen:
            user = chosen[0]
            self.root.after(10, lambda: self.run_task(
                f"Compartir con {user} (re-envoltura local de la clave de sesión)",
                lambda: self.svc.share(row.file_id, user), on_done=lambda _r: self.refresh_files()))

    def act_verify(self) -> None:
        row = self._selected()
        if not row:
            return

        def done(res: dict) -> None:
            meta = res["meta"]
            messagebox.showinfo(
                "Verificación correcta",
                f"✓ Firma RSA-PSS válida del dueño '{res['owner']}'\n"
                f"   huella {format_fingerprint(res['owner_fp'])[:24]}…\n"
                f"✓ Metadatos autenticados: fecha {meta['timestamp']}, {meta['size']} bytes\n"
                f"✓ Tag AES-GCM válido: el contenido está íntegro", parent=self.root)
        self.run_task(f"Verificar {row.file_id[:12]}… (firma + tag GCM)", lambda: self.svc.verify(row.file_id),
                      on_done=done)

    def act_fingerprint(self) -> None:
        FingerprintDialog(self.root, self).show()

    def act_lock(self) -> None:
        self.svc.close()
        self.log.append("info", "Clave privada descartada de la memoria; se pedirá la passphrase al necesitarla")
        self.update_header()

    def act_new_window(self) -> None:
        cmd = [sys.executable, str(ROOT_DIR / "grupof_gui.py"), "--server", self.server]
        if self.custom_home:
            cmd += ["--home", str(self.home)]
        subprocess.Popen(cmd, cwd=str(ROOT_DIR))
        self.log.append("info", "Se abrió otra ventana (proceso independiente): elija otro usuario allí")

    def act_switch_user(self) -> None:
        if self.busy:
            return
        if self.svc:
            self.svc.close()
        self.svc = None
        self.buttons = []
        for attr in ("progress", "log"):
            if hasattr(self, attr):
                delattr(self, attr)
        self.root.title("Zero-Trust Storage - Grupo F")
        self.show_start()

    def on_close(self) -> None:
        if self.svc:
            self.svc.close()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cliente gráfico Zero-Trust (Grupo F)")
    parser.add_argument("--user", default=os.environ.get("GRUPOF_USER"))
    parser.add_argument("--server", default=os.environ.get("GRUPOF_SERVER", DEFAULT_SERVER))
    parser.add_argument("--home", default=os.environ.get("GRUPOF_HOME"))
    args = parser.parse_args(argv)
    if os.name == "nt":
        try:  # textos nítidos en pantallas con escalado
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    root = tk.Tk()
    home = Path(args.home) if args.home else None
    app = App(root, args.server, home, custom_home=bool(args.home))
    if args.user and Keystore(args.user.lower(), app.home).exists():
        app.open_user(args.user.lower())
    else:
        app.show_start()
        if args.user:
            app.start_user.set(args.user.lower())
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
