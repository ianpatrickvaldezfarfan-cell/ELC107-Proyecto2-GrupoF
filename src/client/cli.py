"""Interfaz de línea de comandos del cliente Zero-Trust (Grupo F).

Uso:
    python grupof.py --user alice keygen [--bits 2048|3072] [--kdf-iters N]
    python grupof.py --user alice register
    python grupof.py --user alice login
    python grupof.py --user alice upload informe.txt [--share-with bob,carol]
    python grupof.py --user alice list
    python grupof.py --user alice share <file_id> --with bob
    python grupof.py --user bob   download <file_id> [--out carpeta]
    python grupof.py --user bob   verify <file_id> [--signature-only]
    python grupof.py --user bob   fingerprint [alice] [--trust] [--expect HUELLA]
(equivale a `python -m src.client.cli ...`)

Opciones globales (antes o después del comando):
    --user U       usuario local (o variable GRUPOF_USER)
    --server URL   servidor (o GRUPOF_SERVER; por defecto http://127.0.0.1:5000)
    --home DIR     carpeta base de keystores (o GRUPOF_HOME; por defecto ~/.grupof)
    --no-color     sin colores

Passphrase: se pide de forma interactiva (sin eco). SOLO para demostraciones
automatizadas puede tomarse de la variable de entorno GRUPOF_PASSPHRASE.

Códigos de salida: 0 = OK, 1 = error, 2 = uso incorrecto, 3 = FALLO DE SEGURIDAD
(firma/tag inválidos, clave no autorizada, huella cambiada).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time
from pathlib import Path

from ..crypto.encoding import format_fingerprint
from ..crypto.kdf import DEFAULT_ITERATIONS, OWASP_RECOMMENDED_ITERATIONS, default_iterations
from .api_client import ApiClient, ApiError, RequestsTransport
from .envelope import PackageError
from .keystore import Keystore, KeystoreError
from .service import ClientError, ClientService, Reporter, TrustError, fmt_int

DEFAULT_SERVER = "http://127.0.0.1:5000"
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_SECURITY = 0, 1, 2, 3
MIN_PASSPHRASE = 8


# ---------------------------------------------------------------------------
# Colores ANSI (en Windows se habilita el modo de terminal virtual)
# ---------------------------------------------------------------------------
class Style:
    enabled = False
    CODES = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "magenta": "35", "cyan": "36",
             "bold": "1", "dim": "2"}

    @classmethod
    def setup(cls, no_color: bool) -> None:
        if no_color or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
            cls.enabled = False
            return
        cls.enabled = True
        if os.name == "nt":
            try:
                import ctypes
                k32 = ctypes.windll.kernel32
                handle = k32.GetStdHandle(-11)
                mode = ctypes.c_uint32()
                if k32.GetConsoleMode(handle, ctypes.byref(mode)):
                    k32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            except Exception:
                cls.enabled = False

    @classmethod
    def c(cls, text: str, *styles: str) -> str:
        if not cls.enabled:
            return text
        return "".join(f"\033[{cls.CODES[s]}m" for s in styles) + text + "\033[0m"


def out(msg: str = "") -> None:
    print(msg, flush=True)


def ok(msg: str) -> None:
    out(Style.c("[OK] ", "green", "bold") + msg)


def err(msg: str) -> None:
    print(Style.c("[ERROR] ", "red", "bold") + msg, file=sys.stderr, flush=True)


def title(msg: str) -> None:
    out(Style.c(f"== {msg} ==", "cyan", "bold"))


class CliReporter(Reporter):
    def step(self, msg: str) -> None:
        out(Style.c("  -> ", "blue") + msg)

    def info(self, msg: str) -> None:
        out(Style.c("  i  ", "cyan") + msg)

    def ok(self, msg: str) -> None:
        out(Style.c("  ok ", "green") + msg)

    def warn(self, msg: str) -> None:
        out(Style.c("  !  ", "yellow", "bold") + Style.c(msg, "yellow"))


# ---------------------------------------------------------------------------
# Entrada de passphrase y confirmaciones
# ---------------------------------------------------------------------------
def _passphrase_from_env() -> bytearray | None:
    value = os.environ.get("GRUPOF_PASSPHRASE")
    if value is None:
        return None
    out(Style.c("  !  passphrase tomada de GRUPOF_PASSPHRASE (solo para demostración)", "yellow"))
    return bytearray(value.encode("utf-8"))


def ask_passphrase(prompt: str) -> bytearray:
    env = _passphrase_from_env()
    if env is not None:
        return env
    # getpass devuelve un str inmutable: se convierte a bytearray y se descarta la referencia
    value = getpass.getpass(prompt)
    buf = bytearray(value.encode("utf-8"))
    del value
    return buf


def ask_new_passphrase(username: str) -> bytearray:
    env = _passphrase_from_env()
    if env is not None:
        if len(env) < MIN_PASSPHRASE:
            raise ClientError(f"la passphrase debe tener al menos {MIN_PASSPHRASE} caracteres")
        return env
    first = ask_passphrase(f"Nueva passphrase para '{username}' (mín. {MIN_PASSPHRASE} caracteres): ")
    second = ask_passphrase("Repita la passphrase: ")
    try:
        if first != second:
            raise ClientError("las passphrases no coinciden")
        if len(first) < MIN_PASSPHRASE:
            raise ClientError(f"la passphrase debe tener al menos {MIN_PASSPHRASE} caracteres")
    except ClientError:
        first[:] = bytes(len(first))
        raise
    finally:
        second[:] = bytes(len(second))
    return first


def ask_confirm(question: str) -> bool:
    out(Style.c(question, "yellow"))
    if not sys.stdin.isatty():
        out(Style.c("  (entrada no interactiva: se asume NO; use --yes si ya verificó la huella)", "dim"))
        return False
    return input("  [s/N]: ").strip().lower() in ("s", "si", "sí", "y", "yes")


# ---------------------------------------------------------------------------
# Construcción del servicio
# ---------------------------------------------------------------------------
def make_transport(server: str):
    """Fábrica del transporte HTTP (los tests la reemplazan por el test client de Flask)."""
    return RequestsTransport(server)


def build_service(args) -> ClientService:
    if not args.user:
        raise ClientError("indique el usuario con --user (o la variable GRUPOF_USER)")
    ks = Keystore(args.user, Path(args.home) if args.home else None)
    api = ApiClient(make_transport(args.server))
    return ClientService(ks, api, args.server, ask_passphrase, ask_confirm, CliReporter())


def _fmt_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return str(n)


def _resolve_file_id(svc: ClientService, ref: str) -> str:
    """Permite usar un prefijo único del file_id (mín. 6 caracteres) en lugar de los 32."""
    ref = ref.strip().lower()
    if len(ref) == 32:
        return ref
    if len(ref) < 6:
        raise ClientError("indique al menos 6 caracteres del file_id")
    matches = [r.file_id for r in svc.list_files() if r.file_id.startswith(ref)]
    if len(matches) != 1:
        raise ClientError("ningún archivo coincide con ese prefijo" if not matches else "prefijo ambiguo")
    return matches[0]


# ---------------------------------------------------------------------------
# Comandos
# ---------------------------------------------------------------------------
def cmd_keygen(svc: ClientService, args) -> int:
    title(f"keygen: creando identidad de '{svc.user}'")
    iterations = args.kdf_iters or default_iterations()
    if iterations < OWASP_RECOMMENDED_ITERATIONS:
        svc.r.info(f"PBKDF2 con {fmt_int(iterations)} iteraciones (OWASP recomienda "
                   f"{fmt_int(OWASP_RECOMMENDED_ITERATIONS)}; reducido por el costo de Python puro)")
    if args.kdf_iters and args.kdf_iters < DEFAULT_ITERATIONS:
        svc.r.warn(f"{fmt_int(args.kdf_iters)} iteraciones es menos que el valor por defecto "
                   f"({fmt_int(DEFAULT_ITERATIONS)}): úselo SOLO para demostraciones")
    passphrase = ask_new_passphrase(svc.user)
    fp = svc.keygen(passphrase, bits=args.bits, iterations=iterations, overwrite=args.force)
    ok(f"Identidad creada. Huella de su clave pública (compártala fuera de banda):")
    out("     " + Style.c(format_fingerprint(fp), "bold"))
    out(f"  Siguiente paso: python grupof.py --user {svc.user} register")
    return EXIT_OK


def cmd_register(svc: ClientService, args) -> int:
    title(f"register: registrando '{svc.user}' en {args.server}")
    fp = svc.register()
    ok("Usuario registrado. El servidor guardó SOLO su clave pública, con huella:")
    out("     " + Style.c(format_fingerprint(fp), "bold"))
    return EXIT_OK


def cmd_login(svc: ClientService, args) -> int:
    title(f"login: autenticación challenge-response de '{svc.user}'")
    expires = svc.login()
    ok("Sesión iniciada sin enviar contraseñas (firma RSA-PSS del challenge).")
    out(f"  Token guardado en el keystore; válido hasta {time.strftime('%H:%M:%S', time.localtime(expires))}.")
    out("  Los comandos que no necesitan la clave privada (p. ej. 'list') ya no pedirán passphrase.")
    return EXIT_OK


def cmd_upload(svc: ClientService, args) -> int:
    share_with = [s.strip() for s in (args.share_with or "").split(",") if s.strip()]
    title(f"upload: {args.file}")
    file_id = svc.upload(Path(args.file), share_with, assume_yes=args.yes)
    ok("Archivo subido. El servidor solo recibió bytes cifrados (el nombre real también va cifrado).")
    out("  file_id: " + Style.c(file_id, "bold"))
    return EXIT_OK


def cmd_download(svc: ClientService, args) -> int:
    file_id = _resolve_file_id(svc, args.file_id)
    title(f"download: {file_id}")
    opened = svc.download(file_id)
    target = svc.save(opened, Path(args.out) if args.out else None, force=args.force)
    ok(f"Firma válida (dueño: {opened.owner}), tag GCM válido. Archivo descifrado: "
       f"'{opened.filename}' ({_fmt_size(len(opened.data))})")
    out(f"  Guardado en: {target}")
    return EXIT_OK


def cmd_share(svc: ClientService, args) -> int:
    file_id = _resolve_file_id(svc, args.file_id)
    title(f"share: {file_id} -> {args.recipient}")
    recipients = svc.share(file_id, args.recipient, assume_yes=args.yes)
    ok(f"Compartido. Destinatarios con acceso: {', '.join(recipients)}")
    out("  La clave de sesión se re-envolvió localmente; el servidor nunca la vio.")
    return EXIT_OK


def cmd_list(svc: ClientService, args) -> int:
    title(f"list: archivos accesibles para '{svc.user}'")
    rows = svc.list_files()
    if not rows:
        out("  (no hay archivos)")
        return EXIT_OK
    out(Style.c(f"  {'FILE_ID':<32}  {'DUEÑO':<10} {'TAMAÑO':>9}  {'FECHA':<16}  NOMBRE / COMPARTIDO CON", "bold"))
    for r in rows:
        name = r.filename or Style.c("(nombre cifrado: descárguelo)", "dim")
        date = time.strftime("%Y-%m-%d %H:%M", time.localtime(r.created_at))
        shared = f"  [con: {', '.join(x for x in r.recipients if x != svc.user) or '-'}]" if r.is_owner else ""
        out(f"  {r.file_id:<32}  {r.owner:<10} {_fmt_size(r.size):>9}  {date:<16}  {name}{shared}")
    return EXIT_OK


def cmd_verify(svc: ClientService, args) -> int:
    file_id = _resolve_file_id(svc, args.file_id)
    title(f"verify: {file_id}")
    res = svc.verify(file_id, signature_only=args.signature_only)
    ok(f"Firma RSA-PSS válida del dueño '{res['owner']}' ({format_fingerprint(res['owner_fp'])[:19]}...)")
    ok(f"Metadatos autenticados: {res['meta']}")
    if res["gcm_tag"]:
        ok("Clave de sesión desenvuelta y tag AES-GCM válido: el contenido está íntegro")
    else:
        out("  (tag GCM no comprobado: --signature-only)")
    return EXIT_OK


def cmd_fingerprint(svc: ClientService, args) -> int:
    if args.trust or args.expect:
        if not args.username:
            raise ClientError("indique el usuario cuya huella desea confiar")
        fp = svc.trust(args.username, args.expect)
        ok(f"Clave de '{args.username}' marcada como verificada fuera de banda:")
        out("     " + Style.c(format_fingerprint(fp), "bold"))
        return EXIT_OK
    info = svc.fingerprint_info(args.username)
    title(f"fingerprint: {info['username']}")
    out("  " + Style.c(format_fingerprint(info["fingerprint"]), "bold"))
    out(f"  Fuente: {info['source']}")
    if "pinned" in info:
        if info["pinned"] is None:
            out(Style.c("  Aún no fijada en sus contactos. Compárela fuera de banda y use --trust.", "yellow"))
        elif info["matches_pinned"]:
            state = "verificada fuera de banda" if info["verified_out_of_band"] else "fijada por TOFU (sin verificar)"
            ok(f"Coincide con la huella fijada ({state})")
        else:
            err("¡NO coincide con la huella fijada! Posible ataque MITM.")
            return EXIT_SECURITY
    return EXIT_OK


COMMANDS = {
    "keygen": cmd_keygen, "register": cmd_register, "login": cmd_login, "upload": cmd_upload,
    "download": cmd_download, "share": cmd_share, "list": cmd_list, "verify": cmd_verify,
    "fingerprint": cmd_fingerprint,
}


def build_parser() -> argparse.ArgumentParser:
    def add_globals(p: argparse.ArgumentParser, suppress: bool) -> None:
        d = (lambda v: argparse.SUPPRESS) if suppress else (lambda v: v)
        p.add_argument("--user", default=d(os.environ.get("GRUPOF_USER")), help="usuario local (GRUPOF_USER)")
        p.add_argument("--server", default=d(os.environ.get("GRUPOF_SERVER", DEFAULT_SERVER)),
                       help=f"URL del servidor (GRUPOF_SERVER, por defecto {DEFAULT_SERVER})")
        p.add_argument("--home", default=d(os.environ.get("GRUPOF_HOME")),
                       help="carpeta base de keystores (GRUPOF_HOME, por defecto ~/.grupof)")
        p.add_argument("--no-color", action="store_true", default=d(False), help="desactiva los colores")

    parser = argparse.ArgumentParser(prog="grupof", description="Cliente de almacenamiento Zero-Trust (Grupo F)")
    add_globals(parser, suppress=False)
    common = argparse.ArgumentParser(add_help=False)
    add_globals(common, suppress=True)
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMANDO")

    p = sub.add_parser("keygen", parents=[common], help="genera el par RSA y el keystore cifrado")
    p.add_argument("--bits", type=int, choices=(2048, 3072), default=2048)
    p.add_argument("--kdf-iters", type=int, default=None,
                   help=f"iteraciones de PBKDF2 (por defecto {fmt_int(DEFAULT_ITERATIONS)})")
    p.add_argument("--force", action="store_true", help="reemplaza un keystore existente")

    sub.add_parser("register", parents=[common], help="registra la clave pública en el servidor")
    sub.add_parser("login", parents=[common], help="inicia sesión (challenge-response) y guarda el token")

    p = sub.add_parser("upload", parents=[common], help="cifra y sube un archivo")
    p.add_argument("file")
    p.add_argument("--share-with", default="", help="usuarios separados por comas")
    p.add_argument("--yes", action="store_true", help="no preguntar por huellas nuevas (menos seguro)")

    p = sub.add_parser("download", parents=[common], help="descarga, verifica y descifra")
    p.add_argument("file_id")
    p.add_argument("--out", default=None, help="archivo o carpeta de destino")
    p.add_argument("--force", action="store_true", help="sobrescribe si existe")

    p = sub.add_parser("share", parents=[common], help="comparte un archivo propio con otro usuario")
    p.add_argument("file_id")
    p.add_argument("--with", dest="recipient", required=True)
    p.add_argument("--yes", action="store_true", help="no preguntar por la huella (menos seguro)")

    sub.add_parser("list", parents=[common], help="lista los archivos accesibles (no pide passphrase)")

    p = sub.add_parser("verify", parents=[common], help="verifica firma y tag GCM sin guardar el archivo")
    p.add_argument("file_id")
    p.add_argument("--signature-only", action="store_true", help="solo la firma (no pide passphrase)")

    p = sub.add_parser("fingerprint", parents=[common], help="muestra/verifica huellas de claves públicas")
    p.add_argument("username", nargs="?", default=None)
    p.add_argument("--trust", action="store_true", help="marca la clave como verificada fuera de banda")
    p.add_argument("--expect", default=None, help="huella esperada (se compara antes de confiar)")
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    Style.setup(args.no_color)
    try:
        svc = build_service(args)
        try:
            return COMMANDS[args.command](svc, args)
        finally:
            svc.close()
    except (PackageError, TrustError) as exc:
        err(Style.c("FALLO DE SEGURIDAD", "bold") + f" - {exc}")
        err("Operación abortada: no se entregó ningún dato.")
        return EXIT_SECURITY
    except ApiError as exc:
        err(f"servidor: {exc.message}" if exc.status else exc.message)
        return EXIT_ERROR
    except (ClientError, KeystoreError) as exc:
        err(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        err("cancelado por el usuario")
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
