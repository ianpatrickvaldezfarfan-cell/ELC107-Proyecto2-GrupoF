"""Deja el entorno limpio antes de grabar o presentar la demo.

Borra (previa confirmación):
  * la carpeta de datos del servidor (por defecto server_data/: base SQLite + blobs cifrados);
  * los keystores locales de los usuarios indicados (por defecto alice, bob y carol);
  * opcionalmente la carpeta descargas/ (--descargas).

Seguridad del propio script:
  * se niega a continuar si el servidor sigue en ejecución (además, Windows no
    permite borrar la base de datos mientras está abierta);
  * solo borra una carpeta de datos que realmente parezca del servidor
    (contiene metadata.sqlite3 o blobs/);
  * solo borra keystores con nombres de usuario válidos (sin rutas como '..');
  * muestra qué hay antes de borrar y pide confirmación (salvo --yes);
  * --dry-run muestra lo que haría sin borrar nada.

Uso:
    python scripts\\reset_demo.py
    python scripts\\reset_demo.py --users alice,bob,carol,alice_7d42,bob_7d42,carol_7d42
    python scripts\\reset_demo.py --dry-run
    python scripts\\reset_demo.py --solo-keystores --users dave
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sqlite3
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
USERNAME_RE = re.compile(r"^[a-z0-9_-]{3,32}$")
DEFAULT_USERS = "alice,bob,carol"


def default_home() -> Path:
    env = os.environ.get("GRUPOF_HOME")
    return Path(env) if env else Path.home() / ".grupof"


def server_running(url: str) -> bool:
    try:
        with urllib.request.urlopen(url.rstrip("/") + "/api/health", timeout=1.5) as r:
            return r.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def looks_like_server_data(path: Path) -> bool:
    return path.is_dir() and ((path / "metadata.sqlite3").exists() or (path / "blobs").is_dir())


def describe_server_data(path: Path) -> list[str]:
    lines = []
    db = path / "metadata.sqlite3"
    if db.exists():
        try:
            con = sqlite3.connect(f"file:{db.as_posix()}?mode=ro", uri=True)
            users = [r[0] for r in con.execute("SELECT username FROM users ORDER BY username")]
            files = con.execute("SELECT owner, COUNT(*) FROM files GROUP BY owner ORDER BY owner").fetchall()
            con.close()
            lines.append(f"usuarios registrados ({len(users)}): {', '.join(users) or '(ninguno)'}")
            lines.append("archivos por dueño: " + (", ".join(f"{o}={n}" for o, n in files) or "(ninguno)"))
        except sqlite3.Error as exc:
            lines.append(f"(no se pudo leer la base: {exc})")
    blobs = list((path / "blobs").glob("*.bin")) if (path / "blobs").is_dir() else []
    size = sum(b.stat().st_size for b in blobs)
    lines.append(f"blobs cifrados: {len(blobs)} ({size / 1024:.1f} KB)")
    return lines


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="Limpia server_data y keystores de demostración")
    p.add_argument("--data-dir", type=Path, default=ROOT / "server_data", help="carpeta de datos del servidor")
    p.add_argument("--home", type=Path, default=None, help="carpeta base de keystores (GRUPOF_HOME o ~/.grupof)")
    p.add_argument("--users", default=DEFAULT_USERS, help=f"keystores a borrar, separados por comas ({DEFAULT_USERS})")
    p.add_argument("--server", default=os.environ.get("GRUPOF_SERVER", "http://127.0.0.1:5000"),
                   help="URL del servidor, para comprobar que esté detenido")
    p.add_argument("--solo-keystores", action="store_true", help="no tocar los datos del servidor")
    p.add_argument("--solo-servidor", action="store_true", help="no tocar los keystores")
    p.add_argument("--descargas", action="store_true", help="borrar también la carpeta descargas/ del proyecto")
    p.add_argument("--dry-run", action="store_true", help="mostrar lo que se borraría, sin borrar")
    p.add_argument("--yes", action="store_true", help="no pedir confirmación")
    args = p.parse_args(argv)

    home = args.home or default_home()
    users = [u.strip().lower() for u in args.users.split(",") if u.strip()]
    bad = [u for u in users if not USERNAME_RE.match(u)]
    if bad:
        print(f"Nombres de usuario inválidos (no se borra nada): {', '.join(bad)}", file=sys.stderr)
        return 2

    targets: list[tuple[str, Path]] = []
    print("=" * 70)
    print(" LIMPIEZA DEL ENTORNO DE DEMOSTRACIÓN")
    print("=" * 70)

    if not args.solo_keystores:
        data = args.data_dir.resolve()
        if not data.exists():
            print(f"Datos del servidor: {data} (no existe, nada que borrar)")
        elif not looks_like_server_data(data):
            print(f"ABORTADO: {data} no parece una carpeta de datos del servidor "
                  "(no contiene metadata.sqlite3 ni blobs/).", file=sys.stderr)
            return 2
        else:
            if server_running(args.server) and not args.dry_run:
                print(f"ABORTADO: hay un servidor respondiendo en {args.server}.\n"
                      "Deténgalo (Ctrl+C en su terminal) y vuelva a ejecutar este script.", file=sys.stderr)
                return 1
            print(f"Datos del servidor: {data}")
            for line in describe_server_data(data):
                print(f"   - {line}")
            targets.append(("datos del servidor", data))

    if not args.solo_servidor:
        print(f"Keystores en: {home}")
        for u in users:
            d = (home / u).resolve()
            if d.parent != home.resolve():
                continue
            if (d / "private_key.enc.json").exists() or (d / "public_key.pem").exists():
                print(f"   - {u}: se borrará {d}")
                targets.append((f"keystore de {u}", d))
            else:
                print(f"   - {u}: no tiene keystore en esta PC")

    if args.descargas:
        dl = (ROOT / "descargas").resolve()
        if dl.is_dir():
            print(f"Descargas: {dl}")
            targets.append(("descargas", dl))

    if not targets:
        print("\nNada que borrar: el entorno ya está limpio.")
        return 0
    if args.dry_run:
        print(f"\n(--dry-run) Se borrarían {len(targets)} elemento(s). No se borró nada.")
        return 0
    if not args.yes:
        answer = input(f"\n¿Borrar definitivamente {len(targets)} elemento(s)? Escriba 'si' para confirmar: ")
        if answer.strip().lower() not in ("si", "sí", "s"):
            print("Cancelado. No se borró nada.")
            return 0

    errors = 0
    for label, path in targets:
        try:
            shutil.rmtree(path)
            print(f"[OK] borrado: {label} ({path})")
        except PermissionError:
            errors += 1
            print(f"[ERROR] no se pudo borrar {path}: archivo en uso (¿el servidor o la GUI siguen abiertos?)",
                  file=sys.stderr)
        except OSError as exc:
            errors += 1
            print(f"[ERROR] no se pudo borrar {path}: {exc}", file=sys.stderr)
    if errors:
        return 1
    print("\nEntorno limpio. Siguiente paso: iniciar el servidor (python servidor.py) y crear los usuarios.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
