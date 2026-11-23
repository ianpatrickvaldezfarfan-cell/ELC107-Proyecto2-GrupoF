"""Vista del "servidor comprometido": qué ve un atacante que roba TODO el disco del servidor.

Uso como script (lee directamente la carpeta de datos, como haría un atacante):
    python -m src.server.compromised_view --data-dir server_data

También se expone por HTTP en GET /api/admin/compromised-view (solo para la demo).

Entropía de Shannon (bits por byte):
    H(X) = − Σ_{b=0}^{255} p_b · log2(p_b),     p_b = frecuencia relativa del byte b
Un texto en español ronda 4-5 bits/byte; un buen cifrado se acerca al máximo de
8 bits/byte (bytes indistinguibles de aleatorios). Con muestras pequeñas el valor
máximo alcanzable es menor (con n bytes, H ≤ log2(n)), por eso se muestra también
el máximo posible para esa longitud.
"""

from __future__ import annotations

import argparse
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from .storage import Storage


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def max_entropy_for_length(n: int) -> float:
    return min(8.0, math.log2(n)) if n > 0 else 0.0


def printable_ratio(data: bytes) -> float:
    """Proporción de bytes ASCII imprimibles (un texto claro estaría cerca de 1.0)."""
    if not data:
        return 0.0
    return sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)


def _scan_for_secrets(storage: Storage) -> list[str]:
    """Busca marcadores de material secreto en TODOS los bytes que el servidor tiene."""
    markers = [b"PRIVATE KEY", b"GRPF\x01\x02"]  # PEM privado o TLV de clave privada
    found = []
    paths = [storage.db_path] + sorted(storage.blob_dir.glob("*.bin"))
    for p in paths:
        data = p.read_bytes()
        for m in markers:
            if m in data:
                found.append(f"{p.name}: contiene {m!r}")
    return found


def compromised_report(storage: Storage, preview_bytes: int = 32) -> dict[str, Any]:
    files = []
    keys_by_file: dict[str, list[dict[str, Any]]] = {}
    for file_id, recipient, wrapped in storage.all_wrapped_keys():
        keys_by_file.setdefault(file_id, []).append({
            "recipient": recipient,
            "wrapped_key_hex": wrapped[:preview_bytes].hex() + "...",
            "wrapped_key_len": len(wrapped),
        })
    for rec in storage.all_files():
        blob = storage.read_blob(rec.file_id)
        files.append({
            "file_id": rec.file_id,
            "owner": rec.owner,
            "visible_metadata_aad": rec.aad.decode("utf-8", "replace"),
            "ciphertext_len": len(blob),
            "ciphertext_preview_hex": blob[:preview_bytes].hex(),
            "entropy_bits_per_byte": round(shannon_entropy(blob), 4),
            "max_entropy_for_len": round(max_entropy_for_length(len(blob)), 4),
            "printable_ratio": round(printable_ratio(blob), 4),
            "nonce_hex": rec.nonce.hex(),
            "tag_hex": rec.tag.hex(),
            "signature_preview_hex": rec.signature[:preview_bytes].hex() + "...",
            "wrapped_keys": keys_by_file.get(rec.file_id, []),
        })
    return {
        "warning": "Vista de un atacante con acceso total al servidor",
        "users": [{"username": u.username, "fingerprint": u.fingerprint} for u in storage.list_users()],
        "files": files,
        "secret_material_found": _scan_for_secrets(storage),
        "server_has": ["claves públicas", "ciphertext", "nonce", "tag", "AAD (metadatos en claro)",
                       "firmas", "claves de sesión ENVUELTAS con RSA-OAEP", "hashes de tokens"],
        "server_never_has": ["claves privadas", "claves de sesión en claro", "texto claro",
                             "passphrases", "tokens de sesión en claro"],
        "known_leak": "La AAD (nombre de archivo, dueño, fecha, tamaño) es visible: está autenticada, no cifrada.",
    }


def print_report(report: dict[str, Any], out=sys.stdout) -> None:
    w = out.write
    w("=" * 78 + "\n")
    w("  VISTA DEL SERVIDOR COMPROMETIDO (todo lo que un atacante puede leer)\n")
    w("=" * 78 + "\n")
    w(f"Usuarios registrados: {', '.join(u['username'] for u in report['users']) or '(ninguno)'}\n")
    for f in report["files"]:
        w("-" * 78 + "\n")
        w(f"Archivo {f['file_id']}  (dueño: {f['owner']})\n")
        w(f"  Metadatos visibles (AAD): {f['visible_metadata_aad']}\n")
        w(f"  Ciphertext: {f['ciphertext_len']} bytes, inicio: {f['ciphertext_preview_hex']}\n")
        w(f"  Entropía: {f['entropy_bits_per_byte']:.4f} bits/byte "
          f"(máx. posible {f['max_entropy_for_len']:.4f}); imprimibles: {f['printable_ratio']:.1%}\n")
        for k in f["wrapped_keys"]:
            w(f"  Clave envuelta para {k['recipient']} ({k['wrapped_key_len']} B): {k['wrapped_key_hex']}\n")
    w("-" * 78 + "\n")
    found = report["secret_material_found"]
    w("Material secreto encontrado en el servidor: " + ("; ".join(found) if found else "NINGUNO") + "\n")
    w("El servidor NUNCA tiene: " + ", ".join(report["server_never_has"]) + "\n")
    w("Fuga conocida: " + report["known_leak"] + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Muestra lo que ve un atacante que compromete el servidor.")
    parser.add_argument("--data-dir", default="server_data", type=Path)
    args = parser.parse_args(argv)
    if not (args.data_dir / "metadata.sqlite3").exists():
        print(f"No hay datos del servidor en {args.data_dir}", file=sys.stderr)
        return 1
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print_report(compromised_report(Storage(args.data_dir)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
