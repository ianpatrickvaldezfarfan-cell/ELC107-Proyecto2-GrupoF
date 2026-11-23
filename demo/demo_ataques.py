"""Demo de ataques para la defensa en vivo (ELC107 - Proyecto 2 - Grupo F).

Prepara tres usuarios (alice, bob, carol), alice sube un informe de ~50 KB y lo
comparte con bob. Luego ejecuta los ataques y muestra cómo cada capa los detiene:

  a) alterar 1 bit del ciphertext           -> firma PSS y tag GCM fallan
  b) alterar la AAD (metadatos)              -> firma PSS y tag GCM fallan
  c) firma falsificada / con otra clave      -> rechazada
  d) usuario no autorizado intenta descifrar -> no puede desenvolver la clave (OAEP)
  e) replay del challenge de login           -> rechazado (nonce de un solo uso)
  f) vista del servidor comprometido         -> solo bytes ilegibles (entropía)
  g) [extra] sustitución de clave pública en el directorio (MITM) -> detectada

Uso:
    python demo\\demo_ataques.py                 # servidor en el mismo proceso (no hace falta iniciarlo)
    python demo\\demo_ataques.py --pausa         # espera ENTER entre ataques (para presentar)
    python demo\\demo_ataques.py --solo a,e,f    # solo algunos ataques
    python demo\\demo_ataques.py --server http://127.0.0.1:5000   # contra el servidor real

Las cuentas de la demo usan PBKDF2 con 10.000 iteraciones SOLO PARA DEMOSTRACIÓN
(el valor por defecto del sistema es 100.000; OWASP recomienda 600.000).
"""

from __future__ import annotations

import argparse
import copy
import json
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src import protocol as P  # noqa: E402
from src.client import envelope as E  # noqa: E402
from src.client.api_client import ApiClient, ApiError, InProcessTransport, RequestsTransport  # noqa: E402
from src.client.cli import Style  # noqa: E402
from src.client.keystore import Keystore  # noqa: E402
from src.client.service import ClientService, Reporter, TrustError  # noqa: E402
from src.crypto.encoding import fingerprint, format_fingerprint, public_key_to_pem  # noqa: E402
from src.crypto.errors import InvalidTag  # noqa: E402
from src.crypto.gcm import AESGCM, aes_gcm_encrypt  # noqa: E402
from src.crypto.pss import pss_sign, pss_sign_digest  # noqa: E402
from src.crypto.rsa_core import generate_keypair  # noqa: E402
from src.sample_data import sample_text  # noqa: E402
from src.server.compromised_view import expected_random_entropy, printable_ratio, shannon_entropy  # noqa: E402

DEMO_ITERS = 10_000
FILENAME = "informe_confidencial.txt"


# ---------------------------------------------------------------------------
# Salida
# ---------------------------------------------------------------------------
def c(text, *styles):
    return Style.c(text, *styles)


def banner(letter: str, text: str) -> None:
    print()
    print(c("=" * 78, "magenta"))
    print(c(f" ATAQUE {letter}) {text}", "magenta", "bold"))
    print(c("=" * 78, "magenta"))


def say(msg: str = "") -> None:
    print("  " + msg, flush=True)


def attacker(msg: str) -> None:
    print(c("  [ATACANTE] ", "red", "bold") + msg, flush=True)


def blocked(msg: str) -> None:
    print(c("  [BLOQUEADO] ", "green", "bold") + msg, flush=True)


def failed(msg: str) -> None:
    print(c("  [¡NO BLOQUEADO!] ", "red", "bold") + msg, flush=True)


class QuietReporter(Reporter):
    def step(self, msg):
        print(c(f"      · {msg}", "dim"), flush=True)

    def ok(self, msg):
        print(c(f"      · {msg}", "dim"), flush=True)

    def info(self, msg):
        print(c(f"      · {msg}", "dim"), flush=True)

    def warn(self, msg):
        print(c(f"      ! {msg}", "yellow"), flush=True)


def flip_bit_b64(b64: str, byte_index: int, bit: int = 0) -> str:
    raw = bytearray(P.b64d(b64))
    raw[byte_index] ^= 1 << bit
    return P.b64e(bytes(raw))


def bits_different(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------
class Demo:
    def __init__(self, args) -> None:
        self.args = args
        self.workdir = Path(tempfile.mkdtemp(prefix="grupof_demo_"))
        self.results: list[tuple[str, str, bool]] = []
        self.app = None
        if args.server:
            self.server_url = args.server.rstrip("/")
            self.transport = RequestsTransport(self.server_url)
            suffix = secrets.token_hex(2)
            self.names = {n: f"{n}_{suffix}" for n in ("alice", "bob", "carol")}
        else:
            from src.server.app import create_app
            self.app = create_app(self.workdir / "server_data")
            self.server_url = "en-proceso://demo"
            self.transport = InProcessTransport(self.app.test_client())
            self.names = {n: n for n in ("alice", "bob", "carol")}
        self.svc: dict[str, ClientService] = {}

    def pause(self) -> None:
        if self.args.pausa:
            input(c("\n  ENTER para continuar...", "dim"))

    def new_service(self, key: str) -> ClientService:
        user = self.names[key]
        pw = f"demo-{key}-2026".encode()
        return ClientService(Keystore(user, self.workdir / "keystores"), ApiClient(self.transport),
                             self.server_url, lambda _p: bytearray(pw), lambda _q: True, QuietReporter())

    # ------------------------------------------------------------- preparación
    def setup(self) -> None:
        print(c("=" * 78, "cyan"))
        print(c(" PREPARACIÓN: usuarios, registro, login y subida del informe", "cyan", "bold"))
        print(c("=" * 78, "cyan"))
        mode = "servidor en el mismo proceso (datos temporales)" if self.app else f"servidor real {self.server_url}"
        say(f"Modo: {mode}")
        say(c(f"PBKDF2 con {self.args.kdf_iters:,} iteraciones SOLO PARA DEMOSTRACIÓN".replace(",", "."), "yellow")
            + c(" (por defecto 100.000; OWASP recomienda 600.000)", "dim"))
        for key in ("alice", "bob", "carol"):
            svc = self.new_service(key)
            t0 = time.perf_counter()
            say(f"Creando a {c(svc.user, 'bold')}: keygen RSA-2048, register (prueba de posesión), login...")
            svc.keygen(bytearray(f"demo-{key}-2026".encode()), iterations=self.args.kdf_iters)
            svc.register()
            svc.login()
            say(c(f"  listo en {time.perf_counter() - t0:.1f} s; huella {format_fingerprint(svc.ks.fingerprint())[:24]}...",
                  "dim"))
            self.svc[key] = svc

        self.plaintext = sample_text(self.args.size_kb * 1024)
        src = self.workdir / FILENAME
        src.write_bytes(self.plaintext)
        alice, bob = self.svc["alice"], self.svc["bob"]
        say(f"alice sube '{FILENAME}' ({len(self.plaintext) / 1024:.0f} KB) y lo comparte con bob...")
        self.file_id = alice.upload(src, share_with=[bob.user], assume_yes=True)
        say(f"file_id = {c(self.file_id, 'bold')}")
        # Paquete tal como lo recibe bob, y las claves que usará su cliente
        self.pkg = bob.api.download(self.file_id)
        self.bob_priv = bob._unlock()
        self.alice_pub = bob._trusted_key(alice.user, confirm_new=False).public_key
        opened = E.open_package(self.pkg, self.bob_priv, self.alice_pub)
        assert opened.data == self.plaintext
        say(c("Línea base: bob descarga, verifica y descifra correctamente el informe.", "green"))
        self.pause()

    def record(self, letter: str, desc: str, ok: bool) -> None:
        self.results.append((letter, desc, ok))

    def _two_layers(self, tampered: dict) -> tuple[bool, bool]:
        """Capa 1: flujo normal del cliente (firma primero). Capa 2: saltando la firma, solo GCM."""
        layer1 = layer2 = False
        try:
            E.open_package(tampered, self.bob_priv, self.alice_pub)
            failed("el cliente aceptó el paquete alterado")
        except E.PackageError as exc:
            blocked(f"Capa 1 - cliente de bob: '{exc.step}': {exc.message}")
            layer1 = True
        say(c("Supongamos que la firma no existiera: ¿AES-GCM solo también lo detecta?", "dim"))
        key = E.unwrap_session_key(self.pkg, self.bob_priv)
        gcm = AESGCM(key)
        nonce, ct = P.b64d(tampered["nonce"]), P.b64d(tampered["ciphertext"])
        tag, aad = P.b64d(tampered["tag"]), P.b64d(tampered["aad"])
        recomputed = gcm._tag(gcm._j0(nonce), aad, ct)
        say(f"tag recibido:     {tag.hex()}")
        say(f"tag recalculado:  {recomputed.hex()}  ({bits_different(tag, recomputed)} de 128 bits distintos)")
        try:
            gcm.decrypt(nonce, ct, tag, aad)
            failed("GCM aceptó datos alterados")
        except InvalidTag:
            blocked("Capa 2 - AES-GCM: tag inválido; no se entrega ni un byte de texto claro")
            layer2 = True
        finally:
            gcm.wipe()
            key[:] = bytes(len(key))
        return layer1, layer2

    # ----------------------------------------------------------------- ataques
    def attack_a(self) -> None:
        banner("a", "Alterar 1 bit del ciphertext")
        t = copy.deepcopy(self.pkg)
        pos = len(P.b64d(t["ciphertext"])) // 2
        attacker(f"el servidor (o alguien en la red) invierte el bit 0 del byte {pos} del ciphertext")
        t["ciphertext"] = flip_bit_b64(t["ciphertext"], pos)
        l1, l2 = self._two_layers(t)
        self.record("a", "1 bit del ciphertext alterado", l1 and l2)

    def attack_b(self) -> None:
        banner("b", "Alterar la AAD / metadatos")
        t = copy.deepcopy(self.pkg)
        meta = json.loads(P.b64d(t["aad"]))
        attacker(f"cambia la fecha del archivo: {meta['timestamp']} -> 2020-01-01T00:00:00Z")
        meta["timestamp"] = "2020-01-01T00:00:00Z"
        t["aad"] = P.b64e(P.canonical_json(meta))
        l1, l2 = self._two_layers(t)
        self.record("b", "AAD (metadatos) alterada", l1 and l2)

    def attack_c(self) -> None:
        banner("c", "Firma falsificada o hecha con otra clave")
        carol = self.svc["carol"]
        carol_priv = carol._unlock()
        raw = {k: P.b64d(self.pkg[k]) for k in ("ciphertext", "nonce", "tag", "aad")}
        digest = P.file_signature_digest(raw["ciphertext"], raw["nonce"], raw["tag"], raw["aad"])
        ok = True

        attacker("carol firma el paquete con SU clave y pone su huella como firmante")
        t = copy.deepcopy(self.pkg)
        t["signature"] = P.b64e(pss_sign_digest(carol_priv, digest))
        t["signer_fp"] = fingerprint(carol_priv.public_key())
        ok &= self._expect_reject(t)

        attacker("carol firma con su clave pero deja la huella de alice (suplantación)")
        t = copy.deepcopy(self.pkg)
        t["signature"] = P.b64e(pss_sign_digest(carol_priv, digest))
        ok &= self._expect_reject(t)

        attacker("firma con bytes aleatorios")
        t = copy.deepcopy(self.pkg)
        t["signature"] = P.b64e(secrets.token_bytes(256))
        ok &= self._expect_reject(t)

        attacker("carol intenta SUBIR al servidor un archivo que dice ser de alice (AAD owner=alice)")
        alice_name = self.svc["alice"].user
        fid = secrets.token_hex(16)
        inner = P.pack_plaintext("factura.pdf", b"pague a la cuenta de carol")
        aad = P.build_aad(fid, alice_name, E.utc_timestamp(), len(inner))
        ct, tag = aes_gcm_encrypt(secrets.token_bytes(32), secrets.token_bytes(12), inner, aad)
        body = {"file_id": fid, "aad": P.b64e(aad), "nonce": P.b64e(secrets.token_bytes(12)), "tag": P.b64e(tag),
                "ciphertext": P.b64e(ct), "signature": P.b64e(secrets.token_bytes(256)),
                "signer_fp": fingerprint(self.alice_pub), "wrapped_keys": []}
        try:
            carol.api.upload(body)
            failed("el servidor aceptó el archivo falso")
            ok = False
        except ApiError as exc:
            blocked(f"el propio servidor lo rechaza (defensa en profundidad): {exc.message}")
        self.record("c", "firma falsificada / otra clave", ok)

    def _expect_reject(self, t: dict) -> bool:
        try:
            E.open_package(t, self.bob_priv, self.alice_pub)
            failed("se aceptó la firma falsa")
            return False
        except E.PackageError as exc:
            blocked(f"{exc.message}")
            return True

    def attack_d(self) -> None:
        banner("d", "Usuario sin autorización intenta descifrar")
        carol = self.svc["carol"]
        ok = True
        attacker("carol pide el archivo al servidor")
        try:
            carol.api.download(self.file_id)
            failed("el servidor entregó el archivo")
            ok = False
        except ApiError as exc:
            blocked(f"servidor: HTTP {exc.status} - {exc.message}")
        attacker("carol intenta compartirse el archivo a sí misma")
        try:
            carol.api.share(self.file_id, carol.user, carol.ks.fingerprint(), P.b64e(b"\x00" * 256))
            failed("el servidor aceptó")
            ok = False
        except ApiError as exc:
            blocked(f"servidor: HTTP {exc.status} - {exc.message}")
        attacker("carol consigue el paquete COMPLETO de bob (robado del disco o filtrado por el servidor)")
        say(f"clave de sesión envuelta para bob: {P.b64d(self.pkg['wrapped_key'])[:24].hex()}...")
        try:
            E.open_package(self.pkg, carol._unlock(), self.alice_pub)
            failed("carol descifró el archivo")
            ok = False
        except E.PackageError as exc:
            blocked(f"'{exc.step}': {exc.message}")
            say(c("La clave de sesión está cifrada con RSA-OAEP para la clave pública de bob:", "dim"))
            say(c("sin la clave privada de bob no hay forma de obtenerla (problema RSA).", "dim"))
        self.record("d", "usuario no autorizado", ok)

    def attack_e(self) -> None:
        banner("e", "Replay del challenge de login")
        alice = self.svc["alice"]
        api = ApiClient(self.transport)
        ch = api.challenge(alice.user)
        nonce = P.b64d(ch["nonce"])
        sig = pss_sign(alice._unlock(), P.login_message(alice.user, nonce))
        say(f"servidor emite nonce {nonce.hex()[:32]}... (expira en {ch['expires_in']:.0f} s)")
        say("alice responde con su firma RSA-PSS del nonce")
        r = api.respond(alice.user, P.b64e(nonce), P.b64e(sig))
        say(c(f"login legítimo OK: token {r['token'][:10]}...", "green"))
        attacker("capturó (nonce, firma) en la red y los reenvía idénticos")
        ok = False
        try:
            api.respond(alice.user, P.b64e(nonce), P.b64e(sig))
            failed("el servidor aceptó el replay")
        except ApiError as exc:
            blocked(f"servidor: HTTP {exc.status} - {exc.message}")
            ok = True
        attacker("pide un challenge NUEVO y responde con la firma vieja")
        new_nonce = P.b64d(api.challenge(alice.user)["nonce"])
        try:
            api.respond(alice.user, P.b64e(new_nonce), P.b64e(sig))
            failed("aceptado")
            ok = False
        except ApiError as exc:
            blocked(f"servidor: HTTP {exc.status} - {exc.message} (la firma cubre el nonce)")
        self.record("e", "replay del challenge de login", ok)

    def attack_f(self) -> None:
        banner("f", "Vista del servidor comprometido")
        attacker("roba el disco completo del servidor (base de datos + blobs)")
        report = ApiClient(self.transport).compromised_view()
        f = next(x for x in report["files"] if x["file_id"] == self.file_id)
        ct = P.b64d(self.pkg["ciphertext"])
        dump = json.dumps(report, ensure_ascii=False)

        say(c("Lo que ve el atacante:", "bold"))
        say(f"metadatos (AAD): {f['visible_metadata_aad']}")
        say(f"inicio del ciphertext: {f['ciphertext_preview_hex']}")
        preview = self.plaintext[:60].decode("utf-8", "ignore").replace("\n", " ")
        say(f"inicio del texto claro (NO lo ve): {c(preview, 'dim')}")
        say()
        h_pt, h_ct = shannon_entropy(self.plaintext), shannon_entropy(ct)
        exp = expected_random_entropy(len(ct))
        say(c(f"{'':<34}{'TEXTO CLARO':>14}{'CIPHERTEXT':>14}", "bold"))
        say(f"{'Tamaño':<34}{len(self.plaintext):>12} B{len(ct):>12} B")
        say(f"{'Entropía de Shannon (bits/byte)':<34}{h_pt:>14.4f}{h_ct:>14.4f}")
        say(f"{'Esperada si fuera aleatorio':<34}{'':>14}{exp:>14.4f}")
        say(f"{'Bytes ASCII imprimibles':<34}{printable_ratio(self.plaintext):>14.1%}{printable_ratio(ct):>14.1%}")
        say(f"{'Bytes distintos (de 256)':<34}{len(set(self.plaintext)):>14}{len(set(ct)):>14}")
        say()
        say(f"El ciphertext tiene {h_ct:.4f} bits/byte: prácticamente el máximo de 8, indistinguible de")
        say("bytes aleatorios. El texto claro ronda 4-5 bits/byte (letras y espacios repetidos).")
        say()
        say(c("¿Y con archivos muy pequeños? La entropía MEDIDA baja por el tamaño de la muestra:", "bold"))
        say(c(f"{'tamaño':>10}{'ciphertext':>14}{'esperada aleatoria':>22}", "bold"))
        for n in (64, 256, 1024, 4096, 16384, 51200):
            ct_n, _ = aes_gcm_encrypt(secrets.token_bytes(32), secrets.token_bytes(12), sample_text(n))
            say(f"{n:>8} B{shannon_entropy(ct_n):>14.4f}{expected_random_entropy(n):>22.4f}")
        say(c("Con n bytes no pueden aparecer los 256 valores con la misma frecuencia (con 64 bytes,", "dim"))
        say(c("como mucho 64 valores distintos -> H <= log2(64) = 6). No es una debilidad del cifrado:", "dim"))
        say(c("el ciphertext coincide con lo esperado para datos aleatorios de ese mismo tamaño.", "dim"))
        say()
        name_hidden = FILENAME.split(".")[0] not in dump
        found = report["secret_material_found"]
        (blocked if name_hidden else failed)(
            f"nombre real '{FILENAME}' {'NO aparece' if name_hidden else 'APARECE'} en el servidor")
        (blocked if not found else failed)(
            f"material secreto encontrado: {', '.join(found) if found else 'NINGUNO'} "
            "(sin claves privadas, claves de sesión ni texto claro)")
        say(c("Lo que el servidor SÍ conoce (inevitable para el control de acceso): dueño, destinatarios,", "dim"))
        say(c("fechas y tamaño del ciphertext.", "dim"))
        self.record("f", "servidor comprometido", h_ct > 7.99 and name_hidden and not found)

    def attack_g(self) -> None:
        banner("g", "[extra] Sustitución de la clave pública de bob en el directorio (MITM)")
        if self.app is None:
            say(c("Solo disponible en modo en-proceso (requiere modificar la base del servidor).", "dim"))
            return
        alice, bob = self.svc["alice"], self.svc["bob"]
        db = self.app.extensions["grupof_storage"].db_path
        evil = generate_keypair(2048)
        with sqlite3.connect(db) as conn:
            original = conn.execute("SELECT public_key_pem FROM users WHERE username=?", (bob.user,)).fetchone()[0]
            attacker("el servidor reemplaza la clave pública de bob por la del atacante")
            conn.execute("UPDATE users SET public_key_pem=? WHERE username=?",
                         (public_key_to_pem(evil.public_key()), bob.user))
        src = self.workdir / "segundo_informe.txt"
        src.write_bytes(sample_text(2048, seed=2))
        ok = False
        try:
            alice.upload(src, share_with=[bob.user], assume_yes=True)
            failed("alice cifró para la clave del atacante")
        except TrustError as exc:
            blocked(str(exc).splitlines()[0])
            for line in str(exc).splitlines()[1:3]:
                say(line)
            ok = True
        finally:
            with sqlite3.connect(db) as conn:
                conn.execute("UPDATE users SET public_key_pem=? WHERE username=?", (original, bob.user))
        self.record("g", "sustitución de clave (MITM)", ok)

    # ---------------------------------------------------------------- resumen
    def summary(self) -> bool:
        print()
        print(c("=" * 78, "cyan"))
        print(c(" RESUMEN", "cyan", "bold"))
        print(c("=" * 78, "cyan"))
        for letter, desc, ok in self.results:
            mark = c("[BLOQUEADO]", "green", "bold") if ok else c("[FALLÓ]   ", "red", "bold")
            print(f"  {letter})  {desc:<40} {mark}")
        all_ok = all(ok for _, _, ok in self.results)
        print()
        print("  " + (c("Todos los ataques fueron detenidos.", "green", "bold") if all_ok
                      else c("Algún ataque NO fue detenido.", "red", "bold")))
        return all_ok

    def cleanup(self) -> None:
        if self.args.keep:
            say(c(f"Datos de la demo conservados en {self.workdir}", "dim"))
        else:
            shutil.rmtree(self.workdir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Demo de ataques - Proyecto 2 ELC107 Grupo F")
    parser.add_argument("--server", default=None, help="URL de un servidor real (por defecto: en el mismo proceso)")
    parser.add_argument("--solo", default="a,b,c,d,e,f,g", help="ataques a ejecutar, p. ej. a,c,f")
    parser.add_argument("--pausa", action="store_true", help="esperar ENTER entre ataques")
    parser.add_argument("--size-kb", type=int, default=50, help="tamaño del informe de prueba (KB)")
    parser.add_argument("--kdf-iters", type=int, default=DEMO_ITERS,
                        help="iteraciones PBKDF2 de las cuentas de demo (10.000: SOLO DEMOSTRACIÓN)")
    parser.add_argument("--keep", action="store_true", help="no borrar la carpeta temporal al terminar")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args(argv)
    Style.setup(args.no_color)

    demo = Demo(args)
    attacks = {"a": demo.attack_a, "b": demo.attack_b, "c": demo.attack_c, "d": demo.attack_d,
               "e": demo.attack_e, "f": demo.attack_f, "g": demo.attack_g}
    try:
        demo.setup()
        for letter in [x.strip() for x in args.solo.split(",") if x.strip()]:
            if letter not in attacks:
                print(f"ataque desconocido: {letter}", file=sys.stderr)
                return 2
            attacks[letter]()
            demo.pause()
        return 0 if demo.summary() else 1
    except ApiError as exc:
        print(c(f"Error del servidor: {exc.message}", "red"), file=sys.stderr)
        return 1
    finally:
        demo.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
