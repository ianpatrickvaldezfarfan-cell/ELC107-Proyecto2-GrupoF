"""Lógica de cada comando del cliente (independiente de la interfaz de línea de comandos).

La CLI (cli.py), la demo de ataques y los tests end-to-end usan esta clase.

Confianza en claves públicas (directorio del servidor NO confiable):
  * La huella SIEMPRE se recalcula localmente a partir de la clave recibida; nunca
    se confía en la huella que envía el servidor.
  * La primera vez que se usa la clave de otro usuario se FIJA (pinning) en
    contacts.json. Para compartir/enviar se pide confirmar que la huella se verificó
    fuera de banda; para verificar firmas al descargar se usa TOFU (se avisa).
  * Si más adelante el servidor devuelve una clave distinta de la fijada, se aborta:
    es la señal de un ataque man-in-the-middle sobre el directorio de claves.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .. import protocol as P
from ..crypto.encoding import fingerprint, format_fingerprint, public_key_from_pem, public_key_to_pem
from ..crypto.kdf import default_iterations
from ..crypto.pss import pss_sign
from ..crypto.rsa_core import DEFAULT_BITS, KeyGenStats, RSAPrivateKey, generate_keypair
from ..crypto.utils import zeroize
from . import envelope as E
from .api_client import ApiClient, ApiError
from .keystore import Keystore, KeystoreError


class ClientError(Exception):
    """Error de uso u operación (sin implicaciones de seguridad)."""


class TrustError(Exception):
    """Problema de confianza en una clave pública (posible MITM) o confirmación rechazada."""


class Reporter:
    """Receptor de mensajes de progreso. La CLI lo reemplaza por uno con colores."""

    def step(self, msg: str) -> None: ...
    def info(self, msg: str) -> None: ...
    def ok(self, msg: str) -> None: ...
    def warn(self, msg: str) -> None: ...


PassphraseProvider = Callable[[str], bytearray]
Confirm = Callable[[str], bool]

_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def safe_filename(name: str, fallback: str) -> str:
    """Nombre seguro para escribir en disco: sin rutas (evita path traversal tipo '../../x'),
    sin caracteres prohibidos en Windows y sin nombres reservados (CON, NUL, ...)."""
    name = name.replace("\\", "/").split("/")[-1]
    name = re.sub(r'[<>:"|?*\x00-\x1f]', "_", name).strip(" .")
    if not name or name in (".", ".."):
        return fallback
    if name.split(".")[0].upper() in _WINDOWS_RESERVED:
        name = "_" + name
    return name[:200]


def fmt_int(n: int) -> str:
    """100000 -> '100.000' (separador de miles en español)."""
    return f"{n:,}".replace(",", ".")


def normalize_fp(fp: str) -> str:
    return re.sub(r"[^0-9a-fA-F]", "", fp).lower()


@dataclass
class FileRow:
    file_id: str
    owner: str
    filename: str | None
    size: int
    created_at: float
    is_owner: bool
    recipients: list[str] | None


class ClientService:
    def __init__(self, keystore: Keystore, api: ApiClient, server_url: str,
                 passphrase_provider: PassphraseProvider, confirm: Confirm = lambda _msg: False,
                 reporter: Reporter | None = None) -> None:
        self.ks = keystore
        self.api = api
        self.server_url = server_url
        self._passphrase = passphrase_provider
        self._confirm = confirm
        self.r = reporter or Reporter()
        self._priv: RSAPrivateKey | None = None

    @property
    def user(self) -> str:
        return self.ks.username

    # ---------------------------------------------------------------- utilidades
    def _unlock(self) -> RSAPrivateKey:
        """Pide la passphrase y descifra la clave privada (una sola vez por comando)."""
        if self._priv is None:
            iters = self.ks.kdf_iterations()
            passphrase = self._passphrase(f"Passphrase del keystore de '{self.user}': ")
            self.r.step(f"Derivando clave con PBKDF2-HMAC-SHA256 ({fmt_int(iters)} iteraciones); "
                        "puede tardar unos segundos...")
            t0 = time.perf_counter()
            try:
                self._priv = self.ks.unlock(passphrase)
            finally:
                zeroize(passphrase)
            self.r.ok(f"Clave privada desbloqueada ({time.perf_counter() - t0:.1f} s)")
        return self._priv

    def close(self) -> None:
        """Suelta la referencia a la clave privada (ver limitación de borrado en keystore.py)."""
        self._priv = None

    def _require_session(self) -> None:
        if self.api.token is None:
            self.api.token = self.ks.load_session(self.server_url)
        if self.api.token is None:
            raise ClientError(f"no hay sesión activa para '{self.user}' en {self.server_url}: ejecute 'login'")

    def _fetch_key(self, username: str):
        info = self.api.get_key(username)
        pub = public_key_from_pem(info["public_key_pem"])
        return pub, fingerprint(pub)          # huella calculada LOCALMENTE

    def _trusted_key(self, username: str, *, confirm_new: bool, assume_yes: bool = False) -> E.Recipient:
        pub, fp = self._fetch_key(username)
        if username == self.user:
            if fp != self.ks.fingerprint():
                raise TrustError("¡ALERTA! el servidor devuelve para usted una clave pública distinta de la "
                                 "de su keystore (posible ataque MITM)")
            return E.Recipient(username, pub, fp)
        pinned = self.ks.pinned_fingerprint(username)
        if pinned is not None:
            if pinned != fp:
                raise TrustError(f"¡ALERTA! la clave pública de '{username}' CAMBIÓ respecto de la fijada.\n"
                                 f"  fijada:   {format_fingerprint(pinned)}\n  servidor: {format_fingerprint(fp)}\n"
                                 "Posible ataque man-in-the-middle sobre el directorio de claves. Operación abortada.")
            return E.Recipient(username, pub, fp)
        if confirm_new:
            question = (f"Huella de la clave pública de '{username}':\n    {format_fingerprint(fp)}\n"
                        "¿La verificó fuera de banda (en persona/teléfono) y coincide?")
            if not assume_yes and not self._confirm(question):
                raise TrustError(f"no se confirmó la huella de '{username}': operación cancelada")
            self.ks.pin(username, fp, verified=not assume_yes)
            self.r.info(f"Huella de '{username}' fijada en sus contactos")
        else:
            self.ks.pin(username, fp, verified=False)
            self.r.warn(f"Primera vez que ve la clave de '{username}': se fija por TOFU "
                        f"({format_fingerprint(fp)[:19]}...). Verifíquela con 'fingerprint {username}'.")
        return E.Recipient(username, pub, fp)

    # ------------------------------------------------------------------ comandos
    def keygen(self, passphrase: bytearray, bits: int = DEFAULT_BITS, iterations: int | None = None,
               overwrite: bool = False) -> str:
        if self.ks.exists() and not overwrite:
            raise ClientError(f"ya existe un keystore para '{self.user}' ({self.ks.dir}); use --force para reemplazarlo")
        iterations = iterations or default_iterations()
        self.r.step(f"Generando par de claves RSA-{bits} (Miller-Rabin + criba)...")
        st = KeyGenStats()
        t0 = time.perf_counter()
        priv = generate_keypair(bits, stats=st)
        self.r.ok(f"Par generado en {time.perf_counter() - t0:.1f} s "
                  f"({st.prime_stats.candidates} candidatos, {st.prime_stats.mr_tested} pasaron a Miller-Rabin)")
        self.r.step(f"Cifrando la clave privada: PBKDF2-HMAC-SHA256 ({fmt_int(iterations)} iteraciones) "
                    "+ AES-256-GCM; puede tardar unos segundos...")
        t0 = time.perf_counter()
        try:
            fp = self.ks.create(priv, passphrase, iterations, overwrite=overwrite)
        finally:
            zeroize(passphrase)
        self.r.ok(f"Keystore guardado en {self.ks.dir} ({time.perf_counter() - t0:.1f} s)")
        return fp

    def register(self) -> str:
        pub = self.ks.public_key()
        fp = fingerprint(pub)
        priv = self._unlock()
        self.r.step("Firmando la prueba de posesión (RSA-PSS)...")
        sig = pss_sign(priv, P.register_message(self.user, fp))
        resp = self.api.register(self.user, public_key_to_pem(pub), P.b64e(sig))
        if resp.get("fingerprint") != fp:
            raise TrustError("el servidor registró una huella distinta de la local")
        return fp

    def login(self) -> float:
        self.r.step("Solicitando challenge al servidor...")
        ch = self.api.challenge(self.user)
        nonce = P.b64d(ch["nonce"])
        priv = self._unlock()
        self.r.step("Firmando el challenge con RSA-PSS...")
        sig = pss_sign(priv, P.login_message(self.user, nonce))
        resp = self.api.respond(self.user, P.b64e(nonce), P.b64e(sig))
        expires_at = time.time() + float(resp["expires_in"])
        self.ks.save_session(self.server_url, resp["token"], expires_at)
        self.api.token = resp["token"]
        return expires_at

    def upload(self, path: Path, share_with: list[str] | None = None, assume_yes: bool = False) -> str:
        self._require_session()
        path = Path(path)
        if not path.is_file():
            raise ClientError(f"no existe el archivo {path}")
        data = path.read_bytes()
        recipients = [self._trusted_key(self.user, confirm_new=False)]
        for name in dict.fromkeys(share_with or []):
            if name != self.user:
                recipients.append(self._trusted_key(name, confirm_new=True, assume_yes=assume_yes))
        priv = self._unlock()
        self.r.step(f"Cifrando {fmt_int(len(data))} bytes con AES-256-GCM, envolviendo la clave de sesión con "
                    f"RSA-OAEP para {', '.join(r.username for r in recipients)} y firmando con RSA-PSS...")
        t0 = time.perf_counter()
        body = E.seal(self.user, priv, recipients, path.name, data)
        self.r.ok(f"Paquete cifrado y firmado en {time.perf_counter() - t0:.2f} s")
        self.r.step("Subiendo SOLO datos cifrados al servidor...")
        self.api.upload(body)
        self.ks.remember_file(body["file_id"], path.name)
        return body["file_id"]

    def download(self, file_id: str) -> E.OpenedFile:
        self._require_session()
        pkg = self.api.download(file_id)
        owner = self._trusted_key(pkg["owner"], confirm_new=False)
        priv = self._unlock()
        self.r.step("Verificando firma RSA-PSS, desenvolviendo clave (RSA-OAEP) y descifrando (AES-256-GCM)...")
        opened = E.open_package(pkg, priv, owner.public_key)
        self.ks.remember_file(file_id, opened.filename)
        return opened

    def save(self, opened: E.OpenedFile, out: Path | None = None, force: bool = False) -> Path:
        """Escribe el archivo SOLO después de verificarlo completo (escritura atómica)."""
        name = safe_filename(opened.filename, f"{opened.file_id}.bin")
        if out is None:
            target = Path.cwd() / name
        else:
            # `out` es carpeta si ya existe como carpeta, si termina en separador o si no tiene extensión
            as_dir = Path(out).is_dir() or str(out).endswith(("/", "\\")) or Path(out).suffix == ""
            target = Path(out) / name if as_dir else Path(out)
        if target.exists() and not force:
            raise ClientError(f"{target} ya existe; use --force para sobrescribir")
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".part")
        tmp.write_bytes(opened.data)
        os.replace(tmp, target)
        return target

    def share(self, file_id: str, recipient: str, assume_yes: bool = False) -> list[str]:
        self._require_session()
        if recipient == self.user:
            raise ClientError("no tiene sentido compartir con uno mismo")
        pkg = self.api.download(file_id)
        if pkg["owner"] != self.user:
            raise ClientError("solo el dueño puede compartir el archivo")
        me = self._trusted_key(self.user, confirm_new=False)
        rec = self._trusted_key(recipient, confirm_new=True, assume_yes=assume_yes)
        priv = self._unlock()
        self.r.step(f"Desenvolviendo la clave de sesión localmente y re-envolviéndola para '{recipient}'...")
        wrapped = E.rewrap_for(pkg, priv, me.public_key, rec.public_key)
        resp = self.api.share(file_id, recipient, rec.fingerprint, P.b64e(wrapped))
        return resp["recipients"]

    def list_files(self) -> list[FileRow]:
        """No necesita la clave privada: usa el token de sesión guardado por 'login'."""
        self._require_session()
        rows = []
        for f in self.api.list_files()["files"]:
            rows.append(FileRow(f["file_id"], f["owner"], self.ks.known_filename(f["file_id"]), f["size"],
                                f["created_at"], f["is_owner"], f.get("recipients")))
        return rows

    def verify(self, file_id: str, signature_only: bool = False) -> dict[str, Any]:
        self._require_session()
        pkg = self.api.download(file_id)
        owner = self._trusted_key(pkg["owner"], confirm_new=False)
        meta = E.verify_signature(pkg, owner.public_key)
        result = {"file_id": file_id, "owner": pkg["owner"], "owner_fp": owner.fingerprint,
                  "signature": True, "gcm_tag": None, "meta": meta}
        if not signature_only:
            priv = self._unlock()
            E.check_integrity(pkg, priv, owner.public_key)
            result["gcm_tag"] = True
        return result

    def fingerprint_info(self, username: str | None = None) -> dict[str, Any]:
        if username is None or username == self.user:
            return {"username": self.user, "fingerprint": self.ks.fingerprint(), "source": "keystore local"}
        _, fp = self._fetch_key(username)
        pinned = self.ks.pinned_fingerprint(username)
        entry = self.ks.contacts().get(username, {})
        return {"username": username, "fingerprint": fp, "source": "servidor (recalculada localmente)",
                "pinned": pinned, "matches_pinned": None if pinned is None else pinned == fp,
                "verified_out_of_band": entry.get("verified_out_of_band", False)}

    def trust(self, username: str, expected_fp: str | None = None) -> str:
        """Marca como verificada fuera de banda la clave de `username` (opcionalmente comparando la huella)."""
        _, fp = self._fetch_key(username)
        if expected_fp is not None and normalize_fp(expected_fp) != fp:
            raise TrustError(f"la huella indicada NO coincide con la del servidor para '{username}'")
        pinned = self.ks.pinned_fingerprint(username)
        if pinned is not None and pinned != fp:
            raise TrustError(f"la clave de '{username}' cambió respecto de la fijada; no se actualiza")
        self.ks.pin(username, fp, verified=True)
        return fp


__all__ = ["ClientService", "ClientError", "TrustError", "Reporter", "ApiError", "KeystoreError",
           "safe_filename", "normalize_fp", "FileRow"]
