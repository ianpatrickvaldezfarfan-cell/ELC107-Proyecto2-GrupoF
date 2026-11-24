"""Genera los 4 diagramas en formato draw.io (.drawio, XML sin comprimir).

    python docs\\drawio\\generar_drawio.py

Abrir los .drawio en https://app.diagrams.net (o la app de escritorio draw.io /
la extensión de VS Code) y exportarlos con Archivo > Exportar como > PNG/SVG/PDF.
Son el mismo contenido que los diagramas Mermaid de docs/*.md.
"""

from __future__ import annotations

import math
import xml.etree.ElementTree as ET
from pathlib import Path

OUT = Path(__file__).resolve().parent

# Paleta estándar de draw.io (relleno, borde)
BLUE = ("#dae8fc", "#6c8ebf")      # cliente
ORANGE = ("#ffe6cc", "#d79b00")    # servidor
GREEN = ("#d5e8d4", "#82b366")     # criptografía
YELLOW = ("#fff2cc", "#d6b656")    # notas / pasos locales
RED = ("#f8cecc", "#b85450")       # fallos / atacante
GRAY = ("#f5f5f5", "#666666")      # usuario / neutro


class Diagram:
    def __init__(self, name: str, width: int = 1400, height: int = 1000) -> None:
        self.name, self.width, self.height = name, width, height
        self.cells: list[ET.Element] = []
        self._id = 2

    def _new_id(self) -> str:
        self._id += 1
        return f"c{self._id}"

    def vertex(self, label: str, x: float, y: float, w: float, h: float, colors=BLUE, extra: str = "",
               parent: str = "1") -> str:
        cid = self._new_id()
        style = (f"rounded=1;whiteSpace=wrap;html=1;arcSize=6;fillColor={colors[0]};strokeColor={colors[1]};"
                 f"fontSize=12;{extra}")
        cell = ET.Element("mxCell", id=cid, value=label, style=style, vertex="1", parent=parent)
        ET.SubElement(cell, "mxGeometry", x=str(x), y=str(y), width=str(w), height=str(h), **{"as": "geometry"})
        self.cells.append(cell)
        return cid

    def edge(self, label: str = "", source: str | None = None, target: str | None = None,
             p1: tuple[float, float] | None = None, p2: tuple[float, float] | None = None,
             style: str = "endArrow=block;endFill=1;html=1;fontSize=11;") -> str:
        cid = self._new_id()
        attrs = {"id": cid, "value": label, "style": style, "edge": "1", "parent": "1"}
        if source:
            attrs["source"] = source
        if target:
            attrs["target"] = target
        cell = ET.Element("mxCell", **attrs)
        geo = ET.SubElement(cell, "mxGeometry", relative="1", **{"as": "geometry"})
        if p1:
            ET.SubElement(geo, "mxPoint", x=str(p1[0]), y=str(p1[1]), **{"as": "sourcePoint"})
        if p2:
            ET.SubElement(geo, "mxPoint", x=str(p2[0]), y=str(p2[1]), **{"as": "targetPoint"})
        self.cells.append(cell)
        return cid

    def element(self) -> ET.Element:
        diagram = ET.Element("diagram", id=self.name.lower().replace(" ", "-"), name=self.name)
        model = ET.SubElement(diagram, "mxGraphModel", dx="1400", dy="900", grid="1", gridSize="10", guides="1",
                              tooltips="1", connect="1", arrows="1", fold="1", page="1", pageScale="1",
                              pageWidth=str(self.width), pageHeight=str(self.height), math="0", shadow="0")
        root = ET.SubElement(model, "root")
        ET.SubElement(root, "mxCell", id="0")
        ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})
        for c in self.cells:
            root.append(c)
        return diagram


def write(path: Path, diagram: Diagram) -> None:
    mxfile = ET.Element("mxfile", host="app.diagrams.net", type="device")
    mxfile.append(diagram.element())
    ET.indent(mxfile)
    path.write_text(ET.tostring(mxfile, encoding="unicode"), encoding="utf-8")
    print(f"generado: {path.name}")


# ---------------------------------------------------------------------------
# Diagramas de secuencia
# ---------------------------------------------------------------------------
def _html(text: str) -> str:
    """Las celdas usan html=1: '<file_id>' se tomaría como etiqueta HTML. Se escapa y se pasan los saltos a <br>."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")


def _lines_needed(text: str, width: float) -> int:
    per_line = max(10, int((width - 24) / 6.6))
    return sum(max(1, math.ceil(len(line) / per_line)) for line in text.split("\n"))


def sequence(name: str, participants: list[tuple[str, str, tuple]], steps: list[tuple], spacing: int = 300) -> Diagram:
    """participants: (clave, etiqueta, colores). steps:
        ("msg", desde, hacia, texto)            mensaje
        ("ret", desde, hacia, texto)            respuesta (punteada)
        ("note", [claves], texto, colores)      nota sobre una o varias líneas de vida
        ("section", texto, colores)             franja (alternativas / fases)
    """
    box_w, box_h, top = 200, 56, 30
    xs = {key: 60 + i * spacing + box_w / 2 for i, (key, _, _) in enumerate(participants)}
    left, right = 30, 60 + (len(participants) - 1) * spacing + box_w + 30
    d = Diagram(name, width=int(right + 40))
    for key, label, colors in participants:
        d.vertex(label, xs[key] - box_w / 2, top, box_w, box_h, colors, "fontStyle=1;")
    y = top + box_h + 40
    for step in steps:
        kind = step[0]
        if kind in ("msg", "ret"):
            _, a, b, text = step
            dashed = "dashed=1;endArrow=open;endFill=0;" if kind == "ret" else "endArrow=block;endFill=1;"
            n = _lines_needed(text, abs(xs[b] - xs[a]) or 200)
            y += 14 * (n - 1)
            d.edge(_html(text), p1=(xs[a], y), p2=(xs[b], y),
                   style=f"html=1;fontSize=11;verticalAlign=bottom;labelBackgroundColor=none;{dashed}")
            y += 46
        elif kind == "note":
            _, keys, text, colors = step
            longest = max(len(line) for line in text.split("\n"))
            span = max(xs[k] for k in keys) - min(xs[k] for k in keys)
            w = min(max(260, longest * 6.6 + 30, span + 260), span + 2 * spacing - 40)
            cx = (min(xs[k] for k in keys) + max(xs[k] for k in keys)) / 2
            x0 = max(left, min(cx - w / 2, right - w))
            h = 17 * _lines_needed(text, w) + 14
            d.vertex(_html(text), x0, y, w, h, colors, "align=left;spacingLeft=8;verticalAlign=middle;")
            y += h + 24
        elif kind == "section":
            _, text, colors = step
            d.vertex(f"<b>{_html(text)}</b>", left, y, right - left, 28, colors,
                     "align=left;spacingLeft=10;opacity=70;dashed=1;")
            y += 44
    bottom = y + 10
    for key in xs:   # líneas de vida (se dibujan al final pero quedan debajo por el orden de capa)
        d.cells.insert(0, _lifeline(d, xs[key], top + box_h, bottom))
    d.height = int(bottom + 40)
    return d


def _lifeline(d: Diagram, x: float, y0: float, y1: float) -> ET.Element:
    cid = d._new_id()
    cell = ET.Element("mxCell", id=cid, value="", edge="1", parent="1",
                      style="endArrow=none;dashed=1;html=1;strokeColor=#999999;strokeWidth=1;")
    geo = ET.SubElement(cell, "mxGeometry", relative="1", **{"as": "geometry"})
    ET.SubElement(geo, "mxPoint", x=str(x), y=str(y0), **{"as": "sourcePoint"})
    ET.SubElement(geo, "mxPoint", x=str(x), y=str(y1), **{"as": "targetPoint"})
    return cell


def diagram_upload() -> Diagram:
    P = [("u", "alice (usuaria)", GRAY), ("c", "Cliente de alice<br>(CLI / GUI)", BLUE),
         ("k", "Keystore local<br>~/.grupof/alice", GREEN), ("s", "Servidor<br>(no confiable)", ORANGE)]
    S = [
        ("msg", "u", "c", "upload informe.txt --share-with bob"),
        ("msg", "c", "s", "GET /api/keys/alice y /api/keys/bob"),
        ("ret", "s", "c", "claves públicas (PEM)"),
        ("note", ["c"], "Huella = SHA-256(clave pública) calculada LOCALMENTE.\n"
                        "Se compara con la fijada en contacts.json; si es nueva,\n"
                        "se confirma fuera de banda. Si cambió: ALERTA MITM.", YELLOW),
        ("msg", "c", "k", "pedir clave privada (passphrase)"),
        ("note", ["k"], "PBKDF2-HMAC-SHA256(passphrase, sal)\n-> clave AES-256\nAES-256-GCM descifra la clave RSA", GREEN),
        ("ret", "k", "c", "clave privada RSA (en memoria)"),
        ("note", ["c"], "1. K_s (256 bits) y nonce (96 bits) del CSPRNG\n"
                        "2. texto = {nombre real, tamaño} || datos\n"
                        "3. AAD = {file_id, owner, timestamp, tamaño}\n"
                        "4. (C, T) = AES-256-GCM(K_s, nonce, texto, AAD)\n"
                        "5. W_alice, W_bob = RSA-OAEP(pub, K_s)\n"
                        "6. σ = RSA-PSS(priv_alice, SHA-256(C‖nonce‖T‖AAD))\n"
                        "7. K_s se borra de la memoria (zeroize)", GREEN),
        ("msg", "c", "s", "POST /api/files (Bearer token)\n{C, nonce, T, AAD, W_alice, W_bob, σ, huella}"),
        ("note", ["s"], "Verifica: sesión, AAD (owner = usuario),\nfirma PSS y huellas de destinatarios.\n"
                        "Guarda blob cifrado + metadatos.\nNunca ve K_s ni el texto claro.", ORANGE),
        ("ret", "s", "c", "201 Created {file_id}"),
        ("ret", "c", "u", "OK: file_id (el servidor solo recibió bytes cifrados)"),
    ]
    return sequence("Secuencia de subida", P, S)


def diagram_download() -> Diagram:
    P = [("u", "bob (usuario)", GRAY), ("c", "Cliente de bob<br>(CLI / GUI)", BLUE), ("s", "Servidor<br>(no confiable)", ORANGE)]
    S = [
        ("msg", "u", "c", "download <file_id>"),
        ("msg", "c", "s", "GET /api/files/<file_id> (Bearer token)"),
        ("note", ["s"], "¿bob tiene una clave envuelta para este archivo?\nNo -> 404 (no revela si el archivo existe)", ORANGE),
        ("ret", "s", "c", "{C, nonce, T, AAD, σ, huella del firmante, W_bob}\n(solo la clave envuelta de bob)"),
        ("msg", "c", "s", "GET /api/keys/alice"),
        ("ret", "s", "c", "clave pública de alice"),
        ("note", ["c"], "Huella de alice recalculada y comparada con la fijada\n(si cambió: ALERTA MITM y se aborta)", YELLOW),
        ("note", ["c"], "1. Verificar σ con RSA-PSS (clave pública de alice)\n"
                        "2. Validar AAD (dueño, file_id, tamaño)\n"
                        "3. K_s = RSA-OAEP-Dec(priv_bob, W_bob)\n"
                        "4. AES-256-GCM: verificar T y descifrar\n"
                        "5. Separar nombre real y datos; borrar K_s", GREEN),
        ("section", "Si CUALQUIER verificación falla", RED),
        ("ret", "c", "u", "FALLO DE SEGURIDAD: no se entrega ningún dato"),
        ("section", "Si todo es válido", GREEN),
        ("ret", "c", "u", "archivo guardado con su nombre real (escritura atómica)"),
    ]
    return sequence("Secuencia de descarga", P, S, spacing=360)


def diagram_share() -> Diagram:
    P = [("a", "alice (dueña)", GRAY), ("c", "Cliente de alice", BLUE), ("s", "Servidor<br>(no confiable)", ORANGE),
         ("b", "bob", GRAY)]
    S = [
        ("msg", "a", "c", "share <file_id> --with bob"),
        ("msg", "c", "s", "GET /api/files/<file_id>"),
        ("ret", "s", "c", "paquete con W_alice"),
        ("msg", "c", "s", "GET /api/keys/bob"),
        ("ret", "s", "c", "clave pública de bob"),
        ("note", ["c"], "Primera vez: mostrar la huella de bob y confirmar\nque se verificó fuera de banda; luego se fija.\n"
                        "Si difiere de la fijada: ALERTA MITM.", YELLOW),
        ("note", ["c"], "1. Verificar σ del propio archivo\n2. K_s = RSA-OAEP-Dec(priv_alice, W_alice)\n"
                        "3. Comprobar el tag GCM con K_s (clave correcta)\n4. W_bob = RSA-OAEP(pub_bob, K_s)\n5. Borrar K_s",
         GREEN),
        ("msg", "c", "s", "POST /api/files/<file_id>/share {bob, huella, W_bob}"),
        ("note", ["s"], "Solo el dueño puede compartir; la huella debe\ncoincidir con la registrada. Guarda W_bob.\n"
                        "El servidor NUNCA ve K_s.", ORANGE),
        ("ret", "s", "c", "destinatarios: [alice, bob]"),
        ("ret", "c", "a", "compartido"),
        ("note", ["s", "b"], "bob ya puede descargar el archivo (ver secuencia de descarga)", GRAY),
    ]
    return sequence("Secuencia de compartir", P, S)


# ---------------------------------------------------------------------------
# Arquitectura
# ---------------------------------------------------------------------------
def diagram_architecture() -> Diagram:
    d = Diagram("Arquitectura", width=1320, height=840)
    zone = "dashed=1;verticalAlign=top;align=left;spacingLeft=10;spacingTop=6;fontStyle=1;fontSize=14;arcSize=2;"
    # Personas (arriba): la verificación de huellas fuera de banda no pasa por el servidor
    alice = d.vertex("<b>alice</b> (usuaria)<br>comandos + passphrase", 230, 20, 200, 56, GRAY)
    bob = d.vertex("<b>bob</b> (otro usuario)<br>su propio cliente y keystore", 600, 20, 220, 56, GRAY)

    d.vertex("Equipo del usuario - ZONA DE CONFIANZA", 20, 110, 600, 520, ("#f5f9ff", "#6c8ebf"), zone)
    d.vertex("Servidor de almacenamiento - NO CONFIABLE", 760, 110, 540, 570, ("#fffaf3", "#d79b00"), zone)

    cli = d.vertex("<b>CLI</b><br>cli.py (argparse)", 50, 160, 250, 56, BLUE)
    gui = d.vertex("<b>GUI</b><br>gui.py (Tkinter)", 340, 160, 250, 56, BLUE)
    svc = d.vertex("<b>ClientService</b> (service.py)<br>keygen · register · login · upload · download<br>"
                   "share · list · verify · fingerprint<br>pinning de huellas (TOFU / fuera de banda)",
                   50, 250, 540, 90, BLUE)
    env = d.vertex("<b>envelope.py</b> - cifrado híbrido<br>sellar · abrir · verificar · re-envolver",
                   50, 380, 260, 70, GREEN)
    ks = d.vertex("<b>Keystore local</b> (keystore.py)<br>~/.grupof/&lt;usuario&gt;/<br>clave privada cifrada "
                  "(PBKDF2 + AES-256-GCM)<br>token de sesión · contactos · índice de nombres",
                  330, 380, 260, 100, YELLOW)
    cr = d.vertex("<b>src/crypto</b> - Python puro, sin cajas negras<br>SHA-256 · HMAC · PBKDF2 · AES-256 · GCM<br>"
                  "RSA (Miller-Rabin, CRT) · OAEP · PSS", 50, 490, 260, 100, GREEN)
    api = d.vertex("<b>api_client.py</b> (requests)", 330, 530, 260, 56, BLUE)

    app = d.vertex("<b>app.py</b> (Flask)<br>registro con prueba de posesión<br>login challenge-response (nonce de un uso)<br>"
                   "subir · listar · descargar · compartir<br>directorio de claves públicas + huellas",
                   800, 160, 460, 110, ORANGE)
    st = d.vertex("<b>storage.py</b>", 800, 310, 460, 40, ORANGE)
    db = d.vertex("<b>metadata.sqlite3</b><br>usuarios + claves públicas · AAD · nonce · tag<br>firmas · claves de sesión "
                  "ENVUELTAS (OAEP)<br>challenges · hashes de tokens", 800, 380, 220, 140, ORANGE)
    blobs = d.vertex("<b>blobs/*.bin</b><br>ciphertext AES-256-GCM<br>(nombre real cifrado dentro)",
                     1040, 380, 220, 140, ORANGE)
    d.vertex("<b>NUNCA tiene:</b> claves privadas, claves de sesión en claro, texto claro, nombres de archivo, "
             "passphrases.<br><b>Sí conoce:</b> dueño, destinatarios, fechas y tamaño (necesarios para el "
             "control de acceso).", 800, 545, 220, 120, YELLOW, "align=left;spacingLeft=6;fontSize=11;")
    atk = d.vertex("<b>Atacante / servidor comprometido</b><br>solo ve bytes cifrados<br>(entropía ≈ 8 bits/byte)",
                   1010, 730, 280, 80, RED)

    arrow = "endArrow=block;endFill=1;html=1;fontSize=11;"
    d.edge("", alice, cli, style=arrow + "exitX=0.25;exitY=1;")
    d.edge("", alice, gui, style=arrow + "exitX=0.75;exitY=1;")
    d.edge("verificación de huellas<br>FUERA DE BANDA", alice, bob,
           style="endArrow=block;startArrow=block;endFill=1;startFill=1;dashed=1;html=1;fontSize=11;"
                 "exitX=1;exitY=0.5;entryX=0;entryY=0.5;")
    d.edge("HTTP (mismo protocolo)", bob, app,
           style=arrow + "dashed=1;exitX=1;exitY=0.5;entryX=0.5;entryY=0;edgeStyle=orthogonalEdgeStyle;")
    d.edge("", cli, svc, style=arrow)
    d.edge("", gui, svc, style=arrow)
    d.edge("", svc, env, style=arrow + "exitX=0.24;exitY=1;")
    d.edge("", svc, ks, style=arrow + "exitX=0.76;exitY=1;")
    d.edge("", env, cr, style=arrow)
    d.edge("", ks, api, style=arrow + "dashed=1;")
    d.edge("HTTP + JSON<br><b>solo datos cifrados</b>,<br>claves públicas y firmas", api, app,
           style=arrow + "startArrow=block;startFill=1;exitX=1;exitY=0.5;entryX=0;entryY=0.75;")
    d.edge("", app, st, style=arrow)
    d.edge("", st, db, style=arrow + "exitX=0.24;exitY=1;")
    d.edge("", st, blobs, style=arrow + "exitX=0.76;exitY=1;")
    d.edge("roba el disco", atk, blobs, style=arrow + "dashed=1;strokeColor=#b85450;fontColor=#b85450;"
                                               "exitX=0.55;exitY=0;entryX=0.5;entryY=1;")
    return d


def main() -> None:
    write(OUT / "arquitectura.drawio", diagram_architecture())
    write(OUT / "secuencia_subida.drawio", diagram_upload())
    write(OUT / "secuencia_descarga.drawio", diagram_download())
    write(OUT / "secuencia_compartir.drawio", diagram_share())


if __name__ == "__main__":
    main()
