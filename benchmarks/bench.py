"""Benchmarks de las primitivas implementadas desde cero (Proyecto 2 ELC107 - Grupo F).

Mide:
  1. Generación de claves RSA 1024 / 2048 / 3072 (promedio de N corridas, candidatos probados).
  2. Operaciones RSA: OAEP cifrar/descifrar, PSS firmar/verificar, descifrado con y sin CRT.
  3. Throughput de AES-256-GCM (KB/s) para 10 KB, 100 KB, 1 MB y 5 MB (y SHA-256).
  4. PBKDF2-HMAC-SHA256: tiempo según iteraciones (100.000 y 600.000 se estiman linealmente).
  5. Entropía de Shannon del texto claro vs ciphertext según el tamaño del archivo.

Salida en benchmarks/results/: un CSV por tabla, gráficos PNG y RESULTADOS.md (tablas en Markdown
para el informe técnico).

Uso:
    python benchmarks\\bench.py                 # completo (varios minutos)
    python benchmarks\\bench.py --runs 3        # menos corridas de keygen
    python benchmarks\\bench.py --quick         # versión rápida (verificación)
"""

from __future__ import annotations

import argparse
import csv
import platform
import secrets
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.crypto.gcm import AESGCM  # noqa: E402
from src.crypto.kdf import pbkdf2_hmac_sha256  # noqa: E402
from src.crypto.oaep import oaep_decrypt, oaep_encrypt  # noqa: E402
from src.crypto.pss import pss_sign, pss_verify  # noqa: E402
from src.crypto.rsa_core import KeyGenStats, generate_keypair, rsadp, rsadp_no_crt, rsaep  # noqa: E402
from src.crypto.sha256 import sha256  # noqa: E402
from src.sample_data import sample_text  # noqa: E402
from src.server.compromised_view import expected_random_entropy, printable_ratio, shannon_entropy  # noqa: E402

KB = 1024

# Paleta de referencia (dataviz): series en orden fijo, texto en tinta neutra
SURFACE = "#fcfcfb"
TEXT = "#0b0b0b"
TEXT_2 = "#52514e"
GRID = "#e4e3de"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]
REFERENCE = "#8a8984"


def log(msg: str) -> None:
    print(msg, flush=True)


def timed(fn, *args) -> float:
    t0 = time.perf_counter()
    fn(*args)
    return time.perf_counter() - t0


def fmt_size(n: int) -> str:
    if n >= 1024 * 1024:
        return f"{n / (1024 * 1024):g} MB"
    if n >= 1024:
        return f"{n / 1024:g} KB"
    return f"{n} B"


# ---------------------------------------------------------------------------
# Mediciones
# ---------------------------------------------------------------------------
def bench_keygen(sizes: list[int], runs: int) -> tuple[list[dict], dict[int, object]]:
    rows, keys = [], {}
    for bits in sizes:
        times, cands, mr = [], [], []
        for i in range(runs):
            st = KeyGenStats()
            t0 = time.perf_counter()
            key = generate_keypair(bits, stats=st)
            times.append(time.perf_counter() - t0)
            cands.append(st.prime_stats.candidates)
            mr.append(st.prime_stats.mr_tested)
            keys[bits] = key
            log(f"  RSA-{bits} corrida {i + 1}/{runs}: {times[-1]:.2f} s, {cands[-1]} candidatos")
        rows.append({
            "bits": bits, "corridas": runs,
            "promedio_s": statistics.mean(times), "desv_s": statistics.stdev(times) if runs > 1 else 0.0,
            "min_s": min(times), "max_s": max(times),
            "candidatos_prom": statistics.mean(cands), "miller_rabin_prom": statistics.mean(mr),
        })
    return rows, keys


def bench_rsa_ops(keys: dict[int, object], reps: int) -> list[dict]:
    rows = []
    msg = secrets.token_bytes(32)
    for bits in sorted(b for b in keys if b >= 2048):
        k = keys[bits]
        pub = k.public_key()
        n = reps if bits == 2048 else max(1, reps // 2)
        cts = [oaep_encrypt(pub, msg) for _ in range(n)]
        sigs = [pss_sign(k, msg) for _ in range(n)]
        c_int = rsaep(pub, secrets.randbelow(k.n))
        ops = {
            "OAEP cifrar": lambda: oaep_encrypt(pub, msg),
            "OAEP descifrar": lambda: oaep_decrypt(k, cts[0]),
            "PSS firmar": lambda: pss_sign(k, msg),
            "PSS verificar": lambda: pss_verify(pub, msg, sigs[0]),
            "Descifrado CRT": lambda: rsadp(k, c_int, blinding=False),
            "Descifrado sin CRT": lambda: rsadp_no_crt(k, c_int),
        }
        for name, fn in ops.items():
            ts = [timed(fn) for _ in range(n)]
            rows.append({"bits": bits, "operacion": name, "repeticiones": n,
                         "promedio_ms": statistics.mean(ts) * 1000, "min_ms": min(ts) * 1000})
            log(f"  RSA-{bits} {name:<20} {statistics.mean(ts) * 1000:8.2f} ms")
    return rows


def bench_aes(sizes: list[int]) -> list[dict]:
    rows = []
    for size in sizes:
        data = secrets.token_bytes(size)
        reps = 3 if size <= 100 * KB else 1
        g = AESGCM(secrets.token_bytes(32))
        nonce, aad = secrets.token_bytes(12), b'{"file_id":"bench"}'
        enc, dec = [], []
        for _ in range(reps):
            t0 = time.perf_counter()
            ct, tag = g.encrypt(nonce, data, aad)
            enc.append(time.perf_counter() - t0)
            t0 = time.perf_counter()
            assert g.decrypt(nonce, ct, tag, aad) == data
            dec.append(time.perf_counter() - t0)
        te, td = statistics.mean(enc), statistics.mean(dec)
        rows.append({"tamano": fmt_size(size), "bytes": size, "repeticiones": reps,
                     "cifrar_s": te, "descifrar_s": td,
                     "cifrar_KBps": size / KB / te, "descifrar_KBps": size / KB / td})
        log(f"  AES-256-GCM {fmt_size(size):>7}: cifrar {te:.3f} s ({size / KB / te:,.0f} KB/s), "
            f"descifrar {td:.3f} s ({size / KB / td:,.0f} KB/s)")
    return rows


def bench_sha256(size: int) -> dict:
    data = secrets.token_bytes(size)
    t = timed(sha256, data)
    log(f"  SHA-256 {fmt_size(size)}: {t:.3f} s ({size / KB / t:,.0f} KB/s)")
    return {"tamano": fmt_size(size), "bytes": size, "segundos": t, "KBps": size / KB / t}


def bench_pbkdf2(measured: list[int], estimated: list[int]) -> list[dict]:
    rows = []
    per_iter = []
    for it in measured:
        t = timed(pbkdf2_hmac_sha256, b"passphrase de prueba", secrets.token_bytes(16), it, 32)
        per_iter.append(t / it)
        rows.append({"iteraciones": it, "segundos": t, "tipo": "medido"})
        log(f"  PBKDF2 {it:>7} iteraciones: {t:.2f} s (medido)")
    us = statistics.mean(per_iter)
    for it in estimated:
        rows.append({"iteraciones": it, "segundos": us * it, "tipo": "estimado"})
        log(f"  PBKDF2 {it:>7} iteraciones: {us * it:.1f} s (estimado, {us * 1e6:.0f} µs/iteración)")
    return rows


def bench_entropy(sizes: list[int]) -> list[dict]:
    rows = []
    for size in sizes:
        pt = sample_text(size)
        ct, _ = AESGCM(secrets.token_bytes(32)).encrypt(secrets.token_bytes(12), pt)
        rows.append({
            "tamano": fmt_size(size), "bytes": size,
            "entropia_texto_claro": shannon_entropy(pt), "entropia_ciphertext": shannon_entropy(ct),
            "entropia_esperada_aleatoria": expected_random_entropy(size),
            "imprimibles_texto_claro": printable_ratio(pt), "imprimibles_ciphertext": printable_ratio(ct),
        })
        r = rows[-1]
        log(f"  {fmt_size(size):>7}: texto claro {r['entropia_texto_claro']:.4f}  ciphertext "
            f"{r['entropia_ciphertext']:.4f}  esperada aleatoria {r['entropia_esperada_aleatoria']:.4f}")
    return rows


# ---------------------------------------------------------------------------
# Salida: CSV, Markdown y gráficos
# ---------------------------------------------------------------------------
def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 6) if isinstance(v, float) else v) for k, v in r.items()})


def md_table(headers: list[str], rows: list[list]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def _style_axes(ax, title: str, ylabel: str, xlabel: str = "") -> None:
    ax.set_facecolor(SURFACE)
    ax.set_title(title, loc="left", color=TEXT, fontsize=12, fontweight="bold", pad=12)
    ax.set_ylabel(ylabel, color=TEXT_2)
    if xlabel:
        ax.set_xlabel(xlabel, color=TEXT_2)
    ax.tick_params(colors=TEXT_2, length=0)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.grid(axis="y", color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _legend(ax) -> None:
    leg = ax.legend(frameon=False, loc="upper left", fontsize=9)
    for t in leg.get_texts():
        t.set_color(TEXT)


def make_charts(out: Path, keygen, rsa_ops, aes, pbkdf2, entropy) -> list[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 10, "figure.facecolor": SURFACE})
    files = []

    def save(fig, name):
        p = out / name
        fig.tight_layout()
        fig.savefig(p, dpi=160, facecolor=SURFACE)
        plt.close(fig)
        files.append(p)

    # 1. Generación de claves RSA (una serie: sin leyenda, el título la nombra)
    fig, ax = plt.subplots(figsize=(7, 4))
    labels = [f"RSA-{r['bits']}" for r in keygen]
    means = [r["promedio_s"] for r in keygen]
    err_lo = [r["promedio_s"] - r["min_s"] for r in keygen]
    err_hi = [r["max_s"] - r["promedio_s"] for r in keygen]
    ax.bar(labels, means, width=0.5, color=SERIES[0], edgecolor=SURFACE, linewidth=2)
    ax.errorbar(labels, means, yerr=[err_lo, err_hi], fmt="none", ecolor=TEXT_2, elinewidth=1, capsize=4)
    for x, r in zip(labels, keygen):
        ax.annotate(f"{r['promedio_s']:.2f} s\n({r['candidatos_prom']:.0f} cand.)", (x, r["max_s"]),
                    textcoords="offset points", xytext=(0, 6), ha="center", color=TEXT, fontsize=9)
    ax.set_ylim(0, max(r["max_s"] for r in keygen) * 1.3)
    _style_axes(ax, f"Generación de claves RSA (promedio de {keygen[0]['corridas']} corridas)", "segundos")
    ax.text(1.0, 1.02, "línea vertical = rango mín–máx", transform=ax.transAxes, color=TEXT_2, fontsize=9,
            ha="right", va="bottom")
    save(fig, "rsa_keygen.png")

    # 2. Operaciones RSA (2 series; eje log por el rango ms..decenas de ms)
    if rsa_ops:
        ops = list(dict.fromkeys(r["operacion"] for r in rsa_ops))
        bits_list = sorted({r["bits"] for r in rsa_ops})
        fig, ax = plt.subplots(figsize=(8, 4.2))
        width = 0.38
        all_vals = []
        for i, bits in enumerate(bits_list):
            vals = [next(r["promedio_ms"] for r in rsa_ops if r["bits"] == bits and r["operacion"] == op) for op in ops]
            all_vals += vals
            xs = [j + (i - (len(bits_list) - 1) / 2) * width for j in range(len(ops))]
            ax.bar(xs, vals, width=width, color=SERIES[i], edgecolor=SURFACE, linewidth=2, label=f"RSA-{bits}")
            for x, v in zip(xs, vals):
                ax.annotate(f"{v:.1f}", (x, v), textcoords="offset points", xytext=(0, 3), ha="center",
                            color=TEXT, fontsize=8)
        ax.set_xticks(range(len(ops)))
        ax.set_xticklabels(ops, rotation=15, ha="right")
        ax.set_yscale("log")
        ticks = [t for t in (0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500) if t <= max(all_vals) * 3]
        ax.set_ylim(0.5, max(all_vals) * 2.2)
        ax.set_yticks(ticks)
        ax.set_yticklabels([f"{t:g}" for t in ticks])
        ax.minorticks_off()
        _style_axes(ax, "Operaciones RSA (tiempo promedio, escala logarítmica)", "milisegundos")
        _legend(ax)
        save(fig, "rsa_ops.png")

    # 3. Throughput AES-GCM (2 series)
    fig, ax = plt.subplots(figsize=(7, 4))
    width = 0.38
    xs = range(len(aes))
    for i, (key, label) in enumerate((("cifrar_KBps", "Cifrar"), ("descifrar_KBps", "Descifrar + verificar tag"))):
        ax.bar([x + (i - 0.5) * width for x in xs], [r[key] for r in aes], width=width,
               color=SERIES[i], edgecolor=SURFACE, linewidth=2, label=label)
    ax.set_xticks(list(xs))
    ax.set_xticklabels([r["tamano"] for r in aes])
    ax.set_ylim(0, max(max(r["cifrar_KBps"], r["descifrar_KBps"]) for r in aes) * 1.25)
    _style_axes(ax, "Throughput de AES-256-GCM en Python puro", "KB/s", "tamaño del archivo")
    _legend(ax)
    save(fig, "aes_gcm_throughput.png")

    # 4. PBKDF2 (una serie; lo estimado con textura para no depender solo del color)
    fig, ax = plt.subplots(figsize=(7, 4))
    labels = [f"{r['iteraciones']:,}".replace(",", ".") for r in pbkdf2]
    for lab, r in zip(labels, pbkdf2):
        est = r["tipo"] == "estimado"
        ax.bar(lab, r["segundos"], width=0.55, color=SERIES[0] if not est else SURFACE,
               edgecolor=SERIES[0], hatch="//" if est else None, linewidth=1.5,
               label=("estimado (lineal)" if est else "medido"))
        ax.annotate(f"{r['segundos']:.1f} s", (lab, r["segundos"]), textcoords="offset points",
                    xytext=(0, 4), ha="center", color=TEXT, fontsize=9)
    handles, labs = ax.get_legend_handles_labels()
    uniq = dict(zip(labs, handles))
    ax.legend(uniq.values(), uniq.keys(), frameon=False, loc="upper left", fontsize=9)
    ax.set_ylim(0, max(r["segundos"] for r in pbkdf2) * 1.15)
    _style_axes(ax, "PBKDF2-HMAC-SHA256: tiempo según iteraciones", "segundos", "iteraciones")
    save(fig, "pbkdf2.png")

    # 5. Entropía vs tamaño (2 series + referencia gris punteada)
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    xs = [r["bytes"] for r in entropy]
    ax.plot(xs, [r["entropia_esperada_aleatoria"] for r in entropy], color=REFERENCE, linewidth=1.5,
            linestyle="--", label="esperada para bytes aleatorios")
    ax.plot(xs, [r["entropia_ciphertext"] for r in entropy], color=SERIES[0], linewidth=2, marker="o",
            markersize=6, markeredgecolor=SURFACE, markeredgewidth=2, label="ciphertext AES-256-GCM")
    ax.plot(xs, [r["entropia_texto_claro"] for r in entropy], color=SERIES[1], linewidth=2, marker="s",
            markersize=6, markeredgecolor=SURFACE, markeredgewidth=2, label="texto claro (español)")
    ax.axhline(8, color=GRID, linewidth=1)
    ax.set_xscale("log", base=2)
    ax.set_xticks(xs)
    ax.set_xticklabels([r["tamano"] for r in entropy], rotation=0)
    ax.set_ylim(0, 8.6)
    last = entropy[-1]
    ax.annotate(f"{last['entropia_ciphertext']:.3f}", (xs[-1], last["entropia_ciphertext"]),
                textcoords="offset points", xytext=(0, 8), ha="center", color=TEXT, fontsize=9)
    ax.annotate(f"{last['entropia_texto_claro']:.2f}", (xs[-1], last["entropia_texto_claro"]),
                textcoords="offset points", xytext=(0, 8), ha="center", color=TEXT, fontsize=9)
    _style_axes(ax, "Entropía de Shannon según el tamaño del archivo", "bits por byte", "tamaño")
    ax.legend(frameon=False, loc="lower right", fontsize=9)
    save(fig, "entropy_vs_size.png")
    return files


def write_markdown(out: Path, keygen, rsa_ops, aes, sha, pbkdf2, entropy, elapsed: float) -> Path:
    f2 = lambda v: f"{v:.2f}"  # noqa: E731
    parts = [
        "# Resultados de benchmarks - Proyecto 2 ELC107 (Grupo F)",
        "",
        f"- Fecha: {time.strftime('%Y-%m-%d %H:%M')}",
        f"- Python {platform.python_version()} ({platform.python_implementation()}), "
        f"{platform.system()} {platform.release()}, {platform.machine()}",
        f"- Procesador: {platform.processor() or 'desconocido'}",
        f"- Duración total: {elapsed:.0f} s",
        "- Todas las primitivas son implementaciones propias en Python puro (sin librerías criptográficas).",
        "",
        "## 1. Generación de claves RSA",
        "",
        md_table(["Tamaño", "Corridas", "Promedio (s)", "Desv. (s)", "Mín (s)", "Máx (s)",
                  "Candidatos (prom.)", "Llegan a Miller-Rabin (prom.)"],
                 [[f"RSA-{r['bits']}", r["corridas"], f2(r["promedio_s"]), f2(r["desv_s"]), f2(r["min_s"]),
                   f2(r["max_s"]), f"{r['candidatos_prom']:.0f}", f"{r['miller_rabin_prom']:.0f}"] for r in keygen]),
        "",
        "La criba por primos < 2000 descarta la mayoría de los candidatos sin ninguna exponenciación modular.",
        "",
    ]
    if rsa_ops:
        parts += ["## 2. Operaciones RSA", "",
                  md_table(["Tamaño", "Operación", "Repeticiones", "Promedio (ms)", "Mín (ms)"],
                           [[f"RSA-{r['bits']}", r["operacion"], r["repeticiones"], f2(r["promedio_ms"]),
                             f2(r["min_ms"])] for r in rsa_ops]), ""]
        for bits in sorted({r["bits"] for r in rsa_ops}):
            crt = next(r["promedio_ms"] for r in rsa_ops if r["bits"] == bits and r["operacion"] == "Descifrado CRT")
            no = next(r["promedio_ms"] for r in rsa_ops if r["bits"] == bits and r["operacion"] == "Descifrado sin CRT")
            parts.append(f"- RSA-{bits}: el CRT acelera el descifrado **{no / crt:.1f}x**.")
        parts += ["- Cifrar/verificar es rápido porque e = 65537 tiene solo 17 bits.", ""]
    parts += [
        "## 3. Throughput de AES-256-GCM y SHA-256", "",
        md_table(["Tamaño", "Cifrar (s)", "Cifrar (KB/s)", "Descifrar (s)", "Descifrar (KB/s)"],
                 [[r["tamano"], f"{r['cifrar_s']:.3f}", f"{r['cifrar_KBps']:.0f}", f"{r['descifrar_s']:.3f}",
                   f"{r['descifrar_KBps']:.0f}"] for r in aes]),
        "",
        f"SHA-256 ({sha['tamano']}): {sha['segundos']:.3f} s = {sha['KBps']:.0f} KB/s.",
        "",
        "## 4. PBKDF2-HMAC-SHA256", "",
        md_table(["Iteraciones", "Tiempo (s)", "Tipo"],
                 [[f"{r['iteraciones']:,}".replace(",", "."), f"{r['segundos']:.2f}", r["tipo"]] for r in pbkdf2]),
        "",
        "100.000 es el valor por defecto del sistema; OWASP recomienda 600.000. 10.000 se usa SOLO en la demo.",
        "",
        "## 5. Entropía según el tamaño del archivo", "",
        md_table(["Tamaño", "Texto claro (bits/byte)", "Ciphertext (bits/byte)", "Esperada aleatoria",
                  "Imprimibles texto", "Imprimibles ciphertext"],
                 [[r["tamano"], f"{r['entropia_texto_claro']:.4f}", f"{r['entropia_ciphertext']:.4f}",
                   f"{r['entropia_esperada_aleatoria']:.4f}", f"{r['imprimibles_texto_claro']:.1%}",
                   f"{r['imprimibles_ciphertext']:.1%}"] for r in entropy]),
        "",
        "Con muestras pequeñas la entropía medida es menor aunque los bytes sean perfectamente aleatorios",
        "(con n bytes hay a lo sumo n valores distintos). El ciphertext coincide con el valor esperado",
        "exacto para datos aleatorios del mismo tamaño (conteos Binomial(n, 1/256)).",
        "",
        "## Gráficos", "",
        "![Generación RSA](rsa_keygen.png)", "", "![Operaciones RSA](rsa_ops.png)", "",
        "![AES-GCM](aes_gcm_throughput.png)", "", "![PBKDF2](pbkdf2.png)", "", "![Entropía](entropy_vs_size.png)", "",
    ]
    p = out / "RESULTADOS.md"
    p.write_text("\n".join(parts), encoding="utf-8")
    return p


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Benchmarks de las primitivas criptográficas propias")
    parser.add_argument("--runs", type=int, default=5, help="corridas de generación por tamaño de clave")
    parser.add_argument("--reps", type=int, default=20, help="repeticiones por operación RSA")
    parser.add_argument("--out", type=Path, default=ROOT / "benchmarks" / "results")
    parser.add_argument("--quick", action="store_true", help="versión rápida para verificar el script")
    parser.add_argument("--no-charts", action="store_true")
    args = parser.parse_args(argv)
    args.out.mkdir(parents=True, exist_ok=True)

    if args.quick:
        rsa_sizes, runs, reps = [1024, 2048], 1, 2
        aes_sizes = [10 * KB, 100 * KB]
        pb_measured, pb_estimated = [1000], [10_000, 100_000, 600_000]
        ent_sizes = [64, 1 * KB, 16 * KB]
        sha_size = 100 * KB
    else:
        rsa_sizes, runs, reps = [1024, 2048, 3072], args.runs, args.reps
        aes_sizes = [10 * KB, 100 * KB, 1024 * KB, 5 * 1024 * KB]
        pb_measured, pb_estimated = [1000, 10_000, 20_000], [100_000, 600_000]
        ent_sizes = [64, 256, 1 * KB, 4 * KB, 16 * KB, 64 * KB, 256 * KB, 1024 * KB]
        sha_size = 1024 * KB

    t_start = time.perf_counter()
    log("== 1. Generación de claves RSA ==")
    keygen, keys = bench_keygen(rsa_sizes, runs)
    log("== 2. Operaciones RSA (OAEP, PSS, CRT) ==")
    rsa_ops = bench_rsa_ops(keys, reps)
    log("== 3. AES-256-GCM y SHA-256 ==")
    aes = bench_aes(aes_sizes)
    sha = bench_sha256(sha_size)
    log("== 4. PBKDF2-HMAC-SHA256 ==")
    pbkdf2 = bench_pbkdf2(pb_measured, pb_estimated)
    log("== 5. Entropía según tamaño ==")
    entropy = bench_entropy(ent_sizes)
    elapsed = time.perf_counter() - t_start

    write_csv(args.out / "rsa_keygen.csv", keygen)
    if rsa_ops:
        write_csv(args.out / "rsa_ops.csv", rsa_ops)
    write_csv(args.out / "aes_gcm.csv", aes)
    write_csv(args.out / "sha256.csv", [sha])
    write_csv(args.out / "pbkdf2.csv", pbkdf2)
    write_csv(args.out / "entropia.csv", entropy)
    md = write_markdown(args.out, keygen, rsa_ops, aes, sha, pbkdf2, entropy, elapsed)
    if not args.no_charts:
        for p in make_charts(args.out, keygen, rsa_ops, aes, pbkdf2, entropy):
            log(f"  gráfico: {p}")
    log(f"\nResultados en {args.out} (tablas en {md.name}); duración {elapsed:.0f} s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
