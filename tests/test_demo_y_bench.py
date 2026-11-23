"""Verifica que la demo de ataques y el benchmark se ejecutan y producen lo esperado."""

import importlib.util
import secrets
from pathlib import Path

import pytest

from src.server.compromised_view import expected_random_entropy, shannon_entropy

ROOT = Path(__file__).resolve().parent.parent


def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_demo_ataques_todos_bloqueados(capsys, fast_keygen):
    demo = _load(ROOT / "demo" / "demo_ataques.py")
    # 1000 iteraciones solo para que el test sea rápido (la demo real usa 10.000)
    assert demo.main(["--no-color", "--kdf-iters", "1000", "--size-kb", "20"]) == 0
    out = capsys.readouterr().out
    assert "Todos los ataques fueron detenidos" in out
    assert out.count("[BLOQUEADO]") >= 15
    assert "¡NO BLOQUEADO!" not in out


def test_benchmark_rapido(tmp_path):
    bench = _load(ROOT / "benchmarks" / "bench.py")
    assert bench.main(["--quick", "--out", str(tmp_path)]) == 0
    for name in ("rsa_keygen.csv", "rsa_ops.csv", "aes_gcm.csv", "pbkdf2.csv", "entropia.csv",
                 "RESULTADOS.md", "rsa_keygen.png", "aes_gcm_throughput.png", "entropy_vs_size.png"):
        assert (tmp_path / name).exists(), name
    assert "Entropía según el tamaño" in (tmp_path / "RESULTADOS.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("n", [64, 1024, 65536])
def test_entropia_esperada_coincide_con_simulacion(n):
    trials = 300 if n < 4096 else 5
    sim = sum(shannon_entropy(secrets.token_bytes(n)) for _ in range(trials)) / trials
    assert abs(sim - expected_random_entropy(n)) < 0.02
