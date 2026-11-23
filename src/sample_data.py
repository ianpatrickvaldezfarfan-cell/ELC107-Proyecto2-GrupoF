"""Generador determinista de texto en español para la demo y los benchmarks.

Produce un "informe" de longitud dada combinando frases al azar (con semilla),
para tener un texto claro realista (entropía ~4-4.5 bits/byte) sin depender de
archivos externos.
"""

from __future__ import annotations

import random

_FRASES = [
    "El presupuesto consolidado del área de sistemas para la próxima gestión asciende a Bs 1.250.000.",
    "La reunión de directorio aprobó la migración del centro de datos al nuevo proveedor de nube.",
    "Se recomienda rotar las credenciales de acceso de los servidores de producción cada noventa días.",
    "Los resultados de la auditoría interna muestran tres observaciones de severidad media.",
    "El equipo de seguridad detectó intentos de acceso no autorizados desde direcciones externas.",
    "La planilla salarial del personal administrativo se encuentra en revisión por recursos humanos.",
    "El contrato con la empresa de mantenimiento vence el treinta y uno de diciembre.",
    "Se solicita mantener la confidencialidad de este documento hasta su publicación oficial.",
    "La Facultad de Ingeniería en Ciencias de la Computación coordinará la capacitación del personal.",
    "El acta fue firmada por los miembros presentes y se archivará en la secretaría general.",
    "Las copias de respaldo se realizan diariamente y se conservan cifradas durante seis meses.",
    "El plan de continuidad del negocio contempla un tiempo máximo de recuperación de cuatro horas.",
    "Se aprobó la compra de licencias y equipos de red para los laboratorios del segundo piso.",
    "El informe técnico describe la arquitectura de cifrado híbrido con RSA y AES-256-GCM.",
    "Los usuarios deberán verificar las huellas de las claves públicas por un canal independiente.",
    "La próxima sesión ordinaria se realizará el lunes a las ocho de la mañana en la sala de reuniones.",
]
_TITULOS = ["INFORME CONFIDENCIAL", "Resumen ejecutivo", "Antecedentes", "Observaciones",
            "Recomendaciones", "Conclusiones", "Anexo técnico"]


def sample_text(n_bytes: int, seed: int = 107) -> bytes:
    """Texto UTF-8 de exactamente `n_bytes` bytes (se recorta al final, respetando caracteres)."""
    rng = random.Random(seed)
    parts: list[str] = []
    size = 0
    while size < n_bytes + 64:
        if rng.random() < 0.08:
            block = f"\n\n{rng.choice(_TITULOS).upper()}\n"
        else:
            block = " ".join(rng.choice(_FRASES) for _ in range(rng.randint(2, 5))) + "\n"
        parts.append(block)
        size += len(block.encode("utf-8"))
    data = "".join(parts).encode("utf-8")[:n_bytes]
    return data.decode("utf-8", errors="ignore").encode("utf-8").ljust(n_bytes, b" ")
