# Documentación técnica

| Documento | Contenido |
|---|---|
| [arquitectura.md](arquitectura.md) | Zonas de confianza, módulos, qué guarda cada lado, login challenge-response |
| [secuencia_subida.md](secuencia_subida.md) | Cifrado híbrido en el cliente y subida |
| [secuencia_descarga.md](secuencia_descarga.md) | Verificación (firma → AAD → OAEP → GCM) y descarga |
| [secuencia_compartir.md](secuencia_compartir.md) | Re-envoltura local de la clave de sesión |
| [drawio/](drawio/) | Los 4 diagramas en formato draw.io, para exportarlos como imagen al informe |
| [capturas/](capturas/) | Capturas de pantalla para el README y el informe (pendientes) |

Los diagramas Mermaid se ven directamente en GitHub y en VS Code (con la vista previa de Markdown).

## Exportar los diagramas draw.io como imagen

1. Abrir el `.drawio` en <https://app.diagrams.net>, en draw.io Desktop o con la extensión *Draw.io Integration* de VS Code.
2. *Archivo → Exportar como → PNG* (o SVG/PDF). Para el informe se recomienda PNG con escala 200 % y fondo blanco.

Los `.drawio` se generan con un script, así que cualquier cambio de contenido conviene hacerlo allí y regenerarlos:

```powershell
python docs\drawio\generar_drawio.py
```

Si se ajustan a mano en draw.io (posiciones, colores), no vuelva a ejecutar el script o se perderán esos cambios.
