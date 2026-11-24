# Secuencia de descarga (verificar antes de entregar)

bob descarga el archivo que alice compartió con él. El orden de las verificaciones importa: **ante cualquier fallo se aborta sin entregar ni un byte** de texto claro.

```mermaid
sequenceDiagram
    autonumber
    actor U as bob
    participant C as Cliente de bob (CLI / GUI)
    participant S as Servidor (no confiable)

    U->>C: download {file_id}
    C->>S: GET /api/files/{file_id} (Bearer token)
    Note over S: ¿bob tiene una clave envuelta para este archivo?<br>No → 404 (no revela si el archivo existe)
    S-->>C: {C, nonce, T, AAD, σ, huella del firmante, W_bob}<br>(solo la clave envuelta de bob)
    C->>S: GET /api/keys/alice
    S-->>C: clave pública de alice
    Note over C: Huella de alice recalculada y comparada con la fijada<br>(si cambió: ALERTA MITM y se aborta)
    Note over C: 1. Verificar σ con RSA-PSS (clave pública de alice)<br>2. Validar la AAD (dueño, file_id, tamaño)<br>3. K_s = RSA-OAEP-Dec(priv_bob, W_bob)<br>4. AES-256-GCM: verificar T y luego descifrar<br>5. Separar el nombre real de los datos y borrar K_s
    alt cualquier verificación falla
        C-->>U: FALLO DE SEGURIDAD: no se entrega ningún dato (código de salida 3)
    else todo es válido
        C-->>U: archivo guardado con su nombre real (escritura atómica)
    end
```

Versión editable para el informe: [drawio/secuencia_descarga.drawio](drawio/secuencia_descarga.drawio).

## Qué detiene cada verificación

| Paso | Si falla | Ataque que detiene |
|---|---|---|
| Huella del dueño = fijada | `TrustError` (alerta MITM) | El servidor sustituye la clave pública del dueño |
| Firma RSA-PSS | `PackageError("firma")` | Alterar ciphertext, nonce, tag o AAD; firmar con otra clave |
| Coherencia de la AAD | `PackageError("metadatos")` | Entregar el paquete de otro archivo |
| RSA-OAEP | `PackageError("clave de sesión")` | Usuario no autorizado con un paquete robado |
| Tag AES-GCM | `PackageError("integridad")` | Cualquier alteración del ciphertext o la AAD (aun sin firma) |

- AES-GCM compara el tag en **tiempo constante** y *antes* de producir texto claro (SP 800-38D §7.2).
- El archivo se escribe primero como `.part` y se renombra solo al final, así que nunca queda un archivo a medias.
- El nombre recibido se sanea (`..\..\evil.dll` se guarda como `evil.dll`; nombres reservados de Windows como `CON` reciben un prefijo).
- **Código:** `src/client/envelope.py::open_package`, `src/client/service.py::download` y `save`.
