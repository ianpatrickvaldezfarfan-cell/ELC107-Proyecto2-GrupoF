# Arquitectura del sistema

El sistema separa dos zonas de confianza:

- **Equipo del usuario (zona de confianza):** toda la criptografía ocurre aquí. El cliente (CLI o GUI) genera las claves, cifra, firma, descifra y verifica. La clave privada vive en un keystore local cifrado con una clave derivada de la passphrase.
- **Servidor de almacenamiento (no confiable):** solo guarda y entrega bytes cifrados, claves públicas, firmas y claves de sesión *envueltas*. No posee ninguna clave privada ni de sesión. Aun así aplica controles propios (defensa en profundidad): login sin contraseñas por challenge-response, verificación de firmas al subir y control de acceso por destinatario.

```mermaid
flowchart LR
    alice["alice (usuaria)<br>comandos + passphrase"]
    bob["bob (otro usuario)<br>su propio cliente y keystore"]

    subgraph CLIENTE["Equipo del usuario: ZONA DE CONFIANZA"]
        direction TB
        cli["CLI<br>cli.py (argparse)"]
        gui["GUI<br>gui.py (Tkinter)"]
        svc["ClientService (service.py)<br>keygen, register, login, upload,<br>download, share, list, verify, fingerprint<br>pinning de huellas"]
        env["envelope.py<br>cifrado híbrido: sellar, abrir,<br>verificar, re-envolver"]
        ks[("Keystore local ~/.grupof/usuario<br>clave privada cifrada (PBKDF2 + AES-256-GCM)<br>token, contactos, índice de nombres")]
        crypto["src/crypto: Python puro<br>SHA-256, HMAC, PBKDF2, AES-256, GCM<br>RSA (Miller-Rabin, CRT), OAEP, PSS"]
        api["api_client.py (requests)"]
    end

    subgraph SERVIDOR["Servidor de almacenamiento: NO CONFIABLE"]
        direction TB
        app["app.py (Flask)<br>registro con prueba de posesión<br>challenge-response, archivos, compartir<br>directorio de claves públicas"]
        st["storage.py"]
        db[("metadata.sqlite3<br>claves públicas, AAD, nonce, tag, firmas<br>claves de sesión ENVUELTAS, hashes de tokens")]
        blobs[("blobs/*.bin<br>ciphertext AES-256-GCM")]
    end

    atk["Atacante / servidor comprometido<br>solo ve bytes cifrados (entropía ≈ 8 bits/byte)"]

    alice --> cli
    alice --> gui
    cli --> svc
    gui --> svc
    svc --> env --> crypto
    svc --> ks
    svc --> api
    api <-->|"HTTP + JSON: solo datos cifrados,<br>claves públicas y firmas"| app
    app --> st
    st --> db
    st --> blobs
    atk -.->|roba el disco| blobs
    alice <-.->|"verificación de huellas<br>FUERA DE BANDA"| bob
    bob -.->|HTTP| app
```

Versión editable para el informe: [drawio/arquitectura.drawio](drawio/arquitectura.drawio).

## Qué guarda cada lado

| Dato | Cliente | Servidor |
|---|---|---|
| Clave privada RSA | Sí, cifrada en el keystore (PBKDF2 + AES-256-GCM) | **Nunca** |
| Clave de sesión AES-256 en claro | Solo en memoria durante la operación, luego se borra | **Nunca** |
| Clave de sesión envuelta (RSA-OAEP) | Se recibe la propia | Una por destinatario |
| Texto claro y nombre real del archivo | Sí | **Nunca** (el nombre va cifrado dentro del contenido) |
| Ciphertext, nonce, tag, firma | Se generan | Se guardan |
| AAD: file_id, dueño, fecha, tamaño del ciphertext | Se genera | Visible (autenticada, no cifrada) |
| Quién comparte con quién | Sí | Visible (necesario para el control de acceso) |
| Token de sesión | En el keystore (15 min) | Solo su SHA-256 |

## Login sin contraseñas (challenge-response)

```mermaid
sequenceDiagram
    autonumber
    participant C as Cliente de alice
    participant S as Servidor
    C->>S: POST /api/auth/challenge {username}
    S-->>C: nonce aleatorio de 32 bytes (expira en 60 s)
    Note over C: Desbloquea la clave privada (PBKDF2 + AES-GCM)<br>σ = RSA-PSS(priv, "GRUPOF-v1/LOGIN" ‖ usuario ‖ nonce)
    C->>S: POST /api/auth/response {username, nonce, σ}
    Note over S: 1. BORRA el nonce (uso único, anti-replay)<br>2. Comprueba que no expiró<br>3. Verifica σ con la clave pública registrada
    S-->>C: token de sesión aleatorio (15 min), se guarda en el keystore
    Note over C,S: Un replay del mismo (nonce, σ) recibe HTTP 401
```

## Módulos

| Módulo | Responsabilidad |
|---|---|
| `src/crypto/` | Primitivas criptográficas propias (ver tabla en el README) |
| `src/protocol.py` | Bytes exactos que se firman (separación de dominios, prefijos de longitud), AAD canónica, encabezado interno cifrado |
| `src/client/envelope.py` | Cifrado híbrido del archivo: sellar, abrir, verificar, re-envolver |
| `src/client/service.py` | Lógica de cada comando y confianza en claves públicas (pinning) |
| `src/client/keystore.py` | Keystore local cifrado, sesión, contactos, índice de nombres |
| `src/client/cli.py`, `gui.py` | Interfaces de línea de comandos y gráfica (sin criptografía propia) |
| `src/server/app.py` | API Flask: registro, challenge-response, archivos, compartir |
| `src/server/storage.py` | SQLite + blobs en disco |
| `src/server/compromised_view.py` | Vista del atacante que roba el disco del servidor |
