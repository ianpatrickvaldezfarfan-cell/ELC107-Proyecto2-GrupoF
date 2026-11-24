# Secuencia de subida (cifrado híbrido en el cliente)

alice sube `informe.txt` y lo comparte con bob en el mismo paso. Todo el cifrado ocurre en el cliente: el servidor solo recibe bytes cifrados.

```mermaid
sequenceDiagram
    autonumber
    actor U as alice
    participant C as Cliente de alice (CLI / GUI)
    participant K as Keystore local
    participant S as Servidor (no confiable)

    U->>C: upload informe.txt --share-with bob
    C->>S: GET /api/keys/alice y /api/keys/bob
    S-->>C: claves públicas (PEM)
    Note over C: Huella = SHA-256(clave pública) calculada LOCALMENTE.<br>Se compara con la fijada en contacts.json.<br>Si es nueva se confirma fuera de banda. Si cambió: ALERTA MITM.
    C->>K: pedir la clave privada (passphrase)
    Note over K: PBKDF2-HMAC-SHA256(passphrase, sal) → clave AES-256<br>AES-256-GCM descifra la clave privada RSA
    K-->>C: clave privada RSA (en memoria)
    Note over C: 1. K_s (256 bits) y nonce (96 bits) del CSPRNG<br>2. texto = {nombre real, tamaño} ‖ datos<br>3. AAD = {file_id, owner, timestamp, tamaño del ciphertext}<br>4. (C, T) = AES-256-GCM(K_s, nonce, texto, AAD)<br>5. W_alice, W_bob = RSA-OAEP(pub, K_s)<br>6. σ = RSA-PSS(priv_alice, SHA-256(C ‖ nonce ‖ T ‖ AAD))<br>7. K_s se borra de la memoria
    C->>S: POST /api/files (Bearer token)<br>{C, nonce, T, AAD, W_alice, W_bob, σ, huella}
    Note over S: Verifica sesión, AAD (owner = usuario autenticado),<br>firma PSS y huellas de los destinatarios.<br>Guarda el blob cifrado y los metadatos.<br>Nunca ve K_s ni el texto claro.
    S-->>C: 201 Created {file_id}
    C-->>U: OK: file_id (el servidor solo recibió bytes cifrados)
```

Versión editable para el informe: [drawio/secuencia_subida.drawio](drawio/secuencia_subida.drawio).

## Detalles

- **Clave de sesión nueva por archivo:** cada archivo usa su propia K_s y su propio nonce, así que la reutilización de (clave, nonce) en GCM es prácticamente imposible.
- **Nombre del archivo cifrado:** el nombre real y el tamaño original van en un encabezado interno *dentro* del texto que se cifra. La AAD solo lleva lo que el servidor necesita para el control de acceso.
- **Qué se firma:** `SHA-256("GRUPOF-v1/FILE" ‖ LP(C) ‖ LP(nonce) ‖ LP(T) ‖ LP(AAD))`, donde LP antepone la longitud en 8 bytes. Sin los prefijos, bytes del final de un campo podrían "moverse" al siguiente y producir otra tupla con la misma firma.
- **Defensa en profundidad:** el servidor también verifica la firma y que la AAD diga que el dueño es el usuario autenticado. Un usuario no puede subir un archivo "a nombre de" otro.
- **Código:** `src/client/envelope.py::seal`, `src/client/service.py::upload`, `src/server/app.py::upload`.
