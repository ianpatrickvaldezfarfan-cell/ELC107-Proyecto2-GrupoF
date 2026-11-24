# Secuencia de compartir (re-envoltura local de la clave de sesión)

alice comparte con bob un archivo que ya subió. El archivo **no se vuelve a cifrar**: alice desenvuelve localmente la clave de sesión y la envuelve de nuevo con la clave pública de bob. El servidor nunca ve la clave de sesión.

```mermaid
sequenceDiagram
    autonumber
    actor A as alice (dueña)
    participant C as Cliente de alice
    participant S as Servidor (no confiable)
    actor B as bob

    A->>C: share {file_id} --with bob
    C->>S: GET /api/files/{file_id}
    S-->>C: paquete con W_alice
    C->>S: GET /api/keys/bob
    S-->>C: clave pública de bob
    Note over C: Primera vez: se muestra la huella de bob y se confirma<br>que se verificó fuera de banda. Luego queda fijada.<br>Si difiere de la fijada: ALERTA MITM.
    Note over C: 1. Verificar σ del propio archivo<br>2. K_s = RSA-OAEP-Dec(priv_alice, W_alice)<br>3. Comprobar el tag GCM con K_s (es la clave correcta)<br>4. W_bob = RSA-OAEP(pub_bob, K_s)<br>5. Borrar K_s
    C->>S: POST /api/files/{file_id}/share {bob, huella, W_bob}
    Note over S: Solo el dueño puede compartir.<br>La huella debe coincidir con la registrada.<br>Guarda W_bob. NUNCA ve K_s.
    S-->>C: destinatarios: [alice, bob]
    C-->>A: compartido
    Note over S,B: bob ya puede descargar el archivo (ver secuencia de descarga)
```

Versión editable para el informe: [drawio/secuencia_compartir.drawio](drawio/secuencia_compartir.drawio).

## Detalles

- **Por qué se verifica el tag antes de re-envolver:** si alguien alterara `W_alice` en el servidor, OAEP fallaría. Pero el tag GCM garantiza además que la clave obtenida es exactamente la que autentica este archivo, así que nunca se comparte una clave equivocada.
- **Por qué importa la huella:** si el servidor entregara su propia clave pública en lugar de la de bob, alice envolvería K_s para el atacante. El *pinning* de huellas y la verificación fuera de banda lo impiden (ataque g de la demo).
- **Limitación:** dejar de compartir no está implementado. Revocar el acceso de verdad exigiría volver a cifrar el archivo con una K_s nueva, porque bob pudo haber guardado la anterior.
- **Código:** `src/client/envelope.py::rewrap_for`, `src/client/service.py::share`, `src/server/app.py::share`.
