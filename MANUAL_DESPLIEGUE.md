# Manual de despliegue y uso (Windows)

**ELC107 Criptografía y Seguridad - Proyecto 2 - Grupo F**
Sistema de almacenamiento en la nube con cifrado híbrido Zero-Trust.

Este manual explica, paso a paso y en Windows 10/11 con PowerShell, cómo instalar el sistema, iniciar el servidor, usar la línea de comandos y la interfaz gráfica, ejecutar las pruebas, los benchmarks y la demo de ataques, y dejar el entorno limpio antes de grabar la demostración.

> **Convención:** todos los comandos se ejecutan en **PowerShell**, desde la carpeta raíz del proyecto (`ELC107-Proyecto2-GrupoF`), con el entorno virtual activado (sección 2).

## Índice

1. [Requisitos](#1-requisitos)
2. [Instalación](#2-instalación)
3. [Iniciar el servidor](#3-iniciar-el-servidor)
4. [Uso de la línea de comandos (CLI)](#4-uso-de-la-línea-de-comandos-cli)
5. [Uso de la interfaz gráfica (GUI)](#5-uso-de-la-interfaz-gráfica-gui)
6. [Vista del servidor comprometido](#6-vista-del-servidor-comprometido)
7. [Pruebas automatizadas](#7-pruebas-automatizadas)
8. [Benchmarks](#8-benchmarks)
9. [Demo de ataques](#9-demo-de-ataques)
10. [Limpiar el entorno antes de la demo](#10-limpiar-el-entorno-antes-de-la-demo)
11. [Diagramas para el informe](#11-diagramas-para-el-informe)
12. [Referencia: opciones, variables y archivos](#12-referencia-opciones-variables-y-archivos)
13. [Solución de problemas](#13-solución-de-problemas)
14. [Guion sugerido para la defensa](#14-guion-sugerido-para-la-defensa)

---

## 1. Requisitos

| Requisito | Detalle |
|---|---|
| Sistema operativo | Windows 10 u 11 (también funciona en Linux/macOS cambiando las rutas) |
| Python | 3.11 o superior (probado con **3.14**), instalado desde python.org con las opciones *Add python.exe to PATH* y *tcl/tk and IDLE* (necesaria para la GUI) |
| Git | Para clonar el repositorio (opcional si se descarga el ZIP) |
| Espacio | ≈ 200 MB (entorno virtual + dependencias) |
| Red | Solo para instalar dependencias; el sistema funciona en `127.0.0.1` |

Dependencias (ninguna criptográfica en tiempo de ejecución):

- `requirements.txt`: `flask` (servidor), `requests` (cliente HTTP) y `matplotlib` (gráficos de los benchmarks).
- `requirements-dev.txt`: además `pytest` y `cryptography`. Esta última se usa **solo dentro de `tests/`** para validar nuestras implementaciones de forma cruzada.

## 2. Instalación

### 2.1 Obtener el proyecto

```powershell
git clone <URL-del-repositorio> ELC107-Proyecto2-GrupoF
cd ELC107-Proyecto2-GrupoF
```

(O descomprima el ZIP y abra PowerShell en esa carpeta.)

### 2.2 Crear y activar el entorno virtual

```powershell
py -m venv .venv                 # o: python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

El prompt mostrará `(.venv)`. Si PowerShell bloquea el script de activación ("la ejecución de scripts está deshabilitada"):

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

y vuelva a activar el entorno. Alternativa sin activar: anteponer `.\.venv\Scripts\python.exe` a cada comando.

### 2.3 Instalar dependencias

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt    # incluye pytest y cryptography (para las pruebas)
# o solo lo necesario para ejecutar:  python -m pip install -r requirements.txt
```

### 2.4 Verificar la instalación

```powershell
python -m pytest -m "not slow"
```

Debe terminar con todas las pruebas en verde (`... passed`), en aproximadamente 1 minuto.

## 3. Iniciar el servidor

Abra una **terminal dedicada** (con el entorno activado) y déjela abierta:

```powershell
python servidor.py
```

Salida esperada:

```
================================================================
  Servidor Zero-Trust - Grupo F (ELC107)
  Datos en: C:\...\ELC107-Proyecto2-GrupoF\server_data
  Escuchando en http://127.0.0.1:5000
  Este servidor NO posee claves privadas ni claves de sesión.
================================================================
```

Comprobación desde otra terminal:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/health
```

Opciones:

| Opción | Por defecto | Uso |
|---|---|---|
| `--port N` | 5000 | Otro puerto (si el 5000 está ocupado) |
| `--host H` | 127.0.0.1 | Interfaz de escucha |
| `--data-dir DIR` | `server_data` | Carpeta de la base SQLite y los blobs cifrados |
| `--no-compromised-view` | (activada) | Desactiva el endpoint de demostración `/api/admin/compromised-view` |

Para detener el servidor: `Ctrl + C` en su terminal.

> Si usa otro puerto, indíquelo también al cliente: `--server http://127.0.0.1:5055` o `$env:GRUPOF_SERVER = "http://127.0.0.1:5055"`.

## 4. Uso de la línea de comandos (CLI)

### 4.1 Conceptos

- **Usuario local:** cada comando indica el usuario con `--user` (o la variable `GRUPOF_USER`). Cada usuario tiene su propia carpeta de keystore, así que se pueden simular varios usuarios en la misma PC.
- **Keystore:** `%USERPROFILE%\.grupof\<usuario>\` (o la carpeta indicada con `--home` / `GRUPOF_HOME`). Contiene la clave privada **cifrada**, la clave pública, el token de sesión, los contactos (huellas fijadas) y un índice local de nombres de archivo.
- **Passphrase:** se pide sin eco cuando el comando necesita la clave privada (keygen, register, login, upload, download, share, verify). `list` y `verify --signature-only` **no** la piden: usan el token guardado por `login`.
- **Derivación de la clave:** desbloquear la clave privada aplica PBKDF2-HMAC-SHA256. Con 100.000 iteraciones (valor por defecto) tarda ≈ 25 s en Python puro; con 10.000, ≈ 2,5 s.

> ⚠️ **Solo para la demostración:** los ejemplos usan `--kdf-iters 10000` para que la demo en vivo sea ágil. **No es un valor seguro para uso real:** el valor por defecto del sistema es 100.000 y OWASP recomienda 600.000. El número de iteraciones queda guardado en cada keystore.

Se puede usar `python grupof.py ...` o, de forma equivalente, `python -m src.client.cli ...`. Las opciones globales (`--user`, `--server`, `--home`, `--no-color`) pueden ir antes o después del comando.

### 4.2 Recorrido completo con alice, bob y carol

**Paso 1: crear las identidades** (pide la passphrase dos veces; mínimo 8 caracteres):

```powershell
python grupof.py --user alice keygen --kdf-iters 10000
python grupof.py --user bob   keygen --kdf-iters 10000
python grupof.py --user carol keygen --kdf-iters 10000
```

Cada comando genera un par RSA-2048 (Miller-Rabin + criba), cifra la clave privada y muestra la **huella** de la clave pública (16 grupos de 4 caracteres). Para RSA-3072: `--bits 3072`.

**Paso 2: registrarse en el servidor** (se envía solo la clave pública, junto con una firma que prueba la posesión de la privada):

```powershell
python grupof.py --user alice register
python grupof.py --user bob   register
python grupof.py --user carol register
```

**Paso 3: iniciar sesión** (challenge-response; el token queda guardado 15 minutos):

```powershell
python grupof.py --user alice login
python grupof.py --user bob   login
python grupof.py --user carol login
```

**Paso 4: alice sube un archivo pequeño y lo comparte con bob:**

```powershell
"Acta de la reunión del Grupo F: presupuesto confidencial." | Set-Content -Encoding utf8 memo.txt
python grupof.py --user alice upload memo.txt --share-with bob
```

La primera vez que alice usa la clave de bob, el cliente muestra su huella y pregunta si se verificó **fuera de banda** (en persona o por teléfono). Compárela con la que mostró `keygen` de bob y responda `s`. En scripts no interactivos se puede usar `--yes` (menos seguro). El comando imprime el `file_id`.

> `memo.txt`, `descargas/` y `server_data/` están en el `.gitignore`: no se suben al repositorio.

**Paso 5: listar** (no pide passphrase):

```powershell
python grupof.py --user alice list
python grupof.py --user bob   list      # bob ve el archivo; el nombre aparece cifrado hasta que lo descarga
python grupof.py --user carol list      # carol no ve nada
```

**Paso 6: bob descarga y verifica.** Basta con los primeros 6 u 8 caracteres del `file_id`:

```powershell
python grupof.py --user bob download 3f2a91c0 --out descargas
python grupof.py --user bob verify 3f2a91c0
```

El cliente verifica la firma RSA-PSS, la AAD y el tag AES-GCM. Solo si todo es válido escribe `descargas\memo.txt` con su nombre real.

**Paso 7: compartir después de subir** (solo el dueño puede):

```powershell
python grupof.py --user alice share 3f2a91c0 --with carol
python grupof.py --user carol download 3f2a91c0 --out descargas
```

**Paso 8: huellas.**

```powershell
python grupof.py --user alice fingerprint                 # mi huella
python grupof.py --user bob   fingerprint alice           # huella de alice según el servidor + estado del pinning
python grupof.py --user bob   fingerprint alice --trust   # marcarla como verificada fuera de banda
python grupof.py --user bob   fingerprint alice --expect "AB12 CD34 ..."   # comparar con la huella dictada; si coincide, la marca como verificada
```

### 4.3 Resumen de comandos

| Comando | Necesita passphrase | Opciones |
|---|---|---|
| `keygen` | Sí (nueva, dos veces) | `--bits 2048\|3072`, `--kdf-iters N`, `--force` (reemplaza el keystore) |
| `register` | Sí | - |
| `login` | Sí | - |
| `upload ARCHIVO` | Sí | `--share-with u1,u2`, `--yes` |
| `list` | No | - |
| `download FILE_ID` | Sí | `--out CARPETA_O_ARCHIVO`, `--force` (sobrescribir) |
| `share FILE_ID` | Sí | `--with USUARIO`, `--yes` |
| `verify FILE_ID` | Sí (No con `--signature-only`) | `--signature-only` |
| `fingerprint [USUARIO]` | No | `--trust`, `--expect HUELLA` |

Códigos de salida: `0` = correcto, `1` = error, `2` = uso incorrecto, **`3` = fallo de seguridad** (firma o tag inválidos, clave no autorizada, huella cambiada). Ante un fallo de seguridad **no se escribe ningún archivo**.

## 5. Uso de la interfaz gráfica (GUI)

La GUI (Tkinter, sin dependencias extra) usa exactamente la misma lógica que la CLI: no contiene criptografía propia. Con el servidor iniciado:

```powershell
python grupof_gui.py                    # pantalla inicial: elegir o crear usuario
python grupof_gui.py --user alice       # abre directamente a alice
```

### 5.1 Primer uso de un usuario

1. En la pantalla inicial verifique el **Servidor** (`http://127.0.0.1:5000`).
2. Pulse **Crear usuario nuevo…**: escriba el usuario y la passphrase (dos veces), elija las **iteraciones de PBKDF2** (para la demo: *10.000 (SOLO demostración)*; el diálogo lo advierte en color) y el tamaño RSA. Pulse **Generar**.
3. Pulse **Registrar** (la primera vez) y luego **Iniciar sesión**.

Para un usuario existente: elíjalo en la lista, pulse **Abrir usuario** e ingrese su passphrase. La clave privada se desbloquea en segundo plano y queda en memoria mientras la ventana esté abierta. **Bloquear clave** la descarta y la passphrase se volverá a pedir cuando haga falta.

### 5.2 Dos usuarios a la vez (alice y bob)

- Ejecute `python grupof_gui.py` en **dos terminales**, o pulse **Abrir otra ventana** dentro de la GUI.
- Cada ventana es un proceso independiente: en una abra a alice y en la otra a bob. El título de cada ventana muestra el usuario.

### 5.3 Operaciones

| Botón | Qué hace |
|---|---|
| **Generar claves** | Crea (o reemplaza, con advertencia) el par RSA y el keystore, con selector de iteraciones |
| **Registrar** | Envía la clave pública con prueba de posesión |
| **Iniciar sesión** | Challenge-response; guarda el token (15 min) |
| **⬆ Subir archivo** | Elegir el archivo y luego los destinatarios con casillas |
| **⬇ Descargar** | Verifica y descifra el archivo seleccionado; luego pregunta dónde guardarlo (si quita la extensión al renombrar, se conserva la original). También con doble clic en la fila |
| **Compartir** | Solo para archivos propios: elegir el destinatario |
| **✔ Verificar firma** | Firma RSA-PSS + AAD + tag AES-GCM, sin guardar el archivo |
| **Ver mi huella** | Muestra y copia su huella; consulta la de otro usuario y permite marcarla como verificada |
| **⟳ Actualizar lista** | Refresca la tabla (no pide passphrase) |
| **Bloquear clave**, **Cambiar usuario**, **Abrir otra ventana** | Gestión de la sesión y de las ventanas |

**Tabla de archivos:** nombre (si se conoce; si no, *nombre cifrado: descárguelo*), `file_id` corto, dueño, tamaño, fecha y con quién está compartido.

**Registro de operaciones** (panel inferior): muestra paso a paso lo que ocurre criptográficamente. Por ejemplo, al subir:

```
══ Subir «presupuesto.txt» compartido con bob ══
  ▸ Clave de sesión AES-256 generada (256 bits del CSPRNG del sistema operativo)
  ▸ Nonce GCM de 96 bits generado: de50e3f57e74...
  ▸ Encabezado interno con el nombre real ('presupuesto.txt') y el tamaño original: irá CIFRADO
  ▸ Contenido cifrado con AES-256-GCM: 6.256 bytes (tag: 610307440d96d034...)
  ▸ Clave de sesión envuelta con RSA-OAEP-SHA256 para bob (huella AB193E7B...)
  ▸ Clave de sesión en claro borrada de la memoria (sobrescrita con ceros)
  ▸ Firma RSA-PSS creada sobre SHA-256(ciphertext‖nonce‖tag‖AAD)
  ▸ Enviado al servidor: solo datos cifrados (ciphertext, nonce, tag, AAD, claves envueltas, firma)
```

**Diálogos de seguridad:**

- **Huella nueva:** al compartir con alguien por primera vez se muestra su huella y se pregunta si se verificó fuera de banda.
- **¡POSIBLE ATAQUE MITM!:** diálogo rojo si el servidor devuelve una clave pública distinta de la fijada; no se cifra nada para esa clave.
- **FALLO DE SEGURIDAD:** diálogo rojo si la firma o el tag no son válidos; indica el paso que falló y que no se entregó ningún dato.

Las operaciones lentas (PBKDF2, generación de claves, cifrado) se ejecutan en segundo plano con una barra de progreso, así que la ventana no se congela.

## 6. Vista del servidor comprometido

Muestra lo que vería un atacante que roba todo el disco del servidor (se puede ejecutar con el servidor detenido):

```powershell
python -m src.server.compromised_view --data-dir server_data
```

Para cada archivo: metadatos visibles (file_id, dueño, fecha y tamaño, **sin el nombre real**), inicio del ciphertext, entropía de Shannon comparada con la esperada para bytes aleatorios del mismo tamaño, porcentaje de bytes imprimibles y claves envueltas. Al final busca material secreto en todo el disco (resultado esperado: **NINGUNO**).

También disponible por HTTP con el servidor en marcha: `http://127.0.0.1:5000/api/admin/compromised-view`.

## 7. Pruebas automatizadas

```powershell
python -m pytest                          # suite completa (≈ 2 min; incluye pruebas lentas)
python -m pytest -m "not slow"            # sin las lentas (≈ 1 min)
python -m pytest tests/test_gcm.py -v     # un archivo, con detalle
python -m pytest -k carmichael -v         # por nombre
```

Las pruebas no necesitan el servidor iniciado: lo levantan en memoria con datos temporales. Durante las pruebas `GRUPOF_KDF_ITERS` se fija en 1000 para que sean rápidas (`tests/conftest.py`).

## 8. Benchmarks

```powershell
python benchmarks\bench.py              # completo (≈ 1 min)
python benchmarks\bench.py --runs 10    # más corridas de generación de claves
python benchmarks\bench.py --quick      # verificación rápida (≈ 5 s)
```

Mide la generación de claves RSA 1024/2048/3072 (promedio de N corridas y candidatos probados), OAEP, PSS, CRT frente a sin CRT, el throughput de AES-256-GCM (10 KB, 100 KB, 1 MB y 5 MB), SHA-256, PBKDF2 y la entropía según el tamaño del archivo. Los resultados quedan en `benchmarks\results\`: un CSV por tabla, gráficos PNG y `RESULTADOS.md` con tablas listas para el informe.

## 9. Demo de ataques

```powershell
python demo\demo_ataques.py               # completa (≈ 30 s); NO necesita el servidor iniciado
python demo\demo_ataques.py --pausa       # espera ENTER entre ataques (recomendado para presentar)
python demo\demo_ataques.py --solo a,e,f  # solo algunos ataques
```

Crea alice, bob y carol con **10.000 iteraciones (solo demostración)** en un servidor en memoria con datos temporales; alice sube un informe de ≈ 50 KB y lo comparte con bob. Luego ejecuta:

| Ataque | Qué se muestra |
|---|---|
| a) 1 bit del ciphertext | Falla la firma PSS; y aun sin firma, falla el tag GCM (tag recibido frente a recalculado) |
| b) AAD alterada | Igual que a) |
| c) Firma falsificada | Firma de otra clave, huella suplantada, bytes aleatorios; el servidor rechaza un archivo "a nombre de" otro |
| d) Usuario no autorizado | 404 del servidor; con un paquete robado, OAEP no se puede desenvolver |
| e) Replay del login | El mismo (nonce, firma) recibe 401; la firma vieja no sirve para un nonce nuevo |
| f) Servidor comprometido | Entropía texto claro (≈ 4,4) frente a ciphertext (≈ 8), tabla por tamaño, nombre real ilegible |
| g) Extra: MITM | El servidor sustituye la clave de bob y el cliente de alice lo detecta |

Al final muestra un resumen con todos los ataques **BLOQUEADOS**.

> **Contra el servidor real:** `python demo\demo_ataques.py --server http://127.0.0.1:5000`. En este modo la demo **registra usuarios reales en ese servidor**, con un sufijo aleatorio (por ejemplo `alice_7d42`, `bob_7d42`, `carol_7d42`), y sube un archivo. Para quitarlos después, use el script de la sección 10. El ataque g) solo funciona en el modo por defecto (en memoria).

## 10. Limpiar el entorno antes de la demo

`scripts\reset_demo.py` borra, **previa confirmación**, la carpeta de datos del servidor (`server_data`) y los keystores locales de los usuarios indicados, para empezar la grabación desde cero.

**Paso 1: detenga el servidor** (`Ctrl + C` en su terminal) y cierre las ventanas de la GUI. El script se niega a continuar si el servidor responde, y Windows no permite borrar la base de datos abierta.

**Paso 2: vea qué se borraría** (no borra nada):

```powershell
python scripts\reset_demo.py --users alice,bob,carol,alice_7d42,bob_7d42,carol_7d42 --dry-run
```

Muestra los usuarios registrados y los archivos por dueño en `server_data`, y qué keystores existen en esta PC.

**Paso 3: limpie** (pide escribir `si` para confirmar):

```powershell
python scripts\reset_demo.py --users alice,bob,carol,alice_7d42,bob_7d42,carol_7d42
```

| Opción | Uso |
|---|---|
| `--users u1,u2` | Keystores a borrar (por defecto `alice,bob,carol`). Los usuarios con sufijo creados por la demo con `--server` no tienen keystore local, pero se eliminan del servidor al borrar `server_data` |
| `--data-dir DIR` | Carpeta de datos del servidor (por defecto `server_data`) |
| `--home DIR` | Carpeta de keystores (por defecto `GRUPOF_HOME` o `%USERPROFILE%\.grupof`) |
| `--solo-keystores` / `--solo-servidor` | Limpiar solo una de las dos partes |
| `--descargas` | Borrar también la carpeta `descargas\` del proyecto |
| `--dry-run` | Mostrar sin borrar |
| `--yes` | No pedir confirmación |
| `--server URL` | Servidor cuya ejecución se comprueba (por defecto `http://127.0.0.1:5000`) |

Medidas de seguridad del propio script: solo borra una carpeta de datos que contenga `metadata.sqlite3` o `blobs/`, y solo keystores con nombres de usuario válidos (sin rutas como `..`).

**Paso 4:** vuelva a iniciar el servidor (`python servidor.py`) y siga la sección 4 o la 5.

## 11. Diagramas para el informe

- Mermaid (se ven en GitHub/VS Code): `docs\arquitectura.md`, `docs\secuencia_subida.md`, `docs\secuencia_descarga.md`, `docs\secuencia_compartir.md`.
- draw.io (editables, para exportar como imagen): `docs\drawio\*.drawio`. Ábralos en <https://app.diagrams.net> o en draw.io Desktop y use *Archivo → Exportar como → PNG* (escala 200 %, fondo blanco).
- Si cambia el contenido: `python docs\drawio\generar_drawio.py` (regenera los 4 archivos y sobrescribe los ajustes manuales).

## 12. Referencia: opciones, variables y archivos

### Variables de entorno

| Variable | Efecto |
|---|---|
| `GRUPOF_USER` | Usuario por defecto de la CLI/GUI (en lugar de `--user`) |
| `GRUPOF_SERVER` | URL del servidor (por defecto `http://127.0.0.1:5000`) |
| `GRUPOF_HOME` | Carpeta base de keystores (por defecto `%USERPROFILE%\.grupof`) |
| `GRUPOF_KDF_ITERS` | Iteraciones de PBKDF2 por defecto para keystores **nuevos** (por defecto 100.000; las pruebas usan 1000) |
| `GRUPOF_PASSPHRASE` | **Solo para demostraciones automatizadas:** la CLI/GUI toma la passphrase de aquí y lo avisa. No la use en uso real |
| `NO_COLOR` | Desactiva los colores de la CLI |

Ejemplo (válido solo para la terminal actual):

```powershell
$env:GRUPOF_SERVER = "http://127.0.0.1:5055"
Remove-Item Env:GRUPOF_SERVER        # quitarla
```

### Archivos y carpetas que se generan

| Ruta | Contenido | ¿En git? |
|---|---|---|
| `server_data\metadata.sqlite3` | Usuarios, claves públicas, AAD, firmas, claves envueltas, challenges, hashes de tokens | No |
| `server_data\blobs\*.bin` | Ciphertext AES-256-GCM | No |
| `%USERPROFILE%\.grupof\<usuario>\private_key.enc.json` | Clave privada **cifrada** + parámetros de PBKDF2 | No |
| `...\<usuario>\public_key.pem` | Clave pública (formato GRUPOF) | No |
| `...\<usuario>\session.json` | Token de sesión (15 min) | No |
| `...\<usuario>\contacts.json` | Huellas fijadas de otros usuarios | No |
| `...\<usuario>\files_index.json` | `file_id` → nombre real (solo local) | No |
| `benchmarks\results\` | CSV, PNG y RESULTADOS.md | Sí |
| `descargas\`, `memo.txt` | Archivos de los ejemplos | No |

## 13. Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| `Activate.ps1 no se puede cargar... la ejecución de scripts está deshabilitada` | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, o use `.\.venv\Scripts\python.exe` directamente |
| `python` no se reconoce | Reinstale Python marcando *Add python.exe to PATH*, o use `py` |
| `ModuleNotFoundError: flask` (u otro) | El entorno virtual no está activado o faltan dependencias: `.\.venv\Scripts\Activate.ps1` y `python -m pip install -r requirements-dev.txt` |
| `No module named 'src'` | Ejecute los comandos desde la carpeta raíz del proyecto |
| El servidor no arranca: *address already in use* / *solo se permite un uso de cada dirección de socket* | El puerto 5000 está ocupado, a menudo por otro servidor del proyecto que quedó abierto. Ver quién lo usa: `Get-NetTCPConnection -LocalPort 5000 -State Listen \| Select OwningProcess` y luego `Get-Process -Id <PID>`. Ciérrelo o use otro puerto: `python servidor.py --port 5055` y en el cliente `--server http://127.0.0.1:5055` |
| ⚠️ El cliente habla con un servidor distinto al esperado | Si inicia un segundo servidor en un puerto ocupado, este falla y el cliente se conecta al que ya estaba. Compruebe siempre el mensaje de inicio del servidor y la carpeta de datos |
| `no se pudo conectar con el servidor ... (¿está iniciado?)` | Inicie `python servidor.py` o revise `--server` / `GRUPOF_SERVER` |
| `passphrase incorrecta o keystore alterado` | Passphrase equivocada (distingue mayúsculas), o el archivo del keystore fue modificado |
| `no hay sesión activa ... ejecute 'login'` | El token dura 15 minutos: vuelva a ejecutar `login` (o **Iniciar sesión** en la GUI) |
| `usuario no encontrado` al hacer login | Falta `register`, o se limpió `server_data`: vuelva a registrarse |
| `el usuario o la clave pública ya están registrados` (409) | Ese nombre ya existe en el servidor. Use otro nombre o limpie el entorno (sección 10) |
| `ya existe un keystore para 'alice'` | Use `keygen --force` (perderá el acceso a los archivos anteriores) o limpie con `reset_demo.py` |
| `¡ALERTA! la clave pública de 'bob' CAMBIÓ` (código 3) | El servidor devuelve una clave distinta de la fijada: **posible ataque MITM**. Si bob regeneró sus claves de forma legítima, verifique la nueva huella con él y borre su entrada de `contacts.json` |
| `FALLO DE SEGURIDAD - firma: ...` (código 3) | El archivo o sus metadatos fueron alterados en el servidor; no se entregó ningún dato |
| `no se pudo desenvolver con su clave privada (no autorizado)` | El archivo no fue compartido con ese usuario |
| `solo el dueño puede compartir el archivo` | Solo el dueño puede ejecutar `share` |
| Los comandos tardan varios segundos | Es PBKDF2 en Python puro (≈ 0,25 ms por iteración). Esperado; para la demo use `--kdf-iters 10000` |
| Caracteres extraños (Ã±, cuadros) en la consola | Use Windows Terminal, o ejecute `chcp 65001` antes. Para quitar colores: `--no-color` |
| La GUI no abre: `No module named 'tkinter'` | Reinstale Python marcando *tcl/tk and IDLE* |
| La GUI se ve muy pequeña o muy grande | Se adapta al escalado de Windows; puede redimensionar la ventana y el divisor entre la tabla y el registro |
| `reset_demo.py`: `hay un servidor respondiendo` | Detenga el servidor (`Ctrl + C`) antes de limpiar |
| `reset_demo.py`: `archivo en uso` | Cierre el servidor y las ventanas de la GUI, y vuelva a intentarlo |
| Windows Defender pregunta por el acceso a la red al iniciar el servidor | Permita el acceso en *redes privadas*; el servidor escucha solo en `127.0.0.1` |

## 14. Guion sugerido para la defensa

1. **Preparar** (antes de presentar): detener servidores, `python scripts\reset_demo.py --dry-run` y luego la limpieza; `python servidor.py`.
2. **Pruebas:** `python -m pytest -m "not slow"`, mostrando que los vectores oficiales y la validación cruzada pasan, y `tests/test_politica_sin_cajas_negras.py` (sin librerías criptográficas en `src/`).
3. **Flujo con la GUI:** dos ventanas (alice y bob, 10.000 iteraciones), registrar, iniciar sesión, subir compartiendo con bob, mostrar el registro de operaciones; bob descarga.
4. **Servidor comprometido:** `python -m src.server.compromised_view --data-dir server_data` (el nombre del archivo no es legible; entropía ≈ 8).
5. **Ataques:** `python demo\demo_ataques.py --pausa`.
6. **Rendimiento:** abrir `benchmarks\results\RESULTADOS.md` y los gráficos.
7. **Código:** recorrer `src/crypto/` (comentarios con referencias a FIPS/RFC) y los diagramas de `docs/`.
