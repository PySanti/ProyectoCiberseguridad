# Portal de Gestión de Actualizaciones y Firmwares — versión arreglada

Esta es la **versión segura** de nuestro proyecto de Ciberseguridad (UCAB). Es la misma
página web de antes (el portal de actualizaciones con su login y su panel de admin),
pero con las **dos fallas ya corregidas**. Toda la seguridad la escribimos a mano, sin
usar librerías que la resuelvan solas (así lo pide la materia).

## Qué se arregló

- **A04 – Criptografía:** antes las contraseñas se guardaban con MD5 (débil) y el token
  se podía falsificar. Ahora las contraseñas se protegen con un método lento y con
  "sal" hecho a mano (PBKDF2 + HMAC), y el token va **firmado**: si alguien lo modifica,
  el servidor lo rechaza. La llave secreta ya no está en el código, se pone en una
  variable del sistema.
- **A08 – Integridad:** antes el servidor ejecutaba cualquier paquete que le subieran.
  Ahora revisa que el archivo sea de verdad un `.zip`/`.tar`, comprueba una **firma**
  para saber que es legítimo, y **nunca ejecuta** nada de adentro.

Resultado: el mismo ataque que funcionaba en la rama `version-vulnerable` aquí **ya no
funciona** (eso es la "validación de cierre").

## Las dos ramas

- `version-vulnerable` → la app con las fallas.
- `version-asegurada` → esta, la app ya corregida.

## Con qué está hecho

- **Backend (el servidor):** Python con Flask
- **Base de datos:** SQLite (`portal.db`)
- **Frontend (lo que se ve):** HTML, CSS y plantillas Jinja2

## Cómo levantar la app

Esta versión necesita **una cosa extra**: una llave secreta puesta en una variable del
sistema (`PORTAL_SECRET`). Si no la pones, la app no arranca (a propósito, para no dejar
la llave en el código).

**En Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PORTAL_SECRET = "una-clave-larga-y-cualquiera"
python init_db.py      # crea la base de datos con los usuarios
python app.py          # levanta el servidor
```

**En Linux / la VM (Ubuntu):**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export PORTAL_SECRET='una-clave-larga-y-cualquiera'
python3 init_db.py
python3 app.py
```

Cuando arranque, abre en el navegador: **http://localhost:8080**
(o, si es la VM, `http://<IP_VICTIMA>:8080`)

Para apagar el servidor: `Ctrl + C`.

### Usuarios para entrar

| usuario  | contraseña      | rol           |
|----------|-----------------|---------------|
| operador | operador123     | usuario normal |
| admin    | SuperAdmin2026! | administrador  |

## Probar que el ataque ya NO funciona

Para la parte defensiva de la demo, se corren **los mismos scripts de ataque** de la
carpeta `red-team/` (que están en la rama `version-vulnerable`) contra esta versión, y
se ve que fallan:

- El script que falsifica el token de admin: aquí el token no tiene la firma correcta,
  así que el servidor responde "no autorizado".
- El script que sube el paquete malicioso: se rechaza porque no trae una firma válida, y
  además nada se ejecuta.

## Las rutas de la app (endpoints)

| Método | Ruta             | Qué hace                        | Cómo está protegida       |
|--------|------------------|---------------------------------|---------------------------|
| GET    | `/`              | Pantalla de login               | —                         |
| POST   | `/login`         | Entrar (usa PBKDF2 a mano)      | contraseña con sal        |
| GET    | `/dashboard`     | Panel del usuario               | token firmado con HMAC    |
| GET    | `/admin`         | Panel de carga (solo admin)     | —                         |
| POST   | `/upload-update` | Sube un paquete firmado         | revisa firma + tipo real  |

> Nota: en esta versión ya no existe la ruta `/api/config` (se quitó porque filtraba
> información).
