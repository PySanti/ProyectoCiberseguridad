# Portal de Gestión de Actualizaciones y Firmwares

Este es nuestro proyecto de la materia de Ciberseguridad (UCAB). Es una página web
que hicimos **a propósito con fallas de seguridad**, para después atacarla y también
arreglarla. La idea es mostrar cómo un sistema mal hecho se puede romper y cómo se
protege.

La app simula un portal donde se suben "actualizaciones" (paquetes de archivos), con
su login y su panel de administrador.

## Qué riesgos presenta

Metimos dos fallas del estándar OWASP:

- **A04 – Fallas de criptografía:** las contraseñas y el token de sesión se guardan
  de forma débil, así que se pueden romper o falsificar.
- **A08 – Fallas de integridad:** el portal acepta y ejecuta los paquetes de
  actualización sin revisar si son de confianza, así que se puede colar un archivo
  malicioso.

## Las dos ramas

- `version-vulnerable` → la app con las fallas (esta rama). El código tiene
  comentarios explicando por qué cada parte es insegura.
- `version-asegurada` → la misma app pero ya arreglada, con la seguridad escrita a
  mano.

## Con qué está hecho

- **Backend (el servidor):** Python con Flask
- **Base de datos:** SQLite (un archivo, `portal.db`)
- **Frontend (lo que se ve):** HTML, CSS y plantillas Jinja2

## Cómo levantar la app

### Opción rápida: probarla en tu PC

Sirve para ver que el login y el panel funcionan. (Ojo: la parte del ataque A08, que
es la de la consola remota, solo funciona bien en Linux; en Windows se ve la web pero
esa parte no corre.)

**En Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python init_db.py      # crea la base de datos con los usuarios
python app.py          # levanta el servidor
```

**En Linux / la VM víctima (Ubuntu):**

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 init_db.py
python3 app.py
```

Cuando arranque, abre en el navegador: **http://localhost:8080**
(si es la VM, usa la IP de la víctima: `http://<IP_VICTIMA>:8080`)

Para apagar el servidor: `Ctrl + C`.

### Usuarios para entrar

| usuario  | contraseña      | rol           |
|----------|-----------------|---------------|
| operador | operador123     | usuario normal |
| admin    | SuperAdmin2026! | administrador  |

Con `admin` aparece el panel para subir actualizaciones.

## Cómo probar el ataque completo

El ataque de verdad (con la consola remota y el robo de la base de datos) se hace
desde una máquina **Kali** contra la **VM víctima**, siguiendo el paso a paso.
Todos los scripts están en la carpeta `red-team/`:

- `recon.sh` → mira qué tiene abierto la víctima
- `exploit_a04.py` → falsifica el token para entrar como admin
- `paquete_malicioso_red_team` → arma el paquete con el código dañino
- `exploit_a08.py` → sube ese paquete
- `listener.sh` → recibe la consola remota en Kali
- `post_exploit.sh` → roba la base de datos
- `crack_hashes.py` → descubre las contraseñas
- `payloads.sh` → todos los comandos juntos

Antes de correrlos hay que poner las IPs reales (`<IP_VICTIMA>` e `<IP_KALI>`) en los
scripts.

## Las rutas de la app (endpoints)

| Método | Ruta             | Qué hace                        | Falla |
|--------|------------------|---------------------------------|-------|
| GET    | `/`              | Pantalla de login               | A04   |
| POST   | `/login`         | Entrar (usa MD5)                | A04   |
| GET    | `/dashboard`     | Panel del usuario               | A04   |
| GET    | `/api/config`    | Muestra config del sistema      | A04   |
| GET    | `/admin`         | Panel de carga (solo admin)     | A08   |
| POST   | `/upload-update` | Sube un paquete `.zip` / `.tar` | A08   |
