# Portal de Gestión de Actualizaciones y Firmwares

Proyecto académico de Ciberseguridad (UCAB). App web **intencionalmente
vulnerable** para demostrar dos riesgos OWASP y su remediación.

- Riesgos: **A04 Cryptographic Failures** y **A08 Software or Data Integrity Failures**.
- Rama `version-vulnerable`: app con los fallos + comentarios que los explican.
- Rama `version-asegurada`: mismos endpoints con la remediación manual.

## Stack

- Backend: Python + Flask
- Base de datos: SQLite (`portal.db`)
- Frontend: HTML/CSS + Jinja2

## Despliegue (VM víctima — Ubuntu Server 22.04)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export PORTAL_SECRET='cambia-esto-por-un-secreto-largo-y-aleatorio'
python3 init_db.py
python3 app.py          # escucha en 0.0.0.0:8080
```

## Usuarios semilla

| usuario  | password        | rol   |
|----------|-----------------|-------|
| operador | operador123     | user  |
| admin    | SuperAdmin2026! | admin |

## Inventario de endpoints

| Método | Ruta             | Descripción                        | Seguridad                       |
|--------|------------------|------------------------------------|---------------------------------|
| GET    | `/`              | Login                              | —                               |
| POST   | `/login`         | Autenticación (PBKDF2 manual)      | salt por usuario                |
| GET    | `/dashboard`     | Panel de usuario                   | token firmado con HMAC          |
| GET    | `/admin`         | Panel de carga (solo admin)        | —                               |
| POST   | `/upload-update` | Carga de paquete firmado           | verifica HMAC + tipo real       |