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
python3 init_db.py
python3 app.py          # escucha en 0.0.0.0:8080
```

## Usuarios semilla

| usuario  | password        | rol   |
|----------|-----------------|-------|
| operador | operador123     | user  |
| admin    | SuperAdmin2026! | admin |

## Inventario de endpoints

| Método | Ruta             | Descripción                    | Riesgo |
|--------|------------------|--------------------------------|--------|
| GET    | `/`              | Login                          | A04    |
| POST   | `/login`         | Autenticación (MD5)            | A04    |
| GET    | `/dashboard`     | Panel de usuario               | A04    |
| GET    | `/api/config`    | Config expuesta al cliente     | A04    |
| GET    | `/admin`         | Panel de carga (solo admin)    | A08    |
| POST   | `/upload-update` | Carga de paquete `.zip`/`.tar` | A08    |
