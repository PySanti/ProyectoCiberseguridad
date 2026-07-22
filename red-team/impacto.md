# Acciones sobre objetivos — evidencia de impacto

Cadena: A04 (token reversible → acceso admin) → A08 (paquete malicioso → RCE →
reverse shell) → post-explotación.

Con la reverse shell en la víctima se ejecutó `post_exploit.sh`:

1. Se localizó y **robó `portal.db`** (base de datos completa del portal).
2. Se **volcó la tabla `usuarios`**: todos los hashes MD5 sin salt.
3. `crack_hashes.py` **recuperó las contraseñas en claro** por diccionario
   (`operador123`, `SuperAdmin2026!`), gracias a que MD5 sin salt (A04) permite
   precomputar y comparar.

## Impacto
- **Confidencialidad:** comprometida por completo — credenciales de todos los
  usuarios, incluido `admin`.
- **Integridad / disponibilidad del host:** control total del servidor (RCE de A08).