#!/bin/bash
# Reconocimiento del objetivo. Reemplaza <IP_VICTIMA> con la IP de la víctima.
VICTIMA="<IP_VICTIMA>"

# Revisamos qué puertos y servicios tiene abiertos la máquina víctima.
nmap -sV -p 1-10000 "$VICTIMA"

# Pedimos la página de configuración, que por error nos cuenta cómo protege los tokens.
curl -s "http://$VICTIMA:8080/api/config"
