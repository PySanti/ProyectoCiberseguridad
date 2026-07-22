#!/bin/bash
# MITRE T1595 - Active Scanning. Reemplaza <IP_VICTIMA>.
VICTIMA="<IP_VICTIMA>"

# Descubrir puertos y servicios de la VM víctima
nmap -sV -p 1-10000 "$VICTIMA"

# Endpoint de configuración que filtra el esquema criptográfico
curl -s "http://$VICTIMA:8080/api/config"
