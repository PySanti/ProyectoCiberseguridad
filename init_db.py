import sqlite3
from crypto_secure import hash_password

con = sqlite3.connect("portal.db")
cur = con.cursor()
cur.executescript("""
DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS paquetes;
DROP TABLE IF EXISTS logs;
CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, password TEXT, rol TEXT);
CREATE TABLE paquetes (id INTEGER PRIMARY KEY, nombre TEXT, ruta TEXT, subido_por TEXT);
CREATE TABLE logs (id INTEGER PRIMARY KEY, evento TEXT);
""")
# Passwords guardadas como MD5 sin salt (ver crypto_vuln.hash_password).
cur.execute("INSERT INTO usuarios (usuario, password, rol) VALUES (?, ?, ?)",
            ("operador", hash_password("operador123"), "user"))
cur.execute("INSERT INTO usuarios (usuario, password, rol) VALUES (?, ?, ?)",
            ("admin", hash_password("SuperAdmin2026!"), "admin"))
con.commit()
con.close()
print("DB inicializada")
