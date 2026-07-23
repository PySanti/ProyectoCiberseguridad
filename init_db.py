import sqlite3
# Cambiamos la importación al módulo seguro
from crypto_secure import hash_password

con = sqlite3.connect("portal.db")
cur = con.cursor()
cur.executescript("""
DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS paquetes;
DROP TABLE IF EXISTS logs;
CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, password TEXT, rol TEXT);
CREATE TABLE paquetes (id INTEGER PRIMARY KEY, dispositivo TEXT, nombre TEXT, version TEXT, checksum TEXT, fecha TEXT, archivo TEXT, subido_por TEXT, eliminado INTEGER DEFAULT 0);
CREATE TABLE logs (id INTEGER PRIMARY KEY, evento TEXT);
""")

# Ahora hash_password generará las contraseñas con el formato seguro que espera el login
cur.execute("INSERT INTO usuarios (usuario, password, rol) VALUES (?, ?, ?)",
            ("operador", hash_password("operador123"), "user"))
cur.execute("INSERT INTO usuarios (usuario, password, rol) VALUES (?, ?, ?)",
            ("admin", hash_password("SuperAdmin2026!"), "admin"))
# Añadimos tu usuario de pruebas habitual
cur.execute("INSERT INTO usuarios (usuario, password, rol) VALUES (?, ?, ?)",
            ("sebasllambi", hash_password("admin123"), "admin"))
con.commit()

# Datos iniciales para el catálogo de firmwares
cur.executescript("""
INSERT INTO paquetes (dispositivo, nombre, version, checksum, fecha, archivo, subido_por) 
VALUES ('Router Cisco X500', 'Firmware Router Enterprise X500', 'v3.2.1-stable', 'e3b0c44298fc1c149afbf4...', '2026-06-15', 'fw_router_x500_v321.zip', 'admin');

INSERT INTO paquetes (dispositivo, nombre, version, checksum, fecha, archivo, subido_por) 
VALUES ('Switch Core UCAB-9000', 'Firmware Switch Core UCAB-9000', 'v1.0.4-patch', '8f434346648f6b96df89dd...', '2026-07-01', 'fw_switch_c9000_v104.zip', 'admin');

INSERT INTO paquetes (dispositivo, nombre, version, checksum, fecha, archivo, subido_por) 
VALUES ('Sensor Térmico T4', 'Firmware Sensor IoT Industrial T4', 'v2.1.0-rel', 'a591a6d48bf420484a8117...', '2026-07-10', 'fw_sensor_t4_v210.tar', 'admin');
""")
con.commit()
con.close()
print("DB inicializada")