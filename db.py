import sqlite3

# Nombre del archivo de la base de datos SQLite
DB = "portal.db"

# Abre una conexión a la base de datos SQLite del portal
# y devuelve filas con acceso por nombre de columna.
def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con
