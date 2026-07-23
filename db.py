import sqlite3

# Definimos el nombre del archivo de la base de datos
DB = "portal.db"

# Función para obtener la conexión a la base de datos
def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con
