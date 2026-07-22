import sqlite3

DB = "portal.db"


def get_db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    return con
