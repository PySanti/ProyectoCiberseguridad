from flask import Blueprint, request, render_template, redirect, abort, url_for
from crypto_vuln import leer_token
from package_processor import procesar_paquete
from db import get_db
import os
import hashlib
from datetime import datetime

updates_bp = Blueprint("updates", __name__)
UPLOAD_DIR = "uploads"


@updates_bp.route("/admin")
def admin():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")
    # Aquí decidimos si es admin leyendo el rol del token del cliente, que como
    # vimos se puede falsificar.
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)
        
    con = get_db()
    paquetes = con.execute("SELECT * FROM paquetes WHERE eliminado = 0 ORDER BY id DESC").fetchall()
    con.close()
    
    deleted_id = request.args.get('deleted_id')
    return render_template("admin.html", usuario=usuario, rol=rol, paquetes=paquetes, deleted_id=deleted_id)


@updates_bp.route("/upload-update", methods=["POST"])
def upload_update():
    token = request.cookies.get("session")
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)

    archivo = request.files["paquete"]
    nombre = archivo.filename
    # Esta es la vulnerabilidad CWE-434 (Unrestricted Upload of File with
    # Dangerous Type): lo único que revisamos es que el nombre del archivo termine
    # en .zip o .tar, algo que el atacante controla fácil. No miramos el contenido
    # real del archivo. Faltaría revisar de verdad qué tipo de archivo es y si es
    # confiable.
    if not (nombre.endswith(".zip") or nombre.endswith(".tar")):
        return render_template("upload_result.html", usuario=usuario, rol=rol, resultado="Error: Formato no permitido. Solo se aceptan archivos .zip o .tar"), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ruta = os.path.join(UPLOAD_DIR, nombre)
    archivo.save(ruta)
    # Aquí lo guardamos y lo procesamos (se descomprime y se ejecuta) sin ninguna
    # comprobación de que sea seguro.
    resultado = procesar_paquete(ruta)
    
    # Guardar la información en la base de datos para que sea dinámica
    nombre_form = request.form.get("nombre", nombre)
    dispositivo = request.form.get("dispositivo", "Desconocido")
    version = request.form.get("version", "1.0")
    fecha = datetime.now().strftime("%Y-%m-%d")
    
    # Calculamos un checksum sencillo del archivo (para propósitos visuales)
    hasher = hashlib.sha256()
    with open(ruta, 'rb') as f:
        hasher.update(f.read())
    checksum = hasher.hexdigest()[:22] + "..."
    
    con = get_db()
    con.execute("""
        INSERT INTO paquetes (dispositivo, nombre, version, checksum, fecha, archivo, subido_por)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (dispositivo, nombre_form, version, checksum, fecha, nombre, usuario))
    con.commit()
    con.close()
    
    return render_template("upload_result.html", usuario=usuario, rol=rol, resultado=resultado)

@updates_bp.route("/delete-update/<int:paquete_id>", methods=["POST"])
def delete_update(paquete_id):
    token = request.cookies.get("session")
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)
        
    con = get_db()
    con.execute("UPDATE paquetes SET eliminado = 1 WHERE id = ?", (paquete_id,))
    con.commit()
    con.close()
    return redirect(url_for("updates.admin", deleted_id=paquete_id))

@updates_bp.route("/undo-delete/<int:paquete_id>", methods=["POST"])
def undo_delete(paquete_id):
    token = request.cookies.get("session")
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)
        
    con = get_db()
    con.execute("UPDATE paquetes SET eliminado = 0 WHERE id = ?", (paquete_id,))
    con.commit()
    con.close()
    return redirect(url_for("updates.admin"))

@updates_bp.route("/edit-update/<int:paquete_id>", methods=["POST"])
def edit_update(paquete_id):
    token = request.cookies.get("session")
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)
        
    nombre = request.form.get("nombre")
    dispositivo = request.form.get("dispositivo")
    version = request.form.get("version")
    
    if nombre and dispositivo and version:
        con = get_db()
        con.execute("UPDATE paquetes SET nombre = ?, dispositivo = ?, version = ? WHERE id = ?",
                    (nombre, dispositivo, version, paquete_id))
        con.commit()
        con.close()
        
    return redirect(url_for("updates.admin"))
