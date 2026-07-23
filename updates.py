from flask import Blueprint, request, render_template, redirect, abort, url_for
from crypto_secure import leer_token # Importamos del módulo seguro
from package_processor import verificar_integridad, procesar_paquete # Añadimos verificar_integridad
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
    
    # Manejo seguro del token: si alguien lo alteró y falla, lo sacamos
    try:
        usuario, rol = leer_token(token)
    except (ValueError, AttributeError):
        return redirect("/")
        
    if rol != "admin":
        abort(403)
        
    # Mantenemos la lógica de la base de datos de la versión vulnerable
    con = get_db()
    paquetes = con.execute("SELECT * FROM paquetes WHERE eliminado = 0 ORDER BY id DESC").fetchall()
    con.close()
    
    deleted_id = request.args.get('deleted_id')
    return render_template("admin.html", usuario=usuario, rol=rol, paquetes=paquetes, deleted_id=deleted_id)


@updates_bp.route("/upload-update", methods=["POST"])
def upload_update():
    token = request.cookies.get("session")
    try:
        usuario, rol = leer_token(token)
    except (ValueError, AttributeError):
        return "No autorizado", 401
        
    if rol != "admin":
        abort(403)

    archivo = request.files["paquete"]
    firma = request.form.get("firma", "")
    datos = archivo.read() # Leemos a memoria para verificar la firma

    # 1) Verificamos la firma criptográfica (Mitiga OWASP A08)
    if not verificar_integridad(datos, firma):
        return render_template("upload_result.html", usuario=usuario, rol=rol, resultado="Error: Integridad inválida. Paquete rechazado por firma incorrecta."), 400

    # 2) Sanitizamos el nombre del archivo para evitar ataques de Path Traversal
    nombre = os.path.basename(archivo.filename) 
    
    if not (nombre.endswith(".zip") or nombre.endswith(".tar")):
        return render_template("upload_result.html", usuario=usuario, rol=rol, resultado="Error: Formato no permitido. Solo se aceptan archivos .zip o .tar"), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ruta = os.path.join(UPLOAD_DIR, nombre)
    
    with open(ruta, "wb") as f:
        f.write(datos)

    # 3) Procesamos el paquete controlando errores imprevistos
    try:
        resultado = procesar_paquete(ruta)
    except ValueError as e:
        return render_template("upload_result.html", usuario=usuario, rol=rol, resultado=f"Error al procesar: {e}"), 400
    
    # 4) Guardamos la información en la base de datos (Lógica mantenida)
    nombre_form = request.form.get("nombre", nombre)
    dispositivo = request.form.get("dispositivo", "Desconocido")
    version = request.form.get("version", "1.0")
    fecha = datetime.now().strftime("%Y-%m-%d")
    
    # Calculamos el checksum usando los datos que ya tenemos en memoria
    hasher = hashlib.sha256()
    hasher.update(datos)
    checksum = hasher.hexdigest()[:22] + "..."
    
    con = get_db()
    con.execute("""
        INSERT INTO paquetes (dispositivo, nombre, version, checksum, fecha, archivo, subido_por)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (dispositivo, nombre_form, version, checksum, fecha, nombre, usuario))
    con.commit()
    con.close()
    
    return render_template("upload_result.html", usuario=usuario, rol=rol, resultado=f"Éxito: {resultado}")


@updates_bp.route("/delete-update/<int:paquete_id>", methods=["POST"])
def delete_update(paquete_id):
    token = request.cookies.get("session")
    try:
        usuario, rol = leer_token(token)
    except (ValueError, AttributeError):
        return "No autorizado", 401
        
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
    try:
        usuario, rol = leer_token(token)
    except (ValueError, AttributeError):
        return "No autorizado", 401
        
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
    try:
        usuario, rol = leer_token(token)
    except (ValueError, AttributeError):
        return "No autorizado", 401
        
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