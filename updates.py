from flask import Blueprint, request, render_template, redirect
from crypto_secure import leer_token
from package_processor import verificar_integridad, procesar_paquete
import os

updates_bp = Blueprint("updates", __name__)
UPLOAD_DIR = "uploads"


@updates_bp.route("/admin")
def admin():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")
    try:
        usuario, rol = leer_token(token)
    except ValueError:
        return redirect("/")
    if rol != "admin":
        return "Acceso denegado", 403
    return render_template("admin.html", usuario=usuario)


@updates_bp.route("/upload-update", methods=["POST"])
def upload_update():
    token = request.cookies.get("session")
    try:
        usuario, rol = leer_token(token)
    except (ValueError, AttributeError):
        return "No autorizado", 401
    if rol != "admin":
        return "Acceso denegado", 403

    archivo = request.files["paquete"]
    firma = request.form.get("firma", "")
    datos = archivo.read()

    # 1) Antes de tocar el archivo, comprobamos su firma. Si no es válida, lo
    #    rechazamos y no lo guardamos ni lo procesamos.
    if not verificar_integridad(datos, firma):
        return "Integridad inválida: paquete rechazado", 400

    nombre = os.path.basename(archivo.filename)  # nos quedamos solo con el nombre, sin rutas
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ruta = os.path.join(UPLOAD_DIR, nombre)
    with open(ruta, "wb") as f:
        f.write(datos)

    # 2) Lo procesamos con cuidado: si algo falla, se maneja sin romper la app.
    try:
        resultado = procesar_paquete(ruta)
    except ValueError as e:
        return f"Paquete rechazado: {e}", 400
    return f"Paquete procesado: {resultado}"
