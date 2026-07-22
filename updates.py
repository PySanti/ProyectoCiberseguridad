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

    # 1) Verifica la integridad ANTES de tocar el archivo. Sin firma válida, se
    #    rechaza y nunca se guarda ni se procesa.
    if not verificar_integridad(datos, firma):
        return "Integridad inválida: paquete rechazado", 400

    nombre = os.path.basename(archivo.filename)  # evita rutas en el nombre
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ruta = os.path.join(UPLOAD_DIR, nombre)
    with open(ruta, "wb") as f:
        f.write(datos)

    # 2) Procesa dentro de try/except; cualquier fallo se maneja controladamente.
    try:
        resultado = procesar_paquete(ruta)
    except ValueError as e:
        return f"Paquete rechazado: {e}", 400
    return f"Paquete procesado: {resultado}"