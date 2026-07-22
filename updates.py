from flask import Blueprint, request, render_template, redirect
from crypto_vuln import leer_token
from package_processor import procesar_paquete
import os

updates_bp = Blueprint("updates", __name__)
UPLOAD_DIR = "uploads"


@updates_bp.route("/admin")
def admin():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")
    # El rol se lee del token reversible del cliente (heredado de A04).
    usuario, rol = leer_token(token)
    if rol != "admin":
        return "Acceso denegado", 403
    return render_template("admin.html", usuario=usuario)


@updates_bp.route("/upload-update", methods=["POST"])
def upload_update():
    token = request.cookies.get("session")
    usuario, rol = leer_token(token)
    if rol != "admin":
        return "Acceso denegado", 403

    archivo = request.files["paquete"]
    nombre = archivo.filename
    # CWE-434 (Unrestricted Upload of File with Dangerous Type): la única
    # validación es la extensión del nombre, que el cliente controla por
    # completo. No se comprueba el tipo real (magic bytes) ni el contenido.
    # FALTA: validar el tipo real del archivo y verificar su integridad.
    if not (nombre.endswith(".zip") or nombre.endswith(".tar")):
        return "Formato no permitido", 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ruta = os.path.join(UPLOAD_DIR, nombre)
    archivo.save(ruta)
    # Se procesa (extrae + ejecuta) sin ninguna verificación de integridad.
    resultado = procesar_paquete(ruta)
    return f"Paquete procesado: {resultado}"