from flask import Blueprint, request, render_template, redirect, abort
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
    # Aquí decidimos si es admin leyendo el rol del token del cliente, que como
    # vimos se puede falsificar.
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)
    return render_template("admin.html", usuario=usuario, rol=rol)


@updates_bp.route("/upload-update", methods=["POST"])
def upload_update():
    token = request.cookies.get("session")
    usuario, rol = leer_token(token)
    if rol != "admin":
        abort(403)

    archivo = request.files["paquete"]
    nombre = archivo.filename
    # Aquí lo único que revisamos es que el nombre termine en .zip o .tar, algo
    # que el atacante controla fácil. No miramos el contenido real del archivo.
    # Faltaría revisar de verdad qué tipo de archivo es y si es confiable.
    if not (nombre.endswith(".zip") or nombre.endswith(".tar")):
        return render_template("upload_result.html", usuario=usuario, rol=rol, resultado="Error: Formato no permitido. Solo se aceptan archivos .zip o .tar"), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    ruta = os.path.join(UPLOAD_DIR, nombre)
    archivo.save(ruta)
    # Aquí lo guardamos y lo procesamos (se descomprime y se ejecuta) sin ninguna
    # comprobación de que sea seguro.
    resultado = procesar_paquete(ruta)
    return render_template("upload_result.html", usuario=usuario, rol=rol, resultado=resultado)
