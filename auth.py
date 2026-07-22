from flask import Blueprint, request, render_template, make_response, redirect, jsonify
from db import get_db
from crypto_vuln import hash_password, crear_token, leer_token, LLAVE_TOKEN

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET"])
def index():
    return render_template("login.html")


@auth_bp.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario", "")
    password = request.form.get("password", "")
    con = get_db()
    fila = con.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
    con.close()
    # Compara el MD5 sin salt de la contraseña recibida contra el almacenado.
    if fila and fila["password"] == hash_password(password):
        # Entrega al cliente un token reversible en una cookie (A04).
        token = crear_token(fila["usuario"], fila["rol"])
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("session", token)
        return resp
    return render_template("login.html", error="Credenciales invalidas")


@auth_bp.route("/dashboard")
def dashboard():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")
    # El rol se toma directamente del token del cliente, sin verificar firma.
    usuario, rol = leer_token(token)
    return render_template("dashboard.html", usuario=usuario, rol=rol)


@auth_bp.route("/api/config")
def api_config():
    # A04 + CWE-200: expone al cliente detalles internos de configuración,
    # incluyendo el ESQUEMA del token y el algoritmo de hashing, además de una
    # pista de la llave. Esto le regala al atacante todo lo que necesita para
    # atacar la criptografía. FALTA: no exponer detalles de seguridad al cliente.
    return jsonify({
        "app": "Portal de Gestion de Actualizaciones y Firmwares",
        "version": "1.0",
        "token_scheme": "base64(XOR(usuario|rol, LLAVE))",
        "hash_passwords": "md5",
        "debug": True,
        "llave_pista": LLAVE_TOKEN.decode()[:4] + "***",
    })
