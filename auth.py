from flask import Blueprint, request, render_template, make_response, redirect, jsonify
from db import get_db
from crypto_vuln import hash_password, crear_token, leer_token, LLAVE_TOKEN

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET"])
def index():
    token = request.cookies.get("session")
    usuario = None
    rol = None
    if token:
        try:
            usuario, rol = leer_token(token)
        except:
            pass
            
    con = get_db()
    paquetes = con.execute("SELECT * FROM paquetes WHERE eliminado = 0 ORDER BY id DESC").fetchall()
    con.close()
    
    return render_template("login.html", usuario=usuario, rol=rol, paquetes=paquetes)


@auth_bp.route("/login", methods=["POST"])
def login():
    usuario = request.form.get("usuario", "")
    password = request.form.get("password", "")
    con = get_db()
    fila = con.execute("SELECT * FROM usuarios WHERE usuario = ?", (usuario,)).fetchone()
    con.close()
    # Aquí comparamos la contraseña que escribió el usuario (convertida con MD5)
    # contra la que está guardada.
    if fila and fila["password"] == hash_password(password):
        # Si coincide, le entregamos un token dentro de una cookie. Como ese
        # token se puede modificar, aquí está el punto débil.
        token = crear_token(fila["usuario"], fila["rol"])
        resp = make_response(redirect("/dashboard"))
        resp.set_cookie("session", token)
        return resp
    return render_template("login.html", error="Credenciales invalidas")


@auth_bp.route("/logout")
def logout():
    resp = make_response(redirect("/"))
    resp.delete_cookie("session")
    return resp


@auth_bp.route("/dashboard")
def dashboard():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")
    # Aquí tomamos el rol directo del token del cliente, sin comprobar si es de
    # verdad. Si alguien lo cambió a "admin", le creemos igual.
    usuario, rol = leer_token(token)
    return render_template("dashboard.html", usuario=usuario, rol=rol)


@auth_bp.route("/api/config")
def api_config():
    # Esta es la vulnerabilidad CWE-200 (Exposure of Sensitive Information): por
    # error le mostramos al cliente cómo funciona la app por dentro, cómo se arma
    # el token, qué método usa para las contraseñas y una pista de la llave. Eso
    # le da al atacante justo lo que necesita para atacarnos. No deberíamos
    # mostrar nada de esto.
    return jsonify({
        "app": "Portal de Gestion de Actualizaciones y Firmwares",
        "version": "1.0",
        "token_scheme": "base64(XOR(usuario|rol, LLAVE))",
        "hash_passwords": "md5",
        "debug": True,
        "llave_pista": LLAVE_TOKEN.decode()[:4] + "***",
    })

@auth_bp.route("/download/<path:filename>")
def download_fake(filename):
    contenido = f"¡Felicidades! Has encontrado un easter egg.\n\nEste archivo '{filename}' es un firmware ficticio para pruebas de ciberseguridad en el portal UCAB HARDWARE."
    resp = make_response(contenido)
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    resp.headers["Content-Type"] = "text/plain"
    return resp
