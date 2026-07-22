from flask import Blueprint, request, render_template, make_response, redirect
from db import get_db
from crypto_secure import verificar_password, crear_token, leer_token

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
    if fila and verificar_password(password, fila["password"]):
        token = crear_token(fila["usuario"], fila["rol"])
        resp = make_response(redirect("/dashboard"))
        # Guardamos el token en una cookie más protegida: no se puede leer desde
        # JavaScript ni se envía a otros sitios.
        resp.set_cookie("session", token, httponly=True, samesite="Strict")
        return resp
    return render_template("login.html", error="Credenciales invalidas")


@auth_bp.route("/dashboard")
def dashboard():
    token = request.cookies.get("session")
    if not token:
        return redirect("/")
    try:
        # Si el token fue modificado, esto falla y no lo dejamos pasar.
        usuario, rol = leer_token(token)
    except ValueError:
        return redirect("/")
    return render_template("dashboard.html", usuario=usuario, rol=rol)
