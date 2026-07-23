from flask import Blueprint, request, render_template, make_response, redirect
from db import get_db
from crypto_secure import verificar_password, crear_token, leer_token

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/", methods=["GET"])
def index():
    token = request.cookies.get("session")
    usuario = None
    rol = None
    if token:
        try:
            # Si el token es válido, extraemos los datos.
            usuario, rol = leer_token(token)
        except ValueError:
            # Si fue alterado, ignoramos el token silenciosamente.
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
    
    # Comprobamos la contraseña utilizando la función segura
    if fila and verificar_password(password, fila["password"]):
        token = crear_token(fila["usuario"], fila["rol"])
        resp = make_response(redirect("/dashboard"))
        # Guardamos el token en una cookie protegida
        resp.set_cookie("session", token, httponly=True, samesite="Strict")
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
        
    try:
        # Validación estricta: si falla la firma, se expulsa al usuario
        usuario, rol = leer_token(token)
    except ValueError:
        return redirect("/")
        
    return render_template("dashboard.html", usuario=usuario, rol=rol)


# Esto corrige la vulnerabilidad CWE-200 (Exposure of Sensitive Information):
# quitamos la ruta /api/config que había en la versión vulnerable. Antes filtraba
# cómo se armaba el token, el método de las contraseñas y una pista de la llave;
# ahora simplemente ya no existe, así que no le damos esa información al atacante.
@auth_bp.route("/download/<path:filename>")
def download_fake(filename):
    contenido = f"¡Felicidades! Has encontrado un easter egg.\n\nEste archivo '{filename}' es un firmware ficticio para pruebas de ciberseguridad en el portal UCAB HARDWARE."
    resp = make_response(contenido)
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    resp.headers["Content-Type"] = "text/plain"
    return resp