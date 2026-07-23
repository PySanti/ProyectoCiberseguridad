from flask import Flask, render_template, request
from auth import auth_bp
from updates import updates_bp
from crypto_secure import leer_token  # Importamos del módulo seguro

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(updates_bp)

@app.errorhandler(404)
def page_not_found(e):
    token = request.cookies.get("session")
    usuario = None
    rol = None
    if token:
        try:
            # Utilizamos el método seguro, atrapando el error si fue manipulado
            usuario, rol = leer_token(token)
        except ValueError:
            pass
    return render_template('404.html', usuario=usuario, rol=rol), 404

@app.errorhandler(403)
def forbidden(e):
    token = request.cookies.get("session")
    usuario = None
    rol = None
    if token:
        try:
            usuario, rol = leer_token(token)
        except ValueError:
            pass
    return render_template('403.html', usuario=usuario, rol=rol), 403

if __name__ == "__main__":
    # Apagamos el modo de depuración en la versión segura (debug=False), 
    # para no exponer la consola interactiva ni información interna del servidor.
    app.run(host="0.0.0.0", port=8080, debug=False)