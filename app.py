from flask import Flask, render_template, request
from auth import auth_bp
from updates import updates_bp
from crypto_vuln import leer_token

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
            usuario, rol = leer_token(token)
        except:
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
        except:
            pass
    return render_template('403.html', usuario=usuario, rol=rol), 403

if __name__ == "__main__":
    # Dejamos la app escuchando en toda la red del laboratorio y con el modo de
    # depuración prendido. Ese modo, ante un error, muestra información interna y
    # hasta permite ejecutar comandos en el servidor, esto es una configuración
    # insegura que le da más terreno al atacante.
    app.run(host="0.0.0.0", port=8080, debug=True)
