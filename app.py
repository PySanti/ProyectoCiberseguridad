from flask import Flask
from auth import auth_bp
from updates import updates_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(updates_bp)

if __name__ == "__main__":
    # Apagamos el modo de depuración en la versión segura, para no mostrar
    # información interna del servidor.
    app.run(host="0.0.0.0", port=8080, debug=False)