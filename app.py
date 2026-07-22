from flask import Flask
from auth import auth_bp
from updates import updates_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(updates_bp)

if __name__ == "__main__":
    # Dejamos la app escuchando en toda la red del laboratorio y con el modo de
    # depuración prendido. Ese modo, ante un error, muestra información interna y
    # hasta permite ejecutar comandos en el servidor: es una configuración
    # insegura que le da más terreno al atacante.
    app.run(host="0.0.0.0", port=8080, debug=True)
