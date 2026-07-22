from flask import Flask
from auth import auth_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)

# --- Jesús (módulo de carga A08): registra aquí el blueprint updates_bp ---
# from updates import updates_bp
# app.register_blueprint(updates_bp)

if __name__ == "__main__":
    # host=0.0.0.0 -> la app queda expuesta en la red interna del laboratorio.
    # debug=True -> activa el debugger interactivo de Werkzeug, que ante una
    # excepción muestra código y permite ejecución en el servidor: configuración
    # insegura por defecto que amplía la superficie de ataque.
    app.run(host="0.0.0.0", port=8080, debug=True)
