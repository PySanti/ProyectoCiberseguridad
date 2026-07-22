from flask import Flask
from auth import auth_bp
from updates import updates_bp

app = Flask(__name__)
app.register_blueprint(auth_bp)
app.register_blueprint(updates_bp)

if __name__ == "__main__":
    # debug=False en la versión asegurada: no exponer el debugger de Werkzeug.
    app.run(host="0.0.0.0", port=8080, debug=False)