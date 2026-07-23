import hashlib
import base64

# Esta es la vulnerabilidad CWE-798 (Use of Hard-coded Credentials): dejamos la
# llave secreta escrita directo en el código. Eso es peligroso porque cualquiera
# que pueda ver estos archivos la puede leer. Lo correcto sería guardarla afuera
# (en una variable del sistema), nunca aquí dentro del código.
LLAVE_TOKEN = b"S3cr3t0_P0rt4l_2026"


def hash_password(password: str) -> str:
    # Aquí está la vulnerabilidad CWE-327 (Use of a Broken or Risky Cryptographic
    # Algorithm): guardamos la contraseña usando MD5, un método viejo y fácil
    # de romper, que además no le agrega "sal". Por eso es sencillo descubrir la
    # contraseña real. Lo ideal sería un método más lento y con una sal distinta
    # para cada usuario.
    return hashlib.md5(password.encode()).hexdigest()


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def crear_token(usuario: str, rol: str) -> str:
    # Esta también es la vulnerabilidad CWE-327: armamos el token mezclando los
    # datos con la llave y codificándolos, pero esa mezcla se puede deshacer, por
    # lo que el usuario podría abrir el token, cambiar "user" por "admin" y
    # volverlo a armar. Faltaría firmarlo para que nadie lo pueda modificar sin
    # que nos demos cuenta.
    payload = f"{usuario}|{rol}".encode()
    return base64.b64encode(_xor(payload, LLAVE_TOKEN)).decode()


def leer_token(token: str):
    # Aquí leemos el token que manda el cliente y le creemos sin revisar nada.
    # Lo que venga se abre y se usa tal cual, aunque lo hayan alterado.
    datos = _xor(base64.b64decode(token), LLAVE_TOKEN).decode()
    usuario, rol = datos.split("|")
    return usuario, rol
