import hashlib
import base64

# CWE-798 (Use of Hard-coded Credentials): la llave del token está escrita
# directamente en el código fuente. Cualquiera con acceso al repositorio o que
# obtenga los archivos del servidor la lee. FALTA: cargar el secreto desde una
# variable de entorno o gestor de secretos, nunca dejarlo en el código.
LLAVE_TOKEN = b"S3cr3t0_P0rt4l_2026"


def hash_password(password: str) -> str:
    # CWE-327 (Broken/Risky Crypto Algorithm): MD5 es un algoritmo obsoleto y
    # roto. Es rapidísimo de calcular -> vulnerable a fuerza bruta y a rainbow
    # tables. Además NO usa salt, así que dos usuarios con la misma contraseña
    # producen el mismo hash. FALTA: una función de derivación de clave lenta
    # con salt por usuario (PBKDF2/Argon2/bcrypt), implementada manualmente.
    return hashlib.md5(password.encode()).hexdigest()


def _xor(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def crear_token(usuario: str, rol: str) -> str:
    # CWE-327: el token es REVERSIBLE. Es solo XOR con una llave fija + base64,
    # sin ninguna firma. El cliente puede descifrarlo, cambiar "user" por
    # "admin" y volver a cifrarlo. FALTA: firmar el token con HMAC y verificar
    # esa firma en el servidor, para que el cliente no pueda alterarlo.
    payload = f"{usuario}|{rol}".encode()
    return base64.b64encode(_xor(payload, LLAVE_TOKEN)).decode()


def leer_token(token: str):
    # No verifica integridad: confía ciegamente en lo que manda el cliente en la
    # cookie. Lo que venga se decodifica y se usa tal cual.
    datos = _xor(base64.b64decode(token), LLAVE_TOKEN).decode()
    usuario, rol = datos.split("|")
    return usuario, rol
