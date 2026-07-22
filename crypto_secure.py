import base64
import hashlib
import os

# CORRIGE CWE-798: el secreto se carga desde una variable de entorno, no está
# en el código. Si falta, la app no arranca.
SECRETO = os.environ.get("PORTAL_SECRET", "").encode()
if not SECRETO:
    raise RuntimeError("Falta la variable de entorno PORTAL_SECRET")

BLOQUE = 64


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    if len(key) > BLOQUE:
        key = _sha256(key)
    key = key.ljust(BLOQUE, b"\x00")
    o_key = bytes(b ^ 0x5C for b in key)
    i_key = bytes(b ^ 0x36 for b in key)
    return _sha256(o_key + _sha256(i_key + msg))


def pbkdf2(password: bytes, salt: bytes, iteraciones: int = 200000, dklen: int = 32) -> bytes:
    dk = b""
    bloque = 1
    while len(dk) < dklen:
        u = hmac_sha256(password, salt + bloque.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(iteraciones - 1):
            u = hmac_sha256(password, u)
            for i in range(len(t)):
                t[i] ^= u[i]
        dk += bytes(t)
        bloque += 1
    return dk[:dklen]


def comparar_constante(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    r = 0
    for x, y in zip(a, b):
        r |= x ^ y
    return r == 0


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    dk = pbkdf2(password.encode(), salt)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verificar_password(password: str, almacenado: str) -> bool:
    salt_b64, dk_b64 = almacenado.split("$")
    salt = base64.b64decode(salt_b64)
    esperado = base64.b64decode(dk_b64)
    calculado = pbkdf2(password.encode(), salt)
    return comparar_constante(calculado, esperado)


def crear_token(usuario: str, rol: str) -> str:
    payload = f"{usuario}|{rol}".encode()
    firma = hmac_sha256(SECRETO, payload)
    return base64.b64encode(payload).decode() + "." + base64.b64encode(firma).decode()


def leer_token(token: str):
    payload_b64, firma_b64 = token.split(".")
    payload = base64.b64decode(payload_b64)
    firma = base64.b64decode(firma_b64)
    if not comparar_constante(hmac_sha256(SECRETO, payload), firma):
        raise ValueError("Token invalido o manipulado")
    usuario, rol = payload.decode().split("|")
    return usuario, rol