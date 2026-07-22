import tarfile
import zipfile
import os
from crypto_secure import hmac_sha256, comparar_constante, SECRETO

EXTRACT_DIR = "paquetes_extraidos"


def verificar_integridad(datos: bytes, firma_hex: str) -> bool:
    # Aquí comprobamos que el paquete sea de confianza: recalculamos su firma con
    # el secreto del servidor y la comparamos con la firma que vino con él. Solo
    # quien tiene el secreto pudo haber hecho una firma válida.
    try:
        esperado = hmac_sha256(SECRETO, datos)
        return comparar_constante(esperado, bytes.fromhex(firma_hex))
    except (ValueError, TypeError):
        return False


def _tipo_real_valido(ruta: str) -> bool:
    # Aquí miramos el contenido real del archivo (sus primeros bytes) para saber
    # si de verdad es un .zip o un .tar, sin fiarnos del nombre.
    with open(ruta, "rb") as f:
        cabecera = f.read(6)
    es_zip = cabecera[:4] == b"PK\x03\x04"
    with open(ruta, "rb") as f:
        f.seek(257)
        es_tar = f.read(5) == b"ustar"
    return es_zip or es_tar


def _ruta_segura(base: str, objetivo: str) -> bool:
    # Aquí nos aseguramos de que cada archivo del paquete se guarde dentro de la
    # carpeta prevista y no en otra parte del sistema.
    base_abs = os.path.realpath(base)
    destino = os.path.realpath(objetivo)
    return destino == base_abs or destino.startswith(base_abs + os.sep)


def procesar_paquete(ruta: str) -> str:
    if not _tipo_real_valido(ruta):
        raise ValueError("Tipo de archivo no válido")

    os.makedirs(EXTRACT_DIR, exist_ok=True)
    # Descomprimimos revisando cada archivo, y ahora NO ejecutamos nada de lo que
    # venga adentro.
    if ruta.endswith(".tar"):
        with tarfile.open(ruta) as t:
            for miembro in t.getmembers():
                destino = os.path.join(EXTRACT_DIR, miembro.name)
                if not _ruta_segura(EXTRACT_DIR, destino):
                    raise ValueError(f"Ruta insegura en el paquete: {miembro.name}")
            t.extractall(EXTRACT_DIR)
    else:
        with zipfile.ZipFile(ruta) as z:
            for nombre in z.namelist():
                destino = os.path.join(EXTRACT_DIR, nombre)
                if not _ruta_segura(EXTRACT_DIR, destino):
                    raise ValueError(f"Ruta insegura en el paquete: {nombre}")
            z.extractall(EXTRACT_DIR)
    return "paquete verificado y extraido (sin ejecucion)"
