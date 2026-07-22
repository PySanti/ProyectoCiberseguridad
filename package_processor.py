import tarfile
import zipfile
import os
from crypto_secure import hmac_sha256, comparar_constante, SECRETO

EXTRACT_DIR = "paquetes_extraidos"


def verificar_integridad(datos: bytes, firma_hex: str) -> bool:
    # Recalcula el HMAC-SHA256 del paquete con el secreto del servidor y lo
    # compara (en tiempo constante) contra la firma que acompaña al paquete.
    # Solo quien tiene el secreto pudo generar una firma válida -> corrige
    # CWE-494 (verificación de integridad antes de procesar).
    try:
        esperado = hmac_sha256(SECRETO, datos)
        return comparar_constante(esperado, bytes.fromhex(firma_hex))
    except (ValueError, TypeError):
        return False


def _tipo_real_valido(ruta: str) -> bool:
    # Valida el tipo REAL por magic bytes, no por la extensión -> corrige CWE-434.
    with open(ruta, "rb") as f:
        cabecera = f.read(6)
    es_zip = cabecera[:4] == b"PK\x03\x04"
    with open(ruta, "rb") as f:
        f.seek(257)
        es_tar = f.read(5) == b"ustar"
    return es_zip or es_tar


def _ruta_segura(base: str, objetivo: str) -> bool:
    # Bloquea path traversal: la ruta final debe quedar dentro de base.
    base_abs = os.path.realpath(base)
    destino = os.path.realpath(objetivo)
    return destino == base_abs or destino.startswith(base_abs + os.sep)


def procesar_paquete(ruta: str) -> str:
    if not _tipo_real_valido(ruta):
        raise ValueError("Tipo de archivo no válido")

    os.makedirs(EXTRACT_DIR, exist_ok=True)
    # Extracción segura validando cada miembro; NO se ejecuta ningún script.
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