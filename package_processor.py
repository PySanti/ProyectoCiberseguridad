import tarfile
import zipfile
import os
import subprocess

EXTRACT_DIR = "paquetes_extraidos"


def procesar_paquete(ruta):
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    # CWE-494 (Download of Code Without Integrity Check): descomprime el paquete
    # sin verificar firma digital, hash ni procedencia. Además extractall() no
    # protege contra path traversal: un miembro del tar llamado "../../x" puede
    # escribir FUERA del directorio de extracción. FALTA: verificar la integridad
    # (HMAC/firma) del paquete y extraer de forma segura validando cada ruta.
    if ruta.endswith(".tar"):
        with tarfile.open(ruta) as t:
            t.extractall(EXTRACT_DIR)
    else:
        with zipfile.ZipFile(ruta) as z:
            z.extractall(EXTRACT_DIR)

    # CWE-494 + MITRE T1059 (Command and Scripting Interpreter): el servidor
    # EJECUTA automáticamente el script que venga dentro del paquete, confiando
    # en que es legítimo. Esto es ejecución de código arbitrario del atacante.
    # FALTA: nunca ejecutar contenido recibido; procesar solo tras validar firma.
    script = os.path.join(EXTRACT_DIR, "update.sh")
    if os.path.exists(script):
        subprocess.run(["bash", script])
        return "actualizacion aplicada (update.sh ejecutado)"
    return "paquete extraido sin script de actualizacion"