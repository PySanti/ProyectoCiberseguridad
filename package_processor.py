import tarfile
import zipfile
import os
import subprocess

EXTRACT_DIR = "paquetes_extraidos"


def procesar_paquete(ruta):
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    # Aquí descomprimimos el paquete sin revisar de dónde viene ni si alguien lo
    # cambió. Ademas, al descomprimir así, un archivo dentro del paquete podría
    # terminar guardándose fuera de la carpeta prevista. Faltaría comprobar que
    # el paquete es legítimo y descomprimir revisando cada archivo.
    if ruta.endswith(".tar"):
        with tarfile.open(ruta) as t:
            t.extractall(EXTRACT_DIR)
    else:
        with zipfile.ZipFile(ruta) as z:
            z.extractall(EXTRACT_DIR)

    # Y aquí está lo más grave, si el paquete trae un "update.sh", el servidor lo
    # ejecuta solo, confiando en que es bueno. Eso deja que el atacante corra lo
    # que quiera en el servidor. Nunca deberíamos ejecutar algo que nos llega de
    # afuera sin revisarlo antes.
    script = os.path.join(EXTRACT_DIR, "update.sh")
    if os.path.exists(script):
        subprocess.run(["bash", script])
        return "actualizacion aplicada (update.sh ejecutado)"
    return "paquete extraido sin script de actualizacion"
