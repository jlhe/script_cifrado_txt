#!/usr/bin/env python3
"""
mini_file_encryptor.py

Autor: José Luis Herrera
Fecha: 2025

Este script fue creado como parte de un laboratorio en un entorno local y controlado, 
con el objetivo de mostrar de manera sencilla cómo se puede cifrar y descifrar 
un archivo de texto plano. 

La idea es demostrar lo siguiente:
1. Un archivo .txt con contenido legible puede abrirse normalmente y también visualizarse con herramientas como `strings`.
2. Una vez cifrado, el archivo deja de ser legible tanto en un editor de texto como en `strings`, 
   además de que hasta su nombre original se pierde (el archivo pasa a tener un nombre aleatorio sin extensión).
3. Posteriormente, puede ser descifrado con la clave correcta, recuperando tanto el contenido como el nombre original.

⚠️ Importante:
- Este esquema es **solo educativo**. No debe usarse en producción porque utiliza XOR + PBKDF2, 
  que carecen de las garantías de seguridad modernas como integridad o resistencia frente a atacantes reales.
- El objetivo es visualizar qué pasa en la práctica con los archivos cifrados y la necesidad de 
  implementar contramedidas serias frente a ataques en dispositivos.

Formato del archivo cifrado:
  MAGIC(6) + SALT(16) + name_len(2 BE) + enc_name(name_len) + enc_data(...)

Donde:
- MAGIC es un identificador fijo para reconocer que el archivo fue generado por este script.
- SALT es un valor aleatorio único usado en el derivado de la clave.
- name_len es la longitud del nombre cifrado.
- enc_name es el nombre del archivo original cifrado.
- enc_data es el contenido del archivo cifrado.

Uso:
  python mini_file_encryptor.py encrypt archivo.txt
  python mini_file_encryptor.py decrypt archivo_cifrado_sin_ext
"""

import sys, os, uuid, struct, hashlib, hmac
from os import urandom

MAGIC = b"MINENC1"  # Identificador fijo del formato
SALT_LEN = 16
ITER = 200_000  # iteraciones de PBKDF2 (para derivar la clave)

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITER, dklen=32)

def keystream(key: bytes, length: int):
    """Genera un flujo de bytes pseudoaleatorio a partir de HMAC-SHA256 (para XOR)."""
    counter = 0
    out = bytearray()
    while len(out) < length:
        ctr = counter.to_bytes(8, 'big')
        block = hmac.new(key, ctr, hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])

def xor_bytes(data: bytes, key: bytes) -> bytes:
    ks = keystream(key, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))

def encrypt_file(path: str, password: str):
    if not path.lower().endswith('.txt'):
        raise SystemExit("Solo .txt permitidos.")
    with open(path, 'rb') as f:
        plain = f.read()
    salt = urandom(SALT_LEN)
    key = derive_key(password, salt)
    # cifrar nombre
    name = os.path.basename(path).encode('utf-8')
    enc_name = xor_bytes(name, key)
    # cifrar contenido
    enc_data = xor_bytes(plain, key)
    # salida con nombre aleatorio sin extensión
    out_name = uuid.uuid4().hex
    with open(out_name, 'wb') as out:
        out.write(MAGIC)
        out.write(salt)
        out.write(struct.pack('>H', len(enc_name)))
        out.write(enc_name)
        out.write(enc_data)
    print(f"Cifrado -> {out_name} (nombre original cifrado en encabezado)")

def decrypt_file(path: str, password: str):
    with open(path, 'rb') as f:
        content = f.read()
    if not content.startswith(MAGIC):
        raise SystemExit("No es un archivo compatible (MAGIC no coincide).")
    idx = len(MAGIC)
    salt = content[idx:idx+SALT_LEN]; idx += SALT_LEN
    name_len = struct.unpack('>H', content[idx:idx+2])[0]; idx += 2
    enc_name = content[idx:idx+name_len]; idx += name_len
    enc_data = content[idx:]
    key = derive_key(password, salt)
    try:
        name = xor_bytes(enc_name, key).decode('utf-8')
    except Exception:
        raise SystemExit("Contraseña incorrecta o nombre corrupto.")
    try:
        plain = xor_bytes(enc_data, key)
    except Exception:
        raise SystemExit("Contraseña incorrecta o datos corruptos.")
    out_path = name + '.restored.txt'
    with open(out_path, 'wb') as f:
        f.write(plain)
    print(f"Descifrado -> {out_path}")

def usage():
    print("Uso:")
    print("  python mini_file_encryptor.py encrypt archivo.txt")
    print("  python mini_file_encryptor.py decrypt archivo_cifrado_sin_ext")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 3: usage()
    cmd, filepath = sys.argv[1], sys.argv[2]
    if not os.path.exists(filepath):
        raise SystemExit("Archivo no encontrado.")
    pwd = input("Contraseña: ")
    if cmd == 'encrypt':
        encrypt_file(filepath, pwd)
    elif cmd == 'decrypt':
        decrypt_file(filepath, pwd)
    else:
        usage()
