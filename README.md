# Mini File Encryptor

Autor: José Luis Herrera  
Fecha: 2025  

Este proyecto es parte de un laboratorio educativo en un entorno **local y controlado**.  
El objetivo es mostrar de manera simple cómo un archivo `.txt` puede ser cifrado y dejar de ser legible, 
y cómo luego puede recuperarse con la clave correcta.

---

## Objetivo del laboratorio

1. **Archivo original**: legible en Bloc de notas o con `strings`.
2. **Archivo cifrado**: pierde legibilidad, incluso con `strings`. Además pierde su extensión y nombre original.
3. **Archivo descifrado**: vuelve a ser legible, con el nombre original restaurado.

---

## Uso

```bash
# Cifrar
python mini_file_encryptor.py encrypt secreto.txt

# Descifrar
python mini_file_encryptor.py decrypt <archivo_cifrado_sin_extension>
