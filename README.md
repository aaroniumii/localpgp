# LocalPGP

LocalPGP es una aplicación de escritorio ligera escrita en Python que facilita el cifrado y descifrado de archivos y textos utilizando GnuPG de forma local. La interfaz gráfica está construida con Tkinter y permite trabajar con múltiples destinatarios, firmar con una clave seleccionada y realizar importaciones de claves públicas sin tener que utilizar la línea de comandos directamente.

## Características principales

- **Gestión de claves**: detecta las claves públicas disponibles en el llavero local e incluye herramientas para importar nuevas claves.
- **Cifrado y descifrado de archivos**: procesa directorios completos, cifra sus contenidos y opcionalmente elimina los originales tras generar la versión cifrada.
- **Firmado y verificación**: genera firmas ASCII para archivos o textos y comprueba su validez de forma local.
- **Cifrado y descifrado de texto**: permite introducir texto libre, cifrarlo para uno o varios destinatarios y copiar el resultado en formato ASCII armor.
- **Registro y seguimiento**: muestra el progreso de las operaciones y un registro de eventos para diagnosticar problemas.

## Requisitos

- Python 3.9 o superior.
- GnuPG instalado y accesible mediante el comando `gpg`.
- Tkinter (incluido en la mayoría de distribuciones estándar de Python; en Linux puede requerir el paquete `python3-tk`).

## Instalación

1. Clona este repositorio y entra en el directorio del proyecto:
   ```bash
   git clone https://github.com/<usuario>/localpgp.git
   cd localpgp
   ```
2. (Opcional) Crea y activa un entorno virtual:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # En Windows: .venv\\Scripts\\activate
   ```
3. Instala las dependencias declaradas (actualmente solo dependencias estándar de la biblioteca estándar de Python y GnuPG externo).

## Uso

Ejecuta la aplicación a través del módulo principal:

```bash
python app.py
```

Al iniciar se mostrará la ventana principal con las siguientes secciones:

- **Clave de firma**: selecciona la clave con la que quieres firmar los mensajes (opcional).
- **Destinatarios**: marca las claves públicas que recibirán los mensajes cifrados.
- **Pestaña Archivos**: elige un directorio y pulsa "Cifrar", "Firmar", "Descifrar" o "Verificar" según la operación que necesites.
- **Pestaña Texto**: introduce texto plano para cifrarlo o firmarlo, o pega texto cifrado/firmado para descifrarlo o verificarlo.
- **Registro**: revisa el progreso y los mensajes de diagnóstico.

Durante las operaciones que requieran passphrase, la aplicación solicitará la contraseña de la clave privada correspondiente.

## Pruebas

Actualmente el proyecto no incluye una batería de pruebas automatizadas. Se recomienda verificar manualmente las funciones principales mediante GnuPG antes de su uso en entornos sensibles.

## Licencia

Este proyecto se distribuye bajo los términos de la licencia MIT. Consulta el archivo `LICENSE` para más detalles.
