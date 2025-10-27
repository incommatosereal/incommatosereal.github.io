---
title: Cómo desplegar T-Pot en la Nube
permalink: /Despliegue-T-Pot-en-Cloud/
toc: true
toc_label: Topics
excerpt: Conoce de qué manera operan los ciberatacantes en el mundo real.
sidebar:
  - main
tags:
  - Honeypot
  - T-Pot
  - VPS
  - Cloud
categories:
  - threat intelligence
  - cybersecurity
  - blue team
toc_sticky: true
seo_tittle: 
seo_description: Conoce de qué manera operan los ciberatacantes en el mundo real.
header:
  overlay_image: /assets/images/headers/honeypot-tpot.jpg
  overlay_filter: 0.7
  og_image: /assets/images/headers/honeypot-tpot.jpg
---
# Introducción
---
## ¿Qué es un Honeypot?

 En palabras simples, un **honeypot** es un sistema señuelo diseñado para simular servicios vulnerables, con el propósito de atraer ciberataques. Este tipo de herramientas son utilizadas por los equipos de ciberseguridad para **detectar, analizar y responder** a ataques cibernéticos sin poner en riesgo sistemas críticos y/o datos reales.
<br>
Con el propósito de realizar una serie de pruebas, utilizaremos la herramienta [`T-Pot`](https://github.com/telekom-security/tpotce) para desplegar múltiples instancias de `Honeypots`. Adicionalmente, luego de una investigación previa, el proveedor seleccionado para esta ocasión ha sido [`Vultr`](https://www.vultr.com/), debido a sus precios y la alternativa de pagar ya sea con `PayPal` o con criptomonedas.

> **¿Qué es T-Pot?**
> T-pot es una plataforma de `honeypots` de código abierto desarrollada por `Telekom Security`. Esta herramienta fue diseñada para **detectar y analizar ciberataques en tiempo real** presentando la información recopilada en `Dashboards` gracias a la herramienta `Kibana` (software de visualización y análisis de datos). 
{: .notice--info}

## ¿Por qué implementar un `Honeypot`?

Dentro de las razones más destacables para utilizar este tipo de herramientas, podemos mencionar las siguientes:
- Identificar **intentos de intrusión** antes de que lleguen a los sistemas reales.
- Identificar **vulnerabilidades o ataques desconocidos** (`zero-day`).
- Los datos de estos sistemas **no son reales**, por lo que si son comprometidos, no perderemos información crítica.
- Los datos que son recopilados en estos sistemas pueden ser utilizados para **entrenar a los equipos** de `Blue Team`.
<br>


# Instalación de T-Pot en un VPS (Virtual Private Server)
---
Comenzaremos **creando una nueva instancia** dentro de `Vultr`, podemos perfectamente utilizar el tipo `Cloud Compute - Shared CPU`, que comparte CPU en un mismo servidor, será más que suficiente para este tipo de pruebas

![image-center](/assets/images/posts/honeypot-tpot-vps.png)
{: .align-center}

> De acuerdo a los [requerimientos técnicos](https://github.com/telekom-security/tpotce?tab=readme-ov-file#system-requirements), necesitamos un servidor con algo de **potencia** para desplegar los honeypots eficientemente
{: .notice--danger}

En mi caso he elegido un servidor que cuesta alrededor de `$12 USD` a la semana

![image-center](/assets/images/posts/honeypot-tpot-vps-2.png)
{: .align-center}

Podemos **deshabilitar las copias de seguridad automáticas**, ya que no alojaremos información crítica en este servidor y sus fines son meramente realizar pruebas

![image-center](/assets/images/posts/honeypot-tpot-vps-3.png)
{: .align-center}

En los detalles del servidor, veremos la información general del estado de nuestro servidor, así como también las credenciales del usuario `root`




## Acceso inicial con SSH

Una vez desplegamos el servidor, podemos ingresar por `ssh` con las credenciales proporcionadas, podemos ingresar desde Windows o Linux, el único requerimiento es contar con un cliente `ssh` instalado en nuestro sistema.

Desde una terminal, podremos conectarnos con el siguiente comando.

~~~ bash
ssh root@[SERVER_IP]
~~~


## Instalación desde línea de comandos

Una vez accedimos al servidor, comenzaremos con la instalación de `tpot`. Primeramente actualizaremos los paquetes en el sistema e instalaremos las dependencias necesarias, en este caso, solamente `curl` (es posible que se encuentre instalado)

~~~ bash
root@vultr:~# apt update
root@vultr:~# apt -y install curl
~~~

Una vez las dependencias han sido actualizadas, crearemos un nuevo usuario, quien será designado para instalar `T-Pot`

> Recuerda usar contraseñas robustas que no sean fáciles de adivinar, como combinaciones de caracteres especiales y números aleatorios, por ejemplo `4ewD$R3_:#$`
{: .notice--danger}

~~~ bash
root@vultr:~# adduser tuser

New password:
Retype new password:
passwd: password updated successfully
Changing the user information for tuser
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n]
Adding new user `tuser' to supplemental / extra groups `users' ...
Adding user `tuser' to group `users' ...
~~~

A continuación, agregaremos al nuevo usuario en el grupo `sudo` con el comando `usermod`

~~~ bash
root@vultr:~# usermod -aG sudo tuser
~~~

Una vez el usuario esté configurado, podremos continuar con la instalación de `T-Pot`. Primeramente debemos cambiar al nuevo usuario

~~~ bash
root@vultr:~# su tuser
tuser@vultr:/root$ cd # Ir al directorio /home
~~~

Desde el repositorio se recomienda utilizar el siguiente comando para la instalación, aquí necesitaremos utilizar la contraseña que asignamos al usuario que agregamos

~~~
tuser@vultr:~$ env bash -c "$(curl -sL https://github.com/telekom-security/tpotce/raw/master/install.sh)"

 _____     ____       _      ___           _        _ _
|_   _|   |  _ \ ___ | |_   |_ _|_ __  ___| |_ __ _| | | ___ _ __
  | |_____| |_) / _ \| __|   | || '_ \/ __| __/ _` | | |/ _ \ '__|
  | |_____|  __/ (_) | |_    | || | | \__ \ || (_| | | |  __/ |
  |_|     |_|   \___/ \__|  |___|_| |_|___/\__\__,_|_|_|\___|_|


### This script will now install T-Pot and all of its dependencies.

### Install? (y/n) y


### Now installing required packages ...

[sudo] password for tuser:
~~~

A continuación se nos preguntará sobre el tipo de instalación que realizaremos, podemos simplemente elegir la versión `Standard` 

![image-center](/assets/images/posts/honeypot-tpot-cli.png)
{: .align-center}

Procederemos con la creación del usuario para acceder vía web, en este caso, he elegido el mismo nombre de usuario pero con una **contraseña distinta**

![image-center](/assets/images/posts/honeypot-tpot-cli-2.png)
{: .align-center}

Cuando se complete la instalación, veremos el siguiente mensaje, donde se nos indica que el acceso `ssh` ah cambiado al puerto `64295` 

![image-center](/assets/images/posts/honeypot-tpot-cli-3.png)
{: .align-center}

En caso de que necesitemos acceder por `ssh`, usaremos el siguiente comando

~~~ bash
ssh tuser@[SERVER_IP] -p 64295
~~~

Cuando la instalación finaliza, es **necesario aplicar un reinicio al servidor**, desde la sesión lo realizaremos de la siguiente manera

~~~ bash
tuser@vultr:~$ sudo reboot now
~~~


## Servicios Vulnerables

A continuación se muestran algunos de los diferentes servicios vulnerables que despliega `T-Pot`.

![image-center](/assets/images/posts/honeypot-tpot-test.png)
{: .align-center}

Si utilizamos una herramienta de escaneo para ver las tecnologías web, podemos ver cómo se utilizan servicios con versiones muy antiguas, ideales para bots o escáneres que recolectan o automatizan explotación a diferentes servicios

![image-center](/assets/images/posts/honeypot-tpot-test-2.png)
{: .align-center}
<br>


# Acceso Web Inicial

Una vez ya instalamos `T-Pot`, podemos acceder desde un navegador, debemos ingresar por el puerto `64297`

~~~ bash
https://[SERVER_IP]:64297/
~~~

> Cuando intentemos cargar la web, seguramente nuestro navegador bloquee la conexión o muestre una advertencia, esto es debido a que el certificado SSL que emplea el servidor web es auto-firmado
{: .notice--warning} 

![image-center](/assets/images/posts/honeypot-tpot-web.png)
{: .align-center}

Antes de que me juzgues, ya sé que no censuré la IP, porque el servidor ya no está activo y no existe, así que continuemos

## Herramientas

Al acceder con las credenciales que habíamos creado, veremos diversas herramientas que podemos utilizar

![image-center](/assets/images/posts/honeypot-tpot-web-2.png)
{: .align-center}

### Attack Map

Un mapa donde puedes ver el tráfico que se dirige a nuestra serie de `Honeypots` en tiempo real, registrando datos como la IP, ubicación y servicios afectados

![image-center](/assets/images/posts/honeypot-tpot-attack-map.png)
{: .align-center}

### Cyberchef

Herramienta ampliamente conocida por sus funcionalidades de manipulación, decodificación y descifrado y conversión de datos. Este servicio podremos utilizarlo como una instancia local

![image-center](/assets/images/posts/honeypot-tpot-cyberchef.png)
{: .align-center}

### Elasticvue

Herramienta de código abierto diseñada administración y exploración de datos

![image-center](/assets/images/posts/honeypot-tpot-elasticvue.png)
{: .align-center}

### Kibana

Herramienta de visualización de datos de código abierto. Será la herramienta principal que utilizaremos para nuestros análisis.

A penas desplegamos el `honeypot` veremos actividad en el dashboard principal, con una cantidad considerable de actividad para llevar activo menos de `15` minutos

![image-center](/assets/images/posts/honeypot-tpot-kibana.png)
{: .align-center}

El dashboard principal contiene un resumen de la actividad recolectada y la muestra en base a ciertos criterios, tales como **puertos de destino, país de origen de las IP, motivo de la actividad, reputación de las IP, etc.**

<div class="video-center">
  <video controls>
    <source src="{{ '/assets/images/posts/honeypot-tpot-demo.mp4' | relative_url }}" type="video/mp4">
    Tu navegador no soporta la reproducción de videos.
  </video>
</div>
<br>


# Análisis de Resultados obtenidos (2 Semanas)

Para recopilar actividad maliciosa, el servidor utilizado en este artículo quedó activo durante dos semanas. A simple vista notaremos la gran cantidad de ataques y escaneos que han recibido la serie de honeypots desplegados

> 2 Millones de ataques registrados en dos semanas, imagina la cantidad de actividad sospechosa que deben recibir servicios críticos.
{: .notice--warning}

![image-center](/assets/images/posts/honeypot-tpot-resultados.png)
{: .align-center}

En la siguiente imagen podemos ver las credenciales que más intentaron los atacantes, donde destaca `root` como usuario y la contraseña `1235456`

![image-center](/assets/images/posts/honeypot-tpot-resultados-2.png)
{: .align-center}

A continuación podemos ver una recolección de recursos vía web que los atacantes descargaron una vez ganaron acceso vía SSH (Honeypot `Cowrie`)

![image-center](/assets/images/posts/honeypot-tpot-resultados-3.jpg)
{: .align-center}

Detectamos actividad que comparte ciertos patrones, como **descargas de recursos específicos**, que **descargan malware** para tratar de infectar dispositivos de **múltiples arquitecturas**.


## Reflexión

Aunque servicios críticos expuestos en internet posean una **seguridad generalmente robusta**, muchas empresas poco experimentadas **no consideran la seguridad** una prioridad fundamental, esto podemos verlo reflejado en **ciberataques y fugas de información** de diversas empresas reconocidas. 

Es por eso que existen **legislaciones cibernéticas** que exigen estándares mínimos de seguridad para los servicios que se despliegan hacia la red. Allí afuera nadie está a salvo, este tipo de herramientas nos acercan a comprender un poco cómo operan las redes de cibercriminales.
Por último te dejo la cita del día, muchas gracias por leer.

> If the single man plant himself indomitably on his instincts, and there abide, the huge world will come round to him.
> — Ralph Emerson
{: .notice--info}
