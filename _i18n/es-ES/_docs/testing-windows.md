# Cómo probar motores basados en Windows

En esta página usamos `microengine-mywindowsengine` como nombre de directorio del micromotor. En tus pruebas usarás el nombre de directorio de tu propio micromotor. Asimismo, en estas instrucciones hemos abreviado el indicador de entrada de comandos de PowerShell a `PS >` para mejorar la legibilidad de los comandos. El indicador real de PowerShell que veas será similar a: `(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine>`. Del mismo modo, en la línea de comandos de Linux, hemos abreviado la indicación de entrada a `$`. En la realidad, habrá más texto a la izquierda del símbolo `$`.

## Pruebas unitarias

Usaremos `tox` para probar nuestro micromotor. Este comando ejecutará todas las pruebas unitarias que añadas en `tests/scan_test.py`.

Activa un entorno virtual en una ventana de PowerShell y ejecuta el comando `tox` desde el directorio base de tu micromotor.

```powershell
PS > tox
```

La salida será parecida a esto:

```powershell
GLOB sdist-make: C:\Users\user\microengine-mywindowsengine\setup.py
py35 create: C:\Users\user\microengine-mywindowsengine\.tox\py35
py35 installdeps: -rrequirements.txt
py35 inst: C:\Users\user\microengine-mywindowsengine\.tox\dist\polyswarm_mywindowsengine-0.1.zip
py35 installed: aiodns==1.1.1,aiohttp==2.3.1,aioresponses==0.5.0,async-generator==1.10,async-timeout==3.0.1,asynctest==0.12.2,atomicwrites==1.2.1,attrdict==2.0.0,attrs==18.2.0,base58==0.2.5,certifi==2018.11.29,chardet==3.0.4,clamd==1.0.2,click==6.7,colorama==0.4.1,coverage==4.5.1,cytoolz==0.9.0.1,eth-abi==1.3.0,eth-account==0.3.0,eth-hash==0.2.0,eth-keyfile==0.5.1,eth-keys==0.2.0b3,eth-rlp==0.1.2,eth-typing==2.0.0,eth-utils==1.4.0,hexbytes==0.1.0,hypothesis==3.82.1,idna==2.7,lru-dict==1.1.6,malwarerepoclient==0.1,more-itertools==4.3.0,multidict==4.5.2,parsimonious==0.8.1,pathlib2==2.3.3,pluggy==0.8.0,polyswarm-client==0.2.0,polyswarm-mywindowsengine==0.1,py==1.7.0,pycares==2.3.0,pycryptodome==3.7.2,pypiwin32==223,pytest==3.9.2,pytest-asyncio==0.9.0,pytest-cov==2.6.0,pytest-timeout==1.3.2,python-json-logger==0.1.9,python-magic==0.4.15,pywin32==224,requests==2.19.1,rlp==1.0.3,six==1.11.0,toml==0.10.0,toolz==0.9.0,tox==3.4.0,urllib3==1.23,virtualenv==16.1.0,web3==4.6.0,websockets==6.0,yara-python==3.7.0,yarl==1.2.6
py35 run-test-pre: PYTHONHASHSEED='432'
py35 runtests: commands[0] | pytest -s
================================================= test session starts =================================================
platform win32 -- Python 3.5.4, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('C:\\Users\\user\\microengine-mywindowsengine\\.hypothesis\\examples')
rootdir: C:\Users\user\microengine-mywindowsengine, inifile:
plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
collected 1 item

tests\scan_test.py .

================================================== warnings summary ===================================================
c:\users\user\microengine-mywindowsengine\.tox\py35\lib\site-packages\eth_utils\applicators.py:32: DeprecationWarning: combine_argument_formatters(formatter1, formatter2)([item1, item2])has been deprecated and will be removed in a subsequent major version release of the eth-utils library. Update your calls to use apply_formatters_to_sequence([formatter1, formatter2], [item1, item2]) instead.
  "combine_argument_formatters(formatter1, formatter2)([item1, item2])"

-- Docs: https://docs.pytest.org/en/latest/warnings.html
======================================== 1 passed, 1 warnings in 0.52 seconds =========================================
_______________________________________________________ summary _______________________________________________________
  py35: commands succeeded
  congratulations :)
```

Puedes ignorar completamente el aviso `combine_argument_formatters`.

## Pruebas de integración

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong>
    Por el momento, las pruebas de integración de motores basados en Windows solo son posibles a través de VirtualBox.
    Consulta <a href="/development-environment-windows/">Entorno de desarrollo Windows</a> para obtener más información.
  </p>
</div>

Las pruebas de integración de motores basados en Windows requieren dos máquinas virtuales (máquinas virtuales/invitados):

1. Un invitado de Windows para ejecutar el motor basado en Windows (ya lo tenemos).
2. Un invitado de Linux para levantar una red de pruebas local para PolySwarm (lo crearemos ahora).

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong> Las recomendaciones aquí incluidas son el resultado de un trabajo minucioso. Te recomendamos encarecidamente que realices las pruebas usando las indicaciones exactas proporcionadas. Nos resultará más difícil prestarte ayuda si empleas cualquier otra configuración.
  </p>
</div>

### Crea un invitado de Linux

#### Crea la máquina virtual

Crea una máquina virtual Linux usando los siguientes parámetros:

* Nombre: `polyswarm_lin`
* Tipo: Linux
* Versión: Ubuntu (64 bits)
* RAM: 8 GB o más
* CPU: 4 núcleos o más
* memoria de vídeo: 128 MB
* espacio en disco: 50 GB o más

Usa la configuración por defecto para las demás opciones. Sobre todo, NO habilites la aceleración 3D.

Por lo general, preferirás asignar los recursos adicionales de RAM y CPU a la máquina virtual Linux para que la red de pruebas ofrezca un mejor rendimiento.

#### Instala Xubuntu 18.04 amd64

* [Descarga la ISO de Xubuntu 18.04 amd64](https://xubuntu.org/release/18-04/)

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong>
    Para crear invitados en VirtualBox, recomendamos sin lugar a dudas Xubuntu frente a Ubuntu.
    Ubuntu presenta una serie de problemas de retardo a nivel visual y tiende a producir cuelgues totales de vídeo cuando se instalan las herramientas de VirtualBox.
  </p>
</div>

Usa la ISO descargada para instalar Xubuntu en la máquina virtual.

#### (Opcional) Instala adiciones de invitados de VirtualBox

Las adiciones de invitados ("Guest Additions") son necesarias para disfrutar de las funciones de portapapeles compartido o copiar y pegar entre el invitado y el host.

[Consulta el manual de VirtualBox](https://www.virtualbox.org/manual/ch04.html).

### Configura la red de comunicaciones entre invitados

Necesitamos establecer una red interna para que nuestras máquinas virtuales de Linux y Windows puedan comunicarse entre sí.

Antes de empezar, apaga tanto el invitado de Linux como el de Windows.

En tu host de Windows, abre una instancia de PowerShell y desplázate hasta el directorio de instalación de VirtualBox:

```powershell
PS > pushd $Env:Programfiles\Oracle\VirtualBox
```

Tu indicador de entrada de comandos debería ser similar a esto:

```powershell
PS C:\Program Files\Oracle\VirtualBox>
```

#### Crea una red PolySwarm interna

Crea y asigna una red interna específica de Polyswarm a cada máquina virtual.

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong>
    Estos comandos reconfigurarán el adaptador de red #5 en tus máquinas virtuales.
    Si ya lo estás usando, lo cual es poco probable, cambia su número a continuación.
  </p>
</div>

```powershell
PS > .\VBoxManage.exe modifyvm "polyswarm_win" --nic5 intnet
PS > .\VBoxManage.exe modifyvm "polyswarm_win" --intnet5 "polyswarm_net"
PS > .\VBoxManage.exe modifyvm "polyswarm_lin" --nic5 intnet
PS > .\VBoxManage.exe modifyvm "polyswarm_lin" --intnet5 "polyswarm_net"
```

<div class="m-flag">
  <p>
    <strong>Información:</strong>
    Para saber más sobre cómo crear redes internas en VirtualBox, consulta su <a href="https://www.virtualbox.org/manual/ch06.html#network_internal">documentación oficial</a>.
  </p>
</div>

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong>
    No verás un "adaptador #5" enumerado en la configuración de la máquina virtual ni dentro de ella.
    Lo que sí verás es que tu máquina virtual tendrá al menos dos adaptadores de red activos y, al
    añadir <code>"polyswarm_net"</code> al adaptador #5, debería ser más fácil encontrarlo, al convertirse en
    la interfaz de red con el número más alto dentro de la máquina virtual.
  </p>
</div>

#### Configura las máquinas virtuales con direcciones IP estáticas

Arranca la máquina virtual `polyswarm_lin` y edita la configuración de red para asignar al nuevo adaptador los siguientes datos de IPv4 estática:

* Dirección: `10.10.42.101`
* Máscara de red: `255.255.255.0`
* Puerta de enlace: `10.10.42.1`

Si no te queda claro a qué interfaz de red debes aplicar estos ajustes, ejecuta el comando `ifconfig -a`: la salida resultante debería incluir varias interfaces de red que empiecen por `enp0s`. Normalmente, la interfaz que se modificará será la que posea el número más alto tras ese prefijo.

Arranca la máquina virtual `polyswarm_win` y edita la configuración de red para que el nuevo adaptador use estos valores de IPv4 estática:

* Dirección: `10.10.42.102`
* Máscara de red: `255.255.255.0`
* Puerta de enlace: `10.10.42.1`

Si no te queda claro a qué interfaz de red debes aplicar estos ajustes, ejecuta el comando `ipconfig /all`: la salida resultante debería incluir varias interfaces de red que empiecen por `Ethernet adapter Ethernet`. Normalmente, la interfaz que se modificará será la que posea el número más alto tras ese prefijo.

#### Configura la máquina virtual Windows para resolución de DNS con `polyswarmd`

Por último, tu máquina virtual Windows necesita saber que tu máquina virtual Linux hospeda `polyswarmd`. Abre una instancia elevada de Notepad y añade `polyswarmd` al final del archivo `C:\Windows\System32\Drivers\etc\hosts`:

    # Copyright (c) 1993-2009 Microsoft Corp.
    #
    # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
    #
    # This file contains the mappings of IP addresses to host names. Each
    # entry should be kept on an individual line. The IP address should
    # be placed in the first column followed by the corresponding host name.
    # The IP address and the host name should be separated by at least one
    # space.
    #
    # Additionally, comments (such as these) may be inserted on individual
    # lines or following the machine name denoted by a '#' symbol.
    #
    # For example:
    #
    #      102.54.94.97     rhino.acme.com          # source server
    #       38.25.63.10     x.acme.com              # x client host
    
    # localhost name resolution is handled within DNS itself.
    #   127.0.0.1       localhost
    #   ::1             localhost
    
    10.10.42.101 polyswarmd
    

#### Verifica la configuración

Finalmente, verifica que Windows resuelva `polyswarmd` a tu máquina virtual Linux y pueda alcanzarla. Antes, realiza una prueba de DNS así:

```powershell
PS > Resolve-DnsName -name polyswarmd
```

La salida debería parecerse a esto:

```powershell
Name                                           Type   TTL   Section    IPAddress
----                                           ----   ---   -------    ---------
polyswarmd                                     A      86400 Answer     10.10.42.101
```

A continuación, haz una prueba de *ping*:

```powershell
PS > ping polyswarmd
```

La salida debería parecerse a esto:

```powershell
Pinging polyswarmd [10.10.42.101] with 32 bytes of data:
Reply from 10.10.42.101: bytes=32 time<1ms TTL=64
```

Si obtienes esos mismos resultados, habrás configurado todo correctamente y podrás continuar.

### Configura la máquina virtual Linux para alojar una red de pruebas local

#### Instalar Docker

Hemos *dockerizado* la versión de pruebas del mercado de PolySwarm. Para usarla, debes instalar Docker-CE (la base) y Docker Compose. Si no dispones de una instalación reciente de Docker, [instálalo ahora](https://www.docker.com/community-edition).

En Xubuntu:

```bash
$ sudo apt-get update && sudo apt-get install -y curl
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ chmod +x get-docker.sh
$ ./get-docker.sh
$ sudo usermod -aG docker $USER
```

Cierra la sesión y vuelve a iniciarla.

Al terminar, comprueba que la instalación funcione ejecutando el siguiente comando:

```bash
$ docker ps
```

Que debería devolver:

    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    

Además [instala `docker-compose`](https://docs.docker.com/compose/install/).

En Xubuntu:

```bash
$ curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o docker-compose
$ sudo mv docker-compose /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
```

Cuando completes la instalación, comprueba que funcione correctamente.

```bash
$ docker-compose -v
```

Esto debería mostrar, al menos: `docker-compose version 1.21.1, build 5a3f1a3`.

<div class="m-flag">
  <p>
    <strong>Información:</strong>
    Si te encuentras con errores de permisos al ejecutar los comandos <code>docker</code> o <code>docker-compose</code>, <a href="https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user">configura tu cuenta de usuario para darle permisos a Docker</a>.
  </p>
</div>

#### Instalar Git

Necesitaremos descargarnos varios repositorios de código fuente. Lo más fácil es usar Git. [Instala Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) para tu entorno de desarrollo.

En Xubuntu 18.04:

```bash
$ sudo apt update && sudo apt install -y git
```

#### Descarga `orchestration`

Usaremos el proyecto [`orchestration`](https://github.com/polyswarm/orchestration) de PolySwarm para lanzar nuestra red de pruebas de desarrollo. Nosotros empleamos ese mismo proyecto para llevar a cabo pruebas de integración de extremo a extremo.

Clona `orchestration`:

```bash
$ git clone https://github.com/polyswarm/orchestration
```

### Prueba tu motor

Ahora tendremos que pasar varias veces de una máquina virtual a otra. Primero arrancaremos la red de pruebas en la máquina virtual Linux. Después arrancaremos tu micromotor en la máquina virtual Windows. Por último, arrancaremos el embajador en la máquina virtual Linux.

#### Máquina virtual Linux: lanza la red de pruebas

En tu máquina virtual Linux, pon en marcha un subconjunto de la red de pruebas dejando al margen el micromotor `microengine` incluido por defecto (lo reemplazaremos por el nuestro) y también el embajador `ambassador` por el momento (lo arrancaremos después). Para ello, ejecuta los siguientes comandos en una ventana de terminal nueva:

```bash
$ cd orchestration
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

Habrá que esperar unos minutos hasta que `polyswarmd` esté disponible. Durante este tiempo verás muchos mensajes del tipo `Problem with dial... dial tcp connection refused.` y `chain for config not available in consul yet`. Ten paciencia: estos errores son normales mientras se está inicializando la red de pruebas.

Una vez lo esté, comenzará a proporcionar respuestas a los clientes. Por ejemplo:

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

Ahora ya es seguro avanzar hasta el paso siguiente.

#### Máquina virtual Windows: prueba la conexión a `polyswarmd`

En tu máquina virtual Windows, confirma que `polyswarmd` esté disponible y listo para responder a tu micromotor. Para ello, ejecuta el siguiente comando en PowerShell:

```powershell
PS > curl -UseBasicParsing http://polyswarmd:31337/status
```

Debería generar este resultado:

```powershell
StatusCode        : 200
StatusDescription : OK
Content           : {"result":{"home":{"block":189,"reachable":true,"syncing":false},"ipfs":{"reachable":true},"side":{
                    "block":191,"reachable":true,"syncing":false}},"status":"OK"}
...
```

Lo verdaderamente importante de esa respuesta es `"status":"OK"`.

#### Máquina virtual Windows VM: lanza `balancemanager` y tu motor

Abre una nueva ventana de PowerShell y activa tu entorno virtual. A continuación, cámbiate al directorio de tu micromotor.

En él, instala los requisitos previos del micromotor y el propio micromotor.

```powershell
PS > pip install -r requirements.txt
PS > pip install .
```

La utilidad `balancemanager`, basada en `polyswarm-client`, nos ayudará a mantener un saldo de (falso) néctar (NCT) de PolySwarm en la cadena paralela de nuestra red de pruebas local, que es donde se llevarán a cabo todas las transacciones.

En esa misma ventana de PowerShell, lanza `balancemanager` del siguiente modo:

```powershell
PS > balancemanager maintain --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport 100000 500000
```

Mostrará un resultado similar a esto:

```powershell
INFO:root:2018-12-06 16:55:30,800 Logging in text format.
INFO:balancemanager.__main__:2018-12-06 16:55:30,815 Maintaining the minimum balance by depositing 500000.0 when it falls below 100000.0
INFO:polyswarmclient:2018-12-06 16:55:31,440 Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:polyswarmclient:2018-12-06 16:55:32,050 Received connected on chain home: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:55:32,050 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:55:32,050 Received block on chain home: {'number': 18182}
INFO:polyswarmclient:2018-12-06 16:55:32,096 Received connected on chain side: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:55:32,096 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:55:33,034 Received block on chain home: {'number': 18183}
INFO:polyswarmclient:2018-12-06 16:55:33,080 Received block on chain side: {'number': 18206}
```

Cuando empiecen a mostrarse mensajes `Received block on chain` ("bloque recibido en la cadena") podrás lanzar tu micromotor.

Abre otra ventana nueva de PowerShell y activa tu entorno virtual. A continuación, cámbiate al directorio de tu micromotor.

Ejecuta tu micromotor usando un comando similar al siguiente. Asegúrate de modificar el valor del argumento `--backend` para que coincida con el nombre del directorio del paquete de tu micromotor (es decir, el directorio de `src/`):

```powershell
PS > microengine --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport --testing 2 --backend acme_myeicarengine
```

Mostrará un resultado similar a esto:

```powershell
INFO:root:2018-12-06 16:56:20,674 Logging in text format.
INFO:polyswarmclient:2018-12-06 16:56:21,299 Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:polyswarmclient:2018-12-06 16:56:21,690 Received connected on chain side: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:56:21,690 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:56:22,691 Received block on chain side: {'number': 18255}
...
INFO:polyswarmclient:2018-12-06 16:56:44,205 Received block on chain side: {'number': 18277}
INFO:polyswarmclient:2018-12-06 16:56:44,283 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18297', 'uri': 'QmVoLQJ2nm4V6XiZXC9vEUrCaTHdkXS7y3crztZ5HwC9iK', 'guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'amount': '62500000000000000'}
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:44,283 Testing mode, 1 bounties remaining
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:44,455 Responding to bounty: 48dd5360-47a3-4e12-a975-eb30fed5cc22
INFO:polyswarmclient:2018-12-06 16:56:45,237 Received block on chain side: {'number': 18278}
INFO:polyswarmclient:2018-12-06 16:56:46,393 Received block on chain side: {'number': 18279}
INFO:polyswarmclient.events:2018-12-06 16:56:46,440 OnNewBountyCallback callback results: [[{'bounty_guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'mask': [True], 'bid': '62500000000000000', 'commitment': '44296088244268214239924675885675264686302131561550908677050134822720003742540', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}]]
INFO:polyswarmclient:2018-12-06 16:56:46,456 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18299', 'uri': 'QmVjWbqv8aXEPE53vDYS9r3wG7odJjrHXf7ci1xfLyNAEU', 'guid': '40862925-3e00-41b2-a946-365135d87070', 'amount': '62500000000000000'}
INFO:polyswarmclient:2018-12-06 16:56:46,456 Received assertion on chain side: {'bounty_guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'mask': [True], 'bid': '62500000000000000', 'commitment': '44296088244268214239924675885675264686302131561550908677050134822720003742540', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:46,456 Testing mode, 0 bounties remaining
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:46,643 Responding to bounty: 40862925-3e00-41b2-a946-365135d87070
INFO:polyswarmclient:2018-12-06 16:56:47,409 Received block on chain side: {'number': 18280}
INFO:polyswarmclient.events:2018-12-06 16:56:48,222 OnNewBountyCallback callback results: [[{'bounty_guid': '40862925-3e00-41b2-a946-365135d87070', 'mask': [True], 'bid': '62500000000000000', 'commitment': '26135711486835189252810507112407250051211627558503078858520125577864847775053', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}]]
INFO:polyswarmclient:2018-12-06 16:56:48,440 Received block on chain side: {'number': 18281}
INFO:polyswarmclient:2018-12-06 16:56:48,503 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18301', 'uri': 'QmVoLQJ2nm4V6XiZXC9vEUrCaTHdkXS7y3crztZ5HwC9iK', 'guid': 'b41ef0f8-039f-4448-aadf-4d4135cdd94b', 'amount': '62500000000000000'}
INFO:polyswarmclient:2018-12-06 16:56:48,503 Received assertion on chain side: {'bounty_guid': '40862925-3e00-41b2-a946-365135d87070', 'mask': [True], 'bid': '62500000000000000', 'commitment': '26135711486835189252810507112407250051211627558503078858520125577864847775053', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}
WARNING:polyswarmclient.abstractmicroengine:2018-12-06 16:56:48,503 Received new bounty, but finished with testing mode
```

El argumento `--testing 2` significa que tu micromotor responderá a dos recompensas y, después, declinará responder a otra y se cerrará. Puedes ajustar este valor si deseas que procese más recompensas en tus pruebas.

No obstante, el micromotor no tendrá recompensas que procesar hasta que haya un embajador que las envíe a la red de pruebas.

#### Máquina virtual Linux: lanza el embajador

En tu máquina virtual Linux, lanza ahora el embajador `ambassador`, que enviará recompensas a la red de pruebas para que tu micromotor pueda responder a ellas. Abre una nueva terminal y ejecuta los siguientes comandos:

```bash
$ cd orchestration
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Poco después, comenzarás a ver mensajes en la ventana PowerShell de tu micromotor mientras este procesa las recompensas.

### Pruebas concluidas

¡Enhorabuena!

Tu motor basado en Windows debería estar respondiendo ahora a las recompensas ofrecidas en una red local de pruebas hospedada en tu máquina virtual Linux.

Déjalo funcionando hasta que se cierre por sí solo.

Revisa con atención la salida del micromotor para asegurarte de que esté haciendo lo que se supone. :)