## Requisitos del sistema

* CPU x86-64
* 8 GB de RAM

Estas instrucciones han sido desarrolladas y probadas para funcionar en Xubuntu 18.04 amd64.

## Instalar Docker

Hemos integrado en Docker tanto como nos ha sido posible para que te sea más fácil iniciarte con rapidez.

Debes instalar tanto Docker-CE (como base) como Docker Compose. Si no dispones de una instalación reciente de Docker, [instálalo ahora](https://docs.docker.com/install/).

Al finalizar, comprueba que la instalación funciona ejecutando:

```bash
$ docker ps
```

Que debería generar de vuelta:

    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    

Después, [instala `docker-compose`](https://docs.docker.com/compose/install/).

Una vez instalado, comprueba que funciona ejecutando:

```bash
$ docker-compose -v
```

Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`

Después de instalar Docker, te recomendamos añadir tu usuario al grupo `docker` para que puedas emitir fácilmente comandos `docker` sin `sudo`:

```bash
$ sudo usermod -aG docker ${USER}
```

Deberás reiniciar el equipo para que el cambio surta efecto.

## Instalar Git

We'll need to grab a few source code repositories; it'll be easiest to use Git. Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.

## Instalar Python y PIP

Desarrollar para PolySwarm requiere Python 3.5.4 o superior. Instala [Python](https://www.python.org/downloads/) y [PIP](https://pip.pypa.io/en/stable/installing/) para tu plataforma de desarrollo.

## (Opcional) Configura un entorno virtual (virtualenv)

Si piensas usar este equipo para otros fines, te recomendamos mantener limpios los paquetes de Python que afectan a todo el sistema creando un entorno virtual virtualenv de PolySwarm:

```bash
pip install virtualenv
cd ~
virtualenv polyswarmvenv -p <PATH TO PYTHON 3.5.4 OR ABOVE>
source polyswarmvenv/bin/activate
```

## Instala las bibliotecas de `polyswarm-client`

<div class="m-flag">
  <p>
    <strong>Información:</strong> Si usas un entorno virtual virtualenv (ver arriba), asegúrate de activarlo antes de instalar polyswarm-client.
  </p>
</div>

Compilar e instalar las bibliotecas de `polyswarm-client` es muy sencillo.

Primero, instala los encabezados y los requisitos de compilación de Python 3.

En Ubuntu se hace con:

    $ sudo apt install python3-dev
    

A continuación:

```bash
pip install polyswarm-client
```

## Verificar la instalación

You should now have a working development environment!

To verify, simply try importing `polyswarmclient`:

```bash
$ python
...
>>> import polyswarmclient
>>>
```

You should be able to import `polyswarmclient` without issue.

Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file.

[Make a "Hello World" Microengine →](/microengines-scratch-to-eicar/)