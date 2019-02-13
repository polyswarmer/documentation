# Micromotor "Hola mundo"

## Aspectos generales

Cuando se desarrollan soluciones contra código malicioso, el equivalente al "Hola mundo" es, indefectiblemente, el [archivo de prueba EICAR](https://en.wikipedia.org/wiki/EICAR_test_file).

Este archivo benigno es identificado como "malicioso" por los productos anticódigo malicioso más importantes del mundo; una manera fiable de probar un resultado positivo.

Nuestro primer micromotor no puede ser menos: ¡detectemos el archivo EICAR!

[(Opcional) Repasa los componentes de un micromotor →](/concepts-participants-microengine/#breaking-down-microengines)

## Elementos básicos

Esta guía mencionará y se apoyará en los siguientes elementos:

* [**engine-template**](https://github.com/polyswarm/engine-template): Como su nombre indica, es una práctica plantilla con entrada interactiva de datos para crear nuevos motores. La usaremos en nuestro tutorial.

* [**polyswarm-client**](https://github.com/polyswarm/polyswarm-client): La navaja multiusos de los distintos prototipos de participantes de PolySwarm ("clientes"). `polyswarm-client` puede actuar como micromotor (`microengine`) (usaremos esta funcionalidad en este tutorial), árbitro (`arbiter`) o embajador (`ambassador`) (usaremos esta otra funcionalidad para probar lo que creemos).

## Personaliza `engine-template`

<div class="m-flag m-flag--warning">
  <p>
    <strong>Aviso:</strong>
    Los motores basados en Windows solamente son compatibles como imágenes de máquina de Amazon Web Services (AMI).
  </p>
  <p>
    El proceso de personalización de los motores basados en Windows asume que dispones de una cuenta AWS con su correspondiente identificador.
  </p>
  <p>
    We'll be expanding deployment options in near future, including self-hosted options. Linux-based engines have no such stipulation.
  </p>
</div>

We're going to cut our Engine from `engine-template`. To do this, we'll need `cookiecutter`:

```bash
pip install cookiecutter
```

With `cookiecutter` installed, jump-starting your engine from our template is as easy as:

```bash
cookiecutter https://github.com/polyswarm/engine-template
```

Prompts will appear, here's how we'll answer them:

* `engine_name`: MyEicarEngine (the name of your engine)
* `engine_name_slug`: (accept the default)
* `project_slug`: (accept the default)
* `author_org`: ACME (or the real name of your organization)
* `author_org_slug`: (accept the default)
* `package_slug`: (accept the default)
* `author_name`: Wile E Coyote (or your real name)
* `author_email`: (your email address)
* `platform`: answer truthfully - will this Engine run on Linux or Windows?
* `has_backend`: 1 for false (see explanation below)
* `aws_account_for_ami`: (Windows only) your AWS account ID (for Linux engines, just accept the default)

<div class="m-callout">
  <p>One of the prompt items is <code>has_backend</code>, which can be thought of as "has a disjoint backend" and deserves additional explanation.</p>
  <p>When wrapping your scan engine, inheritance of <code>polyswarm-client</code> classes and implementation of class functionality are referred to as "frontend" changes. If your scan engine "frontend" must reach out across a network or local socket to a separate process that does the real scanning work (the "backend"), then you have a disjoint "backend" and you should answer <code>true</code> to <code>has_backend</code>. If instead your scan engine can easily be encapsulated in a single Docker image (Linux) or AMI (Windows), then you should select <code>false</code> for <code>has_backend</code>.</p>
  <p>Example of disjoint frontend / backend:</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/5959742f0014a582baf5046c7bf6694c23f7435e/src/microengine/clamav.py#L18">ClamAV</a></li>
  </ul>
  <p>Example of only a frontend (has_backend is false):</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/yara.py">Yara</a></li>
  </ul>
</div>

You're all set!

You should find a `microengine-myeicarengine` in your current working directory - this is what we'll be editing to implement EICAR scan functionality.

## Implement an EICAR Scanner & Microengine

Detecting EICAR is as simple as:

1. implementing a Scanner class that knows how to identify the EICAR test file
2. implementing a Microengine class that uses this Scanner class

Let's get started.

Open `microengine-myeicarengine/src/(the org slug name)_myeicarengine/__init__.py`.

If you used our cookiecutter `engine-template` from above, you will have some code in your `__init__.py`.

We will modify this file to implement both our Scanner and Microengine classes:

* **Scanner**: our Scanner class. This class will implement our EICAR-detecting logic in its `scan` function.

* **Microengine**: our Microengine class. This class will wrap the aforementioned Scanner to handle all the necessary tasks of being a Microengine that detects EICAR.

### Write EICAR Detection Logic

The EICAR test file is defined as a file that contains only the following string: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.

There are, of course, many ways to identify files that match this criteria. The `scan` function's `content` parameter contains the entire content of the artifact in question - this is what you're matching against.

The following are 2 examples for how you can write your `scan()` function to detect `EICAR`. Update the code in your `__init__.py` file with the changes from one of these examples.

The first way, is the simplest design and is used in [`eicar.py`](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/eicar.py):

```python
import base64
from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')

class Scanner(AbstractScanner):

    async def scan(self, guid, content, chain):
        if content == EICAR:
            return True, True, ''

        return True, False, ''


class Microengine(AbstractMicroengine):
    def __init__(self, client, testing=0, scanner=None, chains=None):
        scanner = Scanner()
        super().__init__(client, testing, scanner, chains)

```

Here's another way, this time comparing the SHA-256 of the EICAR test file with a known-bad hash:

```python
import base64

from hashlib import sha256
from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
HASH = sha256(EICAR).hexdigest()

class Scanner(AbstractScanner):

    async def scan(self, guid, content, chain):
        testhash = sha256(content).hexdigest()
        if (testhash == HASH):
            return True, True, ''

        return True, False, ''


class Microengine(AbstractMicroengine):
    def __init__(self, client, testing=0, scanner=None, chains=None):
        scanner = Scanner()
        super().__init__(client, testing, scanner, chains)

```

### Develop a Staking Strategy

At a minimum, Microengines are responsible for: (a) detecting malicious files, (b) rendering assertions with NCT staked on them.

Staking logic is implemented in the Microengine's `bid` function.

By default, all assertions are placed with the minimum stake permitted by the community a Microengine is joined to.

Check back soon for an exploration of various staking strategies.

## Finalización y prueba de tu motor

La utilidad `cookiecutter` solo personaliza `engine-template` hasta cierto punto; los demás elementos deberás personalizarlos tú. Aunque hemos abordado los más importantes, te aconsejamos que hagas una búsqueda rápida de `CUSTOMIZE_HERE` para asegurarte de haber personalizado todos los aspectos necesarios.

Una vez que esté todo listo, probaremos nuestro motor:

[Prueba los motores basados en Linux →](/testing-linux/)

[Prueba los motores basados en Windows →](/testing-windows/)

## Próximos pasos

Implementing scan logic directly in the Scanner class is difficult to manage and scale. Instead, you'll likely want your Microengine class to call out to an external binary or service that holds the actual scan logic.

[Next, we'll wrap ClamAV into a Microengine →](/microengines-scratch-to-clamav/)