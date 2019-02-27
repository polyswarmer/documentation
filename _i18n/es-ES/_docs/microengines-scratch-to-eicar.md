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
    Próximamente, ampliaremos las opciones de despliegue, incluida la posibilidad de hospedaje propio. Los motores basados en Linux no presentan esa restricción.
  </p>
</div>

Modelaremos nuestro motor usando `engine-template`. Para ello necesitaremos `cookiecutter`:

```bash
pip install cookiecutter
```

Con `cookiecutter` instalado, crear un motor a partir de la plantilla es así de fácil:

```bash
cookiecutter https://github.com/polyswarm/engine-template
```

Estas son las respuestas que debes dar a las distintas peticiones de entrada de datos que aparecerán:

* `engine_name`: MyEicarEngine (el nombre de tu motor)
* `engine_name_slug`: (acepta el valor por defecto)
* `project_slug`: (acepta el valor por defecto)
* `author_org`: ACME (o el nombre real de tu organización)
* `author_org_slug`: (acepta el valor por defecto)
* `package_slug`: (acepta el valor por defecto)
* `author_name`: Pepito Grillo (o tu nombre real)
* `author_email`: (tu dirección de correo electrónico)
* `platform`: responde con exactitud: ¿este motor se ejecutará en Linux o en Windows?
* `has_backend`: 1 si es falso (consulta la explicación siguiente)
* `aws_account_for_ami`: (solo Windows) El identificador de tu cuenta AWS (para motores Linux, basta con aceptar el valor por defecto)

<div class="m-callout">
  <p>Una de las peticiones es <code>has_backend</code>, que puede interpretarse como "¿cuenta el motor con un procesador de análisis disociado?" y merece explicarse en más detalle:</p>
  <p>Cuando encapsulas tu motor de escaneo, al proceso de heredar las clases de <code>polyswarm-client</code> e implementar su funcionalidad se le denomina cambiar el "frontal" (<i>frontend</i>). Si el "frontal" de tu motor de escaneo debe comunicarse a través de una red o de un <i>socket</i> local con un proceso independiente que realice el auténtico trabajo de escaneo (el procesador de análisis o <i>backend</i>), tendrás un procesador disociado y deberás responder <code>true</code> a la pregunta <code>has_backend</code>. Si, por contra, tu motor de escaneo puede encapsularse fácilmente en una sola imagen de Docker (Linux) o AMI (Windows), debes responder <code>false</code> a la pregunta <code>has_backend</code>.</p>
  <p>Ejemplo de "frontal" y procesador de análisis disociados:</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/5959742f0014a582baf5046c7bf6694c23f7435e/src/microengine/clamav.py#L18">ClamAV</a></li>
  </ul>
  <p>Ejemplo que solamente consta de "frontal" ("has_backend" es falso):</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/yara.py">Yara</a></li>
  </ul>
</div>

¡Ya está todo listo!

Ahora, tu directorio de trabajo actual debería contener el archivo `microengine-myeicarengine`. Este es el motor que editaremos para implementar la funcionalidad de escaneo de EICAR.

## Implementa un escáner y un micromotor para EICAR

Detectar EICAR es tan sencillo como:

1. implementar una clase Scanner que sepa cómo identificar el archivo de prueba EICAR, e
2. implementar una clase Microengine que use esa clase Scanner.

Comencemos.

Abre `microengine-myeicarengine/src/(el nombre con org)_myeicarengine/__init__.py`.

Si usaste la plantilla `engine-template` de Cookiecutter arriba, tu `__init__.py` contendrá código.

Modificaremos este archivo para implementar nuestras clases Scanner y Microengine:

* **Scanner**: Nuestra clase Scanner. Esta clase implementará la lógica de detección de EICAR en su función `scan`.

* **Microengine**: Nuestra clase Microengine. Esta clase encapsulará la clase Scanner anterior para gestionar todas las tareas que implica ser un micromotor que detecta EICAR.

### Escribe la lógica de detección de EICAR

El archivo de prueba EICAR se define como un archivo que contiene exclusivamente la siguiente cadena: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.

Por supuesto, existen numerosos modos de identificar archivos que cumplan con estos criterios. El parámetro `content` de la función `scan` alberga el contenido completo del artefacto en cuestión; es decir, la coincidencia a localizar.

Incluimos a continuación dos ejemplos de cómo escribir tu función `scan()` para detectar `EICAR`. Actualiza el código contenido en el archivo `__init__.py` con los cambios indicados en uno de los dos.

El primero representa el diseño más sencillo y se usa en [`eicar.py`](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/eicar.py):

```python
import base64
from polyswarmclient.abstractmicroengine 
import AbstractMicroengine
from polyswarmclient.abstractscanner 
import AbstractScanner

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

En el segundo ejemplo, comparamos el valor SHA-256 del archivo de prueba EICAR con un *hash* malicioso conocido:

```python
import base64

from hashlib import sha256
from polyswarmclient.abstractmicroengine 
import AbstractMicroengine
from polyswarmclient.abstractscanner 
import AbstractScanner

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

### Desarrolla una estrategia de apuesta

Los micromotores son responsables, como mínimo, de: (a) detectar archivos maliciosos, (b) efectuar afirmaciones, por las que apuestan NCT.

La lógica de apuestas está implementada en la función `bid` del micromotor.

Por defecto, para todas las afirmaciones se apuesta el valor mínimo permitido por la comunidad a la que pertenece el micromotor.

Vuelve a consultar esta documentación próximamente para conocer las distintas estrategias de apuesta.

## Finalización y prueba de tu motor

La utilidad `cookiecutter` solo personaliza `engine-template` hasta cierto punto; los demás elementos deberás personalizarlos tú. Aunque hemos abordado los más importantes, te aconsejamos que hagas una búsqueda rápida de `CUSTOMIZE_HERE` para asegurarte de haber personalizado todos los aspectos necesarios.

Una vez que esté todo listo, probaremos nuestro motor:

[Prueba los motores basados en Linux →](/testing-linux/)

[Prueba los motores basados en Windows →](/testing-windows/)

## Próximos pasos

Implementar la lógica de escaneo directamente en la clase Scanner es difícil de gestionar y de escalar. En su lugar, probablemente prefieras que tu clase Microengine invoque un código binario o un servicio externo que albergue la verdadera lógica de escaneo.

[A continuación, encapsularemos ClamAV en un micromotor →](/microengines-scratch-to-clamav/)