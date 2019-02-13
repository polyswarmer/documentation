# Cómo encapsular un motor real: ClamAV

## Preparativos

ClamAV es un motor de código abierto basado en firmas y equipado con un *daemon* que proporciona un rápido análisis de los artefactos que identifica. Este tutorial te guiará paso a paso en la creación de tu segundo motor de PolySwarm incorporando ClamAV como procesador de análisis.

<div class="m-flag">
  <p>
    <strong>Nota:</strong>
    El mercado de PolySwarm será una fuente de código malicioso jamás visto anteriormente.
  </p>
  <p>
    No es muy probable que depender de un procesador de análisis con un motor estrictamente basado en firmas, especialmente uno a cuyas firmas puede acceder cualquiera (por ejemplo, ClamAV), proporcione información privilegiada sobre los artefactos detectados por el "enjambre", y poco probable, en consecuencia, que supere a otros motores.
  </p>
  <p>
    La presente guía no pretende sugerir el modo de abordar el mercado, sino proporcionar un ejemplo de cómo incorporar un procesador de análisis existente en el esqueleto de un <strong>micromotor</strong>.
  </p>
</div>

Este tutorial guiará al lector en la creación de [microengine/clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py); consulta el trabajo finalizado en `clamav.py`.

## Implementación e integración de `clamd`

Comienza con una [plantilla de motor nueva](/microengines-scratch-to-eicar/#customize-engine-template) y usa `engine-name` para bautizarla como "MyClamAvEngine". Tu directorio de trabajo actual debería contener ahora el archivo `microengine-myclamavengine`. Este es el motor que editaremos para implementar la funcionalidad de escaneo de ClamAV.

Edita `__init__.py` del siguiente modo:

Comenzamos nuestro procesador de análisis ClamAV importando el módulo `clamd` y configurando algunas variables globales.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import clamd
import logging
import os
from io import BytesIO

from polyswarmclient.abstractmicroengine
import AbstractMicroengine
from polyswarmclient.abstractscanner
import AbstractScanner

logger = logging.getLogger(__name__)  # Inicialización de las trazas

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0
```

¿Me creerías si te dijera que ya casi hemos terminado? Vamos a inicializar y ejecutar `clamd` para que pueda comunicarse con `clamd-daemon` a través de un *socket* de red.

```python
class Scanner(AbstractScanner):
    def __init__(self):
        self.clamd = clamd.ClamdAsyncNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```

Interactuamos con `clamd` enviándole el contenido de los artefactos como secuencias de bytes.

ClamAV responde a las secuencias en este formato:

```json
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```

Podemos analizar fácilmente el resultado usando el operador `[]` de Python. Veremos que `result[0]` es la palabra `FOUND`, y `result[1]`, en esta instancia, es `Eicar-Test-Signature`.

Ahora solo nos queda implementar el método *scan* en la clase Scanner.

```python
    async def scan(self, guid, content, chain):
        result = await self.clamd.instream(BytesIO(content))
        stream_result = result.get('stream', [])
        if len(stream_result) >= 2 and stream_result[0] == 'FOUND':
            return True, True, ''

        return True, False, ''
```

If `clamd` detects a piece of malware, it puts `FOUND` in `result[0]`.

The return values that the Microengine expects are:

1. `bit` : a `boolean` representing a `malicious` or `benign` determination
2. `verdict`: another `boolean` representing whether the engine wishes to assert on the artifact
3. `metadata`: (optional) `string` describing the artifact

We leave including ClamAV's `metadata` as an exercise to the reader - or check [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) :)

<div class="m-flag">
  <p>
    <strong>Información:</strong>
    Aunque se requiere la clase Microengine, no se muestra aquí al no ser necesario modificarla.
  </p>
  <p>
    Python 3's Asyncio - It is important that any external calls you make during a scan do not block the event loop.
    We forked the clamd project to add support for python 3's asyncio.
    Thus, for this example to run, you need install our python-clamd project to get the clamd package until our changes are merged upstream.
    The command you need is: `pip install git+https://github.com/polyswarm/python-clamd.git@async#egg=clamd`.
  </p>
</div>

## Finalizing & Testing Your Engine

`cookiecutter` customizes `engine-template` only so far - there are a handful of items you'll need to fill out yourself. We've already covered the major items above, but you'll want to do a quick search for `CUSTOMIZE_HERE` to ensure all customization have been made.

Once everything is in place, let's test our engine:

[Test Linux-based Engines →](/testing-linux/)

[Test Windows-based Engines →](/testing-windows/)

## Próximos pasos

In the Eicar example, we showed you how to implement scan logic directly in the Scanner class. And in this ClamAV example, we showed you how to call out to an external socket to access scanning logic.

[Next, we'll wrap ClamAV and Yara into a single Microengine ->](/microengines-clamav-to-multi/)