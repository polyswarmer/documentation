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

Edit the `__init__.py` as we describe below:

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

Si `clamd` detecta un fragmento de código malicioso, inserta `FOUND` (encontrado) en `result[0]`.

Los valores de retorno que espera el micromotor son:

1. `bit` : Un `booleano` que representa la determinación de `malicioso` o `benigno`.
2. `verdict`: Otro `booleano` que indica si el motor desea realizar una afirmación sobre el artefacto.
3. `metadata`: Valor de `cadena` (opcional) que describe el artefacto.

Dejamos la inclusión del valor `metadata` de ClamAV como un ejercicio para el lector. También puedes echarle un vistazo a [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py). :)

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    The Microengine class is required, but we do not need to modify it, so it is not shown here.
  </p>
  <p>
    Librería asyncio de Python 3: Es importante que cualquier llamada externa que se haga durante el escaneo no bloquee el bucle de eventos.
    Hemos bifurcado el proyecto clamd para que sea compatible con asyncio de Python 3.
    Así, para que este ejemplo funcione, debes instalar nuestro proyecto python-clamd para obtener el paquete clamd hasta que nuestros cambios se combinen en el repositorio original.
    El comando que necesitas es: "pip install git+https://github.com/polyswarm/python-clamd.git@async#egg=clamd".
  </p>
</div>

## Finalización y prueba de tu motor

La utilidad `cookiecutter` solo personaliza `engine-template` hasta cierto punto; los demás elementos deberás personalizarlos tú. Aunque hemos abordado los más importantes, te aconsejamos que hagas una búsqueda rápida de `CUSTOMIZE_HERE` para asegurarte de haber personalizado todos los aspectos necesarios.

Una vez que esté todo listo, probaremos nuestro motor:

[Prueba los motores basados en Linux →](/testing-linux/)

[Prueba los motores basados en Windows →](/testing-windows/)

## Next Steps

En el ejemplo de EICAR, te enseñamos a implementar la lógica de escaneo directamente en la clase Scanner. Y en este ejemplo con ClamAV, has aprendido a invocar un *socket* externo para acceder a la lógica de escaneo.

[A continuación, encapsularemos ClamAV y Yara en un único micromotor ->](/microengines-clamav-to-multi/)