# Cómo crear un micromotor multiproceso

Este tutorial te mostrará cómo combinar varios procesadores de análisis y te ofrecerá un esbozo de una primitiva básica para la sintetización de veredictos. Los procesadores a combinar serán `ClamAV` (del anterior tutorial) y [YARA](https://virustotal.github.io/yara/).

## Incorporación de YARA

Comienza con una [plantilla de motor](/microengines-scratch-to-eicar/#customize-engine-template) nueva y usa `engine-name` para bautizarla como "MyYaraEngine". Al hacerlo, en tu actual directorio de trabajo debería aparecer el micromotor `microengine-myyaraengine`: será lo que editemos para implementar la funcionalidad de Yara.

Vamos a añadirle un procesador YARA a nuestro micromotor, pero antes necesitaremos algunas firmas de YARA (reglas).

El repositorio [Yara-Rules](https://github.com/Yara-Rules/rules) es una excelente fuente de reglas gratuitas. Descárgalas y colócalas en el directorio `pkg` de tu micromotor `microengine-myyaraengine`:

```sh
cd microengine-myyaraengine/pkg
git clone https://github.com/Yara-Rules/rules.git
```

También necesitaremos el módulo `yara-python` para interpretarlas. Instálalo si no lo tienes:

```sh
pip install yara-python
```

A continuación, crearemos un escáner que use `yara-python` para escanear artefactos.

Edita `__init__.py` del siguiente modo:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import yara

from polyswarmclient.abstractmicroengine
import AbstractMicroengine
from polyswarmclient.abstractscanner
import AbstractScanner

logger = logging.getLogger(__name__)  # Inicialización de las trazas
RULES_DIR = os.getenv('RULES_DIR', 'docker/yara-rules')

class Scanner(AbstractScanner):
    def __init__(self):
        self.rules = yara.compile(os.path.join(RULES_DIR, "malware/MALW_Eicar"))

    async def scan(self, guid, content, chain):
        matches = self.rules.match(data=content)
        if matches:
            return True, True, ''

        return True, False, ''
```

<div class="m-flag">
  <p>
    <strong>Información:</strong>
    Aunque se requiere la clase Microengine, no se muestra aquí al no ser necesario modificarla.
  </p>
</div>

El procesador YARA incluido con `polyswarm-client` acepta una variable de entorno `RULES_DIR` que te permite apuntar a las reglas de YARA. Por tanto, para probar este motor, modifica la variable de entorno `RULES_DIR` para que apunte a las reglas de YARA que descargaste.

<div class="m-flag">
  <p>
    <strong>Información:</strong>
    Al realizar las pruebas de integración (<a href="/testing-linux/#integration-testing">Linux</a>, <a href="/testing-windows/">Windows</a>), nuestro embajador de prueba solo ofrecerá recompensa por dos archivos: el archivo EICAR y otro distinto a EICAR.
    Para probar nuestra infraestructura, por tanto, solo necesitaremos una regla de YARA que detecte EICAR.
  </p>
</div>

De este modo, ya tendremos un micromotor YARA. Sin embargo, nuestro plan era disponer de varios motores gestionados por un solo micromotor, así que, prosigamos.

## Escáner ClamAV

Reutilizaremos el escáner ClamAV del [tutorial anterior](/microengines-scratch-to-clamav/).

En [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) puedes encontrar una solución terminada.

## Varios procesadores de análisis

Comienza con una [plantilla de motor](/microengines-scratch-to-eicar/#customize-engine-template) nueva y usa `engine-name` para bautizarla como "MyMultiEngine". Al hacerlo, en tu actual directorio de trabajo debería aparecer el micromotor `microengine-mymultiengine`: será lo que editemos para usar la funcionalidad tanto de ClamAV como de Yara.

Extenderemos nuestro micromotor para que utilice varios procesadores de análisis, por lo que necesitaremos algún modo de recibir los resultados de ambos procesadores (YARA y ClamAV) y sintetizar nuestro veredicto a partir de ellos. Vamos a crear un micromotor que inicialice varios escáneres:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import logging

from polyswarmclient.abstractmicroengine 
import AbstractMicroengine
from polyswarmclient.abstractscanner 
import AbstractScanner
from polyswarm_myclamavengine 
import Scanner as ClamavScanner
from polyswarm_myyaraengine 
import Scanner as YaraScanner

logger = logging.getLogger(__name__)  # Inicialización de las trazas
BACKENDS = [ClamavScanner, YaraScanner]


class Scanner(AbstractScanner):

    def __init__(self):
        super(Scanner, self).__init__()
        self.backends = [cls() for cls in BACKENDS]

```

<div class="m-flag">
  <p>
    <strong>Información:</strong>
    Aunque se requiere la clase Microengine, no se muestra aquí al no ser necesario modificarla.
  </p>
</div>

Esto crea una lista de procesadores que contienen instancias de nuestras clases, YaraScanner y ClamavScanner.

Ahora que ya podemos acceder a ambos, vamos a usar sus resultados para sintetizar un veredicto final en la función `scan()` de nuestra función Scanner.

```python
    async def scan(self, guid, content, chain):
        results = await asyncio.gather(*[backend.scan(guid, content, chain) for backend in self.backends])

        # Descompresión de las tuplas resultantes
        bits, verdicts, metadatas = tuple(zip(*results))
        return any(bits), any(verdicts), ';'.join(metadatas)
```

Aquí calculamos todos los resultados de nuestros escáneres de forma asíncrona y los combinamos después en nuestro veredicto final. De esta manera, comprobaremos si alguno de los procesadores devuelve el bit "verdadero" y afirmaremos que el artefacto es malicioso en caso de que alguno de los procesadores así lo indique. También combinaremos todos los metadatos de nuestros escáneres en una sola cadena, que incluiremos junto con la afirmación.

En [multi.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/multi.py) puede verse una solución terminada.

Nota: Los módulos Python `polyswarm_myclamavengine` y `polyswarm_myyaraengine` proceden de ejemplos anteriores. Para que este multimotor pueda usar los motores ClamAV y YARA, deben estar disponibles en tu variable de entorno PYTHONPATH. Para ello, puedes ejecutar el siguiente comando desde la raíz de ambos directorios de proyecto, ClamAV y YARA:

```bash
pip install .
```

## Próximos pasos

Ahora que ya sabemos cómo crear diferentes tipos de micromotores usando productos antivirus existentes, ya puedes comenzar a crear tu propio micromotor personalizado.