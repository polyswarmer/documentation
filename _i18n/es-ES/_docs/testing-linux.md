# Cómo probar motores basados en Linux

## Pruebas unitarias

Realizar pruebas unitarias de tu micromotor es un proceso muy sencillo:

1. construye una imagen de tu micromotor en Docker, y
2. ejecuta `docker-compose` para usar `tox` con el fin de llevar a cabo tu lógica de pruebas en `tests/scan_test.py`.

Ejecuta los siguientes comandos desde el directorio raíz de tu proyecto.

Construye tu micromotor como una imagen de Docker:

```bash
$ docker build -t ${PWD##*/} -f docker/Dockerfile .
```

Esto producirá una imagen de Docker etiquetada con el nombre del directorio (por ejemplo, `microengine-myeicarengine`).

Ejecuta las pruebas:

```bash
$ docker-compose -f docker/test-unit.yml up
```

Si tu micromotor es capaz de detectar EICAR sin producir un falso positivo en la cadena "not a malicious file", deberías superar estas sencillas pruebas unitarias y ver algo así:

```bash
$ docker-compose -f docker/test-unit.yml up
Recreating docker_test_engine_mylinuxengine_1_a9d540dc7394 ... done
Attaching to docker_test_engine_mylinuxengine_1_a9d540dc7394
...
test_engine_mylinuxengine_1_a9d540dc7394 | py35 run-test-pre: PYTHONHASHSEED='1705267802'
test_engine_mylinuxengine_1_a9d540dc7394 | py35 runtests: commands[0] | pytest -s
test_engine_mylinuxengine_1_a9d540dc7394 | ============================= test session starts ==============================
test_engine_mylinuxengine_1_a9d540dc7394 | platform linux -- Python 3.5.6, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
test_engine_mylinuxengine_1_a9d540dc7394 | hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/usr/src/app/.hypothesis/examples')
test_engine_mylinuxengine_1_a9d540dc7394 | rootdir: /usr/src/app, inifile:
test_engine_mylinuxengine_1_a9d540dc7394 | plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
test_engine_mylinuxengine_1_a9d540dc7394 | collected 36 items
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | tests/scan_test.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bloom.py ......
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bounties.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_client.py ............
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_corpus.py ..
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_events.py ..............
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | ========================== 36 passed in 39.42 seconds ==========================
test_engine_mylinuxengine_1_a9d540dc7394 | ___________________________________ summary ____________________________________
test_engine_mylinuxengine_1_a9d540dc7394 |   py35: commands succeeded
test_engine_mylinuxengine_1_a9d540dc7394 |   congratulations :)
```

Obviamente, estas pruebas son muy limitadas y deberás ampliarlas en `scan_test.py` según proceda para tu micromotor.

## Pruebas de integración

El mercado de PolySwarm consta de multitud de participantes y tecnologías: nodos Ethereum e IPFS, contratos, micromotores, embajadores, árbitros, artefactos y mucho más. Probar un único componente exige a menudo la disponibilidad de todos los demás.

El proyecto `orchestration` permite levantar una red de pruebas completa en un abrir y cerrar de ojos. Fiel a su nombre, `orchestration` coordina todos los componentes necesarios para levantar y desmantelar un entorno de mercado PolySwarm entero desde una máquina de desarrollo local.

Clona `orchestration` junto a tu directorio `microengine-myeicarengine`:

```bash
$ git clone https://github.com/polyswarm/orchestration
```

### (Opcional) Experimenta una red de pruebas completa y funcional

Pongamos en marcha una red de pruebas completa y funcional que te permita hacerte una idea de cómo *debería* verse todo.

En el directorio `orchestration` clonado:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up
```

Verás datos de salida de los siguientes servicios:

1. `homechain`: Nodo [geth](https://github.com/ethereum/go-ethereum) que ejecuta la cadena base de nuestra red de pruebas. Consulta [Cadenas base y cadenas paralelas](/#chains-home-vs-side) para obtener una explicación de nuestro modelo de cadenas separadas.
2. `sidechain`: Otra instancia de `geth`, en este caso ejecutando la cadena paralela de nuestra red de pruebas.
3. `ipfs`: Nodo IPFS responsable de hospedar todos lo artefactos de nuestra red de pruebas de desarrollo.
4. `polyswarmd`: El *daemon* de PolySwarm que proporciona fácil acceso a los servicios ofrecidos por `homechain`, `sidechain` e `ipfs`.
5. `contracts`: Responsable de albergar e implementar los contratos de néctar (NCT) y `BountyRegistry` de PolySwarm en nuestra red de pruebas de desarrollo.
6. `ambassador`: Embajador de prueba (proporcionado por `polyswarm-client`) que fijará recompensas por [el archivo EICAR](https://en.wikipedia.org/wiki/EICAR_test_file) y por un archivo que no sea el EICAR.
7. `arbiter`: Árbitro de prueba (proporcionado por `polyswarm-client`) que emitirá veredictos sobre artefactos detectados y determinará la verdad terreno.
8. `microengine`: Micromotor simulado (proporcionado por `polyswarm-client`) que investigará los artefactos detectados y generará afirmaciones.

Desplázate por los registros presentados en pantalla para hacerte una idea de lo que está haciendo cada uno de estos componentes. Deja todo funcionando al menos durante 5 minutos. Desplegar los contratos puede llevar su tiempo... ¡Luego empieza lo bueno! :)

Cuando hayas visto suficientes registros, presiona `Ctrl-C` para detener fácilmente la red de pruebas de desarrollo.

### Prueba tu motor

Vamos a poner en marcha un subconjunto de la red de pruebas dejando al margen el micromotor `microengine` incluido por defecto (lo sustituiremos por el nuestro) y los servicios del embajador `ambassador`.

En el proyecto `orchestration` clonado:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

Habrá que esperar unos minutos hasta que `polyswarmd` esté disponible. Una vez lo esté, comenzará a proporcionar respuestas a los clientes. Por ejemplo:

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

Ahora lancemos nuestro micromotor en una segunda ventana de terminal abierta en su propio directorio:

```bash
$ docker-compose -f docker/test-integration.yml up
```

Por último, introduzcamos algunos artefactos en una tercera ventana de terminal abierta en el directorio `orchestration` para que los escanee nuestro micromotor:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Fíjate en los registros de las tres ventanas: ¡deberías ver cómo tu micromotor responde a las recompensas del embajador!

Cuando hagas cambios en el motor, probarlos será tan sencillo como reconstruir su imagen en Docker y volver a ejectuar el servicio `ambassador` para inyectar una nueva pareja de artefactos maligno (EICAR) y benigno. El resto de la red de pruebas se puede mantener en funcionamiento durante el proceso de iteración.