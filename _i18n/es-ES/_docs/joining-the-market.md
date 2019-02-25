# Cómo participar en el mercado de PolySwarm

Una vez que hayas probado a fondo tu motor, querrás ponerlo en funcionamiento en el mercado real de PolySwarm.

Desde una perspectiva de alto nivel, para conectar con el mercado de PolySwarm basta con:

1. determinar a qué comunidades te gustaría incorporarte, y
2. apuntar tus motores a la instancia hospedada de `polyswarmd` correspondiente a esas comunidades.

Para ello, se deben tener en cuenta determinados aspectos, que abordamos a continuación.

## Carteras y archivos de claves

PolySwarm está creado sobre Ethereum, un ordenador mundial programable impulsado por una criptomoneda nativa denominada "Ether" (ETH). Cuando un usuario de Ethereum ejecuta una transferencia de ETH o realiza una llamada a un "contrato inteligente" de Ethereum (por ejemplo, los contratos de transferencia de PolySwarm), dicho usuario debe pagarle a la red Ethereum con "Gas" para ejecutar tal transacción. El gas se deduce del saldo de ETH del usuario.

PolySwarm opera con néctar (NCT), una criptomoneda de capa de aplicación que funciona sobre Ethereum. NCT es esencial para participar en el mercado de PolySwarm.

Tu motor, que actúa en representación tuya dentro del mercado de PolySwarm, debe disponer de acceso tanto a ETH como a NCT.

### Carteras de criptomonedas

Al igual que sucede con las demás criptomonedas (por ejemplo, el bitcóin), los fondos se guardan en lo que se denomina "carteras". Técnicamente, una cartera no es más que un par de claves criptográficas y ciertos metadatos que describen su uso. Las carteras se identifican de forma unívoca por medio de un *hash* criptográfico de la porción pública de ese par de claves criptográficas. La posesión o control de una cartera (y de los fondos contenidos en ella) equivale a la posesión de la porción privada de su par de claves.

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      En PolySwarm, al igual que sucede con las demás aplicaciones de criptomonedas, un atacante que disponga de acceso a la clave privada de tu cartera puede robarte todos sus fondos (ETH y NCT) y suplantar tu identidad en el mercado.
      Debes mantener en secreto la clave privada de tu cartera por encima de todo.
    </strong>
  </p>
</div>

Los medios para garantizar la protección de tu clave privada quedan fuera del ámbito de este documento. Para que tu motor participe en el mercado de PolySwarm (y realice transacciones en tu nombre), deberá ser capaz de firmar transacciones usando la clave privada de tu cartera. Ello implica que deberá disponer de acceso directo a la clave (método menos seguro) o deberá poder solicitar las firmas a un dispositivo o proceso que cuente con acceso a la clave (método más seguro). En la actualidad, `polyswarm-client` ya admite el método de acceso directo al archivo de la clave. La posibilidad de delegar la firma de la transacción a otro dispositivo llegará en un futura versión de `polyswarm-client`.

### Uso de carteras en PolySwarm

Al probar nuestros motores, les dijimos dónde encontrar un "archivo de clave" que contenga nuestra clave privada encriptada por medio del argumento `--keyfile` en las utilidades de `polyswarm-client` (es decir, `microengine` y `balancemanager`). Todos los archivos de clave distribuidos con `polyswarm-client` (y otros proyectos de PolySwarm) se encriptan con una contraseña trivial, `password`, que se especifica por medio del argumento `--password`.

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      La única finalidad de estos archivos de clave distribuidos es realizar pruebas con vales NCT y ETH falsos.
      Nunca emplees los archivos de clave usados para pruebas en los proyectos de PolySwarm en producción o en comunidades reales.
      Nunca transfieras fondos reales de NCT o ETH a las carteras contenidas en estos archivos de prueba.
    </strong>
  </p>
  <p>
    <strong>
      Cuando operes fuera de los entornos de prueba usados para el desarrollo, deberás crear tu propio archivo de clave de producción.
    </strong>
  </p>
  <p>
    <strong>
      Tú eres el único responsable de la seguridad de tu archivo de clave de producción.
    </strong>
  </p>
</div>

El cliente oficial de Ethereum (`go-ethereum`, o `geth` de forma abreviada) ofrece instrucciones para generar un archivo de clave. Consulta [Cómo administrar tus cuentas con geth](https://github.com/ethereum/go-ethereum/wiki/Managing-your-accounts).

## Cómo añadir fondos a tu cartera

Una vez que hayas generado tu propio archivo de clave, tendrás que añadir fondos ETH y NCT a tu cartera.

Normalmente existen tres modos de hacerlo:

1. Comprar ETH y NCT en casas de cambio de criptomonedas y transferirlas a la cartera de producción representada por el archivo de clave de producción de tu micromotor. Los métodos empleados para adquirir y transferir criptomonedas quedan fuera del ámbito de este documento.
2. Suscribirse a PolySwarm Direct, un servicio futuro que permitirá configurar recargas automáticas para que tu motor siempre disponga de saldo. Este servicio está actualmente en desarrollo. ¡Seguiremos informando!
3. Los socios iniciales han recibido un fondo inicial de NCT en su cartera de producción de acuerdo con el programa de distribución publicado.

## Cómo localizar tus comunidades

El mercado de PolySwarm es un crisol de distintas comunidades. Las comunidades son grupos de individuos y empresas que comparten un interés específico en el código malicioso o acuerdan mutuamente mantener la confidencialidad de los artefactos intercambiados dentro de ellas.

La primera comunidad de PolySwarm, Epoch, es una comunidad pública accesible a todo el mundo: será tu punto de partida. Epoch sirve como escenario donde los expertos en seguridad pueden demostrar su valía y forjarse una buena reputación para su motor. Una vez que los expertos en seguridad posean una reputación, quizá deseen participar en otras comunidades. A medida que se vayan creando nuevas comunidades, estas aparecerán en el portal de PolySwarm: <button disabled>Explorar comunidades → (¡próximamente!)</button>

De momento, asumamos que solo deseas incorporarte a la comunidad Epoch.

<div class="m-flag">
  <p>
    <strong>Información:</strong>
      Actualmente, los motores basados en <code>polyswarm-client</code> no pueden comunicarse con más de una comunidad al mismo tiempo.
      En una futura versión se incluirá la posibilidad de hacerlo con varias comunidades.
      Mientras tanto, deberás ejecutar una instancia de tu motor (y de <code>balancemanager</code>) para cada comunidad.
  </p>
</div>

## Cómo transferir NCT a tus comunidades

Recuerda que cada comunidad posee una [cadena paralela](/#chains-home-vs-side) exclusiva donde se producen las transacciones de PolySwarm. Para participar, deberás mantener un saldo de NCT (no se necesitan ETH) en la cadena paralela de la comunidad.

Te hemos facilitado las cosas: puedes usar la utilidad de gestión de saldo `balancemanager` de `polyswarm-client`. Tendrás que ejecutar tanto tu motor como un `balancemanager` para mantener un saldo de NCT en la cadena paralela de la comunidad. Los usuarios de Windows recordarán haber ejecutado `balancemanager` en las [instrucciones para las pruebas de integración de motores en Windows](/testing-windows/#integration-testing). Para los usuarios de Linux, Docker se encarga de `balancemanager` de manera transparente.

`balancemanager` puede ejecutarse en tres modos distintos:

1. `deposit`: ingresa en la comunidad la cantidad de NCT configurada y sale.
2. `withdraw`: retira de la comunidad la cantidad de NCT configurada y sale.
3. `maintain`: se asegura de mantener en la comunidad un saldo de NCT constante configurable.

La mayor parte de usuarios preferirán simplemente mantener un saldo con `maintain`: entraremos en detalle en esta funcionalidad más adelante. Algunos usuarios avanzados pueden querer ingresar (`deposit`) y retirar (`withdraw`) fondos.

## Claves API

Con el fin de protegerse de cualquier abuso o ataque de denegación de servicio (DoS), las comunidades pueden decidir entregar a sus miembros claves API y aplicarles límites de uso. Epoch lo hace así, pero las claves API están disponibles para todos.

Para obtener tu clave API para Epoch, date de alta en el [portal de PolySwarm](https://polyswarm.network/), haz clic en tu nombre en la esquina superior derecha y selecciona Cuenta. La clave API para Epoch se mostrará en tu perfil.

### Uso de la clave API en motores de `polyswarm-client`

Usar tu clave API en motores de `polyswarm-client` es tan sencillo como proporcionarle un valor al argumento `--api-key` en la línea de comandos. Lo abordamos más adelante.

### Uso de la clave API en un motor personalizado

Si creas un motor personalizado, asegúrate de que todas las solicitudes API que dirijas a instancias de `polyswarmd` hospedadas en una comunidad contengan tu clave API en los encabezados:

    Authorization: [CLAVE API]
    

Para obtener más detalles sobre la `API de polyswarmd`, consulta nuestra especificación: [Documentación de la API de polyswarmd](/polyswarmd-api/).

## Recapitulemos

En resumen:

1. Hemos generado un archivo de clave de cartera para su uso en *producción*.
2. Hemos añadido saldo de ETH y NCT a esa cartera.
3. Hemos decidido las comunidades de las que formaremos parte.
4. Hemos obtenido la clave API de esas comunidades.

Ahora ya estamos listos para conectar nuestro motor (y `balancemanager`) al mercado de PolySwarm.

Si has creado tu motor con `polyswarm-client` (por ejemplo, usando nuestra plantilla de motor `engine-template` de Cookiecutter en estos tutoriales), solo tienes que especificar algunos argumentos en la línea de comandos (también pueden especificarse como variables de entorno):

```bash
# microengine \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <ruta al archivo de clave autogenerado y cargado con saldo> \
  --password <contraseña de encriptación del archivo de clave> \
  --api-key <tu clave API para Epoch>
  --backend <el nombre (en formato "slug") de tu motor de escaneo (p. ej., acme_myeicarengine)>
```

Para obtener la lista completa de argumentos de línea de comandos, usa la opción `--help`:

```bash
# microengine --help
Utilización: microengine [OPTIONS]

  Punto de entrada al controlador del micromotor

  Argumentos: log (str): Nivel de traza     polyswarmd_addr(str): Dirección de
polyswarmd keyfile (str): Ruta al archivo de clave privada que se usará para firmar las transacciones password (str): Contraseña para desencriptar la clave privada encriptada backend (str): Implementación del procesador de análisis que se usará api_key(str): Clave API que se usará con polyswarmd testing (int): Modo para procesar N recompensas y salir (opcional)     insecure_transport (bool): Conectarse a polyswarmd sin TLS log_format (str): Formato en el que presentar las trazas. `text` o
  `json`

Opciones:
  --log TEXT Nivel de traza
  --polyswarmd-addr TEXT Dirección de la instancia de polyswarmd (host:puerto)
  --keyfile PATH Archivo de almacén de claves que contiene la clave privada que se usará con este micromotor
  --password TEXT Contraseña con la que desencriptar el archivo de clave
  --api-key TEXT Clave API que se usará con polyswarmd
  --backend TEXT Procesador de análisis que se usará
  --testing INTEGER Habilitar modo de pruebas de integración, responder a N recompensas y N ofertas y salir
  --insecure-transport Conectarse a polyswarmd mediante http:// y ws://, mutuamente exclusivos cuando se usa --api-key
  --chains TEXT Cadenas en las que operar
  --log-format TEXT Formato de trazas. Puede ser 'json' o 'text' (por defecto)
  --help Mostrar este mensaje y salir.
```

Además de tu motor, necesitarás ejecutar un gestor de saldo `balancemanager`.

`balancemanager` también necesitará acceso a tu archivo de clave `keyfile`:

```bash
# balancemanager maintain \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <ruta al archivo de clave autogenerado y cargado con saldo> \
  --password <contraseña de encriptación del archivo de clave> \
  --api-key <tu clave API para Epoch>
  --maximum <(opcional) el máximo saldo permisible en la comunidad antes de realizar una retirada>
  <MINIMUM: realizar un ingreso en la comunidad cuando el saldo caiga por debajo de este valor>
  <REFILL_AMOUNT: el importe en NCT a transferir cuando el saldo de la comunidad caiga por debajo de MINIMUM>
```

For the full list of command line arguments, use the `--help` CLI flag:

```bash
# balancemanager maintain --help
INFO:root:2018-12-28 03:04:11,352 Trazas en formato de texto.
Utilización: balancemanager maintain [OPTIONS] MINIMUM REFILL_AMOUNT

  Punto de entrada para retirar NCT desde una cadena paralela a la cadena base

  Argumentos: minimum (float): Valor de NCT en la cadena paralela donde deseas transferir más NCT     refill-amount (float): Valor de NCT que se transferirá en cuanto el saldo caiga por debajo del mínimo

Opciones:
  --polyswarmd-addr TEXT Dirección de la instancia de polyswarmd (host:puerto)
  --keyfile PATH Archivo de almacén de claves que contiene la clave privada que se usará con este micromotor
  --password TEXT Contraseña con la que desencriptar el archivo de clave
  --api-key TEXT Clave API que se usará con polyswarmd
  --testing INTEGER Habilitar modo de pruebas de integración, activar N saldos en la cadena paralela y salir
  --insecure-transport Conectarse a polyswarmd mediante http:// y ws://, mutuamente exclusivos cuando se usa --api-key
  --maximum FLOAT Máximo saldo permisible antes de activar una retirada desde la cadena paralela
  --withdraw-target FLOAT El saldo objetivo en la cadena paralela después de la retirada
  --confirmations INTEGER Número de confirmaciones de bloque transmitidas antes de autorizar la transferencia
  --help Mostrar este mensaje y salir.
```

## Felicidades

Con tu motor y `balancemanager` en marcha, ¡ya estás conectado a las comunidades que elegiste!