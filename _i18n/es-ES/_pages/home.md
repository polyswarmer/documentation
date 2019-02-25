## Saludos

¡Te damos la bienvenida! ¡Gracias por tu interés en PolySwarm!

Aquí encontrarás todo lo necesario para empezar a desarrollar para PolySwarm.

Antes de zambullirnos en el código, vamos a aclarar los conceptos básicos:

* ¿Cómo se desarrolla la participación en PolySwarm?
* ¿Qué función se adapta a mi caso de uso?
* ¿En qué comunidades deseo involucrarme?
* ¿Cómo superviso el rendimiento de mis motores?
* ¿Qué son las "comunidades"? ¿Qué es un "motor"?

Vamos a repasar algunos de los conceptos más generales, profundizando en los detalles cuando corresponda.

## Portal

El portal de PolySwarm es el punto de acceso único para:

* supervisar el rendimiento de los motores,
* descubrir comunidades (ver más adelante),
* darle nombre a los motores,
* crear perfiles,
* conectar con expertos en seguridad,

... y muchas cosas más.

[Explora el portal →](https://polyswarm.network/)

## Comunidades

PolySwarm se compone de una serie de comunidades (de ahí el prefijo "poly-" que recuerda a "poli"). Cada una de ellas tiene una finalidad específica y puede permitir la participación de cualquier persona o restringir el acceso solo a determinados individuos.

En su lanzamiento, PolySwarm contará con dos comunidades:

* **Genesis: comunidad pública de la red principal o "mainnet"**; todo el mundo puede unirse a ella y participar.
* **Hive: comunidad de pruebas privada**; una comunidad cerrada donde los socios iniciales se pueden preparar para el lanzamiento en Genesis.

Esta lista se ampliará y permitirá a embajadores y desarrolladores de micromotores controlar su audiencia. Las comunidades futuras pueden incluir:

* Una comunidad donde un grupo cerrado de participantes cualificados pueda compartir artefactos entre sí respetando el RGPD.
* Una red de proveedores de servicios de seguridad gestionada (PSSG) y expertos en seguridad que hayan suscrito acuerdos de confidencialidad mutuos.

Cualquier persona podrá administrar su propia comunidad y publicitarla a través del portal de PolySwarm.

### Cadenas base y cadenas paralelas 

Cada comunidad cuenta con una cadena base, o "homechain", y una cadena paralela, o "sidechain", y ambas pueden compartirse con otras comunidades. En términos generales, la cadena base es donde residen de forma nativa los criptoactivos, mientras que la cadena paralela es donde tienen lugar las transacciones de PolySwarm.

Por ejemplo, **Genesis**, la primera comunidad pública, estará estructurada del siguiente modo:

* `homechain`: la red principal de Ethereum.
* `sidechain`: un conjunto de nodos `geth` ejecutándose en [configuración Clique](https://github.com/ethereum/EIPs/issues/225).

PolySwarm Nectar (NCT) reside de forma nativa en la red principal de Ethereum. Por desgracia, esta red es demasiado lenta (~15 s por bloque) y costosa para albergar el tipo de microtransacciones que requiere PolySwarm.

En lugar de efectuar las transacciones directamente en la red principal de Ethereum, los participantes de PolySwarm transferirán NCT desde dicha red principal a la cadena paralela de Genesis y llevarán a cabo sus actividades en ella. La librería [`balancemanager`](https://github.com/polyswarm/polyswarm-client/tree/master/src/balancemanager) de `polyswarm-client` facilita el mantenimiento de un saldo mínimo en la cadena paralela.

Este diseño en cadenas separadas brinda dos ventajas fundamentales:

1. **Escalabilidad:** Actualmente, Ethereum no es escalable (aunque, obviamente, están trabajando en ello), por lo que, si las aplicaciones exigen transacciones con un alto caudal o una baja latencia, se ven obligadas a implementar sus propias soluciones de escalado de capa 2.
2. **Confidencialidad:** PolySwarm es compatible con el concepto de comunidades privadas con acceso restringido. El diseño en cadenas separadas lo hace posible.

<button disabled>Explorar comunidades → (¡próximamente!)</button>

## Tu función en el mercado de PolySwarm

Hay varias formas de participar en el ecosistema de PolySwarm: ¿crearás un micromotor, un embajador, un árbitro o algo totalmente distinto?

[Determina dónde encajas dentro de PolySwarm →](/concepts-participants/)