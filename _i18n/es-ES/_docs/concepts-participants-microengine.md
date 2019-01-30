## Micromotores: aspectos generales

![Arquitectura de los micromotores](/public-src/images/microengine-architecture.svg)

Los micromotores son la representación de los expertos en seguridad dentro del mercado de PolySwarm. Encapsulan la especialización en seguridad en forma de firmas, heurística, análisis dinámicos, emulación, virtualización, una combinación de lo anterior o, quizás, algo completamente distinto.

Los micromotores responden a las recompensas y las ofertas que se presentan en el mercado de PolySwarm, determinando si un archivo sospechoso es malicioso o benigno, y apuestan una determinada cantidad de vales o "tokens" néctar (NCT) por esa afirmación. Los expertos en seguridad mantienen y ajustan sus micromotores en respuesta a nuevas informaciones sobre amenazas y nuevas herramientas de análisis, compitiendo entre sí para mantenerse a la vanguardia de su área de especialización.

Si posees conocimientos especializados sobre una familia concreta de código malicioso y quieres ganar vales NCT y forjarte una reputación por esos conocimientos, ¡lo que te interesa es desarrollar un micromotor!

## Papel de los micromotores en el mercado

En el mercado de PolySwarm, los **embajadores** utilizan la colaboración masiva o "crowdsourcing" para pedirle al mercado una opinión sobre el artefacto sospechoso (el archivo), utilizando para ello el sistema de recompensas de Polyswarm al estilo del salvaje oeste americano. *Los embajadores también pueden pedir la opinión de expertos específicos a través de los canales de la oferta; este tema se abordará más adelante.*

Desde una perspectiva de alto nivel:

1. Un **embajador** ofrece una recompensa por un `artefacto` sospechoso (un archivo).
2. Los **micromotores** se enteran de la existencia de este nuevo artefacto gracias a los eventos de Ethereum (a través de `polyswarmd`).
3. Cada **micromotor** decide si el artefacto en cuestión pertenece a su área de especialización.
4. Si el **micromotor** posee conocimientos sobre el artefacto, produce una `afirmación` y `apuesta` una determinada cantidad de vales NCT por tal `afirmación`. Este importe queda en depósito en el contrato inteligente del registro de recompensas BountyRegistry.
5. El **embajador** evalúa todas las `afirmaciones` y genera un `veredicto` a su cliente.
6. Tras esto, transcurre un cierto tiempo.
7. Los **árbitros** ofrecen la *verdad terreno* con respecto a las intenciones maliciosas del artefacto.
8. Los **micromotores** que estuvieran en lo cierto son recompensados con los fondos puestos en depósito por los **micromotores** que se hubieran equivocado.

Para conocer todos los detalles de este proceso, consulta el [libro blanco de PolySwarm](https://polyswarm.io/polyswarm-whitepaper.pdf).

## Descripción detallada de los micromotores

Conceptualmente, un micromotor se compone de lo siguiente:

1. `N` **procesadores de análisis**: los escáneres que analizan los artefactos (archivos) y determinan si son `maliciosos` o `benignos`.
2. `1` **motor de sintetización de veredictos**: analiza el resultado de los procesadores de análisis y los sintetiza para obtener un único `veredicto` y un `intervalo de confianza`.
3. `1` **motor de apuestas**: analiza el resultado de la sintetización de veredictos, así como información sobre la competencia y el mercado, para producir una `apuesta` que se cuantifica en unidades néctar (NCT).

Los micromotores son representantes autónomos de los expertos en seguridad dentro del mercado de PolySwarm. Se encargan de todas las tareas: desde escanear los archivos hasta apostar por las afirmaciones realizadas con respecto a sus intenciones maliciosas.

En particular, los micromotores:

1. Se enteran de las recompensas y ofertas realizadas en la cadena de bloques de Ethereum (a través de `polyswarmd`).
2. Recogen artefactos del IPFS (a través de `polyswarmd`).
3. Escanean/Analizan los artefactos (mediante uno o más **procesadores de análisis**).
4. Determinan el importe de la apuesta en néctar (NCT) (**a través de un motor de sintetización de veredictos**).
5. Generan una afirmación (su `veredicto` y `apuesta`) (a través de un **motor de apuestas**).

Todos los micromotores comparten este conjunto de tareas. Este tutorial se centrará exclusivamente en el punto 3: crear un procesador de análisis dentro de nuestro proyecto esquemático `microengine-scratch`. Todos los demás puntos se llevarán a cabo usando los valores por defecto de `polyswarmd`. Una vez completados estos tutoriales, los usuarios avanzados quizá deseen consultar la [**API de polyswarmd**](/polyswarmd-api/) para aprender a personalizar los demás aspectos de su micromotor.

## Cómo desarrollar un micromotor

¿Estás listo para desarrollar tu primer micromotor y empezar a ganar NCT?

(Recomendado) [Quiero crear un micromotor en Linux →](/development-environment-linux/)

Los micromotores creados en Linux son mucho más fáciles de probar e incluyen más opciones de implementación que los creados en Windows.

[Mi motor de escaneo solo es compatible con Windows; quiero crear un micromotor en Windows →](/development-environment-windows/)