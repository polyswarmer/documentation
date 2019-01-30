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

For full details on this process, please refer to the [PolySwarm whitepaper](https://polyswarm.io/polyswarm-whitepaper.pdf).

## Breaking Down Microengines

Conceptually, a Microengine is composed of:

1. `N` **analysis backends**: the scanners that ingest artifacts (files) and determine `malicious` or `benign`.
2. `1` **verdict distillation engine**: ingests analysis backend(s) output, distills to a single `verdict` + a `confidence interval`
3. `1` **staking engine**: ingests verdict distillation output and market / competitive information and produces a `stake` in units of Nectar (NCT)

Microengines are Security Experts' autonomous representatives in the PolySwarm marketplace. They handle everything from scanning files to placing stakes on assertions concerning the malintent of files.

Specifically, Microengines:

1. Listen for Bounties and Offers on the Ethereum blockchain (via `polyswarmd`)
2. Pull artifacts from IPFS (via `polyswarmd`)
3. Scan/analyze the artifacts (via one or more **analysis backends**)
4. Determine a Nectar (NCT) staking amount (via a **verdict distillation engine**)
5. Render an assertion (their `verdict` + `stake`) (via a **staking engine**)

All Microengines share this set of tasks. This tutorial will focus exclusively on item #3: bulding an analysis backend into our `microengine-scratch` skeleton project. All other items will be covered by `polyswarmd` defaults. After completing these tutorials, advanced users may want to refer to [**polyswarmd API**](/polyswarmd-api/) for pointers on customizing these other aspects of their Microengine.

## Developing a Microengine

Ready to develop your first Microengine and start earning NCT?

(Recommended) [I want to build a Linux-based Microengine →](/development-environment-linux/)

Linux-based Engines are far easier to test and come with more deployment options than Windows-based Engines.

[My scan engine only supports Windows; I want to build a Windows-based Microengine →](/development-environment-windows/)