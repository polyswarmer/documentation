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
* discovering Communities (see below)
* naming Engines
* creating Profiles
* connecting with Security Experts

... and much, much more.

[Explore Portal →](https://polyswarm.network/)

## Communities

PolySwarm is made up of a series of Communities (hence the "Poly"). Each Community serves a particular purpose and can either permit everyone to join or limit access to specific participants.

PolySwarm will launch with two communities:

* **Genesis: the public mainnet community**: everyone can join & participate!
* **Hive: a private testing community**: a closed Community for initial partners preparing for launch on Genesis

This list will expand, allowing Ambassadors and Microengine developers to control their audience. Future communities may include:

* A GDPR-compliant community with artifact sharing amongst a closed set of compliant participants.
* A network of mutually NDA'ed MSSPs & security experts.

Anyone will be able to administer their own Community and advertise their community through PolySwarm Portal.

### Chains: Home vs Side

Each Community has a "homechain" and a "sidechain", either of which may be shared with other Communities. Generally speaking, the "homechain" is where crypto assets natviely exist and the "sidechain" is where PolySwarm transations take place.

For example, **Genesis**, the first public Community will be configured as such:

* `homechain`: the Ethereum Mainnet
* `sidechain`: a set of hosted `geth` nodes running in a [Clique configuration](https://github.com/ethereum/EIPs/issues/225)

PolySwarm Nectar (NCT) natively lives on the Ethereum Mainnet. Unfortunately, the Ethereum mainnet is far too slow (~15s block time) and far too expensive to support the sort of micro-transactions required by PolySwarm.

Rather than transacting directly on the Ethereum Mainnet, PolySwarm participants will instead relay NCT from Mainnet to the Genesis sidechain and conduct their business on this sidechain. Maintaining a minimal balance on the sidechain is made easy by `polyswarm-client`'s [`balancemanager`](https://github.com/polyswarm/polyswarm-client/tree/master/src/balancemanager).

This split-chain design provides two key benefits:

1. **Scalability** Today, Ethereum does not scale (they're working on this of course), so applications must implement their own "Layer 2" scaling solutions if they demand low latency or high throughput transactions.
2. **Confidentiality** PolySwarm supports the notion of limited-access, private Communities. This split-chain design makes that possible.

<button disabled>Browse Communities → (coming soon!)</button>

## Your Role in the PolySwarm Marketplace

There are several ways to participate in the PolySwarm ecosystem: will you create a Microengine, an Ambassador, an Arbiter or something else entirely?

[Determine where you fit into PolySwarm →](/concepts-participants/)