## Welcome

Welcome and thank you for your interest in PolySwarm!

Here you'll find everything you need to get started developing for PolySwarm.

Before we dive into the code, let's get our bearings:
* What does it look like to participate in PolySwarm?
* Which role fits my use case?
* Which Communities do I want to engage with?
* How do I monitor the performance of my Engines?
* What are Communities? What is an Engine?

Let's take a look at some of the high level concepts and drill down into details where appropriate.


## Portal

PolySwarm Portal is PolySwarm's one-stop shop for:
* tracking Engine performance
* discovering Communities (see below)
* naming Engines
* creating Profiles
* connecting with Security Experts

... and much, much more.

[Explore Portal →](https://polyswarm.network/)


## Communities

PolySwarm is composed of a series of Communities (hence the "Poly").
Each Community serves a particular purpose and can either permit everyone to join or limit access to specific participants.

PolySwarm will launch with two communities:
* **Genesis: the public mainnet community**: everyone can join & participate!
* **Hive: a private testing community**: a closed Community for initial partners preparing for launch on Genesis

This list will expand, allowing Ambassadors and Microengine developers to control their audience.
Future communities may include:
* A GDPR-compliant community with artifact sharing amongst a closed set of complaint participants.
* A network of mutually NDA'ed MSSPs & security experts.

Anyone will be able to administer their own Community and advertise their community through PolySwarm Portal.


### Chains: Home vs Side

Each Community has a "homechain" and a "sidechain", either of which may be shared with other Communities.
Generally speaking, the "homechain" is where crypto assets natviely exist and the "sidechain" is where PolySwarm transations take place.

For example, **Genesis**, the first public Community will be configured as such:
* `homechain`: the Ethereum Mainnet
* `sidechain`: a set of hosted `geth` nodes running in a [Clique configuration](https://github.com/ethereum/EIPs/issues/225)

PolySwarm Nectar (NCT) natively lives on the Ethereum Mainnet.
Unfortunately, the Ethereum mainnet is far too slow (~15s block time) and far too expensive to support the sort of micro-transactions required by PolySwarm.

Rather than transacting directly on the Ethereum Mainnet, PolySwarm participants will instead relay NCT from Mainnet to the Genesis sidechain and conduct their business on this sidechain.
Maintaining a minimal balance on the sidechain is made easy by `polyswarm-client`'s [`balancemanager`](https://github.com/polyswarm/polyswarm-client/tree/master/src/balancemanager).

This split-chain design provides two key benefits:
1. **Scalability**
Today, Ethereum does not scale (they're working on this of course), so applications must implement their own "Layer 2" scaling solutions if they demand low latency or high throughput transactions.
1. **Confidentiality**
PolySwarm supports the notion of limited-access, private Communities.
This split-chain design makes that possible.

<button disabled>Browse Communities → (coming soon!)</button>


## Your Role in the PolySwarm Marketplace

There are several ways to participate in the PolySwarm ecosystem: will you create a Microengine, an Ambassador, an Arbiter or something else entirely?

[Determine where you fit into PolySwarm →](/concepts-participants/)
