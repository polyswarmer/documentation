# PolySwarm Market Participants

For a high-level overview of the roles in the PolySwarm marketplace, take a look at our TODO https://polyswarm.io/how_it_works/

In brief:

*Ambassadors* pay a fee or purchase a subscription to submit files (artifacts) to the PolySwarm network.
This fee funds Security Experts who have developed Microengines and Arbiters who are responsible for determining Ground Truth.
In return for their fee, Ambassadors receive timely crowdsourced threat intelligence on their artifact, aiding in triage or incident response.

*Microengines* are developed by individuals or organizations who have a knack for identifying malware.
Microengines encapsulate security expertise and bundle it in an autonomous process that 

In return, they recieve crowdsourced expertise 

in brief, TODO

## Choose Your Own Adventure

### Building a Microengine

![Microengine Architecture](/public-src/images/microengine-architecture.jpg)

Microengines are Security Experts' representatives in the PolySwarm marketplace; they encapsulate security expertise in the form of signatures, heuristics, dynamic analyses, emulation, virtualization, a combination of these things or perhaps something else entirely.
If you have unique insight into a particular malware family, file format or category of malicious behavior, you are encouraged to encapsulate your knowledge into a PolySwarm Microengine, hook it up to the PolySwarm network and (potentially) earn passive income for your insight!

Microengines respond to Bounties and Offers in the PolySwarm marketplace, determining whether a suspect file is malicious or benign and stake a certain amount of Nectar (NCT) tokens alongside that assertion.
Security Experts maintain and tweak their Microengines in response to new threat information and new analyses tools, vying against one another to stay at the forefront of their area of expertise.


### Microengines' Role in the PolySwarm Marketplace

In the PolySwarm marketplace, **Ambassadors** ask the market for a crowdsourced opinion on a suspect artifact (file) through the Wild-West style PolySwarm Bounty mechanism.
*Ambassadors may also ask specific Experts via Offer channels; Offers will be discussed in a later tutorial.*

At a high level:
1. An **Ambassador** "bounties" a suspect artifact.
2. **Microengines** hear about this new artifact by listening for Ethereum events (optionally via `polyswarmd`).
3. Each **Microengine** decides if the artifact at hand is within their wheelhouse of expertise.
4. If the **Microengine** has insight on the artifact, it produces an `assertion` + a `stake` of NCT on that `assertion`.
5. The **Ambassador** can see all `assertions` and returns a `verdict` to their customer.
6. Some time passes.
7. **Arbiters** offer *ground truth* regarding the malintent of the artifact.
Correct **Microengines** are rewarded with the escrowed funds of incorrect **Microengines**.

For full details on this process, please refer to the [PolySwarm whitepaper](https://polyswarm.io/polyswarm-whitepaper.pdf) for now - more documentation is forthcoming!

### Building an Ambassador

TODO

### Becoming an Arbiter

TODO - we're working with initial partners on this role - inctructions to come
