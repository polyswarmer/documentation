# Microengine Overview

![Microengine Architecture](/public-src/images/microengine-architecture.jpg)

Microengines are Security Experts' representation in the PolySwarm marketplace.
Microengines encapsulate security expertise in the form of signatures, heuristics, dynamic analyses, emulation, virtualization, a combination of these things or perhaps something else entirely.

Microengines respond to Bounties and Offers in the PolySwarm marketplace, determining whether a suspect file is malicious or benign and stake a certain amount of Nectar (NCT) tokens alongside that assertion.
Security Experts maintain and tweak their Microengines in response to new threat information and new analyses tools, vying against one another to stay at the forefront of their area of expertise.

If you have unique insight into a particular malware family and want to earn tokens (NCT) along with a reputation for that insight, you want to develop a Microengine!


## Microengines' Role in the Marketplace

In the PolySwarm marketplace, **Ambassadors** ask the market for a crowdsourced opinion on a suspect artifact (file) through the Wild-West style PolySwarm Bounty mechanism.
*Ambassadors may also ask specific Experts via Offer channels; this topic will be covered later.*

At a high level:
1. An **Ambassador** "bounties" a suspect `artifact` (a file).
2. **Microengines** hear about this new artifact by listening for Ethereum events (via `polyswarmd`).
3. Each **Microengine** decides if the artifact at hand is within their area of expertise.
4. If the **Microengine** posesses insight on the artifact, it produces an `assertion` and places a `stake` of NCT on that `assertion`, escrowed into the BountyRegistry smart contract.
5. The **Ambassador** considers all `assertions` and returns a `verdict` to their customer.
6. Some time passes.
7. **Arbiters** offer *ground truth* regarding the malintent of the artifact.
8. Correct **Microengines** are rewarded with the escrowed funds of incorrect **Microengines**.

For full details on this process, please refer to the [PolySwarm whitepaper](https://polyswarm.io/polyswarm-whitepaper.pdf).


## Breaking Down Microengines

Conceptually, a Microengine is composed of:

1. `N` **analysis backends**: the scanners that ingest artifacts (files) and determine `malicious` or `benign`.
1. `1` **verdict distillation engine**: ingests analysis backend(s) output, distills to a single `verdict` + a `confidence interval`
1. `1` **staking engine**: ingests verdict distillation output and market / competitive information and produces a `stake` in units of Nectar (NCT)

Microengines are Security Experts' autonomous representatives in the PolySwarm marketplace.
They handle everything from scanning files to placing stakes on assertions concerning the malintent of files.

Specifically, Microengines:
1. Listen for Bounties and Offers on the Ethereum blockchain (via `polyswarmd`)
2. Pull artifacts from IPFS (via `polyswarmd`)
3. Scan/analyze the artifacts (via one or more **analysis backends**)
4. Determine a Nectar (NCT) staking amount (via a **verdict distillation engine**)
5. Render an assertion (their `verdict` + `stake`) (via a **staking engine**)

All Microengines share this set of tasks.
This tutorial will focus exclusively on item #3: bulding an analysis backend into our `microengine-scratch` skeleton project.
All other items will be covered by `polyswarmd` defaults.
After completing these tutorials, advanced users may want to refer to [**polyswarmd API**](https://docs.polyswarm.io/API-polyswarm/) for pointers on customizing these other aspects of their Microengine.


## Developing a Microengine

Ready to develop your first Microengine and start earning NCT?

(Recommended) [I want to build a Linux-based Microengine ->](TODO: link to dev_env_lin.md)

Linux-based Engines are far easier to test and come with more deployment options than Windows-based Engines.

[My scan engine only supports Windows; I want to build a Windows-based Microengine ->](TODO: links to dev_env_win.md)
