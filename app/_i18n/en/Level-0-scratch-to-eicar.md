## Building Your First PolySwarm Microengine

This tutorial will step you through building your very first PolySwarm microengine - a `hello world` microengine capable of detecting the EICAR test file (and nothing else).
You'll start with `microengine-scratch`, a Microengine that lacks an "Analysis Backed", and end up with `microengine-eicar`, a simple Microengine with a trivial EICAR-detecting Analysis Backend.

For those anxious for the code, this guide will reference and build on:
* [**microengine-scratch**](https://github.com/polyswarm/microengine-scratch): a shell of a Microengine that lacks an **analysis backend**
* [**microengine-eicar**](https://github.com/polyswarm/microengine-eicar): a fully functional Microengine capable of detecting the EICAR test string
* [**polyswarmd**](https://github.com/polyswarm/polyswarmd): the PolySwarm daemon that abstracts away Ethereum and IPFS idiosyncrasies, allowing you to focus on Microengine development
* [**polyswarm-contracts**](https://github.com/polyswarm/polyswarm-contracts): the contracts all Microengines must support

Without further ado, let's get started!


## Background on Microengines

![Microengine_Architecture](/public-src/images/Microengine_Architecture.png)

Microengines are Security Experts' representatives in the PolySwarm marketplace; they encapsulate security expertise in the form of signatures, heuristics, dynamic analyses, emulation, virtualization, a combination of these things or perhaps something else entirely.
If you have unique insight into a particular malware family, file format or category of malicious behavior, you are encouraged to encapsulate your knowledge into a PolySwarm Microengine, hook it up to the PolySwarm network and (potentially) earn passive income for your insight!

Microengines respond to Bounties and Offers in the PolySwarm marketplace, determining whether a suspect file is malicious or benign and stake a certain amount of Nectar (NCT) tokens alongside that assertion.
Security Experts maintain and tweak their Microengines in response to new threat information and new analyses tools, vying against one another to stay at the forefront of their area of expertise.


### Microengine Components

Conceptually, a microengine is composed of:

1. `N` **analysis backends**: the scanners that ingest artifacts (files) and determine `malicious` or `benign`. 
1. `1` **verdict distillation engine**: ingests analysis engine output, distills to a single `verdict` + a `confidence interval`
1. `1` **staking engine**: ingests verdict distillation output and market / competitive information and produces a `stake` in units of Nectar (NCT)
1. **glue** that binds all the above together, tracks state, communicates with the blockchain and IPFS


### What Microengines Do

Microengines are Security Experts' autonomous representatives in the PolySwarm marketplace.
They handle everything from scanning files to placing stakes on assertions concerning the malintent of files.

Specifically, Microengines:
1. listen for Bounties and Offers on the Ethereum blockchain (via `polyswarmd`)
2. pull artifacts from IPFS (via `polyswarmd`)
3. scan the artifacts (via one or more **analysis backends**)
4. determine a Nectar (NCT) staking amount (via a **verdict distillation engine**)
5. render an assertion (their `verdict` + `stake``) (via a **staking engine**)

All Microengines share this set of tasks.
This tutorial will focus exclusively on item #3: bulding an analysis backend into our `microengine-scratch` skeleton project.

To avoid duplication of effort and to make getting started as easy as possible, we abstract Ethereum and IPFS-specific items away with `polyswarmd`, providing a convenient REST API to the Microengine for interacting with these networks.
In addition, we provide exemplar Microengines like `microengine-clamav` that everyone is welcome to build on.
We license all of our code under a permissive MIT license, allowing even for commercial, closed-source use.


## Microengines' Role in the PolySwarm Marketplace

In the PolySwarm marketplace, **Ambassadors** ask the market for a crowdsourced opinion on a suspect artifact (file) through the Wild-West style PolySwarm Bounty mechanism.
*Ambassadors may also ask specific Experts via Offer channels; Offers will be discussed in a later tutorial.*

At a high level:
1. An **Ambassaor** "bounties" a suspect artifact.
2. **Microengines** hear about this new artifact by listening for Ethereum events (optionally via `polyswarmd`).
3. Each **Microengine** decides if the artifact at hand is within their wheelhouse of expertise.
4. If **Microengine** has insight on the artifact, it produces an `assertion` + a `stake` of NCT on that `assertion`.
5. The **Ambassador** can see all `assertions` and return a `verdict` to their customer.
6. Some time passes.
7. **Arbiters** offer *ground truth* regarding the malintent of the artifact. 
Correct **Microengines** are rewarded with the escrowed funds of incorrect **Microengines**.

For full details on this process, please refer to the [PolySwarm whitepaper](https://polyswarm.io/polyswarm-whitepaper.pdf) for now - more documentation is forthcoming!


## Set up a Microengine Development Environment

### Docker

We've Docker-ized as many things as we could to make it as easy as possible to get started, regardless of your development environment.
Assuming Docker is installed, these images should *just work* under Windows, macOS and Linux.

To get started, you'll need Docker (base) as well as Docker Compose (packaged with Docker in all modern releases).
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

Once installed, verify that the installation works.

```sh
$ docker -v
Docker version 18.05.0-ce build f150324

$ docker-compose -v
docker-compose version 1.21.1, build 5a3f1a3
```

### Git

We'll need to grab a a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.


### Grab the Code

```sh
$ git clone https://github.com/polyswarm/microengine-scratch
$ git clone https://github.com/polyswarm/orchestration
```

### Spin Up a Development Enviroment

```sh
$ pushd orchestration
$ docker-compose -f dev.yml -f tutorial.yml up
```

That's it!
You should be good to go, working on your fancy new Microengine.


## Writing the Your First Analysis Backend

`microengine-scratch` is a full-featured Microengine, aside from the analysis backend.

Conceptually, all Microengines using `polyswarmd` should support the following endpoints:

* `getArtifact` - send a GET web request to `polyswarmd` to download an artifact via polyswarmd IPFS
* `scan` - tells your analysis backend to process the artifact and process the output of your analysis backend
* `sendVerdict` - relay your analysis backend's verdict to polyswarmd via POST webrequest
* `waitForEvent()` - listen for events from polyswarmd (daemon), process events. Minimum functionality - handle/process bounties  
 

### Start with microengine-scratch

We'll start with `scratch.go` and work toward `eicar.go`.   

If we look at `scratch.go`, specifically the `scan` method, we see the following:

```go
func scan(artifact io.ReadCloser) (string, string, error) {
  status      := NOT_FOUND
  description := ""

  return status, description, nil
}
```

As you can see, there's nothing to detect the EICAR test file, much less a real piece of malware! 


### Write EICAR Detection Logic

The EICAR test file contains the following string:
`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.  

There are many ways to search a file for a string. 
`scratch.go` handles all of the IPFS interactions and all we have to worry about is writing the `scan` method. 

```sh
$ cp scratch.go eicar.go
$ vi eicar.go
```

Feel free to Google around and search for yourself, if you so desire.
There's not a lot of technical know-how required so here's one way:

```go
func scan(artifact string) (string, string, error) {
  status      := NOT_FOUND
  description := ""

  if artifact.Contains('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'){
    status      = FOUND
    description = "EICAR Detected." 
  }

  return status, description, nil
}
```

### Test Your Brand New EICAR-Detecting Microengine!

```sh
$ go run scratch.go
```
