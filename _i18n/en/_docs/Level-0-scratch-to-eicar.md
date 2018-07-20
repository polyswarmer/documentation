## Building Your First PolySwarm Microengine

This tutorial will step you through building your very first PolySwarm microengine - a `hello world` microengine capable of detecting the EICAR test file (and nothing else).
You'll start with `microengine-scratch`, a Microengine that lacks an "Analysis Backed", and end up with `microengine-eicar`, a simple Microengine with a trivial EICAR-detecting Analysis Backend.

For those anxious for the code, this guide will reference and build on:
* [**microengine-scratch**](https://github.com/polyswarm/microengine): a shell of a Microengine that lacks an **analysis backend**
* [**microengine-eicar**](https://github.com/polyswarm/microengine): a fully functional Microengine capable of detecting the EICAR test string
* [**polyswarmd**](https://github.com/polyswarm/polyswarmd): the PolySwarm daemon that abstracts away Ethereum and IPFS idiosyncrasies, allowing you to focus on Microengine development
* [**polyswarm-contracts**](https://github.com/polyswarm/contracts): the contracts that all Microengines must support

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
1. `1` **verdict distillation engine**: ingests analysis backend(s) output, distills to a single `verdict` + a `confidence interval`
1. `1` **staking engine**: ingests verdict distillation output and market / competitive information and produces a `stake` in units of Nectar (NCT)
1. **glue** that binds all the above together, tracks state, communicates with the blockchain and IPFS


### What Microengines Do

Microengines are Security Experts' autonomous representatives in the PolySwarm marketplace.
They handle everything from scanning files to placing stakes on assertions concerning the malintent of files.

Specifically, Microengines:
1. listen for Bounties and Offers on the Ethereum blockchain (via `polyswarmd`)
2. pull artifacts from IPFS (via `polyswarmd`)
3. scan/analyze the artifacts (via one or more **analysis backends**)
4. determine a Nectar (NCT) staking amount (via a **verdict distillation engine**)
5. render an assertion (their `verdict` + `stake`) (via a **staking engine**)

All Microengines share this set of tasks.
This tutorial will focus exclusively on item #3: bulding an analysis backend into our `microengine-scratch` skeleton project.

To avoid duplication of effort and to make getting started as easy as possible, we abstract Ethereum and IPFS-specific items away with `polyswarmd`, providing a convenient REST API to the Microengine for interacting with these networks.
In addition, we provide exemplar Microengines like `microengine-clamav` that everyone is welcome to build on.
We license all of our code under a permissive MIT license, allowing even for commercial, closed-source use.


## Microengines' Role in the PolySwarm Marketplace

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


## Set up a Microengine Development Environment

### Docker

We've Docker-ized as many things as we could to make it as easy as possible to get started, regardless of your development environment.
Assuming Docker is installed, these images should *just work* under Windows, macOS and Linux.

To get started, you'll need Docker-CE (base) as well as Docker Compose (packaged with Docker in all modern releases).
If you do not have a recent Docker setup, please [install Docker now](https://www.docker.com/community-edition).

Once installed, verify that the installation works.

```sh
$ docker -v
Docker version 18.05.0-ce build f150324

$ docker-compose -v
docker-compose version 1.21.1, build 5a3f1a3
```

### Git

We'll need to grab a few source code repositories; it'll be easiest to use Git.
Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.


### Grab the Code

```sh
$ git clone https://github.com/polyswarm/microengine
$ git clone https://github.com/polyswarm/orchestration
```

### Spin Up a Development Environment

```sh
$ pushd orchestration
$ docker-compose -f dev.yml -f tutorial.yml up
```

That's it!
You should be good to go, working on your fancy new Microengine.


## Writing Your First Analysis Backend

`microengine-scratch` is a full-featured Microengine, aside from the analysis backend.

Conceptually, all Microengines using `polyswarmd` should support the following:

* `waitForEvent` - listen for and process events from polyswarmd (daemon). Minimum functionality - handle/process bounties
* `getArtifact` - send a GET web request to `polyswarmd` to download an artifact via polyswarmd IPFS
* `scan` - tells your analysis backend to process the artifact and process the output of your analysis backend
* `sendVerdict` - relay your analysis backend's verdict to polyswarmd via POST web request


### Start with microengine-scratch

We'll start with `microengine/src/microengine/scratch.py` and work toward `microengine/src/microengine/eicar.py`.

If we look at `scratch.py`, we see the following:
```python
from microengine import Microengine

class ScratchMicroengine(Microengine):
    """Scratch microengine is the same as the default behavior"""
    pass
```
Default behavior happens in `__init.py__`, so let's open that up, and look at the scan method.

```python
async def scan(self, guid, content):
        """Override this to implement custom scanning logic"""
        """return bit, assertion, metadata"""
        return True, True, ''
```

The return values that the microengine expects are: 
1. `bit` : a `boolean` representing a `malicious` or `benign` determination
1. `assertion`: another `boolean` representing whether the engine wishes to assert on the artifact
1. `metadata`: (optional) `string` describing the artifact

As you can see, there's nothing to detect the EICAR test file, much less a real piece of malware!

### Write EICAR Detection Logic

The EICAR test file contains the following string:
`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.

There are many ways to search a file for a string.
`__init__.py` handles all of the IPFS and ethereum interactions, so all we have to worry about is writing the `scan` method.

```sh
$ vim scratch.py
```

Feel free to Google around and search for yourself, if you so desire.
There's not a lot of technical know-how required so here's one way:
```python
from microengine import Microengine

EICAR = b'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

class EicarMicroengine(Microengine):
    """Microengine which tests for the EICAR test file"""

    async def scan(self, guid, content):
        if content == EICAR:
            return True, True, ''

        return False, False, ''
```
Here's another way, this time with a `signature` ;)
```python
...
from os import write,close
import tempfile
from hashlib import sha256
...
   async def scan(self, content):
        """Override this to implement custom scanning logic"""
        eicar = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        hash3 = sha256(eicar.encode()).hexdigest()

        print(content)
        hash1 = sha256(content).hexdigest()
        print("looking to see if " +hash1 + " (hash of content) == " +hash3 + "(hash of eicarstring).")

        bit, assertion = False,False
        if (hash1 == hash3):
            print ("EICAR TEST FILE detected...reporting as Infected.")
            bit, assertion = True, True
            return bit, assertion, ''
        print ("I can only detect EICAR. I detected no EICAR.")
        print ("Not EICAR.")

        return bit, assertion, ''
```

### Build and Test Your Brand New EICAR-Detecting Microengine!
Now we're going to build our docker images and see what's going on!
```sh
$ docker build -t polyswarm/eicar -f docker/Dockerfile .
# with `docker-compose _dev environment_` still running in the background/another pane (see Spin Up a Dev Enviroment^^)
$ docker run -it --net=orchestration_default polyswarm/eicar bash
# get dropped into a new container
bash-4.4# microengine --polyswarmd-addr polyswarmd:31337 --keyfile docker/keyfile --password password
#open a new pane/terminal window
$ docker run -it --net=orchestration_default polyswarm/ambassador bash
# get dropped into a new container
bash-4.4# python newAmbassador.py
```
And now you should have one pane running the dev.yml setup, another running your EICAR-detecting microengine, and a third running the mock `ambassador`! Exciting.

If you don't feel like copying in and pasting the code to detect EICAR, you can use the flag for `microengine` "`--backend eicar`". Neat.
