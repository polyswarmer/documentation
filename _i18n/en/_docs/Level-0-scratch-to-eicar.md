## Building Your First PolySwarm Microengine

This tutorial will step you through building your very first PolySwarm Microengine - a `hello world` Microengine capable of detecting the EICAR test file (and nothing else).
We'll start with a "scratch" Microengine that lacks an "Analysis Backed", and iterate toward a simple Microengine with a trivial EICAR-detecting Analysis Backend.

### Breaking Down Microengines

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



### Stand Up a Development Testnet

Before creating our Microengine, let's take a look at how all the pre-packaged elements work together.
Do the following:

```sh
pushd orchestration
docker-compose -f base.yml -f tutorial0.yml up
```

You'll see output from the following services:
1. `homechain`: A [geth](https://github.com/ethereum/go-ethereum) node running a toy copy of our "homechain". 
In production use, "homechain" may be the Ethereum mainnet or a limited-access Ethereum private network. More on that later.
1. `sidechain`: Another geth instance running a "sidechain". 
In production, "sidechains" will be used to address scalability concerns and support limit-access artifact sharing.
1. `ipfs`: A sole IPFS node responsible for hosting all artifacts in our development testnet.
1. `polyswarmd`: The PolySwarm daemon providing convenient access to the services offered by `homechain`, `sidechain` and `ipfs`.
1. `contracts`: Responsible for deploying the PolySwarm Nectar and `BountyRegistry` contracts onto our development testnet.
1. `ambassador`: A mock Ambassador (provided by `polyswarm-client`) that will place bounties on [the EICAR file](https://en.wikipedia.org/wiki/EICAR_test_file) and on a file that is not EICAR.
1. `arbiter`: A mock Arbiter (provided by `polyswarm-client`) that will deliver verdicts on "swarmed" artifacts and settle Bounties.
1. `microengine`: A mock Microengine (provided by `polyswarm-client`) that will investigate the "swarmed" artifacts and render Assertions.

When you've seen enough log output, do `Ctrl-C` to halt the development testnet.

## Writing Your First Analysis Backend

Conceptually, all Microengines using `polyswarmd` should support the following:

* `scan` - Scan an artifact associated with a bounty and return an assertion
* `bid` - Calculate how much NCT to stake with an assertion

### Start with the scratch Microengine

We'll start with [microengine/scratch.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/scratch.py) and work toward [microengine/eicar.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/eicar.py)

If we look at `scratch.py`, we see the following:
```python
from polyswarmclient.microengine import Microengine

class ScratchMicroengine(Microengine):
    """Scratch microengine is the same as the default behavior"""
    pass
```

Default behavior happens in [microengine.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/polyswarmclient/microengine.py), so let's open that up, and look at the scan method.

```python
    async def scan(self, guid, content, chain):
        """Override this to implement custom scanning logic

        Args:
            guid (str): GUID of the bounty under analysis, use to track artifacts in the same bounty
            content (bytes): Content of the artifact to be scan
            chain (str): Chain we are operating on
        Returns:
            (bool, bool, str): Tuple of bit, verdict, metadata

            bit (bool): Whether to include this artifact in the assertion or not
            verdict (bool): Whether this artifact is malicious or not
            metadata (str): Optional metadata about this artifact
        """
        if self.scanner:
            return await self.scacnner.scan(guid, content, chain)

        return False, False, ''
```

The return values that the Microengine expects are:
1. `bit`: A `boolean` representing whether the engine wishes to assert on the artifact
1. `verdict`: A `boolean` representing a `malicious` or `benign` determination
1. `metadata`: Optional `string` describing the artifact

As you can see, there's nothing to detect the EICAR test file, much less a real piece of malware!

### Write EICAR Detection Logic

The EICAR test file contains the following string:
`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.

There are many ways to search a file for a string; let's take a look at how [eicar.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/polyswarmclient/microengine.py) does this detection:

```python
import base64

from polyswarmclient.microengine import Microengine

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')

class EicarMicroengine(Microengine):
    async def scan(self, guid, content, chain):
        if content == EICAR:
            return True, True, ''

        return True, False, ''
```

Here's another way, this time comparing the SHA-256 of the EICAR test file with a known-bad hash:

```python
import base64

from hashlib import sha256
from polyswarmclient.microengine import Microengine

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
HASH = sha256(EICAR).hexdigest()

class EicarMicroengine(Microengine):
    async def scan(self, guid, content, chain):
        testhash = sha256(content).hexdigest()
        if (testhash == HASH):
            return True, True, ''

        return True, False, ''
```

### Build and Test Your Brand New EICAR-Detecting Microengine!

Let's build a docker image to test our new Microengine. 
Put your EICAR code into a file named `eicar.py`, and create a `Dockerfile` with the following contents:
```dockerfile
FROM polyswarm/polyswarm-client
LABEL maintainer="Your Name <your@email.com>"

COPY eicar.py src/microengine/eicar.py
RUN set -x && pip install .

ENV KEYFILE=docker/microengine_keyfile
ENV PASSWORD=password

ENTRYPOINT ["microengine"]
CMD ["--polyswarmd-addr", "polyswarmd:31337", "--insecure-transport", "--testing", "10", "--backend", "eicar"]
```

Build your image with
```sh
docker build -t microengine-eicar .
```

Let's spin up a subset of the end-to-end testnet, leaving out the `tutorial` (Microengine) and `ambassador` services:
```sh
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

Once `contracts` has reported that it has successfully deployed the PolySwarm contracts, let's spin up our Microengine in a second terminal window:
```sh
$ docker run -it --net=orchestration_default microengine-eicar
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window:
```sh
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!

If you update your EICAR Microengine, you can retest the engine by re-building the `microengine-eicar` docker image and re-running the `ambassador` service to inject a new pair of EICAR/not-EICAR artifacts.

If you don't feel like copying in and pasting the code to detect EICAR, you can use the EICAR backend for the `polyswarm/polyswarm-client` image with the flag: "`--backend eicar`". Neat.
