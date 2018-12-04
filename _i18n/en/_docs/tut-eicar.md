# Microengine "Hello World"


## Overview 

The "Hello World" of developing an anti-malware solution is invariably detecting the [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file).

This benign file is detected as "malicious" by all major anti-malware products - a safe way to test a positive result.

Our first Microengine will be no different: let's detect EICAR!

[(Optional) Review the components of a Microengine ->](TODO: link to participants_microengine.md, section "Breaking Down Microengines")


## Building Blocks

This guide will reference and build on:

* [**engine-template**](https://github.com/polyswarm/engine-template):
The name says it all - this is a convenient template with interactive prompts for creating new engines.
We'll use this in our tutorial.

* [**polyswarm-client**](https://github.com/polyswarm/polyswarm-client): 
The Swiss Army knife of exemplar PolySwarm participants ("clients"). 
`polyswarm-client` can function as a `microengine` (we'll build on this functionality in this tutorial), an `arbiter` and an `ambassador` (we'll use these to test what we built).


## Customize `engine-template`

> Warning: Windows-based engines are currently only supported as AMIs - AWS Machine Images.
The customization process for Window-based engines assumes you have an AWS account and its ID handy.
We'll be expanding deployment options in near future, including self-hosted options.
Linux-based engines have no such stipulation.

We're going to cut our Engine from `engine-template`.
To do this, we'll need `cookiecutter`:
```bash
pip install cookiecutter
```

With `cookiecutter` installed, jump-starting your engine from our template is as easy as:
```bash
cookiecutter https://github.com/polyswarm/engine-template
```

Prompts will appear, here's how we'll answer them:
* `engine_name`: **MyEicarEngine**
* `engine_name_slug`: (accept the default)
* `project_slug`: (accept the default)
* `author_org`: ACME (or your real company)
* `author_org_slug`: (accept the default)
* `package_slug`: (accept the default)
* `author_name`: Wile E Coyote (or your real name)
* `author_email`: (whatever you want)
* `platform`: answer truthfully - will this Engine run on Linux or Windows?
* `has_backend`: no - [because this Engine will not have a disjoint backend scanner](https://github.com/polyswarm/engine-template/blob/master/README.md#has_backend)
* `aws_account_for_ami`: (Windows only) your AWS account ID

All set!

You should find a `microengine-myeicarengine` in your current working direction - this is what we'll be editing to implement EICAR scan functionality.


### Start with the `scratch` Microengine

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
```bash
docker build -t microengine-eicar .
```

Let's spin up a subset of the end-to-end testnet, leaving out the `tutorial` (Microengine) and `ambassador` services:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

Once `contracts` has reported that it has successfully deployed the PolySwarm contracts, let's spin up our Microengine in a second terminal window:
```bash
$ docker run -it --net=orchestration_default microengine-eicar
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!

If you update your EICAR Microengine, you can retest the engine by re-building the `microengine-eicar` docker image and re-running the `ambassador` service to inject a new pair of EICAR/not-EICAR artifacts.

If you don't feel like copying in and pasting the code to detect EICAR, you can use the EICAR backend for the `polyswarm/polyswarm-client` image with the flag: "`--backend eicar`". Neat.
