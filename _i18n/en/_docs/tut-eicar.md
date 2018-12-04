# Microengine "Hello World"


## Overview 

The "Hello World" of developing an anti-malware solution is invariably detecting the [EICAR test file](https://en.wikipedia.org/wiki/EICAR_test_file).

This benign file is detected as "malicious" by all major anti-malware products - a safe way to test a positive result.

Our first Microengine will be no different: let's detect EICAR!

[(Optional) review the components of a Microengine ->](TODO: link to participants_microengine.md, section "Breaking Down Microengines")


## Building Blocks

This guide will reference and build on:

* [**engine-template**](https://github.com/polyswarm/engine-template):
The name says it all - this is a convenient template with interactive prompts for creating new engines.
We'll use this in our tutorial.

* [**polyswarm-client**](https://github.com/polyswarm/polyswarm-client): 
The Swiss Army knife of exemplar PolySwarm participants ("clients"). 
`polyswarm-client` can function as a `microengine` (we'll build on this functionality in this tutorial), an `arbiter` and an `ambassador` (we'll use these to test what we built).


## Customize `engine-template`

> Warning: Windows-based engines are currently only supported as AMIs (AWS Machine Images).
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
* `engine_name`: **MyEicarEngine** (the name of your engine)
* `engine_name_slug`: (accept the default)
* `project_slug`: (accept the default)
* `author_org`: ACME (or the real name of your organization)
* `author_org_slug`: (accept the default)
* `package_slug`: (accept the default)
* `author_name`: Wile E Coyote (or your real name)
* `author_email`: (your email address)
* `platform`: answer truthfully - will this Engine run on Linux or Windows?
* `has_backend`: no (see explanation below)
* `aws_account_for_ami`: (Windows only) your AWS account ID (for Linux engines, just accept the default)

TODO: make this whole section into some sort of aside / callout, start here

One of the prompt items is `has_backend`, which can be thought of as "has a disjoint backend" and deserves additional explanation.

When wrapping your scan engine, inheritance of `polyswarm-client` classes and implementation of class functionality are referred to as "frontend" changes.
If your scan engine "frontend" must reach out across a network or local socket to a separate process that does the real scanning work (the "backend"), then you have a disjoint "backend" and you should answer `yes` to `has_backend`.
If instead your scan engine can easily be encapsulated in a single Docker image (Linux) or AMI (Windows), then you should select `no` for `has_backend`.

Example of disjoint frontend / backend:
* ClamAV: https://github.com/polyswarm/polyswarm-client/blob/5959742f0014a582baf5046c7bf6694c23f7435e/src/microengine/clamav.py#L18

Example of only a frontend (has_backend is false):
* Yara: https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/yara.py

TODO: end aside

You're all set!

You should find a `microengine-myeicarengine` in your current working direction - this is what we'll be editing to implement EICAR scan functionality.


## Implement an EICAR Scanner & Microengine

Detecting EICAR is as simple as:
1. implementing a Scanner class that knows how to identify the EICAR test file
1. implementing a Microengine class that uses this Scanner class

Let's get started.

Open `microengine-myeicarengine/src/(the org slug name)_myeicarengine/__init__.py`.

This file will implement both our Scanner and Microengine classes:

* **Scanner**: our Scanner class. 
This class will implement our EICAR-detecting logic in its `scan` function.

* **Microengine**: our Microengine class.
This class will wrap the aforementioned Scanner to handle all the necessary tasks of being a Microengine that detects EICAR.


### Write EICAR Detection Logic

The EICAR test file is defined as a file that contains only the following string: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.

There are, of course, many ways to identify files that match this criteria.
The `scan` function's `content` parameter contains the entire content of the artifact in question - this is what you're matching against.

**Try your hand at writing a `scan` function that detects the EICAR test file.**
If you'd like some inspiration, below are a couple of ways to go about it.
 
From [`eicar.py`](https://github.com/polyswarm/polyswarm-client/blob/master/src/polyswarmclient/microengine.py):

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

That's it!

Don't worry, we'll test your Microengine shorty :)


### Develop a Staking Strategy

At a minimum, Microengines are responsible for: (a) detecting malicious files, (b) rendering assertions with NCT staked on them.

Staking logic is implemented in the Microengine's `bid` function.

By default, all assertions are placed with the minimum stake permitted by the community a Microengine is joined to.

Check back soon for an exploration of various staking strategies.


## Finalizing Your Engine

`cookiecutter` customizes `engine-template` only so far - there are a handful of items you'll need to fill out yourself.
We've already covered the major items above, but do a quick search for `CUSTOMIZE_HERE` to ensure all customization have been made.

[Let's test our engine ->](TODO link to testing.md)
