## The More The Merrier: YARA

This tutorial will show you how to combine multiple analysis backends and outlines a basic verdict distillation primitive.
The two backends will be `ClamAV` (from the last tutorial) and [`YARA`](https://virustotal.github.io/yara/).

## Adding YARA to the Mix

Start with a fresh engine-template, give it the `engine-name` of "MyYaraEngine".
You should find a `microengine-myyaraengine` in your current working directory - this is what we'll be editing to implement Yara's functionality.
TODO: "engine-template" above should link to the tut-eicar.md section called "Customize engine-template"

We're going to add a YARA backend to our Microengine - but we need some YARA signatures (rules) first!

The [Yara-Rules](https://github.com/Yara-Rules/rules) repo is a great resource for free rules.
So, let's get those rules: 

```sh
git clone https://github.com/Yara-Rules/rules.git
```

We will also need the `yara-python` module to interpret these rules - install this if you don't have it:
```sh
pip install yara-python
```

Next, we will create a Scanner which uses `yara-python` to scan artifacts.

Edit the `__init__.py` as we describe below:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import yara

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

logger = logging.getLogger(__name__)  # Initialize logger
RULES_DIR = os.getenv('RULES_DIR', 'docker/yara-rules')

class Scanner(AbstractScanner):
    def __init__(self):
        self.rules = yara.compile(os.path.join(RULES_DIR, "malware/MALW_Eicar"))

    async def scan(self, guid, content, chain):
        matches = self.rules.match(data=content)
        if matches:
            return True, True, ''

        return True, False, ''
```

The YARA backend included with `polyswarm-client` accepts a `RULES_DIR` environment variable that lets you point to your YARA rules.
So, you should set the `RULES_DIR` environment variable to point to the yara rules you downloaded when you test this engine.
Since our mock Ambassador only posts 2 files, EICAR and not_EICAR, it is sufficient for the content of this tutorial to only include the relevant EICAR rule.

Note: the Microengine class is required, but we do not need to modify it, so it is not shown here.

With that we have a Yara microengine. But, our plan was to have multiple engines run by a single microengine, so let's continue.

## ClamAV Scanner

We are going to re-use the ClamAV scanner from the previous tutorial.
TODO: make "previous tutorial" link to tut-clamav.md.

A finished solution can be found in [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py)

## Multiple Analysis Backends

Start with a fresh engine-template, give it the `engine-name` of "MyMultiEngine".
You should find a `microengine-mymultiengine` in your current working directory - this is what we'll be editing to implement Yara's functionality.
TODO: "engine-template" above should link to the tut-eicar.md section called "Customize engine-template"

We will extend our Microengine to utilize multiple analysis backends, which means we need to have some way to get the result of both backends (YARA and ClamAV) and distill that into our verdict.
Let's create a Microengine which initializes multiple scanners:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import logging

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner
from polyswarm_myclamavengine import Scanner as ClamavScanner
from polyswarm_myyaraengine import Scanner as YaraScanner

logger = logging.getLogger(__name__)  # Initialize logger
BACKENDS = [ClamavScanner, YaraScanner]


class Scanner(AbstractScanner):

    def __init__(self):
        super(Scanner, self).__init__()
        self.backends = [cls() for cls in BACKENDS]

```

This creates a list of backends containing instances of our YaraScanner, plus your ClamavScanner.

Now that we can access both Scanners, let's use both of their results to distill a final verdict in our Scanner's `scan()` function.

```python
    async def scan(self, guid, content, chain):
        results = await asyncio.gather(*[backend.scan(guid, content, chain) for backend in self.backends])

        # Unzip the result tuples
        bits, verdicts, metadatas = tuple(zip(*results))
        return any(bits), any(verdicts), ';'.join(metadatas)
```

Here we calculate all of our Scanner's results asynchronously, and then combine them into our final verdict.
Here we will assert if any of the backends return a True bit, and we will assert that the artifact is malicious if any backend claims it is.
We will also combine all of the metadata from our scanners into one string to be attached to our assertion.

Note: the Microengine class is required, but we do not need to modify it, so it is not shown here.

A finished solution can be found in [multi.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/multi.py).

Note: the python modules `polyswarm_myclamavengine` and `polyswarm_myyaraengine` come from the previous examples.
In order for this Multi-engine to be able to use the ClamAV and Yara engines, they have to be available in your PYTHONPATH.
To achieve that, you can run the following command in the root of both the ClamAV and the Yara project directories:

```bash
pip install .
```

## Next Steps

Now that we've learned how to make a variety of microengines using existing AV products, you can move onto creating your own custom microengine.

