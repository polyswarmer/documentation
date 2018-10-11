## Setting the Stage

ClamAV is an open source signature-based engine with a daemon that provides quick analysis of artifacts that it recognizes. This tutorial will step you through building your second PolySwarm Microengine by means of incorporating ClamAV as an analysis backend.

<div class="m-flag">
  <p><strong style="display: inline;">Note:</strong> the PolySwarm marketplace will be a source of previously unseen malware.</p>
  <p>Relying on a strictly signature-based engine as your analysis backend, particularly one whose signatures everyone can access (e.g. ClamAV) is unlikely to yield unique insight into "swarmed" artifacts and therefore unlikely to outperform other engines. </p>
  <p>This guide should not be taken as a recommendation for how to approach the marketplace but rather an example of how to incorporate an existing analysis backend into a <strong style="display: inline;">Microengine</strong> skeleton.</p>
</div>

This tutorial will walk the reader through building [microengine/clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py); please refer to `clamav.py` for the completed work.

## `clamd` Implementation and Integration

We begin our ClamAV `analysis backend` by importing the `clamd` module and configuring some globals. Let's edit [microengine/scratch.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/scratch.py) and begin writing a ClamAV analysis backend:

```python
import clamd
import os

from io import BytesIO
from polyswarmclient.microengine import Microengine

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0
```

Would you believe me if I said we were almost done? Let's get `clamd` initialized and running.

```python
class ClamavMicroengine(Microengine):
    def __init__(self, polyswarmd_addr, keyfile, password, api_key=None, testing=0, insecure_transport=False, chains={'home'}):
        super().__init__(polyswarmd_addr, keyfile, password, api_key, testing, insecure_transport, chains)
        self.clamd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```

Now, all we need is a scan method.

```python
    async def scan(self, guid, content):
```

We interact with `clamd` by sending it a byte stream of artifact contents.

ClamAV responds to these byte streams in the form:

```json
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```

We can easily parse the result using python's `[]` operator. `result[0]` is the word `FOUND`, and `result[1]` in this instance is `Eicar-Test-Signature`.

To complete our scan function:

```python
        result = self.clamd.instream(BytesIO(content)).get('stream')
        if len(result) >= 2 and result[0] == 'FOUND':
            return True, True, ''

        return True, False, ''
```

If `clamd` detects a piece of malware, it puts `FOUND` in `result[0]`.

The return values that the Microengine expects are:

1. `bit` : a `boolean` representing a `malicious` or `benign` determination
2. `verdict`: another `boolean` representing whether the engine wishes to assert on the artifact
3. `metadata`: (optional) `string` describing the artifact

We leave submitting ClamAV's `metadata` as an exercise to the reader - or check [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) :)

## Testing, Testing, Testing

Let's build a docker image to test our new Microengine. Put your ClamAV code into a file named `clamav.py`, and create a `Dockerfile` with the following contents:

```dockerfile
FROM polyswarm/polyswarm-client
LABEL maintainer="Your Name <your@email.com>"

COPY clamav.py src/microengine/clamav.py
RUN set -x && pip install .

ENV KEYFILE=docker/microengine_keyfile
ENV PASSWORD=password
ENV CLAMD_HOST=clamav
ENV CLAMD_PORT=3310

ENTRYPOINT ["microengine"]
CMD ["--polyswarmd-addr", "polyswarmd:31337", "--insecure-transport", "--testing", "10", "--backend", "clamav"]
```

Build your image with

```sh
docker build -t microengine-clamav .
```

Let's spin up a subset of the end-to-end testnet, leaving out the `tutorial` (Microengine) and `ambassador` services, but including a `clamav` service listening for samples over the network:

```sh
$ docker-compose -f base.yml -f tutorial1.yml up --scale microengine=0 --scale ambassador=0
```

Once `contracts` has reported that it has successfully deployed the PolySwarm contracts, let's spin up our Microengine in a second terminal window:

```sh
$ docker run -it --net=orchestration_default microengine-clamav
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window:

```sh
$ docker-compose -f base.yml -f tutorial1.yml up --no-deps ambassador
```

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!