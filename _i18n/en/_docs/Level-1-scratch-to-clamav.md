## Let's Get it On: ClamAV

ClamAV is an open source signature-based engine with a daemon that provides quick analysis of artifacts that it recognizes.
This tutorial will step you through building your second PolySwarm microengine by means of incorporating ClamAV as an analysis backend.

We'll be building on these projects:
* [**polyswarm/microengine**](https://github.com/polyswarm/microengine)
* [**polyswarm/orchestration**](https://github.com/polyswarm/orchestration)

<div class="m-flag">
  <p><strong style="display: inline;">Note:</strong> the PolySwarm marketplace will be a source of previously unseen malware.</p>
  <p>Relying on a strictly signature-based engine as your analysis backend, particularly one whose signatures everyone can access (e.g. ClamAV) is unlikely to yield unique insight into "swarmed" artifacts and therefore unlikely to outperform other engines. </p>
  <p>This guide should not be taken as a recommendation for how to approach the marketplace but rather an example of how to incorporate an existing analysis backend into the <strong style="display: inline;">microengine</strong> skeleton.</p>
</div>

### Recall `src/microengine/eicar.py`:

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

This simple engine asserts `malicious` on the EICAR test file and `benign` on all other files.
Let's expand on this simple backend and incorporate a full-fledged ClamAV instance as our analysis backend.
ClamAV, of course, detects much more than just EICAR :)

## `clamd` Implementation and Integration

We begin our ClamAV `analysis backend` by importing the `clamd` module and configuring some globals.

```python
import clamd
import os

from io import BytesIO
from microengine import Microengine

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0
```

Would you believe me if I said we were almost done?
Let's get `clamd` initialized and running.

```python
class ClamavMicroengine(Microengine):
    """Clamav microengine scans samples through clamd"""
    def __init__(self, polyswarmd_addr, keyfile, password):
        # initialize clamAV Daemon (clamd)
        super().__init__(polyswarmd_addr, keyfile, password)
        self.clamd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```

Now, all we need is a scan method.
Let's rock.

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
async def scan(self, guid, content):
    result = self.clamd.instream(BytesIO(content)).get('stream')
    print(result)
    if len(result) >= 2 and result[0] == 'FOUND':
        return True, True, result[1]

    return True, False, ''
```

If `clamd` detects a piece of malware, it puts `FOUND` in `result[0]`.

The return values that the microengine expects are:

1. `bit` : a `boolean` representing a `malicious` or `benign` determination
1. `assertion`: another `boolean` representing whether the engine wishes to assert on the artifact
1. `metadata`: (optional) `string` describing the artifact

We leave submitting ClamAV's `metadata` as an exercise to the reader.

## Testing, Testing, Testing

Great, we've written our method to interpret `clamd`'s result.
Finally, let's test!

```sh
$ cd microengine
$ docker build -t polyswarm/microengine -f docker/Dockerfile .
$ cd ../orchestration
$ docker-compose -f dev.yml -f tutorial1.yml up
```

The above will compose the development environment(Polyswarmd, the contract migration, ipfs, and geth) and the tutorial components(A mock arbiter, mock ambassador, and your ClamAV microengine).

### Unit Testing

We have also included a unit testing suite, for your convenience, so that you may quickly test the functionality of any microengine's scan function.
Start off by composing the clamAV daemon.
```sh
docker-compose -f dev.yml -f tutorial1.yml up clamav
```
In a new window/pane:
```sh
docker run -it --net=orchestration_default polyswarm/microengine bash
```
You will get dropped into a running microengine container.
```bash
root@id:/usr/src/app# export CLAMD_HOST=clamav
root@id:/usr/src/app# bash
root@id:/usr/src/app# microengine-unit-test --malware_repo dummy --backend clamav
Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
.
----------------------------------------------------------------------
Ran 1 test in 7.782s

OK
```

## Testing Locally(not advised)

### Install `clamd`

To get started, install and launch the ClamAV daemon, `clamd`.

On Ubuntu:

```sh
$ sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
$ sudo freshclam
$ sudo service clamav-daemon start
```

### Install the `clamd` Python Module

We will be interacting with `clamd` via the `clamd` Python module.

If you installed all of the `polyswarm/microengine` required PIP modules in the previous tutorial, you already have the `clamd` module installed.
If not, just do:

```sh
$ pip install clamd
```

Source code for the `clamd` Python module can be found [here](https://github.com/graingert/python-clamd).

### Install the microengine

```sh
$ pip install .
$ pip install -r requirements.txt
```
### Expose the Clamd port
```sh
vim orchestration/tutorial1.yml
...
  clamav:
        image: "mkodockx/docker-clamav"
        ports:
           - 3310:3310
```
### Run it!

```sh
#in one pane, get clamd running
$ docker-compose -f orchestration/dev.yml -f orchestration/tutorial1.yml up polyswarmd contracts clamav
#in another pane, once orchestration_contracts_1 exited with code 0
$ cd microengine/
$ microengine --backend clamav --malware_repo dummy
#expected output:
........
```