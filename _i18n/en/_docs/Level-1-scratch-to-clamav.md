## Let's Get it On: ClamAV
ClamAV is an open-source signature-based engine with a daemon that provides quick analysis of artifacts that it recognizes. 
This tutorial will step you through building your second PolySwarm microengine by means of incorporating ClamAV.
Required code:
[polyswarm/microengine](https://github.com/polyswarm/microengine)
[polyswarm/orchestration](https://github.com/polyswarm/orchestration)
#### Disclaimer: it is very likely that the PolySwarm marketplace will be a source of new/fresh malware and that signature-based scanners such as ClamAV won't be performant sources of income. This is not a recommendation for how to approach the marketplace but rather an example of how to incorporate an analysis backend into the microengine skeleton.

### Recall src/microengine/eicar.py:
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
This engine asserts that it thinks that a sample is EICAR and that it does want to bet on it whenever it detects the standard EICAR test file. Let's make it a bit more robust.

## [Clamd Source](https://github.com/graingert/python-clamd)

## Clamd Installation(Ubuntu)
You need to install clamd on your host in order to be able to interact with it via pythonClamd.
```
sudo apt-get install clamav-daemon clamav-freshclam clamav-unofficial-sigs
sudo freshclam
sudo service clamav-daemon start
```

## Clamd Implementation and Integration
In requirements.txt, we `pip install`ed clamd, the ClamAV daemon. Let's import that, and some other dependencies, as well as set some globals.
```python
import clamd
import os

from io import BytesIO
from microengine import Microengine

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0
```
Would you believe me if I said we were almost done? Let's get Clamd initialized and running.
```python
class ClamavMicroengine(Microengine):
    """Clamav microengine scans samples through clamd"""
    def __init__(self, polyswarmd_addr, keyfile, password):
    	#initialize clamAV Daemon (clamd)
        super().__init__(polyswarmd_addr, keyfile, password)
        self.clamd = clamd.ClamdNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```
Now, all we need is a scan method. Let's rock.
```python
async def scan(self, guid, content):
```
The way we interact with clamd in this tutorial is by sending it the byte stream. Clamd responds to the EICAR test file with: `{'stream': ('FOUND', 'Eicar-Test-Signature')}`.
```python
async def scan(self, guid, content):
	result = self.clamd.instream(BytesIO(content)).get('stream')
```
We can easily parse the result using python's `[]` operator. result[0] is the word 'FOUND', and result[1] in this instance is 'Eicar-Test-Signature'.
To complete our scan function:
```python
async def scan(self, guid, content):
        result = self.clamd.instream(BytesIO(content)).get('stream')
        print(result)
        if len(result) >= 2 and result[0] == 'FOUND':
            return True, True, result[1]

        return True, False, ''
```
If clamd detects a piece of malware, it puts 'FOUND' in result[0]. The return values that the microengine expects are: `bit, assertion, metadata` where `bit` is a boolean representing whether or not the file is malware, `assertion` is another boolean representing whether or not the engine wishes to assert on it, and `metadata` is an optional string identifying the artifact. Since ClamAV is signature-based, we'll submit the metadata of the artifact since we can generally trust it to be accurate.

## ClamAV microengine testing!

Great, we've written our method to interpret clamd's result. Now, let's test it all!
```sh
cd orchestration
docker-compose -f dev.yml -f tutorial.yml up
```