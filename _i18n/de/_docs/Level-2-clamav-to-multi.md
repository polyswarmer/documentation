## The More The Merrier: YARA

This tutorial will show you how to combine multiple analysis backends and outlines a basic verdict distillation primitive. The two backends will be `ClamAV` (from the last tutorial) and [`YARA`](https://virustotal.github.io/yara/).

## Introducing Scanners

For the past two tutorials we've been overriding the `scan` method in the Microengine class to implement our custom scanning functionality. This is simple and works great for when you're just getting started.

To make developing multiple Scanners as easy as possible, `polyswarm-client` also provides for `Scanner` objects, which contain the same `scan` method which can be overridden to customize behavior. This allows a separation between scanning logic and bounty / offer submission logic, and for easier reuse in other Microengines or Arbiters.

If we examine the base `micorengine` scan implementation, we can see that, when provided with a `scanner` object, `scanner.scan()` is invoked by default.

```py
    async def scan(self, guid, content, chain):
        if self.scanner:
            return await self.scanner.scan(guid, content, chain)

        return False, False, ''
```

## Adding YARA to the Mix

We're going to add a YARA backend to our Microengine - but we need some YARA signatures (rules) first!

The [Yara-Rules](https://github.com/Yara-Rules/rules) repo is a great resource for free rules; we've submodule'd this repo to `polyswarm-client` your convenience. If you didn't clone `polyswarm-client` with `git clone --recursive`, run this to update pull these free rules in the root of the `polyswarm-client` directory:

```sh
git submodule update --init --recursive
```

We will also need the `yara-python` module to interpret these rules - install this if you don't have it:

```sh
pip install yara-python
```

Next, we will create a Scanner which uses `yara-python` to scan artifacts. Our Scanner will look something like this:

```py
class YaraScanner(Scanner):
    def __init__(self):
        self.rules = yara.compile(os.path.join(RULES_DIR, "malware/MALW_Eicar"))

    async def scan(self, guid, content, chain):
        matches = self.rules.match(data=content)
        if matches:
            return True, True, ''

        return True, False, ''
```

You can also add custom YARA signatures to your Microengine. The YARA backend included with `polyswarm-client` accepts a `RULES_DIR` environment variable that lets you point to your YARA rules. You can copy custom rules to the `docker/yara-rules` directory that exists by default in the `polyswarm-client` repository, this is also where the `Yara-Rules` submodule is located.

Since our mock Ambassador only posts 2 files, EICAR and not_EICAR, it is sufficient for the content of this tutorial to only include the relevant EICAR rule.

## ClamAV Scanner

Take what you've learned about Scanners and the implementing a ClamAV Microengine (previous tutorial) and implement a ClamAV Scanner. This is left as an exercise to the reader.

A finished solution can be found in [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py)

## Multiple Analysis Backends

We will extend our Microengine to utilize multiple analysis backends, which means we need to have some way to get the result of both backends (YARA and ClamAV) and distill that into our verdict. Let's create a Microengine which initializes multiple scanners for use can name it `multi.py`:

```py
BACKENDS = [ClamavScanner, YaraScanner]


class MultiMicroengine(Microengine):
    def __init__(self, client, testing=0, scanner=None, chains={'home'}):
        super().__init__(client, testing, None, chains)
        self.backends = [cls() for cls in BACKENDS]
```

This creates instances of our YaraScanner, plus your ClamavScanner.

Now that we can access both Scanners, let's use both of their results to distill a final verdict in our Microengine's `scan()` function.

```py
    async def scan(self, guid, content, chain):
        results = await asyncio.gather(*[backend.scan(guid, content, chain) for backend in self.backends])

        # Unzip the result tuples
        bits, verdicts, metadatas = tuple(zip(*results))
        return any(bits), any(verdicts), ';'.join(metadatas)
```

Here we calculate all of our Scanner's results asynchronously, and then combine them into our final verdict. Here we will assert if any of the backends return a True bit, and we will assert that the artifact is malicious if any backend claims it is. We will also combine all of the metadata from our scanners into one string to be attached to our assertion.

A finished solution can be found in [multi.py]((https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/multi.py)).

## Testing

Let's build a docker image to test our new Microengine. With our code in files `clamav.py`, `yara.py`, `multi.py`, lets build an image with the following `Dockerfile`:

```dockerfile
FROM polyswarm/polyswarm-client
LABEL maintainer="Your Name <your@email.com>"

COPY clamav.py src/microengine/clamav.py
COPY yara.py src/microengine/yara.py
COPY multi.py src/microengine/multi.py
RUN set -x && pip install .

ENV KEYFILE=docker/microengine_keyfile
ENV PASSWORD=password
ENV CLAMD_HOST=clamav
ENV CLAMD_PORT=3310

ENTRYPOINT ["microengine"]
CMD ["--polyswarmd-addr", "polyswarmd:31337", "--insecure-transport", "--testing", "10", "--backend", "multi"]
```

Build your image with

```sh
docker build -t microengine-multi .
```

Let's spin up a subset of the end-to-end testnet, leaving out the `tutorial` (Microengine) and `ambassador` services, but including a `clamav` service listening for samples over the network. YARA does not require an additional container; `yara-python` will do our rule matching for us.

```sh
$ docker-compose -f dev.yml -f tutorial2.yml up --scale tutorial=0 --scale ambassador=0
```

Once `contracts` has reported that it has successfully deployed the PolySwarm contracts, let's spin up our Microengine in a second terminal window:

```sh
$ docker run -it --net=orchestration_default microengine-multi
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window:

```sh
$ docker-compose -f dev.yml -f tutorial2.yml up --no-deps ambassador
```

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!

### Custom Backends

All of our backends so far have friendly names passed to the `--backend` flag in our `Dockerfiles` as they are built-in cases in our base [microengine](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/__main__.py). We can load in arbitrary microengines from any Python module by using the form e.g. `--backend microengine.custom:CustomMicroengine` where `microengine.custom` is our module and `CustomMicroengine` is our Microengine class. Try this yourself to test out new Microengine ideas!
