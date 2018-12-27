# Testing Linux-Based Engines


## Unit Testing

Unit testing your Microengine is a simple process:
1. build a Docker image of your Microengine
1. run `docker-compose` to use `tox` to execute your testing logic in `tests/scan_test.py`

Run the following commands from the root of your project directory.

Build your Microengine into a Docker image:
```bash
docker build -t ${PWD##*/} -f docker/Dockerfile .
```

This will produce a Docker image tagged with the name of the directory, e.g. `microengine-myeicarengine`.

Run the tests:
```bash
docker-compose -f docker/test-unit.yml up
```

If your Microengine is capable of detecting EICAR and not producing a false positive on the string "not a malicious file", then you should pass these basic unittests and see something like this:

```bash
e$ docker-compose -f docker/test-unit.yml up
Recreating docker_test_engine_mylinuxengine_1_a9d540dc7394 ... done
Attaching to docker_test_engine_mylinuxengine_1_a9d540dc7394
...
test_engine_mylinuxengine_1_a9d540dc7394 | py35 run-test-pre: PYTHONHASHSEED='1705267802'
test_engine_mylinuxengine_1_a9d540dc7394 | py35 runtests: commands[0] | pytest -s
test_engine_mylinuxengine_1_a9d540dc7394 | ============================= test session starts ==============================
test_engine_mylinuxengine_1_a9d540dc7394 | platform linux -- Python 3.5.6, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
test_engine_mylinuxengine_1_a9d540dc7394 | hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/usr/src/app/.hypothesis/examples')
test_engine_mylinuxengine_1_a9d540dc7394 | rootdir: /usr/src/app, inifile:
test_engine_mylinuxengine_1_a9d540dc7394 | plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
test_engine_mylinuxengine_1_a9d540dc7394 | collected 36 items
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | tests/scan_test.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bloom.py ......
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bounties.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_client.py ............
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_corpus.py ..
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_events.py ..............
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | ========================== 36 passed in 39.42 seconds ==========================
test_engine_mylinuxengine_1_a9d540dc7394 | ___________________________________ summary ____________________________________
test_engine_mylinuxengine_1_a9d540dc7394 |   py35: commands succeeded
test_engine_mylinuxengine_1_a9d540dc7394 |   congratulations :)
```

Of course, this testing is quite limited - you'll want to expand on your tests in `scan_test.py`, as appropriate for your Microengine.


## Local Integration Testing

The PolySwarm marketplace is composed of a myriad of participants and technologies: Ethereum & IPFS nodes, contracts, Microengines, Ambassadors, Arbiters, artifacts and much more.
Testing a single component often demands availability of all of the other components.

The `orchestration` project makes standing up a complete testnet easy and seamless.
True to its name, `orchestration` orchestrates all the components necessary to stand up and tear down an entire PolySwarm marketplace environment on a local development machine.

Clone `orchestration`:
```bash
git clone https://github.com/polyswarm/orchestration
```

### (Optional) Preview a Complete, Working Testnet

Let's spin up a complete, working testnet to get a sense for what things *should* look like:
```bash
pushd orchestration
docker-compose -f base.yml -f tutorial0.yml up
```

You'll see output from the following services:
1. `homechain`: A [geth](https://github.com/ethereum/go-ethereum) node running our testnet's "homechain".
See [Chains: Home vs Side](/#chains-home-vs-side) for an explanation of our split-chain design.
1. `sidechain`: Another `geth` instance, this one running our testnet's "sidechain".
1. `ipfs`: An IPFS node responsible for hosting all artifacts in our development testnet.
1. `polyswarmd`: The PolySwarm daemon providing convenient access to the services offered by `homechain`, `sidechain` and `ipfs`.
1. `contracts`: Responsible for housing & deploying the PolySwarm Nectar (NCT) and `BountyRegistry` contracts onto our development testnet.
1. `ambassador`: A mock Ambassador (provided by `polyswarm-client`) that will place bounties on [the EICAR file](https://en.wikipedia.org/wiki/EICAR_test_file) and on a file that is not EICAR.
1. `arbiter`: A mock Arbiter (provided by `polyswarm-client`) that will deliver Verdicts on "swarmed" artifacts, determining ground truth.
1. `microengine`: A mock Microengine (provided by `polyswarm-client`) that will investigate the "swarmed" artifacts and render Assertions.

Browse through the logs scroll on the screen to get a sense for what each of these components is doing.
Let it run for at least 5 minutes - it can take time to deploy contracts - and then the fun starts :)

When you've seen enough log output, do `Ctrl-C` to halt the development testnet gracefully.


### Test Your Engine

Let's spin up a subset of the testnet, leaving out the stock `microengine` (we'll be replacing this with our own) and the `ambassador` services.

In the cloned `orchestration` project:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

It will take several minutes for `polyswarmd` to become available.
Once `polyswarmd` is available, it will begin serving responses to clients, e.g.:
```
INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
```

Next, let's spin up our Microengine in a second terminal window in our microengine's directory:
```bash
$ docker-compose -f docker/test-integration.yml up
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window in the `orchestration` directory:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!

When you make changes to your Engine, testing those changes is as simple as re-building your Docker image and re-running the `ambassador` service to inject a new a new pair of EICAR/not-EICAR artifacts.
You can keep the rest of the testnet running while you iterate.
