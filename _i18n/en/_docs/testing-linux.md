## Unit Testing

Unit testing your Microengine is a simple process:
1. build a Docker image of your Microengine
1. run `docker-compose` to use `tox` to execute your testing logic in `src/scan_test.py`

Run the following commands from the root of your project directory.


Build your Microengine into a Docker image:
```bash
docker build -t ${PWD##*/} -f docker/Dockerfile .
```

This will produce a Docker image tagged with the name of the directory, e.g. `microengine-myeicarengine`.

Run the tests:
```bash
docker-compose -f docker/test.yml up
```

TODO this is broken:
```bash
$ docker-compose -f docker/test.yml up
Starting docker_test_engine_myeicarengine_1_800a4ac410b0 ... done
Attaching to docker_test_engine_myeicarengine_1_800a4ac410b0
test_engine_myeicarengine_1_800a4ac410b0 | GLOB sdist-make: /usr/src/app/setup.py
test_engine_myeicarengine_1_800a4ac410b0 | py35 inst-nodeps: /usr/src/app/.tox/dist/polyswarm_myeicarengine-0.1.zip
test_engine_myeicarengine_1_800a4ac410b0 | py35 installed: aiodns==1.1.1,aiohttp==2.3.1,aioresponses==0.5.0,async-generator==1.10,async-timeout==3.0.1,asynctest==0.12.2,atomicwrites==1.2.1,attrdict==2.0.0,attrs==18.2.0,base58==0.2.5,certifi==2018.11.29,chardet==3.0.4,clamd==1.0.2,click==6.7,coverage==4.5.1,cytoolz==0.9.0.1,eth-abi==1.2.2,eth-account==0.3.0,eth-hash==0.2.0,eth-keyfile==0.5.1,eth-keys==0.2.0b3,eth-rlp==0.1.2,eth-typing==1.3.0,eth-utils==1.3.0,hexbytes==0.1.0,hypothesis==3.82.1,idna==2.7,lru-dict==1.1.6,malwarerepoclient==0.1,more-itertools==4.3.0,multidict==4.5.2,parsimonious==0.8.1,pathlib2==2.3.3,pluggy==0.8.0,polyswarm-client==0.2.0,polyswarm-myeicarengine==0.1,py==1.7.0,pycares==2.3.0,pycryptodome==3.7.2,pytest==3.9.2,pytest-asyncio==0.9.0,pytest-cov==2.6.0,pytest-timeout==1.3.2,python-json-logger==0.1.9,python-magic==0.4.15,requests==2.19.1,rlp==1.0.3,six==1.11.0,toml==0.10.0,toolz==0.9.0,tox==3.4.0,urllib3==1.23,virtualenv==16.1.0,web3==4.6.0,websockets==6.0,yara-python==3.7.0,yarl==1.2.6
test_engine_myeicarengine_1_800a4ac410b0 | py35 run-test-pre: PYTHONHASHSEED='4238516882'
test_engine_myeicarengine_1_800a4ac410b0 | py35 runtests: commands[0] | pytest -s
test_engine_myeicarengine_1_800a4ac410b0 | ============================= test session starts ==============================
test_engine_myeicarengine_1_800a4ac410b0 | platform linux -- Python 3.5.6, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
test_engine_myeicarengine_1_800a4ac410b0 | hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/usr/src/app/.hypothesis/examples')
test_engine_myeicarengine_1_800a4ac410b0 | rootdir: /usr/src/app, inifile:
test_engine_myeicarengine_1_800a4ac410b0 | plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
test_engine_myeicarengine_1_800a4ac410b0 | collected 2 items / 1 errors
test_engine_myeicarengine_1_800a4ac410b0 |
test_engine_myeicarengine_1_800a4ac410b0 | ==================================== ERRORS ====================================
test_engine_myeicarengine_1_800a4ac410b0 | __________ ERROR collecting src/polyswarm_myeicarengine/scan_test.py ___________
test_engine_myeicarengine_1_800a4ac410b0 | ImportError while importing test module '/usr/src/app/src/polyswarm_myeicarengine/scan_test.py'.
test_engine_myeicarengine_1_800a4ac410b0 | Hint: make sure your test modules/packages have valid Python names.
test_engine_myeicarengine_1_800a4ac410b0 | Traceback:
test_engine_myeicarengine_1_800a4ac410b0 | src/polyswarm_myeicarengine/__init__.py:8: in <module>
test_engine_myeicarengine_1_800a4ac410b0 |     from polyswarmclient.abstractmicroengine import AbstractMicroengine
test_engine_myeicarengine_1_800a4ac410b0 | E   ImportError: No module named 'polyswarmclient.abstractmicroengine'
test_engine_myeicarengine_1_800a4ac410b0 | =============================== warnings summary ===============================
test_engine_myeicarengine_1_800a4ac410b0 | /usr/src/app/.tox/py35/lib/python3.5/site-packages/eth_utils/applicators.py:32: DeprecationWarning: combine_argument_formatters(formatter1, formatter2)([item1, item2])has been deprecated and will be removed in a subsequent major version release of the eth-utils library. Update your calls to use apply_formatters_to_sequence([formatter1, formatter2], [item1, item2]) instead.
test_engine_myeicarengine_1_800a4ac410b0 |   "combine_argument_formatters(formatter1, formatter2)([item1, item2])"
test_engine_myeicarengine_1_800a4ac410b0 |
test_engine_myeicarengine_1_800a4ac410b0 | -- Docs: https://docs.pytest.org/en/latest/warnings.html
test_engine_myeicarengine_1_800a4ac410b0 | !!!!!!!!!!!!!!!!!!! Interrupted: 1 errors during collection !!!!!!!!!!!!!!!!!!!!
test_engine_myeicarengine_1_800a4ac410b0 | ===================== 1 warnings, 1 error in 0.81 seconds ======================
test_engine_myeicarengine_1_800a4ac410b0 | ERROR: InvocationError for command '/usr/src/app/.tox/py35/bin/pytest -s' (exited with code 2)
test_engine_myeicarengine_1_800a4ac410b0 | ___________________________________ summary ____________________________________
test_engine_myeicarengine_1_800a4ac410b0 | ERROR:   py35: commands failed
docker_test_engine_myeicarengine_1_800a4ac410b0 exited with code 1
```

`Ctrl-C` when done.


## Integration Testing

The PolySwarm marketplace is composed of a myriad of participants and technologies: Ethereum & IPFS nodes, contracts, Microengines, Ambassadors, Arbiters, artifacts and much more.
Testing a single component often demands availability of all of the other components.

The `orchestration` project makes standing up a complete testnet easy and seamless.
True to its name, `orchestration` orchestrates all the components necessary to stand up and tear down an entire PolySwarm marketplace environment on a local development machine.

Grab `orchestration`:
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

Let's spin up a subset of the testnet, leaving out the stock `microengine` (we'll be replacing this with our own) and the `ambassador` services:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

Once `contracts` has reported that it has successfully deployed the PolySwarm contracts (watch the logs), let's spin up our Microengine in a second terminal window:
```bash
$ docker run -it --net=orchestration_default ${PWD##*/}
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window:
```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```
TODO: do we want to use scale in above?

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!

When you make changes to your Engine, testing those changes is as simple as re-building your Docker image and re-running the `ambassador` service to inject a new a new pair of EICAR/not-EICAR artifacts.
You can keep the rest of the testnet running while you iterate.
