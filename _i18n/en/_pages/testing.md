# Testing Your Engine

> Info: Current testing procedures are limited to Microengines.
Please check back soon for instructions on testing Ambassadors and Arbiters.


## Testing Linux-based Engines

### Building Blocks

This guide will reference and build on:

* [**polyswarmd**](https://github.com/polyswarm/polyswarmd): 
The PolySwarm daemon. 
This daemon handles Ethereum and IPFS idiosyncrasies for you, allowing you to focus on Microengine development.

* [**contracts**](https://github.com/polyswarm/contracts): 
The Ethereum smart contracts that all Microengines must support (and scaffolding for deploying, etc).

* [**orchestration**](https://github.com/polyswarm/orchestration): 
A set of `docker-compose` files that we'll use to conveniently stand up a local test network.


### Grab Orchestration

The PolySwarm marketplace is composed of a myriad of participants and technologies: `geth` & IPFS nodes, contracts, Microengines, Ambassadors, Arbiters, artifacts and much more.
Testing a single component often demands availability of the other components.

Fortunately, `orchestration` makes this easy and seamless.
True to its name, `orchestration` orchestrates all the components necessary to stand up and tear down an entire PolySwarm marketplace environment on a local development machine.


 - by orchestrating various PolySwarm components in a local testing environment 

The `orchestration` project will help us with TODO.

Clone it:
```bash
git clone https://github.com/polyswarm/orchestration
```

### Testing Linux-Based Microengines

TODO this section

Before creating our Microengine (TODO), let's take a look at how all the pre-packaged elements work together.
Do the following:

```bash
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




## Testing Windows-Based Engines

TODO

