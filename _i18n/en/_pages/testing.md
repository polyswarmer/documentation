# Testing Your Engine

> Info: Current instructions cover testing Microengines.
Please check back soon for instructions on testing Ambassadors and Arbiters.

## Testing Linux-based Engines

### Building Blocks

This guide will reference and build on:

* [**polyswarmd**](https://github.com/polyswarm/polyswarmd): 
The PolySwarm daemon. 
This daemon handles Ethereum and IPFS idiosyncrasies for you, allowing you to focus on Microengine development.

* [**contracts**](https://github.com/polyswarm/contracts): 
The Ethereum smart contracts that all Microengines must support.

* [**orchestration**](https://github.com/polyswarm/orchestration): 
A set of `docker-compose` files that we'll use to conveniently stand up a local test network.


### Orchestration

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


## Testing Windows-Based Engines

TODO

