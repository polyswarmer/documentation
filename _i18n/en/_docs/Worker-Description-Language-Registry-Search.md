## Worker Description Language (WDL)

Security Experts in the PolySwarm marketplace may avertise their wares (microengines) by authoring JSON that conforms to the WDL schema and then registering this JSON blog with the PolySwarm Worker Registry (WR).
This is registry allows security experts to advertise that `microengine-mypdfanalyzer` is good at detecting malware in PDFs, for example.

Refer to the WDL JSON schema: TODO

At a high level, security experts produce a single JSON blob that contains:
1. (voluntary) `developer metadata` describing the security expert themselves
2. an array of `N` microengine descriptions

TODO ^ expand on above

In the `developer metadata` field, security experts may choose to link their pseudononymous on-chain addresses to real-world identifiers on services like Twitter, GitHub, Keybase and others.

Each item in the `microengine` array will describe the `microengines` that the `developer` is advertising at this time.
Each item in this array is signed with the private key associated with the `microengine` being described.

The whole JSON blob is signed by the `developer`'s master private key corresponding to their public Ethereum address.

All peers must validate these signatures to ensure that malicious actors cannot advertise others' `microengines` to their benefit.


## PolySwarm Registry
* a smart contract
* people send the IPFS address of a signed WDL JSON blog into the registry
* anyone can reference the registry to look up info about a security expert
* security experts are incentivized to always have their JSON blob be available (it's advertisement)


## Registry Search
CLI (and later a webapp) that:

1. ingests a public address of a developer
2. uses registry contract to resolve public address to IPFS hash
3. pull WDL JSON from IPFS
4. display information concerning developer + their microengines to the user
