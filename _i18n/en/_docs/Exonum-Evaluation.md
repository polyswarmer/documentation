`polyswarm-relay` enables us to use non-Ethereum smart contract platforms by
moving NCT from the Ethereum mainnet to a sidechain chosen by us. First version
of relay uses an PoA Ethereum sidechain as it allows us to reuse our existing
smart contract code deployed on a private network. There are several
disadvantages to continuing with this setup, and Exonum might be an attractive
option with some tradeoffs.

Initial research suggests pros:
* Makes a lot of the DoS questions easier by making NCT the "native" coin on the
  sidechain, instead of a mirror deployed ERC20 token. Can charge fees in NCT to
  discourage DoS independent of gas, don't need fake ether to pay tx fees
* Let's us write our business logic in rust rather than solidity. Allows us to
  do more sophisticated things econ might want without running into limitations
  based on EVM, block size, solidity stack variable limits, gas costs etc.
* Greater theoretical tx/sec and faster clearing times than our ethereum setup
  (5k-15k tx/sec with 0.5s clearing time advertised)
* Concept of anchoring blocks is a well-supported feature, and can supplement or
  replace our current anchoring implementation in relay.
* Light client included that would prevent us from having to set up our
  infura-type service for the sidechain
* Relay could be integrated into the full node as a service, both written in
  rust so natural extension point

Cons:
* Less projects are using it, but it is being used
* Anchoring service uses bitcoin chain by default, (don't think this is a big
  deal)
