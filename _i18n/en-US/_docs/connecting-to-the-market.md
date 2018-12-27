## Joining the PolySwarm Marketplace

Once you've thoroughly tested your engine, you'll want to put it to work in the real PolySwarm marketplace!

At a high level, plugging into the PolySwarm marketplace is a simple matter of:
1. determining which community(ies) you'd like to join 
2. pointing your engines to the hosted instance of `polyswarmd ` for those communities

There are a few items to be aware of when doing this; we discuss below.


### Choosing Communities

The PolySwarm marketplace is composed of a patchwork of communities.
Communities are groups of individuals and corporations that perhaps share a particular malware interest or mutually agree to maintain the confidentiality of artifacts exchanged within the community.

PolySwarm's first community, Origin, is a public community accessible to everyone.
Origin is where you'll want to get started.
Origin acts as a sort of "proving ground" for security expert to build a reputation and later perhaps engage in additional communities.
As more communities come online, they'll appear in PolySwarm Portal: <button disabled>Browse Communities → (coming soon!)</button>

For now, let's proceed under the assumption that we only want to join the Origin community.


### Wallets & Keyfiles

PolySwarm is built on top of Ethereum, a programmable world computer fueled by a native cryptocurrency.
Ehtereum's native currency is Ether (ETH).
When an Ethereum user executes a transfer of Ether or conducts a call into am Ethereum "smart contract" (e.g. PolySwarm's relay contracts), the user must pay the Ethereum network to carry out this transaction in the form of "Gas".

PolySwarm operates on Nectar (NCT) - an application-layer crypto token build on top of Ethereum.
When your engine transacts with the PolySwarm marketplace, it must have access to both ETH and NCT.

As with all cryptocurrencies (e.g. Bitcoin), funds are maintained in "wallets" that are uniquely identified by a cryptographic hash of the public portion of the cryptographic keypair that defines the wallet.
Possession / control of a wallet (and all funds within it) is analogous to possession of the private portion of the wallet's keypair.

In PolySwarm, as with all cryptocurrency applications, 

(TODO: RED, BOLD)

An attacker with access to your wallet's private key can steal all your cryptocurrency (ETH & NCT).
Therefore, you must take care to protect the secrecy of your wallet's private key.

(TODO: end aside)

Means to secure your private key are generally outside of the scope of this document.
However, in order for your engine to participate in the PolySwarm marketplace (and place transactions on your behalf), your engine must have the ability to sign transactions with your wallet's private key.
This could mean the engine has direct access to the key (and can execute signatures by itself) or is able to request signatures of a device / process that has access to the key.

When testing our engines, we told our engines where to find a "keyfile" that contains our encrypted private key (the `--keyfile` argument).
For testing, that keyfile is encrypted with a trivial password (`password`, specified via the `--password` argument).

(TODO: RED, BOLD)

NEVER USE keyfiles FOUND IN POLYSWARM PROJECTS FOR SPEAKING TO THE POLYSWARM MARKETPLACE.
YOU MUST CREATE YOUR OWN KEYFILE.
YOU ARE SOLELY RESPONSIBLE FOR THE SECURITY OF YOUR KEYFILE.

(TODO: END ASIDE)

Using the official go-ethereum (geth) Ehtereum client, you may create a keyfile as such:
TODO

When running your engines, tell your engine where to find your keyfile (via the `--keyfile` argument) and what your encryption password is (via the `--password` argument).


### API Key

TODO

Copy your provisioned `wallet.json` into the project:
```sh
cp wallet.json polyswarm-client/docker/
pushd polyswarm-client
docker build -t polyswarm/polyswarm-client:tutorial -f docker/Dockerfile .
popd
```

Run our EICAR-detecting Microengine, hooked into Hive:
```sh
docker run polyswarm/polyswarm-client:tutorial \
    microengine \
    --api-key "<YOUR API KEY HERE>" \
    --keyfile "docker/wallet.json" \
    --password "password" \
    --polyswarmd-addr "gamma-polyswarmd.stage.polyswarm.network" \
    --backend "eicar"
```

That's it!


#### Configuring a Custom Client

If you're building a custom client, please ensure that all API requests to Hive hosted `polyswarmd` instances must contain your API key in the headers:

```
Authorization: [API KEY]
```

Furthermore, please ensure that the wallet utilized by your custom client matches the API key sent in all API calls.

For more details on the `polyswarmd API`, please refer to our API specification [polyswarmd API Documentation](/polyswarmd-api/).


### Configuring Your Engine

TODO


