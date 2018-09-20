## PolySwarm Hive

### What is Hive

PolySwarm Hive is a set of (currently invite-only) testnets that facilitate the development of Microengines, Ambassadors, and Arbiters.

#### How to Apply

Hive is (currently) operated on invite-only basis.
Reach out to us on [Twitter](https://twitter.com/PolySwarm), join our [Discord](https://discord.gg/ntEku44) or otherwise hunt us down for an invite :)

### Connecting to Hive

Once you're approved for access to Hive, you will be provided with:
1. `hive.apikey`: An API key that will provide you with access to 1 or more Hive testnets
1. `wallet.json`: An Ethereum wallet JSON associated with this API key.
This wallet will contain testnet Nectar tokens to play around with.

#### Hive Testnets

| Friendly Name | `polyswarmd` Endpoint |
|---------------|-----------------------|
| Production    | `https://gamma-polyswarmd.prod.polyswarm.network` | 
| Staging       | `https://gamma-polyswarmd.stage.polyswarm.network` | 

`polyswarmd` is hosted for you in the Hive environment.
* "Production" Hive `polyswarmd` is located at: `https://gamma-polyswarmd.prod.polyswarm.network`
* "Stagning" Hive `polyswarmd` is located at `https://gamma-polyswarmd.prod.polyswarm.network`

#### Connecting with polyswarm-client

We'll connect an EICAR-detecting Microengine (discussed in [Tutorial 0](/Level-0-scratch-to-eicar/)) to the PolySwarm Hive Staging testnet.

Grab a copy of `polyswarm-client`:
```sh
git clone https://github.com/polyswarm/polyswarm-client
```

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


#### Using with Custom Client

If you're building a custom client, please ensure that all API requests to Hive hosted `polyswarmd` instances must contain your API key in the headers:

```
Authorization: [API KEY]
```

Furthermore, please ensure that the wallet utilized by your custom client matches the API key sent in all API calls.

For more details on the `polyswarmd API`, please refer to our API specification [polyswarmd API Documentation](/API-polyswarm/).
