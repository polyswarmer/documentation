## PolySwarm Hive

### What is Hive

PolySwarm Hive is a set of (currently invite-only) testnets that facilitate the development of Microengines, Ambassadors, and Arbiters.

#### How to Apply

Hive is (currently) operated on invite-only basis.
Reach out to us on [Twitter](https://twitter.com/PolySwarm), join our [Discord](https://discord.gg/ntEku44) or otherwise hunt us down for an invite :)

### Connecting to Hive

Once you're approved for access to Hive, you will be provided with:
1. An API key that will provide you with access to 1 or more Hive testnets
1. An Ethereum wallet JSON associated with this API key.
This wallet will contain a certain number of testnet Nectar tokens to play around with.

#### Hive Testnets

| Friendly Name | `polyswarmd` Endpoint |
|---------------|-----------------------|
| Production    | `https://gamma-polyswarmd.prod.polyswarm.network` | 
| Stagning      | `https://gamma-polyswarmd.prod.polyswarm.network` | 

`polyswarmd` is hosted for you in the Hive environment.
* "Production" Hive `polyswarmd` is located at: `https://gamma-polyswarmd.prod.polyswarm.network`
* "Stagning" Hive `polyswarmd` is located at `https://gamma-polyswarmd.prod.polyswarm.network`

#### Connecting with polyswarm-client

Let's connect an EICAR-detecting microengine (discussed in [Tutorial 0](/Level-0-scratch-to-eicar/)) to the PolySwarm Hive Staging testnet.

```sh
docker run 
```

If you don't have a local copy of `polyswarm/polyswarm-client` already, Docker will pull a new copy from Docker Hub.

Connecting is as simple as dropping your API key & wallet JSON into `polyswarm-client` (or your own client) and pointing it toward the hosted `polyswarmd` instance:


#### Using with Custom Client

If you're building a custom client, please ensure that all API requests to Hive hosted `polyswarmd` instances must contain your API key in the headers:

```
Authorization: [API KEY]
```

Furthermore, please ensure that the wallet utilized by your custom client matches the API key sent in all API calls.

For more details on the `polyswarmd API`, please refer to our API specification [polyswarmd API Documentation](/API-polyswarm/).
