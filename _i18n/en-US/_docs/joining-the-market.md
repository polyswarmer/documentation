# Participating in the PolySwarm Marketplace

Once you've thoroughly tested your engine, you'll want to put it to work in the real PolySwarm marketplace!

At a high level, plugging into the PolySwarm marketplace is a simple matter of:
1. determining which Community(ies) you'd like to join
2. pointing your engines to the hosted instance of `polyswarmd ` for those Communities

There are a few items to be aware of when doing this; we discuss below.


## Wallets & Keyfiles

PolySwarm is built on top of Ethereum, a programmable world computer fueled by a native cryptocurrency called Ether (ETH).
When an Ethereum user executes a transfer of ETH or conducts a call into an Ethereum "smart contract" (e.g. PolySwarm's Relay contracts), the user must pay the Ethereum network to carry out this transaction in the form of "Gas".
Gas is deducted from the user's ETH balance.

PolySwarm operates on Nectar (NCT) - an application-layer cryptocurrency token built on top of Ethereum.
NCT is essential for participating in the PolySwarm marketplace.

Your engine, acting as your representative on the PolySwarm marketplace, must have access to both ETH and NCT.

### Cryptocurrency Wallets

As with all cryptocurrencies (e.g. Bitcoin), funds are maintained in "wallets".
Technically, a wallet is simply a cryptographic keypair and some metadata that describes the keypairs' usage.
Wallets are uniquely identified by a cryptographic hash of the public portion of this cryptographic keypair.
Possession / control of a wallet (and all funds contained therein) is analogous to possession of the private portion of the wallet's keypair.

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      In PolySwarm, as with all cryptocurrency applications, an attacker with access to your wallet's private key can steal all your cryptocurrency (ETH & NCT) and impersonate you in the marketplace.
      It is absolutely essential that you protect the secrecy of your wallet's private key.
    </strong>
  </p>
</div>

Means to secure your private key are outside of the scope of this document.
In order for your engine to participate in the PolySwarm marketplace (and place transactions on your behalf), your engine must have the ability to sign transactions with your wallet's private key.
This means the engine must either have direct access to the key (less secure) or have the ability to request signatures of a device / process that has access to the key (more secure).
The direct keyfile access method is supported by `polyswarm-client` today.
Support for offloading transaction signing to another device will arrive in a future `polyswarm-client` release.

### Wallet Usage in PolySwarm

When testing our engines, we told our engines where to find a "keyfile" that contains our encrypted private key via the `--keyfile` argument to the `polyswarm-client` utilities (i.e. `microengine` and `balancemanager`).
All keyfiles distributed with `polyswarm-client` (and other PolySwarm projects) are encrypted with a trivial password: `password`, specified via the `--password` argument.

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      The sole purpose of these distributed keyfiles is for testing with fake nct and fake eth.
      Never use testing keyfiles from polyswarm projects in production or in real communities.
      Never fund the wallets contained in these testing keyfiles with real nct or real eth.
    </strong>
  </p>
  <p>
    <strong>
      When operating outside of a development testing environment you must create your own production keyfile.
    </strong>
  </p>
  <p>
    <strong>
      You are solely responsible for the security of your production keyfile.
    </strong>
  </p>
</div>

The official Ethereum client (`go-ethereum` or `geth` for short) has instructions for generating a keyfile. See [Managing your accounts in geth](https://github.com/ethereum/go-ethereum/wiki/Managing-your-accounts).


## Funding Your Wallet

Once you've generated your own keyfile, you'll need to fund your wallet with ETH and NCT.

Generally, there are three funding avenues available:
1. Purchase ETH and NCT on cryptocurrency exchanges and transfer them to the production wallet represented by your microengine's production keyfile.
Methods to purchase & transfer cryptocurrencies are outside the scope of this document.
2. Subscribe to PolySwarm Direct - an upcoming service with configurable auto-refills that ensure your engine is funded.
This service is in development, stay tuned!
3. Initial partners have received a NCT seedling in their production wallet per our published distribution schedule.


## Finding Your Community(ies)

The PolySwarm marketplace is made up of a patchwork of Communities.
Communities are groups of individuals and corporations that share a particular malware interest or mutually agree to maintain the confidentiality of artifacts exchanged within the Community.

PolySwarm's first Community, Epoch, is a public Community accessible to everyone - it's where you'll want to get started.
Epoch acts as a sort of "proving ground" for security experts to build a reputation for their engine.
Once security experts build a reputation, they may want to engage in additional Communities.
As more communities come online, they'll appear in PolySwarm Portal: <button disabled>Browse Communities → (coming soon!)</button>

For now, let's proceed under the assumption that we only want to join the Epoch community.

<div class="m-flag">
  <p>
    <strong>Info:</strong>
      <code>polyswarm-client</code> based engines currently only support communicating with a single Community at a given time.
      Support for multiple Communities will be included in a future release.
      In the meantime, please run an instance of your engine (& <code>balancemanager</code>) per Community.
  </p>
</div>


## Relaying NCT to Your Community(ies)

Recall that each community has a distinct [sidechain](/#chains-home-vs-side) where PolySwarm transactions occur.
In order to participate, you'll need to maintain a balance of NCT (ETH not required) on the Community's sidechain.

We've made this easy: you can use `polyswarm-client`'s `balancemanager` utility.
You'll need to run both your engine and a `balancemanager` to maintain a balance of NCT on the Community sidechain.
Windows users will recall running `balancemanager` from the [Windows engine Integration Testing instructions](/testing-windows/#integration-testing).
Linux users had `balancemanager` handled for them by Docker transparently.

`balancemanager` can be run in three modes:
1. `deposit`: deposit the configured amount of NCT onto the Community and exit
2. `withdraw`: withdraw the configured amount of NCT from the Community and exit
3. `maintain`: continually ensure a configurable balance of NCT in the Community

Most users will want to simply `maintain` a balance - we'll dive into using this functionality below.
Advanced users may want to manually `deposit` and `withdraw` funds.


## API Keys

In order to protect themselves from griefing / Denial of Service (DoS), Communities may elect to issue their members API keys and apply rate limits to these keys.
Epoch is one such community, but API keys are available to everyone.

To obtain your Epoch API key, sign up on [PolySwarm Portal](https://polyswarm.network/), click your name in the top right corner and select Account.
Your Epoch API key will be displayed in your Profile.


### API Key Usage in `polyswarm-client`-Based Engines

Using your API key in `polyswarm-client` based engines is as simple as populating the `--api-key` command line argument.
We discuss this below.


### API Key Usage in a Custom Engine

If you're building a custom engine, please ensure that all API requests to Community-hosted `polyswarmd` instances contain your API key in the headers:

```
Authorization: [API KEY]
```

For more details on the `polyswarmd API`, please refer to our API specification [polyswarmd API Documentation](/polyswarmd-api/).


## Putting it all Together

To recap, we've:
1. generated a wallet keyfile for *production* use
2. funded this wallet with both ETH and NCT
3. decided on our Community(ies)
4. retrieved our API key for our Community(ies)

Now we're ready to plug our engine (& `balancemanager`) into the PolySwarm marketplace!

If you've built your engine on `polyswarm-client`, (e.g. using our cookiecutter `engine-template` in the tutorials here), you simply need to specify some command line arguments (can also be specified as environment variables):

```bash
# microengine \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <path to your self-generated and funded keyfile> \
  --password <encryption password for your keyfile> \
  --api-key <your Epoch API key>
  --backend <the name ("slug") of your scan engine (e.g. acme_myeicarengine)>
```

For the full list of command line arguments, use the `--help` CLI flag:
```bash
# microengine --help
Usage: microengine [OPTIONS]

  Entrypoint for the microengine driver

  Args:     log (str): Logging level     polyswarmd_addr(str): Address of
  polyswarmd     keyfile (str): Path to private key file to use to sign
  transactions     password (str): Password to decrypt the encrypted private
  key     backend (str): Backend implementation to use     api_key(str): API
  key to use with polyswarmd     testing (int): Mode to process N bounties
  then exit (optional)     insecure_transport (bool): Connect to polyswarmd
  without TLS     log_format (str): Format to output logs in. `text` or
  `json`

Options:
  --log TEXT              Logging level
  --polyswarmd-addr TEXT  Address (host:port) of polyswarmd instance
  --keyfile PATH          Keystore file containing the private key to use with
                          this microengine
  --password TEXT         Password to decrypt the keyfile with
  --api-key TEXT          API key to use with polyswarmd
  --backend TEXT          Backend to use
  --testing INTEGER       Activate testing mode for integration testing,
                          respond to N bounties and N offers then exit
  --insecure-transport    Connect to polyswarmd via http:// and ws://,
                          mutually exclusive with --api-key
  --chains TEXT           Chain(s) to operate on
  --log-format TEXT       Log format. Can be `json` or `text` (default)
  --help                  Show this message and exit.
```

In addition to your engine, you'll need to run a `balancemanager`.

`balancemanager` will also require access to your `keyfile`:
```bash
# balancemanager maintain \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <path to your self-generated and funded keyfile> \
  --password <encryption password for your keyfile> \
  --api-key <your Epoch API key> \
  --maximum <(optional) the maximum allowable balance in the Community before a withdraw is made>
  <MINIMUM: deposit into the Community when balance drops below this value>
  <REFILLE_AMOUNT: the amount of NCT to transfer when Community balance falls below MINIMUM>
```

For the full list of command line arguments, use the `--help` CLI flag:
```bash
# balancemanager maintain --help
INFO:root:2018-12-28 03:04:11,352 Logging in text format.
Usage: balancemanager maintain [OPTIONS] MINIMUM REFILL_AMOUNT

  Entrypoint to withdraw NCT from a sidechain into the homechain

  Args:     minimum (float): Value of NCT on sidechain where you want to
  transfer more NCT     refill-amount (float): Value of NCT to transfer
  anytime the balance falls below the minimum

Options:
  --polyswarmd-addr TEXT   Address (host:port) of polyswarmd instance
  --keyfile PATH           Keystore file containing the private key to use
                           with this microengine
  --password TEXT          Password to decrypt the keyfile with
  --api-key TEXT           API key to use with polyswarmd
  --testing INTEGER        Activate testing mode for integration testing,
                           trigger N balances to the sidechain then exit
  --insecure-transport     Connect to polyswarmd via http:// and ws://,
                           mutually exclusive with --api-key
  --maximum FLOAT          Maximum allowable balance before triggering a
                           withdraw from the sidechain
  --withdraw-target FLOAT  The goal balance of the sidechain after the
                           withdrawal
  --confirmations INTEGER  Number of block confirmations relay requires before
                           approving the transfer
  --help                   Show this message and exit.
```

## Congratulations

With your engine & `balancemanager` running, you are now plugged into your Community(ies) of choice!
