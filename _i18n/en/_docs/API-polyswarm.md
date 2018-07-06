## Bounties API

### Post Bounty

Called by end users and ambassadors to post a bounty.

**URL** : `/bounties?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

amount - the amount of NCT to post as a reward
uri - uri of the artifacts comprising this bounty
duration - duration of this bounty in blocks

```json
{
  "amount": "[string minimum length 1 / max length 100]",
  "uri": "[string minimum length 1 / max length 100]",
  "duration": [integer minimum 1]
}
```

**Data example** All fields must be sent.

```json
{
  "amount": "30000",
  "uri": "QmYNmQKp6SuaVrpgWRsPTgCQCnpxUYGq76YEKBXuj2N4H6",
  "duration": 10
}
```

### Vote on Bounty

Called by arbiter after bounty expiration to settle with their ground truth determination and pay out assertion rewards.

**URL** : `/bounties/<uuid:guid>/vote?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

verdicts - array of verdicts representing ground truth for the bounty's artifacts

valid_bloom - if this is a bloom vote


```json
{
  "verdicts": "[array with a max of 256 boolean items]",
  "valid_bloom": "[boolean]"
}
```

**Data example** All fields must be sent.

```json
{
  "verdicts": "[true, false, true, true, false]",
  "valid_bloom": "true"
}
```

### Settle Bounty

Callable after the voting window has closed to handle reward disbursal.

**URL** : `/bounties/<uuid:guid>/settle?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**No data needed for this request**

### Assert on bounty

Called by security experts to post an assertion on a bounty

**URL** : `/bounties/<uuid:guid>/assertions?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

bid - the amount of NCT to stake

mask - the artifacts to assert on from the set in the bounty

verdicts - array of verdicts on bounty artifacts

```json
{
  "bid": "[string minimum length 1 with max length 100]",
  "mask": "[array with a max of 256 boolean items]",
  "verdicts": "[array with a max of 256 boolean items]"
}
```

**Data example** All fields must be sent.

```json
{
  "bid": "200000",
  "mask": "[true, true, true]",
  "verdicts": "[false, true, false]"
}
```

#### Success Response

**Condition** : If everything is OK the generated nonce will be created later used for reveal

**Code** : `200`

**Content example**

```json
{
  "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
  "author": "0x000000000000000000000000000000000",
  "index": "1",
  "bid": "200000",
  "mask": "0",
  "commitment": "0",
  "nonce": "103"
}
```

### Reveal bounty assersions

Called by arbiter after bounty expiration to settle with their ground truth determination and pay out assertion rewards.

**URL** : `/bounties/<uuid:guid>/vote?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

nonce - the nonce used to generate the commitment hash (returned from asserting on a bounty)

verdicts - the verdicts making up this assertion

metadata - to include in the assertion (can be empty string)

```json
{
  "nonce": "[string minimum length 1 with max length 100]",
  "verdicts": "[array with a max of 256 boolean items]",
  "metadata": "[string minimum length 1 with max length 1024]"
}
```

**Data example** All fields must be sent.

```json
{
  "nonce": "123",
  "verdicts": "[true, false, true]",
  "metadata": "Dropper"
}
```

### Get all the bounties

**URL** : `/bounties?chain=[chain_name]`

**Method** : `GET`

### Get all active bounties

**URL** : `/active?chain=[chain_name]`

**Method** : `GET`

### Get all pending bounties

**URL** : `/pending?chain=[chain_name]`

**Method** : `GET`

### Get a bounty's info

**URL** : `/<uuid:guid>?chain=[chain_name]`

**Method** : `GET`

### Get assertions for a bounty

**URL** : `/<uuid:guid>/assertions?chain=[chain_name]`

**Method** : `GET`

### Get an assertion for a bounty

**URL** : `/<uuid:guid>/assertions/<int:id_>?chain=[chain_name]`

**Method** : `GET`

## Artifacts API

### Post Artifact

Post an artifact to IPFS

**URL** : `/artifacts`

**Method** : `POST`

**Data constraints**

Provide:

List of files to upload. You can upload a max of 256

### Get file links associated with hash 

**URL** : `/<ipfshash>`

**Method** : `GET`

### Get a link associated with hash and link index 

**URL** : `/<ipfshash>/<int:id_>`

**Method** : `GET`

### Get stats on artifact link

**URL** : `/<ipfshash>/<int:id_>/stat`

**Method** : `GET`

## Offers API
*Stateless offer api coming soon*

### Create an offer channel

Called by ambassador to initialize an offer contract It deploys a new offer multi sig

**URL** : `/offers?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

ambassador - address of ambassador using channel
expert - address of expert using channel
settlementPeriodLength - how long the parties have to dispute the settlement offer channel
websocketUri - uri of socket to send messages to ambassador 

```json
{
  "ambassador": "[string minimum length 42]",
  "expert": "[string minimum length 42]",
  "settlementPeriodLength": "[integer minimum 60]",
  "websocketUri": [string with minimum length 1 max 32]
}
```

**Data example** All fields must be sent.

```json
{
  "amount": "0x34E583cf9C1789c3141538EeC77D9F0B8F7E89f2",
  "uri": "0xf0243D9b2E332D7072dD4B143a881B3f135F380c",
  "duration": 80,
  "websocketUri": "ws://localhost:9999/echo"
}
```

### Open channel

Called by ambassador to open channel with expert

**URL** : `/open/<uuid:guid>?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

state - inital offer state
v - the recovery id from signature of state string
r - output of ECDSA signature of state string
s - output of ECDSA signature of state string

```json
{
  "state": "[string minimum length 32]",
  "v": "[integer minimum 0]",
  "r": "[string minimum length 64]",
  "s": "[string minimum length 64]"
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc",
  "v": "27",
  "r": "0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9",
  "s": "0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66"
}
```

### Join channel

Called by expert to join ambassador channel

**URL** : `/open?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state from ambassador
v - the recovery id from signature of state string
r - output of ECDSA signature of state string
s - output of ECDSA signature of state string

```json
{
  "state": "[string minimum length 32]",
  "v": "[integer minimum 0]",
  "r": "[string minimum length 64]",
  "s": "[string minimum length 64]",
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "27",
  "r": "0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9",
  "s": "0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66"
}
```

### Cancel channel

Called by ambassador to cancel if the contract hasn't been joined yet

**URL** : `/cancel?account=[eth_account_here]`

**Method** : `POST`

### Close channel

Called by any party with a both signatures on a state with a closed state flag set to 1

**URL** : `/close?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state with closed flag
v - array of the recovery ids from signature of state string for both parties
r - array of outputs of ECDSA signature of state string for both parties
s - rray of outputs of ECDSA signature of state string for both parties

```json
{
  "state": "[string minimum length 32]",
  "v": "[array of 2 integers]",
  "r": "[array of 2 strings with min length 64]",
  "s": "[array of 2 strings with min length 64]",
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

### Close challenged channel with timeout

Called by any party with a both signatures on a state that is the final challenge state

**URL** : `/closeChallenged?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state with closed flag
v - array of the recovery ids from signature of state string for both parties
r - array of outputs of ECDSA signature of state string for both parties
s - rray of outputs of ECDSA signature of state string for both parties

```json
{
  "state": "[string minimum length 32]",
  "v": "[array of 2 integers]",
  "r": "[array of 2 strings with min length 64]",
  "s": "[array of 2 strings with min length 64]",
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

### Settle channel

Called by ambassador or expert to start initalize a disputed settlement using an agreed upon state. It starts a timeout for a reply using `settlementPeriodLength`

**URL** : `/settle?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state both parties signed
v - array of the recovery ids from signature of state string for both parties
r - array of outputs of ECDSA signature of state string for both parties
s - rray of outputs of ECDSA signature of state string for both parties

```json
{
  "state": "[string minimum length 32]",
  "v": "[array of 2 integers]",
  "r": "[array of 2 strings with min length 64]",
  "s": "[array of 2 strings with min length 64]",
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

### Challenge settle channel state

Called by ambassador or expert to challenge a disputed state. The new state is accepted if it is signed by both parties and has a higher sequence number

**URL** : `/challenge?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state both parties signed
v - array of the recovery ids from signature of state string for both parties
r - array of outputs of ECDSA signature of state string for both parties
s - rray of outputs of ECDSA signature of state string for both parties

```json
{
  "state": "[string minimum length 32]",
  "v": "[array of 2 integers]",
  "r": "[array of 2 strings with min length 64]",
  "s": "[array of 2 strings with min length 64]",
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

### Send message to ambassador socket

Called to pass state to a participant.

**URL** : `/challenge?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide:
fromSocketUri - uri sending (used to return messages)
state - offer state both parties signed

Optional:
toSocketUri - to send to a different person (defaults to the ambassador)
v - recovery ids from signature of state string for both parties
r - ECDSA signature of state string
s - ECDSA signature of state string

```json
{
  "fromSocketUri": "[string]",
  "state": "[string minimum length 32]",
  "v": "[array of 2 integers]",
  "r": "[array of 2 strings with min length 64]",
  "s": "[array of 2 strings with min length 64]"
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "fromSocketUri": "ws://localhost:9999/echo"
}
```

### Get offer channel info

**URL** : `/<uuid:guid>`

**Method** : `GET`

### Get offer channel settlement period

**URL** : `/<uuid:guid>/settlementPeriod`

**Method** : `GET`

### Get ambassador websocket uri

**URL** : `/<uuid:guid>/websocket`

**Method** : `GET`

### Get pending offers

**URL** : `/pending`

**Method** : `GET`

### Get opened offers

**URL** : `/opened`

**Method** : `GET`

### Get closed offers

**URL** : `/closed`

**Method** : `GET`

### Get my offers

**URL** : `/myoffers?account=[eth_account_here]`

**Method** : `GET`

## TX Signing

All transactions are sent over a websocket where they can be individually signed. 

To add transaction signing to your polyswarmd dependent project you need to to
write/use something that follows the steps below..

0) Listen to the websocket at `ws://localhost:31337/transactions`

1) Upon receiving JSON formatted message, parse the id, chainId, and transaction data

2) Sign the Transaction data with your private key

3) Return a JSON object containing the id, chainID, and signed data as data.

There is a javascript example embedded below, though you can use any 
other language.

```javascript
const EthereumTx = require('ethereumjs-tx');
const keythereum = require('keythereum');
const WebSocket = require('isomorphic-ws');

const ws = new WebSocket('ws://localhost:31337/transactions');

const DATADIR = '/home/user/.ethereum/priv_testnet';
const ADDRESS = '34e583cf9c1789c3141538eec77d9f0b8f7e89f2';
const PASSWORD = 'password';

const enc_key = keythereum.importFromFile(ADDRESS, DATADIR);
const key = keythereum.recover(PASSWORD, enc_key);

ws.onmessage = msg => {
  console.log(msg.data);
  const {id, data} = JSON.parse(msg.data);
  const {chainId} = data;
  console.log(data);
  const tx = new EthereumTx(data);
  tx.sign(key);

  ws.send(JSON.stringify({'id': id, 'chainId': chainId, 'data': tx.serialize().toString('hex')}));
};
```

## State

### Creating State

The state byte string contains details the ambassabor and expert sign off on. Each element below in a padded hex concated together.

```
/// @dev Required State
// [0-31] is close flag
// [32-63] nonce
// [64-95] ambassador address
// [96-127] expert address
// [128-159] msig address
// [160-191] balance in nectar for ambassador
// [192-223] balance in nectar for expert
// [224-255] token address
// [256-287] A globally-unique identifier for the Listing.
// [288-319] The Offer Amount.

/// @dev Optional State
// [320-351] Cryptographic hash of the Artifact.
// [352-383] The IPFS URI of the Artifact.
// [384-415] Engagement Deadline
// [416-447] Assertion Deadline
// [448-479] current commitment
// [480-511] bitmap of verdicts
// [512-543] meta data
```

Example state

```javascript
let state = []
state.push(0) // is close
state.push(0) // nonce
state.push(ambassador) // ambassador address
state.push(expert) // expert address
state.push(msig.address) // msig address
state.push(20) // balance in nectar ambassador
state.push(0) // balance in nectar expert
state.push(nectaraddress) // token address
```

#### Gets tranformed to:

```
0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc
```

### Signing State

The offers api requires signed states here's an example of signing to create the v, r, and s signature peices in Javascript.

```javascript
const EthereumTx = require('ethereumjs-tx');
const keythereum = require('keythereum');
const WebSocket = require('isomorphic-ws');

const ws = new WebSocket('ws://localhost:31337/transactions');

const DATADIR = '/home/user/.ethereum/priv_testnet';
const ADDRESS = '34e583cf9c1789c3141538eec77d9f0b8f7e89f2';
const PASSWORD = 'password';

const enc_key = keythereum.importFromFile(ADDRESS, DATADIR);
const key = keythereum.recover(PASSWORD, enc_key);

const buff_key = etherutils.toBuffer(key);
const state = web3.toHex("0x00000000000000000000000000000000000000000000000000000000....");
let msg = '0x' + etherutils.keccak(etherutils.toBuffer(state)).toString('hex');
msg = '0x' + etherutils.hashPersonalMessage(etherutils.toBuffer(msg)).toString('hex');
const sig = etherutils.ecsign(etherutils.toBuffer(msg), buff_key);
let r = '0x' + sig.r.toString('hex')
let s = '0x' + sig.s.toString('hex')
let v = sig.v
```

### State Messages

Ambassadors open a websocket with the url defined in the contract. Locally - messages are sent on `ws://localhost:31337/messages/<uuid:guid>`

**Data constraints**

Provide:
type - type of message (payment, request, assertion)
state - offer state

Optional:
toSocketUri - to send to a different person (defaults to the ambassador)
v - recovery ids from signature of state string for both parties
r - ECDSA signature of state string
s - ECDSA signature of state string

```json
{
  "fromSocketUri": "[string]",
  "state": "[string minimum length 32]",
  "v": "[array of 2 integers]",
  "r": "[array of 2 strings with min length 64]",
  "s": "[array of 2 strings with min length 64]",
}
```

**Data example** All fields must be sent.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "fromSocketUri": "payment"
}
```

## Events

A websocket for contract events

Listen to the websocket at `ws://localhost:31337/events/<chain>`

**Event Types**

***Block***

Sent when a new block is mined, reports the latest block number

**Content example**

```json
{
  "event": "block",
  "data": {
    "number": 1000
  }
}
```

***Bounty***

Sent when a new bounty is posted

**Content example**

```json
{
  "event": "bounty",
  "data": {
    "guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "author": "0x000000000000000000000000000000000",
    "amount": "1000",
    "uri": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
    "expiration": "1000"
  }
}
```

***Assertion***

Sent when a new assertion to a bounty is posted

**Content example**

```json
{
  "event": "assertion",
  "data": {
    "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "author": "0x000000000000000000000000000000000",
    "index": 0,
    "bid": "1000",
    "mask": [true],
    "commitment": "1000"
  }
}
```

***Verdict***

Sent when an arbiter votes on a bounty

**Content example**

```json
{
  "event": "verdict",
  "data": {
    "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "verdicts": [true]
  }
}
```
