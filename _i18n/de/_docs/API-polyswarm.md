## Bounties API

### Post Bounty

Called by end users and ambassadors to post a bounty.

**URL** : `/bounties?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

base_nonce - (optional) a number for transaction nonce

amount - the amount of NCT to post as a reward

uri - uri of the artifacts comprising this bounty

duration - duration of this bounty in blocks

```json
{
  "amount": "[string minimum length 1 / max length 100]",
  "uri": "[string minimum length 1 / max length 100]",
  "duration": "[integer minimum 1]"
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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    },
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Vote on Bounty

Called by arbiter after bounty expiration to settle with their ground truth determination and pay out assertion rewards.

**URL** : `/bounties/<uuid:guid>/vote?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

base_nonce - (optional) a number for transaction nonce

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Settle Bounty

Callable after the voting window has closed to handle reward disbursal.

**URL** : `/bounties/<uuid:guid>/settle?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**No data needed for this request**

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Assert on bounty

Called by security experts to post an assertion on a bounty

**URL** : `/bounties/<uuid:guid>/assertions?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

base_nonce - (optional) a number for transaction nonce

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

**Condition** : If everything is OK the generated nonce will be created later used for reveal and you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{ "nonce": 432984098,
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Reveal bounty assersions

Called by arbiter after bounty expiration to settle with their ground truth determination and pay out assertion rewards.

**URL** : `/bounties/<uuid:guid>/vote?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

base_nonce - (optional) a number for transaction nonce

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
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

## Staking API

### Post Deposit Stake

Called by arbiters to deposit stake Nectar.

**URL** : `/staking/deposit?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

amount - the amount of NCT to add to current stake

```json
{
  "amount": "[string minimum length 1 / max length 100]"
}
```

**Data example** All fields must be sent.

```json
{
  "amount": "30000000000"
}
```

### Post Withdrawal Stake

Called by arbiters to withdraw available staked Nectar.

**URL** : `/staking/withdraw?account=[eth_account_here]&chain=[chain_name]`

**Method** : `POST`

**Data constraints**

Provide:

amount - the amount of NCT to withdraw from current stake

```json
{
  "amount": "[string minimum length 1 / max length 100]"
}
```

**Data example** All fields must be sent.

```json
{
  "amount": "30000000000"
}
```

### Get total stake balance

**URL** : `/balances/<address>/staking/total`

**Method** : `GET`

### Get withdrawable stake balance

**URL** : `/balances/<address>/staking/withdrawable`

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

Called by an ambassador to deploy a new multi signature offer

**URL** : `/offers?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce ambassador - address of ambassador using channel expert - address of expert using channel settlementPeriodLength - how long the parties have to dispute the settlement offer channel websocketUri - uri of socket to send messages to ambassador

```json
{
  "ambassador": "[string minimum length 42]",
  "expert": "[string minimum length 42]",
  "settlementPeriodLength": "[integer minimum 60]",
  "websocketUri": "[string with minimum length 1 max 32]"
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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Open channel

Called by ambassador to open channel with expert

**URL** : `offers/open/<uuid:guid>?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce state - inital offer state v - the recovery id from signature of state string r - output of ECDSA signature of state string s - output of ECDSA signature of state string

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Join channel

Called by expert to join ambassador channel

**URL** : `offers/open?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce state - offer state from ambassador v - the recovery id from signature of state string r - output of ECDSA signature of state string s - output of ECDSA signature of state string

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Cancel channel

Called by ambassador to cancel if the contract hasn't been joined yet

**URL** : `offers/cancel?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Close channel

Called by any party with a both signatures on a state with a closed state flag set to 1

**URL** : `/close?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce state - offer state with closed flag v - array of the recovery ids from signature of state string for both parties r - array of outputs of ECDSA signature of state string for both parties s - rray of outputs of ECDSA signature of state string for both parties

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Close challenged channel with timeout

Called by any party with a both signatures on a state that is the final challenge state

**URL** : `/offers/closeChallenged?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce state - offer state with closed flag v - array of the recovery ids from signature of state string for both parties r - array of outputs of ECDSA signature of state string for both parties s - rray of outputs of ECDSA signature of state string for both parties

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Settle channel

Called by ambassador or expert to start initalize a disputed settlement using an agreed upon state. It starts a timeout for a reply using `settlementPeriodLength`

**URL** : `/offers/settle?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce state - offer state both parties signed v - array of the recovery ids from signature of state string for both parties r - array of outputs of ECDSA signature of state string for both parties s - rray of outputs of ECDSA signature of state string for both parties

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Challenge settle channel state

Called by ambassador or expert to challenge a disputed state. The new state is accepted if it is signed by both parties and has a higher sequence number

**URL** : `/offers/challenge?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: base_nonce - (optional) a number for transaction nonce state - offer state both parties signed v - array of the recovery ids from signature of state string for both parties r - array of outputs of ECDSA signature of state string for both parties s - rray of outputs of ECDSA signature of state string for both parties

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Send message to ambassador socket

Called to pass state to a participant.

**URL** : `/offers/challenge?account=[eth_account_here]`

**Method** : `POST`

**Data constraints**

Provide: fromSocketUri - uri sending (used to return messages) state - offer state both parties signed

Optional: toSocketUri - to send to a different person (defaults to the ambassador) v - recovery ids from signature of state string for both parties r - ECDSA signature of state string s - ECDSA signature of state string

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

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
{
  "transactions": [
    { "chainId": 1337,
      "data": "0x095ea7b30000000000000000000000007d012af57b89fceded483f6716d2f0862b3af396000000000000000000000000000000000000000000000000098a7d9b8314c000",
      "gas": 5000000,
      "gasPrice": 100000000000,
      "nonce": 748,
      "to": "0xEfEaF137150FC048B1d828B764e44f7ed628Bd66",
      "value": 0
    }
  ]
}
```

### Get offer channel info

**URL** : `/offers/<uuid:guid>`

**Method** : `GET`

### Get offer channel settlement period

**URL** : `/offers/<uuid:guid>/settlementPeriod`

**Method** : `GET`

### Get ambassador websocket uri

**URL** : `/offers/<uuid:guid>/websocket`

**Method** : `GET`

### Get pending offers

**URL** : `/offers/pending`

**Method** : `GET`

### Get opened offers

**URL** : `/offers/opened`

**Method** : `GET`

### Get closed offers

**URL** : `/offers/closed`

**Method** : `GET`

### Get my offers

**URL** : `/offers/myoffers?account=[eth_account_here]`

**Method** : `GET`

## Transaction Signing

**URL** : `/transactions?chain=[chain_here]`

**Method** : `POST`

All signied transactions are POSTed here to start the transaction on the chain of choice.

To add transaction signing to your polyswarmd dependent project you need to to write/use something that follows the steps below.

0) Upon receiving transaction data from a transaction dependent endpoint

1) Sign the Transaction data with your private key

2) POST the signed transaction to `/transactions`

There is a python example embedded below, though you can use any other language.

```python
import json
import requests
from web3.auto import w3 as web3

POLYSWARMD_ADDR = 'localhost:31337'
KEYFILE = 'keyfile'
PASSWORD = 'password'
ADDRESS, PRIV_KEY = unlock_key(KEYFILE, PASSWORD)

def unlock_key(keyfile, password):
    """Open an encrypted keystore file and decrypt it"""
    with open(keyfile, 'r') as f:
        priv_key = web3.eth.account.decrypt(f.read(), password)

    address = web3.eth.account.privateKeyToAccount(priv_key).address
    return (address, priv_key)

def post_transactions(transactions):
    """Post a set of (signed) transactions to Ethereum via polyswarmd, parsing the emitted events"""
    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, PRIV_KEY)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = 'http://{0}/transactions'.format(POLYSWARMD_ADDR)

    response = requests.post(uri, data=json.dumps({'transactions': signed})):
    return response.json()
```

## State

### Creating State

The state byte string contains details the ambassabor and expert sign off on.

**URL** : `/offers/state`

**Method** : `POST`

**Data constraints**

Provide:

    close_flag - 1 or 0 for is this state is closeable
    nonce - the sequnce of the state
    ambassador - ambassador address
    expert - expert address
    msig_address - multi signature address
    ambassador_balance - balance in nectar for ambassador
    nectar_balance - balance in nectar for expert
    guid - a globally-unique identifier for the offer listing
    offer_amount - the offer amount paid for assertion
    

Optional:

    artifact_hash - cryptographic hash of the artifact
    ipfs_hash - the IPFS URI of the artifact
    engagement_deadline - engagement Deadline
    assertion_deadline - assertion Deadline
    current_commitment - current commitment
    verdicts - bitmap of verdicts
    meta_data - meta data about current offer
    

Example POST data:

    {
      "close_flag": 0,
      "nonce": 0,
      "ambassador": "0x000000000000000000000000000000000",
      "ambassador_balance": 100,
      "expert_balance": 0,
      "expert":"0x000000000000000000000000000000000",
      "msig_address": "0x05027017bd3284c3f794474cc9f047e247bea04a"
    }
    

#### Gets tranformed to the below bytes string in the response:

    0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc
    

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

Provide: type - type of message (payment, request, assertion) state - offer state

Optional: toSocketUri - to send to a different person (defaults to the ambassador) v - recovery ids from signature of state string for both parties r - ECDSA signature of state string s - ECDSA signature of state string

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