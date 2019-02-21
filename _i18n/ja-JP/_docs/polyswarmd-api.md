## 報奨金 API

### 報奨金パラメーター

**URL** : `/bounties/parameters?chain=[chain_name]`

**メソッド** : `GET`

### 報奨金の提示

エンド・ユーザーおよびアンバサダーが報奨金を提示するために呼び出します。

**URL** :`/bounties?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**メソッド** : `POST`

**データ制約**

指定:

amount - 報酬として提示する金額 (NCT)

uri - 当該報奨金の対象アーティファクトの URI

duration - 当該報奨金の期間 (ブロック単位)

```json
{
  "amount": "[文字列、最小長 1 / 最大長 100]",
  "uri": "[文字列、最小長 1 / 最大長 100]",
  "duration": "[整数、最小 1]"
}
```

**データの例** すべてのフィールドを送信する必要があります。

```json
{
  "amount": "30000",
  "uri": "QmYNmQKp6SuaVrpgWRsPTgCQCnpxUYGq76YEKBXuj2N4H6",
  "duration": 10
}
```

#### 成功応答

**条件** : 正常に処理された場合、生の未署名のトランザクションの配列が返されます。これに署名して `/transactions` エンドポイントを介して送信する必要があります。

**コード** : `200`

**コンテンツの例**

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

### 報奨金に対する投票

報奨金の有効期限後に、評価者が、各アーティファクトが悪意のあるものなのか無害なのかを指定して呼び出します。これは、最終的な確認・評価結果の決定に利用されます。

**URL** :`/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

votes - 報奨金のアーティファクトの確認・評価結果を表す投票の配列

valid\_bloom - ブルーム投票の場合

```json
{
  "votes": "[最大 256 個の boolean 項目から成る配列]",
  "valid\_bloom": "[boolean]"
}
```

**Data example** All fields must be sent.

```json
{
  "votes": "[true, false, true, true, false]",
  "valid\_bloom": "true"
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

### 報奨金の決済

投票期間が終了した後に、報酬の支払いを処理するために呼び出すことができます。

**URL** : `/bounties/<uuid:guid>/settle?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**この要求では、データは不要です。**

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

### 報奨金に対するアサーション提示

セキュリティー専門家が報奨金に対するアサーションを送信するために呼び出します。

**URL** : `/bounties/<uuid:guid>/assertions?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

bid - 投資金額 (NCT)

mask - 報奨金に含まれている一連のアーティファクトでアサーションを提示するアーティファクト

verdicts - 報奨金の対象アーティファクトの判定の配列

```json
{
  "bid": "[文字列、最小長 1、最大長 100]",
  "mask": "[最大で 256 個の boolean 項目が含まれた配列]",
  "verdicts": "[最大で 256 個の boolean 項目が含まれた配列]"
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

**条件** : 正常に処理された場合、後から評価で使用するためのノンスが生成され、また生の未署名のトランザクションの配列が返されます。このトランザクションに署名して `/transactions` エンドポイントを介して送信する必要があります。

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

### 報奨金アサーションの評価

報奨金の有効期限後に評価者が確認・評価結果を確定し、アサーションの報酬を支払うために呼び出します。

**URL** : `/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

nonce - コミットメント・ハッシュの生成に使用するノンス (報奨金に対するアサート提示で返されたもの)

verdicts - 当該アサーションの判定

metadata - アサーションに含めるもの (空文字列可)

```json
{
  "nonce": "[文字列、最小長 1、最大長 100]",
  "verdicts": "[最大で 256 個の boolean 項目が含まれた配列]",
  "metadata": "[文字列、最小長 1、最大長 1024]"
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

### 報奨金情報の取得

**URL** : `/<uuid:guid>?chain=[chain_name]`

**Method** : `GET`

### 報奨金の複数のアサーション取得

**URL** : `/<uuid:guid>/assertions?chain=[chain_name]`

**Method** : `GET`

### 報奨金の単一のアサーション取得

**URL** : `/<uuid:guid>/assertions/<int:id_>?chain=[chain_name]`

**Method** : `GET`

### 報奨金のブルーム取得

**URL** : `/<uuid:guid>/bloom?chain=[chain_name]`

**Method** : `GET`

### 報奨金の複数の投票取得

**URL** : `/<uuid:guid>/votes?chain=[chain_name]`

**Method** : `GET`

### 報奨金の単一の投票取得

**URL** : `/<uuid:guid>/votes/<int:id_>?chain=[chain_name]`

**Method** : `GET`

## 投資 API

### 投資パラメーター

**URL** : `/staking/parameters?chain=[chain_name]`

**Method** : `GET`

### 投資金の預金

評価者が Nectar を預金するために呼び出します。

**URL** : `/staking/deposit?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

amount - 現在の投資金に追加する金額 (NCT)

```json
{
  "amount": "[文字列、最小長 1 / 最大長 100]"
}
```

**Data example** All fields must be sent.

```json
{
  "amount": "30000000000"
}
```

### 投資金の引き出し

評価者が投資された利用可能な Nectar を引き出すために呼び出します。

**URL** : `/staking/withdraw?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

amount - 現在の投資金から引き出す金額 (NCT)

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

### 合計投資金残高の取得

**URL** : `/balances/<address>/staking/total`

**Method** : `GET`

### 引き出し可能な投資金残高の取得

**URL** : `/balances/<address>/staking/withdrawable`

**Method** : `GET`

## アーティファクト API

### アーティファクトの送信

アーティファクトを IPFS に送信します。

**URL** : `/artifacts`

**Method** : `POST`

**Data constraints**

Provide:

アップロードするファイルのリスト。 最大 256 個までアップロード可能

### ハッシュに関連付けられているファイル・リンクの取得

**URL** : `/<ipfshash>`

**Method** : `GET`

### ハッシュとリンク・インデックスに関連付けられているリンクの取得

**URL** : `/<ipfshash>/<int:id_>`

**Method** : `GET`

### アーティファクト・リンクの統計の取得

**URL** : `/<ipfshash>/<int:id_>/stat`

**Method** : `GET`

## オファー API

*ステートレスのオファー API を近日公開予定です。*

### オファー・チャネルの作成

アンバサダーが新しいマルチ署名オファーをデプロイするために使用します。

**URL** : `/offers?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

ambassador - チャネルを使用するアンバサダーのアドレス

expert - チャネルを使用する専門家のアドレス

settlementPeriodLength - 当事者がオファー・チャネルの決済を得ようと争う期間

websocketUri - メッセージをアンバサダーに送信するためのソケットの URI

```json
{
  "ambassador": "[文字列、最小長 42]",
  "expert": "[文字列、最小長 42]",
  "settlementPeriodLength": "[整数、最小 60]",
  "websocketUri": "[文字列、最小長 1、最大長 32]"
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

### チャネルのオープン

アンバサダーが専門家とのチャネルをオープンするために呼び出します。

**URL** : `offers/open/<uuid:guid>?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - 初期オファー状態

v - 状態文字列の署名のリカバリー ID

r - 状態文字列の ECDSA 署名の出力

s - 状態文字列の ECDSA 署名の出力

```json
{
  "state": "[文字列、最小長 32]",
  "v": "[整数、最小 0]",
  "r": "[文字列、最小長 64]",
  "s": "[文字列、最小長 64]"
}
```

**Data example** All fields must be sent.

状態の[説明](#state)をご覧ください。

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

### チャネルへの参加

専門家がアンバサダーのチャネルに参加するために呼び出します。

**URL** : `offers/open?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - アンバサダーからのオファー状態

v - the recovery id from signature of state string

r - output of ECDSA signature of state string

s - output of ECDSA signature of state string

```json
{
  "state": "[文字列、最小長 32]",
  "v": "[整数、最小 0]",
  "r": "[文字列、最小長 64]",
  "s": "[文字列、最小長 64]",
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

### チャネルのキャンセル

コントラクトにまだ参加していない場合にアンバサダーがキャンセルするために呼び出します。

**URL** : `offers/cancel?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

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

### チャネルのクローズ

任意の当事者が、クローズ状態フラグが 1 に設定された状態で両者の署名を指定して呼び出します。

**URL** : `/close?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - クローズ・フラグが設定されたオファー状態

v - 両者の状態文字列の署名からのリカバリー ID の配列

r - 両者の状態文字列の ECDSA 署名の出力の配列

s - array of outputs of ECDSA signature of state string for both parties

```json
{
  "state": "[文字列、最小長 32]",
  "v": "[2 個の整数の配列]",
  "r": "[最小長が 64 の 2 個の文字列の配列]",
  "s": "[最小長が 64 の 2 個の文字列の配列]",
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

### タイムアウトがあるチャレンジされたチャネルのクローズ

任意の当事者が、最終チャレンジ状態である状態に両者の署名を付けて呼び出します。

**URL** : `/offers/closeChallenged?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state with closed flag

v - array of the recovery ids from signature of state string for both parties

r - array of outputs of ECDSA signature of state string for both parties

s - array of outputs of ECDSA signature of state string for both parties

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

### チャネルの決済

アンバサダーまたは専門家が、合意した状態を使用して、争点の決済の初期化を開始するために呼び出します。 `settlementPeriodLength` を使用して応答のタイムアウトが開始されます。

**URL** : `/offers/settle?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - 両者が署名したオファー状態

v - array of the recovery ids from signature of state string for both parties

r - array of outputs of ECDSA signature of state string for both parties

s - 両者の状態文字列の ECDSA 署名の出力の配列

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

### 決済チャネル状態へのチャレンジ

アンバサダーまたは専門家が、争点の状態にチャレンジするために呼び出します。 両者が署名し、シーケンス番号が大きい場合、新しい状態が受け入れられます。

**URL** : `/offers/challenge?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - offer state both parties signed

v - array of the recovery ids from signature of state string for both parties

r - array of outputs of ECDSA signature of state string for both parties

s - array of outputs of ECDSA signature of state string for both parties

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

### オファー・チャネル情報の取得

**URL** : `/offers/<uuid:guid>`

**Method** : `GET`

### オファー・チャネル決済期間の取得

**URL** : `/offers/<uuid:guid>/settlementPeriod`

**Method** : `GET`

### アンバサダー WebSocket URI の取得

**URL** : `/offers/<uuid:guid>/websocket`

**Method** : `GET`

### 未解決のオファーの取得

**URL** : `/offers/pending`

**Method** : `GET`

### オープン・オファーの取得

**URL** : `/offers/opened`

**Method** : `GET`

### クローズ・オファーの取得

**URL** : `/offers/closed`

**Method** : `GET`

### 自分のオファーの取得

**URL** : `/offers/myoffers?account=[eth_address]`

**Method** : `GET`

## トランザクションの署名

**URL** : `/transactions?chain=[chain_here]`

**Method** : `POST`

すべての署名済みトランザクションは、選択したチェーンでトランザクションを開始するために、ここで POST されます。

トランザクションの署名を polyswarmd 依存プロジェクトに追加するには、以下のステップに従ったものを作成/使用する必要があります。

0) トランザクション依存エンドポイントからトランザクション・データを受け取る

1) 秘密鍵を使用してトランザクション・データに署名する

2) 署名済みトランザクションを `/transactions` に POST する

以下に、Python の例を埋め込んでいます。ただし、任意の他の言語を使用できます。

```python
import json
import requests
from web3.auto import w3 as web3

POLYSWARMD_ADDR = 'localhost:31337'
KEYFILE = 'keyfile'
PASSWORD = 'password'
ADDRESS, PRIV_KEY = unlock_key(KEYFILE, PASSWORD)

def unlock_key(keyfile, password):
    """暗号化鍵ストア・ファイルを開いて復号"""
    with open(keyfile, 'r') as f:
        priv_key = web3.eth.account.decrypt(f.read(), password)

    address = web3.eth.account.privateKeyToAccount(priv_key).address
    return (address, priv_key)

def post_transactions(transactions):
    """polyswarmd を介して一連の (署名済み) トランザクションをイーサリアムに POST、出されたイベントを解析"""
    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, PRIV_KEY)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = 'http://{0}/transactions'.format(POLYSWARMD_ADDR)

    response = requests.post(uri, data=json.dumps({'transactions': signed})):
    return response.json()
```

#### Success Response

**Condition** : If everything is OK you will get an array of raw unsigned transactions to be signed and sent through the `/transactions` endpoint

**Code** : `200`

**Content example**

```json
[
  {
    "is_error": false,
    "message": "0x3ba9b38a6014048897a47633727eec4999d7936ea0f1d8e7bd42a51a1164ffad"
  },
]
```

## Transaction Events

A list of events or errors that resulted from the transaction with the given hash

**URL** : `/transactions/?chain=[chain_here]`

**Method** : `GET`

**Data constraints**

Provide:

transactions - a list transaction hashes to check

```json
{
  "transactions": "[array of transaction hashes]",
}
```

**Data example** All fields must be sent.

```json
{
  "transactions": ["0x3ba9b38a6014048897a47633727eec4999d7936ea0f1d8e7bd42a51a1164ffad"],
}
```

#### Success Response

**Condition** : If all of the transactions completed without reverting. (If some failed, it will return 400)

**Code** : `200`

**Content example**

```json
{
  "transfers": [
    {
    "value": 20000000000000000,
    "from": "0x000000000000000000000000000000000",
    "to": "0x000000000000000000000000000000000"
    }
  ],
  "bounties": [
    {
      "guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
      "author": "0x000000000000000000000000000000000",
      "amount": "1000",
      "uri": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
      "expiration": "1000"
    }
  ],
  "assertions": [
    {
      "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
      "author": "0x000000000000000000000000000000000",
      "index": 0,
      "bid": "1000",
      "mask": [true],
      "commitment": "1000"
    }
  ],
  "reveals": [
    {
      "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
      "author": "0x000000000000000000000000000000000",
      "index": 0,
      "nonce": "0",
      "verdicts": [true],
      "metadata": ""
    }
  ],
  "votes": [
    {
      "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
      "votes": [true],
      "voter": "0x000000000000000000000000000000000"
    }
  ],
  "settles": [
    {
      "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
      "settler": "0x000000000000000000000000000000000",
      "payout": 0
    }
  ],
  "withdrawals": [
    {
      "to": "0x000000000000000000000000000000000",
      "value": 0
    }
  ],
  "deposits": [
    {
      "from": "0x000000000000000000000000000000000",
      "value": 0
    }
  ],
  "errors": []
}
```

## State

### 状態の作成

The state byte string contains details the ambassador and expert sign off on.

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
    

### 状態への署名

The offers api requires signed states. Here's an example of signing to create the v, r, and s signature pieces in Javascript.

```javascript
const EthereumTx = require('ethereumjs-tx');
const keythereum = require('keythereum');

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

### 状態メッセージ

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

See state [explanation](#state)

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

***Reveal***

Sent when an assertion to a bounty is revealed

**Content example**

```json
{
  "event": "assertion",
  "data": {
    "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "author": "0x000000000000000000000000000000000",
    "index": 0,
    "nonce": "0",
    "verdicts": [true],
    "metadata": ""
  }
}
```

***Vote***

Sent when an arbiter votes on a bounty

**Content example**

```json
{
  "event": "vote",
  "data": {
    "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "votes": [true],
    "voter": "0x000000000000000000000000000000000"
  }
}
```

***Quorum***

Sent when arbiters have reached quorum on a bounty

**Content example**

```json
{
  "event": "quorum",
  "data": {
    "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "quorum_block": 1000
  }
}
```

***Settled***

Sent when a participant settles their portion of a bounty

**Content example**

```json
{
  "event": "settled_bounty",
  "data": {
    "bounty_guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "settler": "0x0000000000000000000000000000000000000000",
    "payout": 0
  }
}
```

***Initialized Channel***

Sent when a new channel is initialized

**Content example**

```json
{
  "event": "initialized_channel",
  "data": {
    "guid": "20085e89-c5e3-4fb4-a6cd-055feb342097",
    "ambassador": "0x0000000000000000000000000000000000000000",
    "expert": "0x0000000000000000000000000000000000000000",
    "mutl_signature": "0x0000000000000000000000000000000000000000"
  }
}
```