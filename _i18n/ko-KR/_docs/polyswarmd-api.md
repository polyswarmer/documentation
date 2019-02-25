## 현상금 API

### 현상금 매개 변수

**URL** : `/bounties/parameters?chain=[chain_name]`

**메소드**: `GET`

### 현상금 게시

현상금을 게시하기 위하여 최종 사용자와 홍보대사가 호출합니다.

**URL** :`/bounties?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**메소드**: `POST`

**데이터 제약 조건**

제공:

금액 - 보상으로 게시할 NCT의 수량

uri - 이 현상금을 구성하는 아티팩트의 uri

지속 시간 - 블록 안에서 이 현상금이 유지되는 시간

```json
{
"amount": "[string minimum length 1 / max length 100]",
"uri": "[string minimum length 1 / max length 100]",
"duration": "[integer minimum 1]"
}
```

**데이터 예** 모든 필드를 전송해야 합니다.

```json
{
"amount": "30000",
"uri": "QmYNmQKp6SuaVrpgWRsPTgCQCnpxUYGq76YEKBXuj2N4H6",
"duration": 10
}
```

#### 성공 응답

**조건**: 모든 항목이 적절하면 서명되지 않은 원시 트랜잭션의 배열을 얻으며, `/트랜잭션` 엔드포인트를 통해서 전송하게 됩니다.

**코드**: `200`

**내용 예제**

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

### 현상금 투표

현상금 게시 만료 후 중재자가 각 아티팩트에 대한 악성 또는 정상 투표를 호출하고 최종 사실 검증 판단에 연결됩니다.

**URL** :`/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

투표 - 현상금 대상 아티팩트에 대한 사실 검증에 해당하는 투표의 배열

valid\_bloom - 블룸 투표의 경우

```json
{
"votes": "[array with a max of 256 boolean items]",
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

### 현상금 결정

투표 창을 닫은 후 보상금 지불을 처리하기 위하여 호출합니다.

**URL** : `/bounties/<uuid:guid>/settle?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**이 요청에는 데이터가 필요하지 않습니다**

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

### 현상금에 대한 주장

현상금에 대하여 주장을 게시하기 위하여 보안 전문가들이 호출합니다

**URL** : `/bounties/<uuid:guid>/assertions?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

bid - 판돈으로 걸 NCT의 수량

마스크 - 현상금 세트에서 주장할 대상 아티팩트

의견 - 현상금 아티팩트에 대한 의견의 배열

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

**조건**: 모든 항목이 적절하면 나중에 공개 시 사용할 논스가 생성되고, 서명되지 않은 원시 트랜잭션의 배열을 얻으며, 서명 후 `/트랜잭션` 엔드포인트를 통해서 전송하게 됩니다.

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

### 현상금 주장 공개

현상금 만료 후 사실 검증에 대한 본인의 판단을 확정하고 주장에 대한 보상을 지급하기 위하여 중재자가 호출합니다.

**URL** : `/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

논스 - 약속 해시를 생성하는 데 사용되는 논스 (현상금에 대한 주장에서 반환됨)

의견 - 이 주장을 구성하는 의견들

메타데이터 - 주장에 포함됨 (빈 문자열일 수 있음)

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

### 현상금 정보 가져오기

**URL** : `/<uuid:guid>?chain=[chain_name]`

**Method** : `GET`

### 현상금에 대한 주장 가져오기

**URL** : `/<uuid:guid>/assertions?chain=[chain_name]`

**Method** : `GET`

### 현상금에 대한 특정 주장 가져오기

**URL** : `/<uuid:guid>/assertions/<int:id_>?chain=[chain_name]`

**Method** : `GET`

### 현상금에 대한 블룸 가져오기

**URL** : `/<uuid:guid>/bloom?chain=[chain_name]`

**Method** : `GET`

### 현상금에 대한 투표 가져오기

**URL** : `/<uuid:guid>/votes?chain=[chain_name]`

**Method** : `GET`

### 현상금에 대한 특정 투표 가져오기

**URL** : `/<uuid:guid>/votes/<int:id_>?chain=[chain_name]`

**Method** : `GET`

## 판돈 설정 API

### 판돈 설정 매개 변수

**URL** : `/staking/parameters?chain=[chain_name]`

**Method** : `GET`

### 판돈 입금 게시

Nectar 판돈을 입금하기 위하여 중재자가 호출합니다.

**URL** : `/staking/deposit?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

수량 - 현재 판돈에 추가할 NCT의 수량

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

### 판돈 출금 게시

남아 있는 Nectar 판돈을 출금하기 위하여 중재자가 호출합니다.

**URL** : `/staking/withdraw?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

수량 - 현재 판돈에서 출금할 NCT의 수량

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

### 총 판돈 잔고 가져오기

**URL** : `/balances/<address>/staking/total`

**Method** : `GET`

### 출금 가능한 판돈 잔고 가져오기

**URL** : `/balances/<address>/staking/withdrawable`

**Method** : `GET`

## 아티팩트 API

### 아티팩트 게시

IPFS에 아티팩스를 게시합니다

**URL** : `/artifacts`

**Method** : `POST`

**Data constraints**

Provide:

업로드할 파일 목록. 최대 256개를 업로드할 수 있습니다

### 해시와 관련된 파일 링크 가져오기

**URL** : `/<ipfshash>`

**Method** : `GET`

### 해시와 관련된 링크 및 링크 인덱스 가져오기

**URL** : `/<ipfshash>/<int:id_>`

**Method** : `GET`

### 아티팩트 링크에 대한 통계 가져오기

**URL** : `/<ipfshash>/<int:id_>/stat`

**Method** : `GET`

## 제안 API

*상태 비저장 제안 API 추가 예정*

### 제안 채널 만들기

새로운 다중 서명 제안을 배포하기 위하여 홍보대사가 호출합니다

**URL** : `/offers?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

ambassador - 채널을 사용하는 홍보대사의 주소

expert - 채널을 사용하는 전문가의 주소

settlementPeriodLength - how long the parties have to dispute the settlement offer channel

websocketUri - 홍보대사에게 메시지를 전송할 소켓의 uri

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

### 채널 개설

전문가와 함께 채널을 개설하기 위하여 홍보대사가 호출합니다

**URL** : `offers/open/<uuid:guid>?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - 초기 제안 상태

v - 상태 문자열 서명에서 복구 id

r - 상태 문자열 ECDSA 서명의 출력

s - 상태 문자열 ECDSA 서명의 출력

```json
{
"state": "[string minimum length 32]",
"v": "[integer minimum 0]",
"r": "[string minimum length 64]",
"s": "[string minimum length 64]"
}
```

**Data example** All fields must be sent.

상태에 대한 [설명](#state)을 참조하세요

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

### 채널 가입

홍보대사의 채널에 가입하기 위하여 전문가가 호출합니다

**URL** : `offers/open?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - 홍보대사의 제안 상태

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

### 채널 취소

아직 계약이 체결되지 않은 경우 취소하기 위하여 홍보대사가 호출합니다

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

### 채널 종료

종료 상태 플래그를 1로 설정하고 상태에 대한 두 서명을 포함하여 임의의 당사자가 호출합니다

**URL** : `/close?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state - 종료 플래그가 포함된 제안 상태

v - 양 당사자에 대한 상태 문자열 서명에서 복구 id 배열

r - 양 당사자에 대한 상태 문자열 ECDSA 서명의 출력 배열

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

### Close challenged channel with timeout

Called by any party with a both signatures on a state that is the final challenge state

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

### Settle channel

Called by ambassador or expert to start initialize a disputed settlement using an agreed upon state. It starts a timeout for a reply using `settlementPeriodLength`

**URL** : `/offers/settle?account=[eth_address]&base_nonce=[integer]`

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

### Challenge settle channel state

Called by ambassador or expert to challenge a disputed state. The new state is accepted if it is signed by both parties and has a higher sequence number

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

**URL** : `/offers/myoffers?account=[eth_address]`

**Method** : `GET`

## Transaction Signing

**URL** : `/transactions?chain=[chain_here]`

**Method** : `POST`

All signed transactions are POSTed here to start the transaction on the chain of choice.

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

### Creating State

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
    

### Signing State

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