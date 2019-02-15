## API de recompensas

### Parámetros de una recompensa

**URL**: `/bounties/parameters?chain=[chain_name]`

**Método**: `GET`

### Fijar recompensa

Invocado por usuarios finales y embajadores para fijar una recompensa.

**URL**: `/bounties?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

amount: El importe en NCT a fijar como recompensa.

uri: URI de los artefactos que conforman esta recompensa.

duration: Duración de esta recompensa, en bloques.

```json
{
  "amount": "[cadena, longitud mín. 1 / longitud máx. 100]",
  "uri": "[cadena, longitud mín. 1 / longitud máx. 100]",
  "duration": "[entero, mín. 1]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "amount": "30000",
  "uri": "QmYNmQKp6SuaVrpgWRsPTgCQCnpxUYGq76YEKBXuj2N4H6",
  "duration": 10
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Votar recompensa

Invocado por el árbitro al vencer la recompensa, con un voto de "malicioso" o "benigno" para cada artefacto, con el fin de contribuir a establecer la verdad terreno definitiva.

**URL**: `/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

votes: Matriz de votos que representa la verdad terreno para los artefactos vinculados a la recompensa.

valid\_bloom: Si se trata de un voto *bloom*.

```json
{
  "votes": "[matriz con un máx. de 256 booleanos]",
  "valid\_bloom": "[boolean]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "votes": "[true, false, true, true, false]",
  "valid\_bloom": "true"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Liquidar recompensa

Invocable una vez cerrada la ventana de votación para gestionar el desembolso de la recompensa.

**URL**: `/bounties/<uuid:guid>/settle?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Esta petición no requiere datos**

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Realizar una afirmación sobre una recompensa

Invocado por los expertos en seguridad para emitir una afirmación al respecto de una recompensa.

**URL**: `/bounties/<uuid:guid>/assertions?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

bid: La cantidad en NCT a apostar.

mask: Los artefactos del conjunto incluido en la recompensa respecto para los que se emite la afirmación.

verdicts: Matriz de veredictos a emitir sobre los artefactos de la recompensa.

```json
{
  "bid": "[cadena, longitud mín. 1 y longitud máx. 100]",
  "mask": "[matriz, máx. de 256 booleanos]",
  "verdicts": "[matriz, máx. de 256 booleanos]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "bid": "200000",
  "mask": "[true, true, true]",
  "verdicts": "[false, true, false]"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, se creará un hápax (*nonce*) que se usará después para revelar la afirmación, y obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Revelar afirmaciones sobre una recompensa

Invocado por un árbitro una vez vencida la recompensa, permite realizar la liquidación con su determinación de la verdad terreno y abonar las recompensas correspondientes por las afirmaciones.

**URL**: `/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

nonce: El hápax (*nonce*) usado para generar el *hash* de compromiso (obtenido tras realizar una afirmación para obtener una recompensa).

verdicts: Los veredictos que componen esta afirmación.

metadata: Metadatos a incluir en la afirmación (puede ser una cadena vacía).

```json
{
  "nonce": "[cadena, longitud mín. 1 y longitud máx. 100]",
  "verdicts": "[matriz, máx. de 256 booleanos]",
  "metadata": "[cadena, longitud mín. 1 y longitud máx. 1024]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "nonce": "123",
  "verdicts": "[true, false, true]",
  "metadata": "Dropper"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Obtener información sobre una recompensa

**URL**: `/<uuid:guid>?chain=[chain_name]`

**Método**: `GET`

### Obtener afirmaciones para una recompensa

**URL**: `/<uuid:guid>/assertions?chain=[chain_name]`

**Método**: `GET`

### Obtener una afirmación para una recompensa

**URL**: `/<uuid:guid>/assertions/<int:id_>?chain=[chain_name]`

**Método**: `GET`

### Obtener filtro *bloom* para una recompensa

**URL** : `/<uuid:guid>/bloom?chain=[chain_name]`

**Método**: `GET`

### Obtener votos para una recompensa

**URL**: `/<uuid:guid>/votes?chain=[chain_name]`

**Método**: `GET`

### Obtener un voto para una recompensa

**URL** : `/<uuid:guid>/votes/<int:id_>?chain=[chain_name]`

**Método**: `GET`

## API de apuestas

### Parámetros de una apuesta

**URL**: `/staking/parameters?chain=[chain_name]`

**Método**: `GET`

### Enviar depósito de apuesta

Invocado por los árbitros para depositar NCT en la apuesta.

**URL**: `/staking/deposit?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

amount: El importe en NCT a añadir a la apuesta actual.

```json
{
  "amount": "[cadena, longitud mín. 1 / longitud máx. 100]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "amount": "30000000000"
}
```

### Enviar retirada de apuesta

Invocado por los árbitros para retirar el NCT disponible apostado.

**URL**: `/staking/withdraw?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

amount: La cantidad de NCT a retirar de la apuesta actual.

```json
{
  "amount": "[cadena, longitud mín. 1 / longitud máx. 100]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "amount": "30000000000"
}
```

### Obtener balance total apostado

**URL** : `/balances/<address>/staking/total`

**Método**: `GET`

### Get withdrawable stake balance

**URL** : `/balances/<address>/staking/withdrawable`

**Método**: `GET`

## Artifacts API

### Post Artifact

Post an artifact to IPFS

**URL** : `/artifacts`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

List of files to upload. You can upload a max of 256

### Get file links associated with hash

**URL** : `/<ipfshash>`

**Método**: `GET`

### Get a link associated with hash and link index

**URL** : `/<ipfshash>/<int:id_>`

**Método**: `GET`

### Get stats on artifact link

**URL** : `/<ipfshash>/<int:id_>/stat`

**Método**: `GET`

## Offers API

*Stateless offer api coming soon*

### Create an offer channel

Called by an ambassador to deploy a new multi signature offer

**URL** : `/offers?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

ambassador - address of ambassador using channel

expert - address of expert using channel

settlementPeriodLength - how long the parties have to dispute the settlement offer channel

websocketUri - uri of socket to send messages to ambassador

```json
{
  "ambassador": "[string minimum length 42]",
  "expert": "[string minimum length 42]",
  "settlementPeriodLength": "[integer minimum 60]",
  "websocketUri": "[string with minimum length 1 max 32]"
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "amount": "0x34E583cf9C1789c3141538EeC77D9F0B8F7E89f2",
  "uri": "0xf0243D9b2E332D7072dD4B143a881B3f135F380c",
  "duration": 80,
  "websocketUri": "ws://localhost:9999/echo"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

**URL** : `offers/open/<uuid:guid>?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

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

**Ejemplo de datos**: Deben completarse todos los campos.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc",
  "v": "27",
  "r": "0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9",
  "s": "0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

**URL** : `offers/open?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

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

**Ejemplo de datos**: Deben completarse todos los campos.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "27",
  "r": "0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9",
  "s": "0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

**URL** : `offers/cancel?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

**URL** : `/close?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

state - offer state with closed flag

v - array of the recovery ids from signature of state string for both parties

r: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

s: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[matriz de 2 enteros]",
  "r": "[matriz de 2 cadenas con longitud mín. 64]",
  "s": "[matriz de 2 cadenas con longitud mín. 64]",
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Cerrar canal impugnado con plazo de espera vencido

Invocado por cualquiera de las partes con ambas firmas en un estado que sea el estado final de impugnación.

**URL**: `/offers/closeChallenged?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

state - offer state with closed flag

v - array of the recovery ids from signature of state string for both parties

r: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

s: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[matriz de 2 enteros]",
  "r": "[matriz de 2 cadenas con longitud mín. 64]",
  "s": "[matriz de 2 cadenas con longitud mín. 64]",
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Liquidar canal

Invocado por un embajador o un experto para inicializar una liquidación en disputa usando un estado previamente acordado. Abre un plazo de respuesta con `settlementPeriodLength`.

**URL**: `/offers/settle?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

state: Estado de la oferta firmado por ambas partes.

v - array of the recovery ids from signature of state string for both parties

r: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

s: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[matriz de 2 enteros]",
  "r": "[matriz de 2 cadenas con longitud mín. 64]",
  "s": "[matriz de 2 cadenas con longitud mín. 64]",
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Impugnar estado de liquidación de canal

Invocado por un embajador o un experto para impugnar un estado en disputa. El nuevo estado se aceptará si es firmado por ambas partes y posee un número de secuencia más elevado.

**URL**: `/offers/challenge?account=[eth_address]&base_nonce=[integer]`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

state: Estado de la oferta firmado por ambas partes.

v - array of the recovery ids from signature of state string for both parties

r: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

s: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[matriz de 2 enteros]",
  "r": "[matriz de 2 cadenas con longitud mín. 64]",
  "s": "[matriz de 2 cadenas con longitud mín. 64]",
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

See state [explaintion](#state)

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "v": "[27, 28]",
  "r": "['0x99e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 0x59e21a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9]",
  "s": "['0x129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66', '0x138ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca66']"
}
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

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

### Obtener información de canal de oferta

**URL**: `/offers/<uuid:guid>`

**Método**: `GET`

### Obtener periodo de liquidación de canal de oferta

**URL**: `/offers/<uuid:guid>/settlementPeriod`

**Método**: `GET`

### Obtener URI del *socket* web del embajador

**URL**: `/offers/<uuid:guid>/websocket`

**Método**: `GET`

### Obtener ofertas pendientes

**URL**: `/offers/pending`

**Método**: `GET`

### Obtener ofertas abiertas

**URL**: `/offers/opened`

**Método**: `GET`

### Obtener ofertas cerradas

**URL**: `/offers/closed`

**Método**: `GET`

### Obtener mis ofertas

**URL**: `/offers/myoffers?account=[eth_address]`

**Método**: `GET`

## Firma de transacciones

**URL**: `/transactions?chain=[chain_here]`

**Método**: `POST`

Todas las transacciones firmadas se envían aquí mediante POST para iniciarlas en la cadena deseada.

Para incorporar la funcionalidad de firma de transacciones en tu proyecto dependiente de polyswarmd, tu código debe llevar a cabo las siguientes acciones:

0) Al recibir los datos de la transacción desde un nodo basado en transacciones:

1) firma los datos de la transacción con tu clave privada, y

2) envía la transacción firmada mediante POST a `/transactions`.

A continuación se incluye un ejemplo con Python, pero puedes usar cualquier otro lenguaje.

```python
import json
import requests
from web3.auto import w3 as web3

POLYSWARMD_ADDR = 'localhost:31337'
KEYFILE = 'keyfile'
PASSWORD = 'password'
ADDRESS, PRIV_KEY = unlock_key(KEYFILE, PASSWORD)

def unlock_key(keyfile, password):
    """Abrir un archivo de almacén de claves encriptado y desencriptarlo"""
    with open(keyfile, 'r') as f:
        priv_key = web3.eth.account.decrypt(f.read(), password)

    address = web3.eth.account.privateKeyToAccount(priv_key).address
    return (address, priv_key)

def post_transactions(transactions):
    """Enviar un conjunto de transacciones (firmadas) a Ethereum mediante polyswarmd, parseando los eventos emitidos"""
    signed = []
    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, PRIV_KEY)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    uri = 'http://{0}/transactions'.format(POLYSWARMD_ADDR)

    response = requests.post(uri, data=json.dumps({'transactions': signed})):
    return response.json()
```

#### Respuesta correcta

**Condición**: Si todo es correcto, obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

**Código**: `200`

**Ejemplo de contenido**

```json
[
  {
    "is_error": false,
    "message": "0x3ba9b38a6014048897a47633727eec4999d7936ea0f1d8e7bd42a51a1164ffad"
  },
]
```

## Eventos de transacción

Lista de eventos o errores resultantes de la transacción designada con el *hash* proporcionado.

**URL**: `/transactions/?chain=[chain_here]`

**Método**: `GET`

**Restricciones de datos**

Debes suministrar:

transactions: Lista de *hashes* correspondientes a las transacciones a comprobar.

```json
{
  "transactions": "[matriz de <i>hashes</i> de transacción]",
}
```

**Ejemplo de datos**: Deben completarse todos los campos.

```json
{
  "transactions": ["0x3ba9b38a6014048897a47633727eec4999d7936ea0f1d8e7bd42a51a1164ffad"],
}
```

#### Respuesta correcta

**Condición**: Que todas las transacciones se hayan completado sin revertirse (si alguna de ellas hubiera fallado, se devolverá un código 400).

**Código**: `200`

**Ejemplo de contenido**

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

## Estado

### Creating State

The state byte string contains details the ambassador and expert sign off on.

**URL** : `/offers/state`

**Método**: `POST`

**Restricciones de datos**

Debes suministrar:

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

**Restricciones de datos**

Debes suministrar:

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

**Ejemplo de datos**: Deben completarse todos los campos.

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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

**Ejemplo de contenido**

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