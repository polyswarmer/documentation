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

**Method** : `POST`

**Data constraints**

Provide:

votes: Matriz de votos que representa la verdad terreno para los artefactos vinculados a la recompensa.

valid\_bloom: Si se trata de un voto *bloom*.

```json
{
  "votes": "[matriz con un máx. de 256 booleanos]",
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

### Liquidar recompensa

Invocable una vez cerrada la ventana de votación para gestionar el desembolso de la recompensa.

**URL**: `/bounties/<uuid:guid>/settle?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Esta petición no requiere datos**

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

### Realizar una afirmación sobre una recompensa

Invocado por los expertos en seguridad para emitir una afirmación al respecto de una recompensa.

**URL**: `/bounties/<uuid:guid>/assertions?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

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

**Data example** All fields must be sent.

```json
{
  "bid": "200000",
  "mask": "[true, true, true]",
  "verdicts": "[false, true, false]"
}
```

#### Success Response

**Condición**: Si todo es correcto, se creará un hápax (*nonce*) que se usará después para revelar la afirmación, y obtendrás una matriz de transacciones en crudo sin firmar, que deberán firmarse y enviarse a través del nodo `/transactions`.

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

### Revelar afirmaciones sobre una recompensa

Invocado por un árbitro una vez vencida la recompensa, permite realizar la liquidación con su determinación de la verdad terreno y abonar las recompensas correspondientes por las afirmaciones.

**URL**: `/bounties/<uuid:guid>/vote?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

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

### Obtener información sobre una recompensa

**URL**: `/<uuid:guid>?chain=[chain_name]`

**Method** : `GET`

### Obtener afirmaciones para una recompensa

**URL**: `/<uuid:guid>/assertions?chain=[chain_name]`

**Method** : `GET`

### Obtener una afirmación para una recompensa

**URL**: `/<uuid:guid>/assertions/<int:id_>?chain=[chain_name]`

**Method** : `GET`

### Obtener filtro *bloom* para una recompensa

**URL** : `/<uuid:guid>/bloom?chain=[chain_name]`

**Method** : `GET`

### Obtener votos para una recompensa

**URL**: `/<uuid:guid>/votes?chain=[chain_name]`

**Method** : `GET`

### Obtener un voto para una recompensa

**URL** : `/<uuid:guid>/votes/<int:id_>?chain=[chain_name]`

**Method** : `GET`

## API de apuestas

### Parámetros de una apuesta

**URL**: `/staking/parameters?chain=[chain_name]`

**Method** : `GET`

### Enviar depósito de apuesta

Invocado por los árbitros para depositar NCT en la apuesta.

**URL**: `/staking/deposit?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

amount: El importe en NCT a añadir a la apuesta actual.

```json
{
  "amount": "[cadena, longitud mín. 1 / longitud máx. 100]"
}
```

**Data example** All fields must be sent.

```json
{
  "amount": "30000000000"
}
```

### Enviar retirada de apuesta

Invocado por los árbitros para retirar el NCT disponible apostado.

**URL**: `/staking/withdraw?account=[eth_address]&chain=[chain_name]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

amount: La cantidad de NCT a retirar de la apuesta actual.

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

### Obtener balance total apostado

**URL**: `/balances/<dirección>/staking/total`

**Method** : `GET`

### Obtener saldo apostado retirable

**URL**: `/balances/<dirección>/staking/withdrawable`

**Method** : `GET`

## API de artefactos

### Enviar artefacto

Enviar un artefacto al IPFS.

**URL**: `/artifacts`

**Method** : `POST`

**Data constraints**

Provide:

Lista de archivos a cargar. El máximo son 256.

### Obtener vínculos de archivos asociados a un *hash*

**URL**: `/<ipfshash>`

**Method** : `GET`

### Obtener un vínculo asociado a un *hash* con un índice

**URL**: `/<ipfshash>/<int:id_>`

**Method** : `GET`

### Obtener estadísticas de un vínculo a un artefacto

**URL**: `/<ipfshash>/<int:id_>/stat`

**Method** : `GET`

## API de ofertas

*Próximamente, API de ofertas sin estado*

### Crear un canal de ofertas

Invocado por un embajador para desplegar una nueva oferta multifirma.

**URL**: `/offers?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

ambassador: Dirección del embajador que usará el canal.

experto: Dirección del experto que usará el canal.

settlementPeriodLength: Tiempo del que disponen las partes para disputar la liquidación del canal de oferta.

websocketUri: URI del *socket* para enviar mensajes al embajador.

```json
{
  "ambassador": "[cadena, longitud mín. 42]",
  "expert": "[cadena, longitud mín. 42]",
  "settlementPeriodLength": "[entero, mínimo 60]",
  "websocketUri": "[cadena, longitud mín. 1 y máx. 32]"
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

### Abrir canal

Invocado por un embajador para abrir un canal con un experto.

**URL**: `offers/open/<uuid:guid>?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state: Estado de oferta inicial.

v: El identificador de recuperación de la firma correspondiente a la cadena de estado.

r: Salida de la firma ECDSA de la cadena de estado.

s: Salida de la firma ECDSA de la cadena de estado.

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[entero, mínimo 0]",
  "r": "[cadena, longitud mínima 64]",
  "s": "[cadena, longitud mínima 64]"
}
```

**Data example** All fields must be sent.

Consulta la explicación sobre el [estado](#state).

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

### Unirse a un canal

Invocado por el experto para unirse al canal de un embajador.

**URL**: `offers/open?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state: Estado de oferta del embajador.

v - the recovery id from signature of state string

r - output of ECDSA signature of state string

s - output of ECDSA signature of state string

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[entero, mínimo 0]",
  "r": "[cadena, longitud mínima 64]",
  "s": "[cadena, longitud mínima 64]",
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

### Cancelar canal

Invocado por un embajador para cancelar el canal si el contrato todavía no se ha incorporado.

**URL**: `offers/cancel?account=[eth_address]&base_nonce=[integer]`

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

### Cerrar canal

Invocado por cualquiera de las partes con ambas firmas en un estado cuyo indicador `close_flag` sea 1.

**URL**: `/close?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state: Estado de oferta con indicador `close_flag` igual a 1.

v: Matriz formada por los identificadores de recuperación de firma de la cadena de estado de ambas partes.

r: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

s - array of outputs of ECDSA signature of state string for both parties

```json
{
  "state": "[cadena, longitud mínima 32]",
  "v": "[matriz de 2 enteros]",
  "r": "[matriz de 2 cadenas con longitud mín. 64]",
  "s": "[matriz de 2 cadenas con longitud mín. 64]",
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

### Cerrar canal impugnado con plazo de espera vencido

Invocado por cualquiera de las partes con ambas firmas en un estado que sea el estado final de impugnación.

**URL**: `/offers/closeChallenged?account=[eth_address]&base_nonce=[integer]`

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

### Liquidar canal

Invocado por un embajador o un experto para inicializar una liquidación en disputa usando un estado previamente acordado. Abre un plazo de respuesta con `settlementPeriodLength`.

**URL**: `/offers/settle?account=[eth_address]&base_nonce=[integer]`

**Method** : `POST`

**Data constraints**

Provide:

state: Estado de la oferta firmado por ambas partes.

v - array of the recovery ids from signature of state string for both parties

r - array of outputs of ECDSA signature of state string for both parties

s: Matriz formada por las salidas de la firma ECDSA de la cadena de estado de ambas partes.

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

### Impugnar estado de liquidación de canal

Invocado por un embajador o un experto para impugnar un estado en disputa. El nuevo estado se aceptará si es firmado por ambas partes y posee un número de secuencia más elevado.

**URL**: `/offers/challenge?account=[eth_address]&base_nonce=[integer]`

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

### Obtener información de canal de oferta

**URL**: `/offers/<uuid:guid>`

**Method** : `GET`

### Obtener periodo de liquidación de canal de oferta

**URL**: `/offers/<uuid:guid>/settlementPeriod`

**Method** : `GET`

### Obtener URI del *socket* web del embajador

**URL**: `/offers/<uuid:guid>/websocket`

**Method** : `GET`

### Obtener ofertas pendientes

**URL**: `/offers/pending`

**Method** : `GET`

### Obtener ofertas abiertas

**URL**: `/offers/opened`

**Method** : `GET`

### Obtener ofertas cerradas

**URL**: `/offers/closed`

**Method** : `GET`

### Obtener mis ofertas

**URL**: `/offers/myoffers?account=[eth_address]`

**Method** : `GET`

## Firma de transacciones

**URL**: `/transactions?chain=[chain_here]`

**Method** : `POST`

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

## Eventos de transacción

Lista de eventos o errores resultantes de la transacción designada con el *hash* proporcionado.

**URL**: `/transactions/?chain=[chain_here]`

**Method** : `GET`

**Data constraints**

Provide:

transactions: Lista de *hashes* correspondientes a las transacciones a comprobar.

```json
{
  "transactions": "[matriz de <i>hashes</i> de transacción]",
}
```

**Data example** All fields must be sent.

```json
{
  "transactions": ["0x3ba9b38a6014048897a47633727eec4999d7936ea0f1d8e7bd42a51a1164ffad"],
}
```

#### Success Response

**Condición**: Que todas las transacciones se hayan completado sin revertirse (si alguna de ellas hubiera fallado, se devolverá un código 400).

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

## Estado

### Creación de un estado

La cadena de *bytes* de estado contiene detalles que el embajador y el experto acuerdan mediante su firma.

**URL**: `/offers/state`

**Method** : `POST`

**Data constraints**

Provide:

    close_flag: 1 o 0 para "¿este estado se puede cerrar?"
    nonce: La secuencia del estado
    ambassador: Dirección del embajador
    expert: Dirección del experto
    msig_address: Dirección de multifirma
    ambassador_balance: Saldo en néctares para el embajador
    nectar_balance: Saldo en néctares para el experto
    guid: Identificador único global para la publicación de la oferta
    offer_amount: El importe de la oferta abonado por afirmación
    

Opcional:

    artifact_hash: <i>Hash</i> criptográfico del artefacto
    ipfs_hash: La URI al IPFS del artefacto
    engagement_deadline: Vencimiento de participación
    assertion_deadline: Vencimiento de afirmación
    current_commitment: Compromiso actual
    verdicts: Mapa de bits de los veredictos
    meta_data: Metadatos relativos a la oferta actual
    

Ejemplo de datos enviados mediante POST:

    {
      "close_flag": 0,
      "nonce": 0,
      "ambassador": "0x000000000000000000000000000000000",
      "ambassador_balance": 100,
      "expert_balance": 0,
      "expert":"0x000000000000000000000000000000000",
      "msig_address": "0x05027017bd3284c3f794474cc9f047e247bea04a"
    }
    

#### Convertidos a la siguiente cadena de *bytes* en la respuesta:

    0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc
    

### Estado de las firmas

La API de ofertas requiere remitir estados firmados. Este es un ejemplo de cómo firmar para crear los elementos v, r y s de la firma en Javascript:

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

### Mensajes de estado

Los embajadores abren un *socket* web con la URL definida en el contrato. Localmente, los mensajes se envían a `ws://localhost:31337/messages/<uuid:guid>`.

**Data constraints**

Provide:

type: Tipo de mensaje (pago, petición, afirmación).

state: Estado de oferta.

Optional:

toSocketUri: Para enviar a una persona distinta (por defecto, va al embajador).

v: Identificadores de recuperación correspondientes a la firma de la cadena de estado de ambas partes.

r: Firma ECDSA de la cadena de estado.

s: Firma ECDSA de la cadena de estado.

```json
{
  "fromSocketUri": "[cadena]",
  "state": "[cadena, longitud mínima 32]",
  "v": "[matriz de 2 enteros]",
  "r": "[matriz de 2 cadenas con longitud mín. 64]",
  "s": "[matriz de 2 cadenas con longitud mín. 64]",
}
```

**Data example** All fields must be sent.

Consulta la explicación sobre el [estado](#state).

```json
{
  "state": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000f17f52151ebef6c7334fad080c5704d77216b732000000000000000000000000c5fdf4076b8f3a5357c5e395ab970b5b54098fef000000000000000000000000fa21e79ca2dfb3ab15469796069622903919159c00000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000219ebb52f4e92c4fa554e80316b95d4adefb3ed600000000000000000000000000000000000000000000000000000000000001bc000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000320000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006e6f6e650000000000000000000000000000000000000000000000000000004c6f636b79",
  "fromSocketUri": "payment"
}
```

## Eventos

Un *socket* web para eventos contractuales.

Debes dirigir la escucha a `ws://localhost:31337/events/<chain>`.

**Tipos de eventos**

***Bloque***

Enviado cuando se mina un nuevo bloque; comunica el número de bloque más reciente.

**Content example**

```json
{
  "event": "block",
  "data": {
    "number": 1000
  }
}
```

***Recompensa***

Enviado cuando se fija una nueva recompensa.

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

***Afirmación***

Enviado cuando se remite una nueva afirmación al respecto de una recompensa.

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

***Revelación***

Enviado cuando se revela una afirmación al respecto de una recompensa.

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

***Voto***

Enviado cuando un árbritro vota al respecto de una recompensa.

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

***Cuórum***

Enviado cuando los árbitros han alcanzado el cuórum al respecto de una recompensa.

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

***Liquidado***

Enviado cuando un participante liquida su parte de una recompensa.

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

***Canal inicializado***

Enviado cuando se inicializa un nuevo canal.

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