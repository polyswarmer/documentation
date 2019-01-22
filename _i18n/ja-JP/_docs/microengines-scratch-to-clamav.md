# Wrapping a Real Engine: ClamAV

## Setting the Stage

ClamAV is an open source signature-based engine with a daemon that provides quick analysis of artifacts that it recognizes. This tutorial will step you through building your second PolySwarm Microengine by means of incorporating ClamAV as an analysis backend.

<div class="m-flag">
  <p>
    <strong>Note:</strong>
    The PolySwarm marketplace will be a source of previously unseen malware.
  </p>
  <p>
    Relying on a strictly signature-based engine as your analysis backend, particularly one whose signatures everyone can access (e.g. ClamAV) is unlikely to yield unique insight into "swarmed" artifacts and therefore unlikely to outperform other engines.
  </p>
  <p>
    This guide should not be taken as a recommendation for how to approach the marketplace but rather an example of how to incorporate an existing analysis backend into a <strong>Microengine</strong> skeleton.
  </p>
</div>

This tutorial will walk the reader through building [microengine/clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py); please refer to `clamav.py` for the completed work.

## `clamd` Implementation and Integration

Start with a [fresh engine-template](/microengines-scratch-to-eicar/#customize-engine-template), give it the `engine-name` of "MyClamAvEngine". You should find a `microengine-myclamavengine` in your current working directory - this is what we'll be editing to implement ClamAV scan functionality.

Edit the `__init__.py` as we describe below:

We begin our ClamAV `analysis backend` by importing the `clamd` module and configuring some globals.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import clamd
import logging
import os
from io import BytesIO

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

logger = logging.getLogger(__name__)  # Initialize logger

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0
```

Would you believe me if I said we were almost done? Let's get `clamd` initialized and running, so it can communicate with the `clamd-daemon` over a network socket.

```python
class Scanner(AbstractScanner):
    def __init__(self):
        self.clamd = clamd.ClamdAsyncNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```

`clamd` の操作は、アーティファクト・コンテンツのバイト・ストリームを送信して行います。

ClamAV は、このバイト・ストリームに対して以下の形式で応答します。

```json
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```

Python の `[]` 演算子を使用して簡単に結果を解析できます。 `result[0]` は単語「`FOUND`」であり、この例の `result[1]` は「`Eicar-Test-Signature`」です。

これで、後は Scanner クラスに scan メソッドを実装するだけです。

```python
    async def scan(self, guid, content, chain):
        result = await self.clamd.instream(BytesIO(content))
        stream_result = result.get('stream', [])
        if len(stream_result) >= 2 and stream_result[0] == 'FOUND':
            return True, True, ''

        return True, False, ''
```

`clamd` は、マルウェアを検出すると、`result[0]` に「`FOUND`」を入れます。

マイクロエンジンで予期される戻り値は、以下のとおりです。

1. `bit` : `malicious` (悪意がある) か `benign` (無害) かの判定を表す `boolean`
2. `verdict`: エンジンでアーティファクトに関するアサーションを出すかどうかを表す `boolean`
3. `metadata`: (オプション) アーティファクトについて記述した `string`

We leave including ClamAV's `metadata` as an exercise to the reader - or check [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) :)

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    The Microengine class is required, but we do not need to modify it, so it is not shown here.
  </p>
  <p>
    Python 3's Asyncio - It is important that any external calls you make during a scan do not block the event loop.
    We forked the clamd project to add support for python 3's asyncio.
    Thus, for this example to run, you need install our python-clamd project to get the clamd package until our changes are merged upstream.
    The command you need is: `pip install git+https://github.com/polyswarm/python-clamd.git@async#egg=clamd`.
  </p>
</div>

## Finalizing & Testing Your Engine

`cookiecutter` customizes `engine-template` only so far - there are a handful of items you'll need to fill out yourself. We've already covered the major items above, but you'll want to do a quick search for `CUSTOMIZE_HERE` to ensure all customization have been made.

Once everything is in place, let's test our engine:

[Test Linux-based Engines →](/testing-linux/)

[Test Windows-based Engines →](/testing-windows/)

## Next Steps

In the Eicar example, we showed you how to implement scan logic directly in the Scanner class. And in this ClamAV example, we showed you how to call out to an external socket to access scanning logic.

[Next, we'll wrap ClamAV and Yara into a single Microengine ->](/microengines-clamav-to-multi/)