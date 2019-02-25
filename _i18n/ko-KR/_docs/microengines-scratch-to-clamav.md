# 실제 엔진 래핑: ClamAV

## 스테이지 설정

ClamAV는 오픈 소스 서명 기반 엔진으로 식별한 아티팩트에 대하여 빠른 분석을 제공하는 데몬을 갖추고 있습니다. 이 튜토리얼에서는 ClamAV를 분석 백엔드로 통합하여 두 번째 PolySwarm 마이크로엔진을 구축하는 방법에 대하여 설명합니다.

<div class="m-flag">
  <p>
    <strong>참고:</strong>
 PolySwarm 마켓플레이스는 전에는 알려지지 않은 맬웨어를 발견하는 곳이 될 것입니다.
  </p>
  <p>
    엄격한 서명 기반 엔진, 특히 누구나 서명에 액세스할 수 있는 엔진(예: ClamAV)을 분석 엔진으로 사용하면 '접수된' 아티팩트에 대하여 고유한 통찰력을 제공하기가 힘들며, 따라서 다른 엔진보다 우수한 성능을 발휘할 가능성이 적습니다.
  </p>
  <p>
    이 가이드를 마켓플레이스 접근 방법에 대한 권장 사항으로 생각해서는 안 됩니다. 기존의 분석 백엔드를 어떻게 <strong>마이크로엔진</strong>의 틀 안에 통합시킬 수 있는지에 대한 예로 생각하시기 바랍니다.
  </p>
</div>

이 튜토리얼은 [microengine/clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py)를 구축하는 방법을 안내합니다. 완성된 작업은 `clamav.py`를 참조하세요.

## `clamd` 구현 및 통합

[새로운 engine-template](/microengines-scratch-to-eicar/#customize-engine-template)으로 시작해서 'MyClamAvEngine'으로 `engine-name`을 부여합니다. 현재 작업 중인 디렉터리에서 `microengine-myclamavengine`을 찾을 수 있습니다. ClamAV의 검사 함수를 구현하기 위해 이를 편집합니다.

Edit the `__init__.py` as we describe below:

`clamd` 모듈을 불러오고 일부 전역 구성하여 ClamAV `분석 백엔드` 구축을 시작합니다.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import clamd
import logging
import os
from io import BytesIO

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

logger = logging.getLogger(__name__) # Initialize logger

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

We interact with `clamd` by sending it a byte stream of artifact contents.

ClamAV responds to these byte streams in the form:

```json
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```

We can easily parse the result using python's `[]` operator. `result[0]` is the word `FOUND`, and `result[1]` in this instance is `Eicar-Test-Signature`.

Now, all we need is to implement the scan method in the Scanner class.

```python
    async def scan(self, guid, content, chain):
        result = await self.clamd.instream(BytesIO(content))
        stream_result = result.get('stream', [])
        if len(stream_result) >= 2 and stream_result[0] == 'FOUND':
            return True, True, ''

        return True, False, ''
```

If `clamd` detects a piece of malware, it puts `FOUND` in `result[0]`.

The return values that the Microengine expects are:

1. `bit` : a `boolean` representing a `malicious` or `benign` determination
2. `verdict`: another `boolean` representing whether the engine wishes to assert on the artifact
3. `metadata`: (optional) `string` describing the artifact

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