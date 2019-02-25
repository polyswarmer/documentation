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

아래와 같이 `__init__.py`를 편집합니다.

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

거의 다 끝났습니다. 네트워크 소켓을 통해 `clamd-daemon`과 통신할 수 있도록 `clamd`를 초기화하고 실행합니다.

```python
class Scanner(AbstractScanner):
def __init__(self):
self.clamd = clamd.ClamdAsyncNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```

아티팩트 콘텐츠의 바이트 스트림을 전송해서 `clamd`와 상호 작용합니다.

ClamAV는 다음과 같은 형태로 이러한 바이트 스트림에 응답합니다.

```json
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```

python의 `[]` 연산자를 사용하여 결과를 쉽게 구문 분석할 수 있습니다. `result[0]`은 `FOUND`라는 단어이고, 인스턴스에서 `result[1]`은 `Eicar-Test-Signature`입니다.

이제 스캐너 클래스의 검사 메소드를 구현하기만 하면 됩니다.

```python
    async def scan(self, guid, content, chain):
result = await self.clamd.instream(BytesIO(content))
stream_result = result.get('stream', [])
if len(stream_result) >= 2 and stream_result[0] == 'FOUND':
return True, True, ''

return True, False, ''
```

`clamd`가 맬웨어를 탐지하면 `result[0]`에 `FOUND`를 넣습니다.

마이크로엔진이 예상하는 반환 값은 다음과 같습니다.

1. `bit`: `악성` 또는 `정상` 판단을 나타내는 `불리언`
2. `verdict`: 엔진이 아티팩트에 대해 주장을 할지 여부를 나타내는 `불리언`
3. `metadata`: (선택 사항) 아티팩트에 대해 설명하는 `문자열`

ClamAV의 `메타데이터`를 포함시키는 방법은 직접 확인해보시거나, [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py)를 참조하시기 바랍니다 :)

<div class="m-flag">
  <p>
    <strong>정보:</strong>
 마이크로엔진 클래스가 필요하지만, 수정할 필요가 없으므로 여기에 표시하지 않았습니다.
  </p>
  <p>
    Python 3의 Asyncio - 검사하는 동안 수행한 외부 호출이 이벤트 루프를 차단하지 않도록 해야 합니다.
    python 3의 asyncio에 대한 지원을 추가하기 위하여 clamd 프로젝트를 포크(fork)하였습니다.
    따라서, 이 예제를 실행하려면 변경 사항이 업스트림에서 병합될 때까지 python-clamd 프로젝트를 설치하여 clamd 패키지를 취득하셔야 합니다.
    필요한 명령: `pip install git+https://github.com/polyswarm/python-clamd.git@async#egg=clamd`.
  </p>
</div>

## 엔진 완성 & 테스트

지금까지는 `cookiecutter`가 `engine-template`을 적절히 변경했지만, 사용자가 직접 작성해야 하는 몇 가지 항목이 있습니다. 주요 항목들은 위에 다루어져 있지만, `CUSTOMIZE_HERE`라고 검색하여 모든 사용자 지정 항목이 작성되었는지 확인하시기 바랍니다.

모든 준비가 완료되면 엔진을 테스트합니다.

[Linux 기반 엔진 테스트 →](/testing-linux/)

[Windows 기반 엔진 테스트 →](/testing-windows/)

## 다음 단계

Eicar 예제를 통해 스캐너 클래스의 검사 로직을 직접 구현하는 방법에 대하여 설명했습니다. 그리고 이번 ClamAV 예에서 외부 소켓을 호출하여 검사 로직에 액세스하는 방법에 대하여 설명했습니다.

[다음에는 ClamAV와 Yara를 단일한 마이크로엔진에 래핑하겠습니다 ->](/microengines-clamav-to-multi/)