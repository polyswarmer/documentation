# 다중 백엔드 마이크로엔진 구축

이 튜토리얼에서는 여러 개의 분석 백엔드를 결합하는 방법과 기본적인 의견 도출 엔진에 대하여 설명합니다. 두 개의 백엔드는 (지난 튜토리얼에서 설명된) `ClamAV`와 [YARA](https://virustotal.github.io/yara/)입니다.

## Mix에 YARA 추가하기

새로운 [engine-template](/microengines-scratch-to-eicar/#customize-engine-template)으로 시작해서 'MyYaraEngine'으로 `engine-name`을 부여합니다. 현재 작업 중인 디렉터리에서 `microengine-myyaraengine`을 찾을 수 있습니다. Yara의 함수를 구현하기 위해 이를 편집합니다.

이제 YARA 백엔드를 마이크로엔진에 추가합니다. 하지만, 먼저 일부 YARA 서명(규칙)이 필요합니다!

[Yara-Rules](https://github.com/Yara-Rules/rules) 저장소는 무료 규칙을 얻을 수 있는 훌륭한 장소입니다. 그럼 이제 규칙을 얻어서 `microengine-myyaraengine`의 `pkg` 디렉터리에 넣어보도록 하겠습니다.

```sh
cd microengine-myyaraengine/pkg
git clone https://github.com/Yara-Rules/rules.git
```

이 규칙을 해석하려면 `yara-python` 모듈이 필요합니다. 모듈이 없을 경우 설치하세요.

```sh
pip install yara-python
```

다음으로, `yara-python`을 사용해서 아티팩트를 검사하는 스캐너를 만듭니다.

아래와 같이 `__init__.py`를 편집합니다.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import yara

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

logger = logging.getLogger(__name__) # Initialize logger
RULES_DIR = os.getenv('RULES_DIR', 'docker/yara-rules')

class Scanner(AbstractScanner):
def __init__(self):
self.rules = yara.compile(os.path.join(RULES_DIR, "malware/MALW_Eicar"))

async def scan(self, guid, content, chain):
matches = self.rules.match(data=content)
if matches:
return True, True, ''

return True, False, ''
```

<div class="m-flag">
  <p>
    <strong>정보:</strong>
 마이크로엔진 클래스가 필요하지만, 수정할 필요가 없으므로 여기에 표시하지 않았습니다.
  </p>
</div>

`polyswarm-client`에 포함된 YARA 백엔드는 YARA 규칙을 가리키는 `RULES_DIR` 환경 변수를 허용합니다. 따라서, 이 엔진을 테스트할 경우 다운로드한 YARA 규칙을 가리키도록 `RULES_DIR` 환경 변수를 설정해야 합니다.

<div class="m-flag">
  <p>
    <strong>정보:</strong> 통합 테스트 수행 시(<a href="/testing-linux/#integration-testing">Linux</a>, <a href="/testing-windows/">Windows</a>) 모의 홍보대사는 두 개의 파일(EICAR 및 EICAR이 아닌 파일)에 대해서만 현상금을 겁니다. 따라서, 당사의 프레임워크에서 테스트를 하기 위해서는 EICAR을 탐지하는 YARA 규칙만 있으면 됩니다.
  </p>
</div>

이제 YARA 마이크로엔진이 준비되었습니다. 하지만, 우리의 계획은 단일한 마이크로엔진에 의해 실행되는 여러 개의 엔진을 갖추는 것이므로, 계속 진행해보겠습니다.

## ClamAV 스캐너

[이전 튜토리얼](/microengines-scratch-to-clamav/)에서 설명된 ClamAV 스캐너를 다시 사용합니다.

완성된 솔루션은 [clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py)에서 확인할 수 있습니다.

## 다중 분석 백엔드

새로운 [engine-template](/microengines-scratch-to-eicar/#customize-engine-template)으로 시작해서 'MyMultiEngine'으로 `engine-name`을 부여합니다. 현재 작업 중인 디렉터리에서 `microengine-mymultiengine`을 찾을 수 있습니다. ClamAv 및 YARA의 함수를 모두 사용하기 위해서 이를 편집합니다.

여러 개의 분석 백엔드를 사용할 수 있도록 마이크로엔진을 확장하겠습니다. 이를 위해, 두 개의 백엔드(YARA와 ClamAV)에서 결과를 얻어 의견을 도출하기 위한 방법이 필요합니다. 여러 개의 스캐너를 초기화하는 마이크로엔진을 만들어보겠습니다.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import logging

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner
from polyswarm_myclamavengine import Scanner as ClamavScanner
from polyswarm_myyaraengine import Scanner as YaraScanner

logger = logging.getLogger(__name__) # Initialize logger
BACKENDS = [ClamavScanner, YaraScanner]


class Scanner(AbstractScanner):

def __init__(self):
super(Scanner, self).__init__()
self.backends = [cls() for cls in BACKENDS]

```

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    The Microengine class is required, but we do not need to modify it, so it is not shown here.
  </p>
</div>

YaraScanner와 ClamavScanner의 인스턴스가 포함된 백엔드 목록이 생성됩니다.

이제 두 스캐너에 모두 액세스할 수 있습니다. 두 스캐너의 결과를 사용하여 스캐너의 `scan()` 함수에서 최종 의견을 도출해보겠습니다.

```python
    async def scan(self, guid, content, chain):
results = await asyncio.gather(*[backend.scan(guid, content, chain) for backend in self.backends])

# Unzip the result tuples
bits, verdicts, metadatas = tuple(zip(*results))
return any(bits), any(verdicts), ';'.join(metadatas)
```

이제 모든 스캐너의 결과를 비동기적으로 계산한 후, 이들을 결합하여 최종 의견을 도출합니다. 여기에서는 어떤 백엔드가 True 비트를 반환할 경우 주장을 제시하고, 백엔드가 악성이라고 판단하면 아티팩트가 악성이라는 주장을 제시합니다. 또한, 스캐너의 모든 메타데이터를 하나의 문자열로 결합하어 주장에 첨부합니다.

완성된 솔루션은 [multi.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/multi.py)에서 확인할 수 있습니다.

참고: python 모듈 `polyswarm_myclamavengine` 및 `polyswarm_myyaraengine`은 이전 예에서 가져온 것입니다. 이 다중 엔진이 ClamAV 및 YARA 엔진을 사용하려면 PYTHONPATH에서 이용할 수 있어야 합니다. To achieve that, you can run the following command in the root of both the ClamAV and the YARA project directories:

```bash
pip install .
```

## Next Steps

Now that we've learned how to make a variety of microengines using existing AV products, you can move onto creating your own custom microengine.