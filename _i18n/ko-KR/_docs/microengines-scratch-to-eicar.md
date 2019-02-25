# "Hello World" 마이크로엔진

## 개요

맬웨어 방지 솔루션을 개발할 때 "Hello World"는 언제나 [EICAR 테스트 파일](https://en.wikipedia.org/wiki/EICAR_test_file)을 탐지하고 있습니다.

이 정상 파일은 모든 주요 맬웨어 방지 제품이 '악성'으로 식별하므로, 안전하게 긍정적인 결과를 테스트해볼 수 있습니다.

우리의 첫 번째 마이크로엔진도 다르지 않습니다. EICAR을 탐지해보겠습니다!

[(선택 사항) 마이크로엔진의 구성 요소 검토 →](/concepts-participants-microengine/#breaking-down-microengines)

## 빌딩 블록

본 가이드는 다음을 참고하여 작성합니다.

* [**engine-template**](https://github.com/polyswarm/engine-template): 이름 그대로 대화식 프롬프트를 통해 간편하게 새로운 엔진을 만들 수 있는 템플릿입니다. 이는 튜토리얼에서 사용됩니다.

* [**polyswarm-client**](https://github.com/polyswarm/polyswarm-client): 전형적인 PolySwarm 참가자("클라이언트")의 스위스 아미 나이프라고 할 수 있습니다. `polyswarm-client`는 `마이크로엔진`(본 튜토리얼에서는 이 기능을 구축합니다), `중재자` 및 `홍보대사`(나중에 이 기능을 사용해 구축한 내용을 테스트합니다)의 기능을 수행할 수 있습니다.

## 사용자 지정 `engine-template`

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong>
 Windows 기반 엔진은 현재 AMI(AWS Machine Images)로만 지원됩니다.
  </p>
  <p>
    Window 기반 엔진의 사용자 지정 과정에서는 사용자가 AWS 계정 및 ID를 가지고 있다고 가정합니다.
  </p>
  <p>
    향후 자체 호스팅 옵션을 포함하여 배포 옵션을 확대할 예정입니다. Linux 기반 엔진은 이러한 조건이 없습니다.
  </p>
</div>

`engine-template`에서 엔진을 자릅니다. 이를 위해 `cookiecutter`가 필요합니다.

```bash
pip install cookiecutter
```

`cookiecutter`가 설치되면 템플릿에서 엔진을 아주 쉽게 시작할 수 있습니다.

```bash
cookiecutter https://github.com/polyswarm/engine-template
```

프롬프트가 표시되면, 다음과 같이 응답합니다.

* `engine_name`: MyEicarEngine (엔진의 이름)
* `engine_name_slug`: (기본 값 사용)
* `project_slug`: (기본 값 사용)
* `author_org`: ACME (또는 조직의 실제 이름)
* `author_org_slug`: (기본 값 사용)
* `package_slug`: (기본 값 사용)
* `author_name`: Wile E Coyote (또는 실제 이름)
* `author_email`: (이메일 주소)
* `플랫폼`: 정직하게 답변합니다 - 이 엔진이 Linux와 Windows 중 어디에서 실행됩니까?
* `has_backend`: false의 경우 1 (아래 설명 참조)
* `aws_account_for_ami`: (Windows만 해당) AWS 계정 ID (Linux 엔진의 경우 기본 값 사용)

<div class="m-callout">
  <p>프롬프트 중 하나는 '분리된 백엔드가 있음'이라고 생각하면 되는 <code>has_backend</code>이며, 추가적인 설명이 필요합니다.</p>
  <p>검사 엔진을 래핑할 때, <code>polyswarm-client</code> 클래스의 상속과 클래스 함수의 구현은 '프런트엔드' 변경으로 간주됩니다. 검사 엔진 '프런트엔드'가 네트워크나 로컬 소켓을 통하여 실제 검사 작업을 수행하는 별도의 프로세스("백엔드")에 접속해야 할 경우, 분리된 '백엔드'가 있는 셈이므로 <code>has_backend</code>에 <code>true</code>라고 답해야 합니다. 대신 검사 엔진이 단일한 Docker 이미지(Linux) 또는 AMI(Windows)로 쉽게 캡슐화할 수 있다면 <code>has_backend</code>를 <code>false</code>로 선택해야 합니다.</p>
  <p>분리된 프런트엔드 / 백엔드의 예:</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/5959742f0014a582baf5046c7bf6694c23f7435e/src/microengine/clamav.py#L18">ClamAV</a></li>
  </ul>
  <p>프런트엔드만 존재하는 예(has_backend가 false):</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/yara.py">Yara</a></li>
  </ul>
</div>

모든 준비가 완료되었습니다!

현재 작업 중인 디렉터리에서 `microengine-myeicarengine`을 찾을 수 있습니다. EICAR의 검사 함수를 구현하기 위해서 이를 편집합니다.

## EICAR 스캐너 & 마이크로엔진 구현

EICAR은 간단히 탐지할 수 있습니다.

1. EICAR 테스트 파일을 탐지할 수 있는 스캐너 클래스 구현
2. 이 스캐너 클래스를 사용하는 마이크로엔진 클래스 구현

이제 시작해보겠습니다.

`microengine-myeicarengine/src/(the org slug name)_myeicarengine/__init__.py`를 엽니다.

위에서 cookiecutter `engine-template`을 사용한 경우 `__init__.py`에 코드가 포함됩니다.

이 파일을 수정하여 스캐너와 마이크로엔진 클래스를 구현합니다.

* **스캐너**: 우리가 사용할 스캐너 클래스. 이 클래스는 자체 `검사` 함수에서 EICAR 탐지 로직을 구현합니다.

* **마이크로엔진**: 우리가 사용할 마이크로엔진 클래스. 이 클래스는 위에 기술된 스캐너를 래핑하여 EICAR을 탐지하는 마이크로엔진에 필요한 모든 작업을 처리합니다.

### EICAR 탐지 로직 작성

EICAR 테스트 파일은 `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*` 문자열만 포함하는 파일로 정의됩니다.

물론, 이 기준에 부합하는 파일을 식별하는 방법은 많이 있습니다. `검사` 함수의 `콘텐츠` 매개 변수에 해당 아티팩트의 전체 내용이 포함됩니다. 사용자는 이것을 처리해야 합니다.

다음 두 가지 예는 `EICAR`을 탐지하는 `scan()` 함수를 작성하는 방법에 관한 것입니다. 이들 중 하나를 변경하여 `__init__.py` 파일의 코드를 업데이트합니다.

첫 번째 방법은 가장 간단한 것으로 [`eicar.py`](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/eicar.py)에서 사용됩니다.

```python
import base64
from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')

class Scanner(AbstractScanner):

async def scan(self, guid, content, chain):
if content == EICAR:
return True, True, ''

return True, False, ''


class Microengine(AbstractMicroengine):
def __init__(self, client, testing=0, scanner=None, chains=None):
scanner = Scanner()
super().__init__(client, testing, scanner, chains)

```

다른 방법으로는 이미 알려진 악성 해시가 포함된 EICAR 테스트 파일의 SHA-256을 비교합니다.

```python
import base64

from hashlib import sha256
from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

EICAR = base64.b64decode(b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=')
HASH = sha256(EICAR).hexdigest()

class Scanner(AbstractScanner):

async def scan(self, guid, content, chain):
testhash = sha256(content).hexdigest()
if (testhash == HASH):
return True, True, ''

return True, False, ''


class Microengine(AbstractMicroengine):
def __init__(self, client, testing=0, scanner=None, chains=None):
scanner = Scanner()
super().__init__(client, testing, scanner, chains)

```

### 판돈 설정 전략 개발

마이크로엔진은 최소한 (a) 악성 파일을 식별하고 (b) 판돈으로 설정된 NCT가 포함된 주장을 제시해야 합니다.

판돈 설정 로직은 마이크로엔진의 `bid` 함수에서 구현됩니다.

기본적으로 모든 주장은 마이크로엔진이 가입한 커뮤니티의 최소 판돈 금액과 함께 제시됩니다.

다양한 판돈 설정 전략에 대해 알아보려면 나중에 다시 확인해보세요.

## 엔진 완성 & 테스트

지금까지는 `cookiecutter`가 `engine-template`을 적절히 변경했지만, 사용자가 직접 작성해야 하는 몇 가지 항목이 있습니다. 주요 항목들은 위에 다루어져 있지만, `CUSTOMIZE_HERE`라고 검색하여 모든 사용자 지정 항목이 작성되었는지 확인하시기 바랍니다.

모든 준비가 완료되면 엔진을 테스트합니다.

[Linux 기반 엔진 테스트 →](/testing-linux/)

[Windows 기반 엔진 테스트 →](/testing-windows/)

## 다음 단계

검사 로직을 스캐너 클래스 안에서 직접 구현하면 관리 및 확장하기가 어렵습니다. 그 대신, 마이크로엔진 클래스가 실제 검사 로직이 포함된 외부 바이너리나 서비스를 호출하게 하는 것이 좋습니다.

[다음으로 ClamAV를 마이크로엔진에 래핑하겠습니다 →](/microengines-scratch-to-clamav/)