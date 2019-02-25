# "Hello World" 마이크로엔진

## 개요

맬웨어 방지 솔루션을 개발할 때 "Hello World"는 언제나 [EICAR 테스트 파일](https://en.wikipedia.org/wiki/EICAR_test_file)을 탐지하고 있습니다.

이 양성 파일은 모든 주요 맬웨어 방지 제품이 '악성'으로 식별하므로, 안전하게 긍정적인 결과를 테스트해볼 수 있습니다.

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
  <p>검사 엔진을 래핑할 때, <code>polyswarm-client</code> 클래스의 상속과 클래스 함수의 구현은 '프런트엔드' 변경으로 간주됩니다. 검사 엔진 '프런트엔드'가 네트워크나 로컬 소켓을 통하여 실제 검사 작업을 수행하는 별도의 프로세스("백엔드")에 접속해야 할 경우, 분리된 '백엔드'가 있는 셈이므로 <code>has_backend</code>에 <code>true</code>라고 답해야 합니다. If instead your scan engine can easily be encapsulated in a single Docker image (Linux) or AMI (Windows), then you should select <code>false</code> for <code>has_backend</code>.</p>
  <p>Example of disjoint frontend / backend:</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/5959742f0014a582baf5046c7bf6694c23f7435e/src/microengine/clamav.py#L18">ClamAV</a></li>
  </ul>
  <p>Example of only a frontend (has_backend is false):</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/yara.py">Yara</a></li>
  </ul>
</div>

You're all set!

You should find a `microengine-myeicarengine` in your current working directory - this is what we'll be editing to implement EICAR scan functionality.

## Implement an EICAR Scanner & Microengine

Detecting EICAR is as simple as:

1. implementing a Scanner class that knows how to identify the EICAR test file
2. implementing a Microengine class that uses this Scanner class

Let's get started.

Open `microengine-myeicarengine/src/(the org slug name)_myeicarengine/__init__.py`.

If you used our cookiecutter `engine-template` from above, you will have some code in your `__init__.py`.

We will modify this file to implement both our Scanner and Microengine classes:

* **Scanner**: our Scanner class. This class will implement our EICAR-detecting logic in its `scan` function.

* **Microengine**: our Microengine class. This class will wrap the aforementioned Scanner to handle all the necessary tasks of being a Microengine that detects EICAR.

### Write EICAR Detection Logic

The EICAR test file is defined as a file that contains only the following string: `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`.

There are, of course, many ways to identify files that match this criteria. The `scan` function's `content` parameter contains the entire content of the artifact in question - this is what you're matching against.

The following are 2 examples for how you can write your `scan()` function to detect `EICAR`. Update the code in your `__init__.py` file with the changes from one of these examples.

The first way, is the simplest design and is used in [`eicar.py`](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/eicar.py):

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

Here's another way, this time comparing the SHA-256 of the EICAR test file with a known-bad hash:

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

### Develop a Staking Strategy

At a minimum, Microengines are responsible for: (a) detecting malicious files, (b) rendering assertions with NCT staked on them.

Staking logic is implemented in the Microengine's `bid` function.

By default, all assertions are placed with the minimum stake permitted by the community a Microengine is joined to.

Check back soon for an exploration of various staking strategies.

## Finalizing & Testing Your Engine

`cookiecutter` customizes `engine-template` only so far - there are a handful of items you'll need to fill out yourself. We've already covered the major items above, but you'll want to do a quick search for `CUSTOMIZE_HERE` to ensure all customization have been made.

Once everything is in place, let's test our engine:

[Test Linux-based Engines →](/testing-linux/)

[Test Windows-based Engines →](/testing-windows/)

## Next Steps

Implementing scan logic directly in the Scanner class is difficult to manage and scale. Instead, you'll likely want your Microengine class to call out to an external binary or service that holds the actual scan logic.

[Next, we'll wrap ClamAV into a Microengine →](/microengines-scratch-to-clamav/)