# Windows 기반 엔진 테스트

이 페이지에서는 마이크로엔진 디렉터리의 이름으로 `microengine-mywindowsengine`을 사용합니다. 귀하의 테스트에서는 귀하의 마이크로엔진 디렉터리의 이름을 대신 사용하시면 됩니다. 또한, 이 설명에서는 명령을 더 쉽게 읽을 수 있도록 PowerShell 명령 프롬프트를 `PS >`로 단축하였습니다. 실제 PowerShell 명령 프롬프트는 다음과 비슷합니다: `(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine>`. Linux 명령 프롬프트와 비슷하게 `$`로 단축하였지만, 실제 명령 프롬프트는 `$`의 왼쪽에 더 많은 텍스트가 있을 겁니다.

## Unit Testing

`tox`를 사용해서 마이크로엔진을 테스트합니다. `tox`는 사용자가 `tests/scan_test.py`에 추가한 유닛 테스트를 실행합니다.

가상 환경이 활성화된 파워셸 창을 통하여 마이크로엔진의 기본 디렉터리에서 `tox` 명령을 실행합니다.

```powershell
PS > tox
```

출력 결과는 다음과 비슷합니다.

```powershell
GLOB sdist-make: C:\Users\user\microengine-mywindowsengine\setup.py
py35 create: C:\Users\user\microengine-mywindowsengine\.tox\py35
py35 installdeps: -rrequirements.txt
py35 inst: C:\Users\user\microengine-mywindowsengine\.tox\dist\polyswarm_mywindowsengine-0.1.zip
py35 installed: aiodns==1.1.1,aiohttp==2.3.1,aioresponses==0.5.0,async-generator==1.10,async-timeout==3.0.1,asynctest==0.12.2,atomicwrites==1.2.1,attrdict==2.0.0,attrs==18.2.0,base58==0.2.5,certifi==2018.11.29,chardet==3.0.4,clamd==1.0.2,click==6.7,colorama==0.4.1,coverage==4.5.1,cytoolz==0.9.0.1,eth-abi==1.3.0,eth-account==0.3.0,eth-hash==0.2.0,eth-keyfile==0.5.1,eth-keys==0.2.0b3,eth-rlp==0.1.2,eth-typing==2.0.0,eth-utils==1.4.0,hexbytes==0.1.0,hypothesis==3.82.1,idna==2.7,lru-dict==1.1.6,malwarerepoclient==0.1,more-itertools==4.3.0,multidict==4.5.2,parsimonious==0.8.1,pathlib2==2.3.3,pluggy==0.8.0,polyswarm-client==0.2.0,polyswarm-mywindowsengine==0.1,py==1.7.0,pycares==2.3.0,pycryptodome==3.7.2,pypiwin32==223,pytest==3.9.2,pytest-asyncio==0.9.0,pytest-cov==2.6.0,pytest-timeout==1.3.2,python-json-logger==0.1.9,python-magic==0.4.15,pywin32==224,requests==2.19.1,rlp==1.0.3,six==1.11.0,toml==0.10.0,toolz==0.9.0,tox==3.4.0,urllib3==1.23,virtualenv==16.1.0,web3==4.6.0,websockets==6.0,yara-python==3.7.0,yarl==1.2.6
py35 run-test-pre: PYTHONHASHSEED='432'
py35 runtests: commands[0] | pytest -s
================================================= test session starts =================================================
platform win32 -- Python 3.5.4, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('C:\\Users\\user\\microengine-mywindowsengine\\.hypothesis\\examples')
rootdir: C:\Users\user\microengine-mywindowsengine, inifile:
plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
collected 1 item

tests\scan_test.py .

================================================== warnings summary ===================================================
c:\users\user\microengine-mywindowsengine\.tox\py35\lib\site-packages\eth_utils\applicators.py:32: DeprecationWarning: combine_argument_formatters(formatter1, formatter2)([item1, item2])has been deprecated and will be removed in a subsequent major version release of the eth-utils library. Update your calls to use apply_formatters_to_sequence([formatter1, formatter2], [item1, item2]) instead.
  "combine_argument_formatters(formatter1, formatter2)([item1, item2])"

-- Docs: https://docs.pytest.org/en/latest/warnings.html
======================================== 1 passed, 1 warnings in 0.52 seconds =========================================
_______________________________________________________ summary _______________________________________________________
  py35: commands succeeded
  congratulations :)
```

`combine_argument_formatters` 경고는 무시하셔도 안전합니다.

## Integration Testing

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> Windows 기반 엔진에서 통합 테스트를 수행하는 것은 현재 VirtualBox 구성에서만 지원됩니다. 자세한 정보는 <a href="/development-environment-windows/">Windows 개발 환경</a>을 참조하세요.
  </p>
</div>

Windows 기반 엔진의 통합 테스트 시 두 개의 가상 머신이 필요합니다(VM / 게스트).

1. Windows 기반 엔진을 실행하기 위한 Windows 게스트(이미 만들었습니다).
2. 로컬 PolySwarm 테스트넷을 구축하기 위한 Linux 게스트(지금 만들 것입니다).

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    The recommendations presented here are hard-won.
    여기에 제시된 권장 사항을 정확히 사용하여 테스트하실 것을 강력히 권장합니다.
    Using any other configuration will make it difficult for us to provide you with support.
  </p>
</div>

### Linux 게스트 만들기

#### 가상 머신 만들기

다음 매개 변수를 사용해서 Linux VM을 만듭니다.

* 이름: `polyswarm_lin`
* 종류: Linux
* 버전: Ubuntu (64비트)
* RAM: 8GB 이상
* CPU: 코어 4개 이상
* video memory: 128MB
* disk space: 50GB+

Use the default setting for all other options. 특히, 3D 가속을 활성화하지 마십시오.

일반적으로, Linux VM에 이용 가능한 RAM과 CPU 자원을 추가로 제공하면 테스트넷의 성능이 향상됩니다.

#### Xubuntu 18.04 amd64 설치

* [Xubuntu 18.04 amd64 ISO 다운로드](https://xubuntu.org/release/18-04/)

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> VirtualBox 게스트의 경우 Ubuntu 대신 Xubuntu를 사용하실 것을 강력히 권장합니다. Ubuntu는 많은 시각적 렉 문제가 있고 VirtualBox 도구가 설치된 경우 시각적으로 완전히 멈춰버리는 경향이 있습니다.
  </p>
</div>

다운로드한 ISO를 사용해서 VM에 Xubuntu를 설치합니다.

#### (선택 사항) VirtualBox 게스트 확장 설치

게스트 확장은 게스트 및 호스트 사이에 공유 클립보드 / 복사 & 붙여넣기 기능을 사용하기 위하여 필요합니다.

[Refer to VirtualBox's manual](https://www.virtualbox.org/manual/ch04.html).

### 게스트 간 네트워크 구성

Linux 및 Windows VM이 서로 통신할 때 사용할 수 있는 '내부' 네트워크를 설정해야 합니다.

작업을 시작하기 전에 Linux 및 Windows 게스트를 모두 종료합니다.

Windows 호스트에서 PowerShell을 열고 VirtualBox 설치 디렉터리로 변경합니다.

```powershell
PS > pushd $Env:Programfiles\Oracle\VirtualBox
```

다음과 비슷한 명령 프롬프트가 표시되어야 합니다.

```powershell
PS C:\Program Files\Oracle\VirtualBox>
```

#### 내부 PolySwarm 네트워크 만들기

각 VM에 전용 PolySwarm 내부 네트워크를 생성하여 할당합니다.

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> 이 명령은 VM의 5번 네트워크 어댑터를 다시 구성합니다. (가능성은 적지만) 이미 이 어댑터를 사용하고 있는 경우 명령에서 번호를 변경합니다.
  </p>
</div>

```powershell
PS > .\VBoxManage.exe modifyvm "polyswarm_win" --nic5 intnet
PS > .\VBoxManage.exe modifyvm "polyswarm_win" --intnet5 "polyswarm_net"
PS > .\VBoxManage.exe modifyvm "polyswarm_lin" --nic5 intnet
PS > .\VBoxManage.exe modifyvm "polyswarm_lin" --intnet5 "polyswarm_net"
```

<div class="m-flag">
  <p>
    <strong>정보:</strong> VirtualBox의 내부 네트워크에 대한 자세한 정보는 <a href="https://www.virtualbox.org/manual/ch06.html#network_internal">공식 설명서</a>를 참조하세요.
  </p>
</div>

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong>
 VM 설정 또는 VM 안에서 '어댑터 #5'라고 표시되지 않습니다.
    단지 VM에 2개 이상의 활성화된 네트워크 어댑터가 있다고만 표시됩니다. "polyswarm_net"를 어댑터 5에 추가하면 VM에서 가장 번호가 높은 네트워크 인터페이스가 되므로 더 쉽게 찾을 수 있습니다.
  </p>
</div>

#### 고정 IP 주소로 가상 머신 구성하기

`polyswarm_lin` VM을 부팅하고 네트워크 설정을 편집하여 다음과 같이 고정 IPv4 정보를 새로운 어댑터에 할당합니다.

* 주소: `10.10.42.101`
* 넷마스크: `255.255.255.0`
* 게이트웨이: `10.10.42.1`

이 설정을 어떤 네트워크 인터페이스에 적용해야 할지 확실치 않으면 `ifconfig -a` 명령을 실행합니다. 그러면, `enp0s`로 시작하는 여러 개의 네트워크 인터페이스가 출력됩니다. 이 접두사 다음에 나오는 번호가 가장 큰 인터페이스가 일반적으로 수정할 대상입니다.

`polyswarm_win` VM을 부팅하고 네트워크 설정을 편집하여 이 고정 IPv4 설정에 맞게 새로운 어댑터를 구성합니다.

* 주소: `10.10.42.102`
* netmask: `255.255.255.0`
* gateway: `10.10.42.1`

이 설정을 어떤 네트워크 인터페이스에 적용해야 할지 확실치 않으면 `ipconfig /all` 명령을 실행합니다. 그러면, `Ethernet adapter Ethernet`으로 시작되는 여러 개의 네트워크 인터페이스가 출력됩니다. The interface with the largest number after that prefix is usually the one you want to modify.

#### `polyswarmd` DNS 확인을 위한 Windows VM 구성하기

마지막으로, Linux VM이 `polyswarmd`를 호스팅하고 있다는 것을 Windows VM이 알게 해야 합니다. 관리자 권한으로 Notepad의 인스턴스를 열고 `C:\Windows\System32\Drivers\etc\hosts`의 밑에 `polyswarmd`를 추가합니다.

    # Copyright (c) 1993-2009 Microsoft Corp.
    #
    # This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
    #
    # This file contains the mappings of IP addresses to host names. Each
    # entry should be kept on an individual line. The IP address should
    # be placed in the first column followed by the corresponding host name.
    # The IP address and the host name should be separated by at least one
    # space.
    #
    # Additionally, comments (such as these) may be inserted on individual
    # lines or following the machine name denoted by a '#' symbol.
    #
    # For example:
    #
    #      102.54.94.97     rhino.acme.com          # source server
    #       38.25.63.10     x.acme.com              # x client host
    
    # localhost name resolution is handled within DNS itself.
    #   127.0.0.1       localhost
    #   ::1             localhost
    
    10.10.42.101 polyswarmd
    

#### 구성 확인

마지막으로, Windows가 `polyswarmd`의 주소를 확인해서 Linux VM을 찾고 해당 VM에 접속할 수 있는지 확인합니다. 먼저 다음과 같이 DNS 테스트를 수행합니다.

```powershell
PS > Resolve-DnsName -name polyswarmd
```

출력 결과는 다음과 같아야 합니다.

```powershell
Name Type TTL Section IPAddress
---- ---- --- ------- ---------
polyswarmd A 86400 Answer 10.10.42.101
```

다음으로, 다음과 같이 핑 테스트를 수행합니다.

```powershell
PS > ping polyswarmd
```

The output should look like this:

```powershell
Pinging polyswarmd [10.10.42.101] with 32 bytes of data:
Reply from 10.10.42.101: bytes=32 time<1ms TTL=64
```

출력 결과가 같으면, 모든 항목이 제대로 설정된 것입니다. 계속 진행합니다.

### 로컬 테스트넷을 호스팅하도록 Linux VM 구성하기

#### Install Docker

PolySwarm 마켓플레이스의 테스트 버전은 Docker를 사용해서 구축되었습니다. 이를 사용하려면 Docker-CE(기본) 및 Docker Compose를 설치해야 합니다. 최신 Docker가 설치되지 않은 경우 [지금 Docker를 설치](https://www.docker.com/community-edition)하시기 바랍니다.

Xubuntu에서:

```bash
$ sudo apt-get update && sudo apt-get install -y curl
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ chmod +x get-docker.sh
$ ./get-docker.sh
$ sudo usermod -aG docker $USER
```

로그아웃하고 다시 로그인합니다.

설치 후 다음 명령을 실행하여 작동하는지 확인합니다.

```bash
$ docker ps
```

기대되는 출력 결과:

    CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
    

그리고, [`docker-compose`](https://docs.docker.com/compose/install/)를 설치합니다.

On Xubuntu:

```bash
$ curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o docker-compose
$ sudo mv docker-compose /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
```

설치 후 작동하는지 확인합니다.

```bash
$ docker-compose -v
```

다음 중 하나가 출력되어야 합니다. `docker-compose version 1.21.1, build 5a3f1a3`

<div class="m-flag">
  <p>
    <strong>정보:</strong> docker 또는 docker-compose 명령 실행 시 권한 오류가 발생하면 <a href="https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user">docker 권한을 취득할 수 있도록 사용자 계정을 구성합니다</a>.
  </p>
</div>

#### Install Git

일부 소스 코드 저장소가 필요합니다. Git을 사용하는 것이 가장 쉽습니다. 개발 환경용으로 [Git을 설치](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)하시기 바랍니다.

Xubuntu 18.04에서:

```bash
$ sudo apt update && sudo apt install -y git
```

#### `orchestration` 다운로드

PolySwarm [`orchestration`](https://github.com/polyswarm/orchestration) 프로젝트를 사용하여 개발 테스트넷을 실행합니다. 내부적으로도 똑같은 프로젝트를 사용하여 종단 간(통합) 테스트를 수행합니다.

`orchestration`을 복제합니다.

```bash
$ git clone https://github.com/polyswarm/orchestration
```

### Test Your Engine

여기서 VM들을 약간 전환해보겠습니다. 먼저 Linux VM에서 테스트넷을 시작합니다. 그 다음 Windows VM에서 마이크로엔진을 시작합니다. 마지막으로, Linux VM에서 홍보대사를 시작합니다.

#### Linux VM: 테스트넷 실행

Linux VM에서 테스트넷의 서브세트를 구축하여 기본으로 제공된 `microengine`(사용자의 것으로 대체함) 및 `ambassador` 서비스를 당분간 생략합니다(나중에 시작함). 이를 위해 새로운 터미널 창에서 다음 명령을 실행합니다.

```bash
$ cd orchestration
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

It will take several minutes for `polyswarmd` to become available. 이 작업을 수행하는 동안 `Problem with dial... dial tcp connection refused.` 및 `chain for config not available in consul yet`와 같은 많은 메시지가 표시됩니다. 테스트넷을 초기화하는 동안 이러한 오류는 정상이므로 계속 기다립니다.

Once `polyswarmd` is available, it will begin serving responses to clients, e.g.:

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

이제 안전하게 다음 단계로 이동할 수 있습니다.

#### Windows VM: `polyswarmd`에 대한 연결 테스트

Windows VM에서 `polyswarmd`를 이용할 수 있고 마이크로엔진에 응답할 준비가 되어 있는지 확인합니다. 이를 위해 PowerShell에서 다음 명령을 실행합니다.

```powershell
PS > curl -UseBasicParsing http://polyswarmd:31337/status
```

출력 결과는 다음과 같아야 합니다.

```powershell
StatusCode : 200
StatusDescription : OK
Content : {"result":{"home":{"block":189,"reachable":true,"syncing":false},"ipfs":{"reachable":true},"side":{
"block":191,"reachable":true,"syncing":false}},"status":"OK"}
...
```

찾아볼 항목 중 가장 중요한 것은 `"status":"OK"`입니다.

#### Windows VM: `balancemanager` & 사용자의 엔진 실행

새로운 PowerShell 창을 시작하고 가상 환경을 활성화합니다. 그 다음 마이크로엔진의 디렉터리로 변경합니다.

마이크로엔진의 디렉터리에서 마이크로엔진의 필수 구성 요소 및 마이크로엔진 자체를 설치합니다.

```powershell
PS > pip install -r requirements.txt
PS > pip install .
```

`balancemanager`는 (`polyswarm-client`에 기반) 유틸리티로서 모든 트랜잭션이 발생하는 로컬 테스트넷의 사이드체인에서 (모의) PolySwarm Nectar(NCT)의 균형을 유지합니다.

같은 PowerShell 창에서 다음과 같이 `balancemanager`를 실행합니다.

```powershell
PS > balancemanager maintain --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport 100000 500000
```

다음과 비슷한 결과가 출력됩니다.

```powershell
INFO:root:2018-12-06 16:55:30,800 Logging in text format.
INFO:balancemanager.__main__:2018-12-06 16:55:30,815 Maintaining the minimum balance by depositing 500000.0 when it falls below 100000.0
INFO:polyswarmclient:2018-12-06 16:55:31,440 Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:polyswarmclient:2018-12-06 16:55:32,050 Received connected on chain home: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:55:32,050 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:55:32,050 Received block on chain home: {'number': 18182}
INFO:polyswarmclient:2018-12-06 16:55:32,096 Received connected on chain side: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:55:32,096 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:55:33,034 Received block on chain home: {'number': 18183}
INFO:polyswarmclient:2018-12-06 16:55:33,080 Received block on chain side: {'number': 18206}
```

`Received block on chain`이라는 메시지가 출력되기 시작하면 마이크로엔진을 실행할 준비가 된 것입니다.

새로운 PowerShell 창을 시작하고 가상 환경을 활성화합니다. Then change into your Microengine's directory.

다음 명령과 비슷한 명령을 사용하여 마이크로엔진을 실행합니다. 마이크로엔진의 패키지 디렉터리 이름과 일치하도록 `--backend` 인수의 값을 업데이트합니다(예: `src/`의 디렉터리).

```powershell
PS > microengine --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport --testing 2 --backend acme_myeicarengine
```

It will print output similar to the following:

```powershell
INFO:root:2018-12-06 16:56:20,674 Logging in text format.
INFO:polyswarmclient:2018-12-06 16:56:21,299 Using account: 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
INFO:polyswarmclient:2018-12-06 16:56:21,690 Received connected on chain side: {'start_time': '1544126035.507124'}
INFO:root:2018-12-06 16:56:21,690 Connected to event socket at: 1544126035.507124
INFO:polyswarmclient:2018-12-06 16:56:22,691 Received block on chain side: {'number': 18255}
...
INFO:polyswarmclient:2018-12-06 16:56:44,205 Received block on chain side: {'number': 18277}
INFO:polyswarmclient:2018-12-06 16:56:44,283 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18297', 'uri': 'QmVoLQJ2nm4V6XiZXC9vEUrCaTHdkXS7y3crztZ5HwC9iK', 'guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'amount': '62500000000000000'}
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:44,283 Testing mode, 1 bounties remaining
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:44,455 Responding to bounty: 48dd5360-47a3-4e12-a975-eb30fed5cc22
INFO:polyswarmclient:2018-12-06 16:56:45,237 Received block on chain side: {'number': 18278}
INFO:polyswarmclient:2018-12-06 16:56:46,393 Received block on chain side: {'number': 18279}
INFO:polyswarmclient.events:2018-12-06 16:56:46,440 OnNewBountyCallback callback results: [[{'bounty_guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'mask': [True], 'bid': '62500000000000000', 'commitment': '44296088244268214239924675885675264686302131561550908677050134822720003742540', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}]]
INFO:polyswarmclient:2018-12-06 16:56:46,456 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18299', 'uri': 'QmVjWbqv8aXEPE53vDYS9r3wG7odJjrHXf7ci1xfLyNAEU', 'guid': '40862925-3e00-41b2-a946-365135d87070', 'amount': '62500000000000000'}
INFO:polyswarmclient:2018-12-06 16:56:46,456 Received assertion on chain side: {'bounty_guid': '48dd5360-47a3-4e12-a975-eb30fed5cc22', 'mask': [True], 'bid': '62500000000000000', 'commitment': '44296088244268214239924675885675264686302131561550908677050134822720003742540', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:46,456 Testing mode, 0 bounties remaining
INFO:polyswarmclient.abstractmicroengine:2018-12-06 16:56:46,643 Responding to bounty: 40862925-3e00-41b2-a946-365135d87070
INFO:polyswarmclient:2018-12-06 16:56:47,409 Received block on chain side: {'number': 18280}
INFO:polyswarmclient.events:2018-12-06 16:56:48,222 OnNewBountyCallback callback results: [[{'bounty_guid': '40862925-3e00-41b2-a946-365135d87070', 'mask': [True], 'bid': '62500000000000000', 'commitment': '26135711486835189252810507112407250051211627558503078858520125577864847775053', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}]]
INFO:polyswarmclient:2018-12-06 16:56:48,440 Received block on chain side: {'number': 18281}
INFO:polyswarmclient:2018-12-06 16:56:48,503 Received bounty on chain side: {'author': '0x4B1867c484871926109E3C47668d5C0938CA3527', 'expiration': '18301', 'uri': 'QmVoLQJ2nm4V6XiZXC9vEUrCaTHdkXS7y3crztZ5HwC9iK', 'guid': 'b41ef0f8-039f-4448-aadf-4d4135cdd94b', 'amount': '62500000000000000'}
INFO:polyswarmclient:2018-12-06 16:56:48,503 Received assertion on chain side: {'bounty_guid': '40862925-3e00-41b2-a946-365135d87070', 'mask': [True], 'bid': '62500000000000000', 'commitment': '26135711486835189252810507112407250051211627558503078858520125577864847775053', 'author': '0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8', 'index': 0}
WARNING:polyswarmclient.abstractmicroengine:2018-12-06 16:56:48,503 Received new bounty, but finished with testing mode
```

`--testing 2`로 실행한다는 것은 마이크로엔진이 2개의 현상금 공고에 응답하고 스스로 종료함으로써 추가적인 현상금 공고에는 응답을 거부한다는 뜻입니다. 테스트에서 더 많은 현상금 공고를 처리하고 싶으면 이 번호를 변경하시면 됩니다.

하지만, 홍보대사가 테스트넷에 현상금 공고를 전송해야만 마이크로엔진이 현상금 공고를 처리할 수 있습니다.

#### Linux VM: 홍보대사 실행

이제 Linux VM에서 `ambassador`를 실행합니다. 마이크로엔진은 홍보대사가 테스트넷에 게시한 현상금 공고를 처리하게 됩니다. 새로운 터미널을 시작하고 다음 명령을 실행합니다.

```bash
$ cd orchestration
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

작업 시작 직후 마이크로엔진이 현상금 공고를 처리할 때 마이크로엔진의 PowerShell 창에 메시지가 표시됩니다.

### 작업 완료

축하합니다!

이제 Windows 기반 엔진이 Linux VM에 호스팅된 로컬 테스트넷에 게시된 현상금 공고에 응답할 것입니다.

스스로 종료할 때까지 마이크로엔진이 실행되도록 합니다.

원하는 대로 작업하고 있는지 엔진이 출력하는 내용을 살펴보세요 :)