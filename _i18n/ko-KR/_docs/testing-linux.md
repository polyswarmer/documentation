# Linux 기반 엔진 테스트

## 유닛 테스트

마이크로엔진의 유닛 테스트 절차는 간단합니다.

1. 마이크로엔진의 Docker 이미지를 빌드합니다
2. `docker-compose`를 실행하여 `tox`를 사용해 `tests/scan_test.py`에서 테스트 로직을 실행합니다

프로젝트 디렉터리의 루트에서 다음 명령을 실행합니다.

마이크로엔진을 Docker 이미지로 빌드합니다.

```bash
$ docker build -t ${PWD##*/} -f docker/Dockerfile .
```

이를 통해 디렉터리 이름으로 표시된 Docker 이미지(예: `microengine-myeicarengine`)가 생성됩니다.

이를 통해 디렉터리 이름으로 표시된 Docker 이미지(예: <0>microengine-myeicarengine</0>)가 생성됩니다.

```bash
$ docker-compose -f docker/test-unit.yml up
```

마이크로엔진이 EICAR을 탐지할 수 있고 "not a malicious file" 문자열에 긍정 오류를 생산하지 않을 경우 이 기본 유닛 테스트를 통과해서 다음과 같은 내용이 표시되어야 합니다.

```bash
$ docker-compose -f docker/test-unit.yml up
Recreating docker_test_engine_mylinuxengine_1_a9d540dc7394 ... done
Attaching to docker_test_engine_mylinuxengine_1_a9d540dc7394
...
test_engine_mylinuxengine_1_a9d540dc7394 | py35 run-test-pre: PYTHONHASHSEED='1705267802'
test_engine_mylinuxengine_1_a9d540dc7394 | py35 runtests: commands[0] | pytest -s
test_engine_mylinuxengine_1_a9d540dc7394 | ============================= test session starts ==============================
test_engine_mylinuxengine_1_a9d540dc7394 | platform linux -- Python 3.5.6, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
test_engine_mylinuxengine_1_a9d540dc7394 | hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/usr/src/app/.hypothesis/examples')
test_engine_mylinuxengine_1_a9d540dc7394 | rootdir: /usr/src/app, inifile:
test_engine_mylinuxengine_1_a9d540dc7394 | plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
test_engine_mylinuxengine_1_a9d540dc7394 | collected 36 items
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | tests/scan_test.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bloom.py ......
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bounties.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_client.py ............
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_corpus.py ..
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_events.py ..............
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | ========================== 36 passed in 39.42 seconds ==========================
test_engine_mylinuxengine_1_a9d540dc7394 | ___________________________________ summary ____________________________________
test_engine_mylinuxengine_1_a9d540dc7394 |   py35: commands succeeded
test_engine_mylinuxengine_1_a9d540dc7394 |   congratulations :)
```

물론 이 테스트는 제한이 많습니다. 자신의 마이크로엔진에 맞게 `scan_test.py`에서 테스트를 확대해보는 것이 좋습니다.

## 통합 테스트

PolySwarm 마켓플레이스는 이더리움 & IPFS 노드, 계약, 마이크로엔진, 홍보대사, 중재자, 아티팩트 등 수많은 참가자와 기술로 구성되어 있습니다. 따라서, 하나의 구성 요소를 테스트하려고 해도 종종 다른 모든 구성 요소가 필요합니다.

`orchestration` 프로젝트로 쉽고 원활하게 완전한 테스트넷을 구축할 수 있습니다. 이름에서 알 수 있듯이 `orchestration`은 오케스트라를 지휘하듯 필요한 모든 구성 요소를 사용하여 로컬 개발 머신에서 PolySwarm 마켓플레이스의 전체 환경을 구축하고 해체합니다.

`microengine-myeicarengine` 디렉터리에 인접한 `orchestration`을 복제합니다.

```bash
$ git clone https://github.com/polyswarm/orchestration
```

### (선택 사항) 완벽하게 작동하는 테스트넷 미리 보기

어떤 모습을 *갖춰야 하는지* 감을 잡을 수 있도록 완벽하게 작동하는 테스트넷을 간단히 구축해보겠습니다.

복제된 `orchestration` 디렉터리:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up
```

각 서비스에서 출력되는 내용은 다음과 같습니다.

1. `homechain`: 테스트넷의 '홈체인'을 실행하는 [geth](https://github.com/ethereum/go-ethereum) 노드. 체인-분할 설계에 대한 설명은 [체인: 홈 vs 사이드](/#chains-home-vs-side)를 참조하세요.
2. `sidechain`: 테스트넷의 "사이드체인"을 실행하는 `geth` 인스턴스.
3. `ipfs`: 개발 테스트넷에 모든 아티팩트를 호스팅하는 IPFS 노드.
4. `polyswarmd`: `homechain`, `sidechain` 및 `ipfs`가 제공하는 서비스에 편리하게 액세스하게 해주는 PolySwarm 데몬.
5. `contracts`: PolySwarm Nectar(NCT) 및 `BountyRegistry` 계약을 개발 테스트넷에 보관 & 배포.
6. `ambassador`: [EICAR 파일](https://en.wikipedia.org/wiki/EICAR_test_file)과 EICAR이 아닌 파일에 현상금을 거는 모의 홍보대사(`polyswarm-client`가 제공).
7. `arbiter`: '접수된' 아티팩트에 대하여 의견을 제시하고 사실 검증을 판단하는 모의 중재자(`polyswarm-client`가 제공).
8. `microengine`: '접수된' 아티팩트를 검사하고 주장을 제시하는 모의 마이크로엔진(`polyswarm-client`가 제공).

화면에 표시된 로그를 스크롤해서 탐색하며 각 구성 요소가 어떤 작업을 하는지 살펴보시기 바랍니다. 적어도 5분 이상 실행되도록 합니다. 계약을 배포하는 데는 시간이 걸릴 수 있습니다. 그리고 재미있는 일들이 시작됩니다 :)

로그가 충분히 출력되면 `Ctrl-C`를 눌러서 개발 테스트넷을 중단시킵니다.

### 엔진 테스트

테스트넷의 서브세트를 구축하여 기본으로 제공된 `microengine`(사용자의 것으로 대체함) 및 `ambassador` 서비스를 생략합니다.

복제된 `orchestration` 프로젝트:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

`polyswarmd`를 이용할 수 있을 때까지 몇 분 정도 소요됩니다. `polyswarmd`를 이용할 수 있게 되면, 다음과 같이 클라이언트에 응답을 제공하기 시작합니다.

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

다음으로, 마이크로엔진 디렉터리의 두 번째 터미널 창에서 사용자의 마이크로엔진을 구축합니다.

```bash
$ docker-compose -f docker/test-integration.yml up
```

마지막으로, `orchestration` 디렉터리의 세 번째 터미널 창에서 사용자의 마이크로엔진을 위한 아티팩트를 몇 개 도입합니다.

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

세 개의 터미널 창의 로그를 모두 확인합니다. 마이크로엔진이 홍보대사의 현상금에 응답하고 있어야 합니다!

엔진에 변경을 가할 경우 Docker 이미지를 다시 빌드하고 `ambassador` 서비스를 다시 실행해서 EICAR/비-EICAR 아티팩트의 새로운 쌍을 투입함으로써 간단하게 변경 사항을 테스트할 수 있습니다. 작업을 반복하는 동안 테스트넷의 나머지 부분은 계속 실행되도록 놔둘 수 있습니다.