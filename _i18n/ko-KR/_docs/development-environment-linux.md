## 시스템 요구사항

* x86-64 CPU
* 8GB RAM

다음 설명은 Xubuntu 18.04 amd64에서 개발하고 테스트한 내용을 바탕으로 합니다.

## Docker 설치

작업을 쉽게 진행할 수 있도록 최대한 많은 곳에서 Docker가 활용되었습니다.

Docker-CE(기본) 및 Docker Compose를 설치해야 합니다. 최신 Docker가 설치되지 않은 경우 [지금 Docker를 설치](https://docs.docker.com/install/)하시기 바랍니다.

설치 후 실행하여 작동하는지 확인합니다.

```bash
$ docker ps
```

기대되는 출력 결과:

    CONTAINER ID IMAGE COMMAND CREATED STATUS PORTS NAMES
    

그 다음, [`docker-compose`를 설치](https://docs.docker.com/compose/install/)합니다.

설치 후 실행하여 작동하는지 확인합니다.

```bash
$ docker-compose -v
```

다음 중 하나가 출력되어야 합니다: `docker-compose version 1.21.1, build 5a3f1a3`

Docker를 설치한 후, `sudo` 없이 `docker` 명령을 쉽게 실행할 수 있도록 `docker` 그룹에 사용자를 추가하실 것을 권장합니다.

```bash
$ sudo usermod -aG docker ${USER}
```

변경 사항을 적용하려면 다시 부팅해야 합니다.

## Git 설치

일부 소스 코드 저장소가 필요합니다. Git을 사용하는 것이 가장 쉽습니다. 개발 환경용으로 [Git을 설치](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)하시기 바랍니다.

## Python & PIP 설치

PolySwarm 개발 시 Python 3.5.4 이상 버전이 필요합니다. 개발 플랫폼용으로 [Python](https://www.python.org/downloads/) 및 [PIP](https://pip.pypa.io/en/stable/installing/)를 설치하시기 바랍니다.

## (선택 사항) 가상 환경 설치 (virtualenv)

다른 용도로 가상 머신을 사용하실 계획이라면 시스템 전체에서 Python 패키지를 원활하게 관리할 수 있도록 PolySwarm virtualenv를 생성하실 것을 권장합니다.

```bash
pip install virtualenv
cd ~
virtualenv polyswarmvenv -p <PATH TO PYTHON 3.5.4 OR ABOVE>
source polyswarmvenv/bin/activate
```

## `polyswarm-client` 라이브러리 설치

<div class="m-flag">
  <p>
    <strong>정보:</strong> virtualenv를 사용하는 경우 (상기 내용 참조), polyswarm-client를 설치하기 전에 활성화해야 합니다.
  </p>
</div>

`polyswarm-client` 라이브러리는 간단하게 컴파일 & 설치할 수 있습니다.

먼저 Python 3 헤더 / 빌드 필수 요소를 설치합니다.

Ubuntu에서 다음과 같이 작업합니다.

    $ sudo apt install python3-dev
    

다음:

```bash
pip install polyswarm-client
```

## 설치 확인

이제 작업 개발 환경이 준비되었습니다!

확인을 위해 `polyswarmclient`를 불러오기만 하면 됩니다.

```bash
$ python
...
>>> import polyswarmclient
>>>
```

`polyswarmclient`를 문제 없이 불러올 수 있어야 합니다.

다음으로, EICAR 테스트 파일을 탐지할 수 있는 PolySwarm 마이크로엔진을 구축하는 방법에 대해 설명드리겠습니다.

["Hello World" 마이크로엔진 만들기 →](/microengines-scratch-to-eicar/)