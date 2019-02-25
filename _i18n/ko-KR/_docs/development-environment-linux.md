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

## Python 및 PIP 설치

PolySwarm development requires Python 3.5.4 or above. Please install [Python](https://www.python.org/downloads/) and [PIP](https://pip.pypa.io/en/stable/installing/) for your development platform.

## (Optional) Set up a Virtual Environment (virtualenv)

If you plan to use this machine for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
pip install virtualenv
cd ~
virtualenv polyswarmvenv -p <PATH TO PYTHON 3.5.4 OR ABOVE>
source polyswarmvenv/bin/activate
```

## Install `polyswarm-client` Libraries

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    If you're using a virtualenv (see above), ensure that you activate it before installing polyswarm-client.
  </p>
</div>

Compiling & installing `polyswarm-client` libraries is simple.

First, install Python 3 headers / build requirements.

On Ubuntu, this is achieved with:

    $ sudo apt install python3-dev
    

Next:

```bash
pip install polyswarm-client
```

## Verify Installation

You should now have a working development environment!

To verify, simply try importing `polyswarmclient`:

```bash
$ python
...
>>> import polyswarmclient
>>>
```

You should be able to import `polyswarmclient` without issue.

Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file.

[Make a "Hello World" Microengine →](/microengines-scratch-to-eicar/)