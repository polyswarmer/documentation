## (권장) VirtualBox 게스트 구성

현재 유일하게 완벽히 지원되는 구성은 VirtualBox 게스트 안에서 Windows 기반 엔진을 개발하는 경우입니다.

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> 여기에 제시된 권장 사항은 어렵습니다. 여기에 제시된 매개 변수들을 정확히 사용하여 테스트하실 것을 강력히 권장합니다. 다른 구성을 사용하실 경우 지원을 제공해드리기 어려울 수 있습니다.
  </p>
</div>

### System Requirements

Windows 기반 엔진 개발 시 개발 호스트용으로 특수한 시스템 요구 사항이 필요합니다.

- Windows 10 ( Windows 10 Pro, 1809 버전에서 테스트했습니다)
- BIOS에서 VT-x 지원 및 활성화
- 16GB 이상의 RAM
- 4개 이상의 CPU 코어
- 100GB 이상의 디스크 공간

VirtualBox가 사용됩니다. **VirtualBox는 하이퍼바이저를 단독으로 소유해야 합니다**. 즉, 다음 기능은 수행할 수 없습니다.

- Hyper-V
- Windows Credential Guard
- Windows Device Guard
- VMWare Workstation / Player
- 하이퍼바이저 확장을 사용하는 다른 제품

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> 중첩 가상화는 현재 지원되는 구성이 아닙니다.
  </p>
  
  <p>
    여기에 제시된 설명은 사용자의 호스트 Windows 설치가 '베어 메탈(bare metal)'에서 실행되고 있다고 가정합니다. 하이퍼바이저를 사용한 개발(예: AWS)에 대한 별도의 설명이 곧 추가될 예정입니다!
  </p>
</div>

### 기본 요구 사항

- [VirtualBox를 다운로드 및 설치합니다](https://www.virtualbox.org/wiki/Downloads). VirtualBox 5.2.22에서 테스트했습니다.
- [Windows 10 Pro ISO를 다운로드합니다](https://www.microsoft.com/en-us/software-download/windows10ISO). Media Creation Tool을 사용해서 .ISO 이미지를 만듭니다. Windows 10 Pro, 빌드 10240에서 테스트했습니다.

### Windows 게스트 만들기

VirtualBox에서 다음 매개 변수를 사용해서 Windows VM을 만듭니다.

- 이름: `polyswarm_win`
- 종류: Microsoft Windows
- 버전 Windows 10 (64비트)
- RAM: 4GB 이상
- CPU: 코어 2개 이상
- 비디오 메모리: 128MB
- 디스크 공간: 50GB 이상

다른 옵션에는 기본 설정을 사용합니다. 특히, **3D 가속을 활성화하지 마세요**.

### Windows 10 설치

다운로드한 ISO를 사용해서 VM에 Windows를 설치합니다.

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> VirtualBox VM에서 Windows 업데이트를 수행하는 것은 권장하지 않습니다. VM이 부팅할 수 없는 상태가 될 수 있습니다. VM에서 Windows를 설치한 후 즉시 <a href="https://www.thewindowsclub.com/turn-off-windows-update-in-windows-10">Windows 업데이트를 비활성화할 것</a>을 권장합니다.
  </p>
</div>

### VirtualBox 게스트 확장 설치

게스트 확장은 게스트 및 호스트 사이에 공유 클립보드 / 복사 & 붙여넣기 기능을 사용하기 위하여 필요합니다.

[VirtualBox 설명서를 참조하세요](https://www.virtualbox.org/manual/ch04.html).

### 게스트 생성 완료

게스트 확장이 설치되면 VM에서 개발하기 위한 [Windows 구성](#configure-windows)을 할 준비가 되었습니다.

## (지원 안 됨) 사용자 지정 구성

<div class="m-flag m-flag--warning">
  <p>
    <strong>경고:</strong> VirtualBox 가상 머신 밖에서 Windows 기반 엔진을 개발할 경우 통합 테스트를 수행할 수 없습니다. 위에 설명된 대로 Windows VirtualBox 게스트 안에서 개발을 수행하실 것을 강력히 권장합니다.
  </p>
</div>

최소 시스템 요구 사항:

- Windows 10*
- 4+ CPU cores
- 4GB RAM

*이전 버전의 Windows도 가능할 수 있지만, 현재는 테스트되지 않았으며, 지원되지 않습니다.

## Windows 구성

관리자 권한을 사용하여 Windows 기본 설정을 몇 가지 변경해야 합니다. '권한이 높거나' '권한 있는' PowerShell 콘솔이 필요합니다.

- 바탕화면 검색 창에서 'PowerShell'을 검색합니다
- 'Windows PowerShell'을 오른쪽 클릭합니다
- '관리자 권한으로 실행'을 선택합니다.

권한 있는 PowerShell 콘솔에서 다음과 같이 실행합니다.

1. Permit script execution (necessary for installing Chocolatey & using virtualenvs):
    
    ```powershell
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
    ```

2. Force PowerShell to use TLSv2 (required of some dependancies):
    
    ```powershell
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    ```

## Install Chocolatey & Prerequisities

Chocolatey is a package manager for Windows. We'll use it to help with installing some prerequisites.

Run the following in a *privileged* PowerShell console.

1. Install Chocolatey:
    
    ```powershell
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    ```

2. Use Chocolatey to install prerequisites (do these one at a time):
    
    ```powershell
    choco install -y python --version 3.5.4
    choco install -y git
    choco install -y visualcpp-build-tools --version 14.0.25420.1
    ```

## Disable Anti-Malware Products

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    We strongly recommend disabling all anti-malware products in your development environment - including the built-in Windows Defender.
    Below, we describe disabling Windows Defender.
    Disabling third party solutions is left as an exercise for the reader.
  </p>
</div>

PolySwarm engines should expect to come into contact with malware. Existing anti-malware engines, including the built-in Windows Defender, can easily get in our way, quarantining or deleting files during development.

Disabling Windows Defender is a two step process.

1. Run the following command in a privileged PowerShell:
    
    ```powershell
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1
    ```

2. Reboot Windows.

## Set up a Virtual Environment (virtualenv)

If you plan to use this Windows installation for other purposes, we recommend that you create a PolySwarm virtualenv so as to keep the system-wide Python packages clean:

```bash
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

## Install `polyswarm-client` Libraries

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    If you're using a virtualenv (see above), ensure that you activate it before installing `polyswarm-client`.
  </p>
</div>

Installing `polyswarm-client` is as simple as:

```bash
pip install polyswarm-client
```

## Verify Installation

You should now have a working development environment!

To verify, simply try importing `polyswarmclient`:

```bash
$ python
Python 3.5.4 (v3.5.4:3f56838, Aug  8 2017, 02:17:05) [MSC v.1900 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import polyswarmclient
>>>
```

You should be able to import `polyswarmclient` without issue.

Next, we'll walk you through building your very own PolySwarm Microengine, capable of detecting the EICAR test file.

[Make a "Hello World" Microengine →](/microengines-scratch-to-eicar/)