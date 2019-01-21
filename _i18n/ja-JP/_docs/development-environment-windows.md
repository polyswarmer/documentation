## (推奨) VirtualBox Guest の構成

Windows ベースのエンジンについては、現時点で完全にサポートされる構成は、VirtualBox Guest 内での開発のみです。

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    ここで示している推奨は、多大な労力を費やして作成されました。
    ここで示しているのとまったく同じパラメーターを使用してテストすることを強くお勧めします。
    他の構成を使用すると、当社でサポートするのが困難になる可能性があります。
  </p>
</div>

### システム要件

Windows ベースのエンジンの開発では、開発ホストに以下の重要なシステム要件があります。

- Windows 10 (Windows 10 Pro バージョン 1809 でテストしました)
- VT-x がサポートされ、BIOS で有効になっている
- 16GB 以上の RAM
- 4 個以上の CPU コア
- 100GB 以上のディスク・スペース

VirtualBox を使用します。 **VirtualBox は、ハイパーバイザーの単独の所有権を備えている必要があります**。 このため、以下を実行することはできません。

- Hyper-V
- Windows Credential Guard
- Windows Device Guard
- VMWare Workstation / Player
- ハイパーバイザー拡張機能を使用する他のすべての製品

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    Nested virtualization is NOT a currently supported configuration.
  </p>
  <p>
    ここで示している説明では、ホスト Windows インストール環境が「ベアメタル」で稼働しているものと想定されています。
    ハイパーバイザー (例えば AWS 上など) での開発の説明は別途準備中であり、近日公開いたします。
  </p>
</div>

### 前提条件

- [VirtualBox をダウンロードしてインストールします](https://www.virtualbox.org/wiki/Downloads)。 VirtualBox 5.2.22 でテストしました。
- [Windows 10 Pro ISO をダウンロードします](https://www.microsoft.com/en-us/software-download/windows10ISO)。 Media Creation Tool を使用して .ISO イメージを作成します。 Windows 10 Pro ビルド 10240 を使用してテストしました。

### Windows Guest の作成

VirtualBox を使用して、以下のパラメーターで Windows VM を作成します。

- 名前: `polyswarm_win`
- タイプ: Microsoft Windows
- バージョン: Windows 10 (64 ビット)
- RAM: 4GB 以上
- CPU: 2 個以上のコア
- ビデオ・メモリー: 128MB
- ディスク・スペース: 50GB 以上

他のすべてのオプションについては、デフォルト設定を使用します。 特に、**3D アクセラレーションは有効にしないでください**。

### Windows 10 のインストール

ダウンロードした ISO を使用して Windows 10 を VM にインストールします。

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    VirtualBox VM での Windows 更新の実行は推奨されません。実行すると、VM が起動不能状態に陥る可能性が非常に高くなります。
    VM に Windows をインストールした直後に <a href="https://www.thewindowsclub.com/turn-off-windows-update-in-windows-10">Windows 更新を無効にする</a>ことをお勧めします。
  </p>
</div>

### VirtualBox Guest Additions のインストール

ゲストとホスト間でのクリップボードの共有やコピー・アンド・ペーストの機能を使用するために、Guest Additions が必要です。

[VirtualBox の資料をご覧ください](https://www.virtualbox.org/manual/ch04.html)。

### ゲストの作成の完了

Guest Additions がインストールされ、VM 内での開発のために [Windows を構成する](#configure-windows)準備ができました。

## (サポート対象外) カスタム構成

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    現時点では、VirtualBox 仮想マシン以外で Windows ベースのエンジンを開発する場合、統合テストを実行できません。
    現時点では、Windows VirtualBox Guest (上記を参照) 内で開発することを強くお勧めします。
  </p>
</div>

最小システム要件:

- Windows 10*
- 4 個以上の CPU コア
- 4GB の RAM

*これより古いバージョンの Windows でも機能する可能性があります、現時点ではテストされておらず、サポート対象外です。

## Windows の構成

We'll need to use Administrator privilege to make several changes to default Windows settings. We'll need an "elevated" / "privileged" PowerShell console:

- search "PowerShell" in the desktop search bar
- right click on "Windows PowerShell"
- select "Run as administrator".

Run the following in this privileged PowerShell console.

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

## `polyswarm-client` ライブラリーのインストール

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

## インストールの確認

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