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

### System Requirements

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
    <strong>警告:</strong>
    現在、仮想化のネストは、サポート対象外の構成です。
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
- 4+ CPU cores
- 4GB の RAM

*これより古いバージョンの Windows でも機能する可能性があります、現時点ではテストされておらず、サポート対象外です。

## Windows の構成

デフォルトの Windows 設定を変更するために、管理者権限を使用する必要があります。 「昇格された」/「権限が付与された」PowerShell コンソールが必要です。以下のようにします。

- デスクトップの検索バーで「PowerShell」を検索します。
- 「Windows PowerShell」を右クリックします。
- 「管理者として実行」を選択します。

権限が付与された PowerShell コンソールで以下を実行します。

1. 以下のように、スクリプト実行を許可します (Chocolatey のインストールや virtualenvs の使用に必要です)。
    
    ```powershell
    Set-ExecutionPolicy Bypass -Scope LocalMachine -Force
    ```

2. 以下のように、PowerShell で TLSv2 を強制的に使用するようにします (一部の依存関係のために必要です)。
    
    ```powershell
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    ```

## Chocolatey と前提条件のインストール

Chocolatey は、Windows 用のパッケージ・マネージャーです。 一部の前提条件をインストールするために使用します。

*権限が付与された* PowerShell コンソールで以下を実行します。

1. 以下のように、Chocolatey をインストールします。
    
    ```powershell
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    ```

2. 以下のように、Chocolatey を使用して前提条件をインストールします (一度に 1 つずつ行います)。
    
    ```powershell
    choco install -y python --version 3.5.4
    choco install -y git
    choco install -y visualcpp-build-tools --version 14.0.25420.1
    ```

## マルウェア対策製品の無効化

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    組み込みの Windows Defender も含め、環境内のすべてのマルウェア対策製品を無効にすることを強くお勧めします。
    以下に、Windows Defender の無効化について説明します。
    サード・パーティー・ソリューションの無効化は、自分で調べて行ってください。
  </p>
</div>

PolySwarm エンジンは、マルウェアを検出する必要があります。 組み込みの Windows Defender も含め、既存のマルウェア対策エンジンは、開発中にファイルを隔離したり、削除したりするため、邪魔になります。

Windows Defender の無効化は、2 つのステップで完了するプロセスです。

1. 権限が付与された PowerShell で以下のコマンドを実行します。
    
    ```powershell
    Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' DisableAntiSpyware 1
    ```

2. Windows を再起動します。

## 仮想環境 (virtualenv) のセットアップ

当該 Windows インストール環境を他の目的で使用する予定の場合は、システム全体の Python パッケージがクリーンな状態に保たれるように、以下のように PolySwarm virtualenv を作成することをお勧めします。

```bash
cd ~
python -m venv polyswarmvenv
./polyswarmvenv/Scripts/Activate.ps1
```

## Install `polyswarm-client` Libraries

<div class="m-flag">
  <p>
    <strong>情報:</strong>
    virtualenv (上記を参照) を使用する場合は、polyswarm-client をインストールする前に virtualenv をアクティブ化してください。
  </p>
</div>

`polyswarm-client` のインストールはシンプルであり、以下のようにします。

```bash
pip install polyswarm-client
```

## Verify Installation

これで有効な開発環境が用意できているはずです。

確認するために、以下のように `polyswarmclient` をインポートします。

```bash
$ python
Python 3.5.4 (v3.5.4:3f56838, Aug  8 2017, 02:17:05) [MSC v.1900 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import polyswarmclient
>>>
```

問題なく `polyswarmclient` をインポートできる必要があります。

次に、EICAR テスト・ファイルを検出できる独自の PolySwarm マイクロエンジンの作成について説明します。

[「Hello World」マイクロエンジンの作成 →](/microengines-scratch-to-eicar/)