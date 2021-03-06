# Windows ベースのエンジンのテスト

このページでは、マイクロエンジンのディレクトリーの名前として `microengine-mywindowsengine` を使用します。 ユーザー独自のテストでは、ご使用のマイクロエンジンのディレクトリーの名前を使用します。 また、この説明では、コマンドが読みやすくなるように、PowerShell コマンド・プロンプトを `PS >` と短縮しています。 実際の PowerShell コマンド・プロンプトは、`(polyswarmvenv) PS C:\Users\user\microengine-mywindowsengine>` のようになります。 同様に、Linux コマンド・プロンプトでは、`$` と短縮していますが、実際のコマンド・プロンプトでは、`$` の左側に追加のテキストがあります。

## Unit Testing

`tox` を使用してマイクロエンジンをテストします。 `tox` は、`tests/scan_test.py` に追加したすべての単体テストを実行します。

アクティブ化された仮想環境の PowerShell ウィンドウで、マイクロエンジンのディレクトリーから `tox` コマンドを実行します。

```powershell
PS > tox
```

出力は、以下のようになります。

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

`combine_argument_formatters` の警告は無視して問題ありません。

## Integration Testing

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    現在、Windows ベースのエンジンでの統合テストの実行は、VirtualBox 構成でのみサポートされます。
    詳細については、「<a href="/development-environment-windows/">Windows 開発環境</a>」をご覧ください。
  </p>
</div>

Windows ベースのエンジンの統合テストでは、以下の 2 つの仮想マシン (VM / ゲスト) が必要です。

1. Windows ベースのエンジンを実行するための Windows ゲスト (これは既に作成しました)
2. ローカル PolySwarm testnet を支えるための Linux ゲスト (この説明で作成します)

<div class="m-flag m-flag--warning">
  <p>
    <strong>Warning:</strong>
    The recommendations presented here are hard-won.
    ここで示しているのとまったく同じ推奨を使用してテストすることを強くお勧めします。
    Using any other configuration will make it difficult for us to provide you with support.
  </p>
</div>

### Linux ゲストの作成

#### 仮想マシンの作成

以下のパラメーターを使用して Linux VM を作成します。

* 名前: `polyswarm_lin`
* タイプ: Linux
* バージョン: Ubuntu (64 ビット)
* RAM: 8GB 以上
* CPU: 4 個以上のコア
* video memory: 128MB
* disk space: 50GB+

Use the default setting for all other options. 特に、3D アクセラレーションは有効にしないでください。

通常、testnet のパフォーマンスを向上させるため、Linux VM で使用可能な RAM と CPU のリソースを追加することをお勧めします。

#### Xubuntu 18.04 amd64 のインストール

* [Xubuntu 18.04 amd64 ISO のダウンロード](https://xubuntu.org/release/18-04/)

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    VirtualBox ゲストには、Ubuntu よりも Xubuntu を強くお勧めします。
    Ubuntu では、さまざまな視覚的なラグの問題が発生し、VirtualBox ツールをインストールすると、完全な視覚的なロックアップに陥る傾向にあります。
  </p>
</div>

ダウンロードした ISO を使用して、VM に Xubuntu をインストールします。

#### (オプション) VirtualBox Guest Additions のインストール

Guest Additions are necessary for Shared Clipboard / Copy & Paste features between Guest and Host.

[Refer to VirtualBox's manual](https://www.virtualbox.org/manual/ch04.html).

### ゲスト間ネットワークの構成

Linux VM と Windows VM が相互通信に使用する「内部」ネットワークを確立する必要があります。

始める前に、Linux ゲストと Windows ゲストの両方をシャットダウンします。

Windows ホストで、PowerShell を開いて、以下のように VirtualBox インストール環境ディレクトリーに移動します。

```powershell
PS > pushd $Env:Programfiles\Oracle\VirtualBox
```

これで、以下のようなコマンド・プロンプトが表示されます。

```powershell
PS C:\Program Files\Oracle\VirtualBox>
```

#### 内部 PolySwarm ネットワークの作成

専用 PolySwarm 内部ネットワークを作成して各 VM に割り当てます。

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    以下のコマンドでは、VM 上のネットワーク・アダプター 5 を再構成します。
    (可能性は非常に低いですが) このアダプターを既に使用している場合は、コマンド内の番号を変更してください。
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
    <strong>情報:</strong>
    VirtualBox の内部ネットワークの詳細については、<a href="https://www.virtualbox.org/manual/ch06.html#network_internal">公式資料</a>をご覧ください。
  </p>
</div>

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    VM 設定や VM 内で「アダプター 5」はリストされません。
    表示されるのは、VM で少なくとも 2 つのアクティブなネットワーク・アダプターがあるということです。「polyswarm_net」をアダプター 5 に追加すると、VM 内で最も番号が大きいネットワーク・インターフェースになるため、見つけやすくなります。
  </p>
</div>

#### 静的 IP アドレスを使用した仮想マシンの構成

`polyswarm_lin` VM を起動し、ネットワーク設定を編集して以下の静的 IPv4 情報を新しいアダプターに割り当てます。

* アドレス: `10.10.42.101`
* ネットマスク: `255.255.255.0`
* ゲートウェイ: `10.10.42.1`

上記設定を適用するネットワーク・インターフェースが分からない場合は、`ifconfig -a` コマンドを実行します。出力で、`enp0s` から開始する複数のネットワーク・インターフェースが表示されるはずです。 通常、そのプレフィックスの後の番号が最大であるインターフェースが変更対象のものです。

`polyswarm_win` VM を起動し、ネットワーク設定を編集して以下の静的 IPv4 設定で新しいアダプターを構成します。

* アドレス: `10.10.42.102`
* netmask: `255.255.255.0`
* gateway: `10.10.42.1`

上記設定を適用するネットワーク・インターフェースが分からない場合は、`ipconfig /all` コマンドを実行します。出力で、`Ethernet adapter Ethernet` から開始する複数のネットワーク・インターフェースが表示されるはずです。 The interface with the largest number after that prefix is usually the one you want to modify.

#### `polyswarmd` DNS 解決のための Windows VM の構成

最後に、Linux VM で `polyswarmd` がホストされていることを Windows VM が認識する必要があります。 権限が昇格されたメモ帳のインスタンスを開き、以下のように `polyswarmd` を `C:\Windows\System32\Drivers\etc\hosts` の末尾に追加します。

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
    

#### 構成の確認

最後に、Windows で `polyswarmd` が Linux VM に解決され、VM に到達できることを確認します。 まず、以下のように DNS テストを実行します。

```powershell
PS > Resolve-DnsName -name polyswarmd
```

出力は、以下のようになっている必要があります。

```powershell
Name                                           Type   TTL   Section    IPAddress
----                                           ----   ---   -------    ---------
polyswarmd                                     A      86400 Answer     10.10.42.101
```

次に、以下のように ping テストを実行します。

```powershell
PS > ping polyswarmd
```

The output should look like this:

```powershell
Pinging polyswarmd [10.10.42.101] with 32 bytes of data:
Reply from 10.10.42.101: bytes=32 time<1ms TTL=64
```

同様の出力結果が得られた場合、すべてが正しくセットアップされているので、先に進めましょう。

### ローカル testnet をホストするための Linux VM の構成

#### Install Docker

PolySwarm マーケットプレイスのテスト・バージョンを Docker 化しました。 これを使用するには、Docker-CE (ベース) と Docker Compose をインストールする必要があります。 最新の Docker セットアップがない場合は、[ここで Docker をインストールしてください](https://www.docker.com/community-edition)。

Xubuntu の場合:

```bash
$ sudo apt-get update && sudo apt-get install -y curl
$ curl -fsSL https://get.docker.com -o get-docker.sh
$ chmod +x get-docker.sh
$ ./get-docker.sh
$ sudo usermod -aG docker $USER
```

ログアウトしてからログインし直します。

インストール後、以下のコマンドを実行してインストール環境が機能していることを確認します。

```bash
$ docker ps
```

以下のように出力される必要があります。

    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    

また、[`docker-compose` をインストールします](https://docs.docker.com/compose/install/)。

On Xubuntu:

```bash
$ curl -L "https://github.com/docker/compose/releases/download/1.23.1/docker-compose-$(uname -s)-$(uname -m)" -o docker-compose
$ sudo mv docker-compose /usr/local/bin/docker-compose
$ sudo chmod +x /usr/local/bin/docker-compose
```

インストール後、インストール環境が機能していることを確認します。

```bash
$ docker-compose -v
```

少なくとも `docker-compose version 1.21.1, build 5a3f1a3` が出力される必要があります。

<div class="m-flag">
  <p>
    <strong>情報:</strong>
    docker または docker-compose コマンドの実行時に許可に関するエラーが表示された場合は、<a href="https://docs.docker.com/install/linux/linux-postinstall/#manage-docker-as-a-non-root-user">Docker 許可のためにユーザー・アカウントを構成してください</a>。
  </p>
</div>

#### Install Git

いくつかのソース・コード・リポジトリーを利用する必要があります。Git を使用するのが最も簡単でしょう。 ご使用の開発環境用の [Git をインストール](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git)してください。

Xubuntu 18.04 では、以下のようにします。

```bash
$ sudo apt update && sudo apt install -y git
```

#### `orchestration` のダウンロード

PolySwarm [`orchestration`](https://github.com/polyswarm/orchestration) プロジェクトを使用して開発 testnet を起動します。 この同じプロジェクトを内部で使用して、エンドツーエンドの (統合) テストを実行します。

以下のように、`orchestration` を複製します。

```bash
$ git clone https://github.com/polyswarm/orchestration
```

### Test Your Engine

ここでは、少々 VM を切り替える必要があります。 まず、Linux VM で testnet を開始します。 次に、Windows VM でマイクロエンジンを開始します。 最後に、Linux VM でアンバサダーを開始します。

#### Linux VM: testnet の起動

Linux VM で、testnet のサブセットを開始します。ここでは、ストックの `microengine` は除外し (これは独自のもので置き換えます)、`ambassador` も除外します (これは後から開始します)。 そうするために、新しい端末ウィンドウで以下のコマンドを実行します。

```bash
$ cd orchestration
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

It will take several minutes for `polyswarmd` to become available. このとき、以下のような多数のメッセージが表示されます。「`Problem with dial... dial tcp connection refused.`」や「`chain for config not available in consul yet`」。 testnet の初期化中にこうしたエラーが出ても正常であるため、待機してください。

Once `polyswarmd` is available, it will begin serving responses to clients, e.g.:

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

これで、問題なく次のステップに進むことができます。

#### Windows VM: `polyswarmd` への接続のテスト

Windows VM で、`polyswarmd` が使用可能であり、マイクロエンジンに応答する準備ができていることを確認します。 これを行うために、PowerShell で以下のコマンドを実行します。

```powershell
PS > curl -UseBasicParsing http://polyswarmd:31337/status
```

以下のように出力される必要があります。

```powershell
StatusCode        : 200
StatusDescription : OK
Content           : {"result":{"home":{"block":189,"reachable":true,"syncing":false},"ipfs":{"reachable":true},"side":{
                    "block":191,"reachable":true,"syncing":false}},"status":"OK"}
...
```

確認する必要がある重要な部分は「`"status":"OK"`」です。

#### Windows VM: `balancemanager` とエンジンの起動

新しい PowerShell ウィンドウを開始し、仮想環境をアクティブ化します。 次に、マイクロエンジンのディレクトリーに移動します。

マイクロエンジンのディレクトリーで、マイクロエンジンの前提条件とマイクロエンジン自体をインストールします。

```powershell
PS > pip install -r requirements.txt
PS > pip install .
```

`balancemanager` は、すべてのトランザクションが行われるローカル testnet のサイドチェーンで (フェイク) PolySwarm Nectar (NCT) の残高を維持できるようにする (`polyswarm-client` に基づいた) ユーティリティーです。

同じ PowerShell ウィンドウで、以下のように `balancemanager` を起動します。

```powershell
PS > balancemanager maintain --keyfile microengine_keyfile --password password --polyswarmd-addr polyswarmd:31337 --insecure-transport 100000 500000
```

以下のような出力になります。

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

「`Received block on chain`」メッセージが出力され始めたら、マイクロエンジンを起動する準備ができています。

別の新しい PowerShell ウィンドウを開始し、仮想環境をアクティブ化します。 Then change into your Microengine's directory.

以下のようなコマンドを使用して、マイクロエンジンを実行します。 必ず、`--backend` 引数の値を更新して、ご使用のマイクロエンジンのパッケージ・ディレクトリー (つまり、`src/` 内のディレクトリー) の名前にしてください。

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

`--testing 2` と指定して実行すると、マイクロエンジンは 2 つの報奨金に応答してから、自動的にシャットダウンしてそれ以上報奨金に応答しなくなります。 テストでさらに報奨金を処理する場合は、この数値を調整してください。

ただし、アンバサダーが報奨金を testnet に送信するまで、処理するための報奨金はマイクロエンジンに提示されません。

#### Linux VM: ambassador の起動

次に、Linux VM で `ambassador` を起動します。これは、報奨金を testnet に提示し、マイクロエンジンでその報奨金に応答できるようにします。 新しい端末を開始し、以下のコマンドを実行します。

```bash
$ cd orchestration
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

この開始後すぐに、マイクロエンジンの PowerShell ウィンドウで、報奨金処理中のメッセージが表示されます。

### 完了

完了です。

これで、Windows ベースのエンジンが、Linux VM にホストされたローカル testnet で提示された報奨金に応答しています。

自動的にシャットダウンするまでマイクロエンジンを実行してみましょう。

エンジンの出力を詳しく調べて、期待される処理を実行しているかを確認してください。