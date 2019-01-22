## システム要件

* x86-64 CPU
* 8GB の RAM

この説明は、Xubuntu 18.04 amd64 に基づいて作成、テストされています。

## Docker のインストール

簡単に実行できるように、できる限り多くのものを Docker 化しています。

Docker-CE (ベース) と Docker Compose をインストールする必要があります。 最新の Docker セットアップがない場合は、[ここで Docker をインストールしてください](https://docs.docker.com/install/)。

インストール後、以下を実行してインストール環境が機能していることを確認します。

```bash
$ docker ps
```

以下のように出力される必要があります。

    CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
    

次に、[`docker-compose` をインストールします](https://docs.docker.com/compose/install/)。

インストール後、以下を実行してインストール環境が機能していることを確認します。

```bash
$ docker-compose -v
```

Should output at least: `docker-compose version 1.21.1, build 5a3f1a3`

Docker のインストール後、以下のようにユーザーを `docker` グループに追加して、`sudo` なしで `docker` コマンドを簡単に実行できるようにすることをお勧めします。

```bash
$ sudo usermod -aG docker ${USER}
```

変更を有効にするには、再起動する必要があります。

## Git のインストール

We'll need to grab a few source code repositories; it'll be easiest to use Git. Please [install Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) for your development environment.

## Python と PIP のインストール

PolySwarm での開発では、Python 3.5.4 以上が必要です。 ご使用の開発プラットフォーム用の [Python](https://www.python.org/downloads/) と [PIP](https://pip.pypa.io/en/stable/installing/) をインストールしてください。

## (オプション) 仮想環境 (virtualenv) のセットアップ

当該マシンを他の目的で使用する予定の場合は、システム全体の Python パッケージがクリーンな状態に保たれるように、以下のように PolySwarm virtualenv を作成することをお勧めします。

```bash
pip install virtualenv
cd ~
virtualenv polyswarmvenv -p <PYTHON 3.5.4 以上のパス>
source polyswarmvenv/bin/activate
```

## `polyswarm-client` ライブラリーのインストール

<div class="m-flag">
  <p>
    <strong>情報:</strong>
    virtualenv (上記を参照) を使用する場合は、polyswarm-client をインストールする前に virtualenv をアクティブ化してください。
  </p>
</div>

`polyswarm-client` ライブラリーのコンパイルとインストールはシンプルです。

まず、Python 3 のヘッダー/ビルド要件をインストールします。

Ubuntu では、以下のようにします。

    $ sudo apt install python3-dev
    

次に、以下のようにします。

```bash
pip install polyswarm-client
```

## インストールの確認

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