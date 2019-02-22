# 「Hello World」マイクロエンジン

## 概要

マルウェア対策ソリューション開発の「Hello World」では常に、[EICAR テスト・ファイル](https://ja.wikipedia.org/wiki/EICAR%E3%83%86%E3%82%B9%E3%83%88%E3%83%95%E3%82%A1%E3%82%A4%E3%83%AB)を検出します。

この無害なファイルは、すべての主要マルウェア対策製品で「悪因がある」ものとして検出され、陽性結果をテストする安全な手段となります。

PolySwarm での最初のマイクロエンジンも同様です。EICAR を検出してみましょう。

[(オプション) マイクロエンジンのコンポーネントの確認 →](/concepts-participants-microengine/#breaking-down-microengines)

## ビルディング・ブロック

このガイドでは、以下を参照し、以下に基づいて作成します。

* [**engine-template**](https://github.com/polyswarm/engine-template): 名前のとおりです。これは、新規エンジンを作成するための便利なテンプレートであり、対話式プロンプトを備えています。 チュートリアルで使用します。

* [**polyswarm-client**](https://github.com/polyswarm/polyswarm-client): 万能的なサンプル PolySwarm 参加者 (「クライアント」)。 `polyswarm-client` は、`microengine` (マイクロエンジン: このチュートリアルでは、この機能に基づいて作成)、`arbiter` (評価者)、および `ambassador` (アンバサダー: 作成したものをテストするために使用) として機能できます。

## `engine-template` のカスタマイズ

<div class="m-flag m-flag--warning">
  <p>
    <strong>警告:</strong>
    現在、Windows ベースのエンジンは、AMI (AWS Machine Image) としてのみサポートされます。
  </p>
  <p>
    Windows ベースのエンジンのカスタマイズ・プロセスでは、AWS アカウントがあり、その ID を使用できることを前提としています。
  </p>
  <p>
    近い将来、自己ホスト・オプションなど、デプロイメント・オプションを拡張する予定です。 Linux ベースのエンジンには、そのような制約はありません。
  </p>
</div>

`engine-template` からエンジンを作成します。 これを行うには、`cookiecutter` が必要です。以下のようにします。

```bash
pip install cookiecutter
```

`cookiecutter` がインストールされたので、以下に示すように簡単に、テンプレートからエンジンを作成できます。

```bash
cookiecutter https://github.com/polyswarm/engine-template
```

プロンプトが表示されます。以下のように応答します。

* `engine_name`: MyEicarEngine (エンジン名)
* `engine_name_slug`: (デフォルトを受け入れる)
* `project_slug`: (デフォルトを受け入れる)
* `author_org`: ACME (または実際の組織名)
* `author_org_slug`: (デフォルトを受け入れる)
* `package_slug`: (デフォルトを受け入れる)
* `author_name`: Wile E Coyote (または自分の実際の名前)
* `author_email`: (E メール・アドレス)
* `platform`: このエンジンの実行プラットフォームが Linux なのか Windows なのかを正しく応答してください
* `has_backend`: バックエンドがない場合は 1 (後述の説明を参照)
* `aws_account_for_ami`: (Windows のみ) AWS アカウント ID (Linux エンジンの場合は、デフォルトを受け入れる)

<div class="m-callout">
  <p>プロンプト項目の 1 つに <code>has_backend</code> があります。これは、「外部のバックエンドがあるかどうか」と捉えることができます。これについて説明を追加します。</p>
  <p>スキャン・エンジンをラップする際に、<code>polyswarm-client</code> クラスの継承やクラス機能の実装は、「フロントエンド」の変更と呼びます。 スキャン・エンジンの「フロントエンド」がネットワークまたはローカル・ソケットを介して、実際のスキャン処理を行う別プロセス (バックエンド) を利用する場合、外部の「バックエンド」があり、<code>has_backend</code> に対して <code>true</code> と応答する必要があります。 そうではなく、スキャン・エンジンが単一の Docker イメージ (Linux) または AMI (Windows) に容易にカプセル化できる場合は、<code>has_backend</code> に対して <code>false</code> を選択する必要があります。</p>
  <p>外部のフロントエンド/バックエンドの例:</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/5959742f0014a582baf5046c7bf6694c23f7435e/src/microengine/clamav.py#L18">ClamAV</a></li>
  </ul>
  <p>フロントエンドのみの例 (has_backend は false):</p>
  <ul>
    <li><a href="https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/yara.py">Yara</a></li>
  </ul>
</div>

これで完了です。

現行作業ディレクトリーに `microengine-myeicarengine` があり、これを編集して EICAR スキャンの機能を実装します。

## EICAR スキャナーとマイクロエンジンの実装

EICAR の検出は、以下のようにシンプルです。

1. EICAR テスト・ファイルを特定する方法を知っている Scanner クラスを実装する
2. この Scanner クラスを使用する Microengine クラスを実装する

では開始しましょう。

`microengine-myeicarengine/src/(組織のスラグ名)_myeicarengine/__init__.py` を開きます。

上記の cookiecutter `engine-template` を使用した場合、`__init__.py` にコードが含まれています。

以下のように、このファイルを変更して、xScanner クラスと Microengine クラスの両方を実装します。

* **Scanner**: Scanner クラス。 このクラスでは、`scan` 関数で EICAR 検出ロジックを実装します。

* **Microengine**: Microengine クラス。 このクラスは、前述の Scanner をラップして、EICAR を検出マイクロエンジンとして必要なすべてのタスクを処理します。

### EICAR 検出ロジックの作成

EICAR テスト・ファイルは、文字列「`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`」のみが含まれたファイルとして定義されます。

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

### 投資戦略の作成

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