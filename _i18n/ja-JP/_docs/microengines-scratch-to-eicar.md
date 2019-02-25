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

もちろん、この条件に一致するファイルを特定する方法はたくさん存在します。 `scan` 関数の `content` パラメーターには、対象アーティファクトの全コンテンツが含まれます。これに対して突き合わせを行います。

以下に、`EICAR` を検出する `scan()` 関数を作成する方法を示した例を示します。 以下の例のいずれかの変更により、`__init__.py` ファイルのコードを更新します。

以下のように、最初の方法は最もシンプルな設計であり、[`eicar.py`](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/eicar.py) で使用します。

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

以下に別の方法を示します。今度は、EICAR テスト・ファイルの SHA-256 を既知の不正ハッシュと比較します。

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

最低でも、マイクロエンジンは、(a) 悪意のあるファイルの検出、(b) NCT の投資とアサーションの作成を行う必要があります。

投資ロジックは、マイクロエンジンの `bid` 関数で実装されます。

デフォルトでは、すべてのアサーションは、マイクロエンジンが参加しているコミュニティーで許可される最小の投資額で生成されます。

各種投資戦略の説明を追加していきますので、定期的にここの情報をご確認ください。

## Finalizing & Testing Your Engine

`cookiecutter` customizes `engine-template` only so far - there are a handful of items you'll need to fill out yourself. We've already covered the major items above, but you'll want to do a quick search for `CUSTOMIZE_HERE` to ensure all customization have been made.

Once everything is in place, let's test our engine:

[Test Linux-based Engines →](/testing-linux/)

[Test Windows-based Engines →](/testing-windows/)

## Next Steps

Scanner クラスにスキャン・ロジックを直接実装すると、管理も拡張も困難です。 そうではなく、実際のスキャン・ロジックが含まれている外部のバイナリーやサービスを Microengine クラスで呼び出すことをお勧めします。

[次は、ClamAV をマイクロエンジンにラップします →](/microengines-scratch-to-clamav/)