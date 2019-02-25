# マルチバックエンド・マイクロエンジンの作成

このチュートリアルでは、複数の分析バックエンドを組み合わせる方法について説明し、基本判定生成プリミティブの概要を示します。 バックエンドは 2 つあり、`ClamAV` (直前のチュートリアルのもの) と [YARA](https://virustotal.github.io/yara/) です。

## 組み合わせへの YARA の追加

何も手を加えていない [engine-template](/microengines-scratch-to-eicar/#customize-engine-template) から開始し、「MyYaraEngine」という `engine-name` (エンジン名) を付けます。 現行作業ディレクトリーに `microengine-myyaraengine` があり、これを編集して Yara の機能を実装します。

YARA バックエンドをマイクロエンジンに追加します。ただし、まず、いくつかの YARA シグネチャー (ルール) が必要です。

[Yara-Rules](https://github.com/Yara-Rules/rules) リポジトリーは、無料のルールの優れたリソースです。 では、以下のように、ルールを取得して `microengine-myyaraengine` の `pkg` ディレクトリーに入れます。

```sh
cd microengine-myyaraengine/pkg
git clone https://github.com/Yara-Rules/rules.git
```

ルールを解釈するために `yara-python` モジュールも必要です。まだインストールされていない場合は、以下のようにインストールします。

```sh
pip install yara-python
```

次に、`yara-python` を使用してアーティファクトをスキャンするスキャナーを作成します。

以下のように、`__init__.py` を編集します。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import yara

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

logger = logging.getLogger(__name__)  # ロガーを初期化
RULES_DIR = os.getenv('RULES_DIR', 'docker/yara-rules')

class Scanner(AbstractScanner):
    def __init__(self):
        self.rules = yara.compile(os.path.join(RULES_DIR, "malware/MALW_Eicar"))

    async def scan(self, guid, content, chain):
        matches = self.rules.match(data=content)
        if matches:
            return True, True, ''

        return True, False, ''
```

<div class="m-flag">
  <p>
    <strong>情報:</strong>
    Microengine クラスが必要ですが、変更する必要がないため、ここでは記載していません。
  </p>
</div>

`polyswarm-client` に付属の YARA バックエンドは、YARA ルールの場所を指定できる `RULES_DIR` 環境変数を受け入れます。 そのため、このエンジンのテスト時には、`RULES_DIR` 環境変数を設定して、ダウンロードした YARA ルールの場所を指定する必要があります。

<div class="m-flag">
  <p>
    <strong>情報:</strong>
    統合テストを実行する際 (<a href="/testing-linux/#integration-testing">Linux</a>、<a href="/testing-windows/">Windows</a>)、演習用アンバサダーは、2 つのファイル (EICAR と EICAR でないファイル) のみに報奨金を設定します。
    従って、このフレームワークのテスト目的では、EICAR を検出する YARA ルールのみが必要になります。
  </p>
</div>

これに関しては、YARA マイクロエンジンがあります。 ただし、ここでは、単一のマイクロエンジンで複数のエンジンを実行することが目的です。では、説明を進めます。

## ClamAV スキャナー

[前のチュートリアル](/microengines-scratch-to-clamav/)の ClamAV スキャナーを再利用します。

完成ソリューションは、[clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) で確認できます。

## 複数の分析バックエンド

何も手を加えていない [engine-template](/microengines-scratch-to-eicar/#customize-engine-template) から開始し、「MyMultiEngine」という `engine-name` (エンジン名) を付けます。 現行作業ディレクトリーに `microengine-mymultiengine` があり、これを編集して、ClamAv と YARA の両方の機能を使用します。

複数の分析バックエンドを利用するようにマイクロエンジンを拡張します。つまり、両バックエンド (YARA と ClamAV) の結果を取得して判定を生成する手段が必要です。 では、複数のスキャナーを初期化するマイクロエンジンを作成しましょう。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import asyncio
import logging

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner
from polyswarm_myclamavengine import Scanner as ClamavScanner
from polyswarm_myyaraengine import Scanner as YaraScanner

logger = logging.getLogger(__name__)  # ロガーを初期化
BACKENDS = [ClamavScanner, YaraScanner]


class Scanner(AbstractScanner):

    def __init__(self):
        super(Scanner, self).__init__()
        self.backends = [cls() for cls in BACKENDS]

```

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    The Microengine class is required, but we do not need to modify it, so it is not shown here.
  </p>
</div>

これにより、YaraScanner と ClamavScanner のインスタンスが含まれたバックエンドのリストが作成されます。

両方のスキャナーにアクセスできるようになったため、両方の結果を使用して、スキャナーの `scan()` 関数で最終判定を生成しましょう。

```python
    async def scan(self, guid, content, chain):
        results = await asyncio.gather(*[backend.scan(guid, content, chain) for backend in self.backends])

        # 結果タプルを解凍
        bits, verdicts, metadatas = tuple(zip(*results))
        return any(bits), any(verdicts), ';'.join(metadatas)
```

ここでは、スキャナーのすべての結果を非同期的に計算してから、結合して最終判定を生成しています。 この例では、バックエンドのいずれかが True ビットを返したかどうかを判定し、いずれかのバックエンドが悪意があると判別した場合にアーティファクトが悪意のあるものであるというアサーションを生成します。 また、スキャナーからのすべてのメタデータを単一の文字列に結合し、アサーションに添付します。

完成ソリューションは、[multi.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/multi.py) で確認できます。

注: Python モジュール `polyswarm_myclamavengine` および `polyswarm_myyaraengine` は、前述の例からのものです。 このマルチエンジンで ClamAV エンジンと YARA エンジンを使用するには、PYTHONPATH に該当モジュールがなければなりません。 そのために、ClamAV と YARA の両方のプロジェクト・ディレクトリーのルートで以下のコマンドを実行できます。

```bash
pip install .
```

## 次のステップ

既存のウィルス対策製品を使用してさまざまなマイクロエンジンを作成する方法について学びました。次は、独自のカスタム・マイクロエンジンの作成に進むことができます。