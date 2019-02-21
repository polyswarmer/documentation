# 実際のエンジンのラップ: ClamAV

## 準備

ClamAV は、オープン・ソースのシグネチャー・ベースのエンジンであり、認識したアーティファクトを迅速に分析するデーモンを備えています。 このチュートリアルでは、ClamAV を分析バックエンドとして取り込むことで、2 つ目の PolySwarm マイクロエンジンを作成するプロセスについて順に説明します。

<div class="m-flag">
  <p>
    <strong>注:</strong>
    PolySwarm マーケットプレイスは、未知のマルウェアのソースになります。
  </p>
  <p>
    厳密なシグネチャー・ベースのエンジン、特にシグネチャーに誰もがアクセスできるもの (ClamAV など) を分析バックエンドとして利用した場合、「swarm」されたアーティファクトに対する独自の知見が得られることはないと思われるため、他のエンジンに勝つことはできないでしょう。
  </p>
  <p>
    このガイドは、マーケットプレイスへのアプローチの推奨と捉えるのではなく、既存の分析バックエンドを<strong>マイクロエンジン</strong>・スケルトンに取り込む方法を示した例としてお読みください。
  </p>
</div>

このチュートリアルでは、[microengine/clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) の作成について説明します。完成したソリューションについては、`clamav.py` をご覧ください。

## `clamd` の実装と統合

[何も手を加えていない engine-template](/microengines-scratch-to-eicar/#customize-engine-template) から開始し、「MyClamAvEngine」という `engine-name` (エンジン名) を付けます。 現行作業ディレクトリーに `microengine-myclamavengine` があり、これを編集して ClamAV スキャンの機能を実装します。

Edit the `__init__.py` as we describe below:

`clamd` モジュールをインポートして、グローバル変数を構成することで、ClamAV `分析バックエンド`を開始します。

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import clamd
import logging
import os
from io import BytesIO

from polyswarmclient.abstractmicroengine import AbstractMicroengine
from polyswarmclient.abstractscanner import AbstractScanner

logger = logging.getLogger(__name__)  # ロガーを初期化

CLAMD_HOST = os.getenv('CLAMD_HOST', 'localhost')
CLAMD_PORT = int(os.getenv('CLAMD_PORT', '3310'))
CLAMD_TIMEOUT = 30.0
```

これでもうすぐ完了と言ったら信じられますか? ネットワーク・ソケットを介して `clamd-daemon` と通信できるように、`clamd` を初期化して実行しましょう。

```python
class Scanner(AbstractScanner):
    def __init__(self):
        self.clamd = clamd.ClamdAsyncNetworkSocket(CLAMD_HOST, CLAMD_PORT, CLAMD_TIMEOUT)
```

`clamd` の操作は、アーティファクト・コンテンツのバイト・ストリームを送信して行います。

ClamAV は、このバイト・ストリームに対して以下の形式で応答します。

```json
{'stream': ('FOUND', 'Eicar-Test-Signature')}
```

Python の `[]` 演算子を使用して簡単に結果を解析できます。 `result[0]` は単語「`FOUND`」であり、この例の `result[1]` は「`Eicar-Test-Signature`」です。

これで、後は Scanner クラスに scan メソッドを実装するだけです。

```python
    async def scan(self, guid, content, chain):
        result = await self.clamd.instream(BytesIO(content))
        stream_result = result.get('stream', [])
        if len(stream_result) >= 2 and stream_result[0] == 'FOUND':
            return True, True, ''

        return True, False, ''
```

`clamd` は、マルウェアを検出すると、`result[0]` に「`FOUND`」を入れます。

マイクロエンジンで予期される戻り値は、以下のとおりです。

1. `bit` : `malicious` (悪意がある) か `benign` (無害) かの判定を表す `boolean`
2. `verdict`: エンジンでアーティファクトに関するアサーションを出すかどうかを表す `boolean`
3. `metadata`: (オプション) アーティファクトについて記述した `string`

練習問題として ClamAV の `metadata` の組み込みを行ってください。あるいは、[clamav.py](https://github.com/polyswarm/polyswarm-client/blob/master/src/microengine/clamav.py) を確認してください。

<div class="m-flag">
  <p>
    <strong>Info:</strong>
    The Microengine class is required, but we do not need to modify it, so it is not shown here.
  </p>
  <p>
    Python 3 の Asyncio - スキャン時に行った外部呼び出しによってイベント・ループがブロックされないことが重要です。
    clamd プロジェクトをフォークして、Python 3 の asyncio のサポートを追加しました。
    そのため、変更がアップストリームでマージされるまで、この例を実行するには、PolySwarm の python-clamd プロジェクトをインストールして clamd パッケージを取得する必要があります。
    必要なコマンドは、「pip install git+https://github.com/polyswarm/python-clamd.git@async#egg=clamd」です。
  </p>
</div>

## エンジンの仕上げとテスト

これまでのところ、`cookiecutter` は `engine-template` のみをカスタマイズしています。自分で作成する必要がある項目が少しあります。 主な項目については上記で説明しましたが、`CUSTOMIZE_HERE` をクイック検索して、すべてのカスタマイズが行われたかを確認できます。

すべての準備ができたら、エンジンをテストしましょう。

[Linux ベースのエンジンのテスト →](/testing-linux/)

[Windows ベースのエンジンのテスト →](/testing-windows/)

## Next Steps

Eicar の例では、Scanner クラスでスキャン・ロジックを直接実装する方法について説明しました。 この ClamAV の例では、外部ソケットを呼び出してスキャン・ロジックにアクセスする方法を示しました。

[次は、ClamAV と Yara を単一のマイクロエンジンにラップします ->](/microengines-clamav-to-multi/)