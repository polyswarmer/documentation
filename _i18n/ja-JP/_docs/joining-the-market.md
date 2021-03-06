# PolySwarm マーケットプレイスへの参加

エンジンを詳細にテストした後に、そのエンジンを実際の PolySwarm マーケットプレイスに展開します。

大まかに言うと、PolySwarm マーケットプレイスへの接続は、以下のような単純なタスクです。

1. 参加する単一または複数のコミュニティーを決定する
2. ご使用のエンジンで、該当するコミュニティーの `polyswarmd` のホスト・インスタンスを指定する

これを行う際の留意事項がいくつかあります。以下で説明します。

## ウォレットとキーファイル

PolySwarm は、イーサ (ETH) というネイティブ暗号通貨で支えられているプログラム可能なワールド・コンピューターであるイーサリアム上に構築されています。 イーサリアム・ユーザーが ETH の送金を実行するか、イーサリアムの「スマート・コントラクト」(例えば、PolySwarm のリレー・コントラクト) の呼び出しを実行する場合、そのユーザーは、そのトランザクションを実行するためにイーサリアム・ネットワークに「ガス」の形式で支払う必要があります。 ガスは、ユーザーの ETH 残高から差し引かれます。

PolySwarm は、イーサリアム上に構築されたアプリケーション層の暗号通貨トークンである Nectar (NCT) を基盤として稼働しています。 NCT は、PolySwarm マーケットプレイスに参加するために必須です。

PolySwarm ネットワークでユーザーに代わって動作するエンジンは、ETH と NCT の両方を利用できる必要があります。

### 暗号通貨ウォレット

すべての暗号通貨 (ビットコインなど) と同様に、資金は「ウォレット」で保持されます。 厳密には、ウォレットは単に、暗号鍵ペアと、鍵ペアの使用法を記述したメタデータです。 ウォレットは、この暗号鍵ペアの公開部分の暗号ハッシュによって一意に識別されます。 ウォレット (およびそこに入っているすべての資金) の所有/管理は、ウォレットの鍵ペアの秘密部分の所有と同義です。

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      あらゆる暗号通貨アプリケーションと同様に、PolySwarm では、あるユーザーのウォレットの秘密鍵を利用できる攻撃者は、そのユーザーのすべての暗号通貨 (ETH と NCT) を盗んだり、マーケットプレイス内でそのユーザーになりすましたりすることができます。
      ウォレットの秘密鍵の機密性を保持することは、非常に重要です。
    </strong>
  </p>
</div>

秘密鍵を保護する手段については、この資料の対象外です。 エンジンが PolySwarm マーケットプレイスに参加するには (また、ユーザーに代わってトランザクションを行うには)、エンジンがウォレットの秘密鍵を使用してトランザクションに署名できる必要があります。 つまり、エンジンは、鍵に直接アクセスできるか (低セキュリティー)、鍵にアクセスできるデバイス/プロセスに署名を要求できる (高セキュリティー) 必要があります。 現在、キーファイルへの直接アクセス方法は、`polyswarm-client` でサポートされています。 別のデバイスへのトランザクションの署名のオフロードのサポートについては、今後の `polyswarm-client` リリースで対応する予定です。

### PolySwarm でのウォレットの使用方法

エンジンをテストする際、`--keyfile` 引数を `polyswarm-client` ユーティリティー (つまり、`microengine` や `balancemanager`) に渡して、暗号秘密鍵が入っている「キーファイル」の場所をエンジンに教える必要があります。 `polyswarm-client` (および他の PolySwarm プロジェクト) で配布されているすべてのキーファイルは、単純なパスワード `password` (`--password` 引数で指定) を使用して暗号化されています。

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      配布されているキーファイルはフェイク NCT とフェイク ETH を使用してテストするためだけのものです。
      実稼働環境や実コミュニティーでは、PolySwarm プロジェクトからのテスト用キーファイルを使用しないでください。
      テスト用キーファイルに含まれているウォレットに本物の NCT や本物の ETH を入れないでください。
    </strong>
  </p>
  <p>
    <strong>
      開発テスト環境以外の運用では、独自の実動キーファイルを作成する必要があります。
    </strong>
  </p>
  <p>
    <strong>
      実動キーファイルのセキュリティーについては、ユーザーが全責任を負います。
    </strong>
  </p>
</div>

公式のイーサリアム・クライアント (`go-ethereum` (短縮名は `geth`)) に、キーファイルの生成に関する説明があります。 [geth でのアカウントの管理に関する説明](https://github.com/ethereum/go-ethereum/wiki/Managing-your-accounts)をご覧ください。

## ウォレットへの入金

独自のキーファイルを生成した後には、ウォレットに ETH と NCT を入れる必要があります。

通常、以下の 3 つの入金方法を利用できます。

1. 暗号通貨取引所で ETH と NCT を購入し、マイクロエンジンの実動キーファイルで表された実動ウォレットに送金します。 暗号通貨の購入と送金の方法については、この資料の対象外です。
2. PolySwarm Direct (エンジンが常に入金された状態に保つ構成可能な自動再入金機能を備えた近日公開予定のサービス) をサブスクライブします。 このサービスは開発中です。お待ちください。
3. 初期パートナーの皆様は、公開された配布スケジュールに従って、実動ウォレットで NCT を受け取ります。

## コミュニティーの検索

PolySwarm マーケットプレイスは、複数のコミュニティーで構成されています。 コミュニティーは、特定のマルウェアに対する関心を共有している、あるいはコミュニティー内で交換されるアーティファクトの機密性を保持することを相互に合意した個人や企業から成るグループです。

PolySwarm の最初のコミュニティー Epoch は、誰もがアクセスできる公開コミュニティーであり、そこから開始できます。 Epoch は一種の実験の場であり、セキュリティー専門家はエンジンの評判を築き上げることができます。 セキュリティー専門家は、評判を築き上げた後に、別のコミュニティーに参加できます。 コミュニティーが追加されると、PolySwarm のポータルに表示されます。<button disabled>コミュニティーの参照 → (近日公開予定)</button>

では、Epoch コミュニティーに参加するという想定で先に進めましょう。

<div class="m-flag">
  <p>
    <strong>情報:</strong>
      現在、<code>polyswarm-client</code> ベースのエンジンでは、一度に 1 つのコミュニティーとしか通信できません。
      複数のコミュニティーのサポートは、将来のリリースで追加される予定です。
      それまでは、コミュニティーごとにエンジンのインスタンスを実行してください (& <code>balancemanager</code>)。
  </p>
</div>

## コミュニティーへの NCT のリレー

各コミュニティーには、PolySwarm トランザクションが行われる固有の[サイドチェーン](/#chains-home-vs-side)があることに留意してください。 参加するには、コミュニティーのサイドチェーンで NCT の残高を維持する必要があります (ETH は不要です)。

`polyswarm-client` の `balancemanager` ユーティリティーを使用することで、これは簡単に行うことができます。 コミュニティーのサイドチェーンで NCT の残高を維持するには、エンジンと `balancemanager` の両方を実行する必要があります。 Windows ユーザーは、[Windows エンジン統合テストの説明](/testing-windows/#integration-testing)にある `balancemanager` の実行を行います。 Linux ユーザーの場合、`balancemanager` は Docker によって透過的に処理されます。

`balancemanager` は、以下の 3 つのモードで実行できます。

1. `deposit`: コミュニティーに構成された金額の NCT を預金して終了します
2. `withdraw`: コミュニティーから構成された金額の NCT を引き出し、終了します
3. `maintain`: コミュニティーで構成可能な NCT の残高を継続的に確保します

ほとんどのユーザーは、残高の維持 (`maintain`) のみを行います。この機能の使用については、後で詳しく説明します。 上級ユーザーは、預金 (`deposit`) と資金の引き出し (`withdraw`) を手動で行えます。

## API キー

荒らし行為やサービス拒否 (DoS) からの保護のため、コミュニティーは、メンバーに API キーを発行し、レート制限を各キーに適用することがあります。 Epoch もこれに該当するコミュニティーですが、API キーは全ユーザーが使用可能です。

Epoch の API キーを取得するには、[PolySwarm ポータル](https://polyswarm.network/)に登録し、右上隅にある名前をクリックして「アカウント」を選択します。 Epoch の API キーが、プロファイルに表示されます。

### `polyswarm-client` ベースのエンジンでの API キーの使用法

`polyswarm-client` ベースのエンジンでの API の使用はシンプルであり、`--api-key` コマンド・ライン引数を指定するだけです。 これについては、後で説明します。

### カスタム・エンジンでの API キーの使用法

カスタム・エンジンを作成する場合、以下のように、コミュニティーでホストされた `polyswarmd` インスタンスへのすべての API 要求のヘッダーに API キーを必ず含めてください。

    Authorization: [API キー]
    

`polyswarmd API` の詳細については、PolySwarm の API 仕様が示されている [polyswarmd API 資料](/polyswarmd-api/)をご覧ください。

## 最後の作業

まとめると、以下を行いました。

1. *実稼働環境*で使用するためのウォレットのキーファイルを生成しました
2. そのウォレットに ETH と NCT の両方を入金しました
3. コミュニティーを決定しました
4. コミュニティーの API キーを取得しました

これで、エンジン (および `balancemanager`) を PolySwarm マーケットプレイスに接続する準備ができました。

`polyswarm-client` でエンジンを作成した場合 (例えば、このチュートリアルの `engine-template` テンプレートを使用した場合)、以下のように、いくつかのコマンド・ライン引数を指定するだけで済みます (環境変数として指定することも可能です)。

```bash
# microengine \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <自分で生成し、入金したキーファイルのパス> \
  --password <キーファイルの暗号化パスワード> \
  --api-key <Epoch API キー>
  --backend <スキャン・エンジンの名前 (「スラグ」) (例えば、acme_myeicarengine)>
```

コマンド・ライン引数の完全なリストを表示するには、以下のように `--help` CLI フラグを使用します。

```bash
# microengine --help
使用法: microengine [オプション]

  マイクロエンジン・ドライバーのエントリーポイント

  引数:     log (str): ロギングのレベル     polyswarmd_addr(str): 
  polyswarmd のアドレス     keyfile (str): トランザクションの署名に使用する
  秘密鍵ファイルのパス     password (str): 暗号秘密鍵を複合するためのパス
  ワード     backend (str): 使用するバックエンド実装     api_key(str): polyswarmd
  で使用する API キー     testing (int): N 報奨金を処理して終了するモード
   (オプション)     insecure_transport (bool): TLS なしで polyswarmd
  に接続     log_format (str): ログの出力フォーマット (「text」または
  「json」)

オプション:
  --log TEXT              ロギング・レベル
  --polyswarmd-addr TEXT  polyswarmd インスタンスのアドレス (ホスト:ポート)
  --keyfile PATH          当該マイクロエンジンで使用する秘密鍵が含まれている
                          鍵ストア・ファイル
  --password TEXT         キーファイルを複合するためのパスワード
  --api-key TEXT          polyswarmd で使用する API キー 
  --backend TEXT          使用するバックエンド
  --testing INTEGER       統合テスト用にテスト・モードをアクティブ化。
                          N 報奨金と N オファーに応答して終了
  --insecure-transport    http:// および ws:// を介して polyswarmd 
                          に接続。--api-key との同時使用不可
  --chains TEXT           動作対象のチェーン
  --log-format TEXT       ログ・フォーマット。 「json」または「text」(デフォルト)
  --help                  このメッセージ (英語) を表示して終了
```

エンジンに加え、`balancemanager` を実行する必要があります。

以下のように、`balancemanager` でも `keyfile` にアクセスできる必要があります。

```bash
# balancemanager maintain \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <自分で生成して入金したキーファイルのパス> \
  --password <キーファイルの暗号化パスワード> \
  --api-key <Epoch API キー> \
  --maximum <(オプション) コミュニティー内の最大許容残高。この値を超えると、引き出しが実行される>
  <MINIMUM: 残高がこの金額を下回ると、コミュニティーに対する預金を実行>
  <REFILL_AMOUNT: コミュニティーの残高が MINIMUM を下回ったときに送金する金額 (NCT)>
```

For the full list of command line arguments, use the `--help` CLI flag:

```bash
# balancemanager maintain --help
INFO:root:2018-12-28 03:04:11,352 テキスト・フォーマットでロギング
使用法: balancemanager maintain [オプション] MINIMUM REFILL_AMOUNT

  サイドチェーンからホームチェーンに NCT を引き出すエントリーポイント

  引数:     minimum (float): NCT を送金するサイドチェーンの金額 (NCT)
       refill-amount (float): 残高が minimum を下回ったときに送金する金額 (NCT)

オプション:
  --polyswarmd-addr TEXT   polyswarmd インスタンスのアドレス (ホスト:ポート)
  --keyfile PATH           当該マイクロエンジンで使用する秘密鍵が含まれている
                           鍵ストア・ファイル
  --password TEXT          キーファイルを複合するためのパスワード
  --api-key TEXT           polyswarmd で使用する API キー
  --testing INTEGER        統合テスト用にテスト・モードをアクティブ化。
                          サイドチェーンに残高 N をトリガーして終了
  --insecure-transport     http:// および ws:// を介して polyswarmd 
                          に接続。--api-key との同時使用不可
  --maximum FLOAT          最大許容残高。この値を超えると、サイドチェーン
                           からの引き出しがトリガーされる
  --withdraw-target FLOAT  引き出し後のサイドチェーンの目標残高
  --confirmations INTEGER  リレーでの送金の承認に必要なブロック
                           確認数
  --help                   このメッセージ (英語) を表示して終了
```

## 結果

エンジンと `balancemanager` が実行され、任意のコミュニティーに接続できるようになりました。