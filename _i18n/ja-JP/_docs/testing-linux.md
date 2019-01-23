# Linux ベースのエンジンのテスト

## 単体テスト

マイクロエンジンの単体テストは、以下のようにシンプルなプロセスです。

1. マイクロエンジンの Docker イメージをビルドする
2. `docker-compose` を実行し、`tox` を使用して `tests/scan_test.py` のテスト・ロジックを実行する

プロジェクト・ディレクトリーのルートから以下のコマンドを実行します。

以下のように、マイクロエンジンを Docker イメージにビルドします。

```bash
$ docker build -t ${PWD##*/} -f docker/Dockerfile .
```

これにより、ディレクトリーの名前でタグ付けされた Docker イメージが生成されます (例えば、`microengine-myeicarengine`)。

以下のようにテストを実行します。

```bash
$ docker-compose -f docker/test-unit.yml up
```

マイクロエンジンで文字列「not a malicious file」に対して誤検出を生成することなく、EICAR を検出できる場合、基本単体テストに合格し、以下のような出力が表示されます。

```bash
$ docker-compose -f docker/test-unit.yml up
Recreating docker_test_engine_mylinuxengine_1_a9d540dc7394 ... done
Attaching to docker_test_engine_mylinuxengine_1_a9d540dc7394
...
test_engine_mylinuxengine_1_a9d540dc7394 | py35 run-test-pre: PYTHONHASHSEED='1705267802'
test_engine_mylinuxengine_1_a9d540dc7394 | py35 runtests: commands[0] | pytest -s
test_engine_mylinuxengine_1_a9d540dc7394 | ============================= test session starts ==============================
test_engine_mylinuxengine_1_a9d540dc7394 | platform linux -- Python 3.5.6, pytest-3.9.2, py-1.7.0, pluggy-0.8.0
test_engine_mylinuxengine_1_a9d540dc7394 | hypothesis profile 'default' -> database=DirectoryBasedExampleDatabase('/usr/src/app/.hypothesis/examples')
test_engine_mylinuxengine_1_a9d540dc7394 | rootdir: /usr/src/app, inifile:
test_engine_mylinuxengine_1_a9d540dc7394 | plugins: timeout-1.3.2, cov-2.6.0, asyncio-0.9.0, hypothesis-3.82.1
test_engine_mylinuxengine_1_a9d540dc7394 | collected 36 items
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | tests/scan_test.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bloom.py ......
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_bounties.py .
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_client.py ............
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_corpus.py ..
test_engine_mylinuxengine_1_a9d540dc7394 | tests/test_events.py ..............
test_engine_mylinuxengine_1_a9d540dc7394 |
test_engine_mylinuxengine_1_a9d540dc7394 | ========================== 36 passed in 39.42 seconds ==========================
test_engine_mylinuxengine_1_a9d540dc7394 | ___________________________________ summary ____________________________________
test_engine_mylinuxengine_1_a9d540dc7394 |   py35: commands succeeded
test_engine_mylinuxengine_1_a9d540dc7394 |   congratulations :)
```

もちろん、このテストは非常に限定されたものであるため、ご使用のマイクロエンジンに合わせて、`scan_test.py` でテストを拡張できます。

## 統合テスト

PolySwarm マーケットプレイスは、多数の参加者とテクノロジー (イーサリアム・ノード、IPFS ノード、コントラクト、マイクロエンジン、アンバサダー、評価者、アーティファクトなど) で構成されます。 多くの場合、単一のコンポーネントをテストするには、あらゆる他のコンポーネントが使用可能でなければなりません。

`orchestration` プロジェクトは、完全な testnet を容易かつシームレスに利用できるようにします。 名前の通り、`orchestration` は、ローカル開発マシンで PolySwarm マーケットプレイス環境を立ち上げて破棄するために必要なすべてのコンポーネントをオーケストレーションします。

以下のように、`microengine-myeicarengine` ディレクトリーの隣に `orchestration` を複製します。

```bash
$ git clone https://github.com/polyswarm/orchestration
```

### (オプション) 機能している完全な testnet のプレビュー

機能している完全な testnet を立ち上げて、どのようになる*はず* なのかを確認してみましょう。

複製した `orchestration` ディレクトリーで、以下のようにします。

```bash
$ docker-compose -f base.yml -f tutorial0.yml up
```

以下のサービスからの出力が表示されます。

1. `homechain`: testnet の「ホームチェーン」を実行している [geth](https://github.com/ethereum/go-ethereum) ノード。 分割チェーン設計の説明については、「[チェーン: ホームとサイド](/#chains-home-vs-side)」をご覧ください。
2. `sidechain`: testnet の「サイドチェーン」を実行している別の `geth` インスタンス。
3. `ipfs`: 開発 testnet ですべてのアーティファクトをホストする IPFS ノード。
4. `polyswarmd`: `homechain`、`sidechain`、`ipfs` から提供されているサービスに簡便にアクセスできるようにする PolySwarm デーモン。
5. `contracts`: PolySwarm Nectar (NCT) と `BountyRegistry` コントラクトを格納して開発 testnet にデプロイします。
6. `ambassador`: A mock Ambassador (provided by `polyswarm-client`) that will place bounties on [the EICAR file](https://en.wikipedia.org/wiki/EICAR_test_file) and on a file that is not EICAR.
7. `arbiter`: (`polyswarm-client` で提供されている) 演習用評価者。確認・評価を行い、「swarm」されたアーティファクトに関する判定を提供します。
8. `microengine`: (`polyswarm-client` で提供されている) 演習用マイクロエンジン。「swarm」されたアーティファクトを調べて、アサーションを作成します。

画面でスクロールするログを確認し、上記の各コンポーネントが実行している内容の感触を掴んでください。 少なくとも 5 分間は実行させてください。コントラクトのデプロイに時間がかかることがありますが、その後は興味深くなります。

ログ出力を十分に確認したら、`Ctrl-C` を押して開発 testnet を正常に停止します。

### エンジンのテスト

testnet のサブセットを開始しましょう。ここでは、ストックの `microengine` (これは独自のもので置き換えます) と `ambassador` サービスは除外します。

複製した `orchestration` プロジェクトで、以下のようにします。

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

`polyswarmd` が使用可能になるまでに数分かかります。 `polyswarmd` は、使用可能になると、クライアントに応答を提供しはじめます。例: 

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

次に、2 つ目の端末ウィンドウでマイクロエンジンを開始しましょう。マイクロエンジンのディレクトリーで、以下のようにします。

```bash
$ docker-compose -f docker/test-integration.yml up
```

最後に、3 つ目の端末ウィンドウで、マイクロエンジンがスキャンする対象アーティファクトを導入します。`orchestration` ディレクトリーで以下のようにします。

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

3 つすべての端末ウィンドウのログを確認します。マイクロエンジンがアンバサダーの報奨金に応答しているのが分かるはずです。

エンジンに変更を加えた場合、その変更をテストするのは簡単です。Docker イメージを再ビルドし、`ambassador` サービスを再実行して新しい EICAR と非 EICAR アーティファクトのペアを注入するだけです。 反復処理時には、testnet の残りの部分は実行されたままで構いません。