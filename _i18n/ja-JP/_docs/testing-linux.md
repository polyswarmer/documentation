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
7. `arbiter`: A mock Arbiter (provided by `polyswarm-client`) that will deliver Verdicts on "swarmed" artifacts, determining ground truth.
8. `microengine`: A mock Microengine (provided by `polyswarm-client`) that will investigate the "swarmed" artifacts and render Assertions.

Browse through the logs scroll on the screen to get a sense for what each of these components is doing. Let it run for at least 5 minutes - it can take time to deploy contracts - and then the fun starts :)

When you've seen enough log output, do `Ctrl-C` to halt the development testnet gracefully.

### Test Your Engine

Let's spin up a subset of the testnet, leaving out the stock `microengine` (we'll be replacing this with our own) and the `ambassador` services.

In the cloned `orchestration` project:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --scale microengine=0 --scale ambassador=0
```

It will take several minutes for `polyswarmd` to become available. Once `polyswarmd` is available, it will begin serving responses to clients, e.g.:

    INFO:polyswarmd:2018-12-06 05:42:08.396534 GET 200 /nonce 0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8
    INFO:geventwebsocket.handler:::ffff:172.19.0.12 - - [2018-12-06 05:42:08] "GET /nonce?account=0x05328f171b8c1463eaFDACCA478D9EE6a1d923F8&chain=home HTTP/1.1" 200 135 0.048543
    

Next, let's spin up our Microengine in a second terminal window in our microengine's directory:

```bash
$ docker-compose -f docker/test-integration.yml up
```

Finally, let's introduce some artifacts for our Microengine to scan in a third terminal window in the `orchestration` directory:

```bash
$ docker-compose -f base.yml -f tutorial0.yml up --no-deps ambassador
```

Take a look at the logs from all three terminal windows - you should see your Microengine responding to the Ambassador's Bounties!

When you make changes to your Engine, testing those changes is as simple as re-building your Docker image and re-running the `ambassador` service to inject a new a new pair of EICAR/not-EICAR artifacts. You can keep the rest of the testnet running while you iterate.