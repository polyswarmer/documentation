# Testing Linux-Based Engines

## Unit Testing

Unit testing your Microengine is a simple process:

1. build a Docker image of your Microengine
2. run `docker-compose` to use `tox` to execute your testing logic in `tests/scan_test.py`

Run the following commands from the root of your project directory.

Build your Microengine into a Docker image:

```bash
docker build -t ${PWD##*/} -f docker/Dockerfile .
```

This will produce a Docker image tagged with the name of the directory, e.g. `microengine-myeicarengine`.

Run the tests:

```bash
docker-compose -f docker/test-unit.yml up
```

如果您的微引擎能够检测 EICAR 并且不会在字串 “not a malicious file”上产生误报，这时您就可以传入这些基本的单元测试并且看到以下内容：

```bash
e$ docker-compose -f docker/test-unit.yml up
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

Of course, this testing is quite limited - you'll want to expand on your tests in `scan_test.py`, as appropriate for your Microengine.

## Integration Testing

PolySwarm 市场是由众多参与者及技术所组成的：以太坊、 IPFS 节点、合约、微引擎、代表、仲裁者、工件等等。 Testing a single component often demands availability of all of the other components.

The `orchestration` project makes standing up a complete testnet easy and seamless. True to its name, `orchestration` orchestrates all the components necessary to stand up and tear down an entire PolySwarm marketplace environment on a local development machine.

Clone `orchestration` adjacent to your `microengine-myeicarengine` directory:

```bash
git clone https://github.com/polyswarm/orchestration
```

### （可选）预览一个完整、可用的测试网

让我们建立一个完整、可用的测试网，所以我们可以对事情*如何*运行更有概念。

In the cloned `orchestration` directory:

```bash
docker-compose -f base.yml -f tutorial0.yml up
```

You'll see output from the following services:

1. `homechain`: A [geth](https://github.com/ethereum/go-ethereum) node running our testnet's "homechain". See [Chains: Home vs Side](/#chains-home-vs-side) for an explanation of our split-chain design.
2. `sidechain` ：另一个运行着我们测试网的“sidechain”的 `geth` 个体。
3. `ipfs`：一个 IPFS 节点，负责托管我们“开发中”测试网路中所有的工件。
4. `polyswarmd`：提供方便访问 `homechain`、`sidechain` 和 `ipfs` 所提供的服务的 PolySwarm 守护进程。
5. `contracts`: Responsible for housing & deploying the PolySwarm Nectar (NCT) and `BountyRegistry` contracts onto our development testnet.
6. `ambassador`：一个虚拟代表（由 `polyswarm-client` 提供），它会置放悬赏在 [EICAR 的文件](https://en.wikipedia.org/wiki/EICAR_test_file) 和非 EICAR 的文件上面。
7. `arbiter`：一个虚拟仲裁者（由 `polyswarm-client` 提供），它会对热门的工件发送判定和决定“真正事实”。
8. `microengine`：一个虚拟微引擎 （由 `polyswarm-client` 提供），它会调查“热门”的工件和产生“断言”。

Browse through the logs scroll on the screen to get a sense for what each of these components is doing. 我们让它运行至少5分钟，因为部署合约可能会需要点时间，这时就开始变得有趣了 :)

When you've seen enough log output, do `Ctrl-C` to halt the development testnet gracefully.

### Test Your Engine

让我们运行一部分的测试网，不包含预设的 `微引擎`（我们会用我们自己的微引擎来取代）和 `代表` 服务。

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