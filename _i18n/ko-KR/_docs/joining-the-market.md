# PolySwarm 마켓플레이스에 참가하기

엔진 테스트를 철저하게 완료했다면 이제 실제 PolySwarm 마켓플레이스에서 작동하도록 만들 차례입니다!

개략적으로 말씀드리면 엔진을 PolySwarm 마켓플레이스에 연결하는 것은 다음과 같이 매우 간단합니다.

1. 가입할 커뮤니티를 결정합니다
2. 엔진이 해당 커뮤니티에 대한 `polyswarmd`의 호스팅된 인스턴스를 가리키도록 합니다

이 작업을 수행할 때 주의해야 할 몇 가지 사항에 대하여 아래에서 설명하겠습니다.

## 지갑 & 키 파일

PolySwarm은 이더리움 상에 구축되는데, 이는 이더(ETH)라고 불리는 기본 암호화폐를 사용하는, 프로그래밍 가능한 전 세계적인 컴퓨터 네트워크입니다. 이더리움 사용자가 ETH를 전송하거나 이더리움의 '스마트 계약'(예: PolySwarm의 릴레이 계약)을 호출할 경우 사용자는 이 트랜잭션을 수행하기 위하여 이더리움 네트워크에 '가스'라는 수수료를 지불해야 합니다. 가스는 해당 사용자의 ETH 잔고에서 공제됩니다.

PolySwarm은 이더리움 상에 구축된 애플리케이션-레이어 암호화폐 토큰인 Nectar(NCT)에 기반하여 운영됩니다. NCT는 PolySwarm 마켓플레이스에 참가할 때 필수적인 요소입니다.

PolySwarm 마켓플레이스에서 사용자의 대리인 역할을 하는 마이크로엔진은 ETH와 NCT 모두에 액세스할 수 있어야 합니다.

### 암호화폐 지갑

다른 모든 암호화폐(예: 비트코인)처럼 자금은 '지갑'에 보관됩니다. 기술적으로 지갑은 단순히 암호화 키 쌍과 키 쌍의 사용법을 기술하는 몇 가지 메타데이터로 구성됩니다. 지갑은 이 암호화 키 쌍의 공개 부분에 대한 암호화 해시로 고유하게 식별됩니다. 지갑(및 그 안에 포함된 모든 자금)을 소유 / 통제한다는 것은 해당 지갑에 속한 키 쌍의 비공개 부분을 소유한다는 것과 유사합니다.

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      다른 모든 암호화폐 애플리케이션과 마찬가지로 PolySwarm에서 사용자 지갑의 개인 키에 접근한 해커는 모든 암호화폐(ETH 및 NCT)를 훔치고, 마켓플레이스에서 해당 사용자를 사칭할 수 있습니다.
      따라서, 반드시 지갑의 개인 키를 기밀로 보호해야 합니다.
    </strong>
  </p>
</div>

개인 키를 보호하는 방법은 이 문서가 다루는 범위에 속하지 않습니다. 사용자의 엔진이 PolySwarm 마켓플레이스에 참여하고 사용자를 대신하여 거래를 진행하려면, 엔진이 지갑의 개인 키로 거래에 서명할 수 있어야 합니다. 즉, 엔진이 개인 키에 직접 접근할 수 있거나(보안성이 약함) 개인 키에 접근 권한이 있는 장치 / 프로세스에 서명을 요청할 수 있는 능력을 보유해야 합니다(보안성이 강함). 현재 `polyswarm-client`는 직접 키파일 접근 방법을 지원하고 있습니다. 다른 장치로 거래 서명을 오프로딩하는 것은 향후 발표될 `polyswarm-client` 릴리스에서 지원됩니다.

### PolySwarm에서 지갑 사용

엔진을 테스트할 때는 `polyswarm-client` 유틸리티(예: `microengine` 및 `balancemanager`)에 `--keyfile` 인수를 전달하는 방식을 통하여 암호화된 개인 키가 포함된 '키파일'을 찾을 수 있는 장소를 엔진에 알려주었습니다. `polyswarm-client`(및 다른 PolySwarm 프로젝트)를 통하여 배포되는 모든 키파일은 `--password` 인수를 통하여 지정된 평범한 암호인 `password`로 암호화됩니다.

<div class="m-flag m-flag--danger">
  <p>
    <strong>
      이렇게 배포된 키파일의 유일한 목적은 모의 NCT 및 모의 ETH를 테스트하기 위함입니다.
      생산 단계나 실제 커뮤니티에서 polyswarm 프로젝트의 테스트용 키파일을 절대로 사용하지 마십시오.
      이 테스트용 키파일에 포함된 지갑에 실제 NCT 또는 실제 ETH를 절대로 입금하지 마십시오.
    </strong>
  </p>
  <p>
    <strong>
      개발 테스트 환경 밖에서 작업할 경우 자신만의 생산 키파일을 생성해야 합니다.
    </strong>
  </p>
  <p>
    <strong>
      생산 키파일의 보안에 대한 책임은 전적으로 사용자에게 있습니다.
    </strong>
  </p>
</div>

The official Ethereum client (`go-ethereum` or `geth` for short) has instructions for generating a keyfile. See [Managing your accounts in geth](https://github.com/ethereum/go-ethereum/wiki/Managing-your-accounts).

## Funding Your Wallet

Once you've generated your own keyfile, you'll need to fund your wallet with ETH and NCT.

Generally, there are three funding avenues available:

1. Purchase ETH and NCT on cryptocurrency exchanges and transfer them to the production wallet represented by your microengine's production keyfile. Methods to purchase & transfer cryptocurrencies are outside the scope of this document.
2. Subscribe to PolySwarm Direct - an upcoming service with configurable auto-refills that ensure your engine is funded. This service is in development, stay tuned!
3. Initial partners have received a NCT seedling in their production wallet per our published distribution schedule.

## Finding Your Community(ies)

The PolySwarm marketplace is made up of a patchwork of Communities. Communities are groups of individuals and corporations that share a particular malware interest or mutually agree to maintain the confidentiality of artifacts exchanged within the Community.

PolySwarm's first Community, Epoch, is a public Community accessible to everyone - it's where you'll want to get started. Epoch acts as a sort of "proving ground" for security experts to build a reputation for their engine. Once security experts build a reputation, they may want to engage in additional Communities. As more communities come online, they'll appear in PolySwarm Portal: <button disabled>Browse Communities → (coming soon!)</button>

For now, let's proceed under the assumption that we only want to join the Epoch community.

<div class="m-flag">
  <p>
    <strong>Info:</strong>
      <code>polyswarm-client</code> based engines currently only support communicating with a single Community at a given time.
      Support for multiple Communities will be included in a future release.
      In the meantime, please run an instance of your engine (& <code>balancemanager</code>) per Community.
  </p>
</div>

## Relaying NCT to Your Community(ies)

Recall that each community has a distinct [sidechain](/#chains-home-vs-side) where PolySwarm transactions occur. In order to participate, you'll need to maintain a balance of NCT (ETH not required) on the Community's sidechain.

We've made this easy: you can use `polyswarm-client`'s `balancemanager` utility. You'll need to run both your engine and a `balancemanager` to maintain a balance of NCT on the Community sidechain. Windows users will recall running `balancemanager` from the [Windows engine Integration Testing instructions](/testing-windows/#integration-testing). Linux users had `balancemanager` handled for them by Docker transparently.

`balancemanager` can be run in three modes:

1. `deposit`: deposit the configured amount of NCT onto the Community and exit
2. `withdraw`: withdraw the configured amount of NCT from the Community and exit
3. `maintain`: continually ensure a configurable balance of NCT in the Community

Most users will want to simply `maintain` a balance - we'll dive into using this functionality below. Advanced users may want to manually `deposit` and `withdraw` funds.

## API Keys

In order to protect themselves from griefing / Denial of Service (DoS), Communities may elect to issue their members API keys and apply rate limits to these keys. Epoch is one such community, but API keys are available to everyone.

To obtain your Epoch API key, sign up on [PolySwarm Portal](https://polyswarm.network/), click your name in the top right corner and select Account. Your Epoch API key will be displayed in your Profile.

### API Key Usage in `polyswarm-client`-Based Engines

Using your API key in `polyswarm-client` based engines is as simple as populating the `--api-key` command line argument. We discuss this below.

### API Key Usage in a Custom Engine

If you're building a custom engine, please ensure that all API requests to Community-hosted `polyswarmd` instances contain your API key in the headers:

    Authorization: [API KEY]
    

For more details on the `polyswarmd API`, please refer to our API specification [polyswarmd API Documentation](/polyswarmd-api/).

## Putting it all Together

To recap, we've:

1. generated a wallet keyfile for *production* use
2. funded this wallet with both ETH and NCT
3. decided on our Community(ies)
4. retrieved our API key for our Community(ies)

Now we're ready to plug our engine (& `balancemanager`) into the PolySwarm marketplace!

If you've built your engine on `polyswarm-client`, (e.g. using our cookiecutter `engine-template` in the tutorials here), you simply need to specify some command line arguments (can also be specified as environment variables):

```bash
# microengine \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <path to your self-generated and funded keyfile> \
  --password <encryption password for your keyfile> \
  --api-key <your Epoch API key>
  --backend <the name ("slug") of your scan engine (e.g. acme_myeicarengine)>
```

For the full list of command line arguments, use the `--help` CLI flag:

```bash
# microengine --help
Usage: microengine [OPTIONS]

  Entrypoint for the microengine driver

  Args:     log (str): Logging level     polyswarmd_addr(str): Address of
  polyswarmd     keyfile (str): Path to private key file to use to sign
  transactions     password (str): Password to decrypt the encrypted private
  key     backend (str): Backend implementation to use     api_key(str): API
  key to use with polyswarmd     testing (int): Mode to process N bounties
  then exit (optional)     insecure_transport (bool): Connect to polyswarmd
  without TLS     log_format (str): Format to output logs in. `text` or
  `json`

Options:
  --log TEXT              Logging level
  --polyswarmd-addr TEXT  Address (host:port) of polyswarmd instance
  --keyfile PATH          Keystore file containing the private key to use with
                          this microengine
  --password TEXT         Password to decrypt the keyfile with
  --api-key TEXT          API key to use with polyswarmd
  --backend TEXT          Backend to use
  --testing INTEGER       Activate testing mode for integration testing,
                          respond to N bounties and N offers then exit
  --insecure-transport    Connect to polyswarmd via http:// and ws://,
                          mutually exclusive with --api-key
  --chains TEXT           Chain(s) to operate on
  --log-format TEXT       Log format. Can be `json` or `text` (default)
  --help                  Show this message and exit.
```

In addition to your engine, you'll need to run a `balancemanager`.

`balancemanager` will also require access to your `keyfile`:

```bash
# balancemanager maintain \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <path to your self-generated and funded keyfile> \
  --password <encryption password for your keyfile> \
  --api-key <your Epoch API key> \
  --maximum <(optional) the maximum allowable balance in the Community before a withdraw is made>
  <MINIMUM: deposit into the Community when balance drops below this value>
  <REFILL_AMOUNT: the amount of NCT to transfer when Community balance falls below MINIMUM>
```

For the full list of command line arguments, use the `--help` CLI flag:

```bash
# balancemanager maintain --help
INFO:root:2018-12-28 03:04:11,352 Logging in text format.
Usage: balancemanager maintain [OPTIONS] MINIMUM REFILL_AMOUNT

  Entrypoint to withdraw NCT from a sidechain into the homechain

  Args:     minimum (float): Value of NCT on sidechain where you want to
  transfer more NCT     refill-amount (float): Value of NCT to transfer
  anytime the balance falls below the minimum

Options:
  --polyswarmd-addr TEXT   Address (host:port) of polyswarmd instance
  --keyfile PATH           Keystore file containing the private key to use
                           with this microengine
  --password TEXT          Password to decrypt the keyfile with
  --api-key TEXT           API key to use with polyswarmd
  --testing INTEGER        Activate testing mode for integration testing,
                           trigger N balances to the sidechain then exit
  --insecure-transport     Connect to polyswarmd via http:// and ws://,
                           mutually exclusive with --api-key
  --maximum FLOAT          Maximum allowable balance before triggering a
                           withdraw from the sidechain
  --withdraw-target FLOAT  The goal balance of the sidechain after the
                           withdrawal
  --confirmations INTEGER  Number of block confirmations relay requires before
                           approving the transfer
  --help                   Show this message and exit.
```

## Congratulations

With your engine & `balancemanager` running, you are now plugged into your Community(ies) of choice!