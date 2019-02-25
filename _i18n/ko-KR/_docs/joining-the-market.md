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

공식 이더리움 클라이언트(`go-ethereum` 또는 간략하게 `geth`)에서 키파일 생성에 대한 설명을 찾을 수 있습니다. [geth에서 계정 관리하기](https://github.com/ethereum/go-ethereum/wiki/Managing-your-accounts)를 참조하십시오.

## 지갑에 자금 입금

키파일을 생성했으면 지갑에 ETH와 NCT를 입금해야 합니다.

일반적으로 세 가지 입금 방법이 있습니다.

1. 암호화폐 거래소에서 ETH와 NCT를 구입하여 마이크로엔진의 생산 키파일로 나타나는 생산 지갑에 전송합니다. 암호화폐를 구입 & 전송하는 방법은 이 문서가 다루는 범위에 속하지 않습니다.
2. PolySwarm Direct(향후 예정된 서비스로 구성 가능한 자동 보충 기능을 통하여 사용자의 엔진에 자금 제공)에 가입합니다. 이 서비스는 현재 개발 중이므로, 계속 지켜봐 주십시오!
3. 당사가 게시한 배포 일정에 따라 초기 파트너들은 자신들의 생산 지갑에 NCT 씨앗을 받았습니다.

## 커뮤니티 찾기

PolySwarm 마켓플레이스는 다양한 커뮤니티로 구성되어 있습니다. 커뮤니티는 특정 맬웨어에 대한 관심을 공유하거나 커뮤니티 내에서 교환된 아티팩트에 대한 기밀을 유지하기로 서로 합의한 개인들과 기업들로 구성된 단체입니다.

PolySwarm의 첫 번째 커뮤니티인 Epoch은 누구나 가입할 수 있는 공개 커뮤니티로 여기서 시작하시면 좋습니다. Epoch은 일종의 '성능 시험장'으로 보안 전문가들이 자신의 엔진에 대한 명성을 쌓는 곳입니다. 보안 전문가가 명성을 쌓게 되면 다른 커뮤니티에도 참여하게 될 것입니다. 새로운 커뮤니티가 추가되면 PolySwarm 포털에 표시됩니다: <button disabled>커뮤니티 탐색 → (추가 예정!)</button>

당분간은 Epoch 커뮤니티에만 가입한다는 가정 하에 진행하겠습니다.

<div class="m-flag">
  <p>
    <strong>참고:</strong> <code>polyswarm-client</code> 기반 엔진은 특정 시간에 하나의 커뮤니티와만 소통할 수 있습니다. 여러 커뮤니티에 대한 지원은 향후 릴리스에 포함될 예정입니다. 당분간은 커뮤니티마다 하나씩 엔진의 인스턴스(및 <code>balancemanager</code>)를 실행해 주십시오.
  </p>
</div>

## 사용자의 커뮤니티에 NCT 전달하기

각 커뮤니티에는 PolySwarm 트랜잭션이 발생하는 별도의 [사이드체인](/#chains-home-vs-side)이 있다는 것을 기억하십시오. 여기에 참가하려는 사용자는 해당 커뮤니티의 사이드체인에 NCT(ETH는 필요하지 않음) 잔고를 유지해야 합니다.

이 과정은 간소화되어서 `polyswarm-client`의 `balancemanager` 유틸리티를 사용하면 됩니다. 엔진과 `balancemanager`를 모두 실행하여 커뮤니티 사이드체인에서 NCT 잔고를 유지해야 합니다. Windows 사용자는 [Windows 엔진 통합 테스트에 대한 설명](/testing-windows/#integration-testing)에서 `balancemanager`를 실행한 것을 기억하실 겁니다. Linux 사용자는 Docker가 투명하게 `balancemanager`를 처리하도록 하였습니다.

`balancemanager`는 세 가지 모드로 실행될 수 있습니다.

1. `deposit`: 설정된 NCT 금액을 커뮤니티에 입금하고 종료합니다
2. `withdraw`: 설정된 NCT 금액을 커뮤니티에서 출금하고 종료합니다
3. `maintain`: 설정 가능한 NCT 잔고를 커뮤니티에 계속 유지합니다

대부분의 사용자는 단순히 잔고를 `maintain`(유지)하기를 원할 겁니다. 아래에서는 이 기능을 사용하는 법에 대하여 다뤄보겠습니다. 고급 사용자는 자금을 수동으로 `deposit`(입금) 및 `withdraw`(출금)해보고 싶을 겁니다.

## API 키

커뮤니티는 그리핑(griefing) / 서비스 거부 공격(DoS)으로부터 스스로를 보호하기 위하여 회원들에게 API 키를 발급하고 이 키들에 속도 제한을 적용할 수 있습니다. Epoch도 이러한 커뮤니티 중 하나이지만 API 키는 누구에게나 제공됩니다.

Epoch API 키를 획득하려면 [PolySwarm 포털](https://polyswarm.network/)에 가입한 후, 우측 상단 모서리에 있는 자신의 이름을 클릭하고 계정을 선택합니다. 사용자의 Epoch API 키는 프로필에 표시되어 있습니다.

### `polyswarm-client` 기반 엔진에서의 API 키 사용

`polyswarm-client` 기반 엔진에서 API 키를 사용하려면 간단하게 `--api-key` 명령줄 인수에 입력하기만 하면 됩니다. 이 사항은 아래에 설명되어 있습니다.

### 사용자 지정 엔진에서의 API 키 사용

사용자 지정 엔진을 구축하시면 커뮤니티에 호스팅된 `polyswarmd` 인스턴스에 대한 모든 API 요청이 헤더에 사용자의 API 키를 포함하는지 확인하세요.

    허가: [API 키]
    

`polyswarmd API`에 대한 자세한 사항은 당사의 API 사양 [polyswarmd API 설명서](/polyswarmd-api/)를 참조하시기 바랍니다.

## 모든 항목 종합하기

지금까지 수행한 작업을 요약하면 다음과 같습니다.

1. *생산*용 지갑 키파일 생성
2. 이 지갑에 ETH 및 NCT 입금
3. 커뮤니티 결정
4. 커뮤니티에 대한 API 키 취득

이제 엔진(및 `balancemanager`)을 PolySwarm 마켓플레이스에 연결할 준비가 되었습니다!

`polyswarm-client`에 기반하여 엔진을 구축하신 경우(예: 튜토리얼에서 cookiecutter `engine-template` 사용) 몇 가지 명령줄 인수만 지정하시면 됩니다(환경 변수로서 지정할 수도 있음).

```bash
# microengine \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <사용자가 생성하고 자금을 제공한 키파일의 경로> \
  --password <키파일의 암호화 암호> \
  --api-key <사용자의 Epoch API 키>
  --backend <검사엔진의 이름("슬러그")(예: acme_myeicarengine)>
```

명령줄 인수의 전체 목록을 보려면 `--help` CLI 플래그를 사용하십시오.

```bash
# microengine --help
사용법: microengine [OPTIONS]

마이크로엔진 드라이버에 대한 엔트리 포인트

인수:     log (str): 로깅 수준     polyswarmd_addr(str): polyswarmd의
주소     keyfile (str): 트랜잭션에 서명할 때 사용하는 개인 키 파일의
경로     password (str): 암호화된 개인 키를 해독하는
암호     backend (str): 사용할 백엔드 구현     api_key(str): polyswarmd에서 사용할 API 키     testing (int): N개의 현상금 공고를 처리한 후
종료하는 모드 (선택 사항)     insecure_transport (bool): TLS 없이 polyswarmd에
연결     log_format (str): 로그 출력 형식.

 `text` 또는
`json`

옵션:
--log TEXT              로깅 수준
--polyswarmd-addr TEXT  polyswarmd 인스턴스의 주소 (호스트:포트)
--keyfile PATH          이 마이크로엔진에서 사용하는 개인 키가 포함된
Keystore 파일
--password TEXT         키파일을 해독하는 암호
--api-key TEXT          polyswarmd에서 사용하는 API 키
--backend TEXT          사용할 백엔드
--testing INTEGER       통합 테스트용 테스트 모드 활성화,
N개의 현상금 공고 및 N개의 제안에 응답한 후 종료
--insecure-transport    http:// and ws://를 통하여 polyswarmd에 연결,
--api-key와 서로 배타적임
--chains TEXT           운영 대상 체인
--log-format TEXT       로그 형식. `json` 또는 `text` (기본)
  --help 이 메시지를 표시하고 종료.
```

엔진과 함께 `balancemanager`를 실행해야 합니다.

`balancemanager`는 `keyfile`에 대한 접근 권한도 필요합니다.

```bash
# balancemanager maintain \
  --polyswarmd-addr polyswarmd.epoch.polyswarm.network \
  --keyfile <사용자가 생성하고 자금을 제공한 키파일의 경로> \
  --password <키파일의 암호화 암호> \
  --api-key <사용자의 Epoch API 키> \
  --maximum &lt;(선택 옵션) 출금 전 허용된 커뮤니티 내 최대 잔고&gt;
  &lt;MINIMUM: 잔고가 이 수치 아래로 떨어질 경우 커뮤니티에 입금&gt;
  &lt;REFILL_AMOUNT: 커뮤니티 잔고가 MINIMUM 아래로 떨어질 경우 전송할 NCT의 수량&gt;
```

For the full list of command line arguments, use the `--help` CLI flag:

```bash
# balancemanager maintain --help
INFO:root:2018-12-28 03:04:11,352 텍스트 형식으로 로깅.
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