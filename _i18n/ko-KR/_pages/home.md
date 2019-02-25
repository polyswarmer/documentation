## 환영합니다

PolySwarm에 오신 것을 환영하며, 관심을 가져주셔서 감사합니다!

여기에서 PolySwarm에 관한 개발을 시작하는 데 필요한 모든 정보를 찾으실 수 있습니다.

코드를 살펴보기 전에 주목해야 할 사항을 검토해보시기 바랍니다.

* PolySwarm에 참여하는 방식
* 자신의 사례에 적합한 역할
* 참여하고 싶은 커뮤니티
* 엔진의 성능을 확인하는 방법
* 커뮤니티의 개념. 엔진의 개념

먼저 전체적인 개요를 살펴보고, 필요에 따라 세부적인 사항을 들여다보도록 하겠습니다.

## 포털

PolySwarm 포털은 PolySwarm의 원스톱 지원 센터입니다.

* 엔진 성능 추적
* 커뮤니티 검색 (아래 참조)
* 엔진 이름 지정
* 프로필 생성
* 보안 전문가와 연결

... 그 밖에 수많은 작업이 가능합니다.

[포털 탐색 →](https://polyswarm.network/)

## 커뮤니티

PolySwarm은 여러 커뮤니티로 구성되어 있습니다(그래서 "Poly"라고 함). 각 커뮤니티는 특정한 목적을 위해 활동하며, 누구에게나 가입을 허용하거나 특정 참가자로만 접근을 제한할 수 있습니다.

PolySwarm will launch with two communities:

* **Genesis: the public mainnet community**: everyone can join & participate!
* **Hive: a private testing community**: a closed Community for initial partners preparing for launch on Genesis

This list will expand, allowing Ambassadors and Microengine developers to control their audience. Future communities may include:

* A GDPR-compliant community with artifact sharing amongst a closed set of compliant participants.
* A network of mutually NDA'ed MSSPs & security experts.

Anyone will be able to administer their own Community and advertise their community through PolySwarm Portal.

### Chains: Home vs Side

Each Community has a "homechain" and a "sidechain", either of which may be shared with other Communities. Generally speaking, the "homechain" is where crypto assets natviely exist and the "sidechain" is where PolySwarm transations take place.

For example, **Genesis**, the first public Community will be configured as such:

* `homechain`: the Ethereum Mainnet
* `sidechain`: a set of hosted `geth` nodes running in a [Clique configuration](https://github.com/ethereum/EIPs/issues/225)

PolySwarm Nectar (NCT) natively lives on the Ethereum Mainnet. Unfortunately, the Ethereum mainnet is far too slow (~15s block time) and far too expensive to support the sort of micro-transactions required by PolySwarm.

Rather than transacting directly on the Ethereum Mainnet, PolySwarm participants will instead relay NCT from Mainnet to the Genesis sidechain and conduct their business on this sidechain. Maintaining a minimal balance on the sidechain is made easy by `polyswarm-client`'s [`balancemanager`](https://github.com/polyswarm/polyswarm-client/tree/master/src/balancemanager).

This split-chain design provides two key benefits:

1. **Scalability** Today, Ethereum does not scale (they're working on this of course), so applications must implement their own "Layer 2" scaling solutions if they demand low latency or high throughput transactions.
2. **Confidentiality** PolySwarm supports the notion of limited-access, private Communities. This split-chain design makes that possible.

<button disabled>Browse Communities → (coming soon!)</button>

## Your Role in the PolySwarm Marketplace

There are several ways to participate in the PolySwarm ecosystem: will you create a Microengine, an Ambassador, an Arbiter or something else entirely?

[Determine where you fit into PolySwarm →](/concepts-participants/)