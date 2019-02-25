## 마이크로엔진 개요

![마이크로엔진 아키텍처](/public-src/images/microengine-architecture.svg)

마이크로엔진은 PolySwarm 마켓플레이스에서 보안 전문가들을 대변합니다. 마이크로엔진은 보안 전문가들의 전문 지식을 서명, 휴리스틱, 동적 분석, 에뮬레이션, 가상화를 조합한 형태나 완전히 색다른 형태로 캡슐화합니다.

마이크로엔진은 PolySwarm 마켓플레이스의 현상금과 제안에 대응하여 의심스러운 파일이 악의적인지 정상적인지 판별하고 관련 주장과 함께 일정 금액의 Necta(NCT)를 판돈으로 겁니다. 보안 전문가들은 새로운 보안 위협과 분석 도구에 대응할 수 있도록 마이크로엔진을 유지, 조정하며 각자의 전문 분야에서 선두를 차지하기 위해 서로 경쟁합니다.

특정 맬웨어에 대한 특별한 통찰력이 있고, 이 통찰력을 발휘하여 명성과 토큰(NCT)을 획득하고 싶으시다면, 마이크로엔진을 개발해보시기 바랍니다!

## 마켓플레이스에서 마이크로엔진의 역할

PolySwarm 마켓플레이스에서 **홍보대사**는 서부 시대의 현상금과 비슷한 PolySwarm 현상금 시스템을 통하여 의심스러운 아티팩트(파일)에 대해 크라우드소싱 방식으로 여러 사람의 의견을 구합니다. *홍보대사는 제안 채널을 통하여 특정 전문가들에게 의견을 구할 수도 있습니다. 이 주제에 대해선 나중에 다루도록 하겠습니다.*

전체적인 개요:

1. **홍보대사**는 의심스러운 `아티팩트`(파일)에 대하여 "현상금"을 겁니다.
2. **마이크로엔진**은 (`polyswarmd`를 통하여) 이더리움 이벤트를 경청함으로써 이 새로운 아티팩트를 인식합니다.
3. 각 **마이크로엔진**은 해당 아티팩트가 자신의 전문 영역에 속하는지 판단합니다.
4. **마이크로엔진**이 해당 아이팩트에 대하여 통찰력이 있을 경우 `주장`을 개진하고 `주장`에 대하여 일정 금액의 NCT를 `판돈`으로 겁니다. 판돈은 BountyRegistry 스마트 계약에 보관됩니다.
5. **홍보대사**는 모든 `주장`을 참작한 후 고객에게 `의견`을 전달합니다.
6. 얼마간의 시간이 경과합니다.
7. **중재자**가 아티팩트의 악성 여부에 대하여 *사실 검증*을 제공합니다.
8. 주장이 맞은 **마이크로엔진**이 틀린 **마이크로엔진**의 보관된 자금으로 보상을 받습니다.

이 과정에 대한 자세한 내용은 [PolySwarm 백서](https://polyswarm.io/polyswarm-whitepaper.pdf)를 참조하시기 바랍니다.

## 마이크로엔진 세부 내역

마이크로엔진의 개념적인 구성 요소:

1. `N` **분석 백엔드**: 아티팩트(파일)를 입력하여 `악성` 또는 `정상` 여부를 판단하는 스캐너.
2. `1` **verdict distillation engine**: ingests analysis backend(s) output, distills to a single `verdict` + a `confidence interval`
3. `1` **staking engine**: ingests verdict distillation output and market / competitive information and produces a `stake` in units of Nectar (NCT)

Microengines are Security Experts' autonomous representatives in the PolySwarm marketplace. They handle everything from scanning files to placing stakes on assertions concerning the malintent of files.

Specifically, Microengines:

1. Listen for Bounties and Offers on the Ethereum blockchain (via `polyswarmd`)
2. Pull artifacts from IPFS (via `polyswarmd`)
3. Scan/analyze the artifacts (via one or more **analysis backends**)
4. Determine a Nectar (NCT) staking amount (via a **verdict distillation engine**)
5. Render an assertion (their `verdict` + `stake`) (via a **staking engine**)

All Microengines share this set of tasks. This tutorial will focus exclusively on item #3: bulding an analysis backend into our `microengine-scratch` skeleton project. All other items will be covered by `polyswarmd` defaults. After completing these tutorials, advanced users may want to refer to [**polyswarmd API**](/polyswarmd-api/) for pointers on customizing these other aspects of their Microengine.

## Developing a Microengine

Ready to develop your first Microengine and start earning NCT?

(Recommended) [I want to build a Linux-based Microengine →](/development-environment-linux/)

Linux-based Engines are far easier to test and come with more deployment options than Windows-based Engines.

[My scan engine only supports Windows; I want to build a Windows-based Microengine →](/development-environment-windows/)