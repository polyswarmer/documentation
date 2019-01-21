## マイクロエンジンの概要

![マイクロエンジン・アーキテクチャー](/public-src/images/microengine-architecture.svg)

マイクロエンジンは、PolySwarm マーケットプレイスでセキュリティー専門家の代理として機能します。 マイクロエンジンは、シグネチャー、ヒューリスティックス、動的分析、エミュレーション、仮想化などを単体または組み合わせた形で、セキュリティーの専門知識をカプセル化します。

マイクロエンジンは、PolySwarm マーケットプレイスで報奨金とオファーに応答し、疑わしいファイルが悪意のあるものなのか無害なのかを判別して、そのアサーションとともに一定量の Nectar (NCT) トークンを投資します。 セキュリティー専門家は、新しい脅威情報や新しい分析ツールに対応して、自身のマイクロエンジンを保守および調整し、専門家同士で競い合って、自身の専門知識分野で先頭に立とうとします。

特定のマルウェア系統に関する独自の知見を有している場合、その知見に対する評判とトークン (NCT) を獲得するために、マイクロエンジンを開発できます。

## マーケットプレイスにおけるマイクロエンジンの役割

PolySwarm マーケットプレイスでは、**アンバサダー**が、西部劇の指名手配のような PolySwarm 報奨金メカニズムを利用して、疑わしいアーティファクト (ファイル) についてクラウドソーシングを活用した意見をマーケットに求めます。 *アンバサダーは、オファー・チャネルを利用して特定の専門家に依頼することもできます。これについては、後述します。*

概要:

1. **アンバサダー**が、疑わしい`アーティファクト` (ファイル) に報奨金をかけます。
2. **Microengines** hear about this new artifact by listening for Ethereum events (via `polyswarmd`).
3. 当該アーティファクトが専門知識分野の範囲内かどうかを各**マイクロエンジン**が判断します。
4. **マイクロエンジン**は、アーティファクトに関する知見がある場合、`アサーション`を生成し、その`アサーション`に対して NCT を`投資`します。この NCT はいったん BountyRegistry スマート・コントラクトに預託されます。
5. **アンバサダー**がすべての`アサーション`を検討し、`判定`を顧客に返します。
6. (時間の経過)
7. **評価者**が、アーティファクトの悪意性について*確認・評価*を行います。
8. 不正解だった**マイクロエンジン**が預託した資金を利用して、正解を出した**マイクロエンジン**に報酬が支払われます。

このプロセスの詳細については、[PolySwarm ホワイトペーパー](https://polyswarm.io/polyswarm-whitepaper.pdf)をご覧ください。

## マイクロエンジンの構成

概念的に、マイクロエンジンは以下から構成されています。

1. `N` 個の**分析バックエンド**: アーティファクト (ファイル) を取り込んで、`悪意がある`か`無害`かを判別します。
2. `1` 個の**判定生成エンジン**: 分析バックエンドの出力を取り込み、単一の`判定` + `信頼区間`を生成します。
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