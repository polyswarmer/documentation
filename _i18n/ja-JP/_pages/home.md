## ようこそ

ようこそ。PolySwarm に興味を持っていただき、ありがとうございます。

ここには、PolySwarm での開発を開始する際に必要となるすべての情報があります。

コードに立ち入る前に、現在の知識、状況を確認してみましょう。

* PolySwarm に参加するのはどのような感じでしょうか?
* 自分のユース・ケースに適合するのはどの役割ですか?
* どのコミュニティーに参加しますか?
* エンジンのパフォーマンスはどのように監視しますか?
* コミュニティーとは何ですか? エンジンとは何ですか?

それでは、大まかな概念をいくつか確認し、該当する場合には詳細に掘り下げましょう。

## ポータル

PolySwarm ポータルは、以下を行うための PolySwarm のワンストップ・ショップです。

* エンジンのパフォーマンスを追跡する
* コミュニティー (以下を参照) を見つける
* エンジンに名前を付ける
* プロファイルを作成する
* セキュリティー専門家と交流する

... など

[ポータルの探索 →](https://polyswarm.network/)

## コミュニティー

PolySwarm は、一連のコミュニティーで構成されます (そのため、「たくさん」を表す「Poly」を冠しています)。 各コミュニティーは特定の目的を果たし、全員に参加を許可する場合もあれば、特定の参加者のみにアクセスを制限している場合もあります。

PolySwarm の立ち上げ時には、以下の 2 つのコミュニティーがあります。

* **Genesis: 公開メインネット・コミュニティー**: 全員が参加できます。
* **Hive: 非公開テスト・コミュニティー**: Genesis での立ち上げの準備をする初期パートナー用の非公開コミュニティー。

今後、このリストは拡張されて、アンバサダーやマイクロエンジン開発者が対象ユーザーを管理できるようになります。 将来のコミュニティーとして、以下のようなものが考えられます。

* 準拠している限られた参加者間でアーティファクトを共有する GDPR 準拠のコミュニティー
* 相互に機密保持契約を交わした MSSP とセキュリティー専門家のネットワーク

誰でも独自のコミュニティーを管理し、PolySwarm ポータルでそのコミュニティーを公開できます。

### チェーン: ホームとサイド

各コミュニティーには、「ホームチェーン」と「サイドチェーン」があります。いずれも他のコミュニティーと共有できます。 一般的に、「ホームチェーン」は暗号資産がネイティブに存在している場所であり、「サイドチェーン」は PolySwarm トランザクションが行われる場所です。

例えば、最初の公開コミュニティーである **Genesis** は以下のように構成されています。

* `homechain` (ホームチェーン): イーサリアム・メインネット
* `sidechain` (サイドチェーン): [Clique 構成](https://github.com/ethereum/EIPs/issues/225)で実行されている一連のホストされた `geth` ノード

PolySwarm Nectar (NCT) は、イーサリアム・メインネット上にネイティブに存在しています。 残念ながら、イーサリアム・メインネットは遅すぎ (~15s ブロック時間)、また PolySwarm で要求されるタイプのマイクロ・トランザクションをサポートするにはあまりにも高すぎます。

PolySwarm の参加者は、イーサリアム・メインネットで直接トランザクションを実行するのではなく、メインネットから Genesis サイドチェーンに NCT をリレーし、そのサイドチェーンでビジネスを実行します。 `polyswarm-client` の [`balancemanager`](https://github.com/polyswarm/polyswarm-client/tree/master/src/balancemanager) を使用することで、サイドチェーンで最小限の残高を簡単に維持できます。

この分割チェーン設計により、以下のような 2 つの主要なメリットが得られます。

1. **拡張可能性** 現在、イーサリアムの拡張性は高くありません (もちろん、イーサリアムでは、この問題に取り組んではいますが)。そのため、低待ち時間/高スループットのトランザクションが必要な場合は、アプリケーションで独自の「レイヤー 2」の拡張対応ソリューションを実装する必要があります。
2. **機密性** PolySwarm では、アクセスが制限された非公開コミュニティーという概念がサポートされます。 この分割チェーン設計により、それが可能になっています。

<button disabled>コミュニティーの参照 → (近日公開予定)</button>

## PolySwarm マーケットプレイスでの役割

PolySwarm エコシステムに参加する方法はいくつかあります。マイクロエンジン、アンバサダー、評価者などを作成してください。

[PolySwarm における自分に適合した役割の判別 →](/concepts-participants/)