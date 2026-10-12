# 設計決定 (Design Decisions)

## 1. Design Decisions

実装前のブレインストーミングで確定した設計決定を記録する。各決定は「背景 → 選択 → 理由」で残す。

### 追加された前提(攻撃の強度と対象)

- 隔離された仮想環境内で、**実際のクラッカー対企業ネットワーク**を再現する。
- 自分たちが所有する Ephemeral / Isolated 環境に対しては、**手加減なし(容赦ない)攻撃**を実行する。
- Web / API だけでなく、**VPN・ネットワーク境界のクラッキング**も検証対象に含める。
- 目的は常に「自分たちのアプリ・ネットワーク・クラウドをより強固にする」ための検証であり、「Legal / Safety Design」(Legal / Safety)の枠内で行う(所有・隔離・許可が前提)。

---

### Decision A — Authoring Model: Hybrid(確定)

**論点**: Security Test と Attack Scenario をどの記法で書くか。

**選択: Option 3 — Hybrid**

- **Security Test**(個別の期待挙動。認可・IDOR などロジックを要する検証)→ **Rust**(`#[security_test]` proc-macro + ビルダー API)
- **Attack Scenario**(攻撃経路・トポロジ・多段ステップ)→ **宣言的 DSL**(経路が一目で読め、Attack Graph を自動生成できる)
- DSL で表現しきれない複雑ステップは **Rust 関数を呼ぶエスケープハッチ**(`action: custom, run: "..."`)で逃がす。

**段階導入の方針**:
1. MVP では **Rust 側(Security Test API + Scenario ビルダー)を先に実装**し、`cargo test` 相当の体験を最優先で成立させる。
2. **DSL は Phase 3 で後付け**する。DSL は Rust ビルダー API の内部表現を共有する「薄い宣言的ラッパ」として設計し、言語設計の泥沼を避ける。

**理由**:
- 「Security Test = Executable Specification」(ロジック)と「Attack Scenario = 俯瞰可能な攻撃経路」(トポロジ)は求めるものが異なり、一方へ寄せると必ず歪む。
- Rust 先行なら言語設計で止まらず、早期に動く体験を出せる。DSL は内部表現を共有して後付けできる。
- 純 DSL 単独は IDOR/認可など動的ロジックの検証で早々に表現力の壁に当たる。

**未決(今後詰める)**: DSL の具体フォーマット(YAML か独自か)、エスケープハッチの境界ガイドライン、Rust/DSL どちらで書くべきかの判断基準。

**MVP implementation note (settled in #2)**: the mechanics of the Rust Security Test API are fixed as follows. The later units (#3 to #6) build on this topology.

- `#[security_test]` is a proc-macro in the crate `redstep-macros`, and tests are discovered through `inventory` (a proc-macro has to live in its own crate).
- Crate topology is a workspace: `crates/redstep` (core + thin CLI) and `crates/redstep-macros`.
- A test is `async fn(ctx: &TestContext) -> redstep::Result<()>`. The runner runs tests sequentially in name order on one current-thread runtime, maps `Ok` to Passed, `Err(Check)` to Failed, any other `Err` or a panic to Errored, and exits zero only when every test passed.
- Scope is resolved at run level. The CLI's `--allow host:port` is an interim source; the durable origin is the environment definition (Decision C). A `ScopedTarget` is constructible only through the resolver (Decision F, security.md section 2).

---

### Decision B — Attacker Capability: Hybrid(確定)

**論点**: 攻撃能力(スキャン・Web 攻撃・認証情報クラック・VPN/ネットワーク攻撃・Exploit)をどう実装するか。

**選択: Option 3 — Hybrid(Rust コア + ツールアダプタ、統一 Capability 抽象)**

- 能力を統一 trait `Capability` で抽象化し、実体を2系統に分ける:
  - **Native Rust プリミティブ**: 到達性 / ネットワークセグメンテーション / HTTP 仕様検証 / 認可チェック など、**速く・決定的・毎回 CI で回す**もの。
  - **Tool アダプタ**: nmap / hydra / sqlmap / metasploit(msfrpc)/ VPN・暗号クラック など、**本格オフェンシブ**は実ツールを起動して結果を取り込む。
- 両系統を同じ `Capability` インターフェースと **Evidence モデル**に正規化する。
- 攻撃を **Intensity Level**(`Safe` / `Controlled` / `Aggressive`)でタグ付けし、Scope / Allowlist と組み合わせて段階的に解放する。「容赦ない攻撃」は `Intensity::Aggressive` として**明示的に解放**する形にし、「隔離環境では全力、しかし誤って本番に向けない」を両立する。

**攻撃者コンテナのベースイメージ: Kali Linux 系(確定)**

- 最初から Kali Linux 系をベースにし、主要なオフェンシブツールが揃った状態から始める。
- 軽量イメージに後から足す方式は採らない(ツール網羅性と現実の攻撃者環境への近さを優先)。

**段階導入の方針**:
1. **MVP**: Native プリミティブ(TCP 到達性・セグメンテーション・HTTP 仕様検証)+ `Capability` trait + `Intensity` + Evidence 正規化のみ。これで 「First Prototype Goal」 の最初の PoC(「攻撃者は DB に直接到達できない」)が成立する。
2. **Phase 4 以降**: Tool アダプタ(nmap → hydra → sqlmap → metasploit → VPN/暗号クラック)をプラグインとして順次追加。「容赦ない攻撃」はここで本領発揮。

**理由**:
- hydra / metasploit / VPN クラックの Rust 再実装は非現実的。一方で全能力を外部プロセスにすると、毎回回したい Safe Check まで重くなる。
- 統一 `Capability` 抽象を先に用意すれば、native でもツール経由でも**同じ Evidence・同じ安全装置(Intensity × Scope)**を通せる。「Security Testing Levels」(Security Testing Levels)と 「Legal / Safety Design」(Safety)の設計と一致する。

**未決(今後詰める)**: Capability / Evidence の正規化スキーマ、Intensity と Scope ガードの具体的な連動方法、どのツールをどのアダプタ順で追加するか、Kali ベースイメージのサイズ最適化(CI 用の slim 版の是非)。

**MVP implementation note (settled in #3)**: the native, Safe capability layer is fixed as follows. The oracle unit (Decision J) and the evidence unit (Decision D) build on these shapes.

- The `Capability` trait has an associated `Value` type and `async fn execute(&self) -> Result<(Observation<Value>, EvidenceDraft)>` (the #5 note supersedes the original `Evidence` return: a capability emits a draft, the store mints the record). It is used through a generic `TestContext::run`, not a `dyn` registry; the plugin registry is deferred.
- A capability holds a `ScopedTarget` (the scope gate is type-enforced, since only the resolver produces one) and reports its `Intensity`. `run` refuses any intensity but `Safe`, surfaced as `Error::IntensityRefused`; `Controlled`/`Aggressive` await the authorization and isolation proof (Decision F).
- Minimal pure model types, each superseded later: `Intensity { Safe, Controlled, Aggressive }`; `Observation<T> { value, confidence }` with `Confidence { High, Medium, Low }` (Decision J's observation, without the signals and corroboration); `Evidence { capability, target, intensity, reachable, confidence }` (Decision D's record, without the store, id, timestamp, or artifacts).
- `TcpConnect` (native, Safe) maps a connection that opened to reachable/High, a refusal to unreachable/High, and a timeout to unreachable/Low. The timeout stays `Low` so a transient failure cannot read as a confident boundary hold (a false PASS); the connect is bounded by a timeout.

---

### Decision C — Environment & Orchestration: Hybrid + bollard(確定)

**論点**: 隔離環境(攻撃者 + ターゲット群 + ネットワーク境界)をどう定義・生成・破棄し、Docker をどう操作するか。検証の主対象が「ネットワーク境界そのもの」である以上、境界はフレームワークが握る必要がある(設計原則 4「Environment is first-class」、「Network Testing」「Network Testing」)。

**選択 1: 環境定義モデル = Option 3 — Hybrid**

役割分担:
- **フレームワークが所有**: セグメント、境界(firewall / routing)、攻撃者配置、環境の生成・破棄(Ephemeral ライフサイクル)。← 検証対象なので第一級。
- **ユーザーが提供**: ターゲットの中身(= 既存の Docker イメージ、または compose サービスを参照)。ビルド・env・volume の二重管理を避ける。

```yaml
environment:
  # ネットワーク境界はフレームワークが握る（検証の主対象）
  segments: [internet, dmz, internal]
  boundaries:
    - { from: internet, to: dmz,      allow: ["web:443"] }
    - { from: dmz,      to: internal, allow: ["api:8080"] }
    - { from: internet, to: internal, allow: [] }

  # ワークロードの中身は既存資産を参照（再発明しない）
  workloads:
    - { name: web, from: compose(./docker-compose.yml#web), segment: dmz }
    - { name: api, from: image(myapp/api:latest),           segment: internal }
    - { name: db,  from: image(postgres:16),                segment: internal }

  attacker: { segment: internet }   # Kali ベース
```

**選択 2: オーケストレーション手段 = (i) `bollard`(Rust の Docker API クライアント)**

- プログラムから直接 Docker API を叩き、ネットワーク作成・コンテナ配置・境界制御・Ephemeral 破棄を型安全かつ精密に制御する。
- docker CLI の shell 呼び出し(出力パース依存で脆い)、testcontainers-rs(複雑なセグメンテーション制御に力不足)は採らない。

**理由**:
- 検証の主対象が「ネットワーク境界」である以上、境界を compose に預ける案(Option 1)は根本的に弱い。ターゲット定義まで独自化する案(Option 2)は既存アプリ資産と二重管理になり採用障壁が上がる。
- Option 3 は「境界はフレームワークが握り、中身は既存資産を参照」で両立。bollard はこのセグメント/境界制御・Ephemeral 破棄をプログラムから精密に回すのに最適。

**段階導入の方針**: MVP では `internet / internal` の2セグメント + `web / api / db` の最小構成から始め、DMZ・VPN・複数セグメント・ルーティングは段階追加する。

**未決(今後詰める)**: 環境定義フォーマットの詳細(DSL / A の Attack Scenario DSL との統合)、compose サービスを引き取りつつ独自ネットワーク定義を無視する統合ロジック、境界(firewall / routing)を Docker ネットワーク上でどう実装するか(iptables / 独立ネットワーク + ゲートウェイ等)、VPN 境界の表現方法。

---

### Decision D — Evidence & Attack Path: Layered(確定)

**論点**: 攻撃結果をどんなデータモデルとして残すか。設計原則 5「Evidence over Simple PASS/FAIL」の核心。B で決めた2系統(Native プリミティブ / ツールアダプタ)の出力を同じ器に正規化する必要がある。

**選択: Option 3 — Layered(2層構造)**

- **下層 = Evidence レコード(append-only・不変。唯一の真実)**: Capability 実行1回ごとの原子的な事実。native でもツール経由でも同じスキーマに正規化する。
- **上層 = Attack Path / Graph(導出ビュー)**: Evidence を参照して構築する射影。ノード/エッジは Evidence の ID を指すだけ。

```rust
// 下層：原子的な事実（すべての能力がこれを吐く）
struct Evidence {
    id: EvidenceId,
    capability: String,          // "tcp_connect" / "nmap" / "hydra" ...
    source: NodeRef,             // どのセグメント/ホストから
    target: NodeRef,             // どこへ
    intensity: Intensity,        // Safe / Controlled / Aggressive
    result: Outcome,             // Pass / Fail / Error
    artifacts: Vec<Artifact>,    // HTTP 全文, ツール raw 出力, pcap, ログ
    reproduction: Reproduction,  // 再現コマンド/入力
    timestamp: DateTime,
}

// 上層：Evidence を指すだけの射影（可視化・集計用）
struct AttackGraph {
    nodes: Vec<Node>,            // host / segment / privilege / credential
    edges: Vec<Edge>,            // { from, to, evidence_id, result }
}
```

**理由**:
- 「Evidence」 が求める Evidence(HTTP 全文・ログ・pcap・再現情報)と 「Attack Scenario」/10 が求める Attack Graph は別物。前者は「原子的な事実」、後者は「事実をつないだ構造」。Flat Log(Option 1)は後者を失い、Graph ファースト(Option 2)は前者を薄くする。
- Evidence を唯一の真実にすれば、領域 E(Report / JSON / SARIF)も Attack Graph 可視化も**同じ下層データからの射影**にできる — 最も壊れにくい。
- B の「native とツールを統一 Capability にする」決定と直結(その出力の受け皿が統一 Evidence スキーマ)。

**段階導入の方針**: MVP では単純な Security Test は Evidence レコードを吐くだけ(Graph 化なし)。Attack Scenario のときだけ Evidence から Attack Graph を導出する。

**未決(今後詰める)**: Evidence スキーマの確定(Artifact / Reproduction の具体型)、Attack Graph のノード種別(host / segment / privilege / credential)の正式定義、Evidence の永続化先(ファイル / 埋め込み DB)、大きな artifact(pcap 等)の保存戦略。

**MVP implementation note (settled in #5)**: the evidence record is reshaped from the #3 placeholder into the capability-neutral, append-only record. This supersedes the `Evidence { capability, target, intensity, reachable, confidence }` of the Decision B note, and the Rust sketch above diverges from it as recorded here.

- **Capability-neutral outcome.** `reachable: bool` was `TcpConnect`-specific. The record now carries the observation erased to a `serde_json::Value` plus its `Confidence` and a short summary (`observed` / `confidence` / `summary`), so a non-bool capability (an HTTP header check, a credential find) stores its value without a lossy coercion to bool. This closes the constraint recorded in the #3 review (reshape before the first non-reachability native capability).
- **Observation, not verdict.** The sketch's `result: Outcome // Pass/Fail/Error` is retired from the record, not renamed. Per Decision J the record holds the observed fact; the `Verdict` stays in `Judgement`, and the two *will be* linked by an evidence id in a later step (the link does not exist yet, see the deferral below). This is the Decision J note's "reconcile Decision D's `Outcome` with `Verdict` before #5" done: #5 invents no second name.
- **Producer vs store.** A capability produces a pure `EvidenceDraft` (capability, target, intensity, observed, confidence, summary, reproduction) with no id and no timestamp, since it cannot know either. The run-level `EvidenceStore::append` stamps a run-scoped sequential `EvidenceId` and an epoch-millis timestamp (the runner supplies the clock, so the store stays pure and deterministic), producing the immutable `Evidence`. The store is append-only by construction: it exposes append (crate-internal) and read, and no mutate or remove, so the compiler holds the invariant.
- **Collection.** `TestContext` gains an evidence sink beside the judgement sink; `run` records one draft per capability execution. The runner drains each test's drafts into `RunSummary`'s `EvidenceStore`, in test-then-draft order. Serde (`serde` + `serde_json`) is added to the model so the record and the store round-trip, which is the Decision E canonical-JSON pivot's input; no second model is introduced.
- **Deferred to their producers (recorded, not dropped).** `source` (the sketch's `NodeRef`) waits for the environment/segment model (Decision C) and the attack graph; `artifacts` wait for the tool adapters; the attack-graph projection, the success witness, large-artifact storage, and persistence beyond in-memory + JSON are all out of scope here (per the issue). `reproduction` is in now, because `TcpConnect` can populate it (target + timeout) and Decision V's witness builds on it. The evidence-id-to-`Judgement` link is also deferred: its only consumer is #6 reporting, so building it now is an interface with no caller. The Decision J note's constraint stands and is restated: **#6 must not freeze the canonical JSON before that link lands.** Scope note (corrected from the Decision J forward note, which called it a field on `Judgement`): the id is assigned run-scoped at *drain* time, after the test body that built the `Judgement` has returned, and a `Judgement` and the `EvidenceDraft` it judged share no correlation key today. So the link is not a one-field add. It needs either a run-scoped id source threaded into `TestContext` at construction (changing the public `TestContext::new` signature) and surfaced against the observation, or a per-test correlation token carried from `run` through the returned value and remapped to ids by the runner at drain. Both change what `run` returns (currently a bare `Observation`). The link step before #6 must budget for that, not for a field.

---

### Decision E — Reporting: Canonical JSON Pivot(確定)

**論点**: D の Evidence(唯一の真実)から、人間可読レポート / JSON / SARIF / Attack Graph 可視化をどのアーキテクチャで生成するか。SARIF は本来 static analysis 向けで、多段の攻撃経路をそのまま表現できない点をどう扱うか。

**選択: Option 2 — Canonical JSON Pivot**

- Evidence + Attack Graph を**1つの正規 JSON スキーマ**にシリアライズし、それを「唯一の中間表現」とする。
- terminal / SARIF / HTML(グラフ可視化)はすべて**その正規 JSON からレンダリングする薄いレンダラ**にする。フォーマット間のズレを構造的に防ぐ。
- 正規 JSON 自体を外部ツール連携の API として扱う。CI の Merge Gate 判定も正規 JSON を見て行う。

```text
Evidence Store ──> Canonical JSON (= 機械可読の真実の輸出形)
                        ├──> terminal report  (cargo test 風)
                        ├──> SARIF            (codeFlows に攻撃経路を写像)
                        └──> HTML / Attack Graph 可視化
```

**SARIF 写像方針(確定)**:
- 1つの FAIL した期待(例:「Internet から DB に到達できてしまった」)= 1つの SARIF `result`。
- 攻撃経路の各ステップ = `result.codeFlows[].threadFlows[].locations[]`(SARIF の経路表現を流用)。
- 再現情報・Evidence ID = `properties` bag に格納。

**理由**:
- D の「Evidence = 唯一の真実、各出力はその射影」と一直線に繋がる。正規 JSON を1枚挟むことで全出力が同じ中間表現の射影になり、フォーマット間のズレ(Direct Renderers の致命的弱点)を防げる。
- 汎用テンプレートエンジン(Option 3)は過剰。必要になれば正規 JSON の上に後付けできる。

**段階導入の方針**:
- MVP: **terminal report + 正規 JSON** のみ(`cargo test` 風の PASS/FAIL + Attack Path 表示)。Merge Gate は正規 JSON の exit code / 集計で判定。
- Phase 6: SARIF と HTML グラフ可視化を正規 JSON のレンダラとして追加。

**未決(今後詰める)**: 正規 JSON スキーマの確定(D の Evidence/Graph との対応)、SARIF の severity マッピング規則、HTML 可視化の実装方法、CI アノテーション(GitHub/GitLab)の具体形式。

---

### Decision F — Safety / Scope: Defense-in-Depth(確定)

**論点**: 「容赦ない攻撃(metasploit / hydra / VPN・暗号クラック)」と「正当なテスト(「Legal / Safety Design」)」を両立させる安全装置。誤爆すれば本物の攻撃になるため最重要。

**選択: Option 3 — Defense-in-Depth(多層防御)**

独立した複数層で担保し、1層抜けても別の層が止める:

1. **ネットワーク隔離(最下層・物理的)**: framework が作る Ephemeral 環境は**既定でインターネット/本番への経路を持たない**(C の bollard で egress 無しネットワークを生成)。攻撃パケットがそもそも外へ出られない。
2. **Scope Gate(ソフトウェア)**: 全 Capability がターゲットを Scope リゾルバ経由で解決。allowlist 外はハードエラー。生 IP/URL の直接指定を型で禁止する。
3. **Intensity ラダー**: `Aggressive` は **(a) 明示的 opt-in** かつ **(b) 対象が framework 生成の隔離環境であること**(isolation proof)の両方が揃わないと実行不可。ユーザー提供の外部エンドポイントには Aggressive を絶対に向けられない。
4. **Safe-by-default**: 既定 Intensity = `Safe`、既定 Scope = deny。何も指定しなければ何も壊さない。

**理由**:
- B で metasploit・hydra・VPN/暗号クラックという本物の攻撃兵器を扱うと決めた以上、安全を単一チェックに委ねるのは不整合。「容赦ない攻撃」を本当に解放するには、その攻撃が物理的に外へ出られない保証(ネットワーク隔離)が土台に要る。
- 「隔離環境では全力、本番には絶対飛ばない」は多層防御でしか綺麗に両立しない。`Aggressive` を「隔離環境 × 明示 opt-in」に縛るのが肝。
- C で「境界は framework が bollard で所有」と決めたので、egress 無しネットワークの生成はその延長で自然に実装できる。原則 9「Safe by Design」/ 「Legal / Safety Design」 に最も忠実。

**段階導入の方針**:
- MVP 必須: 層1(egress 無しの隔離ネットワーク)+ 層2(Scope Gate)+ 層4(Safe-by-default)。
- 層3 の完全版(isolation proof による Aggressive 縛り)はツールアダプタを入れる Phase 4 と同時に本格化。それまで Aggressive は未解放でよい。

**未決(今後詰める)**: isolation proof の具体的な実装(何をもって「隔離環境」と証明するか)、隔離の抜け道(DNS / サイドチャネル / 共有カーネル経由)の塞ぎ方と継続検証、Scope allowlist の記法、Aggressive opt-in の UX(CLI フラグ / 環境定義 / 両方)。

---

### Decision G — Tool Integration: Plugin + Role 階層(確定)

**論点**: 既存ツール(ZAP / Nuclei / InSpec / OpenVAS / nmap / sqlmap / metasploit)との関係。「Existing Tools との関係」「置き換えず統合・利用」/ 「Scanner と Security Test の分離」「Scanner と Security Test を分離して統合」/ 「Next Research Questions」-18「Plugin architecture」が出発点。

**選択: Option 3 — Plugin Architecture + Role 階層**

プラグイン機構を持ちつつ、役割ごとに契約を分ける(「Scanner と Security Test の分離」 の分離を型で表現):

- **Capability アダプタ**: Attack Scenario のステップとして能動実行(nmap, hydra, sqlmap, metasploit)。Intensity・Scope Gate(F)を通す。
- **Scanner 統合**: 一括で問題を発見し結果を Evidence/Finding に取り込む(Trivy, Nuclei, OpenVAS)。Attack 経路とは別フロー。
- **Interop Importer**: 独立実行するツールの native 出力を取り込むだけ(ZAP の JSON, InSpec, 既存 SARIF)。実行制御はしない。

```rust
trait CapabilityAdapter { async fn execute(&self, ctx: &AttackCtx) -> Vec<EvidenceDraft>; } // 能動攻撃
trait ScannerAdapter    { async fn scan(&self, target: &ScopedTarget) -> Vec<Finding>; }     // 一括発見
trait InteropImporter   { fn import(&self, raw: &[u8]) -> Vec<EvidenceDraft>; }               // 結果取り込み
```

**プラグイン形態の決定: Rust の静的プラグイン(コンパイル時組み込み)から始める(確定)**

- 安全で単純。WASM 等の動的ロードは将来の検討事項とし、当面は採らない。

**理由**:
- 「Scanner と Security Test の分離」 が「Scanner と Security Test を分ける」と宣言済み。単一アダプタ契約ではこの分離を型レベルで潰す。
- ZAP / InSpec は自前完結型。framework が実行制御する Capability に混ぜると F の隔離・Scope 保証の外で動くものを内枠に入れることになり危険。「結果だけ取り込む Interop」として分けるのが安全で自然。
- B のツールアダプタ(Capability)は、この3階層のうち Capability 階層の具体化と位置づけられる。

**ツール優先順位**:
- MVP: native のみ(外部ツール統合なし)。
- Phase 4: Capability に **nmap**、Scanner に **Trivy** + **Nuclei** を第一級で。
- Phase 5 以降: Capability に hydra → sqlmap → metasploit。
- Interop: ZAP / InSpec / 外部 SARIF 取り込みは随時。

**未決(今後詰める)**: CapabilityAdapter と B の Capability trait の統合関係(同一か包含か)、各階層のレジストリ登録方法、ツールのバージョン差・出力フォーマット変更への追従戦略。

---

### Decision H — Vulnerable Playground: Hybrid(教育層なし)(確定)

**論点**: 「Security Education」 +「実際のクラッカー対企業ネットワークをデモ」するための脆弱ターゲット群をどう用意するか。

**選択: Option 3 — Hybrid(教育層は含めない)**

- **既存脆弱アプリ**(Juice Shop, DVWA 等)を各ホストの中身として再利用(アプリ層脆弱性の深さを借りる)。
- **framework が企業ネットワークのリファレンストポロジを提供**:internet / dmz / internal セグメント、境界、VPN、多段の攻撃経路。
- 既存アプリだけでは足りない「横展開の中継点」(内部 Admin API、Secrets ストア等)は**薄い自作内部サービス**で補う。
- C の環境モデル(workloads 参照 + framework が境界を所有)にそのまま乗る。Playground = その構造のリファレンス実装。

**教育層は作らない(確定・方針転換)**:
- 以前の Option 3 案に含めていた「各テストに解説メタデータを付ける教育層」は**スコープから除外**する。
- 「教育」はプロジェクトの動機(開発者がセキュリティの重要性を自然と意識するようになること)であって、システム機能として実装する対象ではない。

**段階導入の方針**:
- MVP は**小さな自作3層(web → internal-api → db)**のみ。「First Prototype Goal」 の PoC「攻撃者は DB に直接到達できない」を完全制御された最小構成で成立させる。
- Phase 5(App/API Security)で Juice Shop / DVWA を取り込み、アプリ層脆弱性を深掘り。
- リファレンス企業ネットワーク(VPN・DMZ・横展開込み)は Phase 5〜9 で段階構築。

**未決(今後詰める)**: リファレンストポロジの具体構成、薄い自作中継サービスの範囲、取り込む既存アプリのライセンス確認。

---

### Decision H-2 — rustc 風の実行可能な FAIL 診断(確定・横断方針)

**論点**: セキュリティテストが FAIL したとき、「何が問題で、どう直すか」まで丁寧に導く診断体験を提供するか。

**選択: 提供する。`rustc` のコンパイルエラーのように、実行可能な修正指針まで出す。**

- 修正ガイダンスは **テスト作者が1件ずつ書くのではなく、フレームワーク組み込みのチェック(到達性・セグメンテーション・認可など)が自動で出す**。
- FAIL 出力には最低限、**期待 / 実際 / 推定原因 / 修正のヒント / 対応する Evidence ID** を含める。
- テスト作者は任意で `.hint("...")` を足せるが、必須ではない(「教育層」のような必須メタデータにはしない)。

```text
FAIL  internet から database へ到達可能（本来は到達不可であるべき）
  期待: internet → internal は遮断
  実際: tcp:5432 が到達（Evidence: ev_12）
  推定原因: internal セグメントへの境界ルールが緩い
  修正のヒント: internet→internal の allow を空にする、または db を internal 専用ネットワークに隔離する
```

**理由**: これは「教育メタデータ層」とは別物で、フレームワークの**診断品質**の問題。組み込みチェックは FAIL の意味(例: セグメンテーション違反)を知っているので、作者の記述なしに実行可能な指針を出せる。開発者がセキュリティを意識するようになるという動機に、システムを汚さず自然に寄与する。

**位置づけ**: 領域 E(Reporting / Canonical JSON Pivot)と、アサーション / Capability の設計に属する横断的方針。正規 JSON の finding に `expected` / `actual` / `probable_cause` / `remediation` フィールドを持たせ、terminal/SARIF/HTML の全出力がそれをレンダリングする。

**未決(今後詰める)**: 組み込みチェックごとの remediation テンプレートの整備方針、ヒントの精度をどう担保するか、多言語(日本語/英語)対応の是非。

---


### Decision J — Verdict Oracle: Layered Oracle(確定)

**論点**: 「攻撃が成功した / 境界が守られた」を framework がどう判定するか。実ツール(sqlmap/hydra/metasploit)の雑多な出力から、信頼できる PASS/FAIL をどう導くか。ユーザー目標「実際に攻撃して上手くいくか/防げているかを検証する」の核心。

**先に:判定は2層ある(重要な意味論)**:
- **Observation(観測)**: 攻撃アクション自体が技術的に成立したか(資格情報を見つけた / TCP が繋がった / 行を抽出した)。
- **Verdict(セキュリティ判定)**: その観測は PASS か FAIL か。攻撃が成立したら通常は**セキュリティ的に FAIL**、境界が守られたら PASS(符号が反転する)。この2つを混ぜない。

**選択: Option 3 — Layered Oracle**

Observation / Expectation の分離を土台に、実ツールの誤爆に耐える層を足す:

1. **Signal Extractor(能力ごと)**: 生のツール出力 → **型付き Observation + confidence(High/Medium/Low)** に正規化。
2. **Expectation / Assertion 層**: ステップが期待を宣言、オラクルが Observation と突き合わせて Verdict。
3. **Corroboration(裏付け)**: 重要判定は複数シグナルで裏取りし、false positive/negative を抑える(例「DB 到達可能」= TCP 接続成功 かつ バナー応答 かつ 認証到達)。

```rust
struct Observation<T> {
    value: T,                 // reachable: true / creds: [...]
    confidence: Confidence,   // High / Medium / Low
    signals: Vec<Signal>,     // 裏付けに使った個別シグナル（Evidence に残す）
}

let obs = ctx.cap(TcpConnect::new(target("db"), 5432))
    .corroborate_with([Banner::Postgres, AuthPrompt])
    .await;
ctx.expect(obs.reachable()).to_be(false).min_confidence(Confidence::High);
```

**Verdict は3値 + Error: `Pass` / `Fail` / `Inconclusive`(+ `Error`)**。Inconclusive は CI で「gating しない情報」に回せる(Decision O と直結)。

**理由**:
- 目的は「実際に攻撃して本当に通るか/防げているかを検証する」こと。実ツールは誤検知が日常なので、単純なパターン判定や裏取りなしの観測では「攻撃できた/防げた」の誤報が起き、検証の信頼性が崩れる。
- confidence + corroboration で微妙なケース(TCP は繋がるがアプリは拒否 等)を正しく Inconclusive に落とせる → CI 安定性(O)に直結。
- 観測/判定の分離で符号反転が宣言的になり、D(Evidence)・H-2(rustc 風診断)に一直線で繋がる。

**段階導入の方針**:
- MVP: Observation の型 + Expectation 判定 + Verdict 3値まで。native 能力(到達性/HTTP/セグメンテーション)は裏付けシグナルが単純なので軽く実装。
- Phase 5: 誤検知の多い実ツール(sqlmap/hydra/metasploit)導入と同時に Corroboration(複数シグナル裏取り)を本格化。

**未決(今後詰める)**: 能力ごとの Signal 種別と裏取り規則の定義、confidence の算出方法、Inconclusive を CI でどう扱うかの既定(O で確定)、Observation 型の共通設計。

**MVP implementation note (settled in #4)**: the oracle's MVP shape is fixed. Reporting (#6) and later corroboration build on it.

- `Verdict { Pass, Fail, Inconclusive, Error }` (model layer) is the per-test result. It replaces the runner's placeholder `Outcome`, so the naming reconciliation the #2 and #3 notes deferred to "when J lands" is done.
- `Expectation<T> { expected, min_confidence }` and the pure `judge(&Observation<T>, &Expectation<T>) -> Judgement`. `Judgement { verdict, expected, actual, confidence }` carries the machine-readable reason. The sign is in the expectation: a test declares the safe value, so a mismatch (the attack succeeded) is a `Fail`.
- `judge` yields Pass / Fail / Inconclusive; a signal below the required confidence is `Inconclusive` whatever its value. The minimum confidence is **`High` by default** (fail-closed): an unqualified `expect(&obs).to_be(v)` on a weak signal (a timeout, a probe-side error) is `Inconclusive`, not a confident verdict, and a test opts down explicitly with `min_confidence(Low)`. `Error` is a run-level state (a body that errored or panicked), not produced by the oracle. Corroboration across signals stays deferred (noisy real tools), so a capability sets the confidence directly for now.
- `ctx.expect(&obs).min_confidence(c).to_be(v)` records a `Judgement` in an interior-mutable sink; `to_be` is the terminal (`ExpectationBuilder` is `#[must_use]`, so a forgotten terminal is a compile warning). `check` records a judgement too (a bare boolean). The runner builds a `TestContext` per test and aggregates the recorded judgements by `Verdict::severity` (`Fail` > `Error` > `Inconclusive` > `Pass`): a test that recorded **nothing** is `Inconclusive`, not `Pass` (it proved nothing), and a recorded `Fail` survives a later body error or panic rather than being demoted to `Error`.
- The run's exit code is `0` only when at least one test ran and every verdict is `Pass`; `Inconclusive` is non-zero (fail-closed), because an unconfirmed result must not read as a green gate. Decision O's informational treatment of `Inconclusive` is at the discovery-vs-replay layer, not this deterministic runner's exit.
- **Forward constraints for #5/#6 (recorded in review):** `Judgement` carries only `expected`/`actual`/`confidence`, not an evidence id, probable cause, or remediation. Decision H-2 requires those on a FAIL finding and Decision E treats the canonical JSON as a published contract, so **#5 (the evidence link) must land before #6 freezes the canonical JSON**, or #6's schema ships without `evidence_id` and #5 then versions a published contract. When the link is added, the evidence reference attaches at the `ExpectationBuilder` seam (a field on `Judgement`), **not** on the pure `Observation` and **not** inside `judge`. Separately, Decision D still plans an Evidence `Outcome` (Pass/Fail/Error); reconcile it with `Verdict` in place before #5 rather than letting #5 invent a second name.

---

### Decision N — 境界強制の実装方式: Layered + 境界セルフチェック(確定)

**論点**: J で判定する「境界が守られたか」の対象を、Docker 上で実際にどう作り、egress 無しの隔離をどう保証するか。C(bollard)・F(隔離を安全の最下層に)の具体化。

**Docker の土台プリミティブ**: 別ネットワーク = セグメント分離 / `internal: true` = egress 遮断 / 複数ネットワーク接続 = 意図した経路の表現。ただし素の Docker は L4 ポート単位の allow/deny ができない(接続可否は all-or-nothing)。

**選択: Option 3 — Layered(Membership 基盤 + 必要な境界だけ FW + 境界セルフチェック)**

- **基盤**: セグメント分離 = 別ネットワーク、egress 遮断 = `internal:true`。all-or-nothing で足りる境界はこれだけで実現。
- **必要時のみ**: ポート単位 / 非対称ルールが宣言された境界にだけ、**firewall ゲートウェイコンテナ**(nftables/iptables)を挿入。framework が境界定義を見て最小の機構を自動選択。
- **境界セルフチェック(必須)**: テスト本体を走らせる前に、「宣言した境界が実際に効いているか(禁止経路が本当に遮断されているか)」を framework 自身が検証してから Security Test / Scenario を実行する。F の isolation proof の具体化であり、`internal:true` の付け忘れ等による**偽 PASS を防ぐ**。

```text
環境生成時:
  1. 境界宣言を解析 → 境界ごとに「membership で足りる / FW 要る」を判定
  2. ネットワーク構築（internal:true で egress 遮断）
  3. 必要な境界に FW ゲートウェイ挿入
  4. ★ 境界セルフチェック: 攻撃前に禁止経路の遮断を framework が確認
  5. セルフチェック通過後にのみ Security Test / Scenario を実行
```

**理由**:
- 「First Prototype Goal」 の PoC は membership だけで成立 → MVP を軽量に始められる。現実の企業 NW(ポート単位境界)は FW が要る。「必要な境界だけ FW」で両立。
- 境界セルフチェックがないと、テスト基盤の境界が壊れていても全テストが偽 PASS になり検証全体が無意味化する。J の「判定の信頼性」重視と同じ理由で必須。
- membership も FW も bollard から構築・制御でき C と整合。

**段階導入の方針**:
- MVP: membership のみ(2セグメント internet/internal、`internal:true` で egress 遮断)+ 境界セルフチェックの最小版。
- Phase 4: ポート単位/非対称境界のための FW ゲートウェイコンテナを追加。DMZ・多段境界はここで。

**未決(今後詰める)**: FW ゲートウェイの実装(nftables/iptables の構成、特権コンテナと隔離の両立)、境界セルフチェックの具体的な検査項目と頻度、membership/FW のハイブリッド構成の内部表現、VPN 境界の表現方法(「Attack Tooling Survey」 の ike-scan 検証と接続)。

---

### Decision L — シナリオ状態モデル: Attacker State Graph(確定)

**論点**: 多段攻撃で攻撃者が獲得したもの(資格情報・セッション・シェル・到達点・権限)をステップ間でどう持ち回るか。「Attack Scenario」 の `from: web`(踏み台化)と 「Attack Simulation」 の Lateral Movement / PrivEsc の土台。

**前提**: pivot には「到達できる」だけでなく「そこから攻撃を実行できる足場(foothold)」が要る。状態モデルはこの足場を表現できねばならない。

**選択: Option 3 — Attacker State Graph**

攻撃者の状態を成長する(単調増加の)資産集合としてモデル化し、D の Attack Graph と同一視する:

- **AttackerState** = `footholds`(実行できる足場)+ `credentials` + `sessions` + `privileges` + `knowledge`
- **Foothold** = 攻撃を実行できる起点(初期 = 攻撃者自身の箱 / 獲得後 = web 上のシェル、コンテナ exec 等)。「到達可能」とは区別する。
- **ステップ = 遷移**: ある foothold から ターゲット へ能力を実行し、成功すれば新たな資産を獲得して state を拡張。
- **pivot = `foothold.execute(capability)`**。`from: web` は「web の foothold を起点に使う」の意。
- 獲得資産は D の Evidence を指し、**AttackerState の時間的射影がそのまま Attack Graph** になる(L と D が一体化)。

```rust
let web_foothold = ctx.from(attacker_box).exploit(target("web")).yields_foothold().await?;
ctx.from(web_foothold).http_get(target("api"), "/internal").expect(reachable()).await?;  // pivot
```
```yaml
- { from: attacker, action: exploit, target: web, yields: foothold(web) }
- { from: web,      action: http_get, target: api, path: /internal, expect: reachable }
```

**理由**:
- 「Ultimate Goal」「侵入した攻撃者は最終的に何ができるか」= 攻撃者 state がどこまで成長したかの検証。Option 3 はその state を第一級にする。
- D の「Evidence = 事実、Graph = 射影」と一体化(AttackerState の成長履歴 = Attack Graph)。状態の二重管理を避けられる。
- pivot を「足場からの実行」として明示モデル化でき、「Attack Simulation」 の Lateral Movement / PrivEsc がそのまま乗る。

**段階導入の方針**:
- MVP: AttackerState の骨格(初期 foothold = 攻撃者の箱、獲得した到達性・資格情報の記録)のみ。「First Prototype Goal」 の PoC は単段なので初期箱だけで成立。「将来の pivot に耐える器」を用意するに留める。
- Phase 5 以降: リモートシェルを yield する本格 pivot(Metasploit 導入と同時)。

**未決(今後詰める)**: Foothold の抽象化(シェル / コンテナ exec / ネットワーク位置をどう統一型にするか)、資産型(Credential/Session/Privilege)の設計、AttackerState と D の AttackGraph の具体的な対応関係、権限昇格(同一ホスト内の privilege 遷移)の表現。

---

### Decision M — プラットフォーム実現範囲 + mock/real 二系統(確定)

> ※ この決定以降は「このプロジェクトが最終的に何を実現するか(完成形の到達範囲)」の軸で決める。
> MVP スコープ(どこまでを最初に作るか)は実現範囲を決め切ってから最後に確定する。

**論点**: 対象 OS / プラットフォームの実現範囲と、実環境 / モックの扱い。

**選択(実現範囲)**:
- **Linux コンテナ** — 対象
- **Windows / Active Directory(実 VM)** — 対象
- **クラウド(AWS / Azure / GCP、実環境)** — 対象
- **Kubernetes / インフラ / IaC** — 対象
- **無線(WiFi / aircrack)・物理攻撃** — **非対象(non-goal)として宣言**。無線ハードウェア依存でモック不能・実機専用のため、下記の設計原則に合わない。VPN クラックは無線とは切り離し、IPsec/IKE の弱 PSK・漏洩鍵・設定不備として**ネットワーク層で**再現する(要望は満たす)。

**設計原則(確定・プロジェクトの芯)**:
> **「モックでも再現でき、かつ実機でも検証できる」対象だけを扱うテストフレームワークにする。**
> 物理ハードウェア依存でモック不能なものは扱わない。この原則が無線を外す根拠でもある。

**mock / real 二系統(Environment Provider 抽象)**:
- 各ワークロード種別が **real バックエンドと mock バックエンドの両方**を持ち、実行時に選べる。C の workload 抽象に乗せる。
  - クラウド → real(実 AWS/Azure/GCP)/ mock(LocalStack・moto 等)
  - Windows/AD → real(Hyper-V/QEMU の Windows VM)/ 軽量シミュレーション
  - Kubernetes → real クラスタ / ローカル(kind・k3d 等)
  - Linux ホスト/サービス → コンテナ(既定)/ 実 VM
- モックは CI での Ephemeral・安全・低コストな検証に、実機は本番に近い最終検証に使う。

**理由**:
- ユーザー指定で Windows VM・クラウドは実環境を扱う。同時に「基本はモックで回せる」ことを重視 → real/mock 二系統を第一級にする。
- 無線は実機専用でモック不能なため、上記の芯となる設計原則から自然に外れる。「できないことを正直に宣言する」点で F / 「Legal / Safety Design」 とも整合。

**未決(今後詰める)**: Environment Provider 抽象の具体設計(real/mock の切り替え方、同一テストが両方で通る保証)、Windows/AD の「軽量シミュレーション」で何をどこまで再現するか、VM オーケストレーションの実装(Hyper-V/QEMU/libvirt のどれを一次対象にするか)、クラウド mock(LocalStack 等)でカバーできない API の扱い。

---

### Decision O — 実行・信頼性モデル: CI gating を前提にしない(確定)

**論点**: 非決定的で遅い実攻撃ツールを使うなかで、どんな実行・判定の信頼性モデルを提供するか。

**選択: CI gating を前提にしない。レポート + Evidence を一次出力とする。**

- 実攻撃ツールは本質的に **flaky(非決定的)で遅い** → `cargo test` 的な緑/赤の **merge gate には馴染まない**。合否で merge を止めることを前提にしない。
- 一次出力は **レポート + Evidence**(D/E)。ローカルでも CI でも回せるが、**CI 連携は任意の informational(情報提供)**扱い。
- flaky なシグナルは J の `Inconclusive` に落とし、偽 Fail にしない。
- 決定性の補助(シード / タイムアウト / リトライ / スキャンプロファイル fast・full)は提供するが保証はしない。

**「CI/CD Integration」 / 原則 8 の修正**: 「CI-native(cargo test の security 版)」は、**必須の gate ではなく任意の informational 連携**へ格下げする。CI で回すこと自体は引き続きサポートする。

**Decision V による補強**: 上記は「探索(discovery)」についての方針。Decision V で導入する **Pinned Replay(捕捉した Success Witness の決定的な再実行)は gating 可能**であり、CI は「既知脆弱性の回帰」を確実に止められる。つまり **探索 = 非 gating / 既知条件の回帰 = gating 可能** の2層になる。

**未決(今後詰める)**: Inconclusive の既定の集計方法、informational として CI にどう表示するか、再現シードをどこまで効かせられるか。

---

### Decision U — AI-driven Security Testing: Exploration + Verification + 昇格機構(確定)

**論点**: AI(Claude / OpenAI 等)を使ったセキュリティテストをどう位置づけるか。AI に「制約なしで自由に攻撃させる」か「用意した攻撃手法を使わせる」か。

**安全面の前提**: F の Defense-in-Depth で環境は egress 無しの隔離なので、**AI の"自由"は『手法選択の自由』であって『隔離を破る自由』ではない**。隔離環境内でなら AI が何をしても外へ出られない → 自由攻撃も安全に成立する。

**選択: Option 3 — 2モード + 発見→コード化パイプライン(以下の形に shape)**

- **Verification モード(Curated)= 既定の人間ワークフロー**: エンジニアは普段、フレームワークの型付き Capability / 決められた攻撃手法でテストする。全行動が Scope Gate・Intensity・Oracle(J)・Evidence(D)を通る。
- **Exploration モード(Free)= 未知の攻撃手法の発見が目的**: AI が隔離環境内で手法を選ばず自由に攻撃する。生ログ + pcap を Evidence 化。
  - **主にフレームワーク開発**で使う(新しい攻撃手法を発見して追加するため)。
  - **フレームワーク利用者にも opt-in で開放**(自分の隔離環境に対する自由な AI セキュリティテスト)。
- **昇格(Promotion)機構**: AI が未知の攻撃を発見したら、**構造化された「昇格レポート」**を生成し、**Issue 起票**や **Capability / Scenario へのコード化**に繋げる。これが「発見→コード化」の出口。
- **AI プロバイダ抽象**: Claude(Anthropic API)/ OpenAI を差し替え可能な **AI Operator 抽象**で扱う(1社に固定しない)。

```text
[Exploration] AI 自由攻撃（隔離内・F に縛られ安全）
      │ 未知の攻撃を発見
      ▼
[Promotion] 構造化された昇格レポート → Issue 起票
      │ 人/AI がコード化
      ▼
[Verification] Capability / Scenario として再現可能テスト化（以後の既定ワークフロー）
```

**理由**:
- ユーザーの構想「自由攻撃で未知を発見 → フレームに落とし込む」が、まさに Exploration → Promotion → Verification のパイプライン。Free だけだと資産が貯まらず、Curated だけだと発見がない。両者を繋ぐと好循環になる。
- Free の安全性は F の隔離が既に担保済み → 「制約なしで自由に」を安全に実現できる。
- 「AI を使う方が効率的」という狙いを最大化しつつ、人間の日常利用は Curated で安定させられる。

**未決(今後詰める)**: 昇格レポートのスキーマと Issue 連携(GitHub Issue 等)、Exploration の生ログ → 構造化 Evidence への意味づけ、AI Operator が Capability を呼ぶ tool-use インターフェース、AI コスト管理、Free モードで AI に渡す権限範囲(シェル / Capability どちらも渡すか)。

---

### Decision K — 攻撃タクソノミ標準: 任意だが第一級のタグ付け(確定)

**論点**: 扱う攻撃手法を既存標準にどう対応づけるか。MITRE ATT&CK は攻撃者技術の共通言語で相互運用に効くが、U(AI が未知の攻撃を発見)を考えると既存 ID に収まらない攻撃も出る。

**選択: Option 3 — 任意だが第一級のタグ付け(ATT&CK 主軸 + OWASP 併用 + 未分類/独自を許容)**

- タクソノミをモデルとして第一級に持つが、**付与は任意(推奨)**。
- 各 Capability / Scenario に **ATT&CK Technique ID**(+ Application 層は **OWASP** Top10/API Top10/WSTG)を**タグ**として付けられる。
- カバレッジビュー・レポート(E)・ATT&CK Navigator 風ヒートマップは**このタグから自動生成**。
- **未分類(`unmapped`)や独自タグも正当**に扱う → U の未知攻撃は「暫定マッピング or unmapped」で登録でき、後から正式 ID に昇格できる。

```rust
#[capability(attack = ["T1190"], owasp = ["A03:2021"])]                 // 任意
struct SqlInjection { ... }
#[capability(attack = unmapped, note = "AI exploration で発見")]        // 未分類も可
struct NovelChain { ... }
```

**理由**:
- ATT&CK/OWASP 対応はカバレッジ可視化・SOC との対話・レポート相互運用で価値がある(独自のみはこれを捨てる)。
- U で「未知の攻撃を発見して昇格」と決めた以上、必須マッピングは未知の攻撃を登録不能にする。任意+未分類許容なら「標準タグで整理 + 未分類も正当 + 昇格で正式 ID 化」が成立し、K が U・E と一直線に繋がる。
- ATT&CK を主軸、Application は OWASP を併用。

**未決(今後詰める)**: ATT&CK のどのマトリクス(Enterprise/Cloud/Containers)をどこまで取り込むか、カバレッジ算出の定義(タグ有無だけか、実行結果も加味するか)、タグ付与を運用でどう促すか、未分類 → 正式 ID 昇格のワークフロー(U と連動)。

---

### Decision P — 攻撃者の起点(Vantage): 外部 + assume-breach を第一級(確定)

**論点**: 攻撃の起点をどこに置けるか。外部攻撃者(Internet 起点)のみか、assume-breach(侵害前提:既に内部に侵入済みの状態から開始)も第一級にするか。

**選択: 外部攻撃者と assume-breach の両方を第一級にする。**

- **External(外部起点)**: 初期 foothold = Internet セグメントの攻撃者箱。「Attack Simulation」/4 の基本形。
- **Assume-breach(侵害前提起点)**: 初期 foothold を**内部の任意セグメント/ホスト(例: DMZ の web を既に取得済み)に置ける**。「ここを取られたら内部にどこまで行けるか」を直接検証できる。
- L(Attacker State Graph)の「初期 foothold」をどこに配置するかで表現する。複数の起点シナリオ(外部 / 内部 / 特定ホスト侵害済み)を並行して定義できる。

```yaml
# 外部起点
scenario: external-to-internal
  vantage: { type: external, segment: internet }

# assume-breach 起点（DMZ の web を既に侵害済みとして開始）
scenario: breach-of-web-to-crown-jewels
  vantage: { type: assume_breach, foothold: web, privilege: www-data }
```

**理由**:
- 現実の高度な検証では「侵入を完全に防ぐ」だけでなく「侵入されても被害をどこで止められるか(blast radius)」が重要。assume-breach はこれを直接測れる。「Ultimate Goal」「侵入した攻撃者は最終的に何ができるか」の核心でもある。
- L で初期 foothold を第一級にしたので、その配置先を内部にも置けるようにするだけで自然に実現できる。

**未決(今後詰める)**: assume-breach 時の初期資産(どの権限・資格情報・セッションを与えて開始するか)の指定方法、起点ごとの期待結果(blast radius)の表現、assume-breach と境界セルフチェック(N)の関係。

---

### Decision Q — 攻撃データ管理: バージョン固定データパック + 明示的更新(確定)

**論点**: ワードリスト・Nuclei テンプレ・Exploit-DB・ペイロード・脆弱性 DB の扱い。鮮度(最新脅威の反映)と再現性(同結果の再現)のトレードオフ。

**決定的な制約**: F で「テスト環境は egress 無しの隔離」と決めたため、**テスト実行中に最新データを取得することは原理的に不可**。実行時取得(Option 2)は F と非両立のため採用不可。

**選択: Option 3 — バージョン固定「データパック」+ 明示的な更新ワークフロー**

- データを名前付き・バージョン固定の**データパック**として管理(`wordlists@2026.09`, `nuclei-templates@v10.x`, `exploit-db@<date>`, `vuln-db@<snapshot>`)。
- 環境生成時に、**マニフェストに固定されたバージョン**をキャッシュ/ステージングから投入(実行中は egress 不要 → F と整合)。
- **更新は明示的な操作**:隔離の外でマニフェストのバージョンを意図的に bump → 新しい固定スナップショットを取得(自動ではない)。
- **使ったパックのバージョンを Evidence に記録**(D の再現情報)→「いつのデータでこの結果か」が辿れる。
- 大きなデータ(rockyou 等)はオンデマンドで必要なパックだけ投入し、イメージ肥大を回避。

```text
data-manifest.lock:
  wordlists: 2026.09 / nuclei-templates: v10.3.1 / exploit-db: 2026-10-01 / vuln-db: osv-2026-10-05
環境生成 → 固定版をステージングから投入（egress 不要）
更新 → 隔離の外で update → manifest を bump → レビューしてコミット
Evidence → 使用パック版を記録（再現性）
```

**理由**:
- F の egress 遮断により実行時取得は採れない。丸ごと同梱(Option 1)はイメージ肥大と部分更新不能が痛い。
- パック単位ピン止め + 環境生成時投入 + 隔離外での明示更新で、F と整合しつつ再現性と鮮度を両立。使用版を Evidence(D)に残せば再現性が完全。
- Kali 同梱分(R で決定)とフレームワーク管理パックの境界も明確化できる。

**未決(今後詰める)**: データパックの配布/キャッシュ基盤(レジストリ / OCI アーティファクト / 独自)、パックの粒度、ライセンス(各ワードリスト/テンプレの再配布可否)、Kali 同梱分との重複整理(R と連動)。

---

### Decision R — 攻撃者イメージの構成と出所: 固定ベース + ツールプロファイル(確定)

**論点**: B で決めた Kali ベース攻撃者コンテナの中身をどう構成し、信頼性・ライセンスをどう担保するか。U の2モード(Verification は決まったアダプタツールで足り、Exploration は広いツールセットほど発見が増える)が構成に影響する。

**選択: Option 3 — ダイジェスト固定の最小 Kali ベース + 合成可能なツールプロファイル**

- **ツールプロファイル**で合成(`core` / `web` / `network` / `cloud` / `ad` …)。
- **lean イメージ(Verification 用)** = 必要プロファイルだけ(小・再現可能・CI 向き)。
- **full イメージ(Exploration 用)** = 広い or 全プロファイル(AI Free モード用、U と対応)。
- 各イメージは**ベースのダイジェスト固定 + 宣言マニフェストから再現ビルド**(Q と同じピン止め思想)。
- **ライセンス審査をプロファイル単位で**実施(Metasploit BSD 可、Cobalt Strike は除外済み、Nessus は Interop で別扱い)。
- **供給網信頼**: ベースのダイジェスト固定 + 再現ビルド + **SBOM 生成**で中身を常に明示・監査可能にする。

```text
attacker-image-manifest:
  base: kali-rolling@sha256:<digest>
  profiles: [core, web, network]
  sbom: generated
変種: lean(verification) = core + 必要分 / full(exploration) = 全プロファイル
```

**理由**:
- U の2モードに合わせ、イメージも lean(再現可能・検証用)と full(広い・発見用)の2変種が自然に要る。プロファイル合成で両立。
- フル全部入りは巨大・監査不能・ライセンス確認非現実的。最小厳選は Exploration の幅を殺す。プロファイルは中間で両取り。
- ダイジェスト固定 + SBOM + プロファイル単位のライセンス審査で「何が入り / どこから来て / 再配布してよいか」を明示(T と接続)。Q と同じ宣言+ピン止め思想で一貫。

**未決(今後詰める)**: プロファイルの正式な粒度と対応ツール、ベースイメージの入手元(公式 Kali / 自前ミラー)、SBOM 形式(SPDX/CycloneDX)、イメージ更新の頻度とダイジェスト bump のワークフロー、Exploration full イメージのサイズ上限。

---

### Decision S — 敵対者エミュレーション / C2: Hybrid(方針確定・実装は Phase 9)

**論点**: Sliver/Mythic/Havoc 等の C2 を Level 3 多段攻撃(「Security Testing Levels」)でどう扱うか。C2 はステートフルで長時間動く(implant → callback/beacon → セッション → 操作)点が一発実行の Capability と異なる。

**選択: Option 3 — G のプラグインで統合 + C2 セッション = L の Foothold + 薄い implant ライフサイクル層**

- **統合は G のプラグイン機構**(Capability アダプタ)を使う。並行サブシステムは作らない。
- **C2 セッション = L の Foothold の一種**(`C2Session` 型)。implant 投入 = foothold 獲得(`yields_foothold`)、ビーコン越しの操作 = その foothold からの Capability 実行。L の Attacker State Graph にそのまま乗る。
- 一発実行の Capability に無い部分 —— implant/セッションのライフサイクル(投入・callback 待ち・維持・破棄)—— だけを薄いオーケストレーション層として足す。
- **安全(F と整合)**: C2 サーバは攻撃者セグメントで動き、implant の callback は隔離ネットワーク内に閉じる(egress 遮断により本物の外部 callback は発生しない)。

**理由**:
- C2 は一発実行(Option 1)に収まらないが、専用サブシステム(Option 2)は G のプラグインと L の状態モデルを二重化する。
- 「C2 セッション = L の Foothold」と見なすのが綺麗。implant 投入で foothold を得て pivot する ── L で決めた多段攻撃モデルそのもの。足すのは implant ライフサイクル層だけ。
- F の egress 遮断で callback が隔離内に閉じ、安全に敵対者エミュレーションを実行できる。U の AI Exploration が C2 を道具にするのも同じ経路。

**未決(今後詰める)**: C2 の非同期(callback 待ち)を状態モデルにどう統合するか、どの C2(Sliver 一次候補)から着手するか、implant ライフサイクル層の API。

---

### Decision T — 法務 / 配布ポリシ: リスク階層型ガバナンス(確定)

**論点**: 攻撃ツールを同梱し本物の攻撃を実行する framework を配布する以上、「Legal / Safety Design」「正当なセキュリティテスト」を具体的な仕組みと文書に落とす。F が技術的安全装置、T はその上の法務・ガバナンス・文書層。

**選択: Option 3 — リスク階層型ガバナンス**

リスク階層に応じてガバナンス強度を変える(F の Intensity ラダー・M の mock/real 区分と連動):

- **文書(ベースライン・常時)**: SECURITY.md / README 用途明示 / **ACCEPTABLE_USE(利用規約)** / LICENSE(+ R の同梱ツールのライセンス明記)/ 免責。
- **低リスク(mock / 隔離 / Safe)**: ベースライン承認のみ。摩擦ほぼゼロ。
- **高リスク(実環境に向ける / Aggressive)**: 明示的なスコープ認可 —— 「対象を所有 or 許可されている」ことを宣言する**認可ファイル(スコープ宣言)**+ 確認ゲート。これが **F の Scope Gate の人間側の入口**。
- **監査**: 高リスク実行は「誰が・いつ・どのスコープに」を **Evidence(D)に記録**。
- **デュアルユース姿勢**: 攻撃手法は隠さないが Safe-by-default + 隔離ファースト。責任ある開示(responsible disclosure)の指針を添える。

**適用範囲 / 法域(確定)**:
- **全世界向け**のテストフレームワークにする。
- 規約・法務はコンピュータ不正利用に関する法令が国ごとに異なるため、差異がある部分は**まず米国と日本を優先**して整備し、順次拡大する。
- リリース前に専門家 / 法務レビュー(「Legal / Safety Design」 を更新:日本のみ → **米国・日本を優先した多法域**)。

**理由**:
- 文書のみ(Option 1)は責任として弱く実環境同意が無い。一律強制(Option 2)は mock/隔離の低リスク利用まで摩擦を課す。
- Option 3 は F の Intensity・M の mock/real とそのまま一致。「隔離 mock は軽く、実環境・Aggressive だけ明示認可」で、技術ガード(F)と法務ガード(T)を Scope Gate 一点で接続でき一貫する。
- 高リスク実行の同意を Evidence に残すことで「正当なテストであった」ことを後から示せる。

**未決(今後詰める)**: 認可ファイルのスキーマと UX、ACCEPTABLE_USE の具体文面、米国・日本の関連法令(米 CFAA、日本の不正アクセス禁止法等)の要確認ポイント、responsible disclosure 指針の内容、同梱ツール各ライセンスの再配布条件の精査。

---

### Decision V — Success Witness と Pinned Replay(確定)

**論点**: 実ツールを使うと探索は flaky(非決定的)になる。しかし攻撃が成功した瞬間の条件を捕捉・固定すれば、それは安定した静的チェックになるのではないか(現実のクラッカーも「どの条件で入れたか」を記憶している)。

**核心原則**:
> **攻撃経路を「探す」のは非決定的(flaky)だが、「見つかった条件を再検証する」のは決定的である。**
> (証明を見つけるのは難しいが、見つけた証明の検証は容易、と同じ構造。)

**選択: 2層のテストモデル + Success Witness の捕捉 + Pinned Replay の自動生成**

- **Discovery テスト(探索・flaky・非 gating)**: ファジング / ブルートフォース / AI Free 探索。仕事は「成功条件を見つけること」。遅く非決定的なので informational のまま。
- **Replay / 回帰テスト(決定的・gating 可能)**: 見つかった成功条件をそのまま固定して再実行。仕事は「既知の脆弱性がまだ存在するか」を高速・決定的に確認すること。

```text
SQLi:  探索（無数のペイロード, flaky） → 成功ペイロード+エンドポイントを固定 → 「まだ抜けるか?」を決定的判定
Brute: 探索（遅い, flaky）             → 「admin = Summer2024!」判明         → 「まだ受け付けるか?」を瞬時に決定的判定
```

**既存決定への嵌まり方**:
- **J(Oracle)**: 攻撃成功(= セキュリティ FAIL)を観測した瞬間に **Success Witness = 成功を再現する最小の正確な条件**(エンドポイント / ペイロード / 使った foothold・資格情報 / データパック版 / シード)を捕捉。
- **D(Evidence)**: Witness は Evidence の `reproduction` そのもの(既に「再現情報を残す」と決定済み)。
- **U(昇格)**: Witness から**固定された Replay テストを自動生成(codify)**。これが「発見→コード化」の中身。
- **O の修正**: 「探索は flaky・非 gating」はそのまま。ただし **Witness から生成した Replay は決定的なので gating 可能** → CI は「既知脆弱性の回帰」を確実に止められる(O で保留した CI gate の価値を、信頼できる部分だけ取り戻す)。
- **H-2 / 「Security Education」 ループ**: `発見 → Fix → Replay が今度は攻撃失敗 → PASS` が回る。

**留保**: 大半の成功条件は決定的に再実行できるが、真のレースコンディション / タイミング依存攻撃は条件を固定しても再実行がなお確率的になり得る。その場合も **Witness(条件)は必ず捕捉・レポート**するが、その Replay は gating ではなく informational とする(framework が「この Replay は決定的か」を分類する)。

**未決(今後詰める)**: Success Witness のスキーマ(能力ごとに何を記録すれば再現十分か)、Witness の最小化(余計な条件を削る)、Replay が決定的かの自動分類基準、Replay テストの生成形式(Rust コード生成 / DSL / データ)。

---

### Decision MVP — Milestone 1 のスコープ(確定)

**位置づけ**: MVP は「最小で止めるもの」ではなく、実用的なフレームワークを入念に積み上げるロードマップ(「Milestone Roadmap」)の**最初のマイルストーン M1**。

**MVP の目的**: 単なる疎通確認でなく、「**攻撃が通る → 条件を捕捉 → 直す → 今度は防げる**」という J/V/H-2 のループを端から端まで動かす。= ユーザー目標「実際に攻撃して上手くいくか / 実際の攻撃をデモして防げるか」を成立させる。

**見せる縦スライス**: 自作の脆弱な3層 `web → internal-api → db`(Linux コンテナのみ)に対し、
- **① 境界デモ**: 攻撃者 → db 直接到達を試行 → 遮断を確認(PASS)。`internal:true` を外すと FAIL + rustc 風診断。
- **② 攻撃→防御デモ**: 実在脆弱性(SQLi)を突いて攻撃成功(= FAIL)→ Success Witness 捕捉 → 診断レポート → Fix → Pinned Replay で攻撃失敗(PASS)。

**IN スコープ**:
- A: Rust の `#[security_test]` + Scenario ビルダー(DSL なし)
- B: `Capability` trait + `Intensity`(Safe のみ)+ Evidence 正規化
- C: bollard で `internet/internal` 2セグメント + 自作3層
- D: Evidence レコード(Scenario のみ Graph 導出)
- E: terminal report + Canonical JSON(rustc 風診断)
- F: 層1(egress 無し隔離)+ 層2(Scope Gate)+ 層4(Safe-by-default)
- J: Observation + Expectation + Verdict 3値
- L: AttackerState 骨格 + external / assume-breach の起点配置(P)
- N: membership のみ(`internal:true`)+ 境界セルフチェック最小版
- V: Success Witness 捕捉 + Pinned Replay 生成
- H/H-2: 自作脆弱3層 + 組み込みチェックの remediation 診断
- G/B: **nmap + sqlmap の2アダプタを前倒し**(静的プラグイン)。実ツールで「攻撃→防御」を実演し、アダプタ機構と V を実ツールで検証
- Q/R: 最小データパック + lean Kali core プロファイル
- T: ベースライン文書 + スコープ承認(低リスク)

**OUT スコープ(後続マイルストーン)**: DSL / FW ゲートウェイ・DMZ・多段境界 / Attack Graph 可視化・SARIF / Windows・AD・クラウド・K8s・mock/real / リモートシェル pivot / C2 / AI Exploration / Scanner・Interop / Aggressive 解放 / 既存脆弱アプリ取り込み / ATT&CK カバレッジ UI。

**実ツールの扱い(確定)**: Option (1) — **nmap + sqlmap を MVP に前倒し**。ユーザーの「実際にクラッカーが使う成熟ツールで検証する」意図に忠実。

---

