# MVP / 最初のプロトタイプ (MVP & First Prototype)

## 1. MVP

最初からクラウド・Kubernetes・Windows・Active Directoryなどを全部扱わない。

まずはDockerベースの隔離環境を構築する。

```text
Security Test Runner
       │
       ├─────────────┐
       ▼             ▼
   Attacker        Target
   Container       Containers
       │             │
       │        ┌────┴────┐
       │        │         │
       │       Web       DB
       │        │
       │      Internal API
       │
       └── isolated network
```

### MVPの構成

```text
Docker
+
Isolated Network
+
Attacker Container
+
Target Containers
+
Attack Scenario
+
Security Test
+
Evidence
+
CI
```

### MVPで検証したいこと

1. 攻撃者コンテナを作成できる
2. ターゲット環境を一時的に作成できる
3. ネットワーク境界を再現できる
4. Security Testを定義できる
5. Attack Scenarioを定義できる
6. 攻撃経路を実行できる
7. Evidenceを収集できる
8. PASS/FAILを判定できる
9. CIで実行できる
10. テスト後に環境を破棄できる

---


## 2. First Prototype Goal

最初のPoCでは、以下だけを成立させる。

```text
Attacker Container
       │
       │ network
       ▼
Web Container
       │
       ▼
Internal API Container
       │
       ▼
Database Container
```

そして、

```text
Security Test:
    Internet attacker cannot reach Database

Attack Scenario:
    External attacker
        ↓
    Web
        ↓
    Internal API
        ↓
    Database
```

を実行する。

Expected:

```text
Web          reachable
Internal API reachable only through intended path
Database     unreachable directly from attacker
```

これをCIで実行し、

```text
PASS / FAIL
+
Evidence
+
Attack Path
+
Report
```

を出せた時点を最初の大きなマイルストーンとする。

**M1 vs M3 (clarified, #33)**: of the three Expected lines, M1 proves "Database unreachable" natively (the boundary Security Test, #28) and reaches a single Web target for a real-tool single-hop (the nmap/sqlmap adapter mechanism and ADR-0022), so "Web reachable" is demonstrated for that one hop. "Internal API reachable only through the intended path" is the M3 port boundary (the firewall gateway). The full external -> web -> api -> db chain the Attack Scenario draws is the M3 / Phase 5 end-state (the gateway for the port boundary, the ADR-0012 pivot for the chain), not an M1 checklist.

---

## 3. M1 スコープ

**位置づけ**: MVP は「最小で止めるもの」ではなく、実用的なフレームワークを入念に積み上げるロードマップ(本章 §1-2)の**最初のマイルストーン M1**。

**目的**: 単なる疎通確認でなく、「**攻撃が通る → 条件を捕捉 → 直す → 今度は防げる**」という [ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md) / [ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md) / [ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md) のループを端から端まで動かす。ユーザー目標「実際に攻撃して上手くいくか / 実際の攻撃をデモして防げるか」を成立させる。

**見せる縦スライス**: 自作の脆弱な3層 `web → internal-api → db`(Linux コンテナのみ)に対し、

- **① 境界デモ**: 攻撃者 → db 直接到達を試行 → 遮断を確認(PASS)。`internal:true` を外すと FAIL + rustc 風診断。
- **② 攻撃→防御デモ**: 実在脆弱性(SQLi)を突いて攻撃成功(= FAIL)→ Success Witness 捕捉 → 診断レポート → Fix → Pinned Replay で攻撃失敗(PASS)。

### IN スコープ

- [ADR-0001](../adr/0001-write-security-tests-in-rust-and-attack-scenarios-in-a-dsl.md): Rust の `#[security_test]` + Scenario ビルダー(DSL なし)
- [ADR-0002](../adr/0002-unify-capabilities-behind-one-trait-gated-by-intensity.md): `Capability` trait + `Intensity`(Safe のみ)+ Evidence 正規化
- [ADR-0003](../adr/0003-own-the-network-boundary-and-drive-docker-with-bollard.md): bollard で `internet/internal` 2セグメント + 自作3層
- [ADR-0004](../adr/0004-record-evidence-as-an-append-only-fact-project-the-graph-from-it.md): Evidence レコード(Scenario のみ Graph 導出)
- [ADR-0005](../adr/0005-render-every-report-from-one-canonical-json.md): terminal report + Canonical JSON(rustc 風診断)
- [ADR-0006](../adr/0006-guarantee-safety-in-independent-layers.md): 層1(egress 無し隔離)+ 層2(Scope Gate)+ 層4(Safe-by-default)
- [ADR-0010](../adr/0010-separate-observation-from-verdict-and-default-to-high-confidence.md): Observation + Expectation + Verdict 3値
- [ADR-0012](../adr/0012-model-the-attacker-state-as-a-growing-asset-set.md): AttackerState 骨格 + external / assume-breach の起点配置([ADR-0017](../adr/0017-make-external-and-assume-breach-vantages-first-class.md))
- [ADR-0011](../adr/0011-enforce-boundaries-by-membership-and-self-check-before-any-test.md): membership のみ(`internal:true`)+ 境界セルフチェック最小版
- [ADR-0022](../adr/0022-capture-a-success-witness-and-generate-a-pinned-replay.md): Success Witness 捕捉 + Pinned Replay 生成
- [ADR-0008](../adr/0008-reuse-vulnerable-apps-and-own-the-reference-topology.md) / [ADR-0009](../adr/0009-emit-an-executable-rustc-style-fail-diagnostic-from-the-oracle.md): 自作脆弱3層 + 組み込みチェックの remediation 診断
- [ADR-0007](../adr/0007-integrate-tools-as-a-plugin-with-three-role-contracts.md) / [ADR-0002](../adr/0002-unify-capabilities-behind-one-trait-gated-by-intensity.md): **nmap + sqlmap の2アダプタを前倒し**(静的プラグイン)。実ツールで「攻撃→防御」を実演し、アダプタ機構と ADR-0022 を実ツールで検証
- [ADR-0018](../adr/0018-manage-attack-data-as-version-pinned-packs.md) / [ADR-0019](../adr/0019-build-the-attacker-image-from-a-pinned-base-and-tool-profiles.md): 最小データパック + lean Kali core プロファイル
- [ADR-0021](../adr/0021-govern-distribution-by-risk-tier.md): ベースライン文書 + スコープ承認(低リスク)

### OUT スコープ(後続マイルストーン)

DSL / FW ゲートウェイ・DMZ・多段境界 / Attack Graph 可視化・SARIF / Windows・AD・クラウド・K8s・mock/real / リモートシェル pivot / C2 / AI Exploration / Scanner・Interop / Aggressive 解放 / 既存脆弱アプリ取り込み / ATT&CK カバレッジ UI。

### 実ツールの扱い

nmap + sqlmap を MVP に前倒しする([ADR-0007](../adr/0007-integrate-tools-as-a-plugin-with-three-role-contracts.md) / [ADR-0002](../adr/0002-unify-capabilities-behind-one-trait-gated-by-intensity.md))。「実際にクラッカーが使う成熟ツールで検証する」というユーザー意図に忠実。M1 での単一ホップの範囲と M3 への繰り延べは §2 の「M1 vs M3」注記のとおり。汎用的なコンテナ内 capability シーム(#27 のメモ、その形は M3 のツールアダプタに引きずられる)は M1 では作らない。

---

