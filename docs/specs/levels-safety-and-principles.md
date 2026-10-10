# レベル・安全・設計原則 (Levels, Safety, Principles)

## 1. Security Testing Levels

### Level 1 — Safe Checks

比較的安全な自動チェック。

```text
Port reachable?
TLS correct?
Authentication required?
Authorization correct?
Secret exposed?
Container configuration?
IAM configuration?
```

### Level 2 — Controlled Attack Simulation

隔離されたテスト環境で攻撃シナリオを実行する。

```text
SQL injection detection
IDOR verification
SSRF verification
Privilege boundary test
Network segmentation test
Credential boundary test
```

### Level 3 — Advanced Adversary Simulation

より高度な攻撃者行動を段階的に再現する。

```text
Initial access
 ↓
Privilege escalation
 ↓
Credential access
 ↓
Internal discovery
 ↓
Lateral movement
 ↓
Impact
```

Level 3は初期MVPの必須要件にはしない。

---

## 2. CI/CD Integration

Security Testing FrameworkをCI/CDに組み込む。

```text
Build
  ↓
Deploy ephemeral environment
  ↓
Security Tests
  ↓
Attack Scenarios
  ↓
Evidence collection
  ↓
Security Report
  ↓
SARIF
  ↓
Merge Gate
  ↓
Destroy environment
```

### 目標

通常のテストと同じ感覚で、

```text
cargo test
```

のように、

```text
security test
```

を実行できる体験を目指す。

> **Security version of cargo test / pytest**

という位置付け。

---

## 3. Security Education

Security Testing Frameworkは、単なるツールではなくセキュリティ学習基盤としても利用できるようにする。

各Security Testに、

- 脆弱性とは何か
- どのような攻撃モデルか
- なぜ攻撃が成立するのか
- 本来どう防ぐべきか
- テストが何を検証しているか
- 修正後にどう変わるか

を説明できるようにする。

### Vulnerable Playground

意図的に脆弱なアプリケーションを用意する。

```text
SQL Injection
XSS
CSRF
IDOR
SSRF
Path Traversal
Command Injection
Authentication flaws
Authorization flaws
```

基本的な流れ:

```text
Vulnerable
    ↓
Attack
    ↓
Observe
    ↓
Fix
    ↓
Security Test
    ↓
PASS
```

攻撃手法を「知識」として学び、防御側の理解につなげる。

---

## 4. Legal / Safety Design

本プロジェクトは正当なセキュリティテストを目的とする。

重要な原則:

- 対象システムへの明示的な許可を前提とする
- 本番環境への破壊的テストを前提にしない
- Ephemeral / Isolated Environmentを推奨する
- README / Documentationで用途を明確化する
- LICENSE / SECURITY.mdを整備する
- 安全なテストモードと高度なテストモードを分離する
- 対象範囲を明示できるAllowlist / Scope設定を検討する
- リリース前に日本のサイバー法務について専門家へ確認する

攻撃手法そのものを隠すのではなく、

> **攻撃を理解し、安全に再現し、防御を検証するためのフレームワーク**

として設計する。

---


## 5. Long-Term Architecture

```text
                    Security Testing Framework
                              │
             ┌────────────────┼────────────────┐
             │                │                │
          Scanner       Attack Scenario    Security Test
             │                │                │
             │                ▼                │
             │          Attacker Model         │
             │                │                │
             │        ┌───────┴───────┐        │
             │        │               │        │
             │      Network          Host      │
             │        │               │        │
             │      Cloud         Application  │
             │        │               │        │
             └────────┴───────┬───────┴────────┘
                              │
                          Evidence
                              │
                        Security Report
                              │
                            CI/CD
```

---

## 6. Core Design Principles

### 1. Attacker Perspective First

防御側だけでなく、攻撃者が何を見て、何を試し、どこへ移動できるかをモデル化する。

### 2. Attack Scenario is First-class

攻撃シナリオをフレームワークの中心的な概念として扱う。

### 3. Security Test is Executable Specification

セキュリティ要件をコードとして記述し、継続的に実行する。

### 4. Environment is First-class

ネットワーク・ホスト・アプリケーション・クラウドを含むテスト環境そのものを扱う。

### 5. Evidence over Simple PASS/FAIL

結果だけでなく、なぜFAILしたのかを再現可能なEvidenceとして残す。

### 6. Ephemeral by Default

テスト環境は作成・検証・破棄する。

### 7. Integrate Existing Tools

既存の優れたSecurity Toolを無理に再実装しない。

### 8. CI-native

通常のテストと同じようにCIで実行できる。

### 9. Safe by Design

Authorized testingを前提とし、Scope / Isolation / Environmentを明示的に扱う。

### 10. Progressive Complexity

最初から完全なAdversary Emulationを目指さず、

```text
Safe Check
   ↓
Controlled Attack
   ↓
Attack Scenario
   ↓
Multi-stage Attack
   ↓
Advanced Adversary Simulation
```

と段階的に発展させる。

---

