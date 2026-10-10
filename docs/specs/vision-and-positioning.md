# ビジョンと位置づけ (Vision & Positioning)

## 1. Project Vision

### 仮称

Security Testing Framework

### コンセプト

> **開発者が自分のWebアプリ・API・Docker・クラウド・インフラを、攻撃者視点で継続的に検証するためのRust製Security Testing Framework**

単なる脆弱性スキャナではなく、

> **攻撃者が侵入を試み、内部ネットワークへ到達し、権限を拡大し、別のシステムへ移動し、最終的な目的を達成するまでを、許可されたテスト環境内で再現・検証する。**

ことを目標とする。

### プロジェクトの思想

- 攻撃手法を理解することは、防御するために重要
- 「攻撃できるか」だけでなく「攻撃後にどこまで到達できるか」を検証する
- Security Testを「実行可能なセキュリティ仕様」として扱う
- CI/CDに組み込み、継続的にセキュリティを検証する
- 実際の攻撃に近いシナリオを、隔離されたテスト環境で安全に再現する
- 攻撃結果だけでなく、再現可能なEvidenceを収集する

---

## 2. Why

一般的なWeb脆弱性スキャンだけでは、

```text
Web Application
    ↓
SQL Injection?
XSS?
IDOR?
SSRF?
```

のような個別の脆弱性を確認することはできても、

```text
Internet
    ↓
Web
    ↓
Internal API
    ↓
Internal Server
    ↓
Database
    ↓
Secrets
```

という「侵入後の攻撃経路」まで十分に評価できない。

本プロジェクトでは、

> **「この脆弱性が存在する」から「この脆弱性を利用すると攻撃者はどこまで行ける」へ**

テストの対象を広げる。

---


## 3. Existing Toolsとの関係

既存ツールをすべて置き換えることを目的にしない。

候補:

```text
OWASP ZAP
Nmap
OpenVAS / Greenbone
Trivy
OWASP API Security Testing Framework
Chef InSpec
Burp Suite BChecks
Nuclei
```

本プロジェクトは、それらと競合するだけではなく、必要に応じて統合・利用する。

差別化の中心:

```text
Application
     +
API
     +
Container
     +
Network
     +
Cloud
     +
Infrastructure
     +
Attack Scenario
     +
Security Test
     +
Evidence
     +
CI/CD
```

---

## 4. Differentiation

単なる、

> Rust版のZAP

や、

> Rust版のNmap

を作ることは目的としない。

目指すものは、

> **攻撃者視点でシステム全体を継続的に検証するSecurity Testing Framework**

である。

特に重要なのは、

### Vulnerability

```text
「脆弱性がある」
```

だけで終わらず、

### Attack Path

```text
「その脆弱性を利用すると、攻撃者はここまで到達できる」
```

まで検証すること。

---


## 5. 最初の完成イメージ

最初の実用的な完成形は、

```text
developer
    │
    │ git push
    ▼
CI
    │
    ▼
Security Framework
    │
    ├── Create attacker
    ├── Create target environment
    ├── Create isolated networks
    │
    ├── Run Security Tests
    ├── Run Attack Scenarios
    ├── Collect Evidence
    │
    ├── Generate Report
    ├── Generate SARIF
    │
    └── Destroy environment
```

という流れ。

最終的には、

> **「自分のアプリケーションやインフラに対して、攻撃者なら何ができるか？」をCIで毎回検証できる**

ことを目標とする。

---

## 6. Project Positioning

候補となる表現:

> **Rust製 Security Testing Framework**

> **攻撃者視点のSecurity Testing Framework**

> **Security Testing Framework + Attack Simulation + Security Education + CI/CD Integration + Security Reporting**

より短く表現するなら:

> **Security Testing Framework for Continuous Adversarial Validation**

日本語では:

> **攻撃者視点でシステム全体を継続的に検証するRust製Security Testing Framework**

---


## 7. Ultimate Goal

最終的な目標は、

> **攻撃者を完全に再現することではない。**

現実の攻撃者が利用する、

- ネットワーク
- アプリケーション
- 認証情報
- 権限
- ホスト
- コンテナ
- クラウド
- インフラ
- 横展開
- 攻撃経路

を可能な限りモデル化し、

> **「この環境に侵入した攻撃者は、最終的に何ができるのか？」**

を、開発者自身が安全に、繰り返し、CIから検証できるようにする。

最終的には、

```text
Vulnerability Scanner
        +
Security Test Framework
        +
Attack Simulation
        +
Network Testing
        +
Infrastructure Testing
        +
Evidence / Reporting
        +
CI/CD
        +
Security Education
```

を一つの開発体験として提供する。

> **攻撃を知らなければ、防御できない。**
>
> **だからこそ、攻撃を安全に再現し、防御を継続的に検証する。**

---

