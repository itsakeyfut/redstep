# コア概念 (Core Concepts)

## 1. Attack Simulation

攻撃者の一部始終を、段階的なAttack Scenarioとしてモデル化する。

```text
Attacker
   ↓
Reconnaissance
   ↓
Initial Access
   ↓
Exploit / Abuse
   ↓
Privilege Escalation
   ↓
Lateral Movement
   ↓
Credential / Secret Discovery
   ↓
Internal Access
   ↓
Impact
```

ただし、最初から現実の攻撃者を完全再現することは目指さない。

現実的な範囲から始め、段階的に高度化する。

---

## 2. Attacker Environment

攻撃者側の環境をテスト対象とは分離する。

```text
┌───────────────────────────┐
│ Attacker Environment      │
│                           │
│ Linux / Kali / etc.       │
│ Security Test Runner      │
└─────────────┬─────────────┘
              │
          Network
              │
              ▼
┌───────────────────────────┐
│ Target Environment        │
│                           │
│ Firewall / WAF / LB       │
│       ↓                   │
│ Web / API                 │
│       ↓                   │
│ Internal Network          │
│       ↓                   │
│ DB / Internal API / etc.  │
└───────────────────────────┘
```

Kali Linux自体を必須にするのではなく、

> **攻撃者からターゲットへネットワーク越しにアクセスする**

という構造を再現する。

攻撃者環境はLinux、Kali、その他のOS/環境などを抽象化できる設計を検討する。

---

## 3. Test Environment

本物の攻撃に近いテストを実施するため、隔離された仮想環境を第一級の概念として扱う。

### CIでの基本フロー

```text
Developer
    │
    │ git push
    ▼
CI
    │
    ├── Build Application
    │
    ├── Build Infrastructure
    │
    ▼
Ephemeral Security Environment
    │
    ├── Attacker
    ├── Internet segment
    ├── DMZ
    ├── Internal network
    ├── Web
    ├── API
    ├── DB
    └── Cloud / Infrastructure mocks
    │
    ▼
Security Tests
    │
    ▼
Evidence
    │
    ▼
Security Report / SARIF
    │
    ▼
Destroy Environment
```

### 基本方針

- テスト環境は可能な限りEphemeralにする
- 攻撃テストは隔離された環境で実施する
- 本番環境に対して破壊的な攻撃を自動実行することを前提にしない
- 環境生成と破棄を自動化する
- 可能な限り本番に近いネットワーク構成を再現する

---

## 4. Network Testing

Web APIだけでなく、ネットワーク境界そのものをテスト対象にする。

例えば外部から、

```text
Internet
   │
   ├── Web       ✓
   ├── API       ✓
   ├── DB        ✗
   ├── Admin     ✗
   └── Internal  ✗
```

であるべき場合、

```text
Internet
   │
   ├── Web       ✓
   ├── API       ✓
   ├── DB        ✓  ← FAIL
   ├── Admin     ✓  ← FAIL
   └── Internal  ✓  ← FAIL
```

を検出する。

### テスト対象

- Port reachability
- Network segmentation
- Firewall rules
- Routing
- DNS
- VPN
- Internal network access
- DMZ
- External → Internal boundary
- Container network isolation
- Cloud network configuration

---

## 5. Attack Scenario

本フレームワークの中心概念として `Attack Scenario` を設ける。

```text
Attack Scenario
│
├── Attacker
├── Entry Point
├── Actions
├── Network Transitions
├── Privilege Transitions
├── Evidence
└── Expected Outcome
```

例:

```text
Scenario: External attacker compromises web application

Step 1
Internet → Web
        PASS

Step 2
Web → Internal API
        PASS

Step 3
Internal API → Admin service
        PASS

Step 4
Admin service → Database
        PASS

Step 5
Database → Production secrets
        FAIL
```

単なる脆弱性一覧ではなく、

> **攻撃経路 / Attack Path**

として結果を表現する。

---

## 6. Security Test

Security Testは「セキュリティに関する期待される挙動」を実行可能な形で記述する。

概念例:

```rust
#[security_test]
async fn user_cannot_access_another_users_profile(ctx: &TestContext) {
    let user_a = ctx.create_user().await;
    let user_b = ctx.create_user().await;

    let response = ctx
        .as_user(&user_a)
        .get(format!("/users/{}", user_b.id))
        .send()
        .await;

    assert_forbidden(response);
}
```

重要なのは、

> Security Test = Executable Security Specification

と考えること。

### 検証対象

- Authentication
- Authorization
- IDOR
- Session
- CSRF
- SQL Injection
- XSS
- SSRF
- Path Traversal
- Command Injection
- Secret exposure
- Container security
- Network segmentation
- IAM
- Cloud configuration
- Infrastructure configuration

---

## 7. ScannerとSecurity Testの分離

自動探索と明示的なセキュリティ仕様は分ける。

### Scanner

自動的に問題を発見する。

```text
Dependency
Container
TLS
IaC
Configuration
Network
Known vulnerabilities
```

### Security Test

開発者が明示的に期待するセキュリティ挙動を検証する。

```text
User A cannot access User B's resource
Internet cannot access DB
Container A cannot access Internal Network
Admin API requires authentication
Production secret cannot be exposed
```

Scanner + Security Testを統合して扱う。

---

## 8. Evidence

テスト結果はPASS/FAILだけにしない。

```text
Attack Scenario: External → Internal API

[1] Attacker
    source: attacker-network

[2] Web
    reachable: YES

[3] Internal API
    reachable: YES

[4] Admin API
    reachable: YES  ← unexpected

Evidence:
    network path
    HTTP response
    request metadata
    container logs
    security events

Result:
    FAIL
```

収集するEvidenceの例:

- Network path
- Request / Response metadata
- HTTP status
- Container logs
- Security logs
- Authentication state
- Authorization state
- Cloud/IaC configuration
- Executed test steps
- Attack graph
- Reproduction information

---

## 9. Environment Abstraction

すべてのOS・クラウド・ネットワークを自前で実装しない。

既存の仮想化・コンテナ・クラウド/IaC技術をオーケストレーションする。

### Layer 1 — Application

```text
HTTP
REST
GraphQL
WebSocket
Auth
Session
```

### Layer 2 — Host

```text
Linux
Windows
Container
VM
```

### Layer 3 — Network

```text
VLAN
Subnet
Firewall
DNS
Routing
VPN
```

### Layer 4 — Infrastructure

```text
Docker
Kubernetes
Terraform
Cloud
IAM
Storage
```

---

