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

**M1 vs M3 (clarified, #33)**: of the three Expected lines, M1 proves "Database unreachable" natively (the boundary Security Test, #28) and reaches a single Web target for a real-tool single-hop (the nmap/sqlmap adapter mechanism and Decision V), so "Web reachable" is demonstrated for that one hop. "Internal API reachable only through the intended path" is the M3 port boundary (the firewall gateway). The full external -> web -> api -> db chain the Attack Scenario draws is the M3 / Phase 5 end-state (the gateway for the port boundary, the Decision L pivot for the chain), not an M1 checklist.

---

