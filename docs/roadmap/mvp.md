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

**M1 vs M3 (clarified, #33)**: M1 delivers the Security Test above, "the internet attacker cannot reach the database" (#28), plus a single-hop real-tool attack against a reachable target (the nmap/sqlmap adapter mechanism and Decision V). The multi-step Attack Scenario (web -> api -> db) and "Internal API reachable only through the intended path" are the M3 expansion of this same goal: the firewall gateway supplies the port boundary, and the Decision L pivot (Phase 5) supplies the chain. So "Web reachable / API reachable only through the intended path / Database unreachable" is the end-state the goal describes, not an M1 checklist; M1 proves the Database line natively and demonstrates a real tool single-hop.

---

