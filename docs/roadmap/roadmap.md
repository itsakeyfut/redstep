# ロードマップ (Roadmap)

## 1. Development Roadmap

### Phase 1 — Core Security Test Runner

- Rust製Test Runner
- Security Test API
- PASS / FAIL
- Test Context
- Evidence model
- CLI

### Phase 2 — Docker Environment

- Attacker Container
- Target Container
- Isolated Network
- Environment lifecycle
- Environment teardown

### Phase 3 — Attack Scenario

- Attacker model
- Entry Point
- Step
- Network transition
- Privilege transition
- Expected outcome
- Attack path

### Phase 4 — Network Security

- Port reachability
- Network segmentation
- Firewall
- Internal network
- DMZ
- External → Internal boundary

### Phase 5 — Application / API Security

- Authentication
- Authorization
- IDOR
- Session
- SSRF
- Injection
- Path traversal
- Security regression tests

### Phase 6 — Evidence / Reporting

- Evidence collection
- Human-readable report
- JSON
- SARIF
- Attack graph
- CI annotations

### Phase 7 — CI/CD

- GitHub Actions
- GitLab CI
- Merge gate
- Ephemeral environment
- Security regression pipeline

### Phase 8 — Infrastructure / IaC

- Docker
- Terraform
- Kubernetes
- Cloud configuration
- IAM
- Infrastructure security tests

### Phase 9 — Advanced Attack Simulation

- Multi-stage attack
- Lateral movement
- Privilege escalation
- Credential boundary
- Attack graph
- Adversary simulation

---


## 2. Milestone Roadmap(確定)

実用的なフレームワークを入念に積み上げるための道程。MVP は最初のマイルストーン M1。
「Development Roadmap」(Development Roadmap)を、「Design Decisions」 の全決定(A〜V)で具体化して束ね直したもの。
各マイルストーン内でさらに細分タスクを切っていく。

| M | マイルストーン | 中身(対応決定) | 達成で言えること |
|---|--------------|----------------|-----------------|
| **M1** | **MVP:攻撃→防御ループの縦スライス** | Decision MVP(Runner/env/Evidence/report/safety + nmap+sqlmap + Witness/Replay)。A/B/C/D/E/F/J/L/N/P/V/H/H-2/G/Q/R/T の MVP 分 | 「実ツールで攻撃が通り、直すと防げる」を1本動かせる |
| **M2** | **記述性と可視化** | DSL(A)/ Attack Graph 可視化・SARIF・HTML(D/E)/ ATT&CK・OWASP タグ + カバレッジ(K)/ web 系 native 能力拡充(ffuf 等) | シナリオを宣言的に書け、結果を標準語彙で可視化・共有できる |
| **M3** | **本格オフェンシブと多段攻撃** | Metasploit・Hydra・ike-scan アダプタ(B)/ リモートシェル pivot・Lateral Movement(L)/ Scanner 階層:Trivy・Nuclei(G)/ FW ゲートウェイ・DMZ・多段境界(N)/ 既存脆弱アプリ取り込み(H)/ Corroboration 深化(J) | 多段の攻撃経路を本物のツールで再現し、企業 NW 的トポロジを検証できる |
| **M4** | **プラットフォーム拡張と mock/real** | Windows/AD(実VM)・クラウド・K8s・IaC(M)/ Environment Provider(real/mock, LocalStack 等)/ クラウド攻撃(Pacu/CloudFox)/ Interop 取り込み(ZAP/Burp/Nessus/BloodHound) | アプリ・NW・インフラ・クラウド全層を、mock でも実機でも検証できる |
| **M5** | **AI 駆動と敵対者エミュレーション** | AI Operator(Claude/OpenAI)/ Exploration・Verification・昇格(U)/ C2(Sliver/Mythic)Level 3 多段(S) | AI が未知の攻撃を発見し、フレームワークの再現テストに昇格できる |
| **横断** | **ガバナンス・資産保守(継続)** | リスク階層ガバナンスの成熟・米/日法務レビュー(T)/ データパック・イメージ保守(Q/R)/ responsible disclosure | 全世界向けに安全・合法・再現可能に配布し続けられる |

**芯の流れ**: M1 で「攻撃→防御ループ」を1本通す → M2 で書きやすく見やすく → M3 で本物の多段攻撃 → M4 で全層・mock/real → M5 で AI と敵対者エミュレーション。
