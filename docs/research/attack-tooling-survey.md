# Attack Techniques & Tooling Survey

本フレームワークが「成熟していて、実際にクラッカーが使うツール」で検証を行うための調査。
docs/adr/ の ADR-0002(Hybrid: Rust コア + ツールアダプタ)/ ADR-0007(Plugin + Role 階層:
Capability / Scanner / Interop)に沿って、各ツールを**役割階層・攻撃フェーズ・レイヤー**で分類する。

> 調査日: 2026-10-10 / 動きの速い領域(クラウド・C2・AD)は Web 検索で現況を確認。
> 本書は「決定」ではなく「決定のための入力(reference)」。実装前に各ツールの最新状態を再確認する。

---

## 1. 分類の軸

- **攻撃フェーズ**(「Attack Simulation」 のキルチェーン): Recon → Initial Access → Exploit/Abuse →
  Privilege Escalation → Credential/Secret Discovery → Lateral Movement → Internal Access → Impact
- **レイヤー**(「Environment Abstraction」): Application / Host / Network / Infrastructure(+ Cloud)
- **Role 階層**(ADR-0007):
  - **Capability** = 能動実行(攻撃ステップ。Intensity × Scope Gate を通す)
  - **Scanner** = 一括発見(Finding 生成)
  - **Interop** = 独立実行型の結果取り込みのみ(framework は実行制御しない)

---

## 2. 参照すべき既存フレームワーク / 標準(タクソノミ候補)

技術を「我流」で並べず、既存の標準に対応づけるかどうかは要決定(→ 後述 ADR-0010 候補)。

| 標準 | 内容 | 用途 |
|------|------|------|
| **MITRE ATT&CK (Enterprise)** | 攻撃者の Tactics / Techniques を ID 体系化(TA0001, T1190 等) | Attack Scenario のステップ分類・カバレッジ測定・レポート |
| **Cyber Kill Chain (Lockheed)** | Recon→Weaponize→…→Actions の7段階 | 「Attack Simulation」 とほぼ一致 |
| **OWASP Top 10 / API Top 10 / WSTG** | Web/API の脆弱性分類とテスト手順 | Application 層の Security Test 設計 |
| **PTES / OSSTMM** | ペンテスト実施標準 | 全体フローの裏付け |
| **CIS Benchmarks** | ホスト/コンテナ/クラウドのハードニング基準 | Scanner(設定検査)の判定基準 |

---

## 3. Recon / Scanning(Network・レイヤー: Network)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **Nmap (+NSE)** | ポート/サービス/バージョン/OS 検出、スクリプト | 事実上の標準 | Capability | NPSL(BSD 系) | XML/grepable 出力 → パース容易。**最優先アダプタ** |
| **masscan** | インターネット規模の超高速ポートスキャン | 広域 | Capability | AGPL | 速いが精度は nmap に劣る。併用型 |
| **RustScan** | 高速スキャン(Rust 製)、nmap をラップ | | Capability | GPL | Rust 製で親和性高。内製代替の参考 |
| **naabu**(ProjectDiscovery) | 高速ポートスキャン | | Capability | MIT | JSON 出力、パイプライン親和 |
| **httpx**(ProjectDiscovery) | HTTP プローブ/技術判定 | App/Net | Capability | MIT | JSON 出力 |
| **subfinder / dnsx / Amass** | サブドメイン/DNS 列挙 | Net | Capability | MIT/各種 | 外部資産列挙(隔離環境では用途限定) |
| **katana**(ProjectDiscovery) | Web クローラ | App | Capability | MIT | 攻撃面列挙 |

> **ProjectDiscovery 系(naabu/httpx/dnsx/nuclei/katana/subfinder)** は全て CLI + JSON 出力 +
> パイプライン前提で、**アダプタ統合が最も容易**。有力候補群。

---

## 4. Vulnerability Scanning(レイヤー: Network/Host)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **Nuclei**(ProjectDiscovery) | テンプレ型脆弱性スキャナ | YAML テンプレで既知脆弱性/誤設定を検出 | Scanner | MIT | **最優先 Scanner**。テンプレ資産が巨大 |
| **OpenVAS / Greenbone** | 総合ネットワーク脆弱性スキャナ | OSS の定番 | Scanner | GPL | 重い。デーモン常駐。Interop 寄りも検討 |
| **Nessus**(Tenable) | 総合脆弱性スキャナ | 業界標準(商用) | Interop | 商用 | ライセンス制約。結果取り込み型が現実的 |

---

## 5. Web / API Application(レイヤー: Application)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **sqlmap** | SQLi 自動化 | 検出〜抽出〜OS シェルまで | Capability | GPL | **最優先**。CLI、`--batch`、JSON ログ |
| **OWASP ZAP** | プロキシ/動的スキャナ | API・Automation Framework で自動化可 | Scanner/Interop | Apache-2.0 | REST API / zap CLI。自動化しやすい |
| **Burp Suite** | プロキシ/スキャナ | 業界標準(Community 無料/Pro 商用) | Interop | 商用/無料 | 主に GUI。BChecks/結果取り込み型 |
| **ffuf** | 高速 Web ファジング(ディレクトリ/パラメータ) | | Capability | MIT | JSON 出力、高速 |
| **feroxbuster** | コンテンツ探索(Rust 製) | | Capability | MIT | Rust 製で親和性高 |
| **gobuster** | ディレクトリ/DNS/vhost 探索 | | Capability | Apache | |
| **dalfox** | XSS 検出(Go 製) | | Capability | MIT | JSON 出力 |
| **commix** | コマンドインジェクション自動化 | | Capability | GPL | |
| **tplmap** | SSTI(テンプレートインジェクション) | | Capability | — | |
| **Nikto** | Web サーバ既知問題スキャン | | Scanner | GPL | 古いが定番 |
| **wpscan** | WordPress 特化 | | Scanner | 独自 | CMS 検証用 |
| **Kiterunner / restler** | API ルート発見 / API ファジング | API | Capability | 各種 | API 検証(「Next Research Questions」-1 に関連) |

---

## 6. Exploitation / Post-Exploitation(レイヤー: Host/Network)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **Metasploit Framework** | 総合エクスプロイト/ポストエクスプロイト | 事実上の標準 | Capability | BSD | `msfrpcd`(RPC)でプログラム制御可。**最優先(Phase 5)** |
| **searchsploit / Exploit-DB** | 公開エクスプロイト検索 | | 参照 | GPL/各種 | ローカル DB。CVE → PoC |
| **Sliver** | オープンソース C2 / 敵対者エミュレーション(Go 製) | mTLS/HTTPS/DNS 実装、多 OS | Capability(高度) | GPL | **Level 3 多段攻撃**向け。Phase 9 |
| **Mythic** | モジュラ C2(多エージェント/多プロトコル) | 長期オペ向け | Capability(高度) | BSD | 構築複雑。Phase 9 |
| **Havoc** | 軽量 C2(モダン GUI、Go) | | Capability(高度) | GPL | Phase 9 |
| **AdaptixC2** | 拡張可能なポストエクスプロイト/敵対者エミュ | | Capability(高度) | 各種 | 新興。要継続観察 |
| **Cobalt Strike** | 商用敵対者シミュレーション | 赤チーム定番だが**ライセンス厳格・利用制限** | 対象外 | 商用(制限) | **統合しない**(入手制限・悪用規制) |

---

## 7. Password / Credential Attacks(レイヤー: Host/Network/App)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **Hydra** | オンライン総当たり(多プロトコル: SSH/HTTP/DB 等) | | Capability | AGPL | **最優先**。CLI、結果パース可。`Aggressive` |
| **Medusa / Ncrack** | オンライン総当たり(別実装) | | Capability | GPL | Hydra 代替/補完 |
| **John the Ripper** | オフラインハッシュクラック(CPU) | | Capability | GPL | 取得ハッシュの解析。`Aggressive` |
| **Hashcat** | オフラインハッシュクラック(GPU) | 最速 | Capability | MIT | GPU 前提。CI 制約に注意 |
| **Patator** | 汎用ブルートフォーサ | | Capability | GPL | |
| **CeWL / crunch** | ワードリスト生成 | | 補助 | GPL | |
| **SecLists / rockyou / fuzzdb / PayloadsAllTheThings** | ワードリスト/ペイロード集 | データ資産 | データ | 各種 | 攻撃データ管理の対象(→ Decision 候補) |

---

## 8. Network / MITM / Sniffing(レイヤー: Network)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **tcpdump / tshark(Wireshark)** | パケットキャプチャ/解析 | pcap を Evidence 化 | Capability/Interop | BSD/GPL | **Evidence(pcap)取得源**として重要(ADR-0004) |
| **Scapy** | パケット生成/操作(Python) | 任意プロトコル | Capability | GPL | 低レベル攻撃・内製代替の参考 |
| **bettercap / ettercap** | MITM フレームワーク | ARP/DNS スプーフ等 | Capability | GPL/EUPL | 隔離 L2 内での中間者 |
| **Responder** | LLMNR/NBT-NS/mDNS ポイズニング | 資格情報窃取 | Capability | GPL | AD 環境で定番(Phase: Windows) |
| **mitmproxy** | HTTP(S) 中間者プロキシ | | Capability | MIT | API 改ざん検証 |

---

## 9. VPN / TLS / Wireless / Crypto(ユーザー要望: VPN クラック)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **ike-scan (+ psk-crack)** | IKE/IPsec VPN 列挙 + PSK クラック | 弱い PSK の総当たり | Capability | GPL | **VPN クラック検証の中核**。隔離 lab で実行可 |
| **sslscan / testssl.sh / sslyze** | TLS 構成検査(弱い暗号/プロトコル) | | Scanner | GPL/各種 | TLS 誤設定検出 |
| **OpenVPN / WireGuard 検証** | 設定/資格情報/証明書の弱点 | ツールより構成依存 | Capability | — | 弱 PSK/漏洩鍵/MITM を lab で再現 |
| **aircrack-ng suite** | WiFi WPA/WEP クラック | **無線**(ハンドシェイク捕捉 → クラック) | Capability(特殊) | GPL | ⚠ **無線 I/F が必要。素の Docker では不可**(→ Scope 要決定) |
| **hashcat/John** | 捕捉ハンドシェイク/PSK のオフライン解析 | | Capability | 上記 | 無線で捕捉後の解析に流用 |

> ⚠ **重要な制約**: 無線(aircrack)や一部物理攻撃は、コンテナ/仮想ネットワークでは再現できない
> (無線ハードウェアが要る)。**VPN クラックは IPsec/IKE の弱 PSK・漏洩鍵・設定不備として
> 隔離 lab で再現可能**だが、WiFi 系は MVP スコープ外に置くのが現実的(→ ADR-0013 候補)。

---

## 10. Container / Kubernetes(レイヤー: Infrastructure)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **Trivy** | コンテナ/IaC/secret/K8s スキャン | 最も活発 | Scanner | Apache-2.0 | **最優先 Scanner(Phase 4)**。JSON/SARIF 出力 |
| **Grype + Syft** | SBOM 生成 + 脆弱性照合 | | Scanner | Apache | 依存脆弱性 |
| **kube-bench** | CIS Kubernetes Benchmark 検査 | | Scanner | Apache | 新規はこちら推奨 |
| **kubeaudit** | K8s 設定監査 | | Scanner | Apache | |
| **kube-hunter** | K8s 攻撃面探索 | **非推奨(開発停止)** | 対象外 | Apache | 既存ワークフロー限定 |
| **Peirates** | K8s 侵入後の権限昇格/横展開 | 能動攻撃 | Capability | Apache | K8s 内 Lateral(Phase 8) |
| **Docker Bench for Security** | Docker ホスト CIS 検査 | | Scanner | Apache | |

---

## 11. IaC / Cloud(レイヤー: Infrastructure/Cloud)

| ツール | 役割 | 内容 | 階層 | ライセンス | 統合メモ |
|--------|------|------|------|-----------|----------|
| **Checkov** | IaC 静的解析(TF/K8s/CFN 等) | | Scanner | Apache | 広範。JSON/SARIF |
| **tfsec / Terrascan / KICS** | Terraform/IaC 誤設定検査 | | Scanner | 各種 | Checkov と競合/補完 |
| **Prowler** | クラウド構成評価(AWS/Azure/GCP、300+ チェック) | CSPM | Scanner | Apache | マルチクラウド。SARIF 可 |
| **ScoutSuite** | マルチクラウド監査レポート | | Scanner | GPL | レポート生成が強み |
| **Pacu**(Rhino Security) | AWS **攻撃**フレームワーク(IAM 列挙/権限昇格/永続化) | 能動 | Capability | BSD | クラウド攻撃の中核(Phase 8) |
| **CloudFox** | AWS/Azure 攻撃経路列挙 | | Capability | Apache | Attack Path(ADR-0004 と親和) |
| **Cartography** | クラウド資産の関係グラフ化 | | Scanner/graph | Apache | Attack Graph 補強 |
| **enumerate-iam** | AWS IAM 権限列挙 | | Capability | — | |

---

## 12. Attack Data(資産管理の対象)

攻撃には「コード」以外に**データ資産**が要る。再現性(ピン止め)と鮮度のトレードオフが論点(→ Decision 候補)。

- ワードリスト: **SecLists**, rockyou, fuzzdb, CeWL 生成物
- ペイロード: **PayloadsAllTheThings**, FuzzDB
- エクスプロイト: **Exploit-DB / searchsploit**, Metasploit modules
- 脆弱性テンプレ: **Nuclei templates**
- 脆弱性 DB: NVD/CVE, GitHub Advisory, OSV(Trivy/Grype が参照)

---

## 13. 役割階層ごとの「第一候補」まとめ(統合の優先順位素案)

| 階層 | MVP(native 中心) | Phase 4 | Phase 5+ | 高度(Phase 8–9) |
|------|------|---------|----------|------------------|
| **Capability** | 内製(TCP 到達性/HTTP/セグメンテーション) | **Nmap** | **sqlmap, Hydra, Metasploit**, ffuf/feroxbuster | Sliver/Mythic, Pacu/CloudFox, Impacket/NetExec, ike-scan |
| **Scanner** | — | **Trivy, Nuclei** | OpenVAS, sslscan, Nikto | Prowler/ScoutSuite, Checkov, kube-bench |
| **Interop** | — | — | ZAP, Burp, Nessus 結果取り込み | BloodHound グラフ, 外部 SARIF |

---

## 14. Windows / Active Directory ツール群(プラットフォーム判断が必要)

AD 系は現実の企業ネットワーク攻撃の中核だが、**Windows ターゲットが必要で Docker-Linux だけでは完結しない**
(→ ADR-0013「プラットフォームスコープ」で扱う)。

| ツール | 役割 | 内容 |
|--------|------|------|
| **Impacket** | Windows プロトコル操作の Python 群 | secretsdump, ntlmrelayx, wmiexec, psexec, GetUserSPNs |
| **BloodHound + SharpHound** | AD 権限昇格経路の可視化 | 攻撃グラフ(ADR-0004 と親和) |
| **Mimikatz** | LSASS からの資格情報窃取 | PtH, Golden/Silver Ticket |
| **Rubeus** | Kerberos 攻撃 | Kerberoasting, AS-REP roasting |
| **NetExec(旧 CrackMapExec)** | AD/SMB 横断操作 | スプレー&チェックの標準(2024 以降 NetExec) |
| **Responder** | LLMNR/NBT-NS ポイズニング | 資格情報窃取 |
| **Certipy** | AD CS(証明書サービス)攻撃 | ESC1-ESC8 |
| **Kerbrute** | ユーザー列挙/パスワードスプレー | |

---

## 15. この調査から見えた「まだ決めていない論点」(gap)

これらの論点はすべて [ADR](../adr/README.md) として決着済み。当時の要点のみ:

1. **攻撃タクソノミ標準**(MITRE ATT&CK に対応づけるか)
2. **成功判定オラクル**(「攻撃が成功した/境界が守られた」を framework がどう判定するか)— 最重要
3. **CI 安定性モデル**(実ツールの非決定性・遅さ・ノイズ。gating vs informational、タイムアウト/リトライ、時間予算)
4. **プラットフォームスコープと順序**(Linux → Windows/AD → 無線。何を対象外にするか)
5. **攻撃データ管理**(ワードリスト/テンプレ/エクスプロイト DB のバンドル・ピン止め・更新)
6. **攻撃者イメージの構成と出所**(何を同梱するか、ライセンス、Cobalt Strike 除外、バージョン固定、供給網信頼)
7. **シナリオ状態モデル**(多段ステップ間で資格情報/セッション/ホスト文脈をどう持ち回るか = pivot)
8. **境界強制の実装方式**(Docker 上で firewall/routing/セグメントをどう実現するか)
9. **攻撃者の起点(vantage)**(外部攻撃者 vs assume-breach の内部起点)
10. **敵対者エミュレーション/C2 統合の方針**(Sliver/Mythic を Level 3 でどう扱うか)
11. **法務/配布ポリシの具体化**(攻撃ツールを同梱する framework の SECURITY.md・利用規約・スコープ UX)

---

## Sources(現況確認に使用)

- [eSecurity Planet — Best Penetration Testing Tools 2026](https://www.esecurityplanet.com/products/top-penetration-testing-tools.html)
- [CyberSecurityNews — Ethical Hacking Tools](https://cybersecuritynews.com/ethical-hacking-tools/amp/)
- [DeepStrike — Best Tools for Cloud Penetration Testing 2025](https://deepstrike.io/blog/best-tools-for-cloud-penetration-testing-in-2025)
- [Astra — Best Cloud Penetration Testing Tools](https://www.getastra.com/blog/cloud/best-cloud-penetration-testing-tools/)
- [Bishop Fox — 2025 Red Team Tools: C2, AD, Network Exploitation](https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation)
- [TryHackMe — Active Directory Attacks Lab Guide](https://tryhackme.com/resources/blog/active-directory-attacks-you-can-practise-today-a-red-teamers-lab-guide)
- [Aqua Security — Trivy Kubernetes scanning](https://www.aquasec.com/news/third-party-code-scanning-tools-infrastructure-as-code-container-scanning/)
- [cyberwarfare.live — Sliver, Havoc, Mythic](https://cyberwarfare.live/?p=496322)
