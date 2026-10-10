# 決定バックログ / 進捗 (Decisions Backlog)

## 1. Remaining Decisions Backlog

ブレインストーミングで順番に決めていく論点の一覧。MVP スコープ(旧「領域 I」)は、以下を決め切ってから確定する。

### 確定済み(「Design Decisions」 参照)

| # | 領域 | 決定 |
|---|------|------|
| A | Authoring Model | Hybrid(Rust 先行 → DSL 後付け) |
| B | Attacker Capability | Hybrid(Rust コア + ツールアダプタ)+ Kali ベース |
| C | Environment & Orchestration | Hybrid(境界は framework 所有)+ bollard |
| D | Evidence & Attack Path | Layered(Evidence = 事実 / Graph = 射影) |
| E | Reporting | Canonical JSON Pivot + SARIF(codeFlows) |
| F | Safety / Scope | Defense-in-Depth |
| G | Tool Integration | Plugin + Role 階層 / 静的プラグインから開始 |
| H | Vulnerable Playground | Hybrid(教育層なし)+ H-2: rustc 風 FAIL 診断 |
| J | Verdict Oracle | Layered Oracle(Signal + Expectation + Corroboration、Pass/Fail/Inconclusive) |
| N | 境界強制の実装方式 | Layered(Membership 基盤 + 必要な境界だけ FW + 境界セルフチェック) |
| L | シナリオ状態モデル | Attacker State Graph(足場と資産を成長する状態、D と一体化) |
| M | プラットフォーム実現範囲 | Linux + Windows/AD(実VM)+ クラウド(実)+ 各レイヤー mock/real、無線は非対象 |
| O | 実行・信頼性モデル | CI gating を前提にしない。レポート+Evidence 一次、CI は任意 informational |
| U | AI-driven Testing | Exploration(Free)+ Verification(Curated)+ 昇格機構、AI Operator 抽象 |
| K | 攻撃タクソノミ標準 | 任意だが第一級のタグ付け(ATT&CK 主軸 + OWASP 併用 + 未分類/独自を許容) |
| P | 攻撃者の起点(Vantage) | 外部 + assume-breach を第一級 |
| Q | 攻撃データ管理 | バージョン固定データパック + 明示的更新ワークフロー |
| R | 攻撃者イメージの構成と出所 | 固定ベース + 合成可能なツールプロファイル(lean/full 変種、SBOM・ライセンス審査) |
| S | 敵対者エミュレーション / C2 | Hybrid(G プラグイン + C2 セッション = L の Foothold + implant ライフサイクル層)。実装 Phase 9 |
| T | 法務 / 配布ポリシ | リスク階層型ガバナンス。全世界向け・米国/日本優先 |

### 未決(実現範囲)

**すべて確定済み。** 残るは実装前の最終ステップ:

| # | 領域 | 内容 |
|---|------|------|
| **MVP** | MVP スコープ確定 | 以上の実現範囲のうち、どこまでを最初に作るかを確定する(各決定の「段階導入の方針」を統合) |

> ※ Decision M 以降は「このプロジェクトが最終的に何を実現するか」の軸で決めた。実現範囲は確定したので、
> 次は各決定に散らばる「段階導入の方針」を1枚に束ねて **MVP スコープ**を確定する。

---

