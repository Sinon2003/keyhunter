# KeyHunter 规则编译与匹配架构（设计草案）

版本：v0.1（仅文档，尚未实现）

本文档给出在当前代码基础上引入“规则编译与匹配解耦”的整体方案，使规则数扩张后仍可保持较短的启动时间与稳定吞吐。设计强调可渐进落地、可回退到现有实现、默认行为与输出不变。

## 1. 目标与原则
- 高可扩展：规则量级上千时，启动编译时间可控（秒级）。
- 精确提取：保留“优先使用第1捕获组，否则取整个匹配”的既有语义。
- 吞吐稳定：多级漏斗 + 背压，避免正则风暴拖垮系统。
- 可回退：默认仍使用当前路径；新架构通过开关逐步启用。
- 可观测：对编译与匹配的耗时/命中率统计，辅助调优。

## 2. 现状复盘（代码基线）
- 模块：
  - 配置与统计：`crates/keyhunter-core/src/options.rs`
  - 规则加载：`crates/keyhunter-core/src/rules.rs`
  - 检测器：`crates/keyhunter-core/src/detectors.rs`
  - 引擎：`crates/keyhunter-core/src/engine_bytes.rs`, `engine_utf8.rs`
  - 扫描主流程：`crates/keyhunter-core/src/scan.rs`
- 规则加载：TOML → 归一化为 `RuleSpec { id, name, pat }`，仅保留正则文本。
- 编译：按需仅编译被选引擎（Bytes/UTF-8）的一整套正则；失败则跳过。
- 匹配：
  - Bytes：小文件整读；大文件分块（4MiB+512B overlap）。
  - 文件内去重与稳定排序；流式 JSON 输出。

问题：规则数很大时，启动期“全量正则编译”将显著增长；且匹配阶段始终在全文件/全块上直接跑完整捕获型正则，成本偏高。

## 3. 核心思想（编译与匹配解耦）
- 规则在加载后生成“可编译 IR”，对正则做静态分析，抽取可判定的必含字面量（must_literals）作为锚点（anchor）。
- 规则按“主锚点”分片（sharding）：每个分片包含若干锚点、一个粗筛集合（RegexSet，无捕获）和一组精准正则（带捕获）。
- 启动期只编译：
  - 全局锚点 Aho-Corasick 自动机（一次编译，小体量）。
  - 分片的“粗筛 RegexSet”（可选择部分高频分片预编译，其余 lazy）。
- 精准正则（带捕获）改为“按需首次命中时编译 + LRU 缓存”。
- 扫描时采用漏斗：
  1) 二进制/文本快速鉴别 → 2) 全局锚点扫描 → 3) 分片 RegexSet 粗筛（窗口化）→ 4) 精准提取（带捕获）。

## 4. 规则 IR 与静态分析
- RuleIR（拟新增类型）：
  - 源字段：id、name、raw_pattern（bytes 模式）、flags（大小写等）
  - 分析字段：anchors: Vec<Literal>（must_literals），alt_anchors（同义/别名）、kind（普通/PEM/JWT/熵类）
  - 粗筛模式：filter_pattern（去捕获/非贪婪/限制回溯）
  - 精准模式：precise_pattern（保持当前语义）
- must_literals 提取策略：
  - 有确定字面量前缀/片段（≥3 字符）则加入 anchors，如 `sk-`、`ghp_`、`AKIA`。
  - 复杂表达式（如字符类、分支）尝试近似抽取（`xox[abp]-` → `xox` 与 `-`）。
  - 若无法提取，绑定“上下文词”作为锚（如 token|secret|key|auth）。
- 规范化约束（尽量在规则源头收敛）：禁 Unicode，限制量词上限，非捕获用于上下文，捕获仅包裹真实密钥。

## 5. 规则分片（Sharding）
- Shard = { shard_id, anchors: Vec<Literal>, filter_set: RegexSet, precise: Vec<Regex>, special: Option<Kind> }
- 分片依据：主锚点（如 `sk-` 分片、`ghp_` 分片、`AKIA|ASIA` 分片）。
- 目的：
  - AC 命中锚点 → 快速定位分片，避免全规则触发。
  - RegexSet 仅对关联规则粗筛，减少无关正则的命中检查。

## 6. 编译阶段（多层缓存）
- 管线：TOML → RuleIR → Anchors + Shards →
  - 构建全局 Anchor AC（aho-corasick，dfa(true)，LeftmostLongest）。
  - 为每个分片构建 filter RegexSet（bytes 模式，禁捕获，简化模式）。
  - 精准 regex（capturing）：仅对“高频分片”预编译；其余延迟到首次触发再编译，并放入 LRU。
- 并行化：
  - IR 构建、RegexSet 编译、精准 regex 编译均可 Rayon 并行，受 `--compile-threads` 控制。
- 持久化缓存（可选，分层）：
  - L1：IR 缓存（JSON），跳过 TOML 解析。
  - L2：锚点列表与 RegexSet 源模式文本缓存，跳过 IR→模式组装。
  - L3（可选）：底层自动机/数据库序列化（如 regex-automata DFA/Hyperscan DB），绑定 CPU 特性并提供回退路径。
- 缓存键：hash(规则文件内容 + 引擎 + 编译选项 + CPU 特性 + 版本号)。
- 成本画像（Cost Profile）：为每分片/规则统计编译耗时与状态规模，供调度与预编译优先级参考。

## 7. 扫描匹配（漏斗 + 窗口化）
- 0) 快速文本鉴别：
  - 跳过明显二进制（NUL 比例/可打印比例低）；PEM/私钥块例外直接走块识别。
- 1) 全局锚点扫描（AC）：
  - 在 bytes 块上一次线性扫描，得到 (anchor_id, offset)。
  - 将命中 anchor 映射到分片 id，合并到“候选分片集合”。
- 2) 窗口化：
  - 以 offset 为中心切 [pos - Wb, pos + Wa]（默认 Wb=256, Wa=2048，可调）。
  - 合并重叠窗口，保留原始索引映射；多锚点同窗合并其分片集合。
- 3) 分片级粗筛（RegexSet）：
  - 对窗口运行 shard.filter_set.is_match(bytes)；无捕获，仅判定是否需要精准阶段。
- 4) 精准提取（按需编译 + LRU）：
  - 首次命中某分片且尚未编译其精准 regex：立即并行编译并载入 LRU（容量可配）。
  - 对粗筛命中的窗口，运行精准 regex（带捕获）提取 value，沿用“优先 group(1)”语义。
- 5) 专项匹配器：
  - PEM/SSH/PGP 私钥：块型边界解析；JWT：3 段结构校验；熵类：限定窗口内字母表与熵阈值。
- 6) 去重与排序：
  - 保持“单文件基于 value 去重 + 稳定排序 + 流式输出”的既有约束。

## 8. 并行与背压
- 线程模型：
  - 保持现有“worker 并行 + writer 单线程”架构。
  - 新增编译任务池（可与扫描池相同或独立配置），并设置有界队列形成背压。
- 调度：
  - 优先处理窗口较小、命中锚点密度高的任务；
  - 结合成本画像选择“高收益分片”先编译；
  - 对大量冷分片采取 lazy 并限制并发编译数量。

## 9. 配置与开关（仅文档，不改现有 CLI）
- 预筛与锚点：
  - `--prefilter {none|regexset|aho}`（默认 `regexset` + 全局锚点 AC 开）
  - `--anchors-min-len <N>`（默认 3）
- 编译：
  - `--compile-threads <N>`（默认 CPU 核数的一半或 `auto`）
  - `--lazy-precise`（默认启用）
  - `--lazy-lru-capacity <N>`（默认 1024）
  - `--compile-cache-dir <path>`（默认禁用）
- 窗口：
  - `--window-before <B>`（默认 256）
  - `--window-after <A>`（默认 2048）
- 其他：
  - `--binary-skip`（默认启用，可配 NUL/可打印比阈值）
  - `--shard-autoload <list>`（开局预编译指定分片）

## 10. 数据结构（草案）
- `RuleIR { id, name, raw, flags, anchors: Vec<Literal>, kind, filter_pattern, precise_pattern }`
- `Anchor { literal: Vec<u8>, shard_id }`
- `Shard { id, anchors: Vec<Anchor>, filter_set: RegexSetBytes, precise_specs: Vec<PreciseSpec>, special: Option<Kind> }`
- `PreciseSpec { id, pat_bytes, compiled: Option<RegexBytes> }`
- `Plan { ac: AhoCorasick, shards: Vec<Shard>, lru: PreciseCache, cost: CostProfile }`

## 11. 兼容性与回退
- 默认保持现有路径（不启用 AC/RegexSet/窗口），输出与排序完全一致。
- 任一阶段出错（规则编译失败/缓存损坏）时回退：
  - 对单规则：从缓存编译失败 → 直接 `Regex::new` 编译一次。
  - 对分片：RegexSet 失效 → 退回到“无预筛，直接精准正则”。

## 12. 观测与统计
- 编译：总耗时、IR 构建耗时、RegexSet 编译耗时、精准 regex lazy 次数/命中率、LRU 命中率。
- 匹配：锚点命中密度、窗口数量与平均大小、粗筛通过率、精准提取成功率、最终候选数。
- 输出到日志（tracing）并可选 JSON 摘要（方便后续基准脚本）。

## 13. 渐进落地路线
- P0：并行编译与按需编译（已完成按需引擎编译；新增并行与指标，不改变结果）。
- P1：引入锚点 AC + 分片 RegexSet 作为预筛（保持结果一致，降低匹配成本）。
- P2：窗口化与精确 regex 延迟编译 + LRU（结果一致，进一步降耗）。
- P3：持久化缓存 L1/L2（跨运行加速）。
- P4：专项匹配器（PEM/SSH/JWT/熵）与误报控制策略。

## 14. 对现有代码的对接点（不立即实现，仅标注）
- 新增模块建议：
  - `ir.rs`：RuleIR 构建与 must_literals 抽取
  - `anchors.rs`：全局 AC 构建与查询
  - `shard.rs`：分片建模、RegexSet 生成
  - `precise.rs`：精准 regex 懒编译与 LRU
  - `prefilter.rs`：窗口化策略与粗筛执行
  - `cache.rs`：编译缓存（L1/L2/L3）
- 与现有流程集成：
  - `engine_bytes.rs` 的分块扫描处，插入“锚点扫描→窗口化→分片粗筛→精准提取”的漏斗；
  - `scan.rs` 保持 writer/顺序与统计不变。

---

备注：本设计保持“file+value 唯一、单文件内去重、稳定排序、流式 JSON 输出”的评测适配不变；仅在内部编译与匹配路径增加效率手段，并提供严格的回退策略以保证正确性与可复现性。

