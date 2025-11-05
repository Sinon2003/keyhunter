# KeyHunter 项目进度（滚动更新）

最后更新时间：2025-11-05

当前策略：字节级检测器按阶段逐步设计与落地；UTF-8 扫描路径继续保留现状用于对比与回退。

**已完成**
- 工作区骨架与包划分：CLI 可执行与 Core 库建立，基础日志、参数解析到位。
- 扫描主流程（单线程 demo）：
  - 遍历单层目录，按文件名（md5）排序，确保输出顺序稳定。
  - 单文件内去重键为 `(file_hash, value)`；流式写出 JSON 数组。
  - 参考：crates/keyhunter-core/src/lib.rs:140。
- 引擎与参数：
  - 新增扫描引擎 `--engine {bytes|utf8}`，默认 bytes；CLI/Options 已打通。
    - 参考：crates/keyhunter-cli/src/main.rs:41, crates/keyhunter-cli/src/main.rs:63。
  - Bytes 引擎使用 `regex::bytes::Regex` 在原始字节上匹配；UTF-8 引擎保留。
    - 参考：crates/keyhunter-core/src/lib.rs:83, crates/keyhunter-core/src/lib.rs:112。
- 规则驱动：
  - 新增 `--rules` 参数与 `rules/default.toml`，默认从该文件加载规则。
    - 参考：crates/keyhunter-cli/src/main.rs:45, crates/keyhunter-core/src/lib.rs:145。
  - 从 gitleaks.toml 摘取常见高置信规则（OpenAI/GitHub/GitLab/AWS/Slack/Stripe）至默认规则集。
    - 参考：rules/default.toml:1。
- 注释与文档：
  - 核心与 CLI 关键位置中文注释补齐；PLAN.md 已更新字节级扫描策略与里程碑。

- 并行调度（新）：
  - 建索引后使用 Rayon 线程池按文件并行扫描（仅 bytes 引擎）；主线程 Writer 通过有界通道重排并按文件名序流式写出，保证稳定顺序。
    - 参考：crates/keyhunter-core/src/lib.rs:360。
  - 小/大文件路径：≤1MiB 整读，>1MiB 分块扫描（4MiB 块、512B 重叠），跨块匹配不丢失；文件内基于 value 去重。
    - 参考：crates/keyhunter-core/src/lib.rs:452, crates/keyhunter-core/src/lib.rs:478。
  - `--threads` 参数打通：`auto`=CPU 核数，>1 触发并行；UTF-8 引擎仍走串行回退路径。
    - 参考：crates/keyhunter-cli/src/main.rs:63, crates/keyhunter-core/src/lib.rs:173。

**已验证**
- 构建与运行：
  - 样本集扫描（可能无命中属正常，视样本而定）：
    - `cargo run -p keyhunter-cli -- scan --input ./exmple --output ./result.json --engine bytes`。
  - 输出格式：`result.json` 为稳定顺序的 JSON 数组；空结果时为 `[]`。

**进行中（WIP）**
- 字节级检测器深化设计：保留 regex::bytes 最小可用实现，规划迁移到 regex-automata 0.4（Hybrid/Dense DFA）。
- 规则集扩充与收敛：从 gitleaks 精选更多高置信规则，持续在样本集中校验误报。

**下一步计划（短期）**
- 引擎与 I/O
  - 引入 regex-automata 0.4，先落地 Hybrid DFA；保留回退路径。
  - 分块读取 + K 字节重叠，保证跨块匹配完整；为多行规则预留状态承接。
- 检测器
  - PEM/JWT 多行抽取；Base64 受控解码再检测；KV/JSON/QueryString 抽取（局部 UTF-8 解码）。
- 校验与过滤
  - 熵/长度/字符集比例；Provider-specific 二次校验；黑白名单与常见哈希/UUID 过滤。
- 重建（Recon）
  - 字符串常量拼接与轻量常量传播（小窗口、限变量数）。
- 测试与度量
  - 为 detectors/validators/recon 补单测；exmple 目录做集成验证；统计输出数量与耗时基线。

**潜在风险**
- 规则过多导致误报：先以高置信规则为主，逐步扩展；引入二次校验与阈值分层。
- 非 UTF-8 文本/混合编码：坚持 bytes-first；仅在需要上下文时局部解码。
- 吞吐与内存：后续按 Hybrid/Dense DFA 与分块策略优化。

**运行指引（当前 demo）**
- 使用默认规则与字节引擎：
  - `keyhunter scan --input /home/sinon/study/datacon/keyhunter/exmple --output ./result.json --engine bytes`
- 指定规则文件：
  - `keyhunter scan --input ./exmple --output ./result.json --engine bytes --rules ./rules/default.toml`
 - 指定线程数：
   - `keyhunter scan --input ./exmple --output ./result.json --engine bytes --threads 8`
   - 或 `--threads auto`（默认）

—— 本文档将随功能推进持续更新，用于同步观测点与后续里程碑。
