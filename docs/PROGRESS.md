# KeyHunter 项目进度（滚动更新）

最后更新时间：2025-11-05

当前策略：字节级检测器按阶段逐步设计与落地；UTF-8 扫描路径继续保留现状用于对比与回退。

**已完成**
- 工作区骨架与包划分：CLI 可执行与 Core 库建立，基础日志、参数解析到位。
- 扫描主流程（单线程 demo）：
  - 遍历单层目录，按文件名（md5）排序，确保输出顺序稳定。
  - 单文件内去重键为 `(file_hash, value)`；流式写出 JSON 数组。
- 引擎与参数：
  - 新增扫描引擎 `--engine {bytes|utf8}`，默认 bytes；CLI/Options 已打通。
  - Bytes 引擎使用 `regex::bytes::Regex` 在原始字节上匹配；UTF-8 引擎保留。
- 规则驱动：
  - 新增 `--rules` 参数与 `rules/default.toml`，默认从该文件加载规则。
  - 从 gitleaks.toml 摘取常见高置信规则（OpenAI/GitHub/GitLab/AWS/Slack/Stripe）至默认规则集。
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
- 规则集扩充与收敛：从 gitleaks 精选更多高置信规则，持续在样本集中校验误报。

**下一步计划（短期）**

—— 本文档将随功能推进持续更新，用于同步观测点与后续里程碑。
