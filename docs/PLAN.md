# DataCon 2025 密钥猎人 — 项目架构与开发计划

本文档给出针对 DataCon 2025 软件供应链安全赛道（密钥猎人）的整体架构设计、开发里程碑与测试验证方案，以“准确率优先、后续逐步提速”为策略，面向主办方离线评测与可复现运行。

- 代码语言：Rust（rustc 1.91）
- 运行场景：本地单机扫描 120万+ 文本/代码文件
- 开发样本：`/home/sinon/study/datacon/keyhunter/exmple`（约 2500 文件）
- 全量数据：`/home/sinon/study/datacon/all_files_hash`（约 120 万文件，文件名即内容 md5）
- 输出文件：`result.json`（JSON 数组，每项包含 `file_hash` 与 `value`）

## 变更摘要（相对初版 PLAN）
- 新增 CLI 参数：`--engine {bytes|utf8}`、`--rules <path>`、`--max-file-size <bytes>`（已落地）。
- 扫描假设细化：数据集为单层目录，遍历深度固定为 1（已落地）。
- 输出稳定性细化：单文件内候选排序规则明确为“偏移升序 → 长度降序 → 字典序升序”（已落地）。
- 规则加载增强：支持字段名 `pattern` 或 `regex`；编译失败跳过不中断（已落地）。
- 引擎阶段性方案：当前使用 `regex::bytes::Regex`，后续迁移 `regex-automata 0.4`。
- 回退路径：提供完整 `Utf8` 引擎以便对比/排障（已落地）。
- 输出编码保障：字节引擎命中值以 `from_utf8_lossy` 有损转换保证 JSON 可写（已落地）。
- 并行调度：Bytes 引擎已实现 Rayon 多线程扫描 + Writer 单线程重排与流式写出；小/大文件分别走整读/分块（4MiB 块、512B 重叠）（已落地）。

## 1. 目标与评测适配
- 精度优先：以高召回+低误报为第一阶段目标，逐步引入性能优化。
- 唯一性判定：以“文件名（md5）+ 密钥值”作为唯一键；同一文件重复同值仅首次计分。
- 长密钥（≥100）相似度判定：尽量还原原文，兼顾去除多余空白/换行；必要时做轻量规范化（去 BOM、统一换行）。
- 构造/混淆/截断密钥：实现“字符串常量拼接重建”“简单常量传播”“QueryString/JSON 片段解析”等能力，优先在样本集打磨后推广至全量。

## 2. 顶层目录结构（预期）
```
keyhunter/
  Cargo.toml                   # 工作区与依赖
  crates/
    keyhunter-cli/            # 可执行入口（clap 参数、配置加载、调度）
    keyhunter-core/           # 核心库（扫描、检测、评分、重建、输出）
  rules/
    default.toml              # 可扩展规则库（正则/长度/字符集）
    gitleaks.toml             # 网上现成的规则库 （此库暂时未检查 rust 适配性）
  configs/
    default.toml              # 运行配置示例（阈值、并发、过滤项）
  docs/
    PLAN.md                   # 本文档
  scripts/
    bench.sh                  # （后期）简单基准脚本
```

## 3. 模块划分与职责
- keyhunter-cli（bin）
  - 解析 CLI 参数（clap）：输入目录、输出路径、并发、规则与阈值配置等。
  - 新增参数（已落地）：`--engine {bytes|utf8}`、`--rules <path>`、`--max-file-size <bytes>`；默认引擎为 bytes，默认规则文件为 `./rules/default.toml`。
  - 初始化日志（tracing）、装载规则与配置，启动扫描管线，输出结果与统计报告。
  - keyhunter-core（lib）
  - pipeline：
    - walker：遍历输入路径（ignore + walkdir），按文件名即 md5 作为 `file_hash`；当前实现假定数据集为“单层目录”，遍历深度固定为 1（min_depth=1, max_depth=1）。
    - scheduler/worker：Rayon/跨线程工作池，按文件粒度并行；小文件批量，减少调度开销。（当前 demo 为单线程，后续切换并行）
    - aggregator：仅在“单文件内”基于 `(file_hash, value)` 去重；跨行/跨片段重建后产出最终候选（不跨文件去重，以符合评测 file+value 口径并避免全局内存放大）。
    - writer：流式写出 JSON 数组，避免巨量内存驻留；同时保证稳定顺序（文件按名称排序；单文件内候选按固定规则排序：起始偏移升序 → 值长度降序 → 值字典序升序）。
  - scanner：
    - engine（字节级优先）：
      - 阶段性实现：M1 采用 `regex::bytes::Regex` 在原始字节上匹配（已落地）。
      - 规划升级：M2 迁移至 `regex-automata 0.4`（Hybrid/Dense DFA）以提升吞吐并降低回溯开销。
      - 回退路径：提供 `Utf8` 扫描路径（整文件 UTF-8 读取 + `regex::Regex`）用于对比与排障。
      - 输出兼容：字节引擎下命中值用 `from_utf8_lossy` 有损转换保证 JSON 可写（已落地）。
    - readers：BufRead/分块读取（固定块大小 + 重叠滑窗），保证跨块匹配不中断；支持跨行模式（如 PEM）。当前 Bytes 引擎已实现分块读取路径（4MiB、512B 重叠）。
    - normalizer：默认不做全文件 UTF-8 解码；仅在“需要语义上下文”的探测器阶段（如 JSON 字段名、语言关键字/语法）对命中附近的小窗口尝试解码（UTF-8 优先，必要时采用有损解码）。
  - detectors（检测器）：
    - regex_detector：大规模模式库（GitHub/GitLab/Slack/Stripe/OpenAI/AWS/GCP/Azure/…）。底层统一走 bytes 引擎；仅当规则需要分组提取/命名组时，对局部窗口走 UTF-8 路径。
    - entropy_detector：高熵字符串 + 长度/字符集约束 + 上下文词命中（token/secret/key/...）。
    - pem_detector：私钥/证书块（BEGIN...END）提取，支持多行。
    - jwt_detector：三段式 Base64url，校验头部 JSON 解码与字段特征。
    - base64_detector：疑似 base64 片段尝试解码并再过一次规则（限长/白名单前缀）。
    - kv_detector：从 `key=value`、URL 查询串、JSON/YAML 中抽取常见字段（secret/api_key/...）。仅对包含关键分隔符的局部窗口解码（UTF-8 优先），失败时回退到 bytes 上的启发式抽取。
  - recon（重建/反混淆）：
    - concat_rebuilder：对 Python/JS/TS/Go/Java 常见的“字符串常量 + 运算”进行轻量重建（同/邻近行，或小范围变量赋值-引用链）。
    - const_propagation：极简常量传播（仅字符串字面量 + 拼接），限定窗口大小与变量数。
    - segment_merge：针对出现 `sec*******ret` 的截断样式，尝试与邻近片段前后缀拼接（启发式，默认关闭，仅样本验证后打开）。
  - validators（校验/打分）：
    - checksum/Luhn/结构长度/字符集比例过滤，避免 MD5/SHA1/UUID 等常见非密钥。
    - provider_specific：如 AWS AccessKey 长度/前缀、Slack xox[a-z]- 前缀等二次校验。
  - scoring（候选打分）：
    - 基于检测器来源权重、上下文命中、熵、长度等合成分。
    - 阈值过滤（min_score），分层输出（强匹配/弱匹配）。
  - report（统计）：
    - 扫描文件数、候选数量、最终命中数、耗时、平均吞吐等。

## 4. 规则库与检测策略
- 规则管理
  - 默认规则内置于 `rules/default.toml`，支持外部覆盖；当前实现编译为 `regex::bytes::Regex`（已落地），规划迁移为 `regex-automata 0.4` 的字节级自动机（Hybrid/Dense DFA）。`regex::Regex` 用于 `Utf8` 引擎与少量局部提取。
  - 规则条目（v0 已实现）：`id`、`name`、`pattern` 或 `regex`（字段名二选一，均表示正则模式）。其余字段（如 `hint_keywords[]`、`min_len`、`char_class`、`post_validation`）作为后续扩展。
  - 容错策略：同时兼容字段名 `pattern` 或 `regex`；正则编译失败将跳过该规则但不中断扫描（记录计数/日志）。
- 典型规则（示例，不穷尽）
  - OpenAI：`sk-[A-Za-z0-9]{20,}`
  - GitHub PAT：`gh[opus]_\w{36,}`
  - Slack：`xox[baprs]-[A-Za-z0-9-]{10,}`
  - Stripe：`sk_(live|test)_[A-Za-z0-9]{20,}`
  - AWS AKIA/ASIA：`(A3T|AKIA|ASIA)[A-Z0-9]{16}` 与 SecretKey 高熵检测
  - GCP/Azure/Cloudflare/Telegram/Bearer/JWT/NPM/PyPI/SSH/RSA/PGP 等
- 熵与上下文
  - 字符熵阈值 + 长度阈值 + 字符类别比例（大小写/数字/特殊字符）
  - 上下文关键字（变量名、键名、注释、附近 80 字符）命中加分
- Base64/JWT/PEM
  - 受控解码：长度/字典限制/JSON 合法性校验，避免误爆
- 反混淆/重建
  - 轻量常量传播与字符串拼接求值（单文件内局部窗口，例如 200 行内）
  - QueryString/表单体解析：从 `secret_key=...`、`token=...` 中抽取 value
  - 截断拼接（可选）：`abc***xyz` 与邻近片段拼合（仅在样本集中验证有效后开启）

### 4.1 字节级扫描策略（新增）
- 输入视为原始字节序列，不做全局解码；避免遇到非 UTF-8 或混合编码文本时的漏检。
- 自动机选择：
  - Hybrid DFA：默认，内存占用可控且高吞吐；
  - Dense DFA：对稳定高频规则使用，交换更高内存以获得极致速度；
  - 按规则集分桶构建多套自动机，结合首字符/长度前缀快速路由。
- 分块搜索：固定块大小（如 64–256 KiB）+ K 字节重叠，保证跨块匹配完整；对多行模式（PEM/JWT）启用跨块状态承接。
- 局部解码：当探测器需要上下文（JSON Key、语言 token、注释/字符串字面量边界）时，仅对命中附近窗口进行 UTF-8 解码；失败时采用有损解码或回退 bytes 处理。
- 输出规范化：最终 value 按匹配到的原始字节切片直接输出（尽量原样），仅在长密钥（≥100）必要时做空白统一与换行归一。

## 5. 去重与结果规范化
- 去重范围与键：
  - 仅在“单文件内”去重，键为 `(file_hash, value)`；同一文件内相同 `value` 仅输出一次；不同文件即使 `value` 相同也分别保留。
- 规范化（value 输出约定）：
  - 仅输出“值本身”，不包含键名/等号/引号/前缀等包装；保留原始大小写。
  - 对多行块（如 PEM/SSH 私钥）保留原始内容的换行但统一为 LF；不改动行宽与内容顺序。
  - 对长密钥（≥100）不做内容重排或重新编码；仅进行必要的包裹符去除与换行统一，避免影响相似度判定。
  - 示例：
    - `secret=abc123` → `abc123`
    - `"token":"xyz"` → `xyz`
    - `Authorization: Bearer sk-AAA...` → `sk-AAA...`
    - URL 查询串 `...&api_key=K1mN...&x=1` → `K1mN...`
    - 表单体 `secret_key=gna#3...d` → `gna#3...d`
- 稳定排序输出（可复现）：
  - 全局：遍历文件时先收集并按文件名（`file_hash`）字典序排序后再调度；Rayon 并行扫描 + Writer 单线程重排写出，确保输出顺序稳定。
  - 单文件内：候选按 `(start_offset_ASC, length_DESC, value_ASC)` 的确定性规则排序后输出；如无偏移信息，则退化为 `(value_ASC)`。
  - 写出：流式 JSON 数组，按上述顺序依次写入对象；通过有界通道形成背压，避免并发导致的顺序抖动与内存放大。
- 输出：
  - 流式写 JSON 数组：先写 `[`，逐条写入对象并以逗号分隔，末尾闭合 `]`。

## 6. CLI 设计（预期）
```
keyhunter scan \
  --input /home/sinon/study/datacon/keyhunter/exmple \
  --output ./result.json \
  --rules ./rules/default.toml \
  --config ./configs/default.toml \
  --threads auto \
  --min-score 0.75 \
  --max-file-size 5MB \
  --enable-reconstruct true
```
- 子命令：`scan`、`dry-run`（不写文件，打印统计）、`print-rules`（调试）、`self-test`（样例校验）。

## 7. 性能与工程化策略（分阶段）
- 第1阶段（准确优先）
  - 预编译正则；逐行扫描 + 滑窗；多行检测器仅在候选条件触发时启用。
  - Rayon 池按 CPU 核数并行；小文件批处理。
- 第2阶段（吞吐优化）
  - I/O：mmap/`sendfile` 风格的顺序读取（按平台能力）；减少分配与拷贝。
  - 规则分桶：按首字符/前缀/长度快速路由，减少无谓正则匹配。
  - 热路径分析（`-Z self-profile`/`perf`），针对热点正则做自动机化或改写。
  - 限制高开销检测器触发频率（采样/背压）。

## 8. 测试与验证
- 单元测试
  - detectors/validators/recon 的输入输出用例（覆盖常见与反例）。
- 集成测试
  - 对 `exmple` 目录跑全流程，校验：输出格式、去重逻辑、基础规则命中。
- 回归用例集
  - 收集误报/漏报样本，加入 `crates/keyhunter-core/tests/data/`。
- 度量
  - 统计：扫描文件数、候选数、最终输出数、耗时、P95 单文件时延。

## 9. 开发里程碑（建议节奏）
- M0 骨架（0.5 天）
  - 建立 Cargo 工作区、CLI/CORE 包、基础日志与参数。
- M1 基础扫描（1.5 天）
  - 文件遍历 + 字节级正则引擎（regex-automata 0.4）+ 流式 JSON 输出；实现 8–12 类高置信规则（OpenAI/GitHub/Slack/Stripe/AWS/...）。
- M2 校验与打分（1 天）
  - 熵/上下文/长度校验、provider-specific 校验、min-score 过滤。
- M3 重建（2 天）
  - 字符串拼接与轻量常量传播；QueryString/JSON 字段解析；可选截断拼接试验。
- M4 减误报（1 天）
  - 负样本对齐、黑白名单、常见哈希/UUID/URL 过滤。
- M5 性能优化（2 天）
  - 线程池调优、规则分桶、I/O 提升；Hybrid/Dense DFA 选型与内存/吞吐权衡，跨块状态承接优化。
- M6 打包与复现（0.5 天）
  - 固定依赖、提供运行脚本/参数示例、README/结果说明。

## 10. 关键风险与对策
- 规则覆盖不足 → 逐步扩充 provider 列表，优先高权重平台。
- 构造/混淆难度高 → 先局部启用在样本集验证，逐步推广。
- 误报偏高 → 增强二次校验与上下文约束，引入阈值分层输出。
- 性能瓶颈 → 分阶段优化、分桶匹配、降低跨行检测开销。

## 11. 复现与运行（预期命令）
- 开发环境要求：Rust 1.91，clang（可选），无网络依赖运行。
- 典型运行：
```
# 样本集调试
keyhunter scan \
  --input /home/sinon/study/datacon/keyhunter/exmple \
  --output ./result.json \
  --engine bytes \
  --rules ./rules/default.toml \
  --threads auto \
  --min-score 0.75

# 全量扫描（仅示例，后期根据机器内存/CPU 调参）
keyhunter scan \
  --input /home/sinon/study/datacon/all_files_hash \
  --output ./result.json \
  --engine bytes \
  --rules ./rules/default.toml \
  --threads auto \
  --min-score 0.75 \
  --enable-reconstruct true
```

## 12. 附：默认规则与配置（示意）
 - `rules/default.toml`（片段示意）
   - 说明：当前已实现的 v0 规则格式仅支持字段 `id`、`name`、`pattern`/`regex`；下面示例中的 `hint_keywords`、`min_len` 等为后续扩展占位。
```
[[rules]]
id = "openai.sk"
name = "OpenAI API Key"
pattern = "sk-[A-Za-z0-9]{20,}"
hint_keywords = ["openai", "gpt", "api_key", "auth", "token"]
min_len = 24

[[rules]]
id = "github.pat"
name = "GitHub PAT"
pattern = "gh[oprsu]_[A-Za-z0-9_]{36,}"
hint_keywords = ["github", "gh", "token", "pat"]
min_len = 40
```
- `configs/default.toml`（片段示意）
```
[scan]
threads = "auto"
min_score = 0.75
max_file_size = "5MB"
enable_reconstruct = true
engine = "bytes"  # 扫描引擎：bytes|utf8（默认 bytes）

[filters]
max_candidates_per_file = 200
ignore_extensions = []
```

---
本计划将作为后续实现与评审的依据，实施过程中可按样本集/全量集反馈做小步快迭与规则调优。
