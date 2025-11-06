//! 核心扫描库（demo 版）
//!
//! 设计要点（与 PLAN 对齐）：
//! - 优先采用“字节级”扫描（Bytes 引擎），避免 UTF-8 解码失败导致的漏检/退化。
//! - 仅在需要语义上下文时（如 JSON 键名、语言关键字）再对局部窗口尝试 UTF-8 解码。
//! - 单文件内按 `(file_hash, value)` 去重；全局不去重，符合评测口径。
//! - 输出为流式 JSON 数组，保证稳定顺序与可复现性（此处由外层控制）。

// 模块化拆分：仅重构为多文件模块，不改变任何逻辑
mod options;
mod types;
mod findings;
mod detectors;
mod rules;
mod engine_bytes;
mod engine_utf8;
mod scan;

// 对外暴露与原 API 保持一致
pub use options::{ScanOptions, ScanEngine, ScanStats};
pub use types::OutputItem;
pub use scan::scan_and_write;
