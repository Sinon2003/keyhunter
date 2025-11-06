//! 扫描选项与统计信息（模块）
use std::path::PathBuf;

/// 扫描引擎类型
/// - Bytes：基于 `regex::bytes` 的字节级正则匹配，稳健且避免编码问题。
/// - Utf8：传统基于 `String` 的匹配，适合需要 UTF-8 语义的场景。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEngine {
    Bytes,
    Utf8,
}

/// 扫描选项
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// 最小打分阈值（demo 暂未使用，预留）
    pub min_score: f32,
    /// 最大文件大小（字节）；超过则跳过
    pub max_file_size: Option<u64>,
    /// 扫描引擎：Bytes（字节级）或 Utf8（基于字符串）
    pub engine: ScanEngine,
    /// 规则文件路径（TOML）；为空则使用默认路径 ./rules/default.toml
    pub rules_path: Option<PathBuf>,
    /// 线程数：None 表示自动（等于 CPU 核数）；Some(1) 走串行
    pub threads: Option<usize>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            min_score: 0.0,
            max_file_size: None,
            engine: ScanEngine::Bytes,
            rules_path: None,
            threads: None,
        }
    }
}

/// 扫描统计信息（便于 CLI 打印）
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub candidates_total: usize,
    pub outputs_written: usize,
}

