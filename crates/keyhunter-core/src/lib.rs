//! 核心扫描库（demo 版）
//!
//! 设计要点（与 PLAN 对齐）：
//! - 优先采用“字节级”扫描（Bytes 引擎），避免 UTF-8 解码失败导致的漏检/退化。
//! - 仅在需要语义上下文时（如 JSON 键名、语言关键字）再对局部窗口尝试 UTF-8 解码。
//! - 单文件内按 `(file_hash, value)` 去重；全局不去重，符合评测口径。
//! - 输出为流式 JSON 数组，保证稳定顺序与可复现性（此处由外层控制）。

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use std::sync::Arc;
use crossbeam_channel as channel;
use rayon::prelude::*;

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

/// 扫描引擎类型
/// - Bytes：基于 `regex::bytes` 的字节级正则匹配，稳健且避免编码问题。
/// - Utf8：传统基于 `String` 的匹配，适合需要 UTF-8 语义的场景。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanEngine {
    Bytes,
    Utf8,
}

/// 输出项结构（对应 result.json 的单个元素）
#[derive(Debug, Clone, Serialize)]
pub struct OutputItem<'a> {
    pub file_hash: &'a str,
    pub value: &'a str,
}

/// 单次命中的内部表示
#[derive(Debug, Clone)]
pub struct Finding {
    pub file_hash: String,
    pub value: String,
    pub start_offset: usize,
}

/// 扫描统计信息（便于 CLI 打印）
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub files_scanned: usize,
    pub candidates_total: usize,
    pub outputs_written: usize,
}

/// 字节级检测器集合（demo：少量高置信规则）
pub struct DetectorSetBytes {
    patterns: Vec<regex::bytes::Regex>,
}

/// UTF-8 检测器集合（与上面规则等价，便于切换引擎）
pub struct DetectorSetUtf8 {
    patterns: Vec<regex::Regex>,
}

impl DetectorSetBytes {
    /// 从规则条目构建字节级检测器集合
    pub(crate) fn from_specs(specs: &[RuleSpec]) -> Result<Self> {
        let mut patterns = Vec::new();
        for r in specs {
            if let Some(pat) = r.pattern() {
                // 对于 bytes 引擎，直接编译为 bytes::Regex
                if let Ok(rx) = regex::bytes::Regex::new(pat) {
                    patterns.push(rx);
                }
            }
        }
        Ok(Self { patterns })
    }
    /// 旧的内置规则（演示用），现已由文件驱动，保留注释以供参考
    #[allow(dead_code)]
    pub fn default_rules_demo_only() -> Self {
        // let patterns = vec![
        //     regex::bytes::Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        //     regex::bytes::Regex::new(r"gh[oprsu]_[A-Za-z0-9_]{36,}").unwrap(),
        //     regex::bytes::Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
        //     regex::bytes::Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{20,}").unwrap(),
        //     regex::bytes::Regex::new(r"(?:A3T|AKIA|ASIA)[A-Z0-9]{16}").unwrap(),
        // ];
        // Self { patterns }
        Self { patterns: Vec::new() }
    }
}

impl DetectorSetUtf8 {
    /// 从规则条目构建 UTF-8 检测器集合
    pub(crate) fn from_specs(specs: &[RuleSpec]) -> Result<Self> {
        let mut patterns = Vec::new();
        for r in specs {
            if let Some(pat) = r.pattern() {
                if let Ok(rx) = regex::Regex::new(pat) {
                    patterns.push(rx);
                }
            }
        }
        Ok(Self { patterns })
    }
    /// 旧的内置规则（演示用），现已由文件驱动，保留注释以供参考
    #[allow(dead_code)]
    pub fn default_rules_demo_only() -> Self {
        // let patterns = vec![
        //     regex::Regex::new(r"sk-[A-Za-z0-9]{20,}").unwrap(),
        //     regex::Regex::new(r"gh[oprsu]_[A-Za-z0-9_]{36,}").unwrap(),
        //     regex::Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
        //     regex::Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{20,}").unwrap(),
        //     regex::Regex::new(r"(?:A3T|AKIA|ASIA)[A-Z0-9]{16}").unwrap(),
        // ];
        // Self { patterns }
        Self { patterns: Vec::new() }
    }
}

/// 扫描目录并将结果以 JSON 数组流式写入 `out`
/// 稳定性保证：
/// - 文件级：先收集文件并按文件名（md5）排序，确保输出顺序可复现
/// - 文件内：命中项按 (start_offset 升序, value 长度降序, value 字典序升序) 排序
pub fn scan_and_write(input_dir: &Path, out: &mut dyn Write, opts: &ScanOptions) -> Result<ScanStats> {
    // 加载规则文件（默认 ./rules/default.toml）
    let rules_path = opts
        .rules_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("./rules/default.toml"));
    let rule_specs = load_rule_specs(&rules_path)?;
    // 构建对应引擎的检测器集合（另一种引擎仅在切换时使用）
    let detectors_bytes = Arc::new(DetectorSetBytes::from_specs(&rule_specs)?);
    let detectors_utf8 = DetectorSetUtf8::from_specs(&rule_specs)?;

    let mut stats = ScanStats::default();

    let mut files: Vec<PathBuf> = vec![];
    // 遍历输入目录（数据集为单层目录，这里限制深度为 1）
    for entry in WalkDir::new(input_dir).min_depth(1).max_depth(1) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if entry.file_type().is_file() { files.push(entry.into_path()); }
    }
    // 按文件名排序，确保输出顺序稳定
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    // 决策：若为 Bytes 引擎且线程数>1，则走并行调度；否则使用串行扫描
    let threads = opts.threads.unwrap_or_else(|| num_cpus::get());
    let use_parallel = matches!(opts.engine, ScanEngine::Bytes) && threads > 1;

    if use_parallel {
        scan_and_write_parallel_bytes(&files, out, opts, &detectors_bytes, &mut stats, threads)?;
        return Ok(stats);
    }

    // 串行路径（保持原有逻辑，UTF-8 亦在此路径执行）
    write!(out, "[")?;
    let mut first = true;
    for path in files {
        let file_name = match path.file_name().and_then(|s| s.to_str()) { Some(s) => s, None => continue };
        if let Some(max) = opts.max_file_size { if let Ok(md) = std::fs::metadata(&path) { if md.len() > max { continue; } } }
        let res = match opts.engine {
            ScanEngine::Bytes => scan_file_bytes(&path, file_name, &detectors_bytes),
            ScanEngine::Utf8 => scan_file_utf8(&path, file_name, &detectors_utf8),
        };
        match res {
            Ok(mut findings) => {
                stats.files_scanned += 1;
                // 文件内稳定排序
                sort_findings_stable(&mut findings);
                for f in findings.iter() {
                    stats.outputs_written += 1;
                    if !first { write!(out, ",")?; } else { first = false; }
                    let item = serde_json::json!({ "file_hash": f.file_hash, "value": f.value });
                    serde_json::to_writer(&mut *out, &item)?;
                }
            }
            Err(_) => continue,
        }
    }
    write!(out, "]")?;
    Ok(stats)
}

/// 对单文件命中进行稳定排序：起始偏移升序 → 长度降序 → 值字典序升序
fn sort_findings_stable(findings: &mut Vec<Finding>) {
    findings.sort_by(|a, b| {
        use std::cmp::Ordering;
        match a.start_offset.cmp(&b.start_offset) {
            Ordering::Equal => match b.value.len().cmp(&a.value.len()) {
                Ordering::Equal => a.value.cmp(&b.value),
                o => o,
            },
            o => o,
        }
    });
}

/// 并行调度（Bytes 引擎）：
/// - 建索引后使用 Rayon 线程池并行扫描
/// - 单线程 Writer 按 idx 重排并流式写 JSON，保证稳定顺序
fn scan_and_write_parallel_bytes(
    files: &[PathBuf],
    out: &mut dyn Write,
    opts: &ScanOptions,
    detectors: &Arc<DetectorSetBytes>,
    stats: &mut ScanStats,
    threads: usize,
) -> Result<()> {
    // 写 JSON 开始符
    write!(out, "[")?;
    let mut first = true;

    // 通道用于 worker → writer 传递结果
    type Msg = (usize /*idx*/, Vec<Finding> /*findings*/, bool /*scanned*/);
    let (tx, rx) = channel::bounded::<Msg>(256);

    // 为防止 &mut out 的跨线程所有权问题，Writer 保持在当前线程
    // 扫描在后台线程内创建 Rayon 线程池并执行
    let detectors = Arc::clone(detectors);
    let max_file_size = opts.max_file_size;

    let files_vec: Vec<(usize, PathBuf)> = files
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p.clone()))
        .collect();

    let scan_thread = std::thread::spawn(move || {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("build rayon pool");
        pool.install(|| {
            files_vec.par_iter().for_each(|(idx, path)| {
                // 路径与文件名
                let file_name = match path.file_name().and_then(|s| s.to_str()) { Some(s) => s.to_string(), None => { let _ = tx.send((*idx, Vec::new(), false)); return; } };
                // 大小过滤（与串行一致）
                if let Some(max) = max_file_size { if let Ok(md) = std::fs::metadata(path) { if md.len() > max { let _ = tx.send((*idx, Vec::new(), false)); return; } } }

                // 选择读取策略：小文件整读，超大文件分块
                let findings_res = match std::fs::metadata(path) {
                    Ok(md) => {
                        let sz = md.len();
                        if sz <= SMALL_FILE_MAX as u64 {
                            scan_file_bytes(path, &file_name, &detectors)
                        } else {
                            scan_file_bytes_chunked(path, &file_name, &detectors)
                        }
                    }
                    Err(_) => Err(anyhow::anyhow!("metadata failed")),
                };

                match findings_res {
                    Ok(mut findings) => {
                        // 稳定排序可在 writer 进行；此处也可预排序以降低主线程负担
                        sort_findings_stable(&mut findings);
                        let _ = tx.send((*idx, findings, true));
                    }
                    Err(_) => { let _ = tx.send((*idx, Vec::new(), false)); }
                }
            });
        });
        // 结束后 Sender 全部被丢弃，Receiver 将收到关闭信号
    });

    // Writer：维护 next_idx 与缓存，按序输出
    use std::collections::BTreeMap;
    let mut next_idx: usize = 0;
    let mut buffer: BTreeMap<usize, (Vec<Finding>, bool)> = BTreeMap::new();

    while let Ok((idx, findings, scanned)) = rx.recv() {
        buffer.insert(idx, (findings, scanned));
        // 尝试从 next_idx 开始顺序冲刷
        while let Some((mut findings, scanned)) = buffer.remove(&next_idx).map(|v| v) {
            if scanned { stats.files_scanned += 1; }
            // 文件内稳定排序已在 worker 执行；此处再保证一次
            sort_findings_stable(&mut findings);
            for f in findings.iter() {
                stats.outputs_written += 1;
                if !first { write!(out, ",")?; } else { first = false; }
                let item = serde_json::json!({ "file_hash": f.file_hash, "value": f.value });
                serde_json::to_writer(&mut *out, &item)?;
            }
            next_idx += 1;
        }
    }

    // 等待扫描线程结束
    let _ = scan_thread.join();

    // 最终冲刷残余（理论上缓冲应已清空）
    while let Some((mut findings, scanned)) = buffer.remove(&next_idx) {
        if scanned { stats.files_scanned += 1; }
        sort_findings_stable(&mut findings);
        for f in findings.iter() {
            stats.outputs_written += 1;
            if !first { write!(out, ",")?; } else { first = false; }
            let item = serde_json::json!({ "file_hash": f.file_hash, "value": f.value });
            serde_json::to_writer(&mut *out, &item)?;
        }
        next_idx += 1;
    }

    // 写 JSON 结束符
    write!(out, "]")?;
    Ok(())
}

/// 小文件阈值（字节）。小文件整读，超出则分块扫描。
const SMALL_FILE_MAX: usize = 1 * 1024 * 1024; // 1 MiB
/// 分块大小与重叠字节数（覆盖常见密钥长度/跨块情况）
const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
const CHUNK_OVERLAP: usize = 512; // 512 bytes

/// 分块扫描大文件（Bytes 引擎）
fn scan_file_bytes_chunked(path: &Path, file_hash: &str, detectors: &DetectorSetBytes) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut carry: Vec<u8> = Vec::new();
    let mut file_offset: usize = 0; // 当前块在文件中的起始偏移（不含 carry）

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let mut chunk: Vec<u8> = Vec::with_capacity(carry.len() + n);
        if !carry.is_empty() { chunk.extend_from_slice(&carry); }
        chunk.extend_from_slice(&buf[..n]);

        // 在 chunk 上运行检测器，匹配到的偏移需要映射回文件偏移
        for re in &detectors.patterns {
            for caps in re.captures_iter(&chunk) {
                let (start, end) = match caps.get(1) {
                    Some(m) => (m.start(), m.end()),
                    None => caps.get(0).map(|m| (m.start(), m.end())).unwrap_or((0, 0)),
                };
                if end <= start { continue; }
                let raw = &chunk[start..end];
                let value = String::from_utf8_lossy(raw).to_string();
                if seen.insert(value.clone()) {
                    // 计算全局偏移： (file_offset - carry_len) + start
                    let base = file_offset.saturating_sub(carry.len());
                    let global_start = base + start;
                    findings.push(Finding { file_hash: file_hash.to_string(), value, start_offset: global_start });
                }
            }
        }

        // 更新 carry：保留当前 chunk 的末尾重叠区域
        let keep = CHUNK_OVERLAP.min(carry.len() + n);
        let total_len = carry.len() + n;
        if keep > 0 {
            carry = chunk[total_len - keep..total_len].to_vec();
        } else {
            carry.clear();
        }
        // 移动文件偏移：增加本次实际推进的字节数（即 n）
        file_offset = file_offset.saturating_add(n);
    }

    Ok(findings)
}

/// 按“字节级”方式扫描单个文件
/// - 直接读取所有字节并在 `regex::bytes` 上匹配
/// - 命中值输出时使用 `from_utf8_lossy` 进行有损转换，保证 JSON 可写
/// - 单文件内基于 value 去重，防止重复输出
fn scan_file_bytes(path: &Path, file_hash: &str, detectors: &DetectorSetBytes) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for re in &detectors.patterns {
        // 使用捕获组：若存在第1个捕获组，则优先作为“真实密钥值”；否则退回整个匹配
        for caps in re.captures_iter(&buf) {
            // 选择匹配片段（优先 group(1)）
            let (start, end) = match caps.get(1) {
                Some(m) => (m.start(), m.end()),
                None => caps
                .get(0)
                .map(|m| (m.start(), m.end()))
                .unwrap_or((0, 0)),
            };
            if end <= start { continue; }

            let raw = &buf[start..end];
            // 将字节转换为字符串（有损），确保可写入 JSON
            let value = String::from_utf8_lossy(raw).to_string();

            if seen.insert(value.clone()) {
                findings.push(Finding {
                    file_hash: file_hash.to_string(),
                    value,
                    start_offset: start,
                });
            }
        }
    }

    Ok(findings)
}

/// 按“UTF-8 字符串”方式扫描单个文件
/// - 适合需要 UTF-8 语义的检测器（demo 保持与 Bytes 等价规则）
/// - 单文件内基于 value 去重
fn scan_file_utf8(path: &Path, file_hash: &str, detectors: &DetectorSetUtf8) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = String::new();
    reader.read_to_string(&mut buf)?;

    let mut seen: HashSet<String> = HashSet::new();
    let mut findings: Vec<Finding> = Vec::new();

    for re in &detectors.patterns {
        // 同样优先使用第1个捕获组，兼容部分规则末尾存在分隔符/换行等上下文
        for caps in re.captures_iter(&buf) {
            let (start, end) = match caps.get(1) {
            Some(m) => (m.start(), m.end()),
            None => caps
                .get(0)
                .map(|m| (m.start(), m.end()))
              .unwrap_or((0, 0)),
            };
            if end <= start { continue; }

            let value = buf[start..end].to_string();
            if seen.insert(value.clone()) {
                findings.push(Finding {
                    file_hash: file_hash.to_string(),
                    value,
                    start_offset: start,
                });
            }
        }
    }

    Ok(findings)
}

// ---------------- 规则加载（TOML） ----------------

/// 单条规则的配置（支持 pattern 或 regex 字段）
#[derive(Debug, Clone, Deserialize)]
struct RuleEntry {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

/// 顶层规则文件结构
#[derive(Debug, Clone, Deserialize)]
struct RuleFile {
    #[serde(default)]
    pub rules: Vec<RuleEntry>,
}

/// 归一化后的规则规格（内部使用）
#[derive(Debug, Clone)]
struct RuleSpec {
    pub id: String,
    pub name: Option<String>,
    pub pat: String,
}

impl RuleSpec {
    fn pattern(&self) -> Option<&str> { Some(&self.pat) }
}

/// 从 TOML 规则文件加载并归一化为 RuleSpec 列表
fn load_rule_specs(path: &Path) -> Result<Vec<RuleSpec>> {
    let txt = std::fs::read_to_string(path)?;
    let parsed: RuleFile = toml::from_str(&txt)?;
    let mut out = Vec::new();

    for e in parsed.rules {
        // 兼容两种字段名：pattern 或 regex
        let pat = match (e.pattern, e.regex) {
            (Some(p), _) => p,
            (None, Some(r)) => r,
            _ => continue,
        };
        out.push(RuleSpec { id: e.id, name: e.name, pat });
    }

    Ok(out)
}
