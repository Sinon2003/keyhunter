//! 字节级扫描引擎（小文件整读 + 大文件分块）
use anyhow::Result;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::detectors::DetectorSetBytes;
use crate::findings::FindingPublic as Finding;

/// 小文件阈值（字节）。小文件整读，超出则分块扫描。
pub(crate) const SMALL_FILE_MAX: usize = 1 * 1024 * 1024; // 1 MiB
/// 分块大小与重叠字节数（覆盖常见密钥长度/跨块情况）
pub(crate) const CHUNK_SIZE: usize = 4 * 1024 * 1024; // 4 MiB
pub(crate) const CHUNK_OVERLAP: usize = 512; // 512 bytes

/// 分块扫描大文件（Bytes 引擎）
pub(crate) fn scan_file_bytes_chunked(path: &Path, file_hash: &str, detectors: &DetectorSetBytes) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut carry: Vec<u8> = Vec::new();
    let mut file_offset: usize = 0; // 当前块在文件中的起始偏移（不含 carry）

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
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
pub(crate) fn scan_file_bytes(path: &Path, file_hash: &str, detectors: &DetectorSetBytes) -> Result<Vec<Finding>> {
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
                None => caps.get(0).map(|m| (m.start(), m.end())).unwrap_or((0, 0)),
            };
            if end <= start { continue; }

            let raw = &buf[start..end];
            // 将字节转换为字符串（有损），确保可写入 JSON
            let value = String::from_utf8_lossy(raw).to_string();

            if seen.insert(value.clone()) {
                findings.push(Finding { file_hash: file_hash.to_string(), value, start_offset: start });
            }
        }
    }

    Ok(findings)
}

