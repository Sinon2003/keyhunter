//! 字节级扫描引擎（小文件整读 + 大文件分块）
use anyhow::Result;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::detectors::DetectorSetBytes;
use crate::findings::FindingPublic as Finding;
use crate::prefilter::{PrefilterPlan, WINDOW_AFTER, WINDOW_BEFORE, get_or_compile_bytes_regex};

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

/// 使用预筛计划进行小文件扫描（字节引擎）
pub(crate) fn scan_file_bytes_prefilter(path: &Path, file_hash: &str, plan: &PrefilterPlan) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;

    Ok(scan_buffer_with_prefilter(&buf, 0, file_hash, plan))
}

/// 使用预筛计划进行大文件分块扫描（字节引擎）
pub(crate) fn scan_file_bytes_chunked_prefilter(path: &Path, file_hash: &str, plan: &PrefilterPlan) -> Result<Vec<Finding>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut carry: Vec<u8> = Vec::new();
    let mut file_offset: usize = 0;

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 { break; }
        let mut chunk: Vec<u8> = Vec::with_capacity(carry.len() + n);
        if !carry.is_empty() { chunk.extend_from_slice(&carry); }
        chunk.extend_from_slice(&buf[..n]);

        let base = file_offset.saturating_sub(carry.len());
        let mut part = scan_buffer_with_prefilter(&chunk, base, file_hash, plan);
        // 合并并确保文件内去重
        for f in part.drain(..) {
            if seen.insert(f.value.clone()) {
                findings.push(f);
            }
        }

        // 更新 carry 与偏移
        let keep = CHUNK_OVERLAP.min(carry.len() + n);
        let total_len = carry.len() + n;
        if keep > 0 {
            carry = chunk[total_len - keep..total_len].to_vec();
        } else {
            carry.clear();
        }
        file_offset = file_offset.saturating_add(n);
    }

    Ok(findings)
}

/// 在给定缓冲区上执行预筛匹配，返回命中项（不排序）
fn scan_buffer_with_prefilter(buf: &[u8], base_offset: usize, file_hash: &str, plan: &PrefilterPlan) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // 1) 全局 AC 扫描，收集命中位置
    let mut hits: Vec<(usize /*pos*/, usize /*anchor_id*/)> = Vec::new();
    for m in plan.ac.find_iter(buf) {
        hits.push((m.start(), m.pattern().as_usize()));
    }
    if hits.is_empty() {
        // 无锚点命中：直接返回空结果（不做全量回退，以提升性能）
        return findings;
    }

    // 2) 生成窗口并合并
    hits.sort_by_key(|h| h.0);
    let mut windows: Vec<(usize, usize, Vec<usize>)> = Vec::new(); // (start,end, anchor_ids)
    for (pos, aid) in hits.into_iter() {
        let s = pos.saturating_sub(WINDOW_BEFORE);
        let e = (pos + WINDOW_AFTER).min(buf.len());
        if let Some(last) = windows.last_mut() {
            if s <= last.1 { // 重叠，合并
                last.1 = last.1.max(e);
                last.2.push(aid);
                continue;
            }
        }
        windows.push((s, e, vec![aid]));
    }

    // 3) 对每个窗口确定候选规则并执行精准正则提取
    for (ws, we, aids) in windows.into_iter() {
        // 聚合规则索引
        let mut rule_set: HashSet<usize> = HashSet::new();
        for aid in aids {
            if let Some(rules) = plan.anchor_to_rules.get(aid) {
                for &ri in rules.iter() { rule_set.insert(ri); }
            }
        }
        if rule_set.is_empty() { continue; }
        let window = &buf[ws..we];

        for ri in rule_set.into_iter() {
            if let Some(rx) = get_or_compile_bytes_regex(plan, ri) {
                for caps in rx.captures_iter(window) {
                    let (start, end) = match caps.get(1) {
                        Some(m) => (m.start(), m.end()),
                        None => caps.get(0).map(|m| (m.start(), m.end())).unwrap_or((0, 0)),
                    };
                    if end <= start { continue; }
                    let raw = &window[start..end];
                    let value = String::from_utf8_lossy(raw).to_string();
                    if seen.insert(value.clone()) {
                        let global_start = base_offset + ws + start;
                        findings.push(Finding { file_hash: file_hash.to_string(), value, start_offset: global_start });
                    }
                }
            }
        }
    }

    findings
}
