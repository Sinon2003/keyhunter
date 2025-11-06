//! 字节级扫描引擎（小文件整读 + 大文件分块）
use anyhow::Result;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::detectors::DetectorSetBytes;
use crate::findings::FindingPublic as Finding;
use crate::prefilter::{PrefilterPlan, WINDOW_AFTER, WINDOW_BEFORE, get_or_compile_meta_regex};
use regex_automata as ra;
use ra::Input;

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

    // 二进制文件快速判定（保守）：
    // - 若包含 NUL 字节，则视为二进制，直接跳过；
    // - 或可打印字符占比过低（< 25%）也跳过。
    if is_probably_binary(&buf) {
        return Ok(Vec::new());
    }

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

        // 对首个块做二进制判定；若疑似二进制，直接跳过整个文件。
        if file_offset == 0 {
            // 只抽样前 8KiB，避免超大 chunk 误判
            let sample_len = chunk.len().min(8192);
            if is_probably_binary(&chunk[..sample_len]) {
                return Ok(Vec::new());
            }
        }

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
        // 针对 PEM/私钥类锚点放大窗口，避免长块被截断导致无法匹配完整 BEGIN..END 结构
        let anchor = plan.anchors.get(aid).map(|v| v.as_slice()).unwrap_or(&[]);
        let is_begin = anchor.starts_with(b"-----BEGIN ");
        let is_end   = anchor.starts_with(b"-----END ");
        let is_priv  = anchor.windows(12).any(|w| w == b"PRIVATE KEY");

        let before = if is_end || is_priv { WINDOW_BEFORE.max(2048) } else { WINDOW_BEFORE };
        let after  = if is_begin || is_priv { WINDOW_AFTER.max(16 * 1024) } else { WINDOW_AFTER };

        let s = pos.saturating_sub(before);
        let e = (pos + after).min(buf.len());
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
            if let Some(rx) = get_or_compile_meta_regex(plan, ri) {
                // 使用 regex-automata 0.4 meta 引擎执行匹配并提取捕获
                let re = &*rx;
                let mut caps = re.create_captures();
                let mut at = 0usize;
                loop {
                    // 在 [at..] 范围内继续查找下一个匹配
                    let input = Input::new(window).span(at..window.len());
                    re.captures(input, &mut caps);
                    let m0 = match caps.get_group(0) { Some(sp) => sp, None => break };
                    let (start, end) = if let Some(g1) = caps.get_group(1) {
                        (g1.start, g1.end)
                    } else {
                        (m0.start, m0.end)
                    };
                    if end <= start { at = m0.end.saturating_add(1); continue; }
                    let raw = &window[start..end];
                    let value = String::from_utf8_lossy(raw).to_string();
                    if seen.insert(value.clone()) {
                        let global_start = base_offset + ws + start;
                        findings.push(Finding { file_hash: file_hash.to_string(), value, start_offset: global_start });
                    }
                    // 推进光标，防止零宽循环
                    at = if m0.end > at { m0.end } else { at.saturating_add(1) };
                }
            }
        }
    }

    findings
}

/// 判定缓冲区是否“明显是二进制”
/// 策略（保守，尽量不误杀文本）：
/// - 只要包含任何 NUL 字节（0x00）即认为二进制；
/// - 否则计算可打印 ASCII 比例（包含 tab/CR/LF），低于 25% 则认为二进制。
fn is_probably_binary(buf: &[u8]) -> bool {
    if buf.is_empty() { return false; }
    if buf.iter().any(|&b| b == 0) { return true; }
    let printable = buf.iter().filter(|&&b| matches!(b, 0x09 | 0x0A | 0x0D) || (0x20..=0x7E).contains(&b)).count();
    let ratio = printable as f32 / (buf.len() as f32);
    ratio < 0.25
}
