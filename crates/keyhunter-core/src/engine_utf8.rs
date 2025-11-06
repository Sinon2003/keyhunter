//! UTF-8 字符串扫描引擎
use anyhow::Result;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::detectors::DetectorSetUtf8;
use crate::findings::FindingPublic as Finding;

/// 按“UTF-8 字符串”方式扫描单个文件
/// - 适合需要 UTF-8 语义的检测器（demo 保持与 Bytes 等价规则）
/// - 单文件内基于 value 去重
pub(crate) fn scan_file_utf8(path: &Path, file_hash: &str, detectors: &DetectorSetUtf8) -> Result<Vec<Finding>> {
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
                None => caps.get(0).map(|m| (m.start(), m.end())).unwrap_or((0, 0)),
            };
            if end <= start { continue; }

            let value = buf[start..end].to_string();
            if seen.insert(value.clone()) {
                findings.push(Finding { file_hash: file_hash.to_string(), value, start_offset: start });
            }
        }
    }

    Ok(findings)
}

