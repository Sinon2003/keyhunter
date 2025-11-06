//! 命中项与排序（内部使用）

/// 单次命中的内部表示
#[derive(Debug, Clone)]
pub(crate) struct Finding {
    pub(crate) file_hash: String,
    pub(crate) value: String,
    pub(crate) start_offset: usize,
}

/// 对单文件命中进行稳定排序：起始偏移升序 → 长度降序 → 值字典序升序
pub(crate) fn sort_findings_stable(findings: &mut Vec<Finding>) {
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

// 供其他模块使用
pub(crate) use Finding as FindingPublic;

