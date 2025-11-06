//! 检测器集合（Bytes/Utf8）
use anyhow::Result;
use crate::rules::RuleSpec;

/// 字节级检测器集合（demo：少量高置信规则）
pub(crate) struct DetectorSetBytes {
    pub(crate) patterns: Vec<regex::bytes::Regex>,
}

/// UTF-8 检测器集合（与上面规则等价，便于切换引擎）
pub(crate) struct DetectorSetUtf8 {
    pub(crate) patterns: Vec<regex::Regex>,
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
    pub(crate) fn default_rules_demo_only() -> Self {
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
    pub(crate) fn default_rules_demo_only() -> Self {
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

// 供其他模块使用的类型别名（可直引）
pub(crate) use DetectorSetBytes as DetectorSetBytesPublic;
pub(crate) use DetectorSetUtf8 as DetectorSetUtf8Public;

