//! 规则文件加载（TOML）
use anyhow::Result;
use serde::Deserialize;
use std::path::Path;

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
pub(crate) struct RuleSpec {
    pub id: String,
    pub name: Option<String>,
    pub pat: String,
}

impl RuleSpec {
    pub(crate) fn pattern(&self) -> Option<&str> { Some(&self.pat) }
}

/// 从 TOML 规则文件加载并归一化为 RuleSpec 列表
pub(crate) fn load_rule_specs(path: &Path) -> Result<Vec<RuleSpec>> {
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

