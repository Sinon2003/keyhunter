//! 公共类型（对外暴露）
use serde::Serialize;

/// 输出项结构（对应 result.json 的单个元素）
#[derive(Debug, Clone, Serialize)]
pub struct OutputItem<'a> {
    pub file_hash: &'a str,
    pub value: &'a str,
}

