//! 预筛与锚点计划（Aho-Corasick + 懒编译缓存）
//!
//! 设计目标：
//! - 从规则正则中抽取“锚点”字面量（must literals），构建全局 AC 自动机。
//! - 将锚点映射到规则索引，扫描时先用 AC 找到候选窗口，再对窗口内相关规则运行精准正则。
//! - 精准正则采用懒编译 + 进程内缓存，避免启动期编译整个规则集。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};

/// 归一化后的规则（来自 rules.rs 的 RuleSpec）
use crate::rules::RuleSpec;

/// 预筛计划（线程安全，可跨线程共享）
pub(crate) struct PrefilterPlan {
    /// 全局锚点自动机（按 anchors 的顺序构建）
    pub(crate) ac: AhoCorasick,
    /// 锚点字节序列（与 ac 模式索引一一对应）
    pub(crate) anchors: Vec<Vec<u8>>,
    /// 锚点索引 -> 规则索引列表（每个规则索引对应 rule_patterns 的下标）
    pub(crate) anchor_to_rules: Vec<Vec<usize>>,
    /// 规则原始模式文本（bytes 正则）
    pub(crate) rule_patterns: Vec<String>,
    /// 懒编译后的 bytes::Regex 缓存（key 为规则索引）
    pub(crate) cache: Mutex<HashMap<usize, regex::bytes::Regex>>,
}

/// 窗口参数（以 AC 命中位置为中心）
pub(crate) const WINDOW_BEFORE: usize = 256;
pub(crate) const WINDOW_AFTER: usize = 2048;

/// 从 RuleSpec 列表构建预筛计划
pub(crate) fn build_prefilter_plan(specs: &[RuleSpec]) -> Arc<PrefilterPlan> {
    // 1) 为每条规则抽取锚点
    let mut all_anchors: Vec<Vec<u8>> = Vec::new();
    let mut anchor_index: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut tmp_map_rule_to_anchor_ids: Vec<Vec<usize>> = vec![Vec::new(); specs.len()];

    for (idx, spec) in specs.iter().enumerate() {
        let pat = match spec.pattern() { Some(p) => p, None => continue };
        let anchors = extract_anchors_from_pattern(pat);
        if anchors.is_empty() {
            continue;
        }
        for a in anchors {
            let id = match anchor_index.get(&a) {
                Some(id) => *id,
                None => {
                    let id = all_anchors.len();
                    all_anchors.push(a.clone());
                    anchor_index.insert(a.clone(), id);
                    id
                }
            };
            tmp_map_rule_to_anchor_ids[idx].push(id);
        }
    }

    // 2) 反向映射：锚点 -> 规则索引列表
    let mut anchor_to_rules: Vec<Vec<usize>> = vec![Vec::new(); all_anchors.len()];
    for (rule_idx, ids) in tmp_map_rule_to_anchor_ids.iter().enumerate() {
        for &aid in ids {
            anchor_to_rules[aid].push(rule_idx);
        }
    }

    // 3) 构建 AC 自动机
    let ac = AhoCorasickBuilder::new()
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(&all_anchors)
        .expect("build aho-corasick");

    // 4) 收集规则模式文本
    let mut rule_patterns = Vec::with_capacity(specs.len());
    for s in specs {
        rule_patterns.push(s.pat.clone());
    }

    Arc::new(PrefilterPlan {
        ac,
        anchors: all_anchors,
        anchor_to_rules,
        rule_patterns,
        cache: Mutex::new(HashMap::new()),
    })
}

/// 从正则模式中抽取锚点（启发式）：
/// - 优先匹配常见密钥前缀（sk-, ghp_, glpat-, AKIA, ASIA, hf_, api_org_, SG., shpat_ 等）
/// - 其次提取模式中的连续字面量片段（长度≥3），排除常见元字符区域（[]{}()*+?|^$\\）
fn extract_anchors_from_pattern(pat: &str) -> Vec<Vec<u8>> {
    let mut out: HashSet<Vec<u8>> = HashSet::new();
    let candidates = [
        "sk-", "ghp_", "gho_", "ghr_", "ghs_", "ghu_", "github_pat_", "glpat-",
        "xox", "xapp-", "hooks.slack.com", "slack.com", "sk_", "rk_",
        "AKIA", "ASIA", "A3T", "ABIA", "ACCA", "v1.0-", "cloudflare",
        "doo_v1_", "dop_v1_", "dor_v1_", "discord", "dropbox", "EAA", "facebook",
        "heroku", "HRKU-AA", "hf_", "api_org_", "lin_api_", "mailgun", "ntn_",
        "PMAK-", "pnu_", "ATATT3", "SG.", "sntrys_", "sntryu_", "shpat_", "shpca_",
        "shppa_", "shpss_", "telegram", "SK", "AIza", "ya29.", "openai", "cohere",
    ];
    for c in candidates.iter() {
        if pat.contains(c) { out.insert(c.as_bytes().to_vec()); }
    }

    // 简单字面量扫描：提取不含元字符的连续片段
    let mut cur = String::new();
    let is_meta = |ch: char| matches!(ch, '['|']'|'{'|'}'|'('|')'|'?'|'*'|'+'|'|'|'^'|'$'|'\\');
    let allow = |ch: char| ch.is_ascii_alphanumeric() || matches!(ch, '-'|'_'|'.'|'/');
    let mut in_class = false; // 粗略处理字符类
    let mut chars = pat.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '[' { in_class = true; flush_literal(&mut cur, &mut out); continue; }
        if ch == ']' { in_class = false; flush_literal(&mut cur, &mut out); continue; }
        if in_class { continue; }
        if is_meta(ch) {
            flush_literal(&mut cur, &mut out);
            continue;
        }
        if allow(ch) {
            cur.push(ch);
        } else {
            flush_literal(&mut cur, &mut out);
        }
    }
    flush_literal(&mut cur, &mut out);

    // 过滤过短字面量
    let mut v: Vec<Vec<u8>> = out.into_iter().filter(|s| s.len() >= 3).collect();
    // 排序以稳定（长度降序，字典序）
    v.sort_by(|a, b| {
        use std::cmp::Ordering;
        match b.len().cmp(&a.len()) { Ordering::Equal => a.cmp(b), o => o }
    });
    v
}

fn flush_literal(cur: &mut String, out: &mut HashSet<Vec<u8>>) {
    if cur.len() >= 3 {
        out.insert(cur.as_bytes().to_vec());
    }
    cur.clear();
}

/// 获取（或懒编译）指定规则索引的 bytes 正则
pub(crate) fn get_or_compile_bytes_regex(plan: &PrefilterPlan, rule_idx: usize) -> Option<regex::bytes::Regex> {
    if rule_idx >= plan.rule_patterns.len() { return None; }
    // 快路径：先查缓存
    if let Some(rx) = plan.cache.lock().unwrap().get(&rule_idx).cloned() {
        return Some(rx);
    }
    let pat = &plan.rule_patterns[rule_idx];
    match regex::bytes::Regex::new(pat) {
        Ok(rx) => {
            plan.cache.lock().unwrap().insert(rule_idx, rx.clone());
            Some(rx)
        }
        Err(_) => None,
    }
}
