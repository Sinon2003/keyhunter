//! 预筛与锚点计划（Aho-Corasick + 懒编译缓存）
//!
//! 设计目标：
//! - 从规则正则中抽取“锚点”字面量（must literals），构建全局 AC 自动机。
//! - 将锚点映射到规则索引，扫描时先用 AC 找到候选窗口，再对窗口内相关规则运行精准正则。
//! - 精准正则采用懒编译 + 进程内缓存，避免启动期编译整个规则集。

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use regex_automata as ra;
use ra::meta::Regex as MetaRegex;

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
    /// 懒编译后的 regex-automata 元引擎正则缓存（key 为规则索引）
    /// 说明：此处使用 meta::Regex，支持捕获组；使用 Arc 以便跨线程轻量克隆
    pub(crate) cache: Mutex<HashMap<usize, Arc<MetaRegex>>>,
}

/// 窗口参数（以 AC 命中位置为中心）
/// 说明：在默认规则集中，多数密钥都紧邻锚点（如前缀/域名）。
/// 将窗口收敛可显著减少精准正则的处理字节量，提升吞吐。
/// 若发现召回下降，可在后续通过 CLI 参数暴露成可调项。
pub(crate) const WINDOW_BEFORE: usize = 128;
pub(crate) const WINDOW_AFTER: usize = 1024;

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
    // out 收集候选锚点（字节串），避免重复
    let mut out: HashSet<Vec<u8>> = HashSet::new();

    // 1) 精选的高置信锚点（覆盖主流密钥前缀/域名/标识），优先使用
    //    注意：尽量使用具有区分度的前缀，避免如 "SK" 这类过于宽泛的短 token。
    let curated = [
        // 通用厂商/产品前缀
        "sk-", "sk_", "rk_", "ghp_", "gho_", "ghr_", "ghs_", "ghu_", "github_pat_", "glpat-",
        "xoxb-", "xoxp-", "xoxe-", "xoxs-", "xapp-", "hooks.slack.com", "slack.com",
        "AKIA", "ASIA", "A3T", "ABIA", "ACCA", "v1.0-", "cloudflare",
        "doo_v1_", "dop_v1_", "dor_v1_", "discord", "dropbox", "EAA", "facebook",
        "heroku", "HRKU-AA", "hf_", "api_org_", "lin_api_", "mailgun", "ntn_",
        "PMAK-", "pnu_", "ATATT3", "SG.", "sntrys_", "sntryu_", "shpat_", "shpca_",
        "shppa_", "shpss_", "telegram", "AIza", "ya29.", "openai", "cohere",
        // PEM/私钥常见边界（避免使用通用的 "KEY"、"BEGIN"，选择更具体的片段）
        "-----BEGIN ", "-----END ", "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ];
    for c in curated.iter() {
        if pat.contains(c) { out.insert(c.as_bytes().to_vec()); }
    }

    // 1.1 针对含有字符类/分支但目标文本具备确定前缀的规则，主动扩展锚点：
    //  - Slack 用户令牌：xox[pe]- → { "xoxp-", "xoxe-" }
    //  - Slack 旧令牌：  xox[os]- → { "xoxo-", "xoxs-" }
    //  - GitHub App：    (?:ghu|ghs)_ → { "ghu_", "ghs_" }
    //  - Stripe sk/rk：  (?:sk|rk)_   → { "sk_",  "rk_" }
    if pat.contains("xox[pe]") || pat.contains("xox(?:p|e)") { out.insert(b"xoxp-".to_vec()); out.insert(b"xoxe-".to_vec()); }
    if pat.contains("xox[os]") || pat.contains("xox(?:o|s)") { out.insert(b"xoxo-".to_vec()); out.insert(b"xoxs-".to_vec()); }
    if pat.contains("(?:ghu|ghs)_") || pat.contains("ghu|ghs)_") { out.insert(b"ghu_".to_vec()); out.insert(b"ghs_".to_vec()); }
    if pat.contains("(?:sk|rk)_")  || pat.contains("sk|rk)_")  { out.insert(b"sk_".to_vec());  out.insert(b"rk_".to_vec()); }

    // 2) 保守的字面量抽取（降噪版）：
    //    - 仅提取不含元字符的连续片段
    //    - 过滤掉过短或过于通用的词（例如 KEY/BEGIN/END 等）
    //    - 保留包含分隔符(-_/.)的短片段，或长度>=6 的纯字母数字片段
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

    // 3) 过滤规则：
    //    - 长度>=6 直接保留；
    //    - 长度>=4 且包含 - _ . / 之一保留（如 glpat-、AIza、ya29.）
    //    - 排除通用词（stoplist），避免产生大量无关窗口
    let stoplist = [
        "KEY", "BEGIN", "END", "PRIVATE", "TOKEN", "ACCESS", "SECRET", "AUTH", "PASSWORD",
    ];

    let has_sep = |s: &Vec<u8>| s.iter().any(|&b| matches!(b, b'-'|b'_'|b'.'|b'/'));
    let is_stop = |s: &Vec<u8>| {
        if s.len() < 3 { return true; }
        let up = String::from_utf8_lossy(s).to_ascii_uppercase();
        stoplist.iter().any(|w| up == *w)
    };

    // 短锚点白名单（即使不满足长度/分隔符规则也保留）
    let short_whitelist: &[&[u8]] = &[b"sk_", b"rk_", b"ghu_", b"ghs_", b"xoxp-", b"xoxe-", b"xoxs-", b"xoxo-"];

    let mut v: Vec<Vec<u8>> = out
        .into_iter()
        .filter(|s| {
            if short_whitelist.iter().any(|w| *w == &s[..]) { return true; }
            if is_stop(s) { return false; }
            let len = s.len();
            if len >= 6 { return true; }
            if len >= 4 && has_sep(s) { return true; }
            // 兼容少数高价值短锚点（白名单-字符串）
            let ss = String::from_utf8_lossy(s);
            matches!(ss.as_ref(), "AIza" | "ya29.")
        })
        .collect();

    // 稳定排序（长度降序，字典序升序）
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
pub(crate) fn get_or_compile_meta_regex(plan: &PrefilterPlan, rule_idx: usize) -> Option<Arc<MetaRegex>> {
    if rule_idx >= plan.rule_patterns.len() { return None; }
    // 快路径：先查缓存
    if let Some(rx) = plan.cache.lock().unwrap().get(&rule_idx).cloned() {
        return Some(rx);
    }
    let pat = &plan.rule_patterns[rule_idx];
    match MetaRegex::new(pat) {
        Ok(rx) => {
            let rx = Arc::new(rx);
            plan.cache.lock().unwrap().insert(rule_idx, rx.clone());
            Some(rx)
        }
        Err(_) => None,
    }
}
