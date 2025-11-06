//! 扫描主流程与并行调度
use anyhow::Result;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use walkdir::WalkDir;

use crate::detectors::DetectorSetUtf8;
use crate::engine_bytes::{scan_file_bytes_prefilter, scan_file_bytes_chunked_prefilter, SMALL_FILE_MAX};
use crate::engine_utf8::scan_file_utf8;
use crate::findings::{sort_findings_stable, FindingPublic as Finding};
use crate::options::{ScanEngine, ScanOptions, ScanStats};
use crate::rules::load_rule_specs;
use crate::prefilter::{build_prefilter_plan, PrefilterPlan};

/// 扫描目录并将结果以 JSON 数组流式写入 `out`
/// 稳定性保证：
/// - 文件级：先收集文件并按文件名（md5）排序，确保输出顺序可复现
/// - 文件内：命中项按 (start_offset 升序, value 长度降序, value 字典序升序) 排序
pub fn scan_and_write(input_dir: &Path, out: &mut dyn Write, opts: &ScanOptions) -> Result<ScanStats> {
    // 加载规则文件（默认 ./rules/default.toml）
    let rules_path = opts
        .rules_path
        .clone()
        .unwrap_or_else(|| PathBuf::from("./rules/default.toml"));
    let rule_specs = load_rule_specs(&rules_path)?;
    // 引擎初始化：按需构建
    // - Bytes：构建预筛计划（AC + 懒编译缓存），避免启动期编译整套正则
    // - Utf8：仅编译 UTF-8 规则集合
    let (prefilter_plan, detectors_utf8): (Option<Arc<PrefilterPlan>>, Option<DetectorSetUtf8>) = match opts.engine {
        ScanEngine::Bytes => (Some(build_prefilter_plan(&rule_specs)), None),
        ScanEngine::Utf8 => (None, Some(DetectorSetUtf8::from_specs(&rule_specs)?)),
    };

    let mut stats = ScanStats::default();

    let mut files: Vec<PathBuf> = vec![];
    // 遍历输入目录（数据集为单层目录，这里限制深度为 1）
    for entry in WalkDir::new(input_dir).min_depth(1).max_depth(1) {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        if entry.file_type().is_file() { files.push(entry.into_path()); }
    }
    // 按文件名排序，确保输出顺序稳定
    files.sort_by(|a, b| a.file_name().cmp(&b.file_name()));

    // 决策：若为 Bytes 引擎且线程数>1，则走并行调度；否则使用串行扫描
    let threads = opts.threads.unwrap_or_else(|| num_cpus::get());
    let use_parallel = matches!(opts.engine, ScanEngine::Bytes) && threads > 1;

    if use_parallel {
        // Bytes 引擎并行路径：必有预筛计划
        let plan = prefilter_plan.as_ref().expect("prefilter plan not built");
        scan_and_write_parallel_bytes(&files, out, opts, plan, &mut stats, threads)?;
        return Ok(stats);
    }

    // 串行路径（保持原有逻辑，UTF-8 亦在此路径执行）
    write!(out, "[")?;
    let mut first = true;
    for path in files {
        let file_name = match path.file_name().and_then(|s| s.to_str()) { Some(s) => s, None => continue };
        if let Some(max) = opts.max_file_size { if let Ok(md) = std::fs::metadata(&path) { if md.len() > max { continue; } } }
        let res = match opts.engine {
            ScanEngine::Bytes => {
                let plan = prefilter_plan.as_ref().expect("prefilter plan not built");
                match std::fs::metadata(&path) {
                    Ok(md) => {
                        if md.len() <= SMALL_FILE_MAX as u64 {
                            scan_file_bytes_prefilter(&path, file_name, plan)
                        } else {
                            scan_file_bytes_chunked_prefilter(&path, file_name, plan)
                        }
                    }
                    Err(_) => Err(anyhow::anyhow!("metadata failed")),
                }
            }
            ScanEngine::Utf8 => {
                let det = detectors_utf8.as_ref().expect("utf8 detectors not built");
                scan_file_utf8(&path, file_name, det)
            }
        };
        match res {
            Ok(mut findings) => {
                stats.files_scanned += 1;
                // 文件内稳定排序
                sort_findings_stable(&mut findings);
                for f in findings.iter() {
                    stats.outputs_written += 1;
                    if !first { write!(out, ",")?; } else { first = false; }
                    let item = serde_json::json!({ "file_hash": f.file_hash, "value": f.value });
                    serde_json::to_writer(&mut *out, &item)?;
                }
            }
            Err(_) => continue,
        }
    }
    write!(out, "]")?;
    Ok(stats)
}

/// 并行调度（Bytes 引擎）：
/// - 建索引后使用 Rayon 线程池并行扫描
/// - 单线程 Writer 按 idx 重排并流式写 JSON，保证稳定顺序
fn scan_and_write_parallel_bytes(
    files: &[PathBuf],
    out: &mut dyn Write,
    opts: &ScanOptions,
    plan: &Arc<PrefilterPlan>,
    stats: &mut ScanStats,
    threads: usize,
) -> Result<()> {
    use crossbeam_channel as channel;
    use rayon::prelude::*;

    // 写 JSON 开始符
    write!(out, "[")?;
    let mut first = true;

    // 通道用于 worker → writer 传递结果
    type Msg = (usize /*idx*/, Vec<Finding> /*findings*/, bool /*scanned*/);
    let (tx, rx) = channel::bounded::<Msg>(256);

    // 为防止 &mut out 的跨线程所有权问题，Writer 保持在当前线程
    // 扫描在后台线程内创建 Rayon 线程池并执行
    let plan = Arc::clone(plan);
    let max_file_size = opts.max_file_size;

    let files_vec: Vec<(usize, PathBuf)> = files
        .iter()
        .enumerate()
        .map(|(i, p)| (i, p.clone()))
        .collect();

    let scan_thread = std::thread::spawn(move || {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("build rayon pool");
        pool.install(|| {
            files_vec.par_iter().for_each(|(idx, path)| {
                // 路径与文件名
                let file_name = match path.file_name().and_then(|s| s.to_str()) { Some(s) => s.to_string(), None => { let _ = tx.send((*idx, Vec::new(), false)); return; } };
                // 大小过滤（与串行一致）
                if let Some(max) = max_file_size { if let Ok(md) = std::fs::metadata(path) { if md.len() > max { let _ = tx.send((*idx, Vec::new(), false)); return; } } }

                // 选择读取策略：小文件整读，超大文件分块
                let findings_res = match std::fs::metadata(path) {
                    Ok(md) => {
                        let sz = md.len();
                        if sz <= SMALL_FILE_MAX as u64 {
                            crate::engine_bytes::scan_file_bytes_prefilter(path, &file_name, &plan)
                        } else {
                            crate::engine_bytes::scan_file_bytes_chunked_prefilter(path, &file_name, &plan)
                        }
                    }
                    Err(_) => Err(anyhow::anyhow!("metadata failed")),
                };

                match findings_res {
                    Ok(mut findings) => {
                        // 稳定排序可在 writer 进行；此处也可预排序以降低主线程负担
                        sort_findings_stable(&mut findings);
                        let _ = tx.send((*idx, findings, true));
                    }
                    Err(_) => { let _ = tx.send((*idx, Vec::new(), false)); }
                }
            });
        });
        // 结束后 Sender 全部被丢弃，Receiver 将收到关闭信号
    });

    // Writer：维护 next_idx 与缓存，按序输出
    use std::collections::BTreeMap;
    let mut next_idx: usize = 0;
    let mut buffer: BTreeMap<usize, (Vec<Finding>, bool)> = BTreeMap::new();

    while let Ok((idx, findings, scanned)) = rx.recv() {
        buffer.insert(idx, (findings, scanned));
        // 尝试从 next_idx 开始顺序冲刷
        while let Some((mut findings, scanned)) = buffer.remove(&next_idx).map(|v| v) {
            if scanned { stats.files_scanned += 1; }
            // 文件内稳定排序已在 worker 执行；此处再保证一次
            sort_findings_stable(&mut findings);
            for f in findings.iter() {
                stats.outputs_written += 1;
                if !first { write!(out, ",")?; } else { first = false; }
                let item = serde_json::json!({ "file_hash": f.file_hash, "value": f.value });
                serde_json::to_writer(&mut *out, &item)?;
            }
            next_idx += 1;
        }
    }

    // 等待扫描线程结束
    let _ = scan_thread.join();

    // 最终冲刷残余（理论上缓冲应已清空）
    while let Some((mut findings, scanned)) = buffer.remove(&next_idx) {
        if scanned { stats.files_scanned += 1; }
        sort_findings_stable(&mut findings);
        for f in findings.iter() {
            stats.outputs_written += 1;
            if !first { write!(out, ",")?; } else { first = false; }
            let item = serde_json::json!({ "file_hash": f.file_hash, "value": f.value });
            serde_json::to_writer(&mut *out, &item)?;
        }
        next_idx += 1;
    }

    // 写 JSON 结束符
    write!(out, "]")?;
    Ok(())
}
