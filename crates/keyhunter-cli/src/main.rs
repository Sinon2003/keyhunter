use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keyhunter_core::{scan_and_write, ScanEngine, ScanOptions};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use tracing::{error, info};

/// 命令行入口（基于 clap）
#[derive(Parser, Debug)]
#[command(name = "keyhunter", version, about = "DataCon 2025 密钥猎人")] 
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 扫描目录并生成 result.json
    Scan {
        /// 输入目录（数据集或样本目录）
        #[arg(long)]
        input: PathBuf,

        /// 输出文件（JSON 数组）
        #[arg(long, default_value = "./result.json")]
        output: PathBuf,

        /// 线程数（bytes 引擎启用并行；"auto"=CPU 核心数）
        #[arg(long, default_value = "auto")]
        threads: String,

        /// 最小打分阈值（demo 暂未使用）
        #[arg(long, default_value_t = 0.0)]
        min_score: f32,

        /// 最大扫描文件大小（单位字节，例如 5242880 代表 5MB）
        #[arg(long)]
        max_file_size: Option<u64>,

        /// 扫描引擎：bytes 或 utf8（默认 bytes）
        #[arg(long, default_value = "bytes", value_parser = ["bytes", "utf8"])]
        engine: String,

        /// 规则文件路径（TOML），默认 ./rules/default.toml
        #[arg(long)]
        rules: Option<PathBuf>,
    },
}

fn main() -> Result<()> {
    // 初始化日志（支持通过 RUST_LOG 控制等级，例如 info、debug）
    init_tracing();
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { input, output, threads, min_score, max_file_size, engine, rules } => {
            info!(?input, ?output, "starting scan");

            // 以缓冲方式打开输出文件，按 JSON 数组流式写入
            let mut out = BufWriter::new(File::create(&output).context("create output file")?);

            // 解析扫描引擎参数
            let engine = match engine.as_str() {
                "utf8" => ScanEngine::Utf8,
                _ => ScanEngine::Bytes,
            };
            // 解析线程参数："auto" 表示自动（等于 CPU 核数）；其他为具体数值
            let threads_opt = parse_threads(&threads);

            // 组装扫描参数（min_score 暂未使用，预留）
            let opts = ScanOptions { min_score, max_file_size, engine, rules_path: rules, threads: threads_opt };
            let stats = scan_and_write(&input, &mut out, &opts).context("scan and write failed")?;
            out.flush().ok();

            info!(files_scanned = stats.files_scanned, outputs_written = stats.outputs_written, "scan finished");
        }
    }

    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, FmtSubscriber};
    // 支持通过环境变量 RUST_LOG 控制日志等级，如：RUST_LOG=debug
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = FmtSubscriber::builder().with_env_filter(env_filter).finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// 解析线程参数
fn parse_threads(s: &str) -> Option<usize> {
    if s.eq_ignore_ascii_case("auto") { return None; }
    match s.parse::<usize>() {
        Ok(n) if n >= 1 => Some(n),
        _ => None,
    }
}
