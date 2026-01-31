use clap::{Parser, Subcommand};
use incitape_core::config::Config;
use incitape_core::{AppError, AppResult};
use incitape_recorder::{record, RecorderSettings, DEFAULT_REQUEST_TIMEOUT_SECS};
use incitape_replay::{
    replay_tape_dir, ReplayConfig, ReplayFilter, ReplaySpeed, DEFAULT_CONNECT_TIMEOUT_SECS,
    DEFAULT_RPC_TIMEOUT_SECS,
};
use incitape_tape::bounds::Bounds;
use std::path::PathBuf;
use std::process;
use std::time::Duration;

mod analyze;
mod eval;
mod minimize;
mod report;
mod validate;

#[derive(Parser)]
#[command(name = "incitape")]
#[command(
    about = "Incidents as replayable telemetry tapes + deterministic RCA + regression gates."
)]
struct Cli {
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[arg(long, value_name = "LEVEL", default_value = "info")]
    log_level: String,

    #[arg(long, value_name = "FORMAT", default_value = "text")]
    log_format: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Record {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        #[arg(long, value_name = "SECS")]
        duration: Option<u64>,
        #[arg(long, value_name = "BYTES")]
        max_tape_bytes: Option<u64>,
    },
    Replay {
        #[arg(value_name = "TAPE_DIR")]
        tape_dir: PathBuf,
        #[arg(long, value_name = "OTLP_GRPC_URL")]
        to: String,
        #[arg(long, value_name = "SPEED", default_value = "1x")]
        speed: String,
        #[arg(long, value_name = "FILTER")]
        filter: Option<String>,
    },
    Analyze {
        #[arg(value_name = "TAPE_DIR")]
        tape_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        #[arg(long, value_name = "N", default_value_t = 5)]
        top_k: u32,
        #[arg(long)]
        overwrite: bool,
    },
    Report {
        #[arg(value_name = "TAPE_DIR")]
        tape_dir: PathBuf,
        #[arg(long, value_name = "PATH")]
        analysis: Option<PathBuf>,
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        #[arg(long)]
        ai: bool,
        #[arg(long)]
        ai_strict: bool,
        #[arg(long)]
        ai_deterministic: bool,
        #[arg(long)]
        overwrite: bool,
    },
    Eval {
        #[command(subcommand)]
        command: EvalCommands,
    },
    Validate {
        #[arg(value_name = "TAPE_DIR")]
        tape_dir: PathBuf,
        #[arg(long)]
        strict: bool,
    },
    Minimize {
        #[arg(value_name = "TAPE_DIR")]
        tape_dir: PathBuf,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        #[arg(long, value_name = "PATH")]
        policy: Option<PathBuf>,
        #[arg(long, value_name = "N", default_value_t = 3)]
        top_k: u32,
        #[arg(long, value_name = "SECS", default_value_t = 120)]
        keep_window_secs: u32,
        #[arg(long, default_value_t = true)]
        drop_logs_metrics: bool,
        #[arg(long)]
        overwrite: bool,
    },
}

#[derive(Subcommand)]
enum EvalCommands {
    Generate {
        #[arg(long, value_name = "PATH")]
        suite: PathBuf,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        #[arg(long)]
        overwrite: bool,
    },
    Run {
        #[arg(long, value_name = "PATH")]
        suite: PathBuf,
        #[arg(long, value_name = "PATH")]
        out: Option<PathBuf>,
        #[arg(long)]
        overwrite: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli).await {
        eprintln!("{}", err.message());
        process::exit(err.exit_code());
    }
}

async fn run(cli: Cli) -> AppResult<()> {
    validate_log_level(&cli.log_level)?;
    validate_log_format(&cli.log_format)?;

    let config = Config::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Record {
            out,
            duration,
            max_tape_bytes,
        } => {
            config.validate_record()?;
            let mut bounds = Bounds::default();
            if let Some(max_bytes) = max_tape_bytes {
                if max_bytes == 0 {
                    return Err(AppError::usage("--max-tape-bytes must be > 0"));
                }
                bounds.max_tape_file_bytes = max_bytes;
            }
            let settings = RecorderSettings::from_config(
                &config.recorder,
                bounds,
                Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            )
            .await?;
            let duration = duration.map(Duration::from_secs);
            record(settings, out, duration).await
        }
        Commands::Replay {
            tape_dir,
            to,
            speed,
            filter,
        } => {
            let speed = ReplaySpeed::parse(&speed)?;
            let filter = match filter {
                Some(value) => Some(ReplayFilter::parse(&value)?),
                None => None,
            };
            let config = ReplayConfig {
                endpoint: to,
                speed,
                filter,
                connect_timeout: Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
                rpc_timeout: Duration::from_secs(DEFAULT_RPC_TIMEOUT_SECS),
            };
            replay_tape_dir(&tape_dir, config).await
        }
        Commands::Analyze {
            tape_dir,
            out,
            top_k,
            overwrite,
        } => analyze::analyze_command(&tape_dir, out, top_k, overwrite),
        Commands::Report {
            tape_dir,
            analysis,
            out,
            ai,
            ai_strict,
            ai_deterministic,
            overwrite,
        } => report::report_command(
            &tape_dir,
            analysis,
            out,
            ai,
            ai_strict,
            ai_deterministic,
            overwrite,
            &config,
        ),
        Commands::Eval { command } => match command {
            EvalCommands::Generate {
                suite,
                out,
                overwrite,
            } => eval::eval_generate(&suite, &out, overwrite),
            EvalCommands::Run {
                suite,
                out,
                overwrite,
            } => eval::eval_run(&suite, out, overwrite),
        },
        Commands::Validate { tape_dir, strict } => {
            validate::validate_tape_dir(&tape_dir, strict)?;
            Ok(())
        }
        Commands::Minimize {
            tape_dir,
            out,
            policy,
            top_k,
            keep_window_secs,
            drop_logs_metrics,
            overwrite,
        } => minimize::minimize_command(
            &tape_dir,
            &out,
            policy,
            top_k,
            keep_window_secs,
            drop_logs_metrics,
            overwrite,
        ),
    }
}

fn validate_log_level(value: &str) -> AppResult<()> {
    match value {
        "error" | "warn" | "info" | "debug" | "trace" => Ok(()),
        _ => Err(AppError::usage(format!(
            "invalid --log-level '{value}'; expected error|warn|info|debug|trace"
        ))),
    }
}

fn validate_log_format(value: &str) -> AppResult<()> {
    match value {
        "text" | "json" => Ok(()),
        _ => Err(AppError::usage(format!(
            "invalid --log-format '{value}'; expected text|json"
        ))),
    }
}
