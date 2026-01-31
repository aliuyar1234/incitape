use incitape_analyzer::{analyze_tape_dir, AnalyzerConfig};
use incitape_core::{AppError, AppResult};
use std::path::{Path, PathBuf};

pub fn analyze_command(
    tape_dir: &Path,
    out: Option<PathBuf>,
    top_k: u32,
    overwrite: bool,
) -> AppResult<()> {
    if !tape_dir.is_dir() {
        return Err(AppError::validation("tape_dir is not a directory"));
    }
    let out_path = out.unwrap_or_else(|| tape_dir.join("analysis.json"));
    if out_path.exists() && !overwrite {
        return Err(AppError::usage(
            "analysis.json already exists; use --overwrite to replace",
        ));
    }
    if out_path.exists() && out_path.is_dir() {
        return Err(AppError::validation("analysis output path is a directory"));
    }
    let config = AnalyzerConfig::new(top_k)?;
    analyze_tape_dir(tape_dir, config, &out_path)
}
