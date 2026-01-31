use incitape_core::{AppError, AppResult};
use incitape_eval::{generate_suite, run_suite};
use std::path::{Path, PathBuf};

pub fn eval_generate(suite: &Path, out: &Path, overwrite: bool) -> AppResult<()> {
    if out.exists() && !out.is_dir() {
        return Err(AppError::validation("eval output path is not a directory"));
    }
    generate_suite(suite, out, overwrite)
}

pub fn eval_run(suite: &Path, out: Option<PathBuf>, overwrite: bool) -> AppResult<()> {
    let out_path = out.unwrap_or_else(|| PathBuf::from("eval_out").join("eval.json"));
    run_suite(suite, &out_path, overwrite)
}
