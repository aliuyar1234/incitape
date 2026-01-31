use incitape_core::AppResult;
use incitape_minimize::{minimize_tape_dir, MinimizePolicy};
use std::path::{Path, PathBuf};

pub fn minimize_command(
    tape_dir: &Path,
    out: &Path,
    policy_path: Option<PathBuf>,
    top_k: u32,
    keep_window_secs: u32,
    drop_logs_metrics: bool,
    overwrite: bool,
) -> AppResult<()> {
    let policy = match policy_path {
        Some(path) => MinimizePolicy::load(&path)?,
        None => MinimizePolicy::new(top_k, keep_window_secs, drop_logs_metrics)?,
    };
    minimize_tape_dir(tape_dir, out, policy, overwrite)
}
