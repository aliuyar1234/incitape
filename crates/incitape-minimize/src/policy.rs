use incitape_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MinimizePolicy {
    pub top_k: u32,
    pub keep_window_secs: u32,
    pub drop_logs_metrics: bool,
}

impl MinimizePolicy {
    pub fn new(top_k: u32, keep_window_secs: u32, drop_logs_metrics: bool) -> AppResult<Self> {
        let policy = Self {
            top_k,
            keep_window_secs,
            drop_logs_metrics,
        };
        policy.validate()?;
        Ok(policy)
    }

    pub fn load(path: &Path) -> AppResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AppError::usage(format!("failed to read policy {}: {e}", path.display()))
        })?;
        let policy: MinimizePolicy = serde_yaml::from_str(&content).map_err(|e| {
            AppError::usage(format!("failed to parse policy {}: {e}", path.display()))
        })?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.top_k == 0 {
            return Err(AppError::usage("top_k must be > 0"));
        }
        Ok(())
    }
}
