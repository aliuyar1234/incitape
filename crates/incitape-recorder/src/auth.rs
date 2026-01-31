use incitape_core::{AppError, AppResult};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct BearerToken {
    token: String,
}

impl BearerToken {
    pub async fn load(path: &Path) -> AppResult<Self> {
        let raw = tokio::fs::read_to_string(path).await.map_err(|e| {
            AppError::usage(format!("failed to read auth token {}: {e}", path.display()))
        })?;
        let token = raw.trim().to_string();
        if token.is_empty() {
            return Err(AppError::usage("auth token file is empty"));
        }
        Ok(Self { token })
    }

    pub fn verify(&self, value: &str) -> bool {
        let value = value.trim();
        let mut parts = value.splitn(2, ' ');
        let scheme = parts.next().unwrap_or("");
        let token = parts.next().unwrap_or("");
        if !scheme.eq_ignore_ascii_case("bearer") {
            return false;
        }
        token == self.token
    }
}
