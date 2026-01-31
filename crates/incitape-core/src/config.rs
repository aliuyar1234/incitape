use crate::error::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub recorder: RecorderConfig,
    pub ai: AiConfig,
}

impl Config {
    pub fn load(path: Option<&Path>) -> AppResult<Self> {
        let config = if let Some(path) = path {
            let data = std::fs::read_to_string(path).map_err(|e| {
                AppError::usage(format!("failed to read config {}: {e}", path.display()))
            })?;
            serde_yaml::from_str::<Config>(&data).map_err(|e| {
                AppError::usage(format!("failed to parse config {}: {e}", path.display()))
            })?
        } else {
            Config::default()
        };

        Ok(config)
    }

    pub fn validate_record(&self) -> AppResult<()> {
        self.recorder.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RecorderConfig {
    pub grpc_bind: String,
    pub http_bind: String,
    pub tls: TlsConfig,
    pub auth: AuthConfig,
}

impl Default for RecorderConfig {
    fn default() -> Self {
        Self {
            grpc_bind: "127.0.0.1:4317".to_string(),
            http_bind: "127.0.0.1:4318".to_string(),
            tls: TlsConfig::default(),
            auth: AuthConfig::default(),
        }
    }
}

impl RecorderConfig {
    pub fn validate(&self) -> AppResult<()> {
        let grpc = parse_bind("recorder.grpc_bind", &self.grpc_bind)?;
        let http = parse_bind("recorder.http_bind", &self.http_bind)?;
        let non_loopback = !grpc.ip().is_loopback() || !http.ip().is_loopback();

        if non_loopback {
            if !self.tls.enabled || self.tls.cert_path.is_none() || self.tls.key_path.is_none() {
                return Err(AppError::security(
                    "non-loopback bind requires tls.enabled=true with cert_path and key_path",
                ));
            }
            if !self.auth.enabled || self.auth.token_path.is_none() {
                return Err(AppError::security(
                    "non-loopback bind requires auth.enabled=true with token_path",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    pub enabled: bool,
    pub token_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AiConfig {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub timeout_secs: u64,
}

impl Default for AiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            timeout_secs: 30,
        }
    }
}

fn parse_bind(field: &str, value: &str) -> AppResult<SocketAddr> {
    SocketAddr::from_str(value)
        .map_err(|_| AppError::usage(format!("invalid {field} '{value}'; expected ip:port")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_loopback() {
        let config = Config::default();
        assert!(config.validate_record().is_ok());
    }

    #[test]
    fn non_loopback_requires_tls_and_auth() {
        let mut config = Config::default();
        config.recorder.grpc_bind = "0.0.0.0:4317".to_string();
        let err = config.validate_record().unwrap_err();
        assert_eq!(err.kind(), crate::error::ErrorKind::Security);
    }
}
