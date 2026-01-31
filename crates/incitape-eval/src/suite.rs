use incitape_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvalSuiteConfig {
    pub version: u32,
    pub name: String,
    pub tapes_dir: PathBuf,
    pub scenarios: Vec<ScenarioConfig>,
    pub thresholds: Thresholds,
}

impl EvalSuiteConfig {
    pub fn load(path: &Path) -> AppResult<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            AppError::usage(format!("failed to read suite {}: {e}", path.display()))
        })?;
        let suite: EvalSuiteConfig = serde_yaml::from_str(&content).map_err(|e| {
            AppError::usage(format!("failed to parse suite {}: {e}", path.display()))
        })?;
        suite.validate()?;
        Ok(suite)
    }

    pub fn validate(&self) -> AppResult<()> {
        if self.version != 1 {
            return Err(AppError::validation("unsupported suite version"));
        }
        if self.name.trim().is_empty() {
            return Err(AppError::validation("suite name is empty"));
        }
        if self.scenarios.is_empty() {
            return Err(AppError::validation("suite scenarios empty"));
        }
        self.thresholds.validate()?;
        let mut ids = std::collections::BTreeSet::new();
        for scenario in &self.scenarios {
            scenario.validate()?;
            if !ids.insert(scenario.id.clone()) {
                return Err(AppError::validation("duplicate scenario id"));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioConfig {
    pub id: String,
    pub seed: u64,
    pub services: u32,
    pub fanout: u32,
    pub traces: u32,
    pub fault: FaultConfig,
    #[serde(default)]
    pub inject_secret: bool,
}

impl ScenarioConfig {
    fn validate(&self) -> AppResult<()> {
        if self.id.trim().is_empty() {
            return Err(AppError::validation("scenario id is empty"));
        }
        if self.services < 2 {
            return Err(AppError::validation("scenario services must be >= 2"));
        }
        if self.fanout == 0 {
            return Err(AppError::validation("scenario fanout must be >= 1"));
        }
        if self.traces == 0 {
            return Err(AppError::validation("scenario traces must be >= 1"));
        }
        self.fault.validate(self.services)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FaultKind {
    Latency,
    Error,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FaultConfig {
    pub kind: FaultKind,
    pub target_index: u32,
    #[serde(default)]
    pub added_latency_ms: Option<u64>,
    #[serde(default)]
    pub rate_percent: Option<u32>,
}

impl FaultConfig {
    fn validate(&self, services: u32) -> AppResult<()> {
        if self.target_index >= services {
            return Err(AppError::validation("fault target_index out of range"));
        }
        let rate = self.rate_percent.unwrap_or(50);
        if rate > 100 {
            return Err(AppError::validation("fault rate_percent must be <= 100"));
        }
        if let FaultKind::Latency = self.kind {
            if self.added_latency_ms.unwrap_or(0) == 0 {
                return Err(AppError::validation(
                    "latency fault requires added_latency_ms > 0",
                ));
            }
        }
        Ok(())
    }

    pub fn rate_percent(&self) -> u32 {
        self.rate_percent.unwrap_or(50)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    pub top1_micros: u64,
    pub top3_micros: u64,
    pub mrr_micros: u64,
    #[serde(default = "default_leakage_zero")]
    pub leakage_zero: bool,
}

impl Thresholds {
    fn validate(&self) -> AppResult<()> {
        for (name, value) in [
            ("top1_micros", self.top1_micros),
            ("top3_micros", self.top3_micros),
            ("mrr_micros", self.mrr_micros),
        ] {
            if value > 1_000_000 {
                return Err(AppError::validation(format!("{name} must be <= 1_000_000")));
            }
        }
        Ok(())
    }
}

fn default_leakage_zero() -> bool {
    true
}
