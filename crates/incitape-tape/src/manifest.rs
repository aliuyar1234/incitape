use incitape_core::{AppError, AppResult};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub tape_version: u16,
    pub tape_id: String,
    pub capture: Capture,
    pub redaction: Redaction,
    pub ground_truth: Option<GroundTruth>,
    #[serde(default)]
    pub derived_from: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capture {
    pub started_at_rfc3339: String,
    pub ended_at_rfc3339: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Redaction {
    pub profile: String,
    pub ruleset_sha256: String,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub root_cause: GroundTruthTarget,
    pub faults: Vec<Fault>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruthTarget {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fault {
    pub at_capture_time_unix_nano: u64,
    pub kind: String,
    pub target: GroundTruthTarget,
    pub params: FaultParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaultParams {
    pub added_latency_ms: Option<u64>,
}

impl Manifest {
    pub fn load(path: &Path) -> AppResult<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| AppError::validation(format!("failed to read manifest: {e}")))?;
        serde_yaml::from_str(&content)
            .map_err(|e| AppError::validation(format!("manifest parse error: {e}")))
    }

    pub fn write(&self, path: &Path) -> AppResult<()> {
        let content = serde_yaml::to_string(self)
            .map_err(|e| AppError::internal(format!("manifest encode error: {e}")))?;
        fs::write(path, content)
            .map_err(|e| AppError::internal(format!("manifest write error: {e}")))
    }

    pub fn validate(&self, expected_tape_id: &str) -> AppResult<()> {
        if self.tape_version != 1 {
            return Err(AppError::validation("unsupported tape_version"));
        }
        if !is_lower_hex_64(&self.tape_id) {
            return Err(AppError::validation("invalid manifest tape_id"));
        }
        if self.tape_id != expected_tape_id {
            return Err(AppError::validation("manifest tape_id mismatch"));
        }
        if !is_lower_hex_64(&self.redaction.ruleset_sha256) {
            return Err(AppError::validation("invalid redaction ruleset_sha256"));
        }
        if let Some(source) = &self.derived_from {
            if !is_lower_hex_64(source) {
                return Err(AppError::validation("invalid derived_from tape_id"));
            }
        }
        if let Some(gt) = &self.ground_truth {
            if gt.faults.is_empty() {
                return Err(AppError::validation("ground_truth faults empty"));
            }
        }
        Ok(())
    }
}

fn is_lower_hex_64(value: &str) -> bool {
    if value.len() != 64 {
        return false;
    }
    value.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_tape_id() {
        let manifest = Manifest {
            tape_version: 1,
            tape_id: "bad".to_string(),
            capture: Capture {
                started_at_rfc3339: "2025-01-01T00:00:00Z".to_string(),
                ended_at_rfc3339: "2025-01-01T00:00:01Z".to_string(),
                source: "otlp_receiver".to_string(),
            },
            redaction: Redaction {
                profile: "safe_default".to_string(),
                ruleset_sha256: "0".repeat(64),
                applied: true,
            },
            ground_truth: None,
            derived_from: None,
        };
        assert!(manifest.validate(&"0".repeat(64)).is_err());
    }
}
