use crate::baselines::ServiceKey;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct EvalOutput {
    pub suite: SuiteSummary,
    pub metrics: BTreeMap<String, ModelMetrics>,
    pub scenarios: Vec<ScenarioResult>,
    pub determinism_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuiteSummary {
    pub name: String,
    pub tapes_dir: String,
    pub scenario_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelMetrics {
    pub top1_micros: u64,
    pub top3_micros: u64,
    pub mrr_micros: u64,
    pub time_to_rank_ms: u64,
    pub leakage_count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScenarioResult {
    pub id: String,
    pub tape_dir: String,
    pub tape_id: String,
    pub root_cause: GroundTruthRef,
    pub leakage_count: u64,
    pub models: BTreeMap<String, ModelScenarioResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GroundTruthRef {
    pub kind: String,
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModelScenarioResult {
    pub rank: Option<u32>,
    pub top_hit: Option<ServiceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub determinism_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServiceRef {
    pub name: String,
    pub namespace: String,
}

impl From<ServiceKey> for ServiceRef {
    fn from(value: ServiceKey) -> Self {
        Self {
            name: value.name,
            namespace: value.namespace,
        }
    }
}
