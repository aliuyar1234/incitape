use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOutput {
    pub tape_id: String,
    pub ranking: Vec<RankingEntry>,
    #[serde(default)]
    pub window: AnalysisWindow,
    pub determinism_hash: String,
    pub config_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisWindow {
    pub t0_unix_nano: u64,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankingEntry {
    pub entity: EntityRef,
    pub score_micros: i64,
    pub self_signal: i64,
    pub temporal_precedence: i64,
    pub downstream_impact: i64,
    pub centrality: i64,
    pub evidence_refs: Vec<EvidenceRef>,
    #[serde(default)]
    pub features: RankingFeatures,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RankingFeatures {
    pub error_rate_delta_ppm: i64,
    pub latency_p95_delta_us: i64,
    pub throughput_delta_ppm: i64,
    pub first_anom_offset_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EntityRef {
    pub kind: String,
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EvidenceRef {
    TraceExemplar { trace_id: String, span_id: String },
}
