use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOutput {
    pub tape_id: String,
    pub ranking: Vec<RankingEntry>,
    pub determinism_hash: String,
    pub config_hash: String,
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
