use incitape_core::{AppError, AppResult};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AiRequest {
    pub prompt: String,
    pub evidence_pack_json: String,
    pub deterministic: bool,
    pub seed: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct AiResponse {
    pub json: String,
}

pub trait AiProvider {
    fn generate_report(&self, request: &AiRequest) -> AppResult<AiResponse>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledAiProvider;

impl DisabledAiProvider {
    pub fn new() -> Self {
        Self
    }
}

impl AiProvider for DisabledAiProvider {
    fn generate_report(&self, _request: &AiRequest) -> AppResult<AiResponse> {
        Err(AppError::usage(
            "ai provider is disabled; enable it in config and pass --ai",
        ))
    }
}

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    endpoint: String,
    timeout: Duration,
    model: String,
}

impl OllamaProvider {
    pub fn new(endpoint: String, timeout: Duration) -> Self {
        Self {
            endpoint,
            timeout,
            model: "llama3".to_string(),
        }
    }

    fn endpoint_url(&self) -> String {
        if self.endpoint.contains("/api/") {
            self.endpoint.clone()
        } else {
            format!("{}/api/generate", self.endpoint.trim_end_matches('/'))
        }
    }
}

impl AiProvider for OllamaProvider {
    fn generate_report(&self, request: &AiRequest) -> AppResult<AiResponse> {
        let url = self.endpoint_url();
        let body = GenerateRequest {
            model: self.model.clone(),
            prompt: request.prompt.clone(),
            stream: false,
            options: if request.deterministic {
                Some(OllamaOptions {
                    temperature: 0.0,
                    top_p: 1.0,
                    seed: request.seed.unwrap_or(0),
                })
            } else {
                None
            },
        };
        let response = ureq::post(&url)
            .timeout(self.timeout)
            .send_json(body)
            .map_err(|e| AppError::internal(format!("ai request failed: {e}")))?;
        let value: serde_json::Value = response
            .into_json()
            .map_err(|e| AppError::internal(format!("ai response parse error: {e}")))?;
        let text = value
            .get("response")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::validation("ai response missing 'response'"))?;
        Ok(AiResponse {
            json: text.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
struct GenerateRequest {
    model: String,
    prompt: String,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    temperature: f32,
    top_p: f32,
    seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockMode {
    Valid,
    InvalidSchema,
    HallucinateIds,
    LeakSecret,
    WrongRootCause,
}

#[derive(Debug, Clone)]
pub struct MockProvider {
    mode: MockMode,
}

impl MockProvider {
    pub fn from_endpoint(endpoint: &str) -> Option<Self> {
        let mode = match endpoint {
            "mock://valid" => MockMode::Valid,
            "mock://invalid_schema" => MockMode::InvalidSchema,
            "mock://hallucinate_ids" => MockMode::HallucinateIds,
            "mock://leak_secret" => MockMode::LeakSecret,
            "mock://wrong_rootcause" => MockMode::WrongRootCause,
            _ => return None,
        };
        Some(Self { mode })
    }
}

impl AiProvider for MockProvider {
    fn generate_report(&self, request: &AiRequest) -> AppResult<AiResponse> {
        let pack_value: Value = serde_json::from_str(&request.evidence_pack_json)
            .map_err(|e| AppError::internal(format!("mock ai pack parse error: {e}")))?;
        let pack = MockPack::parse(&pack_value)?;

        let response = match self.mode {
            MockMode::InvalidSchema => json!({ "schema_version": "ai_report_v1" }),
            MockMode::HallucinateIds => pack.build_hallucinated(),
            MockMode::LeakSecret => pack.build_leaky(),
            MockMode::WrongRootCause => pack.build_wrong_rootcause(),
            MockMode::Valid => pack.build_valid(),
        };
        Ok(AiResponse {
            json: response.to_string(),
        })
    }
}

#[derive(Debug)]
struct MockPack {
    tape_id: String,
    analysis_sha256: String,
    suspects: Vec<MockSuspect>,
}

#[derive(Debug)]
struct MockSuspect {
    suspect_id: String,
    evidence_ids: Vec<String>,
    scores_ppm: MockScores,
}

#[derive(Debug)]
struct MockScores {
    total: u64,
    self_signal: u64,
    temporal_precedence: u64,
    downstream_impact: u64,
    centrality: u64,
}

impl MockPack {
    fn parse(value: &Value) -> AppResult<Self> {
        let tape_id = value
            .get("tape_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::internal("mock ai pack missing tape_id"))?
            .to_string();
        let analysis_sha256 = value
            .get("analysis_sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::internal("mock ai pack missing analysis_sha256"))?
            .to_string();
        let suspects_value = value
            .get("suspects")
            .and_then(|v| v.as_array())
            .ok_or_else(|| AppError::internal("mock ai pack missing suspects"))?;
        let mut suspects = Vec::new();
        for suspect in suspects_value {
            let suspect_id = suspect
                .get("suspect_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AppError::internal("mock ai pack missing suspect_id"))?
                .to_string();
            let evidence_ids = suspect
                .get("evidence_ids")
                .and_then(|v| v.as_array())
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let scores = suspect
                .get("scores_ppm")
                .and_then(|v| v.as_object())
                .ok_or_else(|| AppError::internal("mock ai pack missing scores_ppm"))?;
            let scores_ppm = MockScores {
                total: scores.get("total").and_then(|v| v.as_u64()).unwrap_or(0),
                self_signal: scores
                    .get("self_signal")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                temporal_precedence: scores
                    .get("temporal_precedence")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                downstream_impact: scores
                    .get("downstream_impact")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                centrality: scores
                    .get("centrality")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            };
            suspects.push(MockSuspect {
                suspect_id,
                evidence_ids,
                scores_ppm,
            });
        }
        Ok(Self {
            tape_id,
            analysis_sha256,
            suspects,
        })
    }

    fn build_valid(&self) -> Value {
        let top = self.suspects.first();
        let top_id = top
            .map(|s| s.suspect_id.clone())
            .unwrap_or_else(|| "svc:unknown".to_string());
        let evidence = top
            .and_then(|s| s.evidence_ids.first())
            .cloned()
            .unwrap_or_else(|| "EVID-0001".to_string());
        let scores = top.map(|s| &s.scores_ppm);
        let (total, self_signal, temporal, downstream, centrality) = match scores {
            Some(scores) => (
                scores.total,
                scores.self_signal,
                scores.temporal_precedence,
                scores.downstream_impact,
                scores.centrality,
            ),
            None => (0, 0, 0, 0, 0),
        };
        json!({
            "schema_version": "ai_report_v1",
            "tape_id": self.tape_id,
            "analysis_ref": {
                "analysis_sha256": self.analysis_sha256,
                "top_k": self.suspects.len()
            },
            "executive_summary": "Primary suspect identified from trace anomalies.",
            "root_cause": {
                "primary_suspect_id": top_id,
                "why": "Evidence aligns with earliest anomalous traces.",
                "score_summary": {
                    "total_score_ppm": total,
                    "breakdown_ppm": {
                        "self_signal": self_signal,
                        "temporal_precedence": temporal,
                        "downstream_impact": downstream,
                        "centrality": centrality
                    }
                }
            },
            "timeline": [{
                "t_start_ms": 0,
                "t_end_ms": 1000,
                "severity": "critical",
                "summary": "Anomalous span detected.",
                "suspect_ids": [top_id],
                "evidence_ids": [evidence]
            }],
            "impact": {
                "user_symptoms": ["elevated latency"],
                "services_affected": [top_id],
                "duration_ms_estimate": 1000,
                "slo_risk": "high"
            },
            "mitigation": {
                "immediate_checks": [{
                    "title": "Check recent deploys",
                    "details": "Review deploy history and error spikes.",
                    "linked_suspect_ids": [top_id],
                    "linked_evidence_ids": [evidence]
                }],
                "long_term_fixes": [{
                    "title": "Add latency guardrails",
                    "details": "Introduce circuit breakers and SLO alerts.",
                    "linked_suspect_ids": [top_id],
                    "linked_evidence_ids": [evidence]
                }]
            },
            "unknowns": [],
            "confidence": {
                "overall": 70,
                "level": "medium",
                "reasoning": ["limited trace volume"]
            },
            "citations": {
                "used_suspect_ids": [top_id],
                "used_evidence_ids": [evidence]
            }
        })
    }

    fn build_wrong_rootcause(&self) -> Value {
        let mut value = self.build_valid();
        if let Some(second) = self.suspects.get(1) {
            value["root_cause"]["primary_suspect_id"] = json!(second.suspect_id);
        } else {
            value["root_cause"]["primary_suspect_id"] = json!("svc:wrong");
        }
        value
    }

    fn build_hallucinated(&self) -> Value {
        let mut value = self.build_valid();
        value["root_cause"]["primary_suspect_id"] = json!("svc:hallucinated");
        value["timeline"][0]["evidence_ids"] = json!(["EVID-9999"]);
        value["citations"]["used_evidence_ids"] = json!(["EVID-9999"]);
        value
    }

    fn build_leaky(&self) -> Value {
        let mut value = self.build_valid();
        value["executive_summary"] = json!("Bearer abcdefghijklmnopqrstuvwxyz");
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_provider_fails() {
        let provider = DisabledAiProvider::new();
        let result = provider.generate_report(&AiRequest {
            prompt: "test".to_string(),
            evidence_pack_json: "{}".to_string(),
            deterministic: false,
            seed: None,
        });
        assert!(result.is_err());
    }
}
