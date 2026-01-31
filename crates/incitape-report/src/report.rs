use crate::ai::{AiProvider, AiRequest};
use incitape_analyzer::{AnalysisOutput, EvidenceRef};
use incitape_core::{AppError, AppResult};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

const MAX_EVIDENCE_BYTES: usize = 8_000;
const MAX_FIELD_CHARS: usize = 256;
const MAX_SUSPECTS: usize = 5;
const MAX_EVIDENCE_REFS: usize = 3;

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub ai_enabled: bool,
    pub ai_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiReport {
    pub summary: String,
    pub suspects: Vec<AiSuspect>,
    pub checks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiSuspect {
    pub name: String,
    pub namespace: String,
    pub reason: String,
}

pub fn render_report(analysis: &AnalysisOutput, ai_section: Option<&AiReport>) -> String {
    let mut out = String::new();
    out.push_str("# IncidentTape Report\n\n");
    out.push_str(&format!("- tape_id: `{}`\n\n", analysis.tape_id));

    out.push_str("## Top Suspects\n\n");
    for (idx, entry) in analysis.ranking.iter().enumerate() {
        out.push_str(&format!(
            "{}. **{}** (score_micros: {})\n",
            idx + 1,
            service_label(&entry.entity.name, &entry.entity.namespace),
            entry.score_micros
        ));
        out.push_str(&format!(
            "   - self_signal: {}\n   - temporal_precedence: {}\n   - downstream_impact: {}\n   - centrality: {}\n",
            entry.self_signal, entry.temporal_precedence, entry.downstream_impact, entry.centrality
        ));
        for evidence in &entry.evidence_refs {
            out.push_str(&format!("   - evidence: {}\n", format_evidence(evidence)));
        }
        out.push('\n');
    }

    out.push_str("## Recommended Checks\n\n");
    for check in recommended_checks(&analysis.ranking) {
        out.push_str(&format!("- {check}\n"));
    }

    if let Some(ai) = ai_section {
        out.push_str("\n## AI Summary (Optional)\n\n");
        out.push_str(&format!("{}\n\n", ai.summary.trim()));
        if !ai.suspects.is_empty() {
            out.push_str("### AI Suspects\n\n");
            for suspect in &ai.suspects {
                out.push_str(&format!(
                    "- {}: {}\n",
                    service_label(&suspect.name, &suspect.namespace),
                    suspect.reason.trim()
                ));
            }
        }
        if !ai.checks.is_empty() {
            out.push_str("\n### AI Suggested Checks\n\n");
            for check in &ai.checks {
                out.push_str(&format!("- {}\n", check.trim()));
            }
        }
    }

    out
}

pub fn build_evidence_pack(analysis: &AnalysisOutput) -> AppResult<String> {
    let mut suspects = Vec::new();
    for entry in analysis.ranking.iter().take(MAX_SUSPECTS) {
        let mut evidence_refs = Vec::new();
        for evidence in entry.evidence_refs.iter().take(MAX_EVIDENCE_REFS) {
            evidence_refs.push(format_evidence(evidence));
        }
        suspects.push(EvidenceSuspect {
            name: sanitize_str(&entry.entity.name),
            namespace: sanitize_str(&entry.entity.namespace),
            score_micros: entry.score_micros,
            evidence_refs,
        });
    }

    let pack = EvidencePack {
        tape_id: sanitize_str(&analysis.tape_id),
        suspects,
    };
    let mut text = serde_json::to_string(&pack)
        .map_err(|e| AppError::internal(format!("evidence pack encode error: {e}")))?;
    text = strip_code_blocks(&text);
    text = strip_urls(&text);
    text = normalize_whitespace(&text);

    if text.len() > MAX_EVIDENCE_BYTES {
        text.truncate(MAX_EVIDENCE_BYTES);
    }
    Ok(text)
}

pub fn generate_ai_section(
    provider: &dyn AiProvider,
    evidence_pack: &str,
) -> AppResult<Option<AiReport>> {
    let schema = include_str!("../schema/ai_report.schema.json");
    let prompt = format!(
        "You are an incident RCA assistant. Return ONLY valid JSON that matches this schema:\\n{schema}\\n\\nEvidence pack (sanitized):\\n{evidence_pack}"
    );
    let response = match provider.generate_report(&AiRequest {
        evidence_pack: prompt,
    }) {
        Ok(resp) => resp,
        Err(_) => return Ok(None),
    };
    match validate_ai_response(&response.json, schema) {
        Ok(report) => Ok(Some(report)),
        Err(_) => Ok(None),
    }
}

fn validate_ai_response(json: &str, schema: &str) -> AppResult<AiReport> {
    let schema_json: Value = serde_json::from_str(schema)
        .map_err(|e| AppError::internal(format!("ai schema parse error: {e}")))?;
    let response_json: Value = serde_json::from_str(json)
        .map_err(|e| AppError::validation(format!("ai response json error: {e}")))?;
    let compiled = jsonschema::JSONSchema::compile(&schema_json)
        .map_err(|e| AppError::internal(format!("ai schema compile error: {e}")))?;
    if compiled.is_valid(&response_json) {
        serde_json::from_value(response_json)
            .map_err(|e| AppError::validation(format!("ai response decode error: {e}")))
    } else {
        Err(AppError::validation("ai response schema validation failed"))
    }
}

fn recommended_checks(ranking: &[incitape_analyzer::RankingEntry]) -> Vec<String> {
    let mut checks = Vec::new();
    for entry in ranking.iter().take(3) {
        checks.push(format!(
            "Inspect {} error logs and recent deploys around suspect window.",
            service_label(&entry.entity.name, &entry.entity.namespace)
        ));
        checks.push(format!(
            "Verify downstream dependencies of {} for cascading failures.",
            service_label(&entry.entity.name, &entry.entity.namespace)
        ));
    }
    checks
}

fn format_evidence(evidence: &EvidenceRef) -> String {
    match evidence {
        EvidenceRef::TraceExemplar { trace_id, span_id } => {
            format!("trace_exemplar(trace_id={}, span_id={})", trace_id, span_id)
        }
    }
}

fn service_label(name: &str, namespace: &str) -> String {
    if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}/{name}")
    }
}

fn sanitize_str(value: &str) -> String {
    let mut out = strip_code_blocks(value);
    out = strip_urls(&out);
    out = out.replace("http://", "").replace("https://", "");
    out = normalize_whitespace(&out);
    if out.chars().count() > MAX_FIELD_CHARS {
        out = out.chars().take(MAX_FIELD_CHARS).collect();
    }
    out
}

fn strip_code_blocks(input: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    let mut i = 0;
    let bytes = input.as_bytes();
    while i < bytes.len() {
        if i + 2 < bytes.len() && bytes[i] == b'`' && bytes[i + 1] == b'`' && bytes[i + 2] == b'`' {
            in_block = !in_block;
            i += 3;
            continue;
        }
        if !in_block {
            out.push(bytes[i] as char);
        }
        i += 1;
    }
    out
}

fn strip_urls(input: &str) -> String {
    let re = Regex::new(r"https?:\\\\/\\\\/\\S+|https?://\\S+").unwrap();
    re.replace_all(input, "[redacted-url]").to_string()
}

fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, Serialize)]
struct EvidencePack {
    tape_id: String,
    suspects: Vec<EvidenceSuspect>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceSuspect {
    name: String,
    namespace: String,
    score_micros: i64,
    evidence_refs: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::AiResponse;
    use incitape_analyzer::{AnalysisOutput, RankingEntry};

    fn sample_analysis() -> AnalysisOutput {
        AnalysisOutput {
            tape_id: "0".repeat(64),
            ranking: vec![RankingEntry {
                entity: incitape_analyzer::model::EntityRef {
                    kind: "service".to_string(),
                    name: "svc-1".to_string(),
                    namespace: String::new(),
                },
                score_micros: 100,
                self_signal: 80,
                temporal_precedence: 10,
                downstream_impact: 5,
                centrality: 5,
                evidence_refs: vec![EvidenceRef::TraceExemplar {
                    trace_id: "abcd".to_string(),
                    span_id: "1234".to_string(),
                }],
            }],
            determinism_hash: String::new(),
            config_hash: String::new(),
        }
    }

    fn analysis_with_name(name: &str) -> AnalysisOutput {
        let mut analysis = sample_analysis();
        analysis.ranking[0].entity.name = name.to_string();
        analysis
    }

    struct StaticProvider {
        json: String,
    }

    impl AiProvider for StaticProvider {
        fn generate_report(&self, _request: &AiRequest) -> AppResult<AiResponse> {
            Ok(AiResponse {
                json: self.json.clone(),
            })
        }
    }

    #[test]
    fn evidence_pack_strips_urls_and_code_blocks() {
        let mut analysis = sample_analysis();
        analysis.ranking[0].entity.name = "svc-1```ignore```https://example.com".to_string();
        let pack = build_evidence_pack(&analysis).unwrap();
        assert!(!pack.contains("https://"));
        assert!(!pack.contains("```"));
    }

    #[test]
    fn evidence_pack_sanitizes_prompt_injection() {
        let injection = format!(
            "svc-1```ignore```http://evil.example {}",
            "A".repeat(MAX_FIELD_CHARS * 4)
        );
        let analysis = analysis_with_name(&injection);
        let pack = build_evidence_pack(&analysis).unwrap();
        assert!(!pack.contains("http://"));
        assert!(!pack.contains("https://"));
        assert!(!pack.contains("```"));
        assert!(pack.len() <= MAX_EVIDENCE_BYTES);
    }

    #[test]
    fn ai_section_accepts_schema_valid_json() {
        let schema = include_str!("../schema/ai_report.schema.json");
        let json = r#"{"summary":"ok","suspects":[{"name":"svc","namespace":"","reason":"because"}],"checks":["check"]}"#;
        let report = validate_ai_response(json, schema)
            .unwrap_or_else(|err| panic!("schema validation failed: {}", err.message()));
        assert_eq!(report.summary, "ok");
        let provider = StaticProvider {
            json: json.to_string(),
        };
        let section = generate_ai_section(&provider, "evidence").unwrap();
        assert!(section.is_some());
    }

    #[test]
    fn ai_section_rejects_invalid_schema() {
        let provider = StaticProvider {
            json: r#"{"summary":"missing checks"}"#.to_string(),
        };
        let section = generate_ai_section(&provider, "evidence").unwrap();
        assert!(section.is_none());
    }
}
