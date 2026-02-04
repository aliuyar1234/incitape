use crate::ai::AiProvider;
use crate::ai::AiRequest;
use incitape_analyzer::{AnalysisOutput, EvidenceRef, RankingEntry, ScoreWeights};
use incitape_core::{AppError, AppResult};
use incitape_redaction::{scan_json_value, LeakageScanner, RedactionEngine, RedactionRuleset};
use incitape_tape::bounds::Bounds;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::RecordType;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

const AI_SCHEMA_VERSION: &str = "ai_report_v1";
const EVIDENCE_PACK_VERSION: &str = "evidence_pack_v1";

const MAX_EVIDENCE_PACK_BYTES: usize = 98_304;
const MAX_AI_JSON_BYTES: usize = 32_768;
const MAX_REPORT_MD_BYTES: usize = 131_072;

const MAX_SUSPECTS: usize = 5;
const MAX_EVIDENCE_PER_SUSPECT: usize = 5;
const MAX_TOTAL_EVIDENCE: usize = 25;

const MAX_NAME_CHARS: usize = 96;
const MAX_SUMMARY_CHARS: usize = 512;
const MAX_DETAIL_CHARS: usize = 512;
const MAX_EXEC_SUMMARY_CHARS: usize = 600;

const LEAKAGE_SKIP_KEYS: [&str; 6] = [
    "tape_id",
    "analysis_sha256",
    "determinism_hash",
    "config_hash",
    "trace_id",
    "span_id",
];

const AI_CONSTRAINTS: [&str; 4] = [
    "LLM MUST output JSON only matching the schema.",
    "LLM MUST NOT change root cause; primary_suspect_id must equal suspects[0].suspect_id.",
    "LLM MAY ONLY reference suspect_ids and evidence_ids present in the evidence pack.",
    "LLM MUST suggest checks only; no actions or tools.",
];

const ATTR_ALLOWLIST: [&str; 7] = [
    "http.method",
    "http.route",
    "rpc.system",
    "rpc.service",
    "rpc.method",
    "db.system",
    "db.operation",
];

#[derive(Debug, Clone)]
pub struct ReportConfig {
    pub ai_enabled: bool,
    pub ai_timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiReport {
    pub schema_version: String,
    pub tape_id: String,
    pub analysis_ref: AiAnalysisRef,
    pub executive_summary: String,
    pub root_cause: AiRootCause,
    pub timeline: Vec<AiTimelineEvent>,
    pub impact: AiImpact,
    pub mitigation: AiMitigation,
    pub unknowns: Vec<AiUnknown>,
    pub confidence: AiConfidence,
    pub citations: AiCitations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisRef {
    pub analysis_sha256: String,
    pub top_k: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRootCause {
    pub primary_suspect_id: String,
    pub why: String,
    pub score_summary: AiScoreSummary,
    #[serde(default)]
    pub alternatives: Vec<AiAlternative>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScoreSummary {
    pub total_score_ppm: u64,
    pub breakdown_ppm: AiScoreBreakdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiScoreBreakdown {
    pub self_signal: u64,
    pub temporal_precedence: u64,
    pub downstream_impact: u64,
    pub centrality: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAlternative {
    pub suspect_id: String,
    pub why: String,
    pub what_would_change_mind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTimelineEvent {
    pub t_start_ms: u64,
    pub t_end_ms: u64,
    pub severity: String,
    pub summary: String,
    pub suspect_ids: Vec<String>,
    pub evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiImpact {
    pub user_symptoms: Vec<String>,
    pub services_affected: Vec<String>,
    pub duration_ms_estimate: u64,
    pub slo_risk: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiMitigation {
    pub immediate_checks: Vec<AiMitigationItem>,
    pub long_term_fixes: Vec<AiMitigationItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiMitigationItem {
    pub title: String,
    pub details: String,
    pub linked_suspect_ids: Vec<String>,
    pub linked_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiUnknown {
    pub question: String,
    pub why_it_matters: String,
    pub data_needed: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfidence {
    pub overall: u64,
    pub level: String,
    pub reasoning: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiCitations {
    pub used_suspect_ids: Vec<String>,
    pub used_evidence_ids: Vec<String>,
}

pub fn render_report(
    analysis: &AnalysisOutput,
    ai_section: Option<&AiReport>,
    ai_fallback_used: bool,
) -> String {
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
        out.push_str(&format!(
            "{}\n\n",
            render_safe_text(&ai.executive_summary, MAX_EXEC_SUMMARY_CHARS)
        ));
        out.push_str("### Root Cause\n\n");
        out.push_str(&format!(
            "- primary_suspect_id: `{}`\n",
            render_safe_text(&ai.root_cause.primary_suspect_id, MAX_NAME_CHARS)
        ));
        out.push_str(&format!(
            "- why: {}\n",
            render_safe_text(&ai.root_cause.why, MAX_SUMMARY_CHARS)
        ));
        out.push_str(&format!(
            "- score_summary.total_score_ppm: {}\n",
            ai.root_cause.score_summary.total_score_ppm
        ));
        out.push_str(&format!(
            "  - self_signal: {}\n  - temporal_precedence: {}\n  - downstream_impact: {}\n  - centrality: {}\n\n",
            ai.root_cause.score_summary.breakdown_ppm.self_signal,
            ai.root_cause.score_summary.breakdown_ppm.temporal_precedence,
            ai.root_cause.score_summary.breakdown_ppm.downstream_impact,
            ai.root_cause.score_summary.breakdown_ppm.centrality
        ));

        if !ai.root_cause.alternatives.is_empty() {
            out.push_str("### Alternative Hypotheses\n\n");
            for alt in &ai.root_cause.alternatives {
                out.push_str(&format!(
                    "- {}: {}\n",
                    render_safe_text(&alt.suspect_id, MAX_NAME_CHARS),
                    render_safe_text(&alt.why, MAX_SUMMARY_CHARS)
                ));
                out.push_str(&format!(
                    "  - what_would_change_mind: {}\n",
                    render_safe_text(&alt.what_would_change_mind, MAX_SUMMARY_CHARS)
                ));
            }
            out.push('\n');
        }

        out.push_str("### Timeline\n\n");
        for event in &ai.timeline {
            out.push_str(&format!(
                "- [{}] {} ({}ms - {}ms)\n",
                render_safe_text(&event.severity, MAX_NAME_CHARS),
                render_safe_text(&event.summary, MAX_SUMMARY_CHARS),
                event.t_start_ms,
                event.t_end_ms
            ));
            if !event.suspect_ids.is_empty() {
                out.push_str(&format!("  - suspects: {}\n", join_ids(&event.suspect_ids)));
            }
            if !event.evidence_ids.is_empty() {
                out.push_str(&format!(
                    "  - evidence: {}\n",
                    join_ids(&event.evidence_ids)
                ));
            }
        }
        out.push('\n');

        out.push_str("### Impact\n\n");
        if !ai.impact.user_symptoms.is_empty() {
            out.push_str(&format!(
                "- user_symptoms: {}\n",
                join_text(&ai.impact.user_symptoms, MAX_SUMMARY_CHARS)
            ));
        }
        if !ai.impact.services_affected.is_empty() {
            out.push_str(&format!(
                "- services_affected: {}\n",
                join_ids(&ai.impact.services_affected)
            ));
        }
        out.push_str(&format!(
            "- duration_ms_estimate: {}\n- slo_risk: {}\n\n",
            ai.impact.duration_ms_estimate,
            render_safe_text(&ai.impact.slo_risk, MAX_NAME_CHARS)
        ));

        out.push_str("### Mitigation\n\n");
        if !ai.mitigation.immediate_checks.is_empty() {
            out.push_str("#### Immediate Checks\n\n");
            for check in &ai.mitigation.immediate_checks {
                out.push_str(&format!(
                    "- {}: {}\n",
                    render_safe_text(&check.title, MAX_NAME_CHARS),
                    render_safe_text(&check.details, MAX_DETAIL_CHARS)
                ));
                if !check.linked_suspect_ids.is_empty() {
                    out.push_str(&format!(
                        "  - suspects: {}\n",
                        join_ids(&check.linked_suspect_ids)
                    ));
                }
                if !check.linked_evidence_ids.is_empty() {
                    out.push_str(&format!(
                        "  - evidence: {}\n",
                        join_ids(&check.linked_evidence_ids)
                    ));
                }
            }
            out.push('\n');
        }
        if !ai.mitigation.long_term_fixes.is_empty() {
            out.push_str("#### Long-term Fixes\n\n");
            for fix in &ai.mitigation.long_term_fixes {
                out.push_str(&format!(
                    "- {}: {}\n",
                    render_safe_text(&fix.title, MAX_NAME_CHARS),
                    render_safe_text(&fix.details, MAX_DETAIL_CHARS)
                ));
                if !fix.linked_suspect_ids.is_empty() {
                    out.push_str(&format!(
                        "  - suspects: {}\n",
                        join_ids(&fix.linked_suspect_ids)
                    ));
                }
                if !fix.linked_evidence_ids.is_empty() {
                    out.push_str(&format!(
                        "  - evidence: {}\n",
                        join_ids(&fix.linked_evidence_ids)
                    ));
                }
            }
            out.push('\n');
        }

        if !ai.unknowns.is_empty() {
            out.push_str("### Unknowns\n\n");
            for item in &ai.unknowns {
                out.push_str(&format!(
                    "- {} (why: {})\n",
                    render_safe_text(&item.question, MAX_SUMMARY_CHARS),
                    render_safe_text(&item.why_it_matters, MAX_SUMMARY_CHARS)
                ));
                out.push_str(&format!(
                    "  - data_needed: {}\n",
                    render_safe_text(&item.data_needed, MAX_SUMMARY_CHARS)
                ));
            }
            out.push('\n');
        }

        out.push_str("### Confidence\n\n");
        out.push_str(&format!(
            "- overall: {} ({})\n",
            ai.confidence.overall,
            render_safe_text(&ai.confidence.level, MAX_NAME_CHARS)
        ));
        if !ai.confidence.reasoning.is_empty() {
            out.push_str(&format!(
                "- reasoning: {}\n\n",
                join_text(&ai.confidence.reasoning, MAX_SUMMARY_CHARS)
            ));
        } else {
            out.push('\n');
        }

        out.push_str("### Citations\n\n");
        out.push_str(&format!(
            "- used_suspect_ids: {}\n",
            join_ids(&ai.citations.used_suspect_ids)
        ));
        out.push_str(&format!(
            "- used_evidence_ids: {}\n",
            join_ids(&ai.citations.used_evidence_ids)
        ));
    }

    if ai_fallback_used {
        out.push_str("\n---\nAI_STATUS: FALLBACK_USED\n");
    }

    out
}

pub fn build_evidence_pack(
    tape_dir: &Path,
    analysis: &AnalysisOutput,
    analysis_sha256: &str,
) -> AppResult<EvidencePack> {
    let redactor = RedactionEngine::new(RedactionRuleset::safe_default()?);
    let weights = ScoreWeights::default();

    let mut evidence_map: BTreeMap<EvidenceKey, String> = BTreeMap::new();
    let mut next_id = 1usize;
    let mut suspects = Vec::new();

    for (idx, entry) in analysis.ranking.iter().take(MAX_SUSPECTS).enumerate() {
        let suspect_id = suspect_id_for(&entry.entity.name, &entry.entity.namespace);
        let mut evidence_ids = Vec::new();
        for evidence in entry.evidence_refs.iter().take(MAX_EVIDENCE_PER_SUSPECT) {
            if evidence_map.len() >= MAX_TOTAL_EVIDENCE {
                break;
            }
            if let Some(key) = evidence_key_from_ref(evidence) {
                let id = evidence_map.entry(key).or_insert_with(|| {
                    let assigned = format!("EVID-{next_id:04}");
                    next_id += 1;
                    assigned
                });
                if evidence_ids.len() < MAX_EVIDENCE_PER_SUSPECT {
                    evidence_ids.push(id.clone());
                }
            }
        }
        suspects.push(EvidenceSuspect {
            suspect_id,
            rank: (idx + 1) as u32,
            service_name: sanitize_text(&redactor, &entry.entity.name, MAX_NAME_CHARS),
            scores_ppm: EvidenceScores {
                total: entry.score_micros.max(0) as u64,
                self_signal: entry.self_signal.max(0) as u64,
                temporal_precedence: entry.temporal_precedence.max(0) as u64,
                downstream_impact: entry.downstream_impact.max(0) as u64,
                centrality: entry.centrality.max(0) as u64,
            },
            features: EvidenceFeatures {
                error_rate_delta_ppm: entry.features.error_rate_delta_ppm,
                latency_p95_delta_us: entry.features.latency_p95_delta_us,
                throughput_delta_ppm: entry.features.throughput_delta_ppm,
                first_anom_offset_ms: entry.features.first_anom_offset_ms,
            },
            evidence_ids,
        });
    }

    let evidence_index = collect_evidence_index(
        tape_dir,
        &evidence_map,
        &redactor,
        analysis.window.t0_unix_nano,
    )?;

    let analyzer = EvidenceAnalyzer {
        ranking_weights_ppm: weights_map(&weights),
        constraints: AI_CONSTRAINTS.iter().map(|s| s.to_string()).collect(),
    };

    let mut pack = EvidencePack {
        schema_version: EVIDENCE_PACK_VERSION.to_string(),
        tape_id: analysis.tape_id.clone(),
        analysis_sha256: analysis_sha256.to_string(),
        window: EvidenceWindow {
            t0_unix_nano: analysis.window.t0_unix_nano,
            duration_ms: analysis.window.duration_ms,
        },
        analyzer,
        suspects,
        evidence_index,
    };

    pack = shrink_evidence_pack(pack)?;
    Ok(pack)
}

pub fn generate_ai_section(
    provider: &dyn AiProvider,
    evidence_pack: &EvidencePack,
    evidence_pack_json: &str,
    deterministic: bool,
    seed: Option<u64>,
) -> AppResult<AiReport> {
    let schema = include_str!("../schema/ai_report.schema.json");
    let prompt = format!(
        "You are an incident RCA assistant. Return ONLY valid JSON that matches this schema:\n{schema}\n\nEvidence pack (sanitized):\n{evidence_pack_json}"
    );
    let response = provider.generate_report(&AiRequest {
        prompt,
        evidence_pack_json: evidence_pack_json.to_string(),
        deterministic,
        seed,
    })?;
    validate_ai_response(&response.json, schema, evidence_pack)
}

pub fn analysis_sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    format!("sha256:{}", hex::encode(digest))
}

pub fn ensure_report_size(report: &str) -> AppResult<()> {
    if report.len() > MAX_REPORT_MD_BYTES {
        return Err(AppError::validation("report exceeds max bytes"));
    }
    Ok(())
}

pub fn scan_report_for_leakage(report: &str) -> AppResult<()> {
    let scanner = LeakageScanner::new(RedactionRuleset::safe_default()?);
    let sanitized = strip_known_ids(report);
    let leakage = scanner.scan_str(&sanitized);
    if leakage > 0 {
        return Err(AppError::validation("report failed leakage scan"));
    }
    Ok(())
}

fn validate_ai_response(
    json: &str,
    schema: &str,
    evidence_pack: &EvidencePack,
) -> AppResult<AiReport> {
    if json.len() > MAX_AI_JSON_BYTES {
        return Err(AppError::validation("ai response exceeds max bytes"));
    }
    let schema_json: Value = serde_json::from_str(schema)
        .map_err(|e| AppError::internal(format!("ai schema parse error: {e}")))?;
    let response_json: Value = serde_json::from_str(json)
        .map_err(|e| AppError::validation(format!("ai response json error: {e}")))?;
    let compiled = jsonschema::JSONSchema::compile(&schema_json)
        .map_err(|e| AppError::internal(format!("ai schema compile error: {e}")))?;
    if !compiled.is_valid(&response_json) {
        return Err(AppError::validation("ai response schema validation failed"));
    }

    if contains_url_in_json(&response_json) {
        return Err(AppError::validation("ai response contains url patterns"));
    }

    let report: AiReport = serde_json::from_value(response_json.clone())
        .map_err(|e| AppError::validation(format!("ai response decode error: {e}")))?;
    enforce_ai_constraints(&report, evidence_pack)?;

    let scanner = LeakageScanner::new(RedactionRuleset::safe_default()?);
    let leakage = scan_json_value(&response_json, &scanner, &LEAKAGE_SKIP_KEYS);
    if leakage > 0 {
        return Err(AppError::validation("ai response failed leakage scan"));
    }

    Ok(report)
}

fn enforce_ai_constraints(report: &AiReport, evidence_pack: &EvidencePack) -> AppResult<()> {
    if report.schema_version != AI_SCHEMA_VERSION {
        return Err(AppError::validation("ai report schema_version mismatch"));
    }
    if report.tape_id != evidence_pack.tape_id {
        return Err(AppError::validation("ai report tape_id mismatch"));
    }
    if report.analysis_ref.analysis_sha256 != evidence_pack.analysis_sha256 {
        return Err(AppError::validation("ai report analysis_sha256 mismatch"));
    }
    if report.analysis_ref.top_k as usize != evidence_pack.suspects.len() {
        return Err(AppError::validation("ai report top_k mismatch"));
    }
    let top_suspect = evidence_pack
        .suspects
        .first()
        .ok_or_else(|| AppError::validation("evidence pack missing suspects"))?;
    if report.root_cause.primary_suspect_id != top_suspect.suspect_id {
        return Err(AppError::validation(
            "ai report primary_suspect_id must match top suspect",
        ));
    }

    let suspect_ids: BTreeSet<&str> = evidence_pack
        .suspects
        .iter()
        .map(|s| s.suspect_id.as_str())
        .collect();
    let evidence_ids: BTreeSet<&str> = evidence_pack
        .evidence_index
        .keys()
        .map(|k| k.as_str())
        .collect();

    let mut timeline_has_evidence = false;
    for event in &report.timeline {
        if event.t_end_ms < event.t_start_ms {
            return Err(AppError::validation("ai timeline t_end_ms < t_start_ms"));
        }
        if !event.evidence_ids.is_empty() {
            timeline_has_evidence = true;
        }
        ensure_ids_exist(&event.suspect_ids, &suspect_ids, "timeline suspect_ids")?;
        ensure_ids_exist(&event.evidence_ids, &evidence_ids, "timeline evidence_ids")?;
    }
    if !timeline_has_evidence {
        return Err(AppError::validation(
            "ai timeline must reference at least one evidence_id",
        ));
    }

    ensure_ids_exist(
        std::slice::from_ref(&report.root_cause.primary_suspect_id),
        &suspect_ids,
        "root_cause.primary_suspect_id",
    )?;
    for alt in &report.root_cause.alternatives {
        if alt.suspect_id == report.root_cause.primary_suspect_id {
            return Err(AppError::validation(
                "root_cause.alternatives must not include primary_suspect_id",
            ));
        }
        ensure_ids_exist(
            std::slice::from_ref(&alt.suspect_id),
            &suspect_ids,
            "root_cause.alternatives",
        )?;
    }

    ensure_ids_exist(
        &report.impact.services_affected,
        &suspect_ids,
        "impact.services_affected",
    )?;
    for item in &report.mitigation.immediate_checks {
        ensure_ids_exist(
            &item.linked_suspect_ids,
            &suspect_ids,
            "mitigation.immediate_checks.suspect_ids",
        )?;
        ensure_ids_exist(
            &item.linked_evidence_ids,
            &evidence_ids,
            "mitigation.immediate_checks.evidence_ids",
        )?;
    }
    for item in &report.mitigation.long_term_fixes {
        ensure_ids_exist(
            &item.linked_suspect_ids,
            &suspect_ids,
            "mitigation.long_term_fixes.suspect_ids",
        )?;
        ensure_ids_exist(
            &item.linked_evidence_ids,
            &evidence_ids,
            "mitigation.long_term_fixes.evidence_ids",
        )?;
    }
    ensure_ids_exist(
        &report.citations.used_suspect_ids,
        &suspect_ids,
        "citations.used_suspect_ids",
    )?;
    ensure_ids_exist(
        &report.citations.used_evidence_ids,
        &evidence_ids,
        "citations.used_evidence_ids",
    )?;

    let top_evidence = top_suspect.evidence_ids.iter().collect::<BTreeSet<_>>();
    let cited_top1 = report
        .citations
        .used_evidence_ids
        .iter()
        .any(|id| top_evidence.contains(id));
    if !cited_top1 {
        return Err(AppError::validation(
            "citations.used_evidence_ids must include top suspect evidence",
        ));
    }

    Ok(())
}

fn ensure_ids_exist(values: &[String], allowed: &BTreeSet<&str>, label: &str) -> AppResult<()> {
    for value in values {
        if !allowed.contains(value.as_str()) {
            return Err(AppError::validation(format!(
                "ai report references unknown id in {label}"
            )));
        }
    }
    Ok(())
}

fn recommended_checks(ranking: &[RankingEntry]) -> Vec<String> {
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

fn suspect_id_for(name: &str, namespace: &str) -> String {
    let base = if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    };
    let mut sanitized: String = base
        .to_ascii_lowercase()
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' => ch,
            _ => '_',
        })
        .collect();
    if sanitized.is_empty() {
        sanitized = "unknown".to_string();
    }
    if !sanitized
        .chars()
        .next()
        .map(|ch| ch.is_ascii_alphanumeric())
        .unwrap_or(false)
    {
        sanitized = format!("s{sanitized}");
    }
    if sanitized.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(base.as_bytes());
        let digest = hasher.finalize();
        let suffix = &hex::encode(digest)[..8];
        let prefix_len = 64usize.saturating_sub(9);
        sanitized.truncate(prefix_len);
        sanitized.push('-');
        sanitized.push_str(suffix);
    }
    format!("svc:{sanitized}")
}

fn evidence_key_from_ref(evidence: &EvidenceRef) -> Option<EvidenceKey> {
    match evidence {
        EvidenceRef::TraceExemplar { trace_id, span_id } => Some(EvidenceKey {
            trace_id: trace_id.clone(),
            span_id: span_id.clone(),
        }),
    }
}

fn collect_evidence_index(
    tape_dir: &Path,
    evidence_map: &BTreeMap<EvidenceKey, String>,
    redactor: &RedactionEngine,
    window_start_unix_nano: u64,
) -> AppResult<BTreeMap<String, EvidenceItem>> {
    if evidence_map.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut remaining: BTreeSet<&EvidenceKey> = evidence_map.keys().collect();
    let mut evidence_index: BTreeMap<String, EvidenceItem> = BTreeMap::new();

    let tape_path = tape_dir.join("tape.tape.zst");
    let mut reader = TapeReader::open(&tape_path, Bounds::default())?;
    while let Some(record) = reader.read_next()? {
        if record.record_type != RecordType::Traces {
            continue;
        }
        let request = ExportTraceServiceRequest::decode(record.otlp_payload_bytes.as_slice())
            .map_err(|e| AppError::validation(format!("trace decode error: {e}")))?;
        for resource_spans in &request.resource_spans {
            let service_name = extract_attribute(resource_spans.resource.as_ref(), "service.name")
                .unwrap_or_else(|| "unknown".to_string());
            for scope_span in &resource_spans.scope_spans {
                for span in &scope_span.spans {
                    let trace_id = match hex_id(&span.trace_id, 16) {
                        Some(id) => id,
                        None => continue,
                    };
                    let span_id = match hex_id(&span.span_id, 8) {
                        Some(id) => id,
                        None => continue,
                    };
                    let key = EvidenceKey { trace_id, span_id };
                    if !remaining.contains(&key) {
                        continue;
                    }
                    let evidence_id = evidence_map
                        .get(&key)
                        .ok_or_else(|| AppError::internal("missing evidence id"))?
                        .clone();
                    let item = build_trace_evidence_item(
                        span,
                        &service_name,
                        redactor,
                        window_start_unix_nano,
                    );
                    evidence_index.insert(evidence_id, item);
                    remaining.remove(&key);
                    if remaining.is_empty() {
                        return Ok(evidence_index);
                    }
                }
            }
        }
    }

    if !remaining.is_empty() {
        return Err(AppError::validation(
            "failed to resolve all evidence refs in tape",
        ));
    }
    Ok(evidence_index)
}

fn build_trace_evidence_item(
    span: &Span,
    service_name: &str,
    redactor: &RedactionEngine,
    window_start_unix_nano: u64,
) -> EvidenceItem {
    let parent_span_id =
        if span.parent_span_id.is_empty() || span.parent_span_id.iter().all(|b| *b == 0) {
            String::new()
        } else {
            hex::encode(&span.parent_span_id)
        };
    let duration_us = if span.end_time_unix_nano >= span.start_time_unix_nano {
        (span.end_time_unix_nano - span.start_time_unix_nano) / 1_000
    } else {
        0
    };
    let start_offset_ms = span
        .start_time_unix_nano
        .saturating_sub(window_start_unix_nano)
        / 1_000_000;
    let end_offset_ms = span
        .end_time_unix_nano
        .saturating_sub(window_start_unix_nano)
        / 1_000_000;

    let mut attributes = BTreeMap::new();
    for attr in &span.attributes {
        if !ATTR_ALLOWLIST.contains(&attr.key.as_str()) {
            continue;
        }
        if let Some(AnyValue::StringValue(value)) =
            attr.value.as_ref().and_then(|v| v.value.as_ref())
        {
            let cleaned = sanitize_text(redactor, value, MAX_NAME_CHARS);
            if !cleaned.is_empty() {
                attributes.insert(attr.key.clone(), cleaned);
            }
        }
    }

    EvidenceItem::TraceExemplar {
        trace_id: hex::encode(&span.trace_id),
        span_id: hex::encode(&span.span_id),
        parent_span_id,
        service_name: sanitize_text(redactor, service_name, MAX_NAME_CHARS),
        span_name: sanitize_text(redactor, &span.name, MAX_NAME_CHARS),
        status_code: span_status_code(span),
        duration_us,
        start_offset_ms,
        end_offset_ms,
        attributes_allowlist: if attributes.is_empty() {
            None
        } else {
            Some(attributes)
        },
    }
}

fn span_status_code(span: &Span) -> String {
    match span.status.as_ref().map(|s| s.code).unwrap_or(0) {
        1 => "OK",
        2 => "ERROR",
        _ => "UNSET",
    }
    .to_string()
}

fn extract_attribute(
    resource: Option<&opentelemetry_proto::tonic::resource::v1::Resource>,
    key: &str,
) -> Option<String> {
    let attrs: &[KeyValue] = resource?.attributes.as_slice();
    for kv in attrs {
        if kv.key == key {
            if let Some(AnyValue::StringValue(s)) = kv.value.as_ref().and_then(|v| v.value.as_ref())
            {
                return Some(s.clone());
            }
        }
    }
    None
}

fn hex_id(bytes: &[u8], expected_len: usize) -> Option<String> {
    if bytes.len() != expected_len {
        return None;
    }
    Some(hex::encode(bytes))
}

fn weights_map(weights: &ScoreWeights) -> BTreeMap<String, u64> {
    let mut map = BTreeMap::new();
    map.insert("self_signal".to_string(), weights.self_signal);
    map.insert(
        "temporal_precedence".to_string(),
        weights.temporal_precedence,
    );
    map.insert("downstream_impact".to_string(), weights.downstream_impact);
    map.insert("centrality".to_string(), weights.centrality);
    map
}

fn shrink_evidence_pack(pack: EvidencePack) -> AppResult<EvidencePack> {
    let mut pack = pack;
    if evidence_pack_bytes(&pack)? <= MAX_EVIDENCE_PACK_BYTES {
        return Ok(pack);
    }

    for max_per_suspect in [4usize, 3, 2] {
        for suspect in &mut pack.suspects {
            if suspect.evidence_ids.len() > max_per_suspect {
                suspect.evidence_ids.truncate(max_per_suspect);
            }
        }
        prune_evidence_index(&mut pack);
        if evidence_pack_bytes(&pack)? <= MAX_EVIDENCE_PACK_BYTES {
            return Ok(pack);
        }
    }

    for max_suspects in [4usize, 3] {
        if pack.suspects.len() > max_suspects {
            pack.suspects.truncate(max_suspects);
            prune_evidence_index(&mut pack);
        }
        if evidence_pack_bytes(&pack)? <= MAX_EVIDENCE_PACK_BYTES {
            return Ok(pack);
        }
    }

    drop_attributes_allowlist(&mut pack);
    prune_evidence_index(&mut pack);
    if evidence_pack_bytes(&pack)? <= MAX_EVIDENCE_PACK_BYTES {
        return Ok(pack);
    }

    Err(AppError::validation(
        "evidence pack exceeds max bytes after shrink",
    ))
}

fn evidence_pack_bytes(pack: &EvidencePack) -> AppResult<usize> {
    let bytes = serde_json::to_vec(pack)
        .map_err(|e| AppError::internal(format!("evidence pack encode error: {e}")))?;
    Ok(bytes.len())
}

fn prune_evidence_index(pack: &mut EvidencePack) {
    let used_ids: BTreeSet<&str> = pack
        .suspects
        .iter()
        .flat_map(|s| s.evidence_ids.iter().map(|id| id.as_str()))
        .collect();
    pack.evidence_index
        .retain(|key, _| used_ids.contains(key.as_str()));
}

fn drop_attributes_allowlist(pack: &mut EvidencePack) {
    for item in pack.evidence_index.values_mut() {
        let EvidenceItem::TraceExemplar {
            attributes_allowlist,
            ..
        } = item;
        *attributes_allowlist = None;
    }
}

fn sanitize_text(redactor: &RedactionEngine, value: &str, max_len: usize) -> String {
    let redacted = redactor.redact_str(value);
    let mut out = strip_code_blocks(&redacted);
    out = strip_urls(&out);
    out = out.replace('`', "");
    out = out.replace(['<', '>'], "");
    out = normalize_whitespace(&out);
    if out.chars().count() > max_len {
        out = out.chars().take(max_len).collect();
    }
    out
}

fn render_safe_text(value: &str, max_len: usize) -> String {
    let mut out = strip_code_blocks(value);
    out = strip_urls(&out);
    out = out.replace('`', "");
    out = out.replace(['<', '>'], "");
    out = normalize_whitespace(&out);
    if out.chars().count() > max_len {
        out = out.chars().take(max_len).collect();
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
    let re = Regex::new(r"https?://\S+|www\.\S+").unwrap();
    re.replace_all(input, "[redacted-url]").to_string()
}

fn contains_url_in_json(value: &Value) -> bool {
    match value {
        Value::String(text) => contains_url(text),
        Value::Array(items) => items.iter().any(contains_url_in_json),
        Value::Object(map) => map.values().any(contains_url_in_json),
        _ => false,
    }
}

fn contains_url(input: &str) -> bool {
    input.contains("http://") || input.contains("https://") || input.contains("www.")
}

fn normalize_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn join_ids(values: &[String]) -> String {
    values
        .iter()
        .map(|value| format!("`{}`", render_safe_text(value, MAX_NAME_CHARS)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_text(values: &[String], max_len: usize) -> String {
    values
        .iter()
        .map(|value| render_safe_text(value, max_len))
        .collect::<Vec<_>>()
        .join("; ")
}

fn strip_known_ids(input: &str) -> String {
    let mut output = input.to_string();
    let replacements = [
        "tape_id: `",
        "trace_id=",
        "span_id=",
        "trace_id: `",
        "span_id: `",
    ];
    for marker in replacements {
        output = strip_hex_after_marker(&output, marker);
    }
    output
}

fn strip_hex_after_marker(input: &str, marker: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(idx) = rest.find(marker) {
        out.push_str(&rest[..idx + marker.len()]);
        rest = &rest[idx + marker.len()..];
        let mut cut = 0usize;
        for ch in rest.chars() {
            if ch.is_ascii_hexdigit() {
                cut += ch.len_utf8();
            } else {
                break;
            }
        }
        out.push_str("<id>");
        rest = &rest[cut..];
    }
    out.push_str(rest);
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidencePack {
    schema_version: String,
    tape_id: String,
    analysis_sha256: String,
    window: EvidenceWindow,
    analyzer: EvidenceAnalyzer,
    suspects: Vec<EvidenceSuspect>,
    evidence_index: BTreeMap<String, EvidenceItem>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceWindow {
    t0_unix_nano: u64,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceAnalyzer {
    ranking_weights_ppm: BTreeMap<String, u64>,
    constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceSuspect {
    suspect_id: String,
    rank: u32,
    service_name: String,
    scores_ppm: EvidenceScores,
    features: EvidenceFeatures,
    evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceScores {
    total: u64,
    self_signal: u64,
    temporal_precedence: u64,
    downstream_impact: u64,
    centrality: u64,
}

#[derive(Debug, Clone, Serialize)]
struct EvidenceFeatures {
    error_rate_delta_ppm: i64,
    latency_p95_delta_us: i64,
    throughput_delta_ppm: i64,
    first_anom_offset_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EvidenceKey {
    trace_id: String,
    span_id: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum EvidenceItem {
    TraceExemplar {
        trace_id: String,
        span_id: String,
        parent_span_id: String,
        service_name: String,
        span_name: String,
        status_code: String,
        duration_us: u64,
        start_offset_ms: u64,
        end_offset_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        attributes_allowlist: Option<BTreeMap<String, String>>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai::MockProvider;

    fn sample_pack() -> EvidencePack {
        EvidencePack {
            schema_version: EVIDENCE_PACK_VERSION.to_string(),
            tape_id: "0".repeat(64),
            analysis_sha256: "sha256:".to_string() + &"0".repeat(64),
            window: EvidenceWindow {
                t0_unix_nano: 0,
                duration_ms: 0,
            },
            analyzer: EvidenceAnalyzer {
                ranking_weights_ppm: weights_map(&ScoreWeights::default()),
                constraints: AI_CONSTRAINTS.iter().map(|s| s.to_string()).collect(),
            },
            suspects: vec![EvidenceSuspect {
                suspect_id: "svc:svc-1".to_string(),
                rank: 1,
                service_name: "svc-1".to_string(),
                scores_ppm: EvidenceScores {
                    total: 100,
                    self_signal: 80,
                    temporal_precedence: 10,
                    downstream_impact: 5,
                    centrality: 5,
                },
                features: EvidenceFeatures {
                    error_rate_delta_ppm: 0,
                    latency_p95_delta_us: 0,
                    throughput_delta_ppm: 0,
                    first_anom_offset_ms: 0,
                },
                evidence_ids: vec!["EVID-0001".to_string()],
            }],
            evidence_index: BTreeMap::from([(
                "EVID-0001".to_string(),
                EvidenceItem::TraceExemplar {
                    trace_id: "0".repeat(32),
                    span_id: "0".repeat(16),
                    parent_span_id: String::new(),
                    service_name: "svc-1".to_string(),
                    span_name: "span".to_string(),
                    status_code: "ERROR".to_string(),
                    duration_us: 10,
                    start_offset_ms: 0,
                    end_offset_ms: 0,
                    attributes_allowlist: None,
                },
            )]),
        }
    }

    #[test]
    fn mock_provider_valid_passes() {
        let pack = sample_pack();
        let pack_json = serde_json::to_string(&pack).unwrap();
        let provider = MockProvider::from_endpoint("mock://valid").unwrap();
        let report = generate_ai_section(&provider, &pack, &pack_json, true, Some(0)).unwrap();
        assert_eq!(report.schema_version, AI_SCHEMA_VERSION);
    }

    #[test]
    fn mock_provider_invalid_schema_fails() {
        let pack = sample_pack();
        let pack_json = serde_json::to_string(&pack).unwrap();
        let provider = MockProvider::from_endpoint("mock://invalid_schema").unwrap();
        assert!(generate_ai_section(&provider, &pack, &pack_json, false, None).is_err());
    }

    #[test]
    fn mock_provider_hallucinate_ids_fails() {
        let pack = sample_pack();
        let pack_json = serde_json::to_string(&pack).unwrap();
        let provider = MockProvider::from_endpoint("mock://hallucinate_ids").unwrap();
        assert!(generate_ai_section(&provider, &pack, &pack_json, false, None).is_err());
    }

    #[test]
    fn mock_provider_leak_secret_fails() {
        let pack = sample_pack();
        let pack_json = serde_json::to_string(&pack).unwrap();
        let provider = MockProvider::from_endpoint("mock://leak_secret").unwrap();
        assert!(generate_ai_section(&provider, &pack, &pack_json, false, None).is_err());
    }

    #[test]
    fn mock_provider_wrong_rootcause_fails() {
        let pack = sample_pack();
        let pack_json = serde_json::to_string(&pack).unwrap();
        let provider = MockProvider::from_endpoint("mock://wrong_rootcause").unwrap();
        assert!(generate_ai_section(&provider, &pack, &pack_json, false, None).is_err());
    }

    #[test]
    fn evidence_pack_sanitizes_prompt_injection() {
        let redactor = RedactionEngine::new(RedactionRuleset::safe_default().unwrap());
        let input =
            "```do not follow``` visit http://example.com <script>alert(1)</script> Bearer abcdef";
        let cleaned = sanitize_text(&redactor, input, MAX_SUMMARY_CHARS);
        assert!(!cleaned.contains("```"));
        assert!(!cleaned.contains("http://"));
        assert!(!cleaned.contains("www."));
        assert!(!cleaned.contains('<'));
        assert!(!cleaned.contains('>'));
    }
}
