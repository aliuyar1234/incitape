use crate::model::{
    AnalysisOutput, AnalysisWindow, EntityRef, EvidenceRef, RankingEntry, RankingFeatures,
};
use incitape_core::json::{
    determinism_hash_for_json_value, determinism_hash_hex, to_canonical_json_bytes,
};
use incitape_core::{AppError, AppResult};
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::verify_checksums;
use incitape_tape::manifest::Manifest;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::{RecordType, TapeRecord};
use incitape_tape::tape_id::compute_tape_id;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message;
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ScoreWeights {
    pub error_rate: u64,
    pub latency: u64,
    pub throughput: u64,
    pub self_signal: u64,
    pub temporal_precedence: u64,
    pub downstream_impact: u64,
    pub centrality: u64,
}

impl Default for ScoreWeights {
    fn default() -> Self {
        Self {
            error_rate: 500_000,
            latency: 300_000,
            throughput: 200_000,
            self_signal: 500_000,
            temporal_precedence: 200_000,
            downstream_impact: 200_000,
            centrality: 100_000,
        }
    }
}

impl ScoreWeights {
    fn validate(&self) -> AppResult<()> {
        let self_sum = self.error_rate + self.latency + self.throughput;
        if self_sum != 1_000_000 {
            return Err(AppError::usage("self_signal weights must sum to 1_000_000"));
        }
        let total_sum =
            self.self_signal + self.temporal_precedence + self.downstream_impact + self.centrality;
        if total_sum != 1_000_000 {
            return Err(AppError::usage("ranking weights must sum to 1_000_000"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalyzerConfig {
    pub top_k: u32,
    pub weights: ScoreWeights,
}

impl AnalyzerConfig {
    pub fn new(top_k: u32) -> AppResult<Self> {
        if top_k == 0 {
            return Err(AppError::usage("--top-k must be > 0"));
        }
        let weights = ScoreWeights::default();
        weights.validate()?;
        Ok(Self { top_k, weights })
    }

    pub fn config_hash(&self) -> AppResult<String> {
        let bytes = to_canonical_json_bytes(self)?;
        Ok(determinism_hash_hex(&bytes))
    }

    fn validate(&self) -> AppResult<()> {
        if self.top_k == 0 {
            return Err(AppError::usage("--top-k must be > 0"));
        }
        self.weights.validate()
    }
}

pub fn analyze_tape_dir(tape_dir: &Path, config: AnalyzerConfig, out_path: &Path) -> AppResult<()> {
    config.validate()?;
    ensure_not_partial(tape_dir)?;
    verify_checksums(tape_dir)?;

    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest = Manifest::load(&tape_dir.join("manifest.yaml"))?;
    manifest.validate(&tape_id)?;

    let reader = TapeReader::open(&tape_path, Bounds::default())?;
    let records = reader.read_all_sorted()?;

    let analysis = analyze_records(&records, &tape_id, &config)?;
    let bytes = to_canonical_json_bytes(&analysis)?;
    std::fs::write(out_path, bytes)
        .map_err(|e| AppError::internal(format!("failed to write analysis.json: {e}")))?;
    Ok(())
}

pub fn analyze_tape_dir_to_output(
    tape_dir: &Path,
    config: AnalyzerConfig,
) -> AppResult<AnalysisOutput> {
    config.validate()?;
    ensure_not_partial(tape_dir)?;
    verify_checksums(tape_dir)?;

    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest = Manifest::load(&tape_dir.join("manifest.yaml"))?;
    manifest.validate(&tape_id)?;

    let reader = TapeReader::open(&tape_path, Bounds::default())?;
    let records = reader.read_all_sorted()?;

    analyze_records(&records, &tape_id, &config)
}

fn ensure_not_partial(tape_dir: &Path) -> AppResult<()> {
    if let Some(name) = tape_dir.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".partial") {
            return Err(AppError::validation("partial tape_dir is not valid"));
        }
    }
    Ok(())
}

fn analyze_records(
    records: &[TapeRecord],
    tape_id: &str,
    config: &AnalyzerConfig,
) -> AppResult<AnalysisOutput> {
    let mut stats = BTreeMap::<ServiceKey, ServiceStats>::new();
    let mut edges = BTreeMap::<ServiceKey, BTreeSet<ServiceKey>>::new();
    let mut incoming = BTreeMap::<ServiceKey, BTreeSet<ServiceKey>>::new();
    let mut window_start = u64::MAX;
    let mut window_end = 0u64;

    for record in records {
        if record.record_type != RecordType::Traces {
            continue;
        }
        window_start = window_start.min(record.capture_time_unix_nano);
        window_end = window_end.max(record.capture_time_unix_nano);
        let request = ExportTraceServiceRequest::decode(record.otlp_payload_bytes.as_slice())
            .map_err(|e| AppError::validation(format!("trace decode error: {e}")))?;
        process_trace_request(
            &request,
            record.capture_time_unix_nano,
            &mut stats,
            &mut edges,
            &mut incoming,
        )?;
    }

    let window = if window_start == u64::MAX {
        AnalysisWindow {
            t0_unix_nano: 0,
            duration_ms: 0,
        }
    } else {
        let duration = if window_end > window_start {
            (window_end - window_start) / 1_000_000
        } else {
            0
        };
        AnalysisWindow {
            t0_unix_nano: window_start,
            duration_ms: duration,
        }
    };

    let ranking = build_ranking(stats, edges, incoming, config, window.t0_unix_nano)?;
    let config_hash = config.config_hash()?;

    let mut output = AnalysisOutput {
        tape_id: tape_id.to_string(),
        ranking,
        window,
        determinism_hash: String::new(),
        config_hash,
    };
    let value = serde_json::to_value(&output)
        .map_err(|e| AppError::internal(format!("analysis json encode error: {e}")))?;
    let hash = determinism_hash_for_json_value(value, "determinism_hash")?;
    output.determinism_hash = hash;
    Ok(output)
}

fn process_trace_request(
    request: &ExportTraceServiceRequest,
    capture_time_unix_nano: u64,
    stats: &mut BTreeMap<ServiceKey, ServiceStats>,
    edges: &mut BTreeMap<ServiceKey, BTreeSet<ServiceKey>>,
    incoming: &mut BTreeMap<ServiceKey, BTreeSet<ServiceKey>>,
) -> AppResult<()> {
    for resource_spans in &request.resource_spans {
        let resource = resource_spans.resource.as_ref();
        let attributes = resource.map(|r| r.attributes.as_slice());
        let service_name =
            extract_attribute(attributes, "service.name").unwrap_or_else(|| "unknown".to_string());
        let service_namespace =
            extract_attribute(attributes, "service.namespace").unwrap_or_default();
        let service_key = ServiceKey {
            name: service_name,
            namespace: service_namespace,
        };

        for scope_span in &resource_spans.scope_spans {
            let mut span_map: HashMap<SpanKey, ServiceKey> = HashMap::new();
            let mut span_infos: Vec<SpanInfo> = Vec::new();

            for span in &scope_span.spans {
                let trace_id = match parse_trace_id(&span.trace_id) {
                    Some(trace_id) => trace_id,
                    None => continue,
                };
                let span_id = match parse_span_id(&span.span_id) {
                    Some(span_id) => span_id,
                    None => continue,
                };
                let duration = span_duration_micros(span);
                let is_error = span_is_error(span);
                let start_time = span.start_time_unix_nano;
                let end_time = span.end_time_unix_nano;

                let candidate = SpanCandidate {
                    trace_id,
                    span_id,
                    duration_micros: duration,
                    end_time_unix_nano: end_time,
                    is_error,
                };
                update_stats(
                    stats,
                    &service_key,
                    candidate,
                    start_time,
                    capture_time_unix_nano,
                );

                span_map.insert(SpanKey { trace_id, span_id }, service_key.clone());
                span_infos.push(SpanInfo {
                    service: service_key.clone(),
                    parent_span_id: parse_parent_span_id(span),
                    trace_id,
                    is_error,
                });
            }

            for info in span_infos {
                if let Some(parent_id) = info.parent_span_id {
                    let parent_key = SpanKey {
                        trace_id: info.trace_id,
                        span_id: parent_id,
                    };
                    if let Some(parent_service) = span_map.get(&parent_key) {
                        if parent_service != &info.service {
                            edges
                                .entry(parent_service.clone())
                                .or_default()
                                .insert(info.service.clone());
                            incoming
                                .entry(info.service.clone())
                                .or_default()
                                .insert(parent_service.clone());
                            if info.is_error {
                                if let Some(entry) = stats.get_mut(parent_service) {
                                    entry.downstream_error_count =
                                        entry.downstream_error_count.saturating_add(1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

fn update_stats(
    stats: &mut BTreeMap<ServiceKey, ServiceStats>,
    service: &ServiceKey,
    candidate: SpanCandidate,
    start_time: u64,
    capture_time_unix_nano: u64,
) {
    let entry = stats
        .entry(service.clone())
        .or_insert_with(ServiceStats::new);
    entry.span_count += 1;
    if candidate.is_error {
        entry.error_count += 1;
    }
    entry.durations.push(candidate.duration_micros);
    entry.earliest_start = entry.earliest_start.min(start_time);
    entry.latest_end = entry.latest_end.max(candidate.end_time_unix_nano);
    let capture_bin = capture_time_unix_nano / 1_000_000_000;
    entry.earliest_capture_bin = entry.earliest_capture_bin.min(capture_bin);
    entry.candidates.push(candidate);
}

fn build_ranking(
    stats: BTreeMap<ServiceKey, ServiceStats>,
    edges: BTreeMap<ServiceKey, BTreeSet<ServiceKey>>,
    incoming: BTreeMap<ServiceKey, BTreeSet<ServiceKey>>,
    config: &AnalyzerConfig,
    window_start_unix_nano: u64,
) -> AppResult<Vec<RankingEntry>> {
    if stats.is_empty() {
        return Ok(Vec::new());
    }

    let mut latency_medians: Vec<u64> = Vec::new();
    let mut latency_p95s: Vec<u64> = Vec::new();
    let mut latency_mads: Vec<u64> = Vec::new();
    let mut error_rates: Vec<u64> = Vec::new();
    let mut throughput_rates: Vec<u64> = Vec::new();
    let mut earliest_bins: Vec<u64> = Vec::new();
    let mut metrics = BTreeMap::<ServiceKey, ServiceMetrics>::new();

    for (service, stat) in &stats {
        let median_latency = percentile(&stat.durations, 50);
        let p95_latency = percentile(&stat.durations, 95);
        let mad_latency = median_absolute_deviation(&stat.durations, median_latency);
        let window_micros = time_window_micros(stat);
        let throughput_rate = throughput_rate(stat.span_count, window_micros);
        let error_rate = ratio_micros(stat.error_count, stat.span_count);
        let earliest_capture_bin = if stat.earliest_capture_bin == u64::MAX {
            0
        } else {
            stat.earliest_capture_bin
        };

        latency_medians.push(median_latency);
        latency_p95s.push(p95_latency);
        latency_mads.push(mad_latency);
        error_rates.push(error_rate);
        throughput_rates.push(throughput_rate);
        earliest_bins.push(earliest_capture_bin);

        let exemplar = select_exemplar(&stat.candidates, median_latency, mad_latency);

        metrics.insert(
            service.clone(),
            ServiceMetrics {
                median_latency,
                p95_latency,
                throughput_rate,
                earliest_capture_bin,
                downstream_error_count: stat.downstream_error_count,
                exemplar,
            },
        );
    }

    let latency_baseline = median(&mut latency_medians);
    let p95_baseline = median(&mut latency_p95s);
    let mad_baseline = median(&mut latency_mads);
    let error_rate_baseline = median(&mut error_rates);
    let throughput_baseline = median(&mut throughput_rates);
    let earliest_min = earliest_bins.iter().min().copied().unwrap_or(0);
    let earliest_max = earliest_bins.iter().max().copied().unwrap_or(0);

    let mut max_degree = 0u64;
    for service in stats.keys() {
        let out_degree = edges.get(service).map(|s| s.len() as u64).unwrap_or(0);
        let in_degree = incoming.get(service).map(|s| s.len() as u64).unwrap_or(0);
        max_degree = max_degree.max(out_degree + in_degree);
    }
    let max_downstream_errors = metrics
        .values()
        .map(|metric| metric.downstream_error_count)
        .max()
        .unwrap_or(0);

    let mut entries = Vec::new();
    for (service, stat) in stats {
        let service_metrics = metrics
            .get(&service)
            .ok_or_else(|| AppError::internal("missing analyzer metrics for service"))?;

        let latency_delta = service_metrics
            .median_latency
            .saturating_sub(latency_baseline);
        let latency_scale = if mad_baseline > 0 {
            mad_baseline
        } else {
            latency_baseline.max(1)
        };
        let error_rate = ratio_micros(stat.error_count, stat.span_count);
        let latency_score = ratio_micros(latency_delta, latency_scale);
        let throughput_score =
            if throughput_baseline > 0 && service_metrics.throughput_rate < throughput_baseline {
                ratio_micros(
                    throughput_baseline - service_metrics.throughput_rate,
                    throughput_baseline,
                )
            } else {
                0
            };

        let self_signal = weighted_average(
            &[
                (error_rate, config.weights.error_rate),
                (latency_score, config.weights.latency),
                (throughput_score, config.weights.throughput),
            ],
            1_000_000,
        );

        let temporal = if earliest_max > earliest_min {
            ratio_micros(
                earliest_max - service_metrics.earliest_capture_bin,
                earliest_max - earliest_min,
            )
        } else {
            0
        };

        let out_degree = edges.get(&service).map(|s| s.len() as u64).unwrap_or(0);
        let in_degree = incoming.get(&service).map(|s| s.len() as u64).unwrap_or(0);
        let downstream = if max_downstream_errors > 0 {
            ratio_micros(
                service_metrics.downstream_error_count,
                max_downstream_errors,
            )
        } else {
            0
        };
        let centrality = if max_degree > 0 {
            ratio_micros(out_degree + in_degree, max_degree)
        } else {
            0
        };

        let score = weighted_average(
            &[
                (self_signal, config.weights.self_signal),
                (temporal, config.weights.temporal_precedence),
                (downstream, config.weights.downstream_impact),
                (centrality, config.weights.centrality),
            ],
            1_000_000,
        );

        let error_rate_delta_ppm = error_rate as i64 - error_rate_baseline as i64;
        let latency_p95_delta_us = service_metrics.p95_latency as i64 - p95_baseline as i64;
        let throughput_delta_ppm = if throughput_baseline > 0 {
            let diff = service_metrics.throughput_rate as i128 - throughput_baseline as i128;
            let ppm = diff.saturating_mul(1_000_000) / throughput_baseline as i128;
            ppm.clamp(i64::MIN as i128, i64::MAX as i128) as i64
        } else {
            0
        };
        let first_anom_offset_ms = service_metrics
            .exemplar
            .map(|exemplar| {
                let delta = exemplar
                    .end_time_unix_nano
                    .saturating_sub(window_start_unix_nano);
                (delta / 1_000_000) as i64
            })
            .unwrap_or(0);

        let entity = EntityRef {
            kind: "service".to_string(),
            name: service.name.clone(),
            namespace: service.namespace.clone(),
        };

        let evidence_refs = match service_metrics.exemplar {
            Some(exemplar) => vec![EvidenceRef::TraceExemplar {
                trace_id: hex::encode(exemplar.trace_id),
                span_id: hex::encode(exemplar.span_id),
            }],
            None => Vec::new(),
        };

        entries.push(RankingEntry {
            entity,
            score_micros: score as i64,
            self_signal: self_signal as i64,
            temporal_precedence: temporal as i64,
            downstream_impact: downstream as i64,
            centrality: centrality as i64,
            evidence_refs,
            features: RankingFeatures {
                error_rate_delta_ppm,
                latency_p95_delta_us,
                throughput_delta_ppm,
                first_anom_offset_ms,
            },
        });
    }

    entries.sort_by(compare_entries);
    let top_k = config.top_k as usize;
    if entries.len() > top_k {
        entries.truncate(top_k);
    }
    Ok(entries)
}

fn compare_entries(a: &RankingEntry, b: &RankingEntry) -> Ordering {
    match b.score_micros.cmp(&a.score_micros) {
        Ordering::Equal => {
            let kind_cmp = a.entity.kind.cmp(&b.entity.kind);
            if kind_cmp != Ordering::Equal {
                return kind_cmp;
            }
            let name_cmp = a.entity.name.cmp(&b.entity.name);
            if name_cmp != Ordering::Equal {
                return name_cmp;
            }
            a.entity.namespace.cmp(&b.entity.namespace)
        }
        other => other,
    }
}

fn ratio_micros(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    let value = (numerator as u128)
        .saturating_mul(1_000_000u128)
        .saturating_div(denominator as u128);
    value.min(1_000_000) as u64
}

fn throughput_rate(span_count: u64, window_micros: u64) -> u64 {
    if window_micros == 0 {
        return 0;
    }
    let value = (span_count as u128)
        .saturating_mul(1_000_000u128)
        .saturating_div(window_micros as u128);
    value.min(u64::MAX as u128) as u64
}

fn time_window_micros(stat: &ServiceStats) -> u64 {
    if stat.earliest_start == u64::MAX {
        return 0;
    }
    if stat.latest_end <= stat.earliest_start {
        return 0;
    }
    (stat.latest_end - stat.earliest_start) / 1_000
}

fn median_absolute_deviation(values: &[u64], median: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut deviations: Vec<u64> = values.iter().map(|value| value.abs_diff(median)).collect();
    deviations.sort_unstable();
    deviations[deviations.len() / 2]
}

fn weighted_average(values: &[(u64, u64)], divisor: u64) -> u64 {
    if divisor == 0 {
        return 0;
    }
    let mut total = 0u128;
    for (value, weight) in values {
        total = total.saturating_add((*value as u128).saturating_mul(*weight as u128));
    }
    let scaled = total / divisor as u128;
    scaled.min(1_000_000) as u64
}

fn percentile(values: &[u64], pct: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let idx = ((sorted.len() - 1) as u64 * pct / 100) as usize;
    sorted[idx]
}

fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}

fn extract_attribute(attributes: Option<&[KeyValue]>, key: &str) -> Option<String> {
    let attrs = attributes?;
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

fn span_duration_micros(span: &Span) -> u64 {
    if span.end_time_unix_nano >= span.start_time_unix_nano {
        (span.end_time_unix_nano - span.start_time_unix_nano) / 1_000
    } else {
        0
    }
}

fn span_is_error(span: &Span) -> bool {
    match span.status.as_ref() {
        Some(status) => status.code == 2,
        None => false,
    }
}

fn parse_trace_id(bytes: &[u8]) -> Option<[u8; 16]> {
    if bytes.len() != 16 {
        return None;
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(bytes);
    Some(out)
}

fn parse_span_id(bytes: &[u8]) -> Option<[u8; 8]> {
    if bytes.len() != 8 {
        return None;
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Some(out)
}

fn parse_parent_span_id(span: &Span) -> Option<[u8; 8]> {
    if span.parent_span_id.is_empty() {
        return None;
    }
    if span.parent_span_id.len() != 8 {
        return None;
    }
    if span.parent_span_id.iter().all(|b| *b == 0) {
        return None;
    }
    let mut out = [0u8; 8];
    out.copy_from_slice(&span.parent_span_id);
    Some(out)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ServiceKey {
    name: String,
    namespace: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SpanKey {
    trace_id: [u8; 16],
    span_id: [u8; 8],
}

#[derive(Debug, Clone)]
struct SpanInfo {
    service: ServiceKey,
    parent_span_id: Option<[u8; 8]>,
    trace_id: [u8; 16],
    is_error: bool,
}

#[derive(Debug, Clone, Copy)]
struct SpanCandidate {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    duration_micros: u64,
    end_time_unix_nano: u64,
    is_error: bool,
}

#[derive(Debug, Clone)]
struct ServiceMetrics {
    median_latency: u64,
    p95_latency: u64,
    throughput_rate: u64,
    earliest_capture_bin: u64,
    downstream_error_count: u64,
    exemplar: Option<SpanCandidate>,
}

#[derive(Debug, Clone)]
struct ServiceStats {
    span_count: u64,
    error_count: u64,
    durations: Vec<u64>,
    earliest_start: u64,
    latest_end: u64,
    earliest_capture_bin: u64,
    downstream_error_count: u64,
    candidates: Vec<SpanCandidate>,
}

impl ServiceStats {
    fn new() -> Self {
        Self {
            span_count: 0,
            error_count: 0,
            durations: Vec::new(),
            earliest_start: u64::MAX,
            latest_end: 0,
            earliest_capture_bin: u64::MAX,
            downstream_error_count: 0,
            candidates: Vec::new(),
        }
    }
}

fn select_exemplar(
    candidates: &[SpanCandidate],
    median_latency: u64,
    mad_latency: u64,
) -> Option<SpanCandidate> {
    if candidates.is_empty() {
        return None;
    }
    let threshold = median_latency.saturating_add(mad_latency);
    let mut best: Option<SpanCandidate> = None;
    for candidate in candidates {
        let anomalous = candidate.is_error || candidate.duration_micros > threshold;
        if !anomalous {
            continue;
        }
        best = Some(match best {
            None => *candidate,
            Some(current) => select_earlier(current, *candidate),
        });
    }
    if best.is_some() {
        return best;
    }
    let mut earliest = candidates[0];
    for candidate in candidates.iter().skip(1) {
        earliest = select_earlier(earliest, *candidate);
    }
    Some(earliest)
}

fn select_earlier(current: SpanCandidate, candidate: SpanCandidate) -> SpanCandidate {
    match candidate
        .end_time_unix_nano
        .cmp(&current.end_time_unix_nano)
    {
        Ordering::Less => candidate,
        Ordering::Greater => current,
        Ordering::Equal => match candidate.span_id.cmp(&current.span_id) {
            Ordering::Less => candidate,
            Ordering::Greater => current,
            Ordering::Equal => {
                if candidate.trace_id < current.trace_id {
                    candidate
                } else {
                    current
                }
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use incitape_tape::bounds::Bounds;
    use incitape_tape::record::RecordType;
    use incitape_tape::writer::TapeWriter;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;
    use opentelemetry_proto::tonic::common::v1::AnyValue as OtlpAnyValue;
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
    use tempfile::tempdir;

    fn kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(OtlpAnyValue {
                value: Some(AnyValueInner::StringValue(value.to_string())),
            }),
        }
    }

    #[test]
    fn analyze_writes_deterministic_output() {
        let dir = tempdir().unwrap();
        let tape_dir = dir.path().join("tape");
        std::fs::create_dir_all(&tape_dir).unwrap();

        let mut writer =
            TapeWriter::create(&tape_dir.join("tape.tape.zst"), Bounds::default()).unwrap();
        let span = Span {
            trace_id: vec![1; 16],
            span_id: vec![2; 8],
            trace_state: String::new(),
            parent_span_id: vec![],
            flags: 0,
            name: "span".to_string(),
            kind: 0,
            start_time_unix_nano: 10,
            end_time_unix_nano: 20,
            attributes: vec![],
            dropped_attributes_count: 0,
            events: vec![],
            dropped_events_count: 0,
            links: vec![],
            dropped_links_count: 0,
            status: Some(Status {
                message: String::new(),
                code: 2,
            }),
        };
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![kv("service.name", "checkout")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![span],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };
        let mut buf = Vec::new();
        req.encode(&mut buf).unwrap();
        writer.write_record(RecordType::Traces, 1, &buf).unwrap();
        writer.finish().unwrap();

        let manifest = Manifest {
            tape_version: 1,
            tape_id: "0".repeat(64),
            capture: incitape_tape::manifest::Capture {
                started_at_rfc3339: "2025-01-01T00:00:00Z".to_string(),
                ended_at_rfc3339: "2025-01-01T00:00:01Z".to_string(),
                source: "otlp_receiver".to_string(),
            },
            redaction: incitape_tape::manifest::Redaction {
                profile: "safe_default".to_string(),
                ruleset_sha256: "0".repeat(64),
                applied: true,
            },
            ground_truth: None,
            derived_from: None,
        };
        manifest.write(&tape_dir.join("manifest.yaml")).unwrap();
        incitape_tape::checksums::write_checksums(&tape_dir, &["manifest.yaml", "tape.tape.zst"])
            .unwrap();

        let tape_id = compute_tape_id(&tape_dir.join("tape.tape.zst")).unwrap();
        let cfg = AnalyzerConfig::new(5).unwrap();
        let output = analyze_records(
            &TapeReader::open(&tape_dir.join("tape.tape.zst"), Bounds::default())
                .unwrap()
                .read_all_sorted()
                .unwrap(),
            &tape_id,
            &cfg,
        )
        .unwrap();

        let bytes = to_canonical_json_bytes(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let hash = parsed
            .get("determinism_hash")
            .and_then(|v| v.as_str())
            .unwrap();
        let expected = determinism_hash_for_json_value(parsed.clone(), "determinism_hash").unwrap();
        assert_eq!(hash, expected);
    }
}
