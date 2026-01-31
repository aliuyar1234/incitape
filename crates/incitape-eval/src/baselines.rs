use incitape_core::{AppError, AppResult};
use incitape_tape::record::{RecordType, TapeRecord};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::trace::v1::Span;
use prost::Message;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceKey {
    pub name: String,
    pub namespace: String,
}

#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub service: ServiceKey,
    pub score_micros: i64,
}

#[derive(Debug, Clone)]
pub struct TraceStats {
    pub services: BTreeMap<ServiceKey, ServiceStats>,
    pub edges: BTreeMap<ServiceKey, BTreeSet<ServiceKey>>,
    pub incoming: BTreeMap<ServiceKey, BTreeSet<ServiceKey>>,
}

#[derive(Debug, Clone)]
pub struct ServiceStats {
    pub span_count: u64,
    pub error_count: u64,
    pub durations: Vec<u64>,
    pub earliest_start: u64,
    pub latest_end: u64,
}

impl ServiceStats {
    fn new() -> Self {
        Self {
            span_count: 0,
            error_count: 0,
            durations: Vec::new(),
            earliest_start: u64::MAX,
            latest_end: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SpanKey {
    trace_id: [u8; 16],
    span_id: [u8; 8],
}

pub fn collect_trace_stats(records: &[TapeRecord]) -> AppResult<TraceStats> {
    let mut services = BTreeMap::<ServiceKey, ServiceStats>::new();
    let mut edges = BTreeMap::<ServiceKey, BTreeSet<ServiceKey>>::new();
    let mut incoming = BTreeMap::<ServiceKey, BTreeSet<ServiceKey>>::new();

    for record in records {
        if record.record_type != RecordType::Traces {
            continue;
        }
        let request = ExportTraceServiceRequest::decode(record.otlp_payload_bytes.as_slice())
            .map_err(|e| AppError::validation(format!("trace decode error: {e}")))?;
        for resource_spans in &request.resource_spans {
            let resource = resource_spans.resource.as_ref();
            let attrs = resource.map(|r| r.attributes.as_slice());
            let service_name =
                extract_attribute(attrs, "service.name").unwrap_or_else(|| "unknown".to_string());
            let service_namespace =
                extract_attribute(attrs, "service.namespace").unwrap_or_default();
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

                    let entry = services
                        .entry(service_key.clone())
                        .or_insert_with(ServiceStats::new);
                    entry.span_count += 1;
                    if is_error {
                        entry.error_count += 1;
                    }
                    entry.durations.push(duration);
                    entry.earliest_start = entry.earliest_start.min(start_time);
                    entry.latest_end = entry.latest_end.max(end_time);

                    span_map.insert(SpanKey { trace_id, span_id }, service_key.clone());
                    span_infos.push(SpanInfo {
                        service: service_key.clone(),
                        parent_span_id: parse_parent_span_id(span),
                        trace_id,
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
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(TraceStats {
        services,
        edges,
        incoming,
    })
}

pub fn baseline_heuristic(stats: &TraceStats) -> Vec<BaselineEntry> {
    let mut latency_medians: Vec<u64> = Vec::new();
    for stat in stats.services.values() {
        latency_medians.push(percentile(&stat.durations, 50));
    }
    let latency_baseline = median(&mut latency_medians);
    let mad_baseline = median_absolute_deviation(latency_medians.as_slice(), latency_baseline)
        .max(latency_baseline)
        .max(1);

    let mut entries = Vec::new();
    for (service, stat) in &stats.services {
        let median_latency = percentile(&stat.durations, 50);
        let latency_delta = median_latency.saturating_sub(latency_baseline);
        let latency_score = ratio_micros(latency_delta, mad_baseline);
        let error_rate = ratio_micros(stat.error_count, stat.span_count);
        let score = weighted_average(
            &[(error_rate, 600_000), (latency_score, 400_000)],
            1_000_000,
        );
        entries.push(BaselineEntry {
            service: service.clone(),
            score_micros: score as i64,
        });
    }

    entries.sort_by(compare_entries);
    entries
}

pub fn baseline_graph(stats: &TraceStats) -> Vec<BaselineEntry> {
    let mut max_degree = 0u64;
    for service in stats.services.keys() {
        let out_degree = stats
            .edges
            .get(service)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        let in_degree = stats
            .incoming
            .get(service)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        max_degree = max_degree.max(out_degree + in_degree);
    }

    let mut entries = Vec::new();
    for service in stats.services.keys() {
        let out_degree = stats
            .edges
            .get(service)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        let in_degree = stats
            .incoming
            .get(service)
            .map(|s| s.len() as u64)
            .unwrap_or(0);
        let score = if max_degree > 0 {
            ratio_micros(out_degree + in_degree, max_degree)
        } else {
            0
        };
        entries.push(BaselineEntry {
            service: service.clone(),
            score_micros: score as i64,
        });
    }

    entries.sort_by(compare_entries);
    entries
}

fn compare_entries(a: &BaselineEntry, b: &BaselineEntry) -> Ordering {
    match b.score_micros.cmp(&a.score_micros) {
        Ordering::Equal => {
            let name_cmp = a.service.name.cmp(&b.service.name);
            if name_cmp != Ordering::Equal {
                return name_cmp;
            }
            a.service.namespace.cmp(&b.service.namespace)
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

fn median_absolute_deviation(values: &[u64], median: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut deviations: Vec<u64> = values.iter().map(|value| value.abs_diff(median)).collect();
    deviations.sort_unstable();
    deviations[deviations.len() / 2]
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

#[derive(Debug, Clone)]
struct SpanInfo {
    service: ServiceKey,
    parent_span_id: Option<[u8; 8]>,
    trace_id: [u8; 16],
}
