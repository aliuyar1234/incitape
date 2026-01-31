use crate::redaction::{LeakageScanner, RedactionEngine};
use incitape_core::{AppError, AppResult};
use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
use opentelemetry_proto::tonic::collector::metrics::v1::ExportMetricsServiceRequest;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::logs::v1::LogRecord;
use opentelemetry_proto::tonic::metrics::v1::metric::Data;
use opentelemetry_proto::tonic::metrics::v1::{
    Exemplar, ExponentialHistogram, ExponentialHistogramDataPoint, Gauge, Histogram,
    HistogramDataPoint, Metric, NumberDataPoint, Sum, Summary, SummaryDataPoint,
};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{span::Event, span::Link, Span};
use prost::Message;

pub fn redact_trace_request(bytes: &[u8], engine: &RedactionEngine) -> AppResult<Vec<u8>> {
    let mut req = ExportTraceServiceRequest::decode(bytes)
        .map_err(|e| AppError::validation(format!("otlp trace decode error: {e}")))?;
    let mut visitor = RedactVisitor { engine };
    apply_trace_request(&mut req, &mut visitor);
    encode(req, "otlp trace encode")
}

pub fn redact_metrics_request(bytes: &[u8], engine: &RedactionEngine) -> AppResult<Vec<u8>> {
    let mut req = ExportMetricsServiceRequest::decode(bytes)
        .map_err(|e| AppError::validation(format!("otlp metrics decode error: {e}")))?;
    let mut visitor = RedactVisitor { engine };
    apply_metrics_request(&mut req, &mut visitor);
    encode(req, "otlp metrics encode")
}

pub fn redact_logs_request(bytes: &[u8], engine: &RedactionEngine) -> AppResult<Vec<u8>> {
    let mut req = ExportLogsServiceRequest::decode(bytes)
        .map_err(|e| AppError::validation(format!("otlp logs decode error: {e}")))?;
    let mut visitor = RedactVisitor { engine };
    apply_logs_request(&mut req, &mut visitor);
    encode(req, "otlp logs encode")
}

pub fn scan_trace_request(bytes: &[u8], scanner: &LeakageScanner) -> AppResult<u64> {
    let mut req = ExportTraceServiceRequest::decode(bytes)
        .map_err(|e| AppError::validation(format!("otlp trace decode error: {e}")))?;
    let mut visitor = ScanVisitor::new(scanner);
    apply_trace_request(&mut req, &mut visitor);
    Ok(visitor.count)
}

pub fn scan_metrics_request(bytes: &[u8], scanner: &LeakageScanner) -> AppResult<u64> {
    let mut req = ExportMetricsServiceRequest::decode(bytes)
        .map_err(|e| AppError::validation(format!("otlp metrics decode error: {e}")))?;
    let mut visitor = ScanVisitor::new(scanner);
    apply_metrics_request(&mut req, &mut visitor);
    Ok(visitor.count)
}

pub fn scan_logs_request(bytes: &[u8], scanner: &LeakageScanner) -> AppResult<u64> {
    let mut req = ExportLogsServiceRequest::decode(bytes)
        .map_err(|e| AppError::validation(format!("otlp logs decode error: {e}")))?;
    let mut visitor = ScanVisitor::new(scanner);
    apply_logs_request(&mut req, &mut visitor);
    Ok(visitor.count)
}

fn encode<T: Message>(message: T, context: &str) -> AppResult<Vec<u8>> {
    let mut buf = Vec::new();
    message
        .encode(&mut buf)
        .map_err(|e| AppError::internal(format!("{context} error: {e}")))?;
    Ok(buf)
}

trait AnyValueVisitor {
    fn visit_string(&mut self, value: &mut String);
    fn visit_bytes(&mut self, value: &mut Vec<u8>);
}

struct RedactVisitor<'a> {
    engine: &'a RedactionEngine,
}

impl AnyValueVisitor for RedactVisitor<'_> {
    fn visit_string(&mut self, value: &mut String) {
        *value = self.engine.redact_str(value);
    }

    fn visit_bytes(&mut self, value: &mut Vec<u8>) {
        *value = self.engine.redact_bytes(value);
    }
}

struct ScanVisitor<'a> {
    scanner: &'a LeakageScanner,
    count: u64,
}

impl<'a> ScanVisitor<'a> {
    fn new(scanner: &'a LeakageScanner) -> Self {
        Self { scanner, count: 0 }
    }
}

impl AnyValueVisitor for ScanVisitor<'_> {
    fn visit_string(&mut self, value: &mut String) {
        self.count = self.count.saturating_add(self.scanner.scan_str(value));
    }

    fn visit_bytes(&mut self, value: &mut Vec<u8>) {
        self.count = self.count.saturating_add(self.scanner.scan_bytes(value));
    }
}

fn apply_trace_request(req: &mut ExportTraceServiceRequest, visitor: &mut impl AnyValueVisitor) {
    for resource_span in &mut req.resource_spans {
        visit_resource(resource_span.resource.as_mut(), visitor);
        for scope_span in &mut resource_span.scope_spans {
            visit_scope(scope_span.scope.as_mut(), visitor);
            for span in &mut scope_span.spans {
                visit_span(span, visitor);
            }
        }
    }
}

fn apply_metrics_request(
    req: &mut ExportMetricsServiceRequest,
    visitor: &mut impl AnyValueVisitor,
) {
    for resource_metrics in &mut req.resource_metrics {
        visit_resource(resource_metrics.resource.as_mut(), visitor);
        for scope_metrics in &mut resource_metrics.scope_metrics {
            visit_scope(scope_metrics.scope.as_mut(), visitor);
            for metric in &mut scope_metrics.metrics {
                visit_metric(metric, visitor);
            }
        }
    }
}

fn apply_logs_request(req: &mut ExportLogsServiceRequest, visitor: &mut impl AnyValueVisitor) {
    for resource_logs in &mut req.resource_logs {
        visit_resource(resource_logs.resource.as_mut(), visitor);
        for scope_logs in &mut resource_logs.scope_logs {
            visit_scope(scope_logs.scope.as_mut(), visitor);
            for record in &mut scope_logs.log_records {
                visit_log_record(record, visitor);
            }
        }
    }
}

fn visit_resource(resource: Option<&mut Resource>, visitor: &mut impl AnyValueVisitor) {
    if let Some(resource) = resource {
        visit_key_values(&mut resource.attributes, visitor);
    }
}

fn visit_scope(
    scope: Option<&mut opentelemetry_proto::tonic::common::v1::InstrumentationScope>,
    visitor: &mut impl AnyValueVisitor,
) {
    if let Some(scope) = scope {
        visit_key_values(&mut scope.attributes, visitor);
    }
}

fn visit_span(span: &mut Span, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut span.attributes, visitor);
    for event in &mut span.events {
        visit_event(event, visitor);
    }
    for link in &mut span.links {
        visit_link(link, visitor);
    }
}

fn visit_event(event: &mut Event, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut event.attributes, visitor);
}

fn visit_link(link: &mut Link, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut link.attributes, visitor);
}

fn visit_log_record(record: &mut LogRecord, visitor: &mut impl AnyValueVisitor) {
    if let Some(body) = record.body.as_mut() {
        visit_any_value(body, visitor);
    }
    visit_key_values(&mut record.attributes, visitor);
}

fn visit_metric(metric: &mut Metric, visitor: &mut impl AnyValueVisitor) {
    if let Some(data) = metric.data.as_mut() {
        match data {
            Data::Gauge(Gauge { data_points }) => {
                for point in data_points {
                    visit_number_data_point(point, visitor);
                }
            }
            Data::Sum(Sum { data_points, .. }) => {
                for point in data_points {
                    visit_number_data_point(point, visitor);
                }
            }
            Data::Histogram(Histogram { data_points, .. }) => {
                for point in data_points {
                    visit_histogram_data_point(point, visitor);
                }
            }
            Data::ExponentialHistogram(ExponentialHistogram { data_points, .. }) => {
                for point in data_points {
                    visit_exponential_histogram_data_point(point, visitor);
                }
            }
            Data::Summary(Summary { data_points }) => {
                for point in data_points {
                    visit_summary_data_point(point, visitor);
                }
            }
        }
    }
}

fn visit_number_data_point(point: &mut NumberDataPoint, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut point.attributes, visitor);
    for exemplar in &mut point.exemplars {
        visit_exemplar(exemplar, visitor);
    }
}

fn visit_histogram_data_point(point: &mut HistogramDataPoint, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut point.attributes, visitor);
    for exemplar in &mut point.exemplars {
        visit_exemplar(exemplar, visitor);
    }
}

fn visit_exponential_histogram_data_point(
    point: &mut ExponentialHistogramDataPoint,
    visitor: &mut impl AnyValueVisitor,
) {
    visit_key_values(&mut point.attributes, visitor);
    for exemplar in &mut point.exemplars {
        visit_exemplar(exemplar, visitor);
    }
}

fn visit_summary_data_point(point: &mut SummaryDataPoint, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut point.attributes, visitor);
}

fn visit_exemplar(exemplar: &mut Exemplar, visitor: &mut impl AnyValueVisitor) {
    visit_key_values(&mut exemplar.filtered_attributes, visitor);
}

fn visit_key_values(values: &mut Vec<KeyValue>, visitor: &mut impl AnyValueVisitor) {
    for kv in values {
        if let Some(value) = kv.value.as_mut() {
            visit_any_value(value, visitor);
        }
    }
}

fn visit_any_value(value: &mut AnyValue, visitor: &mut impl AnyValueVisitor) {
    match value.value.as_mut() {
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::StringValue(s)) => {
            visitor.visit_string(s);
        }
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::BytesValue(bytes)) => {
            visitor.visit_bytes(bytes);
        }
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::ArrayValue(arr)) => {
            for item in &mut arr.values {
                visit_any_value(item, visitor);
            }
        }
        Some(opentelemetry_proto::tonic::common::v1::any_value::Value::KvlistValue(kvlist)) => {
            visit_key_values(&mut kvlist.values, visitor);
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionRuleset;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::metrics::v1::{
        metric::Data, NumberDataPoint, ResourceMetrics, ScopeMetrics,
    };
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};

    fn kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(AnyValue {
                value: Some(AnyValueInner::StringValue(value.to_string())),
            }),
        }
    }

    #[test]
    fn redact_trace_attributes() {
        let engine = RedactionEngine::new(RedactionRuleset::safe_default().unwrap());
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![kv("token", "Bearer abcdefghijklmnopqrstuvwxyz")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![Span {
                        trace_id: vec![1; 16],
                        span_id: vec![2; 8],
                        trace_state: String::new(),
                        parent_span_id: vec![],
                        flags: 0,
                        name: "span".to_string(),
                        kind: 0,
                        start_time_unix_nano: 0,
                        end_time_unix_nano: 0,
                        attributes: vec![kv("auth", "Bearer abcdefghijklmnopqrstuvwxyz")],
                        dropped_attributes_count: 0,
                        events: vec![],
                        dropped_events_count: 0,
                        links: vec![],
                        dropped_links_count: 0,
                        status: None,
                    }],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let bytes = encode(req.clone(), "encode").unwrap();
        let redacted = redact_trace_request(&bytes, &engine).unwrap();
        let decoded = ExportTraceServiceRequest::decode(redacted.as_slice()).unwrap();
        let attrs = &decoded.resource_spans[0]
            .resource
            .as_ref()
            .unwrap()
            .attributes;
        let value = attrs[0].value.as_ref().unwrap();
        if let Some(AnyValueInner::StringValue(s)) = &value.value {
            assert!(s.contains("REDACTED"));
        } else {
            panic!("expected string redaction");
        }
        let span_attr = &decoded.resource_spans[0].scope_spans[0].spans[0].attributes[0]
            .value
            .as_ref()
            .unwrap();
        if let Some(AnyValueInner::StringValue(s)) = &span_attr.value {
            assert!(s.contains("REDACTED"));
        } else {
            panic!("expected string redaction");
        }
    }

    #[test]
    fn redact_logs_body() {
        let engine = RedactionEngine::new(RedactionRuleset::safe_default().unwrap());
        let log_record = LogRecord {
            time_unix_nano: 0,
            observed_time_unix_nano: 0,
            severity_number: 0,
            severity_text: String::new(),
            body: Some(AnyValue {
                value: Some(AnyValueInner::StringValue(
                    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz".to_string(),
                )),
            }),
            attributes: vec![],
            dropped_attributes_count: 0,
            flags: 0,
            trace_id: vec![],
            span_id: vec![],
            event_name: String::new(),
        };

        let req = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Some(Resource {
                    attributes: vec![kv("k", "Bearer abcdefghijklmnopqrstuvwxyz")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_logs: vec![ScopeLogs {
                    scope: None,
                    log_records: vec![log_record],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let bytes = encode(req, "encode").unwrap();
        let redacted = redact_logs_request(&bytes, &engine).unwrap();
        let decoded = ExportLogsServiceRequest::decode(redacted.as_slice()).unwrap();
        let body = decoded.resource_logs[0].scope_logs[0].log_records[0]
            .body
            .as_ref()
            .unwrap();
        if let Some(AnyValueInner::StringValue(s)) = &body.value {
            assert!(s.contains("REDACTED"));
        } else {
            panic!("expected string redaction");
        }
    }

    #[test]
    fn redact_metrics_attributes() {
        let engine = RedactionEngine::new(RedactionRuleset::safe_default().unwrap());
        let data_point = NumberDataPoint {
            attributes: vec![kv("token", "Bearer abcdefghijklmnopqrstuvwxyz")],
            start_time_unix_nano: 0,
            time_unix_nano: 0,
            exemplars: vec![],
            flags: 0,
            value: None,
        };
        let metric = Metric {
            name: "requests".to_string(),
            description: String::new(),
            unit: String::new(),
            metadata: Vec::new(),
            data: Some(Data::Gauge(Gauge {
                data_points: vec![data_point],
            })),
        };

        let req = ExportMetricsServiceRequest {
            resource_metrics: vec![ResourceMetrics {
                resource: Some(Resource {
                    attributes: vec![kv("k", "Bearer abcdefghijklmnopqrstuvwxyz")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_metrics: vec![ScopeMetrics {
                    scope: None,
                    metrics: vec![metric],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            }],
        };

        let bytes = encode(req, "encode").unwrap();
        let redacted = redact_metrics_request(&bytes, &engine).unwrap();
        let decoded = ExportMetricsServiceRequest::decode(redacted.as_slice()).unwrap();
        let attr = &decoded.resource_metrics[0].scope_metrics[0].metrics[0]
            .data
            .as_ref()
            .unwrap();
        if let Data::Gauge(Gauge { data_points }) = attr {
            let value = data_points[0].attributes[0].value.as_ref().unwrap();
            if let Some(AnyValueInner::StringValue(s)) = &value.value {
                assert!(s.contains("REDACTED"));
            } else {
                panic!("expected string redaction");
            }
        } else {
            panic!("expected gauge");
        }
    }

    #[test]
    fn scan_detects_leakage_in_trace() {
        let scanner = LeakageScanner::new(RedactionRuleset::safe_default().unwrap());
        let req = ExportTraceServiceRequest {
            resource_spans: vec![ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![kv("token", "Bearer abcdefghijklmnopqrstuvwxyz")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![],
                schema_url: String::new(),
            }],
        };

        let bytes = encode(req, "encode").unwrap();
        let count = scan_trace_request(&bytes, &scanner).unwrap();
        assert!(count > 0);
    }
}
