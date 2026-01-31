use incitape_core::{AppError, AppResult};
use incitape_tape::record::{RecordType, TapeRecord};
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValue;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use prost::Message;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayFilter {
    pub record_type: Option<RecordType>,
    pub service: Option<String>,
    pub trace_id: Option<[u8; 16]>,
}

impl ReplayFilter {
    pub fn parse(input: &str) -> AppResult<Self> {
        let value = input.trim();
        if value.is_empty() {
            return Err(AppError::usage("filter expression is empty"));
        }
        let mut filter = ReplayFilter::default();
        for part in value.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(AppError::usage("filter expression contains empty segment"));
            }
            let mut iter = part.splitn(2, '=');
            let key = iter
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::usage("filter key is missing"))?;
            let value = iter
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| AppError::usage("filter value is missing"))?;
            match key {
                "record_type" => {
                    if filter.record_type.is_some() {
                        return Err(AppError::usage(
                            "record_type filter specified more than once",
                        ));
                    }
                    filter.record_type = Some(parse_record_type(value)?);
                }
                "service" => {
                    if filter.service.is_some() {
                        return Err(AppError::usage("service filter specified more than once"));
                    }
                    filter.service = Some(value.to_string());
                }
                "trace_id" => {
                    if filter.trace_id.is_some() {
                        return Err(AppError::usage("trace_id filter specified more than once"));
                    }
                    filter.trace_id = Some(parse_trace_id(value)?);
                }
                _ => {
                    return Err(AppError::usage(format!("unknown filter key '{key}'")));
                }
            }
        }
        Ok(filter)
    }

    pub fn matches(&self, record: &TapeRecord) -> AppResult<bool> {
        if let Some(expected) = self.record_type {
            if record.record_type != expected {
                return Ok(false);
            }
        }

        if self.service.is_none() && self.trace_id.is_none() {
            return Ok(true);
        }

        if record.record_type != RecordType::Traces {
            return Ok(false);
        }

        let request = ExportTraceServiceRequest::decode(record.otlp_payload_bytes.as_slice())
            .map_err(|e| AppError::validation(format!("trace decode error: {e}")))?;

        let mut service_match = self.service.is_none();
        let mut trace_match = self.trace_id.is_none();

        for resource_spans in &request.resource_spans {
            let resource_service = resource_spans
                .resource
                .as_ref()
                .and_then(|resource| extract_service_name(&resource.attributes));

            let service_ok = match (&self.service, resource_service) {
                (Some(expected), Some(actual)) => expected == &actual,
                (Some(_), None) => false,
                (None, _) => true,
            };

            if service_ok {
                if self.service.is_some() {
                    service_match = true;
                }
                if let Some(expected_trace_id) = self.trace_id {
                    if resource_spans.scope_spans.iter().any(|scope| {
                        scope
                            .spans
                            .iter()
                            .any(|span| span.trace_id.as_slice() == expected_trace_id.as_slice())
                    }) {
                        trace_match = true;
                    }
                }
            }

            if service_match && trace_match {
                return Ok(true);
            }
        }

        Ok(service_match && trace_match)
    }
}

fn parse_record_type(value: &str) -> AppResult<RecordType> {
    match value.to_ascii_uppercase().as_str() {
        "TRACES" => Ok(RecordType::Traces),
        "METRICS" => Ok(RecordType::Metrics),
        "LOGS" => Ok(RecordType::Logs),
        _ => Err(AppError::usage(format!(
            "invalid record_type '{value}'; expected TRACES|METRICS|LOGS"
        ))),
    }
}

fn parse_trace_id(value: &str) -> AppResult<[u8; 16]> {
    let cleaned = value.trim().to_ascii_lowercase();
    let bytes = hex::decode(&cleaned).map_err(|_| AppError::usage("trace_id must be hex"))?;
    if bytes.len() != 16 {
        return Err(AppError::usage("trace_id must be 16 bytes hex"));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn extract_service_name(attributes: &[KeyValue]) -> Option<String> {
    for kv in attributes {
        if kv.key == "service.name" {
            if let Some(AnyValue::StringValue(s)) = kv.value.as_ref().and_then(|v| v.value.as_ref())
            {
                return Some(s.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use incitape_tape::bounds::Bounds;
    use incitape_tape::record::TapeRecord;
    use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;
    use opentelemetry_proto::tonic::common::v1::AnyValue as OtlpAnyValue;
    use opentelemetry_proto::tonic::resource::v1::Resource;
    use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span};

    fn kv(key: &str, value: &str) -> KeyValue {
        KeyValue {
            key: key.to_string(),
            value: Some(OtlpAnyValue {
                value: Some(AnyValueInner::StringValue(value.to_string())),
            }),
        }
    }

    #[test]
    fn parse_filter_rejects_unknown_key() {
        let err = ReplayFilter::parse("foo=bar").unwrap_err();
        assert_eq!(err.kind(), incitape_core::ErrorKind::Usage);
    }

    #[test]
    fn filter_matches_service_and_trace_id() {
        let trace_id = [7u8; 16];
        let request = ExportTraceServiceRequest {
            resource_spans: vec![
                ResourceSpans {
                    resource: Some(Resource {
                        attributes: vec![kv("service.name", "checkout")],
                        dropped_attributes_count: 0,
                        entity_refs: Vec::new(),
                    }),
                    scope_spans: vec![ScopeSpans {
                        scope: None,
                        spans: vec![Span {
                            trace_id: trace_id.to_vec(),
                            span_id: vec![1; 8],
                            trace_state: String::new(),
                            parent_span_id: vec![],
                            flags: 0,
                            name: "span".to_string(),
                            kind: 0,
                            start_time_unix_nano: 0,
                            end_time_unix_nano: 0,
                            attributes: vec![],
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
                },
                ResourceSpans {
                    resource: Some(Resource {
                        attributes: vec![kv("service.name", "payments")],
                        dropped_attributes_count: 0,
                        entity_refs: Vec::new(),
                    }),
                    scope_spans: vec![],
                    schema_url: String::new(),
                },
            ],
        };

        let mut buf = Vec::new();
        request.encode(&mut buf).unwrap();
        let record = TapeRecord::new(RecordType::Traces, 0, buf, Bounds::default()).unwrap();

        let filter = ReplayFilter {
            record_type: None,
            service: Some("checkout".to_string()),
            trace_id: Some(trace_id),
        };
        assert!(filter.matches(&record).unwrap());

        let filter = ReplayFilter {
            record_type: None,
            service: Some("checkout".to_string()),
            trace_id: Some([1u8; 16]),
        };
        assert!(!filter.matches(&record).unwrap());
    }
}
