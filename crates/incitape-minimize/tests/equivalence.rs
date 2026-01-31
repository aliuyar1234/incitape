use incitape_analyzer::{analyze_tape_dir, analyze_tape_dir_to_output, AnalyzerConfig};
use incitape_minimize::{minimize_tape_dir, MinimizePolicy};
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::write_checksums;
use incitape_tape::manifest::{Capture, Manifest, Redaction};
use incitape_tape::record::RecordType;
use incitape_tape::tape_id::compute_tape_id;
use incitape_tape::writer::TapeWriter;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;
use opentelemetry_proto::tonic::common::v1::AnyValue as OtlpAnyValue;
use opentelemetry_proto::tonic::common::v1::KeyValue;
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
use prost::Message;
use tempfile::tempdir;

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(OtlpAnyValue {
            value: Some(AnyValueInner::StringValue(value.to_string())),
        }),
    }
}

fn write_two_service_tape(tape_dir: &std::path::Path) {
    std::fs::create_dir_all(tape_dir).unwrap();
    let mut writer =
        TapeWriter::create(&tape_dir.join("tape.tape.zst"), Bounds::default()).unwrap();

    let trace_id = vec![1; 16];
    let root_span_id = vec![1; 8];
    let child_span_id = vec![2; 8];

    let root_span = Span {
        trace_id: trace_id.clone(),
        span_id: root_span_id.clone(),
        trace_state: String::new(),
        parent_span_id: vec![],
        flags: 0,
        name: "root".to_string(),
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
            code: 0,
        }),
    };
    let child_span = Span {
        trace_id: trace_id.clone(),
        span_id: child_span_id.clone(),
        trace_state: String::new(),
        parent_span_id: root_span_id.clone(),
        flags: 0,
        name: "child".to_string(),
        kind: 0,
        start_time_unix_nano: 12,
        end_time_unix_nano: 30,
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
        resource_spans: vec![
            ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![kv("service.name", "frontend")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![root_span],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            },
            ResourceSpans {
                resource: Some(Resource {
                    attributes: vec![kv("service.name", "checkout")],
                    dropped_attributes_count: 0,
                    entity_refs: Vec::new(),
                }),
                scope_spans: vec![ScopeSpans {
                    scope: None,
                    spans: vec![child_span],
                    schema_url: String::new(),
                }],
                schema_url: String::new(),
            },
        ],
    };
    let mut buf = Vec::new();
    req.encode(&mut buf).unwrap();
    writer.write_record(RecordType::Traces, 1, &buf).unwrap();
    writer.finish().unwrap();

    let tape_id = compute_tape_id(&tape_dir.join("tape.tape.zst")).unwrap();
    let manifest = Manifest {
        tape_version: 1,
        tape_id,
        capture: Capture {
            started_at_rfc3339: "2025-01-01T00:00:00Z".to_string(),
            ended_at_rfc3339: "2025-01-01T00:00:01Z".to_string(),
            source: "otlp_receiver".to_string(),
        },
        redaction: Redaction {
            profile: "safe_default".to_string(),
            ruleset_sha256: "0".repeat(64),
            applied: true,
        },
        ground_truth: None,
        derived_from: None,
    };
    manifest.write(&tape_dir.join("manifest.yaml")).unwrap();
    write_checksums(tape_dir, &["manifest.yaml", "tape.tape.zst"]).unwrap();
}

#[test]
fn minimize_preserves_top1() {
    let temp = tempdir().unwrap();
    let tape_dir = temp.path().join("tape");
    write_two_service_tape(&tape_dir);

    let analyze_path = tape_dir.join("analysis.json");
    analyze_tape_dir(&tape_dir, AnalyzerConfig::new(5).unwrap(), &analyze_path).unwrap();

    let minimized = temp.path().join("min");
    let policy = MinimizePolicy::new(1, 0, true).unwrap();
    minimize_tape_dir(&tape_dir, &minimized, policy, true).unwrap();

    let original = analyze_tape_dir_to_output(&tape_dir, AnalyzerConfig::new(5).unwrap()).unwrap();
    let minimized_output =
        analyze_tape_dir_to_output(&minimized, AnalyzerConfig::new(5).unwrap()).unwrap();

    let orig_top = original.ranking.first().map(|e| e.entity.name.clone());
    let min_top = minimized_output
        .ranking
        .first()
        .map(|e| e.entity.name.clone());
    assert_eq!(orig_top, min_top);
}
