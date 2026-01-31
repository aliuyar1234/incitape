use assert_cmd::Command;
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
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(OtlpAnyValue {
            value: Some(AnyValueInner::StringValue(value.to_string())),
        }),
    }
}

fn write_minimal_tape(tape_dir: &Path) {
    fs::create_dir_all(tape_dir).unwrap();
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
fn analyze_writes_analysis_json() {
    let temp = tempdir().unwrap();
    let tape_dir = temp.path().join("tape");
    write_minimal_tape(&tape_dir);

    let mut cmd = Command::new(assert_cmd::cargo_bin!("incitape"));
    cmd.arg("analyze").arg(&tape_dir);
    cmd.assert().success();

    assert!(tape_dir.join("analysis.json").exists());
}

#[test]
fn analyze_refuses_overwrite_without_flag() {
    let temp = tempdir().unwrap();
    let tape_dir = temp.path().join("tape");
    write_minimal_tape(&tape_dir);

    let analysis_path = tape_dir.join("analysis.json");
    fs::write(&analysis_path, "sentinel").unwrap();

    let mut cmd = Command::new(assert_cmd::cargo_bin!("incitape"));
    cmd.arg("analyze").arg(&tape_dir);
    cmd.assert().failure().code(2);

    let contents = fs::read_to_string(&analysis_path).unwrap();
    assert_eq!(contents, "sentinel");
}
