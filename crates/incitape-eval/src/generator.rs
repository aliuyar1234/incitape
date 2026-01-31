use crate::suite::{EvalSuiteConfig, FaultKind, ScenarioConfig};
use incitape_core::{AppError, AppResult};
use incitape_redaction::{redact_trace_request, RedactionEngine, RedactionRuleset};
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::write_checksums;
use incitape_tape::manifest::{
    Capture, Fault, FaultParams, GroundTruth, GroundTruthTarget, Manifest, Redaction,
};
use incitape_tape::record::RecordType;
use incitape_tape::tape_id::compute_tape_id;
use incitape_tape::writer::TapeWriter;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use opentelemetry_proto::tonic::common::v1::any_value::Value as AnyValueInner;
use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue};
use opentelemetry_proto::tonic::resource::v1::Resource;
use opentelemetry_proto::tonic::trace::v1::{ResourceSpans, ScopeSpans, Span, Status};
use prost::Message;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::fs;
use std::path::{Path, PathBuf};

const BASE_TIME_UNIX_NANO: u64 = 1_700_000_000_000_000_000;

pub fn generate_suite(suite_path: &Path, out_dir: &Path, overwrite: bool) -> AppResult<()> {
    let suite = EvalSuiteConfig::load(suite_path)?;
    ensure_out_dir(&suite, out_dir)?;
    fs::create_dir_all(out_dir)
        .map_err(|e| AppError::internal(format!("failed to create eval output dir: {e}")))?;

    for scenario in &suite.scenarios {
        generate_scenario(out_dir, scenario, overwrite)?;
    }
    Ok(())
}

fn ensure_out_dir(suite: &EvalSuiteConfig, out_dir: &Path) -> AppResult<()> {
    let suite_dir = normalize_path(&suite.tapes_dir)?;
    let out_dir = normalize_path(out_dir)?;
    if suite_dir != out_dir {
        return Err(AppError::usage(
            "eval generate --out must match suite.tapes_dir",
        ));
    }
    Ok(())
}

fn normalize_path(path: &Path) -> AppResult<PathBuf> {
    if path.is_absolute() {
        return Ok(clean_path(path));
    }
    let cwd = std::env::current_dir()
        .map_err(|e| AppError::internal(format!("failed to read cwd: {e}")))?;
    Ok(clean_path(&cwd.join(path)))
}

fn clean_path(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn generate_scenario(out_dir: &Path, scenario: &ScenarioConfig, overwrite: bool) -> AppResult<()> {
    let final_dir = out_dir.join(&scenario.id);
    if final_dir.exists() {
        if !overwrite {
            return Err(AppError::usage(format!(
                "scenario {} already exists; use --overwrite",
                scenario.id
            )));
        }
        fs::remove_dir_all(&final_dir).map_err(|e| {
            AppError::internal(format!("failed to remove existing scenario dir: {e}"))
        })?;
    }

    let partial_dir = out_dir.join(format!("{}.partial", scenario.id));
    if partial_dir.exists() {
        fs::remove_dir_all(&partial_dir).map_err(|e| {
            AppError::internal(format!("failed to remove existing partial dir: {e}"))
        })?;
    }
    fs::create_dir_all(&partial_dir)
        .map_err(|e| AppError::internal(format!("failed to create scenario dir: {e}")))?;

    write_scenario_tape(&partial_dir, scenario)?;
    fs::rename(&partial_dir, &final_dir)
        .map_err(|e| AppError::internal(format!("failed to finalize scenario dir: {e}")))?;
    Ok(())
}

fn write_scenario_tape(tape_dir: &Path, scenario: &ScenarioConfig) -> AppResult<()> {
    let ruleset = RedactionRuleset::safe_default()?;
    let engine = RedactionEngine::new(ruleset.clone());
    let mut writer = TapeWriter::create(&tape_dir.join("tape.tape.zst"), Bounds::default())?;
    let mut rng = ChaCha8Rng::seed_from_u64(scenario.seed);

    for trace_idx in 0..scenario.traces {
        let (req, capture_time) = build_trace_request(scenario, trace_idx, &mut rng)?;
        let mut buf = Vec::new();
        req.encode(&mut buf)
            .map_err(|e| AppError::internal(format!("trace encode error: {e}")))?;
        let redacted = redact_trace_request(&buf, &engine)?;
        writer.write_record(RecordType::Traces, capture_time, &redacted)?;
    }
    writer.finish()?;

    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest = Manifest {
        tape_version: 1,
        tape_id: tape_id.clone(),
        capture: Capture {
            started_at_rfc3339: "2025-01-01T00:00:00Z".to_string(),
            ended_at_rfc3339: "2025-01-01T00:00:01Z".to_string(),
            source: "eval_generator".to_string(),
        },
        redaction: Redaction {
            profile: "safe_default".to_string(),
            ruleset_sha256: ruleset.ruleset_sha256(),
            applied: true,
        },
        ground_truth: Some(GroundTruth {
            root_cause: GroundTruthTarget {
                kind: "service".to_string(),
                name: service_name(scenario.fault.target_index),
                namespace: String::new(),
            },
            faults: vec![Fault {
                at_capture_time_unix_nano: BASE_TIME_UNIX_NANO,
                kind: fault_kind_label(&scenario.fault.kind),
                target: GroundTruthTarget {
                    kind: "service".to_string(),
                    name: service_name(scenario.fault.target_index),
                    namespace: String::new(),
                },
                params: FaultParams {
                    added_latency_ms: scenario.fault.added_latency_ms,
                },
            }],
        }),
        derived_from: None,
    };
    manifest.write(&tape_dir.join("manifest.yaml"))?;
    write_checksums(tape_dir, &["manifest.yaml", "tape.tape.zst"])?;
    Ok(())
}

fn build_trace_request(
    scenario: &ScenarioConfig,
    trace_idx: u32,
    rng: &mut ChaCha8Rng,
) -> AppResult<(ExportTraceServiceRequest, u64)> {
    let trace_id = next_trace_id(rng);
    let mut span_ids = Vec::new();
    for _ in 0..scenario.services {
        span_ids.push(next_span_id(rng));
    }

    let capture_time = BASE_TIME_UNIX_NANO + (trace_idx as u64) * 1_000_000_000;
    let mut resource_spans = Vec::new();
    for service_idx in 0..scenario.services {
        let parent = if service_idx == 0 {
            None
        } else {
            let parent_idx = (service_idx - 1) / scenario.fanout;
            Some(span_ids[parent_idx as usize])
        };
        let (duration_micros, is_error) = span_behavior(scenario, service_idx, trace_idx, rng);
        let start_nano = BASE_TIME_UNIX_NANO
            + (trace_idx as u64) * 1_000_000_000
            + (service_idx as u64) * 1_000_000;
        let end_nano = start_nano + duration_micros * 1_000;
        let mut attributes = Vec::new();
        if scenario.inject_secret && service_idx == scenario.fault.target_index {
            attributes.push(kv("auth", "Bearer abcdefghijklmnopqrstuvwxyz"));
        }
        let span = Span {
            trace_id: trace_id.to_vec(),
            span_id: span_ids[service_idx as usize].to_vec(),
            trace_state: String::new(),
            parent_span_id: parent.map(|p| p.to_vec()).unwrap_or_default(),
            flags: 0,
            name: format!("op-{}", service_idx),
            kind: 0,
            start_time_unix_nano: start_nano,
            end_time_unix_nano: end_nano,
            attributes,
            dropped_attributes_count: 0,
            events: Vec::new(),
            dropped_events_count: 0,
            links: Vec::new(),
            dropped_links_count: 0,
            status: Some(Status {
                message: String::new(),
                code: if is_error { 2 } else { 0 },
            }),
        };

        let resource = Resource {
            attributes: vec![kv("service.name", &service_name(service_idx))],
            dropped_attributes_count: 0,
            entity_refs: Vec::new(),
        };
        let scope_spans = ScopeSpans {
            scope: None,
            spans: vec![span],
            schema_url: String::new(),
        };
        resource_spans.push(ResourceSpans {
            resource: Some(resource),
            scope_spans: vec![scope_spans],
            schema_url: String::new(),
        });
    }

    Ok((ExportTraceServiceRequest { resource_spans }, capture_time))
}

fn span_behavior(
    scenario: &ScenarioConfig,
    service_idx: u32,
    trace_idx: u32,
    rng: &mut ChaCha8Rng,
) -> (u64, bool) {
    let base = 1_000 + (service_idx as u64) * 200 + (rng.next_u32() % 200) as u64;
    let mut duration = base;
    let mut is_error = false;
    if service_idx == scenario.fault.target_index {
        let rate = scenario.fault.rate_percent();
        let roll = rng.next_u32() % 100;
        if roll < rate {
            match scenario.fault.kind {
                FaultKind::Latency => {
                    duration = duration.saturating_add(
                        scenario
                            .fault
                            .added_latency_ms
                            .unwrap_or(0)
                            .saturating_mul(1_000),
                    );
                }
                FaultKind::Error => {
                    is_error = true;
                }
            }
        }
    }
    let _ = trace_idx;
    (duration, is_error)
}

fn next_trace_id(rng: &mut ChaCha8Rng) -> [u8; 16] {
    let mut out = [0u8; 16];
    rng.fill_bytes(&mut out);
    out
}

fn next_span_id(rng: &mut ChaCha8Rng) -> [u8; 8] {
    let mut out = [0u8; 8];
    rng.fill_bytes(&mut out);
    out
}

fn kv(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(AnyValueInner::StringValue(value.to_string())),
        }),
    }
}

fn service_name(index: u32) -> String {
    format!("svc-{index}")
}

fn fault_kind_label(kind: &FaultKind) -> String {
    match kind {
        FaultKind::Latency => "latency_injection".to_string(),
        FaultKind::Error => "error_injection".to_string(),
    }
}
