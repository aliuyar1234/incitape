use crate::policy::MinimizePolicy;
use incitape_analyzer::{analyze_tape_dir_to_output, AnalyzerConfig};
use incitape_core::{AppError, AppResult};
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::{verify_checksums, write_checksums};
use incitape_tape::manifest::Manifest;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::{RecordType, TapeRecord};
use incitape_tape::tape_id::compute_tape_id;
use incitape_tape::writer::TapeWriter;
use opentelemetry_proto::tonic::collector::trace::v1::ExportTraceServiceRequest;
use prost::Message;
use std::collections::BTreeSet;
use std::path::Path;

pub fn minimize_tape_dir(
    tape_dir: &Path,
    out_dir: &Path,
    policy: MinimizePolicy,
    overwrite: bool,
) -> AppResult<()> {
    ensure_not_partial(tape_dir)?;
    if !tape_dir.is_dir() {
        return Err(AppError::validation("tape_dir is not a directory"));
    }
    verify_checksums(tape_dir)?;

    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest = Manifest::load(&tape_dir.join("manifest.yaml"))?;
    manifest.validate(&tape_id)?;

    if out_dir.exists() {
        if !overwrite {
            return Err(AppError::usage(
                "minimize output dir exists; use --overwrite",
            ));
        }
        std::fs::remove_dir_all(out_dir)
            .map_err(|e| AppError::internal(format!("failed to remove output dir: {e}")))?;
    }
    std::fs::create_dir_all(out_dir)
        .map_err(|e| AppError::internal(format!("failed to create output dir: {e}")))?;

    let records = read_records(&tape_path)?;
    let analysis = load_or_analyze(tape_dir, policy.top_k)?;
    let trace_ids = collect_trace_ids(&analysis, policy.top_k)?;

    let mut selected_indices = Vec::with_capacity(records.len());
    let mut min_time: Option<u64> = None;
    let mut max_time: Option<u64> = None;

    for record in &records {
        let mut selected = false;
        if record.record_type == RecordType::Traces {
            selected = record_has_trace_id(record, &trace_ids)?;
        }
        if selected {
            min_time = Some(min_time.map_or(record.capture_time_unix_nano, |v| {
                v.min(record.capture_time_unix_nano)
            }));
            max_time = Some(max_time.map_or(record.capture_time_unix_nano, |v| {
                v.max(record.capture_time_unix_nano)
            }));
        }
        selected_indices.push(selected);
    }

    let (min_time, max_time) = match (min_time, max_time) {
        (Some(min), Some(max)) => (min, max),
        _ => return Err(AppError::validation("no traces matched evidence refs")),
    };

    let window_nanos = (policy.keep_window_secs as u64).saturating_mul(1_000_000_000);
    let window_start = min_time.saturating_sub(window_nanos);
    let window_end = max_time.saturating_add(window_nanos);

    let mut writer = TapeWriter::create(&out_dir.join("tape.tape.zst"), Bounds::default())?;
    for (idx, record) in records.iter().enumerate() {
        let in_window = record.capture_time_unix_nano >= window_start
            && record.capture_time_unix_nano <= window_end;
        let allow_record = record.record_type == RecordType::Traces || !policy.drop_logs_metrics;
        let include = selected_indices[idx] || (in_window && allow_record);
        if include {
            writer.write_record(
                record.record_type,
                record.capture_time_unix_nano,
                &record.otlp_payload_bytes,
            )?;
        }
    }
    writer.finish()?;

    let new_tape_id = compute_tape_id(&out_dir.join("tape.tape.zst"))?;
    let mut new_manifest = manifest.clone();
    new_manifest.tape_id = new_tape_id;
    new_manifest.derived_from = Some(tape_id);
    new_manifest.write(&out_dir.join("manifest.yaml"))?;
    write_checksums(out_dir, &["manifest.yaml", "tape.tape.zst"])?;
    Ok(())
}

fn read_records(path: &Path) -> AppResult<Vec<TapeRecord>> {
    let reader = TapeReader::open(path, Bounds::default())?;
    reader.read_all_sorted()
}

fn load_or_analyze(tape_dir: &Path, top_k: u32) -> AppResult<incitape_analyzer::AnalysisOutput> {
    let analysis_path = tape_dir.join("analysis.json");
    if analysis_path.exists() {
        let text = std::fs::read_to_string(&analysis_path)
            .map_err(|e| AppError::validation(format!("failed to read analysis.json: {e}")))?;
        let analysis: incitape_analyzer::AnalysisOutput = serde_json::from_str(&text)
            .map_err(|e| AppError::validation(format!("analysis.json parse error: {e}")))?;
        return Ok(analysis);
    }
    analyze_tape_dir_to_output(tape_dir, AnalyzerConfig::new(top_k)?)
}

fn collect_trace_ids(
    analysis: &incitape_analyzer::AnalysisOutput,
    top_k: u32,
) -> AppResult<BTreeSet<[u8; 16]>> {
    let mut ids = BTreeSet::new();
    for entry in analysis.ranking.iter().take(top_k as usize) {
        for evidence in &entry.evidence_refs {
            let incitape_analyzer::EvidenceRef::TraceExemplar { trace_id, .. } = evidence;
            let bytes = hex::decode(trace_id)
                .map_err(|_| AppError::validation("invalid trace_id hex in analysis"))?;
            if bytes.len() != 16 {
                return Err(AppError::validation("invalid trace_id length in analysis"));
            }
            let mut array = [0u8; 16];
            array.copy_from_slice(&bytes);
            ids.insert(array);
        }
    }
    Ok(ids)
}

fn record_has_trace_id(record: &TapeRecord, target_ids: &BTreeSet<[u8; 16]>) -> AppResult<bool> {
    let req = ExportTraceServiceRequest::decode(record.otlp_payload_bytes.as_slice())
        .map_err(|e| AppError::validation(format!("trace decode error: {e}")))?;
    for resource_spans in &req.resource_spans {
        for scope_span in &resource_spans.scope_spans {
            for span in &scope_span.spans {
                if span.trace_id.len() == 16 {
                    let mut trace_id = [0u8; 16];
                    trace_id.copy_from_slice(&span.trace_id);
                    if target_ids.contains(&trace_id) {
                        return Ok(true);
                    }
                }
            }
        }
    }
    Ok(false)
}

fn ensure_not_partial(tape_dir: &Path) -> AppResult<()> {
    if let Some(name) = tape_dir.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".partial") {
            return Err(AppError::validation("partial tape_dir is not valid"));
        }
    }
    Ok(())
}
