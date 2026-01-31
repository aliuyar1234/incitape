use incitape_core::json::determinism_hash_for_json_value;
use incitape_core::{AppError, AppResult};
use incitape_redaction::{
    scan_logs_request, scan_metrics_request, scan_trace_request, LeakageScanner, RedactionRuleset,
};
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::verify_checksums;
use incitape_tape::manifest::Manifest;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::RecordType;
use incitape_tape::tape_id::compute_tape_id;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub fn validate_tape_dir(tape_dir: &Path, strict: bool) -> AppResult<()> {
    ensure_not_partial(tape_dir)?;
    if !tape_dir.is_dir() {
        return Err(AppError::validation("tape_dir is not a directory"));
    }

    verify_checksums(tape_dir)?;

    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest_path = tape_dir.join("manifest.yaml");
    let manifest = Manifest::load(&manifest_path)?;
    manifest.validate(&tape_id)?;

    if !manifest.redaction.applied {
        return Err(AppError::validation("manifest redaction.applied is false"));
    }

    let scanner = if strict {
        let ruleset = RedactionRuleset::safe_default()?;
        if manifest.redaction.ruleset_sha256 != ruleset.ruleset_sha256() {
            return Err(AppError::security(
                "redaction ruleset hash does not match supported safe_default ruleset",
            ));
        }
        Some(LeakageScanner::new(ruleset))
    } else {
        None
    };

    let bounds = Bounds::default();
    let mut reader = TapeReader::open(&tape_path, bounds)?;
    let mut record_count = 0u64;
    let mut leakage_count = 0u64;
    while let Some(record) = reader.read_next()? {
        record_count += 1;
        if record_count > bounds.max_records_per_tape {
            return Err(AppError::validation("max_records_per_tape exceeded"));
        }
        if let Some(scanner) = &scanner {
            leakage_count = leakage_count.saturating_add(scan_record(record, scanner)?);
        }
    }

    leakage_count = leakage_count.saturating_add(validate_outputs(
        tape_dir,
        &tape_id,
        strict,
        scanner.as_ref(),
    )?);

    if strict && leakage_count > 0 {
        return Err(AppError::security("leakage_count > 0"));
    }

    Ok(())
}

fn ensure_not_partial(tape_dir: &Path) -> AppResult<()> {
    if let Some(name) = tape_dir.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".partial") {
            return Err(AppError::validation("partial tape_dir is not valid"));
        }
    }
    Ok(())
}

fn scan_record(
    record: incitape_tape::record::TapeRecord,
    scanner: &LeakageScanner,
) -> AppResult<u64> {
    match record.record_type {
        RecordType::Traces => scan_trace_request(&record.otlp_payload_bytes, scanner),
        RecordType::Metrics => scan_metrics_request(&record.otlp_payload_bytes, scanner),
        RecordType::Logs => scan_logs_request(&record.otlp_payload_bytes, scanner),
    }
}

fn validate_outputs(
    tape_dir: &Path,
    tape_id: &str,
    strict: bool,
    scanner: Option<&LeakageScanner>,
) -> AppResult<u64> {
    let mut leakage = 0u64;
    let analysis_path = tape_dir.join("analysis.json");
    if analysis_path.exists() {
        leakage =
            leakage.saturating_add(validate_analysis(&analysis_path, tape_id, strict, scanner)?);
    }

    let eval_path = tape_dir.join("eval.json");
    if eval_path.exists() {
        leakage = leakage.saturating_add(validate_eval(&eval_path, strict, scanner)?);
    }

    let report_path = tape_dir.join("report.md");
    if report_path.exists() {
        leakage = leakage.saturating_add(validate_report(&report_path, tape_id, strict, scanner)?);
    }

    Ok(leakage)
}

fn validate_analysis(
    path: &Path,
    tape_id: &str,
    strict: bool,
    scanner: Option<&LeakageScanner>,
) -> AppResult<u64> {
    let bytes = fs::read(path)
        .map_err(|e| AppError::validation(format!("failed to read analysis.json: {e}")))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| AppError::validation(format!("analysis.json is not utf-8: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| AppError::validation(format!("analysis.json parse error: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| AppError::validation("analysis.json must be an object"))?;

    let tape = obj
        .get("tape_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation("analysis.json missing tape_id"))?;
    if tape != tape_id {
        return Err(AppError::validation("analysis.json tape_id mismatch"));
    }

    let determinism = obj
        .get("determinism_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation("analysis.json missing determinism_hash"))?;
    let config_hash = obj
        .get("config_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation("analysis.json missing config_hash"))?;
    if config_hash.is_empty() {
        return Err(AppError::validation("analysis.json config_hash empty"));
    }
    if !obj.get("ranking").map(|v| v.is_array()).unwrap_or(false) {
        return Err(AppError::validation(
            "analysis.json ranking must be an array",
        ));
    }

    let computed = determinism_hash_for_json_value(value.clone(), "determinism_hash")?;
    if determinism != computed {
        return Err(AppError::validation(
            "analysis.json determinism_hash mismatch",
        ));
    }

    let leakage = if strict {
        scanner
            .map(|scanner| scan_json_value(&value, scanner))
            .unwrap_or(0)
    } else {
        0
    };
    Ok(leakage)
}

fn validate_eval(path: &Path, strict: bool, scanner: Option<&LeakageScanner>) -> AppResult<u64> {
    let bytes = fs::read(path)
        .map_err(|e| AppError::validation(format!("failed to read eval.json: {e}")))?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| AppError::validation(format!("eval.json is not utf-8: {e}")))?;
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| AppError::validation(format!("eval.json parse error: {e}")))?;
    let obj = value
        .as_object()
        .ok_or_else(|| AppError::validation("eval.json must be an object"))?;

    let determinism = obj
        .get("determinism_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::validation("eval.json missing determinism_hash"))?;
    if !obj.get("suite").map(|v| v.is_object()).unwrap_or(false) {
        return Err(AppError::validation("eval.json missing suite"));
    }
    if !obj.get("metrics").map(|v| v.is_object()).unwrap_or(false) {
        return Err(AppError::validation("eval.json missing metrics"));
    }
    if !obj.get("scenarios").map(|v| v.is_array()).unwrap_or(false) {
        return Err(AppError::validation("eval.json missing scenarios"));
    }
    let computed = determinism_hash_for_json_value(value.clone(), "determinism_hash")?;
    if determinism != computed {
        return Err(AppError::validation("eval.json determinism_hash mismatch"));
    }

    let leakage = if strict {
        scanner
            .map(|scanner| scan_json_value(&value, scanner))
            .unwrap_or(0)
    } else {
        0
    };
    Ok(leakage)
}

fn validate_report(
    path: &Path,
    tape_id: &str,
    strict: bool,
    scanner: Option<&LeakageScanner>,
) -> AppResult<u64> {
    let content = fs::read_to_string(path)
        .map_err(|e| AppError::validation(format!("failed to read report.md: {e}")))?;
    if !content.contains(tape_id) {
        return Err(AppError::validation("report.md missing tape_id"));
    }

    let leakage = if strict {
        scanner
            .map(|scanner| {
                let sanitized = strip_known_ids(&content);
                scanner.scan_str(&sanitized)
            })
            .unwrap_or(0)
    } else {
        0
    };
    Ok(leakage)
}

fn scan_json_value(value: &serde_json::Value, scanner: &LeakageScanner) -> u64 {
    let mut skip = HashSet::new();
    for key in [
        "tape_id",
        "determinism_hash",
        "config_hash",
        "trace_id",
        "span_id",
    ] {
        skip.insert(key);
    }
    scan_json_value_inner(value, scanner, &skip)
}

fn scan_json_value_inner(
    value: &serde_json::Value,
    scanner: &LeakageScanner,
    skip: &HashSet<&'static str>,
) -> u64 {
    match value {
        serde_json::Value::String(s) => scanner.scan_str(s),
        serde_json::Value::Array(items) => items
            .iter()
            .map(|item| scan_json_value_inner(item, scanner, skip))
            .sum(),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| {
                if skip.contains(key.as_str()) {
                    0
                } else {
                    scan_json_value_inner(value, scanner, skip)
                }
            })
            .sum(),
        _ => 0,
    }
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
