use incitape_core::json::to_canonical_json_bytes;
use incitape_core::{AppError, AppResult};
use incitape_report::{
    analysis_sha256_hex, build_evidence_pack, ensure_report_size, generate_ai_section,
    render_report, scan_report_for_leakage, MockProvider, OllamaProvider,
};
use incitape_tape::checksums::verify_checksums;
use incitape_tape::manifest::Manifest;
use incitape_tape::tape_id::compute_tape_id;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct ReportCommandArgs {
    pub analysis: Option<PathBuf>,
    pub out: Option<PathBuf>,
    pub ai: bool,
    pub ai_strict: bool,
    pub ai_deterministic: bool,
    pub overwrite: bool,
}

pub fn report_command(
    tape_dir: &Path,
    args: ReportCommandArgs,
    config: &incitape_core::config::Config,
) -> AppResult<()> {
    let ReportCommandArgs {
        analysis,
        out,
        ai,
        ai_strict,
        ai_deterministic,
        overwrite,
    } = args;
    ensure_not_partial(tape_dir)?;
    if !tape_dir.is_dir() {
        return Err(AppError::validation("tape_dir is not a directory"));
    }

    verify_checksums(tape_dir)?;
    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest = Manifest::load(&tape_dir.join("manifest.yaml"))?;
    manifest.validate(&tape_id)?;

    let analysis_path = analysis.unwrap_or_else(|| tape_dir.join("analysis.json"));
    if !analysis_path.exists() {
        return Err(AppError::validation("analysis.json is missing"));
    }
    let analysis_bytes = fs::read(&analysis_path)
        .map_err(|e| AppError::validation(format!("failed to read analysis.json: {e}")))?;
    let analysis_text = std::str::from_utf8(&analysis_bytes)
        .map_err(|e| AppError::validation(format!("analysis.json is not utf-8: {e}")))?;
    let analysis_value: serde_json::Value = serde_json::from_str(analysis_text)
        .map_err(|e| AppError::validation(format!("analysis.json parse error: {e}")))?;
    let analysis: incitape_analyzer::AnalysisOutput =
        serde_json::from_value(analysis_value.clone())
            .map_err(|e| AppError::validation(format!("analysis.json decode error: {e}")))?;
    if analysis.tape_id != tape_id {
        return Err(AppError::validation("analysis.json tape_id mismatch"));
    }
    let canonical = to_canonical_json_bytes(&analysis_value)?;
    let analysis_sha256 = analysis_sha256_hex(&canonical);

    let out_path = out.unwrap_or_else(|| tape_dir.join("report.md"));
    if out_path.exists() && !overwrite {
        return Err(AppError::usage(
            "report.md already exists; use --overwrite to replace",
        ));
    }
    if out_path.exists() && out_path.is_dir() {
        return Err(AppError::validation("report output path is a directory"));
    }

    let mut ai_section = None;
    let mut ai_fallback_used = false;
    if ai {
        if !config.ai.enabled {
            return Err(AppError::usage("ai is disabled in config"));
        }
        let endpoint = config
            .ai
            .endpoint
            .clone()
            .ok_or_else(|| AppError::usage("ai.endpoint is required when ai is enabled"))?;
        let provider =
            ai_provider_from_endpoint(&endpoint, Duration::from_secs(config.ai.timeout_secs))?;
        let evidence_pack = match build_evidence_pack(tape_dir, &analysis, &analysis_sha256) {
            Ok(pack) => Some(pack),
            Err(err) => {
                if ai_strict {
                    return Err(err);
                }
                ai_fallback_used = true;
                None
            }
        };
        if let Some(pack) = evidence_pack {
            let evidence_json = serde_json::to_string(&pack)
                .map_err(|e| AppError::internal(format!("evidence pack encode error: {e}")))?;
            match generate_ai_section(
                provider.as_ref(),
                &pack,
                &evidence_json,
                ai_deterministic,
                if ai_deterministic { Some(0) } else { None },
            ) {
                Ok(report) => ai_section = Some(report),
                Err(err) => {
                    if ai_strict {
                        return Err(err);
                    }
                    ai_fallback_used = true;
                }
            }
        }
    }

    let report = render_report(&analysis, ai_section.as_ref(), ai_fallback_used);
    ensure_report_size(&report)?;
    if ai_section.is_some() {
        scan_report_for_leakage(&report)?;
    }
    fs::write(&out_path, report)
        .map_err(|e| AppError::internal(format!("failed to write report.md: {e}")))?;
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

fn ai_provider_from_endpoint(
    endpoint: &str,
    timeout: Duration,
) -> AppResult<Box<dyn incitape_report::AiProvider>> {
    if let Some(provider) = MockProvider::from_endpoint(endpoint) {
        return Ok(Box::new(provider));
    }
    if !is_loopback_endpoint(endpoint) {
        return Err(AppError::security(
            "ai endpoint must be loopback-only (http://127.0.0.1 or http://[::1])",
        ));
    }
    Ok(Box::new(OllamaProvider::new(endpoint.to_string(), timeout)))
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("http://127.0.0.1") || endpoint.starts_with("http://[::1]")
}
