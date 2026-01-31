use incitape_core::{AppError, AppResult};
use incitape_report::{build_evidence_pack, generate_ai_section, render_report, OllamaProvider};
use incitape_tape::checksums::verify_checksums;
use incitape_tape::manifest::Manifest;
use incitape_tape::tape_id::compute_tape_id;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn report_command(
    tape_dir: &Path,
    analysis: Option<PathBuf>,
    out: Option<PathBuf>,
    ai: bool,
    overwrite: bool,
    config: &incitape_core::config::Config,
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

    let analysis_path = analysis.unwrap_or_else(|| tape_dir.join("analysis.json"));
    if !analysis_path.exists() {
        return Err(AppError::validation("analysis.json is missing"));
    }
    let analysis_text = fs::read_to_string(&analysis_path)
        .map_err(|e| AppError::validation(format!("failed to read analysis.json: {e}")))?;
    let analysis: incitape_analyzer::AnalysisOutput = serde_json::from_str(&analysis_text)
        .map_err(|e| AppError::validation(format!("analysis.json parse error: {e}")))?;
    if analysis.tape_id != tape_id {
        return Err(AppError::validation("analysis.json tape_id mismatch"));
    }

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
    if ai {
        if !config.ai.enabled {
            return Err(AppError::usage("ai is disabled in config"));
        }
        let endpoint = config
            .ai
            .endpoint
            .clone()
            .ok_or_else(|| AppError::usage("ai.endpoint is required when ai is enabled"))?;
        let provider = OllamaProvider::new(endpoint, Duration::from_secs(config.ai.timeout_secs));
        let evidence_pack = build_evidence_pack(&analysis)?;
        ai_section = generate_ai_section(&provider, &evidence_pack)?;
    }

    let report = render_report(&analysis, ai_section.as_ref());
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
