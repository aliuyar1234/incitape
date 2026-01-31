use crate::baselines::{baseline_graph, baseline_heuristic, collect_trace_stats, BaselineEntry};
use crate::model::{
    EvalOutput, GroundTruthRef, ModelMetrics, ModelScenarioResult, ScenarioResult, ServiceRef,
    SuiteSummary,
};
use crate::suite::EvalSuiteConfig;
use incitape_analyzer::{analyze_tape_dir_to_output, AnalyzerConfig};
use incitape_core::json::{determinism_hash_for_json_value, to_canonical_json_bytes};
use incitape_core::{AppError, AppResult};
use incitape_redaction::{
    scan_logs_request, scan_metrics_request, scan_trace_request, LeakageScanner, RedactionRuleset,
};
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::verify_checksums;
use incitape_tape::manifest::Manifest;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::{RecordType, TapeRecord};
use incitape_tape::tape_id::compute_tape_id;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

const BASELINE_TOP1_MARGIN_MICROS: u64 = 100_000;

pub fn run_suite(suite_path: &Path, out_path: &Path, overwrite: bool) -> AppResult<()> {
    let suite = EvalSuiteConfig::load(suite_path)?;
    if out_path.exists() && !overwrite {
        return Err(AppError::usage(
            "eval.json already exists; use --overwrite to replace",
        ));
    }
    if out_path.exists() && out_path.is_dir() {
        return Err(AppError::validation("eval output path is a directory"));
    }
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AppError::internal(format!("failed to create eval output dir: {e}"))
            })?;
        }
    }

    let mut scenarios = suite.scenarios.clone();
    scenarios.sort_by(|a, b| a.id.cmp(&b.id));

    let scanner = LeakageScanner::new(RedactionRuleset::safe_default()?);
    let mut scenario_results = Vec::new();
    let mut metrics = MetricsAccumulator::new();
    let mut total_leakage = 0u64;

    for scenario in scenarios {
        let tape_dir = suite.tapes_dir.join(&scenario.id);
        ensure_not_partial(&tape_dir)?;
        verify_checksums(&tape_dir)?;

        let tape_path = tape_dir.join("tape.tape.zst");
        let tape_id = compute_tape_id(&tape_path)?;
        let manifest = Manifest::load(&tape_dir.join("manifest.yaml"))?;
        manifest.validate(&tape_id)?;
        let ground_truth = manifest
            .ground_truth
            .ok_or_else(|| AppError::validation("ground_truth missing in manifest"))?;
        let root = ground_truth.root_cause;

        let records = read_records(&tape_path)?;
        let mut leakage_count = scan_leakage(&records, &scanner)?;
        total_leakage = total_leakage.saturating_add(leakage_count);

        let analyzer_start = Instant::now();
        let analysis = analyze_tape_dir_to_output(&tape_dir, AnalyzerConfig::new(5)?)?;
        let analyzer_time_ms = analyzer_start.elapsed().as_millis() as u64;
        let analysis_bytes = to_canonical_json_bytes(&analysis)?;
        let analysis_text = String::from_utf8(analysis_bytes.clone())
            .map_err(|e| AppError::internal(format!("analysis json utf-8 error: {e}")))?;
        leakage_count = leakage_count.saturating_add(scanner.scan_str(&analysis_text));
        let analysis_value: serde_json::Value = serde_json::from_slice(&analysis_bytes)
            .map_err(|e| AppError::internal(format!("analysis json decode error: {e}")))?;
        let analysis_hash =
            determinism_hash_for_json_value(analysis_value.clone(), "determinism_hash")?;
        if analysis_hash != analysis.determinism_hash {
            return Err(AppError::validation("analysis determinism_hash mismatch"));
        }

        let analyzer_rank = rank_for_service(&analysis.ranking, &root);
        metrics.analyzer.observe(analyzer_rank, analyzer_time_ms);

        let baseline_start = Instant::now();
        let stats = collect_trace_stats(&records)?;
        let heuristic = baseline_heuristic(&stats);
        let heuristic_time = baseline_start.elapsed().as_millis() as u64;
        let heuristic_rank = rank_for_baseline(&heuristic, &root);
        metrics
            .baseline_heuristic
            .observe(heuristic_rank, heuristic_time);

        let graph_start = Instant::now();
        let graph = baseline_graph(&stats);
        let graph_time = graph_start.elapsed().as_millis() as u64;
        let graph_rank = rank_for_baseline(&graph, &root);
        metrics.baseline_graph.observe(graph_rank, graph_time);

        let mut models = BTreeMap::new();
        models.insert(
            "analyzer".to_string(),
            ModelScenarioResult {
                rank: analyzer_rank.map(|r| r as u32),
                top_hit: analysis.ranking.first().map(|entry| ServiceRef {
                    name: entry.entity.name.clone(),
                    namespace: entry.entity.namespace.clone(),
                }),
                determinism_hash: Some(analysis.determinism_hash.clone()),
            },
        );
        models.insert(
            "baseline_heuristic".to_string(),
            ModelScenarioResult {
                rank: heuristic_rank.map(|r| r as u32),
                top_hit: heuristic.first().map(|entry| ServiceRef {
                    name: entry.service.name.clone(),
                    namespace: entry.service.namespace.clone(),
                }),
                determinism_hash: None,
            },
        );
        models.insert(
            "baseline_graph".to_string(),
            ModelScenarioResult {
                rank: graph_rank.map(|r| r as u32),
                top_hit: graph.first().map(|entry| ServiceRef {
                    name: entry.service.name.clone(),
                    namespace: entry.service.namespace.clone(),
                }),
                determinism_hash: None,
            },
        );

        scenario_results.push(ScenarioResult {
            id: scenario.id,
            tape_dir: tape_dir.to_string_lossy().to_string(),
            tape_id,
            root_cause: GroundTruthRef {
                kind: root.kind,
                name: root.name,
                namespace: root.namespace,
            },
            leakage_count,
            models,
        });
    }

    if suite.thresholds.leakage_zero && total_leakage > 0 {
        return Err(AppError::security("leakage_count > 0"));
    }

    let metrics_map = metrics.finalize(total_leakage);
    let analyzer_metrics = metrics_map
        .get("analyzer")
        .ok_or_else(|| AppError::internal("missing analyzer metrics"))?;
    let baseline_metrics = metrics_map
        .get("baseline_heuristic")
        .ok_or_else(|| AppError::internal("missing baseline metrics"))?;
    if analyzer_metrics.top1_micros < suite.thresholds.top1_micros
        || analyzer_metrics.top3_micros < suite.thresholds.top3_micros
        || analyzer_metrics.mrr_micros < suite.thresholds.mrr_micros
    {
        return Err(AppError::validation("eval thresholds not met"));
    }
    if suite.thresholds.top1_micros > 0 {
        let required_top1 = baseline_metrics
            .top1_micros
            .saturating_add(BASELINE_TOP1_MARGIN_MICROS)
            .min(1_000_000);
        if analyzer_metrics.top1_micros < required_top1 {
            return Err(AppError::validation(
                "analyzer top1 below heuristic baseline margin",
            ));
        }
    }

    let mut output = EvalOutput {
        suite: SuiteSummary {
            name: suite.name,
            tapes_dir: suite.tapes_dir.to_string_lossy().to_string(),
            scenario_count: scenario_results.len() as u32,
        },
        metrics: metrics_map,
        scenarios: scenario_results,
        determinism_hash: String::new(),
    };
    let value = serde_json::to_value(&output)
        .map_err(|e| AppError::internal(format!("eval json encode error: {e}")))?;
    let hash = determinism_hash_for_json_value(value, "determinism_hash")?;
    output.determinism_hash = hash;
    let bytes = to_canonical_json_bytes(&output)?;
    std::fs::write(out_path, bytes)
        .map_err(|e| AppError::internal(format!("failed to write eval.json: {e}")))?;
    Ok(())
}

fn read_records(tape_path: &Path) -> AppResult<Vec<TapeRecord>> {
    let reader = TapeReader::open(tape_path, Bounds::default())?;
    reader.read_all_sorted()
}

fn scan_leakage(records: &[TapeRecord], scanner: &LeakageScanner) -> AppResult<u64> {
    let mut leakage = 0u64;
    for record in records {
        leakage = leakage.saturating_add(match record.record_type {
            RecordType::Traces => scan_trace_request(&record.otlp_payload_bytes, scanner)?,
            RecordType::Metrics => scan_metrics_request(&record.otlp_payload_bytes, scanner)?,
            RecordType::Logs => scan_logs_request(&record.otlp_payload_bytes, scanner)?,
        });
    }
    Ok(leakage)
}

fn rank_for_service(
    ranking: &[incitape_analyzer::RankingEntry],
    target: &incitape_tape::manifest::GroundTruthTarget,
) -> Option<usize> {
    for (idx, entry) in ranking.iter().enumerate() {
        if entry.entity.name == target.name && entry.entity.namespace == target.namespace {
            return Some(idx + 1);
        }
    }
    None
}

fn rank_for_baseline(
    ranking: &[BaselineEntry],
    target: &incitape_tape::manifest::GroundTruthTarget,
) -> Option<usize> {
    for (idx, entry) in ranking.iter().enumerate() {
        if entry.service.name == target.name && entry.service.namespace == target.namespace {
            return Some(idx + 1);
        }
    }
    None
}

fn ensure_not_partial(tape_dir: &Path) -> AppResult<()> {
    if let Some(name) = tape_dir.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".partial") {
            return Err(AppError::validation("partial tape_dir is not valid"));
        }
    }
    Ok(())
}

struct MetricsAccumulator {
    analyzer: ModelAccumulator,
    baseline_heuristic: ModelAccumulator,
    baseline_graph: ModelAccumulator,
}

impl MetricsAccumulator {
    fn new() -> Self {
        Self {
            analyzer: ModelAccumulator::new(),
            baseline_heuristic: ModelAccumulator::new(),
            baseline_graph: ModelAccumulator::new(),
        }
    }

    fn finalize(self, total_leakage: u64) -> BTreeMap<String, ModelMetrics> {
        let mut map = BTreeMap::new();
        map.insert("analyzer".to_string(), self.analyzer.metrics(total_leakage));
        map.insert(
            "baseline_heuristic".to_string(),
            self.baseline_heuristic.metrics(total_leakage),
        );
        map.insert(
            "baseline_graph".to_string(),
            self.baseline_graph.metrics(total_leakage),
        );
        map
    }
}

struct ModelAccumulator {
    total: u64,
    top1: u64,
    top3: u64,
    mrr_sum: u64,
    time_ms_sum: u64,
}

impl ModelAccumulator {
    fn new() -> Self {
        Self {
            total: 0,
            top1: 0,
            top3: 0,
            mrr_sum: 0,
            time_ms_sum: 0,
        }
    }

    fn observe(&mut self, rank: Option<usize>, time_ms: u64) {
        self.total += 1;
        if let Some(rank) = rank {
            if rank == 1 {
                self.top1 += 1;
            }
            if rank <= 3 {
                self.top3 += 1;
            }
            self.mrr_sum = self.mrr_sum.saturating_add(1_000_000u64 / rank as u64);
        }
        self.time_ms_sum = self.time_ms_sum.saturating_add(time_ms);
    }

    fn metrics(&self, leakage: u64) -> ModelMetrics {
        let denom = if self.total == 0 { 1 } else { self.total };
        ModelMetrics {
            top1_micros: ratio_micros(self.top1, denom),
            top3_micros: ratio_micros(self.top3, denom),
            mrr_micros: self.mrr_sum / denom,
            time_to_rank_ms: self.time_ms_sum / denom,
            leakage_count: leakage,
        }
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
