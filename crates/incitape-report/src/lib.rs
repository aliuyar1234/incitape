pub mod ai;
pub mod report;

pub use ai::{AiProvider, AiRequest, AiResponse, DisabledAiProvider, MockProvider, OllamaProvider};
pub use report::{
    analysis_sha256_hex, build_evidence_pack, ensure_report_size, generate_ai_section,
    render_report, scan_report_for_leakage, AiReport, ReportConfig,
};
