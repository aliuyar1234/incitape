pub mod ai;
pub mod report;

pub use ai::{AiProvider, AiRequest, AiResponse, DisabledAiProvider, OllamaProvider};
pub use report::{build_evidence_pack, generate_ai_section, render_report, AiReport, ReportConfig};
