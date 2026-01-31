pub mod baselines;
pub mod generator;
pub mod model;
pub mod runner;
pub mod suite;

pub use generator::generate_suite;
pub use runner::run_suite;
pub use suite::{EvalSuiteConfig, FaultConfig, ScenarioConfig, Thresholds};
