use incitape_core::{AppError, AppResult};
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct AiRequest {
    pub evidence_pack: String,
}

#[derive(Clone, Debug)]
pub struct AiResponse {
    pub json: String,
}

pub trait AiProvider {
    fn generate_report(&self, request: &AiRequest) -> AppResult<AiResponse>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct DisabledAiProvider;

impl DisabledAiProvider {
    pub fn new() -> Self {
        Self
    }
}

impl AiProvider for DisabledAiProvider {
    fn generate_report(&self, _request: &AiRequest) -> AppResult<AiResponse> {
        Err(AppError::usage(
            "ai provider is disabled; enable it in config and pass --ai",
        ))
    }
}

#[derive(Debug, Clone)]
pub struct OllamaProvider {
    endpoint: String,
    timeout: Duration,
    model: String,
}

impl OllamaProvider {
    pub fn new(endpoint: String, timeout: Duration) -> Self {
        Self {
            endpoint,
            timeout,
            model: "llama3".to_string(),
        }
    }

    fn endpoint_url(&self) -> String {
        if self.endpoint.contains("/api/") {
            self.endpoint.clone()
        } else {
            format!("{}/api/generate", self.endpoint.trim_end_matches('/'))
        }
    }
}

impl AiProvider for OllamaProvider {
    fn generate_report(&self, request: &AiRequest) -> AppResult<AiResponse> {
        let url = self.endpoint_url();
        let body = GenerateRequest {
            model: self.model.clone(),
            prompt: request.evidence_pack.clone(),
            stream: false,
        };
        let response = ureq::post(&url)
            .timeout(self.timeout)
            .send_json(body)
            .map_err(|e| AppError::internal(format!("ai request failed: {e}")))?;
        let value: serde_json::Value = response
            .into_json()
            .map_err(|e| AppError::internal(format!("ai response parse error: {e}")))?;
        let text = value
            .get("response")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AppError::validation("ai response missing 'response'"))?;
        Ok(AiResponse {
            json: text.to_string(),
        })
    }
}

#[derive(Debug, Serialize)]
struct GenerateRequest {
    model: String,
    prompt: String,
    stream: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_provider_fails() {
        let provider = DisabledAiProvider::new();
        let result = provider.generate_report(&AiRequest {
            evidence_pack: "test".to_string(),
        });
        assert!(result.is_err());
    }
}
