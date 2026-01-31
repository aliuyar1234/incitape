use incitape_core::{AppError, AppResult};
use regex::Regex;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub struct RedactionRule {
    pub name: String,
    pub pattern: String,
    regex: Regex,
}

impl RedactionRule {
    pub fn new(name: impl Into<String>, pattern: impl Into<String>) -> AppResult<Self> {
        let name = name.into();
        let pattern = pattern.into();
        let regex = Regex::new(&pattern)
            .map_err(|e| AppError::internal(format!("invalid redaction regex {name}: {e}")))?;
        Ok(Self {
            name,
            pattern,
            regex,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EntropyConfig {
    pub min_hex_len: usize,
    pub min_base64_len: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_hex_len: 32,
            min_base64_len: 40,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RedactionRuleset {
    pub name: String,
    pub rules: Vec<RedactionRule>,
    pub entropy: EntropyConfig,
}

impl RedactionRuleset {
    pub fn safe_default() -> AppResult<Self> {
        Ok(Self {
            name: "safe_default".to_string(),
            rules: vec![
                RedactionRule::new("jwt", r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")?,
                RedactionRule::new("bearer_token", r"(?i)bearer\s+[A-Za-z0-9._\-+/=]{10,}")?,
                RedactionRule::new("authorization_header", r"(?i)authorization\s*[:=]\s*[^\s]+")?,
                RedactionRule::new(
                    "api_key",
                    r"(?i)(api[_-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
                )?,
                RedactionRule::new(
                    "private_key_block",
                    r"(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----",
                )?,
            ],
            entropy: EntropyConfig::default(),
        })
    }

    pub fn ruleset_sha256(&self) -> String {
        let mut canonical = String::new();
        canonical.push_str(&format!("name={}\n", self.name));
        canonical.push_str(&format!(
            "entropy.min_hex_len={}\n",
            self.entropy.min_hex_len
        ));
        canonical.push_str(&format!(
            "entropy.min_base64_len={}\n",
            self.entropy.min_base64_len
        ));
        for rule in &self.rules {
            canonical.push_str(&format!("rule:{}={}\n", rule.name, rule.pattern));
        }
        let digest = Sha256::digest(canonical.as_bytes());
        hex::encode(digest)
    }
}

#[derive(Debug, Clone)]
pub struct RedactionEngine {
    pub ruleset: RedactionRuleset,
}

impl RedactionEngine {
    pub fn new(ruleset: RedactionRuleset) -> Self {
        Self { ruleset }
    }

    pub fn redact_str(&self, input: &str) -> String {
        let mut output = input.to_string();
        for rule in &self.ruleset.rules {
            output = rule
                .regex
                .replace_all(&output, |caps: &regex::Captures<'_>| {
                    let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
                    replacement(&rule.name, matched.as_bytes())
                })
                .to_string();
        }
        output = redact_entropy_hex(&output, self.ruleset.entropy.min_hex_len);
        output = redact_entropy_base64(&output, self.ruleset.entropy.min_base64_len);
        output
    }

    pub fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        if input.is_empty() {
            return Vec::new();
        }
        match std::str::from_utf8(input) {
            Ok(text) => self.redact_str(text).into_bytes(),
            Err(_) => replacement("bytes", input).into_bytes(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LeakageScanner {
    pub ruleset: RedactionRuleset,
}

impl LeakageScanner {
    pub fn new(ruleset: RedactionRuleset) -> Self {
        Self { ruleset }
    }

    pub fn scan_str(&self, input: &str) -> u64 {
        if input.is_empty() {
            return 0;
        }
        let mut count = 0u64;
        for rule in &self.ruleset.rules {
            count += rule.regex.find_iter(input).count() as u64;
        }
        count += scan_entropy_hex(input, self.ruleset.entropy.min_hex_len);
        count += scan_entropy_base64(input, self.ruleset.entropy.min_base64_len);
        count
    }

    pub fn scan_bytes(&self, input: &[u8]) -> u64 {
        if input.is_empty() {
            return 0;
        }
        match std::str::from_utf8(input) {
            Ok(text) => self.scan_str(text),
            Err(_) => 1,
        }
    }
}

fn replacement(rule_name: &str, bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex_hash = hex::encode(digest);
    let short = &hex_hash[..8];
    format!("REDACTED:{rule_name}:{short}")
}

fn redact_entropy_hex(input: &str, min_len: usize) -> String {
    redact_by_charset(input, min_len, |b: u8| b.is_ascii_hexdigit(), "entropy_hex")
}

fn redact_entropy_base64(input: &str, min_len: usize) -> String {
    redact_by_charset(
        input,
        min_len,
        |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='),
        "entropy_b64",
    )
}

fn redact_by_charset<F>(input: &str, min_len: usize, is_allowed: F, rule: &str) -> String
where
    F: Fn(u8) -> bool,
{
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if !is_allowed(bytes[i]) {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_allowed(bytes[i]) {
            i += 1;
        }
        let segment = &bytes[start..i];
        if segment.len() >= min_len {
            out.push_str(&replacement(rule, segment));
        } else {
            out.push_str(std::str::from_utf8(segment).unwrap_or(""));
        }
    }
    out
}

fn scan_entropy_hex(input: &str, min_len: usize) -> u64 {
    scan_by_charset(input, min_len, |b: u8| b.is_ascii_hexdigit())
}

fn scan_entropy_base64(input: &str, min_len: usize) -> u64 {
    scan_by_charset(
        input,
        min_len,
        |b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'='),
    )
}

fn scan_by_charset<F>(input: &str, min_len: usize, is_allowed: F) -> u64
where
    F: Fn(u8) -> bool,
{
    let bytes = input.as_bytes();
    let mut count = 0u64;
    let mut i = 0usize;
    while i < bytes.len() {
        if !is_allowed(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_allowed(bytes[i]) {
            i += 1;
        }
        if i - start >= min_len {
            count += 1;
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_bearer_token() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let engine = RedactionEngine::new(ruleset);
        let input = "Bearer abcdefghijklmnopqrstuvwxyz";
        let output = engine.redact_str(input);
        assert!(output.contains("REDACTED:bearer_token:"));
    }

    #[test]
    fn redacts_authorization_header() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let engine = RedactionEngine::new(ruleset);
        let input = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz";
        let output = engine.redact_str(input);
        assert!(output.contains("REDACTED:authorization_header:"));
    }

    #[test]
    fn redacts_entropy_hex() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let engine = RedactionEngine::new(ruleset);
        let secret = "0123456789abcdef0123456789abcdef";
        let output = engine.redact_str(secret);
        assert!(output.starts_with("REDACTED:entropy_hex:"));
    }

    #[test]
    fn ruleset_hash_is_stable() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let hash1 = ruleset.ruleset_sha256();
        let hash2 = ruleset.ruleset_sha256();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn redacts_utf8_bytes() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let engine = RedactionEngine::new(ruleset);
        let input = b"Bearer abcdefghijklmnopqrstuvwxyz";
        let output = engine.redact_bytes(input);
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.contains("REDACTED:bearer_token:"));
    }

    #[test]
    fn redacts_non_utf8_bytes() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let engine = RedactionEngine::new(ruleset);
        let input = vec![0xff, 0xfe, 0xfd, 0xfc];
        let output = engine.redact_bytes(&input);
        let output_str = String::from_utf8(output).unwrap();
        assert!(output_str.starts_with("REDACTED:bytes:"));
    }

    #[test]
    fn scanner_detects_leakage() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let scanner = LeakageScanner::new(ruleset);
        let count = scanner.scan_str("Bearer abcdefghijklmnopqrstuvwxyz");
        assert!(count > 0);
    }

    #[test]
    fn scanner_reports_zero_for_clean_text() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let scanner = LeakageScanner::new(ruleset);
        let count = scanner.scan_str("no secrets here");
        assert_eq!(count, 0);
    }

    #[test]
    fn scanner_flags_non_utf8_bytes() {
        let ruleset = RedactionRuleset::safe_default().unwrap();
        let scanner = LeakageScanner::new(ruleset);
        let count = scanner.scan_bytes(&[0xff, 0xfe]);
        assert_eq!(count, 1);
    }
}
