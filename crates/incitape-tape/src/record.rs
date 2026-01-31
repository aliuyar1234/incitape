use crate::bounds::Bounds;
use incitape_core::{AppError, AppResult};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Traces = 1,
    Metrics = 2,
    Logs = 3,
}

impl RecordType {
    pub fn from_u8(value: u8) -> AppResult<Self> {
        match value {
            1 => Ok(RecordType::Traces),
            2 => Ok(RecordType::Metrics),
            3 => Ok(RecordType::Logs),
            _ => Err(AppError::validation(format!("invalid record_type {value}"))),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone)]
pub struct TapeRecord {
    pub record_type: RecordType,
    pub capture_time_unix_nano: u64,
    pub otlp_payload_bytes: Vec<u8>,
    pub payload_sha256: [u8; 32],
}

impl TapeRecord {
    pub fn new(
        record_type: RecordType,
        capture_time_unix_nano: u64,
        otlp_payload_bytes: Vec<u8>,
        bounds: Bounds,
    ) -> AppResult<Self> {
        if otlp_payload_bytes.len() > bounds.max_record_bytes as usize {
            return Err(AppError::validation(
                "record payload exceeds max_record_bytes",
            ));
        }
        let digest = Sha256::digest(&otlp_payload_bytes);
        let mut payload_sha256 = [0u8; 32];
        payload_sha256.copy_from_slice(&digest);
        Ok(Self {
            record_type,
            capture_time_unix_nano,
            otlp_payload_bytes,
            payload_sha256,
        })
    }

    pub fn sort_key(&self) -> (u64, u8, [u8; 32]) {
        (
            self.capture_time_unix_nano,
            self.record_type.as_u8(),
            self.payload_sha256,
        )
    }
}

impl PartialEq for TapeRecord {
    fn eq(&self, other: &Self) -> bool {
        self.sort_key() == other.sort_key()
    }
}

impl Eq for TapeRecord {}

impl PartialOrd for TapeRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TapeRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.sort_key().cmp(&other.sort_key())
    }
}
