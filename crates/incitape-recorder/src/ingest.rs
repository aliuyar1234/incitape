use incitape_core::{AppError, AppResult, ErrorKind};
use incitape_redaction::{
    redact_logs_request, redact_metrics_request, redact_trace_request, RedactionEngine,
};
use incitape_tape::bounds::Bounds;
use incitape_tape::record::RecordType;
use incitape_tape::writer::TapeWriter;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

#[derive(Debug)]
pub enum IngestOutcome {
    Accepted,
    Rejected(AppError),
    Fatal(AppError),
}

pub struct RecorderIngest {
    engine: RedactionEngine,
    bounds: Bounds,
    writer: Mutex<Option<TapeWriter>>,
    fatal_tx: mpsc::Sender<AppError>,
}

impl RecorderIngest {
    pub fn new(
        engine: RedactionEngine,
        bounds: Bounds,
        writer: TapeWriter,
        fatal_tx: mpsc::Sender<AppError>,
    ) -> Self {
        Self {
            engine,
            bounds,
            writer: Mutex::new(Some(writer)),
            fatal_tx,
        }
    }

    pub async fn ingest(&self, record_type: RecordType, payload: &[u8]) -> IngestOutcome {
        if payload.len() > self.bounds.max_record_bytes as usize {
            return IngestOutcome::Rejected(AppError::validation(
                "record payload exceeds max_record_bytes",
            ));
        }

        let redacted = match record_type {
            RecordType::Traces => redact_trace_request(payload, &self.engine),
            RecordType::Metrics => redact_metrics_request(payload, &self.engine),
            RecordType::Logs => redact_logs_request(payload, &self.engine),
        };

        let redacted = match redacted {
            Ok(bytes) => bytes,
            Err(err) => {
                if err.kind() == ErrorKind::Validation {
                    return IngestOutcome::Rejected(err);
                }
                return self.fatal(err);
            }
        };

        if redacted.len() > self.bounds.max_record_bytes as usize {
            return IngestOutcome::Rejected(AppError::validation(
                "record payload exceeds max_record_bytes",
            ));
        }

        let capture_time_unix_nano = match capture_time_unix_nano() {
            Ok(value) => value,
            Err(err) => return self.fatal(err),
        };

        let mut writer = self.writer.lock().await;
        let writer = match writer.as_mut() {
            Some(writer) => writer,
            None => {
                return self.fatal(AppError::internal(
                    "recorder writer unavailable during ingest",
                ))
            }
        };

        if let Err(err) = writer.write_record(record_type, capture_time_unix_nano, &redacted) {
            return self.fatal_if_validation(err);
        }

        IngestOutcome::Accepted
    }

    pub async fn finish(&self) -> AppResult<()> {
        let mut writer = self.writer.lock().await;
        if let Some(writer) = writer.take() {
            writer.finish()?;
        }
        Ok(())
    }

    fn fatal(&self, err: AppError) -> IngestOutcome {
        let _ = self.fatal_tx.try_send(err.clone());
        IngestOutcome::Fatal(err)
    }

    fn fatal_if_validation(&self, err: AppError) -> IngestOutcome {
        match err.kind() {
            ErrorKind::Validation | ErrorKind::Internal => self.fatal(err),
            ErrorKind::Usage | ErrorKind::Security => IngestOutcome::Fatal(err),
        }
    }
}

fn capture_time_unix_nano() -> AppResult<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| AppError::internal(format!("system time error: {e}")))?;
    let nanos = now.as_nanos();
    if nanos > u64::MAX as u128 {
        return Err(AppError::internal("capture_time_unix_nano overflow"));
    }
    Ok(nanos as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use incitape_redaction::RedactionRuleset;
    use incitape_tape::bounds::Bounds;
    use tempfile::tempdir;

    #[tokio::test]
    async fn rejects_invalid_protobuf() {
        let dir = tempdir().unwrap();
        let tape_path = dir.path().join("tape.tape.zst");
        let bounds = Bounds::default();
        let writer = TapeWriter::create(&tape_path, bounds).unwrap();
        let (fatal_tx, _fatal_rx) = mpsc::channel(1);
        let engine = RedactionEngine::new(RedactionRuleset::safe_default().unwrap());
        let ingest = RecorderIngest::new(engine, bounds, writer, fatal_tx);

        let result = ingest.ingest(RecordType::Traces, b"not protobuf").await;
        assert!(matches!(result, IngestOutcome::Rejected(_)));
    }

    #[tokio::test]
    async fn rejects_oversized_payload() {
        let dir = tempdir().unwrap();
        let tape_path = dir.path().join("tape.tape.zst");
        let mut bounds = Bounds::default();
        bounds.max_record_bytes = 4;
        bounds.max_frame_len = bounds.max_record_bytes + 64;
        let writer = TapeWriter::create(&tape_path, bounds).unwrap();
        let (fatal_tx, _fatal_rx) = mpsc::channel(1);
        let engine = RedactionEngine::new(RedactionRuleset::safe_default().unwrap());
        let ingest = RecorderIngest::new(engine, bounds, writer, fatal_tx);

        let payload = vec![0u8; 5];
        let result = ingest.ingest(RecordType::Traces, &payload).await;
        assert!(matches!(result, IngestOutcome::Rejected(_)));
    }
}
