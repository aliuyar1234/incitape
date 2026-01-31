use crate::client::GrpcExporter;
use crate::filter::ReplayFilter;
use crate::sink::{ReplayPayload, ReplaySink};
use crate::speed::ReplaySpeed;
use incitape_core::AppResult;
use incitape_tape::bounds::Bounds;
use incitape_tape::checksums::verify_checksums;
use incitape_tape::manifest::Manifest;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::TapeRecord;
use incitape_tape::tape_id::compute_tape_id;
use std::path::Path;
use std::time::Duration;
use tokio::time::sleep;

pub const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;
pub const DEFAULT_RPC_TIMEOUT_SECS: u64 = 15;

pub struct ReplayConfig {
    pub endpoint: String,
    pub speed: ReplaySpeed,
    pub filter: Option<ReplayFilter>,
    pub connect_timeout: Duration,
    pub rpc_timeout: Duration,
}

pub async fn replay_tape_dir(tape_dir: &Path, config: ReplayConfig) -> AppResult<()> {
    verify_checksums(tape_dir)?;
    let tape_path = tape_dir.join("tape.tape.zst");
    let tape_id = compute_tape_id(&tape_path)?;
    let manifest = Manifest::load(&tape_dir.join("manifest.yaml"))?;
    manifest.validate(&tape_id)?;

    let reader = TapeReader::open(&tape_path, Bounds::default())?;
    let records = reader.read_all_sorted()?;

    let mut exporter =
        GrpcExporter::connect(&config.endpoint, config.connect_timeout, config.rpc_timeout).await?;

    replay_records_with_exporter(records, &config, &mut exporter).await
}

pub async fn replay_records_with_sink<S: ReplaySink>(
    records: Vec<TapeRecord>,
    config: &ReplayConfig,
    sink: &mut S,
) -> AppResult<()> {
    replay_records_with_sink_inner(records, config, sink).await
}

async fn replay_records_with_exporter(
    records: Vec<TapeRecord>,
    config: &ReplayConfig,
    exporter: &mut GrpcExporter,
) -> AppResult<()> {
    let filter = config.filter.as_ref();
    let mut last_capture: Option<u64> = None;

    for record in records {
        if let Some(filter) = filter {
            if !filter.matches(&record)? {
                continue;
            }
        }

        maybe_sleep(
            &config.speed,
            &mut last_capture,
            record.capture_time_unix_nano,
        )
        .await;
        last_capture = Some(record.capture_time_unix_nano);

        exporter
            .send(record.record_type, &record.otlp_payload_bytes)
            .await?;
    }

    Ok(())
}

async fn replay_records_with_sink_inner<S: ReplaySink>(
    records: Vec<TapeRecord>,
    config: &ReplayConfig,
    sink: &mut S,
) -> AppResult<()> {
    let filter = config.filter.as_ref();
    let mut last_capture: Option<u64> = None;

    for record in records {
        if let Some(filter) = filter {
            if !filter.matches(&record)? {
                continue;
            }
        }

        maybe_sleep(
            &config.speed,
            &mut last_capture,
            record.capture_time_unix_nano,
        )
        .await;
        last_capture = Some(record.capture_time_unix_nano);

        sink.send(ReplayPayload {
            record_type: record.record_type,
            capture_time_unix_nano: record.capture_time_unix_nano,
            bytes: record.otlp_payload_bytes,
        })?;
    }

    Ok(())
}

async fn maybe_sleep(speed: &ReplaySpeed, last_capture: &mut Option<u64>, current: u64) {
    if speed.is_zero() {
        return;
    }
    if let Some(prev) = *last_capture {
        if current > prev {
            let delta = current - prev;
            let delay = speed.scale_delay(delta);
            if delay.as_nanos() > 0 {
                sleep(delay).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink::InMemorySink;
    use incitape_tape::record::RecordType;

    #[tokio::test]
    async fn replay_records_applies_filter() {
        let records = vec![
            TapeRecord {
                record_type: RecordType::Metrics,
                capture_time_unix_nano: 10,
                otlp_payload_bytes: vec![1, 2, 3],
                payload_sha256: [0u8; 32],
            },
            TapeRecord {
                record_type: RecordType::Logs,
                capture_time_unix_nano: 20,
                otlp_payload_bytes: vec![4, 5],
                payload_sha256: [1u8; 32],
            },
        ];

        let config = ReplayConfig {
            endpoint: "http://127.0.0.1:4317".to_string(),
            speed: ReplaySpeed::zero(),
            filter: Some(ReplayFilter {
                record_type: Some(RecordType::Logs),
                service: None,
                trace_id: None,
            }),
            connect_timeout: Duration::from_secs(1),
            rpc_timeout: Duration::from_secs(1),
        };
        let mut sink = InMemorySink::new();
        replay_records_with_sink(records, &config, &mut sink)
            .await
            .unwrap();
        assert_eq!(sink.payloads.len(), 1);
        assert_eq!(sink.payloads[0].record_type, RecordType::Logs);
    }
}
