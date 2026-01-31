use incitape_core::AppResult;
use incitape_tape::record::RecordType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayPayload {
    pub record_type: RecordType,
    pub capture_time_unix_nano: u64,
    pub bytes: Vec<u8>,
}

pub trait ReplaySink {
    fn send(&mut self, payload: ReplayPayload) -> AppResult<()>;
}

#[derive(Default)]
pub struct InMemorySink {
    pub payloads: Vec<ReplayPayload>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self {
            payloads: Vec::new(),
        }
    }
}

impl ReplaySink for InMemorySink {
    fn send(&mut self, payload: ReplayPayload) -> AppResult<()> {
        self.payloads.push(payload);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_sink_collects_payloads() {
        let mut sink = InMemorySink::new();
        sink.send(ReplayPayload {
            record_type: RecordType::Traces,
            capture_time_unix_nano: 1,
            bytes: vec![1, 2, 3],
        })
        .unwrap();
        sink.send(ReplayPayload {
            record_type: RecordType::Logs,
            capture_time_unix_nano: 2,
            bytes: vec![4, 5],
        })
        .unwrap();
        assert_eq!(sink.payloads.len(), 2);
        assert_eq!(sink.payloads[0].bytes, vec![1, 2, 3]);
        assert_eq!(sink.payloads[0].record_type, RecordType::Traces);
    }
}
