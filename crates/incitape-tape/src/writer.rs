use crate::bounds::Bounds;
use crate::format::{FLAGS, MAGIC, VERSION};
use crate::record::RecordType;
use byteorder::{LittleEndian, WriteBytesExt};
use incitape_core::{AppError, AppResult};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
use zstd::stream::write::Encoder;

pub struct TapeWriter {
    encoder: Encoder<'static, CountingWriter<File>>,
    bounds: Bounds,
    records_written: u64,
}

impl TapeWriter {
    pub fn create(path: &Path, bounds: Bounds) -> AppResult<Self> {
        let file = File::create(path)
            .map_err(|e| AppError::internal(format!("failed to create tape file: {e}")))?;
        let writer = CountingWriter::new(file, bounds.max_tape_file_bytes);
        let mut encoder = Encoder::new(writer, 0)
            .map_err(|e| AppError::internal(format!("zstd encoder init failed: {e}")))?;

        encoder
            .write_all(&MAGIC)
            .and_then(|_| encoder.write_u16::<LittleEndian>(VERSION))
            .and_then(|_| encoder.write_u16::<LittleEndian>(FLAGS))
            .map_err(map_io_error)?;

        Ok(Self {
            encoder,
            bounds,
            records_written: 0,
        })
    }

    pub fn write_record(
        &mut self,
        record_type: RecordType,
        capture_time_unix_nano: u64,
        otlp_payload_bytes: &[u8],
    ) -> AppResult<()> {
        if self.records_written >= self.bounds.max_records_per_tape {
            return Err(AppError::validation("max_records_per_tape exceeded"));
        }

        let payload_len = otlp_payload_bytes.len();
        if payload_len > self.bounds.max_record_bytes as usize {
            return Err(AppError::validation(
                "record payload exceeds max_record_bytes",
            ));
        }

        let frame_len = 1 + 8 + 4 + payload_len + 32;
        if frame_len > self.bounds.max_frame_len as usize {
            return Err(AppError::validation("record frame exceeds max_frame_len"));
        }

        let payload_hash = Sha256::digest(otlp_payload_bytes);

        self.encoder
            .write_u32::<LittleEndian>(frame_len as u32)
            .and_then(|_| self.encoder.write_u8(record_type.as_u8()))
            .and_then(|_| {
                self.encoder
                    .write_u64::<LittleEndian>(capture_time_unix_nano)
            })
            .and_then(|_| self.encoder.write_u32::<LittleEndian>(payload_len as u32))
            .and_then(|_| self.encoder.write_all(otlp_payload_bytes))
            .and_then(|_| self.encoder.write_all(&payload_hash))
            .map_err(map_io_error)?;

        self.records_written += 1;
        Ok(())
    }

    pub fn finish(self) -> AppResult<()> {
        self.encoder
            .finish()
            .map(|_| ())
            .map_err(|e| AppError::internal(format!("zstd finish failed: {e}")))
    }
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
    max_bytes: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            written: 0,
            max_bytes,
        }
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let next = self.written.saturating_add(buf.len() as u64);
        if next > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "max_tape_file_bytes exceeded",
            ));
        }
        let written = self.inner.write(buf)?;
        self.written = self.written.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn map_io_error(err: io::Error) -> AppError {
    if err
        .to_string()
        .to_lowercase()
        .contains("max_tape_file_bytes")
    {
        AppError::validation("tape file exceeds max_tape_file_bytes")
    } else {
        AppError::internal(format!("io error: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::TapeReader;
    use crate::record::RecordType;
    use tempfile::tempdir;

    #[test]
    fn write_and_read_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("tape.tape.zst");
        let bounds = Bounds::default();

        let mut writer = TapeWriter::create(&path, bounds).unwrap();
        writer
            .write_record(RecordType::Traces, 10, b"payload")
            .unwrap();
        writer.finish().unwrap();

        let reader = TapeReader::open(&path, bounds).unwrap();
        let records = reader.read_all_sorted().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].record_type, RecordType::Traces);
        assert_eq!(records[0].capture_time_unix_nano, 10);
        assert_eq!(records[0].otlp_payload_bytes, b"payload");
    }
}
