use crate::bounds::Bounds;
use crate::format::{FLAGS, MAGIC, VERSION};
use crate::record::{RecordType, TapeRecord};
use byteorder::{LittleEndian, ReadBytesExt};
use incitape_core::{AppError, AppResult};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;
use zstd::stream::read::Decoder;

pub struct TapeReader {
    reader: BoundedRead<Decoder<'static, BufReader<File>>>,
    bounds: Bounds,
}

impl TapeReader {
    pub fn open(path: &Path, bounds: Bounds) -> AppResult<Self> {
        let metadata = std::fs::metadata(path)
            .map_err(|e| AppError::validation(format!("tape file missing: {e}")))?;
        if metadata.len() > bounds.max_tape_file_bytes {
            return Err(AppError::validation(
                "tape file exceeds max_tape_file_bytes",
            ));
        }

        let file = File::open(path)
            .map_err(|e| AppError::validation(format!("failed to open tape: {e}")))?;
        let decoder = Decoder::new(file)
            .map_err(|e| AppError::validation(format!("zstd decode error: {e}")))?;
        let mut reader = BoundedRead::new(decoder, bounds.max_decompressed_bytes);

        let mut magic = [0u8; 8];
        reader.read_exact(&mut magic).map_err(map_io_error)?;
        if magic != MAGIC {
            return Err(AppError::validation("invalid tape magic"));
        }
        let version = reader.read_u16::<LittleEndian>().map_err(map_io_error)?;
        if version != VERSION {
            return Err(AppError::validation("unsupported tape_version"));
        }
        let flags = reader.read_u16::<LittleEndian>().map_err(map_io_error)?;
        if flags != FLAGS {
            return Err(AppError::validation("unsupported tape flags"));
        }

        Ok(Self { reader, bounds })
    }

    pub fn read_all_sorted(mut self) -> AppResult<Vec<TapeRecord>> {
        let mut records = Vec::new();
        while let Some(record) = self.read_next()? {
            records.push(record);
            if records.len() as u64 > self.bounds.max_records_per_tape {
                return Err(AppError::validation("max_records_per_tape exceeded"));
            }
        }
        records.sort();
        Ok(records)
    }

    pub fn read_next(&mut self) -> AppResult<Option<TapeRecord>> {
        let frame_len = match read_u32_opt(&mut self.reader).map_err(map_io_error)? {
            Some(value) => value as usize,
            None => return Ok(None),
        };

        if frame_len > self.bounds.max_frame_len as usize {
            return Err(AppError::validation("frame_len exceeds max_frame_len"));
        }

        let mut payload = vec![0u8; frame_len];
        self.reader.read_exact(&mut payload).map_err(map_io_error)?;

        let mut cursor = Cursor::new(&payload);
        let record_type = RecordType::from_u8(cursor.read_u8().map_err(map_io_error)?)?;
        let capture_time = cursor.read_u64::<LittleEndian>().map_err(map_io_error)?;
        let otlp_len = cursor.read_u32::<LittleEndian>().map_err(map_io_error)? as usize;

        if otlp_len > self.bounds.max_record_bytes as usize {
            return Err(AppError::validation(
                "record payload exceeds max_record_bytes",
            ));
        }

        let expected_frame_len = 1 + 8 + 4 + otlp_len + 32;
        if frame_len != expected_frame_len {
            return Err(AppError::validation("frame_len mismatch"));
        }

        let mut otlp_payload_bytes = vec![0u8; otlp_len];
        cursor
            .read_exact(&mut otlp_payload_bytes)
            .map_err(map_io_error)?;
        let mut payload_sha256 = [0u8; 32];
        cursor
            .read_exact(&mut payload_sha256)
            .map_err(map_io_error)?;

        if cursor.position() as usize != frame_len {
            return Err(AppError::validation("frame payload length mismatch"));
        }

        let digest = Sha256::digest(&otlp_payload_bytes);
        if digest.as_slice() != payload_sha256 {
            return Err(AppError::validation("payload_sha256 mismatch"));
        }

        Ok(Some(TapeRecord {
            record_type,
            capture_time_unix_nano: capture_time,
            otlp_payload_bytes,
            payload_sha256,
        }))
    }
}

struct BoundedRead<R> {
    inner: R,
    max_bytes: u64,
    read: u64,
}

impl<R> BoundedRead<R> {
    fn new(inner: R, max_bytes: u64) -> Self {
        Self {
            inner,
            max_bytes,
            read: 0,
        }
    }
}

impl<R: Read> Read for BoundedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read = self.read.saturating_add(n as u64);
        if self.read > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "max_decompressed_bytes exceeded",
            ));
        }
        Ok(n)
    }
}

fn read_u32_opt<R: Read>(reader: &mut R) -> io::Result<Option<u32>> {
    let mut buf = [0u8; 4];
    let mut read = 0usize;
    while read < 4 {
        let n = reader.read(&mut buf[read..])?;
        if n == 0 {
            if read == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame_len",
            ));
        }
        read += n;
    }
    Ok(Some(u32::from_le_bytes(buf)))
}

fn map_io_error(err: io::Error) -> AppError {
    if err
        .to_string()
        .to_lowercase()
        .contains("max_decompressed_bytes")
    {
        AppError::validation("tape exceeds max_decompressed_bytes")
    } else if err.kind() == io::ErrorKind::UnexpectedEof {
        AppError::validation("unexpected end of tape")
    } else {
        AppError::validation(format!("tape read error: {err}"))
    }
}

// tests live in crates/incitape-tape/tests
