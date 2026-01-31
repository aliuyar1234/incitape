use byteorder::{LittleEndian, WriteBytesExt};
use incitape_tape::bounds::Bounds;
use incitape_tape::format::MAGIC;
use incitape_tape::reader::TapeReader;
use incitape_tape::record::RecordType;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use tempfile::tempdir;

fn build_frame(
    record_type: u8,
    capture_time: u64,
    payload: &[u8],
    frame_len_override: Option<u32>,
    hash_override: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut frame = Vec::new();
    let frame_len = frame_len_override.unwrap_or((1 + 8 + 4 + payload.len() + 32) as u32);
    frame.write_u32::<LittleEndian>(frame_len).unwrap();
    frame.write_u8(record_type).unwrap();
    frame.write_u64::<LittleEndian>(capture_time).unwrap();
    frame
        .write_u32::<LittleEndian>(payload.len() as u32)
        .unwrap();
    frame.extend_from_slice(payload);
    let hash = hash_override.unwrap_or_else(|| {
        let digest = Sha256::digest(payload);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    });
    frame.extend_from_slice(&hash);
    frame
}

fn build_tape_bytes(magic: [u8; 8], version: u16, flags: u16, frames: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&magic);
    bytes.write_u16::<LittleEndian>(version).unwrap();
    bytes.write_u16::<LittleEndian>(flags).unwrap();
    for frame in frames {
        bytes.extend_from_slice(frame);
    }
    bytes
}

fn write_compressed(path: &std::path::Path, decompressed: &[u8]) {
    let compressed = zstd::stream::encode_all(Cursor::new(decompressed), 0).unwrap();
    std::fs::write(path, compressed).unwrap();
}

#[test]
fn reader_rejects_bad_magic() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let mut bad_magic = MAGIC;
    bad_magic[0] ^= 0xFF;
    let bytes = build_tape_bytes(bad_magic, 1, 0, &[]);
    write_compressed(&path, &bytes);

    let result = TapeReader::open(&path, Bounds::default());
    assert!(result.is_err());
}

#[test]
fn reader_rejects_bad_version() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let bytes = build_tape_bytes(MAGIC, 2, 0, &[]);
    write_compressed(&path, &bytes);

    let result = TapeReader::open(&path, Bounds::default());
    assert!(result.is_err());
}

#[test]
fn reader_rejects_frame_len_mismatch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let frame = build_frame(1, 1, b"abc", Some(999), None);
    let bytes = build_tape_bytes(MAGIC, 1, 0, &[frame]);
    write_compressed(&path, &bytes);

    let reader = TapeReader::open(&path, Bounds::default()).unwrap();
    let result = reader.read_all_sorted();
    assert!(result.is_err());
}

#[test]
fn reader_rejects_payload_hash_mismatch() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let mut hash = [0u8; 32];
    hash[0] = 1;
    let frame = build_frame(1, 1, b"abc", None, Some(hash));
    let bytes = build_tape_bytes(MAGIC, 1, 0, &[frame]);
    write_compressed(&path, &bytes);

    let reader = TapeReader::open(&path, Bounds::default()).unwrap();
    let result = reader.read_all_sorted();
    assert!(result.is_err());
}

#[test]
fn reader_orders_canonical() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let frame_a = build_frame(RecordType::Logs.as_u8(), 2, b"b", None, None);
    let frame_b = build_frame(RecordType::Traces.as_u8(), 1, b"a", None, None);
    let bytes = build_tape_bytes(MAGIC, 1, 0, &[frame_a, frame_b]);
    write_compressed(&path, &bytes);

    let reader = TapeReader::open(&path, Bounds::default()).unwrap();
    let records = reader.read_all_sorted().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].capture_time_unix_nano, 1);
    assert_eq!(records[0].record_type, RecordType::Traces);
}

#[test]
fn reader_respects_max_record_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let payload = vec![0u8; 8];
    let frame = build_frame(1, 1, &payload, None, None);
    let bytes = build_tape_bytes(MAGIC, 1, 0, &[frame]);
    write_compressed(&path, &bytes);

    let bounds = Bounds {
        max_record_bytes: 4,
        max_frame_len: 4 + 64,
        max_decompressed_bytes: 1024,
        max_tape_file_bytes: 1024,
        max_records_per_tape: 10,
    };

    let reader = TapeReader::open(&path, bounds).unwrap();
    let result = reader.read_all_sorted();
    assert!(result.is_err());
}

#[test]
fn reader_respects_max_decompressed_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let frame = build_frame(1, 1, b"payload", None, None);
    let bytes = build_tape_bytes(MAGIC, 1, 0, &[frame]);
    write_compressed(&path, &bytes);

    let bounds = Bounds {
        max_record_bytes: 1024,
        max_frame_len: 1024 + 64,
        max_decompressed_bytes: 12,
        max_tape_file_bytes: 1024,
        max_records_per_tape: 10,
    };

    let reader = TapeReader::open(&path, bounds).unwrap();
    let result = reader.read_all_sorted();
    assert!(result.is_err());
}
