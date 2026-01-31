use incitape_tape::bounds::Bounds;
use incitape_tape::record::RecordType;
use incitape_tape::writer::TapeWriter;
use tempfile::tempdir;

#[test]
fn writer_enforces_max_tape_file_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let bounds = Bounds {
        max_record_bytes: 8,
        max_frame_len: 8 + 64,
        max_decompressed_bytes: 1024,
        max_tape_file_bytes: 1,
        max_records_per_tape: 10,
    };

    let mut writer = TapeWriter::create(&path, bounds).unwrap();
    let payload = vec![0u8; 1024];
    let write_result = writer.write_record(RecordType::Traces, 1, &payload);
    let finish_result = if write_result.is_ok() {
        writer.finish().err()
    } else {
        None
    };
    assert!(write_result.is_err() || finish_result.is_some());
}

#[test]
fn writer_enforces_max_records_per_tape() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let bounds = Bounds {
        max_record_bytes: 8,
        max_frame_len: 8 + 64,
        max_decompressed_bytes: 1024,
        max_tape_file_bytes: 1024,
        max_records_per_tape: 1,
    };

    let mut writer = TapeWriter::create(&path, bounds).unwrap();
    writer.write_record(RecordType::Traces, 1, b"a").unwrap();
    let result = writer.write_record(RecordType::Traces, 2, b"b");
    assert!(result.is_err());
}

#[test]
fn writer_enforces_max_record_bytes() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("tape.tape.zst");
    let bounds = Bounds {
        max_record_bytes: 1,
        max_frame_len: 1 + 64,
        max_decompressed_bytes: 1024,
        max_tape_file_bytes: 1024,
        max_records_per_tape: 10,
    };

    let mut writer = TapeWriter::create(&path, bounds).unwrap();
    let result = writer.write_record(RecordType::Traces, 1, b"toolarge");
    assert!(result.is_err());
}
