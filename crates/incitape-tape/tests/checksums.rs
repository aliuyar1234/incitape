use incitape_tape::checksums::{verify_checksums, write_checksums};
use tempfile::tempdir;

#[test]
fn checksums_fail_on_mismatch() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("manifest.yaml"), "a").unwrap();
    std::fs::write(dir.path().join("tape.tape.zst"), "b").unwrap();

    write_checksums(dir.path(), &["manifest.yaml", "tape.tape.zst"]).unwrap();
    std::fs::write(dir.path().join("tape.tape.zst"), "c").unwrap();

    let result = verify_checksums(dir.path());
    assert!(result.is_err());
}

#[test]
fn checksums_fail_on_missing_required_entry() {
    let dir = tempdir().unwrap();
    std::fs::write(dir.path().join("manifest.yaml"), "a").unwrap();
    std::fs::write(dir.path().join("tape.tape.zst"), "b").unwrap();

    std::fs::write(dir.path().join("checksums.sha256"), "abc  tape.tape.zst\n").unwrap();

    let result = verify_checksums(dir.path());
    assert!(result.is_err());
}
