use assert_cmd::Command;
use std::fs;

#[test]
fn record_writes_tape_dir() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    let config = r#"
recorder:
  grpc_bind: "127.0.0.1:0"
  http_bind: "127.0.0.1:0"
"#;
    fs::write(&config_path, config).unwrap();

    let out_dir = temp.path().join("tape");
    let mut cmd = Command::new(assert_cmd::cargo_bin!("incitape"));
    cmd.arg("--config")
        .arg(&config_path)
        .arg("record")
        .arg("--out")
        .arg(&out_dir)
        .arg("--duration")
        .arg("1");

    cmd.assert().success();

    assert!(out_dir.join("manifest.yaml").exists());
    assert!(out_dir.join("tape.tape.zst").exists());
    assert!(out_dir.join("checksums.sha256").exists());

    let mut validate_cmd = Command::new(assert_cmd::cargo_bin!("incitape"));
    validate_cmd.arg("validate").arg(&out_dir).arg("--strict");
    validate_cmd.assert().success();
}
