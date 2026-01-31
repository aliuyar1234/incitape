use assert_cmd::Command;
use std::fs;

#[test]
fn record_refuses_non_loopback_without_tls_auth() {
    let temp = tempfile::tempdir().unwrap();
    let config_path = temp.path().join("config.yaml");
    let config = r#"
recorder:
  grpc_bind: "0.0.0.0:4317"
  http_bind: "127.0.0.1:4318"
"#;
    fs::write(&config_path, config).unwrap();

    let out_dir = temp.path().join("out");
    let mut cmd = Command::new(assert_cmd::cargo_bin!("incitape"));
    cmd.arg("--config")
        .arg(&config_path)
        .arg("record")
        .arg("--out")
        .arg(&out_dir);

    cmd.assert().failure().code(4);
}
