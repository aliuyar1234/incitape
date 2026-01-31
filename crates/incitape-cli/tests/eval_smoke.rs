use assert_cmd::Command;
use std::fs;
use tempfile::tempdir;

fn write_suite(path: &std::path::Path, tapes_dir: &std::path::Path) {
    let suite = format!(
        r#"
version: 1
name: "smoke"
tapes_dir: '{}'
thresholds:
  top1_micros: 0
  top3_micros: 0
  mrr_micros: 0
scenarios:
  - id: "s1"
    seed: 1
    services: 3
    fanout: 1
    traces: 5
    fault:
      kind: "error"
      target_index: 1
"#,
        tapes_dir.to_string_lossy()
    );
    fs::write(path, suite).unwrap();
}

#[test]
fn eval_generate_and_run() {
    let temp = tempdir().unwrap();
    let suite_path = temp.path().join("suite.yaml");
    let tapes_dir = temp.path().join("eval_out").join("smoke");
    write_suite(&suite_path, &tapes_dir);

    let mut gen = Command::new(assert_cmd::cargo_bin!("incitape"));
    gen.arg("eval")
        .arg("generate")
        .arg("--suite")
        .arg(&suite_path)
        .arg("--out")
        .arg(&tapes_dir);
    gen.assert().success();

    let eval_out = temp.path().join("eval.json");
    let mut run = Command::new(assert_cmd::cargo_bin!("incitape"));
    run.arg("eval")
        .arg("run")
        .arg("--suite")
        .arg(&suite_path)
        .arg("--out")
        .arg(&eval_out);
    run.assert().success();

    assert!(eval_out.exists());
}

#[test]
fn eval_refuses_overwrite_without_flag() {
    let temp = tempdir().unwrap();
    let suite_path = temp.path().join("suite.yaml");
    let tapes_dir = temp.path().join("eval_out").join("smoke");
    write_suite(&suite_path, &tapes_dir);

    let mut gen = Command::new(assert_cmd::cargo_bin!("incitape"));
    gen.arg("eval")
        .arg("generate")
        .arg("--suite")
        .arg(&suite_path)
        .arg("--out")
        .arg(&tapes_dir);
    gen.assert().success();

    let eval_out = temp.path().join("eval.json");
    fs::write(&eval_out, "sentinel").unwrap();
    let mut run = Command::new(assert_cmd::cargo_bin!("incitape"));
    run.arg("eval")
        .arg("run")
        .arg("--suite")
        .arg(&suite_path)
        .arg("--out")
        .arg(&eval_out);
    run.assert().failure().code(2);

    let contents = fs::read_to_string(&eval_out).unwrap();
    assert_eq!(contents, "sentinel");
}
