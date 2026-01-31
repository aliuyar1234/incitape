use assert_cmd::Command;

#[test]
fn help_lists_commands() {
    let mut cmd = Command::new(assert_cmd::cargo_bin!("incitape"));
    let output = cmd
        .arg("--help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8_lossy(&output);
    for name in [
        "record", "replay", "analyze", "report", "eval", "validate", "minimize",
    ] {
        assert!(text.contains(name), "missing command {name}");
    }
}
