use std::{
    fs,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn close_without_act_is_dry_run_for_registered_lab_process() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let registry = std::env::temp_dir().join(format!(
        "reaper-autonomy-cli-{}-{unique}.json",
        std::process::id()
    ));
    let mut child = Command::new("sleep")
        .arg("30")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let start_ticks: u64 = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    fs::write(
        &registry,
        format!("[{{\"pid\":{pid},\"start_ticks\":{start_ticks},\"spawned_at\":0}}]\n"),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["close", "--pid", &pid.to_string()])
        .env("REAPER_LAB_REGISTRY", &registry)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("proven=false; no signal"), "{stdout}");
    assert!(
        fs::read_to_string(format!("/proc/{pid}/stat")).is_ok(),
        "dry-run signalled its child"
    );
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "stray lab process"
    );
    fs::remove_file(registry).unwrap();
}
