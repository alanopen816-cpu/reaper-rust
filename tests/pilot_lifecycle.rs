use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn isolated_state() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home =
        std::env::temp_dir().join(format!("reaper-pilot-test-{}-{unique}", std::process::id()));
    fs::create_dir_all(&home).unwrap();
    home
}

fn invoke(home: &PathBuf, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(args)
        .env("HOME", home)
        .env("XDG_STATE_HOME", home.join("state"))
        .output()
        .unwrap()
}

fn pidfile(home: &Path) -> PathBuf {
    home.join("state/reaper/pilot.pid")
}

#[test]
fn lifecycle_roundtrip_and_double_start_refusal() {
    let home = isolated_state();
    {
        let start = invoke(&home, &["pilot", "start", "--interval", "5"]);
        assert!(
            start.status.success(),
            "{}",
            String::from_utf8_lossy(&start.stderr)
        );
        let _: u32 = fs::read_to_string(pidfile(&home))
            .unwrap()
            .split("\"pid\":")
            .nth(1)
            .unwrap()
            .split(',')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let status = invoke(&home, &["pilot", "status"]);
        assert!(status.status.success());
        assert!(String::from_utf8_lossy(&status.stdout).contains("pilot running"));
        let second = invoke(&home, &["pilot", "start", "--interval", "5"]);
        assert!(
            !second.status.success(),
            "double start unexpectedly succeeded"
        );
        let stop = invoke(&home, &["pilot", "stop"]);
        assert!(
            stop.status.success(),
            "{}",
            String::from_utf8_lossy(&stop.stderr)
        );
        let stopped = invoke(&home, &["pilot", "status"]);
        assert!(stopped.status.success());
        assert!(String::from_utf8_lossy(&stopped.stdout).contains("pilot stopped"));
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn stale_pidfile_is_replaced_and_foreign_pidfile_is_preserved_on_stop() {
    let home = isolated_state();
    let file = pidfile(&home);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(&file, "{\"pid\":99999999,\"start_ticks\":0}\n").unwrap();
    let start = invoke(&home, &["pilot", "start", "--interval", "5"]);
    assert!(
        start.status.success(),
        "{}",
        String::from_utf8_lossy(&start.stderr)
    );
    let pid: u32 = fs::read_to_string(&file)
        .unwrap()
        .split("\"pid\":")
        .nth(1)
        .unwrap()
        .split(',')
        .next()
        .unwrap()
        .parse()
        .unwrap();
    {
        assert_ne!(pid, 99999999);
        let stop = invoke(&home, &["pilot", "stop"]);
        assert!(stop.status.success());
        fs::write(&file, "{\"pid\":1,\"start_ticks\":0}\n").unwrap();
        let refused = invoke(&home, &["pilot", "stop"]);
        assert!(!refused.status.success());
        assert!(file.exists(), "foreign pidfile was removed");
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn pilot_smoke_runs_a_bounded_number_of_read_only_cycles() {
    let home = isolated_state();
    let output = invoke(&home, &["pilot", "smoke", "2"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pilot smoke complete"), "{stdout}");
    assert!(stdout.contains("cycles=2"), "{stdout}");
    let _ = fs::remove_dir_all(home);
}

#[test]
fn pilot_source_has_no_wakelock_api_and_read_only_guards_actuation() {
    let main = fs::read_to_string("src/main.rs").unwrap();
    let pilot = fs::read_to_string("src/pilot.rs").unwrap();
    for forbidden in ["WakeLock", "PartialWakeLock", "acquireWakeLock"] {
        assert!(!main.contains(forbidden), "main.rs contains {forbidden}");
        assert!(!pilot.contains(forbidden), "pilot.rs contains {forbidden}");
    }
    assert!(main.contains("PILOT_READ_ONLY.load"));
    assert!(main.contains("--pilot-read-only"));
    assert!(main.contains("!PILOT_READ_ONLY.load") && main.contains("schedule_deep_targets"));
}
