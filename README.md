# Reaper — Rust phase 1 (read-only)

This is the first, deliberately **non-destructive** Rust core for Android/Termux. Its purpose is to inventory visible processes, give conservative classifications, watch process appearances/disappearances and write UTC daily JSONL logs. It **cannot terminate, pause or restart any process**. It does not require ADB, root, systemd, Ubuntu or external Cargo dependencies.

## Install and run on Termux

```sh
pkg install rust
cd ~/reaper-rust
cargo test
cargo build --release
./target/release/reaper scan
./target/release/reaper inspect 12345
./target/release/reaper observe 30
```

Stop observer with Ctrl+C. All observations use normal Termux UID permissions and can omit inaccessible processes. Logs are `~/.local/state/reaper/logs/YYYY-MM-DD.jsonl` (UTC). `XDG_STATE_HOME` is respected. This build does not store command-line arguments in logs to avoid common secret leaks. `inspect` prints only executable argv[0].

## Crucial security properties

- No `kill`, shelling out, signal-sending, service stop, or ADB operations anywhere in the code.
- Every visible process is either critical, session, managed-protected, or unknown-protected. Classification is **not** evidence of abandonment.
- Protect `com.termux`, Reaper and runit supervisors by identity / executable hints. **Do not use classifications in this build to authorize termination.**
- Correctly parse `/proc/<pid>/stat` with a command name containing spaces or `)`; preserve `(pid,start_ticks)` identity on observations.
- Logs are daily UTC files; they log transitions rather than every unchanged process.

## Explicit limitations

- Logs will include process names and identifiers; inspect before sharing.
- RSS is not the amount of unique memory recoverable by killing a process. `VmSwap` may not be available.
- Linux procfs can hide fields and processes on Android. Empty/partial scans are not proof of inactivity.
- Some protections require examining the actual installed Termux APK and current process ancestry. Rules based on names alone are provisional; no production killing should use them.
- This stage has **no** TUI, process-client inference, grace timer, automatic closure, adaptive policies, log retention, IPC, or ADB integration. Those are later phases.
- Developer environment used to create this bundle does not contain Rust/Cargo, so tests **have not been run here**. Run `cargo test` on Termux and report compiler/test output before proceeding.
