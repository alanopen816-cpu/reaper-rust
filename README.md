# Reaper — Rust supervisor (phase 2: observable, still read-only)

Phase 1 (read-only observer) plus the Phase-2 engine: stable identity
`(boot_id, pid, start_ticks, uid, exe)`, relationship trees with
verified-vs-inferred evidence, lifecycle events, a 9-state machine with
auditable transitions, the 12-rule policy engine, 3-tier protection, daily
JSONL logs (levels, rotation, retention, redaction), self metrics and
decoupled owner adapters whose every shutdown request is declined by value.
It **cannot terminate, pause or restart any process**: no signalling code
exists (`grep -i kill/signal` hits only comments and the `Signals` input
struct; no `libc`, no `unsafe`). It does not require ADB, root, systemd,
Ubuntu or external Cargo dependencies (zero deps).

This is the first, deliberately **non-destructive** Rust core for Android/Termux. Its purpose is to inventory visible processes, give conservative classifications, watch process appearances/disappearances and write UTC daily JSONL logs. It **cannot terminate, pause or restart any process**. It does not require ADB, root, systemd, Ubuntu or external Cargo dependencies.

## Phase 2: run the supervisor

```sh
cd ~/reaper-rust
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --release
./target/release/reaper scan
./target/release/reaper inspect <PID>
./target/release/reaper observe 30
```

`observe` recovers `supervisor.json` without trusting old PIDs or timers
(recycled identities are discarded, graces re-arm), then loops: scan →
events → protect → policy → transitions → persist → daily log. Stop with
Ctrl+C. First cycle logs every sighting; steady state logs only changes.

## Install and run on Termux (phase 1 commands still work)

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
- pidfd is evaluated but not linked: headers exist (`$PREFIX/include/sys/pidfd.h`),
  kernel side expected (Android 16, SDK 36), but the registry here offers only a
  pre-release libc, which is unacceptable for a security supervisor. The
  implementation is double revalidation via `(pid, start_ticks, uid)`; the
  `pidfd:` status line says so explicitly. No `pidfd_send_signal` wrapper
  exists anywhere in this phase.
- Owner liveness is honestly `Unknown` for every adapter in this phase
  (endpoint/version presence never proves idleness), so the policy keeps or
  blocks everything: grace arms only in unit tests, never in production runs.
  Wiring real owner reads (`sv status`, broker `/health`) is Phase-3 work.
- This stage has **no** TUI, process-client inference, IPC, or ADB integration.
