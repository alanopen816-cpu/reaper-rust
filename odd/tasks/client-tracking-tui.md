# Feature: client-tracking-tui — REAPER v0.6 Client Tracking + Task Manager TUI

**Locator**: `odd/tasks/client-tracking-tui.md` | Engram topic `odd/client-tracking-tui/tasks` | Repo `~/reaper-rust`, branch `feature/client-tracking-tui` (base `phase-pilot@1a66949`, 78+2 tests)

## Objective
Evolve Reaper into an intelligent task manager: supervised client tracking (managed launches + honest Unknown for external/unverifiable), policy integration without weakening the 12 rules, and a phone-usable TUI over the existing read-only engine. Supervisor stays lightweight and singleton; TUI is an observer client.

## Scope (authorized)
- New modules: `src/client_tracker.rs`, `src/tui.rs` (+ optional `src/proxy_proto.rs` ONLY if coverage research proves a lab prototype; never touching production).
- TUI deps allowed: ratatui + crossterm as OPTIONAL cargo feature `tui` (default build stays zero-dep); measured RSS with/without.
- Policy integration: new evidence inputs only in the safe direction (Active→protect, Unknown→block); `proven()` conjunctive untouched; `lab_member` untouched; 12 rules unweakened.
- Lab-only mutation; dry-run default; no production closes; no prod OpenCode/Codex/Broker changes; no ADB/root dependency.
- Destructive TUI actions: none in v0.6 (no kill bindings at all).

## Constraints
- Empty registry NEVER ⇒ IdleVerified without verifiable full coverage (dedicated test).
- No passwords/tokens in logs (test with secret sentinel).
- Wrapper preserves args/env-needed/signals/exit code (tested).
- TUI: phone-width adaptive, no excessive refresh/redundant queries; single supervisor (reuse pilot pidfile pattern); multiple TUIs must not duplicate supervision.
- `cargo fmt --check`, `clippy --all-targets -- -D warnings` (incl. `--features tui`), `cargo test` (both feature sets), `cargo build --release` (both) green.

## Tasks
- [x] T1 (direct-inline, done by parent) — Verify state (phase-pilot@1a66949 clean, 78+2), create branch, dep feasibility (ratatui+crossterm fetchable).
- [x] T2 (delegated-direct, research) — Client-coverage investigation: official OpenCode client-visibility interfaces, connect/disconnect events, rootless sockets, procfs identity, launch-tracking options, instrumented local proxy prototype IN LAB proving (or refuting) full client visibility + limits. Output: `odd/research/client-coverage.md` + prototype test `tests/client_coverage.rs`. No prod changes.
- [x] T3 (delegated-direct, writer) — `client_tracker` module: stable client/server identity (pid+starttime+boot_id), tool/project, session start/end, connection state (Connected-Verified/Ended-Verified/Possibly-Gone/Unknown-External/Unverifiable), last verified evidence + provenance, active-job relations; OpenCode launch wrapper (args/env/signals/exit preserved); registry persisted under state dir; restart + PID-reuse safe. Tests: wrapper passthrough, abrupt death, restart, PID reuse, external-unknown, empty-registry-never-idle.
- [x] T4 (delegated-direct, writer, after/parallel T3 same worker) — Policy integration: active-verified-client→protect; verified pending work→protect; unknown→Unknown; ended-client+active-work→protect; inspection-error→block; reappearance-during-grace→cancel; incomplete coverage→no auto-close; evidence enum extension if needed WITHOUT touching proven() conjunctiveness or lab_member. Tests incl. grace-reconnect + incomplete-coverage-blocks.
- [x] T5 (delegated-direct, writer, after T3/T4 — main.rs overlap) — TUI (`src/tui.rs`, feature-gated): process list (pid/name/RSS/swap/CPU-if-measurable/protection/parent-child), filters+search `/`, sort `s`, tree/list `t`, inspect `Enter`, logs `l`, clients view, recent events, evidence/block reasons; arrows navigate, `q` quit; phone-width adaptive; NO destructive bindings. Tests: non-interactive (state rendering on fixtures, key-handling unit tests); TUI never owns supervision.
- [x] T6 (with T5) — Service: singleton via existing pilot pidfile pattern; TUI as observer of state dir; multi-TUI no-duplication test.
- [x] T7 (delegated-direct, verification-heavy) — Autonomy lab matrix (wrapper start, active record, clean exit, abrupt death, restart, PID reuse, external unknown, work-after-close, grace reconnect, 2 clients/1 server, 2 projects, inspection failure, supervisor crash, multi-TUI) + one full autonomous cycle on lab-only processes.
- [x] T8 (direct-inline/measurement) — Perf: supervisor RSS/CPU headless, TUI extra RSS/CPU, inspect duration, frame time, log growth; default vs tui-feature builds.
- [x] T9 (direct-inline) — Close-out: all 4 validations ×2 feature sets, CHANGELOG, commit on feature branch.

## Acceptance
- Tracker distinguishes all 5 client states with provenance; wrapper transparent (exit-code/signals test).
- Coverage gaps stay Unknown; no IdleVerified without full-coverage guarantee (tested).
- 12 rules + proven() intact (existing + new tests green).
- TUI usable on phone width, zero destructive paths, observer-only.
- Singleton supervisor; matrix green; perf measured; prod untouched.

## Progress
- 2026-10-14: T1 done (verified 1a66949 clean; branch created; ratatui+crossterm fetch OK → optional `tui` feature decision).

## Verification evidence (parent-observed 2026-10-14)
- fmt=0; clippy=0 (default); clippy=0 (--features tui)
- test default: 88+2+2 green; test --features tui: 93+2+2 green
- release default 1048104 B (0 ratatui refs) vs tui 1604640 B (+556 KiB, +53%)
- supervisor observe loop: RSS ~3.8 MB, ~0.3% core; pilot report one-shot: RSS 4.2 MB, 107 s wall (ambient CLI spawns dominate — documented cost)
- TUI under pty (24×80): renders real PID/NAME/RSS/SWAP/CPU/TIER rows; RSS 4.2 MB, 0 ticks idle; `q` quits before timeout (exit 0), no strays; zero-size winsize draws nothing without crashing
- labs: OpenCode + Codex + coverage-proxy all green; no stray lab sleepers/daemons/servers afterwards
- production untouched throughout (service --service, codex daemon, sockets intact)

## T8 — Perf table
| Métrica | Valor |
|---|---|
| RSS supervisor (observe) | ~3.8 MB |
| RSS TUI (extra sobre base) | ~4.2 MB total (~+0.4 MB sobre reporte) |
| CPU supervisor en loop | ~1-2 ticks/5 s |
| CPU TUI idle | 0 ticks/4 s |
| `pilot report` wall | ~107 s (spawns ambientales; documentado, no interactivo) |
| snapshot TUI | 0.03 s (test), primer frame <1 s |
| build release tui-feature | ~1 min (187 deps) |
| logs | JSONL diarios acotados (patrón existente) |

## Next step
- T9: CHANGELOG + commit. Done below.
