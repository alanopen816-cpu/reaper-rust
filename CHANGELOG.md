# Changelog

## v0.2.0-phase2 — 2026-10-13 (branch `phase-2`)

Observable supervisor, still termination-incapable by construction.

Added (`~/reaper-rust/src/`):
- `procfs.rs` — tolerant /proc reader; one bad PID never aborts a scan
  (skipped counters instead). Evolved from phase-1 parsing, now with
  pgrp/session fields.
- `identity.rs` — `(boot_id, pid, start_ticks, uid, exe)` + `verify()`
  anti-reuse; pidfd evaluated, deliberately not linked (zero-dep;
  double-revalidation fallback documented).
- `relations.rs` — parent/child trees, sessions, groups, decoupled flags,
  watchdog hints requiring name+ancestry (name alone never suffices);
  every claim tagged Verified/Inferred.
- `events.rs` — appeared/disappeared/identity-changed/owner-exited/
  state-changed/scan-degraded; recycled PIDs surface as death+birth;
  owner-exit fires on transition only (no log spam).
- `state.rs` — 9-state machine, full transition records, atomic
  persist (tmp+rename), reload that discards recycled PIDs and re-arms
  graces (never trusts old timers).
- `policy.rs` — the 12 mandatory rules as code; memory pressure input is
  accepted and deliberately ignored; unknown stays protected.
- `protection.rs` — Absolute/Contextual/Known/Unknown tiers; supervisor
  names need ancestry corroboration for Absolute; out-of-UIDScope absolute.
- `logx.rs` — daily JSONL, ERROR..TRACE, size rotation, day retention,
  secret redaction, transitions-only logging.
- `stats.rs` — own RSS/CPU ticks + per-cycle health summary.
- `adapters.rs` — GenericLinux/Runit/McpBroker/OpenCode/Codex traits;
  liveness honestly Unknown; every shutdown returns DeclinedPhase2.
- `main.rs` — `scan` (tier table), `inspect` (identity+relations+
  protection+decision+shutdown verdict), `observe` (default 30 s loop).

Verified on-device (Termux, ARM64, `rustc 1.98.1`):
- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
  `cargo test` → 32 passed, `cargo build --release` → 745 KiB binary.
- Real `scan`: 52 processes, 28 sessions, 31 groups, 9 watchdog hints.
- Real `observe 5` (3 cycles): first cycle 60 events/51 transitions,
  steady state ~1/1; cycle 5–31 ms; self RSS 3.6 MiB, CPU ticks 0.
- Restart recovery live: `recovered=48 discarded_recycled=3`.
- Signal audit: no `kill`, no `libc`, no `unsafe` in `src/`.

## v0.1.0-phase1 — baseline (tag `phase-1`)

Read-only observer: `scan | inspect | observe`, 5 unit tests, ~2.9 MiB
scan RSS. Preserved intact as commit `3a83c39`, tag `phase-1`.
