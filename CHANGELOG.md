# Changelog

## v0.3.0-phase3 — 2026-10-13 (branch `phase-3`, commit `8323bfa`)

Safe lab termination. Dry-run default; `--act` only for registry-verified
lab PIDs. Zero production signal paths (audited twice, independently).

Added (`~/reaper-rust/src/`):
- `pidfd.rs` — dependency-free AArch64 `pidfd_open/send_signal/close`
  (NR 434/424/57) + live self/child probes; classic fallback with receipts.
- `terminate.rs` — `ClosePolicy` (grace 300 s, TERM wait 30 s, KILL opt-in),
  `Signaller`/`SignalExecutor`, `close_sequence` (official-first →
  revalidate → TERM → wait → revalidate → authorized KILL → reap receipt),
  registry+identity pre-checks per signal, dry-run executor, auditable
  refusals; single audited flow (cleanup unified into it).
- `lab.rs` — lab-only spawners (`sleep`, TERM-ignoring `sh`), accumulating
  registry (`REAPER_LAB_REGISTRY` override for tests), verified cleanup.
- `evidence.rs` — `AbandonEvidence` (lab_member + owner + grace_expired +
  revalidated_now); `proven()` true only with all four; positive-vs-absent.
- `adapters.rs` — OpenCode (shared/standalone) + Codex (daemon) readers:
  clients Unknown unless proven; stops prepared as data, declined for
  production; lab-authorized path for lab targets only.
- `main.rs` — `lab` + `close --pid [--act]` CLI; observe feeds owner
  verdicts into evidence (`proven` false outside lab).

Verified on-device: fmt, clippy `-D warnings`, **57 tests ×3 runs**,
release 859 KiB. Live lab: dry-run refusal pre-grace; `--act` friendly
TERM→natural-exit via Pidfd (30 s); `--act` on PID 1 refused (no registry);
TERM-ignorer → authorized KILL → reaped (test). Race fixed: pidfd test
shares lab TEST_LOCK + restores env. Fail-closed: pidfd-send errors refuse
instead of falling through; EINVAL root-caused to 4-arg wrapper.

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

## v0.2.1-phase2-closeout — 2026-10-13 (branch `phase-2`, commit `bea1d25`)

- `procfs::scan_root()` + test con árbol falso (permiso denegado, basura,
  PID cruzado, no-numéricos): 1 válido, 2 skipped_stat, 1 skipped_mismatch,
  sin abortar.
- `events`: test `ScanDegraded` emite el evento Y procesa los vivos del
  mismo ciclo; el ciclo siguiente sigue normal.
- `owner.rs` nuevo: claims desde `supervise/pid` + flag `down`, con
  anti-reciclaje por starttime; cableado a `observe` (mapa por ciclo) e
  `inspect`; `proven_abandoned` sigue `false` (down ⇒ observado, jamás
  candidato). Tests: claim vivo, down vs activo, stale rechazado, basura y
  svdir ausente sin pánico.
- `identity`: `kernel_major_minor` + `pidfd_compat()` (release, header,
  linked=false estructural) + tests de parser y de auto-consistencia viva.
- Vivo: 39 tests, clippy limpio, release; runsv corroborado absoluto;
  `supervise/pid` vacíos ⇒ correctamente sin claims; observe 6–12 ms,
  RSS 3.7 MiB, CPU 0 ticks; reinicios previos recuperan estado.

## v0.1.0-phase1 — baseline (tag `phase-1`)

Read-only observer: `scan | inspect | observe`, 5 unit tests, ~2.9 MiB
scan RSS. Preserved intact as commit `3a83c39`, tag `phase-1`.
