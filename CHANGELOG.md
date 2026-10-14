# Changelog

## v0.6.0-tracking-tui — 2026-10-14 (branch `feature/client-tracking-tui`, base `phase-pilot@1a66949`)

Managed client tracking + phone TUI. Supervision stays singleton, read-only
and dry-run; no production closures.

Added:
- `client_tracker.rs` — managed-client registry (stable pid/start/boot
  identity, 5-state model, job relations persisted incl. round-trip fix,
  reload-before-write merge), OpenCode launch wrapper (args/env/exit
  preserved; async signal forwarding documented impossible zero-dep),
  coverage gate defaulting to incomplete (empty registry never idle).
- Policy integration — protection-monotone signal combination
  (active→protect, unknown→block); `proven()` and the 12 rules untouched.
- `tui.rs` (optional `tui` feature: ratatui+crossterm; default build stays
  zero-dep) — read-only process/detail/clients/events views, phone-width
  adaptive, arrows//Enter/t/s/l/q, fast in-process snapshots (0.03 s),
  no destructive bindings, observer-only (full evidence stays in
  `pilot report`).
- `tests/client_coverage.rs` — loopback accept-proxy prototype proving
  per-connection visibility for proxied traffic only, plus lab
  end-to-end transparency test (correct /api/info + auth forwarding).
- `odd/research/client-coverage.md` — per-mechanism contract and
  ManagedOnly recommendation.

Verified on-device: fmt, clippy ×2 feature sets, tests 88+2+2 default and
93+2+2 with tui, release 1.0 MiB default / 1.5 MiB tui, autonomy labs
(abrupt death, 2-client cycle+restart, concurrent observers, coverage
proxy) green with no strays, TUI pty demo rendering real rows with clean
`q` quit. Two real bugs caught by tests: concurrent wrapper completion
lost updates; work-ids dropped on decode — both fixed with regression
tests. Full-suite wall time grew (ambient CLI probes dominate one-shot
reports; documented).

Known limits: external/unmanaged clients permanently Unknown here
(procfs net denied, no client-list APIs); TUI shows CPU as `—`
(snapshot carries none); wrapper cannot forward async signals zero-dep;
live TUI attach and model-backed Codex activity untested; first real
close still requires presence signal + human review + explicit RDD.

## v0.5.0-evidence — 2026-10-14 (branch `phase-pilot`, uncommitted feature `reaper-abandonment-evidence`)

Real abandonment evidence for OpenCode + Codex adapters. Zero production
closures; dry-run everywhere outside lab tests.

Added:
- `evidence.rs` — `ClientWorkState { Active, IdleVerified, Unknown, Error }`
  plus Codex-grade `WorkAbsent` → `(None, Some(true))`; `client_work_to_fields`
  mapping; `proven()` unchanged and conjunctive (verified by tests).
- `queries.rs` — loopback-guarded OpenCode probes: fast HTTP-direct with
  preemptive Basic auth via stdin-config (netrc unusable: 401 without
  WWW-Authenticate), JSON Content-Type for POSTs, CLI-spawn ambient mode
  (30 s timeout); bounded read-only Codex `sqlite3` counts
  (`threads`, non-archived, `queued_items`); bare-array parsers.
- `adapters.rs` — `OpenCodeProbe` full sweep (session.active/list,
  shell/pty, permission/form global, per-session message/inbox/permission
  deep-check capped at 10, server-PID TCP counter) + `assess_fast` engine
  path (never IdleVerified); `CodexProbe` (daemon-version reachability,
  queued→Active, non-archived→Unknown, zero→WorkAbsent, never
  IdleVerified); per-query contract documented in code.
- `main.rs`/`pilot.rs` — engine feeds OpenCode fast-path fields (Unknown
  dominates; 12 policy rules untouched, Blocked-before-proven holds);
  pilot report shows one ambient assessment per call for opencode/codex rows.
- Tests: 78 unit + 2 integration (was 69+2); gated labs
  `REAPER_LAB_OPENCODE=1` (empty/shell/kill-client/remove/history/auth) and
  `REAPER_LAB_CODEX=1` (isolated non-tmp HOME, empty→WorkAbsent, exact-HOME
  daemon cleanup); sqlite fixture-DB tests; secret-redaction tests.

Verified on-device: fmt, clippy `-D warnings`, full suite, release
(~1.0 MiB), both labs green (OpenCode sweep median ~1.2 s; info 22 ms).
Live pilot over production (read-only): real OpenCode activity detected as
Active, Codex reported Unknown with a true 101-thread inventory, every row
Blocked with proven_abandoned=false. No production process touched.

Known limits: /proc/net/tcp{,6} and /proc/net/unix denied on this Termux →
client presence permanently Unknown here (kinds indistinguishable);
Codex RPC framing unverified (all probed framings silent; sqlite path used
instead); live TUI attach and model-backed Codex activity untested;
`session.active` empty proves nothing (verified during running shell).

## v0.4.0-pilot — 2026-10-13 (branch `phase-pilot`, commits `a0402f3`+`a26e888`)

Observation pilot, zero real closures. Dry-run everywhere outside lab tests.

Added:
- `queries.rs` — loopback-only broker GET (3 s timeout), bounded
  `sv status` spawn+parse, meminfo swap, bounded dir sizing; loopback
  enforced, unknown on unparseable (tested).
- `evidence.rs` — owner-dead/last-client/no-work inputs, all
  Unknown-defaulting; `proven()` conjunctive; rescue invalidates.
- `pilot.rs` + CLI — `pilot report` (candidate table with evidence AND
  limitations per row, zero signals), `pilot metrics`, real lifecycle
  (`start` spawns detached observe, `status`, `stop` only verified-own
  child, foreign-pidfile refusal tested).
- Adapters: broker/runit real reads; OpenCode/Codex stay Unknown with
  named missing interfaces (Unfit markers, never production-ready).
- Tests: 67 unit + 2 integration (all 3× green runs observed), concurrency
  (isolated + shared registries), grace-rescue, restart re-arm.

Verified on-device: fmt, clippy `-D warnings`, release. Live: report over
~60 real processes → **0 candidates** (all Blocked/Protected, honest);
metrics RSS ~3.7 MiB, cycles 9–42 ms, swap 5.7/3.1 GiB, logs ~60 KiB;
lifecycle start→status→stop roundtrip real; stale/foreign pidfiles
refused. Independent verifier: 5 PASS + 1 real FAIL (fixed: start now
spawns).

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
