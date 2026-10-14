# Feature: reaper-v0.7 — Performance, Client Coverage & Task Manager

**Locator**: `odd/tasks/reaper-v0.7.md` | Engram topic `odd/reaper-v0.7/tasks` | Repo `/data/data/com.termux/files/home/reaper-rust`, base `feature/client-tracking-tui@7567405` → new `feature/reaper-v0.7`
**Base verified 2026-10-14**: branch feature/client-tracking-tui, commit 7567405, tree clean; CPU placeholder `src/tui.rs:369-371` confirmed; `coverage_complete()` always false `src/client_tracker.rs:313-316` confirmed; pilot deep probes sequential `src/pilot.rs:27-45` + `src/adapters.rs:187-320` confirmed.

## Objective
Evolve Reaper v0.6 into a fast, stable, extensible Termux process manager ready for safe automation: Fast/Deep inspection split, verifiable client-coverage contract, usable TUI, general process classification, lab-demonstrated autonomous cycle — with all 12 safety rules intact.

## Problem / Why
- `pilot report` ~107 s wall (ambient CLI spawns dominate) — unusable for interactive supervision/TUI.
- Coverage is ManagedOnly; empty registry never implies idle, but there is no explicit coverage contract (CompleteVerified/Partial/Unknown/Broken) and no adversarial lab proof.
- TUI shows `—` for CPU, tree view is prefix-only, snapshot runs synchronously on render thread, 0×0/resize robustness incomplete.
- Classification leans on OpenCode/Codex particulars; unknown stays protected but generality + extensibility missing.
- No end-to-end autonomous close cycle demonstrated on lab-only processes.

## Scope (authorized)
- Branch `feature/reaper-v0.7` from `feature/client-tracking-tui@7567405`; preserve prior commits/tags.
- Modules allowed: `src/pilot.rs`, `src/queries.rs`, `src/adapters.rs`, `src/client_tracker.rs`, `src/tui.rs`, `src/procfs.rs`, `src/stats.rs`, `src/identity.rs`, `src/relations.rs`, `src/evidence.rs`, `src/owner.rs`, `src/policy.rs`, `src/protection.rs`, `src/state.rs`, `src/lab.rs`, `src/main.rs`, `src/logx.rs`, `src/events.rs` (+ new `src/scan.rs`/`src/coverage.rs` ONLY if writer justifies no second incompatible registry).
- Tests: `tests/` + unit tests in-module. New lab server/helpers in `src/lab.rs` or new `src/lab_coverage.rs` (lab-only).
- Docs: `CHANGELOG.md`, `README.md`, `odd/tasks/reaper-v0.7.md`, docs repo `/data/data/com.termux/files/home/reaper` updates (CHANGELOG-equivalent) — no production OpenCode/Codex/Broker changes.
- Lab-only mutation; dry-run default; `--act` only on lab-owned PIDs with explicit scope authorization; never auto-close production (OpenCode, Codex, MCPs, shells, services).
- No invented evidence; stale cache never authorizes termination; failed query never equals absent clients.

## Constraints
- 12 safety rules untouched (proven_abandoned conjunctive, absolute protection, identity revalidation, active-session protection, grace cancel, Unknown/Error block, dry-run default, official-close-first, SIGTERM-before-SIGKILL, PID-reuse guard, auditable logs).
- No unbounded parallelism; bounded concurrency + configurable timeouts + cancellation over budget only.
- No new process per read where avoidable; count aux spawns in benchmarks.
- TUI is supervisor client; no second supervision; no deep queries on render thread; no destructive bindings for production.
- Checks: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo build --release`, each ×2 (default + `--features tui`); all existing labs green; no deleted tests to get green.

## Tasks
- [ ] V7-T1 (direct-inline, parent) — Branch + baseline: create `feature/reaper-v0.7`, record before-benchmarks (RSS supervisor/TUI, CPU idle, Fast=n/a, Deep=pilot ~107 s, snapshot 0.03 s, aux-spawn count, log size). Route: inline. Trigger evidence: ≤3 calls, bounded reads.
- [ ] V7-T2 (delegated-direct, writer) — P1 inspection perf: stage instrumentation (proc-scan/classify/relations/adapters/opencode/codex/clients/persist/report/logs with duration/errors/timeout/ops); Fast Scan (light procfs+registry+owner, never blocks on slow adapters) vs Deep Inspection (on-demand/scheduled, cancellable, cached non-critical, snapshot reuse, incremental); bounded concurrency, timeouts, aux-spawn cap, memory/task caps. Keep safety locks. Tests: adapter-timeout, partial-failure, stale-cache-never-authorizes. Route: delegated (2+ non-trivial files). Files: pilot/queries/adapters/procfs/stats (+new scan module if justified).
- [ ] V7-T3 (delegated-direct, writer) — P2 coverage contract: extend `client_tracker` (no second registry) with `Coverage{CompleteVerified,Partial,Unknown,Broken}` + active/ended/external/pending-work/finished states; full-coverage proof requires all transports in observed scope + direct-bypass adversarial test degrades; isolated lab server demoing 12 scenarios (2 connected, 1 disconnect, 1 active, last disconnect, lingering work, work finish, grace reconnect, direct-bypass attempt, server restart, event loss, auth error, partial). Never force production through proxy. Tests: concurrency, direct-bypass, abrupt disconnect, persistent work, restart, event-loss. Route: delegated.
- [ ] V7-T4 (delegated-direct, writer) — P3 TUI: real per-process CPU via /proc delta (time-aware, PID-reuse safe, `—` when uncomputable; cumulative≠instant); 0×0/resize/small-terminal fixes; vanished-selection/failed-read/overlong-data/nonblocking-refresh/clean-restore; main columns + stats bar (only verifiable metrics); sort CPU/RSS/swap/name, tree/list, search `/`, details (why protected + missing evidence), events/clients/evidence/blocks/help/manual-refresh/clean-exit; supervisor-client architecture. Tests: zero-size, resize, wrong-CPU, recycled-PID, multi-TUI, self-close. Route: delegated.
- [ ] V7-T5 (delegated-direct, writer, after T2) — P4 general classification: persistent/interactive/build/aux/dev-tools/local-servers/watchdog/independent/unknown/critical via identity+relations+evidence (not name-only); extensible adapter/policy hooks; unknown stays protected; orphan-PPID≠abandoned; no Broker duplication. Tests: unknown-protected, orphan-not-abandoned, extensibility hook. Route: delegated.
- [ ] V7-T6 (delegated-direct, writer, after T3) — P5 autonomous lab cycle: 13-step detect→protect→last-disconnect→no-work→grace→revalidate→cancel-on-activity→re-abandon→grace→safe-close→confirm→log on lab-owned processes only, no manual steps between stages. Tests: full cycle + cancel branch. Route: delegated.
- [ ] V7-T7 (delegated-direct, verifier-heavy) — Validation: fmt/clippy/test/build ×2 feature sets; all labs (OpenCode, Codex, tracking, coverage, safe-term, autonomy); regression matrix (terminal-zero, resize, CPU-miscalc, PID-recycle, client-concurrency, direct-bypass, abrupt-disconnect, persistent-work, adapter-timeout, partial-inspection, stale-cache, supervisor-restart, multi-TUI, self-close). Route: delegated verify workers (fresh per-action, no route change).
- [ ] V7-T8 (direct-inline, parent) — Close-out: before/after benchmark table (RSS/CPU/Fast/Deep/pilot/refresh/aux-spawns/errors/log growth + regressions explained), coverage contract doc, autonomy evidence, per-tool/Android limits, independent security audit of 12 rules, missing-requirements-for-real-close list, CHANGELOG+docs, work-unit commits per task. Route: inline (synthesis, no source writes).

## Acceptance
- Fast Scan never blocks on slow adapters (timeout test); Deep never freezes TUI; pilot latency significantly reduced with real before/after numbers; CPU/RAM low; aux spawns counted, no process-per-read where avoidable, no unbounded parallelism; safety locks identical.
- Coverage enum shipped; CompleteVerified only with proven all-transports-observed; bypass test degrades; lab 12-scenario evidence or documented gap; prod never forced through proxy.
- TUI stable on 0×0/resize/small terms, real CPU deltas or `—`, explains protection + missing evidence, supervisor-client only, no prod destructive paths.
- General classification extensible, unknown protected, orphan≠abandoned.
- Lab autonomous 13-step cycle green on lab-owned PIDs only.
- All validations ×2 green; benchmarks delivered; security audit confirms 12 rules; docs updated.

## Applicable checks (per task)
`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`; `cargo build --release`; each also with `--features tui`. Labs: OpenCode, Codex, tracking, coverage, safe-term, autonomy. Bench: RSS/CPU/scan times/spawns/logs.

## Delivery
- Test-first where runnable deterministic RED exists (RED→GREEN→REFACTOR observed); else state exception + proportional checks. Runner: `cargo test` (+ `--features tui`).
- Work-unit commit per task on feature branch (Conventional Commits, no co-author attribution); record identity below. Push/PR/merge = user decisions.
- Forecast authored changed lines ≈1800 (excl. generated) → exceeds ~400 budget; strategy `ask-on-risk` (default): ask once for chain strategy (`stacked-to-main` vs `feature-branch-chain`) before the commit that crosses the budget. Cache choice here when made.
- Native review candidate = work-unit commit or PR slice, never a checkbox; RDD user-owned switch governs.

## Progress
- 2026-10-14: feature doc created (8 tasks V7-T1..T8); branch `feature/reaper-v0.7` created from `feature/client-tracking-tui@7567405`.
- 2026-10-14: V7-T1 done (direct-inline, parent) — before-baseline captured: release binary (tui) 1604640 B observed; v0.6 verified RSS 3.8 MB supervisor / 4.2 MB TUI, CPU ~0.3%, snapshot 0.03 s, pilot ~107 s wall; /proc/net/tcp+unix Permission denied re-confirmed; state-log dir absent (note).
- 2026-10-14: V7-T2 partial (delegated-direct writer ses_ec77f9adeffeaum8huNfgOnU1c) — Fast Scan defers OpenCode/Codex probes to Unknown, registries batched (1 read/report), stage-metric placeholders emitted (`proc_scan_ms=10` smoke, `aux_spawns=0` hardcoded). Gaps: 17 clippy dead-code errors (deep-probe code now unused → check failing), no Deep on-demand path, no timeouts/cancellation, no real aux-spawn count, missing timeout/partial/stale-cache/spawn tests. Only `src/pilot.rs` touched (+170/−99); no commit (checks red). Note: writer cited a parent-authorized surface expansion to client_tracker/relations — no such authorization was given; no writes occurred there.
- 2026-10-14: V7-T2 still open, round 2 partial committed (delegated-direct writer background ses_ec76ec54dffe2461Vt2fMgon4t) — `pilot report --deep` on-demand path wired, clippy green default+tui, tests 91+4 / 96+4 green, Fast smoke 9 ms scan / 0 spawns. Known gaps for round 3: outer deadline drops join handles without cancelling in-flight sync probes (deep smoke ~80 s), Codex sync subprocess lacks end-to-end budget, persist/log metric placeholders, per-stage ops/errors/timeouts incomplete, stale-cache guard + timeout/spawn regressions missing.

## Verification evidence
- (append per task: command → observed result, tier/outcome, commit id)

## Next step
- V7-T1: create branch + capture before-benchmarks.
