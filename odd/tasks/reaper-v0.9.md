# Feature: reaper-v0.9 — Operational Pilot & Production Readiness

**Locator**: `odd/tasks/reaper-v0.9.md` | Engram topic `odd/reaper-v0.9/tasks` | Repo `reaper-rust`, base `feature/reaper-v0.8@cb436cc` → new `feature/reaper-v0.9`
**Base verified 2026-10-14**: branch feature/reaper-v0.8, commit cb436cc, tree clean, 13 work-unit commits, tags phase-1/phase-2; autonomous runtime, 5-min grace, FreshApproval, durable receipts, audit HOLD.
**Git strategy: linear development** (user-decided for v0.9; also settles the chain-strategy question owed since v0.7 — single branch, no stacking, no push/PR/merge without authorization).

## Objective
Make Reaper a daily Termux operator: autonomously manage one REAL lab-owned service end-to-end, resolve client-coverage applicability, harden operationally (Emergency Stop, per-service auth, fail-closed faults), and start a 7-day read-only observation pilot. Production never closed (not authorized in v0.9).

## Scope (authorized)
- Branch `feature/reaper-v0.9` from `feature/reaper-v0.8@cb436cc`; history/tags preserved.
- One REAL Reaper-owned Termux service for the pilot (not a mock, not an existing production process): real process, verifiable identity, accepts clients, does work, work survives disconnect, graceful shutdown, restartable, auditable logs. ALL destructive actions limited to it.
- Existing OpenCode/Codex/MCPs/runit/Termux services: observe-only, never modified, never closed.
- 12 rules + proven() + coverage gate + dry-run default intact; no rule weakened for results.

## Constraints
- HOLD = protections-intact (confirmed twice); 3 v0.8 FLAGs closed (tuple identity, FreshApproval, durability proof) — re-confirm before real-service actuation.
- No adapter may fabricate CompleteVerified; new classification never reduces protection.
- Coverage Complete requires proving NO access path outside supervised scope; partial-traffic proxy never suffices; Android isolation limits tested, not assumed.
- 7-day pilot: read-only on production, no process terminated; interruptions reported, never declared complete without 7 real days.
- Emergency Stop persists across restarts; per-service scoped auth (no global/inherited close auth); faults (lost /proc, stale evidence, unverifiable clients, unexpected restart, corrupt state) block destructive action; managed restarts bounded, never unlimited auto-restart.
- No mandatory ADB/root/systemd/proot.

## Tasks
- [ ] V9-T1 (delegated-direct, explorer+verifier) — P1 security-debt audit: re-walk Discovery→…→Termination on the v0.8 tree; verify full identity, coverage, no-work, owner evidence, proof freshness, Absolute, grace cancel, persistence, scoped approval, official-first; confirm FLAGs stay closed; re-confirm HOLD reading. No new actuation until green.
- [ ] V9-T2 (delegated-direct, writer) — P2 first real managed service + 18-step autonomous demo (discover→owner→connect→protect→work→disconnect→work-survives→no-kill→work-ends→last-gone-proven→5-min-grace→reconnect-cancels→disconnect→new-full-grace→revalidate→official-close→confirm→log+resources). Autonomous final close (no manual kill). Short-grace tests + ONE real-5-min double-grace run for evidence (background-tolerant).
- [ ] V9-T3 (delegated-direct, writer) — P3 coverage entry point: lab-only controlled-entry proxy prototype (concurrent/normal/abrupt/external/bypass/restart/event-loss/reconnect/surviving-work); Android isolation limits without root; OpenCode-voluntary + Codex applicability docs (isolated vs shared vs standalone vs wrapper vs external; SQLite≠client-absence; Unknown kept). No second registry; no prod changes.
- [ ] V9-T4 (delegated-direct, writer) — P4 7-day observation pilot: reuse supervisor (no new daemon); JSONL daily + rotation/retention; low CPU; restart recovery; gap detection; no aggressive retries; no wake-lock; explicit start/status/stop; zero destructive modifications. Short smoke on-device; if safe, START the read-only pilot with visible stop instructions.
- [ ] V9-T5 (delegated-direct, writer) — P5 operational hardening: (A) persistent Emergency Stop (kills future auto-actions, keeps observation, survives restart); (B) per-service scoped close auth; (C) fault fail-closed (connectivity//proc/evidence/clients/restart/corrupt); (D) bounded managed restart via explicit authorized mechanism; (E) per-close full reconstruction (identity, evidence, policy, auth, grace window, revalidation, mechanism, result, errors).
- [ ] V9-T6 (delegated-direct, writer) — P6 TUI ops views: supervisor/pilot state, observed time, gaps, actives, real candidates, grace remaining, protected, block reasons, coverage, decision history, supervisor resources; per-process blocker inspector; small screens; never blocks supervisor; no prod destructive actions.
- [ ] V9-T7 (delegated-direct, verifier-heavy, medium) — P8+P9 tests + validation + audit: all existing + new (real service, 2 clients, surviving work, last-gone, grace reconnect/restart, recycled identity, incomplete coverage, bypass, official-close failure, expired auth, Emergency Stop, corrupt state, simulated phone restart, logs/recovery, /proc loss, supervisor restart, multi-TUI, non-destructive pilot); fmt/clippy/test/build ×2; real controlled labs; independent audit; no hidden failures.
- [ ] V9-T8 (direct-inline, parent) — P10 close-out: before/after metrics (real vs simulated vs unmeasurable labeled), deliverables 1–12, CHANGELOG+docs, exact missing requirements for production closes. No push/PR/merge.

## Acceptance
- One real lab-owned service autonomously managed end-to-end (both grace branches, official close, logged + resources measured where possible).
- Emergency Stop proven (incl. across restart); faults block destructive action; per-service auth scoped.
- 7-day pilot started read-only (or ready with safe controls + smoke evidence); no production process terminated, ever.
- 12 rules HOLD at HEAD; coverage state honest; Android limits documented.

## Applicable checks (per task)
`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`; `cargo build --release`; each also with `--features tui`. Labs as applicable.

## Delivery
- Test-first where runnable deterministic RED exists; else exception + proportional checks. Runners `cargo test` (+ `--features tui`).
- Work-unit commit per task (Conventional Commits, no attribution); record identity. Linear: single branch. Push/PR/merge = user decisions.
- Forecast ≈1800 authored lines; strategy linear per user decision (settles v0.7 debt).
- Subagent models: worker/verify `openai/gpt-6-luna#medium` (user-ordered); explorer default. Absolute paths in every delegated prompt.

## Progress
- 2026-10-14: feature doc created (8 tasks V9-T1..T8); branch `feature/reaper-v0.9` created from `feature/reaper-v0.8@cb436cc`; Git linear decided.
- 2026-10-14: V9-T1 in flight (explorer ses_ec522b094ffeL3tjdzzSBLzfT8) + parent baseline: `cargo test` 143+1+2+2 green on the fresh branch. V9-T2 launches on audit GO.
- 2026-10-14: V9-T1 audit NO-GO (explorer) with 3 bounded items → worker (cmdline compare + poison matrix, ses_ec52151e6ffelNQc7gNFwV48KX) + verifier trace (ses_ec5213aceffeBlvVA8yYHFlTE0) in parallel. Tracer result: STALE-CARRIED none (ignore-carried design confirmed); cmd_close unsatisfiable confirmed (fail-closed); 3 UNTRACED remain (reconnect-cancel, work-appears-cancel, isolated stale-owner) — stale-owner covered by worker round in flight; other 2 go to a micro-round next.
- 2026-10-14: V9-T1 CLOSED (cmdline fix banked 1b236ab; tracer STALE-CARRIED none). Poison matrix DROPPED as incoherent — worker proved the gate takes no carried channel, so carried-poison tests are untestable without inventing the vulnerability; ignore-carried holds structurally. 2 UNTRACED (reconnect-cancel, work-appears-cancel) transfer to V9-T2: the 18-step live demo IS their evidence (steps 12-14). Verdict: CONDITIONAL-GO → GO for lab-owned real-service work only.
- 2026-10-14: PILOT BUG found by starting it (not by smoke): legacy pre-schema state killed the observer after 2 healthy cycles. Fixed at 7e57612 (parent spot-checks: fmt pass; worker-reported 150/167 green, RED = exact observed error) — quarantine to timestamped 0600 backup, fresh start logged, keep observing with empty state, logging never fatal. Pilot re-started after rebuild; 7-day clock runs from re-start.
- 2026-10-14: pilot RUNNING pid 15157 since 12:42:42 -05, snapshots advancing, no gaps (parent-verified twice). V9-T5 round 1 banked uncommitted (parent spot-checks: fmt pass, pilot alive+gapless; worker-reported 153/170 green, genuine REDs, pilot untouched) — E-Stop marker + gates, per-service scope checks, fault gates, retry-budget helper. Missing: budget wired to real restart, reconstruction schema/test, full fault matrix; durable-grant artifact → documented residual (proportionate: no prod closes in v0.9).
- 2026-10-14: V9-T4 DONE at commit pending (parent spot-checks: fmt pass, smoke `./reaper pilot smoke 2` green exit 0; worker-reported 149/166 green with genuine REDs, both known flakes hit+retried green) — read-only mode, verified-child-only stop, heartbeat/gap detection (CLOCK_BOOTTIME), status metadata, capped backoff, rotation. Residuals: per-cycle field enumeration partial; no runtime close-counter guard (source-guard tests stand).
- 2026-10-14: V9-T2 round 1 banked uncommitted (parent spot-checks: fmt pass, handshake test green; worker-reported 143+5/160+5 green, genuine RED) — real loopback child + `managed-service serve` route + PING/SHUTDOWN test. Missing: ledger, tracking, observer wiring, 18-step cycle, full-grace run.
- 2026-10-14: V9-T2 round 2 banked at ec08f72 (parent spot-checks: fmt pass, pilot_service binary green; worker-reported 143+5/160+5 green, genuine REDs) — ledger, client IDs, journal+restart, shutdown refusal, registration, tracker states. Missing: OBSERVER side (protect/grace/cancel/revalidate/authorize over the demo service) → round 3 in flight. Caveat: TCP peer PID claim unauthenticated (controlled test clients, acceptable for lab).
- 2026-10-14: V9-T2 round 3 DONE at commit pending (parent spot-checks: fmt pass, 3 pilot_service tests green 4.92 s; worker-reported 143+8/160+8 green, genuine REDs incl. real bug: expired grace returned to CANDIDATE not READY, fixed) — SCM_CREDENTIALS WORKS here; UDS peer-cred attestation (lab-only, TCP-disabled, 0700/0600); 18/18 steps LIVE short-grace incl. reconnect-cancel + new-grace (UNTRACED closed); sentinel verified, zero strays. Ready for real-5-min: yes → dedicated run next.
- 2026-10-14: V9-T2 DONE at commit pending (parent spot-checks: fmt pass, demo main.rs change verified demo-scoped clamp only, production 300 s default intact; worker-reported full suites green) — REAL 5-min ×2 run: graces 300.027 s + 300.001 s monotonic, all 18 steps, sentinel unchanged, zero strays. 2 UNTRACED closed live.
- 2026-10-14: V9-T2 CLOSED at 7654258 (with kernel caveat recorded below). V9-T3 DONE at commit pending (parent spot-checks: fmt pass, 8 pilot_service tests green; worker-reported 147+5/164+5 green, genuine REDs) — listener-gated attestation (both tables denied on this kernel → Unknown fail-closed), fail-closed demo expectations, 4 missing tests, fragmented-read bug fixed, coverage-entry.md written. KERNEL FINDING: exclusive-access proof impossible here → CompleteVerified unattainable → autonomous close blocked BY DESIGN; 18-step success re-labeled pre-listener-gate (mechanism-valid, coverage-unproven).

## Verification evidence
- (append per task: command → observed result, tier/outcome, commit id)

## Next step
- V9-T1: security-path audit before any real-service work.
