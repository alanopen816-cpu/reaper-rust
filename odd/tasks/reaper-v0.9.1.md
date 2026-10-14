# Feature: reaper-v0.9.1 — Security Hardening & Autonomous Process Readiness

**Locator**: `odd/tasks/reaper-v0.9.1.md` | Engram topic `odd/reaper-v0.9.1/tasks` | Repo `reaper-rust`, base `feature/reaper-v0.9@9bcd672` → new `feature/reaper-v0.9.1`
**Base verified 2026-10-14**: branch feature/reaper-v0.9, commit 9bcd672, tree clean, 8/8 v0.9 tasks closed, pilot RUNNING pid 15157 (entries=55, gap=missing_cycles), tags/history preserved.
**Git strategy: linear development** (single branch, no stacking, no push/PR/merge without authorization).

## Objective
Close v0.9's critical security debts with reproduction+regression (not paperwork), prove real client coverage in a controlled scope, consolidate autonomous management of the lab-owned service, explain OpenCode/Codex blockers with evidence, preserve the 7-day pilot untouched. No production auto-close in this phase.

## Scope (authorized)
- Branch `feature/reaper-v0.9.1` from `feature/reaper-v0.9@9bcd672`.
- All destructive tests on Reaper-lab-owned processes only (reuse v0.9 `managed-service` lab; do not rebuild if it satisfies the 20-step demo).
- Pilot: read-only status only; never stop/restart/replace binary/touch state dir.
- OpenCode/Codex/MCPs/production: observe-only, voluntary opt-in instrumentation research only.
- 12 rules + proven() + coverage caps + dry-run default intact; no rule weakened for results.

## Constraints
- Debt definitions come from CHANGELOG/code/docs — never invent their meaning.
- A persisted authorization never becomes fresh across restart without revalidation.
- CoverageProof must bind same server + identity + validity window; empty response ≠ absence.
- Fail closed on incomplete evidence; missing_cycles cause claimed only with evidence.
- No second supervisor instance for metrics; elapsed ≠ observed time.

## Tasks
- [ ] V91-T1 (delegated-direct, writer) — P0 security debts: poison matrix, durable-grant, T7 items 1-3, CONDITIONAL-GO conditions. Per debt: real problem, consequences, code paths, reproducing test, minimal fix, regression test, independent verify, close-out evidence. Founded-STOP only with code-verified rationale (parent decides).
- [ ] V91-T2 (delegated-direct, writer) — P0 real client coverage in controlled scope: exclusive-entry listener/proxy for Reaper-managed services, connection tracking, server identity, bypass-degradation proofs, CompleteVerified only with exhaustive-access evidence. Lab-only.
- [ ] V91-T3 (delegated-direct, writer) — P1 controlled operational scope: 20-step demo (detect→2 clients→protect→partial-leave→last-gone→pending-work→work-ends→coverage→grace→cancel→re-grace→revalidate→fresh-auth→estop→official-close→confirm→log+resources). Reuse v0.9 lab if sufficient; gap-fill only.
- [ ] V91-T4 (delegated-direct, explorer) — P1 OpenCode/Codex matrices: verifiable vs not, evidence source per claim, Active vs Unknown conditions, what's missing for IdleVerified, what integration would close the gap. No adapter declared fit unless complete.
- [ ] V91-T5 (direct-inline, parent) — P1 pilot observation: read-only status/report/metrics, missing_cycles root-cause with evidence (suspend vs load vs budget vs real interruption), partial report (observed vs elapsed, inspections, protections, candidates, grace, errors, RSS/CPU, log growth). No retrospective edits.
- [ ] V91-T6 (delegated-direct, writer) — P2 operational readiness: reproducible install, safe binary update/rollback, state compat, log retention/rotation, accessible E-Stop, per-service auth, update-time protection, rootless Termux, TUI/supervisor independence. Justifiable gaps only, no heavy deps.
- [ ] V91-T7 (delegated-direct, verifier-heavy, medium) — validation + audit: fmt/clippy/test/build ×2 (+tui), integration suites (tracking, coverage, labs, autonomy, termination, persistence, estop, auth, restart, concurrency); destructive-scope guard; independent runtime-path audit hunting bypasses. Findings → reproduction + regression.
- [ ] V91-T8 (direct-inline, parent) — close-out: metrics vs v0.9 (19 ms scan, 3.9 MB RSS, sizes 1580720/2226400 B baselines), 13 deliverables, CHANGELOG+docs, exact requirements for first authorized non-lab close. No push/PR/merge.

## Acceptance
- Each P0 debt closed with evidence or explicit code-backed block; protections unregressed.
- CompleteVerified demonstrated in controlled scope if technically possible, else proven why not.
- OpenCode/Codex matrices honest; pilot preserved with partial report; no prod process ever terminated.

## Applicable checks (per task)
`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`; `cargo build --release`; each also with `--features tui`. Labs as applicable.

## Delivery
- Test-first where runnable deterministic RED exists; else exception + proportional checks. Runners `cargo test` (+ `--features tui`).
- Work-unit commit per task (Conventional Commits, no attribution); record identity. Linear: single branch. Push/PR/merge = user decisions.
- Subagent models: worker/verify `openai/gpt-6-luna#medium` (user-ordered); explorer default. Absolute paths in every delegated prompt.

## Progress
- 2026-10-14: feature doc created (8 tasks V91-T1..T8); branch `feature/reaper-v0.9.1` created from `feature/reaper-v0.9@9bcd672`; pilot verified alive entries=55. V91-T1 launches after debt-definition mapping.
- 2026-10-14: V91-T1 explorer map banked (debt quotes + code paths, no new exploit evidence). Writer rounds: carried-input + persisted-grant seams BLOCKED with concrete architecture evidence (close_sequence takes pre-evaluated Option<&FreshApproval>, no injection boundary; Supervisor::persist writes observations only state.rs:351-381 docstring "never irreversible decisions" — parent-verified, so durable-grant fear CLOSED by construction, no grant persists); /proc-loss PINNED with regression test `missing_fresh_scan_target_is_explicitly_refused` (honest-pass, +19 test-only, no prod change). T7 items 1-2 remain interface gaps (fixing = scope expansion). V91-T1 DONE (1 pin + 1 closure-by-construction + 3 founded blocks).

## Verification evidence
- (append per task: command → observed result, tier/outcome, commit id)

## Next step
- V91-T1: map exact debt definitions (CHANGELOG + code + docs) before any fix.
