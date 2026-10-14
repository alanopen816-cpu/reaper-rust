# Feature: reaper-v0.8 — Runtime Integration & Autonomous Lifecycle

**Locator**: `odd/tasks/reaper-v0.8.md` | Engram topic `odd/reaper-v0.8/tasks` | Repo `reaper-rust`, base `feature/reaper-v0.7@f9dbf34` → new `feature/reaper-v0.8`
**Base verified 2026-10-14**: branch feature/reaper-v0.7, commit f9dbf34, tree clean, 10 work-unit commits, tags phase-1/phase-2 preserved; state.rs EXISTS (completeness TBD); Fast <1 s, Deep 35 s bounded; lab 10/12 driven.

## Objective
Connect the existing engine into a persistent, verifiable autonomous runtime: discovery → classification → evidence → policy → durable state → real grace timers → lab-only safe termination, surviving restarts and revalidating before acting. Production never touched.

## Scope (authorized)
- Branch `feature/reaper-v0.8` from `feature/reaper-v0.7@f9dbf34`; history/tags preserved; no push/PR/merge (user decisions).
- All src/*.rs writable as delegated surfaces require; production OpenCode/Codex/Broker installs untouched; lab-owned processes only for signals; dry-run default stays.
- 12 rules + proven() conjunctive + coverage blocking + empty-never-idle + Unknown/Error-block untouched (HOLD = protections intact, confirmed by two audits — see §2 note).
- No mandatory ADB/root/systemd/Ubuntu/proot dependency.

## Constraints
- HOLD semantics: in both v0.7 audits HOLD meant every checked protection held with cited evidence — NOT a security block. Initial audit must confirm this reading before any new actuation path is enabled. Never weaken rules for green results.
- No inferred abandonment (name/load/PPID-1/age alone); Absolute first; misclassification can never promote protected→candidate.
- Restart rule: recover → re-identify → discard recycled/gone → revalidate owner/clients/work → recompute policy → restore only evidence-compatible states. Persisted grace NEVER authorizes immediate post-restart close; without proven time continuity + fresh evidence, start a FULL new grace. Monotonic clock in-run; documented wall-reconstruction after restart.
- Stale/foreign-server/expired proofs unusable for close; production coverage stays incomplete where externally unobservable — never engineer CompleteVerified into reachability.
- Bounded concurrency/timeouts/budgets from v0.7 respected; partial errors → conservative states; no unbounded aux spawns; incremental persistence where apt.

## Tasks
- [ ] V8-T1 (delegated-direct, explorer) — Mandatory initial audit: run current tests (report), map scanner→evidence→policy→tracker→state→adapters→termination integration, pinpoint info-loss breaks, review CHANGELOG gaps, confirm HOLD reading with evidence. Route: delegated (mapping trigger).
- [ ] V8-T2 (delegated-direct, writer) — Classification runtime wiring: every inspected process gets stable identity, class, tier, verified relations, known/unknown owner, verified clients/work, available+missing evidence, lifecycle state, policy decision, block reason. Wire `apply_classification` into real protect() paths (the deferred P4 gap). Tests on the real cycle, not helpers-only.
- [ ] V8-T3 (delegated-direct, writer) — Durable state.rs: persist identity/boot/PID+start/lifecycle/transition reason+evidence/grace-start/policy/cancel-history/owner/clients/work refs/schema version. Atomic writes, corrupt/incomplete recovery, concurrency control, schema versioning, private perms, PID-reuse guard, no silent critical-error loss. Old authorizations never restored as valid.
- [ ] V8-T4 (delegated-direct, writer) — Real grace timer: 5 min default, policy-configurable; DISCOVERED→OBSERVING→CANDIDATE→GRACE_PERIOD→READY_FOR_REVALIDATION→TERMINATION_BLOCKED-or-authorized-close (respect existing names). Starts only on proven abandonment; errors block/cancel; activity/reconnect rescues; identity change invalidates; pending work blocks; coverage loss blocks; policy change re-evaluates; supervisor restart revalidates. No timer bypasses policy.
- [ ] V8-T5 (delegated-direct, writer) — CoverageProof hardening (NOW justified: v0.8 builds real consumers): controlled API issuing proofs only from verified validations (transports, server+clients, identity/freshness, provenance, adapter limits, server changes, restarts, event loss, proxy bypass). Expired/foreign proofs unusable. Production CompleteVerified stays unreachable.
- [ ] V8-T6 (delegated-direct, writer) — Autonomous runtime loop: light snapshot → appears/changed/gone → classify → evidence → clients/work → policy → state machine → grace start/cancel → log transitions → persist → schedule deep when needed. Deep never blocks Fast/TUI; budgets respected; partial errors conservative.
- [ ] V8-T7 (delegated-direct, writer) — Lab termination integration: proven abandonment → approved policy → grace elapsed → full revalidation → stable identity → lab authorization → official-close-if-exists → SIGTERM → bounded wait → revalidate → SIGKILL-only-if-authorized → confirm → durable receipt + logs. No destructive retry after restart without rebuilt state+authorization. Lab-created processes ONLY.
- [ ] V8-T8 (delegated-direct, writer) — Pending labs: the 2 missing coverage scenarios (investigate which) + restart-during/after-grace, PID reuse, reappearing client, work-after-close, corrupt state, torn writes, concurrent updates, expired coverage, proxy evasion, revalidation timeout, auth error, policy change, 2-clients-1-service, 2-projects, vanishing service, failed official-close, ignored SIGTERM, lab SIGKILL, post-restart retries. Non-lab signal targets PROHIBITED.
- [ ] V8-T9 (delegated-direct, writer) — v0.7 debts: (A) OpenCode child cleanup/kill on over-budget (no orphaned inspector children); (B) TUI real lifecycle states (protection, block reason, evidence, coverage, grace remaining, candidate/active, last decision, supervisor state) + real candidate count; (C) metrics honesty (no exact claims from unproven HZ/uptime assumptions — document precision/availability); (D) bounded log/state growth; (E) no mandatory ADB/root/systemd/proot.
- [ ] V8-T10 (delegated-direct, verifier-heavy, medium) — Validation: fmt/clippy/test/build ×2 + labs; new runtime/persistence/coverage/grace tests; independent verifier audit of discovery→termination paths confirming no flow bypasses the 12 rules; no deleted tests.
- [ ] V8-T11 (direct-inline, parent) — Close-out: before/after bench table, CHANGELOG+docs, autonomy/recovery/close demos, audit results, perf numbers, pending limits, exact conditions for a future real pilot. No push/PR/merge without authorization.

## Acceptance
- Real cycle demonstrated in lab: active work protected; proven abandonment → grace → cancel-on-activity; restart survival + revalidation; authorized lab auto-close + logged; production never intervened.
- Grace only from proven abandonment; restart never fast-forwards close; stale/foreign proofs dead.
- Perf: Fast <1 s like v0.7, Deep bounded, no TUI freeze, no child accumulation, low idle CPU, incremental persistence.
- 12 rules HOLD at HEAD; no flow bypasses them; no rule weakened for results.

## Applicable checks (per task)
`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`; `cargo build --release`; each also with `--features tui`. Labs as applicable.

## Delivery
- Test-first where runnable deterministic RED exists; else exception + proportional checks. Runners `cargo test` (+ `--features tui`).
- Work-unit commit per task on feature branch (Conventional Commits, no attribution); record identity. Push/PR/merge = user decisions.
- Forecast ≈2000 authored lines → exceeds ~400 budget; strategy `ask-on-risk` (default): chain-strategy question still owed from v0.7 (recorded debt) — ask once before the commit crossing the budget this time.
- Subagent models: worker/verify on `openai/gpt-6-luna#medium` (user-ordered); explorer default. Absolute paths in every delegated prompt (learned: worker cwd differs).

## Progress
- 2026-10-14: feature doc created (11 tasks V8-T1..T11); branch `feature/reaper-v0.8` created from `feature/reaper-v0.7@f9dbf34`.
- 2026-10-14: V8-T1 in flight (explorer ses_ec6b8f7acffePQc1dBdPvuglGO) + parent baseline: `cargo test` 106+1+2+2 green on the fresh branch. Writers T2+ launch when audit lands.
- 2026-10-14: V8-T1 DONE — audit confirms top-5 breaks (no observer→termination path; proven unsatisfiable in observer; coverage always incomplete; classification test-only; ReadyForRevalidation terminal+skipped) + HOLD = protections-intact reading confirmed. V8-T3 in flight (writer ses_ec6b796e5ffe71YrJ1QtcrJqHn, luna medium): durable state (schema, structured parse, corrupt reporting, perms, locking, restart rule); T2/T4+ queued serially (main.rs shared).
- 2026-10-14: V8-T3 scope Q resolved — worker stopped correctly at over-narrow main.rs range; parent approved reload caller ~690 (inside user-authorized v0.8 scope; task requires logged recovery Results); continuation same session.
- 2026-10-14: V8-T3 DONE at commit pending (parent spot-checks: fmt pass, 10 state tests green; worker-reported clippy×2 + 109/122 green) — versioned schema, strict parse, torn/corrupt explicit errors, 0600, full identity validation (PID/start/UID/boot/exe), logged recovery Results, conservative full-new-grace on reload (= mission restart rule). Residuals → V8-T6 scope: observer pidfile + cross-process locking; cancel-history/owner-client-refs fields.
- 2026-10-14: V8-T4 design breakthrough — worker proved proven() (needs grace-expiry) cannot authorize grace ENTRY (deadlock); parent-approved two-grade evidence (candidate_for_grace entry-only + full proven() readiness-only, proven() byte-identical). Round 2 banked at c905178 (parent spot-checks: fmt pass, 5 candidate tests green; worker-reported 116/129 green, genuine RED observed). Missing: expiry-fresh-revalidation + reconnect cycle tests → test-only round in flight.
- 2026-10-14: V8-T4 DONE at commit pending (parent spot-checks: fmt pass, revalidation + 4 cancel tests green on real scans ~18 s; worker-reported 119/132 green) — READY-fresh-revalidation, grace-cancel with corrected reason (policy rescue ≠ reconnect), candidate≠close-readiness. Caveats: READY constructed directly (no 5-min wait), reconnect via fixtures + existing policy tests.
- 2026-10-14: V8-T2 DONE at commit pending (parent spot-checks: fmt pass, misclassification + 5 absolute tests green; worker-reported clippy×2 + 113/126 green) — classifier wired into Observer::cycle via classified_decision, class→tier before policy, Absolute invariant, spoof/PPID-1/ancient-stay-safe tests on real path. Process note: worker admitted no RED-first this round.

## Verification evidence
- (append per task: command → observed result, tier/outcome, commit id)

## Next step
- V8-T1: initial audit via explorer.
