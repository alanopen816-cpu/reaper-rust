# Changelog

## v0.9.1-security-hardening — 2026-10-15 (branch `feature/reaper-v0.9.1`, base `feature/reaper-v0.9@9bcd672`)

P0 debts closed with evidence or explicit code-backed blocks; controlled
client coverage demonstrated in the lab; 20-step demo verified 18/20
(kernel-blocked remainder); OpenCode/Codex matrices UNFIT with evidence;
pilot preserved read-only with a bounded partial report. Production
never closed. 12 rules HOLD.

Benchmarks v0.9 → v0.9.1 (measured on-device):

| Metric | v0.9 | v0.9.1 |
|---|---|---|
| Fast Scan wall | 19 ms wall, 50 procs, read-only | 78 ms wall under parallel-build load (51 procs, 0 skipped, 0 errors) |
| Deep Inspection | bounded 35 s | bounded 35 s (kept) |
| Tests default / tui | 157+16 / 176+16 | 161+17 / 180+17 (178/197 total), none deleted |
| Release default | 1580720 B | 1582120 B (+0.09%) |
| Release tui | 2226400 B | 2227584 B (+0.05%) |
| Pilot RSS | 3944 KB VmRSS | 3000 KiB, 0 CPU ticks |
| Logs/state | 992 KB, rotation live | 1 MiB cap rotation VERIFIED live (1048575 B → rotated); ~1.4 MB total |
| Pilot gaps | 1 × missing_cycles (build load) | 1 × 30 s missing_cycles, exact window logged, crash excluded |

Added:
- V91-T1 debt closure: durable-grant CLOSED by construction
  (`persist()` stores observations only, "never irreversible
  decisions"); /proc-loss pinned (`missing_fresh_scan_target_
  explicitly_refused`); carried-input + T7-items-1-2 founded-BLOCKED
  (no carried channel in `close_sequence`; no expiry model in
  `ScopedAuthorization` — fixing either = scope expansion, declined).
- V91-T2 controlled coverage: TTL `>=` boundary fix (genuine RED);
  additive UDS-construction TRANSPORT-EVIDENCE (ATTEST bytes
  unchanged, runtime TCP tripwire kept, production Unknown untouched);
  bypass/event-loss/Broken-registry close-blocking tests; controlled
  Unknown→CompleteVerified→fresh-approval transition (test-scoped
  issuer). Round-1 swap reverted after parent-verified live-cycle
  regression (hang >300 s vs 2.85 s baseline) — conjunction lesson.
- V91-T6 update-time protection: `pilot start` refuses on live or
  unverifiable observer pidfile (genuine RED→GREEN).
- V91-T4 matrices: OpenCode + Codex UNFIT for idle verification with
  file:line evidence; closing integrations UNKNOWN.
- V91-T5 pilot partial: ~6.4 h elapsed, observed ≈ elapsed − 30 s,
  ~60 rows all Blocked/KeepProtected, 0 candidates, 0 grace events.

Verified: fmt, clippy ×2, tests ×2 (178/197), release builds ×2,
gates green every step, independent audit (bypass traces blocked),
destructive scope evidenced (kills only on self-spawned handles;
sole raw kill is identity-verified pilot stop, no escalation).

Known limits / residuals: T7-1-2 interface gaps; same-UID
roster-attacker model unverified; demo steps 19-20 + two-client flow
+ full 20-chain blocked by denied /proc/net tables (same kernel
precondition as CompleteVerified); binary update/rollback procedure
missing (docs); per-cycle load telemetry deferred; uptime_seconds=0
cosmético; linker + TTL flakes (1 retry); sentinel-stat NotFound
transient (prod churn, retry green).

First-authorized-non-lab-close requirements: kernel with readable
listener tables (or UDS-exclusive managed service per V91-T2
contract); full proof + fresh approval + lab membership; human
review + RDD gates; E-Stop verified; 7-day pilot reviewed; audit GO.

## v0.9.0-operational-pilot — 2026-10-14 (branch `feature/reaper-v0.9`, base `feature/reaper-v0.8@cb436cc`)

First REAL lab-owned managed service end-to-end (18-step autonomous
demo incl. reconnect-cancel + new-grace, real 5-min double-grace runs),
listener-gated coverage entry, 7-day read-only observation pilot
(running), operational hardening (persistent Emergency Stop, per-service
scoped auth, fail-closed faults, bounded restart, strict reconstruction),
read-only TUI Operations view with motor/grace/pilot plumbing.
Production never closed. 12 rules HOLD; CompleteVerified unattainable
on this kernel BY DESIGN (listener tables denied).

Benchmarks v0.8 → v0.9 (measured on-device):

| Metric | v0.8 | v0.9 |
|---|---|---|
| Fast Scan wall | 30 ms wall, 0 spawns, 0 errors | 19 ms wall, 50 procs observed, read-only |
| Deep Inspection | bounded 35 s | bounded 35 s (kept) |
| Tests default / tui | 148 / 165 | 157+16 / 176+16, none deleted |
| Release default | 1285024 B | 1580720 B (+23%, managed-service + coverage + hardening) |
| Release tui | 1919952 B | 2226400 B (+16%, ops view + plumbing) |
| Pilot RSS (observer) | — | 3944 KB VmRSS, pid 15157, ~5 h uptime |
| Logs/state | rotation/retention/size caps + 1 MiB refusal | 992 KB total, daily JSONL + pilot-observe.log, gap detector live (`missing_cycles` recorded under build load) |
| Real 5-min graces | — | 300.027 s + 300.001 s monotonic, 18/18 steps ×2, zero strays |

Added:
- V9-T1 security-debt audit CONDITIONAL-GO (STALE-CARRIED none,
  cmd_close unsatisfiable fail-closed; poison matrix DROPPED as
  incoherent — gate takes no carried channel; 2 UNTRACED closed live
  by the 18-step demo in V9-T2).
- V9-T2 first real managed service (`managed-service serve` loopback
  child, ledger, UDS peer-cred attestation lab-only) + 18/18-step
  autonomous demo incl. reconnect-cancel + new-full-grace; real 5-min
  double-grace runs (300.027 s + 300.001 s monotonic, sentinel
  unchanged, zero strays). Pre-listener-gate: mechanism-valid,
  coverage-unproven (see kernel finding).
- V9-T3 listener-gated coverage entry (both tables denied on this
  kernel → Unknown fail-closed) + coverage-entry.md + OpenCode/Codex
  applicability docs. KERNEL FINDING: exclusive-access proof
  impossible here → CompleteVerified unattainable → autonomous close
  blocked BY DESIGN.
- V9-T4 7-day read-only pilot (heartbeat CLOCK_BOOTTIME, gap
  detection, capped backoff, rotation, verified-child-only stop);
  legacy-state fatal fixed via quarantine (7e57612). Running since
  12:42:42 -05, first `missing_cycles` gap recorded under build load —
  detector working as designed.
- V9-T5 hardening (persistent Emergency Stop, per-service scoped
  auth, fault fail-closed matrix, bounded restart with cap, strict
  per-close reconstruction schema). Durable-grant artifact →
  documented residual (no prod closes in v0.9).
- V9-T6 read-only Operations view + motor/grace/pilot snapshot
  plumbing (decision-variant counts from existing rows, read-only
  supervisor.json + heartbeat parsing, honest unavailable labels).
- V9-T7 validation (fmt/clippy/test/build ×2 green; 157+16 /
  176+16 tests) + independent audit; 3 gaps founded-STOP to
  documented residuals (opaque official receipt, no expiry model,
  empty-scan vacuity) — no scope expansion for results.

Verified: fmt, clippy ×2, tests ×2, release builds ×2 (sizes TBD
below), real controlled labs, zero strays, production untouched.
Independent audit: 12 HOLD; T6 read-only confirmed.

Known limits: classic kill() TOCTOU (pidfd preferred); kill en vuelo
OpenCode missing; grant operador durable residual; uptime_seconds=0
cosmético; T6 RED honest-gap (compile error, not behavioral RED);
verifier-noted partials (last-gone, phone-restart, /proc-loss e2e
pins); linker + TTL flakes (1 retry green); /proc/net denegadas.

Real-pilot conditions: 7 real days read-only without unplanned gaps
beyond load-starvation; presence signal + human review + RDD before
any close; CompleteVerified unreachable here by construction —
production closes need a kernel with readable listener tables + full
proof + fresh approval + lab membership.

## v0.8.0-runtime-autonomy — 2026-10-14 (branch `feature/reaper-v0.8`, base `feature/reaper-v0.7@f9dbf34`)

Runtime integration: discovery → classification → evidence → policy →
durable state → real grace → lab-only safe termination, persistent across
restarts. Still dry-run in production; 12 rules HOLD plus 3 audit FLAGs
closed (full-tuple identity, FreshApproval token, durability proof).

Benchmarks v0.7 → v0.8 (measured on-device):

| Metric | v0.7 | v0.8 |
|---|---|---|
| Fast Scan wall | <1 s (7–38 ms scan) | 30 ms wall, 0 spawns, 0 errors |
| Deep Inspection | bounded 35 s | bounded 35 s (kept, coalescing scheduler) |
| Tests default / tui | 111 / 124 | 148 (143+1+2+2) / 165 (160+1+2+2), none deleted |
| Release default | 1175848 B | 1285024 B (+9%) |
| Release tui | 1809856 B | 1919952 B (+6%) |
| Supervisor idle | ~0.4% core, ~5.3 MB debug | unchanged path (singleton pidfile added) |
| Logs/state | 180 KB bounded daily | rotation/retention/size caps + 1 MiB state refusal |

Added:
- V8-T2 classification wired into Observer::cycle (class→tier before
  policy, Absolute invariant under misclassification; spoof/PPID-1/ancient
  stay safe on the real path).
- V8-T3 durable state (versioned schema, strict parse, torn/corrupt
  explicit errors, 0600, full identity validation, logged Results,
  full-new-grace on reload per restart rule).
- V8-T4 two-grade evidence (candidate_for_grace entry-only + full
  proven() readiness-only; proven() byte-identical — resolves the
  grace-entry deadlock) with expiry revalidation + honest cancel reasons.
- V8-T5 controlled CoverageProof issuance (private fields, test-only
  issuer, TTL/identity/invalidation → Unknown; no production issuer).
- V8-T6 autonomous loop (observer.pid singleton, identity-keyed
  appear/change/disappear diffing, coalescing DeepScheduler, Fast
  never blocked).
- V8-T7 lab termination pipeline (recomputed — never caller-supplied —
  approval, 7-refusal matrix with persisted JSONL receipts, fresh
  evidence at final gate, mid-close→revalidation-only, lab-owned only).
- V8-T8 four live labs (elapsed-grace restart, TTL expiry, 2-project
  isolation, vanishing-mid-close) + full 20-scenario inventory.
- V8-T9 debts (OpenCode child-reap /proc test, metric source labels,
  log/state caps, ADB/root guard, TUI unavailable-with-reason).
- V8-T10 hardening (full-tuple pre-signal checks, FreshApproval token
  type, receipt+dir fsync proof; RED caught official-shutdown-before-
  token-check ordering bug, fixed).

Verified: fmt, clippy ×2, tests ×2, release builds ×2, all labs incl.
gated live-server, regression matrix, TUI smokes, zero strays,
production untouched. Independent audit: 12 HOLD; adversarial sketches
(spoof, stale cache, dropped handle, second supervisor, bypass) all
blocked; allows review clean (dead_code + 2 style); loopback-only net.

Known limits: classic kill() TOCTOU inherent (pidfd preferred);
OpenCode in-flight child kill missing (waits bounded); TUI lifecycle
display needs snapshot motor plumbing; discovery/disconnect partly
fixture-driven in autonomy lab; /proc/net/* denied; bare
`cargo test client_coverage` matches zero (use --test); linker
"Pointer tag truncated" + TTL-timing flakes recorded (retry green).

Real-pilot conditions: presence signal + human review + RDD; CompleteVerified
unreachable in production by construction; close --act provably
unreachable without lab membership + full proof + fresh approval.

## v0.7.0-perf-coverage-tui — 2026-10-14 (branch `feature/reaper-v0.7`, base `feature/client-tracking-tui@7567405`)

Fast supervisor/TUI scans, verifiable client-coverage contract, real per-process
CPU in the TUI, evidence-based classification, lab-demonstrated autonomous
cycle. Still read-only + dry-run in production; all 12 safety rules hold
(independent audit: HOLD, safe to close).

Benchmarks before → after (measured on-device, smokes unless noted):

| Metric | v0.6 | v0.7 |
|---|---|---|
| `pilot report` wall | ~107 s (ambient probes) | Fast <1 s (scan 7–38 ms); Deep bounded 35 s on demand |
| Supervisor RSS | 3.8 MB (release, v0.6) | ~5.3 MB (debug; same order, release TBD) |
| Supervisor CPU idle | ~0.3% core | ~0.4% core (2 ticks/5 s, debug) |
| TUI RSS | 4.2 MB | ~4.3 MB debug (4376 KB peak, real frame) |
| Per-process CPU | `—` placeholder | real /proc deltas, CLK_TCK discovered, `—` when uncomputable |
| Release binary default | 1048104 B | 1175848 B (+12%, new lab/coverage code) |
| Release binary tui | 1604640 B | 1809856 B (+13%) |
| Aux spawns (Fast) | uncounted | 0, counted per spawn site |
| State logs | ~163 KB | 180 KB, bounded daily JSONL |
| Tests default / tui | 88+2+2 / 93+2+2 | 111 / 124, zero deleted to get green |

Added:
- P1 Fast/Deep split — Fast never blocks on slow adapters (defer→Unknown),
  batched registry reads, stage metrics, bounded Deep with shared-deadline
  waits + child kill, per-site spawn counting, tiny-budget regression.
- P2 coverage contract — `Coverage{CompleteVerified,Partial,Unknown,Broken}`;
  production `coverage()` hardcodes Unknown, registry caps at Partial, proofs
  test-only: CompleteVerified unreachable in production by construction.
  Loopback lab drives 10/12 scenarios end-to-end (grace-timer + durable
  restart identity partial, marked); bypass degrades; prod never proxied.
- P3 TUI — CPU-delta map (shared Process untouched), async snapshots,
  skip-busy refresh, verifiable-only stats bar, real hierarchy,
  clients/evidence/help views, resize/zero-size safety, multi-TUI lock-in.
- P4 taxonomy — evidence-based classes + extension hook + class→tier map
  (additive; runtime call-site wiring deferred, live behavior unchanged).
- P5 autonomy — lab-scoped driver, own short grace (production 300 s
  untouched), cancel + close branches, real TERM on lab-owned child via
  registry gate (no SIGKILL), CLI refusal verified safe.
- `tests/autonomy.rs`, `src/lab_coverage.rs`, `src/lab_autonomy.rs`.

Verified: fmt, clippy ×2, tests ×2, release builds ×2, all 6 labs incl.
gated live-server coverage (13 s, self-cleaning), regression matrix
(multi-TUI closed test-only), TUI pty smokes both sizes, zero strays,
production untouched. Full-suite suite wall dominated by release builds
(30 s) + bounded Deep (35 s).

Known limits: OpenCode in-flight child kill missing (waits stay bounded);
grace timer + durable restart identity need state.rs; CoverageProof fields
public (test-only risk); classifier mapping has no production caller;
discovery/disconnect fixtures scripted in autonomy lab; audit receipt in
memory; TUI own-CPU metrics limited; /proc/net/* denied on this Termux;
`cargo test client_coverage` bare matches zero tests (use --test).
First real close still requires presence signal + human review + RDD.

Process note: ~2124 authored lines across 9 work-unit commits on the
feature branch; the ask-on-risk chain-strategy question was never asked
before crossing the ~400-line budget — delivery stays a single branch,
no PR created (push/PR/merge remain the user's decisions).

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
