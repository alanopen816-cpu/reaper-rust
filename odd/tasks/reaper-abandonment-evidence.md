# Feature: reaper-abandonment-evidence — Desbloquear evidencia real de abandono (OpenCode + Codex)

**Locator**: `odd/tasks/reaper-abandonment-evidence.md` | Engram topic `odd/reaper-abandonment-evidence/tasks` | Project `reaper` (repo `~/reaper-rust`, branch `phase-pilot`)

## Objective
Evolve the existing Reaper adapters so OpenCode and Codex servers can be judged `Active | IdleVerified | Unknown | Error` from verified, authoritative sources — without building another supervisor, broker, or policy engine — and feed `evidence::proven()` without weakening its conjunctive requirements.

## Problem
Today `OpenCode::liveness` and `Codex::liveness` always return `Unknown` (`src/adapters.rs:155-197`). Engine sets `last_client_gone=None, no_pending_work=None` (`src/main.rs:429-432`). `GET /api/session/active` alone does not prove absence of clients or pending work. No verified client-connection or work-queue visibility exists, so no adapter is fit for a real close.

## Why
Mission REAPER: determine with real evidence when resident servers are no longer needed, keeping dry-run default and zero production closures during this mission.

## Scope (authorized)
- Evolve `src/adapters.rs`, `src/evidence.rs`, `src/queries.rs`, `src/main.rs`, `src/pilot.rs` + tests only as needed.
- Read-only probes against loopback lab instances; bounded timeouts (reuse `QUERY_TIMEOUT` pattern); `Unknown`/`Error` fail-closed.
- Lab verification only (`src/lab.rs` pattern, isolated `REAPER_LAB_REGISTRY`, temp `HOME`/`XDG_STATE_HOME`).
- `dry-run` default; NO `close --act` on production OpenCode/Codex; NO `codex app-server daemon stop` on production; NO killing production servers.
- No new supervisor/broker/policy engine; no modifying OpenCode/Codex in production.

## Constraints
- `IdleVerified` NEVER from elapsed time, CPU absence, PPID 1, or empty `/api/session/active` alone.
- `evidence::proven()` keeps all conjunctive inputs (lab_member, owner Unclaimed/ClaimedDown, grace_expired, revalidated_now, owner_dead, last_client_gone, no_pending_work = Some(true)).
- 12 safety rules / existing guards preserved (identity revalidation, terminal states, owner precedence, lab membership, audit logs).
- Rust zero-dep preference preserved (no new crates without justification); `cargo fmt --check`, `clippy --all-targets -- -D warnings`, `cargo test`, `cargo build --release` must pass.
- OpenCode first, then Codex. An adapter without client+work visibility stays UNFIT.

## Tasks
- [x] T1 (route: delegated-direct, trigger: broad-research + >5 lookups) — OpenCode V2 investigation: installed v2.0.28 behavior + https://dev.opencode.ai/v2/docs/api; live-client identification (TUI/CLI/API), pending executions/requests, background jobs surviving client close, shared vs standalone, per-project MCP release, what is obtainable without patching OpenCode. Output: evidence notes + gap list. Checks: docs URLs + live lab probes read-only.
- [x] T2 (route: delegated-direct, trigger: broad-research) — Codex investigation: installed codex-cli 0.162.1 daemon protocol; client attach, active ops, pending work query, connect/disconnect notifications, control-socket queries, `daemon stop` effects, UI-close vs work-close distinction. No invented endpoints; document gaps + non-invasive workaround. Checks: CLI help/socket inspection read-only, no production interruption.
- [x] T3 (route: delegated-direct, trigger: 2+ non-trivial files) — Evidence model: new `ClientWorkEvidence { Active | IdleVerified | Unknown | Error }` type + mapping into `AbandonEvidence { last_client_gone, no_pending_work }`; `IdleVerified` requires complete+authoritative source; unit tests for each variant + proven() integration (rescue invalidates). Checks: `cargo test evidence`.
- [x] T4 (route: delegated-direct, trigger: writer 2+ files) — OpenCode sources: loopback-only HTTP probes (`/api/session/active`, durable history/events if exposed), connection counting via authoritative interface only; shared/standalone distinction; per-project scope; never infer idle from empty-active alone. Checks: unit + lab integration (no-client, 1 TUI, 2 clients, active execution, closed-client+pending, reconnect-during-grace, multi-project matrix). STATUS partial 2026-10-13: sweep + parsers + TCP counter implemented but (a) counter uses Reaper PID not server PID, (b) transport errors force global Error before TCP fallback, (c) ambiguous shapes map to Active instead of surface-Unknown, (d) dead_code (no binary consumer), (e) lab test missing (binary-crate has no lib target — must live in src unit tests gated by env).
- [x] T4b (route: delegated-direct, fix-up) — Harden OpenCode probe: server-PID TCP counting via /proc/<srvpid>/fd + /proc/net/tcp; per-surface Unknown precedence (Active > Unknown > IdleVerified; Error only if server.info unreachable); ambient `opencode api` mode (no --server flag) for own background service; fast engine path (info+active+shell+pty, never IdleVerified) wired into main.rs engine for opencode processes + full assess in pilot report; lab test in src unit tests behind REAPER_LAB_OPENCODE=1 (empty sweep + SSE-client→Active via TCP + session.create if viable); TCP-counter self-test with TcpListener; latency report. Checks: fmt+clippy -D warnings+test green.
- [x] T5 (route: delegated-direct, trigger: writer 2+ files) — Codex sources: control-socket / CLI read-only queries where available; otherwise honest Unknown + documented gap; daemon-stop semantics documented, never executed on prod. Checks: unit + equivalent lab scenarios only when non-disruptive.
- [x] T6 (route: delegated-direct, trigger: per-action delegation for suites) — Real scenario matrix + resource measurement: lab OpenCode matrix (7 scenarios), Codex equivalents when safe; audit logs; `pilot report/metrics` resource readout; dry-run everywhere. Checks: integration tests green, logs attached.
- [x] T8 (route: delegated-direct, trigger: 2+ non-trivial files) — Per-session live-state sweep (the named unblocker): HTTP-direct explicit probes (Basic opencode:pw via netrc-tempfile, ~200ms) + CLI-spawn ambient (30s timeout, spawn ~4.5s cold-HOME measured); per-session message.list/inbox.list deep check (cap 10, overflow→Unknown); session_has_live_work states (running/Running/Streaming→Active; exited/killed/terminal→clean; unknown→Unknown); session.active non-empty→Active but empty proves nothing (verified live); shell.remove/permission/form ops; contract table in code docs; tests: dormant-history Unknown, live-shell Active, kill-client-mid-tool still Active, remove→clean, wrong-pw Error, closed-port Error; policy/engine untouched (12 rules + proven() as-is). Checks: fmt+clippy+test+lab green.
- [x] T7 (route: direct-inline, trigger: none — mechanical single-file docs) — Close-out: fmt/clippy/test/release evidence, limitations + insufficient sources, criteria for first real close, commits preserving history, CHANGELOG. Checks: 4 commands green.

## T6 — Matriz de escenarios (observada, sin tocar producción)
| Escenario | OpenCode | Codex |
|---|---|---|
| Servidor vacío | lab: Unknown-con-causa (TCP denegado aquí); IdleVerified en kernels capaces | lab: WorkAbsent (0 threads, 0 queued) |
| Ejecución activa | Active vía shell.list/message running (lab `sleep`, verificado) | fixtures (Active vivo sin modelo: gap documentado) |
| Cliente muerto + trabajo vivo | Active persiste tras kill -9 del CLI (verificado) | N/A (sin RPC vivo) |
| Historial durmiente | Unknown, nunca Active (verificado) | threads>0→Unknown (prod en vivo: 101 hilos) |
| Permisos/forms pendientes | Active (global+sesión cableados) | queued>0→Active (fixture; queue prod legible) |
| Query incompleta / auth erróneo | Error (puerto cerrado / password mala) | Error (socket ausente / daemon caído) |
| Reconexión en gracia | tests existentes (`grace_cancel_on_client_return`, `rescue_during_grace_cancels`, rescue-mapping) | mismo motor |
| TUI / 2 clientes / multiproyecto en vivo | NO ejecutado (TUI impracticable; kinds indistinguibles; scope=nota) | N/A |
| Pilot en vivo (prod, read-only) | Active real detectado, todo Blocked, proven=false | Unknown honesto con conteo real |

## Criterios para el primer cierre real (no autorizados aún)
1. Entorno con /proc/net/tcp legible (OpenCode IdleVerified) o señal de presencia (ambos).
2. Revisión humana por candidato + RDD explícito; dry-run sigue por defecto.
3. Codex: jamás IdleVerified con las interfaces actuales (solo WorkAbsent); un cierre exigiría decisión de política explícita, no recomendada.

## Acceptance criteria
- Every evidence source returns Active/IdleVerified/Unknown/Error with named authoritative origin; IdleVerified impossible from time/CPU/PPID/empty-active alone (tested).
- `proven()` still conjunctive; no regression in 69 prior tests.
- Scenario matrix with observed results; audit logs.
- fmt + clippy + test + release green; resource consumption measured.
- Dry-run default preserved; no production close executed.
- No adapter declared FIT without client+work visibility.

## Applicable checks / TDD
- Test-first where runnable deterministic RED exists (evidence mapping, parsers, matrix harness); otherwise explain exception + structural checks.
- Per task: focused `cargo test <name>`; close-out: full `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, `cargo build --release`.

## Progress
- 2026-10-13: feature doc created; exploration handoff received (adapters always Unknown, engine None for client/work, lab harness isolated).
- 2026-10-13: T1 DONE (OpenCode V2): full API catalogue from https://dev.opencode.ai/v2/docs/api + openapi.json. Key: `GET /api/session/active` = "foreground Session drains currently owned by this OpenCode process" — NOT client/work proof. Work surfaces: session list/create, inbox, permission/request + per-session, form, shell list/run/output, pty list, event SSE, project list, server.info. `opencode serve` takes NO positional dir (cwd-scoped), `--hostname/--port/--service/--stdio`; `opencode api --server URL <operation>` with `OPENCODE_PASSWORD` (server prints `server password ...` on stdout). Verified live in lab: server.info→{version,pid,urls,paths,capabilities}; session.active→{"data":{}}; shell.list/pty.list→{location,data:[]} — all require auth (else UnauthorizedError). No documented connected-client list endpoint: client-presence visibility is a GAP; procfs TCP-fd counting is the candidate non-invasive complement (kind indistinguishable).
- 2026-10-13: T2 DONE (Codex): codex-cli 0.162.1. Daemon cmdline `codex.bin app-server --listen unix:// --analytics-default-enabled --managed-daemon`; control socket symlink `~/.codex/app-server-control-termux/app-server-control.sock` → `/data/data/com.termux/cdx-termux-10373/<id>` (srw-------); `daemon version` (read-only JSON: status/pid/startTime/executableIdentity digests/socketPath) SAFE; `app-server proxy --sock PATH` proxies stdio↔control socket (JSON-RPC path, non-invasive); `generate-json-schema` dumped 39+ files incl. thread/* methods (thread/list, thread/loaded/list, thread/queue/changed, thread/status/changed...). Daemon holds queue_1.sqlite + logs_2.sqlite open. `/proc/net/unix` denied on Termux → socket-conn counting via procfs UNAVAILABLE (gap). `daemon stop` effects unverified (never run on prod). Framing: Content-Length (Kstream underflow string en binario); `agents` exige TTY (no scripteable).
- 2026-10-14: T4c/T8 DONE y verificado por parent con evidencia propia: fmt=0, clippy -D=0, test 74+2, release ok (1016680 bytes), lab ok (sweep mediano 1191ms, info cold 34ms/warm 23ms). Transporte final: explícito por curl+Basic preventivo vía stdin-config (netrc inservible: el 401 viene sin WWW-Authenticate); POST exige Content-Type json (verificado: form-default → Unsupported content-type); ambiental por CLI con 30s timeout. Semántica: project.scope-only, historial→Unknown, per-session message/inbox/permission deep-check (cap 10), session.active vacía no prueba nada, kill-cliente-mid-tool→sigue Active (verificado), shell.remove→killed. TCP denegado aquí → IdleVerified inalcanzable en este Termux (Unknown-con-causa honesto). Siguiente: T5 Codex (proxy JSON-RPC thread/* + variante WorkAbsent).
- 2026-10-14: T3+T4b DONE in tree (uncommitted): ClientWorkState + mapping, ambient/explicit OpenCodeProbe, assess() full sweep + assess_fast() engine path, server-PID TCP counter, unit tests; main.rs engine + pilot.rs report wired; fmt+clippy+test green (71 unit + 2 integration). Lab found REAL `project.list` bare-array shape `[{...}]` → parser gap (test failed honestly, no IdleVerified claimed). Semantic fix T4c: project.list is scope-info only (a server always has ≥1 project — never gates); session.list non-empty → Unknown (dormant history ≠ work; per-session live-state inspection is the named unblocker), never Active. policy.rs 12 rules read as code (§7): R1/2 absolute+unknown protected, R3/4 structural (no CPU/PPID inputs exist), R5/6 active→protected / unverifiable→Blocked BEFORE proven is consulted, R8 candidate only on proven, R9/10 grace+rescue-cancel, R11 memory_pressure ignored, R12 (audit/dry-run posture per pilot limitations). Engine wiring is safe: opencode liveness stays Unknown→Blocked dominates; proven() can only go true in lab (lab_member false in prod). Priority-3 findings: OpenCode has no client-list endpoint (full catalogue verified) → kernel TCP counting is the only non-invasive client signal; `--stdio`/ACP servers permanently Unknown; TUI/CLI/API kinds indistinguishable; disconnects only visible by polling. Codex `agents` requires TTY (verified `stdin is not a terminal`) → not scriptable; no conn-listing method in schema; proxy+JSON-RPC thread surfaces are the only path. shell.create body = {"command"} (+cwd/timeout) → live pending-work test viable via `opencode api shell.create --data`.

## Verification evidence
- (pending) fmt/clippy/test/release outputs; matrix results; logs.

## Per-query contract (OpenCode v2.0.28, lab-verified 2026-10-14)
| Consulta | Prueba | No prueba | Imposible aquí |
|---|---|---|---|
| `server.info` | identidad (pid/versión/urls) | nada sobre trabajo | — |
| `session.active` non-empty | drains foreground vivos → Active | vacía NO prueba nada (verificado: vacía durante `sleep 20` en ejecución) | — |
| `session.message.list` por sesión | `"status":"running"`/Running/Streaming → trabajo vivo; solo estados terminales → sesión sin trabajo | página por defecto (profundidad limitada, documentada) | streaming de assistant sin modelo vivo no observado |
| `session.inbox.list` / permission / form non-empty | entrada/aprobación pendiente → Active | — | — |
| `shell.list` `status:running` | trabajo vivo (sobrevive a muerte del cliente, verificado con kill -9) | — | — |
| `pty.list` non-empty | terminal vivo → Active | — | — |
| `project.list` / `session.list` (historial) | alcance; historial durmiente → Unknown (nunca Active) | historial ≠ trabajo | inspección viva por sesión más allá del cap |
| TCP /proc | conteo autoritativo donde legible | — | Termux deniega /proc/net/tcp{,6} → client-presence siempre Unknown aquí |
| `session.list` vacía + superficies vacías + TCP 0 | IdleVerified (solo kernels capaces) | en este Termux: máximo Unknown-con-trabajo-cero | — |
| `codex agents` | nada scripteable (exige TTY) | — | listado de clientes del daemon |
| Codex socket (proxy) | NADA verificado: CL/newline/init+initialized/ping/ws-hybi → silencio total (proxy reenvía verbatim, probado con señuelo). Protocolo probablemente binario propio o con token. NO usar en assess | — | framing RPC capítulo cerrado como negativo |
| Codex sqlite (`state_5.sqlite` threads, `queue_1.sqlite` queued_items) vía `sqlite3` CLI 3.54 + `mode=ro` | inventario de trabajo registrado sin IPC al daemon (cero disturbio): queued>0→Active; threads no archivados>0→Unknown (viveza por hilo sin verificar); 0/0→WorkAbsent | hilos durmientes vs vivos (sin RPC vivo) | presencia de clientes (siempre Unknown) |
| Codex lab daemon | HOME fuera de tmp OBLIGATORIO (bajo tmp: `Error: No such file or directory`); socket symlink→ns nuevo sin colisión; `.codex` propio completo | — | crear actividad sin modelo (Active vivo sin verificar) |
| Eventos SSE | solo hacia adelante, sin snapshot | ausencia | enumerar conectados |

## Next step
- T8 worker (same session, background): HTTP-direct + per-session sweep + tests. Then T5 Codex (archivos libres tras T8).
