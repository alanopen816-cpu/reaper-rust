# Feature: reaper-v0.9.2 — Client Registry + Dry-Run + Socket Observability (experimental)

**Locator**: `odd/tasks/reaper-v0.9.2.md` | Engram topic `odd/reaper-v0.9.2/tasks` | Repo `reaper-rust`, base `feature/reaper-v0.9.1@ecafb54` → new `feature/reaper-v0.9.2`
**Base verified 2026-10-15**: HEAD ecafb54, tree clean, branch feature/reaper-v0.9.1, pilot RUNNING pid 15157 (observer read-only, heartbeat live). No push/PR/merge.
**Git strategy**: linear experimental, no history rewrite, no prod touches.

## Objective
Mecanismo cooperativo de registro de clientes + auditoría dry-run + observabilidad /proc fd/socket, fail-closed, sin cierres reales de producción. Reutilizar client_tracker/coverage/identity/managed_service; extensión mínima.

## Scope (authorized)
- Branch `feature/reaper-v0.9.2` desde ecafb54. Solo lab-owned processes para 파괴 tests.
- Pilot: read-only; nunca stop/restart/replace binary/touch state dir (~/.local/state/reaper).
- OpenCode/Codex/MCP/prod: observación/dry-run, sin modificar servicios reales, sin terminación automática.
- 12 rules + proven() + CompleteVerified/Unknown + security gates intactos.
- Dry-run impide materialmente señales destructivas (no solo UI).
- No root/su/sudo, no servicios residentes innecesarios, no duplicar MCP.

## Constraints
- Lease expiry ≠ ausencia; → reconciliación/degradación conservadora.
- Socket count ≠ clientes; fd es complementaria, nunca autoriza cierre sola.
- PID+starttime no elimina TOCTOU; documentar. pidfd solo si compatibilidad demostrada, sin dependencia obligatoria.
- Cobertura incompleta por construcción si bypass no observable; nunca inferir del silencio.
- WOULD_TERMINATE ≠ seguro; distinguir heurística vs evidencia suficiente.
- No tokens/sesiones/datos sensibles en logs; rotación y límites.
- Umbral inactividad 30min solo elegibilidad dry-run, no prueba.

## Tasks
- [ ] V92-T1 (delegated-direct, writer) — Client Registry leases en Rust: register/renew/unregister explícito, lease TTL 30min configurable, expired→Unknown+reconciliación, inconsistent records, active-work solo con evidencia demostrable, Unknown ante pérdida/insuficiencia. Interfaces futuras OpenCode/Codex/MCP sin tocar servicios reales. UDS local cuando justificado; SO_PEERCRED no es auth fuerte. Reutilizar client_tracker.rs:60-79,143-148,382-445, managed_service.rs:697-757.
- [ ] V92-T2 (delegated-direct, writer) — Socket observability /proc/<pid>/fd: socket:[inode] únicos, errores permiso vs desaparecido vs lectura completa, diff entre observaciones, validación identidad antes de atribuir, nunca → clientes ni →CompleteVerified. Reutilizar procfs.rs:23-43,96-120, identity.rs:93-124. Sin sondeo intensivo.
- [ ] V92-T3 (delegated-direct, writer) — Identidad estable + pidfd compat: probar pidfd real en Termux sin asumir; si no, PID+starttime campo22 + validación previa; documentar carrera check-vs-signal; sin dependencia obligatoria pidfd. Toca pidfd.rs:63-65, terminate.rs:211-267, identity.rs.
- [ ] V92-T4 (delegated-direct, writer) — Dry-run permanente + política inicial: log con timestamp, service id, pid/starttime, client state, leases, protected-work, cobertura vías, idle, evidencia presente/ausente, decisión simulada (PROTECT_ACTIVE_CLIENT/WORK/UNKNOWN, WOULD_TERMINATE, INSUFFICIENT_EVIDENCE adaptados), motivo, estado final. Política: OpenCode/Codex protegidos, MCP obs/dry-run, unknown obs. Rotación/límites. Sin capacidad de señal en rutas dry-run (verificación).
- [ ] V92-T5 (delegated-direct, writer+verifier, high) — Adversariales A-G lab-only: A normal, B desaparecido sin unregister, C bypass máxima prioridad (cobertura incompleta por construcción), D carrera durante evaluación, E reinicios/PID reuse, F fallos /proc, G dry-run sin señales. Solo procesos/servidores controlados laboratorio.
- [ ] V92-T6 (direct-inline, parent) — Perf + validación y entrega: RSS/CPU/tiempo inspección/lecturas /proc/tamaño logs/overhead registry vs baseline v0.9.1 (78ms load, 3000KiB, 1582120/2227584B, 178/197 tests). Ejecutar tests existentes+nuevos, auditar rutas señal, verificar prod intacta, documentar límites, confirmar git. Entregables §11.

## Acceptance
- Registro ciclo de vida observable lab, pérdida evidencia → Unknown protegido.
- Bypass demuestra no-CompleteVerified si vía no cubierta.
- Dry-run auditable sin capacidad destructiva.
- Prod intacta, piloto vivo, cero cierres reales.

## Applicable checks (per task)
`cargo fmt --check`; `cargo clippy --all-targets -- -D warnings`; `cargo test`; `cargo build --release`; each also with `--features tui`. Labs as applicable.

## Delivery
- Test-first donde RED determinista; si no, excepción + checks proporcionales. Runner `cargo test`.
- Work-unit commit por tarea (Conventional Commits, sin atribución); record identity. Push/PR/merge = user decisions.
- No declarar CompleteVerified por heurística o dry-runs sin error.

## Progress
- 2026-10-15: feature doc creado (6 tasks V92-T1..T6); branch `feature/reaper-v0.9.2` creada desde ecafb54; piloto verificado vivo pid 15157 read-only. Auditoría base: registry actual no es lease, prod no emite CompleteVerified, pilot stop path separada.
- 2026-10-15: V92-T1 leases implemented and unit-tested in-module; expiry/inconsistent identity remain Unknown and require reconciliation.

## Verification evidence
- (append per task: command → observed result, tier/outcome, commit id)

## Next step
- V92-T1: writer implementa leases sobre client_tracker existente.
