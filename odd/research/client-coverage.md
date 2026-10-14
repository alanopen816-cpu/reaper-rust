# Client coverage investigation (lab only)

## Evidence and contract

| Mechanism | Proves | Does not prove / impossible |
|---|---|---|
| OpenCode `GET /api/event` SSE during API-client attach/detach | The captured event stream can reveal event types emitted by this server instance. | A connected client roster cannot be inferred unless explicit connect/disconnect events occur. An empty stream is not evidence of no clients. |
| `/proc/<pid>/fd`, `/proc/net/tcp{,6}`, `/proc/net/unix` | On capable Linux, these may expose process descriptors and kernel socket endpoints (implementation/configuration dependent). | This device denies these procfs reads, so no socket-to-process attribution was observed; Linux expectations are not verified here. |
| Spawn wrapper marker (`REAPER_MANAGED=<nonce>`) | Identifies processes launched through the wrapper while the marker survives in their environment. | External/direct clients and marker-stripping/replacing launches are invisible; it is not complete server client coverage. |
| Instrumented TCP loopback proxy | Logs connect/disconnect for traffic that traverses it; self-contained test asserts 2 connects and 1 close. | Direct-to-port clients bypass it. It demonstrates a visibility mechanism, not production coverage. Full traffic steering (firewall/redirect) is out of scope and prohibited for production. |

## OpenCode event observation

The task's parent-verified OpenCode API catalogue/auth facts were reused. No server was started in this constrained execution: the runtime supplied no authorized lab launcher/command, and the required `<60s` bound could not be assured. Therefore **no captured SSE sample and no event taxonomy observation are available**; connect/disconnect event types are unknown, not absent. Do not treat this as evidence that SSE is silent. A bounded local lab run remains required to complete this investigation.

## Procfs observation

The parent-provided device observation is that `/proc/net/tcp`, `/proc/net/tcp6`, and `/proc/net/unix` reads are denied. `/proc/<pid>/fd` was not independently probed in this worker; expected permission denial is not asserted as observed. On capable Linux, descriptors and socket tables can potentially be correlated, but namespaces, permissions, races, and kernel configuration limit attribution. This is an expectation, not device evidence.

## Prototype verdict and tracker recommendation

`tests/client_coverage.rs` contains a zero-dependency loopback TCP accept proxy and a fast deterministic connection-count test, plus an opt-in server-info test gated by `REAPER_LAB_COVERAGE=1`. The real-server test needs `REAPER_LAB_PORT` and a lab OpenCode server, and its execution is not evidence unless run with those prerequisites. **Recommended tracker default: ManagedOnly**; wrapper-launched clients can be represented as managed, while all external/unverifiable clients remain Unknown. Proxy-based visibility is useful for a controlled lab, but cannot justify complete production coverage.
