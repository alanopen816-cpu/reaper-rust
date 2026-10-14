# Controlled coverage entry (lab only)

This design is a narrow UDS entry point for a Reaper-owned lab service. It is
not production transport steering, does not redirect production traffic, and
must never force production through a proxy. Dry-run remains the default.

## Meaning and preconditions

`CompleteVerified` is a time-local lab statement about the controlled service
instance, not a claim that every client on the device is globally enumerable.
It is returned only when the live service identity matches its lab registry
entry; the UDS path and parent directory have the expected owner and modes;
registered peer identities remain live and match PID, UID, start ticks, boot,
server path, and nonce; no unregistered peer or event loss has been observed;
the service ledger accounts for clients and work; and listener enumeration
finds no TCP LISTEN socket. A detected listener, unreadable listener tables,
invalid permissions, stale identity, or lost peer/event information fails
closed to non-complete coverage. Any TCP listener is conservatively treated as
unattributed and invalidating: procfs socket tables do not establish which
process owns a socket.

The UDS parent directory is required to be owned by the service UID with mode
0700, and the socket by that UID with mode 0600. These permissions constrain
other UIDs, not hostile processes sharing the same UID. Kernel peer credentials
authenticate PID/UID/GID, but cannot distinguish mutually untrusted same-UID
processes; the explicit roster (PID, start ticks, boot, server, nonce) is the
trust boundary. Same-UID isolation is therefore not guaranteed.

At attestation, `/proc/self/net/tcp` is tried first, then `/proc/net/tcp`.
Entries in TCP state `0A` are listeners. If neither table can be read, coverage
is Unknown. The live check on this worker's Termux kernel found both
`/proc/self/net/tcp` and `/proc/net/tcp` unreadable (permission denied), so a
planted-listener check cannot be performed on this kernel. The implementation
fails closed to Unknown; this observation is environment-specific and not
generalized to Android. `/proc/net` access restrictions can prevent listener
enumeration; Unknown is retained rather than interpreted as absence. A restart
changes the server identity and invalidates outstanding proofs.

The earlier V9-T2 18-step demo run is pre-listener-gate evidence only. It did
not establish transport exclusivity and must not be cited as successful close
evidence under this gate. With both tables denied, the expected V9-T3 result is
steps 1-10 followed by a blocked grace/candidate entry; close is unauthorized.

## Applicability boundaries

### OpenCode

An isolated OpenCode server may be studied only in an explicitly controlled
lab. A shared server has clients and transports outside this roster; it is not
covered. A standalone client is not necessarily wrapper-managed, and a wrapper
marker alone does not prove transport attachment or disconnection. External,
unobservable clients remain Unknown. OpenCode is NOT termination-eligible
while transports or jobs are unverifiable. No production server may be forced
through this UDS entry or a proxy.

### Codex

Codex process presence and absence are separate observations: absence of an
observed process is not proof that a session or work has ended. SQLite state is
not equivalent to disconnection. Unknown remains Unknown; do not promote
missing rows, inaccessible state, or absent process observations into verified
idle coverage.

## Evidence inventory

The accompanying tests cover controlled concurrent connections, observed
disconnects, abrupt child death, reconnect, surviving work, and synthetic event
loss. TCP listener visibility is checked live because procfs availability
varies. These lab observations do not establish production client completeness.
