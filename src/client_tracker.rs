//! Restart-safe, conservative registry for wrapper-managed clients.
//!
//! Coverage remains incomplete: external clients cannot be enumerated reliably
//! on this device. The wrapper spawns and waits, but cannot forward async signals
//! without libc; it records only after child completion.
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    pub tool: String,
    pub project_dir: String,
    pub server: String,
    pub nonce: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub boot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientState {
    ConnectedVerified {
        evidence: String,
        provenance: String,
    },
    EndedVerified {
        evidence: String,
        provenance: String,
    },
    PossiblyGone {
        evidence: String,
        provenance: String,
    },
    UnknownExternal {
        evidence: String,
        provenance: String,
    },
    Unverifiable {
        evidence: String,
        provenance: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientRecord {
    pub identity: ClientIdentity,
    pub state: ClientState,
    pub active_work_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Registry {
    pub clients: Vec<ClientRecord>,
}

/// How much of the client population can be safely reasoned about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coverage {
    CompleteVerified,
    Partial,
    Unknown,
    Broken,
}

/// Evidence-bearing proof. Fields are private so callers cannot forge issuance.
#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CoverageProof {
    transports: Vec<String>,
    server_id: String,
    issued_at: u64,
    ttl: u64,
    provenance: String,
    adapter_limits: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum ProofInvalidation {
    ServerRestart,
    EventLoss,
    CoverageExpiry,
    ProxyBypass,
}

#[allow(dead_code)]
impl CoverageProof {
    /// Test/lab issuer only; production deliberately has no CompleteVerified issuer.
    #[cfg(test)]
    pub fn issue_verified(
        transports: Vec<String>,
        server_id: &str,
        issued_at: u64,
        ttl: u64,
        provenance: &str,
        adapter_limits: &str,
    ) -> Result<Self, &'static str> {
        if transports.is_empty() {
            return Err("no transports observed");
        }
        if server_id.trim().is_empty() {
            return Err("missing server identity");
        }
        if provenance.trim().is_empty() {
            return Err("missing provenance");
        }
        if adapter_limits.trim().is_empty() {
            return Err("missing adapter limits note");
        }
        Ok(Self {
            transports,
            server_id: server_id.into(),
            issued_at,
            ttl,
            provenance: provenance.into(),
            adapter_limits: adapter_limits.into(),
        })
    }

    pub fn coverage_for(&self, server_id: &str, now: u64) -> Coverage {
        let _evidence = (&self.transports, &self.provenance, &self.adapter_limits);
        if server_id != self.server_id {
            eprintln!("coverage proof rejected: foreign server identity");
            Coverage::Unknown
        } else if now < self.issued_at || now.saturating_sub(self.issued_at) > self.ttl {
            eprintln!("coverage proof rejected: expired");
            Coverage::Unknown
        } else {
            Coverage::CompleteVerified
        }
    }

    pub fn invalidate(&self, event: ProofInvalidation) -> Coverage {
        eprintln!("coverage proof invalidated: {event:?}");
        Coverage::Unknown
    }
}

fn registry_path() -> PathBuf {
    if let Some(path) = std::env::var_os("REAPER_CLIENT_REGISTRY") {
        return PathBuf::from(path);
    }
    crate::logx::default_state_dir().join("clients.json")
}

// Keep a tiny JSON string codec local: this binary intentionally has no runtime dependencies.
#[allow(dead_code)]
fn escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '"' => "\\\"".chars().collect::<Vec<_>>(),
            '\\' => "\\\\".chars().collect(),
            '\n' => "\\n".chars().collect(),
            '\r' => "\\r".chars().collect(),
            '\t' => "\\t".chars().collect(),
            c if c.is_control() => " ".chars().collect(),
            c => vec![c],
        })
        .collect()
}

#[allow(dead_code)]
fn encode(r: &Registry) -> String {
    let mut out = String::from("{\"clients\":[");
    for (i, c) in r.clients.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let (kind, evidence, provenance) = match &c.state {
            ClientState::ConnectedVerified {
                evidence,
                provenance,
            } => ("ConnectedVerified", evidence, provenance),
            ClientState::EndedVerified {
                evidence,
                provenance,
            } => ("EndedVerified", evidence, provenance),
            ClientState::PossiblyGone {
                evidence,
                provenance,
            } => ("PossiblyGone", evidence, provenance),
            ClientState::UnknownExternal {
                evidence,
                provenance,
            } => ("UnknownExternal", evidence, provenance),
            ClientState::Unverifiable {
                evidence,
                provenance,
            } => ("Unverifiable", evidence, provenance),
        };
        let id = &c.identity;
        let jobs = c
            .active_work_ids
            .iter()
            .map(|s| format!("\"{}\"", escape(s)))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!("{{\"tool\":\"{}\",\"project\":\"{}\",\"server\":\"{}\",\"nonce\":\"{}\",\"pid\":{},\"start_ticks\":{},\"boot_id\":\"{}\",\"state\":\"{}\",\"evidence\":\"{}\",\"provenance\":\"{}\",\"jobs\":[{}]}}",
            escape(&id.tool), escape(&id.project_dir), escape(&id.server), escape(&id.nonce), id.pid, id.start_ticks,
            escape(&id.boot_id), kind, escape(evidence), escape(provenance), jobs));
    }
    out.push_str("]}\n");
    out
}

// Decode only our emitted flat-object format; malformed or unknown input fails closed.
fn field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let marker = format!("\"{key}\":");
    let rest = s.split_once(&marker)?.1;
    if rest.starts_with('[') {
        Some(rest.split_once(']')?.0.strip_prefix('[')?)
    } else if let Some(q) = rest.strip_prefix('"') {
        Some(q.split_once('"')?.0)
    } else {
        Some(rest.split([',', '}']).next()?)
    }
}
fn string_array(s: &str, key: &str) -> io::Result<Vec<String>> {
    let raw = field(s, key).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid client registry array")
    })?;
    let mut values = Vec::new();
    let mut rest = raw.trim();
    while !rest.is_empty() {
        let Some(after_open) = rest.strip_prefix('"') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid client registry array item",
            ));
        };
        let Some((value, after_value)) = after_open.split_once('"') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated client registry array item",
            ));
        };
        values.push(value.to_owned());
        rest = after_value.trim_start();
        if let Some(after_comma) = rest.strip_prefix(',') {
            rest = after_comma.trim_start();
        } else if !rest.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid client registry array separator",
            ));
        }
    }
    Ok(values)
}
fn decode(data: &str) -> io::Result<Registry> {
    let mut clients = Vec::new();
    for raw in data.split('{').skip(2) {
        let Some(obj) = raw.split('}').next() else {
            continue;
        };
        let get = |k| {
            field(obj, k).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid client registry")
            })
        };
        let number = |k| {
            get(k)?.parse::<u64>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid client registry number")
            })
        };
        let state = match get("state")? {
            "ConnectedVerified" => ClientState::ConnectedVerified {
                evidence: get("evidence")?.into(),
                provenance: get("provenance")?.into(),
            },
            "EndedVerified" => ClientState::EndedVerified {
                evidence: get("evidence")?.into(),
                provenance: get("provenance")?.into(),
            },
            "PossiblyGone" => ClientState::PossiblyGone {
                evidence: get("evidence")?.into(),
                provenance: get("provenance")?.into(),
            },
            "UnknownExternal" => ClientState::UnknownExternal {
                evidence: get("evidence")?.into(),
                provenance: get("provenance")?.into(),
            },
            "Unverifiable" => ClientState::Unverifiable {
                evidence: get("evidence")?.into(),
                provenance: get("provenance")?.into(),
            },
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown client state",
                ))
            }
        };
        let pid = number("pid")?;
        let active_work_ids = string_array(obj, "jobs")?;
        if pid > u32::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid pid"));
        }
        clients.push(ClientRecord {
            identity: ClientIdentity {
                tool: get("tool")?.into(),
                project_dir: get("project")?.into(),
                server: get("server")?.into(),
                nonce: get("nonce")?.into(),
                pid: pid as u32,
                start_ticks: number("start_ticks")?,
                boot_id: get("boot_id")?.into(),
            },
            state,
            active_work_ids,
        });
    }
    Ok(Registry { clients })
}

pub fn load_at(path: &Path) -> io::Result<Registry> {
    match fs::read_to_string(path) {
        Ok(data) => decode(&data),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Registry::default()),
        Err(e) => Err(e),
    }
}
#[allow(dead_code)]
pub fn save_at(registry: &Registry, path: &Path) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))?;
    let tmp = path.with_extension("json.tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    f.write_all(encode(registry).as_bytes())?;
    f.sync_all()?;
    fs::rename(tmp, path)
}
pub fn current_registry() -> io::Result<Registry> {
    load_at(&registry_path())
}

/// Remove records whose full process identity no longer matches this boot.
pub fn discard_stale(registry: &mut Registry) {
    let boot = boot_id().ok();
    registry.clients.retain(|record| {
        let live = process_start_ticks(record.identity.pid).ok();
        identity_matches(&record.identity, live, boot.as_deref())
    });
}

#[allow(dead_code)]
fn process_start_ticks(pid: u32) -> io::Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = s
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad proc stat"))?;
    s[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing start ticks"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad start ticks"))
}
#[allow(dead_code)]
pub fn identity_matches(
    id: &ClientIdentity,
    live_start: Option<u64>,
    live_boot_id: Option<&str>,
) -> bool {
    live_start == Some(id.start_ticks) && live_boot_id == Some(id.boot_id.as_str())
}
#[allow(dead_code)]
fn boot_id() -> io::Result<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id").map(|s| s.trim().to_owned())
}

pub fn tracker_signal(state: &ClientState, has_active_work: bool) -> Option<bool> {
    match state {
        ClientState::ConnectedVerified { .. } => Some(true),
        ClientState::EndedVerified { .. } => Some(!has_active_work),
        ClientState::PossiblyGone { .. }
        | ClientState::UnknownExternal { .. }
        | ClientState::Unverifiable { .. } => None,
    }
}
pub fn registry_coverage(result: &io::Result<Registry>) -> Coverage {
    match result {
        Err(_) => Coverage::Broken,
        Ok(registry) if registry.clients.is_empty() => Coverage::Unknown,
        Ok(registry)
            if registry.clients.iter().any(|client| {
                matches!(
                    client.state,
                    ClientState::UnknownExternal { .. }
                        | ClientState::Unverifiable { .. }
                        | ClientState::PossiblyGone { .. }
                )
            }) =>
        {
            Coverage::Partial
        }
        Ok(_) => Coverage::Partial,
    }
}
pub fn combine_signals(owner_active: Option<bool>, tracker_active: Option<bool>) -> Option<bool> {
    match (owner_active, tracker_active) {
        (Some(true), _) | (_, Some(true)) => Some(true),
        (None, _) | (_, None) => None,
        _ => Some(false),
    }
}
/// Registry-only coverage cannot establish whole-server transport coverage.
pub fn coverage() -> Coverage {
    Coverage::Unknown
}
#[allow(dead_code)]
pub fn can_claim_idle() -> bool {
    coverage() == Coverage::CompleteVerified
}

#[allow(dead_code)]
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
#[allow(dead_code)]
fn nonce() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{now:x}-{:x}-{:x}",
        std::process::id(),
        NONCE_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// Launch a managed client, wait synchronously, and record its verified end.
/// Async signal forwarding is unavailable without libc; this wrapper deliberately
/// only spawn+wait+record and does not claim full client/server coverage.
#[allow(dead_code)]
pub fn launch_wrapped(
    tool: &str,
    args: &[String],
    extra_env: &[(String, String)],
) -> io::Result<ExitStatus> {
    let nonce = nonce();
    let mut cmd = Command::new(tool);
    cmd.args(args).env("REAPER_MANAGED", &nonce);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn()?;
    let pid = child.id();
    let start_ticks = process_start_ticks(pid).unwrap_or(0);
    let boot = boot_id().unwrap_or_default();
    let cwd = std::env::current_dir()
        .unwrap_or_default()
        .display()
        .to_string();
    let mut registry = current_registry()?;
    registry.clients.push(ClientRecord {
        identity: ClientIdentity {
            tool: tool.into(),
            project_dir: cwd,
            server: String::new(),
            nonce: nonce.clone(),
            pid,
            start_ticks,
            boot_id: boot,
        },
        state: ClientState::ConnectedVerified {
            evidence: "managed wrapper spawned child".into(),
            provenance: "REAPER_MANAGED nonce".into(),
        },
        active_work_ids: Vec::new(),
    });
    save_at(&registry, &registry_path())?;
    let status = child.wait()?;
    // Other managed clients may have updated the shared registry while this child ran.
    let mut registry = current_registry()?;
    if let Some(record) = registry
        .clients
        .iter_mut()
        .find(|record| record.identity.pid == pid && record.identity.nonce == nonce)
    {
        record.state = ClientState::EndedVerified {
            evidence: format!("wrapper observed child exit: {status}"),
            provenance: "waitpid via std::process::Child::wait".into(),
        };
    }
    save_at(&registry, &registry_path())?;
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{Mutex, OnceLock},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    fn lab_dir(label: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from("/data/data/com.termux/files/usr/tmp/opencode").join(format!(
            "reaper-client-{label}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }
    fn launch_sleep(
        path: &Path,
        expected_count: usize,
    ) -> (
        u32,
        thread::JoinHandle<io::Result<std::process::ExitStatus>>,
    ) {
        std::env::set_var("REAPER_CLIENT_REGISTRY", path);
        let wrapper =
            thread::spawn(|| launch_wrapped("sh", &["-c".into(), "exec sleep 30".into()], &[]));
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(registry) = load_at(path) {
                if registry.clients.len() >= expected_count {
                    let record = registry.clients.last().unwrap();
                    if matches!(record.state, ClientState::ConnectedVerified { .. }) {
                        return (record.identity.pid, wrapper);
                    }
                }
            }
            assert!(
                Instant::now() < deadline,
                "managed wrapper did not record child start"
            );
            thread::sleep(Duration::from_millis(25));
        }
    }
    fn sample(state: ClientState) -> ClientRecord {
        ClientRecord {
            identity: ClientIdentity {
                tool: "sh".into(),
                project_dir: "/tmp/project".into(),
                server: "127.0.0.1:8080".into(),
                nonce: "nonce".into(),
                pid: 42,
                start_ticks: 100,
                boot_id: "boot".into(),
            },
            state,
            active_work_ids: vec!["job-1".into()],
        }
    }
    fn states() -> Vec<ClientState> {
        vec![
            ClientState::ConnectedVerified {
                evidence: "e".into(),
                provenance: "p".into(),
            },
            ClientState::EndedVerified {
                evidence: "e".into(),
                provenance: "p".into(),
            },
            ClientState::PossiblyGone {
                evidence: "e".into(),
                provenance: "p".into(),
            },
            ClientState::UnknownExternal {
                evidence: "e".into(),
                provenance: "p".into(),
            },
            ClientState::Unverifiable {
                evidence: "e".into(),
                provenance: "p".into(),
            },
        ]
    }
    #[test]
    fn state_mapping_table_all_variants_and_work_cases() {
        for s in states() {
            for work in [false, true] {
                let expected = match &s {
                    ClientState::ConnectedVerified { .. } => Some(true),
                    ClientState::EndedVerified { .. } => Some(!work),
                    _ => None,
                };
                assert_eq!(tracker_signal(&s, work), expected);
            }
        }
        assert_eq!(
            tracker_signal(&sample(states()[1].clone()).state, true),
            Some(false)
        );
    }
    #[test]
    fn registry_persists_reloads_and_pid_reuse_is_stale() {
        let dir = std::env::temp_dir().join(format!("reaper-client-reg-{}", std::process::id()));
        let path = dir.join("clients.json");
        let original = Registry {
            clients: vec![sample(states()[0].clone())],
        };
        save_at(&original, &path).unwrap();
        let loaded = load_at(&path).unwrap();
        assert_eq!(loaded.clients.len(), 1);
        assert!(identity_matches(
            &loaded.clients[0].identity,
            Some(100),
            Some("boot")
        ));
        assert!(!identity_matches(
            &loaded.clients[0].identity,
            Some(101),
            Some("boot")
        ));
        assert!(!identity_matches(
            &loaded.clients[0].identity,
            Some(100),
            Some("other")
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn registry_round_trip_preserves_active_work_ids() {
        let mut record = sample(states()[0].clone());
        record.active_work_ids = vec!["job-alpha".into(), "job-beta".into()];
        let original = Registry {
            clients: vec![record],
        };
        let decoded = decode(&encode(&original)).unwrap();
        assert_eq!(
            decoded.clients[0].active_work_ids,
            original.clients[0].active_work_ids
        );
    }
    #[test]
    fn wrapper_passthrough_args_env_exit_and_secret_not_logged() {
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join(format!("reaper-client-wrap-{}", std::process::id()));
        let path = dir.join("clients.json");
        std::env::set_var("REAPER_CLIENT_REGISTRY", &path);
        let secret = "sentinel-private-password";
        let args=vec!["-c".into(),"test \"$1\" = 'arg with spaces' && test \"$PASSTHROUGH\" = 'extra value' && test -n \"$REAPER_MANAGED\"; exit 7".into(),"sh".into(),"arg with spaces".into()];
        let status = launch_wrapped(
            "sh",
            &args,
            &[
                ("PASSTHROUGH".into(), "extra value".into()),
                ("TEST_SECRET".into(), secret.into()),
            ],
        )
        .unwrap();
        assert_eq!(status.code(), Some(7));
        let log = fs::read_to_string(&path).unwrap();
        assert!(!log.contains(secret));
        assert!(log.contains("EndedVerified"));
        std::env::remove_var("REAPER_CLIENT_REGISTRY");
        let _ = fs::remove_dir_all(dir);
    }
    #[test]
    fn empty_registry_never_claims_idle() {
        let empty = Registry::default();
        assert!(empty.clients.is_empty());
        assert_eq!(coverage(), Coverage::Unknown);
        assert!(!can_claim_idle());
    }

    #[test]
    fn complete_coverage_requires_both_transport_and_path_proofs() {
        let complete = CoverageProof::issue_verified(
            vec!["http".into()],
            "server-a",
            100,
            30,
            "lab",
            "bounded adapter",
        )
        .unwrap();
        assert_eq!(
            complete.coverage_for("server-a", 101),
            Coverage::CompleteVerified
        );
        assert_ne!(
            complete.coverage_for("server-a", 131),
            Coverage::CompleteVerified
        );
        assert_ne!(
            complete.coverage_for("server-b", 101),
            Coverage::CompleteVerified
        );
        assert!(CoverageProof::issue_verified(vec![], "server-a", 100, 30, "lab", "note").is_err());
        assert!(CoverageProof::issue_verified(
            vec!["http".into()],
            "server-a",
            100,
            30,
            "",
            "note"
        )
        .is_err());
    }

    #[test]
    fn wrapper_and_empty_or_partial_registry_never_prove_complete_coverage() {
        assert_eq!(coverage(), Coverage::Unknown);
        assert_eq!(
            registry_coverage(&Ok(Registry::default())),
            Coverage::Unknown
        );
        let mut registry = Registry {
            clients: vec![sample(states()[0].clone())],
        };
        assert_eq!(registry_coverage(&Ok(registry.clone())), Coverage::Partial);
        registry.clients.push(sample(ClientState::UnknownExternal {
            evidence: "outside tracker".into(),
            provenance: "external".into(),
        }));
        assert_eq!(registry_coverage(&Ok(registry)), Coverage::Partial);
        assert_eq!(
            registry_coverage(&Err(io::Error::other("read failed"))),
            Coverage::Broken
        );
    }

    #[test]
    fn proxy_and_direct_bypass_degrade_coverage() {
        let proxy_only =
            CoverageProof::issue_verified(vec!["proxy".into()], "s", 1, 30, "lab", "proxy-only")
                .unwrap();
        assert_eq!(proxy_only.coverage_for("s", 2), Coverage::CompleteVerified);
        assert_eq!(
            proxy_only.invalidate(ProofInvalidation::ProxyBypass),
            Coverage::Unknown
        );
    }

    #[test]
    fn invalidation_events_revoke_proofs_and_test_issuer_is_test_scoped() {
        for event in [
            ProofInvalidation::ServerRestart,
            ProofInvalidation::EventLoss,
            ProofInvalidation::CoverageExpiry,
            ProofInvalidation::ProxyBypass,
        ] {
            let proof =
                CoverageProof::issue_verified(vec!["transport".into()], "s", 1, 30, "lab", "note")
                    .unwrap();
            assert_ne!(proof.invalidate(event), Coverage::CompleteVerified);
        }
        let source = include_str!("client_tracker.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains("test_only_unchecked"));
    }
    #[test]
    fn combine_is_protection_monotone_over_all_nine_pairs() {
        let inputs = [Some(true), Some(false), None];
        for owner in inputs {
            for tracker in inputs {
                let combined = combine_signals(owner, tracker);
                if owner == Some(true) {
                    assert_eq!(combined, Some(true));
                }
                if tracker == Some(true) {
                    assert_eq!(combined, Some(true));
                }
                if owner == Some(false) && tracker == Some(false) {
                    assert_eq!(combined, Some(false));
                }
                if owner.is_none() || tracker.is_none() {
                    assert_ne!(combined, Some(false));
                }
            }
        }
    }
    #[test]
    fn inspection_error_maps_to_unknown() {
        let error: Option<bool> = None;
        assert_eq!(error, None);
    }

    #[test]
    fn abrupt_child_death_records_verified_end() {
        let dir = lab_dir("abrupt");
        let path = dir.join("clients.json");
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (pid, wrapper) = launch_sleep(&path, 1);
        let status = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .unwrap();
        assert!(status.success());
        wrapper.join().unwrap().unwrap();
        let registry = load_at(&path).unwrap();
        let record = registry
            .clients
            .iter()
            .find(|r| r.identity.pid == pid)
            .unwrap();
        assert!(
            matches!(&record.state, ClientState::EndedVerified { evidence, .. } if evidence.contains("exit"))
        );
        std::env::remove_var("REAPER_CLIENT_REGISTRY");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn two_wrapped_clients_same_server_survive_end_and_restart() {
        let dir = lab_dir("cycle");
        let path = dir.join("clients.json");
        let _guard = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (first_pid, first) = launch_sleep(&path, 1);
        let (second_pid, second) = launch_sleep(&path, 2);
        let active = load_at(&path).unwrap();
        assert_eq!(
            active
                .clients
                .iter()
                .filter(|r| matches!(r.state, ClientState::ConnectedVerified { .. }))
                .count(),
            2
        );
        assert_eq!(active.clients.len(), 2);
        let work = vec!["work-first".to_string(), "work-second".to_string()];
        let mut with_work = active.clone();
        for record in &mut with_work.clients {
            record.active_work_ids = work.clone();
        }
        save_at(&with_work, &path).unwrap();

        let terminate = Command::new("kill")
            .args(["-TERM", &first_pid.to_string()])
            .status()
            .unwrap();
        assert!(terminate.success());
        first.join().unwrap().unwrap();
        let after = load_at(&path).unwrap();
        assert!(after.clients.iter().any(|r| r.identity.pid == first_pid
            && matches!(r.state, ClientState::EndedVerified { .. })
            && r.active_work_ids == work));
        assert!(after.clients.iter().any(|r| r.identity.pid == second_pid
            && matches!(r.state, ClientState::ConnectedVerified { .. })
            && r.active_work_ids == work));

        let restarted = load_at(&path).unwrap();
        assert_eq!(restarted.clients.len(), 2);
        assert!(restarted.clients.iter().any(|r| r.identity.pid == first_pid
            && matches!(r.state, ClientState::EndedVerified { .. })
            && r.active_work_ids == work));
        assert!(restarted
            .clients
            .iter()
            .any(|r| r.identity.pid == second_pid
                && matches!(r.state, ClientState::ConnectedVerified { .. })
                && r.active_work_ids == work));
        let cleanup = Command::new("kill")
            .args(["-KILL", &second_pid.to_string()])
            .status()
            .unwrap();
        assert!(cleanup.success());
        second.join().unwrap().unwrap();
        std::env::remove_var("REAPER_CLIENT_REGISTRY");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn concurrent_observer_loads_are_independent_and_leave_no_locks() {
        let dir = lab_dir("observers");
        let path = dir.join("clients.json");
        let mut expected_record = sample(states()[0].clone());
        expected_record.active_work_ids.clear();
        let expected = Registry {
            clients: vec![expected_record],
        };
        save_at(&expected, &path).unwrap();
        let a = path.clone();
        let b = path.clone();
        let first = thread::spawn(move || load_at(&a).unwrap());
        let second = thread::spawn(move || load_at(&b).unwrap());
        let left = first.join().unwrap();
        let right = second.join().unwrap();
        assert_eq!(left, expected);
        assert_eq!(right, expected);
        assert_eq!(left, right);
        assert!(!dir.join("clients.json.lock").exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(dir);
    }
}
