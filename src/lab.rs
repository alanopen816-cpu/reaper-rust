//! Lab-only child registry. No arbitrary PID input is accepted for cleanup.
#[path = "lab_autonomy.rs"]
mod autonomy;
pub use autonomy::close_ready_entry;
#[cfg(test)]
pub use autonomy::{run_lab_cycle, Outcome};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub pid: u32,
    pub start_ticks: u64,
    pub spawned_at: u64,
}
pub struct LabChild {
    child: Child,
    pub entry: Entry,
}
impl LabChild {
    pub fn id(&self) -> u32 {
        self.entry.pid
    }
}
impl LabChild {
    #[cfg(test)]
    pub fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        self.child.wait()
    }
}
impl Drop for LabChild {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn registry_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_REGISTRY_PATH.with(|path| path.borrow().clone()) {
        return path;
    }
    if let Some(path) = std::env::var_os("REAPER_LAB_REGISTRY") {
        return PathBuf::from(path);
    }
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/state")
        })
        .join("reaper/lab.json")
}
fn resolve_tool(name: &str) -> io::Result<PathBuf> {
    let filename = match name {
        "sleep" | "sh" => name,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported lab tool",
            ))
        }
    };
    let prefixed = std::env::var_os("PREFIX")
        .map(PathBuf::from)
        .map(|prefix| prefix.join("bin").join(filename));
    if let Some(path) = prefixed.filter(|path| path.is_file()) {
        return Ok(path);
    }
    let fallback = Path::new("/data/data/com.termux/files/usr/bin").join(filename);
    if fallback.is_file() {
        return Ok(fallback);
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("{filename} not found under $PREFIX nor Termux fallback"),
    ))
}
fn start_ticks(pid: u32) -> io::Result<u64> {
    let s = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = s
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad stat"))?;
    s[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing start_ticks"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad start_ticks"))
}
pub fn identity_ticks(pid: u32) -> io::Result<u64> {
    start_ticks(pid)
}
fn now() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn read_registry_at(path: &std::path::Path) -> io::Result<Vec<Entry>> {
    let data = match fs::read_to_string(path) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut entries = Vec::new();
    for chunk in data.split('{').skip(1) {
        let Some(body) = chunk.split('}').next() else {
            continue;
        };
        let values: Vec<u64> = body
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse().ok())
            .collect();
        if values.len() == 3 && values[0] <= u32::MAX as u64 {
            entries.push(Entry {
                pid: values[0] as u32,
                start_ticks: values[1],
                spawned_at: values[2],
            });
        }
    }
    Ok(entries)
}
fn write_registry(entries: &[Entry], path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("json.tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp)?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    write!(f, "[")?;
    for (i, e) in entries.iter().enumerate() {
        if i != 0 {
            write!(f, ",")?;
        }
        write!(
            f,
            "{{\"pid\":{},\"start_ticks\":{},\"spawned_at\":{}}}",
            e.pid, e.start_ticks, e.spawned_at
        )?;
    }
    writeln!(f, "]")?;
    f.sync_all()?;
    fs::rename(tmp, path)?;
    fs::File::open(path.parent().unwrap())?.sync_all()
}
pub fn registry_contains(entry: &Entry) -> io::Result<bool> {
    Ok(read_registry_at(&registry_path())?
        .iter()
        .any(|e| e.pid == entry.pid && e.start_ticks == entry.start_ticks))
}
pub fn current_registry() -> io::Result<Vec<Entry>> {
    read_registry_at(&registry_path())
}
pub fn registry_path_current() -> PathBuf {
    registry_path()
}

/// Append durable, lab-scoped close receipts beside the lab registry.
pub fn receipt_path_current() -> PathBuf {
    registry_path().with_extension("receipts.jsonl")
}

pub fn close_audit_path_current() -> PathBuf {
    registry_path().with_extension("close-audit.v1")
}

pub fn authorization_for(
    entry: &Entry,
    approval_ref: String,
) -> crate::terminate::ScopedAuthorization {
    let service_id = format!("{}:{}", entry.pid, entry.start_ticks);
    let scope = crate::terminate::close_scope(
        &service_id,
        &registry_path().display().to_string(),
        "reaper-lab",
    );
    crate::terminate::ScopedAuthorization::new(scope, approval_ref)
}

const CLOSE_AUDIT_SCHEMA: &str = "REAPER_CLOSE_AUDIT_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseAuditRecord {
    pub identity: String,
    pub evidence_refs: Vec<String>,
    pub policy_id: String,
    pub policy_version: String,
    pub authorization_scope: String,
    pub approval_refs: Vec<String>,
    pub grace_started_at: u64,
    pub grace_ended_at: u64,
    pub revalidation_results: String,
    pub mechanism: String,
    pub outcome: String,
    pub errors: Vec<String>,
    pub timestamp: u64,
}

impl CloseAuditRecord {
    fn fields(&self) -> io::Result<Vec<String>> {
        if [
            self.identity.as_str(),
            self.policy_id.as_str(),
            self.policy_version.as_str(),
            self.authorization_scope.as_str(),
            self.revalidation_results.as_str(),
            self.mechanism.as_str(),
            self.outcome.as_str(),
        ]
        .iter()
        .any(|value| value.is_empty())
            || self.evidence_refs.is_empty()
            || self.evidence_refs.iter().any(String::is_empty)
            || self.approval_refs.is_empty()
            || self.approval_refs.iter().any(String::is_empty)
            || self.grace_ended_at < self.grace_started_at
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "close audit record is incomplete",
            ));
        }
        Ok(vec![
            self.identity.clone(),
            self.evidence_refs.join("\n"),
            self.policy_id.clone(),
            self.policy_version.clone(),
            self.authorization_scope.clone(),
            self.approval_refs.join("\n"),
            self.grace_started_at.to_string(),
            self.grace_ended_at.to_string(),
            self.revalidation_results.clone(),
            self.mechanism.clone(),
            self.outcome.clone(),
            self.errors.join("\n"),
            self.timestamp.to_string(),
        ])
    }
}

fn audit_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn audit_unhex(value: &str) -> io::Result<String> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "odd audit field",
        ));
    }
    let bytes = (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid audit field"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF8 audit field"))
}

pub fn append_close_audit(path: &Path, record: &CloseAuditRecord) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    static AUDIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = AUDIT_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let fields = record.fields()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let existing = fs::read_to_string(path).unwrap_or_default();
    if !existing.is_empty() && existing.lines().next() != Some(CLOSE_AUDIT_SCHEMA) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported close audit schema",
        ));
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if existing.is_empty() {
        writeln!(file, "{CLOSE_AUDIT_SCHEMA}")?;
    }
    let encoded = fields
        .iter()
        .map(|value| audit_hex(value))
        .collect::<Vec<_>>()
        .join("\t");
    writeln!(file, "{encoded}")?;
    file.sync_all()?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    if reconstruct_close_audit(path)?.last() != Some(record) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted close audit did not reconstruct exactly",
        ));
    }
    Ok(())
}

pub fn reconstruct_close_audit(path: &Path) -> io::Result<Vec<CloseAuditRecord>> {
    let contents = fs::read_to_string(path)?;
    let mut lines = contents.lines();
    if lines.next() != Some(CLOSE_AUDIT_SCHEMA) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported close audit schema",
        ));
    }
    lines
        .map(|line| {
            let fields = line
                .split('\t')
                .map(audit_unhex)
                .collect::<io::Result<Vec<_>>>()?;
            if fields.len() != 13 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "incomplete close audit record",
                ));
            }
            let record = CloseAuditRecord {
                identity: fields[0].clone(),
                evidence_refs: fields[1].split('\n').map(str::to_owned).collect(),
                policy_id: fields[2].clone(),
                policy_version: fields[3].clone(),
                authorization_scope: fields[4].clone(),
                approval_refs: fields[5].split('\n').map(str::to_owned).collect(),
                grace_started_at: fields[6].parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid grace start")
                })?,
                grace_ended_at: fields[7]
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid grace end"))?,
                revalidation_results: fields[8].clone(),
                mechanism: fields[9].clone(),
                outcome: fields[10].clone(),
                errors: if fields[11].is_empty() {
                    Vec::new()
                } else {
                    fields[11].split('\n').map(str::to_owned).collect()
                },
                timestamp: fields[12].parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid audit timestamp")
                })?,
            };
            record.fields()?;
            Ok(record)
        })
        .collect()
}

pub fn persist_close_receipt(entry: &Entry, stages: &[String], verdict: &str) -> io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    static RECEIPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = RECEIPT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = receipt_path_current();
    fs::create_dir_all(path.parent().unwrap())?;
    let quote = |value: &str| -> String {
        format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
    };
    let stages = stages
        .iter()
        .map(|stage| quote(stage))
        .collect::<Vec<_>>()
        .join(",");
    let timestamp = now();
    let authorization_refs = if verdict == "closed" {
        "[\"proven\",\"policy_recomputed\",\"lab_registry\"]"
    } else {
        "[]"
    };
    let line = format!(
        "{{\"scope\":\"reaper-lab\",\"pid\":{},\"start_ticks\":{},\"spawned_at\":{},\"stages\":[{}],\"authorization_refs\":{},\"timestamp\":{},\"verdict\":{},\"reason\":{}}}\n",
        entry.pid,
        entry.start_ticks,
        entry.spawned_at,
        stages,
        authorization_refs,
        timestamp,
        quote(match verdict {
            "closed" => "closed",
            "in_progress" => "in_progress",
            _ => "refused",
        }),
        quote(match verdict {
            "closed" => "close confirmed",
            "in_progress" => "close initiated; restart requires full revalidation",
            _ => verdict,
        })
    );
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&path)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    if file.write(line.as_bytes())? != line.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "lab receipt append was partial",
        ));
    }
    file.sync_all()?;
    fs::File::open(path.parent().unwrap())?.sync_all()?;
    eprintln!("lab close receipt pid={} verdict={verdict}", entry.pid);
    Ok(())
}
fn register(entry: &Entry) -> io::Result<()> {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = registry_path();
    let mut entries = read_registry_at(&path)?;
    entries.retain(|e| e.pid != entry.pid);
    entries.push(entry.clone());
    write_registry(&entries, &path)
}

/// Register an already-running service only after its process identity is read live.
pub fn register_managed_service(pid: u32, ticks: u64) -> io::Result<Entry> {
    if start_ticks(pid)? != ticks {
        return Err(io::Error::other(
            "managed service identity changed before registration",
        ));
    }
    let entry = Entry {
        pid,
        start_ticks: ticks,
        spawned_at: now(),
    };
    register(&entry)?;
    Ok(entry)
}

/// Remove exactly this service identity from the lab roster after confirmed exit.
pub fn unregister_managed_service(entry: &Entry) -> io::Result<()> {
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = registry_path();
    let mut entries = read_registry_at(&path)?;
    entries.retain(|candidate| candidate != entry);
    write_registry(&entries, &path)
}

/// Spawn only known sleeper commands, then persist the exact child identity.
pub fn spawn(ignores_term: bool) -> io::Result<LabChild> {
    let sleep = resolve_tool("sleep")?;
    let sh = resolve_tool("sh")?;
    let mut child = if ignores_term {
        Command::new(sh)
            .args([
                "-c",
                &format!("trap '' TERM; exec '{}' 300", sleep.display()),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?
    } else {
        Command::new(sleep)
            .arg("300")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?
    };
    let entry = Entry {
        pid: child.id(),
        start_ticks: start_ticks(child.id())?,
        spawned_at: now(),
    };
    if let Err(e) = register(&entry) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok(LabChild { child, entry })
}

/// Default cleanup is a refusal and never signals; use explicit authorized
/// close operations for lab children.
#[allow(dead_code)]
pub fn cleanup() -> io::Result<usize> {
    cleanup_with(false)
}
#[allow(dead_code)]
pub fn cleanup_with(allow_sigkill: bool) -> io::Result<usize> {
    if !allow_sigkill {
        eprintln!("lab cleanup refused: explicit act authorization required; registry unchanged");
        return Ok(0);
    }
    let _guard = REGISTRY_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = registry_path();
    if !path.exists() {
        return Ok(0);
    }
    let entries = read_registry_at(&path)?;
    let mut remaining = Vec::new();
    let mut closed = 0;
    for e in entries {
        let record = crate::terminate::LabRecord {
            pid: e.pid,
            start_ticks: e.start_ticks,
            spawned_at: e.spawned_at,
        };
        let mut signaller = crate::terminate::PidfdSignaller;
        let receipts = crate::terminate::close_sequence(
            &record,
            &crate::terminate::ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 1,
                allow_sigkill,
            },
            None,
            &mut signaller,
            |pid, ticks, spawned| {
                registry_contains(&Entry {
                    pid,
                    start_ticks: ticks,
                    spawned_at: spawned,
                })
                .unwrap_or(false)
                    && start_ticks(pid).ok() == Some(ticks)
            },
            std::thread::sleep,
            || "lab cleanup".into(),
        );
        for receipt in &receipts {
            eprintln!("lab cleanup pid {}: {receipt}", e.pid);
        }
        if receipts
            .iter()
            .any(|r| r.starts_with("TERM:") || r.starts_with("KILL:"))
            && start_ticks(e.pid).ok() != Some(e.start_ticks)
        {
            closed += 1;
        } else {
            remaining.push(e);
        }
    }
    write_registry(&remaining, &path)?;
    Ok(closed)
}

#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

static REGISTRY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    static TEST_REGISTRY_PATH: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_audit_round_trip_reconstructs_all_required_fields_and_rejects_truncation() {
        let root = std::env::temp_dir().join(format!(
            "reaper-audit-schema-{}-{}",
            std::process::id(),
            now()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("close.audit");
        let expected = CloseAuditRecord {
            identity: "pid:42:start:77:spawned:100".into(),
            evidence_refs: vec!["scan:101".into(), "attestation:102".into()],
            policy_id: "managed-close".into(),
            policy_version: "1".into(),
            authorization_scope: "service=42:77;registry=lab;project=demo".into(),
            approval_refs: vec!["fresh-approval:42:77".into()],
            grace_started_at: 101,
            grace_ended_at: 105,
            revalidation_results: "identity=true;coverage=true;idle=true;policy=true;proven=true"
                .into(),
            mechanism: "uds+pidfd-term".into(),
            outcome: "closed".into(),
            errors: Vec::new(),
            timestamp: 105,
        };
        append_close_audit(&path, &expected).unwrap();
        let records = reconstruct_close_audit(&path).unwrap();
        assert_eq!(records, vec![expected]);
        std::fs::write(&path, "REAPER_CLOSE_AUDIT_V1\nabc\n").unwrap();
        assert!(reconstruct_close_audit(&path).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
    fn with_registry_path<T>(path: PathBuf, f: impl FnOnce() -> T) -> T {
        TEST_REGISTRY_PATH.with(|slot| *slot.borrow_mut() = Some(path));
        let result = f();
        TEST_REGISTRY_PATH.with(|slot| *slot.borrow_mut() = None);
        result
    }
    #[test]
    fn receipts_and_replaced_registry_reopen_as_a_consistent_durable_pair() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("reaper-receipt-pair-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let registry = root.join("lab.json");
        with_registry_path(registry.clone(), || {
            let first_child = spawn(false).expect("first registered lab child");
            let first_state = std::fs::read(&registry).unwrap();
            let child = spawn(false).expect("second registered lab child replaces registry");
            let entry = child.entry.clone();
            assert_eq!(
                std::fs::metadata(&registry).unwrap().permissions().mode() & 0o777,
                0o600
            );
            persist_close_receipt(&entry, &["stage-one".into()], "in_progress").unwrap();
            persist_close_receipt(&entry, &["stage-two".into()], "closed").unwrap();
            let reopened_state = read_registry_at(&registry).unwrap();
            let receipt_text = std::fs::read_to_string(receipt_path_current()).unwrap();
            assert!(reopened_state.contains(&entry));
            assert!(receipt_text.contains("stage-one") && receipt_text.contains("stage-two"));
            assert!(receipt_text
                .lines()
                .all(|line| line.contains(&format!("\"pid\":{}", entry.pid))
                    && line.contains(&format!("\"start_ticks\":{}", entry.start_ticks))));

            // A refusal before attempting the next atomic registry replacement
            // leaves the last valid state/receipt pair intact; no crash is induced.
            persist_close_receipt(&entry, &["replacement-refused".into()], "refused").unwrap();
            assert_eq!(read_registry_at(&registry).unwrap(), reopened_state);
            assert!(std::fs::read_to_string(receipt_path_current())
                .unwrap()
                .contains("replacement-refused"));
            assert_ne!(first_state, std::fs::read(&registry).unwrap());
            drop(child);
            drop(first_child);
        });
    }
    #[derive(Default)]
    struct FakeExecutor {
        calls: Vec<crate::terminate::SignalKind>,
    }
    impl crate::terminate::SignalExecutor for FakeExecutor {
        fn signal_record(
            &mut self,
            _: &crate::terminate::LabRecord,
            signal: crate::terminate::SignalKind,
            _: &crate::terminate::FreshApproval,
        ) -> Result<crate::terminate::SignalReceipt, crate::terminate::Refusal> {
            self.calls.push(signal);
            Ok(crate::terminate::SignalReceipt {
                path: crate::terminate::SignalPath::Classic,
                signal,
            })
        }
    }
    fn live_test_approval(pid: u32, ticks: u64) -> crate::terminate::FreshApproval {
        let process = crate::procfs::scan()
            .processes
            .into_iter()
            .find(|p| p.pid == pid && p.start_ticks == ticks)
            .expect("live test child");
        crate::terminate::approve_fresh(crate::terminate::FreshApprovalInputs {
            evidence: crate::evidence::AbandonEvidence {
                lab_member: true,
                owner: crate::owner::OwnerVerdict::Unclaimed,
                grace_expired: true,
                revalidated_now: true,
                owner_dead: Some(true),
                last_client_gone: Some(true),
                no_pending_work: Some(true),
            },
            process,
            protection: crate::protection::Protection {
                tier: crate::protection::Tier::Known,
                reason: "test lab child".into(),
            },
            policy: crate::policy::Policy::default(),
            signals: crate::policy::Signals {
                owner_reports_active: Some(false),
                proven_abandoned: true,
                needs_tolerance: false,
                memory_pressure: false,
                client_coverage: crate::client_tracker::Coverage::CompleteVerified,
            },
        })
        .expect("test-owned evidence approves child")
    }
    #[test]
    fn spawn_verify_registry_cleanup_and_drop() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!("reaper-lab-{}-a.json", std::process::id())),
        );
        let child = spawn(false).expect("spawn lab sleeper");
        let pid = child.id();
        let entry = child.entry.clone();
        assert!(fs::read_to_string(format!("/proc/{pid}/stat")).is_ok());
        assert_eq!(start_ticks(pid).ok(), Some(entry.start_ticks));
        // Membership is proven before cleanup; default cleanup refuses to signal.
        let registry = fs::read_to_string(registry_path()).expect("lab registry");
        assert!(registry.contains(&format!("\"pid\":{pid}")));
        drop(child); // test handle reaps only its own spawned process
        let _ = cleanup().expect("registry cleanup");
    }
    #[test]
    fn live_term_ignored_child_requires_authorized_kill() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!("reaper-lab-{}-b.json", std::process::id())),
        );
        let mut child = (0..2)
            .find_map(|_| {
                let child = spawn(true).expect("spawn SIGTERM-ignoring lab child");
                std::thread::sleep(std::time::Duration::from_millis(300));
                (start_ticks(child.id()).ok() == Some(child.entry.start_ticks)).then_some(child)
            })
            .expect("SIGTERM-ignoring lab child exited during both bounded startup attempts");
        let entry = child.entry.clone();
        let record = crate::terminate::LabRecord {
            pid: entry.pid,
            start_ticks: entry.start_ticks,
            spawned_at: entry.spawned_at,
        };
        let mut signer = crate::terminate::PidfdSignaller;
        let receipts = crate::terminate::close_sequence(
            &record,
            &crate::terminate::ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 1,
                allow_sigkill: true,
            },
            Some(&live_test_approval(entry.pid, entry.start_ticks)),
            &mut signer,
            |pid, ticks, spawned| {
                registry_contains(&Entry {
                    pid,
                    start_ticks: ticks,
                    spawned_at: spawned,
                })
                .unwrap_or(false)
                    && start_ticks(pid).ok() == Some(ticks)
            },
            std::thread::sleep,
            || "lab test outcome".into(),
        );
        assert!(
            receipts
                .iter()
                .any(|r| r.starts_with("TERM:") || r.starts_with("TERM refused:")),
            "{receipts:?}"
        );
        assert!(receipts.iter().any(|r| r.starts_with("wait:")));
        assert!(
            receipts
                .iter()
                .any(|r| r == "revalidate: registry membership and identity match"),
            "{receipts:?}"
        );
        assert!(receipts.iter().any(|r| r.starts_with("KILL:")));
        assert!(receipts.iter().any(|r| r.starts_with("confirm reap:")));
        child.wait().expect("reap killed lab child");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_ne!(start_ticks(entry.pid).ok(), Some(entry.start_ticks));
        drop(child);
        let path = registry_path();
        let entries = read_registry_at(&path).expect("read test-created registry");
        let remaining: Vec<_> = entries.into_iter().filter(|e| e.pid != entry.pid).collect();
        write_registry(&remaining, &path).expect("remove test entry");
        assert_eq!(cleanup().expect("second cleanup"), 0);
    }

    #[test]
    fn authorized_cleanup_emits_receipts_and_drops_live_registry_entry() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!("reaper-lab-{}-c.json", std::process::id())),
        );
        let mut child = spawn(false).expect("spawn lab sleeper");
        let entry = child.entry.clone();
        let receipts = crate::terminate::close_sequence(
            &crate::terminate::LabRecord {
                pid: entry.pid,
                start_ticks: entry.start_ticks,
                spawned_at: entry.spawned_at,
            },
            &crate::terminate::ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 1,
                allow_sigkill: false,
            },
            Some(&live_test_approval(entry.pid, entry.start_ticks)),
            &mut crate::terminate::PidfdSignaller,
            |pid, ticks, spawned| {
                registry_contains(&Entry {
                    pid,
                    start_ticks: ticks,
                    spawned_at: spawned,
                })
                .unwrap_or(false)
                    && start_ticks(pid).ok() == Some(ticks)
            },
            std::thread::sleep,
            || "lab cleanup test".into(),
        );
        assert!(
            receipts.iter().any(|receipt| receipt.starts_with("TERM:")),
            "{receipts:?}"
        );
        assert!(
            receipts.iter().any(|receipt| receipt.starts_with("wait:")),
            "{receipts:?}"
        );
        child.wait().expect("reap terminated child");
        let path = registry_path();
        let remaining: Vec<_> = read_registry_at(&path)
            .unwrap()
            .into_iter()
            .filter(|registered| registered.pid != entry.pid)
            .collect();
        write_registry(&remaining, &path).unwrap();
        assert!(!registry_contains(&entry).unwrap());
    }

    #[test]
    fn stale_registry_entry_is_refused_without_signals() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!("reaper-lab-{}-d.json", std::process::id())),
        );
        let child = spawn(false).expect("spawn lab sleeper");
        let mut entry = child.entry.clone();
        drop(child);
        entry.start_ticks = entry.start_ticks.wrapping_add(1);
        write_registry(&[entry.clone()], &registry_path()).unwrap();
        let record = crate::terminate::LabRecord {
            pid: entry.pid,
            start_ticks: entry.start_ticks,
            spawned_at: entry.spawned_at,
        };
        let mut executor = FakeExecutor::default();
        let receipts = crate::terminate::close_sequence(
            &record,
            &crate::terminate::ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 0,
                allow_sigkill: true,
            },
            Some(&crate::terminate::test_approval(
                entry.pid,
                entry.start_ticks,
            )),
            &mut executor,
            |pid, ticks, _| start_ticks(pid).ok() == Some(ticks),
            |_| {},
            || "stale registry test".into(),
        );
        assert!(
            receipts
                .iter()
                .any(|receipt| receipt.contains("identity failed")),
            "{receipts:?}"
        );
        assert!(executor.calls.is_empty());
    }

    #[test]
    fn default_cleanup_refuses_without_signals() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!("reaper-lab-{}-e.json", std::process::id())),
        );
        assert_eq!(cleanup().expect("default cleanup refusal"), 0);
    }

    #[test]
    fn isolated_registries_spawn_verify_and_cleanup_concurrently() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!("reaper-lab-isolated-{}", std::process::id()));
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let path = root.join(format!("registry-{index}.json"));
                std::thread::spawn(move || {
                    with_registry_path(path.clone(), || {
                        let child = spawn(false).expect("spawn isolated lab child");
                        let entry = child.entry.clone();
                        assert!(registry_contains(&entry).expect("verify isolated entry"));
                        assert_eq!(read_registry_at(&path).unwrap(), vec![entry]);
                        drop(child);
                        write_registry(&[], &path).expect("clear isolated test registry");
                        assert!(read_registry_at(&path).unwrap().is_empty());
                    })
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("isolated registry worker");
        }
    }

    #[test]
    fn shared_registry_concurrent_registration_loses_no_entries() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let path =
            std::env::temp_dir().join(format!("reaper-lab-shared-{}.json", std::process::id()));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    with_registry_path(path, || {
                        let child = spawn(false).expect("spawn shared-registry lab child");
                        let entry = child.entry.clone();
                        assert!(registry_contains(&entry).expect("verify shared entry"));
                        barrier.wait();
                        child
                    })
                })
            })
            .collect();
        barrier.wait();
        let children: Vec<_> = threads
            .into_iter()
            .map(|t| t.join().expect("shared worker"))
            .collect();
        let entries = read_registry_at(&path).expect("read shared registry");
        assert_eq!(entries.len(), 8, "registry entries: {entries:?}");
        let pids: std::collections::HashSet<_> = entries.iter().map(|entry| entry.pid).collect();
        assert_eq!(pids.len(), 8, "duplicate registry entries: {entries:?}");
        drop(children);
        with_registry_path(path.clone(), || {
            write_registry(&[], &path).expect("clear shared test registry");
        });
        assert!(read_registry_at(&path).unwrap().is_empty());
    }
}
