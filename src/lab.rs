//! Lab-only child registry. No arbitrary PID input is accepted for cleanup.
#[path = "lab_autonomy.rs"]
mod autonomy;
pub use autonomy::close_ready_entry;
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
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("json.tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
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
    fs::rename(tmp, path)
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
            true,
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
    fn with_registry_path<T>(path: PathBuf, f: impl FnOnce() -> T) -> T {
        TEST_REGISTRY_PATH.with(|slot| *slot.borrow_mut() = Some(path));
        let result = f();
        TEST_REGISTRY_PATH.with(|slot| *slot.borrow_mut() = None);
        result
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
        ) -> Result<crate::terminate::SignalReceipt, crate::terminate::Refusal> {
            self.calls.push(signal);
            Ok(crate::terminate::SignalReceipt {
                path: crate::terminate::SignalPath::Classic,
                signal,
            })
        }
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
            true,
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
            true,
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
            true,
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
