//! Small, real loopback service used only by Reaper's isolated lab.
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

fn log(event: &str) -> io::Result<()> {
    let line = format!("{{\"event\":\"{event}\",\"pid\":{}}}\n", std::process::id());
    io::stderr().lock().write_all(line.as_bytes())?;
    if let Some(path) = std::env::var_os("REAPER_LAB_SERVICE_JOURNAL") {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
    }
    Ok(())
}

fn recover_jobs() -> io::Result<HashMap<String, bool>> {
    let Some(path) = std::env::var_os("REAPER_LAB_SERVICE_JOURNAL") else {
        return Ok(HashMap::new());
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    let mut jobs = HashMap::new();
    for line in text.lines() {
        let Some(event) = line
            .split_once("\"event\":\"")
            .map(|(_, rest)| rest.split('"').next().unwrap_or(""))
        else {
            return Err(io::Error::other("malformed managed-service JSONL journal"));
        };
        if let Some(id) = event.strip_prefix("job_running:") {
            jobs.insert(id.to_owned(), true);
        } else if let Some(id) = event.strip_prefix("job_finished:") {
            jobs.insert(id.to_owned(), false);
        }
    }
    Ok(jobs)
}

#[derive(Default)]
struct ServiceState {
    jobs: HashMap<String, bool>,
    clients: HashMap<String, (u32, u64)>,
    known_clients: HashMap<String, (u32, u64, bool)>,
    work_observed: bool,
}
type Ledger = Arc<Mutex<ServiceState>>;

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceTransport {
    Uds,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConstructionTransportEvidence {
    transports: &'static [ServiceTransport],
}

#[cfg(unix)]
impl ConstructionTransportEvidence {
    const UDS_ONLY: Self = Self {
        transports: &[ServiceTransport::Uds],
    };

    fn is_uds_only(self) -> bool {
        self.transports == [ServiceTransport::Uds]
    }

    fn label(self) -> &'static str {
        if self.is_uds_only() {
            "uds-only"
        } else {
            "other"
        }
    }
}

fn spawn_service_process() -> io::Result<std::process::Child> {
    let executable = std::env::current_exe()?;
    let mut command = std::process::Command::new(executable);
    #[cfg(test)]
    if std::env::var_os("REAPER_TEST_SERVICE_CHILD").is_some() {
        command.args([
            "--exact",
            "managed_service::restart_tests::serve_uds_child",
            "--nocapture",
        ]);
        command.env("REAPER_TEST_SERVE_UDS", "1");
    } else {
        command.args(["managed-service", "serve-uds"]);
    }
    #[cfg(not(test))]
    command.args(["managed-service", "serve-uds"]);
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
}

fn read_service_readiness(
    child: &mut std::process::Child,
    socket: &std::path::Path,
) -> io::Result<()> {
    let output = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("restart readiness unavailable"))?;
    let mut reader = std::io::BufReader::new(output);
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err(io::Error::other("service exited before readiness"));
        }
        if line.trim() == format!("UDS {}", socket.display()) {
            return Ok(());
        }
    }
}

/// Explicit retry budget for a service registered as managed. Each successful
/// request consumes one slot; callers must sleep for the returned backoff.
#[allow(dead_code)]
pub(crate) struct RestartBudget {
    cap: u32,
    used: u32,
    base: Duration,
}

#[allow(dead_code)]
impl RestartBudget {
    pub(crate) fn new(cap: u32, base: Duration) -> Self {
        Self { cap, used: 0, base }
    }

    pub(crate) fn restart(
        &mut self,
        managed: bool,
        authorized: bool,
        restart: impl FnOnce(u32) -> io::Result<()>,
    ) -> io::Result<Duration> {
        if !managed || !authorized {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "managed restart authorization required",
            ));
        }
        if self.used >= self.cap {
            return Err(io::Error::other("managed restart retry cap reached"));
        }
        if self.used > 0 {
            let multiplier = 1u32
                .checked_shl(self.used.saturating_sub(1).min(16))
                .unwrap_or(u32::MAX);
            thread::sleep(
                self.base
                    .saturating_mul(multiplier)
                    .min(Duration::from_secs(300)),
            );
        }
        self.used += 1;
        restart(self.used)?;
        let multiplier = 1u32
            .checked_shl(self.used.saturating_sub(1).min(16))
            .unwrap_or(u32::MAX);
        Ok(self
            .base
            .saturating_mul(multiplier)
            .min(Duration::from_secs(300)))
    }

    pub(crate) fn remaining(&self) -> u32 {
        self.cap.saturating_sub(self.used)
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum RestartError {
    NotManaged,
    Unauthorized,
    AlreadyRunning,
    RefusedAtCap,
    InvalidService,
    Io(io::Error),
}

#[allow(dead_code)]
pub(crate) struct RestartedManagedService {
    pub entry: crate::lab::Entry,
    pub child: std::process::Child,
    pub backoff: Duration,
}

/// Restart only a stopped, still-registered lab UDS service. Durable operator
/// grants remain a documented residual; v0.9 has no production close authority.
#[cfg(unix)]
#[allow(dead_code)]
pub(crate) fn restart_managed_service(
    entry: &crate::lab::Entry,
    socket: &std::path::Path,
    emergency_stop_file: &std::path::Path,
    authorization: &crate::terminate::ScopedAuthorization,
    budget: &mut RestartBudget,
) -> Result<RestartedManagedService, RestartError> {
    use std::os::unix::fs::FileTypeExt;
    if budget.remaining() == 0 {
        let _ = crate::lab::persist_close_receipt(
            entry,
            &["restart refused: RefusedAtCap".into()],
            "RefusedAtCap",
        );
        return Err(RestartError::RefusedAtCap);
    }
    if crate::state::EmergencyStop::is_engaged_at(emergency_stop_file).map_err(RestartError::Io)? {
        return Err(RestartError::Unauthorized);
    }
    let registered = crate::lab::registry_contains(entry).map_err(RestartError::Io)?;
    if !registered {
        return Err(RestartError::NotManaged);
    }
    let service_id = format!("{}:{}", entry.pid, entry.start_ticks);
    let expected = crate::terminate::close_scope(
        &service_id,
        &crate::lab::registry_path_current().display().to_string(),
        "reaper-lab",
    );
    if !authorization.authorizes(&expected) {
        return Err(RestartError::Unauthorized);
    }
    let journal = std::env::var_os("REAPER_LAB_SERVICE_JOURNAL")
        .map(std::path::PathBuf::from)
        .ok_or(RestartError::InvalidService)?;
    let journal_contents = std::fs::read_to_string(journal).map_err(RestartError::Io)?;
    if !journal_contents.contains(&format!("\"event\":\"uds_started\",\"pid\":{}", entry.pid)) {
        return Err(RestartError::InvalidService);
    }
    match std::fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        _ => return Err(RestartError::InvalidService),
    }
    if start_ticks(entry.pid).ok() == Some(entry.start_ticks)
        && process_state(entry.pid).ok() != Some('Z')
    {
        return Err(RestartError::AlreadyRunning);
    }
    match std::fs::remove_file(socket) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(RestartError::Io(error)),
    }
    let mut created = None;
    let backoff = budget
        .restart(true, true, |_| {
            if crate::state::EmergencyStop::is_engaged_at(emergency_stop_file)? {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "emergency stop engaged",
                ));
            }
            let mut child = spawn_service_process()?;
            if let Err(error) = read_service_readiness(&mut child, socket) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            let next = crate::lab::current_registry()?
                .into_iter()
                .find(|candidate| candidate.pid == child.id())
                .ok_or_else(|| io::Error::other("restarted service did not register"))?;
            created = Some((child, next));
            Ok(())
        })
        .map_err(|error| {
            if error.to_string().contains("retry cap") {
                RestartError::RefusedAtCap
            } else {
                RestartError::Io(error)
            }
        })?;
    let (child, entry) =
        created.ok_or_else(|| RestartError::Io(io::Error::other("restart produced no child")))?;
    Ok(RestartedManagedService {
        entry,
        child,
        backoff,
    })
}

fn start_ticks(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("malformed proc stat"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("missing process start ticks"))?
        .parse()
        .map_err(|_| io::Error::other("invalid process start ticks"))
}

fn tcp_table_has_listener(table: &str) -> bool {
    table
        .lines()
        .skip(1)
        .any(|line| line.split_whitespace().nth(3) == Some("0A"))
}

fn tcp_listener_present() -> io::Result<bool> {
    let table = std::fs::read_to_string("/proc/self/net/tcp")
        .or_else(|_| std::fs::read_to_string("/proc/net/tcp"))?;
    Ok(tcp_table_has_listener(&table))
}

#[cfg(test)]
mod tcp_listener_tests {
    use super::*;

    #[test]
    fn construction_transport_evidence_is_uds_only() {
        let evidence = ConstructionTransportEvidence::UDS_ONLY;
        assert!(evidence.is_uds_only());
        assert_eq!(evidence.label(), "uds-only");
    }

    #[test]
    fn controlled_uds_proof_transitions_unknown_to_fresh_lab_approval() {
        use crate::client_tracker::{Coverage, CoverageProof};
        use std::time::{SystemTime, UNIX_EPOCH};

        let evidence = ConstructionTransportEvidence::UDS_ONLY;
        assert!(evidence.is_uds_only());
        let mut coverage = Coverage::Unknown;
        assert_eq!(coverage, Coverage::Unknown);
        let issued_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let proof = CoverageProof::issue_verified(
            vec!["uds".into()],
            "controlled-lab-server",
            issued_at,
            60,
            "exhaustive controlled UDS entry",
            "server- and TTL-window-scoped lab adapter",
        )
        .unwrap();
        coverage = proof.coverage_for("controlled-lab-server", issued_at);
        assert_eq!(coverage, Coverage::CompleteVerified);

        let process = crate::procfs::scan()
            .processes
            .into_iter()
            .find(|process| process.pid == std::process::id())
            .expect("test process present in procfs scan");
        let approval = crate::terminate::approve_fresh(crate::terminate::FreshApprovalInputs {
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
                reason: "controlled UDS lab".into(),
            },
            policy: crate::policy::Policy::default(),
            signals: crate::policy::Signals {
                owner_reports_active: Some(false),
                proven_abandoned: true,
                needs_tolerance: false,
                memory_pressure: false,
                client_coverage: coverage,
            },
        });
        assert!(
            approval.is_some(),
            "complete controlled UDS evidence authorizes lab approval"
        );
    }

    #[test]
    fn managed_restart_budget_enforces_cap_and_authorization() {
        let mut budget = RestartBudget::new(2, Duration::from_secs(1));
        let mut calls = 0;
        assert!(budget
            .restart(true, true, |_| {
                calls += 1;
                Ok(())
            })
            .is_ok());
        assert!(budget
            .restart(true, true, |_| {
                calls += 1;
                Ok(())
            })
            .is_ok());
        assert!(budget
            .restart(true, true, |_| {
                calls += 1;
                Ok(())
            })
            .is_err());
        assert!(budget
            .restart(false, true, |_| {
                calls += 1;
                Ok(())
            })
            .is_err());
        assert!(budget
            .restart(true, false, |_| {
                calls += 1;
                Ok(())
            })
            .is_err());
        assert_eq!(calls, 2);
    }

    #[test]
    fn tcp_listener_table_parser_detects_listen_state() {
        let table = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n   1: 0100007F:1F91 00000000:0000 01 00000000:00000000 00:00000000 00000000 1000 0 12346\n";
        assert!(tcp_table_has_listener(table));
        assert!(!tcp_table_has_listener("header\n"));
    }

    #[test]
    fn live_tcp_table_readability_matches_selected_fallback_and_listener_probe() {
        let self_net = std::fs::read_to_string("/proc/self/net/tcp");
        let proc_net = std::fs::read_to_string("/proc/net/tcp");
        let expected = self_net.as_ref().ok().or(proc_net.as_ref().ok());
        match expected {
            Some(table) => assert_eq!(
                tcp_listener_present().unwrap(),
                tcp_table_has_listener(table)
            ),
            None => assert!(tcp_listener_present().is_err()),
        }
    }

    #[test]
    fn listener_fixture_invalidates_listener_gate() {
        let listener_table = "header\n0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345\n";
        assert!(tcp_table_has_listener(listener_table));
    }
}

#[cfg(test)]
mod restart_tests {
    use super::*;

    #[test]
    fn serve_uds_child() {
        if std::env::var_os("REAPER_TEST_SERVE_UDS").is_some() {
            serve_uds().unwrap();
        }
    }

    #[test]
    fn live_restart_consumes_budget_and_rejects_non_managed_targets() {
        use std::os::unix::fs::PermissionsExt;
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let root = std::env::temp_dir().join(format!(
            "reaper-managed-restart-{}-{}",
            std::process::id(),
            crate::logx::now_secs()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let registry = root.join("lab.json");
        let socket = root.join("service.sock");
        let journal = root.join("service.jsonl");
        struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
        impl Drop for RestoreEnv {
            fn drop(&mut self) {
                for (key, value) in self.0.drain(..) {
                    if let Some(value) = value {
                        std::env::set_var(key, value);
                    } else {
                        std::env::remove_var(key);
                    }
                }
            }
        }
        let _restore = RestoreEnv(
            [
                "REAPER_TEST_SERVICE_CHILD",
                "REAPER_LAB_REGISTRY",
                "REAPER_LAB_SERVICE_SOCKET",
                "REAPER_LAB_SERVICE_JOURNAL",
            ]
            .into_iter()
            .map(|key| (key, std::env::var_os(key)))
            .collect(),
        );
        std::env::set_var("REAPER_TEST_SERVICE_CHILD", "1");
        std::env::set_var("REAPER_LAB_REGISTRY", &registry);
        std::env::set_var("REAPER_LAB_SERVICE_SOCKET", &socket);
        std::env::set_var("REAPER_LAB_SERVICE_JOURNAL", &journal);

        let spawn = || {
            let mut child = spawn_service_process().unwrap();
            read_service_readiness(&mut child, &socket).unwrap();
            child
        };
        let mut first = spawn();
        let entry = crate::lab::current_registry()
            .unwrap()
            .into_iter()
            .find(|e| e.pid == first.id())
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !std::fs::read_to_string(&journal)
            .unwrap_or_default()
            .contains(&format!("\"event\":\"uds_started\",\"pid\":{}", entry.pid))
            && std::time::Instant::now() < deadline
        {
            thread::sleep(Duration::from_millis(5));
        }
        first.kill().unwrap();
        first.wait().unwrap();
        let scope = crate::terminate::close_scope(
            &format!("{}:{}", entry.pid, entry.start_ticks),
            &registry.display().to_string(),
            "reaper-lab",
        );
        let authorization =
            crate::terminate::ScopedAuthorization::new(scope, "operator-approved".into());
        let mut budget = RestartBudget::new(1, Duration::from_secs(1));
        let stop_file = root.join("emergency-stop");
        let mut restarted =
            restart_managed_service(&entry, &socket, &stop_file, &authorization, &mut budget)
                .unwrap();
        assert_eq!(budget.remaining(), 0);
        assert_eq!(
            start_ticks(restarted.entry.pid).ok(),
            Some(restarted.entry.start_ticks)
        );
        assert!(matches!(
            restart_managed_service(
                &restarted.entry,
                &socket,
                &stop_file,
                &authorization,
                &mut budget
            ),
            Err(RestartError::RefusedAtCap)
        ));
        assert!(std::fs::read_to_string(crate::lab::receipt_path_current())
            .unwrap()
            .contains("RefusedAtCap"));
        let unmanaged = crate::lab::Entry {
            pid: u32::MAX,
            start_ticks: 1,
            spawned_at: 1,
        };
        let mut non_managed_budget = RestartBudget::new(1, Duration::from_millis(1));
        assert!(matches!(
            restart_managed_service(
                &unmanaged,
                &socket,
                &stop_file,
                &authorization,
                &mut non_managed_budget
            ),
            Err(RestartError::NotManaged)
        ));
        restarted.child.kill().unwrap();
        let _ = restarted.child.wait();
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(unix)]
fn process_state(pid: u32) -> io::Result<char> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("malformed proc stat"))?;
    stat[end + 1..]
        .split_whitespace()
        .next()
        .and_then(|state| state.chars().next())
        .ok_or_else(|| io::Error::other("missing process state"))
}

#[cfg(unix)]
fn process_uid(pid: u32) -> io::Result<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))?;
    status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| io::Error::other("process UID unavailable"))
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PeerCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
#[repr(C)]
struct IoVec {
    base: *mut std::ffi::c_void,
    len: usize,
}

#[cfg(unix)]
#[repr(C)]
struct MessageHeader {
    name: *mut std::ffi::c_void,
    name_len: u32,
    iov: *mut IoVec,
    iov_len: usize,
    control: *mut std::ffi::c_void,
    control_len: usize,
    flags: i32,
}

#[cfg(unix)]
#[repr(C)]
struct ControlHeader {
    len: usize,
    level: i32,
    kind: i32,
}

#[cfg(unix)]
#[repr(C)]
struct UCred {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[cfg(unix)]
unsafe extern "C" {
    fn setsockopt(fd: i32, level: i32, name: i32, value: *const std::ffi::c_void, len: u32) -> i32;
    fn recvmsg(fd: i32, msg: *mut MessageHeader, flags: i32) -> isize;
}

#[cfg(unix)]
fn enable_passcred(fd: i32) -> io::Result<()> {
    let enabled: i32 = 1;
    // Linux: SOL_SOCKET=1, SO_PASSCRED=16; Android exposes the same ABI.
    let result = unsafe {
        setsockopt(
            fd,
            1,
            16,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as u32,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Enable and consume Linux SCM_CREDENTIALS, never a payload-supplied identity.
#[cfg(unix)]
fn recv_peer_request(
    stream: &std::os::unix::net::UnixStream,
) -> io::Result<(String, PeerCredentials)> {
    use std::os::fd::AsRawFd;
    enable_passcred(stream.as_raw_fd())?;

    let mut data = [0u8; 4096];
    let mut control = [0usize; 8];
    let mut iov = IoVec {
        base: data.as_mut_ptr().cast(),
        len: data.len(),
    };
    let mut message = MessageHeader {
        name: std::ptr::null_mut(),
        name_len: 0,
        iov: &mut iov,
        iov_len: 1,
        control: control.as_mut_ptr().cast(),
        control_len: std::mem::size_of_val(&control),
        flags: 0,
    };
    let received = unsafe { recvmsg(stream.as_raw_fd(), &mut message, 0) };
    if received < 0 {
        return Err(io::Error::last_os_error());
    }
    let received = received as usize;
    let header_size = std::mem::size_of::<ControlHeader>();
    let aligned_header =
        header_size.div_ceil(std::mem::size_of::<usize>()) * std::mem::size_of::<usize>();
    let header = unsafe { &*(control.as_ptr().cast::<ControlHeader>()) };
    if header.level != 1
        || header.kind != 2
        || header.len < aligned_header + std::mem::size_of::<UCred>()
    {
        return Err(io::Error::other(
            "SCM_CREDENTIALS control message unavailable or malformed",
        ));
    }
    let credentials = unsafe {
        &*(control
            .as_ptr()
            .cast::<u8>()
            .add(aligned_header)
            .cast::<UCred>())
    };
    if credentials.pid <= 0 {
        return Err(io::Error::other("SCM_CREDENTIALS supplied invalid pid"));
    }
    let request = String::from_utf8_lossy(&data[..received]).into_owned();
    Ok((
        request,
        PeerCredentials {
            pid: credentials.pid as u32,
            uid: credentials.uid,
            gid: credentials.gid,
        },
    ))
}

#[cfg(unix)]
pub fn serve_uds() -> io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    let path = std::env::var_os("REAPER_LAB_SERVICE_SOCKET")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing lab UDS path"))?;
    let transport_evidence = ConstructionTransportEvidence::UDS_ONLY;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("UDS path has no parent"))?;
    let owner_uid = process_uid(std::process::id())?;
    let parent_meta = std::fs::metadata(parent)?;
    if parent_meta.uid() != owner_uid || parent_meta.permissions().mode() & 0o777 != 0o700 {
        return Err(io::Error::other(
            "lab UDS parent directory must be current-UID-owned mode 0700",
        ));
    }
    let listener = UnixListener::bind(&path)?;
    use std::os::fd::AsRawFd;
    enable_passcred(listener.as_raw_fd())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    if !std::fs::symlink_metadata(&path)?.file_type().is_socket() {
        return Err(io::Error::other("lab listener path is not a socket"));
    }
    let entry =
        crate::lab::register_managed_service(std::process::id(), start_ticks(std::process::id())?)?;
    println!("UDS {}", path.display());
    io::stdout().flush()?;
    log("uds_started")?;
    let ledger: Ledger = Arc::new(Mutex::new(ServiceState {
        jobs: recover_jobs()?,
        ..ServiceState::default()
    }));
    let mut registered: HashMap<u32, (u32, u64, String)> = HashMap::new();
    let mut all_peers_verified = true;
    for incoming in listener.incoming() {
        let stream = incoming?;
        let (request, credentials) = recv_peer_request(&stream)?;
        let fields: Vec<_> = request.split_whitespace().collect();
        let peer = registered
            .get(&credentials.pid)
            .filter(|(uid, ticks, nonce)| {
                *uid == credentials.uid
                    && start_ticks(credentials.pid).ok() == Some(*ticks)
                    && crate::client_tracker::is_lab_client_registered(
                        credentials.pid,
                        *ticks,
                        &path.display().to_string(),
                        nonce,
                    )
            });
        let response = if let ["REGISTER", nonce] = fields.as_slice() {
            let ticks = start_ticks(credentials.pid)?;
            if !crate::client_tracker::is_lab_client_registered(
                credentials.pid,
                ticks,
                &path.display().to_string(),
                nonce,
            ) {
                all_peers_verified = false;
                "REFUSED unregistered_lab_identity\n".to_owned()
            } else {
                registered.insert(credentials.pid, (credentials.uid, ticks, (*nonce).into()));
                log(&format!(
                    "uds_peer_registered:{}:{}",
                    credentials.pid, ticks
                ))?;
                format!("REGISTERED {} {}\n", credentials.pid, ticks)
            }
        } else if peer.is_none() {
            all_peers_verified = false;
            "REFUSED unregistered_peer\n".to_owned()
        } else {
            match fields.as_slice() {
                ["PING"] => format!(
                    "PEER {} {} {}\n",
                    credentials.pid, credentials.uid, credentials.gid
                ),
                ["CONNECT", nonce] => {
                    if registered
                        .get(&credentials.pid)
                        .is_some_and(|(_, _, known)| known == nonce)
                    {
                        let (_, ticks, _) = registered[&credentials.pid].clone();
                        ledger
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .clients
                            .insert((*nonce).into(), (credentials.pid, ticks));
                        {
                            let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                            state
                                .known_clients
                                .insert((*nonce).into(), (credentials.pid, ticks, true));
                            state.work_observed = true;
                        }
                        crate::client_tracker::record_lab_client(
                            credentials.pid,
                            ticks,
                            &path.display().to_string(),
                            nonce,
                            true,
                            Vec::new(),
                        )?;
                        log(&format!("uds_client_connected:{nonce}"))?;
                        format!("CONNECTED {nonce}\n")
                    } else {
                        "REFUSED client_nonce_mismatch\n".to_owned()
                    }
                }
                ["DISCONNECT", nonce] => {
                    let removed = ledger
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .clients
                        .remove(*nonce);
                    if let Some((pid, ticks)) = removed {
                        let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                        state
                            .known_clients
                            .insert((*nonce).into(), (pid, ticks, false));
                        let work: Vec<String> = state
                            .jobs
                            .iter()
                            .filter_map(|(job, running)| running.then_some(job.clone()))
                            .collect();
                        drop(state);
                        crate::client_tracker::record_lab_client(
                            pid,
                            ticks,
                            &path.display().to_string(),
                            nonce,
                            false,
                            work,
                        )?;
                        log(&format!("uds_client_disconnected:{nonce}"))?;
                    }
                    format!("DISCONNECTED {nonce} {}\n", removed.is_some())
                }
                ["START", id, millis]
                    if !id.is_empty()
                        && id
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) =>
                {
                    let duration = millis
                        .parse::<u64>()
                        .map_err(|_| io::Error::other("invalid duration"))?;
                    let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                    if state.jobs.contains_key(*id) {
                        "DUPLICATE\n".to_owned()
                    } else {
                        state.jobs.insert((*id).into(), true);
                        state.work_observed = true;
                        let clients = state.known_clients.clone();
                        drop(state);
                        log(&format!("job_accepted:{id}"))?;
                        log(&format!("job_running:{id}"))?;
                        for (nonce, (pid, ticks, connected)) in clients {
                            let jobs = ledger
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .jobs
                                .iter()
                                .filter_map(|(job, running)| running.then_some(job.clone()))
                                .collect();
                            crate::client_tracker::record_lab_client(
                                pid,
                                ticks,
                                &path.display().to_string(),
                                &nonce,
                                connected,
                                jobs,
                            )?;
                        }
                        let jobs = ledger.clone();
                        let job = (*id).to_owned();
                        let journal_job = job.clone();
                        let tracker_server = path.display().to_string();
                        thread::spawn(move || {
                            thread::sleep(Duration::from_millis(duration));
                            let mut state = jobs.lock().unwrap_or_else(|e| e.into_inner());
                            if let Some(running) = state.jobs.get_mut(&job) {
                                *running = false;
                            }
                            let clients = state.known_clients.clone();
                            let work: Vec<String> = state
                                .jobs
                                .iter()
                                .filter_map(|(job, running)| running.then_some(job.clone()))
                                .collect();
                            drop(state);
                            let _ = log(&format!("job_finished:{journal_job}"));
                            for (nonce, (pid, ticks, connected)) in clients {
                                let _ = crate::client_tracker::record_lab_client(
                                    pid,
                                    ticks,
                                    &tracker_server,
                                    &nonce,
                                    connected,
                                    work.clone(),
                                );
                            }
                        });
                        format!("ACCEPTED {id}\n")
                    }
                }
                ["STATUS", id] => match ledger
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .jobs
                    .get(*id)
                {
                    Some(true) => format!("RUNNING {id}\n"),
                    Some(false) => format!("FINISHED {id}\n"),
                    None => format!("UNKNOWN {id}\n"),
                },
                ["OBSERVE"] | ["ATTEST"] => {
                    let state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                    let active = state.clients.len();
                    let pending = state.jobs.values().filter(|running| **running).count();
                    let owner_active = active > 0 || pending > 0 || !state.work_observed;
                    let metadata = std::fs::symlink_metadata(&path)?;
                    let parent_metadata = std::fs::metadata(parent)?;
                    let secure_path = metadata.file_type().is_socket()
                        && metadata.uid() == credentials.uid
                        && metadata.permissions().mode() & 0o777 == 0o600
                        && parent_metadata.uid() == credentials.uid
                        && parent_metadata.permissions().mode() & 0o777 == 0o700;
                    let registered_valid = registered.iter().all(|(pid, (uid, ticks, nonce))| {
                        start_ticks(*pid).ok() == Some(*ticks)
                            && crate::client_tracker::is_lab_client_registered(
                                *pid,
                                *ticks,
                                &path.display().to_string(),
                                nonce,
                            )
                            && registered
                                .get(pid)
                                .is_some_and(|(peer_uid, _, _)| peer_uid == uid)
                    });
                    let tcp_disabled = match tcp_listener_present() {
                        Ok(false) => true,
                        Ok(true) => {
                            eprintln!("lab attestation downgraded: TCP LISTEN socket observed");
                            false
                        }
                        Err(error) => {
                            eprintln!("lab attestation downgraded: TCP listener tables unreadable: {error}");
                            false
                        }
                    };
                    let attested =
                        all_peers_verified && registered_valid && secure_path && tcp_disabled;
                    format!(
                        "OBSERVATION {} {} {} {} {} {} {} {}\n",
                        std::process::id(),
                        start_ticks(std::process::id())?,
                        active,
                        pending,
                        u8::from(attested),
                        u8::from(secure_path),
                        u8::from(owner_active),
                        u8::from(tcp_disabled)
                    )
                }
                ["TRANSPORT-EVIDENCE"] => {
                    format!("TRANSPORT-EVIDENCE {}\n", transport_evidence.label())
                }
                ["SHUTDOWN"] => {
                    let state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                    if !state.clients.is_empty() || state.jobs.values().any(|running| *running) {
                        "BLOCKED active_client_or_pending_work\n".to_owned()
                    } else {
                        "CLOSING\n".to_owned()
                    }
                }
                _ => "REFUSED unknown_command\n".to_owned(),
            }
        };
        let shutdown = response == "CLOSING\n";
        let mut stream = stream;
        stream.write_all(response.as_bytes())?;
        stream.shutdown(Shutdown::Both)?;
        log("uds_peer_disconnected")?;
        if shutdown {
            log("uds_official_shutdown")?;
            break;
        }
    }
    crate::lab::unregister_managed_service(&entry)?;
    std::fs::remove_file(path)?;
    log("uds_stopped")?;
    Ok(())
}

#[cfg(unix)]
pub(crate) struct LabAttestation {
    pub server_pid: u32,
    pub server_start_ticks: u64,
    pub active_clients: usize,
    pub pending_jobs: usize,
    pub owner_active: bool,
    pub coverage: crate::client_tracker::Coverage,
}

#[cfg(unix)]
fn uds_request(path: &std::path::Path, request: &str) -> io::Result<String> {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(request.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[cfg(unix)]
pub(crate) fn register_current_peer(path: &std::path::Path, nonce: &str) -> io::Result<()> {
    let pid = std::process::id();
    let ticks = start_ticks(pid)?;
    let server = path.display().to_string();
    crate::client_tracker::record_lab_client(pid, ticks, &server, nonce, false, Vec::new())?;
    let response = uds_request(path, &format!("REGISTER {nonce}\n"))?;
    if !response.starts_with(&format!("REGISTERED {pid} {ticks}")) {
        return Err(io::Error::other(format!(
            "lab peer registration refused: {response}"
        )));
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn request_registered_peer(path: &std::path::Path, request: &str) -> io::Result<String> {
    uds_request(path, request)
}

/// Return coverage only after matching the UDS server to its registered live identity.
#[cfg(unix)]
pub(crate) fn attest_lab_service(
    entry: &crate::lab::Entry,
    path: &std::path::Path,
) -> io::Result<LabAttestation> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    if !crate::lab::registry_contains(entry)?
        || start_ticks(entry.pid).ok() != Some(entry.start_ticks)
    {
        return Err(io::Error::other(
            "managed service identity is not registered/live",
        ));
    }
    let socket = std::fs::symlink_metadata(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("UDS path has no parent"))?;
    let parent_meta = std::fs::metadata(parent)?;
    let uid = std::fs::read_to_string("/proc/self/status")?
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| io::Error::other("current UID unavailable"))?;
    let path_secure = socket.file_type().is_socket()
        && socket.uid() == uid
        && socket.permissions().mode() & 0o777 == 0o600
        && parent_meta.uid() == uid
        && parent_meta.permissions().mode() & 0o777 == 0o700;
    let response = uds_request(path, "ATTEST\n")?;
    let fields: Vec<_> = response.split_whitespace().collect();
    if fields.len() != 9 || fields[0] != "OBSERVATION" {
        return Err(io::Error::other(format!(
            "invalid lab attestation response: {response}"
        )));
    }
    let server_pid = fields[1]
        .parse::<u32>()
        .map_err(|_| io::Error::other("bad attestation pid"))?;
    let server_start_ticks = fields[2]
        .parse::<u64>()
        .map_err(|_| io::Error::other("bad attestation start ticks"))?;
    if server_pid != entry.pid
        || server_start_ticks != entry.start_ticks
        || start_ticks(server_pid).ok() != Some(server_start_ticks)
    {
        return Err(io::Error::other("lab attestation server identity mismatch"));
    }
    let active_clients = fields[3]
        .parse::<usize>()
        .map_err(|_| io::Error::other("bad active-client count"))?;
    let pending_jobs = fields[4]
        .parse::<usize>()
        .map_err(|_| io::Error::other("bad pending-job count"))?;
    let peer_population_verified = fields[5] == "1";
    let server_path_secure = fields[6] == "1";
    let owner_active = fields[7] == "1";
    let tcp_disabled = fields[8] == "1";
    let tcp_disabled = match tcp_listener_present() {
        Ok(false) => tcp_disabled,
        Ok(true) => {
            eprintln!("lab attestation downgraded: TCP LISTEN socket observed at observer");
            false
        }
        Err(error) => {
            eprintln!(
                "lab attestation downgraded: observer cannot read TCP listener tables: {error}"
            );
            false
        }
    };
    let coverage = if path_secure && peer_population_verified && server_path_secure && tcp_disabled
    {
        crate::client_tracker::Coverage::CompleteVerified
    } else {
        crate::client_tracker::Coverage::Unknown
    };
    Ok(LabAttestation {
        server_pid,
        server_start_ticks,
        active_clients,
        pending_jobs,
        owner_active,
        coverage,
    })
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct RevalidationReport {
    pub identity: bool,
    pub coverage: bool,
    pub idle_work: bool,
    pub policy: bool,
    pub proven: bool,
}

#[cfg(unix)]
fn fresh_lab_approval(
    entry: &crate::lab::Entry,
    socket: &std::path::Path,
    grace_expired: bool,
) -> io::Result<(crate::terminate::FreshApproval, RevalidationReport)> {
    let scan = crate::procfs::scan();
    let process = scan
        .processes
        .iter()
        .find(|process| process.pid == entry.pid && process.start_ticks == entry.start_ticks)
        .cloned()
        .ok_or_else(|| io::Error::other("managed service missing from fresh procfs scan"))?;
    let relations = crate::relations::build(&scan.processes);
    let attestation = attest_lab_service(entry, socket)?;
    let identity = crate::lab::registry_contains(entry)?
        && crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks)
        && attestation.server_pid == entry.pid
        && attestation.server_start_ticks == entry.start_ticks;
    let coverage_ok = attestation.coverage == crate::client_tracker::Coverage::CompleteVerified;
    let idle_work = attestation.active_clients == 0
        && attestation.pending_jobs == 0
        && !attestation.owner_active;
    let work = crate::evidence::ClientWorkState::IdleVerified {
        surfaces: vec![
            "SCM_CREDENTIALS-authenticated lab client roster".into(),
            "service job ledger".into(),
        ],
    };
    let (last_client_gone, no_pending_work) = crate::evidence::client_work_to_fields(&work);
    let evidence = crate::evidence::AbandonEvidence {
        lab_member: true,
        owner: crate::owner::OwnerVerdict::Unclaimed,
        grace_expired,
        revalidated_now: grace_expired,
        owner_dead: Some(!attestation.owner_active),
        last_client_gone,
        no_pending_work,
    };
    let proven = identity && coverage_ok && idle_work && crate::evidence::proven(&evidence);
    let id = crate::identity::identify(&process, crate::identity::read_boot_id());
    let base = crate::protection::protect(&process, std::process::id(), &relations, process.uid);
    let work_activity = Some(false);
    let work_signal = crate::client_tracker::combine_signals(Some(false), work_activity);
    let signals = crate::policy::Signals {
        owner_reports_active: Some(false),
        proven_abandoned: crate::evidence::candidate_for_grace(&evidence),
        needs_tolerance: false,
        memory_pressure: false,
        client_coverage: attestation.coverage,
    };
    let positively_verified_inactive = coverage_ok && idle_work;
    let (_, protection, decision) = crate::classified_decision(
        &process,
        &id,
        &relations,
        &crate::owner::OwnerVerdict::Unclaimed,
        work_signal,
        positively_verified_inactive,
        base,
        &crate::policy::Policy::default(),
        &signals,
        &[],
    );
    let policy_ok = matches!(decision, crate::policy::Decision::GraceCandidate { .. });
    let report = RevalidationReport {
        identity,
        coverage: coverage_ok,
        idle_work,
        policy: policy_ok,
        proven,
    };
    if !report.identity || !report.coverage || !report.idle_work || !report.policy || !report.proven
    {
        let _ = crate::lab::persist_close_receipt(
            entry,
            &[format!("revalidation refused: {report:?}")],
            "fresh lab revalidation failed",
        );
        return Err(io::Error::other(format!(
            "fresh lab revalidation failed: {report:?}"
        )));
    }
    let approval = crate::terminate::approve_fresh(crate::terminate::FreshApprovalInputs {
        evidence,
        process,
        protection,
        policy: crate::policy::Policy::default(),
        signals,
    })
    .ok_or_else(|| io::Error::other("fresh managed-service policy approval failed"))?;
    Ok((approval, report))
}

#[cfg(unix)]
pub(crate) fn revalidate_for_close(
    entry: &crate::lab::Entry,
    socket: &std::path::Path,
) -> io::Result<RevalidationReport> {
    fresh_lab_approval(entry, socket, true).map(|(_, report)| report)
}

#[cfg(unix)]
pub(crate) fn close_ready_service(
    entry: &crate::lab::Entry,
    socket: &std::path::Path,
    grace_started_at: u64,
    emergency_stop_file: &std::path::Path,
) -> io::Result<Vec<String>> {
    use crate::terminate::{ClosePolicy, LabRecord, PidfdSignaller};
    if crate::state::EmergencyStop::is_engaged_at(emergency_stop_file)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "emergency stop engaged before managed close",
        ));
    }
    let authorization = crate::lab::authorization_for(
        entry,
        format!("fresh-approval:{}:{}", entry.pid, entry.start_ticks),
    );
    let requested_scope = crate::terminate::close_scope(
        &format!("{}:{}", entry.pid, entry.start_ticks),
        &crate::lab::registry_path_current().display().to_string(),
        "reaper-lab",
    );
    if !authorization.authorizes(&requested_scope) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "close authorization scope mismatch",
        ));
    }
    let (approval, report) = fresh_lab_approval(entry, socket, true)?;
    let audit = vec![
        format!(
            "identity=pid:{}:start:{}:spawned:{}",
            entry.pid, entry.start_ticks, entry.spawned_at
        ),
        format!(
            "evidence_snapshot_ref=managed-attestation:{}:{}:{}",
            entry.pid,
            entry.start_ticks,
            crate::logx::now_secs()
        ),
        "policy_id=managed-lab-close;policy_version=1".into(),
        format!(
            "authorization_scope=service:{}:{};registry:{};project:reaper-lab",
            entry.pid,
            entry.start_ticks,
            crate::lab::registry_path_current().display()
        ),
        format!(
            "fresh_approval_ref=fresh-approval:{}:{}",
            entry.pid, entry.start_ticks
        ),
        format!("grace_start=prevalidated;grace_end=expired;revalidation={report:?}"),
        "mechanism=managed-service-uds-official-shutdown+pidfd-term".into(),
    ];
    crate::lab::persist_close_receipt(entry, &audit, "in_progress")?;
    let audit_record =
        |outcome: &str, mechanism: String, errors: Vec<String>| crate::lab::CloseAuditRecord {
            identity: format!(
                "pid:{};start_ticks:{};spawned_at:{}",
                entry.pid, entry.start_ticks, entry.spawned_at
            ),
            evidence_refs: vec![
                format!("procfs-scan:{}:{}", entry.pid, entry.start_ticks),
                format!(
                    "service-attestation:{}:{}:{}",
                    entry.pid,
                    entry.start_ticks,
                    crate::logx::now_secs()
                ),
            ],
            policy_id: "managed-lab-close".into(),
            policy_version: "1".into(),
            authorization_scope: format!(
                "service={}:{};registry={};project=reaper-lab",
                entry.pid,
                entry.start_ticks,
                crate::lab::registry_path_current().display()
            ),
            approval_refs: vec![authorization.fresh_approval_ref.clone()],
            grace_started_at,
            grace_ended_at: crate::logx::now_secs(),
            revalidation_results: format!(
                "identity={};coverage={};idle_work={};policy={};proven={}",
                report.identity, report.coverage, report.idle_work, report.policy, report.proven
            ),
            mechanism,
            outcome: outcome.into(),
            errors,
            timestamp: crate::logx::now_secs(),
        };
    crate::lab::append_close_audit(
        &crate::lab::close_audit_path_current(),
        &audit_record(
            "in_progress",
            "UDS official shutdown with pidfd fallback available".into(),
            Vec::new(),
        ),
    )?;
    if crate::state::EmergencyStop::is_engaged_at(emergency_stop_file)? {
        crate::lab::append_close_audit(
            &crate::lab::close_audit_path_current(),
            &audit_record(
                "refused",
                "emergency stop prevented actuation".into(),
                vec!["emergency stop engaged".into()],
            ),
        )?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "emergency stop engaged before managed actuation",
        ));
    }
    let record = LabRecord {
        pid: entry.pid,
        start_ticks: entry.start_ticks,
        spawned_at: entry.spawned_at,
    };
    let mut signaller = PidfdSignaller;
    let receipts = crate::terminate::close_sequence(
        &record,
        &ClosePolicy {
            grace_secs: 0,
            term_wait_secs: 0,
            allow_sigkill: false,
        },
        Some(&approval),
        &mut signaller,
        |pid, ticks, spawned_at| {
            crate::lab::registry_contains(&crate::lab::Entry {
                pid,
                start_ticks: ticks,
                spawned_at,
            })
            .unwrap_or(false)
                && crate::lab::identity_ticks(pid).ok() == Some(ticks)
        },
        |_| {},
        || {
            let response = uds_request(socket, "SHUTDOWN\n")
                .unwrap_or_else(|error| format!("UDS shutdown error: {error}"));
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            while crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks)
                && process_state(entry.pid).ok() != Some('Z')
                && std::time::Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(5));
            }
            format!("managed-service endpoint {response}")
        },
    );
    if crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks)
        && process_state(entry.pid).ok() != Some('Z')
    {
        let errors = receipts.clone();
        crate::lab::append_close_audit(
            &crate::lab::close_audit_path_current(),
            &audit_record("failed", format!("close sequence: {receipts:?}"), errors),
        )?;
        crate::lab::persist_close_receipt(entry, &receipts, "official close did not stop service")?;
        return Err(io::Error::other(format!(
            "service remained after official shutdown: {receipts:?}"
        )));
    }
    if receipts
        .iter()
        .any(|receipt| receipt.starts_with("TERM:") || receipt.starts_with("KILL:"))
    {
        let errors = receipts.clone();
        crate::lab::append_close_audit(
            &crate::lab::close_audit_path_current(),
            &audit_record("failed", format!("close sequence: {receipts:?}"), errors),
        )?;
        crate::lab::persist_close_receipt(entry, &receipts, "service required signal close")?;
        return Err(io::Error::other(format!(
            "official endpoint failed before signal close: {receipts:?}"
        )));
    }
    crate::lab::append_close_audit(
        &crate::lab::close_audit_path_current(),
        &audit_record(
            "closed",
            format!("close sequence: {receipts:?}"),
            Vec::new(),
        ),
    )?;
    crate::lab::persist_close_receipt(entry, &receipts, "closed")?;
    Ok(receipts)
}

#[cfg(unix)]
pub fn client_agent(path: &std::path::Path) -> io::Result<()> {
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut command = String::new();
    loop {
        command.clear();
        if input.read_line(&mut command)? == 0 {
            break;
        }
        let response = uds_request(path, &command)?;
        output.write_all(response.as_bytes())?;
        output.flush()?;
    }
    Ok(())
}

#[cfg(unix)]
struct ManagedChild(std::process::Child);

#[cfg(unix)]
impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[cfg(unix)]
struct DemoAgent {
    child: std::process::Child,
    input: Option<std::process::ChildStdin>,
    output: std::io::BufReader<std::process::ChildStdout>,
}

#[cfg(unix)]
impl DemoAgent {
    fn spawn(path: &std::path::Path, nonce: &str) -> io::Result<Self> {
        use std::process::Stdio;
        let mut child = std::process::Command::new(std::env::current_exe()?)
            .args([
                "managed-service",
                "client-agent",
                &path.display().to_string(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("client-agent stdin unavailable"))?;
        let output = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("client-agent stdout unavailable"))?;
        let mut agent = Self {
            child,
            input: Some(input),
            output: std::io::BufReader::new(output),
        };
        let pid = agent.child.id();
        let ticks = start_ticks(pid)?;
        let server = path.display().to_string();
        crate::client_tracker::record_lab_client(pid, ticks, &server, nonce, false, Vec::new())?;
        let response = agent.request(&format!("REGISTER {nonce}"))?;
        if !response.starts_with(&format!("REGISTERED {pid} {ticks}")) {
            return Err(io::Error::other(format!(
                "test agent registration refused: {response}"
            )));
        }
        Ok(agent)
    }

    fn request(&mut self, request: &str) -> io::Result<String> {
        let input = self
            .input
            .as_mut()
            .ok_or_else(|| io::Error::other("client-agent already stopped"))?;
        writeln!(input, "{request}")?;
        input.flush()?;
        let mut response = String::new();
        self.output.read_line(&mut response)?;
        Ok(response)
    }

    fn stop(&mut self) -> io::Result<()> {
        self.input.take();
        let status = self.child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("client-agent exited {status}")))
        }
    }
}

#[cfg(unix)]
struct RestoreEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

#[cfg(unix)]
impl Drop for RestoreEnv {
    fn drop(&mut self) {
        for (key, old) in self.0.drain(..) {
            if let Some(value) = old {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

#[cfg(unix)]
fn set_demo_env(key: &'static str, value: &std::ffi::OsStr, restore: &mut RestoreEnv) {
    restore.0.push((key, std::env::var_os(key)));
    std::env::set_var(key, value);
}

#[cfg(unix)]
fn emit_step(number: usize, evidence: &str) {
    println!("STEP {number:02}: {evidence}");
}

#[cfg(unix)]
fn emit_monotonic(event: &str, origin: std::time::Instant) {
    println!("TIME {event}={:.3}s", origin.elapsed().as_secs_f64());
}

#[cfg(unix)]
fn wait_for_job(agent: &mut DemoAgent, job: &str) -> io::Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let result = agent.request(&format!("STATUS {job}"))?;
        if result.trim() == format!("FINISHED {job}") {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "lab job failed to finish",
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

/// Runs the end-to-end short-grace lifecycle against a child-owned UDS-only service.
#[cfg(unix)]
pub fn run_demo(grace_secs: u64) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::time::{SystemTime, UNIX_EPOCH};

    let monotonic_origin = std::time::Instant::now();
    let processes = crate::procfs::scan().processes;
    let sentinel = processes
        .iter()
        .find(|process| process.command.contains("/opencode"))
        .cloned()
        .ok_or_else(|| io::Error::other("no live production OpenCode sentinel available"))?;
    let root = std::env::temp_dir().join(format!(
        "reaper-v9-demo-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root)?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let socket = root.join("service.sock");
    let journal = root.join("service.jsonl");
    let lab_registry = root.join("lab.json");
    let clients_registry = root.join("clients.json");
    let mut restore = RestoreEnv(Vec::new());
    set_demo_env(
        "REAPER_LAB_REGISTRY",
        lab_registry.as_os_str(),
        &mut restore,
    );
    set_demo_env(
        "REAPER_CLIENT_REGISTRY",
        clients_registry.as_os_str(),
        &mut restore,
    );
    set_demo_env(
        "REAPER_LAB_SERVICE_JOURNAL",
        journal.as_os_str(),
        &mut restore,
    );
    set_demo_env(
        "REAPER_LAB_SERVICE_SOCKET",
        socket.as_os_str(),
        &mut restore,
    );

    let mut service = ManagedChild(
        std::process::Command::new(std::env::current_exe()?)
            .args(["managed-service", "serve-uds"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?,
    );
    let stdout = service
        .0
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("service readiness pipe unavailable"))?;
    let mut readiness = std::io::BufReader::new(stdout);
    let mut line = String::new();
    readiness.read_line(&mut line)?;
    if line.trim() != format!("UDS {}", socket.display()) {
        return Err(io::Error::other(format!(
            "unexpected service readiness: {line:?}"
        )));
    }
    let entry = crate::lab::current_registry()?
        .into_iter()
        .find(|entry| entry.pid == service.0.id())
        .ok_or_else(|| io::Error::other("managed service did not register its identity"))?;
    if crate::lab::identity_ticks(entry.pid).ok() != Some(entry.start_ticks) {
        return Err(io::Error::other("service process identity did not verify"));
    }
    set_demo_env(
        "REAPER_LAB_OBSERVER_TARGET",
        entry.pid.to_string().as_ref(),
        &mut restore,
    );
    emit_step(
        1,
        &format!(
            "procfs discovered lab service pid={} start={}",
            entry.pid, entry.start_ticks
        ),
    );

    register_current_peer(&socket, &format!("observer-{}", std::process::id()))?;
    let boot = crate::identity::read_boot_id();
    let state_file = root.join("observer.state");
    let mut observer = crate::Observer {
        tracker: crate::events::Tracker::new(boot.clone()),
        supervisor: crate::state::Supervisor::new(state_file),
        policy: crate::policy::Policy {
            grace_known_secs: grace_secs,
            ..crate::policy::Policy::default()
        },
        log_cfg: crate::logx::LogConfig::new(root.join("logs")),
        boot_id: boot,
        usage_start: crate::stats::self_usage(),
        deep_scheduler: crate::pilot::DeepScheduler::default(),
        context_snapshot: std::collections::HashMap::new(),
        owner_snapshot: std::collections::HashMap::new(),
        emergency_stop_file: root.join("emergency-stop"),
        startup_fault: None,
    };
    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::Observing) {
        return Err(io::Error::other(
            "initial observer cycle did not protect active service",
        ));
    }
    emit_step(
        2,
        "observer cycle identified registered service owner and protected it",
    );

    let mut client = DemoAgent::spawn(&socket, "client-a")?;
    let connected = client.request("CONNECT client-a")?;
    if connected != "CONNECTED client-a\n" {
        return Err(io::Error::other(format!(
            "test client connect failed: {connected}"
        )));
    }
    emit_step(3, "spawned test client connected with kernel credentials");
    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::Observing) {
        return Err(io::Error::other(
            "observer did not protect active client service",
        ));
    }
    emit_step(4, "observer policy decision kept active service protected");

    let started = client.request("START job-live 2500")?;
    if started != "ACCEPTED job-live\n" {
        return Err(io::Error::other(format!("job was not accepted: {started}")));
    }
    emit_step(5, "service accepted and started live job");
    let disconnected = client.request("DISCONNECT client-a")?;
    if disconnected != "DISCONNECTED client-a true\n" {
        return Err(io::Error::other(format!(
            "client disconnect not observed: {disconnected}"
        )));
    }
    emit_step(6, "test client disconnected");
    if client.request("STATUS job-live")?.trim() != "RUNNING job-live" {
        return Err(io::Error::other("job did not survive disconnect"));
    }
    emit_step(7, "job remains running after disconnect");
    observer.cycle()?;
    if crate::lab::identity_ticks(entry.pid).ok() != Some(entry.start_ticks)
        || request_registered_peer(&socket, "SHUTDOWN\n")?.trim()
            != "BLOCKED active_client_or_pending_work"
    {
        return Err(io::Error::other(
            "pending job was not protected from shutdown",
        ));
    }
    emit_step(
        8,
        "observer kept pending-work service alive; shutdown returned BLOCKED",
    );

    wait_for_job(&mut client, "job-live")?;
    emit_step(9, "service job ledger recorded completion");
    let before_grace = attest_lab_service(&entry, &socket)?;
    let evidence = crate::evidence::AbandonEvidence {
        lab_member: true,
        owner: crate::owner::OwnerVerdict::Unclaimed,
        grace_expired: false,
        revalidated_now: false,
        owner_dead: Some(!before_grace.owner_active),
        last_client_gone: Some(before_grace.active_clients == 0),
        no_pending_work: Some(before_grace.pending_jobs == 0),
    };
    if evidence.last_client_gone != Some(true)
        || evidence.no_pending_work != Some(true)
        || !crate::evidence::candidate_for_grace(&evidence)
        || crate::evidence::proven(&evidence)
    {
        return Err(io::Error::other(
            "live last-gone evidence did not match expected pre-grace grade",
        ));
    }
    emit_step(
        10,
        "live client/work evidence fields true; candidate grade true before elapsed-grace proof",
    );

    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::Candidate) {
        return Err(io::Error::other("policy did not enter candidate state"));
    }
    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::GracePeriod) {
        return Err(io::Error::other("first full short grace did not start"));
    }
    if observer
        .supervisor
        .grace_expired(entry.pid, crate::logx::now_secs())
    {
        return Err(io::Error::other("first short grace expired immediately"));
    }
    let first_grace_started = std::time::Instant::now();
    emit_monotonic("grace1_start", monotonic_origin);
    emit_step(
        11,
        &format!("observer armed first full {grace_secs}s grace"),
    );
    thread::sleep(Duration::from_secs(grace_secs));

    if client.request("CONNECT client-a")?.trim() != "CONNECTED client-a" {
        return Err(io::Error::other("live reconnect failed"));
    }
    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::Observing) {
        return Err(io::Error::other("live reconnect did not cancel grace"));
    }
    if first_grace_started.elapsed() < Duration::from_secs(grace_secs) {
        return Err(io::Error::other(
            "first grace elapsed less than requested wall time",
        ));
    }
    emit_monotonic("reconnect_cancel", monotonic_origin);
    emit_step(
        12,
        "real authenticated reconnect cancelled grace in observer cycle",
    );
    if client.request("DISCONNECT client-a")?.trim() != "DISCONNECTED client-a true" {
        return Err(io::Error::other("second disconnect not observed"));
    }
    emit_step(13, "same real client disconnected again");

    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::Candidate) {
        return Err(io::Error::other("second idle candidate not observed"));
    }
    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::GracePeriod)
        || observer
            .supervisor
            .grace_expired(entry.pid, crate::logx::now_secs())
    {
        return Err(io::Error::other(format!(
            "second full grace was not freshly armed: state={:?} expired={} now={} grace_secs={grace_secs}",
            observer.supervisor.state_of(entry.pid),
            observer.supervisor.grace_expired(entry.pid, crate::logx::now_secs()),
            crate::logx::now_secs(),
        )));
    }
    let second_grace_started = std::time::Instant::now();
    emit_monotonic("grace2_start", monotonic_origin);
    emit_step(
        14,
        &format!("observer armed a fresh full {grace_secs}s grace after cancellation"),
    );

    thread::sleep(Duration::from_secs(grace_secs));
    if second_grace_started.elapsed() < Duration::from_secs(grace_secs) {
        return Err(io::Error::other(
            "second grace wall duration was shorter than requested",
        ));
    }
    emit_monotonic("grace2_expiry", monotonic_origin);
    observer.cycle()?;
    if observer.supervisor.state_of(entry.pid) != Some(crate::state::State::ReadyForRevalidation) {
        return Err(io::Error::other(
            "second grace did not reach fresh revalidation",
        ));
    }
    let revalidated = revalidate_for_close(&entry, &socket)?;
    if !(revalidated.identity
        && revalidated.coverage
        && revalidated.idle_work
        && revalidated.policy
        && revalidated.proven)
    {
        return Err(io::Error::other(format!(
            "four-input close revalidation failed: {revalidated:?}"
        )));
    }
    emit_step(
        15,
        &format!("fresh identity+coverage+work+policy+proven gate passed: {revalidated:?}"),
    );

    observer.cycle()?;
    let status = service.0.wait()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "demo service exited unsuccessfully: {status}"
        )));
    }
    if crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks) {
        return Err(io::Error::other(
            "observer-driven official close did not reap demo service",
        ));
    }
    emit_monotonic("official_close", monotonic_origin);
    emit_step(
        16,
        "observer authorized service-owned official shutdown endpoint",
    );
    emit_step(17, "service identity absent and child process reaped");

    client.stop()?;
    let journal_text = std::fs::read_to_string(&journal)?;
    if !journal_text.contains("job_finished:job-live")
        || !journal_text.contains("uds_official_shutdown")
    {
        return Err(io::Error::other(
            "audit journal missed job finish or official shutdown",
        ));
    }
    let usage = crate::stats::self_usage();
    let log_bytes = std::fs::read_dir(root.join("logs"))?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .map(|metadata| metadata.len())
        .sum::<u64>();
    emit_step(
        18,
        &format!("JSONL verified; observer_log_bytes={log_bytes}; self_usage={usage:?}"),
    );

    let sentinel_after = crate::procfs::scan()
        .processes
        .into_iter()
        .find(|process| process.pid == sentinel.pid);
    if !sentinel_after.is_some_and(|process| {
        crate::identity::verify(
            &crate::identity::identify(&sentinel, crate::identity::read_boot_id()),
            &process,
        ) && process.command == sentinel.command
    }) {
        return Err(io::Error::other(
            "production OpenCode sentinel identity changed",
        ));
    }
    Ok(())
}

fn serve_client(
    stream: TcpStream,
    ledger: Ledger,
    stop: Arc<AtomicBool>,
    server: String,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut stream = reader.into_inner();
    let fields: Vec<_> = request.split_whitespace().collect();
    let response = match fields.as_slice() {
        ["PING"] => "PONG\n".to_owned(),
        ["IDENTITY"] => format!(
            "SERVICE {} {} {}\n",
            std::process::id(),
            start_ticks(std::process::id())?,
            std::env::current_exe()?.display()
        ),
        ["START", id, millis]
            if !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) =>
        {
            let duration = millis
                .parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid job duration"))?;
            let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
            if state.jobs.contains_key(*id) {
                "DUPLICATE\n".to_owned()
            } else {
                state.jobs.insert((*id).to_owned(), true);
                drop(state);
                log(&format!("job_accepted:{id}"))?;
                log(&format!("job_running:{id}"))?;
                let current = ledger.lock().unwrap_or_else(|e| e.into_inner());
                for (client, (pid, ticks)) in &current.clients {
                    crate::client_tracker::record_lab_client(
                        *pid,
                        *ticks,
                        &server,
                        client,
                        true,
                        vec![(*id).to_owned()],
                    )?;
                }
                drop(current);
                let jobs = ledger.clone();
                let id = (*id).to_owned();
                let response_id = id.clone();
                let tracker_ledger = ledger.clone();
                let tracker_server = server.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(duration));
                    if let Some(running) = jobs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .jobs
                        .get_mut(&id)
                    {
                        *running = false;
                    }
                    let _ = log(&format!("job_finished:{id}"));
                    let state = tracker_ledger.lock().unwrap_or_else(|e| e.into_inner());
                    let clients = state.known_clients.clone();
                    let work: Vec<String> = state
                        .jobs
                        .iter()
                        .filter_map(|(job, running)| running.then_some(job.clone()))
                        .collect();
                    drop(state);
                    for (client, (pid, ticks, connected)) in clients {
                        let _ = crate::client_tracker::record_lab_client(
                            pid,
                            ticks,
                            &tracker_server,
                            &client,
                            connected,
                            work.clone(),
                        );
                    }
                });
                format!("ACCEPTED {response_id}\n")
            }
        }
        ["STATUS", id] => match ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .jobs
            .get(*id)
        {
            Some(true) => format!("RUNNING {id}\n"),
            Some(false) => format!("FINISHED {id}\n"),
            None => format!("UNKNOWN {id}\n"),
        },
        ["CONNECT", id, pid, ticks] => {
            let pid = pid
                .parse::<u32>()
                .map_err(|_| io::Error::other("invalid client pid"))?;
            let ticks = ticks
                .parse::<u64>()
                .map_err(|_| io::Error::other("invalid client start ticks"))?;
            if start_ticks(pid).ok() != Some(ticks) {
                "REFUSED stale_client_identity\n".to_owned()
            } else {
                ledger
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clients
                    .insert((*id).into(), (pid, ticks));
                ledger
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .known_clients
                    .insert((*id).into(), (pid, ticks, true));
                crate::client_tracker::record_lab_client(
                    pid,
                    ticks,
                    &server,
                    id,
                    true,
                    Vec::new(),
                )?;
                log(&format!("client_registered:{id}:{pid}:{ticks}"))?;
                format!("CONNECTED {id}\n")
            }
        }
        ["DISCONNECT", id] => {
            let removed = ledger
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clients
                .remove(*id);
            if let Some((pid, ticks)) = removed {
                let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                state
                    .known_clients
                    .insert((*id).into(), (pid, ticks, false));
                let work: Vec<String> = state
                    .jobs
                    .iter()
                    .filter_map(|(job, running)| running.then_some(job.clone()))
                    .collect();
                drop(state);
                crate::client_tracker::record_lab_client(pid, ticks, &server, id, false, work)?;
                log(&format!("client_ended:{id}"))?;
            }
            format!("DISCONNECTED {id} {}\n", removed.is_some())
        }
        ["CLIENTS"] => format!(
            "CLIENTS {}\n",
            ledger
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clients
                .len()
        ),
        ["SHUTDOWN"] => {
            let state = ledger.lock().unwrap_or_else(|e| e.into_inner());
            if state.jobs.values().any(|running| *running) || !state.clients.is_empty() {
                "BLOCKED active_client_or_pending_work\n".to_owned()
            } else {
                drop(state);
                log("official_shutdown")?;
                stop.store(true, Ordering::Release);
                "CLOSING\n".to_owned()
            }
        }
        _ => "ERROR\n".to_owned(),
    };
    stream.write_all(response.as_bytes())?;
    stream.shutdown(Shutdown::Both)?;
    log("client_disconnected")
}

pub fn serve() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?.to_string();
    println!("{address}");
    io::stdout().flush()?;
    log("started")?;
    let entry =
        crate::lab::register_managed_service(std::process::id(), start_ticks(std::process::id())?)?;
    let ledger: Ledger = Arc::new(Mutex::new(ServiceState {
        jobs: recover_jobs()?,
        ..ServiceState::default()
    }));
    let stop = Arc::new(AtomicBool::new(false));
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                log("client_connected")?;
                let ledger = ledger.clone();
                let stop = stop.clone();
                let server = address.clone();
                thread::spawn(move || {
                    let _ = serve_client(stream, ledger, stop, server);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    log("stopped")?;
    crate::lab::unregister_managed_service(&entry)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod fresh_close_refusal_tests {
    use super::*;

    #[test]
    fn missing_fresh_scan_target_is_explicitly_refused() {
        let entry = crate::lab::Entry {
            pid: u32::MAX,
            start_ticks: 1,
            spawned_at: 0,
        };

        let error = fresh_lab_approval(&entry, std::path::Path::new("unused.sock"), true)
            .expect_err("an absent fresh-scan target must not be approved");

        assert!(error.to_string().contains("missing from fresh procfs scan"));
    }
}
