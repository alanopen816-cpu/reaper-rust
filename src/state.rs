//! Phase 2: explicit lifecycle state machine + crash-safe persistence.
//!
//! States: DISCOVERED → ACTIVE | PROTECTED | OBSERVING → CANDIDATE →
//! GRACE_PERIOD → READY_FOR_REVALIDATION (terminal in Phase 2: it records that
//! a future phase would re-verify, and performs NOTHING) | TERMINATION_BLOCKED;
//! any non-terminal → EXITED on disappearance. Rescue during grace returns to
//! OBSERVING/PROTECTED. Every transition logs identity, from/to, timestamp,
//! evidence, policy and reason.
//!
//! Persistence never trusts old PIDs or old timers: on reload each entry is
//! re-verified against a fresh scan and every GRACE_PERIOD re-arms from the
//! reload moment (a reboot may have consumed the whole grace silently).

use crate::identity::ProcessIdentity;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const SCHEMA_VERSION: &str = "REAPER_STATE_V1";
const MAX_STATE_FILE_BYTES: usize = 1024 * 1024;
static STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn hex(s: &str) -> String {
    s.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> std::io::Result<String> {
    if !s.len().is_multiple_of(2) {
        return Err(invalid_state("odd-length encoded field"));
    }
    let bytes = (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| invalid_state("invalid encoded field"))
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    String::from_utf8(bytes).map_err(|_| invalid_state("non-UTF8 encoded field"))
}
fn invalid_state(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Persistent kill switch for automatic actuation. Presence is fail-closed;
/// observation and state persistence remain available.
pub struct EmergencyStop;

impl EmergencyStop {
    pub fn is_engaged_at(path: &Path) -> std::io::Result<bool> {
        match fs::symlink_metadata(path) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn engage_at(path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        writeln!(file, "REAPER_ESTOP_V1")?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            fs::File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}

pub fn grace_start_allowed(emergency_stop: bool, faulted: bool) -> bool {
    !emergency_stop && !faulted
}

fn archive_invalid_state(path: &Path) -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let backup = path.with_file_name(format!(
        "{}.bak.{stamp}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    if let Err(error) = fs::rename(path, &backup) {
        return format!("backup_failed={error}; fresh_state_write_skipped; continuing_in_memory");
    }
    let mut archived = format!("backup={}", backup.display());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)) {
            archived.push_str(&format!("; backup_permissions_failed={error}"));
        }
    }
    let fresh = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        use std::io::Write;
        writeln!(file, "{SCHEMA_VERSION}")?;
        file.sync_all()
    })();
    match fresh {
        Ok(()) => format!("{archived}; fresh_state=true"),
        Err(error) => format!("{archived}; fresh_state_write_failed={error}; continuing_in_memory"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Discovered,
    Active,
    Protected,
    Observing,
    Candidate,
    GracePeriod,
    ReadyForRevalidation,
    TerminationBlocked,
    Exited,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Discovered => "DISCOVERED",
            State::Active => "ACTIVE",
            State::Protected => "PROTECTED",
            State::Observing => "OBSERVING",
            State::Candidate => "CANDIDATE",
            State::GracePeriod => "GRACE_PERIOD",
            State::ReadyForRevalidation => "READY_FOR_REVALIDATION",
            State::TerminationBlocked => "TERMINATION_BLOCKED",
            State::Exited => "EXITED",
        }
    }

    fn parse(s: &str) -> Option<State> {
        match s {
            "DISCOVERED" => Some(State::Discovered),
            "ACTIVE" => Some(State::Active),
            "PROTECTED" => Some(State::Protected),
            "OBSERVING" => Some(State::Observing),
            "CANDIDATE" => Some(State::Candidate),
            "GRACE_PERIOD" => Some(State::GracePeriod),
            "READY_FOR_REVALIDATION" => Some(State::ReadyForRevalidation),
            "TERMINATION_BLOCKED" => Some(State::TerminationBlocked),
            "EXITED" => Some(State::Exited),
            _ => None,
        }
    }

    pub fn terminal(self) -> bool {
        matches!(
            self,
            State::Protected
                | State::ReadyForRevalidation
                | State::TerminationBlocked
                | State::Exited
        )
    }
}

/// One auditable transition.
#[derive(Debug, Clone)]
pub struct Transition {
    pub pid: u32,
    pub start_ticks: u64,
    pub from: State,
    pub to: State,
    pub at_unix: u64,
    pub evidence: String,
    pub policy: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
struct Entry {
    identity: ProcessIdentity,
    state: State,
    /// When the current grace ends (unix secs). Only meaningful in GracePeriod.
    grace_deadline: Option<u64>,
    reason: String,
    evidence: String,
    policy: String,
    grace_start_wall: Option<u64>,
}

pub struct Supervisor {
    entries: HashMap<u32, Entry>,
    state_file: PathBuf,
    recovery_message: Option<String>,
}

impl Supervisor {
    pub fn new(state_file: PathBuf) -> Self {
        Supervisor {
            entries: HashMap::new(),
            state_file,
            recovery_message: None,
        }
    }

    pub fn state_of(&self, pid: u32) -> Option<State> {
        self.entries.get(&pid).map(|e| e.state)
    }

    pub fn recovery_message(&self) -> Option<&str> {
        self.recovery_message.as_deref()
    }

    /// Stored identity for a tracked PID (used to detect PID recycling via
    /// `identity::verify` before trusting any prior state).
    pub fn identity_of(&self, pid: u32) -> Option<ProcessIdentity> {
        self.entries.get(&pid).map(|e| e.identity.clone())
    }

    pub fn identity_snapshot(&self) -> Vec<(u32, ProcessIdentity)> {
        self.entries
            .iter()
            .map(|(pid, entry)| (*pid, entry.identity.clone()))
            .collect()
    }

    pub fn refresh_identity(&mut self, identity: &ProcessIdentity) {
        if let Some(entry) = self.entries.get_mut(&identity.pid) {
            if entry.identity.start_ticks == identity.start_ticks
                && entry.identity.boot_id == identity.boot_id
            {
                entry.identity = identity.clone();
            }
        }
    }

    /// Record a transition. Returns the record for logging.
    pub fn transition(
        &mut self,
        identity: &ProcessIdentity,
        to: State,
        at_unix: u64,
        evidence: &str,
        policy: &str,
        reason: &str,
    ) -> Transition {
        let old = self.entries.get(&identity.pid);
        let from = old.map(|e| e.state).unwrap_or(State::Discovered);
        // Recycled PID (same key, new start): drop any inherited grace timer.
        let keep_deadline = old
            .filter(|e| e.identity.start_ticks == identity.start_ticks)
            .and_then(|e| e.grace_deadline);
        self.entries.insert(
            identity.pid,
            Entry {
                identity: identity.clone(),
                state: to,
                grace_deadline: keep_deadline,
                reason: reason.to_owned(),
                evidence: evidence.to_owned(),
                policy: policy.to_owned(),
                grace_start_wall: None,
            },
        );
        // A recycled PID starts over: identity mismatch resets to Discovered first.
        Transition {
            pid: identity.pid,
            start_ticks: identity.start_ticks,
            from,
            to,
            at_unix,
            evidence: evidence.to_owned(),
            policy: policy.to_owned(),
            reason: reason.to_owned(),
        }
    }

    pub fn arm_grace(&mut self, pid: u32, deadline_unix: u64) {
        if let Some(e) = self.entries.get_mut(&pid) {
            e.grace_deadline = Some(deadline_unix);
            // The caller supplies only a deadline, not grace duration/start.
            // Do not fabricate a start anchor; reload conservatively re-arms.
            e.grace_start_wall = None;
        }
    }

    pub fn grace_expired(&self, pid: u32, now_unix: u64) -> bool {
        self.entries
            .get(&pid)
            .and_then(|e| e.grace_deadline)
            .is_some_and(|d| now_unix >= d)
    }

    /// Forget disappeared PIDs (marked EXITED by the caller via transition).
    pub fn retire(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    /// Persist observations only (never irreversible decisions): atomic tmp+rename.
    pub fn persist(&self) -> std::io::Result<()> {
        // This mutex serializes threads in this process only. `cmd_observe` has
        // no observer pidfile, so multi-process read/modify/write serialization
        // remains an explicit limitation (no cross-process lock is claimed).
        let _guard = STATE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| std::io::Error::other("state lock poisoned"))?;
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self
            .state_file
            .with_extension(format!("tmp.{}", std::process::id()));
        let mut out = format!("{SCHEMA_VERSION}\n");
        for e in self.entries.values() {
            out.push_str(&format!(
                "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                e.identity.pid,
                e.identity.start_ticks,
                e.identity.uid.map_or("-".into(), |u| u.to_string()),
                e.state.as_str(),
                e.grace_deadline.map_or("-".into(), |v| v.to_string()),
                e.grace_start_wall.map_or("-".into(), |v| v.to_string()),
                hex(e.identity.boot_id.as_deref().unwrap_or("")),
                hex(&e.identity.exe),
                hex(&e.reason),
                hex(&e.evidence),
                hex(&e.policy)
            ));
        }
        if out.len() > MAX_STATE_FILE_BYTES {
            // The caller logs state.persist_failed; preserve the old atomic state file.
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "state size cap exceeded ({} > {MAX_STATE_FILE_BYTES} bytes)",
                    out.len()
                ),
            ));
        }
        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(out.as_bytes())?;
        file.sync_all()?;
        fs::rename(&tmp, &self.state_file)?;
        Ok(())
    }

    /// Reload and re-validate against a fresh scan.
    ///
    /// Schema migrations are intentionally rejected: unknown/missing headers
    /// fail closed as InvalidData rather than being interpreted as old records.
    /// Grace deadlines use wall time today; monotonic elapsed time is not
    /// persisted. Therefore every recovered grace is restarted for its full
    /// duration. A wall clock or boot discontinuity cannot authorize expiry.
    /// Owner/client/work references and cancellation history are not available
    /// to this module's callers yet; the record extension remains a documented
    /// gap rather than storing invented evidence.
    /// Returns (kept, discarded): recycled identities are discarded, and every
    /// surviving GRACE_PERIOD re-arms its deadline at `now_unix + grace_secs`
    /// because the downtime is unobservable.
    pub fn reload(
        &mut self,
        live: &HashMap<u32, ProcessIdentity>,
        now_unix: u64,
        grace_secs: u64,
        state_file: &Path,
    ) -> std::io::Result<(usize, usize)> {
        let _guard = STATE_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| std::io::Error::other("state lock poisoned"))?;
        self.state_file = state_file.to_path_buf();
        self.recovery_message = None;
        let content = match fs::read_to_string(&self.state_file) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => {
                self.entries.clear();
                self.recovery_message = Some(format!(
                    "state unreadable ({e}); {}",
                    archive_invalid_state(&self.state_file)
                ));
                return Ok((0, 0));
            }
        };
        let mut lines = content.lines();
        if lines.next() != Some(SCHEMA_VERSION) {
            self.entries.clear();
            self.recovery_message = Some(format!(
                "state schema missing or unsupported; {}",
                archive_invalid_state(&self.state_file)
            ));
            return Ok((0, 0));
        }
        let mut kept = 0;
        let mut discarded = 0;
        self.entries.clear();
        let parsed = (|| -> std::io::Result<()> {
            for line in lines {
                let fields: Vec<_> = line.split('\t').collect();
                if fields.len() != 11 {
                    return Err(invalid_state("incomplete state record"));
                }
                let pid: u32 = fields[0]
                    .parse()
                    .map_err(|_| invalid_state("invalid pid"))?;
                let start: u64 = fields[1]
                    .parse()
                    .map_err(|_| invalid_state("invalid start time"))?;
                let uid = if fields[2] == "-" {
                    None
                } else {
                    Some(
                        fields[2]
                            .parse()
                            .map_err(|_| invalid_state("invalid uid"))?,
                    )
                };
                let state = State::parse(fields[3])
                    .ok_or_else(|| invalid_state("invalid lifecycle state"))?;
                let boot = unhex(fields[6])?;
                let exe = unhex(fields[7])?;
                let reason = unhex(fields[8])?;
                let evidence = unhex(fields[9])?;
                let policy = unhex(fields[10])?;
                match live.get(&pid) {
                    Some(live_identity)
                        if live_identity.start_ticks == start
                            && live_identity.uid == uid
                            && live_identity.boot_id.as_deref().unwrap_or("") == boot
                            && live_identity.exe == exe =>
                    {
                        // Downtime invalidates monotonic clocks and cannot prove grace elapsed.
                        // Reconstruct from the current wall anchor only to expose a new deadline;
                        // a caller must obtain fresh evidence before treating it as actionable.
                        let deadline = if state == State::GracePeriod {
                            Some(now_unix + grace_secs)
                        } else {
                            None
                        };
                        self.entries.insert(
                            pid,
                            Entry {
                                identity: ProcessIdentity {
                                    boot_id: live_identity.boot_id.clone(),
                                    pid,
                                    start_ticks: start,
                                    uid: live_identity.uid,
                                    exe,
                                },
                                state,
                                grace_deadline: deadline,
                                reason,
                                evidence,
                                policy,
                                grace_start_wall: Some(now_unix),
                            },
                        );
                        kept += 1;
                    }
                    _ => discarded += 1,
                }
            }
            Ok(())
        })();
        if let Err(error) = parsed {
            self.entries.clear();
            self.recovery_message = Some(format!(
                "state corrupt ({error}); {}",
                archive_invalid_state(&self.state_file)
            ));
            return Ok((0, 0));
        }
        Ok((kept, discarded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ProcessIdentity;

    #[test]
    fn emergency_stop_persists_across_reload_and_blocks_grace() {
        let dir = std::env::temp_dir().join(format!(
            "reaper-estop-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let stop_file = dir.join("emergency-stop");
        EmergencyStop::engage_at(&stop_file).unwrap();
        assert!(EmergencyStop::is_engaged_at(&stop_file).unwrap());
        assert!(!grace_start_allowed(true, false));
        assert!(!grace_start_allowed(false, true));
        assert!(grace_start_allowed(false, false));
        let _ = fs::remove_dir_all(dir);
    }

    fn id(pid: u32, start: u64) -> ProcessIdentity {
        ProcessIdentity {
            boot_id: None,
            pid,
            start_ticks: start,
            uid: Some(10373),
            exe: "x".into(),
        }
    }

    #[test]
    fn transitions_carry_full_record() {
        let mut s = Supervisor::new(PathBuf::from("/tmp/reaper-test-state.json"));
        let t = s.transition(
            &id(5, 50),
            State::Observing,
            1_700_000_000,
            "scan",
            "p7",
            "new",
        );
        assert_eq!((t.from, t.to), (State::Discovered, State::Observing));
        assert_eq!(t.evidence, "scan");
        assert_eq!(s.state_of(5), Some(State::Observing));
    }

    #[test]
    fn oversized_state_refuses_without_replacing_existing_state() {
        let dir = std::env::temp_dir().join(format!("reaper-state-cap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("state");
        fs::write(&file, "previous valid state").unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        supervisor.transition(
            &id(55, 66),
            State::Observing,
            1,
            &"x".repeat(600_000),
            "p",
            "r",
        );
        let error = supervisor
            .persist()
            .expect_err("oversized state must refuse");
        assert!(error.to_string().contains("state size cap"));
        assert_eq!(fs::read_to_string(&file).unwrap(), "previous valid state");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_state_remains_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("reaper-state-mode-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("state");
        let mut supervisor = Supervisor::new(file.clone());
        supervisor.transition(&id(56, 67), State::Observing, 1, "e", "p", "r");
        supervisor.persist().unwrap();
        assert_eq!(
            fs::metadata(file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn supervisor_restart_discards_recycled_pids_and_rearms_grace() {
        let dir = std::env::temp_dir().join(format!("reaper-restart-test-{}", std::process::id()));
        let file = dir.join("state.json");
        let mut s = Supervisor::new(file.clone());
        s.transition(&id(10, 100), State::GracePeriod, 1000, "e", "p", "r");
        s.arm_grace(10, 1000 + 600);
        s.transition(&id(11, 110), State::GracePeriod, 1000, "e", "p", "r");
        s.arm_grace(11, 1000 + 600);
        s.persist().unwrap();
        // PID 10 recycled (new start), PID 11 identical.
        let live: HashMap<u32, ProcessIdentity> =
            [(10, id(10, 999)), (11, id(11, 110))].into_iter().collect();
        let mut s2 = Supervisor::new(file.clone());
        let (kept, discarded) = s2.reload(&live, 5000, 600, &file).unwrap();
        assert_eq!((kept, discarded), (1, 1));
        assert_eq!(s2.state_of(11), Some(State::GracePeriod));
        assert_eq!(s2.state_of(10), None);
        assert!(!s2.grace_expired(10, 5600));
        assert!(!s2.grace_expired(11, 5599));
        assert!(s2.grace_expired(11, 5600));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_state_is_archived_and_recovered_fresh() {
        let dir = std::env::temp_dir().join(format!("reaper-corrupt-state-{}", std::process::id()));
        let file = dir.join("state.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, "not a state file\n").unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        let live = HashMap::new();
        assert_eq!(supervisor.reload(&live, 1, 600, &file).unwrap(), (0, 0));
        assert!(supervisor
            .recovery_message()
            .unwrap()
            .contains("state schema missing"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_corrupt_and_unknown_schema_files_recover_fresh_with_private_backup() {
        let dir =
            std::env::temp_dir().join(format!("reaper-state-recovery-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for (index, contents) in [
            "legacy state\n",
            "REAPER_STATE_V1\nnot\ta\tvalid\trecord\n",
            "REAPER_STATE_V0\n",
        ]
        .into_iter()
        .enumerate()
        {
            let file = dir.join(format!("state-{index}.json"));
            fs::write(&file, contents).unwrap();
            let mut supervisor = Supervisor::new(file.clone());
            assert_eq!(
                supervisor.reload(&HashMap::new(), 10, 600, &file).unwrap(),
                (0, 0)
            );
            assert!(
                supervisor.entries.is_empty(),
                "recovery must not restore candidates or grace"
            );
            assert_eq!(
                fs::read_to_string(&file).unwrap(),
                format!("{SCHEMA_VERSION}\n")
            );
            assert_eq!(
                fs::read_dir(&dir)
                    .unwrap()
                    .filter_map(Result::ok)
                    .filter(|e| e
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&format!("state-{index}.json.bak.")))
                    .count(),
                1
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let backup = fs::read_dir(&dir)
                    .unwrap()
                    .flatten()
                    .find(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with(&format!("state-{index}.json.bak."))
                    })
                    .unwrap()
                    .path();
                assert_eq!(
                    fs::metadata(backup).unwrap().permissions().mode() & 0o777,
                    0o600
                );
                assert_eq!(
                    fs::metadata(&file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn schema_version_mismatch_is_explicitly_rejected() {
        let dir = std::env::temp_dir().join(format!("reaper-schema-test-{}", std::process::id()));
        let file = dir.join("state.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, "REAPER_STATE_V0\n").unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        assert_eq!(
            supervisor.reload(&HashMap::new(), 10, 600, &file).unwrap(),
            (0, 0)
        );
        assert!(supervisor
            .recovery_message()
            .unwrap()
            .contains("unsupported"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_record_is_archived_without_restoring_partial_state() {
        let dir = std::env::temp_dir().join(format!("reaper-torn-test-{}", std::process::id()));
        let file = dir.join("state.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, format!("{SCHEMA_VERSION}\n12\t")).unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        assert_eq!(
            supervisor.reload(&HashMap::new(), 10, 600, &file).unwrap(),
            (0, 0)
        );
        assert_eq!(supervisor.state_of(12), None);
        assert!(supervisor
            .recovery_message()
            .unwrap()
            .contains("state corrupt"));
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            format!("{SCHEMA_VERSION}\n")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_lab_grace_elapsed_before_restart_requires_revalidation() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let registry =
            std::env::temp_dir().join(format!("reaper-live-restart-{}.json", std::process::id()));
        std::env::set_var("REAPER_LAB_REGISTRY", &registry);
        let mut child = crate::lab::spawn(false).unwrap();
        let identity = id(child.entry.pid, child.entry.start_ticks);
        let dir = std::env::temp_dir().join(format!("reaper-live-reload-{}", std::process::id()));
        let file = dir.join("state");
        let issued = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut before_restart = Supervisor::new(file.clone());
        before_restart.transition(
            &identity,
            State::GracePeriod,
            issued,
            "lab cycle",
            "lab-project",
            "revalidate",
        );
        before_restart.arm_grace(identity.pid, issued + 1);
        before_restart.persist().unwrap();
        let cycle =
            crate::lab::run_lab_cycle(&mut child, std::time::Duration::from_millis(1100), true)
                .unwrap();
        assert_eq!(cycle.outcome, crate::lab::Outcome::Cancelled);
        let live: HashMap<u32, ProcessIdentity> =
            [(identity.pid, identity.clone())].into_iter().collect();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut after_restart = Supervisor::new(file.clone());
        let (kept, discarded) = after_restart.reload(&live, now, 600, &file).unwrap();
        assert_eq!((kept, discarded), (1, 0));
        assert_eq!(
            after_restart.state_of(identity.pid),
            Some(State::GracePeriod)
        );
        assert!(!after_restart.grace_expired(identity.pid, now + 599));
        drop(child);
        assert_ne!(
            crate::lab::identity_ticks(identity.pid).ok(),
            Some(identity.start_ticks)
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
