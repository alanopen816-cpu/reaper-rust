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
}

impl Supervisor {
    pub fn new(state_file: PathBuf) -> Self {
        Supervisor {
            entries: HashMap::new(),
            state_file,
        }
    }

    pub fn state_of(&self, pid: u32) -> Option<State> {
        self.entries.get(&pid).map(|e| e.state)
    }

    /// Stored identity for a tracked PID (used to detect PID recycling via
    /// `identity::verify` before trusting any prior state).
    pub fn identity_of(&self, pid: u32) -> Option<ProcessIdentity> {
        self.entries.get(&pid).map(|e| e.identity.clone())
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
        let content = match fs::read_to_string(&self.state_file) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e),
        };
        let mut lines = content.lines();
        if lines.next() != Some(SCHEMA_VERSION) {
            return Err(invalid_state("missing or unsupported state schema version"));
        }
        let mut kept = 0;
        let mut discarded = 0;
        self.entries.clear();
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
            let state =
                State::parse(fields[3]).ok_or_else(|| invalid_state("invalid lifecycle state"))?;
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
        Ok((kept, discarded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ProcessIdentity;

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
    fn malformed_state_is_reported_instead_of_treated_as_empty() {
        let dir = std::env::temp_dir().join(format!("reaper-corrupt-state-{}", std::process::id()));
        let file = dir.join("state.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, "not a state file\n").unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        let live = HashMap::new();
        assert!(supervisor.reload(&live, 1, 600, &file).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn schema_version_mismatch_is_explicitly_rejected() {
        let dir = std::env::temp_dir().join(format!("reaper-schema-test-{}", std::process::id()));
        let file = dir.join("state.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, "REAPER_STATE_V0\n").unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        assert!(supervisor.reload(&HashMap::new(), 10, 600, &file).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_record_is_an_error_and_does_not_restore_partial_state() {
        let dir = std::env::temp_dir().join(format!("reaper-torn-test-{}", std::process::id()));
        let file = dir.join("state.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&file, format!("{SCHEMA_VERSION}\n12\t")).unwrap();
        let mut supervisor = Supervisor::new(file.clone());
        assert!(supervisor.reload(&HashMap::new(), 10, 600, &file).is_err());
        assert_eq!(supervisor.state_of(12), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
