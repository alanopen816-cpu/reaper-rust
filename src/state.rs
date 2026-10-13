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
}

pub struct Supervisor {
    entries: HashMap<u32, Entry>,
    state_file: PathBuf,
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
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
        if let Some(parent) = self.state_file.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.state_file.with_extension("tmp");
        let mut out = String::new();
        for e in self.entries.values() {
            out.push_str(&format!(
                "{{\"pid\":{},\"start\":{},\"uid\":{},\"exe\":\"{}\",\"state\":\"{}\",\"grace\":{}}}\n",
                e.identity.pid,
                e.identity.start_ticks,
                e.identity
                    .uid
                    .map_or("null".to_string(), |u| u.to_string()),
                esc(&e.identity.exe),
                e.state.as_str(),
                e.grace_deadline.map_or("null".to_string(), |g| g.to_string()),
            ));
        }
        fs::write(&tmp, out)?;
        fs::rename(&tmp, &self.state_file)?;
        Ok(())
    }

    /// Reload and re-validate against a fresh scan.
    /// Returns (kept, discarded): recycled identities are discarded, and every
    /// surviving GRACE_PERIOD re-arms its deadline at `now_unix + grace_secs`
    /// because the downtime is unobservable.
    pub fn reload(
        &mut self,
        live: &HashMap<u32, (u64, Option<u32>)>,
        now_unix: u64,
        grace_secs: u64,
        state_file: &Path,
    ) -> (usize, usize) {
        self.state_file = state_file.to_path_buf();
        let content = fs::read_to_string(&self.state_file).unwrap_or_default();
        let mut kept = 0;
        let mut discarded = 0;
        self.entries.clear();
        for line in content.lines() {
            let pid: u32 = match line.split("\"pid\":").nth(1).and_then(|s| {
                s.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|n| n.parse().ok())
            }) {
                Some(v) => v,
                None => {
                    discarded += 1;
                    continue;
                }
            };
            let start: u64 = line
                .split("\"start\":")
                .nth(1)
                .and_then(|s| {
                    s.split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|n| n.parse().ok())
                })
                .unwrap_or(u64::MAX);
            let state = line
                .split("\"state\":\"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .and_then(State::parse)
                .unwrap_or(State::Discovered);
            match live.get(&pid) {
                Some((live_start, live_uid)) if *live_start == start => {
                    let deadline = if state == State::GracePeriod {
                        Some(now_unix + grace_secs)
                    } else {
                        None
                    };
                    self.entries.insert(
                        pid,
                        Entry {
                            identity: ProcessIdentity {
                                boot_id: None,
                                pid,
                                start_ticks: start,
                                uid: *live_uid,
                                exe: String::new(),
                            },
                            state,
                            grace_deadline: deadline,
                        },
                    );
                    kept += 1;
                }
                _ => discarded += 1,
            }
        }
        (kept, discarded)
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
        let dir = std::env::temp_dir().join("reaper-restart-test");
        let _ = fs::remove_dir_all(&dir);
        let file = dir.join("state.json");
        let mut s = Supervisor::new(file.clone());
        s.transition(&id(10, 100), State::GracePeriod, 1000, "e", "p", "r");
        s.arm_grace(10, 1000 + 600);
        s.transition(&id(11, 110), State::Observing, 1000, "e", "p", "r");
        s.persist().unwrap();
        // PID 10 recycled (new start), PID 11 identical.
        let live: HashMap<u32, (u64, Option<u32>)> =
            [(10, (999, Some(10373))), (11, (110, Some(10373)))]
                .into_iter()
                .collect();
        let mut s2 = Supervisor::new(file.clone());
        let (kept, discarded) = s2.reload(&live, 5000, 600, &file);
        assert_eq!((kept, discarded), (1, 1));
        assert_eq!(s2.state_of(11), Some(State::Observing));
        assert_eq!(s2.state_of(10), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
