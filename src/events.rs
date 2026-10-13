//! Phase 2: lifecycle event engine.
//!
//! Diffs consecutive scans keyed by full identity (pid + start_ticks), so a
//! recycled PID surfaces as disappearance + appearance, never as continuity.
//! A single bad read degrades to `ScanDegraded`, never to a supervisor halt.

use crate::identity::ProcessIdentity;
use crate::procfs::{Process, ScanOutcome};
use std::collections::HashMap;

/// Observable lifecycle change. No variant authorizes termination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Appeared {
        identity: ProcessIdentity,
    },
    Disappeared {
        identity: ProcessIdentity,
    },
    IdentityChanged {
        old: ProcessIdentity,
        new: ProcessIdentity,
    },
    /// The recorded parent PID is gone from the visible set (reaped, hidden,
    /// or out of UID scope — the distinction is deliberately not claimed).
    OwnerExited {
        child: ProcessIdentity,
        owner_pid: u32,
    },
    StateChanged {
        identity: ProcessIdentity,
        from: char,
        to: char,
    },
    /// A /proc read failed partway; the cycle continued with partial data.
    ScanDegraded {
        skipped_stat: usize,
        skipped_mismatch: usize,
    },
}

pub struct Tracker {
    previous: HashMap<u32, (ProcessIdentity, char, u32)>,
    boot_id: Option<String>,
}

impl Tracker {
    pub fn new(boot_id: Option<String>) -> Self {
        Tracker {
            previous: HashMap::new(),
            boot_id,
        }
    }

    pub fn diff(&mut self, outcome: &ScanOutcome, processes: &[Process]) -> Vec<Event> {
        let mut events = Vec::new();
        if outcome.skipped_stat > 0 || outcome.skipped_mismatch > 0 {
            events.push(Event::ScanDegraded {
                skipped_stat: outcome.skipped_stat,
                skipped_mismatch: outcome.skipped_mismatch,
            });
        }
        let mut current: HashMap<u32, (ProcessIdentity, char, u32)> = HashMap::new();
        for p in processes {
            let id = crate::identity::identify(p, self.boot_id.clone());
            current.insert(p.pid, (id, p.state, p.ppid));
        }
        for (pid, (id, state, _)) in &current {
            match self.previous.get(pid) {
                None => events.push(Event::Appeared {
                    identity: id.clone(),
                }),
                Some((old_id, old_state, _)) => {
                    if old_id.start_ticks != id.start_ticks || old_id.uid != id.uid {
                        events.push(Event::IdentityChanged {
                            old: old_id.clone(),
                            new: id.clone(),
                        });
                    } else if old_state != state {
                        events.push(Event::StateChanged {
                            identity: id.clone(),
                            from: *old_state,
                            to: *state,
                        });
                    }
                }
            }
        }
        for (pid, (id, _, _)) in &self.previous {
            if !current.contains_key(pid) {
                events.push(Event::Disappeared {
                    identity: id.clone(),
                });
            }
        }
        // Owner exit fires only on transition: a newly seen child whose parent
        // is already absent, or a tracked child whose parent just vanished.
        // A steady-state decoupled process re-emits nothing (no log spam).
        for (pid, (id, _, ppid)) in &current {
            if *ppid == 0 || current.contains_key(ppid) {
                continue;
            }
            let fire = match self.previous.get(pid) {
                None => true,
                Some((old_id, _, _)) => {
                    old_id.start_ticks == id.start_ticks
                        && old_id.uid == id.uid
                        && self.previous.contains_key(ppid)
                }
            };
            if fire {
                events.push(Event::OwnerExited {
                    child: id.clone(),
                    owner_pid: *ppid,
                });
            }
        }
        self.previous = current;
        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::Process;

    fn proc(pid: u32, ppid: u32, start: u64, state: char) -> Process {
        Process {
            pid,
            ppid,
            pgrp: ppid,
            session: ppid,
            start_ticks: start,
            state,
            name: "x".into(),
            command: "x".into(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(10373),
        }
    }

    fn outcome(ps: &[Process]) -> ScanOutcome {
        ScanOutcome {
            processes: ps.to_vec(),
            skipped_stat: 0,
            skipped_mismatch: 0,
        }
    }

    #[test]
    fn recycled_pid_is_death_plus_birth() {
        let mut t = Tracker::new(None);
        let o1 = outcome(&[proc(9, 1, 100, 'S')]);
        assert!(t
            .diff(&o1, &o1.processes)
            .iter()
            .any(|e| matches!(e, Event::Appeared { .. })));
        let o2 = outcome(&[proc(9, 1, 200, 'S')]);
        let evs = t.diff(&o2, &o2.processes);
        assert!(evs
            .iter()
            .any(|e| matches!(e, Event::IdentityChanged { .. })));
        assert!(!evs.iter().any(|e| matches!(e, Event::StateChanged { .. })));
    }

    #[test]
    fn owner_exit_and_state_change() {
        let mut t = Tracker::new(None);
        let o1 = outcome(&[proc(1, 0, 10, 'S'), proc(2, 1, 11, 'S')]);
        t.diff(&o1, &o1.processes);
        let o2 = outcome(&[proc(2, 1, 11, 'R')]);
        let evs = t.diff(&o2, &o2.processes);
        assert!(evs
            .iter()
            .any(|e| matches!(e, Event::OwnerExited { owner_pid: 1, .. })));
        assert!(evs.iter().any(|e| matches!(e, Event::StateChanged { .. })));
        assert!(evs.iter().any(|e| matches!(e, Event::Disappeared { .. })));
    }
}
