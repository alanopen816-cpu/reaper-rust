//! Phase 2: relationship engine.
//!
//! Builds parent/child trees, process groups and sessions from one scan.
//! Every relationship carries its evidence strength: `Verified` (read directly
//! from /proc fields) or `Inferred` (heuristic, never sufficient alone to
//! authorize a future close). PPID 1 never implies abandonment; having no
//! visible children never implies having no clients.

use crate::procfs::Process;
use std::collections::{HashMap, HashSet};

/// How a relationship claim was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    /// Read directly from /proc fields (ppid/pgrp/session present in this scan).
    Verified,
    /// Heuristic (name pattern, co-location). Informational only.
    Inferred,
}

/// One process node with its relationships.
#[derive(Debug, Clone)]
pub struct Node {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub children: Vec<u32>,
    /// Parent PID was not visible in this scan (reaped, hidden, or outside UID).
    pub parent_missing: bool,
    pub evidence: Evidence,
}

/// A watchdog-looking helper: named like a supervisor companion AND related by
/// ancestry to a supervised tree. Name alone is NEVER enough (see tests).
#[derive(Debug, Clone)]
pub struct WatchdogHint {
    pub pid: u32,
    pub for_pid: u32,
    pub evidence: Evidence,
}

pub struct Relations {
    pub nodes: HashMap<u32, Node>,
    /// session id -> member pids (Verified when session field was present).
    pub sessions: HashMap<u32, Vec<u32>>,
    /// process-group id -> member pids.
    pub groups: HashMap<u32, Vec<u32>>,
    pub watchdogs: Vec<WatchdogHint>,
    pub evidence: Evidence,
}

fn looks_like_watchdog(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "watchdog",
        "supervise",
        "svlogd",
        "runsvdir",
        "runsv",
        "s6-supervise",
    ]
    .iter()
    .any(|k| n.contains(k))
}

pub fn build(processes: &[Process]) -> Relations {
    let present: HashSet<u32> = processes.iter().map(|p| p.pid).collect();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in processes {
        children.entry(p.ppid).or_default().push(p.pid);
    }
    let mut nodes = HashMap::new();
    let mut sessions: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut groups: HashMap<u32, Vec<u32>> = HashMap::new();
    for p in processes {
        let kids = children.get(&p.pid).cloned().unwrap_or_default();
        nodes.insert(
            p.pid,
            Node {
                pid: p.pid,
                ppid: p.ppid,
                pgrp: p.pgrp,
                session: p.session,
                children: kids,
                parent_missing: p.ppid != 0 && !present.contains(&p.ppid),
                evidence: Evidence::Verified,
            },
        );
        sessions.entry(p.session).or_default().push(p.pid);
        groups.entry(p.pgrp).or_default().push(p.pid);
    }
    // Watchdog hints require BOTH a suggestive name AND ancestry linkage to a
    // supervised subtree; anything else stays unmarked (Inferred at most).
    let mut watchdogs = Vec::new();
    for p in processes {
        if !looks_like_watchdog(&p.name) && !looks_like_watchdog(&p.command) {
            continue;
        }
        let linked = nodes.get(&p.pid).is_some_and(|n| {
            !n.children.is_empty()
                || n.parent_missing
                || processes
                    .iter()
                    .any(|q| q.ppid == p.pid || (q.pid == p.ppid && looks_like_watchdog(&q.name)))
        });
        if linked {
            watchdogs.push(WatchdogHint {
                pid: p.pid,
                for_pid: p.ppid,
                evidence: Evidence::Inferred,
            });
        }
    }
    Relations {
        nodes,
        sessions,
        groups,
        watchdogs,
        evidence: Evidence::Verified,
    }
}

/// True when `pid` has at least one visible child. False proves NOTHING about
/// clients: sockets, services and future spawns are invisible here.
pub fn has_visible_children(rel: &Relations, pid: u32) -> bool {
    rel.nodes.get(&pid).is_some_and(|n| !n.children.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::Process;

    fn proc(pid: u32, ppid: u32, name: &str) -> Process {
        Process {
            pid,
            ppid,
            pgrp: ppid,
            session: ppid,
            start_ticks: pid as u64,
            state: 'S',
            name: name.into(),
            command: name.into(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(10373),
        }
    }

    #[test]
    fn parent_loss_is_flagged_not_hidden() {
        // Parent exited or invisible: child stays tracked with parent_missing.
        let ps = vec![proc(50, 9999, "orphan")];
        let rel = build(&ps);
        assert!(rel.nodes[&50].parent_missing);
        assert!(rel.nodes.contains_key(&50));
    }

    #[test]
    fn legit_ppid1_is_not_abandonment() {
        // e.g. codex.bin with PPID 1 observed in production: tracked normally,
        // no abandonment flag exists in this engine by design.
        let ps = vec![proc(1, 0, "init"), proc(30349, 1, "codex.bin")];
        let rel = build(&ps);
        let n = &rel.nodes[&30349];
        assert!(!n.parent_missing);
        assert!(rel.nodes[&1].children.contains(&30349));
    }

    #[test]
    fn watchdog_needs_name_plus_linkage() {
        // Same name, no ancestry linkage => no hint (name alone is not proof).
        let ps = vec![
            proc(1, 0, "init"),
            proc(10, 1, "watchdog"),
            proc(20, 1, "app"),
        ];
        assert!(build(&ps).watchdogs.is_empty());
        // Name + parent/child linkage => hint, still only Inferred.
        let ps = vec![
            proc(1, 0, "init"),
            proc(10, 1, "runsv"),
            proc(11, 10, "myservice"),
        ];
        let rel = build(&ps);
        assert_eq!(rel.watchdogs.len(), 1);
        assert_eq!(rel.watchdogs[0].evidence, Evidence::Inferred);
    }

    #[test]
    fn no_children_is_not_client_proof() {
        // There is deliberately no API here claiming "no clients": absence of
        // visible children is just an empty vec, never a client proof.
        let ps = vec![proc(77, 1, "daemon")];
        let rel = build(&ps);
        assert!(!has_visible_children(&rel, 77));
    }
}
