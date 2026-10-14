//! Phase 2: critical-infrastructure protection tiers.
//!
//! Three tiers: Absolute (policy engine can never override), Contextual
//! (shared/managed: keep unless an explicit owner action says otherwise),
//! Known (ordinary services eligible for evidence-based candidacy), Unknown
//! (insufficient verification: same force as absolute).
//!
//! Name matching is explicitly provisional (see Phase-1 README limitation):
//! a name hit alone yields at most Contextual/Unknown, and Absolute requires
//! corroboration (self PID, supervisor ancestry, or Termux app identity).

use crate::procfs::Process;
use crate::relations::Relations;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    Absolute,
    Contextual,
    Known,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Protection {
    pub tier: Tier,
    pub reason: String,
}

/// Apply a classification result monotonically: only proven-inactive independent
/// processes retain ordinary evidence-based policy eligibility.
#[allow(dead_code)]
pub fn apply_classification(
    mut protection: Protection,
    class: crate::identity::ProcessClass,
    positively_verified_inactive: bool,
) -> Protection {
    if class == crate::identity::ProcessClass::Unknown {
        if protection.tier != Tier::Absolute {
            protection.tier = Tier::Unknown;
        }
        protection.reason = "classification unknown; protected by default".into();
    } else if !(class == crate::identity::ProcessClass::Independent && positively_verified_inactive)
    {
        if protection.tier == Tier::Known {
            protection.tier = Tier::Contextual;
        }
        protection.reason = format!("classified {class:?}; protected by default");
    }
    protection
}

fn name_of(p: &Process) -> String {
    p.name.to_ascii_lowercase()
}

/// Corroborated supervisor: suggestive name AND ancestry linkage (has children
/// in the visible tree or is the parent of a service process).
fn corroborated_supervisor(p: &Process, rel: &Relations) -> bool {
    let n = name_of(p);
    let exe = p.command.to_ascii_lowercase();
    let named = ["runsvdir", "runsv", "svlogd", "s6-supervise"]
        .iter()
        .any(|k| n == *k || exe.contains(k));
    if !named {
        return false;
    }
    rel.nodes
        .get(&p.pid)
        .is_some_and(|node| !node.children.is_empty())
        || rel
            .nodes
            .values()
            .any(|node| node.ppid == p.pid && !node.children.is_empty())
}

pub fn protect(p: &Process, self_pid: u32, rel: &Relations, own_uid: Option<u32>) -> Protection {
    // Ourselves, always.
    if p.pid == self_pid {
        return Protection {
            tier: Tier::Absolute,
            reason: "reaper itself".into(),
        };
    }
    // Outside our UID scope: not ours to manage, absolutely out of reach.
    if let (Some(want), Some(got)) = (own_uid, p.uid) {
        if want != got {
            return Protection {
                tier: Tier::Absolute,
                reason: "outside own UID scope".into(),
            };
        }
    }
    let n = name_of(p);
    let exe = p.command.to_ascii_lowercase();
    // Termux app identity and interactive sessions: absolute.
    if n.starts_with("com.termux") || n.starts_with("com.termux:") {
        return Protection {
            tier: Tier::Absolute,
            reason: "termux app process".into(),
        };
    }
    if ["zsh", "bash", "fish", "sh", "tmux", "login"].contains(&n.as_str()) {
        return Protection {
            tier: Tier::Absolute,
            reason: "interactive session shell (provisional name + session linkage pending)".into(),
        };
    }
    // Supervisors: absolute only when corroborated; name alone is contextual.
    if ["runsvdir", "runsv", "svlogd"].contains(&n.as_str()) {
        if corroborated_supervisor(p, rel) {
            return Protection {
                tier: Tier::Absolute,
                reason: "corroborated supervisor (name + ancestry)".into(),
            };
        }
        return Protection {
            tier: Tier::Contextual,
            reason: "supervisor name without ancestry corroboration".into(),
        };
    }
    // Managed agents/runtimes and build jobs: contextual/shared by default.
    if [
        "opencode",
        "codex",
        "codex.bin",
        "engram",
        "node",
        "python",
        "python3",
        "cargo",
        "rustc",
        "gradle",
        "java",
        "sshd",
        "dbus-daemon",
    ]
    .contains(&n.as_str())
        || exe.contains("/opencode")
        || exe.contains("/codex")
        || exe.contains("/codegraph")
        || exe.contains("/rea-")
    {
        return Protection {
            tier: Tier::Contextual,
            reason: "managed agent/runtime or build job: shared until owner proves idle".into(),
        };
    }
    // Insufficient verification (no UID): unknown, never candidate.
    if p.uid.is_none() {
        return Protection {
            tier: Tier::Unknown,
            reason: "identity incomplete (no UID)".into(),
        };
    }
    Protection {
        tier: Tier::Known,
        reason: "ordinary same-UID process, eligible for evidence-based policy".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::Process;
    use std::collections::HashMap;

    fn proc(pid: u32, ppid: u32, name: &str, uid: Option<u32>) -> Process {
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
            uid,
        }
    }

    fn empty_rel() -> Relations {
        Relations {
            nodes: HashMap::new(),
            sessions: HashMap::new(),
            groups: HashMap::new(),
            watchdogs: vec![],
            evidence: crate::relations::Evidence::Verified,
        }
    }

    #[test]
    fn self_is_absolute() {
        let p = proc(100, 1, "reaper", Some(10373));
        let r = protect(&p, 100, &empty_rel(), Some(10373));
        assert_eq!(r.tier, Tier::Absolute);
    }

    #[test]
    fn out_of_scope_uid_is_absolute() {
        let p = proc(50, 1, "svc", Some(0));
        let r = protect(&p, 999, &empty_rel(), Some(10373));
        assert_eq!(r.tier, Tier::Absolute);
    }

    #[test]
    fn supervisor_name_alone_is_not_absolute() {
        // Name match without ancestry corroboration must NOT reach Absolute.
        let p = proc(60, 1, "runsvdir", Some(10373));
        let r = protect(&p, 999, &empty_rel(), Some(10373));
        assert_eq!(r.tier, Tier::Contextual);
    }

    #[test]
    fn unknown_stays_unknown() {
        let p = proc(70, 1, "mystery", None);
        let r = protect(&p, 999, &empty_rel(), Some(10373));
        assert_eq!(r.tier, Tier::Unknown);
    }

    #[test]
    fn classified_persistent_service_is_protected() {
        let result = apply_classification(
            Protection {
                tier: Tier::Known,
                reason: "ordinary".into(),
            },
            crate::identity::ProcessClass::PersistentService,
            false,
        );
        assert_eq!(result.tier, Tier::Contextual);
    }

    #[test]
    fn classified_unknown_is_protected() {
        let result = apply_classification(
            Protection {
                tier: Tier::Known,
                reason: "ordinary".into(),
            },
            crate::identity::ProcessClass::Unknown,
            true,
        );
        assert_eq!(result.tier, Tier::Unknown);
    }

    #[test]
    fn verified_inactive_independent_remains_policy_eligible() {
        let result = apply_classification(
            Protection {
                tier: Tier::Known,
                reason: "ordinary".into(),
            },
            crate::identity::ProcessClass::Independent,
            true,
        );
        assert_eq!(result.tier, Tier::Known);
    }

    #[test]
    fn active_independent_is_protected_by_classifier() {
        let result = apply_classification(
            Protection {
                tier: Tier::Known,
                reason: "ordinary".into(),
            },
            crate::identity::ProcessClass::Independent,
            false,
        );
        assert_eq!(result.tier, Tier::Contextual);
    }
}
