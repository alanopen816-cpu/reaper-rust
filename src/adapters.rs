//! Phase 2: decoupled owner adapters, shutdown paths permanently declined.
//!
//! Each adapter answers one question — "does this process have a living
//! owner?" — with a three-valued answer. `Unknown` is a first-class result:
//! the policy treats it as a block, never as permission.
//!
//! Official control mechanisms are preferred by design, but in Phase 2 every
//! shutdown request returns `DeclinedPhase2`: the decline is a value, not a
//! missing implementation, so no caller can mistake a stub for authority.
//! Reaper never multiplexes MCP connections; the existing broker keeps that
//! responsibility (`~/mcp-broker-lab` is not modified and not duplicated).

use crate::identity::ProcessIdentity;

/// Owner liveness from the owner's own point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    // Spec-mandated interface for future owner adapters (Phase 3+ wires them);
    // Phase 2 honestly answers Unknown everywhere (see adapters test).
    #[allow(dead_code)]
    Alive,
    #[allow(dead_code)]
    Dead,
    Unknown,
}

/// Phase-2 shutdown verdict: always declined, with the reason recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shutdown {
    DeclinedPhase2 { reason: String },
}

pub trait OwnerAdapter {
    fn name(&self) -> &'static str;
    /// Owner-specific detail (e.g. which runit service). Defaults to the name.
    fn detail(&self) -> String {
        self.name().to_owned()
    }
    fn liveness(&self, id: &ProcessIdentity) -> Liveness;
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown;
}

fn declined(id: &ProcessIdentity, owner: &str) -> Shutdown {
    Shutdown::DeclinedPhase2 {
        reason: format!(
            "phase-2 observes only; official {} shutdown for pid={} start={} stays manual",
            owner, id.pid, id.start_ticks
        ),
    }
}

/// Fallback for ordinary Linux processes: no owner channel exists, so the
/// only honest answer is Unknown.
pub struct GenericLinux;
impl OwnerAdapter for GenericLinux {
    fn name(&self) -> &'static str {
        "generic-linux"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "process")
    }
}

/// runit-managed services: liveness would come from `sv status` (owner-read);
/// Phase 2 reports Unknown until that read is wired, never assumes.
pub struct RunitService {
    pub service_name: String,
}
impl OwnerAdapter for RunitService {
    fn name(&self) -> &'static str {
        "runit"
    }
    fn detail(&self) -> String {
        format!("runit:{}", self.service_name)
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "sv down")
    }
}

/// External MCP broker backends: liveness belongs to the broker's /health.
/// Reaper calls the broker interface when wired; it never re-implements the
/// broker's grace/SIGTERM→SIGKILL sequence.
pub struct McpBroker;
impl OwnerAdapter for McpBroker {
    fn name(&self) -> &'static str {
        "mcp-broker"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "broker")
    }
}

/// Shared OpenCode server: endpoint presence proves nothing about clients.
pub struct OpenCode;
impl OwnerAdapter for OpenCode {
    fn name(&self) -> &'static str {
        "opencode"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "opencode service stop (user-only)")
    }
}

/// Codex app-server daemon: version/socket proves responsiveness, not idleness.
pub struct Codex;
impl OwnerAdapter for Codex {
    fn name(&self) -> &'static str {
        "codex"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "codex app-server daemon stop (user-only)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> ProcessIdentity {
        ProcessIdentity {
            boot_id: None,
            pid: 1,
            start_ticks: 1,
            uid: Some(10373),
            exe: "x".into(),
        }
    }

    #[test]
    fn unknown_is_the_honest_default() {
        let adapters: Vec<Box<dyn OwnerAdapter>> = vec![
            Box::new(GenericLinux),
            Box::new(RunitService {
                service_name: "x".into(),
            }),
            Box::new(McpBroker),
            Box::new(OpenCode),
            Box::new(Codex),
        ];
        for a in &adapters {
            assert_eq!(a.liveness(&id()), Liveness::Unknown, "{}", a.name());
            assert!(
                matches!(
                    a.request_official_shutdown(&id()),
                    Shutdown::DeclinedPhase2 { .. }
                ),
                "{}",
                a.name()
            );
        }
    }
}
