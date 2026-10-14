//! Phase 2: policy engine.
//!
//! The twelve mandatory rules (§7 of the mission) as code. Phase 2 outcomes
//! never include termination: the strongest escalation is `ReadyForRevalidation`
//! (a note that a future phase would re-verify) or `Blocked`. Memory pressure,
//! CPU idleness and PPID 1 can never authorize anything.

use crate::procfs::Process;
use crate::protection::{Protection, Tier};

/// Tunables. Grace is per-class and reconfigurable; unknown stays protected.
#[derive(Debug, Clone)]
pub struct Policy {
    /// Grace for known services with proven abandonment (default 5 min).
    pub grace_known_secs: u64,
    /// Grace for services needing reuse tolerance (default 10 min).
    pub grace_tolerant_secs: u64,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            grace_known_secs: 300,
            grace_tolerant_secs: 600,
        }
    }
}

/// What the policy decides for one process in this phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Rule 1/2/5/6/7: hands off, absolutely or contextually.
    KeepProtected { tier: Tier, reason: String },
    /// Under watch; needs evidence + approved policy to advance.
    Observe { reason: String },
    /// Known with sufficient evidence: grace timer may arm (no action yet).
    GraceCandidate { grace_secs: u64, reason: String },
    /// Reserved for a future evidence path that proves abandonment AND owner
    /// idleness together. Unconstructible in Phase 2 by design (no source can
    /// prove both yet); the state machine reaches its own terminal
    /// ReadyForRevalidation state on grace expiry instead, and stops there.
    #[allow(dead_code)]
    ReadyForRevalidation { reason: String },
    /// Explicitly blocked (e.g. clients unverifiable). Records why.
    Blocked { reason: String },
}

/// Inputs the policy reasons over. Everything Option/unknown defaults to
/// the safe side: unverifiable => Blocked/KeepProtected, never candidate.
#[derive(Debug, Clone)]
pub struct Signals {
    /// Owner/adapter liveness: Some(true)=active clients/tasks, Some(false)=
    /// proven idle by its owner, None=unverifiable.
    pub owner_reports_active: Option<bool>,
    /// Proven abandonment evidence approved by policy (never CPU/PPID alone).
    pub proven_abandoned: bool,
    /// Known service needing longer reuse tolerance.
    pub needs_tolerance: bool,
    /// Memory pressure observed (informational: must not override protection).
    pub memory_pressure: bool,
    /// Incomplete client observation must never arm automatic close/grace.
    pub client_coverage: crate::client_tracker::Coverage,
}

impl Default for Signals {
    fn default() -> Self {
        Self {
            owner_reports_active: None,
            proven_abandoned: false,
            needs_tolerance: false,
            memory_pressure: false,
            client_coverage: crate::client_tracker::Coverage::Unknown,
        }
    }
}

pub fn decide(
    policy: &Policy,
    tier: &Protection,
    _process: &Process,
    signals: &Signals,
) -> Decision {
    // Rule 11: memory pressure never overrides protections. It is accepted as
    // input and deliberately ignored below (no branch reads it).
    let _ = signals.memory_pressure;

    // Rules 1+2: absolute protection and unknown stay protected, always.
    if tier.tier == Tier::Absolute {
        return Decision::KeepProtected {
            tier: tier.tier,
            reason: format!("absolute: {}", tier.reason),
        };
    }
    if tier.tier == Tier::Unknown {
        return Decision::KeepProtected {
            tier: tier.tier,
            reason: format!("unknown stays protected: {}", tier.reason),
        };
    }
    // Rules 5+6: active clients/tasks keep it; unverifiable clients block.
    match signals.owner_reports_active {
        Some(true) => {
            return Decision::KeepProtected {
                tier: tier.tier,
                reason: "active clients or tasks reported by owner".into(),
            };
        }
        None => {
            return Decision::Blocked {
                reason: "client/task absence unverifiable; auto-close not authorized".into(),
            };
        }
        Some(false) => {}
    }
    // Rules 3+4 are structural: this engine has no CPU/PPID-abandonment inputs
    // at all, so idleness or PPID 1 cannot flow into a candidate decision.
    if tier.tier == Tier::Contextual {
        return Decision::KeepProtected {
            tier: tier.tier,
            reason: format!("contextual shared/service: {}", tier.reason),
        };
    }
    if signals.client_coverage != crate::client_tracker::Coverage::CompleteVerified {
        return Decision::Blocked {
            reason: format!(
                "client coverage {:?}; auto-close not authorized",
                signals.client_coverage
            ),
        };
    }
    // Rule 8: known services become candidates only with sufficient evidence
    // (proven_abandoned set by an approved policy input) — never by idleness.
    if signals.proven_abandoned {
        // Rules 9+10: configurable grace; rescue cancels (handled by caller
        // re-running decide() — any flip of owner_reports_active back to
        // Some(true)/None moves the process out of grace).
        let grace = if signals.needs_tolerance {
            policy.grace_tolerant_secs
        } else {
            policy.grace_known_secs
        };
        return Decision::GraceCandidate {
            grace_secs: grace,
            reason: "known service, abandonment proven by approved evidence".into(),
        };
    }
    Decision::Observe {
        reason: "known, awaiting sufficient evidence".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::Process;
    use crate::protection::Tier;

    fn proc() -> Process {
        Process {
            pid: 9,
            ppid: 1,
            pgrp: 9,
            session: 9,
            start_ticks: 5,
            state: 'S',
            name: "svc".into(),
            command: "svc".into(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(10373),
        }
    }

    fn prot(tier: Tier) -> Protection {
        Protection {
            tier,
            reason: "test".into(),
        }
    }

    fn known_idle() -> Signals {
        Signals {
            owner_reports_active: Some(false),
            proven_abandoned: true,
            needs_tolerance: false,
            memory_pressure: false,
            client_coverage: crate::client_tracker::Coverage::CompleteVerified,
        }
    }

    #[test]
    fn absolute_protection_is_unoverridable() {
        let p = proc();
        // Even with "proven abandonment" AND memory pressure, absolute wins.
        let s = Signals {
            memory_pressure: true,
            ..known_idle()
        };
        assert!(matches!(
            decide(&Policy::default(), &prot(Tier::Absolute), &p, &s),
            Decision::KeepProtected { .. }
        ));
    }

    #[test]
    fn unknown_processes_stay_protected() {
        let p = proc();
        assert!(matches!(
            decide(&Policy::default(), &prot(Tier::Unknown), &p, &known_idle()),
            Decision::KeepProtected { .. }
        ));
    }

    #[test]
    fn active_client_keeps_process() {
        let p = proc();
        let s = Signals {
            owner_reports_active: Some(true),
            ..known_idle()
        };
        assert!(matches!(
            decide(&Policy::default(), &prot(Tier::Known), &p, &s),
            Decision::KeepProtected { .. }
        ));
    }

    #[test]
    fn unknown_client_blocks_close() {
        let p = proc();
        let s = Signals {
            owner_reports_active: None,
            ..known_idle()
        };
        assert!(matches!(
            decide(&Policy::default(), &prot(Tier::Known), &p, &s),
            Decision::Blocked { .. }
        ));
    }

    #[test]
    fn incomplete_coverage_blocks_even_otherwise_proven_candidate() {
        let p = proc();
        for coverage in [
            crate::client_tracker::Coverage::Partial,
            crate::client_tracker::Coverage::Unknown,
            crate::client_tracker::Coverage::Broken,
        ] {
            let signals = Signals {
                client_coverage: coverage,
                ..known_idle()
            };
            assert!(matches!(
                decide(&Policy::default(), &prot(Tier::Known), &p, &signals),
                Decision::Blocked { .. }
            ));
        }
    }

    #[test]
    fn shared_processes_respect_all_users() {
        let p = proc();
        assert!(matches!(
            decide(
                &Policy::default(),
                &prot(Tier::Contextual),
                &p,
                &known_idle()
            ),
            Decision::KeepProtected { .. }
        ));
    }

    #[test]
    fn memory_pressure_never_overrides() {
        let p = proc();
        let pressured = Signals {
            memory_pressure: true,
            ..known_idle()
        };
        let calm = Signals {
            memory_pressure: false,
            ..known_idle()
        };
        assert_eq!(
            decide(&Policy::default(), &prot(Tier::Known), &p, &pressured),
            decide(&Policy::default(), &prot(Tier::Known), &p, &calm)
        );
    }

    #[test]
    fn grace_cancel_on_client_return() {
        // Rule 10: rescue during grace cancels the close — modelled as the
        // next decide() call with a live client flipping back to protected.
        let p = proc();
        let policy = Policy::default();
        let tier = prot(Tier::Known);
        assert!(matches!(
            decide(&policy, &tier, &p, &known_idle()),
            Decision::GraceCandidate { .. }
        ));
        let rescued = Signals {
            owner_reports_active: Some(true),
            ..known_idle()
        };
        assert!(matches!(
            decide(&policy, &tier, &p, &rescued),
            Decision::KeepProtected { .. }
        ));
    }
}
