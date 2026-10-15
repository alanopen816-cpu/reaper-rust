//! Permanent, read-only audit decisions. This module intentionally has no
//! process-control API or signal-capable dependency.

use crate::client_tracker::Coverage;

pub const IDLE_ELIGIBILITY_SECS: u64 = 30 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportCoverage {
    CoveredExclusiveUds,
    IncompleteByConstruction,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulatedDecision {
    ProtectActiveClient,
    ProtectActiveWork,
    ProtectUnknown,
    WouldTerminateHeuristic,
    InsufficientEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Active,
    Idle,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePolicy {
    ProtectedNoAutoClose,
    ObserveDryRun,
    Observe,
}

pub fn service_policy(service_id: &str) -> ServicePolicy {
    match service_id {
        "opencode-server" | "codex-app-server" => ServicePolicy::ProtectedNoAutoClose,
        "mcp-shared" | "mcp-dedicated" => ServicePolicy::ObserveDryRun,
        _ => ServicePolicy::Observe,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunDecision {
    pub timestamp: u64,
    pub service_id: String,
    pub pid: u32,
    pub start_ticks: u64,
    pub client_state: ClientState,
    pub active_leases: usize,
    pub expired_leases: usize,
    pub protected_work: bool,
    pub transport_coverage: TransportCoverage,
    pub idle_secs: u64,
    pub evidence_present: Vec<String>,
    pub evidence_absent: Vec<String>,
    pub simulated_decision: SimulatedDecision,
    pub reason: String,
    pub final_state: String,
}

/// Pure classification only: a WouldTerminateHeuristic is not safe or
/// authorization. Exhaustive transport coverage and fresh approval would be
/// prerequisites for any separate future action path; dry-run grants neither.
#[allow(clippy::too_many_arguments)]
pub fn decide(
    timestamp: u64,
    service_id: impl Into<String>,
    pid: u32,
    start_ticks: u64,
    client_state: ClientState,
    active_leases: usize,
    expired_leases: usize,
    protected_work: bool,
    transport_coverage: TransportCoverage,
    idle_secs: u64,
    socket_snapshot_complete: bool,
    work_evidence: bool,
) -> DryRunDecision {
    let service_id = service_id.into();
    let mut evidence_present = Vec::new();
    let mut evidence_absent = Vec::new();
    if active_leases > 0 {
        evidence_present.push("active_lease".into());
    }
    if expired_leases > 0 {
        evidence_present.push("expired_lease_requires_reconciliation".into());
    }
    if socket_snapshot_complete {
        evidence_present.push("socket_snapshot_complete".into());
    } else {
        evidence_absent.push("socket_snapshot_incomplete".into());
    }
    if work_evidence {
        evidence_present.push("work_evidence".into());
    } else {
        evidence_absent.push("work_evidence".into());
    }
    if idle_secs >= IDLE_ELIGIBILITY_SECS {
        evidence_present.push("idle_threshold_eligible_only".into());
    }
    let (simulated_decision, reason, final_state) =
        if service_policy(&service_id) == ServicePolicy::ProtectedNoAutoClose {
            (
                SimulatedDecision::ProtectUnknown,
                "service policy forbids auto-close".into(),
                "protected".into(),
            )
        } else if client_state == ClientState::Active || active_leases > 0 {
            (
                SimulatedDecision::ProtectActiveClient,
                "active client evidence".into(),
                "protected".into(),
            )
        } else if protected_work {
            (
                SimulatedDecision::ProtectActiveWork,
                "protected work is active".into(),
                "protected".into(),
            )
        } else if client_state == ClientState::Unknown
            || expired_leases > 0
            || transport_coverage != TransportCoverage::CoveredExclusiveUds
        {
            (
                SimulatedDecision::ProtectUnknown,
                "client or transport evidence is incomplete".into(),
                "protected".into(),
            )
        } else if socket_snapshot_complete && work_evidence && idle_secs >= IDLE_ELIGIBILITY_SECS {
            (
                SimulatedDecision::WouldTerminateHeuristic,
                "heuristic candidate only; dry-run never authorizes termination".into(),
                "would_terminate_heuristic".into(),
            )
        } else {
            (
                SimulatedDecision::InsufficientEvidence,
                "insufficient evidence for even a heuristic candidate".into(),
                "observing".into(),
            )
        };
    DryRunDecision {
        timestamp,
        service_id,
        pid,
        start_ticks,
        client_state,
        active_leases,
        expired_leases,
        protected_work,
        transport_coverage,
        idle_secs,
        evidence_present,
        evidence_absent,
        simulated_decision,
        reason,
        final_state,
    }
}

/// Append a bounded JSONL audit record using the existing logger's rotation.
/// Only service/process identities, counts, and enum-like classifications are written.
pub fn log_decision(
    config: &crate::logx::LogConfig,
    decision: &DryRunDecision,
) -> std::io::Result<usize> {
    let json = format!("{{\"timestamp\":{},\"service_id\":\"{}\",\"pid\":{},\"start_ticks\":{},\"client_state\":\"{:?}\",\"active_leases\":{},\"expired_leases\":{},\"protected_work\":{},\"transport_coverage\":\"{:?}\",\"idle_secs\":{},\"evidence_present\":{},\"evidence_absent\":{},\"simulated_decision\":\"{:?}\",\"reason\":\"{}\",\"final_state\":\"{}\"}}", decision.timestamp, escape(&decision.service_id), decision.pid, decision.start_ticks, decision.client_state, decision.active_leases, decision.expired_leases, decision.protected_work, decision.transport_coverage, decision.idle_secs, json_array(&decision.evidence_present), json_array(&decision.evidence_absent), decision.simulated_decision, escape(&decision.reason), escape(&decision.final_state));
    crate::logx::log(config, crate::logx::Level::Info, "dry_run", &json)
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn json_array(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| format!("\"{}\"", escape(value)))
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[allow(dead_code)]
fn _coverage_type_anchor(_: Coverage) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(
        client: ClientState,
        work: bool,
        coverage: TransportCoverage,
        idle: u64,
        complete: bool,
        work_evidence: bool,
    ) -> DryRunDecision {
        decide(
            1,
            "mcp-dedicated",
            std::process::id(),
            1,
            client,
            0,
            0,
            work,
            coverage,
            idle,
            complete,
            work_evidence,
        )
    }

    #[test]
    fn classifies_all_decision_variants_without_signaling() {
        assert_eq!(
            decision(
                ClientState::Active,
                false,
                TransportCoverage::CoveredExclusiveUds,
                0,
                true,
                true
            )
            .simulated_decision,
            SimulatedDecision::ProtectActiveClient
        );
        assert_eq!(
            decision(
                ClientState::Idle,
                true,
                TransportCoverage::CoveredExclusiveUds,
                0,
                true,
                true
            )
            .simulated_decision,
            SimulatedDecision::ProtectActiveWork
        );
        assert_eq!(
            decision(
                ClientState::Unknown,
                false,
                TransportCoverage::Unknown,
                0,
                false,
                false
            )
            .simulated_decision,
            SimulatedDecision::ProtectUnknown
        );
        assert_eq!(
            decision(
                ClientState::Idle,
                false,
                TransportCoverage::CoveredExclusiveUds,
                1800,
                true,
                true
            )
            .simulated_decision,
            SimulatedDecision::WouldTerminateHeuristic
        );
        assert_eq!(
            decision(
                ClientState::Idle,
                false,
                TransportCoverage::CoveredExclusiveUds,
                0,
                false,
                false
            )
            .simulated_decision,
            SimulatedDecision::InsufficientEvidence
        );
        // The controlled process is this test runner; pure decision evaluation leaves it alive.
        assert!(std::path::Path::new(&format!("/proc/{}/stat", std::process::id())).exists());
    }

    #[test]
    fn service_policy_and_idle_threshold_are_only_eligibility() {
        assert_eq!(
            service_policy("opencode-server"),
            ServicePolicy::ProtectedNoAutoClose
        );
        assert_eq!(
            service_policy("codex-app-server"),
            ServicePolicy::ProtectedNoAutoClose
        );
        assert_eq!(service_policy("mcp-shared"), ServicePolicy::ObserveDryRun);
        assert_eq!(
            service_policy("mcp-dedicated"),
            ServicePolicy::ObserveDryRun
        );
        assert_eq!(service_policy("other"), ServicePolicy::Observe);
        assert_eq!(
            decision(
                ClientState::Idle,
                false,
                TransportCoverage::CoveredExclusiveUds,
                1800,
                false,
                false
            )
            .simulated_decision,
            SimulatedDecision::InsufficientEvidence
        );
        assert_eq!(IDLE_ELIGIBILITY_SECS, 1800);
        assert_eq!(
            crate::logx::LogConfig::new("unused".into()).rotate_bytes,
            1024 * 1024
        );
    }

    #[test]
    fn bypass_race_and_observation_failures_are_never_close_candidates() {
        // The extra transport is deliberately not represented by a lease. Silence
        // in the registry cannot promote constructionally incomplete coverage.
        let bypass = decide(
            1,
            "lab",
            7,
            9,
            ClientState::Unknown,
            0,
            0,
            false,
            TransportCoverage::IncompleteByConstruction,
            1800,
            true,
            true,
        );
        assert_eq!(bypass.simulated_decision, SimulatedDecision::ProtectUnknown);
        assert_ne!(Coverage::Unknown, Coverage::CompleteVerified);

        let during_race = decide(
            2,
            "lab",
            7,
            9,
            ClientState::Unknown,
            0,
            0,
            false,
            TransportCoverage::Unknown,
            0,
            false,
            false,
        );
        assert!(matches!(
            during_race.simulated_decision,
            SimulatedDecision::ProtectUnknown | SimulatedDecision::InsufficientEvidence
        ));
        let lost_response = decide(
            3,
            "lab",
            7,
            9,
            ClientState::Unknown,
            0,
            1,
            false,
            TransportCoverage::Unknown,
            1800,
            false,
            false,
        );
        assert_eq!(
            lost_response.simulated_decision,
            SimulatedDecision::ProtectUnknown
        );

        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        for state in [ClientState::Active, ClientState::Idle, ClientState::Unknown] {
            let result = decide(
                4,
                "lab",
                child.id(),
                1,
                state,
                0,
                0,
                false,
                TransportCoverage::IncompleteByConstruction,
                1800,
                false,
                false,
            );
            assert_ne!(
                result.simulated_decision,
                SimulatedDecision::WouldTerminateHeuristic
            );
        }
        assert!(std::path::Path::new(&format!("/proc/{}/stat", child.id())).exists());
        child.kill().unwrap();
        child.wait().unwrap();

        let source = include_str!("dryrun.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(!production.contains("pidfd_send_signal"));
        assert!(!production.contains("Command::new(\"kill\")"));
        assert!(!production.contains("use nix::sys::signal"));
    }
}
