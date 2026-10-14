//! Short-grace autonomous lifecycle exercised only against registered lab children.
#![allow(dead_code)] // This lab driver is intentionally not wired into production CLI.
use std::{io, thread, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    ServiceDetected,
    ClientActive,
    Protected,
    LastClientDisconnected,
    NoPendingWork,
    GraceEntered,
    Revalidated,
    ActivityCancelled,
    AbandonmentDetected,
    NewGraceEntered,
    SafeClose,
    TerminationConfirmed,
    AuditLogged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Cancelled,
    Closed,
}

#[derive(Debug)]
pub struct CycleReport {
    pub outcome: Outcome,
    pub stages: Vec<Stage>,
    pub receipts: Vec<String>,
}

/// Runs a lab-only two-grace cycle. `activity_returns` models a newly verified
/// client observation between grace periods; absence is never inferred from error.
pub fn run_lab_cycle(
    child: &mut crate::lab::LabChild,
    grace: Duration,
    activity_returns: bool,
) -> io::Result<CycleReport> {
    run_lab_cycle_with_work(
        child,
        grace,
        activity_returns,
        crate::evidence::ClientWorkState::IdleVerified {
            surfaces: vec!["lab client roster".into(), "lab work queue".into()],
        },
    )
}

fn run_lab_cycle_with_work(
    child: &mut crate::lab::LabChild,
    grace: Duration,
    activity_returns: bool,
    idle: crate::evidence::ClientWorkState,
) -> io::Result<CycleReport> {
    use crate::{
        evidence::{self, AbandonEvidence, ClientWorkState},
        owner::OwnerVerdict,
        terminate::{self, ClosePolicy, LabRecord},
    };

    let entry = &child.entry;
    let mut stages = vec![Stage::ServiceDetected];
    if !crate::lab::registry_contains(entry)?
        || crate::lab::identity_ticks(entry.pid).ok() != Some(entry.start_ticks)
    {
        return Err(io::Error::other("lab identity unavailable"));
    }
    stages.extend([
        Stage::ClientActive,
        Stage::Protected,
        Stage::LastClientDisconnected,
    ]);
    if !matches!(idle, ClientWorkState::IdleVerified { .. }) {
        return Err(io::Error::other(format!(
            "client/work observation is not verified idle: {idle:?}"
        )));
    }
    let (last_client_gone, no_pending_work) = evidence::client_work_to_fields(&idle);
    if last_client_gone != Some(true) {
        return Err(io::Error::other("last client state unknown"));
    }
    stages.push(Stage::NoPendingWork);
    stages.push(Stage::GraceEntered);
    thread::sleep(grace);
    if !crate::lab::registry_contains(entry)?
        || crate::lab::identity_ticks(entry.pid).ok() != Some(entry.start_ticks)
    {
        return Err(io::Error::other("lab identity failed revalidation"));
    }
    stages.push(Stage::Revalidated);
    if activity_returns {
        stages.push(Stage::ActivityCancelled);
        return Ok(CycleReport {
            outcome: Outcome::Cancelled,
            stages,
            receipts: vec!["grace.cancelled: verified client activity reappeared".into()],
        });
    }
    stages.extend([Stage::AbandonmentDetected, Stage::NewGraceEntered]);
    thread::sleep(grace);
    let ev = AbandonEvidence {
        lab_member: crate::lab::registry_contains(entry)?,
        owner: OwnerVerdict::Unclaimed,
        grace_expired: true,
        revalidated_now: crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks),
        owner_dead: Some(true),
        last_client_gone,
        no_pending_work,
    };
    if !evidence::proven(&ev) {
        eprintln!("lab close refused: unproven abandonment evidence: {ev:?}");
        return Err(io::Error::other("abandonment evidence incomplete"));
    }
    // Recompute policy at the final gate from the fresh process snapshot and
    // the cycle's verified lab-only client/work observation. No approval token
    // is accepted from a caller.
    let fresh = crate::procfs::scan();
    let process = fresh
        .processes
        .iter()
        .find(|process| process.pid == entry.pid && process.start_ticks == entry.start_ticks)
        .ok_or_else(|| io::Error::other("policy approval refused: fresh identity unavailable"))?;
    let relations = crate::relations::build(&fresh.processes);
    let protection =
        crate::protection::protect(process, std::process::id(), &relations, process.uid);
    let (owner_reports_active, _) = evidence::client_work_to_fields(&idle);
    let approval = crate::policy::decide(
        &crate::policy::Policy::default(),
        &protection,
        process,
        &crate::policy::Signals {
            owner_reports_active: owner_reports_active.map(|idle| !idle),
            proven_abandoned: evidence::proven(&ev),
            needs_tolerance: false,
            memory_pressure: false,
            client_coverage: crate::client_tracker::Coverage::CompleteVerified,
        },
    );
    if !matches!(approval, crate::policy::Decision::GraceCandidate { .. }) {
        eprintln!("lab close refused: recomputed policy approval={approval:?}");
        return Err(io::Error::other(format!(
            "recomputed policy did not approve close: {approval:?}"
        )));
    }
    eprintln!("lab close gate approved: proven evidence and recomputed policy");
    let record = LabRecord {
        pid: entry.pid,
        start_ticks: entry.start_ticks,
        spawned_at: entry.spawned_at,
    };
    let mut receipts = terminate::close_sequence(
        &record,
        &ClosePolicy {
            grace_secs: grace.as_secs(),
            term_wait_secs: 1,
            allow_sigkill: false,
        },
        true,
        &mut terminate::PidfdSignaller,
        |pid, ticks, spawned| {
            crate::lab::registry_contains(&crate::lab::Entry {
                pid,
                start_ticks: ticks,
                spawned_at: spawned,
            })
            .unwrap_or(false)
                && crate::lab::identity_ticks(pid).ok() == Some(ticks)
        },
        thread::sleep,
        || "lab autonomous official-close attempt: unavailable".into(),
    );
    stages.push(Stage::SafeClose);
    let exited = child.child.try_wait()?.is_some();
    if exited {
        let _ = child.child.wait()?;
    }
    let gone = exited || crate::lab::identity_ticks(entry.pid).ok() != Some(entry.start_ticks);
    if !gone {
        // On platforms where TERM cannot be observed promptly, retain a truthful
        // dry-run-style result and never escalate beyond the existing policy.
        receipts.push("confirm reap: matching process remains".into());
        return Err(io::Error::other(format!(
            "registered lab process remained after close: {receipts:?}"
        )));
    }
    stages.extend([Stage::TerminationConfirmed, Stage::AuditLogged]);
    receipts.push(format!(
        "lab-cycle.audit pid={} start_ticks={} outcome=closed",
        entry.pid, entry.start_ticks
    ));
    crate::lab::persist_close_receipt(&child.entry, &receipts, "closed")?;
    Ok(CycleReport {
        outcome: Outcome::Closed,
        stages,
        receipts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_cycle_branches_only_use_registered_lab_children() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!("reaper-autonomy-{}.json", std::process::id())),
        );
        let mut child = crate::lab::spawn(false).unwrap();
        let entry = child.entry.clone();
        let cancelled = run_lab_cycle(&mut child, Duration::from_millis(5), true).unwrap();
        assert_eq!(cancelled.outcome, Outcome::Cancelled);
        assert!(crate::lab::identity_ticks(entry.pid).is_ok());
        let closed = run_lab_cycle(&mut child, Duration::from_millis(5), false).unwrap();
        assert_eq!(closed.outcome, Outcome::Closed);
        assert!(closed.receipts.iter().any(|r| r.contains("audit")));
        let receipt_path = crate::lab::receipt_path_current();
        let persisted = std::fs::read_to_string(receipt_path).unwrap();
        assert!(persisted.contains(&format!("\"pid\":{}", entry.pid)));
        assert!(persisted.contains(&format!("\"start_ticks\":{}", entry.start_ticks)));
        assert!(persisted.contains("\"verdict\":\"closed\""));
        assert!(persisted.contains("\"scope\":\"reaper-lab\""));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(crate::lab::receipt_path_current())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(child);
        assert_ne!(
            crate::lab::identity_ticks(entry.pid).ok(),
            Some(entry.start_ticks)
        );
    }

    #[test]
    fn unknown_work_observation_blocks_before_grace() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!(
                "reaper-autonomy-unknown-{}.json",
                std::process::id()
            )),
        );
        let mut child = crate::lab::spawn(false).unwrap();
        let result = run_lab_cycle_with_work(
            &mut child,
            Duration::from_millis(1),
            false,
            crate::evidence::ClientWorkState::Unknown {
                missing: vec!["query".into()],
            },
        );
        assert!(result.is_err());
        assert!(crate::lab::identity_ticks(child.id()).is_ok());
    }
}
