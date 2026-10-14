//! Short-grace autonomous lifecycle exercised only against registered lab children.
#![allow(dead_code)] // This lab driver is intentionally not wired into production CLI.
use std::{io, thread, time::Duration};

struct CloseInputs {
    process: crate::procfs::Process,
    relations: crate::relations::Relations,
    owner: crate::owner::OwnerVerdict,
    owner_active: Option<bool>,
    client_work: crate::evidence::ClientWorkState,
    coverage: crate::client_tracker::Coverage,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RestartAction {
    Revalidate,
}

/// Uses the same live readers and conservative mappings as `Observer::cycle`.
fn fresh_close_inputs(entry: &crate::lab::Entry) -> io::Result<CloseInputs> {
    let scan = crate::procfs::scan();
    let process = scan
        .processes
        .iter()
        .find(|process| process.pid == entry.pid && process.start_ticks == entry.start_ticks)
        .cloned()
        .ok_or_else(|| io::Error::other("target missing from fresh process scan"))?;
    let relations = crate::relations::build(&scan.processes);
    let claims = crate::owner::claims_map(&crate::owner::default_svdir());
    let owner = crate::owner::resolve(&claims, &process);
    let id = crate::identity::identify(&process, crate::identity::read_boot_id());
    let adapter = crate::adapter_for(&process.name, &process.command);
    let owner_active = match &owner {
        crate::owner::OwnerVerdict::ClaimedActive { .. } => Some(true),
        crate::owner::OwnerVerdict::ClaimedDown { .. } => Some(false),
        crate::owner::OwnerVerdict::Unclaimed => crate::liveness_to_signal(adapter.liveness(&id)),
    };
    let registry_result = crate::client_tracker::current_registry();
    let coverage = crate::client_tracker::registry_coverage(&registry_result);
    let mut registry = registry_result?;
    crate::client_tracker::discard_stale(&mut registry);
    let boot_id = crate::identity::read_boot_id().unwrap_or_default();
    let managed = registry.clients.iter().find(|record| {
        record.identity.pid == entry.pid
            && record.identity.start_ticks == entry.start_ticks
            && record.identity.boot_id == boot_id
    });
    let unknown_external = crate::client_tracker::ClientState::UnknownExternal {
        evidence: "coverage is incomplete".into(),
        provenance: "managed-only registry; external client roster unavailable".into(),
    };
    let managed_state = managed
        .map(|record| &record.state)
        .unwrap_or(&unknown_external);
    let tracker_active = crate::client_tracker::tracker_signal(
        managed_state,
        managed.is_some_and(|record| !record.active_work_ids.is_empty()),
    );
    let owner_active = crate::client_tracker::combine_signals(owner_active, tracker_active);
    let client_work = if adapter.name() == "opencode" {
        crate::adapters::OpenCodeProbe {
            base_url: None,
            password: None,
        }
        .assess_fast()
    } else {
        crate::evidence::ClientWorkState::Unknown {
            missing: vec!["adapter client/work evidence unavailable".into()],
        }
    };
    Ok(CloseInputs {
        process,
        relations,
        owner,
        owner_active,
        client_work,
        coverage,
    })
}

fn final_close_gate(
    entry: &crate::lab::Entry,
    inputs: &CloseInputs,
    grace_elapsed: bool,
) -> io::Result<()> {
    let refuse = |reason: String| -> io::Result<()> {
        eprintln!("lab close refused: {reason}");
        crate::lab::persist_close_receipt(entry, &[format!("gate refused: {reason}")], &reason)?;
        Err(io::Error::other(reason))
    };
    if !grace_elapsed {
        return refuse("grace has not elapsed".into());
    }
    let registered = match crate::lab::registry_contains(entry) {
        Ok(registered) => registered,
        Err(error) => return refuse(format!("lab registry revalidation unavailable: {error}")),
    };
    if !registered {
        return refuse("target is not lab-registered".into());
    }
    let identity_matches = inputs.process.pid == entry.pid
        && inputs.process.start_ticks == entry.start_ticks
        && crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks);
    if !identity_matches {
        return refuse("stable process identity revalidation failed".into());
    }
    let (last_client_gone, no_pending_work) =
        crate::evidence::client_work_to_fields(&inputs.client_work);
    let evidence = crate::evidence::AbandonEvidence {
        lab_member: true,
        owner: inputs.owner.clone(),
        grace_expired: true,
        revalidated_now: true,
        owner_dead: inputs.owner_active.map(|active| !active),
        last_client_gone,
        no_pending_work,
    };
    if !crate::evidence::proven(&evidence) {
        return refuse(format!(
            "fresh abandonment evidence is unproven: {evidence:?}"
        ));
    }
    let work_activity = match inputs.client_work {
        crate::evidence::ClientWorkState::Active { .. } => Some(true),
        crate::evidence::ClientWorkState::IdleVerified { .. } => Some(false),
        crate::evidence::ClientWorkState::Unknown { .. }
        | crate::evidence::ClientWorkState::Error { .. }
        | crate::evidence::ClientWorkState::WorkAbsent { .. } => None,
    };
    let signals = crate::policy::Signals {
        owner_reports_active: inputs.owner_active,
        proven_abandoned: crate::evidence::proven(&evidence),
        needs_tolerance: false,
        memory_pressure: false,
        client_coverage: inputs.coverage,
    };
    let id = crate::identity::identify(&inputs.process, crate::identity::read_boot_id());
    let base = crate::protection::protect(
        &inputs.process,
        std::process::id(),
        &inputs.relations,
        inputs.process.uid,
    );
    let positively_verified_inactive = matches!(
        inputs.client_work,
        crate::evidence::ClientWorkState::IdleVerified { .. }
    ) && inputs.coverage
        == crate::client_tracker::Coverage::CompleteVerified
        && inputs.owner_active == Some(false);
    let work_signal = crate::client_tracker::combine_signals(inputs.owner_active, work_activity);
    let (_, _, approval) = crate::classified_decision(
        &inputs.process,
        &id,
        &inputs.relations,
        &inputs.owner,
        work_signal,
        positively_verified_inactive,
        base,
        &crate::policy::Policy::default(),
        &signals,
        &[],
    );
    if !matches!(approval, crate::policy::Decision::GraceCandidate { .. }) {
        return refuse(format!("recomputed policy refused close: {approval:?}"));
    }
    Ok(())
}

fn interrupted_close_action(entry: &crate::lab::Entry) -> io::Result<Option<RestartAction>> {
    let content = match std::fs::read_to_string(crate::lab::receipt_path_current()) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let pid = format!("\"pid\":{}", entry.pid);
    let ticks = format!("\"start_ticks\":{}", entry.start_ticks);
    let interrupted = content.lines().any(|line| {
        line.contains(&pid)
            && line.contains(&ticks)
            && (line.contains("\"in_progress\"") || line.contains("\"term_sent\""))
    });
    Ok(interrupted.then_some(RestartAction::Revalidate))
}

/// Connects persisted READY_FOR_REVALIDATION entries to the guarded close path.
pub fn close_ready_entry(entry: &crate::lab::Entry) -> io::Result<Vec<String>> {
    use crate::terminate::{self, ClosePolicy, LabRecord};
    if interrupted_close_action(entry)?.is_some() {
        eprintln!("lab close restart: persisted marker resumes only at fresh revalidation");
    }
    let inputs = fresh_close_inputs(entry).map_err(|error| {
        let reason = format!("fresh final-gate evidence unavailable: {error}");
        eprintln!("lab close refused: {reason}");
        let _ =
            crate::lab::persist_close_receipt(entry, &["fresh_evidence:refused".into()], &reason);
        io::Error::other(reason)
    })?;
    final_close_gate(entry, &inputs, true)?;
    crate::lab::persist_close_receipt(entry, &["close_initiated".into()], "in_progress")?;
    let record = LabRecord {
        pid: entry.pid,
        start_ticks: entry.start_ticks,
        spawned_at: entry.spawned_at,
    };
    let mut signaller = terminate::PidfdSignaller;
    let receipts = terminate::close_sequence(
        &record,
        &ClosePolicy {
            grace_secs: 0,
            term_wait_secs: 1,
            allow_sigkill: false,
        },
        true,
        &mut signaller,
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
        || {
            let adapter = crate::adapter_for(&inputs.process.name, &inputs.process.command);
            format!(
                "official-close skipped/attempted: {:?}",
                adapter.request_official_shutdown(&crate::identity::identify(
                    &inputs.process,
                    crate::identity::read_boot_id()
                ))
            )
        },
    );
    if crate::lab::identity_ticks(entry.pid).ok() == Some(entry.start_ticks) {
        let reason = "termination not confirmed; SIGKILL not authorized";
        crate::lab::persist_close_receipt(entry, &receipts, reason)?;
        return Err(io::Error::other(reason));
    }
    crate::lab::persist_close_receipt(entry, &receipts, "closed")?;
    Ok(receipts)
}

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
        fresh_close_inputs,
    )
}

fn run_lab_cycle_with_work<F>(
    child: &mut crate::lab::LabChild,
    grace: Duration,
    activity_returns: bool,
    idle: crate::evidence::ClientWorkState,
    mut observe_close: F,
) -> io::Result<CycleReport>
where
    F: FnMut(&crate::lab::Entry) -> io::Result<CloseInputs>,
{
    use crate::{
        evidence::{self, ClientWorkState},
        terminate::{self, ClosePolicy, LabRecord},
    };

    let entry = &child.entry;
    let mut stages = vec![Stage::ServiceDetected];
    if interrupted_close_action(entry)?.is_some() {
        eprintln!("lab close restart: prior close marker requires full grace and revalidation");
    }
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
    let (last_client_gone, _no_pending_work) = evidence::client_work_to_fields(&idle);
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
    let fresh = observe_close(entry).map_err(|error| {
        let reason = format!("fresh final-gate evidence unavailable: {error}");
        eprintln!("lab close refused: {reason}");
        let _ =
            crate::lab::persist_close_receipt(entry, &["fresh_evidence:refused".into()], &reason);
        io::Error::other(reason)
    })?;
    final_close_gate(entry, &fresh, true)?;
    eprintln!("lab close gate approved: proven evidence and recomputed policy");
    crate::lab::persist_close_receipt(entry, &["close_initiated".into()], "in_progress")?;
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
        || "official-close skipped: no supported shutdown adapter for lab sleeper".into(),
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
    fn verified_lab_inputs(entry: &crate::lab::Entry) -> io::Result<CloseInputs> {
        let scan = crate::procfs::scan();
        let process = scan
            .processes
            .iter()
            .find(|process| process.pid == entry.pid && process.start_ticks == entry.start_ticks)
            .cloned()
            .ok_or_else(|| io::Error::other("lab test process not found"))?;
        Ok(CloseInputs {
            process,
            relations: crate::relations::build(&scan.processes),
            owner: crate::owner::OwnerVerdict::Unclaimed,
            owner_active: Some(false),
            client_work: crate::evidence::ClientWorkState::IdleVerified {
                surfaces: vec!["test-controlled lab client roster".into()],
            },
            coverage: crate::client_tracker::Coverage::CompleteVerified,
        })
    }
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
        let closed = run_lab_cycle_with_work(
            &mut child,
            Duration::from_millis(5),
            false,
            crate::evidence::ClientWorkState::IdleVerified {
                surfaces: vec!["initial test observation".into()],
            },
            verified_lab_inputs,
        )
        .unwrap();
        assert_eq!(closed.outcome, Outcome::Closed);
        assert!(closed.receipts.iter().any(|r| r.contains("audit")));
        assert!(closed
            .receipts
            .iter()
            .any(|r| { r.contains("official-first: official-close skipped") }));
        assert!(closed.receipts.iter().any(|r| r.starts_with("TERM:")));
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
            fresh_close_inputs,
        );
        assert!(result.is_err());
        assert!(crate::lab::identity_ticks(child.id()).is_ok());
    }

    #[test]
    fn stale_injected_work_refuses_and_persists_the_refusal_reason() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!(
                "reaper-autonomy-refusal-{}.json",
                std::process::id()
            )),
        );
        let child = crate::lab::spawn(false).unwrap();
        let scan = crate::procfs::scan();
        let process = scan
            .processes
            .iter()
            .find(|process| process.pid == child.id())
            .unwrap()
            .clone();
        let inputs = CloseInputs {
            process,
            relations: crate::relations::build(&scan.processes),
            owner: crate::owner::OwnerVerdict::Unclaimed,
            owner_active: Some(false),
            client_work: crate::evidence::ClientWorkState::Unknown {
                missing: vec!["deliberately stale input".into()],
            },
            coverage: crate::client_tracker::Coverage::Unknown,
        };
        assert!(final_close_gate(&child.entry, &inputs, true).is_err());
        let receipt = std::fs::read_to_string(crate::lab::receipt_path_current()).unwrap();
        assert!(receipt.contains("\"reason\":\""));
        assert!(receipt.contains("fresh abandonment evidence is unproven"));
        drop(child);
    }

    #[test]
    fn refusal_matrix_persists_policy_grace_scope_identity_and_evidence_reasons() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!(
                "reaper-autonomy-matrix-{}.json",
                std::process::id()
            )),
        );
        let child = crate::lab::spawn(false).unwrap();
        let entry = child.entry.clone();

        let good = verified_lab_inputs(&entry).unwrap();
        assert!(final_close_gate(&entry, &good, false).is_err());

        let mut policy_blocked = verified_lab_inputs(&entry).unwrap();
        policy_blocked.coverage = crate::client_tracker::Coverage::Unknown;
        assert!(final_close_gate(&entry, &policy_blocked, true).is_err());

        let mut stale = verified_lab_inputs(&entry).unwrap();
        stale.process.start_ticks = stale.process.start_ticks.wrapping_add(1);
        assert!(final_close_gate(&entry, &stale, true).is_err());

        let mut unavailable = verified_lab_inputs(&entry).unwrap();
        unavailable.client_work = crate::evidence::ClientWorkState::Unknown {
            missing: vec!["fresh work query unavailable".into()],
        };
        assert!(final_close_gate(&entry, &unavailable, true).is_err());

        let mut foreign = entry.clone();
        foreign.pid = foreign.pid.saturating_add(1);
        assert!(final_close_gate(&foreign, &good, true).is_err());

        let receipts = std::fs::read_to_string(crate::lab::receipt_path_current()).unwrap();
        for reason in [
            "grace has not elapsed",
            "recomputed policy refused close",
            "stable process identity revalidation failed",
            "fresh abandonment evidence is unproven",
            "target is not lab-registered",
        ] {
            assert!(
                receipts.contains(reason),
                "missing receipt for {reason}: {receipts}"
            );
        }
        drop(child);
    }

    #[test]
    fn fabricated_mid_close_receipt_only_resumes_at_revalidation() {
        let _guard = crate::lab::TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "REAPER_LAB_REGISTRY",
            std::env::temp_dir().join(format!(
                "reaper-autonomy-restart-{}.json",
                std::process::id()
            )),
        );
        let child = crate::lab::spawn(false).unwrap();
        crate::lab::persist_close_receipt(&child.entry, &["term_sent".into()], "in_progress")
            .unwrap();
        assert_eq!(
            interrupted_close_action(&child.entry).unwrap(),
            Some(RestartAction::Revalidate)
        );
        let fresh = verified_lab_inputs(&child.entry).unwrap();
        assert!(final_close_gate(&child.entry, &fresh, true).is_ok());
        drop(child);
    }
}
