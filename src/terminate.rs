//! Auditable close planning. Signals are available only through the lab close
//! sequence after registry membership and process identity are revalidated.
use std::{fs, time::Duration};

#[derive(Debug, Clone)]
pub struct FreshApprovalInputs {
    pub evidence: crate::evidence::AbandonEvidence,
    pub process: crate::procfs::Process,
    pub protection: crate::protection::Protection,
    pub policy: crate::policy::Policy,
    pub signals: crate::policy::Signals,
}

#[derive(Debug)]
pub struct FreshApproval {
    pid: u32,
    start_ticks: u64,
    boot_id: String,
    uid: u32,
    executable: String,
    cmdline: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationScope {
    pub service_id: String,
    pub registry: String,
    pub project: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedAuthorization {
    pub scope: AuthorizationScope,
    pub fresh_approval_ref: String,
}

impl ScopedAuthorization {
    pub fn new(scope: AuthorizationScope, fresh_approval_ref: String) -> Self {
        Self {
            scope,
            fresh_approval_ref,
        }
    }

    pub fn authorizes(&self, requested: &AuthorizationScope) -> bool {
        !self.fresh_approval_ref.is_empty() && self.scope == *requested
    }
}

pub fn close_scope(service_id: &str, registry: &str, project: &str) -> AuthorizationScope {
    AuthorizationScope {
        service_id: service_id.to_owned(),
        registry: registry.to_owned(),
        project: project.to_owned(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessTuple {
    pid: u32,
    start_ticks: u64,
    boot_id: String,
    uid: u32,
    executable: String,
    cmdline: Vec<u8>,
}

fn read_process_tuple(pid: u32) -> std::io::Result<ProcessTuple> {
    let base = format!("/proc/{pid}");
    let status = fs::read_to_string(format!("{base}/status"))?;
    let uid = status
        .lines()
        .find_map(|line| {
            line.strip_prefix("Uid:")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .ok_or_else(|| std::io::Error::other("UID unavailable in /proc status"))?;
    let stat = fs::read_to_string(format!("{base}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| std::io::Error::other("malformed /proc stat"))?;
    let start_ticks = stat[close + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| std::io::Error::other("start ticks unavailable in /proc stat"))?
        .parse()
        .map_err(|_| std::io::Error::other("invalid start ticks in /proc stat"))?;
    let cmdline = fs::read(format!("{base}/cmdline"))?;
    if cmdline.is_empty() || cmdline.last() != Some(&0) {
        return Err(std::io::Error::other("empty /proc cmdline"));
    }
    let executable = fs::read_link(format!("{base}/exe"))?
        .to_string_lossy()
        .into_owned();
    if executable.is_empty() {
        return Err(std::io::Error::other("empty /proc exe"));
    }
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    if boot_id.is_empty() {
        return Err(std::io::Error::other("empty boot ID"));
    }
    Ok(ProcessTuple {
        pid,
        start_ticks,
        boot_id,
        uid,
        executable,
        cmdline,
    })
}

pub fn approve_fresh(inputs: FreshApprovalInputs) -> Option<FreshApproval> {
    if !crate::evidence::proven(&inputs.evidence) {
        return None;
    }
    let decision = crate::policy::decide(
        &inputs.policy,
        &inputs.protection,
        &inputs.process,
        &inputs.signals,
    );
    if !matches!(decision, crate::policy::Decision::GraceCandidate { .. }) {
        return None;
    }
    let tuple = match read_process_tuple(inputs.process.pid) {
        Ok(tuple) => tuple,
        Err(error) => {
            eprintln!("fresh approval refused: process identity unavailable: {error}");
            return None;
        }
    };
    if tuple.start_ticks != inputs.process.start_ticks
        || Some(tuple.uid) != inputs.process.uid
        || tuple.cmdline.split(|byte| *byte == 0).next() != Some(inputs.process.command.as_bytes())
    {
        eprintln!("fresh approval refused: process identity differs from supplied evidence");
        return None;
    }
    Some(FreshApproval {
        pid: tuple.pid,
        start_ticks: tuple.start_ticks,
        boot_id: tuple.boot_id,
        uid: tuple.uid,
        executable: tuple.executable,
        cmdline: tuple.cmdline,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosePolicy {
    pub grace_secs: u64,
    pub term_wait_secs: u64,
    pub allow_sigkill: bool,
}
impl Default for ClosePolicy {
    fn default() -> Self {
        Self {
            grace_secs: 300,
            term_wait_secs: 30,
            allow_sigkill: false,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabRecord {
    pub pid: u32,
    pub start_ticks: u64,
    pub spawned_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseStep {
    GraceArm {
        deadline: u64,
    },
    OfficialFirstAttempt,
    Term,
    Wait(Duration),
    Revalidate,
    Kill,
    #[allow(dead_code)]
    Cancelled,
}

pub struct PidfdSignaller;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalKind {
    Term,
    Kill,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalPath {
    Pidfd,
    Classic,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalReceipt {
    pub path: SignalPath,
    pub signal: SignalKind,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    NotRegistered,
    IdentityChanged,
    SignalFailed(String),
}
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}
unsafe fn signal_classic(pid: u32, sig: i32) -> std::io::Result<()> {
    if kill(pid as i32, sig) == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}
impl PidfdSignaller {
    pub fn signal(
        &mut self,
        record: &LabRecord,
        signal: SignalKind,
        expected: &FreshApproval,
    ) -> Result<SignalReceipt, Refusal> {
        let entry = crate::lab::Entry {
            pid: record.pid,
            start_ticks: record.start_ticks,
            spawned_at: record.spawned_at,
        };
        if !crate::lab::registry_contains(&entry)
            .map_err(|e| Refusal::SignalFailed(e.to_string()))?
        {
            return Err(Refusal::NotRegistered);
        }
        let sig = if signal == SignalKind::Term { 15 } else { 9 };
        let pidfd = crate::pidfd::open(record.pid).ok();
        let selected_path = signal_path(pidfd.is_some());
        if let Some(fd) = pidfd.filter(|_| selected_path == SignalPath::Pidfd) {
            if !tuple_matches(record.pid, record.start_ticks, expected) {
                let _ = crate::pidfd::close(fd);
                return Err(Refusal::IdentityChanged);
            }
            let result = crate::pidfd::send_empty(fd, sig);
            let _ = crate::pidfd::close(fd);
            return result
                .map(|_| SignalReceipt {
                    path: selected_path,
                    signal,
                })
                .map_err(|e| Refusal::SignalFailed(e.to_string()));
        }
        // Classic kill(pid) cannot atomically bind validation to delivery; PID
        // reuse between this full-tuple check and kill(2) is inherent. Prefer
        // pidfd whenever available, and fail closed if any tuple datum is absent.
        if !tuple_matches(record.pid, record.start_ticks, expected) {
            return Err(Refusal::IdentityChanged);
        }
        unsafe { signal_classic(record.pid, sig) }
            .map(|_| SignalReceipt {
                path: selected_path,
                signal,
            })
            .map_err(|e| Refusal::SignalFailed(e.to_string()))
    }
}

fn tuple_matches(pid: u32, ticks: u64, expected: &FreshApproval) -> bool {
    if crate::identity::verify_identity(pid, ticks, Some(expected.uid))
        != crate::identity::IdentityVerification::Verified
    {
        return false;
    }
    match read_process_tuple(pid) {
        Ok(actual) => {
            let matches = actual.pid == expected.pid
                && actual.start_ticks == ticks
                && actual.start_ticks == expected.start_ticks
                && actual.boot_id == expected.boot_id
                && actual.uid == expected.uid
                && actual.executable == expected.executable
                && actual.cmdline == expected.cmdline;
            if !matches {
                eprintln!("signal refused: full process identity tuple changed (pid/start/boot/uid/executable/cmdline)");
            }
            matches
        }
        Err(error) => {
            eprintln!("signal refused: full process identity unavailable: {error}");
            false
        }
    }
}

fn signal_path(pidfd_opened: bool) -> SignalPath {
    if pidfd_opened {
        SignalPath::Pidfd
    } else {
        SignalPath::Classic
    }
}

/// The injected check combines registry membership with process identity and
/// is run immediately before each signal.
pub fn close_sequence<S, F, W, O>(
    record: &LabRecord,
    policy: &ClosePolicy,
    approval: Option<&FreshApproval>,
    signaller: &mut S,
    mut verified: F,
    mut wait: W,
    mut official: O,
) -> Vec<String>
where
    S: SignalExecutor,
    F: FnMut(u32, u64, u64) -> bool,
    W: FnMut(Duration),
    O: FnMut() -> String,
{
    let mut receipts = Vec::new();
    let Some(approval) = approval else {
        receipts.push("official-first: not invoked in dry-run".into());
        receipts.extend([
            "TERM: dry-run".into(),
            format!("wait: {}s dry-run", policy.term_wait_secs),
            "revalidate: dry-run".into(),
            if policy.allow_sigkill {
                "KILL: dry-run".into()
            } else {
                "KILL: refused; not authorized".into()
            },
        ]);
        return receipts;
    };
    if approval.pid != record.pid || approval.start_ticks != record.start_ticks {
        eprintln!(
            "close refused: approval identity mismatch for target PID {}",
            record.pid
        );
        receipts.push("close refused: approval identity mismatch".into());
        return receipts;
    }
    receipts.push(format!("official-first: {}", official()));
    if !verified(record.pid, record.start_ticks, record.spawned_at) {
        receipts.push("revalidate before TERM: lab membership or identity failed; aborted".into());
        return receipts;
    }
    receipts.push("revalidate before TERM: registry membership and identity match".into());
    match signaller.signal_record(record, SignalKind::Term, approval) {
        Ok(r) => receipts.push(format!("TERM: {r:?}")),
        Err(e) => {
            receipts.push(format!("TERM refused: {e:?}"));
            return receipts;
        }
    }
    wait(Duration::from_secs(policy.term_wait_secs));
    receipts.push(format!("wait: {}s complete", policy.term_wait_secs));
    if !verified(record.pid, record.start_ticks, record.spawned_at) {
        receipts.push("revalidate: lab membership or identity failed; aborted".into());
        return receipts;
    }
    receipts.push("revalidate: registry membership and identity match".into());
    if !policy.allow_sigkill {
        receipts.push("KILL refused: not authorized".into());
        return receipts;
    }
    match signaller.signal_record(record, SignalKind::Kill, approval) {
        Ok(r) => receipts.push(format!("KILL: {r:?}")),
        Err(e) => {
            receipts.push(format!("KILL refused: {e:?}"));
            return receipts;
        }
    }
    if verified(record.pid, record.start_ticks, record.spawned_at) {
        receipts
            .push("confirm reap: matching process remains (may be zombie awaiting reap)".into());
    } else {
        receipts.push("confirm reap: process gone or identity/registry changed".into());
    }
    receipts
}

pub trait SignalExecutor {
    fn signal_record(
        &mut self,
        record: &LabRecord,
        signal: SignalKind,
        approval: &FreshApproval,
    ) -> Result<SignalReceipt, Refusal>;
}
impl SignalExecutor for PidfdSignaller {
    fn signal_record(
        &mut self,
        record: &LabRecord,
        signal: SignalKind,
        approval: &FreshApproval,
    ) -> Result<SignalReceipt, Refusal> {
        self.signal(record, signal, approval)
    }
}
#[cfg(test)]
pub(crate) fn test_approval(pid: u32, start_ticks: u64) -> FreshApproval {
    // Test-only bypass for fake executors; production exposes no token constructor.
    FreshApproval {
        pid,
        start_ticks,
        boot_id: String::new(),
        uid: 0,
        executable: String::new(),
        cmdline: Vec::new(),
    }
}
// Dry-run never calls SignalExecutor; no raw-PID signalling API is exposed.

#[allow(dead_code)]
pub fn plan_close(record: &LabRecord, owner_verdict: Option<bool>, now: u64) -> Vec<CloseStep> {
    let mut plan = plan_close_with(&ClosePolicy::default(), record, owner_verdict, now);
    if rescue_cancels(owner_verdict) {
        plan.push(CloseStep::Cancelled);
    }
    plan
}
pub fn plan_close_with(
    policy: &ClosePolicy,
    record: &LabRecord,
    owner_verdict: Option<bool>,
    now: u64,
) -> Vec<CloseStep> {
    if owner_verdict != Some(false) {
        return Vec::new();
    }
    let deadline = record.spawned_at.saturating_add(policy.grace_secs);
    let mut steps = vec![CloseStep::GraceArm { deadline }];
    if now < deadline {
        return steps;
    }
    steps.push(CloseStep::OfficialFirstAttempt);
    steps.push(CloseStep::Term);
    steps.push(CloseStep::Wait(Duration::from_secs(policy.term_wait_secs)));
    steps.push(CloseStep::Revalidate);
    if policy.allow_sigkill {
        steps.push(CloseStep::Kill);
    }
    steps
}
/// An owner becoming active during the grace period always cancels.
pub fn rescue_cancels(owner_verdict: Option<bool>) -> bool {
    owner_verdict == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn close_authorization_scope_is_exact_and_service_bound() {
        let a = AuthorizationScope {
            service_id: "service-A".into(),
            registry: "registry".into(),
            project: "project".into(),
        };
        let b = AuthorizationScope {
            service_id: "service-B".into(),
            registry: "registry".into(),
            project: "project".into(),
        };
        let authorization = ScopedAuthorization::new(a.clone(), "approval-1".into());
        assert!(authorization.authorizes(&a));
        assert!(!authorization.authorizes(&b));
    }
    #[test]
    fn fresh_approval_requires_proven_evidence_and_eligible_policy_decision() {
        let observed = read_process_tuple(std::process::id()).unwrap();
        let process = crate::procfs::Process {
            pid: observed.pid,
            ppid: 1,
            pgrp: observed.pid,
            session: observed.pid,
            start_ticks: observed.start_ticks,
            state: 'S',
            name: "svc".into(),
            command: String::from_utf8_lossy(
                observed.cmdline.split(|byte| *byte == 0).next().unwrap(),
            )
            .into_owned(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(observed.uid),
        };
        let inputs = || FreshApprovalInputs {
            evidence: crate::evidence::AbandonEvidence {
                lab_member: true,
                owner: crate::owner::OwnerVerdict::Unclaimed,
                grace_expired: true,
                revalidated_now: true,
                owner_dead: Some(true),
                last_client_gone: Some(true),
                no_pending_work: Some(true),
            },
            process: process.clone(),
            protection: crate::protection::Protection {
                tier: crate::protection::Tier::Known,
                reason: "test".into(),
            },
            policy: crate::policy::Policy::default(),
            signals: crate::policy::Signals {
                owner_reports_active: Some(false),
                proven_abandoned: true,
                needs_tolerance: false,
                memory_pressure: false,
                client_coverage: crate::client_tracker::Coverage::CompleteVerified,
            },
        };
        assert!(approve_fresh(inputs()).is_some());
        let mut wrong_cmdline = inputs();
        wrong_cmdline.process.command.push_str("-mismatch");
        assert!(approve_fresh(wrong_cmdline).is_none());
        let mut stale = inputs();
        stale.evidence.revalidated_now = false;
        assert!(approve_fresh(stale).is_none());
        let mut protected = inputs();
        protected.protection.tier = crate::protection::Tier::Absolute;
        assert!(approve_fresh(protected).is_none());
    }
    #[test]
    fn signal_path_prefers_pidfd_and_uses_classic_only_as_fallback() {
        assert_eq!(signal_path(true), SignalPath::Pidfd);
        assert_eq!(signal_path(false), SignalPath::Classic);
    }
    #[test]
    fn approval_bound_to_different_process_refuses_before_official_shutdown() {
        let mut executor = FakeExecutor::default();
        let mut official_called = false;
        let receipts = close_sequence(
            &LabRecord {
                pid: 7,
                start_ticks: 9,
                spawned_at: 0,
            },
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 0,
                allow_sigkill: true,
            },
            Some(&test_approval(8, 10)),
            &mut executor,
            |_, _, _| true,
            |_| {},
            || {
                official_called = true;
                "called".into()
            },
        );
        assert!(!official_called);
        assert!(executor.calls.is_empty());
        assert!(receipts
            .iter()
            .any(|receipt| receipt.contains("approval identity mismatch")));
    }
    #[derive(Default)]
    struct FakeExecutor {
        calls: Vec<SignalKind>,
    }
    impl SignalExecutor for FakeExecutor {
        fn signal_record(
            &mut self,
            _: &LabRecord,
            signal: SignalKind,
            _: &FreshApproval,
        ) -> Result<SignalReceipt, Refusal> {
            self.calls.push(signal);
            Ok(SignalReceipt {
                path: SignalPath::Classic,
                signal,
            })
        }
    }
    #[test]
    fn dry_run_records_whole_sequence_without_signals() {
        let mut s = FakeExecutor::default();
        let steps = close_sequence(
            &LabRecord {
                pid: 7,
                start_ticks: 9,
                spawned_at: 0,
            },
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 2,
                allow_sigkill: true,
            },
            None,
            &mut s,
            |_, _, _| panic!("dry run revalidated"),
            |_| panic!("dry run waited"),
            || "test outcome".into(),
        );
        assert!(
            steps.iter().any(|s| s.starts_with("official-first"))
                && steps.iter().any(|s| s.starts_with("TERM:"))
                && steps.iter().any(|s| s.starts_with("wait:"))
                && steps.iter().any(|s| s.starts_with("revalidate:"))
                && steps.iter().any(|s| s.starts_with("KILL:"))
        );
        assert!(s.calls.is_empty());
    }
    #[test]
    fn unregistered_pid_aborts_before_signals() {
        let mut s = FakeExecutor::default();
        let out = close_sequence(
            &LabRecord {
                pid: 7,
                start_ticks: 9,
                spawned_at: 0,
            },
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 0,
                allow_sigkill: true,
            },
            Some(&test_approval(7, 9)),
            &mut s,
            |_, _, _| false,
            |_| panic!("must not wait"),
            || "test outcome".into(),
        );
        assert!(out
            .iter()
            .any(|x| x.contains("membership or identity failed")));
        assert!(s.calls.is_empty());
    }
    #[test]
    fn recycled_identity_aborts_before_signals() {
        let mut s = FakeExecutor::default();
        let r = LabRecord {
            pid: 7,
            start_ticks: 9,
            spawned_at: 0,
        };
        let out = close_sequence(
            &r,
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 0,
                allow_sigkill: true,
            },
            Some(&test_approval(7, 9)),
            &mut s,
            |_, _, _| false,
            |_| {},
            || "test outcome".into(),
        );
        assert!(out
            .iter()
            .any(|x| x.contains("membership or identity failed")));
        assert!(s.calls.is_empty());
    }
    #[test]
    fn term_survival_kills_only_when_authorized() {
        let mut s = FakeExecutor::default();
        let r = LabRecord {
            pid: 7,
            start_ticks: 9,
            spawned_at: 0,
        };
        let out = close_sequence(
            &r,
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 0,
                allow_sigkill: true,
            },
            Some(&test_approval(7, 9)),
            &mut s,
            |_, _, _| true,
            |_| {},
            || "test outcome".into(),
        );
        assert_eq!(s.calls, [SignalKind::Term, SignalKind::Kill]);
        assert!(out.iter().any(|x| x.contains("confirm reap")));
        let mut s = FakeExecutor::default();
        close_sequence(
            &r,
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 0,
                allow_sigkill: false,
            },
            Some(&test_approval(7, 9)),
            &mut s,
            |_, _, _| true,
            |_| {},
            || "test outcome".into(),
        );
        assert_eq!(s.calls, [SignalKind::Term]);
    }
    #[test]
    fn rescue_during_grace_cancels() {
        assert!(rescue_cancels(Some(true)));
        assert!(!rescue_cancels(Some(false)));
    }
    #[test]
    fn public_plan_records_rescue_cancellation() {
        assert!(plan_close(
            &LabRecord {
                pid: 1,
                start_ticks: 1,
                spawned_at: 0
            },
            Some(true),
            500
        )
        .contains(&CloseStep::Cancelled));
    }
    #[test]
    fn kill_requires_explicit_authorization() {
        let r = LabRecord {
            pid: 1,
            start_ticks: 2,
            spawned_at: 0,
        };
        let steps = plan_close_with(
            &ClosePolicy {
                grace_secs: 0,
                term_wait_secs: 1,
                allow_sigkill: false,
            },
            &r,
            Some(false),
            10,
        );
        assert!(!steps.contains(&CloseStep::Kill));
    }
}
