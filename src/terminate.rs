//! Auditable close planning. Signals are available only through the lab close
//! sequence after registry membership and process identity are revalidated.
use std::time::Duration;

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
        if let Ok(fd) = crate::pidfd::open(record.pid) {
            if crate::lab::identity_ticks(record.pid).ok() != Some(record.start_ticks) {
                let _ = crate::pidfd::close(fd);
                return Err(Refusal::IdentityChanged);
            }
            let result = crate::pidfd::send_empty(fd, sig);
            let _ = crate::pidfd::close(fd);
            return result
                .map(|_| SignalReceipt {
                    path: SignalPath::Pidfd,
                    signal,
                })
                .map_err(|e| Refusal::SignalFailed(e.to_string()));
        }
        if crate::lab::identity_ticks(record.pid).ok() != Some(record.start_ticks) {
            return Err(Refusal::IdentityChanged);
        }
        if crate::lab::identity_ticks(record.pid).ok() != Some(record.start_ticks) {
            return Err(Refusal::IdentityChanged);
        }
        unsafe { signal_classic(record.pid, sig) }
            .map(|_| SignalReceipt {
                path: SignalPath::Classic,
                signal,
            })
            .map_err(|e| Refusal::SignalFailed(e.to_string()))
    }
}

/// The injected check combines registry membership with process identity and
/// is run immediately before each signal.
pub fn close_sequence<S, F, W, O>(
    record: &LabRecord,
    policy: &ClosePolicy,
    act: bool,
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
    if !act {
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
    }
    receipts.push(format!("official-first: {}", official()));
    if !verified(record.pid, record.start_ticks, record.spawned_at) {
        receipts.push("revalidate before TERM: lab membership or identity failed; aborted".into());
        return receipts;
    }
    receipts.push("revalidate before TERM: registry membership and identity match".into());
    match signaller.signal_record(record, SignalKind::Term) {
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
    match signaller.signal_record(record, SignalKind::Kill) {
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
    ) -> Result<SignalReceipt, Refusal>;
}
impl SignalExecutor for PidfdSignaller {
    fn signal_record(
        &mut self,
        record: &LabRecord,
        signal: SignalKind,
    ) -> Result<SignalReceipt, Refusal> {
        self.signal(record, signal)
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
    #[derive(Default)]
    struct FakeExecutor {
        calls: Vec<SignalKind>,
    }
    impl SignalExecutor for FakeExecutor {
        fn signal_record(
            &mut self,
            _: &LabRecord,
            signal: SignalKind,
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
            false,
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
            true,
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
            true,
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
            true,
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
            true,
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
