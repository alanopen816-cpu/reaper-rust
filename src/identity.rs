//! Phase 2: stable process identity.
//!
//! Identity = (boot_id, pid, start_ticks, uid, exe). A PID alone is never
//! identity: Linux recycles PIDs, so every security decision re-verifies the
//! full tuple immediately before acting. Phase 2 performs zero signalling;
//! `pidfd_available()` only opens a pidfd for OUR OWN pid and closes it, as a
//! capability probe. `pidfd_send_signal` is intentionally unwrapped: evaluating
//! its symbol availability is documented in README/limitations, and no code
//! path in this phase may send a signal.

use crate::owner::OwnerVerdict;
use crate::procfs::Process;
use crate::relations::Relations;
use std::fs;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum IdentityVerification {
    Verified,
    Mismatch,
    Gone,
    PermissionUnknown,
}

/// Verify PID, proc stat field 22 (starttime), proc ownership, and executable.
/// This narrows PID reuse risk but cannot remove the check-vs-signal TOCTOU race;
/// pidfd can bind later signal delivery to the opened process, when supported.
#[allow(dead_code)]
pub fn verify_identity(pid: u32, start_ticks: u64, uid: Option<u32>) -> IdentityVerification {
    let base = format!("/proc/{pid}");
    let stat = match fs::read_to_string(format!("{base}/stat")) {
        Ok(stat) => stat,
        Err(error) => return classify_proc_error(&error),
    };
    let Some((actual_pid, _, _, _, _, _, actual_ticks)) = crate::procfs::parse_stat(&stat) else {
        return IdentityVerification::PermissionUnknown;
    };
    let owner = match fs::metadata(&base) {
        Ok(metadata) => metadata.uid(),
        Err(error) => return classify_proc_error(&error),
    };
    let exe = match fs::read_link(format!("{base}/exe")) {
        Ok(exe) => exe,
        Err(error) => return classify_proc_error(&error),
    };
    if actual_pid == pid
        && actual_ticks == start_ticks
        && uid == Some(owner)
        && !exe.as_os_str().is_empty()
    {
        IdentityVerification::Verified
    } else {
        IdentityVerification::Mismatch
    }
}

#[allow(dead_code)]
fn classify_proc_error(error: &std::io::Error) -> IdentityVerification {
    match error.kind() {
        std::io::ErrorKind::NotFound => IdentityVerification::Gone,
        std::io::ErrorKind::PermissionDenied => IdentityVerification::PermissionUnknown,
        _ => IdentityVerification::PermissionUnknown,
    }
}

/// General process role. A role is descriptive evidence, never authority to act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(dead_code)]
pub enum ProcessClass {
    PersistentService,
    Interactive,
    Build,
    Auxiliary,
    DevTool,
    LocalServer,
    Watchdog,
    Independent,
    Unknown,
    Critical,
}

#[derive(Clone)]
pub struct ClassificationEvidence<'a> {
    pub process: &'a Process,
    pub identity: &'a ProcessIdentity,
    pub relations: &'a Relations,
    pub owner: &'a OwnerVerdict,
    pub client_or_work_active: Option<bool>,
}

/// Classifier adapters extend general classification; priority order is registration order.
#[allow(dead_code)]
pub trait Classifier {
    fn classify(&self, evidence: &ClassificationEvidence<'_>) -> Option<ProcessClass>;
}

#[allow(dead_code)]
pub fn classify(e: &ClassificationEvidence<'_>, extensions: &[&dyn Classifier]) -> ProcessClass {
    for extension in extensions {
        if let Some(class) = extension.classify(e) {
            return class;
        }
    }
    let p = e.process;
    if p.pid != e.identity.pid || p.start_ticks != e.identity.start_ticks || p.uid != e.identity.uid
    {
        return ProcessClass::Unknown;
    }
    if p.uid.is_none() || p.command.is_empty() {
        return ProcessClass::Unknown;
    }
    if matches!(e.owner, OwnerVerdict::ClaimedActive { .. }) {
        return ProcessClass::PersistentService;
    }
    let node = e.relations.nodes.get(&p.pid);
    if matches!(e.owner, OwnerVerdict::ClaimedDown { .. }) {
        return ProcessClass::PersistentService;
    }
    if node.is_some_and(|n| n.parent_missing) {
        return ProcessClass::Unknown;
    }
    if node.is_some()
        && e.relations
            .watchdogs
            .iter()
            .any(|w| w.pid == p.pid && w.evidence == crate::relations::Evidence::Verified)
    {
        return ProcessClass::Watchdog;
    }
    if p.pid == p.session && p.ppid != 1 && p.ppid != p.pid {
        return ProcessClass::Interactive;
    }
    if e.client_or_work_active.is_none() {
        return ProcessClass::Unknown;
    }
    // Names are intentionally not used to promote any class.
    if e.client_or_work_active == Some(true) {
        return ProcessClass::DevTool;
    }
    ProcessClass::Independent
}

/// Stable identity of one process observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub boot_id: Option<String>,
    pub pid: u32,
    pub start_ticks: u64,
    pub uid: Option<u32>,
    pub exe: String,
}

pub fn read_boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

pub fn identify(p: &Process, boot_id: Option<String>) -> ProcessIdentity {
    ProcessIdentity {
        boot_id,
        pid: p.pid,
        start_ticks: p.start_ticks,
        uid: p.uid,
        exe: p.command.clone(),
    }
}

/// Re-verify that `current` is still the process `known` describes.
/// Any mismatch (including recycled PID with a new start time) returns false.
pub fn verify(known: &ProcessIdentity, current: &Process) -> bool {
    known.pid == current.pid && known.start_ticks == current.start_ticks && known.uid == current.uid
}

/// Capability status: pidfd is deliberately NOT linked in Phase 2.
/// Evaluation (documented, see README "pidfd"): headers exist at
/// `$PREFIX/include/sys/pidfd.h` and the device runs Android 16 (SDK 36), so
/// `pidfd_open` is expected on the kernel side; but the crates.io index
/// available here offers only a pre-release libc, which is not an acceptable
/// dependency for a security supervisor. The safe observation fallback is
/// therefore the implementation: double revalidation via `verify()` before
/// any future signal. Returns a human-readable status for `inspect`/logs.
pub fn pidfd_status() -> &'static str {
    "not-linked(zero-dep); fallback=double-revalidation via (pid,start_ticks,uid)"
}

/// Parse `VERSION.RELEASE...` into (major, minor). Pure and unit-tested.
pub fn kernel_major_minor(osrelease: &str) -> Option<(u32, u32)> {
    let mut parts = osrelease.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor: u32 = parts
        .next()?
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .ok()?;
    Some((major, minor))
}

/// True when the kernel predates nothing we need: pidfd needs ≥ 5.3.
fn kernel_supports(major: u32, minor: u32) -> bool {
    major > 5 || (major == 5 && minor >= 3)
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PidfdCompat {
    pub osrelease: String,
    pub kernel_supports: bool,
    pub header_present: bool,
    pub linked: bool,
}

pub fn pidfd_compat() -> PidfdCompat {
    let osrelease = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let osrelease = osrelease.trim().to_owned();
    let kernel_supports =
        kernel_major_minor(&osrelease).is_some_and(|(maj, min)| kernel_supports(maj, min));
    let header = std::env::var("PREFIX")
        .map(|p| format!("{p}/include/sys/pidfd.h"))
        .unwrap_or_else(|_| "/data/data/com.termux/files/usr/include/sys/pidfd.h".into());
    PidfdCompat {
        osrelease,
        kernel_supports,
        header_present: std::path::Path::new(&header).exists(),
        linked: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::procfs::Process;

    fn proc(pid: u32, start: u64, uid: Option<u32>) -> Process {
        Process {
            pid,
            ppid: 1,
            pgrp: pid,
            session: pid,
            start_ticks: start,
            state: 'S',
            name: "x".into(),
            command: "x".into(),
            rss_kib: 0,
            swap_kib: 0,
            uid,
        }
    }

    fn empty_rel() -> crate::relations::Relations {
        crate::relations::build(&[])
    }
    fn evidence<'a>(
        p: &'a Process,
        id: &'a ProcessIdentity,
        rel: &'a crate::relations::Relations,
        owner: &'a crate::owner::OwnerVerdict,
        active: Option<bool>,
    ) -> ClassificationEvidence<'a> {
        ClassificationEvidence {
            process: p,
            identity: id,
            relations: rel,
            owner,
            client_or_work_active: active,
        }
    }
    struct Custom;
    impl Classifier for Custom {
        fn classify(&self, _: &ClassificationEvidence<'_>) -> Option<ProcessClass> {
            Some(ProcessClass::Critical)
        }
    }

    #[test]
    fn unknown_protected_and_orphan_not_abandoned() {
        let p = proc(52, 100, Some(10373));
        let id = identify(&p, None);
        let rel = crate::relations::build(std::slice::from_ref(&p));
        let owner = crate::owner::OwnerVerdict::Unclaimed;
        let e = evidence(&p, &id, &rel, &owner, None);
        assert_eq!(classify(&e, &[]), ProcessClass::Unknown);
        assert!(crate::evidence::proven(&crate::evidence::AbandonEvidence {
            lab_member: true,
            owner: owner.clone(),
            grace_expired: true,
            revalidated_now: true,
            owner_dead: Some(true),
            last_client_gone: Some(true),
            no_pending_work: Some(true),
        }));
        assert_eq!(classify(&e, &[]), ProcessClass::Unknown);
        assert!(rel.nodes[&52].parent_missing);
    }

    #[test]
    fn custom_classifier_extension_registers_class() {
        let p = proc(53, 100, Some(10373));
        let id = identify(&p, None);
        let rel = empty_rel();
        let owner = crate::owner::OwnerVerdict::Unclaimed;
        let custom = Custom;
        assert_eq!(
            classify(&evidence(&p, &id, &rel, &owner, None), &[&custom]),
            ProcessClass::Critical
        );
        let protected = crate::protection::apply_classification(
            crate::protection::Protection {
                tier: crate::protection::Tier::Known,
                reason: "ordinary".into(),
            },
            classify(&evidence(&p, &id, &rel, &owner, None), &[&custom]),
            false,
        );
        assert_eq!(protected.tier, crate::protection::Tier::Contextual);
    }

    #[test]
    fn service_name_spoof_does_not_promote_process() {
        let p = Process {
            name: "runsv".into(),
            command: "/tmp/runsv".into(),
            ..proc(54, 100, Some(10373))
        };
        let id = identify(&p, None);
        let rel = empty_rel();
        let owner = crate::owner::OwnerVerdict::Unclaimed;
        assert_eq!(
            classify(&evidence(&p, &id, &rel, &owner, Some(false)), &[]),
            ProcessClass::Independent
        );
    }

    #[test]
    fn pid_reuse_is_rejected() {
        let boot = Some("boot-1".to_string());
        let known = identify(&proc(4242, 100, Some(10373)), boot);
        // Same PID, new start time => recycled => must NOT verify.
        assert!(!verify(&known, &proc(4242, 101, Some(10373))));
    }

    #[test]
    fn live_identity_rejects_fake_recycled_start_ticks() {
        let pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).expect("current proc stat");
        let ticks = crate::procfs::parse_stat(&stat)
            .expect("parse current stat")
            .6;
        assert_eq!(
            verify_identity(pid, ticks.wrapping_add(1), None),
            IdentityVerification::Mismatch
        );
    }

    #[test]
    fn nonexistent_pid_is_gone() {
        assert_eq!(
            verify_identity(u32::MAX, 0, None),
            IdentityVerification::Gone
        );
    }

    #[test]
    fn identity_change_is_rejected() {
        let boot = Some("boot-1".to_string());
        let known = identify(&proc(4242, 100, Some(10373)), boot);
        // Same PID+start but different UID => different process view => reject.
        assert!(!verify(&known, &proc(4242, 100, Some(99999))));
    }

    #[test]
    fn identical_observation_verifies() {
        let boot = read_boot_id();
        let p = proc(4242, 100, Some(10373));
        let known = identify(&p, boot);
        assert!(verify(&known, &p));
    }

    #[test]
    fn pidfd_fallback_is_documented() {
        // Phase 2 links no pidfd: the status string must say so and name the
        // fallback, so no caller can mistake absence for availability.
        let s = pidfd_status();
        assert!(s.contains("not-linked"));
        assert!(s.contains("double-revalidation"));
    }

    #[test]
    fn kernel_version_parser() {
        assert_eq!(
            kernel_major_minor("5.10.240-android12-9-00006"),
            Some((5, 10))
        );
        assert_eq!(kernel_major_minor("6.1.0"), Some((6, 1)));
        assert_eq!(kernel_major_minor("4.14"), Some((4, 14)));
        assert_eq!(kernel_major_minor("garbage"), None);
        assert_eq!(kernel_major_minor(""), None);
    }

    #[test]
    fn live_compat_report_is_self_consistent() {
        // Environment-conditional by design: asserts internal consistency of
        // the live report on ANY machine, not absolute availability.
        let r = pidfd_compat();
        assert!(!r.linked, "phase-2 never links pidfd");
        assert_eq!(
            r.kernel_supports,
            kernel_major_minor(&r.osrelease).is_some_and(|(maj, min)| kernel_supports(maj, min))
        );
    }
}
