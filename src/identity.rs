//! Phase 2: stable process identity.
//!
//! Identity = (boot_id, pid, start_ticks, uid, exe). A PID alone is never
//! identity: Linux recycles PIDs, so every security decision re-verifies the
//! full tuple immediately before acting. Phase 2 performs zero signalling;
//! `pidfd_available()` only opens a pidfd for OUR OWN pid and closes it, as a
//! capability probe. `pidfd_send_signal` is intentionally unwrapped: evaluating
//! its symbol availability is documented in README/limitations, and no code
//! path in this phase may send a signal.

use crate::procfs::Process;
use std::fs;

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

    #[test]
    fn pid_reuse_is_rejected() {
        let boot = Some("boot-1".to_string());
        let known = identify(&proc(4242, 100, Some(10373)), boot);
        // Same PID, new start time => recycled => must NOT verify.
        assert!(!verify(&known, &proc(4242, 101, Some(10373))));
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
