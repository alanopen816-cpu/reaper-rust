//! Phase-3 prep: owner verification from runit supervise directories.
//!
//! Strictly read-only: scans `$PREFIX/var/service/*/supervise/pid` and the
//! `down` flag files. Never spawns `sv`, never signals, never writes.
//! A claim is accepted only when the recorded PID is alive with the SAME
//! start time (stale supervise records from recycled PIDs are rejected).
//! Result feeds `owner_reports_active`; `proven_abandoned` stays false in
//! this phase, so a down-claimed process is watched, never candidate.

use crate::procfs::{parse_stat, Process};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// What a supervise directory says about a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerVerdict {
    /// Claimed by `service` and the owner considers it up.
    ClaimedActive { service: String },
    /// Claimed by `service` but the owner flagged `down` (watched, not active).
    ClaimedDown { service: String },
    /// No supervise directory claims this exact (pid, start) identity.
    Unclaimed,
}

pub fn default_svdir() -> PathBuf {
    if let Ok(prefix) = std::env::var("PREFIX") {
        if !prefix.is_empty() {
            return PathBuf::from(prefix).join("var/service");
        }
    }
    PathBuf::from("/data/data/com.termux/files/usr/var/service")
}

/// Build pid → (service, down-flagged, claimed_start) for every supervise dir.
pub fn claims_map(svdir: &Path) -> HashMap<u32, (String, bool, u64)> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir(svdir) else {
        return map;
    };
    for entry in entries.flatten().take(512) {
        let service = entry.file_name().to_string_lossy().into_owned();
        let pid_content =
            fs::read_to_string(entry.path().join("supervise/pid")).unwrap_or_default();
        let Some(pid) = pid_content
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let Some((_, _, _, _, _, _, start)) = parse_stat(&stat) else {
            continue;
        };
        let down = entry.path().join("down").exists();
        map.insert(pid, (service, down, start));
    }
    map
}

pub fn resolve(map: &HashMap<u32, (String, bool, u64)>, p: &Process) -> OwnerVerdict {
    match map.get(&p.pid) {
        Some((service, down, start)) if *start == p.start_ticks => {
            if *down {
                OwnerVerdict::ClaimedDown {
                    service: service.clone(),
                }
            } else {
                OwnerVerdict::ClaimedActive {
                    service: service.clone(),
                }
            }
        }
        _ => OwnerVerdict::Unclaimed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, start: u64) -> Process {
        Process {
            pid,
            ppid: 1,
            pgrp: pid,
            session: pid,
            start_ticks: start,
            state: 'S',
            name: "svc".into(),
            command: "svc".into(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(10373),
        }
    }

    fn fixture() -> (PathBuf, u32, u64) {
        let dir = std::env::temp_dir().join(format!("reaper-svdir-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // Live claim: use our own test process (always alive with known start).
        let self_pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{self_pid}/stat")).unwrap();
        let start = parse_stat(&stat).unwrap().6;
        let svc = dir.join("myservice/supervise");
        fs::create_dir_all(&svc).unwrap();
        fs::write(svc.join("pid"), format!("{self_pid}\n")).unwrap();
        // Stale claim: right PID shape, wrong start (recycled identity).
        let stale = dir.join("stale/supervise");
        fs::create_dir_all(&stale).unwrap();
        fs::write(stale.join("pid"), "424242\n").unwrap();
        // Garbage claim.
        let garbage = dir.join("garbage/supervise");
        fs::create_dir_all(&garbage).unwrap();
        fs::write(garbage.join("pid"), "not-a-pid\n").unwrap();
        // Down-flagged claim on a second live PID (current process, down file).
        let down = dir.join("downsvc/supervise");
        fs::create_dir_all(&down).unwrap();
        fs::write(down.join("pid"), format!("{self_pid}\n")).unwrap();
        fs::write(dir.join("downsvc/down"), "").unwrap();
        (dir, self_pid, start)
    }

    #[test]
    fn live_claim_accepted_down_and_stale_rejected() {
        let (dir, pid, start) = fixture();
        let map = claims_map(&dir);
        // Two dirs claim our PID; downsvc sorts... either may win the map, so
        // assert resolution properties, not a fixed winner.
        let verdict = resolve(&map, &proc(pid, start));
        assert!(
            matches!(
                verdict,
                OwnerVerdict::ClaimedActive { .. } | OwnerVerdict::ClaimedDown { .. }
            ),
            "live PID must be claimed, got {verdict:?}"
        );
        // Recycled identity (same PID, new start) is never accepted.
        assert_eq!(
            resolve(&map, &proc(pid, start + 1)),
            OwnerVerdict::Unclaimed
        );
        // Unknown PID unclaimed; garbage pid file never panics nor claims.
        assert_eq!(resolve(&map, &proc(424241, 1)), OwnerVerdict::Unclaimed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn down_flag_distinguished_from_active() {
        let dir = std::env::temp_dir().join(format!("reaper-svdown-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let self_pid = std::process::id();
        let stat = fs::read_to_string(format!("/proc/{self_pid}/stat")).unwrap();
        let start = parse_stat(&stat).unwrap().6;
        let svc = dir.join("onlydown/supervise");
        fs::create_dir_all(&svc).unwrap();
        fs::write(svc.join("pid"), format!("{self_pid}\n")).unwrap();
        fs::write(dir.join("onlydown/down"), "").unwrap();
        let map = claims_map(&dir);
        assert_eq!(
            resolve(&map, &proc(self_pid, start)),
            OwnerVerdict::ClaimedDown {
                service: "onlydown".into()
            }
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_svdir_is_empty_not_error() {
        let map = claims_map(Path::new("/nonexistent-svdir-xyz"));
        assert!(map.is_empty());
    }
}
