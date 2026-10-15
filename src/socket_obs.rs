//! Read-only, single-pass observation of socket descriptors owned by one PID.
//!
//! A socket inode count is not a client count. Low, stable, or historically
//! matching counts must never become `CompleteVerified`; callers must combine
//! this supplemental observation with the lease registry and coverage evidence.

use crate::procfs::parse_stat;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::SystemTime;

const MAX_FDS: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Completeness {
    Complete,
    PartialTruncated,
    UnknownPermission,
    UnknownGone,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketObsError {
    PermissionDenied,
    ProcessGone,
    IdentityMismatch,
    InvalidStat,
    Io,
}

#[derive(Debug, Clone)]
pub struct SocketSnapshot {
    pub pid: u32,
    pub observed_at: SystemTime,
    pub unique_inodes: Vec<u64>,
    pub count: usize,
    pub completeness: Completeness,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotDiff {
    pub added: Vec<u64>,
    pub removed: Vec<u64>,
}

fn classify_io(error: io::Error) -> SocketObsError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => SocketObsError::PermissionDenied,
        io::ErrorKind::NotFound => SocketObsError::ProcessGone,
        _ => SocketObsError::Io,
    }
}

/// Scan `/proc/<pid>/fd` once, attributing results only after start-time validation.
pub fn observe_fd_sockets(
    pid: u32,
    expected_start_ticks: Option<u64>,
) -> Result<SocketSnapshot, SocketObsError> {
    observe_at(&PathBuf::from("/proc"), pid, expected_start_ticks)
}

fn observe_at(
    root: &std::path::Path,
    pid: u32,
    expected_start_ticks: Option<u64>,
) -> Result<SocketSnapshot, SocketObsError> {
    let process = root.join(pid.to_string());
    let stat = fs::read_to_string(process.join("stat")).map_err(classify_io)?;
    let (actual_pid, _, _, _, _, _, start_ticks) =
        parse_stat(&stat).ok_or(SocketObsError::InvalidStat)?;
    if actual_pid != pid || expected_start_ticks.is_some_and(|expected| expected != start_ticks) {
        return Err(SocketObsError::IdentityMismatch);
    }

    let entries = fs::read_dir(process.join("fd")).map_err(classify_io)?;
    let mut inodes = HashSet::new();
    let mut completeness = Completeness::Complete;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_FDS {
            completeness = Completeness::PartialTruncated;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                completeness = Completeness::PartialTruncated;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                completeness = Completeness::UnknownPermission;
                break;
            }
            Err(_) => {
                completeness = Completeness::PartialTruncated;
                continue;
            }
        };
        let target = match fs::read_link(entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                completeness = Completeness::PartialTruncated;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                completeness = Completeness::UnknownPermission;
                break;
            }
            Err(_) => {
                completeness = Completeness::PartialTruncated;
                continue;
            }
        };
        if let Some(number) = target.to_string_lossy().strip_prefix("socket:[") {
            if let Some(inode) = number.strip_suffix(']').and_then(|n| n.parse().ok()) {
                inodes.insert(inode);
            }
        }
    }
    let mut unique_inodes: Vec<_> = inodes.into_iter().collect();
    unique_inodes.sort_unstable();
    Ok(SocketSnapshot {
        pid,
        observed_at: SystemTime::now(),
        count: unique_inodes.len(),
        unique_inodes,
        completeness,
    })
}

pub fn diff_snapshots(old: &SocketSnapshot, new: &SocketSnapshot) -> SnapshotDiff {
    let before: HashSet<_> = old.unique_inodes.iter().copied().collect();
    let after: HashSet<_> = new.unique_inodes.iter().copied().collect();
    SnapshotDiff {
        added: after.difference(&before).copied().collect(),
        removed: before.difference(&after).copied().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(inodes: &[u64]) -> SocketSnapshot {
        SocketSnapshot {
            pid: 1,
            observed_at: SystemTime::now(),
            unique_inodes: inodes.to_vec(),
            count: inodes.len(),
            completeness: Completeness::Complete,
        }
    }

    #[test]
    fn diff_reports_added_and_removed_inodes() {
        let diff = diff_snapshots(&snapshot(&[1, 2]), &snapshot(&[2, 3]));
        assert_eq!(diff.added, [3]);
        assert_eq!(diff.removed, [1]);
    }

    #[test]
    fn nonexistent_process_is_gone() {
        assert_eq!(
            observe_fd_sockets(u32::MAX, None).unwrap_err(),
            SocketObsError::ProcessGone
        );
    }

    #[test]
    fn mismatched_identity_returns_no_snapshot() {
        let pid = std::process::id();
        assert_eq!(
            observe_fd_sockets(pid, Some(u64::MAX)).unwrap_err(),
            SocketObsError::IdentityMismatch
        );
    }

    #[test]
    fn descriptor_target_parser_deduplicates() {
        let mut inodes = HashSet::new();
        for target in ["socket:[12]", "socket:[12]", "socket:[8]", "pipe:[12]"] {
            if let Some(n) = target
                .strip_prefix("socket:[")
                .and_then(|s| s.strip_suffix(']'))
            {
                if let Ok(inode) = n.parse::<u64>() {
                    inodes.insert(inode);
                }
            }
        }
        assert_eq!(inodes, HashSet::from([8, 12]));
    }

    #[test]
    fn gone_or_identity_mismatch_never_yields_a_complete_snapshot() {
        let gone = observe_fd_sockets(u32::MAX, None).unwrap_err();
        assert_eq!(gone, SocketObsError::ProcessGone);
        let reused = observe_fd_sockets(std::process::id(), Some(u64::MAX)).unwrap_err();
        assert_eq!(reused, SocketObsError::IdentityMismatch);
        // No snapshot is preferable to interpreting inaccessible/missing fd data
        // as an empty set of sockets.
        assert!(!matches!(gone, SocketObsError::Io));
    }
}
