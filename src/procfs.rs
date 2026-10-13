//! Phase 2: /proc observation layer. Never sends signals, never writes to /proc.
//! A single unreadable process is skipped and counted; it never aborts a scan.

use std::fs;

/// Live view of one visible process. `command` holds argv[0] only (no arguments)
// // by policy: arguments may contain secrets and are never logged or stored).
#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub start_ticks: u64,
    pub state: char,
    pub name: String,
    pub command: String,
    pub rss_kib: u64,
    pub swap_kib: u64,
    pub uid: Option<u32>,
}

/// Parse `/proc/<pid>/stat`. Returns (pid, comm, state, ppid, pgrp, session, starttime).
/// comm may contain spaces and ')' — anchor on the LAST ')'.
pub fn parse_stat(input: &str) -> Option<(u32, String, char, u32, u32, u32, u64)> {
    let l = input.find('(')?;
    let r = input.rfind(')')?;
    let pid = input[..l].trim().parse().ok()?;
    let name = input[l + 1..r].to_owned();
    let fields: Vec<&str> = input[r + 1..].split_whitespace().collect();
    // After comm: state=3/idx0, ppid=4/idx1, pgrp=5/idx2, session=6/idx3, starttime=22/idx19.
    if fields.len() < 20 {
        return None;
    }
    Some((
        pid,
        name,
        fields[0].chars().next()?,
        fields[1].parse().ok()?,
        fields[2].parse().ok()?,
        fields[3].parse().ok()?,
        fields[19].parse().ok()?,
    ))
}

fn status_numbers(path: &std::path::Path) -> (Option<u32>, u64, u64) {
    let Ok(content) = fs::read_to_string(path) else {
        return (None, 0, 0);
    };
    let mut uid = None;
    let mut rss = 0;
    let mut swap = 0;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("Uid:") {
            uid = v.split_whitespace().next().and_then(|x| x.parse().ok());
        }
        if let Some(v) = line.strip_prefix("VmRSS:") {
            rss = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
        }
        if let Some(v) = line.strip_prefix("VmSwap:") {
            swap = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
        }
    }
    (uid, rss, swap)
}

/// Outcome of a scan: processes plus counts of skipped entries (never an abort).
pub struct ScanOutcome {
    pub processes: Vec<Process>,
    /// Entries skipped because stat was unreadable or unparsable.
    pub skipped_stat: usize,
    /// Entries skipped because the parsed PID did not match the directory name.
    pub skipped_mismatch: usize,
}

pub fn scan() -> ScanOutcome {
    let mut processes = Vec::new();
    let mut skipped_stat = 0;
    let mut skipped_mismatch = 0;
    let Ok(entries) = fs::read_dir("/proc") else {
        return ScanOutcome {
            processes,
            skipped_stat,
            skipped_mismatch,
        };
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else {
            continue;
        };
        let path = entry.path();
        let Ok(stat) = fs::read_to_string(path.join("stat")) else {
            skipped_stat += 1;
            continue;
        };
        let Some((real_pid, name, state, ppid, pgrp, session, start_ticks)) = parse_stat(&stat)
        else {
            skipped_stat += 1;
            continue;
        };
        if real_pid != pid {
            skipped_mismatch += 1;
            continue;
        }
        let (uid, rss_kib, swap_kib) = status_numbers(&path.join("status"));
        let command = fs::read(path.join("cmdline"))
            .map(|v| {
                let mut args = v.split(|b| *b == 0).filter(|s| !s.is_empty());
                args.next()
                    .map(|x| String::from_utf8_lossy(x).into_owned())
                    .unwrap_or_else(|| name.clone())
            })
            .unwrap_or_else(|_| name.clone());
        processes.push(Process {
            pid,
            ppid,
            pgrp,
            session,
            start_ticks,
            state,
            name,
            command,
            rss_kib,
            swap_kib,
            uid,
        });
    }
    processes.sort_by_key(|p| p.pid);
    ScanOutcome {
        processes,
        skipped_stat,
        skipped_mismatch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_with_complex_comm() {
        let filler = vec!["0"; 15].join(" ");
        let s = format!("123 (foo bar) baz) S 1 1 1 {filler} 42");
        let parsed = parse_stat(&s).unwrap();
        assert_eq!(parsed.1, "foo bar) baz");
        assert_eq!(parsed.6, 42);
    }

    #[test]
    fn parse_pgrp_and_session() {
        let filler = vec!["0"; 15].join(" ");
        let s = format!("7 (sh) S 1 5 9 {filler} 77");
        let (_, _, _, ppid, pgrp, session, start) = parse_stat(&s).unwrap();
        assert_eq!((ppid, pgrp, session, start), (1, 5, 9, 77));
    }

    #[test]
    fn incomplete_stat_is_none() {
        assert!(parse_stat("123 (x) S 1").is_none());
        assert!(parse_stat("not a stat line").is_none());
    }

    #[test]
    fn scan_never_aborts_and_counts() {
        let outcome = scan();
        assert!(!outcome.processes.is_empty());
        let self_seen = outcome
            .processes
            .iter()
            .any(|p| p.pid == std::process::id());
        assert!(self_seen, "own process must be visible");
    }
}
