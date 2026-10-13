//! Phase 2: self-measurements and cycle statistics.
//!
//! Tracks Reaper's own RSS/CPU plus per-cycle inspection health. All numbers
//! come from real /proc reads on this device; nothing is synthesized.

use std::fs;
use std::time::Instant;

/// RSS (KiB) and cumulative CPU (utime+stime ticks) of our own process.
#[derive(Debug, Clone, Default)]
pub struct SelfUsage {
    pub rss_kib: u64,
    pub cpu_ticks: u64,
}

pub fn self_usage() -> SelfUsage {
    let pid = std::process::id();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let mut rss_kib = 0;
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            rss_kib = v
                .split_whitespace()
                .next()
                .and_then(|x| x.parse().ok())
                .unwrap_or(0);
            break;
        }
    }
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let cpu_ticks = crate::procfs::parse_stat(&stat)
        .and_then(|_| {
            // utime=14/idx13, stime=15/idx14 after comm.
            let r = stat.rfind(')')?;
            let f: Vec<&str> = stat[r + 1..].split_whitespace().collect();
            let u: u64 = f.get(13)?.parse().ok()?;
            let s: u64 = f.get(14)?.parse().ok()?;
            Some(u + s)
        })
        .unwrap_or(0);
    SelfUsage { rss_kib, cpu_ticks }
}

/// Counters for one inspection cycle.
#[derive(Debug, Clone)]
pub struct CycleStats {
    pub started: Instant,
    pub inspected: usize,
    pub skipped: usize,
    pub events: usize,
    pub transitions: usize,
    pub log_bytes: usize,
    pub errors: usize,
}

impl CycleStats {
    pub fn new() -> Self {
        CycleStats {
            started: Instant::now(),
            inspected: 0,
            skipped: 0,
            events: 0,
            transitions: 0,
            log_bytes: 0,
            errors: 0,
        }
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    pub fn summary(&self, usage: &SelfUsage) -> String {
        format!(
            "cycle_ms={} inspected={} skipped={} events={} transitions={} errors={} log_bytes={} self_rss_kib={} self_cpu_ticks={}",
            self.elapsed_ms(),
            self.inspected,
            self.skipped,
            self.events,
            self.transitions,
            self.errors,
            self.log_bytes,
            usage.rss_kib,
            usage.cpu_ticks
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_measurement_is_real() {
        let u = self_usage();
        assert!(u.rss_kib > 0, "own RSS must be observable");
    }
}
