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
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
    pub log_dir_bytes: u64,
}

impl CycleStats {
    pub fn new(log_dir: &std::path::Path) -> Self {
        CycleStats {
            started: Instant::now(),
            inspected: 0,
            skipped: 0,
            events: 0,
            transitions: 0,
            log_bytes: 0,
            errors: 0,
            swap_total_kib: crate::queries::meminfo_swap().0,
            swap_free_kib: crate::queries::meminfo_swap().1,
            log_dir_bytes: crate::queries::dir_size_bytes(log_dir),
        }
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    pub fn summary(&self, usage: &SelfUsage) -> String {
        format!(
            "cycle_ms={} inspected={} skipped={} events={} transitions={} errors={} log_bytes={} self_rss_kib={} self_cpu_ticks={} swap_total_kib={} swap_free_kib={} log_dir_bytes={}",
            self.elapsed_ms(),
            self.inspected,
            self.skipped,
            self.events,
            self.transitions,
            self.errors,
            self.log_bytes,
            usage.rss_kib,
            usage.cpu_ticks,
            self.swap_total_kib,
            self.swap_free_kib,
            self.log_dir_bytes
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

    #[test]
    fn cycle_metric_uses_configured_log_directory() {
        let dir = std::env::temp_dir().join(format!("reaper-metric-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("one.log"), b"12345").unwrap();
        assert_eq!(CycleStats::new(&dir).log_dir_bytes, 5);
        let _ = fs::remove_dir_all(dir);
    }
}
