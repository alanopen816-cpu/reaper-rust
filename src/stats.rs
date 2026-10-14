//! Phase 2: self-measurements and cycle statistics.
//!
//! Tracks Reaper's own RSS/CPU plus per-cycle inspection health. All numbers
//! come from real /proc reads on this device; nothing is synthesized.

use std::fs;
use std::time::Instant;

/// RSS (KiB) and cumulative CPU (utime+stime ticks) of our own process.
#[derive(Debug, Clone, Default)]
pub struct SelfUsage {
    /// VmRSS from /proc/PID/status, KiB; zero placeholder must be qualified by rss_available.
    pub rss_kib: u64,
    /// utime+stime from /proc/PID/stat, ticks; raw counter, not converted to duration.
    pub cpu_ticks: u64,
    /// False means the procfs field was unreadable or malformed.
    pub rss_available: bool,
    pub cpu_available: bool,
}

pub fn self_usage() -> SelfUsage {
    let pid = std::process::id();
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let rss_kib = status.lines().find_map(|line| {
        line.strip_prefix("VmRSS:")
            .and_then(|v| v.split_whitespace().next().and_then(|x| x.parse().ok()))
    });
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    let cpu_ticks = crate::procfs::parse_stat(&stat).and_then(|_| {
        // utime=14/idx13, stime=15/idx14 after comm.
        let r = stat.rfind(')')?;
        let f: Vec<&str> = stat[r + 1..].split_whitespace().collect();
        let u: u64 = f.get(13)?.parse().ok()?;
        let s: u64 = f.get(14)?.parse().ok()?;
        Some(u + s)
    });
    SelfUsage {
        rss_kib: rss_kib.unwrap_or(0),
        cpu_ticks: cpu_ticks.unwrap_or(0),
        rss_available: rss_kib.is_some(),
        cpu_available: cpu_ticks.is_some(),
    }
}

/// Counters for one inspection cycle.
#[derive(Debug, Clone)]
pub struct CycleStats {
    /// Exact monotonic elapsed time, rounded down to milliseconds.
    pub started: Instant,
    /// Exact counters accumulated by the active observer cycle.
    pub inspected: usize,
    pub skipped: usize,
    pub events: usize,
    pub transitions: usize,
    pub log_bytes: usize,
    pub errors: usize,
    /// `/proc/meminfo` values; unavailable keys are represented as zero and flagged.
    pub swap_total_kib: u64,
    pub swap_free_kib: u64,
    pub swap_available: bool,
    /// Bounded directory walk (4096-entry cap), therefore an estimate if truncated.
    pub log_dir_bytes: u64,
}

impl CycleStats {
    pub fn new(log_dir: &std::path::Path) -> Self {
        let swap = crate::queries::meminfo_swap_verified();
        CycleStats {
            started: Instant::now(),
            inspected: 0,
            skipped: 0,
            events: 0,
            transitions: 0,
            log_bytes: 0,
            errors: 0,
            swap_total_kib: swap.map(|v| v.0).unwrap_or(0),
            swap_free_kib: swap.map(|v| v.1).unwrap_or(0),
            swap_available: swap.is_some(),
            log_dir_bytes: crate::queries::dir_size_bytes(log_dir),
        }
    }

    pub fn elapsed_ms(&self) -> u128 {
        self.started.elapsed().as_millis()
    }

    pub fn summary(&self, usage: &SelfUsage) -> String {
        format!(
            "cycle_ms={} inspected={} skipped={} events={} transitions={} errors={} log_bytes={} self_rss_kib_procfs={} self_cpu_ticks_procfs={} swap_total_kib_procfs={} swap_free_kib_procfs={} log_dir_bytes_estimated={}",
            self.elapsed_ms(),
            self.inspected,
            self.skipped,
            self.events,
            self.transitions,
            self.errors,
            self.log_bytes,
            if usage.rss_available { usage.rss_kib.to_string() } else { "unavailable".into() },
            if usage.cpu_available { usage.cpu_ticks.to_string() } else { "unavailable".into() },
            if self.swap_available { self.swap_total_kib.to_string() } else { "unavailable".into() },
            if self.swap_available { self.swap_free_kib.to_string() } else { "unavailable".into() },
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

    #[test]
    fn summary_labels_procfs_sources_and_unavailable_self_metrics() {
        let dir = std::env::temp_dir().join(format!("reaper-metric-label-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let stats = CycleStats::new(&dir);
        let text = stats.summary(&SelfUsage::default());
        assert!(text.contains("self_rss_kib_procfs=unavailable"));
        assert!(text.contains("self_cpu_ticks_procfs=unavailable"));
        assert!(text.contains("swap_total_kib_procfs="));
        assert!(text.contains("log_dir_bytes_estimated="));
        let _ = fs::remove_dir_all(dir);
    }
}
