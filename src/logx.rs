//! Phase 2: daily JSONL logging with levels, rotation and retention.
//!
//! One file per UTC day (`YYYY-MM-DD.jsonl`), structured events, levels
//! ERROR/WARN/INFO/DEBUG/TRACE, size rotation (`...-N.jsonl`), configurable
//! retention (days), secret redaction. Callers log transitions, evidence,
//! inspection errors, termination blocks (attempts that policy refused),
//! policy changes and identity notes — never unchanged processes every cycle.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    // Required level (mission §9); no Phase-2 path emits it yet.
    #[allow(dead_code)]
    Trace,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LogConfig {
    pub dir: PathBuf,
    pub min_level: Level,
    /// Rotate when the active file exceeds this size (default 1 MiB).
    pub rotate_bytes: u64,
    /// Keep this many daily files (default 14). 0 keeps everything.
    pub retain_days: usize,
}

impl LogConfig {
    pub fn new(dir: PathBuf) -> Self {
        LogConfig {
            dir,
            min_level: Level::Info,
            rotate_bytes: 1024 * 1024,
            retain_days: 14,
        }
    }
}

/// Redact values that look like secrets in free-text details.
/// `key=value` / `key:value` pairs whose key looks token-ish get their value
/// replaced with `[redacted]`. Bare mentions without a value are left alone.
pub fn redact(detail: &str) -> String {
    let sensitive = [
        "token", "secret", "password", "passwd", "api_key", "apikey", "auth",
    ];
    let lower = detail.to_lowercase();
    let bytes = detail.as_bytes();
    let mut out = String::with_capacity(detail.len());
    let mut i = 0;
    while i < bytes.len() {
        let hit = sensitive.iter().find(|k| {
            lower[i..].starts_with(*k) && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric())
        });
        match hit {
            None => {
                out.push(bytes[i] as char);
                i += 1;
            }
            Some(key) => {
                let mut j = i + key.len();
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':') {
                    j += 1;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    // Optional opening quote travels with the value.
                    let mut k = j;
                    if k < bytes.len() && (bytes[k] == b'"' || bytes[k] == b'\'') {
                        k += 1;
                    }
                    let mut end = k;
                    while end < bytes.len()
                        && !bytes[end].is_ascii_whitespace()
                        && bytes[end] != b','
                        && bytes[end] != b'"'
                        && bytes[end] != b'\''
                    {
                        end += 1;
                    }
                    if end > k {
                        out.push_str(&detail[i..k]);
                        out.push_str("[redacted]");
                        i = end;
                        continue;
                    }
                }
                out.push_str(&detail[i..i + key.len()]);
                i += key.len();
            }
        }
    }
    out
}

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if c.is_control() => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn civil_date(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    if m <= 2 {
        y += 1
    };
    (y, m, d)
}

fn day_name(time: u64) -> String {
    let (y, m, d) = civil_date((time / 86400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Resolve the active log file, rotating by size (`<day>-N.jsonl`).
fn active_file(cfg: &LogConfig, time: u64) -> std::io::Result<PathBuf> {
    fs::create_dir_all(&cfg.dir)?;
    let base = day_name(time);
    let mut n = 0;
    loop {
        let name = if n == 0 {
            format!("{base}.jsonl")
        } else {
            format!("{base}-{n}.jsonl")
        };
        let path = cfg.dir.join(name);
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size < cfg.rotate_bytes || n > 999 {
            return Ok(path);
        }
        n += 1;
    }
}

/// Append one event. Returns bytes written (0 when below min_level).
pub fn log(cfg: &LogConfig, level: Level, event: &str, detail: &str) -> std::io::Result<usize> {
    if level > cfg.min_level {
        return Ok(0);
    }
    let time = now_secs();
    let path = active_file(cfg, time)?;
    let mut f = OpenOptions::new().append(true).create(true).open(path)?;
    let line = format!(
        "{{\"time_unix\":{},\"level\":\"{}\",\"event\":\"{}\",\"detail\":\"{}\"}}\n",
        time,
        level.as_str(),
        esc(event),
        esc(&redact(detail))
    );
    f.write_all(line.as_bytes())?;
    Ok(line.len())
}

/// Delete daily files older than `retain_days` (by filename date). Returns removed count.
pub fn enforce_retention(cfg: &LogConfig, today: &str) -> usize {
    if cfg.retain_days == 0 {
        return 0;
    }
    let Ok(entries) = fs::read_dir(&cfg.dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".jsonl") || name.len() < 15 {
            continue;
        }
        let day = &name[..10];
        // Lexicographic compare is valid for zero-padded YYYY-MM-DD.
        if day < today
            && is_dated(name.len(), &name)
            && day_old_enough(day, today, cfg.retain_days)
            && fs::remove_file(entry.path()).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

fn is_dated(len: usize, name: &str) -> bool {
    len >= 15
        && name.as_bytes()[4] == b'-'
        && name.as_bytes()[7] == b'-'
        && name[..10].chars().all(|c| c.is_ascii_digit() || c == '-')
}

fn day_old_enough(day: &str, today: &str, retain: usize) -> bool {
    // Exact decision on parsed YYYY-MM-DD ordinals; unparsable names fail
    // safe (kept).
    let nums: Vec<i64> = day.split('-').filter_map(|x| x.parse().ok()).collect();
    let today_nums: Vec<i64> = today.split('-').filter_map(|x| x.parse().ok()).collect();
    match (&nums[..], &today_nums[..]) {
        ([y, m, d], [ty, tm, td]) => {
            days_from_civil(*y, *m, *d) + retain as i64 <= days_from_civil(*ty, *tm, *td)
        }
        _ => false,
    }
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn default_state_dir() -> PathBuf {
    if let Ok(v) = std::env::var("XDG_STATE_HOME") {
        if !v.is_empty() {
            return PathBuf::from(v).join("reaper");
        }
    }
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/state/reaper")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(name: &str) -> (PathBuf, LogConfig) {
        let dir =
            std::env::temp_dir().join(format!("reaper-log-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let c = LogConfig {
            dir: dir.clone(),
            min_level: Level::Trace,
            rotate_bytes: 200,
            retain_days: 7,
        };
        (dir, c)
    }

    #[test]
    fn rotation_and_levels() {
        let (dir, c) = cfg("rotation");
        assert!(log(&c, Level::Debug, "e", "d").unwrap() > 0);
        // Below min_level writes nothing.
        let quiet = LogConfig {
            min_level: Level::Error,
            ..c.clone()
        };
        assert_eq!(log(&quiet, Level::Info, "e", "d").unwrap(), 0);
        // Force rotation with several events.
        for i in 0..10 {
            log(&c, Level::Info, "evt", &format!("detail number {i}")).unwrap();
        }
        let files: Vec<_> = fs::read_dir(&dir).unwrap().collect();
        assert!(files.len() >= 2, "expected rotated files");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_and_redaction() {
        let (dir, mut c) = cfg("retention");
        c.rotate_bytes = u64::MAX;
        log(&c, Level::Info, "auth", "token=abc123 user=x").unwrap();
        let content = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| fs::read_to_string(e.path()).unwrap_or_default())
            .collect::<String>();
        assert!(content.contains("[redacted]"));
        assert!(!content.contains("abc123"));
        // Old file gets collected, today stays.
        fs::write(dir.join("2020-01-01.jsonl"), "{}\n").unwrap();
        let removed = enforce_retention(&c, &day_name(now_secs()));
        assert_eq!(removed, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn epoch_date() {
        assert_eq!(civil_date(0), (1970, 1, 1));
        assert!(day_old_enough("2020-01-01", "2020-01-10", 7));
        assert!(!day_old_enough("2020-01-05", "2020-01-10", 7));
    }
}
