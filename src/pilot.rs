//! Read-only candidate reporting and lifecycle controls for the pilot.
use crate::{
    adapters::Liveness,
    evidence, identity, owner,
    policy::{self, Policy, Signals},
    procfs,
    protection::{protect, Tier},
    relations, stats,
};
use std::{
    fs, io,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub struct Candidate {
    pub pid: u32,
    pub tier: Tier,
    pub decision: String,
    pub evidence: Vec<String>,
    pub limitations: Vec<String>,
}

pub fn candidates() -> (Vec<Candidate>, usize) {
    // One full bounded ambient probe per report call, not one per process.
    let opencode_state = std::panic::catch_unwind(|| {
        crate::adapters::OpenCodeProbe {
            base_url: None,
            password: None,
        }
        .assess()
    })
    .unwrap_or_else(|_| evidence::ClientWorkState::Unknown {
        missing: vec!["OpenCode probe panicked".into()],
    });
    // Reporting only: Codex WorkAbsent preserves last_client_gone=None because socket-client
    // enumeration is unavailable; the engine's conjunctive proof inputs are intentionally untouched.
    let codex_state =
        std::panic::catch_unwind(|| crate::adapters::CodexProbe { sock_path: None }.assess())
            .unwrap_or_else(|_| evidence::ClientWorkState::Unknown {
                missing: vec!["Codex probe panicked".into()],
            });
    let outcome = procfs::scan();
    let rel = relations::build(&outcome.processes);
    let uid = crate::own_uid();
    let claims = owner::claims_map(&owner::default_svdir());
    let rows = outcome
        .processes
        .iter()
        .map(|p| {
            let prot = protect(p, std::process::id(), &rel, uid);
            let adapter = crate::adapter_for(&p.name, &p.command);
            let id = identity::identify(p, identity::read_boot_id());
            let live = adapter.liveness(&id);
            let client_work =
                (adapter.name() == "opencode").then(|| format!("client_work={opencode_state:?}"));
            let codex_work =
                (adapter.name() == "codex").then(|| format!("client_work={codex_state:?}"));
            let owner = owner::resolve(&claims, p);
            let lab_member = crate::lab::current_registry()
                .unwrap_or_default()
                .iter()
                .any(|e| e.pid == p.pid && e.start_ticks == p.start_ticks);
            let signals = Signals {
                owner_reports_active: match (owner.clone(), live) {
                    (owner::OwnerVerdict::ClaimedActive { .. }, _) | (_, Liveness::Alive) => {
                        Some(true)
                    }
                    (owner::OwnerVerdict::ClaimedDown { .. }, _) | (_, Liveness::Dead) => {
                        Some(false)
                    }
                    _ => None,
                },
                proven_abandoned: false,
                needs_tolerance: false,
                memory_pressure: false,
            };
            let decision = policy::decide(&Policy::default(), &prot, p, &signals);
            let mut evidence = vec![
                format!("owner={owner:?}"),
                format!("adapter={} liveness={live:?}", adapter.detail()),
                format!("lab_registry_member={lab_member}"),
                format!(
                    "proven_abandoned={}",
                    evidence::proven(&evidence::AbandonEvidence {
                        lab_member,
                        owner,
                        grace_expired: false,
                        revalidated_now: false,
                        owner_dead: None,
                        last_client_gone: None,
                        no_pending_work: None
                    })
                ),
            ];
            if let Some(client_work) = client_work {
                evidence.push(client_work);
            }
            if let Some(codex_work) = codex_work {
                evidence.push(codex_work);
            }
            let limitations = vec![
                "dry-run only; no close action is available".into(),
                "client and pending-work absence may be unverifiable".into(),
            ];
            Candidate {
                pid: p.pid,
                tier: prot.tier,
                decision: format!("{decision:?}"),
                evidence,
                limitations,
            }
        })
        .collect();
    (rows, outcome.skipped_stat + outcome.skipped_mismatch)
}

pub fn report() -> io::Result<()> {
    let (rows, skipped) = candidates();
    println!("PID     TIER        DECISION | EVIDENCE | LIMITATIONS");
    for row in rows {
        println!(
            "{}\t{:?}\t{}\t{}\t{}",
            row.pid,
            row.tier,
            row.decision,
            row.evidence.join("; "),
            row.limitations.join("; ")
        );
    }
    println!("skipped={skipped}; READ ONLY — dry-run; no signals sent");
    Ok(())
}

pub fn metrics(state_dir: &Path) -> io::Result<()> {
    let usage = stats::self_usage();
    let (total, free) = crate::queries::meminfo_swap();
    let bytes = crate::queries::dir_size_bytes(&state_dir.join("logs"));
    println!(
        "rss_kib={} cpu_ticks={} swap_total_kib={} swap_free_kib={} log_bytes={} errors=0",
        usage.rss_kib, usage.cpu_ticks, total, free, bytes
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct PilotProcess {
    pid: u32,
    start_ticks: u64,
}

fn pidfile(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("pilot.pid")
}

fn process_start_ticks(pid: u32) -> io::Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad proc stat"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing start_ticks"))?
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad start_ticks"))
}

fn read_record(path: &Path) -> io::Result<PilotProcess> {
    let data = fs::read_to_string(path)?;
    let pid = data
        .split("\"pid\":")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok());
    let start_ticks = data
        .split("\"start_ticks\":")
        .nth(1)
        .and_then(|s| s.split(|c: char| !c.is_ascii_digit()).next())
        .and_then(|s| s.parse().ok());
    match (pid, start_ticks) {
        (Some(pid), Some(start_ticks)) => Ok(PilotProcess { pid, start_ticks }),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid pilot pidfile",
        )),
    }
}

fn verified(record: PilotProcess) -> bool {
    process_start_ticks(record.pid).ok() == Some(record.start_ticks)
        && fs::read(format!("/proc/{}/cmdline", record.pid))
            .ok()
            .is_some_and(|cmd| {
                let args: Vec<_> = cmd.split(|b| *b == 0).filter(|a| !a.is_empty()).collect();
                args.iter().any(|a| a.ends_with(b"/reaper"))
                    && args.iter().any(|a| *a == b"observe")
            })
}

fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn store_record(path: &Path, record: PilotProcess) -> io::Result<()> {
    fs::write(
        path,
        format!(
            "{{\"pid\":{},\"start_ticks\":{}}}\n",
            record.pid, record.start_ticks
        ),
    )
}

pub fn start(state_dir: &Path, interval: u64) -> io::Result<()> {
    fs::create_dir_all(state_dir)?;
    let path = pidfile(state_dir);
    if path.exists() {
        match read_record(&path) {
            Ok(record) if verified(record) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "pilot already running",
                ))
            }
            Ok(record) if process_exists(record.pid) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "refusing to replace live unverified pilot pidfile",
                ))
            }
            _ => {}
        }
        fs::create_dir_all(state_dir.join("logs"))?;
        use std::io::Write;
        writeln!(
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(state_dir.join("logs/pilot-observe.log"))?,
            "stale pilot pidfile replaced"
        )?;
    }
    fs::create_dir_all(state_dir.join("logs"))?;
    let log = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_dir.join("logs/pilot-observe.log"))?;
    let child = Command::new(std::env::current_exe()?)
        .arg("observe")
        .arg(interval.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let record = PilotProcess {
        pid: child.id(),
        start_ticks: process_start_ticks(child.id())?,
    };
    // Never signal a child unless its full recorded identity is available.
    store_record(&path, record)?;
    println!("pilot started pid={}", record.pid);
    Ok(())
}
pub fn status(state_dir: &Path) -> io::Result<()> {
    let path = pidfile(state_dir);
    let Ok(record) = read_record(&path) else {
        if path.exists() {
            fs::remove_file(path)?;
            println!("pilot stale pidfile removed");
        } else {
            println!("pilot stopped pid=-");
        }
        return Ok(());
    };
    if verified(record) {
        let uptime = fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .unwrap_or(0.0);
        let started = record.start_ticks as f64 / 100.0;
        let lines = fs::read_to_string(state_dir.join("logs/pilot-observe.log"))
            .map(|s| s.lines().count())
            .unwrap_or(0);
        println!(
            "pilot running pid={} uptime_seconds={} log_lines={}",
            record.pid,
            (uptime - started).max(0.0) as u64,
            lines
        );
    } else {
        fs::remove_file(path)?;
        println!("pilot stale pid={} (pidfile removed)", record.pid);
    }
    Ok(())
}
pub fn stop(state_dir: &Path) -> io::Result<()> {
    let path = pidfile(state_dir);
    if !path.exists() {
        println!("pilot stopped");
        return Ok(());
    }
    let record = read_record(&path)?;
    if !verified(record) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "refusing to signal: pilot identity verification failed",
        ));
    }
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    if unsafe { kill(record.pid as i32, 15) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && verified(record) {
        thread::sleep(Duration::from_millis(50));
    }
    if verified(record) {
        if unsafe { kill(record.pid as i32, 9) } != 0 {
            return Err(io::Error::last_os_error());
        }
        println!(
            "pilot kill receipt pid={} start_ticks={}",
            record.pid, record.start_ticks
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline && verified(record) {
            thread::sleep(Duration::from_millis(20));
        }
        if verified(record) {
            return Err(io::Error::other("verified pilot did not exit after KILL"));
        }
    }
    fs::remove_file(path)?;
    println!("pilot stopped pid={}", record.pid);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn report_rows_are_limited_and_never_advance_abandonment() {
        let (rows, _) = candidates();
        assert!(rows.iter().all(|r| !r.limitations.is_empty()));
        assert!(rows
            .iter()
            .all(|r| r.evidence.iter().any(|e| e == "proven_abandoned=false")));
    }
    #[test]
    fn metrics_reads_configured_temporary_logs() {
        let dir = std::env::temp_dir().join(format!("reaper-pilot-metrics-{}", std::process::id()));
        fs::create_dir_all(dir.join("logs")).unwrap();
        fs::write(dir.join("logs/a"), b"log").unwrap();
        assert_eq!(crate::queries::dir_size_bytes(&dir.join("logs")), 3);
        let _ = fs::remove_dir_all(dir);
    }
}
