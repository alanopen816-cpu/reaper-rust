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

#[derive(Debug, Default)]
struct StageMetric {
    ms: u128,
    ops: usize,
    errors: usize,
    timeouts: usize,
}

impl StageMetric {
    fn run<T>(f: impl FnOnce() -> T) -> (T, Self) {
        let start = Instant::now();
        let value = f();
        (
            value,
            Self {
                ms: start.elapsed().as_millis(),
                ops: 1,
                ..Self::default()
            },
        )
    }
}

#[derive(Debug, Default)]
struct InspectionMetrics {
    proc_scan: StageMetric,
    classify: StageMetric,
    relations: StageMetric,
    client_reads: StageMetric,
    report_render: StageMetric,
    opencode: StageMetric,
    codex: StageMetric,
    adapter_queries: StageMetric,
    persist: StageMetric,
    logs: StageMetric,
    aux_spawns: usize,
}

#[cfg(test)]
pub fn candidates() -> (Vec<Candidate>, usize) {
    let (rows, skipped, _) = candidates_with_metrics();
    (rows, skipped)
}

fn candidates_with_metrics() -> (Vec<Candidate>, usize, InspectionMetrics) {
    let mut metrics = InspectionMetrics::default();
    let spawn_start = crate::queries::auxiliary_spawn_count();
    // Reports use the same bounded fast snapshot as the supervisor; slow adapters are deferred.
    let (outcome, proc_scan) = StageMetric::run(procfs::scan);
    metrics.proc_scan = proc_scan;
    let (rel, relations) = StageMetric::run(|| relations::build(&outcome.processes));
    metrics.relations = relations;
    let uid = crate::own_uid();
    let claims = owner::claims_map(&owner::default_svdir());
    let lab_registry = crate::lab::current_registry();
    let client_registry = crate::client_tracker::current_registry();
    metrics.client_reads = StageMetric {
        ops: 2,
        errors: usize::from(lab_registry.is_err()) + usize::from(client_registry.is_err()),
        ..StageMetric::default()
    };
    let lab_registry = lab_registry.unwrap_or_default();
    let managed_clients = client_registry.as_ref().map(|r| r.clients.len());
    let opencode_state = evidence::ClientWorkState::Unknown {
        missing: vec!["deep inspection deferred in fast scan".into()],
    };
    let codex_state = opencode_state.clone();
    let (rows, classify_metric) = StageMetric::run(|| {
        outcome
            .processes
            .iter()
            .map(|p| {
                let prot = protect(p, std::process::id(), &rel, uid);
                let adapter = crate::adapter_for(&p.name, &p.command);
                let id = identity::identify(p, identity::read_boot_id());
                let live = adapter.liveness(&id);
                let client_work = (adapter.name() == "opencode")
                    .then(|| format!("client_work={opencode_state:?}"));
                let codex_work =
                    (adapter.name() == "codex").then(|| format!("client_work={codex_state:?}"));
                let owner = owner::resolve(&claims, p);
                let lab_member = lab_registry
                    .iter()
                    .any(|e| e.pid == p.pid && e.start_ticks == p.start_ticks);
                let coverage = client_registry
                    .as_ref()
                    .map(|registry| crate::client_tracker::registry_coverage(&Ok(registry.clone())))
                    .unwrap_or(crate::client_tracker::Coverage::Broken);
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
                    client_coverage: coverage,
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
                let managed_clients = managed_clients.unwrap_or(0);
                let limitations = vec![
                    "dry-run only; no close action is available".into(),
                    "client and pending-work absence may be unverifiable".into(),
                    format!(
                        "managed_clients={managed_clients}; coverage={:?}",
                        signals.client_coverage
                    ),
                ];
                Candidate {
                    pid: p.pid,
                    tier: prot.tier,
                    decision: format!("{decision:?}"),
                    evidence,
                    limitations,
                }
            })
            .collect::<Vec<_>>()
    });
    metrics.classify = StageMetric {
        ops: outcome.processes.len(),
        ..classify_metric
    };
    metrics.report_render = StageMetric {
        ops: rows.len(),
        ..StageMetric::default()
    };
    metrics.aux_spawns = crate::queries::auxiliary_spawn_count().saturating_sub(spawn_start);
    (
        rows,
        outcome.skipped_stat + outcome.skipped_mismatch,
        metrics,
    )
}

pub fn report_mode(deep: bool) -> io::Result<()> {
    let (mut rows, skipped, mut metrics) = candidates_with_metrics();
    if deep {
        deep_inspect(&mut rows, &mut metrics);
    }
    let render_start = Instant::now();
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
    metrics.report_render.ms = render_start.elapsed().as_millis();
    println!("inspection_metrics={{\"proc_scan_ms\":{},\"classify_ms\":{},\"relations_ms\":{},\"adapter_queries_ms\":{},\"opencode_queries_ms\":{},\"codex_queries_ms\":{},\"client_reads_ms\":{},\"persist_ms\":{},\"report_render_ms\":{},\"logs_ms\":{},\"aux_spawns\":{},\"errors\":{},\"timeouts\":{}}}", metrics.proc_scan.ms, metrics.classify.ms, metrics.relations.ms, metrics.adapter_queries.ms, metrics.opencode.ms, metrics.codex.ms, metrics.client_reads.ms, metrics.persist.ms, metrics.report_render.ms, metrics.logs.ms, metrics.aux_spawns, metrics.proc_scan.errors + metrics.classify.errors + metrics.relations.errors + metrics.client_reads.errors + metrics.opencode.errors + metrics.codex.errors, metrics.opencode.timeouts + metrics.codex.timeouts);
    Ok(())
}

const DEEP_TIMEOUT: Duration = Duration::from_secs(35);
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DEEP_WORKERS: usize = 2;
fn deep_inspect(rows: &mut [Candidate], metrics: &mut InspectionMetrics) {
    deep_inspect_with_budget(rows, metrics, DEEP_TIMEOUT);
}

fn deep_inspect_with_budget(
    rows: &mut [Candidate],
    metrics: &mut InspectionMetrics,
    budget: Duration,
) {
    let processes = procfs::scan().processes;
    let targets: Vec<_> = rows
        .iter()
        .filter_map(|r| {
            processes.iter().find(|p| p.pid == r.pid).and_then(|p| {
                let name = crate::adapter_for(&p.name, &p.command).name();
                (name == "opencode" || name == "codex").then_some((r.pid, name.to_owned()))
            })
        })
        .collect();
    deep_inspect_targets_with_budget(rows, metrics, budget, targets);
}

fn deep_inspect_targets_with_budget(
    rows: &mut [Candidate],
    metrics: &mut InspectionMetrics,
    budget: Duration,
    targets: Vec<(u32, String)>,
) {
    deep_inspect_targets_with_probe(
        rows,
        metrics,
        budget,
        targets,
        |name, remaining, cancelled| {
            if name == "opencode" {
                crate::adapters::OpenCodeProbe {
                    base_url: None,
                    password: None,
                }
                .assess_deep()
            } else {
                crate::adapters::CodexProbe { sock_path: None }
                    .assess_deep_with_budget(QUERY_TIMEOUT.min(remaining), &cancelled)
            }
        },
    );
}

fn deep_inspect_targets_with_probe(
    rows: &mut [Candidate],
    metrics: &mut InspectionMetrics,
    budget: Duration,
    targets: Vec<(u32, String)>,
    probe: impl Fn(
            String,
            Duration,
            std::sync::Arc<std::sync::atomic::AtomicBool>,
        ) -> evidence::ClientWorkState
        + Send
        + Sync
        + 'static,
) {
    let probe = std::sync::Arc::new(probe);
    let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started = Instant::now();
    let deadline = started.checked_add(budget).unwrap_or(started);
    for batch in targets.chunks(MAX_DEEP_WORKERS) {
        if Instant::now() >= deadline {
            for (pid, name) in batch {
                mark_unknown(rows, *pid, format!("{name} inspection timeout"));
            }
            metrics.opencode.timeouts += batch.iter().filter(|(_, n)| n == "opencode").count();
            metrics.codex.timeouts += batch.iter().filter(|(_, n)| n == "codex").count();
            continue;
        }
        let handles: Vec<_> = batch
            .iter()
            .map(|(pid, name)| {
                let (pid, name) = (*pid, name.clone());
                let remaining = deadline.saturating_duration_since(Instant::now());
                let cancelled = cancelled.clone();
                let probe = probe.clone();
                thread::spawn(move || {
                    let state = probe(name.clone(), remaining, cancelled);
                    (pid, name, state)
                })
            })
            .collect();
        let (tx, rx) = std::sync::mpsc::channel();
        for ((pid, name), handle) in batch.iter().zip(handles) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                mark_unknown(rows, *pid, format!("{name} inspection timeout"));
                if name == "opencode" {
                    metrics.opencode.timeouts += 1;
                } else {
                    metrics.codex.timeouts += 1;
                }
                drop(handle);
                continue;
            }
            let tx = tx.clone();
            thread::spawn(move || {
                let _ = tx.send(handle.join());
            });
            let result = match rx.recv_timeout(remaining) {
                Ok(Ok(result)) => result,
                _ => {
                    cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                    mark_unknown(rows, *pid, format!("{name} inspection timeout"));
                    if name == "opencode" {
                        metrics.opencode.timeouts += 1;
                    } else {
                        metrics.codex.timeouts += 1;
                    }
                    continue;
                }
            };
            {
                let (pid, name, state) = result;
                let metric = if name == "opencode" {
                    &mut metrics.opencode
                } else {
                    &mut metrics.codex
                };
                metric.ops += 1;
                if matches!(
                    state,
                    evidence::ClientWorkState::Error { .. }
                        | evidence::ClientWorkState::Unknown { .. }
                ) {
                    metric.errors += 1;
                }
                mark_state(rows, pid, format!("client_work={state:?}"));
            }
        }
    }
    metrics.adapter_queries.ms = started.elapsed().as_millis();
}
fn mark_unknown(rows: &mut [Candidate], pid: u32, note: String) {
    mark_state(
        rows,
        pid,
        format!("client_work=Unknown {{ missing: [{note}] }}"),
    );
}
fn mark_state(rows: &mut [Candidate], pid: u32, state: String) {
    if let Some(row) = rows.iter_mut().find(|r| r.pid == pid) {
        row.evidence.retain(|e| !e.starts_with("client_work="));
        row.evidence.push(state);
    }
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
    fn fast_inspection_defers_adapters_and_batches_client_reads() {
        let (rows, _, metrics) = candidates_with_metrics();
        assert_eq!(metrics.opencode.ops + metrics.codex.ops, 0);
        assert_eq!(metrics.client_reads.ops, 2);
        assert!(rows
            .iter()
            .filter(|r| r.evidence.iter().any(|e| e.contains("client_work=")))
            .all(|r| r
                .evidence
                .iter()
                .any(|e| e.contains("deep inspection deferred"))));
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
    #[test]
    fn inspection_failure_and_timeout_are_unknown_not_absent() {
        let mut rows = vec![Candidate {
            pid: 7,
            tier: Tier::Unknown,
            decision: "Blocked".into(),
            evidence: vec![],
            limitations: vec![],
        }];
        mark_unknown(&mut rows, 7, "adapter timeout".into());
        assert!(rows[0].evidence[0].contains("Unknown"));
        assert!(!rows[0].evidence[0].contains("WorkAbsent"));
        assert!(!evidence::proven(&evidence::AbandonEvidence {
            lab_member: true,
            owner: owner::OwnerVerdict::Unclaimed,
            grace_expired: true,
            revalidated_now: true,
            owner_dead: Some(true),
            last_client_gone: None,
            no_pending_work: None
        }));
    }
    #[test]
    fn bounded_deep_worker_count_is_fixed() {
        assert_eq!(MAX_DEEP_WORKERS, 2);
    }

    #[test]
    fn tiny_deep_budget_returns_unknown_within_bound() {
        let mut rows = vec![Candidate {
            pid: std::process::id(),
            tier: Tier::Unknown,
            decision: "Blocked".into(),
            evidence: vec!["client_work=Unknown { missing: [deferred] }".into()],
            limitations: vec![],
        }];
        let started = Instant::now();
        let mut metrics = InspectionMetrics::default();
        deep_inspect_targets_with_probe(
            &mut rows,
            &mut metrics,
            Duration::from_millis(20),
            vec![(std::process::id(), "codex".into())],
            |_, _, _| {
                thread::sleep(Duration::from_secs(1));
                evidence::ClientWorkState::WorkAbsent {
                    note: "late result".into(),
                }
            },
        );
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(rows[0].evidence.iter().any(|e| e.contains("Unknown")));
        assert!(!rows[0].evidence.iter().any(|e| e.contains("WorkAbsent")));
    }
}
