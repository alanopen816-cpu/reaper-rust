//! Reaper phase 2: observable supervisor. Still sends NO signals.
//!
//! `scan` prints one verified snapshot, `inspect <pid>` explains a single
//! process (identity, relations, protection, policy), `observe [secs]`
//! runs the event + state-machine + policy loop with daily JSONL logs.
//! Termination is impossible by construction: no signalling code exists in
//! this binary (see adapters: every shutdown request is declined by value).

mod adapters;
mod events;
mod identity;
mod logx;
mod policy;
mod procfs;
mod protection;
mod relations;
mod state;
mod stats;

use adapters::{Codex, GenericLinux, Liveness, McpBroker, OpenCode, OwnerAdapter, RunitService};
use events::{Event, Tracker};
use policy::{Decision, Policy, Signals};
use protection::{protect, Tier};
use relations::Relations;
use state::{State, Supervisor};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn own_uid() -> Option<u32> {
    fs::read_to_string("/proc/self/status").ok().and_then(|c| {
        c.lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|x| x.parse().ok())
    })
}

fn adapter_for(name: &str, exe: &str) -> Box<dyn OwnerAdapter> {
    let n = name.to_ascii_lowercase();
    if n == "runsvdir" || n == "runsv" || n == "svlogd" {
        return Box::new(RunitService {
            service_name: name.to_owned(),
        });
    }
    if n.contains("opencode") || exe.contains("/opencode") {
        return Box::new(OpenCode);
    }
    if n.contains("codex") || exe.contains("/codex") {
        return Box::new(Codex);
    }
    if exe.contains("/mcp") || n.contains("mcp") {
        return Box::new(McpBroker);
    }
    Box::new(GenericLinux)
}

fn liveness_to_signal(l: Liveness) -> Option<bool> {
    match l {
        Liveness::Alive => Some(true),
        Liveness::Dead => Some(false),
        Liveness::Unknown => None,
    }
}

fn decide_state(decision: &Decision, current: Option<State>) -> State {
    match decision {
        Decision::KeepProtected { tier, .. } => match tier {
            Tier::Absolute | Tier::Unknown => State::Protected,
            // Contextual shared or known-with-active-clients: hands off but
            // kept under watch (non-terminal) so rescue/idle flips re-evaluate.
            Tier::Contextual | Tier::Known => State::Observing,
        },
        Decision::Observe { .. } => State::Observing,
        Decision::GraceCandidate { .. } => State::GracePeriod,
        Decision::ReadyForRevalidation { .. } => State::ReadyForRevalidation,
        Decision::Blocked { .. } => {
            // A blocked process that was already terminally protected stays put.
            if current == Some(State::Protected) {
                State::Protected
            } else {
                State::TerminationBlocked
            }
        }
    }
}

fn render_scan(processes: &[procfs::Process], rel: &Relations, uid: Option<u32>) {
    println!(
        "{:>7} {:>7} {:>9} {:>9} {:>9} {:<12} NAME",
        "PID", "PPID", "RSS KiB", "Swap KiB", "START", "TIER"
    );
    let self_pid = std::process::id();
    for p in processes {
        let tier = match protect(p, self_pid, rel, uid).tier {
            Tier::Absolute => "absolute",
            Tier::Contextual => "contextual",
            Tier::Known => "known",
            Tier::Unknown => "unknown",
        };
        println!(
            "{:>7} {:>7} {:>9} {:>9} {:>9} {:<12} {}",
            p.pid, p.ppid, p.rss_kib, p.swap_kib, p.start_ticks, tier, p.name
        );
    }
}

fn cmd_scan() -> io::Result<()> {
    let outcome = procfs::scan();
    let rel = relations::build(&outcome.processes);
    render_scan(&outcome.processes, &rel, own_uid());
    println!(
        "Observed {} processes ({} skipped), {} sessions, {} groups, {} watchdog hints (inferred only). READ ONLY — no signals sent.",
        outcome.processes.len(),
        outcome.skipped_stat + outcome.skipped_mismatch,
        rel.sessions.len(),
        rel.groups.len(),
        rel.watchdogs.len()
    );
    println!("relations_evidence={:?}", rel.evidence);
    Ok(())
}

fn cmd_inspect(pid: u32) -> io::Result<()> {
    let outcome = procfs::scan();
    let Some(p) = outcome.processes.iter().find(|p| p.pid == pid) else {
        eprintln!("PID not visible");
        return Ok(());
    };
    let rel = relations::build(&outcome.processes);
    let self_pid = std::process::id();
    let uid = own_uid();
    let prot = protect(p, self_pid, &rel, uid);
    let adapter = adapter_for(&p.name, &p.command);
    let live = adapter.liveness(&identity::identify(p, identity::read_boot_id()));
    let signals = Signals {
        owner_reports_active: liveness_to_signal(live),
        proven_abandoned: false,
        needs_tolerance: false,
        memory_pressure: false,
    };
    let decision = policy::decide(&Policy::default(), &prot, p, &signals);
    let node = rel.nodes.get(&pid);
    println!(
        "pid={} ppid={} pgrp={} session={} start_ticks={} state={} uid={:?}",
        p.pid, p.ppid, p.pgrp, p.session, p.start_ticks, p.state, p.uid
    );
    println!(
        "name={} executable={} rss_kib={} swap_kib={}",
        p.name, p.command, p.rss_kib, p.swap_kib
    );
    println!("protection={:?} reason={}", prot.tier, prot.reason);
    println!(
        "owner_adapter={} liveness={:?} shutdown={:?}",
        adapter.detail(),
        live,
        adapter.request_official_shutdown(&identity::identify(p, identity::read_boot_id()))
    );
    println!("decision={:?}", decision);
    if let Some(n) = node {
        println!(
            "node pid={} pgrp={} session={} children={:?} visible_children={} parent_missing={} evidence={:?}",
            n.pid,
            n.pgrp,
            n.session,
            n.children,
            relations::has_visible_children(&rel, pid),
            n.parent_missing,
            n.evidence
        );
    }
    let hints: Vec<String> = rel
        .watchdogs
        .iter()
        .filter(|w| w.pid == pid || w.for_pid == pid)
        .map(|w| format!("pid={} for={} evidence={:?}", w.pid, w.for_pid, w.evidence))
        .collect();
    println!("watchdog_hints={hints:?} (inferred only, never proof)");
    println!(
        "session_members={} group_members={}",
        rel.sessions.get(&p.session).map(Vec::len).unwrap_or(0),
        rel.groups.get(&p.pgrp).map(Vec::len).unwrap_or(0)
    );
    println!("pidfd: {}", identity::pidfd_status());
    Ok(())
}

struct Observer {
    tracker: Tracker,
    supervisor: Supervisor,
    policy: Policy,
    log_cfg: logx::LogConfig,
    boot_id: Option<String>,
    usage_start: stats::SelfUsage,
}

impl Observer {
    fn cycle(&mut self) -> io::Result<stats::CycleStats> {
        let mut st = stats::CycleStats::new();
        let outcome = procfs::scan();
        st.inspected = outcome.processes.len();
        st.skipped = outcome.skipped_stat + outcome.skipped_mismatch;
        let rel = relations::build(&outcome.processes);
        let self_pid = std::process::id();
        let uid = own_uid();
        let now = logx::now_secs();

        for ev in self.tracker.diff(&outcome, &outcome.processes) {
            st.events += 1;
            match &ev {
                Event::Appeared { identity } => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "process.appeared",
                        &format!(
                            "pid={} start={} uid={:?}",
                            identity.pid, identity.start_ticks, identity.uid
                        ),
                    )?;
                }
                Event::Disappeared { identity } => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "process.disappeared",
                        &format!("pid={} start={}", identity.pid, identity.start_ticks),
                    )?;
                    self.supervisor.transition(
                        identity,
                        State::Exited,
                        now,
                        "event:disappeared",
                        "lifecycle",
                        "process no longer visible",
                    );
                    st.transitions += 1;
                    self.supervisor.retire(identity.pid);
                }
                Event::IdentityChanged { old, new } => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "identity.changed",
                        &format!(
                            "pid={} old_start={} new_start={}",
                            new.pid, old.start_ticks, new.start_ticks
                        ),
                    )?;
                }
                Event::OwnerExited { child, owner_pid } => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Debug,
                        "owner.exited",
                        &format!("pid={} owner={}", child.pid, owner_pid),
                    )?;
                }
                Event::StateChanged { identity, from, to } => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Debug,
                        "proc.state",
                        &format!("pid={} {from}->{to}", identity.pid),
                    )?;
                }
                Event::ScanDegraded {
                    skipped_stat,
                    skipped_mismatch,
                } => {
                    st.errors += 1;
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Warn,
                        "scan.degraded",
                        &format!("skipped_stat={skipped_stat} skipped_mismatch={skipped_mismatch}"),
                    )?;
                }
            }
        }

        for p in &outcome.processes {
            let id = identity::identify(p, self.boot_id.clone());
            // Recycled PID under a live tracking key: prior state is void.
            if let Some(stored) = self.supervisor.identity_of(p.pid) {
                if !identity::verify(&stored, p) {
                    let t = self.supervisor.transition(
                        &id,
                        State::Discovered,
                        now,
                        "identity:recycled-pid",
                        "safety",
                        "pid reused with new start_ticks/uid; prior state discarded",
                    );
                    st.transitions += 1;
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "identity.recycled",
                        &format!(
                            "pid={} start={} {}->{} at={} evidence={}",
                            t.pid,
                            t.start_ticks,
                            t.from.as_str(),
                            t.to.as_str(),
                            t.at_unix,
                            t.evidence
                        ),
                    )?;
                }
            }
            // Terminal states persist without re-evaluation in Phase 2: no
            // evidence source can advance them here, and disappearance is
            // handled through events above. (Phase 3 re-opens them on change.)
            if self
                .supervisor
                .state_of(p.pid)
                .is_some_and(|s| s.terminal())
            {
                continue;
            }
            let prot = protect(p, self_pid, &rel, uid);
            let adapter = adapter_for(&p.name, &p.command);
            let signals = Signals {
                owner_reports_active: liveness_to_signal(adapter.liveness(&id)),
                proven_abandoned: false, // Phase 2: no evidence source can prove abandonment yet.
                needs_tolerance: false,
                memory_pressure: false,
            };
            let decision = policy::decide(&self.policy, &prot, p, &signals);
            let current = self.supervisor.state_of(p.pid);
            // Rescue during grace: owner evidence flipped back while we hold a
            // deadline — cancel explicitly and say so.
            if current == Some(State::GracePeriod)
                && !matches!(decision, Decision::GraceCandidate { .. })
            {
                let t = self.supervisor.transition(
                    &id,
                    State::Observing,
                    now,
                    "owner:rescue-during-grace",
                    "policy-10",
                    "client reappeared during grace; close cancelled",
                );
                st.transitions += 1;
                st.log_bytes += logx::log(
                    &self.log_cfg,
                    logx::Level::Info,
                    "grace.cancelled",
                    &format!(
                        "pid={} {}->{} {}",
                        t.pid,
                        t.from.as_str(),
                        t.to.as_str(),
                        t.reason
                    ),
                )?;
                continue;
            }
            let mut next = decide_state(&decision, current);
            // Grace expiry without new evidence: record readiness, do nothing.
            if current == Some(State::GracePeriod)
                && matches!(next, State::GracePeriod)
                && self.supervisor.grace_expired(p.pid, now)
            {
                next = State::ReadyForRevalidation;
            }
            // Fresh sightings start at Discovered (terminal states were skipped
            // above and disappearance is handled through events).
            let from = current.unwrap_or(State::Discovered);
            if next != from {
                if matches!(next, State::GracePeriod) {
                    let grace = match &decision {
                        Decision::GraceCandidate { grace_secs, .. } => *grace_secs,
                        _ => self.policy.grace_known_secs,
                    };
                    self.supervisor.arm_grace(p.pid, now + grace);
                }
                let t = self.supervisor.transition(
                    &id,
                    next,
                    now,
                    "scan+policy",
                    "policy-engine",
                    &format!("{decision:?}"),
                );
                st.transitions += 1;
                st.log_bytes += logx::log(
                    &self.log_cfg,
                    logx::Level::Info,
                    "state.transition",
                    &format!(
                        "pid={} start={} {}->{} at={} evidence={} policy={} reason={}",
                        t.pid,
                        t.start_ticks,
                        t.from.as_str(),
                        t.to.as_str(),
                        t.at_unix,
                        t.evidence,
                        t.policy,
                        t.reason
                    ),
                )?;
            } else if matches!(next, State::GracePeriod) && current.is_none() {
                self.supervisor
                    .arm_grace(p.pid, now + self.policy.grace_known_secs);
            }
        }

        if let Err(e) = self.supervisor.persist() {
            st.errors += 1;
            st.log_bytes += logx::log(
                &self.log_cfg,
                logx::Level::Error,
                "state.persist_failed",
                &format!("error={e}"),
            )?;
        }
        let usage = stats::self_usage();
        st.log_bytes += logx::log(
            &self.log_cfg,
            logx::Level::Info,
            "cycle.summary",
            &st.summary(&usage),
        )?;
        Ok(st)
    }
}

fn cmd_observe(interval: u64, state_dir: &std::path::Path) -> io::Result<()> {
    let log_cfg = logx::LogConfig::new(state_dir.join("logs"));
    let boot_id = identity::read_boot_id();
    let state_file = state_dir.join("supervisor.json");
    let mut supervisor = Supervisor::new(state_file.clone());
    // Recover previous run without trusting old PIDs or timers.
    let outcome = procfs::scan();
    let live: HashMap<u32, (u64, Option<u32>)> = outcome
        .processes
        .iter()
        .map(|p| (p.pid, (p.start_ticks, p.uid)))
        .collect();
    let (kept, discarded) = supervisor.reload(&live, logx::now_secs(), 300, &state_file);
    let usage_start = stats::self_usage();
    logx::log(&log_cfg, logx::Level::Info, "observer.started",
        &format!("read_only=true recovered={kept} discarded_recycled={discarded} pidfd={} interval={interval}",
            identity::pidfd_status()))?;
    logx::enforce_retention(&log_cfg, &{
        let (y, m, d) = logx::civil_date((logx::now_secs() / 86400) as i64);
        format!("{y:04}-{m:02}-{d:02}")
    });
    println!(
        "Reaper observer phase-2: read-only, interval={interval}s, logs={}",
        state_dir.display()
    );
    println!("No signals will ever be sent by this build.");
    let mut obs = Observer {
        tracker: Tracker::new(boot_id),
        supervisor,
        policy: Policy::default(),
        log_cfg,
        boot_id: identity::read_boot_id(),
        usage_start,
    };
    loop {
        match obs.cycle() {
            Ok(st) => {
                let u = stats::self_usage();
                println!("{} {}", logx::now_secs(), st.summary(&u));
                let _ = &obs.usage_start;
            }
            Err(e) => eprintln!("cycle error (continuing): {e}"),
        }
        thread::sleep(Duration::from_secs(interval));
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let state_dir = logx::default_state_dir();
    let result = match args.get(1).map(String::as_str) {
        Some("scan") => cmd_scan(),
        Some("inspect") => match args.get(2).and_then(|s| s.parse::<u32>().ok()) {
            Some(pid) => cmd_inspect(pid),
            None => Err(io::Error::new(io::ErrorKind::InvalidInput, "Expected PID")),
        },
        Some("observe") => {
            let seconds = args
                .get(2)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(30)
                .max(5);
            cmd_observe(seconds, &PathBuf::from(&state_dir))
        }
        _ => {
            println!("Reaper v0.2.0-phase2 (observable supervisor, still read-only)");
            println!("Usage: reaper scan | inspect <PID> | observe [interval_seconds]");
            println!("Never sends signals; READY_FOR_REVALIDATION performs no action.");
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("reaper error: {e}");
        std::process::exit(1);
    }
}
