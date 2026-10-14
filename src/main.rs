//! Reaper supervisor. Signals are possible only via `close --act` for a
//! registry-verified lab PID after the full evidence and close sequence.
//!
//! `scan` prints one verified snapshot, `inspect <pid>` explains a single
//! process (identity, relations, protection, policy), `observe [secs]`
//! runs the event + state-machine + policy loop with daily JSONL logs.
//! Observer and scan paths remain read-only; production processes are never
//! eligible for the lab-only close path.

mod adapters;
mod client_tracker;
mod events;
mod evidence;
mod identity;
mod lab;
mod lab_coverage;
mod logx;
mod owner;
mod pidfd;
mod pilot;
mod policy;
mod procfs;
mod protection;
mod queries;
mod relations;
mod state;
mod stats;
mod terminate;
#[cfg(feature = "tui")]
mod tui;

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
        // Process names alone do not identify a runit service. Resolve claims first;
        // absent a pid+start match, fall through to an honest generic adapter.
        let claims = owner::claims_map(&owner::default_svdir());
        if let owner::OwnerVerdict::ClaimedActive { service }
        | owner::OwnerVerdict::ClaimedDown { service } = owner::resolve(
            &claims,
            &procfs::Process {
                pid: 0,
                ppid: 0,
                pgrp: 0,
                session: 0,
                start_ticks: 0,
                state: 'S',
                name: name.to_owned(),
                command: exe.to_owned(),
                rss_kib: 0,
                swap_kib: 0,
                uid: None,
            },
        ) {
            return Box::new(RunitService {
                service_name: service,
                svdir: owner::default_svdir(),
            });
        }
        return Box::new(GenericLinux);
    }
    if n.contains("opencode") || exe.contains("/opencode") {
        let _mode = OpenCode::classify(exe);
        return Box::new(OpenCode);
    }
    if n.contains("codex") || exe.contains("/codex") {
        let _daemon = Codex::classify(exe);
        return Box::new(Codex);
    }
    if exe.contains("/mcp") || n.contains("mcp") {
        return Box::new(McpBroker {
            endpoint: "127.0.0.1:8377".into(),
        });
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
        client_coverage: client_tracker::Coverage::Unknown,
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
    let verified = vec![
        format!("argv0 observed: {}", p.command),
        format!(
            "supervise claim for pid={} start_ticks={}: {:?}",
            p.pid,
            p.start_ticks,
            owner::resolve(&owner::claims_map(&owner::default_svdir()), p)
        ),
    ];
    let inferred = vec![format!(
        "adapter category (not service identity): {}",
        adapter.name()
    )];
    println!("identification verified={verified:?} inferred={inferred:?}");
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
    let _self_pidfd = pidfd::open_self().and_then(pidfd::close);
    let _self_probe = pidfd::probe_self_empty();
    let compat = identity::pidfd_compat();
    println!(
        "pidfd_compat: kernel={} supports={} header={} linked={}",
        compat.osrelease, compat.kernel_supports, compat.header_present, compat.linked
    );
    let claims = owner::claims_map(&owner::default_svdir());
    println!("owner_claim={:?}", owner::resolve(&claims, p));
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
        let mut st = stats::CycleStats::new(&self.log_cfg.dir);
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

        // Owner claims are rebuilt once per cycle from supervise dirs
        // (pure file reads, no spawns, no signals).
        let claims = owner::claims_map(&owner::default_svdir());

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
            // Owner verdict refines the adapter's Unknown: a live supervise
            // claim means the owner considers it up; a down-claim means the
            // owner parked it (watched, never candidate — proven_abandoned
            // stays false in this phase).
            let (owner_active, owner_tag) = match owner::resolve(&claims, p) {
                owner::OwnerVerdict::ClaimedActive { service } => {
                    (Some(true), format!("runit:{service}"))
                }
                owner::OwnerVerdict::ClaimedDown { service } => {
                    (Some(false), format!("runit:{service}:down"))
                }
                owner::OwnerVerdict::Unclaimed => (
                    liveness_to_signal(adapter.liveness(&id)),
                    "unclaimed".to_string(),
                ),
            };
            // Untracked processes remain UnknownExternal until verified managed-client lookup is wired here.
            let client_registry_result = client_tracker::current_registry();
            let coverage = client_tracker::registry_coverage(&client_registry_result);
            let mut managed_registry = client_registry_result.unwrap_or_default();
            client_tracker::discard_stale(&mut managed_registry);
            let managed_record = managed_registry.clients.iter().find(|record| {
                record.identity.pid == p.pid
                    && record.identity.start_ticks == p.start_ticks
                    && record.identity.boot_id == self.boot_id.clone().unwrap_or_default()
            });
            let unknown_external = client_tracker::ClientState::UnknownExternal {
                evidence: "coverage is incomplete".into(),
                provenance: "managed-only registry; external client roster unavailable".into(),
            };
            let managed_state = managed_record
                .map(|record| &record.state)
                .unwrap_or(&unknown_external);
            let tracker_active = client_tracker::tracker_signal(
                managed_state,
                managed_record.is_some_and(|record| !record.active_work_ids.is_empty()),
            );
            let owner_active = client_tracker::combine_signals(owner_active, tracker_active);
            let lab_member = lab::current_registry()
                .unwrap_or_default()
                .iter()
                .any(|e| e.pid == p.pid && e.start_ticks == p.start_ticks);
            let owner_evidence = match owner::resolve(&claims, p) {
                owner::OwnerVerdict::ClaimedActive { service } => {
                    owner::OwnerVerdict::ClaimedActive { service }
                }
                owner::OwnerVerdict::ClaimedDown { service } => {
                    owner::OwnerVerdict::ClaimedDown { service }
                }
                owner::OwnerVerdict::Unclaimed => owner::OwnerVerdict::Unclaimed,
            };
            let client_work = if adapter.name() == "opencode" {
                adapters::OpenCodeProbe {
                    base_url: None,
                    password: None,
                }
                .assess_fast()
            } else {
                evidence::ClientWorkState::Unknown {
                    missing: vec!["adapter client/work evidence unavailable".into()],
                }
            };
            let (last_client_gone, no_pending_work) = evidence::client_work_to_fields(&client_work);
            let ev = evidence::AbandonEvidence {
                lab_member,
                owner: owner_evidence,
                grace_expired: false,
                revalidated_now: false,
                owner_dead: match owner_active {
                    Some(false) => Some(true),
                    Some(true) => Some(false),
                    None => None,
                },
                last_client_gone,
                no_pending_work,
            };
            let _absence = evidence::positive_vs_absent(&ev);
            let signals = Signals {
                owner_reports_active: owner_active,
                proven_abandoned: evidence::proven(&ev),
                needs_tolerance: false,
                memory_pressure: false,
                client_coverage: coverage,
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
                    &format!("scan+policy owner={owner_tag}"),
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

fn cmd_lab() -> io::Result<()> {
    let child = lab::spawn(false)?;
    println!(
        "lab_spawned pid={} start_ticks={} registry={}",
        child.id(),
        child.entry.start_ticks,
        lab::registry_path_current().display()
    );
    std::mem::forget(child);
    Ok(())
}

fn cmd_close(pid: u32, act: bool) -> io::Result<()> {
    let Some(entry) = lab::current_registry()?.into_iter().find(|e| e.pid == pid) else {
        println!("close receipt: refused; PID is not in lab registry; no signal");
        return Ok(());
    };
    let Some(current) = lab::identity_ticks(pid).ok() else {
        println!("close receipt: refused; PID is gone; no signal");
        return Ok(());
    };
    if current != entry.start_ticks {
        println!("close receipt: refused; identity changed; no signal");
        return Ok(());
    }
    let evidence = evidence::AbandonEvidence {
        lab_member: true,
        owner: owner::OwnerVerdict::Unclaimed,
        grace_expired: logx::now_secs() >= entry.spawned_at.saturating_add(300),
        revalidated_now: true,
        owner_dead: None,
        last_client_gone: None,
        no_pending_work: None,
    };
    if !evidence::proven(&evidence) {
        println!("close receipt: refused; evidence={evidence:?} proven=false; no signal");
        return Ok(());
    }
    let policy = terminate::ClosePolicy::default();
    let rec = terminate::LabRecord {
        pid,
        start_ticks: entry.start_ticks,
        spawned_at: entry.spawned_at,
    };
    if !act {
        for receipt in terminate::close_sequence(
            &rec,
            &policy,
            false,
            &mut terminate::PidfdSignaller,
            |pid, ticks, spawned| {
                lab::registry_contains(&lab::Entry {
                    pid,
                    start_ticks: ticks,
                    spawned_at: spawned,
                })
                .unwrap_or(false)
                    && lab::identity_ticks(pid).ok() == Some(ticks)
            },
            |_| {},
            || "dry-run; official shutdown not invoked".into(),
        ) {
            println!("close receipt: {receipt}");
        }
        return Ok(());
    }
    let Some(p) = procfs::scan().processes.into_iter().find(|p| p.pid == pid) else {
        println!("close receipt: refused; PID is gone; no signal");
        return Ok(());
    };
    let mut s = terminate::PidfdSignaller;
    for receipt in terminate::close_sequence(
        &rec,
        &policy,
        true,
        &mut s,
        |pid, ticks, spawned| {
            lab::registry_contains(&lab::Entry {
                pid,
                start_ticks: ticks,
                spawned_at: spawned,
            })
            .unwrap_or(false)
                && lab::identity_ticks(pid).ok() == Some(ticks)
        },
        thread::sleep,
        || {
            format!(
                "{:?}",
                adapter_for(&p.name, &p.command)
                    .request_official_shutdown(&identity::identify(&p, identity::read_boot_id()))
            )
        },
    ) {
        println!("close receipt: {receipt}");
    }
    Ok(())
}

fn cmd_observe(interval: u64, state_dir: &std::path::Path) -> io::Result<()> {
    let log_cfg = logx::LogConfig::new(state_dir.join("logs"));
    let boot_id = identity::read_boot_id();
    let state_file = state_dir.join("supervisor.json");
    let mut supervisor = Supervisor::new(state_file.clone());
    // Recover previous run without trusting old PIDs or timers.
    let outcome = procfs::scan();
    let live: HashMap<u32, identity::ProcessIdentity> = outcome
        .processes
        .iter()
        .map(|p| (p.pid, identity::identify(p, boot_id.clone())))
        .collect();
    let (kept, discarded) = match supervisor.reload(&live, logx::now_secs(), 300, &state_file) {
        Ok(result) => result,
        Err(e) => {
            logx::log(
                &log_cfg,
                logx::Level::Error,
                "state.recovery_failed",
                &format!("error={e}"),
            )?;
            return Err(e);
        }
    };
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
    println!("Signals are possible only via close --act for registry-verified lab PIDs.");
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
        Some("lab") => cmd_lab(),
        Some("close") => {
            let pid = args
                .iter()
                .position(|a| a == "--pid")
                .and_then(|i| args.get(i + 1))
                .and_then(|s| s.parse::<u32>().ok());
            match pid {
                Some(pid) => cmd_close(pid, args.iter().any(|a| a == "--act")),
                None => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Usage: close --pid PID [--act]",
                )),
            }
        }
        Some("scan") => cmd_scan(),
        Some("tui") => {
            #[cfg(feature = "tui")]
            {
                tui::run()
            }
            #[cfg(not(feature = "tui"))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "rebuild with --features tui",
                ))
            }
        }
        Some("pilot") => match args.get(2).map(String::as_str) {
            Some("report") => pilot::report_mode(args.iter().any(|a| a == "--deep")),
            Some("metrics") => pilot::metrics(&PathBuf::from(&state_dir)),
            Some("start") => {
                let interval = args
                    .iter()
                    .position(|a| a == "--interval")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30)
                    .max(5);
                pilot::start(&PathBuf::from(&state_dir), interval)
            }
            Some("status") => pilot::status(&PathBuf::from(&state_dir)),
            Some("stop") => pilot::stop(&PathBuf::from(&state_dir)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Usage: pilot report|metrics|start|status|stop",
            )),
        },
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
            println!("       reaper tui");
            println!("       reaper pilot report|metrics|start|status|stop");
            println!("Signals are possible only via close --act for registry-verified lab PIDs.");
            Ok(())
        }
    };
    if let Err(e) = result {
        eprintln!("reaper error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod pilot_gap_tests {
    use super::*;

    #[test]
    fn runit_process_name_without_identity_claim_is_not_a_service() {
        let adapter = adapter_for("runsv", "/usr/bin/runsv");
        assert_eq!(adapter.name(), "generic-linux");
    }
}
