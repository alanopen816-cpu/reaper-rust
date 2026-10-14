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
mod managed_service;
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
use protection::{apply_classification, protect, Protection, Tier};
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
        Decision::GraceCandidate { .. } => {
            if current == Some(State::Candidate) {
                State::GracePeriod
            } else {
                State::Candidate
            }
        }
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

#[derive(Debug, PartialEq, Eq)]
enum DurableChange {
    Appeared(identity::ProcessIdentity),
    Changed(identity::ProcessIdentity, identity::ProcessIdentity),
    Disappeared(identity::ProcessIdentity),
}

fn durable_identity_diff(
    previous: &[(u32, identity::ProcessIdentity)],
    current: &[(u32, identity::ProcessIdentity)],
) -> Vec<DurableChange> {
    let same_process = |a: &identity::ProcessIdentity, b: &identity::ProcessIdentity| {
        a.pid == b.pid && a.start_ticks == b.start_ticks && a.boot_id == b.boot_id
    };
    let mut changes = Vec::new();
    for (_, now) in current {
        match previous.iter().find(|(_, old)| same_process(old, now)) {
            None => changes.push(DurableChange::Appeared(now.clone())),
            Some((_, old)) if old != now => {
                changes.push(DurableChange::Changed(old.clone(), now.clone()));
            }
            Some(_) => {}
        }
    }
    for (_, old) in previous {
        if !current.iter().any(|(_, now)| same_process(old, now)) {
            changes.push(DurableChange::Disappeared(old.clone()));
        }
    }
    changes
}

fn same_process(a: &identity::ProcessIdentity, b: &identity::ProcessIdentity) -> bool {
    a.pid == b.pid && a.start_ticks == b.start_ticks && a.boot_id == b.boot_id
}

/// The production classification-to-policy boundary, kept pure so cycle
/// decisions can be exercised with deterministic process evidence.
#[allow(clippy::too_many_arguments)]
fn classified_decision(
    p: &procfs::Process,
    id: &identity::ProcessIdentity,
    rel: &Relations,
    owner: &owner::OwnerVerdict,
    client_or_work_active: Option<bool>,
    positively_verified_inactive: bool,
    base: Protection,
    policy: &Policy,
    signals: &Signals,
    extensions: &[&dyn identity::Classifier],
) -> (identity::ProcessClass, Protection, Decision) {
    let class = identity::classify(
        &identity::ClassificationEvidence {
            process: p,
            identity: id,
            relations: rel,
            owner,
            client_or_work_active,
        },
        extensions,
    );
    let protection = apply_classification(base, class, positively_verified_inactive);
    let decision = policy::decide(policy, &protection, p, signals);
    (class, protection, decision)
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
    deep_scheduler: pilot::DeepScheduler,
    context_snapshot: HashMap<u32, (identity::ProcessIdentity, u32, u32)>,
    owner_snapshot: HashMap<u32, (identity::ProcessIdentity, String)>,
    emergency_stop_file: PathBuf,
    startup_fault: Option<state::OperationalFault>,
}

static PILOT_READ_ONLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

impl Observer {
    fn cycle(&mut self) -> io::Result<stats::CycleStats> {
        let mut st = stats::CycleStats::new(&self.log_cfg.dir);
        let outcome = procfs::scan();
        // The controlled demo exercises the same Observer path but limits its
        // expensive per-process probes to one currently registered lab target.
        // Normal observe mode has no target variable and retains the full scan.
        let lab_observer_target = std::env::var("REAPER_LAB_OBSERVER_TARGET")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| {
                lab::current_registry().ok().is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry.pid == *pid
                            && lab::identity_ticks(*pid).ok() == Some(entry.start_ticks)
                    })
                })
            });
        st.inspected = outcome.processes.len();
        st.skipped = outcome.skipped_stat + outcome.skipped_mismatch;
        let rel = relations::build(&outcome.processes);
        let self_pid = std::process::id();
        let uid = own_uid();
        let now = logx::now_secs();
        let emergency_stop = state::EmergencyStop::is_engaged_at(&self.emergency_stop_file)?;
        let scan_fault = (outcome.skipped_stat + outcome.skipped_mismatch > 0)
            .then_some(state::OperationalFault::Procfs);
        let startup_fault = self.startup_fault.or(scan_fault);
        let faulted = !state::auto_action_initiation_allowed(startup_fault);

        let durable_before = self.supervisor.identity_snapshot();
        let durable_now: Vec<_> = outcome
            .processes
            .iter()
            .map(|p| (p.pid, identity::identify(p, self.boot_id.clone())))
            .collect();
        for change in durable_identity_diff(&durable_before, &durable_now) {
            match change {
                DurableChange::Appeared(id) => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "state.appeared",
                        &format!(
                            "pid={} start={} boot={:?}",
                            id.pid, id.start_ticks, id.boot_id
                        ),
                    )?;
                }
                DurableChange::Changed(old, new) => {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "state.identity_updated",
                        &format!(
                            "pid={} start={} exe={} -> {}",
                            new.pid, new.start_ticks, old.exe, new.exe
                        ),
                    )?;
                    self.supervisor.refresh_identity(&new);
                }
                DurableChange::Disappeared(id) => {
                    if st.skipped > 0 {
                        continue;
                    }
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "state.disappeared",
                        &format!(
                            "pid={} start={} reason=identity absent from light snapshot",
                            id.pid, id.start_ticks
                        ),
                    )?;
                    self.supervisor.transition(
                        &id,
                        State::Exited,
                        now,
                        "event:disappeared",
                        "lifecycle",
                        "identity absent from light snapshot",
                    );
                    self.supervisor.retire(id.pid);
                    st.transitions += 1;
                }
            }
        }
        for process in &outcome.processes {
            let id = identity::identify(process, self.boot_id.clone());
            if let Some((old_id, old_session, old_ppid)) = self.context_snapshot.get(&process.pid) {
                if same_process(old_id, &id)
                    && (*old_session != process.session || *old_ppid != process.ppid)
                {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "process.context_changed",
                        &format!(
                            "pid={} session={} -> {} ppid={} -> {}",
                            process.pid, old_session, process.session, old_ppid, process.ppid
                        ),
                    )?;
                }
            }
            self.context_snapshot
                .insert(process.pid, (id, process.session, process.ppid));
        }

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
                    if st.skipped > 0 {
                        // Partial visibility is not evidence of disappearance;
                        // the durable identity diff will retry on a clean scan.
                        continue;
                    }
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

        let mut unknown_rows = 0usize;
        let mut deep_targets = Vec::new();
        for p in &outcome.processes {
            if lab_observer_target.is_some_and(|target| target != p.pid) {
                continue;
            }
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
            // READY_FOR_REVALIDATION is deliberately reopened below; other
            // terminal states remain fail-closed until disappearance/change.
            if self
                .supervisor
                .state_of(p.pid)
                .is_some_and(|s| s.terminal() && s != State::ReadyForRevalidation)
            {
                continue;
            }
            let base_prot = protect(p, self_pid, &rel, uid);
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
            #[cfg(unix)]
            let service_attestation = if lab_member {
                std::env::var_os("REAPER_LAB_SERVICE_SOCKET").and_then(|path| {
                    let entry = lab::current_registry()
                        .ok()?
                        .into_iter()
                        .find(|entry| entry.pid == p.pid && entry.start_ticks == p.start_ticks)?;
                    managed_service::attest_lab_service(&entry, std::path::Path::new(&path)).ok()
                })
            } else {
                None
            };
            #[cfg(not(unix))]
            let service_attestation: Option<managed_service::LabAttestation> = None;
            let coverage = service_attestation
                .as_ref()
                .map(|attestation| attestation.coverage)
                .unwrap_or(coverage);
            let owner_active = service_attestation
                .as_ref()
                .map(|attestation| Some(attestation.owner_active))
                .unwrap_or(owner_active);
            let owner_evidence = match owner::resolve(&claims, p) {
                owner::OwnerVerdict::ClaimedActive { service } => {
                    owner::OwnerVerdict::ClaimedActive { service }
                }
                owner::OwnerVerdict::ClaimedDown { service } => {
                    owner::OwnerVerdict::ClaimedDown { service }
                }
                owner::OwnerVerdict::Unclaimed => owner::OwnerVerdict::Unclaimed,
            };
            let owner_fingerprint = format!("{owner_evidence:?}");
            if let Some((old_id, old_owner)) = self.owner_snapshot.get(&p.pid) {
                if same_process(old_id, &id) && old_owner != &owner_fingerprint {
                    st.log_bytes += logx::log(
                        &self.log_cfg,
                        logx::Level::Info,
                        "owner.changed",
                        &format!("pid={} owner={} -> {}", p.pid, old_owner, owner_fingerprint),
                    )?;
                }
            }
            self.owner_snapshot
                .insert(p.pid, (id.clone(), owner_fingerprint));
            let client_work = if service_attestation.is_some() {
                if service_attestation
                    .as_ref()
                    .is_some_and(|attestation| attestation.owner_active)
                {
                    evidence::ClientWorkState::Active {
                        reason: "SCM_CREDENTIALS-verified lab clients or service jobs active"
                            .into(),
                    }
                } else {
                    evidence::ClientWorkState::IdleVerified {
                        surfaces: vec![
                            "0700 Unix-domain socket peer roster".into(),
                            "authenticated lab job ledger".into(),
                        ],
                    }
                }
            } else if adapter.name() == "opencode" {
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
            let current = self.supervisor.state_of(p.pid);
            let grace_expired = current == Some(State::ReadyForRevalidation)
                || (current == Some(State::GracePeriod)
                    && self.supervisor.grace_expired(p.pid, now));
            let ev = evidence::AbandonEvidence {
                lab_member,
                owner: owner_evidence.clone(),
                grace_expired,
                revalidated_now: grace_expired,
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
                proven_abandoned: evidence::candidate_for_grace(&ev),
                needs_tolerance: false,
                memory_pressure: false,
                client_coverage: coverage,
            };
            let positively_verified_inactive =
                matches!(client_work, evidence::ClientWorkState::IdleVerified { .. })
                    && coverage == client_tracker::Coverage::CompleteVerified
                    && owner_active == Some(false);
            let work_activity = match client_work {
                evidence::ClientWorkState::Active { .. } => Some(true),
                evidence::ClientWorkState::IdleVerified { .. } => Some(false),
                evidence::ClientWorkState::Unknown { .. }
                | evidence::ClientWorkState::Error { .. }
                | evidence::ClientWorkState::WorkAbsent { .. } => None,
            };
            let classification_activity =
                client_tracker::combine_signals(owner_active, work_activity);
            let (class, _prot, mut decision) = classified_decision(
                p,
                &id,
                &rel,
                &owner_evidence,
                classification_activity,
                positively_verified_inactive,
                base_prot,
                &self.policy,
                &signals,
                &[],
            );
            let process_fault = if owner_active.is_none() {
                Some(state::OperationalFault::Connectivity)
            } else if coverage != client_tracker::Coverage::CompleteVerified {
                Some(state::OperationalFault::UnverifiableClients)
            } else if current == Some(State::GracePeriod) && !evidence::candidate_for_grace(&ev) {
                Some(state::OperationalFault::StaleEvidence)
            } else {
                startup_fault
            };
            let action_candidate = matches!(
                &decision,
                Decision::GraceCandidate { .. } | Decision::ReadyForRevalidation { .. }
            ) || matches!(
                current,
                Some(State::GracePeriod | State::ReadyForRevalidation)
            );
            if action_candidate && (emergency_stop || faulted || process_fault.is_some()) {
                decision = Decision::Blocked {
                    reason: if emergency_stop {
                        "emergency stop engaged".into()
                    } else if process_fault == Some(state::OperationalFault::Connectivity) {
                        "adapter connectivity lost; automatic action blocked".into()
                    } else if process_fault == Some(state::OperationalFault::UnverifiableClients) {
                        "client evidence unverifiable; automatic action blocked".into()
                    } else if process_fault == Some(state::OperationalFault::StaleEvidence) {
                        "grace evidence stale; automatic action blocked".into()
                    } else {
                        "operational evidence fault; automatic action blocked".into()
                    },
                };
            }
            if class == identity::ProcessClass::Unknown {
                unknown_rows += 1;
                let name = adapter.name();
                if name == "opencode" || name == "codex" {
                    deep_targets.push((p.pid, name.to_owned()));
                }
            }
            if current == Some(State::ReadyForRevalidation) {
                decision = if evidence::proven(&ev)
                    && coverage == client_tracker::Coverage::CompleteVerified
                {
                    Decision::ReadyForRevalidation {
                        reason: "fresh post-grace evidence and policy revalidation passed".into(),
                    }
                } else {
                    Decision::Blocked {
                        reason: "fresh post-grace evidence or complete client coverage missing"
                            .into(),
                    }
                };
                if !PILOT_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed)
                    && state::grace_start_allowed(emergency_stop, faulted)
                    && state::auto_action_initiation_allowed(process_fault)
                {
                    if let Some(entry) = lab::current_registry()?
                        .into_iter()
                        .find(|entry| entry.pid == p.pid && entry.start_ticks == p.start_ticks)
                    {
                        #[cfg(unix)]
                        let close_result =
                            if let Some(socket) = std::env::var_os("REAPER_LAB_SERVICE_SOCKET") {
                                let socket = std::path::PathBuf::from(socket);
                                if managed_service::attest_lab_service(&entry, &socket).is_ok() {
                                    match self.supervisor.grace_started_at(p.pid) {
                                        Some(started_at) => managed_service::close_ready_service(
                                            &entry,
                                            &socket,
                                            started_at,
                                            &self.emergency_stop_file,
                                        ),
                                        None => Err(io::Error::other(
                                            "grace start timestamp missing; close refused",
                                        )),
                                    }
                                } else {
                                    lab::close_ready_entry(&entry)
                                }
                            } else {
                                lab::close_ready_entry(&entry)
                            };
                        #[cfg(not(unix))]
                        let close_result = lab::close_ready_entry(&entry);
                        match close_result {
                            Ok(receipts) => {
                                for receipt in receipts {
                                    st.log_bytes += logx::log(
                                        &self.log_cfg,
                                        logx::Level::Info,
                                        "lab.close.stage",
                                        &format!("pid={} {receipt}", entry.pid),
                                    )?;
                                }
                            }
                            Err(error) => {
                                st.errors += 1;
                                st.log_bytes += logx::log(
                                    &self.log_cfg,
                                    logx::Level::Warn,
                                    "lab.close.refused",
                                    &format!("pid={} reason={error}", entry.pid),
                                )?;
                            }
                        }
                    }
                } else if !PILOT_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed) {
                    if let Some(entry) = lab::current_registry()?
                        .into_iter()
                        .find(|entry| entry.pid == p.pid && entry.start_ticks == p.start_ticks)
                    {
                        let reason = if emergency_stop {
                            "emergency stop engaged".to_owned()
                        } else {
                            format!("automatic close blocked by fault: {process_fault:?}")
                        };
                        lab::persist_close_receipt(&entry, std::slice::from_ref(&reason), &reason)?;
                    }
                }
            }
            // Rescue during grace: owner evidence flipped back while we hold a
            // deadline — cancel explicitly and say so.
            if current == Some(State::GracePeriod)
                && (!state::inflight_grace_allowed(process_fault)
                    || !matches!(decision, Decision::GraceCandidate { .. }))
            {
                let t = self.supervisor.transition(
                    &id,
                    State::Observing,
                    now,
                    "owner:rescue-during-grace",
                    "policy-10",
                    "policy re-evaluation no longer authorizes grace; close cancelled",
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
                && matches!(decision, Decision::GraceCandidate { .. })
                && self.supervisor.grace_expired(p.pid, now)
            {
                next = State::ReadyForRevalidation;
            }
            // Fresh sightings start at Discovered (terminal states were skipped
            // above and disappearance is handled through events).
            let from = current.unwrap_or(State::Discovered);
            if next != from {
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
                if matches!(next, State::GracePeriod)
                    && state::grace_start_allowed(emergency_stop, faulted)
                {
                    let grace = match &decision {
                        Decision::GraceCandidate { grace_secs, .. } => *grace_secs,
                        _ => self.policy.grace_known_secs,
                    };
                    self.supervisor.arm_grace_at(p.pid, now, now + grace);
                }
            }
        }

        if st.skipped == 0 {
            let visible: std::collections::HashSet<_> = outcome
                .processes
                .iter()
                .map(|process| process.pid)
                .collect();
            self.context_snapshot.retain(|pid, _| visible.contains(pid));
            self.owner_snapshot.retain(|pid, _| visible.contains(pid));
        }

        if !PILOT_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed)
            && !outcome.processes.is_empty()
            && unknown_rows.saturating_mul(2) >= outcome.processes.len()
            && pilot::schedule_deep_targets(
                &self.deep_scheduler,
                deep_targets,
                Duration::from_secs(35),
            )
        {
            st.log_bytes += logx::log(
                &self.log_cfg,
                logx::Level::Info,
                "deep.scheduled",
                &format!(
                    "unknown_rows={} total_rows={} scheduled_runs={} pending={} budget_secs=35 bounded_workers=2",
                    unknown_rows,
                    outcome.processes.len(),
                    self.deep_scheduler.scheduled(),
                    self.deep_scheduler.pending()
                ),
            )?;
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
        if PILOT_READ_ONLY.load(std::sync::atomic::Ordering::Relaxed) {
            st.log_bytes += logx::log(
                &self.log_cfg,
                logx::Level::Info,
                "pilot.cycle.record",
                &format!("appeared_or_changed={} disappeared_or_transitions={} errors={} entries={} rss_kib={} cpu_ticks={} swap_total_kib={} swap_free_kib={} log_growth_bytes={}", st.events, st.transitions, st.errors, st.inspected, usage.rss_kib, usage.cpu_ticks, st.swap_total_kib, st.swap_free_kib, st.log_bytes),
            )?;
        }
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
    if state::EmergencyStop::is_engaged_at(&logx::default_state_dir().join("emergency-stop"))? {
        println!("close receipt: refused; emergency stop engaged; no signal");
        return Ok(());
    }
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
            None,
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
    let rel = relations::build(std::slice::from_ref(&p));
    let base = protect(&p, std::process::id(), &rel, p.uid);
    let approval = terminate::approve_fresh(terminate::FreshApprovalInputs {
        evidence: evidence.clone(),
        process: p.clone(),
        protection: base,
        policy: Policy::default(),
        signals: Signals {
            owner_reports_active: evidence.owner_dead.map(|dead| !dead),
            proven_abandoned: evidence::proven(&evidence),
            needs_tolerance: false,
            memory_pressure: false,
            client_coverage: client_tracker::Coverage::Unknown,
        },
    });
    let Some(approval) = approval else {
        println!("close receipt: refused; fresh policy approval unavailable; no signal");
        return Ok(());
    };
    if state::EmergencyStop::is_engaged_at(&logx::default_state_dir().join("emergency-stop"))? {
        println!("close receipt: refused; emergency stop engaged before actuation; no signal");
        return Ok(());
    }
    let mut s = terminate::PidfdSignaller;
    for receipt in terminate::close_sequence(
        &rec,
        &policy,
        Some(&approval),
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

fn cmd_observe(
    interval: u64,
    state_dir: &std::path::Path,
    pilot_read_only: bool,
) -> io::Result<()> {
    PILOT_READ_ONLY.store(pilot_read_only, std::sync::atomic::Ordering::Relaxed);
    let _observer_lock = pilot::observer_lock(state_dir)?;
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
    if let Some(recovery) = supervisor.recovery_message() {
        let _ = logx::log(
            &log_cfg,
            logx::Level::Warn,
            "state.recovered_fresh",
            recovery,
        );
        eprintln!("state recovery: {recovery}; observer continues with fresh state");
    }
    let restart_faulted = if pilot_read_only {
        pilot::heartbeat_gap(state_dir, interval, outcome.processes.len())?.is_some()
    } else {
        false
    };
    let startup_fault = if supervisor.recovery_message().is_some() {
        Some(state::OperationalFault::CorruptState)
    } else if restart_faulted {
        Some(state::OperationalFault::UnexpectedRestart)
    } else {
        None
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
        deep_scheduler: pilot::DeepScheduler::default(),
        context_snapshot: HashMap::new(),
        owner_snapshot: HashMap::new(),
        emergency_stop_file: state_dir.join("emergency-stop"),
        startup_fault,
    };
    let mut failures = 0u32;
    loop {
        match obs.cycle() {
            Ok(st) => {
                failures = 0;
                if pilot_read_only {
                    pilot::heartbeat(state_dir, interval, st.inspected)?;
                }
                let u = stats::self_usage();
                println!("{} {}", logx::now_secs(), st.summary(&u));
                let _ = &obs.usage_start;
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                eprintln!("cycle error (continuing): {e}");
            }
        }
        let delay = if failures == 0 {
            Duration::from_secs(interval)
        } else {
            pilot::retry_delay(interval, failures)
        };
        thread::sleep(delay);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let state_dir = logx::default_state_dir();
    let result = match args.get(1).map(String::as_str) {
        Some("managed-service") if args.get(2).map(String::as_str) == Some("serve") => {
            managed_service::serve()
        }
        Some("managed-service") if args.get(2).map(String::as_str) == Some("serve-uds") => {
            #[cfg(unix)]
            {
                managed_service::serve_uds()
            }
            #[cfg(not(unix))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SCM_CREDENTIALS UDS service requires Unix",
                ))
            }
        }
        Some("managed-service") if args.get(2).map(String::as_str) == Some("demo") => {
            #[cfg(unix)]
            {
                let grace = args
                    .iter()
                    .position(|arg| arg == "--grace-secs")
                    .and_then(|index| args.get(index + 1))
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(2)
                    .clamp(1, 300);
                managed_service::run_demo(grace)
            }
            #[cfg(not(unix))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "the credentialed lab demo requires Unix sockets",
                ))
            }
        }
        Some("managed-service") if args.get(2).map(String::as_str) == Some("client-agent") => {
            #[cfg(unix)]
            {
                match args.get(3) {
                    Some(path) => managed_service::client_agent(std::path::Path::new(path)),
                    None => Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "missing UDS path",
                    )),
                }
            }
            #[cfg(not(unix))]
            {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unix sockets unavailable",
                ))
            }
        }
        Some("lab") => cmd_lab(),
        Some("emergency-stop") => {
            state::EmergencyStop::engage_at(&PathBuf::from(&state_dir).join("emergency-stop"))
                .map(|()| println!("emergency stop engaged; observation remains available"))
        }
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
            Some("smoke") => args
                .get(3)
                .and_then(|s| s.parse::<usize>().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Usage: pilot smoke N"))
                .and_then(|n| pilot::smoke(&PathBuf::from(&state_dir), n)),
            Some("metrics") => pilot::metrics(&PathBuf::from(&state_dir)),
            Some("start") => {
                let interval = args
                    .iter()
                    .position(|a| a == "--interval")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(30)
                    .clamp(5, 3600);
                pilot::start(&PathBuf::from(&state_dir), interval)
            }
            Some("status") => pilot::status(&PathBuf::from(&state_dir)),
            Some("stop") => pilot::stop(&PathBuf::from(&state_dir)),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Usage: pilot report|metrics|start|status|stop|smoke N",
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
            cmd_observe(
                seconds,
                &PathBuf::from(&state_dir),
                args.iter().any(|a| a == "--pilot-read-only"),
            )
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

    fn fixture(name: &str, ppid: u32) -> (procfs::Process, Relations) {
        let p = procfs::Process {
            pid: 50,
            ppid,
            pgrp: 50,
            session: 60,
            start_ticks: 10,
            state: 'S',
            name: name.into(),
            command: name.into(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(10373),
        };
        let parent = procfs::Process {
            pid: ppid,
            ppid,
            pgrp: ppid,
            session: ppid,
            start_ticks: 1,
            state: 'S',
            name: "parent".into(),
            command: "parent".into(),
            rss_kib: 0,
            swap_kib: 0,
            uid: Some(10373),
        };
        let rel = relations::build(&[parent, p.clone()]);
        (p, rel)
    }

    #[test]
    fn durable_diff_treats_pid_reuse_as_death_and_birth() {
        let old = identity::ProcessIdentity {
            boot_id: Some("boot".into()),
            pid: 9,
            start_ticks: 10,
            uid: Some(1),
            exe: "old".into(),
        };
        let new = identity::ProcessIdentity {
            start_ticks: 11,
            exe: "new".into(),
            ..old.clone()
        };
        let changes = durable_identity_diff(&[(9, old)], &[(9, new)]);
        assert!(changes
            .iter()
            .any(|change| matches!(change, DurableChange::Disappeared(_))));
        assert!(changes
            .iter()
            .any(|change| matches!(change, DurableChange::Appeared(_))));
        assert!(!changes
            .iter()
            .any(|change| matches!(change, DurableChange::Changed(_, _))));
    }

    fn signals(active: Option<bool>) -> Signals {
        Signals {
            owner_reports_active: active,
            proven_abandoned: false,
            needs_tolerance: false,
            memory_pressure: false,
            client_coverage: client_tracker::Coverage::Unknown,
        }
    }

    #[test]
    fn candidate_evidence_enters_candidate_before_grace() {
        assert_eq!(
            decide_state(
                &Decision::GraceCandidate {
                    grace_secs: 300,
                    reason: "candidate evidence".into(),
                },
                None,
            ),
            State::Candidate
        );
        assert_eq!(
            decide_state(
                &Decision::GraceCandidate {
                    grace_secs: 300,
                    reason: "candidate evidence".into(),
                },
                Some(State::Candidate),
            ),
            State::GracePeriod
        );
    }

    fn observer_with_tracked_self(state: State) -> (Observer, PathBuf, u32) {
        let pid = std::process::id();
        let process = procfs::scan()
            .processes
            .into_iter()
            .find(|process| process.pid == pid)
            .expect("test process is present in procfs");
        let boot_id = identity::read_boot_id();
        let id = identity::identify(&process, boot_id.clone());
        let root = std::env::temp_dir().join(format!(
            "reaper-v8t4-cycle-{}-{}-{}",
            pid,
            process.start_ticks,
            state.as_str()
        ));
        let state_file = root.join("supervisor.state");
        let mut supervisor = Supervisor::new(state_file);
        supervisor.transition(
            &id,
            state,
            1,
            "test:tracked-self",
            "test-policy",
            "deterministic observer-cycle fixture",
        );
        if state == State::GracePeriod {
            supervisor.arm_grace(pid, u64::MAX);
        }
        let log_dir = root.join("logs");
        let obs = Observer {
            tracker: Tracker::new(boot_id.clone()),
            supervisor,
            policy: Policy::default(),
            log_cfg: logx::LogConfig::new(log_dir),
            boot_id,
            usage_start: stats::self_usage(),
            deep_scheduler: pilot::DeepScheduler::default(),
            context_snapshot: HashMap::new(),
            owner_snapshot: HashMap::new(),
            emergency_stop_file: std::env::temp_dir().join("reaper-test-no-estop"),
            startup_fault: None,
        };
        (obs, root, pid)
    }

    #[test]
    fn expired_grace_revalidates_ready_entry_using_fresh_cycle_evidence() {
        let (mut obs, root, pid) = observer_with_tracked_self(State::ReadyForRevalidation);
        obs.cycle().expect("read-only observer cycle succeeds");
        assert_eq!(
            obs.supervisor.state_of(pid),
            Some(State::TerminationBlocked)
        );
        let log = fs::read_dir(root.join("logs"))
            .expect("cycle log directory exists")
            .filter_map(Result::ok)
            .map(|entry| fs::read_to_string(entry.path()).expect("read cycle log"))
            .collect::<String>();
        assert!(log.contains("fresh post-grace evidence or complete client coverage missing"));
    }

    #[test]
    fn ready_lab_entry_runs_final_gate_and_persists_refusal_without_signalling_unknown_target() {
        let _guard = lab::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let pid = std::process::id();
        let registry = std::env::temp_dir().join(format!("reaper-ready-lab-{pid}.json"));
        std::env::set_var("REAPER_LAB_REGISTRY", &registry);
        let child = lab::spawn(false).expect("spawn registered lab child");
        lab::persist_close_receipt(&child.entry, &["term_sent".into()], "in_progress")
            .expect("persist fabricated mid-close state");
        let process = procfs::scan()
            .processes
            .into_iter()
            .find(|process| process.pid == child.id())
            .expect("lab child visible");
        let boot_id = identity::read_boot_id();
        let id = identity::identify(&process, boot_id.clone());
        let root = std::env::temp_dir().join(format!("reaper-ready-lab-cycle-{pid}"));
        let mut supervisor = Supervisor::new(root.join("supervisor.state"));
        supervisor.transition(
            &id,
            State::ReadyForRevalidation,
            1,
            "test:ready-lab",
            "test-policy",
            "readiness feeds final close gate",
        );
        let mut observer = Observer {
            tracker: Tracker::new(boot_id.clone()),
            supervisor,
            policy: Policy::default(),
            log_cfg: logx::LogConfig::new(root.join("logs")),
            boot_id,
            usage_start: stats::self_usage(),
            deep_scheduler: pilot::DeepScheduler::default(),
            context_snapshot: HashMap::new(),
            owner_snapshot: HashMap::new(),
            emergency_stop_file: std::env::temp_dir().join("reaper-test-no-estop"),
            startup_fault: None,
        };

        observer.cycle().expect("observer cycle");
        let receipt = fs::read_to_string(lab::receipt_path_current()).expect("refusal receipt");
        assert!(receipt.contains("\"verdict\":\"refused\""), "{receipt}");
        assert!(
            lab::identity_ticks(child.id()).is_ok(),
            "refusal signalled child"
        );
        drop(child);
    }

    #[test]
    fn policy_rescue_during_grace_cancels_without_readiness() {
        let (mut obs, root, pid) = observer_with_tracked_self(State::GracePeriod);
        obs.cycle().expect("read-only observer cycle succeeds");
        assert_eq!(obs.supervisor.state_of(pid), Some(State::Observing));
        obs.cycle()
            .expect("subsequent read-only cycle does not reauthorize stale grace");
        assert!(!obs
            .supervisor
            .state_of(pid)
            .is_some_and(|state| state == State::ReadyForRevalidation));
        let log = fs::read_dir(root.join("logs"))
            .expect("cycle log directory exists")
            .filter_map(Result::ok)
            .map(|entry| fs::read_to_string(entry.path()).expect("read cycle log"))
            .collect::<String>();
        assert!(log.contains("grace.cancelled"));
        assert!(log.contains("policy re-evaluation no longer authorizes grace; close cancelled"));
    }

    #[test]
    fn candidate_grade_policy_decision_is_not_close_readiness() {
        let mut ev = evidence::AbandonEvidence {
            lab_member: true,
            owner: owner::OwnerVerdict::Unclaimed,
            grace_expired: false,
            revalidated_now: false,
            owner_dead: Some(true),
            last_client_gone: Some(true),
            no_pending_work: Some(true),
        };
        assert!(evidence::candidate_for_grace(&ev));
        assert!(!evidence::proven(&ev));
        let (process, _) = fixture("worker", 1);
        let decision = policy::decide(
            &Policy::default(),
            &Protection {
                tier: Tier::Known,
                reason: "test known process".into(),
            },
            &process,
            &Signals {
                owner_reports_active: Some(false),
                proven_abandoned: evidence::candidate_for_grace(&ev),
                needs_tolerance: false,
                memory_pressure: false,
                client_coverage: client_tracker::Coverage::CompleteVerified,
            },
        );
        assert!(matches!(decision, Decision::GraceCandidate { .. }));
        ev.grace_expired = true;
        ev.revalidated_now = true;
        assert!(evidence::proven(&ev));
    }

    #[test]
    fn production_decision_keeps_unknown_protected_and_orphan_unabandoned() {
        let (p, rel) = fixture("worker", 1);
        let id = identity::identify(&p, None);
        let owner = owner::OwnerVerdict::Unclaimed;
        let (class, protection, decision) = classified_decision(
            &p,
            &id,
            &rel,
            &owner,
            None,
            false,
            Protection {
                tier: Tier::Known,
                reason: "base".into(),
            },
            &Policy::default(),
            &signals(None),
            &[],
        );
        assert_eq!(class, identity::ProcessClass::Unknown);
        assert_eq!(protection.tier, Tier::Unknown);
        assert!(matches!(decision, Decision::KeepProtected { .. }));
        assert!(!evidence::proven(&evidence::AbandonEvidence {
            lab_member: false,
            owner,
            grace_expired: true,
            revalidated_now: true,
            owner_dead: Some(true),
            last_client_gone: Some(true),
            no_pending_work: Some(true),
        }));
    }

    #[test]
    fn production_decision_never_lowers_absolute_protection_on_misclassification() {
        struct Wrong;
        impl identity::Classifier for Wrong {
            fn classify(
                &self,
                _: &identity::ClassificationEvidence<'_>,
            ) -> Option<identity::ProcessClass> {
                Some(identity::ProcessClass::Independent)
            }
        }
        let (p, rel) = fixture("worker", 8);
        let id = identity::identify(&p, None);
        let owner = owner::OwnerVerdict::Unclaimed;
        let wrong = Wrong;
        let (_, protection, decision) = classified_decision(
            &p,
            &id,
            &rel,
            &owner,
            Some(false),
            true,
            Protection {
                tier: Tier::Absolute,
                reason: "absolute".into(),
            },
            &Policy::default(),
            &signals(Some(false)),
            &[&wrong],
        );
        assert_eq!(protection.tier, Tier::Absolute);
        assert!(matches!(
            decision,
            Decision::KeepProtected {
                tier: Tier::Absolute,
                ..
            }
        ));
    }

    #[test]
    fn production_decision_protects_extension_class_and_evaluates_verified_inactive() {
        struct Critical;
        impl identity::Classifier for Critical {
            fn classify(
                &self,
                _: &identity::ClassificationEvidence<'_>,
            ) -> Option<identity::ProcessClass> {
                Some(identity::ProcessClass::Critical)
            }
        }
        let (p, rel) = fixture("ordinary", 8);
        let id = identity::identify(&p, None);
        let owner = owner::OwnerVerdict::Unclaimed;
        let critical = Critical;
        let (_, protection, decision) = classified_decision(
            &p,
            &id,
            &rel,
            &owner,
            Some(true),
            false,
            Protection {
                tier: Tier::Known,
                reason: "base".into(),
            },
            &Policy::default(),
            &signals(Some(true)),
            &[&critical],
        );
        assert_eq!(protection.tier, Tier::Contextual);
        assert!(matches!(decision, Decision::KeepProtected { .. }));

        let (_, protection, decision) = classified_decision(
            &p,
            &id,
            &rel,
            &owner,
            Some(false),
            true,
            Protection {
                tier: Tier::Known,
                reason: "base".into(),
            },
            &Policy::default(),
            &signals(Some(false)),
            &[],
        );
        assert_eq!(protection.tier, Tier::Known);
        assert!(matches!(decision, Decision::Blocked { .. }));
    }

    #[test]
    fn spoofed_name_and_old_sleeper_do_not_classify_as_candidate() {
        for name in ["runsv", "ancient-sleeper"] {
            let (p, rel) = fixture(name, 1);
            let id = identity::identify(&p, None);
            let owner = owner::OwnerVerdict::Unclaimed;
            let (class, protection, decision) = classified_decision(
                &p,
                &id,
                &rel,
                &owner,
                None,
                false,
                Protection {
                    tier: Tier::Known,
                    reason: "base".into(),
                },
                &Policy::default(),
                &signals(None),
                &[],
            );
            assert_ne!(class, identity::ProcessClass::Independent);
            assert_ne!(protection.tier, Tier::Known);
            assert!(!matches!(decision, Decision::GraceCandidate { .. }));
        }
    }

    #[test]
    fn runit_process_name_without_identity_claim_is_not_a_service() {
        let adapter = adapter_for("runsv", "/usr/bin/runsv");
        assert_eq!(adapter.name(), "generic-linux");
    }
}
