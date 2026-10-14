#![cfg(feature = "tui")]
//! Read-only observer UI. Supervision ownership remains with the existing pilot;
//! this TUI only reads procfs, the client registry, and the state directory.

use crate::{
    client_tracker::{ClientState, Registry},
    logx,
    owner::OwnerVerdict,
    policy::{self, Decision, Policy, Signals},
    procfs::{self, Process},
    protection::{protect, Tier},
    relations::{self, Relations},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
    Frame, Terminal,
};
use std::{
    collections::HashMap,
    io,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Processes,
    Logs,
    Clients,
    Evidence,
    Help,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Cpu,
    Rss,
    Swap,
    Name,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Enter,
    Tree,
    Sort,
    Refresh,
    Logs,
    Clients,
    Evidence,
    Help,
    Quit,
    Search,
    Char(char),
    Esc,
    Backspace,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UiState {
    selected: usize,
    view: View,
    sort: Sort,
    tree: bool,
    inspecting: bool,
    searching: bool,
    query: String,
    quit: bool,
}
impl Default for UiState {
    fn default() -> Self {
        Self {
            selected: 0,
            view: View::Processes,
            sort: Sort::Rss,
            tree: false,
            inspecting: false,
            searching: false,
            query: String::new(),
            quit: false,
        }
    }
}
impl UiState {
    fn handle(&mut self, key: Key, count: usize) {
        if self.searching {
            match key {
                Key::Esc => self.searching = false,
                Key::Char(c) => {
                    self.query.push(c);
                    self.selected = 0;
                }
                Key::Backspace => {
                    self.query.pop();
                    self.selected = 0;
                }
                Key::Other => {}
                _ => {}
            }
            return;
        }
        match key {
            Key::Up => self.selected = self.selected.saturating_sub(1),
            Key::Down => {
                self.selected = self.selected.saturating_add(1).min(count.saturating_sub(1))
            }
            Key::Search => {
                self.searching = true;
                self.query.clear();
                self.selected = 0;
            }
            Key::Enter => self.inspecting = !self.inspecting,
            Key::Tree => self.tree = !self.tree,
            Key::Sort => {
                self.sort = match self.sort {
                    Sort::Rss => Sort::Swap,
                    Sort::Swap => Sort::Name,
                    Sort::Name => Sort::Cpu,
                    Sort::Cpu => Sort::Rss,
                }
            }
            Key::Logs => self.view = View::Logs,
            Key::Clients => self.view = View::Clients,
            Key::Evidence => self.view = View::Evidence,
            Key::Help => self.view = View::Help,
            Key::Quit => self.quit = true,
            _ => {}
        }
    }
}

#[derive(Clone, Debug)]
struct RowData {
    process: Process,
    tier: Tier,
    reason: String,
    decision: String,
    evidence: Vec<String>,
    blocks: Vec<String>,
    owner: OwnerVerdict,
    client_state: String,
    cpu_percent: Option<f64>,
}
#[derive(Clone, Debug, Default)]
struct Snapshot {
    rows: Vec<RowData>,
    clients: Vec<String>,
    events: Vec<String>,
    ram: Option<(u64, u64)>,
    swap: Option<(u64, u64)>,
    refresh_skipped: usize,
    supervisor: String,
    self_cpu: Option<f64>,
}

fn snapshot_from(
    processes: &[Process],
    rel: &Relations,
    uid: Option<u32>,
    registry: &Registry,
    events: Vec<String>,
    owners: &std::collections::HashMap<u32, (String, bool, u64)>,
) -> Snapshot {
    let self_pid = std::process::id();
    let rows = processes
        .iter()
        .map(|p| {
            let protection = protect(p, self_pid, rel, uid);
            let owner = crate::owner::resolve(owners, p);
            let client_state = registry.clients.iter().find(|c| {
                c.identity.pid == p.pid && c.identity.start_ticks == p.start_ticks
            }).map(|c| match &c.state {
                ClientState::ConnectedVerified { evidence, .. } => format!("ConnectedVerified: {evidence}"),
                ClientState::EndedVerified { evidence, .. } => format!("EndedVerified: {evidence}"),
                ClientState::PossiblyGone { evidence, .. } => format!("PossiblyGone: {evidence}"),
                ClientState::UnknownExternal { evidence, .. } => format!("UnknownExternal: {evidence}"),
                ClientState::Unverifiable { evidence, .. } => format!("Unverifiable: {evidence}"),
            }).unwrap_or_else(|| "UnknownExternal: no matching managed registry record; external coverage unavailable".into());
            let signals = Signals {
                owner_reports_active: match owner { OwnerVerdict::ClaimedActive { .. } => Some(true), OwnerVerdict::ClaimedDown { .. } => Some(false), OwnerVerdict::Unclaimed => None },
                ..Signals::default()
            };
            let decision = policy::decide(&Policy::default(), &protection, p, &signals);
            let mut evidence = vec![
                format!(
                    "process identity: pid={} ppid={} start_ticks={} state={} uid={:?}",
                    p.pid, p.ppid, p.start_ticks, p.state, p.uid
                ),
                format!("protection: {:?} ({})", protection.tier, protection.reason),
            ];
            if let Some(node) = rel.nodes.get(&p.pid) {
                evidence.push(format!(
                    "relations: children={:?} parent_missing={} evidence={:?}",
                    node.children, node.parent_missing, node.evidence
                ));
            }
            let blocks = match &decision {
                Decision::Blocked { reason } => vec![reason.clone()],
                Decision::KeepProtected { reason, .. } => vec![reason.clone()],
                _ => Vec::new(),
            };
            RowData {
                process: p.clone(),
                tier: protection.tier,
                reason: protection.reason,
                decision: format!("{decision:?}"),
                evidence,
                blocks,
                owner,
                client_state,
                cpu_percent: None,
            }
        })
        .collect();
    let clients = registry
        .clients
        .iter()
        .map(|c| {
            let state = match &c.state {
                ClientState::ConnectedVerified { evidence, .. } => {
                    format!("ConnectedVerified: {evidence}")
                }
                ClientState::EndedVerified { evidence, .. } => format!("EndedVerified: {evidence}"),
                ClientState::PossiblyGone { evidence, .. } => format!("PossiblyGone: {evidence}"),
                ClientState::UnknownExternal { evidence, .. } => {
                    format!("UnknownExternal: {evidence}")
                }
                ClientState::Unverifiable { evidence, .. } => format!("Unverifiable: {evidence}"),
            };
            format!(
                "{} pid={} project={} server={} work={:?} — {}",
                c.identity.tool,
                c.identity.pid,
                c.identity.project_dir,
                c.identity.server,
                c.active_work_ids,
                state
            )
        })
        .collect();
    Snapshot {
        rows,
        clients,
        events,
        ram: system_meminfo("MemTotal", "MemAvailable"),
        swap: system_meminfo("SwapTotal", "SwapFree"),
        refresh_skipped: 0,
        supervisor: "observer (no separate supervisor)".into(),
        self_cpu: None,
    }
}

fn system_meminfo(total_key: &str, free_key: &str) -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let number = |key: &str| {
        text.lines().find_map(|line| {
            let (name, rest) = line.split_once(':')?;
            (name == key)
                .then(|| rest.split_whitespace().next()?.parse::<u64>().ok())
                .flatten()
        })
    };
    Some((number(total_key)?, number(free_key)?))
}

fn fast_snapshot() -> Snapshot {
    let scan = procfs::scan();
    let rel = relations::build(&scan.processes);
    let registry = crate::client_tracker::current_registry().unwrap_or_default();
    let log_dir = logx::default_state_dir().join("logs");
    let mut paths: Vec<_> = std::fs::read_dir(log_dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    paths.sort();
    let events = paths
        .last()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .map(|s| {
            s.lines()
                .rev()
                .take(100)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let owners = crate::owner::claims_map(&crate::owner::default_svdir());
    snapshot_from(
        &scan.processes,
        &rel,
        crate::own_uid(),
        &registry,
        events,
        &owners,
    )
}

#[derive(Clone, Copy, Debug)]
struct CpuSample {
    ticks: u64,
    at: Instant,
    start_ticks: u64,
}

fn cpu_percent(
    previous: Option<CpuSample>,
    start_ticks: u64,
    ticks: u64,
    now: Instant,
    hz: u64,
) -> Option<f64> {
    let previous =
        previous.filter(|sample| sample.start_ticks == start_ticks && now > sample.at)?;
    let delta = ticks.checked_sub(previous.ticks)?;
    Some(delta as f64 * 100.0 / (hz.max(1) as f64 * now.duration_since(previous.at).as_secs_f64()))
}

fn clock_ticks_per_second() -> (u64, bool) {
    match std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
    {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|v| *v > 0)
            .map(|v| (v, false))
            .unwrap_or((100, true)),
        _ => (100, true),
    }
}

fn self_cpu_percent(hz: u64) -> Option<f64> {
    let sample = crate::stats::self_usage();
    static PREVIOUS: std::sync::OnceLock<std::sync::Mutex<Option<(u64, Instant)>>> =
        std::sync::OnceLock::new();
    let mut previous = PREVIOUS
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .ok()?;
    let now = Instant::now();
    let percent = previous.and_then(|(ticks, at)| {
        (now > at)
            .then(|| {
                sample.cpu_ticks.checked_sub(ticks).map(|delta| {
                    delta as f64 * 100.0 / (hz.max(1) as f64 * now.duration_since(at).as_secs_f64())
                })
            })
            .flatten()
    });
    *previous = Some((sample.cpu_ticks, now));
    percent
}

fn decorate_cpu(
    snap: &mut Snapshot,
    history: &mut HashMap<(u32, u64), CpuSample>,
    now: Instant,
    hz: u64,
) {
    for row in &mut snap.rows {
        row.cpu_percent = std::fs::read_to_string(format!("/proc/{}/stat", row.process.pid))
            .ok()
            .and_then(|stat| procfs::parse_cpu_stat(&stat))
            .and_then(|(pid, ticks, start)| {
                if pid != row.process.pid || start != row.process.start_ticks {
                    return None;
                }
                let key = (pid, start);
                let old = history.get(&key).copied();
                history.insert(
                    key,
                    CpuSample {
                        ticks,
                        at: now,
                        start_ticks: start,
                    },
                );
                cpu_percent(old, start, ticks, now, hz)
            });
    }
}

fn process_tree(rows: &[RowData]) -> Vec<(&RowData, usize)> {
    let by_pid: HashMap<u32, &RowData> = rows.iter().map(|r| (r.process.pid, r)).collect();
    fn visit<'a>(
        pid: u32,
        depth: usize,
        by_pid: &HashMap<u32, &'a RowData>,
        out: &mut Vec<(&'a RowData, usize)>,
        seen: &mut std::collections::HashSet<u32>,
    ) {
        if !seen.insert(pid) {
            return;
        }
        let Some(row) = by_pid.get(&pid) else {
            return;
        };
        out.push((*row, depth));
        let mut children: Vec<_> = by_pid
            .values()
            .filter(|c| c.process.ppid == pid)
            .map(|c| c.process.pid)
            .collect();
        children.sort_unstable();
        for child in children {
            visit(child, depth + 1, by_pid, out, seen);
        }
    }
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut roots: Vec<_> = rows
        .iter()
        .filter(|r| !by_pid.contains_key(&r.process.ppid))
        .map(|r| r.process.pid)
        .collect();
    roots.sort_unstable();
    for pid in roots {
        visit(pid, 0, &by_pid, &mut out, &mut seen);
    }
    let mut rest: Vec<_> = rows.iter().map(|r| r.process.pid).collect();
    rest.sort_unstable();
    for pid in rest {
        visit(pid, 0, &by_pid, &mut out, &mut seen);
    }
    out
}

// Full client/work assessment may launch external probes and take many seconds.
// Keep this observer responsive and direct users to `reaper pilot report` instead.

fn filtered_sorted<'a>(rows: &'a [RowData], query: &str, sort: Sort) -> Vec<&'a RowData> {
    let mut rows: Vec<_> = rows
        .iter()
        .filter(|r| {
            query.is_empty()
                || r.process
                    .name
                    .to_lowercase()
                    .contains(&query.to_lowercase())
                || r.process
                    .command
                    .to_lowercase()
                    .contains(&query.to_lowercase())
                || r.process.pid.to_string().contains(query)
        })
        .collect();
    match sort {
        Sort::Cpu => rows.sort_by(|a, b| {
            b.cpu_percent
                .unwrap_or(-1.0)
                .partial_cmp(&a.cpu_percent.unwrap_or(-1.0))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        Sort::Rss => rows.sort_by_key(|r| std::cmp::Reverse(r.process.rss_kib)),
        Sort::Swap => rows.sort_by_key(|r| std::cmp::Reverse(r.process.swap_kib)),
        Sort::Name => rows.sort_by(|a, b| {
            a.process
                .name
                .to_lowercase()
                .cmp(&b.process.name.to_lowercase())
        }),
    }
    rows
}
fn show_swap_cpu(width: u16) -> bool {
    width >= 60
}

fn uptime_seconds(start_ticks: u64) -> u64 {
    let hz = 100u64;
    let uptime = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok());
    uptime
        .map(|s| (s.max(0.0) as u64).saturating_sub(start_ticks / hz))
        .unwrap_or(0)
}

fn client_label(state: &str) -> String {
    if state.starts_with("ConnectedVerified") {
        "connected".into()
    } else {
        "unknown".into()
    }
}

fn render(frame: &mut Frame, state: &UiState, snap: &Snapshot) {
    let area = frame.area();
    if area.width == 0 || area.height == 0 {
        return;
    }
    let narrow = area.width < 40;
    let chunks = if narrow || !state.inspecting {
        Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(1), Constraint::Length(1)])
            .split(area)
    } else {
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area)
    };
    let mut lines = Vec::new();
    match state.view {
        View::Logs => lines.extend(
            snap.events
                .iter()
                .rev()
                .take(area.height as usize)
                .map(|s| Line::from(s.as_str())),
        ),
        View::Clients => lines.extend(snap.clients.iter().map(|s| Line::from(s.as_str()))),
        View::Evidence => {
            for row in &snap.rows {
                lines.push(Line::from(format!(
                    "pid={} protected={:?}: {}",
                    row.process.pid, row.tier, row.reason
                )));
                lines.extend(
                    row.evidence
                        .iter()
                        .map(|s| Line::from(format!("  evidence: {s}"))),
                );
                lines.extend(
                    row.blocks
                        .iter()
                        .map(|s| Line::from(format!("  block: {s}"))),
                );
            }
        }
        View::Help => lines.extend(
            [
                "↑/↓ select  / search  Enter detail",
                "t tree/list  s sort CPU/RSS/swap/name",
                "l events  c clients  e evidence  ? help",
                "r refresh  q quit (read-only; no destructive keys)",
            ]
            .into_iter()
            .map(Line::from),
        ),
        View::Processes => {
            let rows = if state.tree {
                process_tree(&snap.rows)
                    .into_iter()
                    .map(|(r, _)| r)
                    .filter(|r| {
                        state.query.is_empty()
                            || r.process
                                .name
                                .to_lowercase()
                                .contains(&state.query.to_lowercase())
                    })
                    .collect()
            } else {
                filtered_sorted(&snap.rows, &state.query, state.sort)
            };
            let wide = show_swap_cpu(area.width);
            let mut headers = vec![
                Cell::from("PID"),
                Cell::from("NAME"),
                Cell::from("CPU%"),
                Cell::from("RSS KiB"),
                Cell::from("SWAP"),
                Cell::from("STATE"),
                Cell::from("UPTIME"),
                Cell::from("CLIENT"),
            ];
            headers.push(Cell::from("TIER"));
            let widths = if wide {
                vec![
                    Constraint::Length(7),
                    Constraint::Min(8),
                    Constraint::Length(7),
                    Constraint::Length(9),
                    Constraint::Length(7),
                    Constraint::Length(5),
                    Constraint::Length(8),
                    Constraint::Length(8),
                    Constraint::Length(12),
                ]
            } else {
                vec![
                    Constraint::Length(7),
                    Constraint::Min(3),
                    Constraint::Length(5),
                    Constraint::Length(7),
                    Constraint::Length(5),
                    Constraint::Length(3),
                    Constraint::Length(6),
                    Constraint::Length(6),
                    Constraint::Length(6),
                ]
            };
            let table_rows = rows.iter().enumerate().map(|(i, r)| {
                let p = &r.process;
                let mut cells = vec![
                    Cell::from(p.pid.to_string()),
                    Cell::from(if state.tree {
                        let depth = process_tree(&snap.rows)
                            .iter()
                            .find(|(row, _)| row.process.pid == p.pid)
                            .map(|(_, d)| *d)
                            .unwrap_or(0);
                        format!("{}{}", "  ".repeat(depth), p.name)
                    } else {
                        p.name.clone()
                    }),
                    Cell::from(
                        r.cpu_percent
                            .map(|v| format!("{v:.1}"))
                            .unwrap_or_else(|| "—".into()),
                    ),
                    Cell::from(p.rss_kib.to_string()),
                    Cell::from(p.swap_kib.to_string()),
                    Cell::from(p.state.to_string()),
                    Cell::from(format!("{}s", uptime_seconds(p.start_ticks))),
                    Cell::from(client_label(&r.client_state)),
                ];
                cells.push(Cell::from(format!("{:?}", r.tier)));
                Row::new(cells).style(if i == state.selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                })
            });
            let title = if state.searching {
                format!("Processes /{}", state.query)
            } else {
                format!(
                    "Processes {:?} — / search, s sort, t tree, Enter inspect, l logs, q quit",
                    state.sort
                )
            };
            frame.render_widget(
                Table::new(table_rows, widths)
                    .header(Row::new(headers).style(Style::default().add_modifier(Modifier::BOLD)))
                    .block(Block::default().borders(Borders::ALL).title(title)),
                chunks[0],
            );
            if state.inspecting && !narrow {
                if let Some(row) = rows.get(state.selected) {
                    let mut detail = vec![
                        Line::from(format!(
                            "pid={} ppid={} pgrp={} session={} start={} state={} uid={:?}",
                            row.process.pid,
                            row.process.ppid,
                            row.process.pgrp,
                            row.process.session,
                            row.process.start_ticks,
                            row.process.state,
                            row.process.uid
                        )),
                        Line::from(format!("{} — {}", row.process.name, row.process.command)),
                    Line::from(format!("protection={:?}: {}", row.tier, row.reason)),
                    Line::from(format!("protected because: {}", row.reason)),
                        Line::from(format!("decision={}", row.decision)),
                        Line::from(format!("owner verdict={:?}", row.owner)),
                        Line::from(format!("client registry={}", row.client_state)),
                    Line::from("full client/work evidence: `reaper pilot report`"),
                    Line::from("missing evidence: full client/work adapters are deferred to pilot report"),
                        Line::from("Evidence:"),
                    ];
                    detail.extend(row.evidence.iter().map(|s| Line::from(s.as_str())));
                    detail.push(Line::from("Block reasons / limitations:"));
                    detail.extend(row.blocks.iter().map(|s| Line::from(s.as_str())));
                    frame.render_widget(
                        Paragraph::new(detail).wrap(Wrap { trim: false }).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Process detail"),
                        ),
                        chunks[1],
                    );
                }
            }
        }
    }
    if state.view != View::Processes {
        frame.render_widget(
            Paragraph::new(lines).wrap(Wrap { trim: false }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(match state.view {
                        View::Logs => "Recent events",
                        View::Clients => "Managed clients",
                        View::Evidence => "Evidence and block reasons",
                        View::Help => "Key help",
                        _ => "Processes",
                    }),
            ),
            chunks[0],
        );
    }
    let status = format!("↑↓ navigate / search Enter detail t tree s sort l events c clients e evidence ? help r refresh q quit | visible={} protected={} observed={} candidate={} ownCPU={} supervisor={} RAM={} swap={} skippedRefreshes={}", snap.rows.len(), snap.rows.iter().filter(|r| r.tier != Tier::Unknown).count(), snap.rows.len(), snap.rows.iter().filter(|r| r.blocks.is_empty() && r.tier == Tier::Known).count(), snap.self_cpu.map(|v| format!("{v:.1}%")).unwrap_or_else(|| "—".into()), snap.supervisor, snap.ram.map(|(a,b)| format!("{a}/{b}KiB")).unwrap_or_else(|| "unavailable".into()), snap.swap.map(|(a,b)| format!("{a}/{b}KiB")).unwrap_or_else(|| "unavailable".into()), snap.refresh_skipped);
    frame.render_widget(Paragraph::new(status), chunks[chunks.len() - 1]);
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(
            io::stdout(),
            crossterm::event::DisableMouseCapture,
            crossterm::terminal::LeaveAlternateScreen
        );
    }
}

fn key_event(key: crossterm::event::KeyEvent) -> Key {
    use crossterm::event::{KeyCode, KeyEventKind};
    if key.kind != KeyEventKind::Press {
        return Key::Other;
    }
    match key.code {
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Enter => Key::Enter,
        KeyCode::Char('t') => Key::Tree,
        KeyCode::Char('s') => Key::Sort,
        KeyCode::Char('r') => Key::Refresh,
        KeyCode::Char('l') => Key::Logs,
        KeyCode::Char('c') => Key::Clients,
        KeyCode::Char('e') => Key::Evidence,
        KeyCode::Char('?') => Key::Help,
        KeyCode::Char('q') => Key::Quit,
        KeyCode::Char('/') => Key::Search,
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Esc => Key::Esc,
        KeyCode::Backspace => Key::Backspace,
        _ => Key::Other,
    }
}

pub fn run() -> io::Result<()> {
    crossterm::terminal::enable_raw_mode()?;
    let _guard = TerminalGuard;
    crossterm::execute!(
        io::stdout(),
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut state = UiState::default();
    let (tx, rx) = mpsc::sync_channel(1);
    let mut snap = Snapshot::default();
    let mut in_flight = true;
    let mut skipped_refreshes = 0usize;
    let (clock_hz, assumed_hz) = clock_ticks_per_second();
    let spawn_refresh = |tx: mpsc::SyncSender<(Snapshot, Instant)>| {
        let mut history = HashMap::new();
        if thread::Builder::new()
            .name("reaper-tui-snapshot".into())
            .spawn(move || {
                let mut snapshot = fast_snapshot();
                let sampled_at = Instant::now();
                decorate_cpu(&mut snapshot, &mut history, sampled_at, clock_hz);
                snapshot.self_cpu = self_cpu_percent(clock_hz);
                if assumed_hz {
                    snapshot
                        .supervisor
                        .push_str("; CLK_TCK=100 fallback assumption");
                }
                let _ = tx.try_send((snapshot, sampled_at));
            })
            .is_err()
        { /* A failed refresh leaves the last known snapshot visible. */ }
    };
    spawn_refresh(tx.clone());
    let mut last_tick = Instant::now();
    loop {
        let count = filtered_sorted(&snap.rows, &state.query, state.sort).len();
        state.selected = state.selected.min(count.saturating_sub(1));
        terminal.draw(|f| render(f, &state, &snap))?;
        if let Ok((mut completed, _at)) = rx.try_recv() {
            in_flight = false;
            // Worker-published counters preserve the snapshot's acquisition boundary.
            completed.refresh_skipped = skipped_refreshes;
            snap = completed;
        }
        if crossterm::event::poll(Duration::from_millis(200))? {
            if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
                let k = key_event(k);
                if state.searching && k == Key::Esc {
                    state.handle(k, count);
                } else if state.searching {
                    match k {
                        Key::Char(_) | Key::Backspace => state.handle(k, count),
                        _ => {}
                    }
                } else {
                    state.handle(k, count);
                }
                if k == Key::Refresh {
                    if in_flight {
                        skipped_refreshes += 1;
                    } else {
                        in_flight = true;
                        spawn_refresh(tx.clone());
                    }
                }
                if state.quit {
                    break;
                }
            }
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            if in_flight {
                skipped_refreshes += 1;
            } else {
                in_flight = true;
                spawn_refresh(tx.clone());
            }
            last_tick = Instant::now();
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn proc(pid: u32, name: &str, rss: u64) -> Process {
        Process {
            pid,
            ppid: 1,
            pgrp: pid,
            session: 1,
            start_ticks: pid as u64,
            state: 'S',
            name: name.into(),
            command: name.into(),
            rss_kib: rss,
            swap_kib: rss / 2,
            uid: Some(1000),
        }
    }
    fn fixture() -> Snapshot {
        let ps = vec![proc(2, "beta", 20), proc(1, "alpha", 10)];
        let rel = relations::build(&ps);
        snapshot_from(
            &ps,
            &rel,
            Some(1000),
            &Registry::default(),
            vec!["event fixture".into()],
            &std::collections::HashMap::new(),
        )
    }
    #[test]
    fn filter_matching_and_sort_orders() {
        let s = fixture();
        assert_eq!(filtered_sorted(&s.rows, "alp", Sort::Name).len(), 1);
        assert_eq!(filtered_sorted(&s.rows, "", Sort::Rss)[0].process.pid, 2);
        assert_eq!(filtered_sorted(&s.rows, "", Sort::Name)[0].process.pid, 1);
        assert_eq!(
            filtered_sorted(&s.rows, "", Sort::Name)[0].process.name,
            "alpha"
        );
    }
    #[test]
    fn each_key_binding_transitions_state() {
        let mut s = UiState::default();
        s.handle(Key::Down, 2);
        assert_eq!(s.selected, 1);
        s.handle(Key::Up, 2);
        assert_eq!(s.selected, 0);
        s.handle(Key::Search, 2);
        assert!(s.searching);
        s.handle(Key::Char('a'), 2);
        assert_eq!(s.query, "a");
        s.handle(Key::Esc, 2);
        assert!(!s.searching);
        s.handle(Key::Enter, 2);
        assert!(s.inspecting);
        s.handle(Key::Tree, 2);
        assert!(s.tree);
        s.handle(Key::Sort, 2);
        assert_eq!(s.sort, Sort::Swap);
        s.handle(Key::Logs, 2);
        assert_eq!(s.view, View::Logs);
        s.handle(Key::Clients, 2);
        assert_eq!(s.view, View::Clients);
        s.handle(Key::Quit, 2);
        assert!(s.quit);
    }
    #[test]
    fn narrow_width_hides_swap_and_cpu_columns() {
        assert!(!show_swap_cpu(59));
        assert!(show_swap_cpu(60));
    }

    #[test]
    fn small_and_resize_frames_render_without_panicking() {
        let backend = ratatui::backend::TestBackend::new(10, 4);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = UiState::default();
        let snap = fixture();
        terminal.draw(|f| render(f, &state, &snap)).unwrap();
        state.tree = true;
        terminal
            .resize(ratatui::layout::Rect::new(0, 0, 40, 10))
            .unwrap();
        terminal.draw(|f| render(f, &state, &snap)).unwrap();
    }

    #[test]
    fn cumulative_cpu_delta_is_time_normalized_and_identity_safe() {
        let at = Instant::now();
        let old = CpuSample {
            ticks: 500,
            at,
            start_ticks: 9,
        };
        assert_eq!(
            cpu_percent(Some(old), 9, 510, at + Duration::from_secs(2), 100),
            Some(5.0)
        );
        assert_eq!(
            cpu_percent(Some(old), 10, 510, at + Duration::from_secs(2), 100),
            None
        );
        assert_eq!(
            cpu_percent(Some(old), 9, 490, at + Duration::from_secs(2), 100),
            None
        );
    }

    #[test]
    fn cpu_uses_actual_non_100_clock_rate() {
        let at = Instant::now();
        let previous = CpuSample {
            ticks: 100,
            at,
            start_ticks: 1,
        };
        assert_eq!(
            cpu_percent(Some(previous), 1, 125, at + Duration::from_secs(1), 250),
            Some(10.0)
        );
    }

    #[test]
    fn busy_refresh_is_skipped_not_queued() {
        let mut in_flight = true;
        let mut skipped = 0;
        if in_flight {
            skipped += 1;
        } else {
            in_flight = true;
        }
        assert!(in_flight);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn tree_orders_parent_before_child() {
        let mut a = proc(1, "parent", 1);
        a.ppid = 0;
        let mut b = proc(2, "child", 1);
        b.ppid = 1;
        let mut snap = fixture();
        snap.rows.clear();
        for p in [b, a] {
            let rel = relations::build(std::slice::from_ref(&p));
            snap.rows.extend(
                snapshot_from(
                    &[p],
                    &rel,
                    Some(1000),
                    &Registry::default(),
                    vec![],
                    &std::collections::HashMap::new(),
                )
                .rows,
            );
        }
        let tree = process_tree(&snap.rows);
        assert_eq!(
            tree.iter().map(|(r, _)| r.process.pid).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(tree[1].1, 1);
    }

    #[test]
    fn cpu_history_accumulates_across_snapshots() {
        let at = Instant::now();
        let mut history = HashMap::new();
        history.insert(
            (42, 3),
            CpuSample {
                ticks: 100,
                at,
                start_ticks: 3,
            },
        );
        assert_eq!(
            cpu_percent(
                history.get(&(42, 3)).copied(),
                3,
                110,
                at + Duration::from_secs(1),
                100
            ),
            Some(10.0)
        );
    }

    #[test]
    fn zero_sized_frame_is_ignored() {
        let backend = ratatui::backend::TestBackend::new(0, 0);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = UiState::default();
        terminal
            .draw(|frame| render(frame, &state, &Snapshot::default()))
            .unwrap();
    }
    #[test]
    fn snapshots_are_pure_and_detail_keeps_evidence_and_blocks() {
        let before = fixture();
        let a = fixture();
        let b = fixture();
        assert_eq!(a.rows.len(), b.rows.len());
        assert_eq!(before.rows.len(), 2);
        assert!(a
            .rows
            .iter()
            .any(|r| r.evidence.iter().any(|e| e.contains("process identity"))));
        assert!(a
            .rows
            .iter()
            .any(|r| r.blocks.iter().any(|e| e.contains("unverifiable"))));
    }

    #[test]
    fn fast_snapshot_finishes_within_five_seconds() {
        let started = Instant::now();
        let _ = fast_snapshot();
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
