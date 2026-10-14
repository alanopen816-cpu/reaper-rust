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
    io,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum View {
    Processes,
    Logs,
    Clients,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sort {
    Rss,
    Pid,
    Name,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Key {
    Up,
    Down,
    Enter,
    Tree,
    Sort,
    Logs,
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
                    Sort::Rss => Sort::Pid,
                    Sort::Pid => Sort::Name,
                    Sort::Name => Sort::Rss,
                }
            }
            Key::Logs => {
                self.view = match self.view {
                    View::Processes => View::Logs,
                    View::Logs => View::Clients,
                    View::Clients => View::Processes,
                }
            }
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
}
#[derive(Clone, Debug, Default)]
struct Snapshot {
    rows: Vec<RowData>,
    clients: Vec<String>,
    events: Vec<String>,
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
    }
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
        Sort::Rss => rows.sort_by_key(|r| std::cmp::Reverse(r.process.rss_kib)),
        Sort::Pid => rows.sort_by_key(|r| r.process.pid),
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

fn render(frame: &mut Frame, state: &UiState, snap: &Snapshot) {
    let area = frame.area();
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
        View::Processes => {
            let rows = filtered_sorted(&snap.rows, &state.query, state.sort);
            let wide = show_swap_cpu(area.width);
            let mut headers = vec![Cell::from("PID"), Cell::from("NAME"), Cell::from("RSS KiB")];
            if wide {
                headers.extend([Cell::from("SWAP"), Cell::from("CPU")]);
            }
            headers.push(Cell::from("TIER"));
            let widths = if wide {
                vec![
                    Constraint::Length(7),
                    Constraint::Min(8),
                    Constraint::Length(9),
                    Constraint::Length(8),
                    Constraint::Length(5),
                    Constraint::Length(12),
                ]
            } else {
                vec![
                    Constraint::Length(7),
                    Constraint::Min(8),
                    Constraint::Length(9),
                    Constraint::Length(12),
                ]
            };
            let table_rows = rows.iter().enumerate().map(|(i, r)| {
                let p = &r.process;
                let mut cells = vec![
                    Cell::from(p.pid.to_string()),
                    Cell::from(if state.tree {
                        format!("{}{}", if p.ppid == 0 { "" } else { "└ " }, p.name)
                    } else {
                        p.name.clone()
                    }),
                    Cell::from(p.rss_kib.to_string()),
                ];
                if wide {
                    cells.extend([Cell::from(p.swap_kib.to_string()), Cell::from("—")]);
                }
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
                        Line::from(format!("decision={}", row.decision)),
                        Line::from(format!("owner verdict={:?}", row.owner)),
                        Line::from(format!("client registry={}", row.client_state)),
                        Line::from("full client/work evidence: `reaper pilot report`"),
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
                        _ => "Processes",
                    }),
            ),
            chunks[0],
        );
    }
    let status = format!(
        "↑↓ navigate  / search  Enter inspect  t tree/list  s sort  l logs/clients  q quit{}",
        if state.searching {
            "  Esc exit search"
        } else {
            ""
        }
    );
    frame.render_widget(Paragraph::new(status), chunks[chunks.len() - 1]);
}

struct TerminalGuard;
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), crossterm::terminal::LeaveAlternateScreen);
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
        KeyCode::Char('l') => Key::Logs,
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
    crossterm::execute!(io::stdout(), crossterm::terminal::EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut state = UiState::default();
    // Fast snapshotting is deliberately in-process/read-only so the first frame is immediate.
    let mut snap = fast_snapshot();
    let mut last_tick = Instant::now();
    loop {
        let filtered = filtered_sorted(&snap.rows, &state.query, state.sort);
        state.selected = state.selected.min(filtered.len().saturating_sub(1));
        terminal.draw(|f| render(f, &state, &snap))?;
        if crossterm::event::poll(Duration::from_millis(200))? {
            if let crossterm::event::Event::Key(k) = crossterm::event::read()? {
                let k = key_event(k);
                if state.searching && k == Key::Esc {
                    state.handle(k, filtered.len());
                } else if state.searching {
                    match k {
                        Key::Char(_) | Key::Backspace => state.handle(k, filtered.len()),
                        _ => {}
                    }
                } else {
                    state.handle(k, filtered.len());
                }
                if state.quit {
                    break;
                }
            }
        }
        if last_tick.elapsed() >= Duration::from_secs(1) {
            snap = fast_snapshot();
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
        assert_eq!(filtered_sorted(&s.rows, "alp", Sort::Pid).len(), 1);
        assert_eq!(filtered_sorted(&s.rows, "", Sort::Rss)[0].process.pid, 2);
        assert_eq!(filtered_sorted(&s.rows, "", Sort::Pid)[0].process.pid, 1);
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
        assert_eq!(s.sort, Sort::Pid);
        s.handle(Key::Logs, 2);
        assert_eq!(s.view, View::Logs);
        s.handle(Key::Logs, 2);
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
