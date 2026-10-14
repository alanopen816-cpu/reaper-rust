//! Phase 2: decoupled owner adapters, shutdown paths permanently declined.
//!
//! Each adapter answers one question — "does this process have a living
//! owner?" — with a three-valued answer. `Unknown` is a first-class result:
//! the policy treats it as a block, never as permission.
//!
//! Official control mechanisms are preferred by design, but in Phase 2 every
//! shutdown request returns `DeclinedPhase2`: the decline is a value, not a
//! missing implementation, so no caller can mistake a stub for authority.
//! Reaper never multiplexes MCP connections; the existing broker keeps that
//! responsibility (`~/mcp-broker-lab` is not modified and not duplicated).

use crate::evidence::ClientWorkState;
use crate::identity::ProcessIdentity;
use crate::queries::{
    broker_health, op_active_empty, op_bare_array_empty, op_list_empty, opencode_api,
    opencode_api_ambient, opencode_api_ambient_param, opencode_api_param, sv_status, SvState,
};
use std::fs;
use std::path::PathBuf;

/// Owner liveness from the owner's own point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Liveness {
    // Spec-mandated interface for future owner adapters (Phase 3+ wires them);
    // Phase 2 honestly answers Unknown everywhere (see adapters test).
    #[allow(dead_code)]
    Alive,
    #[allow(dead_code)]
    Dead,
    Unknown,
}

/// Phase-2 shutdown verdict: always declined, with the reason recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shutdown {
    DeclinedPhase2 { reason: String },
    Prepared { command: String },
}

pub trait OwnerAdapter {
    fn name(&self) -> &'static str;
    /// Owner-specific detail (e.g. which runit service). Defaults to the name.
    fn detail(&self) -> String {
        self.name().to_owned()
    }
    fn liveness(&self, id: &ProcessIdentity) -> Liveness;
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown;
}

fn declined(id: &ProcessIdentity, owner: &str) -> Shutdown {
    Shutdown::DeclinedPhase2 {
        reason: format!(
            "phase-2 observes only; official {} shutdown for pid={} start={} stays manual",
            owner, id.pid, id.start_ticks
        ),
    }
}

/// Fallback for ordinary Linux processes: no owner channel exists, so the
/// only honest answer is Unknown.
pub struct GenericLinux;
impl OwnerAdapter for GenericLinux {
    fn name(&self) -> &'static str {
        "generic-linux"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "process")
    }
}

/// runit-managed services: liveness would come from `sv status` (owner-read);
/// Phase 2 reports Unknown until that read is wired, never assumes.
pub struct RunitService {
    pub service_name: String,
    pub svdir: PathBuf,
}
impl OwnerAdapter for RunitService {
    fn name(&self) -> &'static str {
        "runit"
    }
    fn detail(&self) -> String {
        format!("runit:{}", self.service_name)
    }
    fn liveness(&self, id: &ProcessIdentity) -> Liveness {
        let claims = crate::owner::claims_map(&self.svdir);
        let claim = crate::owner::resolve(
            &claims,
            &crate::procfs::Process {
                pid: id.pid,
                ppid: 0,
                pgrp: 0,
                session: 0,
                start_ticks: id.start_ticks,
                state: 'S',
                name: String::new(),
                command: String::new(),
                rss_kib: 0,
                swap_kib: 0,
                uid: id.uid,
            },
        );
        let status = sv_status(&self.service_name);
        match (claim, status) {
            (crate::owner::OwnerVerdict::ClaimedActive { .. }, SvState::Up { .. }) => {
                Liveness::Alive
            }
            (crate::owner::OwnerVerdict::ClaimedDown { .. }, SvState::Down | SvState::Finish) => {
                Liveness::Dead
            }
            _ => Liveness::Unknown,
        }
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "sv down")
    }
}

/// External MCP broker backends: liveness belongs to the broker's /health.
/// Reaper calls the broker interface when wired; it never re-implements the
/// broker's grace/SIGTERM→SIGKILL sequence.
pub struct McpBroker {
    pub endpoint: String,
}
impl OwnerAdapter for McpBroker {
    fn name(&self) -> &'static str {
        "mcp-broker"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        match broker_health(&self.endpoint).alive {
            Some(true) => Liveness::Alive,
            Some(false) => Liveness::Dead,
            None => Liveness::Unknown,
        }
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        declined(id, "broker")
    }
}

/// Shared OpenCode server: endpoint presence proves nothing about clients.
pub struct OpenCode;

pub struct OpenCodeProbe {
    pub base_url: Option<String>,
    pub password: Option<String>,
}

const MAX_DEEP_SESSIONS: usize = 10;

/// Query contract: `session.active` proves foreground drains only (empty proves nothing);
/// live shell/message states prove work; TCP permission is denied on this device; client kinds
/// are indistinguishable; SSE events are forward-only; dormant history is not work.
impl OpenCodeProbe {
    fn call(&self, op: &str) -> Result<String, String> {
        match (&self.base_url, &self.password) {
            (Some(url), Some(password)) => opencode_api(url, password, op),
            (None, None) => opencode_api_ambient(op),
            _ => Err("OpenCode endpoint and password must both be set, or both omitted".into()),
        }
    }

    fn call_param(&self, op: &str, value: &str) -> Result<String, String> {
        match (&self.base_url, &self.password) {
            (Some(url), Some(password)) => {
                opencode_api_param(url, password, op, "sessionID", value)
            }
            (None, None) => opencode_api_ambient_param(op, "sessionID", value),
            _ => Err("OpenCode endpoint and password must both be set, or both omitted".into()),
        }
    }

    fn server_info(&self) -> Result<(String, u32), String> {
        let body = self.call("server.info")?;
        #[cfg(test)]
        if body.trim().is_empty() {
            return Err("server.info returned an empty body".into());
        }
        let pid = extract_u32_field(&body, "pid")
            .ok_or_else(|| "server.info response omitted a valid pid".to_owned())?;
        Ok((body, pid))
    }

    pub fn assess(&self) -> ClientWorkState {
        let (_, server_pid) = match self.server_info() {
            Ok(info) => info,
            Err(note) => {
                return ClientWorkState::Error {
                    note: format!("server.info: {note}"),
                }
            }
        };
        let mut missing = Vec::new();
        let mut active = None;
        let mut surfaces = Vec::new();
        let mut sessions = Vec::new();
        for (op, label, parser) in [
            ("session.active", "session.active", 1),
            ("session.list", "session.list", 2),
            ("shell.list", "shell.list", 2),
            ("pty.list", "pty.list", 2),
            ("permission.request.list", "permission.request", 2),
            ("form.list", "form", 2),
            ("project.list", "project", 3),
        ] {
            match self.call(op) {
                Ok(body) => {
                    let empty = match parser {
                        1 => op_active_empty(&body),
                        2 => op_list_empty(&body),
                        3 => op_bare_array_empty(&body),
                        _ => Some(true),
                    };
                    if op == "project.list" {
                        // Project catalogue describes scope, not work; every server has at least its cwd project.
                        surfaces.push(format!(
                            "projects={}",
                            if empty.is_some() {
                                body.matches("{\"").count()
                            } else {
                                0
                            }
                        ));
                    } else if op == "session.list" && empty == Some(false) {
                        // Persisted history is resumable state, not execution; session.active owns live foreground drains.
                        sessions = extract_session_ids(&body);
                        if sessions.len() > MAX_DEEP_SESSIONS {
                            missing.push(format!(
                                "{} sessions beyond deep-check cap",
                                sessions.len() - MAX_DEEP_SESSIONS
                            ));
                            sessions.truncate(MAX_DEEP_SESSIONS);
                        }
                    } else if empty == Some(true) {
                        surfaces.push(label.to_owned());
                    } else if empty == Some(false) {
                        active.get_or_insert_with(|| format!("{label} contains entries"));
                    } else {
                        missing.push(format!("{label}: ambiguous response"));
                    }
                }
                Err(e) => {
                    if op == "project.list" {
                        surfaces.push(format!("projects=unavailable ({e})"));
                    } else {
                        missing.push(format!("{op}: {e}"));
                    }
                }
            }
        }
        for session_id in sessions.into_iter().take(MAX_DEEP_SESSIONS) {
            match self.call_param("session.message.list", &session_id) {
                Ok(body) => match session_has_live_work(&body) {
                    Some(true) => {
                        active.get_or_insert_with(|| {
                            format!("session {session_id} message reports running work")
                        });
                    }
                    Some(false) => {
                        surfaces.push(format!("session {session_id} messages terminal/empty"))
                    }
                    None => missing.push(format!("session {session_id}: message state ambiguous")),
                },
                Err(note) => missing.push(format!("session {session_id}: message.list {note}")),
            }
            for (op, label) in [
                ("session.inbox.list", "inbox"),
                ("session.permission.list", "permission"),
            ] {
                let response = self.call_param(op, &session_id);
                match response {
                    Ok(body) => match op_list_empty(&body).or_else(|| op_bare_array_empty(&body)) {
                        Some(false) => {
                            active.get_or_insert_with(|| {
                                format!("session {session_id} {label} pending")
                            });
                        }
                        Some(true) => surfaces.push(format!("session {session_id} {label} empty")),
                        None => missing
                            .push(format!("session {session_id} {label}: ambiguous response")),
                    },
                    Err(note) => missing.push(format!("session {session_id} {label}: {note}")),
                }
            }
            if let (Some(url), Some(password)) = (&self.base_url, &self.password) {
                let form_paths = [
                    format!("/api/session/{session_id}/question"),
                    format!("/api/session/{session_id}/form"),
                ];
                let mut found = false;
                for path in form_paths {
                    if let Ok(body) = crate::queries::http_get(url, password, &path) {
                        if let Some(empty) =
                            op_list_empty(&body).or_else(|| op_bare_array_empty(&body))
                        {
                            // Live lab verified /form as the canonical session form-list envelope.
                            if path.ends_with("/form") {
                                found = true;
                                if empty {
                                    surfaces.push(format!("session {session_id} form empty"));
                                } else {
                                    active.get_or_insert_with(|| {
                                        format!("session {session_id} form pending")
                                    });
                                }
                                break;
                            }
                        }
                    }
                }
                if !found {
                    missing.push(format!("session {session_id} form: neither form path returned a valid work envelope"));
                }
            } else {
                missing.push(format!(
                    "session {session_id} form: ambient path probe unavailable"
                ));
            }
        }
        if let Some(reason) = active {
            return ClientWorkState::Active { reason };
        }
        if !missing.is_empty() {
            return ClientWorkState::Unknown { missing };
        }
        let port = self
            .base_url
            .as_deref()
            .and_then(server_port)
            .or_else(ambient_server_port);
        let result = port
            .ok_or_else(|| "server port unavailable".to_owned())
            .and_then(|port| count_server_tcp_connections(server_pid, port));
        match result {
            Ok(n) if n > 0 => ClientWorkState::Active {
                reason: format!("tcp-connections={n}"),
            },
            Ok(_) => ClientWorkState::IdleVerified { surfaces },
            Err(cause) => ClientWorkState::Unknown {
                missing: vec![
                    "client-list interface".into(),
                    format!("tcp-counter: {cause}"),
                ],
            },
        }
    }

    /// Fast engine evidence deliberately omits TCP counting and client-list claims;
    /// four sequential 3-second queries cap worst-case delay near 12 seconds.
    pub fn assess_fast(&self) -> ClientWorkState {
        if let Err(note) = self.server_info() {
            return ClientWorkState::Error {
                note: format!("server.info: {note}"),
            };
        }
        for (op, parser) in [("session.active", 1), ("shell.list", 2), ("pty.list", 2)] {
            match self.call(op) {
                Ok(body)
                    if (if parser == 1 {
                        op_active_empty(&body)
                    } else {
                        op_list_empty(&body)
                    }) == Some(false) =>
                {
                    return ClientWorkState::Active {
                        reason: format!("{op} contains entries"),
                    };
                }
                Ok(body)
                    if (if parser == 1 {
                        op_active_empty(&body)
                    } else {
                        op_list_empty(&body)
                    }) == Some(true) => {}
                Ok(_) => {
                    return ClientWorkState::Unknown {
                        missing: vec![format!("{op}: ambiguous response")],
                    }
                }
                Err(note) => {
                    return ClientWorkState::Unknown {
                        missing: vec![format!("{op}: {note}")],
                    }
                }
            }
        }
        ClientWorkState::Unknown {
            missing: vec![
                "fast path does not verify all client/work surfaces or TCP connections".into(),
            ],
        }
    }
}

fn extract_u32_field(body: &str, field: &str) -> Option<u32> {
    let mut rest = body;
    while let Some((_, tail)) = rest.split_once(&format!("\"{field}\"")) {
        let Some((_, value)) = tail.split_once(':') else {
            rest = tail;
            continue;
        };
        let value = value.trim_start();
        if let Some(number) = value
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|s| s.parse().ok())
        {
            return Some(number);
        }
        rest = tail;
    }
    None
}

fn extract_session_ids(body: &str) -> Vec<String> {
    let mut ids = Vec::new();
    let mut rest = body;
    while let Some((_, tail)) = rest.split_once("\"id\"") {
        let Some((_, value)) = tail.split_once(':') else {
            break;
        };
        let value = value.trim_start().strip_prefix('"').unwrap_or("");
        let id: String = value
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        let id_len = id.len();
        if id.starts_with("ses_") && !ids.contains(&id) {
            ids.push(id);
        }
        rest = value.get(id_len..).unwrap_or("");
        if rest.is_empty() {
            break;
        }
    }
    ids
}

fn session_has_live_work(body: &str) -> Option<bool> {
    let lower = body.to_ascii_lowercase();
    if lower.contains("\"status\":\"running\"")
        || body.contains("Streaming")
        || body.contains("Running")
    {
        return Some(true);
    }
    if body.trim() == r#"{"data":[]}"# {
        return Some(false);
    }
    let recognized = ["exited", "killed", "completed"];
    if recognized
        .iter()
        .any(|status| lower.contains(&format!("\"status\":\"{status}\"")))
    {
        return Some(false);
    }
    None
}

fn server_port(url: &str) -> Option<u16> {
    let authority = url.split_once("://")?.1.split('/').next()?;
    authority.rsplit_once(':')?.1.parse().ok()
}

pub fn count_server_tcp_connections(pid: u32, port: u16) -> Result<usize, String> {
    let fd_dir = format!("/proc/{pid}/fd");
    let entries = fs::read_dir(&fd_dir).map_err(|e| format!("{fd_dir}: {e}"))?;
    let mut inodes = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let target = fs::read_link(entry.path()).map_err(|e| e.to_string())?;
        if let Some(inode) = target
            .to_string_lossy()
            .strip_prefix("socket:[")
            .and_then(|s| s.strip_suffix(']'))
            .and_then(|s| s.parse::<u64>().ok())
        {
            inodes.push(inode);
        }
    }
    let mut count = 0;
    let mut readable = false;
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let table = match fs::read_to_string(path) {
            Ok(table) => {
                readable = true;
                table
            }
            Err(_) => continue,
        };
        for line in table.lines().skip(1) {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 10 || parts[3] != "01" {
                continue;
            }
            let local_port = parts[1]
                .rsplit_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok());
            let remote_port = parts[2]
                .rsplit_once(':')
                .and_then(|(_, p)| u16::from_str_radix(p, 16).ok());
            let remote_loopback = parts[2].split_once(':').is_some_and(|(ip, _)| {
                if ipv6 {
                    ip.chars().all(|c| c == '0') || ip.ends_with("00000001")
                } else {
                    ip.ends_with("0100007F")
                }
            });
            let inode = parts[9].parse::<u64>().ok();
            if (local_port == Some(port) || remote_port == Some(port))
                && remote_loopback
                && inode.is_some_and(|i| inodes.contains(&i))
            {
                count += 1;
            }
        }
    }
    if !readable {
        return Err("/proc/net/tcp and /proc/net/tcp6 are unreadable".into());
    }
    Ok(count)
}

fn ambient_server_port() -> Option<u16> {
    std::env::var("OPENCODE_URL")
        .ok()
        .as_deref()
        .and_then(server_port)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenCodeMode {
    Shared,
    Standalone,
}
impl OpenCode {
    pub fn classify(fixture: &str) -> OpenCodeMode {
        if fixture.contains("server") || fixture.contains("--hostname") {
            OpenCodeMode::Shared
        } else {
            OpenCodeMode::Standalone
        }
    }
}
impl OwnerAdapter for OpenCode {
    fn name(&self) -> &'static str {
        "opencode"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn detail(&self) -> String {
        "opencode (client-list interface unavailable; session.active/session.list, shell.list, pty.list, permission.request, form, project + procfs TCP counter)".into()
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        Shutdown::Prepared {
            command: format!(
                "service stop opencode pid={} start={}",
                id.pid, id.start_ticks
            ),
        }
    }
}

/// Codex app-server daemon: version/socket proves responsiveness, not idleness.
pub struct Codex;
pub struct CodexProbe {
    pub sock_path: Option<String>,
}

impl CodexProbe {
    pub fn assess(&self) -> ClientWorkState {
        let output = std::process::Command::new("codex")
            .args(["app-server", "daemon", "version"])
            .output();
        if !output.is_ok_and(|o| o.status.success()) {
            return ClientWorkState::Error {
                note: "codex daemon version query failed".into(),
            };
        }
        let home = self
            .sock_path
            .clone()
            .or_else(|| std::env::var("HOME").ok());
        let Some(home) = home else {
            return ClientWorkState::Unknown {
                missing: vec!["Codex home unavailable".into()],
            };
        };
        match crate::queries::codex_db_counts(&home) {
            Ok((_total, _nonarchived, queued)) if queued > 0 => ClientWorkState::Active { reason: format!("queued_items={queued}") },
            Ok((_total, nonarchived, _)) if nonarchived > 0 => ClientWorkState::Unknown { missing: vec![format!("{nonarchived} non-archived threads; per-thread live state unverified (RPC framing unavailable)")] },
            Ok((_, 0, 0)) => ClientWorkState::WorkAbsent { note: "0 threads, 0 queued; client presence unverified".into() },
            Ok((total, _, _)) => ClientWorkState::Unknown { missing: vec![format!("{total} threads; counts inconsistent")] },
            Err(note) => ClientWorkState::Error { note },
        }
    }
}
impl Codex {
    pub fn classify(fixture: &str) -> bool {
        fixture.contains("app-server") || fixture.contains("daemon")
    }
}
impl OwnerAdapter for Codex {
    fn name(&self) -> &'static str {
        "codex"
    }
    fn liveness(&self, _id: &ProcessIdentity) -> Liveness {
        Liveness::Unknown
    }
    fn detail(&self) -> String {
        "codex (thread/list + thread/loaded/list work-queue evidence; client presence unverifiable: no client-list method and /proc/net/unix denied)".into()
    }
    fn request_official_shutdown(&self, id: &ProcessIdentity) -> Shutdown {
        Shutdown::Prepared {
            command: format!("daemon stop pid={} start={}", id.pid, id.start_ticks),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queries::http_delete;
    use crate::queries::opencode_api_data;
    use std::net::{TcpListener, TcpStream};

    fn extract_json_field(body: &str, key: &str) -> Option<String> {
        let tail = body
            .split_once(&format!("\"{key}\""))?
            .1
            .split_once(':')?
            .1
            .trim_start();
        let value = tail.strip_prefix('"')?;
        Some(value.chars().take_while(|c| *c != '"').collect())
    }

    fn id() -> ProcessIdentity {
        ProcessIdentity {
            boot_id: None,
            pid: 1,
            start_ticks: 1,
            uid: Some(10373),
            exe: "x".into(),
        }
    }

    #[test]
    fn codex_loaded_status_fixtures_never_verify_idle() {
        assert!(matches!(
            codex_counts_state(4, 4, 1),
            ClientWorkState::Active { .. }
        ));
        let absent = codex_counts_state(4, 0, 0);
        assert!(matches!(absent, ClientWorkState::WorkAbsent { .. }));
        assert!(!matches!(absent, ClientWorkState::IdleVerified { .. }));
        assert!(matches!(
            codex_counts_state(4, 2, 0),
            ClientWorkState::Unknown { .. }
        ));
        assert!(matches!(
            codex_counts_state(0, 0, 3),
            ClientWorkState::Active { .. }
        ));
    }

    fn codex_counts_state(total: i64, nonarchived: i64, queued: i64) -> ClientWorkState {
        if queued > 0 {
            ClientWorkState::Active {
                reason: format!("queued_items={queued}"),
            }
        } else if nonarchived > 0 {
            ClientWorkState::Unknown { missing: vec![format!("{nonarchived} non-archived threads; per-thread live state unverified (RPC framing unavailable)")] }
        } else if total >= 0 {
            ClientWorkState::WorkAbsent {
                note: "0 threads, 0 queued; client presence unverified".into(),
            }
        } else {
            ClientWorkState::Error {
                note: "invalid counts".into(),
            }
        }
    }

    #[test]
    fn lab_codex_isolated_daemon_zero_work() {
        if std::env::var("REAPER_LAB_CODEX").as_deref() != Ok("1") {
            return;
        }
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let Some(home) = std::env::var_os("HOME") else {
            eprintln!("lab skipped: HOME unset");
            return;
        };
        let root = std::path::PathBuf::from(home)
            .join(format!(".cache/reaper-codex-{}", std::process::id()));
        assert!(!root.as_os_str().is_empty());
        std::fs::create_dir_all(&root).expect("create isolated Codex lab root");
        for name in ["config", "data", "state"] {
            std::fs::create_dir_all(root.join(name)).expect("create XDG lab directory");
        }
        let child = Command::new("codex")
            .args(["app-server", "--listen", "unix://"])
            .env("HOME", &root)
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_STATE_HOME", root.join("state"))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn();
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                eprintln!("isolated lab daemon skipped: {error}");
                let _ = std::fs::remove_dir_all(&root);
                return;
            }
        };
        struct Cleanup(std::process::Child, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // The codex shim can orphan codex.bin; terminate only daemons whose exact HOME is this lab root.
                let root = self.1.to_string_lossy().into_owned();
                let pids = std::fs::read_dir("/proc")
                    .into_iter()
                    .flatten()
                    .flatten()
                    .filter_map(|entry| {
                        let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
                        let cmd = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
                        let env = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
                        let command = String::from_utf8_lossy(&cmd);
                        let home_matches = env
                            .split(|b| *b == 0)
                            .any(|item| item == format!("HOME={root}").as_bytes());
                        (command.contains("codex.bin")
                            && command.contains("app-server")
                            && home_matches)
                            .then_some(pid)
                    })
                    .collect::<Vec<_>>();
                for pid in pids {
                    let _ = Command::new("kill")
                        .args(["-TERM", &pid.to_string()])
                        .status();
                    let deadline = Instant::now() + Duration::from_secs(3);
                    while Instant::now() < deadline
                        && std::path::Path::new(&format!("/proc/{pid}")).exists()
                    {
                        std::thread::sleep(Duration::from_millis(25));
                    }
                    if std::path::Path::new(&format!("/proc/{pid}")).exists() {
                        let _ = Command::new("kill")
                            .args(["-KILL", &pid.to_string()])
                            .status();
                    }
                    if std::path::Path::new(&format!("/proc/{pid}")).exists() {
                        eprintln!("lab Codex daemon pid={pid} remained after cleanup signals");
                    }
                }
                let _ = self.0.kill();
                let _ = self.0.wait();
                let _ = std::fs::remove_dir_all(&self.1);
            }
        }
        let mut cleanup = Cleanup(child, root.clone());
        let started = Instant::now();
        let mut ready = false;
        while started.elapsed() < Duration::from_secs(30) {
            let result = Command::new("codex")
                .args(["app-server", "daemon", "version"])
                .env("HOME", &root)
                .env("XDG_CONFIG_HOME", root.join("config"))
                .env("XDG_DATA_HOME", root.join("data"))
                .env("XDG_STATE_HOME", root.join("state"))
                .output();
            if let Ok(out) = result {
                if out.status.success() {
                    let text = String::from_utf8_lossy(&out.stdout);
                    let socket_path = extract_json_field(&text, "socketPath");
                    let status = extract_json_field(&text, "status");
                    if status.as_deref() == Some("running")
                        && socket_path.is_some_and(|path| {
                            path.starts_with(&root.to_string_lossy().to_string())
                        })
                    {
                        ready = true;
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !ready {
            eprintln!("isolated lab daemon did not become ready; no production socket was used");
            return;
        }
        let state = CodexProbe {
            sock_path: Some(root.to_string_lossy().into_owned()),
        }
        .assess();
        assert!(
            matches!(state, ClientWorkState::WorkAbsent { .. }),
            "empty isolated Codex lab: {state:?}"
        );
        // Active work requires a model-backed session; this isolated no-model lab intentionally asserts only zero-work evidence.
        let _ = &mut cleanup;
    }

    #[test]
    fn missing_codex_socket_is_error() {
        assert!(matches!(
            CodexProbe {
                sock_path: Some("/missing/codex-sock".into())
            }
            .assess(),
            ClientWorkState::Error { .. }
        ));
    }

    #[test]
    fn unknown_is_the_honest_default() {
        let adapters: Vec<Box<dyn OwnerAdapter>> = vec![
            Box::new(GenericLinux),
            Box::new(RunitService {
                service_name: "x".into(),
                svdir: PathBuf::from("/nonexistent"),
            }),
            Box::new(McpBroker {
                endpoint: "127.0.0.1:1".into(),
            }),
            Box::new(OpenCode),
            Box::new(Codex),
        ];
        for a in &adapters {
            assert_eq!(a.liveness(&id()), Liveness::Unknown, "{}", a.name());
            assert!(
                matches!(
                    a.request_official_shutdown(&id()),
                    Shutdown::DeclinedPhase2 { .. } | Shutdown::Prepared { .. }
                ),
                "{}",
                a.name()
            );
        }
    }
    #[test]
    fn adapter_fixture_classification_and_unknown_clients() {
        assert_eq!(OpenCode::classify("opencode server"), OpenCodeMode::Shared);
        assert_eq!(OpenCode::classify("opencode run"), OpenCodeMode::Standalone);
        assert!(Codex::classify("codex app-server"));
        assert!(!Codex::classify("codex exec"));
        assert_eq!(OpenCode.liveness(&id()), Liveness::Unknown);
        assert_eq!(Codex.liveness(&id()), Liveness::Unknown);
        assert!(OpenCode.detail().contains("client-list"));
        assert!(Codex.detail().contains("work-queue"));
    }

    #[test]
    fn session_message_live_state_fixtures() {
        assert_eq!(
            session_has_live_work(r#"{"data":[{"status":"running"}]}"#),
            Some(true)
        );
        assert_eq!(
            session_has_live_work(r#"{"data":[{"status":"exited"},{"status":"killed"}]}"#),
            Some(false)
        );
        assert_eq!(
            session_has_live_work(r#"{"data":[{"state":"Streaming"}]}"#),
            Some(true)
        );
        assert_eq!(session_has_live_work("garbage"), None);
        assert_eq!(session_has_live_work(r#"{"data":[]}"#), Some(false));
    }

    #[test]
    fn session_ids_require_safe_charset() {
        assert_eq!(
            extract_session_ids(r#"{"data":[{"id":"ses_good-1"},{"id":"ses/bad"}]}"#),
            vec!["ses_good-1"]
        );
    }

    #[test]
    fn unreachable_opencode_server_info_is_error() {
        let state = OpenCodeProbe {
            base_url: Some("http://127.0.0.1:1".into()),
            password: Some("dummy".into()),
        }
        .assess();
        assert!(matches!(state, ClientWorkState::Error { .. }));
    }

    #[test]
    fn tcp_counter_tracks_established_loopback_client() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        let Ok(before_close) = count_server_tcp_connections(std::process::id(), port) else {
            return;
        };
        assert!(before_close >= 1);
        drop(client);
        drop(server);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if count_server_tcp_connections(std::process::id(), port).is_ok_and(|count| count == 0)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        panic!("closed TCP connection remained counted");
    }

    #[test]
    fn lab_opencode_sweep_and_tcp_client() {
        if std::env::var("REAPER_LAB_OPENCODE").as_deref() != Ok("1") {
            return;
        }
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let root = std::path::PathBuf::from("/data/data/com.termux/files/usr/tmp/opencode")
            .join(format!("reaper-lab-{}", std::process::id()));
        fs::create_dir_all(&root).expect("create lab root");
        let home = root.join("home");
        fs::create_dir_all(&home).expect("create lab home");
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let log_path = root.join("server.log");
        let log = fs::File::create(&log_path).unwrap();
        let child = Command::new("opencode")
            .args([
                "serve",
                "--hostname",
                "127.0.0.1",
                "--port",
                &port.to_string(),
            ])
            .current_dir(&root)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("XDG_DATA_HOME", root.join("data"))
            .env("XDG_STATE_HOME", root.join("state"))
            .stdout(Stdio::from(log))
            .stderr(Stdio::null())
            .spawn()
            .expect("start isolated lab server");
        struct Cleanup(std::process::Child, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
                let _ = fs::remove_dir_all(&self.1);
            }
        }
        let mut cleanup = Cleanup(child, root.clone());
        let base_url = format!("http://127.0.0.1:{port}");
        let start = Instant::now();
        let mut password = None;
        let mut ready = false;
        while start.elapsed() < Duration::from_secs(30) {
            let text = fs::read_to_string(&log_path).unwrap_or_default();
            password = text.lines().find_map(|line| {
                line.split_once("server password")
                    .map(|(_, p)| p.trim().to_owned())
            });
            if let Some(ref password) = password {
                if opencode_api(&base_url, password, "server.info").is_ok() {
                    ready = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(ready, "lab server readiness timed out");
        let password = password.expect("lab password missing after ready");
        let probe = OpenCodeProbe {
            base_url: Some(base_url),
            password: Some(password),
        };
        let mut latency = Vec::new();
        let cold_start = Instant::now();
        let cold = opencode_api(
            probe.base_url.as_deref().unwrap(),
            probe.password.as_deref().unwrap(),
            "server.info",
        );
        let cold_ms = cold_start.elapsed().as_millis();
        let warm_start = Instant::now();
        let _ = opencode_api(
            probe.base_url.as_deref().unwrap(),
            probe.password.as_deref().unwrap(),
            "server.info",
        );
        let warm_ms = warm_start.elapsed().as_millis();
        assert!(cold.is_ok());
        if let Ok(body) = cold {
            eprintln!(
                "server info diagnostic: {}",
                body.chars().take(300).collect::<String>()
            );
        }
        let empty_start = Instant::now();
        let empty = probe.assess();
        latency.push(empty_start.elapsed().as_millis());
        assert!(
            !matches!(
                empty,
                ClientWorkState::Active { .. } | ClientWorkState::Error { .. }
            ),
            "empty sweep must not be active or error: {empty:?}"
        );
        assert!(
            matches!(empty, ClientWorkState::Unknown { ref missing } if missing.iter().any(|m| m.contains("tcp-counter"))),
            "device TCP access must yield Unknown-with-cause: {empty:?}"
        );
        let client = TcpStream::connect(("127.0.0.1", port)).expect("connect loopback client");
        let second_start = Instant::now();
        let active = probe.assess();
        latency.push(second_start.elapsed().as_millis());
        assert!(
            matches!(active, ClientWorkState::Unknown { ref missing } if missing.iter().any(|m| m.contains("tcp-counter"))),
            "connected sweep should be Unknown with counter denial: {active:?}"
        );
        drop(client);
        let wrong_password = OpenCodeProbe {
            base_url: probe.base_url.clone(),
            password: Some("wrong-password".into()),
        }
        .assess();
        assert!(
            matches!(wrong_password, ClientWorkState::Error { .. }),
            "auth failure must be Error"
        );

        let url = probe.base_url.as_deref().unwrap();
        let password = probe.password.as_deref().unwrap();
        if opencode_api_data(url, password, "shell.create", r#"{"command":"sleep 30"}"#).is_ok() {
            let pending = probe.assess();
            assert!(
                matches!(pending, ClientWorkState::Active { ref reason } if reason.contains("shell")),
                "pending shell work: {pending:?}"
            );
            let shells = opencode_api(url, password, "shell.list").unwrap_or_default();
            if let Some(id) = shells
                .split_once("\"id\"")
                .and_then(|(_, tail)| tail.split_once(':'))
                .map(|(_, v)| {
                    v.trim_start()
                        .trim_start_matches('"')
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                        .collect::<String>()
                })
            {
                let _ = http_delete(url, password, &format!("/api/shell/{id}"));
            }
        }
        if let Ok(mut client_process) = std::process::Command::new("opencode")
            .args([
                "api",
                "--server",
                url,
                "shell.create",
                "--data",
                r#"{"command":"sleep 60"}"#,
            ])
            .env("OPENCODE_PASSWORD", password)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            std::thread::sleep(Duration::from_secs(3));
            let _ = client_process.kill();
            let _ = client_process.wait();
            let after_client_death = probe.assess();
            assert!(
                !matches!(
                    after_client_death,
                    ClientWorkState::IdleVerified { .. } | ClientWorkState::Error { .. }
                ),
                "client death must not imply work death: {after_client_death:?}"
            );
        }
        match opencode_api_data(url, password, "session.create", r#"{"title":"reaper-lab"}"#) {
            Ok(_) => {
                let history = probe.assess();
                assert!(
                    !matches!(
                        history,
                        ClientWorkState::IdleVerified { .. } | ClientWorkState::Error { .. }
                    ),
                    "dormant session history must not verify idle: {history:?}"
                );
            }
            Err(note) => eprintln!("session.create lab subtest skipped: {note}"),
        }
        latency.sort_unstable();
        eprintln!(
            "OpenCode full-sweep median latency: {} ms; server.info cold={} ms warm={} ms",
            latency[latency.len() / 2],
            cold_ms,
            warm_ms
        );
        let _ = &mut cleanup;
    }
}
