//! Bounded, read-only production queries. Query children are Reaper-owned;
//! they may be killed only when their own query timeout expires.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
const AMBIENT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_QUERY_OUTPUT: usize = 64 * 1024;
const MAX_DIR_ENTRIES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrokerHealth {
    pub alive: Option<bool>,
    pub raw_note: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SvState {
    Up { pid: Option<u32> },
    Down,
    Finish,
    Unknown,
}

/// OpenCode API operation IDs: server.info (GET /api/info), session.active (GET /api/session/active),
/// session.list (GET /api/session), shell.list (GET /api/shell), pty.list (GET /api/pty),
/// permission.request.list (GET /api/permission/request), form.list (GET /api/form),
/// project.list (GET /api/project). IDs follow the OpenCode V2 OpenAPI operationId values.
pub fn opencode_api(base_url: &str, password: &str, op: &str) -> Result<String, String> {
    let path = op_path(op).ok_or_else(|| "unsupported OpenCode operation".to_owned())?;
    http_get(base_url, password, &path)
}

pub fn opencode_api_ambient(op: &str) -> Result<String, String> {
    // Ambient Bun startup can take several seconds on cold HOME; don't use the short HTTP timeout.
    opencode_api_command(None, op, AMBIENT_TIMEOUT)
}

pub fn codex_db_counts(codex_home: &str) -> Result<(i64, i64, i64), String> {
    if codex_home.trim().is_empty() {
        return Err("Codex home is empty".into());
    }
    let state = format!("{}/.codex/state_5.sqlite", codex_home.trim_end_matches('/'));
    let queue = format!("{}/.codex/queue_1.sqlite", codex_home.trim_end_matches('/'));
    let total = sqlite_count(&state, "select count(*) from threads;")?;
    let nonarchived = sqlite_count(&state, "select count(*) from threads where archived=0;")?;
    let queued = sqlite_count(&queue, "select count(*) from queued_items;")?;
    Ok((total, nonarchived, queued))
}

fn sqlite_count(path: &str, sql: &str) -> Result<i64, String> {
    let uri = format!("file:{path}?mode=ro");
    let mut child = Command::new("sqlite3")
        .arg("-readonly")
        .arg(uri)
        .arg(sql)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("sqlite3 spawn failed for {path}: {e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|e| format!("sqlite3 output failed: {e}"))?;
                if !status.success() {
                    return Err(format!("sqlite3 read failed for {path}"));
                }
                return String::from_utf8(output.stdout)
                    .map_err(|_| "sqlite3 output was not UTF-8".to_owned())?
                    .trim()
                    .parse()
                    .map_err(|_| format!("sqlite3 returned invalid count for {path}"));
            }
            Ok(None) if started.elapsed() < QUERY_TIMEOUT => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("sqlite3 query timed out for {path}"));
            }
        }
    }
}

/// The app-server proxy forwarded Content-Length bytes verbatim, but the isolated daemon
/// replied to neither Content-Length, newline JSON-RPC, nor initialize/ping/WebSocket probes.
/// That unverified protocol is intentionally removed; use SQLite's read-only surfaces instead.
pub fn opencode_api_ambient_param(op: &str, _key: &str, value: &str) -> Result<String, String> {
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("invalid OpenCode path parameter".into());
    }
    let path = op_path(op).ok_or_else(|| "unsupported OpenCode operation".to_owned())?;
    let mut command = Command::new("opencode");
    command.arg("api").arg(path.replace("{sessionID}", value));
    run_opencode_command(&mut command, AMBIENT_TIMEOUT)
}

#[cfg(test)]
pub fn opencode_api_data(
    base_url: &str,
    password: &str,
    op: &str,
    data: &str,
) -> Result<String, String> {
    let path = op_path(op).ok_or_else(|| "unsupported OpenCode operation".to_owned())?;
    http_post(base_url, password, &path, data)
}

pub fn opencode_api_param(
    base_url: &str,
    password: &str,
    op: &str,
    _param_key: &str,
    param_value: &str,
) -> Result<String, String> {
    if !param_value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("invalid OpenCode path parameter".into());
    }
    let path = op_path(op).ok_or_else(|| "unsupported OpenCode operation".to_owned())?;
    http_get(
        base_url,
        password,
        &path.replace("{sessionID}", param_value),
    )
}

fn opencode_api_command(
    endpoint: Option<(&str, &str)>,
    op: &str,
    timeout: Duration,
) -> Result<String, String> {
    let mut command = Command::new("opencode");
    command.arg("api");
    if let Some((base_url, password)) = endpoint {
        add_endpoint(&mut command, base_url, password)?;
    }
    command.arg(op);
    run_opencode_command(&mut command, timeout)
}

fn add_endpoint<'a>(
    command: &'a mut Command,
    base_url: &str,
    password: &str,
) -> Result<&'a mut Command, String> {
    let (scheme, rest) = base_url.split_once("://").ok_or("invalid base URL")?;
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority
        .split(':')
        .next()
        .unwrap_or("")
        .trim_matches(['[', ']']);
    if !matches!(scheme, "http" | "https") || !matches!(host, "127.0.0.1" | "localhost") {
        return Err("OpenCode query restricted to loopback URLs".into());
    }
    Ok(command
        .arg("--server")
        .arg(base_url)
        .env("OPENCODE_PASSWORD", password))
}

fn run_opencode_command(command: &mut Command, timeout: Duration) -> Result<String, String> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not start opencode api: {e}"))?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().map_err(|e| e.to_string())?;
                if !status.success() {
                    return Err(format!(
                        "opencode api failed: {}",
                        String::from_utf8_lossy(&output.stderr).trim()
                    ));
                }
                if output.stdout.len() > MAX_QUERY_OUTPUT {
                    return Err("OpenCode response exceeded output limit".into());
                }
                return String::from_utf8(output.stdout)
                    .map_err(|e| format!("invalid UTF-8 response: {e}"));
            }
            Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => {
                // Reaper-owned query child; the sole permitted SIGKILL use.
                let _ = child.kill();
                let _ = child.wait();
                return Err("OpenCode query timed out or could not be polled".into());
            }
        }
    }
}

pub fn http_get(base_url: &str, password: &str, path: &str) -> Result<String, String> {
    curl_request(base_url, password, path, None, "GET")
}
#[cfg(test)]
pub fn http_post(base_url: &str, password: &str, path: &str, data: &str) -> Result<String, String> {
    curl_request(base_url, password, path, Some(data), "POST")
}
#[allow(dead_code)]
pub fn http_delete(base_url: &str, password: &str, path: &str) -> Result<String, String> {
    curl_request(base_url, password, path, None, "DELETE")
}

fn curl_request(
    base_url: &str,
    password: &str,
    path: &str,
    data: Option<&str>,
    method: &str,
) -> Result<String, String> {
    validate_loopback(base_url)?;
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let mut command = Command::new("curl");
    command
        .args(["-s", "-m", "3", "--config", "-"])
        .args(["-X", method])
        .arg(url);
    if let Some(data) = data {
        // OpenCode rejects form encoding for JSON APIs; shell.create requires application/json.
        command.args(["-H", "Content-Type: application/json"]);
        command.args(["--data", data]);
    }
    run_curl(
        &mut command,
        format!(
            "header = \"Authorization: Basic {}\"\n",
            basic_auth_b64("opencode", password)
        )
        .as_bytes(),
    )
}

fn validate_loopback(url: &str) -> Result<(), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "explicit probe failed".to_owned())?;
    let host = rest
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");
    if !matches!(scheme, "http" | "https") || !matches!(host, "127.0.0.1" | "localhost") {
        return Err("explicit probe failed".into());
    }
    Ok(())
}

fn run_curl(command: &mut Command, config: &[u8]) -> Result<String, String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "explicit probe failed".to_owned())?;
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(config).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("explicit probe failed".into());
        }
    }
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child
                    .wait_with_output()
                    .map_err(|_| "explicit probe failed".to_owned())?;
                if !status.success() || output.stdout.len() > MAX_QUERY_OUTPUT {
                    return Err("explicit probe failed".into());
                }
                return String::from_utf8(output.stdout)
                    .map_err(|_| "explicit probe failed".into());
            }
            Ok(None) if start.elapsed() < QUERY_TIMEOUT => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("explicit probe failed".into());
            }
        }
    }
}

fn basic_auth_b64(user: &str, password: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}");
    let bytes = input.as_bytes();
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        output.push(TABLE[(a >> 2) as usize] as char);
        output.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        output.push(if chunk.len() > 1 {
            TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    output
}

fn op_path(op: &str) -> Option<String> {
    Some(
        match op {
            "server.info" => "/api/info",
            "session.active" => "/api/session/active",
            "session.list" => "/api/session",
            "shell.list" => "/api/shell",
            "pty.list" => "/api/pty",
            "permission.request.list" => "/api/permission/request",
            "form.list" => "/api/form",
            "project.list" => "/api/project",
            "session.message.list" => "/api/session/{sessionID}/message",
            "session.inbox.list" => "/api/session/{sessionID}/inbox",
            "session.permission.list" => "/api/session/{sessionID}/permission",
            "session.form.list" => "/api/session/{sessionID}/question",
            "shell.remove" => "/api/shell/{id}",
            "shell.create" => "/api/shell",
            "session.create" => "/api/session",
            _ => return None,
        }
        .into(),
    )
}

pub fn op_bare_array_empty(body: &str) -> Option<bool> {
    let body = body.trim();
    if !body.starts_with('[') || !body.ends_with(']') {
        return None;
    }
    Some(body[1..body.len() - 1].trim().is_empty())
}

fn data_region(body: &str) -> Option<&str> {
    let start = body.find("\"data\"")?;
    let tail = body[start..].split_once(':')?.1.trim_start();
    Some(tail)
}

pub fn op_active_empty(body: &str) -> Option<bool> {
    let data = data_region(body)?;
    if !data.starts_with('{') {
        return None;
    }
    let end = data.find('}')?;
    let contents = data[1..end].trim();
    if contents.is_empty() {
        Some(true)
    } else {
        Some(false)
    }
}

pub fn op_list_empty(body: &str) -> Option<bool> {
    let data = data_region(body)?;
    if !data.starts_with('[') {
        return None;
    }
    let end = data.find(']')?;
    let contents = data[1..end].trim();
    if contents.is_empty() {
        Some(true)
    } else {
        Some(false)
    }
}

fn backend_alive(body: &str) -> Option<bool> {
    for key in ["backendAlive", "backend_alive"] {
        if let Some(rest) = body.split_once(key).map(|(_, rest)| rest) {
            let value = rest.trim_start_matches(|c: char| {
                c.is_whitespace() || c == '"' || c == '\'' || c == ':' || c == '='
            });
            if value.starts_with("true") {
                return Some(true);
            }
            if value.starts_with("false") {
                return Some(false);
            }
        }
    }
    None
}

pub fn broker_health(endpoint: &str) -> BrokerHealth {
    let (host, port) = endpoint.rsplit_once(':').unwrap_or((endpoint, ""));
    if host != "127.0.0.1" && host != "localhost" {
        return BrokerHealth {
            alive: None,
            raw_note: "broker query restricted to loopback endpoints".into(),
        };
    }
    let result = (|| -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(
            &format!("{host}:{port}")
                .parse()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?,
            QUERY_TIMEOUT,
        )?;
        stream.set_read_timeout(Some(QUERY_TIMEOUT))?;
        stream.set_write_timeout(Some(QUERY_TIMEOUT))?;
        stream.write_all(
            format!("GET /health HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )?;
        let mut response = Vec::new();
        (&mut stream)
            .take(MAX_QUERY_OUTPUT as u64)
            .read_to_end(&mut response)?;
        let _ = stream.shutdown(Shutdown::Both);
        Ok(String::from_utf8_lossy(&response).into_owned())
    })();
    match result {
        Ok(raw_note) => {
            let alive = backend_alive(&raw_note);
            let raw_note = if alive.is_some() {
                raw_note
            } else {
                format!("unparseable /health response: {raw_note}")
            };
            BrokerHealth { alive, raw_note }
        }
        Err(error) => BrokerHealth {
            alive: None,
            raw_note: format!("/health query failed: {error}"),
        },
    }
}

fn parse_sv_output(output: &str) -> SvState {
    let lower = output.to_ascii_lowercase();
    if lower.split_whitespace().any(|word| word == "finish") || lower.contains("finish") {
        return SvState::Finish;
    }
    if lower.contains("run:") || lower.contains("run ") {
        let pid = lower
            .split("(pid ")
            .nth(1)
            .and_then(|s| s.split(')').next())
            .and_then(|s| s.parse().ok());
        return SvState::Up { pid };
    }
    if lower.contains("down:") || lower.contains("down ") {
        return SvState::Down;
    }
    SvState::Unknown
}

pub fn sv_status(service: &str) -> SvState {
    let mut child = match Command::new("sv")
        .arg("status")
        .arg(service)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return SvState::Unknown,
    };
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .ok()
                    .map(|o| parse_sv_output(&String::from_utf8_lossy(&o.stdout)))
                    .unwrap_or(SvState::Unknown)
            }
            Ok(None) if started.elapsed() < QUERY_TIMEOUT => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                // This is Reaper's direct query child, the sole allowed SIGKILL exception.
                let _ = child.kill();
                let _ = child.wait();
                return SvState::Unknown;
            }
        }
    }
}

pub fn meminfo_swap() -> (u64, u64) {
    let Ok(contents) = fs::read_to_string("/proc/meminfo") else {
        return (0, 0);
    };
    let mut total = 0;
    let mut free = 0;
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let value = parts.nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        match line.split(':').next().unwrap_or("") {
            "SwapTotal" => total = value,
            "SwapFree" => free = value,
            _ => {}
        }
    }
    (total, free)
}

pub fn dir_size_bytes(path: &std::path::Path) -> u64 {
    let mut pending = vec![path.to_path_buf()];
    let mut total = 0u64;
    let mut visited = 0usize;
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_DIR_ENTRIES {
                return total;
            }
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_health_parser_requires_explicit_boolean() {
        assert_eq!(backend_alive(r#"{"backendAlive":true}"#), Some(true));
        assert_eq!(backend_alive(r#"{"backendAlive":false}"#), Some(false));
        assert_eq!(backend_alive(r#"{"healthy":true}"#), None);
        assert_eq!(broker_health("example.com:8377").alive, None);
    }

    #[test]
    fn sv_status_fixture_parser_distinguishes_states() {
        assert_eq!(
            parse_sv_output("run: /service/x: (pid 123) 4s"),
            SvState::Up { pid: Some(123) }
        );
        assert_eq!(
            parse_sv_output("down: /service/x: 4s, normally up"),
            SvState::Down
        );
        assert_eq!(parse_sv_output("finish: /service/x"), SvState::Finish);
        assert_eq!(parse_sv_output("garbage"), SvState::Unknown);
    }

    #[test]
    fn live_status_never_claims_unverified_liveness() {
        if let SvState::Unknown = sv_status("__reaper_nonexistent_fixture__") {
            assert_eq!(
                sv_status("__reaper_nonexistent_fixture__"),
                SvState::Unknown
            );
        }
    }

    #[test]
    fn opencode_fixture_parsers_and_loopback_guard() {
        assert_eq!(op_active_empty(r#"{"data":{}}"#), Some(true));
        assert_eq!(op_active_empty(r#"{"data":{"id":"x"}}"#), Some(false));
        assert_eq!(op_active_empty(r#"{"data":[]}"#), None);
        assert_eq!(op_list_empty(r#"{"data":[]}"#), Some(true));
        assert_eq!(op_list_empty(r#"{"data":[{"id":"x"}]}"#), Some(false));
        assert_eq!(op_list_empty(r#"{"other":[]}"#), None);
        assert!(opencode_api("https://example.com", "", "server.info").is_err());
        assert_eq!(op_bare_array_empty("[]"), Some(true));
        assert_eq!(op_bare_array_empty("[{...}]"), Some(false));
        assert_eq!(op_bare_array_empty(r#"{"data":[]}"#), None);
        assert_eq!(op_bare_array_empty(""), None);
        let error = http_get("http://127.0.0.1:1", "sentinel-secret", "/api/info").unwrap_err();
        assert!(!error.contains("sentinel-secret"));
        assert!(!http_post(
            "http://127.0.0.1:1",
            "sentinel-secret",
            "/api/session",
            "{}"
        )
        .unwrap_err()
        .contains("sentinel-secret"));
        assert!(
            !http_delete("http://127.0.0.1:1", "sentinel-secret", "/api/shell/x")
                .unwrap_err()
                .contains("sentinel-secret")
        );
        assert_eq!(
            basic_auth_b64("opencode", "dummy-pw-123"),
            "b3BlbmNvZGU6ZHVtbXktcHctMTIz"
        );
        assert_eq!(basic_auth_b64("opencode", "abc"), "b3BlbmNvZGU6YWJj");
        assert!(opencode_api_param(
            "http://127.0.0.1:1",
            "x",
            "session.message.list",
            "sessionID",
            "ses_ok-1"
        )
        .is_err());
        assert!(opencode_api_param(
            "http://127.0.0.1:1",
            "x",
            "session.message.list",
            "sessionID",
            "ses/a"
        )
        .is_err());
    }

    #[test]
    fn codex_db_counts_reads_fixture_databases_read_only() {
        if Command::new("sqlite3").arg("--version").output().is_err() {
            return;
        }
        let home = std::env::temp_dir().join(format!("reaper-codex-db-{}", std::process::id()));
        let codex = home.join(".codex");
        fs::create_dir_all(&codex).unwrap();
        let state = codex.join("state_5.sqlite");
        let queue = codex.join("queue_1.sqlite");
        assert!(Command::new("sqlite3")
            .arg(&state)
            .arg("create table threads(archived integer); insert into threads values(0),(1);")
            .status()
            .unwrap()
            .success());
        assert!(Command::new("sqlite3")
            .arg(&queue)
            .arg("create table queued_items(id integer); insert into queued_items values(1);")
            .status()
            .unwrap()
            .success());
        assert_eq!(codex_db_counts(home.to_str().unwrap()).unwrap(), (2, 1, 1));
        let _ = fs::remove_dir_all(home);
        assert!(codex_db_counts("").is_err());
        assert!(codex_db_counts("/path/that/does/not/exist").is_err());
    }
}
