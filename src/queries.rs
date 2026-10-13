//! Bounded, read-only production queries. Query children are Reaper-owned;
//! they may be killed only when their own query timeout expires.

use std::fs;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const QUERY_TIMEOUT: Duration = Duration::from_secs(3);
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
}
