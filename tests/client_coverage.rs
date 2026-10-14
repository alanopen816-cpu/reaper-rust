use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Connected,
    Disconnected,
}

fn proxy() -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<Event>>>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let logged = events.clone();
    let worker = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let mut workers = Vec::new();
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < until {
            match listener.accept() {
                Ok((mut client, _)) => {
                    logged.lock().unwrap().push(Event::Connected);
                    let out = logged.clone();
                    workers.push(thread::spawn(move || {
                        let mut upstream = std::env::var("REAPER_LAB_PORT")
                            .ok()
                            .and_then(|port| TcpStream::connect(format!("127.0.0.1:{port}")).ok());
                        let mut buffer = [0u8; 4096];
                        loop {
                            match client.read(&mut buffer) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if let Some(server) = upstream.as_mut() {
                                        if server.write_all(&buffer[..n]).is_err() {
                                            break;
                                        }
                                        let _ = server
                                            .set_read_timeout(Some(Duration::from_millis(500)));
                                        match server.read(&mut buffer) {
                                            Ok(m) if m > 0 => {
                                                if client.write_all(&buffer[..m]).is_err() {
                                                    break;
                                                }
                                            }
                                            _ => break,
                                        }
                                    }
                                }
                            }
                        }
                        let _ = client.shutdown(Shutdown::Both);
                        out.lock().unwrap().push(Event::Disconnected);
                    }));
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => break,
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
    });
    (address, events, worker)
}

#[test]
fn proxy_logs_two_connections_and_one_close() {
    let (address, events, worker) = proxy();
    let first = TcpStream::connect(address).unwrap();
    let second = TcpStream::connect(address).unwrap();
    thread::sleep(Duration::from_millis(40));
    drop(first);
    thread::sleep(Duration::from_millis(40));
    let log = events.lock().unwrap().clone();
    assert_eq!(log.iter().filter(|e| **e == Event::Connected).count(), 2);
    assert_eq!(log.iter().filter(|e| **e == Event::Disconnected).count(), 1);
    drop(second);
    worker.join().unwrap();
}

#[test]
fn lab_coverage_server_info_is_transparent_through_proxy() {
    if std::env::var("REAPER_LAB_COVERAGE").as_deref() != Ok("1") {
        return;
    }
    fn b64(input: &str) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = input.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            out.push(TABLE[(a >> 2) as usize] as char);
            out.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(c & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }
    let root = std::path::PathBuf::from("/data/data/com.termux/files/usr/tmp/opencode")
        .join(format!("reaper-cov-{}", std::process::id()));
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let log_path = root.join("serve.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let server = std::process::Command::new("opencode")
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
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start isolated lab server");
    struct Cleanup(std::process::Child, std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
            std::env::remove_var("REAPER_LAB_PORT");
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }
    let mut cleanup = Cleanup(server, root.clone());
    let start = std::time::Instant::now();
    let mut password = None;
    while start.elapsed() < Duration::from_secs(30) {
        let text = std::fs::read_to_string(&log_path).unwrap_or_default();
        password = text.lines().find_map(|line| {
            line.split_once("server password")
                .map(|(_, p)| p.trim().to_owned())
        });
        if password.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let password = password.expect("lab server password timed out");
    std::env::set_var("REAPER_LAB_PORT", port.to_string());
    let (address, _, worker) = proxy();
    let mut client = TcpStream::connect(address).unwrap();
    let request = format!(
        "GET /api/info HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
        b64(&format!("opencode:{password}"))
    );
    client.write_all(request.as_bytes()).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut response = String::new();
    let _ = client.read_to_string(&mut response);
    assert!(
        response.contains("200 OK") && response.contains("\"version\""),
        "unexpected proxied response: {response}"
    );
    drop(client);
    worker.join().unwrap();
    let _ = &mut cleanup;
}
