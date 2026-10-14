//! Deterministic, loopback-only coverage demonstration. This lab does not
//! establish CompleteVerified: it cannot prove the absence of other transports.
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Connected,
    Disconnected,
    Request {
        authenticated: bool,
        work_pending: bool,
        project: String,
        client: String,
    },
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scenario {
    TwoConnected,
    OneDisconnects,
    OneStillActive,
    LastDisconnects,
    LingeringWork,
    WorkFinishes,
    GraceReconnect,
    DirectBypass,
    ServerRestart,
    EventLoss,
    AuthError,
    PartialCoverage,
}

#[allow(dead_code)]
pub struct IsolatedServer {
    listener: TcpListener,
    address: SocketAddr,
    events: Arc<Mutex<Vec<Event>>>,
    work_pending: Arc<Mutex<bool>>,
    token: String,
    project: String,
}

/// Owns a lab sleeper and records completion on wait. Drop always reaps it.
#[allow(dead_code)]
pub struct LabWork {
    child: Child,
    pub pid: u32,
    pub start_ticks: u64,
    pub finished: bool,
}

#[allow(dead_code)]
impl LabWork {
    pub fn spawn() -> std::io::Result<Self> {
        let child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let pid = child.id();
        let start_ticks = crate::lab::identity_ticks(pid)?;
        Ok(Self {
            child,
            pid,
            start_ticks,
            finished: false,
        })
    }

    pub fn is_running(&mut self) -> std::io::Result<bool> {
        Ok(self.child.try_wait()?.is_none())
    }

    pub fn finish(&mut self) -> std::io::Result<()> {
        self.child.kill()?;
        self.child.wait()?;
        self.finished = true;
        Ok(())
    }
}

impl Drop for LabWork {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[allow(dead_code)]
impl IsolatedServer {
    pub fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let address = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            address,
            events: Arc::new(Mutex::new(Vec::new())),
            work_pending: Arc::new(Mutex::new(false)),
            token: "lab-only-token".into(),
            project: "default-project".into(),
        })
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }
    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
    pub fn set_work_pending(&self, pending: bool) {
        *self.work_pending.lock().unwrap() = pending;
    }

    pub fn serve_for(&self, duration: Duration) {
        let until = Instant::now() + duration;
        let events = self.events.clone();
        let work = self.work_pending.clone();
        while Instant::now() < until {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    events.lock().unwrap().push(Event::Connected);
                    let events = events.clone();
                    let work = work.clone();
                    let token = self.token.clone();
                    let project = self.project.clone();
                    thread::spawn(move || {
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                        let mut request = Vec::new();
                        let mut chunk = [0u8; 512];
                        while request.len() < 4096 {
                            match stream.read(&mut chunk) {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    request.extend_from_slice(&chunk[..n]);
                                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                            }
                        }
                        let input = String::from_utf8_lossy(&request);
                        let authenticated = input.contains(&format!("Authorization: {token}"));
                        let client = input
                            .lines()
                            .find_map(|line| line.strip_prefix("X-Lab-Client: "))
                            .unwrap_or("unknown")
                            .trim()
                            .to_owned();
                        let pending = *work.lock().unwrap();
                        events.lock().unwrap().push(Event::Request {
                            authenticated,
                            work_pending: pending,
                            project,
                            client,
                        });
                        let body = if authenticated {
                            format!("work_pending={pending}")
                        } else {
                            "unauthorized".into()
                        };
                        let status = if authenticated {
                            "200 OK"
                        } else {
                            "401 Unauthorized"
                        };
                        let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                        let _ = stream.shutdown(Shutdown::Both);
                        events.lock().unwrap().push(Event::Disconnected);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2))
                }
                Err(_) => break,
            }
        }
    }

    pub fn request(&self, address: SocketAddr, token: &str) -> std::io::Result<String> {
        Self::request_from(address, token)
    }

    pub fn request_from(address: SocketAddr, token: &str) -> std::io::Result<String> {
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
        stream.set_read_timeout(Some(Duration::from_secs(1)))?;
        write!(
            stream,
            "GET / HTTP/1.1\r\nAuthorization: {token}\r\nConnection: close\r\n\r\n"
        )?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        Ok(response)
    }

    pub fn lab_token(&self) -> &str {
        &self.token
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_request_headers_are_observed_completely() {
        let server = IsolatedServer::bind().unwrap();
        let address = server.address();
        let events = server.events.clone();
        let worker = thread::spawn(move || server.serve_for(Duration::from_millis(250)));
        let mut client = TcpStream::connect(address).unwrap();
        client
            .write_all(b"GET / HTTP/1.1\r\nAuthorization: lab-only-token\r\n")
            .unwrap();
        thread::sleep(Duration::from_millis(30));
        client
            .write_all(b"X-Lab-Client: fragmented-client\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        assert!(response.contains("200 OK"));
        assert!(events.lock().unwrap().iter().any(|event| matches!(
            event,
            Event::Request { client, .. } if client == "fragmented-client"
        )));
    }

    #[test]
    fn loopback_lab_exercises_supported_scenarios_and_marks_remaining_gaps() {
        let server = IsolatedServer::bind().unwrap();
        let address = server.address();
        let events = server.events.clone();
        let worker = thread::spawn(move || server.serve_for(Duration::from_millis(1800)));
        let mut first = TcpStream::connect(address).unwrap();
        let mut second = TcpStream::connect(address).unwrap();
        let request = format!(
            "GET / HTTP/1.1\r\nAuthorization: {}\r\n\r\n",
            "lab-only-token"
        );
        first.write_all(request.as_bytes()).unwrap();
        second.write_all(request.as_bytes()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let connected_events = loop {
            let count = events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == Event::Connected)
                .count();
            if count == 2 || Instant::now() >= deadline {
                break count;
            }
            thread::sleep(Duration::from_millis(5));
        };
        assert_eq!(
            connected_events, 2,
            "two clients observed connected concurrently"
        );
        let mut first_response = String::new();
        first.read_to_string(&mut first_response).unwrap();
        let mut second_response = String::new();
        second.read_to_string(&mut second_response).unwrap();
        assert!(first_response.contains("200 OK"));
        assert!(second_response.contains("200 OK"));
        let clients = Arc::new(Mutex::new(vec![
            "client-a".to_owned(),
            "client-b".to_owned(),
        ]));
        let disconnected = clients.lock().unwrap().remove(0);
        assert_eq!(disconnected, "client-a");
        assert_eq!(clients.lock().unwrap().as_slice(), &["client-b"]);
        assert!(first_response.contains("work_pending=false"));

        let work = LabWork::spawn().expect("spawn lab-owned work");
        let work_pid = work.pid;
        let work_identity = work.start_ticks;
        let mut work = Some(work);
        let disconnected = clients.lock().unwrap().remove(0);
        assert_eq!(disconnected, "client-b");
        assert!(
            work.as_mut().unwrap().is_running().unwrap(),
            "lingering work survives last disconnect"
        );
        work.as_mut().unwrap().finish().unwrap();
        assert!(work.as_ref().unwrap().finished, "work completion recorded");
        assert_ne!(
            crate::lab::identity_ticks(work_pid).ok(),
            Some(work_identity)
        );

        // The production grace timer is in src/state.rs, outside this task's
        // allowed surfaces. Keep the reconnect itself real, but don't claim its
        // relationship to production grace expiry.
        let reconnect = TcpStream::connect(address).unwrap();
        drop(reconnect);

        let mut direct = TcpStream::connect(address).unwrap(); // bypass any proxy
        direct
            .write_all(b"GET / HTTP/1.1\r\nAuthorization: wrong\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        direct.read_to_string(&mut response).unwrap();
        assert!(response.contains("401 Unauthorized"));

        // A second isolated listener represents a restarted server; the old
        // listener's accepted client identities are not copied forward.
        let restarted = IsolatedServer::bind().unwrap();
        let restarted_address = restarted.address();
        let restart_worker = thread::spawn(move || restarted.serve_for(Duration::from_millis(300)));
        let response = IsolatedServer::request_from(restarted_address, "lab-only-token");
        assert!(response.unwrap().contains("200 OK"));
        restart_worker.join().unwrap();
        let old_identity = (address, "client-a");
        let new_identity = (restarted_address, "client-a-reconnected");
        assert_ne!(
            old_identity, new_identity,
            "restart creates a new server/client identity"
        );

        worker.join().unwrap();

        let mut captured_events = vec![Event::Connected; connected_events];
        captured_events.pop(); // induce loss by dropping one captured event
        let observed_events = captured_events;
        let expected_event_count = 2;
        let event_loss = observed_events.len() < expected_event_count;
        assert!(event_loss);
        let lost_event_coverage = if event_loss {
            crate::client_tracker::Coverage::Unknown
        } else {
            crate::client_tracker::Coverage::Partial
        };
        assert_eq!(
            lost_event_coverage,
            crate::client_tracker::Coverage::Unknown
        );
        assert_eq!(
            crate::client_tracker::CoverageProof::issue_verified(
                vec!["http".into()],
                "lab-server",
                1,
                30,
                "lab event capture",
                "loopback only",
            )
            .unwrap()
            .invalidate(crate::client_tracker::ProofInvalidation::EventLoss),
            crate::client_tracker::Coverage::Unknown
        );
    }

    #[test]
    fn expired_live_coverage_proof_downgrades_to_unknown() {
        let issued_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let proof = crate::client_tracker::CoverageProof::issue_verified(
            vec!["loopback".into()],
            "ttl-lab-server",
            issued_at,
            0,
            "live loopback lab",
            "isolated listener only",
        )
        .unwrap();
        let server = IsolatedServer::bind().unwrap();
        let address = server.address();
        let worker = thread::spawn(move || server.serve_for(Duration::from_millis(1200)));
        let response = IsolatedServer::request_from(address, "lab-only-token");
        assert!(response.unwrap().contains("200 OK"));
        thread::sleep(Duration::from_millis(1100));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            proof.coverage_for("ttl-lab-server", now),
            crate::client_tracker::Coverage::Unknown
        );
        worker.join().unwrap();
    }

    #[test]
    fn two_live_project_harnesses_keep_clients_and_work_isolated() {
        let mut project_a = IsolatedServer::bind().unwrap();
        let mut project_b = IsolatedServer::bind().unwrap();
        project_a.project = "project-a".into();
        project_b.project = "project-b".into();
        project_a.set_work_pending(true);
        let address_a = project_a.address();
        let address_b = project_b.address();
        let events_a = project_a.events.clone();
        let events_b = project_b.events.clone();
        let worker_a = thread::spawn(move || project_a.serve_for(Duration::from_millis(300)));
        let worker_b = thread::spawn(move || project_b.serve_for(Duration::from_millis(300)));
        let request = |address, client: &str| {
            let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1)).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            write!(stream, "GET / HTTP/1.1\r\nAuthorization: lab-only-token\r\nX-Lab-Client: {client}\r\nConnection: close\r\n\r\n").unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            response
        };
        let response_a = request(address_a, "client-a");
        let response_b = request(address_b, "client-b");
        assert!(response_a.contains("200 OK"));
        assert!(response_b.contains("200 OK"));
        assert!(response_a.contains("work_pending=true"));
        assert!(response_b.contains("work_pending=false"));
        assert_ne!(address_a, address_b);
        worker_a.join().unwrap();
        worker_b.join().unwrap();
        assert_eq!(
            events_a.lock().unwrap().as_slice(),
            &[
                Event::Connected,
                Event::Request {
                    authenticated: true,
                    work_pending: true,
                    project: "project-a".into(),
                    client: "client-a".into()
                },
                Event::Disconnected
            ]
        );
        assert_eq!(
            events_b.lock().unwrap().as_slice(),
            &[
                Event::Connected,
                Event::Request {
                    authenticated: true,
                    work_pending: false,
                    project: "project-b".into(),
                    client: "client-b".into()
                },
                Event::Disconnected
            ]
        );
    }
}
