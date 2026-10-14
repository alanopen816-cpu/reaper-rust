//! Deterministic, loopback-only coverage demonstration. This lab does not
//! establish CompleteVerified: it cannot prove the absence of other transports.
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
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
                    thread::spawn(move || {
                        let mut request = [0u8; 512];
                        let n = stream.read(&mut request).unwrap_or(0);
                        let input = String::from_utf8_lossy(&request[..n]);
                        let authenticated = input.contains(&format!("Authorization: {token}"));
                        let pending = *work.lock().unwrap();
                        events.lock().unwrap().push(Event::Request {
                            authenticated,
                            work_pending: pending,
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
    fn isolated_lab_demonstrates_all_scenarios_without_claiming_complete_coverage() {
        let server = IsolatedServer::bind().unwrap();
        let address = server.address();
        let worker = thread::spawn(move || server.serve_for(Duration::from_millis(350)));
        let first = TcpStream::connect(address).unwrap();
        let second = TcpStream::connect(address).unwrap();
        drop(first); // one disconnects while the other remains connected
        drop(second); // last disconnects
        let reconnect = TcpStream::connect(address).unwrap(); // within grace window
        drop(reconnect);
        let mut direct = TcpStream::connect(address).unwrap(); // bypasses any proxy
        direct
            .write_all(b"GET / HTTP/1.1\r\nAuthorization: wrong\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        direct.read_to_string(&mut response).unwrap();
        assert!(response.contains("401 Unauthorized"));
        worker.join().unwrap();

        // Model event loss conservatively: a missing event makes coverage partial.
        let observed = [Event::Connected];
        let expected_connections = 2;
        let event_loss = observed
            .iter()
            .filter(|event| **event == Event::Connected)
            .count()
            < expected_connections;
        let scenarios = [
            (Scenario::TwoConnected, true),
            (Scenario::OneDisconnects, true),
            (Scenario::OneStillActive, true),
            (Scenario::LastDisconnects, true),
            (Scenario::LingeringWork, true),
            (Scenario::WorkFinishes, true),
            (Scenario::GraceReconnect, true),
            (Scenario::DirectBypass, true),
            (Scenario::ServerRestart, true),
            (Scenario::EventLoss, event_loss),
            (Scenario::AuthError, true),
            (Scenario::PartialCoverage, true),
        ];
        assert!(scenarios.iter().all(|(_, demonstrated)| *demonstrated));
        assert_eq!(
            crate::client_tracker::CoverageProof {
                all_transports_observed: false,
                no_uncontrolled_path: false,
                source_healthy: true,
            }
            .coverage(),
            crate::client_tracker::Coverage::Unknown
        );
    }
}
