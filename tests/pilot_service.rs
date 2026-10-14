use std::io::{BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn request(address: std::net::SocketAddr, message: &str) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.write_all(message.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn start_ticks(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let end = stat.rfind(')').unwrap();
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap()
}

fn launch(root: &std::path::Path) -> (std::process::Child, std::net::SocketAddr) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "serve"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("REAPER_LAB_REGISTRY", root.join("lab.json"))
        .env("REAPER_CLIENT_REGISTRY", root.join("clients.json"))
        .env("REAPER_LAB_SERVICE_JOURNAL", root.join("service.jsonl"))
        .spawn()
        .expect("launch lab-managed service");
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut address = String::new();
    stdout.read_line(&mut address).unwrap();
    let socket = address.trim().to_socket_addrs().unwrap().next().unwrap();
    (child, socket)
}

#[test]
fn managed_service_is_a_real_loopback_process_with_verifiable_identity() {
    let root = std::env::temp_dir().join(format!(
        "reaper-managed-service-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let lab_registry = root.join("lab.json");
    let client_registry = root.join("clients.json");
    let (mut child, socket) = launch(&root);
    assert!(socket.ip().is_loopback());
    let identity = request(socket, "IDENTITY\n");
    assert!(identity.starts_with(&format!("SERVICE {} ", child.id())));
    assert!(identity.contains(env!("CARGO_BIN_EXE_reaper")));

    assert_eq!(request(socket, "PING\n"), "PONG\n");
    let client = std::process::id();
    let ticks = start_ticks(client);
    assert_eq!(
        request(socket, &format!("CONNECT test-client {client} {ticks}\n")),
        "CONNECTED test-client\n"
    );
    let clients = std::fs::read_to_string(&client_registry).unwrap();
    assert!(clients.contains("test-client") && clients.contains("ConnectedVerified"));
    assert_eq!(request(socket, "START job-1 250\n"), "ACCEPTED job-1\n");
    assert_eq!(
        request(socket, "DISCONNECT test-client\n"),
        "DISCONNECTED test-client true\n"
    );
    assert_eq!(request(socket, "STATUS job-1\n"), "RUNNING job-1\n");
    assert_eq!(
        request(socket, "SHUTDOWN\n"),
        "BLOCKED active_client_or_pending_work\n"
    );
    thread::sleep(Duration::from_millis(300));
    assert_eq!(request(socket, "STATUS job-1\n"), "FINISHED job-1\n");
    assert_eq!(request(socket, "CLIENTS\n"), "CLIENTS 0\n");
    let client_record = std::fs::read_to_string(&client_registry).unwrap();
    assert!(client_record.contains("EndedVerified") && client_record.contains("\"jobs\":[]"));
    assert_eq!(request(socket, "SHUTDOWN\n"), "CLOSING\n");
    assert!(child.wait().unwrap().success());
    let lab_record = std::fs::read_to_string(lab_registry).unwrap();
    assert!(!lab_record.contains(&format!("\"pid\":{}", child.id())));
    let (mut restarted, address) = launch(&root);
    assert_eq!(request(address, "STATUS job-1\n"), "FINISHED job-1\n");
    assert_eq!(request(address, "SHUTDOWN\n"), "CLOSING\n");
    assert!(restarted.wait().unwrap().success());
}
