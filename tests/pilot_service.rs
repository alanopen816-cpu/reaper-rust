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

#[cfg(unix)]
#[test]
fn unix_service_reports_kernel_supplied_scm_credentials() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;

    let root = std::env::temp_dir().join(format!(
        "reaper-peercred-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = root.join("service.sock");
    let client_registry = root.join("clients.json");
    let client_pid = std::process::id();
    let client_ticks = start_ticks(client_pid);
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned();
    std::fs::write(
        &client_registry,
        format!(
            "{{\"clients\":[{{\"tool\":\"test-agent\",\"project\":\"test\",\"server\":\"{}\",\"nonce\":\"test-peer\",\"pid\":{},\"start_ticks\":{},\"boot_id\":\"{}\",\"state\":\"EndedVerified\",\"evidence\":\"test-spawn roster\",\"provenance\":\"test parent registered child\",\"jobs\":[]}}]}}\n",
            socket_path.display(), client_pid, client_ticks, boot_id
        ),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "serve-uds"])
        .env("REAPER_LAB_SERVICE_SOCKET", &socket_path)
        .env("REAPER_LAB_REGISTRY", root.join("lab.json"))
        .env("REAPER_CLIENT_REGISTRY", &client_registry)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut ready = String::new();
    out.read_line(&mut ready).unwrap();
    assert!(ready.starts_with("UDS "), "service readiness: {ready:?}");

    let mut client = UnixStream::connect(&socket_path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(b"REGISTER test-peer\n").unwrap();
    let mut registered = String::new();
    client.read_to_string(&mut registered).unwrap();
    assert!(registered.starts_with(&format!("REGISTERED {} ", std::process::id())));
    drop(client);

    let mut client = UnixStream::connect(&socket_path).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(b"PING\n").unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    let fields: Vec<_> = response.split_whitespace().collect();
    assert_eq!(fields.first(), Some(&"PEER"));
    assert_eq!(
        fields.get(1).unwrap().parse::<u32>().unwrap(),
        std::process::id()
    );
    assert_eq!(
        fields.get(2).unwrap().parse::<u32>().unwrap(),
        current_uid()
    );
    let attestation = {
        let mut stream = UnixStream::connect(&socket_path).unwrap();
        stream.write_all(b"ATTEST\n").unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    };
    let attestation_fields: Vec<_> = attestation.split_whitespace().collect();
    assert_eq!(attestation_fields.first(), Some(&"OBSERVATION"));
    assert_eq!(attestation_fields.len(), 9);
    assert_eq!(&attestation_fields[5..], &["1", "1", "1", "1"]);
    let mut unregistered = UnixStream::connect(&socket_path).unwrap();
    unregistered.write_all(b"REGISTER rogue-peer\n").unwrap();
    let mut refused = String::new();
    unregistered.read_to_string(&mut refused).unwrap();
    assert_eq!(refused, "REFUSED unregistered_lab_identity\n");
    let mut close = UnixStream::connect(&socket_path).unwrap();
    close.write_all(b"SHUTDOWN\n").unwrap();
    let mut response = String::new();
    close.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CLOSING\n");
    drop(close);
    assert!(child.wait().unwrap().success());
}

fn current_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[cfg(unix)]
fn production_sentinel() -> Option<(u32, u64)> {
    for item in std::fs::read_dir("/proc").ok()? {
        let item = item.ok()?;
        let pid = item.file_name().to_string_lossy().parse::<u32>().ok();
        let Some(pid) = pid else { continue };
        let exe = std::fs::read_link(item.path().join("exe")).ok()?;
        if !exe.to_string_lossy().contains("/opencode") {
            continue;
        }
        let stat = std::fs::read_to_string(item.path().join("stat")).ok()?;
        let end = stat.rfind(')')?;
        let ticks = stat[end + 1..].split_whitespace().nth(19)?.parse().ok()?;
        return Some((pid, ticks));
    }
    None
}

#[cfg(unix)]
#[test]
fn observer_drives_short_grace_reconnect_cycle_and_closes_only_demo() {
    let sentinel = production_sentinel().expect("production OpenCode sentinel is running");
    let output = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "demo", "--grace-secs", "2"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8_lossy(&output.stdout);
    for step in 1..=18 {
        assert!(
            report.contains(&format!("STEP {step:02}")),
            "missing step {step}: {report}"
        );
    }
    for event in [
        "TIME grace1_start=",
        "TIME reconnect_cancel=",
        "TIME grace2_start=",
        "TIME grace2_expiry=",
        "TIME official_close=",
    ] {
        assert!(
            report.contains(event),
            "missing monotonic timestamp {event}"
        );
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", sentinel.0)).unwrap();
    let end = stat.rfind(')').unwrap();
    let ticks: u64 = stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(ticks, sentinel.1, "production sentinel identity changed");
}
