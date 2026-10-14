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

#[test]
fn live_server_restart_rejects_the_previous_identity_proof() {
    let root = std::env::temp_dir().join(format!(
        "reaper-restart-proof-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let (mut first, first_address) = launch(&root);
    let first_identity = request(first_address, "IDENTITY\n");
    let first_fields: Vec<_> = first_identity.split_whitespace().collect();
    let first_id = (
        first_fields[1].parse::<u32>().unwrap(),
        first_fields[2].parse::<u64>().unwrap(),
    );
    assert_eq!(request(first_address, "SHUTDOWN\n"), "CLOSING\n");
    assert!(first.wait().unwrap().success());

    let (mut restarted, second_address) = launch(&root);
    let second_identity = request(second_address, "IDENTITY\n");
    let second_fields: Vec<_> = second_identity.split_whitespace().collect();
    let second_id = (
        second_fields[1].parse::<u32>().unwrap(),
        second_fields[2].parse::<u64>().unwrap(),
    );
    assert_ne!(
        first_id, second_id,
        "restart must establish a new server identity"
    );
    assert_ne!(
        std::fs::read_to_string(format!("/proc/{}/stat", first_id.0))
            .ok()
            .and_then(|stat| {
                let end = stat.rfind(')')?;
                stat[end + 1..]
                    .split_whitespace()
                    .nth(19)?
                    .parse::<u64>()
                    .ok()
            }),
        Some(first_id.1),
        "old server proof must no longer identify a live process"
    );
    assert_eq!(request(second_address, "SHUTDOWN\n"), "CLOSING\n");
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
    // This Termux kernel denies both TCP tables, so transport exclusivity is
    // unprovable and attestation must fail closed (rather than authorize close).
    let tables_readable = std::fs::read_to_string("/proc/self/net/tcp").is_ok()
        || std::fs::read_to_string("/proc/net/tcp").is_ok();
    let expected = if tables_readable {
        &["1", "1", "1", "1"][..]
    } else {
        &["0", "1", "1", "0"][..]
    };
    assert_eq!(&attestation_fields[5..], expected);
    let mut unregistered = UnixStream::connect(&socket_path).unwrap();
    unregistered.write_all(b"REGISTER rogue-peer\n").unwrap();
    let mut refused = String::new();
    unregistered.read_to_string(&mut refused).unwrap();
    assert_eq!(refused, "REFUSED unregistered_lab_identity\n");
    let mut same_uid_client = UnixStream::connect(&socket_path).unwrap();
    same_uid_client.write_all(b"PING\n").unwrap();
    let mut second_peer = String::new();
    same_uid_client.read_to_string(&mut second_peer).unwrap();
    let second_fields: Vec<_> = second_peer.split_whitespace().collect();
    assert_eq!(second_fields[0], "PEER");
    assert_eq!(second_fields[1], std::process::id().to_string());
    assert_eq!(second_fields[2], current_uid().to_string());
    // Two channels from this UID are credentialed identically; credentials do
    // not isolate same-UID actors. Only the exact registered roster authorizes.
    let mut wrong_nonce = UnixStream::connect(&socket_path).unwrap();
    wrong_nonce.write_all(b"CONNECT rogue-peer\n").unwrap();
    let mut nonce_refused = String::new();
    wrong_nonce.read_to_string(&mut nonce_refused).unwrap();
    assert_eq!(nonce_refused, "REFUSED client_nonce_mismatch\n");
    let mut close = UnixStream::connect(&socket_path).unwrap();
    close.write_all(b"SHUTDOWN\n").unwrap();
    let mut response = String::new();
    close.read_to_string(&mut response).unwrap();
    assert_eq!(response, "CLOSING\n");
    drop(close);
    assert!(child.wait().unwrap().success());
    if !tables_readable {
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(stderr.contains("TCP listener tables unreadable"));
    }
}

#[cfg(unix)]
#[test]
fn unregistered_peer_is_refused_without_roster_membership() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;

    let root = std::env::temp_dir().join(format!("reaper-unregistered-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("service.sock");
    let registry = root.join("clients.json");
    std::fs::write(&registry, "{\"clients\":[]}\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "serve-uds"])
        .env("REAPER_LAB_SERVICE_SOCKET", &socket)
        .env("REAPER_LAB_REGISTRY", root.join("lab.json"))
        .env("REAPER_CLIENT_REGISTRY", registry)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.starts_with("UDS "));
    let mut peer = UnixStream::connect(&socket).unwrap();
    peer.write_all(b"PING\n").unwrap();
    let mut response = String::new();
    peer.read_to_string(&mut response).unwrap();
    assert_eq!(response, "REFUSED unregistered_peer\n");
    child.kill().unwrap();
    child.wait().unwrap();
}

#[cfg(unix)]
#[test]
fn same_uid_child_peer_helper() {
    let Ok(socket) = std::env::var("REAPER_TEST_SAME_UID_SOCKET") else {
        return;
    };
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    thread::sleep(Duration::from_millis(150));
    let mut register = UnixStream::connect(&socket).unwrap();
    register
        .write_all(
            format!(
                "REGISTER {}\n",
                std::env::var("REAPER_TEST_SAME_UID_NONCE").unwrap()
            )
            .as_bytes(),
        )
        .unwrap();
    let mut reply = String::new();
    register.read_to_string(&mut reply).unwrap();
    assert!(reply.starts_with(&format!("REGISTERED {} ", std::process::id())));
    let mut ping = UnixStream::connect(&socket).unwrap();
    ping.write_all(b"PING\n").unwrap();
    reply.clear();
    ping.read_to_string(&mut reply).unwrap();
    println!("CHILD_PEER {}", reply.trim());
}

#[cfg(unix)]
#[test]
fn same_uid_child_is_credentialed_but_roster_remains_authority() {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    let root = std::env::temp_dir().join(format!(
        "reaper-same-uid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("service.sock");
    let registry = root.join("clients.json");
    let mut child = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "serve-uds"])
        .env("REAPER_LAB_SERVICE_SOCKET", &socket)
        .env("REAPER_LAB_REGISTRY", root.join("lab.json"))
        .env("REAPER_CLIENT_REGISTRY", &registry)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    std::io::BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.starts_with("UDS "));
    let mut agent = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "same_uid_child_peer_helper", "--nocapture"])
        .env("REAPER_TEST_SAME_UID_SOCKET", &socket)
        .env("REAPER_TEST_SAME_UID_NONCE", "child-peer")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let ticks = start_ticks(agent.id());
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let parent = std::process::id();
    let parent_ticks = start_ticks(parent);
    let entry = |tool: &str, nonce: &str, pid: u32, start: u64| {
        format!("{{\"tool\":\"{tool}\",\"project\":\"test\",\"server\":\"{}\",\"nonce\":\"{nonce}\",\"pid\":{pid},\"start_ticks\":{start},\"boot_id\":\"{}\",\"state\":\"EndedVerified\",\"evidence\":\"rostered\",\"provenance\":\"test\",\"jobs\":[]}}", socket.display(), boot.trim())
    };
    std::fs::write(
        &registry,
        format!(
            "{{\"clients\":[{},{}]}}\n",
            entry("child", "child-peer", agent.id(), ticks),
            entry("parent", "parent-peer", parent, parent_ticks)
        ),
    )
    .unwrap();
    let mut parent_register = UnixStream::connect(&socket).unwrap();
    parent_register
        .write_all(b"REGISTER parent-peer\n")
        .unwrap();
    let mut parent_registered = String::new();
    parent_register
        .read_to_string(&mut parent_registered)
        .unwrap();
    assert!(parent_registered.starts_with(&format!("REGISTERED {parent} ")));
    let mut parent_ping = UnixStream::connect(&socket).unwrap();
    parent_ping.write_all(b"PING\n").unwrap();
    let mut parent_peer = String::new();
    parent_ping.read_to_string(&mut parent_peer).unwrap();
    assert!(parent_peer.starts_with(&format!("PEER {parent} {} ", current_uid())));
    let mut output = String::new();
    agent
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut output)
        .unwrap();
    assert!(
        agent.wait().unwrap().success(),
        "child peer failed: {output}"
    );
    assert!(output.contains(&format!("CHILD_PEER PEER {} {}", agent.id(), current_uid())));
    assert_ne!(
        parent,
        agent.id(),
        "the two credentialed peers must be distinct processes"
    );
    let mut close = UnixStream::connect(&socket).unwrap();
    close.write_all(b"REGISTER parent-peer\n").unwrap();
    let mut registered = String::new();
    close.read_to_string(&mut registered).unwrap();
    assert!(registered.starts_with(&format!("REGISTERED {parent} ")));
    drop(close);
    let mut close = UnixStream::connect(&socket).unwrap();
    close.write_all(b"SHUTDOWN\n").unwrap();
    let mut reply = String::new();
    close.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "CLOSING\n");
    assert!(child.wait().unwrap().success());
}

#[cfg(unix)]
#[test]
fn wrong_mode_uds_directory_refuses_service_start() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("reaper-bad-mode-{}", std::process::id()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "serve-uds"])
        .env("REAPER_LAB_SERVICE_SOCKET", root.join("service.sock"))
        .env("REAPER_LAB_REGISTRY", root.join("lab.json"))
        .env("REAPER_CLIENT_REGISTRY", root.join("clients.json"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("parent directory must be current-UID-owned mode 0700"));
    assert!(!root.join("service.sock").exists());
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
    let tables_readable = std::fs::read_to_string("/proc/self/net/tcp").is_ok()
        || std::fs::read_to_string("/proc/net/tcp").is_ok();
    let output = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "demo", "--grace-secs", "2"])
        .output()
        .unwrap();
    let report = String::from_utf8_lossy(&output.stdout);
    if !tables_readable {
        // Both tables denied means listener exclusivity is unknown; stop at
        // the grace-entry gate instead of weakening the evidence to close.
        assert!(!output.status.success());
        for step in 1..=10 {
            assert!(
                report.contains(&format!("STEP {step:02}")),
                "missing step {step}: {report}"
            );
        }
        assert!(!report.contains("STEP 11"));
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains("TCP listener tables unreadable"),
            "missing fail-closed reason: {error}"
        );
        assert!(error.contains("policy did not enter candidate state"));
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", sentinel.0)).unwrap();
        let end = stat.rfind(')').unwrap();
        let ticks: u64 = stat[end + 1..]
            .split_whitespace()
            .nth(19)
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(ticks, sentinel.1, "production sentinel identity changed");
        return;
    }
    assert!(
        output.status.success(),
        "demo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
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
