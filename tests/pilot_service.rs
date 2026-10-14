use std::io::{BufRead, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn managed_service_is_a_real_loopback_process_with_verifiable_identity() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_reaper"))
        .args(["managed-service", "serve"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch the explicitly lab-owned service");
    let mut stdout = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut address = String::new();
    stdout.read_line(&mut address).unwrap();
    let address = address.trim();
    let socket = address.to_socket_addrs().unwrap().next().unwrap();
    assert!(socket.ip().is_loopback());

    let mut client = TcpStream::connect(socket).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(b"PING\n").unwrap();
    let mut response = [0; 64];
    let size = client.read(&mut response).unwrap();
    assert_eq!(&response[..size], b"PONG\n");
    drop(client);
    let mut close = TcpStream::connect(socket).unwrap();
    close.write_all(b"SHUTDOWN\n").unwrap();
    drop(close);
    assert!(child.wait().unwrap().success());
}
