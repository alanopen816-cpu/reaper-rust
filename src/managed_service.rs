//! Small, real loopback service used only by Reaper's isolated lab.
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

fn log(event: &str) -> io::Result<()> {
    writeln!(
        io::stderr().lock(),
        "{{\"event\":\"{event}\",\"pid\":{}}}",
        std::process::id()
    )
}

fn serve_client(stream: TcpStream) -> io::Result<bool> {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut stream = reader.into_inner();
    match request.trim() {
        "PING" => stream.write_all(b"PONG\n")?,
        "SHUTDOWN" => {
            stream.write_all(b"CLOSING\n")?;
            log("official_shutdown")?;
            return Ok(true);
        }
        _ => stream.write_all(b"ERROR\n")?,
    }
    Ok(false)
}

pub fn serve() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("{}", listener.local_addr()?);
    io::stdout().flush()?;
    log("started")?;
    for incoming in listener.incoming() {
        let stream = incoming?;
        log("client_connected")?;
        if serve_client(stream)? {
            log("stopped")?;
            break;
        }
        log("client_disconnected")?;
    }
    Ok(())
}
