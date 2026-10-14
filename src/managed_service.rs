//! Small, real loopback service used only by Reaper's isolated lab.
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Duration;

fn log(event: &str) -> io::Result<()> {
    let line = format!("{{\"event\":\"{event}\",\"pid\":{}}}\n", std::process::id());
    io::stderr().lock().write_all(line.as_bytes())?;
    if let Some(path) = std::env::var_os("REAPER_LAB_SERVICE_JOURNAL") {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let path = std::path::PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        file.write_all(line.as_bytes())?;
        file.sync_all()?;
    }
    Ok(())
}

fn recover_jobs() -> io::Result<HashMap<String, bool>> {
    let Some(path) = std::env::var_os("REAPER_LAB_SERVICE_JOURNAL") else {
        return Ok(HashMap::new());
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(error) => return Err(error),
    };
    let mut jobs = HashMap::new();
    for line in text.lines() {
        let Some(event) = line
            .split_once("\"event\":\"")
            .map(|(_, rest)| rest.split('"').next().unwrap_or(""))
        else {
            return Err(io::Error::other("malformed managed-service JSONL journal"));
        };
        if let Some(id) = event.strip_prefix("job_running:") {
            jobs.insert(id.to_owned(), true);
        } else if let Some(id) = event.strip_prefix("job_finished:") {
            jobs.insert(id.to_owned(), false);
        }
    }
    Ok(jobs)
}

#[derive(Default)]
struct ServiceState {
    jobs: HashMap<String, bool>,
    clients: HashMap<String, (u32, u64)>,
    known_clients: HashMap<String, (u32, u64, bool)>,
}
type Ledger = Arc<Mutex<ServiceState>>;

fn start_ticks(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let end = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("malformed proc stat"))?;
    stat[end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| io::Error::other("missing process start ticks"))?
        .parse()
        .map_err(|_| io::Error::other("invalid process start ticks"))
}

fn serve_client(
    stream: TcpStream,
    ledger: Ledger,
    stop: Arc<AtomicBool>,
    server: String,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request = String::new();
    reader.read_line(&mut request)?;
    let mut stream = reader.into_inner();
    let fields: Vec<_> = request.split_whitespace().collect();
    let response = match fields.as_slice() {
        ["PING"] => "PONG\n".to_owned(),
        ["IDENTITY"] => format!(
            "SERVICE {} {} {}\n",
            std::process::id(),
            start_ticks(std::process::id())?,
            std::env::current_exe()?.display()
        ),
        ["START", id, millis]
            if !id.is_empty()
                && id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c)) =>
        {
            let duration = millis
                .parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid job duration"))?;
            let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
            if state.jobs.contains_key(*id) {
                "DUPLICATE\n".to_owned()
            } else {
                state.jobs.insert((*id).to_owned(), true);
                drop(state);
                log(&format!("job_accepted:{id}"))?;
                log(&format!("job_running:{id}"))?;
                let current = ledger.lock().unwrap_or_else(|e| e.into_inner());
                for (client, (pid, ticks)) in &current.clients {
                    crate::client_tracker::record_lab_client(
                        *pid,
                        *ticks,
                        &server,
                        client,
                        true,
                        vec![(*id).to_owned()],
                    )?;
                }
                drop(current);
                let jobs = ledger.clone();
                let id = (*id).to_owned();
                let response_id = id.clone();
                let tracker_ledger = ledger.clone();
                let tracker_server = server.clone();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(duration));
                    if let Some(running) = jobs
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .jobs
                        .get_mut(&id)
                    {
                        *running = false;
                    }
                    let _ = log(&format!("job_finished:{id}"));
                    let state = tracker_ledger.lock().unwrap_or_else(|e| e.into_inner());
                    let clients = state.known_clients.clone();
                    let work: Vec<String> = state
                        .jobs
                        .iter()
                        .filter_map(|(job, running)| running.then_some(job.clone()))
                        .collect();
                    drop(state);
                    for (client, (pid, ticks, connected)) in clients {
                        let _ = crate::client_tracker::record_lab_client(
                            pid,
                            ticks,
                            &tracker_server,
                            &client,
                            connected,
                            work.clone(),
                        );
                    }
                });
                format!("ACCEPTED {response_id}\n")
            }
        }
        ["STATUS", id] => match ledger
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .jobs
            .get(*id)
        {
            Some(true) => format!("RUNNING {id}\n"),
            Some(false) => format!("FINISHED {id}\n"),
            None => format!("UNKNOWN {id}\n"),
        },
        ["CONNECT", id, pid, ticks] => {
            let pid = pid
                .parse::<u32>()
                .map_err(|_| io::Error::other("invalid client pid"))?;
            let ticks = ticks
                .parse::<u64>()
                .map_err(|_| io::Error::other("invalid client start ticks"))?;
            if start_ticks(pid).ok() != Some(ticks) {
                "REFUSED stale_client_identity\n".to_owned()
            } else {
                ledger
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clients
                    .insert((*id).into(), (pid, ticks));
                ledger
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .known_clients
                    .insert((*id).into(), (pid, ticks, true));
                crate::client_tracker::record_lab_client(
                    pid,
                    ticks,
                    &server,
                    id,
                    true,
                    Vec::new(),
                )?;
                log(&format!("client_registered:{id}:{pid}:{ticks}"))?;
                format!("CONNECTED {id}\n")
            }
        }
        ["DISCONNECT", id] => {
            let removed = ledger
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clients
                .remove(*id);
            if let Some((pid, ticks)) = removed {
                let mut state = ledger.lock().unwrap_or_else(|e| e.into_inner());
                state
                    .known_clients
                    .insert((*id).into(), (pid, ticks, false));
                let work: Vec<String> = state
                    .jobs
                    .iter()
                    .filter_map(|(job, running)| running.then_some(job.clone()))
                    .collect();
                drop(state);
                crate::client_tracker::record_lab_client(pid, ticks, &server, id, false, work)?;
                log(&format!("client_ended:{id}"))?;
            }
            format!("DISCONNECTED {id} {}\n", removed.is_some())
        }
        ["CLIENTS"] => format!(
            "CLIENTS {}\n",
            ledger
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clients
                .len()
        ),
        ["SHUTDOWN"] => {
            let state = ledger.lock().unwrap_or_else(|e| e.into_inner());
            if state.jobs.values().any(|running| *running) || !state.clients.is_empty() {
                "BLOCKED active_client_or_pending_work\n".to_owned()
            } else {
                drop(state);
                log("official_shutdown")?;
                stop.store(true, Ordering::Release);
                "CLOSING\n".to_owned()
            }
        }
        _ => "ERROR\n".to_owned(),
    };
    stream.write_all(response.as_bytes())?;
    stream.shutdown(Shutdown::Both)?;
    log("client_disconnected")
}

pub fn serve() -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?.to_string();
    println!("{address}");
    io::stdout().flush()?;
    log("started")?;
    let entry =
        crate::lab::register_managed_service(std::process::id(), start_ticks(std::process::id())?)?;
    let ledger: Ledger = Arc::new(Mutex::new(ServiceState {
        jobs: recover_jobs()?,
        ..ServiceState::default()
    }));
    let stop = Arc::new(AtomicBool::new(false));
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => {
                log("client_connected")?;
                let ledger = ledger.clone();
                let stop = stop.clone();
                let server = address.clone();
                thread::spawn(move || {
                    let _ = serve_client(stream, ledger, stop, server);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    log("stopped")?;
    crate::lab::unregister_managed_service(&entry)?;
    Ok(())
}
