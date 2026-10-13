//! Reaper phase 1: observations only. Absolutely no signal-sending code.
use std::{collections::{BTreeMap, HashMap}, env, fs::{self, OpenOptions}, io::{self, Write}, path::{Path, PathBuf}, thread, time::{Duration, SystemTime, UNIX_EPOCH}};

#[derive(Debug, Clone)]
struct Process {
    pid: u32, ppid: u32, start_ticks: u64, state: char,
    name: String, command: String, rss_kib: u64, swap_kib: u64, uid: Option<u32>,
}
fn parse_stat(input: &str) -> Option<(u32, String, char, u32, u64)> {
    // comm can contain spaces and ')' (including nested parentheses). Find the LAST ')'.
    let l = input.find('(')?;
    let r = input.rfind(')')?;
    let pid = input[..l].trim().parse().ok()?;
    let name = input[l+1..r].to_owned();
    let fields: Vec<&str> = input[r+1..].split_whitespace().collect();
    // after comm: state=field 3/index 0, ppid=field 4/index 1, starttime=field 22/index 19
    if fields.len() < 20 { return None; }
    Some((pid, name, fields[0].chars().next()?, fields[1].parse().ok()?, fields[19].parse().ok()?))
}
fn status_numbers(path: &Path) -> (Option<u32>, u64, u64) {
    let Ok(content) = fs::read_to_string(path) else { return (None, 0, 0) };
    let mut uid = None;
    let mut rss = 0;
    let mut swap = 0;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("Uid:") { uid = v.split_whitespace().next().and_then(|x| x.parse().ok()); }
        if let Some(v) = line.strip_prefix("VmRSS:") { rss = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0); }
        if let Some(v) = line.strip_prefix("VmSwap:") { swap = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0); }
    }
    (uid, rss, swap)
}
fn scan() -> Vec<Process> {
    let mut result = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else { return result };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_string_lossy().parse::<u32>().ok() else { continue };
        let path = entry.path();
        let Ok(stat) = fs::read_to_string(path.join("stat")) else { continue };
        let Some((real_pid, name, state, ppid, start_ticks)) = parse_stat(&stat) else { continue };
        if real_pid != pid { continue; }
        let (uid, rss_kib, swap_kib) = status_numbers(&path.join("status"));
        let command = fs::read(path.join("cmdline")).map(|v| {
            let mut args = v.split(|b| *b == 0).filter(|s| !s.is_empty());
            let first = args.next().map(|x| String::from_utf8_lossy(x).into_owned()).unwrap_or_else(|| name.clone());
            // Deliberately omit arguments: they can contain secrets.
            first
        }).unwrap_or_else(|_| name.clone());
        result.push(Process{ pid, ppid, start_ticks, state, name, command, rss_kib, swap_kib, uid });
    }
    result.sort_by_key(|p| p.pid);
    result
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class { Critical, Session, Managed, Unknown }
impl Class { fn as_str(self) -> &'static str { match self { Self::Critical=>"critical", Self::Session=>"session", Self::Managed=>"managed-protected", Self::Unknown=>"unknown-protected" } } }
fn classify(p: &Process, self_pid: u32) -> Class {
    let name = p.name.to_ascii_lowercase();
    let exe = p.command.to_ascii_lowercase();
    if p.pid == self_pid || ["runsvdir", "runsv", "svlogd", "com.termux", "adbd"].contains(&name.as_str()) ||
        name.starts_with("com.termux:") || name == "reaper" { return Class::Critical; }
    if ["zsh", "bash", "fish", "sh", "tmux", "login"].contains(&name.as_str()) { return Class::Session; }
    if ["opencode", "codex", "codex.bin", "engram", "node", "python", "python3", "serena", "hound", "dbus-daemon", "sshd", "ssh-agent"].contains(&name.as_str()) ||
        exe.contains("/opencode") || exe.contains("/codex") || exe.contains("/serena") || exe.contains("/codegraph") || exe.contains("/rea-") { return Class::Managed; }
    Class::Unknown
}
fn quote_json(raw: &str) -> String {
    let mut result = String::from("\"");
    for c in raw.chars() { match c { '\"' => result.push_str("\\\""), '\\' => result.push_str("\\\\"), '\n'=>result.push_str("\\n"), '\r'=>result.push_str("\\r"), '\t'=>result.push_str("\\t"), c if c.is_control()=> result.push_str(&format!("\\u{:04x}", c as u32)), c=>result.push(c) } }
    result.push('"'); result
}
fn now_secs() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() }
fn civil_date(days: i64) -> (i64, i64, i64) {
    // Gregorian civil-from-days. UTC naming avoids TZ assumptions.
    let z=days+719468; let era=if z>=0 {z} else {z-146096}/146097;
    let doe=z-era*146097; let yoe=(doe-doe/1460+doe/36524-doe/146096)/365;
    let mut y=yoe+era*400; let doy=doe-(365*yoe+yoe/4-yoe/100);
    let mp=(5*doy+2)/153; let d=doy-(153*mp+2)/5+1;
    let m=mp+if mp<10 {3} else {-9}; if m<=2 {y+=1}; (y,m,d)
}
fn default_state_dir() -> PathBuf {
    if let Ok(v) = env::var("XDG_STATE_HOME") { if !v.is_empty() { return PathBuf::from(v).join("reaper"); } }
    PathBuf::from(env::var("HOME").unwrap_or_else(|_| ".".into())).join(".local/state/reaper")
}
fn log_event(state_dir: &Path, event: &str, detail: &str) -> io::Result<()> {
    let time = now_secs(); let (y,m,d) = civil_date((time/86400) as i64);
    let dir=state_dir.join("logs"); fs::create_dir_all(&dir)?;
    let path=dir.join(format!("{:04}-{:02}-{:02}.jsonl",y,m,d));
    let mut f=OpenOptions::new().append(true).create(true).open(path)?;
    writeln!(f, "{{\"time_unix\":{},\"event\":{},\"detail\":{}}}",time,quote_json(event),quote_json(detail))
}
fn render(processes: &[Process]) {
    println!("{:>7} {:>7} {:>9} {:>9} {:>9} {:<18} {}", "PID", "PPID", "RSS KiB", "Swap KiB", "START", "CLASS", "NAME");
    let self_pid=std::process::id();
    for p in processes { println!("{:>7} {:>7} {:>9} {:>9} {:>9} {:<18} {}",p.pid,p.ppid,p.rss_kib,p.swap_kib,p.start_ticks, classify(p,self_pid).as_str(), p.name); }
}
fn observe(interval: u64, state_dir: &Path) -> io::Result<()> {
    log_event(state_dir,"observer.started","read_only=true")?;
    let mut previous: HashMap<u32,u64> = HashMap::new();
    loop {
        let current=scan(); let current_map: HashMap<u32,u64> = current.iter().map(|p|(p.pid,p.start_ticks)).collect();
        let mut counts=BTreeMap::<&str,usize>::new();
        for p in &current {
            let class=classify(p,std::process::id()).as_str(); *counts.entry(class).or_default()+=1;
            if previous.get(&p.pid)!=Some(&p.start_ticks) {
                log_event(state_dir,"process.observed",&format!("pid={} start={} class={} name={}",p.pid,p.start_ticks,class,p.name))?;
            }
        }
        for (pid,start) in &previous { if current_map.get(pid)!=Some(start) { log_event(state_dir,"process.disappeared",&format!("pid={} start={}",pid,start))?; } }
        let overview=counts.iter().map(|(k,v)| format!("{}={}",k,v)).collect::<Vec<_>>().join(" ");
        println!("{} observed={} {}",now_secs(),current.len(),overview);
        previous=current_map;
        thread::sleep(Duration::from_secs(interval));
    }
}
fn main() {
    let args:Vec<String>=env::args().collect();
    let state_dir=default_state_dir();
    let result=match args.get(1).map(String::as_str) {
        Some("scan")=>{let procs=scan();render(&procs);println!("Observed {} processes. READ ONLY.",procs.len());Ok(())},
        Some("inspect")=>{match args.get(2).and_then(|s|s.parse::<u32>().ok()) { Some(pid)=> { let p=scan().into_iter().find(|p|p.pid==pid); if let Some(p)=p {println!("pid={} ppid={} start_ticks={} state={} uid={:?} rss_kib={} swap_kib={} class={} name={} executable={}",p.pid,p.ppid,p.start_ticks,p.state,p.uid,p.rss_kib,p.swap_kib,classify(&p,std::process::id()).as_str(),p.name,p.command); } else {eprintln!("PID not visible");} Ok(())},None=>Err(io::Error::new(io::ErrorKind::InvalidInput,"Expected PID"))}},
        Some("observe")=>{let seconds=args.get(2).and_then(|s|s.parse::<u64>().ok()).unwrap_or(30).max(5); println!("Reaper observer: read-only, interval={}s; logs={}",seconds,state_dir.display());observe(seconds,&state_dir)},
        _=>{println!("Reaper v0.1.0 (safe observation only)\nUsage: reaper scan | inspect <PID> | observe [interval_seconds]\nNever sends signals; no process termination in this build.");Ok(())}
    };
    if let Err(e)=result {eprintln!("reaper error: {}",e);std::process::exit(1)}
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn parse_with_complex_comm(){let s=format!("123 (foo bar) baz) S 1 {}", vec!["0";18].join(" ")); assert_eq!(parse_stat(&s).unwrap().1,"foo bar) baz");}
    #[test] fn never_auto_classify_unknown_as_safe(){let p=Process{pid:123,ppid:1,start_ticks:1,state:'S',name:"mystery".into(),command:"mystery".into(),rss_kib:0,swap_kib:0,uid:None};assert_eq!(classify(&p,999),Class::Unknown);}
    #[test] fn critical_supervisor(){let p=Process{pid:123,ppid:1,start_ticks:1,state:'S',name:"runsvdir".into(),command:"runsvdir".into(),rss_kib:0,swap_kib:0,uid:None};assert_eq!(classify(&p,999),Class::Critical);}
    #[test] fn json_escaping(){assert_eq!(quote_json("a\"\n"),"\"a\\\"\\n\"");}
    #[test] fn utc_epoch(){assert_eq!(civil_date(0),(1970,1,1));}
}
