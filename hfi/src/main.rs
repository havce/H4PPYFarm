use std::{
    collections::{HashMap, HashSet},
    env,
    io::Error,
    ops::Sub,
    process, thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use curl::easy::{Easy, List};
use pk9::{Actions, L4Header, Port, PortManager, Protocol, Role, Verdict};
use serde::Deserialize;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System};

const CFG_UPDATE_INTERVAL: u64 = 60; // in secs
const BUSY_WAIT_INTERVAL: u64 = 10; // in milli-secs
const MAX_IDLE_TIME: u64 = 1; // in minutes

#[derive(Deserialize)]
struct HfiConfig {
    checkers: HashMap<u16, Vec<u64>>,
}

impl HfiConfig {
    fn get_ports(&self, blacklist: &mut HashSet<u16>) -> Vec<Port> {
        let mut ports = Vec::new();
        for port in self.checkers.keys() {
            if !blacklist.contains(port) {
                blacklist.insert(*port);
                let port = Port(*port, Protocol::TCP);
                ports.push(port);
            }
        }
        ports
    }
}

struct HfiActions {
    url: String,
    session: Easy,
    session_cookie: Option<String>,
    config: Option<HfiConfig>,
    added_ports: HashSet<u16>,
    last_update: Instant,
    last_packet: Instant,
}

impl HfiActions {
    fn new(url: &str, debug: bool) -> Self {
        let url = if !url.starts_with("http://") && !url.starts_with("https://") {
            format!("http://{url}")
        } else {
            url.to_string()
        };
        let url = url.trim_end_matches("/").to_string();
        let mut session = Easy::new();
        session.verbose(debug).unwrap();
        // set the timeout to a short interval so that we do not stall packet delivery too much
        // FIXME multithread configuration fetching and remove this
        session.timeout(Duration::from_millis(500)).unwrap();
        let session_cookie = None;
        let config = None;
        let added_ports = HashSet::new();
        // FIXME dirty hack to immediately trigger the update_config() func
        let last_update = Instant::now().sub(Duration::from_secs(CFG_UPDATE_INTERVAL));
        let last_packet = Instant::now();
        Self {
            url,
            session,
            session_cookie,
            config,
            added_ports,
            last_update,
            last_packet,
        }
    }

    fn url_for(&self, endpoint: &str) -> String {
        format!("{}{endpoint}", self.url.as_str())
    }

    fn auth(&mut self, password: &str) {
        let mut session_cookie = None;
        {
            let json = format!(r#"{{"password": "{password}"}}"#);
            let bytes = json.as_bytes();
            let mut headers = List::new();
            headers.append("Content-Type: application/json").unwrap();
            self.session.url(&self.url_for("/api/auth")).unwrap();
            self.session.post(true).unwrap();
            self.session.post_field_size(bytes.len() as _).unwrap();
            self.session.http_headers(headers).unwrap();
            self.session.post_fields_copy(bytes).unwrap();
            let mut transfer = self.session.transfer();
            transfer
                .header_function(|header| {
                    if let Some(header) = std::str::from_utf8(header).ok() {
                        if let Some((key, data)) = header.split_once(':') {
                            let data = data.trim();
                            let key = key.to_lowercase();
                            match key.as_str() {
                                "set-cookie" => session_cookie = Some(data.to_string()),
                                _ => (),
                            }
                        }
                    }
                    true
                })
                .unwrap();
            transfer.perform().unwrap();
        }
        self.session_cookie = session_cookie;
    }

    fn update_config(&mut self) {
        if let Some(session_cookie) = self.session_cookie.clone() {
            let mut json: Vec<u8> = Vec::new();
            self.session.url(&self.url_for("/api/hfi")).unwrap();
            self.session.get(true).unwrap();
            self.session.cookie(&session_cookie).unwrap();
            {
                let mut transfer = self.session.transfer();
                transfer
                    .write_function(|data| {
                        json.extend(data);
                        Ok(data.len())
                    })
                    .unwrap();
                transfer.perform().unwrap();
            }
            self.config = serde_json::from_slice::<HfiConfig>(&json).ok();
            if self.config.is_none() {
                eprintln!("[!] server responded with invalid json");
            } else {
                println!("[+] config updated successfully");
            }
        } else {
            eprintln!("[!] not authenticated");
        }
        self.last_update = Instant::now();
    }
}

impl Actions for HfiActions {
    fn busy_wait(&mut self, port_manager: &mut dyn PortManager) -> bool {
        if self.last_update.elapsed().as_secs() < CFG_UPDATE_INTERVAL {
            thread::sleep(Duration::from_millis(BUSY_WAIT_INTERVAL));
        } else {
            // FIXME this should probably be in another thread
            println!("[*] updating config...");
            self.update_config();
            if let Some(config) = &self.config {
                let ports = config.get_ports(&mut self.added_ports);
                if ports.len() > 0 {
                    match port_manager.add_ports(&ports) {
                        Ok(()) => (),
                        Err(e) => eprintln!("[!] could not add ports to filter: {e}"),
                    }
                }
            }
        }
        let time_since_last_pkt = self.last_packet.elapsed().as_secs();
        let idle_time_not_reached = time_since_last_pkt < (MAX_IDLE_TIME * 60);
        if !idle_time_not_reached {
            eprintln!("[!] max idle time reached! quitting...");
        }
        idle_time_not_reached
    }

    fn filter(&mut self, l4_header: &L4Header, _payload: &[u8]) -> pk9::Verdict {
        self.last_packet = Instant::now();
        match l4_header {
            L4Header::TCP(header) => {
                let dst = header.get_dst_port();
                if let Some(config) = &self.config {
                    if config.checkers.contains_key(&dst) {
                        return Verdict::Transform;
                    }
                }
                Verdict::Pass
            }
        }
    }

    fn transform(&mut self, l4_header: &mut L4Header, payload: &[u8]) -> Vec<u8> {
        match l4_header {
            pk9::L4Header::TCP(tcp) => {
                let dst = tcp.get_dst_port();
                if let Some(ts) = tcp.get_timestamp() {
                    let new_ts = if let Some(config) = &self.config {
                        if let Some(deltas) = config.checkers.get(&dst) {
                            assert!(deltas.len() > 0);
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs();
                            (now + deltas[0]) as _
                        } else {
                            ts
                        }
                    } else {
                        ts
                    };
                    tcp.set_timestamp(new_ts);
                }
            }
        }
        payload.to_vec()
    }
}

fn parse_args() -> (String, String, bool) {
    let mut args = env::args().skip(1);
    let mut server_url = None;
    let mut server_password = None;
    let mut debug = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--server-url" => server_url = args.next(),
            "--server-password" => server_password = args.next(),
            "--debug" => debug = true,
            _ => panic!("unknown argument {arg}"),
        }
    }
    if server_url.is_none() {
        panic!("you should provide the server url as a parameter, like '--server-url URL'");
    }
    if server_password.is_none() {
        panic!(
            "you should provide the server password as a parameter, like '--server-password URL'"
        );
    }
    (server_url.unwrap(), server_password.unwrap(), debug)
}

fn ensure_only_instance() -> bool {
    let sys =
        System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new()));
    let pid = process::id();
    let pid = Pid::from_u32(pid);
    let proc = sys.process(pid).unwrap();
    let name = proc.name();
    let iter = sys.processes_by_exact_name(name);
    iter.count() == 1
}

fn main() -> Result<(), Error> {
    if ensure_only_instance() {
        let (system_url, system_password, debug) = parse_args();
        let mut actions = HfiActions::new(&system_url, debug);
        actions.auth(&system_password);
        pk9::run_with("hfi", Role::Client, &[], &mut actions)?;
    }
    Ok(())
}
