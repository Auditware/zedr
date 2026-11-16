use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use zedr_shared::sensor::{PackageItem, PersistenceItem, ProcessDetails, ProcessKey, Socket, Source};

use crate::{packages, persistence};

const CLOCK_TICKS_PER_SECOND: u64 = 100;
const KERNEL_THREAD_FLAG: u64 = 0x0020_0000;
const MAX_COMMAND_LINE_BYTES: usize = 4096;
const INIT_ROOT: &str = "1/root";

const TCP_SYN_RECV: u8 = 0x03;
const TCP_TIME_WAIT: u8 = 0x06;
const TCP_CLOSE: u8 = 0x07;
const TCP_LISTEN: u8 = 0x0A;

#[derive(Debug, PartialEq, Eq)]
pub struct Stat {
    pub ppid: u32,
    pub start_ticks: u64,
    pub image: u64,
    pub kernel_thread: bool,
    pub exited: bool,
}

pub fn parse_stat(contents: &str) -> Option<Stat> {
    let name_start = contents.find('(')?;
    let name_end = contents.rfind(')')?;
    let name = contents.get(name_start + 1..name_end)?;
    let fields: Vec<&str> = contents.get(name_end + 1..)?.split_whitespace().collect();

    let state = *fields.first()?;
    let flags: u64 = fields.get(6)?.parse().ok()?;
    let start_ticks: u64 = fields.get(19)?.parse().ok()?;
    let stack_start = fields.get(25).copied().unwrap_or("0");
    let arguments_start = fields.get(45).copied().unwrap_or("0");

    let mut image = DefaultHasher::new();
    (name, stack_start, arguments_start).hash(&mut image);

    Some(Stat {
        ppid: fields.get(1)?.parse().ok()?,
        start_ticks,
        image: image.finish(),
        kernel_thread: flags & KERNEL_THREAD_FLAG != 0,
        exited: matches!(state, "Z" | "X" | "x"),
    })
}

pub fn parse_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub fn parse_command_line(raw: &[u8]) -> Vec<String> {
    let raw = &raw[..raw.len().min(MAX_COMMAND_LINE_BYTES)];
    raw.split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).to_string())
        .collect()
}

pub fn parse_boot_time(stat: &str) -> Option<u64> {
    stat.lines()
        .find_map(|line| line.strip_prefix("btime "))?
        .trim()
        .parse()
        .ok()
}

fn bracketed_number(link: &str, prefix: &str) -> Option<u64> {
    link.strip_prefix(prefix)?.strip_suffix(']')?.parse().ok()
}

pub fn parse_socket_link(link: &str) -> Option<u64> {
    bracketed_number(link, "socket:[")
}

pub fn parse_namespace_link(link: &str) -> Option<u64> {
    bracketed_number(link, "net:[")
}

#[derive(Debug, PartialEq, Eq)]
pub struct TcpRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub inode: u64,
}

fn parse_address(field: &str) -> Option<SocketAddr> {
    let (address, port) = field.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    let mut bytes = Vec::with_capacity(16);
    for word in address.as_bytes().chunks(8) {
        let word = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
        bytes.extend_from_slice(&word.to_ne_bytes());
    }

    let ip = match bytes.len() {
        4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?)),
        16 => {
            let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?);
            match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            }
        }
        _ => return None,
    };

    Some(SocketAddr::new(ip, port))
}

pub fn parse_tcp_table(contents: &str) -> Vec<TcpRow> {
    contents
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(TcpRow {
                local: parse_address(fields.get(1)?)?,
                remote: parse_address(fields.get(2)?)?,
                state: u8::from_str_radix(fields.get(3)?, 16).ok()?,
                inode: fields.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

pub fn outbound(rows: Vec<TcpRow>) -> Vec<Socket> {
    let listening: HashSet<u16> = rows
        .iter()
        .filter(|row| row.state == TCP_LISTEN)
        .map(|row| row.local.port())
        .collect();

    rows.into_iter()
        .filter(|row| !matches!(row.state, TCP_LISTEN | TCP_SYN_RECV | TCP_TIME_WAIT | TCP_CLOSE))
        .filter(|row| row.inode != 0 && !listening.contains(&row.local.port()))
        .map(|row| Socket { inode: row.inode, local: row.local, remote: row.remote })
        .collect()
}

struct Seen {
    key: ProcessKey,
    namespace: Option<u64>,
}

pub struct ProcSource {
    root: PathBuf,
    boot_time: u64,
    seen: HashMap<u32, Seen>,
    socket_namespaces: HashMap<u64, Option<u64>>,
}

impl ProcSource {
    pub fn new(root: &Path) -> Result<Self, String> {
        let stat = fs::read_to_string(root.join("stat"))
            .map_err(|e| format!("Failed to read {}: {}", root.join("stat").display(), e))?;
        let boot_time = parse_boot_time(&stat)
            .ok_or_else(|| "The boot time is missing from the kernel statistics".to_string())?;

        Ok(Self {
            root: root.to_path_buf(),
            boot_time,
            seen: HashMap::new(),
            socket_namespaces: HashMap::new(),
        })
    }

    fn process_dir(&self, pid: u32) -> PathBuf {
        self.root.join(pid.to_string())
    }

    fn namespace_of(&self, pid: u32) -> Option<u64> {
        let link = fs::read_link(self.process_dir(pid).join("ns/net")).ok()?;
        parse_namespace_link(&link.to_string_lossy())
    }

    fn tcp_rows(&self, pid: u32) -> Option<Vec<TcpRow>> {
        let net = self.process_dir(pid).join("net");
        let mut rows = parse_tcp_table(&fs::read_to_string(net.join("tcp")).ok()?);
        if let Ok(v6) = fs::read_to_string(net.join("tcp6")) {
            rows.extend(parse_tcp_table(&v6));
        }
        Some(rows)
    }
}

impl Source for ProcSource {
    fn processes(&mut self) -> Result<Vec<ProcessKey>, String> {
        let entries = fs::read_dir(&self.root)
            .map_err(|e| format!("Failed to read {}: {}", self.root.display(), e))?;

        let mut seen = HashMap::new();
        for pid in entries.flatten().filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok()) {
            let Some(stat) = fs::read_to_string(self.process_dir(pid).join("stat")).ok().and_then(|stat| parse_stat(&stat)) else {
                continue;
            };
            if stat.kernel_thread || stat.exited {
                continue;
            }

            let key = ProcessKey { pid, started: stat.start_ticks, image: stat.image };
            let namespace = match self.seen.get(&pid) {
                Some(known) if known.key == key => known.namespace,
                _ => self.namespace_of(pid),
            };
            seen.insert(pid, Seen { key, namespace });
        }

        if seen.is_empty() {
            return Err(format!("No processes found in {}", self.root.display()));
        }

        let mut keys: Vec<ProcessKey> = seen.values().map(|process| process.key).collect();
        keys.sort_unstable_by_key(|key| key.pid);
        self.seen = seen;

        Ok(keys)
    }

    fn describe(&mut self, process: &ProcessKey) -> Option<ProcessDetails> {
        let dir = self.process_dir(process.pid);

        let stat = parse_stat(&fs::read_to_string(dir.join("stat")).ok()?)?;
        if stat.start_ticks != process.started {
            return None;
        }

        let uid = parse_uid(&fs::read_to_string(dir.join("status")).ok()?)?;
        let command_line = parse_command_line(&fs::read(dir.join("cmdline")).ok()?);
        let executable_path = match fs::read_link(dir.join("exe")) {
            Ok(path) => path.to_string_lossy().to_string(),
            Err(_) => String::new(),
        };

        Some(ProcessDetails {
            ppid: stat.ppid,
            uid,
            executable_path,
            command_line,
            started_at: self.boot_time + process.started / CLOCK_TICKS_PER_SECOND,
        })
    }

    fn outbound_sockets(&mut self) -> Result<Vec<Socket>, String> {
        let mut members: HashMap<Option<u64>, Vec<u32>> = HashMap::new();
        for (pid, process) in &self.seen {
            members.entry(process.namespace).or_default().push(*pid);
        }

        let mut sockets: HashMap<u64, Socket> = HashMap::new();
        let mut socket_namespaces: HashMap<u64, Option<u64>> = HashMap::new();
        let mut readable = false;

        for (namespace, mut pids) in members {
            pids.sort_unstable();
            let Some(rows) = pids.iter().find_map(|pid| self.tcp_rows(*pid)) else {
                continue;
            };
            readable = true;

            for socket in outbound(rows) {
                let known_namespace = socket_namespaces.get(&socket.inode).copied().flatten();
                socket_namespaces.insert(socket.inode, known_namespace.or(namespace));
                sockets.insert(socket.inode, socket);
            }
        }

        if !readable {
            return Err("No TCP socket table could be read".to_string());
        }

        self.socket_namespaces = socket_namespaces;

        let mut sockets: Vec<Socket> = sockets.into_values().collect();
        sockets.sort_unstable_by_key(|socket| socket.inode);
        Ok(sockets)
    }

    fn socket_holders(&mut self, sockets: &[Socket]) -> HashMap<u64, Vec<u32>> {
        let wanted: HashSet<u64> = sockets.iter().map(|socket| socket.inode).collect();
        let namespaces: HashSet<Option<u64>> = sockets
            .iter()
            .filter_map(|socket| self.socket_namespaces.get(&socket.inode).copied())
            .collect();

        let mut holders: HashMap<u64, Vec<u32>> = HashMap::new();
        for (pid, process) in &self.seen {
            if !namespaces.contains(&process.namespace) {
                continue;
            }
            let Ok(descriptors) = fs::read_dir(self.process_dir(*pid).join("fd")) else {
                continue;
            };

            let held: HashSet<u64> = descriptors
                .flatten()
                .filter_map(|descriptor| fs::read_link(descriptor.path()).ok())
                .filter_map(|link| parse_socket_link(&link.to_string_lossy()))
                .filter(|inode| wanted.contains(inode))
                .collect();

            for inode in held {
                holders.entry(inode).or_default().push(*pid);
            }
        }

        holders
    }

    fn persistence(&mut self) -> Result<Vec<PersistenceItem>, String> {
        persistence::scan(&self.root.join(INIT_ROOT))
    }

    fn packages(&mut self) -> Result<Vec<PackageItem>, String> {
        packages::scan(&self.root.join(INIT_ROOT))
    }
}
