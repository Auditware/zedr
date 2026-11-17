use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use zedr_shared::sensor::{PackageItem, PersistenceItem, ProcessDetails, ProcessKey, Socket, Source};

use crate::kernel::{self, SOCKET_FDINFO_BYTES};
use crate::{packages, persistence};

const MAX_COMMAND_LINE_BYTES: usize = 4096;
const KERNEL_TASK: u32 = 0;
const MICROS_PER_SECOND: u64 = 1_000_000;

// Offsets into struct socket_fdinfo of <sys/proc_info.h>, measured with the SDK on arm64 and x86_64 alike:
// psi (socket_info) starts at 24, its soi_proto union at 264, which for TCP holds tcp_sockinfo and its in_sockinfo first
const SOI_SO: usize = 160;
const SOI_FAMILY: usize = 184;
const SOI_KIND: usize = 256;
const INSI_FPORT: usize = 264;
const INSI_LPORT: usize = 268;
const INSI_VFLAG: usize = 288;
const INSI_FADDR: usize = 296;
const INSI_LADDR: usize = 312;
const TCPSI_STATE: usize = 344;
/// in4in6_addr keeps an IPv4 address after 12 bytes of padding
const IPV4_IN_IN4IN6: usize = 12;

const SOCKINFO_TCP: i32 = 2;
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;

const TSI_S_CLOSED: i32 = 0;
const TSI_S_LISTEN: i32 = 1;
const TSI_S_SYN_RECEIVED: i32 = 3;
const TSI_S_TIME_WAIT: i32 = 10;

pub fn start_micros(info: &libc::proc_bsdinfo) -> u64 {
    info.pbi_start_tvsec.saturating_mul(MICROS_PER_SECOND).saturating_add(info.pbi_start_tvusec)
}

pub fn image_of(executable_path: &str) -> u64 {
    let mut image = DefaultHasher::new();
    executable_path.hash(&mut image);
    image.finish()
}

/// The arguments in a `KERN_PROCARGS2` area: the argument count, the executable path, padding, then that many arguments and the environment
pub fn parse_arguments(raw: &[u8]) -> Vec<String> {
    let Some((count, rest)) = raw.split_first_chunk::<4>() else {
        return Vec::new();
    };
    let count = usize::try_from(i32::from_ne_bytes(*count)).unwrap_or(0);

    let after_path = rest.iter().position(|byte| *byte == 0).map_or(rest.len(), |end| end + 1);
    let rest = &rest[after_path..];
    let start = rest.iter().position(|byte| *byte != 0).unwrap_or(rest.len());
    let arguments = &rest[start..];

    let mut end = 0;
    for _ in 0..count {
        match arguments[end..].iter().position(|byte| *byte == 0) {
            Some(length) => end += length + 1,
            None => {
                end = arguments.len();
                break;
            }
        }
    }

    let arguments = &arguments[..end.min(MAX_COMMAND_LINE_BYTES)];
    arguments.split(|byte| *byte == 0).filter(|argument| !argument.is_empty()).map(|argument| String::from_utf8_lossy(argument).into_owned()).collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRow {
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: i32,
    pub inode: u64,
}

fn read_i32(info: &[u8; SOCKET_FDINFO_BYTES], offset: usize) -> i32 {
    i32::from_ne_bytes([info[offset], info[offset + 1], info[offset + 2], info[offset + 3]])
}

fn read_address(info: &[u8; SOCKET_FDINFO_BYTES], offset: usize, version: u8) -> Option<IpAddr> {
    let bytes: [u8; 16] = info[offset..offset + 16].try_into().ok()?;
    if version & INI_IPV4 != 0 {
        let v4: [u8; 4] = bytes[IPV4_IN_IN4IN6..].try_into().ok()?;
        return Some(IpAddr::V4(Ipv4Addr::from(v4)));
    }
    if version & INI_IPV6 != 0 {
        let v6 = Ipv6Addr::from(bytes);
        return Some(match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        });
    }
    None
}

/// The kernel keeps a port in network order in the low 16 bits of an int
fn read_port(info: &[u8; SOCKET_FDINFO_BYTES], offset: usize) -> u16 {
    u16::from_be(read_i32(info, offset) as u16)
}

pub fn parse_socket(info: &[u8; SOCKET_FDINFO_BYTES]) -> Option<TcpRow> {
    if read_i32(info, SOI_KIND) != SOCKINFO_TCP || !matches!(read_i32(info, SOI_FAMILY), libc::AF_INET | libc::AF_INET6) {
        return None;
    }

    let version = info[INSI_VFLAG];
    let so: [u8; 8] = info[SOI_SO..SOI_SO + 8].try_into().ok()?;

    Some(TcpRow {
        local: SocketAddr::new(read_address(info, INSI_LADDR, version)?, read_port(info, INSI_LPORT)),
        remote: SocketAddr::new(read_address(info, INSI_FADDR, version)?, read_port(info, INSI_FPORT)),
        state: read_i32(info, TCPSI_STATE),
        inode: u64::from_ne_bytes(so),
    })
}

pub fn outbound(rows: Vec<TcpRow>) -> Vec<Socket> {
    let listening: HashSet<u16> = rows.iter().filter(|row| row.state == TSI_S_LISTEN).map(|row| row.local.port()).collect();

    rows.into_iter()
        .filter(|row| !matches!(row.state, TSI_S_CLOSED | TSI_S_LISTEN | TSI_S_SYN_RECEIVED | TSI_S_TIME_WAIT))
        .filter(|row| row.inode != 0 && !listening.contains(&row.local.port()))
        .map(|row| Socket { inode: row.inode, local: row.local, remote: row.remote })
        .collect()
}

pub struct MacSource {
    root: PathBuf,
    arguments: Vec<u8>,
    pids: Vec<u32>,
    holders: HashMap<u64, Vec<u32>>,
}

impl MacSource {
    /// Reads processes and sockets from the running kernel, and persistence and packages from the file system under `root`
    pub fn new(root: &Path) -> Result<Self, String> {
        let argument_max = kernel::argument_max().ok_or_else(|| "Failed to read the size of the argument area".to_string())?;
        Ok(Self { root: root.to_path_buf(), arguments: vec![0; argument_max], pids: Vec::new(), holders: HashMap::new() })
    }
}

impl Source for MacSource {
    fn processes(&mut self) -> Result<Vec<ProcessKey>, String> {
        let pids = kernel::all_pids().map_err(|e| format!("Failed to list processes: {}", e))?;

        let mut keys: Vec<ProcessKey> = pids
            .into_iter()
            .filter(|pid| *pid != KERNEL_TASK)
            .filter_map(|pid| {
                let info = kernel::bsd_info(pid).filter(|info| info.pbi_status != libc::SZOMB)?;
                let image = image_of(&kernel::executable_path(pid).unwrap_or_default());
                Some(ProcessKey { pid, started: start_micros(&info), image })
            })
            .collect();

        if keys.is_empty() {
            return Err("No process could be read".to_string());
        }

        keys.sort_unstable_by_key(|key| key.pid);
        self.pids = keys.iter().map(|key| key.pid).collect();
        Ok(keys)
    }

    fn describe(&mut self, process: &ProcessKey) -> Option<ProcessDetails> {
        let info = kernel::bsd_info(process.pid)?;
        if start_micros(&info) != process.started {
            return None;
        }

        let executable_path = kernel::executable_path(process.pid).unwrap_or_default();
        let command_line = kernel::process_arguments(process.pid, &mut self.arguments).map(parse_arguments).unwrap_or_default();

        Some(ProcessDetails { ppid: info.pbi_ppid, uid: info.pbi_ruid, executable_path, command_line, started_at: info.pbi_start_tvsec })
    }

    fn outbound_sockets(&mut self) -> Result<Vec<Socket>, String> {
        let mut rows: HashMap<u64, TcpRow> = HashMap::new();
        let mut holders: HashMap<u64, Vec<u32>> = HashMap::new();
        let mut readable = false;

        for &pid in &self.pids {
            let Some(descriptors) = kernel::descriptors(pid) else {
                continue;
            };
            readable = true;

            for descriptor in descriptors.iter().filter(|descriptor| descriptor.proc_fdtype == libc::PROX_FDTYPE_SOCKET as u32) {
                let Some(row) = kernel::socket_info(pid, descriptor.proc_fd).and_then(|info| parse_socket(&info.0)) else {
                    continue;
                };
                let held_by = holders.entry(row.inode).or_default();
                if !held_by.contains(&pid) {
                    held_by.push(pid);
                }
                rows.insert(row.inode, row);
            }
        }

        if !readable {
            return Err("No process's file descriptors could be read".to_string());
        }

        self.holders = holders;

        let mut sockets = outbound(rows.into_values().collect());
        sockets.sort_unstable_by_key(|socket| socket.inode);
        Ok(sockets)
    }

    fn socket_holders(&mut self, sockets: &[Socket]) -> HashMap<u64, Vec<u32>> {
        sockets.iter().filter_map(|socket| self.holders.get(&socket.inode).map(|pids| (socket.inode, pids.clone()))).collect()
    }

    fn persistence(&mut self) -> Result<Vec<PersistenceItem>, String> {
        persistence::scan(&self.root, kernel::user_name)
    }

    fn packages(&mut self) -> Result<Vec<PackageItem>, String> {
        packages::scan(&self.root, kernel::user_name)
    }
}
