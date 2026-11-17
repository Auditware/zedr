use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use zedr_shared::sensor::{PackageItem, PersistenceItem, ProcessDetails, ProcessKey, Socket, Source};
use zedr_shared::windows_text::{self, clip, TcpRow};

use crate::hashing::HashCache;
use crate::process::{self, Open};
use crate::{network, packages, persistence};

const MAX_COMMAND_LINE_BYTES: usize = 4096;
const SYSTEM_IDLE_PID: u32 = 0;

struct Seen {
    key: ProcessKey,
    ppid: u32,
    name: String,
    path: Option<String>,
}

pub struct WindowsSource {
    seen: HashMap<u32, Seen>,
    holders: HashMap<u64, u32>,
    hashes: HashCache,
}

impl WindowsSource {
    pub fn new() -> Self {
        Self { seen: HashMap::new(), holders: HashMap::new(), hashes: HashCache::default() }
    }
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0)
}

impl Source for WindowsSource {
    fn processes(&mut self) -> Result<Vec<ProcessKey>, String> {
        let mut seen = HashMap::new();

        for entry in process::snapshot()? {
            if entry.pid == SYSTEM_IDLE_PID {
                continue;
            }

            // A process that cannot be opened is still listed, from what the snapshot gives: no start time and the image name
            let opened = Open::pid(entry.pid);
            let path = opened.as_ref().and_then(Open::image_path);
            let started = opened.as_ref().and_then(Open::started).unwrap_or(0);
            let image = windows_text::stable_hash(&[path.as_deref().unwrap_or(&entry.name).as_bytes()]);

            let key = ProcessKey { pid: entry.pid, started, image };
            seen.insert(entry.pid, Seen { key, ppid: entry.ppid, name: entry.name, path });
        }

        if seen.is_empty() {
            return Err("No processes found".to_string());
        }

        let mut keys: Vec<ProcessKey> = seen.values().map(|process| process.key).collect();
        keys.sort_unstable_by_key(|key| key.pid);
        self.seen = seen;

        Ok(keys)
    }

    fn describe(&mut self, process: &ProcessKey) -> Option<ProcessDetails> {
        let seen = self.seen.get(&process.pid).filter(|seen| seen.key == *process)?;

        let opened = Open::pid(process.pid);
        if process.started != 0 && opened.as_ref().and_then(Open::started).is_some_and(|started| started != process.started) {
            return None;
        }

        let command_line =
            opened.as_ref().and_then(Open::command_line).map(|line| windows_text::split_command_line(clip(&line, MAX_COMMAND_LINE_BYTES))).unwrap_or_default();
        // The session stands in for the user id, which Windows does not have as a number: 0 is where services run, and a user's
        // programs run in the session of that user. A process whose session cannot be read is reported with 0
        let uid = process::session_of(process.pid).unwrap_or(0);
        let started_at = windows_text::filetime_to_unix(process.started).filter(|_| process.started != 0).unwrap_or_else(unix_now);

        Some(ProcessDetails { ppid: seen.ppid, uid, executable_path: seen.path.clone().unwrap_or_else(|| seen.name.clone()), command_line, started_at })
    }

    fn outbound_sockets(&mut self) -> Result<Vec<Socket>, String> {
        let rows: Vec<TcpRow> = network::outbound()?;

        let mut holders = HashMap::new();
        let mut sockets = Vec::new();
        for row in rows {
            let inode = windows_text::socket_identity(&row);
            if holders.insert(inode, row.pid).is_none() {
                sockets.push(Socket { inode, local: row.local, remote: row.remote });
            }
        }

        sockets.sort_unstable_by_key(|socket| socket.inode);
        self.holders = holders;
        Ok(sockets)
    }

    fn socket_holders(&mut self, sockets: &[Socket]) -> HashMap<u64, Vec<u32>> {
        sockets.iter().filter_map(|socket| self.holders.get(&socket.inode).map(|pid| (socket.inode, vec![*pid]))).collect()
    }

    fn persistence(&mut self) -> Result<Vec<PersistenceItem>, String> {
        persistence::scan(&mut self.hashes)
    }

    fn packages(&mut self) -> Result<Vec<PackageItem>, String> {
        packages::scan()
    }
}
