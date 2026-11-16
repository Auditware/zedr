use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};

use zedr_protocol::{
    InventoryAction, NetworkAction, NetworkEvent, PackageEvent, PackageManager, PersistenceEvent, PersistenceKind,
    ProcessAction, ProcessEvent, SystemEvent,
};

const REPEAT_CONNECTION_AFTER_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub started: u64,
    pub image: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDetails {
    pub ppid: u32,
    pub uid: u32,
    pub executable_path: String,
    pub command_line: Vec<String>,
    pub started_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Socket {
    pub inode: u64,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistenceItem {
    pub kind: PersistenceKind,
    pub name: String,
    pub path: String,
    pub command: String,
    pub user: String,
    pub enabled: bool,
    pub hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageItem {
    pub manager: PackageManager,
    pub name: String,
    pub version: String,
    pub architecture: String,
}

type PersistenceKey = (PersistenceKind, String, String);
type PackageKey = (PackageManager, String, String);

pub trait Source: Send + 'static {
    fn processes(&mut self) -> Result<Vec<ProcessKey>, String>;
    fn describe(&mut self, process: &ProcessKey) -> Option<ProcessDetails>;
    fn outbound_sockets(&mut self) -> Result<Vec<Socket>, String>;
    fn socket_holders(&mut self, sockets: &[Socket]) -> HashMap<u64, Vec<u32>>;
    fn persistence(&mut self) -> Result<Vec<PersistenceItem>, String>;
    fn packages(&mut self) -> Result<Vec<PackageItem>, String>;
}

struct Change<K, V> {
    action: InventoryAction,
    key: K,
    item: V,
    previous: Option<V>,
}

struct Inventory<K, V> {
    interval: u64,
    checked_at: Option<u64>,
    known: Option<BTreeMap<K, V>>,
    error: Option<String>,
}

impl<K: Ord + Clone, V: PartialEq + Clone> Inventory<K, V> {
    fn new(interval: u64) -> Self {
        Self { interval, checked_at: None, known: None, error: None }
    }

    fn is_due(&self, now: u64) -> bool {
        match self.checked_at {
            Some(checked_at) => now < checked_at || now - checked_at >= self.interval,
            None => true,
        }
    }

    fn tracked(&self) -> usize {
        self.known.as_ref().map_or(0, BTreeMap::len)
    }

    fn read(&mut self, now: u64, current: Result<Vec<(K, V)>, String>) -> Vec<Change<K, V>> {
        self.checked_at = Some(now);
        let current = match current {
            Ok(current) => current,
            Err(e) => {
                self.error = Some(e);
                return Vec::new();
            }
        };
        self.error = None;

        let mut found = BTreeMap::new();
        for (key, item) in current {
            found.entry(key).or_insert(item);
        }

        let change = |action, key: &K, item: &V, previous: Option<&V>| Change {
            action,
            key: key.clone(),
            item: item.clone(),
            previous: previous.cloned(),
        };
        let changes = match &self.known {
            None => found.iter().map(|(key, item)| change(InventoryAction::Present, key, item, None)).collect(),
            Some(known) => {
                let mut changes: Vec<Change<K, V>> = known
                    .iter()
                    .filter(|(key, _)| !found.contains_key(*key))
                    .map(|(key, item)| change(InventoryAction::Removed, key, item, None))
                    .collect();
                for (key, item) in &found {
                    match known.get(key) {
                        None => changes.push(change(InventoryAction::Added, key, item, None)),
                        Some(previous) if previous != item => changes.push(change(InventoryAction::Changed, key, item, Some(previous))),
                        Some(_) => {}
                    }
                }
                changes
            }
        };

        self.known = Some(found);
        changes
    }
}

#[derive(Default)]
pub struct Observation {
    pub events: Vec<SystemEvent>,
    pub errors: Vec<String>,
}

struct Tracked {
    key: ProcessKey,
    details: ProcessDetails,
}

pub struct Sensor<S: Source> {
    source: S,
    own_pid: u32,
    processes: HashMap<u32, Tracked>,
    open_sockets: HashSet<Socket>,
    reported_connections: HashMap<(u32, IpAddr, u16), u64>,
    persistence: Inventory<PersistenceKey, PersistenceItem>,
    packages: Inventory<PackageKey, String>,
}

impl<S: Source> Sensor<S> {
    pub fn new(source: S, own_pid: u32, persistence_interval: u64, package_interval: u64) -> Self {
        Self {
            source,
            own_pid,
            processes: HashMap::new(),
            open_sockets: HashSet::new(),
            reported_connections: HashMap::new(),
            persistence: Inventory::new(persistence_interval),
            packages: Inventory::new(package_interval),
        }
    }

    pub fn tracked_processes(&self) -> usize {
        self.processes.len()
    }

    pub fn tracked_persistence(&self) -> usize {
        self.persistence.tracked()
    }

    pub fn tracked_packages(&self) -> usize {
        self.packages.tracked()
    }

    pub fn poll(&mut self, now: u64) -> Observation {
        let mut observation = Observation::default();

        match self.source.processes() {
            Ok(current) => self.observe_processes(current, now, &mut observation.events),
            Err(e) => observation.errors.push(format!("Process list unavailable: {}", e)),
        }

        match self.source.outbound_sockets() {
            Ok(current) => self.observe_sockets(current, now, &mut observation.events),
            Err(e) => observation.errors.push(format!("Socket list unavailable: {}", e)),
        }

        if self.persistence.is_due(now) {
            let current = self.source.persistence().map(|items| {
                items.into_iter().map(|item| ((item.kind, item.path.clone(), item.name.clone()), item)).collect()
            });
            let changes = self.persistence.read(now, current);
            observation.events.extend(changes.iter().map(|change| persistence_event(&change.item, change.action, now)));
        }
        observation.errors.extend(self.persistence.error.iter().map(|e| format!("Persistence inventory unavailable: {}", e)));

        if self.packages.is_due(now) {
            let current = self.source.packages().map(|packages| {
                packages
                    .into_iter()
                    .map(|package| ((package.manager, package.name, package.architecture), package.version))
                    .collect()
            });
            let changes = self.packages.read(now, current);
            observation.events.extend(changes.into_iter().map(|change| package_event(change, now)));
        }
        observation.errors.extend(self.packages.error.iter().map(|e| format!("Package inventory unavailable: {}", e)));

        observation
    }

    fn observe_processes(&mut self, current: Vec<ProcessKey>, now: u64, events: &mut Vec<SystemEvent>) {
        let alive: HashSet<u32> = current.iter().map(|key| key.pid).collect();

        let mut gone: Vec<u32> = self.processes.keys().filter(|pid| !alive.contains(pid)).copied().collect();
        gone.sort_unstable();
        for pid in gone {
            if let Some(tracked) = self.processes.remove(&pid) {
                events.push(process_event(pid, &tracked.details, ProcessAction::Terminate, now));
            }
        }

        let mut appeared = Vec::new();
        for key in current {
            let action = match self.processes.get(&key.pid) {
                Some(tracked) if tracked.key == key => continue,
                Some(tracked) if tracked.key.started == key.started => ProcessAction::Modify,
                _ => ProcessAction::Create,
            };

            let Some(details) = self.source.describe(&key) else {
                continue;
            };

            let replaced = self.processes.remove(&key.pid);
            if let (ProcessAction::Create, Some(replaced)) = (&action, replaced) {
                events.push(process_event(key.pid, &replaced.details, ProcessAction::Terminate, now));
            }

            let timestamp = match action {
                ProcessAction::Create => details.started_at,
                _ => now,
            };
            appeared.push((timestamp, process_event(key.pid, &details, action, timestamp)));
            self.processes.insert(key.pid, Tracked { key, details });
        }

        appeared.sort_by_key(|(timestamp, _)| *timestamp);
        events.extend(appeared.into_iter().map(|(_, event)| event));
    }

    fn observe_sockets(&mut self, current: Vec<Socket>, now: u64, events: &mut Vec<SystemEvent>) {
        let current: Vec<Socket> = current
            .into_iter()
            .filter(|socket| !socket.remote.ip().is_loopback() && !socket.remote.ip().is_unspecified())
            .collect();

        let unseen: Vec<Socket> = current
            .iter()
            .filter(|socket| !self.open_sockets.contains(*socket))
            .cloned()
            .collect();

        let holders = if unseen.is_empty() {
            HashMap::new()
        } else {
            self.source.socket_holders(&unseen)
        };

        let mut still_unattributed = HashSet::new();
        for socket in &unseen {
            let Some((pid, executable_path)) = self.first_holder(holders.get(&socket.inode)) else {
                still_unattributed.insert(socket.clone());
                continue;
            };

            if pid == self.own_pid {
                continue;
            }

            let destination = (pid, socket.remote.ip(), socket.remote.port());
            let reported_recently = self
                .reported_connections
                .get(&destination)
                .is_some_and(|reported_at| now.saturating_sub(*reported_at) < REPEAT_CONNECTION_AFTER_SECS);
            if reported_recently {
                continue;
            }

            self.reported_connections.insert(destination, now);
            events.push(SystemEvent::Network(NetworkEvent {
                timestamp: now,
                pid,
                process_path: executable_path,
                protocol: "tcp".to_string(),
                source_ip: socket.local.ip().to_string(),
                source_port: socket.local.port(),
                dest_ip: socket.remote.ip().to_string(),
                dest_port: socket.remote.port(),
                action: NetworkAction::Connect,
                bytes_sent: 0,
                bytes_received: 0,
            }));
        }

        self.open_sockets = current.into_iter().filter(|socket| !still_unattributed.contains(socket)).collect();
        self.reported_connections
            .retain(|_, reported_at| now.saturating_sub(*reported_at) < REPEAT_CONNECTION_AFTER_SECS);
    }

    fn first_holder(&self, holders: Option<&Vec<u32>>) -> Option<(u32, String)> {
        holders?
            .iter()
            .filter_map(|pid| self.processes.get(pid).map(|tracked| (tracked.details.started_at, *pid, tracked)))
            .min_by_key(|(started_at, pid, _)| (*started_at, *pid))
            .map(|(_, pid, tracked)| (pid, tracked.details.executable_path.clone()))
    }
}

fn process_event(pid: u32, details: &ProcessDetails, action: ProcessAction, timestamp: u64) -> SystemEvent {
    SystemEvent::Process(ProcessEvent {
        timestamp,
        pid,
        ppid: details.ppid,
        executable_path: details.executable_path.clone(),
        command_line: details.command_line.clone(),
        action,
        uid: details.uid,
        hash: None,
    })
}

fn persistence_event(item: &PersistenceItem, action: InventoryAction, timestamp: u64) -> SystemEvent {
    SystemEvent::Persistence(PersistenceEvent {
        timestamp,
        action,
        kind: item.kind,
        name: item.name.clone(),
        path: item.path.clone(),
        command: item.command.clone(),
        user: item.user.clone(),
        enabled: item.enabled,
        hash: item.hash.clone(),
    })
}

fn package_event(change: Change<PackageKey, String>, timestamp: u64) -> SystemEvent {
    let (manager, name, architecture) = change.key;
    SystemEvent::Package(PackageEvent {
        timestamp,
        action: change.action,
        manager,
        name,
        version: change.item,
        architecture,
        previous_version: change.previous,
    })
}

const SEPARATOR_BYTES: usize = 1;

struct Queued {
    event: SystemEvent,
    encoded_bytes: usize,
}

pub struct Outbox {
    events: VecDeque<Queued>,
    limit: usize,
    batch_bytes: usize,
    dropped: u64,
    unsendable: u64,
}

impl Outbox {
    pub fn new(limit: usize, batch_bytes: usize) -> Self {
        Self { events: VecDeque::new(), limit, batch_bytes, dropped: 0, unsendable: 0 }
    }

    pub fn push(&mut self, events: Vec<SystemEvent>) {
        for event in events {
            match serde_json::to_vec(&event) {
                Ok(encoded) if encoded.len() + SEPARATOR_BYTES <= self.batch_bytes => {
                    self.events.push_back(Queued { event, encoded_bytes: encoded.len() });
                }
                _ => self.unsendable += 1,
            }
        }

        while self.events.len() > self.limit {
            self.events.pop_front();
            self.dropped += 1;
        }
    }

    pub fn next_batch(&self, size: usize) -> Vec<SystemEvent> {
        let mut batch = Vec::new();
        let mut room = self.batch_bytes;

        for queued in self.events.iter().take(size) {
            match room.checked_sub(queued.encoded_bytes + SEPARATOR_BYTES) {
                Some(left) => room = left,
                None => break,
            }
            batch.push(queued.event.clone());
        }

        batch
    }

    pub fn confirm(&mut self, sent: usize) {
        self.events.drain(..sent.min(self.events.len()));
    }

    pub fn take_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.dropped)
    }

    pub fn take_unsendable(&mut self) -> u64 {
        std::mem::take(&mut self.unsendable)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct World {
        processes: Vec<(ProcessKey, ProcessDetails)>,
        sockets: Vec<Socket>,
        holders: HashMap<u64, Vec<u32>>,
        holder_lookups: usize,
        fail_processes: bool,
        persistence: Vec<PersistenceItem>,
        persistence_scans: usize,
        fail_persistence: bool,
        packages: Vec<PackageItem>,
        package_scans: usize,
        fail_packages: bool,
    }

    #[derive(Clone, Default)]
    struct FakeSource(Arc<Mutex<World>>);

    impl FakeSource {
        fn start(&self, pid: u32, ppid: u32, started_at: u64, path: &str) {
            self.0.lock().unwrap().processes.push((
                ProcessKey { pid, started: started_at, image: 1 },
                ProcessDetails {
                    ppid,
                    uid: 1000,
                    executable_path: path.to_string(),
                    command_line: vec![path.to_string(), "--flag".to_string()],
                    started_at,
                },
            ));
        }

        fn exit(&self, pid: u32) {
            self.0.lock().unwrap().processes.retain(|(key, _)| key.pid != pid);
        }

        fn exec(&self, pid: u32, path: &str) {
            let mut world = self.0.lock().unwrap();
            let (key, details) = world.processes.iter_mut().find(|(key, _)| key.pid == pid).unwrap();
            key.image += 1;
            details.executable_path = path.to_string();
            details.command_line = vec![path.to_string()];
        }

        fn connect(&self, inode: u64, holders: &[u32], remote: &str) {
            let mut world = self.0.lock().unwrap();
            world.sockets.push(Socket {
                inode,
                local: format!("10.0.0.5:{}", 40000 + inode).parse().unwrap(),
                remote: remote.parse().unwrap(),
            });
            world.holders.insert(inode, holders.to_vec());
        }

        fn close(&self, inode: u64) {
            self.0.lock().unwrap().sockets.retain(|socket| socket.inode != inode);
        }

        fn install(&self, item: PersistenceItem) {
            self.0.lock().unwrap().persistence.push(item);
        }

        fn rewrite(&self, path: &str, change: impl Fn(&mut PersistenceItem)) {
            let mut world = self.0.lock().unwrap();
            change(world.persistence.iter_mut().find(|item| item.path == path).unwrap());
        }

        fn uninstall(&self, name: &str) {
            self.0.lock().unwrap().persistence.retain(|item| item.name != name);
        }

        fn persistence_scans(&self) -> usize {
            self.0.lock().unwrap().persistence_scans
        }

        fn install_package(&self, name: &str, version: &str, architecture: &str) {
            let mut world = self.0.lock().unwrap();
            world.packages.retain(|package| package.name != name || package.architecture != architecture);
            world.packages.push(PackageItem {
                manager: PackageManager::Dpkg,
                name: name.to_string(),
                version: version.to_string(),
                architecture: architecture.to_string(),
            });
        }

        fn remove_package(&self, name: &str) {
            self.0.lock().unwrap().packages.retain(|package| package.name != name);
        }
    }

    impl Source for FakeSource {
        fn processes(&mut self) -> Result<Vec<ProcessKey>, String> {
            let world = self.0.lock().unwrap();
            if world.fail_processes {
                return Err("no /proc".to_string());
            }
            Ok(world.processes.iter().map(|(key, _)| *key).collect())
        }

        fn describe(&mut self, process: &ProcessKey) -> Option<ProcessDetails> {
            let world = self.0.lock().unwrap();
            world.processes.iter().find(|(key, _)| key == process).map(|(_, details)| details.clone())
        }

        fn outbound_sockets(&mut self) -> Result<Vec<Socket>, String> {
            Ok(self.0.lock().unwrap().sockets.clone())
        }

        fn socket_holders(&mut self, sockets: &[Socket]) -> HashMap<u64, Vec<u32>> {
            let mut world = self.0.lock().unwrap();
            world.holder_lookups += 1;
            sockets
                .iter()
                .filter_map(|socket| world.holders.get(&socket.inode).map(|pids| (socket.inode, pids.clone())))
                .collect()
        }

        fn persistence(&mut self) -> Result<Vec<PersistenceItem>, String> {
            let mut world = self.0.lock().unwrap();
            world.persistence_scans += 1;
            if world.fail_persistence {
                return Err("no /etc".to_string());
            }
            Ok(world.persistence.clone())
        }

        fn packages(&mut self) -> Result<Vec<PackageItem>, String> {
            let mut world = self.0.lock().unwrap();
            world.package_scans += 1;
            if world.fail_packages {
                return Err("database is locked".to_string());
            }
            Ok(world.packages.clone())
        }
    }

    const AGENT_PID: u32 = 900;
    const PERSISTENCE_INTERVAL: u64 = 60;
    const PACKAGE_INTERVAL: u64 = 300;

    fn sensor(source: &FakeSource) -> Sensor<FakeSource> {
        Sensor::new(source.clone(), AGENT_PID, PERSISTENCE_INTERVAL, PACKAGE_INTERVAL)
    }

    fn processes(observation: &Observation) -> Vec<(String, u32, u32, String, u64)> {
        observation
            .events
            .iter()
            .filter_map(|event| match event {
                SystemEvent::Process(process) => Some((
                    format!("{:?}", process.action),
                    process.pid,
                    process.ppid,
                    process.executable_path.clone(),
                    process.timestamp,
                )),
                _ => None,
            })
            .collect()
    }

    fn connections(observation: &Observation) -> Vec<(u32, String, String, u16)> {
        observation
            .events
            .iter()
            .filter_map(|event| match event {
                SystemEvent::Network(network) => {
                    Some((network.pid, network.process_path.clone(), network.dest_ip.clone(), network.dest_port))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_first_poll_reports_every_running_process_with_its_start_time_and_parent() {
        let source = FakeSource::default();
        source.start(300, 1, 1_050, "/usr/bin/bash");
        source.start(1, 0, 1_000, "/sbin/init");
        source.start(310, 300, 1_060, "/usr/bin/curl");

        let observation = sensor(&source).poll(2_000);

        assert_eq!(
            processes(&observation),
            vec![
                ("Create".to_string(), 1, 0, "/sbin/init".to_string(), 1_000),
                ("Create".to_string(), 300, 1, "/usr/bin/bash".to_string(), 1_050),
                ("Create".to_string(), 310, 300, "/usr/bin/curl".to_string(), 1_060),
            ],
            "parents come before children and the timestamp is the start time, not the poll time"
        );
        assert!(observation.errors.is_empty());
    }

    #[test]
    fn test_nothing_is_reported_while_nothing_changes() {
        let source = FakeSource::default();
        source.start(1, 0, 1_000, "/sbin/init");
        let mut sensor = sensor(&source);

        sensor.poll(2_000);
        assert!(sensor.poll(2_005).events.is_empty());
        assert_eq!(sensor.tracked_processes(), 1);
    }

    #[test]
    fn test_new_and_ended_processes_are_reported_once() {
        let source = FakeSource::default();
        source.start(1, 0, 1_000, "/sbin/init");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.start(400, 1, 2_003, "/usr/bin/sleep");
        assert_eq!(processes(&sensor.poll(2_005)), vec![("Create".to_string(), 400, 1, "/usr/bin/sleep".to_string(), 2_003)]);

        source.exit(400);
        let ended = sensor.poll(2_010);
        assert_eq!(processes(&ended), vec![("Terminate".to_string(), 400, 1, "/usr/bin/sleep".to_string(), 2_010)]);
        match &ended.events[0] {
            SystemEvent::Process(process) => {
                assert_eq!(process.command_line, vec!["/usr/bin/sleep", "--flag"]);
                assert_eq!(process.uid, 1000);
            }
            other => panic!("unexpected event {:?}", other),
        }

        assert!(sensor.poll(2_015).events.is_empty());
    }

    #[test]
    fn test_exec_in_a_running_process_is_reported_as_a_change() {
        let source = FakeSource::default();
        source.start(500, 1, 1_500, "/usr/bin/bash");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.exec(500, "/usr/bin/nc");

        assert_eq!(processes(&sensor.poll(2_005)), vec![("Modify".to_string(), 500, 1, "/usr/bin/nc".to_string(), 2_005)]);
        assert!(sensor.poll(2_010).events.is_empty());
    }

    #[test]
    fn test_reused_pid_ends_the_old_process_before_the_new_one_starts() {
        let source = FakeSource::default();
        source.start(600, 1, 1_500, "/usr/bin/old");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.exit(600);
        source.start(600, 1, 2_004, "/usr/bin/new");

        assert_eq!(
            processes(&sensor.poll(2_005)),
            vec![
                ("Terminate".to_string(), 600, 1, "/usr/bin/old".to_string(), 2_005),
                ("Create".to_string(), 600, 1, "/usr/bin/new".to_string(), 2_004),
            ]
        );
    }

    #[test]
    fn test_outbound_connection_names_the_process_that_made_it() {
        let source = FakeSource::default();
        source.start(700, 1, 1_500, "/usr/bin/bash");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.connect(11, &[700], "203.0.113.7:4444");
        let observation = sensor.poll(2_005);

        assert_eq!(connections(&observation), vec![(700, "/usr/bin/bash".to_string(), "203.0.113.7".to_string(), 4444)]);
        match &observation.events[0] {
            SystemEvent::Network(network) => {
                assert_eq!(network.protocol, "tcp");
                assert_eq!(network.source_ip, "10.0.0.5");
                assert_eq!(network.source_port, 40011);
                assert_eq!(network.timestamp, 2_005);
                assert!(matches!(network.action, NetworkAction::Connect));
            }
            other => panic!("unexpected event {:?}", other),
        }

        assert!(connections(&sensor.poll(2_010)).is_empty(), "an open connection is reported once");
    }

    #[test]
    fn test_socket_inherited_by_children_is_attributed_to_the_oldest_holder() {
        let source = FakeSource::default();
        source.start(710, 1, 1_500, "/usr/bin/bash");
        source.start(711, 710, 1_900, "/usr/bin/id");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.connect(12, &[711, 710], "203.0.113.7:4444");

        assert_eq!(connections(&sensor.poll(2_005))[0].0, 710);
    }

    #[test]
    fn test_loopback_and_the_agents_own_connections_are_not_reported() {
        let source = FakeSource::default();
        source.start(AGENT_PID, 1, 1_500, "/usr/local/bin/zedr-agent");
        source.start(720, 1, 1_500, "/usr/bin/psql");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.connect(13, &[720], "127.0.0.1:5432");
        source.connect(14, &[720], "[::1]:5432");
        source.connect(15, &[AGENT_PID], "198.51.100.1:443");

        assert!(connections(&sensor.poll(2_005)).is_empty());
        assert!(connections(&sensor.poll(2_010)).is_empty());
    }

    #[test]
    fn test_repeated_connections_to_one_destination_are_reported_once_per_window() {
        let source = FakeSource::default();
        source.start(730, 1, 1_500, "/usr/bin/curl");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.connect(20, &[730], "203.0.113.9:443");
        assert_eq!(connections(&sensor.poll(2_005)).len(), 1);

        source.close(20);
        source.connect(21, &[730], "203.0.113.9:443");
        assert!(connections(&sensor.poll(2_010)).is_empty(), "same process, same destination, inside the window");

        source.connect(22, &[730], "203.0.113.9:8443");
        assert_eq!(connections(&sensor.poll(2_015)).len(), 1, "another port is another destination");

        source.close(21);
        source.connect(23, &[730], "203.0.113.9:443");
        assert_eq!(connections(&sensor.poll(2_005 + REPEAT_CONNECTION_AFTER_SECS)).len(), 1, "reported again after the window");
    }

    #[test]
    fn test_socket_without_a_known_holder_is_looked_up_again_and_holders_are_not_searched_when_idle() {
        let source = FakeSource::default();
        source.start(740, 1, 1_500, "/usr/bin/ssh");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);
        assert_eq!(source.0.lock().unwrap().holder_lookups, 0);

        source.connect(30, &[], "203.0.113.20:22");
        assert!(connections(&sensor.poll(2_005)).is_empty());

        source.0.lock().unwrap().holders.insert(30, vec![740]);
        assert_eq!(connections(&sensor.poll(2_010)), vec![(740, "/usr/bin/ssh".to_string(), "203.0.113.20".to_string(), 22)]);

        let lookups = source.0.lock().unwrap().holder_lookups;
        sensor.poll(2_015);
        sensor.poll(2_020);
        assert_eq!(source.0.lock().unwrap().holder_lookups, lookups, "no new socket, no search through file descriptors");
    }

    #[test]
    fn test_failing_source_is_an_error_and_keeps_what_is_known() {
        let source = FakeSource::default();
        source.start(1, 0, 1_000, "/sbin/init");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.0.lock().unwrap().fail_processes = true;
        let observation = sensor.poll(2_005);

        assert!(observation.events.is_empty(), "a failed read must not look like every process ending");
        assert_eq!(observation.errors.len(), 1);
        assert_eq!(sensor.tracked_processes(), 1);
    }

    fn unit(name: &str, command: &str, hash: &str) -> PersistenceItem {
        PersistenceItem {
            kind: PersistenceKind::SystemdUnit,
            name: name.to_string(),
            path: format!("/etc/systemd/system/{}", name),
            command: command.to_string(),
            user: "root".to_string(),
            enabled: true,
            hash: Some(hash.to_string()),
        }
    }

    fn cron(entry: &str, command: &str) -> PersistenceItem {
        PersistenceItem {
            kind: PersistenceKind::Cron,
            name: entry.to_string(),
            path: "/etc/crontab".to_string(),
            command: command.to_string(),
            user: "root".to_string(),
            enabled: true,
            hash: Some(format!("hash of {}", entry)),
        }
    }

    fn persistence(observation: &Observation) -> Vec<PersistenceEvent> {
        observation
            .events
            .iter()
            .filter_map(|event| match event {
                SystemEvent::Persistence(persistence) => Some(persistence.clone()),
                _ => None,
            })
            .collect()
    }

    fn changes(observation: &Observation) -> Vec<(InventoryAction, String)> {
        persistence(observation).into_iter().map(|event| (event.action, event.name)).collect()
    }

    #[test]
    fn test_first_inventory_reports_every_persistence_item_as_present() {
        let source = FakeSource::default();
        source.install(unit("zeta.service", "/usr/bin/zeta", "aa"));
        source.install(cron("@reboot root /opt/boot.sh", "/opt/boot.sh"));
        source.install(unit("alpha.service", "/usr/bin/alpha --serve", "bb"));

        let observation = sensor(&source).poll(2_000);

        assert_eq!(
            changes(&observation),
            vec![
                (InventoryAction::Present, "alpha.service".to_string()),
                (InventoryAction::Present, "zeta.service".to_string()),
                (InventoryAction::Present, "@reboot root /opt/boot.sh".to_string()),
            ],
            "ordered by kind, path and name whatever order the source listed them in"
        );
        assert_eq!(
            persistence(&observation)[0],
            PersistenceEvent {
                timestamp: 2_000,
                action: InventoryAction::Present,
                kind: PersistenceKind::SystemdUnit,
                name: "alpha.service".to_string(),
                path: "/etc/systemd/system/alpha.service".to_string(),
                command: "/usr/bin/alpha --serve".to_string(),
                user: "root".to_string(),
                enabled: true,
                hash: Some("bb".to_string()),
            }
        );
        assert!(observation.errors.is_empty());
    }

    #[test]
    fn test_persistence_is_read_once_per_interval_and_silent_while_unchanged() {
        let source = FakeSource::default();
        source.install(unit("alpha.service", "/usr/bin/alpha", "aa"));
        let mut sensor = sensor(&source);

        assert_eq!(persistence(&sensor.poll(2_000)).len(), 1);
        for elapsed in (5..PERSISTENCE_INTERVAL).step_by(5) {
            assert!(sensor.poll(2_000 + elapsed).events.is_empty());
        }
        assert_eq!(source.persistence_scans(), 1, "process polls in between do not read the inventory");

        assert!(sensor.poll(2_000 + PERSISTENCE_INTERVAL).events.is_empty());
        assert_eq!(source.persistence_scans(), 2);
        assert_eq!(sensor.tracked_persistence(), 1);
    }

    #[test]
    fn test_added_changed_and_removed_persistence_is_reported_once() {
        let source = FakeSource::default();
        source.install(unit("alpha.service", "/usr/bin/alpha", "aa"));
        source.install(unit("beta.service", "/usr/bin/beta", "bb"));
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.install(unit("implant.service", "/tmp/.x --daemon", "cc"));
        source.rewrite("/etc/systemd/system/alpha.service", |item| {
            item.command = "/tmp/.y".to_string();
            item.hash = Some("dd".to_string());
        });
        source.uninstall("beta.service");

        let observation = sensor.poll(2_060);
        let events = persistence(&observation);
        assert_eq!(
            changes(&observation),
            vec![
                (InventoryAction::Removed, "beta.service".to_string()),
                (InventoryAction::Changed, "alpha.service".to_string()),
                (InventoryAction::Added, "implant.service".to_string()),
            ]
        );
        assert_eq!(events[0].command, "/usr/bin/beta", "a removed item is described as it was last seen");
        assert_eq!(events[0].hash.as_deref(), Some("bb"));
        assert_eq!(events[1].command, "/tmp/.y");
        assert_eq!(events[1].hash.as_deref(), Some("dd"));
        assert_eq!(events[2].command, "/tmp/.x --daemon");
        assert!(events.iter().all(|event| event.timestamp == 2_060));

        assert!(sensor.poll(2_120).events.is_empty());
        assert_eq!(sensor.tracked_persistence(), 2);
    }

    #[test]
    fn test_change_of_state_without_a_change_of_content_is_reported() {
        let source = FakeSource::default();
        source.install(unit("alpha.service", "/usr/bin/alpha", "aa"));
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.rewrite("/etc/systemd/system/alpha.service", |item| item.enabled = false);
        let disabled = persistence(&sensor.poll(2_060));
        assert_eq!(disabled.len(), 1);
        assert_eq!(disabled[0].action, InventoryAction::Changed);
        assert!(!disabled[0].enabled);
        assert_eq!(disabled[0].hash.as_deref(), Some("aa"));

        source.rewrite("/etc/systemd/system/alpha.service", |item| item.user = "www-data".to_string());
        assert_eq!(changes(&sensor.poll(2_120)), vec![(InventoryAction::Changed, "alpha.service".to_string())]);
    }

    #[test]
    fn test_items_that_share_a_file_are_told_apart_by_name() {
        let source = FakeSource::default();
        source.install(cron("@reboot root /opt/boot.sh", "/opt/boot.sh"));
        source.install(cron("0 3 * * * root /opt/nightly.sh", "/opt/nightly.sh"));
        let mut sensor = sensor(&source);
        assert_eq!(persistence(&sensor.poll(2_000)).len(), 2);

        source.uninstall("@reboot root /opt/boot.sh");
        source.install(cron("@reboot root /tmp/.boot", "/tmp/.boot"));

        assert_eq!(
            changes(&sensor.poll(2_060)),
            vec![
                (InventoryAction::Removed, "@reboot root /opt/boot.sh".to_string()),
                (InventoryAction::Added, "@reboot root /tmp/.boot".to_string()),
            ],
            "an edited line is one entry gone and another one new, the untouched entry is not mentioned"
        );
    }

    #[test]
    fn test_failed_inventory_is_an_error_until_it_works_and_removes_nothing() {
        let source = FakeSource::default();
        source.install(unit("alpha.service", "/usr/bin/alpha", "aa"));
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.0.lock().unwrap().fail_persistence = true;
        let failed = sensor.poll(2_060);
        assert!(failed.events.is_empty(), "a failed read must not look like every item being removed");
        assert_eq!(failed.errors, vec!["Persistence inventory unavailable: no /etc".to_string()]);
        assert_eq!(sensor.poll(2_065).errors, failed.errors, "the error stands until the next inventory");
        assert_eq!(sensor.tracked_persistence(), 1);

        source.0.lock().unwrap().fail_persistence = false;
        source.install(unit("implant.service", "/tmp/.x", "cc"));
        let recovered = sensor.poll(2_120);
        assert!(recovered.errors.is_empty());
        assert_eq!(changes(&recovered), vec![(InventoryAction::Added, "implant.service".to_string())]);
    }

    #[test]
    fn test_inventory_that_fails_at_start_is_reported_in_full_once_it_works() {
        let source = FakeSource::default();
        source.install(unit("alpha.service", "/usr/bin/alpha", "aa"));
        source.0.lock().unwrap().fail_persistence = true;
        let mut sensor = sensor(&source);

        assert_eq!(sensor.poll(2_000).errors.len(), 1);
        assert_eq!(sensor.tracked_persistence(), 0);

        source.0.lock().unwrap().fail_persistence = false;
        assert_eq!(changes(&sensor.poll(2_060)), vec![(InventoryAction::Present, "alpha.service".to_string())]);
    }

    #[test]
    fn test_clock_set_back_does_not_stop_the_inventory() {
        let source = FakeSource::default();
        let mut sensor = sensor(&source);
        sensor.poll(90_000);

        source.install(unit("implant.service", "/tmp/.x", "cc"));

        assert_eq!(changes(&sensor.poll(2_000)), vec![(InventoryAction::Added, "implant.service".to_string())]);
    }

    fn packages(observation: &Observation) -> Vec<(InventoryAction, String, String, String, Option<String>)> {
        observation
            .events
            .iter()
            .filter_map(|event| match event {
                SystemEvent::Package(package) => Some((
                    package.action,
                    package.name.clone(),
                    package.version.clone(),
                    package.architecture.clone(),
                    package.previous_version.clone(),
                )),
                _ => None,
            })
            .collect()
    }

    fn package(action: InventoryAction, name: &str, version: &str, architecture: &str, previous: Option<&str>) -> (InventoryAction, String, String, String, Option<String>) {
        (action, name.to_string(), version.to_string(), architecture.to_string(), previous.map(str::to_string))
    }

    #[test]
    fn test_first_inventory_reports_every_installed_package_as_present() {
        let source = FakeSource::default();
        source.install_package("zlib1g", "1:1.3.dfsg-3.1ubuntu2", "amd64");
        source.install_package("libc6", "2.39-0ubuntu8", "i386");
        source.install_package("libc6", "2.39-0ubuntu8", "amd64");

        let observation = sensor(&source).poll(2_000);

        assert_eq!(
            packages(&observation),
            vec![
                package(InventoryAction::Present, "libc6", "2.39-0ubuntu8", "amd64", None),
                package(InventoryAction::Present, "libc6", "2.39-0ubuntu8", "i386", None),
                package(InventoryAction::Present, "zlib1g", "1:1.3.dfsg-3.1ubuntu2", "amd64", None),
            ],
            "ordered by name, and the same package for two architectures is two packages"
        );
        match observation.events.last() {
            Some(SystemEvent::Package(event)) => {
                assert_eq!(event.manager, PackageManager::Dpkg);
                assert_eq!(event.timestamp, 2_000);
            }
            other => panic!("unexpected event {:?}", other),
        }
        assert!(observation.errors.is_empty());
    }

    #[test]
    fn test_installed_upgraded_and_removed_packages_are_reported_once() {
        let source = FakeSource::default();
        source.install_package("openssl", "3.0.13-0ubuntu3", "amd64");
        source.install_package("curl", "8.5.0-2ubuntu10", "amd64");
        source.install_package("libc6", "2.39-0ubuntu8", "amd64");
        source.install_package("libc6", "2.39-0ubuntu8", "i386");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.install_package("openssl", "3.0.13-0ubuntu3.5", "amd64");
        source.install_package("libc6", "2.39-0ubuntu8.4", "amd64");
        source.install_package("netcat-openbsd", "1.226-1ubuntu2", "amd64");
        source.remove_package("curl");

        let observation = sensor.poll(2_000 + PACKAGE_INTERVAL);
        assert_eq!(
            packages(&observation),
            vec![
                package(InventoryAction::Removed, "curl", "8.5.0-2ubuntu10", "amd64", None),
                package(InventoryAction::Changed, "libc6", "2.39-0ubuntu8.4", "amd64", Some("2.39-0ubuntu8")),
                package(InventoryAction::Added, "netcat-openbsd", "1.226-1ubuntu2", "amd64", None),
                package(InventoryAction::Changed, "openssl", "3.0.13-0ubuntu3.5", "amd64", Some("3.0.13-0ubuntu3")),
            ],
            "an upgrade names the version it replaced, the other architecture of libc6 is untouched"
        );

        assert!(sensor.poll(2_000 + 2 * PACKAGE_INTERVAL).events.is_empty());
        assert_eq!(sensor.tracked_packages(), 4);
    }

    #[test]
    fn test_packages_are_read_on_their_own_interval() {
        let source = FakeSource::default();
        source.install_package("openssl", "3.0.13-0ubuntu3", "amd64");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.install_package("openssl", "3.0.13-0ubuntu3.5", "amd64");
        for elapsed in (5..PACKAGE_INTERVAL).step_by(5) {
            assert!(sensor.poll(2_000 + elapsed).events.is_empty());
        }
        let world = |read: fn(&World) -> usize| read(&source.0.lock().unwrap());
        assert_eq!(world(|world| world.package_scans), 1);
        assert_eq!(world(|world| world.persistence_scans), (PACKAGE_INTERVAL / PERSISTENCE_INTERVAL) as usize);

        assert_eq!(packages(&sensor.poll(2_000 + PACKAGE_INTERVAL)).len(), 1);
        assert_eq!(world(|world| world.package_scans), 2);
    }

    #[test]
    fn test_failed_package_read_is_an_error_until_it_works_and_removes_nothing() {
        let source = FakeSource::default();
        source.install_package("openssl", "3.0.13-0ubuntu3", "amd64");
        let mut sensor = sensor(&source);
        sensor.poll(2_000);

        source.0.lock().unwrap().fail_packages = true;
        let failed = sensor.poll(2_000 + PACKAGE_INTERVAL);
        assert!(failed.events.is_empty(), "a failed read must not look like every package being removed");
        assert_eq!(failed.errors, vec!["Package inventory unavailable: database is locked".to_string()]);
        assert_eq!(sensor.poll(2_005 + PACKAGE_INTERVAL).errors, failed.errors);
        assert_eq!(sensor.tracked_packages(), 1);

        source.0.lock().unwrap().fail_packages = false;
        source.install_package("openssl", "3.0.13-0ubuntu3.5", "amd64");
        let recovered = sensor.poll(2_000 + 2 * PACKAGE_INTERVAL);
        assert!(recovered.errors.is_empty());
        assert_eq!(packages(&recovered), vec![package(InventoryAction::Changed, "openssl", "3.0.13-0ubuntu3.5", "amd64", Some("3.0.13-0ubuntu3"))]);
    }

    fn heartbeat(timestamp: u64) -> SystemEvent {
        SystemEvent::Heartbeat(zedr_protocol::HeartbeatEvent { timestamp })
    }

    fn timestamps(events: &[SystemEvent]) -> Vec<u64> {
        events
            .iter()
            .map(|event| match event {
                SystemEvent::Heartbeat(heartbeat) => heartbeat.timestamp,
                _ => 0,
            })
            .collect()
    }

    const ROOMY: usize = 1024 * 1024;

    #[test]
    fn test_outbox_keeps_unsent_events_in_order_and_drops_the_oldest_when_full() {
        let mut outbox = Outbox::new(5, ROOMY);
        outbox.push((1..=4).map(heartbeat).collect());

        assert_eq!(timestamps(&outbox.next_batch(3)), vec![1, 2, 3]);
        assert_eq!(timestamps(&outbox.next_batch(3)), vec![1, 2, 3], "a batch stays queued until it is confirmed");

        outbox.confirm(3);
        assert_eq!(timestamps(&outbox.next_batch(3)), vec![4]);

        outbox.push((5..=10).map(heartbeat).collect());
        assert_eq!(outbox.len(), 5);
        assert_eq!(timestamps(&outbox.next_batch(10)), vec![6, 7, 8, 9, 10]);
        assert_eq!(outbox.take_dropped(), 2);
        assert_eq!(outbox.take_dropped(), 0);

        outbox.confirm(99);
        assert!(outbox.is_empty());
    }

    fn started(pid: u32, argument: &str) -> SystemEvent {
        process_event(
            pid,
            &ProcessDetails {
                ppid: 1,
                uid: 1000,
                executable_path: "/usr/bin/program".to_string(),
                command_line: vec![argument.to_string()],
                started_at: 1_000,
            },
            ProcessAction::Create,
            1_000,
        )
    }

    fn pids(events: &[SystemEvent]) -> Vec<u32> {
        events
            .iter()
            .map(|event| match event {
                SystemEvent::Process(process) => process.pid,
                other => panic!("unexpected event {:?}", other),
            })
            .collect()
    }

    fn encoded_together(events: &[SystemEvent]) -> usize {
        serde_json::to_vec(events).unwrap().len() - "[]".len()
    }

    #[test]
    fn test_outbox_fills_a_batch_by_what_the_events_take_when_encoded() {
        let control_characters = "\u{1}".repeat(4096);
        let one = encoded_together(&[started(1, &control_characters)]);
        assert!(one > 6 * 4096, "a control character takes six bytes on the wire");

        let mut outbox = Outbox::new(100, 3 * (one + SEPARATOR_BYTES));
        outbox.push((1..=5).map(|pid| started(pid, &control_characters)).collect());
        outbox.push((6..=9).map(|pid| started(pid, "short")).collect());

        let first = outbox.next_batch(200);
        assert_eq!(pids(&first), vec![1, 2, 3], "three such events are all that fits");
        assert!(encoded_together(&first) <= 3 * (one + SEPARATOR_BYTES));
        assert_eq!(pids(&outbox.next_batch(2)), vec![1, 2], "the count still limits a batch that has room");

        outbox.confirm(first.len());
        assert_eq!(pids(&outbox.next_batch(200)), vec![4, 5, 6, 7, 8, 9], "order is kept and smaller events fill the room that is left");
        assert_eq!(outbox.take_unsendable(), 0);
    }

    #[test]
    fn test_outbox_leaves_out_only_the_event_that_fits_in_no_batch() {
        let fits_exactly = started(2, "exactly");
        let room = encoded_together(std::slice::from_ref(&fits_exactly)) + SEPARATOR_BYTES;
        let mut outbox = Outbox::new(100, room);

        outbox.push(vec![started(1, "a"), fits_exactly, started(3, "exactly!"), started(4, "b")]);

        assert_eq!(outbox.len(), 3);
        assert_eq!(outbox.take_unsendable(), 1);
        assert_eq!(outbox.take_unsendable(), 0);
        assert_eq!(pids(&outbox.next_batch(200)), vec![1]);
        outbox.confirm(1);
        assert_eq!(pids(&outbox.next_batch(200)), vec![2], "an event as large as the room goes alone");
        outbox.confirm(1);
        assert_eq!(pids(&outbox.next_batch(200)), vec![4]);
        assert_eq!(outbox.take_dropped(), 0);
    }
}
