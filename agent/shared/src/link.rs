use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use zedr_protocol::{
    AgentRegistration, AgentStoppingEvent, EventBatch, ShellCommand, StopReason, SystemEvent, UpgradeCommand,
    MAX_EVENT_BATCH_BYTES, SIGNATURE_HEADER,
};

use crate::identity::{self, Identity};
use crate::journal::{AcceptedCommand, CommandJournal};

const REGISTRATION_TIMEOUT_SECS: u64 = 30;
const STOP_NOTICE_TIMEOUT_SECS: u64 = 5;

pub struct HostDescription {
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
}

pub struct ControlLink {
    server_url: String,
    state_dir: PathBuf,
    agent_id: String,
    identity: Mutex<Identity>,
    accepted_commands: Mutex<Result<CommandJournal, String>>,
}

impl ControlLink {
    pub fn open(server_url: String, state_dir: &Path, agent_id: String) -> Result<Self, String> {
        let identity = Identity::load_or_create(state_dir)?;
        Ok(Self::with_identity(server_url, state_dir, agent_id, identity))
    }

    pub fn open_with_key_id(server_url: String, state_dir: &Path) -> Result<Self, String> {
        let identity = Identity::load_or_create(state_dir)?;
        let agent_id = identity.key_fingerprint();
        Ok(Self::with_identity(server_url, state_dir, agent_id, identity))
    }

    fn with_identity(server_url: String, state_dir: &Path, agent_id: String, identity: Identity) -> Self {
        Self {
            server_url,
            state_dir: state_dir.to_path_buf(),
            agent_id,
            identity: Mutex::new(identity),
            accepted_commands: Mutex::new(CommandJournal::open(state_dir)),
        }
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    fn with_accepted_commands<T>(
        &self,
        act: impl FnOnce(&mut CommandJournal) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut journal = self.accepted_commands.lock()
            .map_err(|e| format!("Failed to lock the record of accepted commands: {}", e))?;

        match journal.as_mut() {
            Ok(journal) => act(journal),
            Err(e) => Err(e.clone()),
        }
    }

    pub fn accept_shell_command(&self, command: &ShellCommand) -> Result<(), String> {
        self.with_accepted_commands(|journal| journal.accept_shell(command, unix_now()))
    }

    pub fn shell_command_answered(&self, nonce: &str) -> Result<(), String> {
        self.with_accepted_commands(|journal| journal.answered(nonce, unix_now()))
    }

    pub fn unanswered_shell_commands(&self) -> Result<Vec<AcceptedCommand>, String> {
        self.with_accepted_commands(|journal| Ok(journal.unanswered()))
    }

    pub fn verify_upgrade_command(&self, command: &UpgradeCommand) -> Result<(), String> {
        self.verify_upgrade_command_with_key(&crate::signing_public_key()?, command)
    }

    pub(crate) fn verify_upgrade_command_with_key(
        &self,
        public_key: &VerifyingKey,
        command: &UpgradeCommand,
    ) -> Result<(), String> {
        crate::verify_upgrade_command_with_key(public_key, command, &self.agent_id)?;
        self.with_accepted_commands(|journal| journal.accept_upgrade(command, unix_now()))
    }

    fn post_signed(
        &self,
        path: &str,
        timeout_secs: u64,
        build_body: impl FnOnce(u64, u64, String) -> Result<String, serde_json::Error>,
    ) -> Result<minreq::Response, String> {
        let mut identity = self.identity.lock()
            .map_err(|e| format!("Failed to lock identity: {}", e))?;

        let seq = identity.next_seq();
        let body = build_body(identity.session(), seq, identity.public_key_hex())
            .map_err(|e| format!("Failed to encode request: {}", e))?;
        let signature = identity.sign(body.as_bytes());

        minreq::post(format!("{}{}", self.server_url, path))
            .with_header("Content-Type", "application/json")
            .with_header(SIGNATURE_HEADER, signature)
            .with_body(body)
            .with_timeout(timeout_secs)
            .send()
            .map_err(|e| format!("Request to {} failed: {}", path, e))
    }

    pub fn event_bytes_per_batch(&self) -> Result<usize, String> {
        let envelope = serde_json::to_vec(&EventBatch {
            agent_id: self.agent_id.clone(),
            session: u64::MAX,
            seq: u64::MAX,
            events: Vec::new(),
        })
        .map_err(|e| format!("Failed to encode request: {}", e))?;

        MAX_EVENT_BATCH_BYTES
            .checked_sub(envelope.len())
            .ok_or_else(|| "Agent id leaves no room for events in a batch".to_string())
    }

    pub fn send_events(&self, events: Vec<SystemEvent>, timeout_secs: u64) -> Result<minreq::Response, String> {
        let agent_id = self.agent_id.clone();
        self.post_signed("/api/events", timeout_secs, |session, seq, _| {
            serde_json::to_string(&EventBatch { agent_id, session, seq, events })
        })
    }

    pub fn register(&self, host: &HostDescription) -> Result<(), String> {
        let enrollment_key = identity::read_enrollment_key(&self.state_dir);

        let response = self.post_signed("/api/agents/register", REGISTRATION_TIMEOUT_SECS, |session, seq, public_key| {
            serde_json::to_string(&AgentRegistration {
                agent_id: self.agent_id.clone(),
                hostname: host.hostname.clone(),
                platform: std::env::consts::OS.to_string(),
                os_version: host.os_version.clone(),
                architecture: std::env::consts::ARCH.to_string(),
                version: host.agent_version.clone(),
                ip_address: local_ip(),
                public_key,
                enrollment_key,
                session,
                seq,
            })
        })?;

        if response.status_code != 200 {
            return Err(format!("Registration rejected: HTTP {}", response.status_code));
        }

        identity::clear_enrollment_key(&self.state_dir)
    }

    pub fn notify_stopping(&self, reason: StopReason) -> Result<i32, String> {
        let event = SystemEvent::AgentStopping(AgentStoppingEvent { timestamp: unix_now(), reason });
        self.send_events(vec![event], STOP_NOTICE_TIMEOUT_SECS)
            .map(|response| response.status_code)
    }
}

pub fn unix_now() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_secs(),
        Err(_) => 0,
    }
}

fn local_ip() -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip().to_string())
}
