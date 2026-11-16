use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use zedr_ledger::{Hash, WindowHeader};
use zedr_protocol::{
    bytes_to_base64, hash_from_hex, hash_to_hex, window_ack_signing_bytes, window_refusal_signing_bytes, AgentRegistration, AgentStoppingEvent,
    EventBatch, ProofSubmission, SealedEvent, SealedWindowAck, SealedWindowHeader, StopReason, SystemEvent, UpgradeCommand, WindowRefusal,
    SIGNATURE_HEADER,
};

use crate::identity::{self, Identity};
use crate::journal::CommandJournal;
use crate::ledger::{Ledger, Release, SealedWindow};

const REGISTRATION_TIMEOUT_SECS: u64 = 30;
const STOP_NOTICE_TIMEOUT_SECS: u64 = 5;
const LEDGER_DIR: &str = "ledger";

pub struct HostDescription {
    pub hostname: String,
    pub os_version: String,
    pub agent_version: String,
}

/// Where the control server's copy of this agent's chain stands, as it signed it in answer to one window it did not take
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerPosition {
    pub epoch: u64,
    pub next_window: u64,
    pub next_index: u64,
    pub head: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowDelivery {
    Accepted,
    Refused(ServerPosition),
}

struct Answered {
    session: u64,
    seq: u64,
    response: minreq::Response,
}

pub struct ControlLink {
    server_url: String,
    state_dir: PathBuf,
    agent_id: String,
    identity: Mutex<Identity>,
    accepted_commands: Mutex<Result<CommandJournal, String>>,
    deployment_key: Result<VerifyingKey, String>,
}

impl ControlLink {
    pub fn open(server_url: String, state_dir: &Path, agent_id: String) -> Result<Self, String> {
        let identity = Identity::load_or_create(state_dir)?;
        Ok(Self::with_identity(server_url, state_dir, agent_id, identity, crate::signing_public_key()))
    }

    pub fn open_with_key_id(server_url: String, state_dir: &Path) -> Result<Self, String> {
        let identity = Identity::load_or_create(state_dir)?;
        let agent_id = identity.key_fingerprint();
        Ok(Self::with_identity(server_url, state_dir, agent_id, identity, crate::signing_public_key()))
    }

    /// For tools and tests only: a link that trusts the deployment key it is given, where an agent trusts the one patched into its binary
    pub fn open_trusting(server_url: String, state_dir: &Path, agent_id: Option<String>, deployment_key: VerifyingKey) -> Result<Self, String> {
        let identity = Identity::load_or_create(state_dir)?;
        let agent_id = agent_id.unwrap_or_else(|| identity.key_fingerprint());
        Ok(Self::with_identity(server_url, state_dir, agent_id, identity, Ok(deployment_key)))
    }

    fn with_identity(server_url: String, state_dir: &Path, agent_id: String, identity: Identity, deployment_key: Result<VerifyingKey, String>) -> Self {
        Self {
            server_url,
            state_dir: state_dir.to_path_buf(),
            agent_id,
            identity: Mutex::new(identity),
            accepted_commands: Mutex::new(CommandJournal::open(state_dir)),
            deployment_key,
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

    pub fn accepted_commands_readable(&self) -> Result<(), String> {
        self.with_accepted_commands(|_| Ok(()))
    }

    pub fn verify_upgrade_command(&self, command: &UpgradeCommand) -> Result<(), String> {
        self.verify_upgrade_command_with_key(self.deployment_key.as_ref().map_err(String::clone)?, command)
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
    ) -> Result<Answered, String> {
        let mut identity = self.identity.lock()
            .map_err(|e| format!("Failed to lock identity: {}", e))?;

        let session = identity.session();
        let seq = identity.next_seq();
        let body = build_body(session, seq, identity.public_key_hex())
            .map_err(|e| format!("Failed to encode request: {}", e))?;
        let signature = identity.sign(body.as_bytes());

        let response = minreq::post(format!("{}{}", self.server_url, path))
            .with_header("Content-Type", "application/json")
            .with_header(SIGNATURE_HEADER, signature)
            .with_body(body)
            .with_timeout(timeout_secs)
            .send()
            .map_err(|e| format!("Request to {} failed: {}", path, e))?;

        Ok(Answered { session, seq, response })
    }

    /// Sends what the agent says about itself. What the sensor saw never goes this way, it leaves the endpoint sealed
    pub fn send_events(&self, events: Vec<SystemEvent>, timeout_secs: u64) -> Result<minreq::Response, String> {
        let sensed = |event: &SystemEvent| {
            matches!(event, SystemEvent::Process(_) | SystemEvent::File(_) | SystemEvent::Network(_) | SystemEvent::Persistence(_) | SystemEvent::Package(_))
        };
        if events.iter().any(sensed) {
            return Err("Sensor events are not sent unsealed".to_string());
        }

        let agent_id = self.agent_id.clone();
        self.post_signed("/api/events", timeout_secs, |session, seq, _| {
            serde_json::to_string(&EventBatch { agent_id, session, seq, events })
        })
        .map(|answered| answered.response)
    }

    pub fn open_ledger(&self, now: u64) -> Result<Ledger, String> {
        let identity = self.identity.lock()
            .map_err(|e| format!("Failed to lock identity: {}", e))?;

        Ledger::open(&self.state_dir.join(LEDGER_DIR), identity.key_hash(), identity.ledger_key(), now)
    }

    /// Hands one sealed window to the control server. Only an answer signed by the deployment counts: its acknowledgement
    /// of exactly this window, or its refusal of this very request with the position its copy of the chain stands at
    pub fn send_window(&self, window: &SealedWindow, proving: bool, timeout_secs: u64) -> Result<WindowDelivery, String> {
        let deployment_key = self.deployment_key.as_ref().map_err(String::clone)?;
        let sent = &window.header;
        let header = wire_header(sent);
        let events = window.leaves.iter().zip(&window.sealed).map(|(leaf, sealed)| SealedEvent { leaf: hash_to_hex(leaf), sealed: bytes_to_base64(sealed) }).collect();
        let releases = window.releases.iter().map(wire_release).collect();

        let answered = self.post_signed("/api/windows", timeout_secs, |session, seq, _| {
            serde_json::to_string(&zedr_protocol::SealedWindow { agent_id: self.agent_id.clone(), session, seq, header, events, releases, proving })
        })?;
        let body = answered.response.as_bytes();

        match answered.response.status_code {
            200 => {
                let ack: SealedWindowAck = serde_json::from_slice(body)
                    .map_err(|e| format!("Unreadable window acknowledgement: {}", e))?;
                let signed = window_ack_signing_bytes(&self.agent_id, ack.window, ack.next_index, &ack.head)?;
                verify_answer(deployment_key, &signed, &ack.signature, "Window acknowledgement")?;

                if (ack.window, ack.next_index, hash_from_hex(&ack.head)?) != (sent.window, sent.next_index(), sent.head) {
                    return Err(format!("Window acknowledgement is for another window than window {}", sent.window));
                }
                Ok(WindowDelivery::Accepted)
            }
            status @ (409 | 422) => {
                let refusal: WindowRefusal = serde_json::from_slice(body)
                    .map_err(|e| format!("HTTP {} without a signed refusal: {}", status, e))?;
                let signed = window_refusal_signing_bytes(&self.agent_id, answered.session, answered.seq, refusal.epoch, refusal.next_window, refusal.next_index, &refusal.head)?;
                verify_answer(deployment_key, &signed, &refusal.signature, "Window refusal")?;

                Ok(WindowDelivery::Refused(ServerPosition {
                    epoch: refusal.epoch,
                    next_window: refusal.next_window,
                    next_index: refusal.next_index,
                    head: hash_from_hex(&refusal.head)?,
                }))
            }
            status => Err(format!("HTTP {}", status)),
        }
    }

    pub fn send_proof(&self, receipt: &[u8], timeout_secs: u64) -> Result<(), String> {
        let agent_id = self.agent_id.clone();
        let receipt = bytes_to_base64(receipt);
        let answered = self.post_signed("/api/proofs", timeout_secs, |session, seq, _| {
            serde_json::to_string(&ProofSubmission { agent_id, session, seq, receipt })
        })?;

        match answered.response.status_code {
            200 => Ok(()),
            status => Err(format!("HTTP {}", status)),
        }
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
        })?
        .response;

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

fn wire_header(header: &WindowHeader) -> SealedWindowHeader {
    SealedWindowHeader {
        epoch: header.epoch,
        window: header.window,
        first_index: header.first_index,
        count: header.count,
        fresh: header.fresh,
        gap: header.gap,
        prev_head: hash_to_hex(&header.prev_head),
        root: hash_to_hex(&header.root),
        head: hash_to_hex(&header.head),
    }
}

fn wire_release(release: &Release) -> zedr_protocol::Release {
    zedr_protocol::Release {
        trigger: release.found.trigger,
        rule: release.found.rule.id().to_string(),
        context: release.found.context.clone(),
        pid: release.found.pid,
        started_at: release.found.started_at,
        openings: release.openings.iter().map(|opening| zedr_protocol::Opening { index: opening.index, seed: hash_to_hex(&opening.seed) }).collect(),
    }
}

fn verify_answer(deployment_key: &VerifyingKey, signed: &[u8], signature: &[u8], what: &str) -> Result<(), String> {
    let signature = Signature::from_slice(signature)
        .map_err(|e| format!("{} carries no signature: {}", what, e))?;

    deployment_key.verify(signed, &signature)
        .map_err(|_| format!("{} is not signed by this deployment", what))
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
