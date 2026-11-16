/// zedr Protocol Types
///
/// Shared types for communication between agents and control server
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

pub const SIGNATURE_HEADER: &str = "x-zedr-signature";

/// Largest request body the control server reads on the event endpoint, an agent fills a batch up to it
pub const MAX_EVENT_BATCH_BYTES: usize = 2 * 1024 * 1024;

const UPGRADE_COMMAND_PURPOSE: &str = "zedr-upgrade-command-v1";
const WINDOW_ACK_PURPOSE: &str = "zedr-window-ack-v1";
const WINDOW_REFUSAL_PURPOSE: &str = "zedr-window-refusal-v1";

/// Agent registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct AgentRegistration {
    pub agent_id: String,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub architecture: String,
    pub version: String,
    pub ip_address: Option<String>,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_key: Option<String>,
    pub session: u64,
    pub seq: u64,
}

/// Agent registration response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct AgentRegistrationResponse {
    pub agent_id: String,
    pub registered_at: i64,
}

/// Detection event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct DetectionEvent {
    pub timestamp: u64,
    pub detection_type: String,
    pub severity: u8,
    pub description: String,
    pub metadata: std::collections::HashMap<String, String>,
}

/// System event types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum SystemEvent {
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Heartbeat(HeartbeatEvent),
    Upgrade(UpgradeEvent),
    Install(InstallEvent),
    AgentStopping(AgentStoppingEvent),
    Persistence(PersistenceEvent),
    Package(PackageEvent),
}

/// A sensor event in the form the agent commits to, seals and evaluates rules over
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum SensorEvent {
    Process(ProcessEvent),
    File(FileEvent),
    Network(NetworkEvent),
    Persistence(PersistenceEvent),
    Package(PackageEvent),
}

impl SensorEvent {
    /// Canonical bytes, the exact form that is hashed into a leaf and sealed
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("a sensor event always encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        borsh::from_slice(bytes).map_err(|e| format!("Not a canonical sensor event: {}", e))
    }
}

impl TryFrom<SystemEvent> for SensorEvent {
    type Error = SystemEvent;

    fn try_from(event: SystemEvent) -> Result<Self, SystemEvent> {
        match event {
            SystemEvent::Process(event) => Ok(SensorEvent::Process(event)),
            SystemEvent::File(event) => Ok(SensorEvent::File(event)),
            SystemEvent::Network(event) => Ok(SensorEvent::Network(event)),
            SystemEvent::Persistence(event) => Ok(SensorEvent::Persistence(event)),
            SystemEvent::Package(event) => Ok(SensorEvent::Package(event)),
            other => Err(other),
        }
    }
}

impl From<SensorEvent> for SystemEvent {
    fn from(event: SensorEvent) -> Self {
        match event {
            SensorEvent::Process(event) => SystemEvent::Process(event),
            SensorEvent::File(event) => SystemEvent::File(event),
            SensorEvent::Network(event) => SystemEvent::Network(event),
            SensorEvent::Persistence(event) => SystemEvent::Persistence(event),
            SensorEvent::Package(event) => SystemEvent::Package(event),
        }
    }
}

/// One thing that makes the system start a program without anyone asking, and what happened to it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PersistenceEvent {
    pub timestamp: u64,
    pub action: InventoryAction,
    pub kind: PersistenceKind,
    pub name: String,
    pub path: String,
    pub command: String,
    pub user: String,
    pub enabled: bool,
    pub hash: Option<String>,
}

/// What happened to an inventory item since the agent last looked, `Present` for the first look after it starts
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum InventoryAction {
    Present,
    Added,
    Changed,
    Removed,
}

/// Where a persistence item lives
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    SystemdUnit,
    SystemdTimer,
    Cron,
    ShellProfile,
    AuthorizedKey,
    LdPreload,
    RcLocal,
    InitScript,
    /// A launchd job that starts at boot, from /Library/LaunchDaemons
    LaunchDaemon,
    /// A launchd job that starts at sign-in, from a LaunchAgents folder
    LaunchAgent,
    /// A Run or RunOnce value in the Windows registry
    RunKey,
    /// A Windows service
    WindowsService,
    /// A Windows scheduled task
    ScheduledTask,
    /// A file in a Windows Startup folder
    StartupFolder,
}

/// One installed package, and what happened to it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct PackageEvent {
    pub timestamp: u64,
    pub action: InventoryAction,
    pub manager: PackageManager,
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub previous_version: Option<String>,
}

/// The package manager whose database lists a package
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Dpkg,
    Apk,
    /// A Homebrew formula or cask
    Homebrew,
    /// An application bundle in an Applications folder of macOS
    MacApp,
    /// A receipt the macOS installer kept
    MacPkg,
    /// A program the Windows registry lists as installed
    WindowsInstalled,
}

/// Sent by the agent when the service manager asks it to stop
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct AgentStoppingEvent {
    pub timestamp: u64,
    pub reason: StopReason,
}

/// Why the agent is stopping
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum StopReason {
    ServiceStop,
    SystemShutdown,
    Upgrade,
}

/// Process event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ProcessEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    pub executable_path: String,
    pub command_line: Vec<String>,
    pub action: ProcessAction,
    pub uid: u32,
    pub hash: Option<String>,
}

/// Process action types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum ProcessAction {
    Create,
    Terminate,
    Modify,
}

/// File event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct FileEvent {
    pub timestamp: u64,
    pub path: String,
    pub action: FileAction,
    pub pid: u32,
    pub process_path: String,
    pub hash: Option<String>,
}

/// File action types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum FileAction {
    Read,
    Write,
    Delete,
    Create,
    Modify,
    Rename,
}

/// Network event
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct NetworkEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub process_path: String,
    pub protocol: String,
    pub source_ip: String,
    pub source_port: u16,
    pub dest_ip: String,
    pub dest_port: u16,
    pub action: NetworkAction,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// Network action types
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum NetworkAction {
    Connect,
    Listen,
    Accept,
    Send,
    Receive,
}

/// Heartbeat event
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct HeartbeatEvent {
    pub timestamp: u64,
}

/// Upgrade command from server to agent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct UpgradeCommand {
    pub agent_id: String,
    pub target_version: String,
    pub signature: Vec<u8>,
    pub issued_at: u64,
    pub nonce: String,
}

/// Upgrade event from agent
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct UpgradeEvent {
    pub timestamp: u64,
    pub from_version: String,
    pub to_version: String,
    pub status: UpgradeStatus,
    pub error: Option<String>,
}

/// Upgrade status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum UpgradeStatus {
    Initiated,
    Started,
    Handoff,
    Completed,
    Failed,
}

/// Install event from agent during initial setup
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct InstallEvent {
    pub timestamp: u64,
    pub version: String,
    pub hostname: String,
    pub platform: String,
    pub os_version: String,
    pub architecture: String,
}

/// Event batch for submitting multiple events
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct EventBatch {
    pub agent_id: String,
    pub session: u64,
    pub seq: u64,
    pub events: Vec<SystemEvent>,
}

#[derive(Serialize)]
struct UpgradeCommandPayload<'a> {
    purpose: &'a str,
    agent_id: &'a str,
    target_version: &'a str,
    nonce: &'a str,
    issued_at: u64,
}

/// Exact bytes signed by the server and verified by the agent for an upgrade command
pub fn upgrade_command_signing_bytes(agent_id: &str, target_version: &str, nonce: &str, issued_at: u64) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&UpgradeCommandPayload { purpose: UPGRADE_COMMAND_PURPOSE, agent_id, target_version, nonce, issued_at })
        .map_err(|e| format!("Failed to encode upgrade command: {}", e))
}

/// Bytes the agent is built with where its signing public key belongs, replaced by the control server on download
pub const SIGNING_PUBLIC_KEY_PLACEHOLDER: [u8; 64] = *b"ZEDR_SIGNING_PUBLIC_KEY_PLACEHOLDER_DO_NOT_MODIFY_64_BYTES_LONG\0";

/// Slot contents the control server writes over the placeholder
pub fn signing_public_key_to_slot(public_key: &[u8; 32]) -> Result<[u8; 64], String> {
    let mut slot = [0u8; 64];
    hex::encode_to_slice(public_key, &mut slot).map_err(|e| format!("Failed to encode signing public key: {}", e))?;
    Ok(slot)
}

/// Signing public key the agent reads back from its slot
pub fn signing_public_key_from_slot(slot: &[u8; 64]) -> Result<[u8; 32], String> {
    let mut public_key = [0u8; 32];
    hex::decode_to_slice(slot, &mut public_key).map_err(|_| "Binary has not been patched with a signing public key".to_string())?;
    Ok(public_key)
}

/// Header of one sealed window. Hashes travel as 64 hex characters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SealedWindowHeader {
    pub epoch: u64,
    pub window: u64,
    pub first_index: u64,
    pub count: u32,
    pub fresh: bool,
    pub gap: bool,
    pub prev_head: String,
    pub root: String,
    pub head: String,
}

/// One sealed event: the leaf that commits to it in hex, and its ciphertext in base64
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SealedEvent {
    pub leaf: String,
    pub sealed: String,
}

/// The secret that opens one sealed event, in hex
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Opening {
    pub index: u64,
    pub seed: String,
}

/// A rule that fired on the endpoint, with the secrets of the events it opens
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct Release {
    pub trigger: u64,
    pub rule: String,
    pub context: Vec<u64>,
    pub pid: u32,
    pub started_at: u64,
    pub openings: Vec<Opening>,
}

/// One sealed window on its way to the control server, with what the rules opened in it
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SealedWindow {
    pub agent_id: String,
    pub session: u64,
    pub seq: u64,
    pub header: SealedWindowHeader,
    pub events: Vec<SealedEvent>,
    pub releases: Vec<Release>,
    /// Whether this endpoint has a prover and will prove the window
    pub proving: bool,
}

/// The control server's signed word that it holds a window
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct SealedWindowAck {
    pub window: u64,
    pub next_index: u64,
    pub head: String,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct WindowAckPayload<'a> {
    purpose: &'a str,
    agent_id: &'a str,
    window: u64,
    next_index: u64,
    head: &'a str,
}

/// Exact bytes signed by the server and verified by the agent for a window acknowledgement
pub fn window_ack_signing_bytes(agent_id: &str, window: u64, next_index: u64, head: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WindowAckPayload { purpose: WINDOW_ACK_PURPOSE, agent_id, window, next_index, head })
        .map_err(|e| format!("Failed to encode window acknowledgement: {}", e))
}

/// The control server's answer to a window it will not take: where its copy of the agent's chain stands.
/// It is signed for the one request it answers, so nobody else can make an agent start over, and never from an old position
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct WindowRefusal {
    pub epoch: u64,
    pub next_window: u64,
    pub next_index: u64,
    pub head: String,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct WindowRefusalPayload<'a> {
    purpose: &'a str,
    agent_id: &'a str,
    session: u64,
    seq: u64,
    epoch: u64,
    next_window: u64,
    next_index: u64,
    head: &'a str,
}

/// Exact bytes signed by the server and verified by the agent for a refused window
pub fn window_refusal_signing_bytes(
    agent_id: &str,
    session: u64,
    seq: u64,
    epoch: u64,
    next_window: u64,
    next_index: u64,
    head: &str,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&WindowRefusalPayload { purpose: WINDOW_REFUSAL_PURPOSE, agent_id, session, seq, epoch, next_window, next_index, head })
        .map_err(|e| format!("Failed to encode window refusal: {}", e))
}

/// A proof that the rules ran over a run of sealed windows, the receipt in base64
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ProofSubmission {
    pub agent_id: String,
    pub session: u64,
    pub seq: u64,
    pub receipt: String,
}

/// The windows a proof was accepted for
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ProofAck {
    pub first_window: u64,
    pub last_window: u64,
}

/// Hex form of a 32-byte hash
pub fn hash_to_hex(hash: &[u8; 32]) -> String {
    hex::encode(hash)
}

pub fn hash_from_hex(text: &str) -> Result<[u8; 32], String> {
    let mut hash = [0u8; 32];
    hex::decode_to_slice(text, &mut hash).map_err(|_| "A hash is 64 hex characters".to_string())?;
    Ok(hash)
}

/// Base64 form of sealed bytes
pub fn bytes_to_base64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn bytes_from_base64(text: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(text).map_err(|_| "Not base64".to_string())
}

/// API error response
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub struct ErrorResponse {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detection_event_serialization() {
        let event = DetectionEvent {
            timestamp: 1234567890,
            detection_type: String::from("test"),
            severity: 5,
            description: String::from("Test detection"),
            metadata: std::collections::HashMap::new(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("test"));
    }

    #[test]
    fn test_agent_registration_serialization() {
        let reg = AgentRegistration {
            agent_id: "agent-1".to_string(),
            hostname: "test-host".to_string(),
            platform: "linux".to_string(),
            os_version: "Ubuntu 22.04".to_string(),
            architecture: "x86_64".to_string(),
            version: "0.1.0".to_string(),
            ip_address: Some("192.168.1.100".to_string()),
            public_key: "00".repeat(32),
            enrollment_key: None,
            session: 1,
            seq: 1,
        };

        let json = serde_json::to_string(&reg).unwrap();
        assert!(json.contains("test-host"));
        assert!(!json.contains("enrollment_key"));
    }

    #[test]
    fn test_persistence_event_has_the_shape_the_console_reads() {
        let event = SystemEvent::Persistence(PersistenceEvent {
            timestamp: 1_794_780_000,
            action: InventoryAction::Added,
            kind: PersistenceKind::SystemdUnit,
            name: "backup.service".to_string(),
            path: "/etc/systemd/system/backup.service".to_string(),
            command: "/usr/local/bin/backup --all".to_string(),
            user: "root".to_string(),
            enabled: true,
            hash: None,
        });

        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({
                "Persistence": {
                    "timestamp": 1_794_780_000u64,
                    "action": "Added",
                    "kind": "systemd_unit",
                    "name": "backup.service",
                    "path": "/etc/systemd/system/backup.service",
                    "command": "/usr/local/bin/backup --all",
                    "user": "root",
                    "enabled": true,
                    "hash": null
                }
            })
        );
    }

    #[test]
    fn test_every_persistence_kind_and_action_has_a_stable_name() {
        let kinds = [
            (PersistenceKind::SystemdUnit, "systemd_unit"),
            (PersistenceKind::SystemdTimer, "systemd_timer"),
            (PersistenceKind::Cron, "cron"),
            (PersistenceKind::ShellProfile, "shell_profile"),
            (PersistenceKind::AuthorizedKey, "authorized_key"),
            (PersistenceKind::LdPreload, "ld_preload"),
            (PersistenceKind::RcLocal, "rc_local"),
            (PersistenceKind::InitScript, "init_script"),
            (PersistenceKind::LaunchDaemon, "launch_daemon"),
            (PersistenceKind::LaunchAgent, "launch_agent"),
            (PersistenceKind::RunKey, "run_key"),
            (PersistenceKind::WindowsService, "windows_service"),
            (PersistenceKind::ScheduledTask, "scheduled_task"),
            (PersistenceKind::StartupFolder, "startup_folder"),
        ];
        for (kind, name) in kinds {
            assert_eq!(serde_json::to_value(kind).unwrap(), name);
            assert_eq!(serde_json::from_value::<PersistenceKind>(serde_json::json!(name)).unwrap(), kind);
        }

        let actions = [
            (InventoryAction::Present, "Present"),
            (InventoryAction::Added, "Added"),
            (InventoryAction::Changed, "Changed"),
            (InventoryAction::Removed, "Removed"),
        ];
        for (action, name) in actions {
            assert_eq!(serde_json::to_value(action).unwrap(), name);
        }
    }

    #[test]
    fn test_package_event_has_the_shape_the_console_reads() {
        let upgraded = SystemEvent::Package(PackageEvent {
            timestamp: 1_794_780_000,
            action: InventoryAction::Changed,
            manager: PackageManager::Dpkg,
            name: "openssl".to_string(),
            version: "3.0.13-0ubuntu3.5".to_string(),
            architecture: "amd64".to_string(),
            previous_version: Some("3.0.13-0ubuntu3".to_string()),
        });

        assert_eq!(
            serde_json::to_value(&upgraded).unwrap(),
            serde_json::json!({
                "Package": {
                    "timestamp": 1_794_780_000u64,
                    "action": "Changed",
                    "manager": "dpkg",
                    "name": "openssl",
                    "version": "3.0.13-0ubuntu3.5",
                    "architecture": "amd64",
                    "previous_version": "3.0.13-0ubuntu3"
                }
            })
        );

        assert_eq!(serde_json::to_value(PackageManager::Apk).unwrap(), "apk");
        for (manager, name) in [
            (PackageManager::Homebrew, "homebrew"),
            (PackageManager::MacApp, "mac_app"),
            (PackageManager::MacPkg, "mac_pkg"),
            (PackageManager::WindowsInstalled, "windows_installed"),
        ] {
            assert_eq!(serde_json::to_value(manager).unwrap(), name);
        }
        assert_eq!(serde_json::from_value::<PackageManager>(serde_json::json!("dpkg")).unwrap(), PackageManager::Dpkg);
    }

    #[test]
    fn test_command_signing_bytes_are_deterministic() {
        let a = upgrade_command_signing_bytes("agent-1", "0.2.0", "nonce", 100).unwrap();
        let b = upgrade_command_signing_bytes("agent-1", "0.2.0", "nonce", 100).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_command_signing_bytes_bind_every_field() {
        let base = upgrade_command_signing_bytes("agent-1", "0.2.0", "n1", 100).unwrap();
        assert_ne!(base, upgrade_command_signing_bytes("agent-2", "0.2.0", "n1", 100).unwrap());
        assert_ne!(base, upgrade_command_signing_bytes("agent-1", "0.2.1", "n1", 100).unwrap());
        assert_ne!(base, upgrade_command_signing_bytes("agent-1", "0.2.0", "n2", 100).unwrap());
        assert_ne!(base, upgrade_command_signing_bytes("agent-1", "0.2.0", "n1", 101).unwrap());
    }

    #[test]
    fn test_target_version_cannot_forge_other_fields() {
        let injected = upgrade_command_signing_bytes("agent-1", r#"x","nonce":"n2","issued_at":1}"#, "n1", 100).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&injected).unwrap();
        assert_eq!(parsed["nonce"], "n1");
        assert_eq!(parsed["issued_at"], 100);
    }

    #[test]
    fn test_signing_public_key_survives_the_slot() {
        let public_key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let slot = signing_public_key_to_slot(&public_key).unwrap();
        assert_eq!(signing_public_key_from_slot(&slot).unwrap(), public_key);
    }

    #[test]
    fn test_unpatched_slot_holds_no_signing_public_key() {
        let err = signing_public_key_from_slot(&SIGNING_PUBLIC_KEY_PLACEHOLDER).unwrap_err();
        assert!(err.contains("not been patched"));
    }

    #[test]
    fn test_half_written_slot_holds_no_signing_public_key() {
        let mut slot = signing_public_key_to_slot(&[0xab; 32]).unwrap();
        slot[40..].copy_from_slice(&SIGNING_PUBLIC_KEY_PLACEHOLDER[40..]);
        assert!(signing_public_key_from_slot(&slot).is_err());
    }

    fn connection() -> NetworkEvent {
        NetworkEvent {
            timestamp: 7,
            pid: 21,
            process_path: "/bin/sh".to_string(),
            protocol: "tcp".to_string(),
            source_ip: "10.0.0.5".to_string(),
            source_port: 50000,
            dest_ip: "203.0.113.9".to_string(),
            dest_port: 443,
            action: NetworkAction::Connect,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    #[test]
    fn test_the_canonical_bytes_of_a_sensor_event_are_fixed() {
        let event = SensorEvent::Network(connection());
        let bytes = event.to_bytes();
        assert_eq!(
            hex::encode(&bytes),
            "02070000000000000015000000070000002f62696e2f7368030000007463700800000031302e302e302e3550c30b0000003230332e302e3131332e39bb010000000000000000000000000000000000",
            "committed leaves are taken over these bytes, a change here breaks every chain that exists"
        );
        assert_eq!(SensorEvent::from_bytes(&bytes).unwrap(), event);
    }

    #[test]
    fn test_bytes_with_anything_added_or_missing_are_not_a_sensor_event() {
        let bytes = SensorEvent::Network(connection()).to_bytes();
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(SensorEvent::from_bytes(&longer).is_err());
        assert!(SensorEvent::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        assert!(SensorEvent::from_bytes(&[9]).is_err(), "an unknown kind of event");
    }

    #[test]
    fn test_only_what_the_sensor_reports_becomes_a_sensor_event() {
        let sensed = SystemEvent::Network(connection());
        let event = SensorEvent::try_from(sensed).unwrap();
        assert!(matches!(SystemEvent::from(event), SystemEvent::Network(_)));

        let heartbeat = SystemEvent::Heartbeat(HeartbeatEvent { timestamp: 1 });
        assert!(matches!(SensorEvent::try_from(heartbeat), Err(SystemEvent::Heartbeat(_))));
    }

    #[test]
    fn test_window_ack_signing_bytes_bind_the_agent_and_the_chain_position() {
        let head = "ab".repeat(32);
        let bytes = window_ack_signing_bytes("agent-1", 5, 40, &head).unwrap();
        assert_eq!(bytes, window_ack_signing_bytes("agent-1", 5, 40, &head).unwrap());
        assert_ne!(bytes, window_ack_signing_bytes("agent-2", 5, 40, &head).unwrap());
        assert_ne!(bytes, window_ack_signing_bytes("agent-1", 6, 40, &head).unwrap());
        assert_ne!(bytes, window_ack_signing_bytes("agent-1", 5, 41, &head).unwrap());
        assert_ne!(bytes, window_ack_signing_bytes("agent-1", 5, 40, &"cd".repeat(32)).unwrap());
        assert_ne!(bytes, upgrade_command_signing_bytes("agent-1", "5", "40", 0).unwrap(), "an acknowledgement is never a command");
    }

    #[test]
    fn test_window_refusal_signing_bytes_bind_the_request_they_answer() {
        let head = "ab".repeat(32);
        let bytes = window_refusal_signing_bytes("agent-1", 3, 9, 2, 5, 40, &head).unwrap();
        assert_ne!(
            bytes,
            window_refusal_signing_bytes("agent-1", 3, 10, 2, 5, 40, &head).unwrap(),
            "a refusal signed for an earlier request is not valid for this one"
        );
        assert_ne!(bytes, window_refusal_signing_bytes("agent-1", 4, 9, 2, 5, 40, &head).unwrap());
        assert_ne!(bytes, window_refusal_signing_bytes("agent-2", 3, 9, 2, 5, 40, &head).unwrap());
        assert_ne!(bytes, window_refusal_signing_bytes("agent-1", 3, 9, 3, 5, 40, &head).unwrap(), "the epoch is signed too");
        assert_ne!(bytes, window_refusal_signing_bytes("agent-1", 3, 9, 2, 6, 40, &head).unwrap());
        assert_ne!(bytes, window_ack_signing_bytes("agent-1", 5, 40, &head).unwrap(), "a refusal is never an acknowledgement");
    }

    #[test]
    fn test_hashes_and_sealed_bytes_survive_their_text_forms() {
        let hash: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(hash_from_hex(&hash_to_hex(&hash)).unwrap(), hash);
        assert!(hash_from_hex("abcd").is_err());
        assert!(hash_from_hex(&"zz".repeat(32)).is_err());

        let sealed = vec![0u8, 255, 16, 32, 7];
        assert_eq!(bytes_from_base64(&bytes_to_base64(&sealed)).unwrap(), sealed);
        assert!(bytes_from_base64("not base64!").is_err());
    }
}
