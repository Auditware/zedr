/// zedr Protocol Types
///
/// Shared types for communication between agents and control server

use serde::{Deserialize, Serialize};

#[cfg(feature = "utoipa")]
use utoipa::ToSchema;

pub const SIGNATURE_HEADER: &str = "x-zedr-signature";

/// Largest request body the control server reads on the event endpoint, an agent fills a batch up to it
pub const MAX_EVENT_BATCH_BYTES: usize = 2 * 1024 * 1024;

const UPGRADE_COMMAND_PURPOSE: &str = "zedr-upgrade-command-v1";

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

/// One thing that makes the system start a program without anyone asking, and what happened to it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum InventoryAction {
    Present,
    Added,
    Changed,
    Removed,
}

/// Where a persistence item lives
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
}

/// One installed package, and what happened to it
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Dpkg,
    Apk,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(ToSchema))]
pub enum ProcessAction {
    Create,
    Terminate,
    Modify,
}

/// File event
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub fn upgrade_command_signing_bytes(
    agent_id: &str,
    target_version: &str,
    nonce: &str,
    issued_at: u64,
) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&UpgradeCommandPayload {
        purpose: UPGRADE_COMMAND_PURPOSE,
        agent_id,
        target_version,
        nonce,
        issued_at,
    })
    .map_err(|e| format!("Failed to encode upgrade command: {}", e))
}

/// Bytes the agent is built with where its signing public key belongs, replaced by the control server on download
pub const SIGNING_PUBLIC_KEY_PLACEHOLDER: [u8; 64] =
    *b"ZEDR_SIGNING_PUBLIC_KEY_PLACEHOLDER_DO_NOT_MODIFY_64_BYTES_LONG\0";

/// Slot contents the control server writes over the placeholder
pub fn signing_public_key_to_slot(public_key: &[u8; 32]) -> Result<[u8; 64], String> {
    let mut slot = [0u8; 64];
    hex::encode_to_slice(public_key, &mut slot)
        .map_err(|e| format!("Failed to encode signing public key: {}", e))?;
    Ok(slot)
}

/// Signing public key the agent reads back from its slot
pub fn signing_public_key_from_slot(slot: &[u8; 64]) -> Result<[u8; 32], String> {
    let mut public_key = [0u8; 32];
    hex::decode_to_slice(slot, &mut public_key)
        .map_err(|_| "Binary has not been patched with a signing public key".to_string())?;
    Ok(public_key)
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
}
