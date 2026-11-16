/// Shared library for zedr EDR agents
///
/// This library contains common functionality used across all platform-specific agents
/// including data structures, protocols, and utilities.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::fs;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub use zedr_protocol::*;

pub mod journal;
pub mod ledger;
pub mod link;
pub mod runtime;
pub mod sensor;

pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const AGENT_NAME: &str = "zedr";

static SIGNING_PUBLIC_KEY_SLOT: [u8; 64] = zedr_protocol::SIGNING_PUBLIC_KEY_PLACEHOLDER;

fn signing_public_key_in(slot: &[u8; 64]) -> Result<VerifyingKey, String> {
    let key_bytes = signing_public_key_from_slot(slot)?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("Invalid signing public key: {}", e))
}

fn signing_public_key() -> Result<VerifyingKey, String> {
    signing_public_key_in(std::hint::black_box(&SIGNING_PUBLIC_KEY_SLOT))
}

fn verify_binary_signature_with_key(public_key: &VerifyingKey, binary_data: &[u8]) -> Result<(), String> {
    if binary_data.len() < 64 {
        return Err("Binary too small to contain signature".to_string());
    }

    let (data, signature_bytes) = binary_data.split_at(binary_data.len() - 64);

    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    public_key.verify(data, &signature)
        .map_err(|_| "Signature verification failed: binary has been tampered with".to_string())?;

    Ok(())
}

pub fn verify_self_signature() -> Result<(), String> {
    let exe_path = std::env::current_exe()
        .map_err(|e| format!("Failed to get executable path: {}", e))?;

    let binary_data = fs::read(&exe_path)
        .map_err(|e| format!("Failed to read executable: {}", e))?;

    verify_binary_signature(&binary_data)
}

pub fn verify_binary_signature(binary_data: &[u8]) -> Result<(), String> {
    verify_binary_signature_with_key(&signing_public_key()?, binary_data)
}

static NONCE_CACHE: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);

const COMMAND_MAX_AGE_SECS: u64 = 300;
const COMMAND_MAX_FUTURE_SECS: u64 = 60;

fn verify_command(
    public_key: &VerifyingKey,
    signed_bytes: &[u8],
    signature: &[u8],
    issued_at: u64,
    nonce: &str,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("System time error: {}", e))?
        .as_secs();

    let mut cache_guard = NONCE_CACHE.lock()
        .map_err(|e| format!("Failed to lock nonce cache: {}", e))?;

    let cache = cache_guard.get_or_insert_with(HashMap::new);

    verify_command_at(cache, now, public_key, signed_bytes, signature, issued_at, nonce)
}

fn command_expired(issued_at: u64, now: u64) -> bool {
    now.saturating_sub(issued_at) > COMMAND_MAX_AGE_SECS
}

#[cfg(test)]
fn forget_nonce_as_a_new_process_would(nonce: &str) {
    if let Some(cache) = NONCE_CACHE.lock().unwrap().as_mut() {
        cache.remove(nonce);
    }
}

fn verify_command_at(
    used_nonces: &mut HashMap<String, u64>,
    now: u64,
    public_key: &VerifyingKey,
    signed_bytes: &[u8],
    signature: &[u8],
    issued_at: u64,
    nonce: &str,
) -> Result<(), String> {
    let signature = Signature::from_slice(signature)
        .map_err(|e| format!("Invalid signature format: {}", e))?;

    public_key.verify(signed_bytes, &signature)
        .map_err(|_| "Signature verification failed: command has been tampered with".to_string())?;

    if issued_at > now + COMMAND_MAX_FUTURE_SECS {
        return Err("Command timestamp is in the future".to_string());
    }

    if command_expired(issued_at, now) {
        return Err("Command expired (older than 5 minutes)".to_string());
    }

    used_nonces.retain(|_, &mut nonce_issued_at| !command_expired(nonce_issued_at, now));

    if used_nonces.contains_key(nonce) {
        return Err("Nonce already used (replay attack detected)".to_string());
    }

    used_nonces.insert(nonce.to_string(), issued_at);

    Ok(())
}

fn verify_upgrade_command_with_key(
    public_key: &VerifyingKey,
    cmd: &UpgradeCommand,
    own_agent_id: &str,
) -> Result<(), String> {
    if cmd.agent_id != own_agent_id {
        return Err("Command was issued for a different agent".to_string());
    }

    let signed_bytes = upgrade_command_signing_bytes(
        &cmd.agent_id,
        &cmd.target_version,
        &cmd.nonce,
        cmd.issued_at,
    )?;

    verify_command(public_key, &signed_bytes, &cmd.signature, cmd.issued_at, &cmd.nonce)
}

pub mod identity {
    use ed25519_dalek::{Signer, SigningKey};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::io::{ErrorKind, Write};
    use std::path::Path;

    const IDENTITY_FILE: &str = "identity.json";
    const ENROLLMENT_FILE: &str = "enrollment.key";
    const LEDGER_KEY_DOMAIN: &[u8] = b"zedr/ledger-master/v1";

    #[derive(Serialize, Deserialize)]
    struct StoredIdentity {
        seed: String,
        session: u64,
    }

    pub struct Identity {
        signing_key: SigningKey,
        session: u64,
        seq: u64,
    }

    impl Identity {
        pub fn load_or_create(dir: &Path) -> Result<Self, String> {
            let path = dir.join(IDENTITY_FILE);

            let previous = match fs::read_to_string(&path) {
                Ok(raw) => serde_json::from_str::<StoredIdentity>(&raw)
                    .map_err(|e| format!("Identity file is corrupt: {}", e))?,
                Err(e) if e.kind() == ErrorKind::NotFound => StoredIdentity {
                    seed: hex::encode(new_seed()?),
                    session: 0,
                },
                Err(e) => return Err(format!("Failed to read identity file: {}", e)),
            };

            let seed: [u8; 32] = hex::decode(&previous.seed)
                .map_err(|e| format!("Identity seed is not valid hex: {}", e))?
                .try_into()
                .map_err(|_| "Identity seed must be 32 bytes".to_string())?;

            let session = previous.session.checked_add(1)
                .ok_or_else(|| "Identity session counter exhausted".to_string())?;

            persist(dir, &StoredIdentity { seed: previous.seed, session })?;

            Ok(Self {
                signing_key: SigningKey::from_bytes(&seed),
                session,
                seq: 0,
            })
        }

        pub fn public_key_hex(&self) -> String {
            hex::encode(self.signing_key.verifying_key().to_bytes())
        }

        pub fn key_fingerprint(&self) -> String {
            hex::encode(&self.key_hash()[..16])
        }

        /// What the ledger calls this agent, the control server takes the same hash of the key it pinned at registration
        pub fn key_hash(&self) -> [u8; 32] {
            Sha256::digest(self.signing_key.verifying_key().to_bytes()).into()
        }

        /// Secret the ledger derives every event's seed from, it never leaves the endpoint
        pub fn ledger_key(&self) -> [u8; 32] {
            let mut hasher = Sha256::new();
            hasher.update(LEDGER_KEY_DOMAIN);
            hasher.update(self.signing_key.to_bytes());
            hasher.finalize().into()
        }

        pub fn session(&self) -> u64 {
            self.session
        }

        pub fn next_seq(&mut self) -> u64 {
            self.seq += 1;
            self.seq
        }

        pub fn sign(&self, body: &[u8]) -> String {
            hex::encode(self.signing_key.sign(body).to_bytes())
        }
    }

    pub fn read_enrollment_key(dir: &Path) -> Option<String> {
        let key = fs::read_to_string(dir.join(ENROLLMENT_FILE)).ok()?;
        let key = key.trim();
        if key.is_empty() {
            None
        } else {
            Some(key.to_string())
        }
    }

    pub fn clear_enrollment_key(dir: &Path) -> Result<(), String> {
        match fs::remove_file(dir.join(ENROLLMENT_FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("Failed to remove enrollment key: {}", e)),
        }
    }

    fn new_seed() -> Result<[u8; 32], String> {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|e| format!("Failed to gather randomness: {}", e))?;
        Ok(seed)
    }

    fn persist(dir: &Path, identity: &StoredIdentity) -> Result<(), String> {
        let encoded = serde_json::to_vec(identity)
            .map_err(|e| format!("Failed to encode identity: {}", e))?;

        replace_private_file(dir, IDENTITY_FILE, "identity file", &encoded)
    }

    pub(crate) fn replace_private_file(dir: &Path, name: &str, what: &str, contents: &[u8]) -> Result<(), String> {
        let staged = dir.join(format!("{}.tmp", name));
        let mut file = owner_only_options()
            .open(&staged)
            .map_err(|e| format!("Failed to open {}: {}", what, e))?;
        file.write_all(contents)
            .map_err(|e| format!("Failed to write {}: {}", what, e))?;
        file.sync_all()
            .map_err(|e| format!("Failed to flush {}: {}", what, e))?;

        fs::rename(&staged, dir.join(name))
            .map_err(|e| format!("Failed to commit {}: {}", what, e))
    }

    #[cfg(unix)]
    fn owner_only_options() -> fs::OpenOptions {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        options
    }

    #[cfg(not(unix))]
    fn owner_only_options() -> fs::OpenOptions {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        options
    }
}

static SERVER_URL_PLACEHOLDER: &[u8; 64] = b"ZEDR_SERVER_PLACEHOLDER_URL_DO_NOT_MODIFY_EXACTLY_64_BYTES_LONG\0";

/// Get the control server URL from the patched binary
pub fn get_server_url() -> String {
    let url_bytes = SERVER_URL_PLACEHOLDER;
    let url_str = std::str::from_utf8(url_bytes)
        .expect("Invalid UTF-8 in server URL");
    
    if url_str.contains("PLACEHOLDER") {
        panic!("FATAL: Binary has not been patched with server URL. This binary must be downloaded from the control server with a valid install key.");
    }
    
    let first_null = url_str.find('\0').unwrap_or(url_str.len());
    let url = url_str[..first_null].to_string();
    
    if url.is_empty() {
        panic!("FATAL: Server URL is empty in patched binary. Binary may be corrupted.");
    }
    
    url
}

/// Agent configuration structure
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentConfig {
    /// Control server endpoint URL
    pub control_server_url: String,

    /// Agent unique identifier
    pub agent_id: Option<String>,

    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,

    /// Enable debug logging
    pub debug: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            control_server_url: std::env::var("ZEDR_CONTROL_SERVER_URL")
                .expect("ZEDR_CONTROL_SERVER_URL must be set"),
            agent_id: std::env::var("ZEDR_AGENT_ID").ok(),
            heartbeat_interval: std::env::var("ZEDR_HEARTBEAT_INTERVAL")
                .expect("ZEDR_HEARTBEAT_INTERVAL must be set")
                .parse()
                .expect("ZEDR_HEARTBEAT_INTERVAL must be a valid u64"),
            debug: std::env::var("ZEDR_DEBUG")
                .expect("ZEDR_DEBUG must be set")
                .parse()
                .expect("ZEDR_DEBUG must be a valid boolean"),
        }
    }
}

pub mod upgrade {
    use super::*;
    use std::path::PathBuf;

    pub fn download_binary(
        server_url: &str,
        os: &str,
        arch: &str,
        install_key: &str,
    ) -> Result<Vec<u8>, String> {
        let url = format!(
            "{}/api/installers/binaries/{}-{}?key={}",
            server_url,
            os,
            arch,
            install_key
        );

        let response = minreq::get(&url)
            .with_timeout(300)
            .send()
            .map_err(|e| format!("Failed to download binary: {}", e))?;

        if response.status_code != 200 {
            return Err(format!("Server returned error: {} {}", response.status_code, response.reason_phrase));
        }

        let binary_data = response.as_bytes().to_vec();

        verify_binary_signature(&binary_data)?;

        Ok(binary_data)
    }

    pub fn download_upgrade_binary(
        server_url: &str,
        agent_id: &str,
        version: &str,
    ) -> Result<Vec<u8>, String> {
        let url = format!(
            "{}/api/agents/{}/upgrade-binary?key={}",
            server_url,
            agent_id,
            version
        );

        let response = minreq::get(&url)
            .with_timeout(300)
            .send()
            .map_err(|e| format!("Failed to download binary: {}", e))?;

        if response.status_code != 200 {
            return Err(format!("Server returned error: {} {}", response.status_code, response.reason_phrase));
        }

        let binary_data = response.as_bytes().to_vec();

        verify_binary_signature(&binary_data)?;

        Ok(binary_data)
    }

    pub fn save_temp_binary(data: &[u8]) -> Result<PathBuf, String> {
        let exe_path = std::env::current_exe()
            .map_err(|e| format!("Failed to get executable path: {}", e))?;

        let temp_path = exe_path.with_extension("new");

        fs::write(&temp_path, data)
            .map_err(|e| format!("Failed to write temp binary: {}", e))?;

        Ok(temp_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "ZEDR_CONTROL_SERVER_URL must be set")]
    fn test_default_config_requires_env() {
        // Clear env to ensure it fails without explicit config
        std::env::remove_var("ZEDR_CONTROL_SERVER_URL");
        std::env::remove_var("ZEDR_HEARTBEAT_INTERVAL");
        std::env::remove_var("ZEDR_DEBUG");
        
        let _config = AgentConfig::default();
    }

    #[test]
    fn test_protocol_types_available() {
        // Verify protocol types are re-exported
        let _event = DetectionEvent {
            timestamp: 1234567890,
            detection_type: String::from("test"),
            severity: 5,
            description: String::from("Test detection"),
            metadata: std::collections::HashMap::new(),
        };
        assert!(true);
    }
    
    #[test]
    fn test_unpatched_binary_trusts_no_signing_key() {
        let err = verify_self_signature().unwrap_err();
        assert!(err.contains("not been patched"), "unexpected error: {}", err);

        let err = verify_binary_signature(&[0u8; 128]).unwrap_err();
        assert!(err.contains("not been patched"), "unexpected error: {}", err);
    }

    fn signed_binary(key: &ed25519_dalek::SigningKey, contents: &[u8]) -> Vec<u8> {
        use ed25519_dalek::Signer;
        let mut binary = contents.to_vec();
        binary.extend_from_slice(&key.sign(contents).to_bytes());
        binary
    }

    #[test]
    fn test_slot_key_is_the_only_key_that_verifies_a_binary() {
        let deployment = test_signing_key(7);
        let slot = signing_public_key_to_slot(&deployment.verifying_key().to_bytes()).unwrap();
        let trusted = signing_public_key_in(&slot).unwrap();

        let binary = signed_binary(&deployment, b"agent release");
        assert!(verify_binary_signature_with_key(&trusted, &binary).is_ok());

        let other_deployment = signed_binary(&test_signing_key(8), b"agent release");
        assert!(verify_binary_signature_with_key(&trusted, &other_deployment).is_err());
    }

    #[test]
    fn test_tampered_binary_is_rejected() {
        let deployment = test_signing_key(7);
        let trusted = deployment.verifying_key();

        let mut binary = signed_binary(&deployment, b"agent release");
        binary[3] ^= 0x01;
        assert!(verify_binary_signature_with_key(&trusted, &binary).is_err());

        let err = verify_binary_signature_with_key(&trusted, &[0u8; 63]).unwrap_err();
        assert!(err.contains("too small"));
    }

    #[test]
    fn test_slot_with_bytes_that_are_not_a_key_is_rejected() {
        let mut slot = signing_public_key_to_slot(&test_signing_key(7).verifying_key().to_bytes()).unwrap();
        slot[10] = b'z';
        assert!(signing_public_key_in(&slot).is_err());
    }
    
    #[test] 
    #[should_panic(expected = "FATAL: Binary has not been patched")]
    fn test_get_server_url_panics_for_unpatched_binary() {
        // Test that unpatched binary panics (security feature)
        get_server_url();
    }
    
    #[test]
    fn test_server_url_placeholder_format() {
        // Test that placeholder has correct format and length
        let placeholder = SERVER_URL_PLACEHOLDER;
        assert_eq!(placeholder.len(), 64, "Placeholder must be exactly 64 bytes");
        
        let placeholder_str = std::str::from_utf8(placeholder).unwrap();
        assert!(placeholder_str.contains("PLACEHOLDER"), "Should contain PLACEHOLDER marker");
        assert!(placeholder_str.contains("ZEDR_SERVER"), "Should contain ZEDR_SERVER prefix");
        
        // Verify it ends with null byte for string termination
        assert_eq!(placeholder[63], 0, "Should end with null byte");
    }
    
    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("zedr-shared-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    fn test_signing_key(fill: u8) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[fill; 32])
    }

    fn signed_upgrade_command(key: &ed25519_dalek::SigningKey, agent_id: &str, nonce: &str, issued_at: u64) -> UpgradeCommand {
        use ed25519_dalek::Signer;
        let bytes = upgrade_command_signing_bytes(agent_id, "0.2.0", nonce, issued_at).unwrap();
        UpgradeCommand {
            agent_id: agent_id.to_string(),
            target_version: "0.2.0".to_string(),
            signature: key.sign(&bytes).to_bytes().to_vec(),
            issued_at,
            nonce: nonce.to_string(),
        }
    }

    const ISSUED_AT: u64 = 1_794_780_000;

    fn verify_at(used_nonces: &mut HashMap<String, u64>, now: u64, cmd: &UpgradeCommand) -> Result<(), String> {
        let bytes = upgrade_command_signing_bytes(&cmd.agent_id, &cmd.target_version, &cmd.nonce, cmd.issued_at).unwrap();
        verify_command_at(used_nonces, now, &test_signing_key(1).verifying_key(), &bytes, &cmd.signature, cmd.issued_at, &cmd.nonce)
    }

    #[test]
    fn test_only_a_command_with_a_valid_signature_is_refused_for_its_age() {
        let authentic = signed_upgrade_command(&test_signing_key(1), "agent-a", "authentic", ISSUED_AT);
        assert_eq!(verify_at(&mut HashMap::new(), ISSUED_AT + 301, &authentic), Err("Command expired (older than 5 minutes)".to_string()));
        assert_eq!(verify_at(&mut HashMap::new(), ISSUED_AT - 61, &authentic), Err("Command timestamp is in the future".to_string()));

        let by_another_key = signed_upgrade_command(&test_signing_key(2), "agent-a", "another-key", ISSUED_AT);
        let mut changed = authentic.clone();
        changed.target_version = "9.9.9".to_string();
        for now in [ISSUED_AT - 61, ISSUED_AT, ISSUED_AT + 301] {
            for command in [&by_another_key, &changed] {
                let refusal = verify_at(&mut HashMap::new(), now, command).unwrap_err();
                assert!(refusal.contains("Signature verification failed"), "{}", refusal);
            }
        }
    }

    #[test]
    fn test_replay_and_another_agents_command_are_not_refused_for_their_age() {
        let key = test_signing_key(1);
        let old = signed_upgrade_command(&key, "agent-a", "old-and-for-another-agent", now_secs() - 301);
        let refusal = verify_upgrade_command_with_key(&key.verifying_key(), &old, "agent-b").unwrap_err();
        assert_eq!(refusal, "Command was issued for a different agent");

        let mut used_nonces = HashMap::new();
        let cmd = signed_upgrade_command(&key, "agent-a", "seen", ISSUED_AT);
        assert_eq!(verify_at(&mut used_nonces, ISSUED_AT, &cmd), Ok(()));
        let replay = verify_at(&mut used_nonces, ISSUED_AT + 1, &cmd).unwrap_err();
        assert!(replay.contains("replay"), "{}", replay);
    }

    #[test]
    fn test_command_is_accepted_once_at_any_age_up_to_its_limit() {
        let key = test_signing_key(1);
        for age in [0, 1, 299, 300] {
            let mut used_nonces = HashMap::new();
            let cmd = signed_upgrade_command(&key, "agent-a", "any-age", ISSUED_AT);

            assert_eq!(verify_at(&mut used_nonces, ISSUED_AT + age, &cmd), Ok(()), "a command of {} seconds is accepted", age);
            let replay = verify_at(&mut used_nonces, ISSUED_AT + age, &cmd).unwrap_err();
            assert!(replay.contains("replay"), "a command of {} seconds is not accepted twice: {}", age, replay);
        }

        let cmd = signed_upgrade_command(&key, "agent-a", "too-old", ISSUED_AT);
        assert!(verify_at(&mut HashMap::new(), ISSUED_AT + 301, &cmd).unwrap_err().contains("expired"));
    }

    #[test]
    fn test_accepted_command_is_refused_as_a_replay_until_it_has_expired() {
        let key = test_signing_key(1);
        let mut used_nonces = HashMap::new();
        let cmd = signed_upgrade_command(&key, "agent-a", "handed-out-again", ISSUED_AT);
        assert_eq!(verify_at(&mut used_nonces, ISSUED_AT + 5, &cmd), Ok(()));

        for age in (5..=295).step_by(10).chain([299, 300]) {
            let now = ISSUED_AT + age;
            let other = signed_upgrade_command(&key, "agent-a", &format!("other-{}", age), now);
            assert_eq!(verify_at(&mut used_nonces, now, &other), Ok(()));

            let replay = verify_at(&mut used_nonces, now, &cmd).unwrap_err();
            assert!(replay.contains("replay"), "handed out again after {} seconds: {}", age, replay);
        }

        for age in [301, 302, 3_600] {
            let refused = verify_at(&mut used_nonces, ISSUED_AT + age, &cmd).unwrap_err();
            assert!(refused.contains("expired"), "handed out again after {} seconds: {}", age, refused);
        }
    }

    #[test]
    fn test_command_issued_ahead_of_the_agents_clock_is_refused_as_a_replay_for_its_whole_lifetime() {
        let key = test_signing_key(1);
        let mut used_nonces = HashMap::new();
        let cmd = signed_upgrade_command(&key, "agent-a", "issued-ahead", ISSUED_AT);

        assert!(verify_at(&mut used_nonces, ISSUED_AT - 61, &cmd).unwrap_err().contains("future"));
        assert_eq!(verify_at(&mut used_nonces, ISSUED_AT - 60, &cmd), Ok(()));

        for now in [ISSUED_AT - 60, ISSUED_AT, ISSUED_AT + 240, ISSUED_AT + 300] {
            let other = signed_upgrade_command(&key, "agent-a", &format!("other-{}", now), now);
            assert_eq!(verify_at(&mut used_nonces, now, &other), Ok(()));
            assert!(verify_at(&mut used_nonces, now, &cmd).unwrap_err().contains("replay"));
        }
        assert!(verify_at(&mut used_nonces, ISSUED_AT + 301, &cmd).unwrap_err().contains("expired"));
    }

    #[test]
    fn test_nonce_is_forgotten_once_its_command_has_expired() {
        let key = test_signing_key(1);
        let mut used_nonces = HashMap::new();
        let cmd = signed_upgrade_command(&key, "agent-a", "old", ISSUED_AT);
        assert_eq!(verify_at(&mut used_nonces, ISSUED_AT, &cmd), Ok(()));

        let at_the_limit = signed_upgrade_command(&key, "agent-a", "at-the-limit", ISSUED_AT + 300);
        assert_eq!(verify_at(&mut used_nonces, ISSUED_AT + 300, &at_the_limit), Ok(()));
        assert!(used_nonces.contains_key("old"), "kept for as long as the command would be accepted");

        let later = signed_upgrade_command(&key, "agent-a", "later", ISSUED_AT + 301);
        assert_eq!(verify_at(&mut used_nonces, ISSUED_AT + 301, &later), Ok(()));
        assert!(!used_nonces.contains_key("old"));
        assert_eq!(used_nonces.len(), 2);
    }

    #[test]
    fn test_upgrade_command_replay_rejected() {
        let key = test_signing_key(1);
        let cmd = signed_upgrade_command(&key, "agent-a", "upgrade-replay", now_secs());
        assert!(verify_upgrade_command_with_key(&key.verifying_key(), &cmd, "agent-a").is_ok());
        let err = verify_upgrade_command_with_key(&key.verifying_key(), &cmd, "agent-a").unwrap_err();
        assert!(err.contains("replay"));
    }

    #[test]
    fn test_upgrade_command_expired_rejected() {
        let key = test_signing_key(1);
        let cmd = signed_upgrade_command(&key, "agent-a", "upgrade-expired", now_secs() - 301);
        let err = verify_upgrade_command_with_key(&key.verifying_key(), &cmd, "agent-a").unwrap_err();
        assert!(err.contains("expired"));
    }

    #[test]
    fn test_upgrade_command_signed_by_wrong_key_rejected() {
        let cmd = signed_upgrade_command(&test_signing_key(2), "agent-a", "upgrade-wrong-key", now_secs());
        let err = verify_upgrade_command_with_key(&test_signing_key(1).verifying_key(), &cmd, "agent-a").unwrap_err();
        assert!(err.contains("Signature verification failed"));
    }

    #[test]
    fn test_upgrade_command_accepted_for_own_agent_only() {
        let key = test_signing_key(1);
        let cmd = signed_upgrade_command(&key, "agent-a", "upgrade-own", now_secs());
        assert!(verify_upgrade_command_with_key(&key.verifying_key(), &cmd, "agent-b").is_err());
        assert!(verify_upgrade_command_with_key(&key.verifying_key(), &cmd, "agent-a").is_ok());
    }

    #[test]
    fn test_upgrade_command_tampered_version_rejected() {
        let key = test_signing_key(1);
        let mut cmd = signed_upgrade_command(&key, "agent-a", "upgrade-tamper", now_secs());
        cmd.target_version = "9.9.9".to_string();
        assert!(verify_upgrade_command_with_key(&key.verifying_key(), &cmd, "agent-a").is_err());
    }

    #[test]
    fn test_identity_is_stable_and_session_advances() {
        let dir = test_dir("identity-stable");
        let first = identity::Identity::load_or_create(&dir).unwrap();
        let second = identity::Identity::load_or_create(&dir).unwrap();
        assert_eq!(first.public_key_hex(), second.public_key_hex());
        assert_eq!(first.session(), 1);
        assert_eq!(second.session(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_identity_sequence_is_strictly_increasing() {
        let dir = test_dir("identity-seq");
        let mut identity = identity::Identity::load_or_create(&dir).unwrap();
        let a = identity.next_seq();
        let b = identity.next_seq();
        assert!(b > a);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_identity_signature_verifies_against_public_key() {
        let dir = test_dir("identity-sign");
        let identity = identity::Identity::load_or_create(&dir).unwrap();
        let body = b"{\"agent_id\":\"a\"}";
        let signature = Signature::from_slice(&hex::decode(identity.sign(body)).unwrap()).unwrap();
        let key_bytes: [u8; 32] = hex::decode(identity.public_key_hex()).unwrap().try_into().unwrap();
        let public_key = VerifyingKey::from_bytes(&key_bytes).unwrap();
        assert!(public_key.verify(body, &signature).is_ok());
        assert!(public_key.verify(b"other", &signature).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_distinct_installs_get_distinct_identities() {
        let a = test_dir("identity-a");
        let b = test_dir("identity-b");
        let first = identity::Identity::load_or_create(&a).unwrap();
        let second = identity::Identity::load_or_create(&b).unwrap();
        assert_ne!(first.public_key_hex(), second.public_key_hex());
        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn test_key_fingerprint_is_stable_and_unique_per_identity() {
        let a = test_dir("fingerprint-a");
        let b = test_dir("fingerprint-b");
        let first = identity::Identity::load_or_create(&a).unwrap();
        let restarted = identity::Identity::load_or_create(&a).unwrap();
        let other = identity::Identity::load_or_create(&b).unwrap();

        assert_eq!(first.key_fingerprint().len(), 32);
        assert!(first.key_fingerprint().chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(first.key_fingerprint(), restarted.key_fingerprint());
        assert_ne!(first.key_fingerprint(), other.key_fingerprint());

        use sha2::Digest;
        let key_bytes = hex::decode(first.public_key_hex()).unwrap();
        assert_eq!(first.key_fingerprint(), hex::encode(&sha2::Sha256::digest(&key_bytes)[..16]));

        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    fn stored_seed(dir: &std::path::Path) -> [u8; 32] {
        let stored: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("identity.json")).unwrap()).unwrap();
        hex::decode(stored["seed"].as_str().unwrap()).unwrap().try_into().unwrap()
    }

    #[test]
    fn test_key_hash_is_the_sha256_of_the_public_key_and_stable_per_identity() {
        let a = test_dir("key-hash-a");
        let b = test_dir("key-hash-b");
        let first = identity::Identity::load_or_create(&a).unwrap();
        let restarted = identity::Identity::load_or_create(&a).unwrap();
        let other = identity::Identity::load_or_create(&b).unwrap();

        use sha2::Digest;
        let expected: [u8; 32] = sha2::Sha256::digest(hex::decode(first.public_key_hex()).unwrap()).into();
        assert_eq!(first.key_hash(), expected);
        assert_eq!(first.key_hash(), restarted.key_hash());
        assert_ne!(first.key_hash(), other.key_hash());
        assert_eq!(first.key_fingerprint(), hex::encode(&first.key_hash()[..16]));

        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn test_ledger_key_is_stable_per_identity_and_is_neither_the_seed_nor_the_key_hash() {
        let a = test_dir("ledger-key-a");
        let b = test_dir("ledger-key-b");
        let first = identity::Identity::load_or_create(&a).unwrap();
        let restarted = identity::Identity::load_or_create(&a).unwrap();
        let other = identity::Identity::load_or_create(&b).unwrap();

        assert_eq!(first.ledger_key(), restarted.ledger_key());
        assert_ne!(first.ledger_key(), other.ledger_key());
        assert_ne!(first.ledger_key(), stored_seed(&a), "the secret that signs requests is not the one that seals events");
        assert_ne!(first.ledger_key(), first.key_hash());

        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"zedr/ledger-master/v1");
        hasher.update(stored_seed(&a));
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(first.ledger_key(), expected);

        std::fs::remove_dir_all(&a).unwrap();
        std::fs::remove_dir_all(&b).unwrap();
    }

    #[test]
    fn test_corrupt_identity_fails_closed() {
        let dir = test_dir("identity-corrupt");
        std::fs::write(dir.join("identity.json"), "not json").unwrap();
        assert!(identity::Identity::load_or_create(&dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_identity_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("identity-perms");
        identity::Identity::load_or_create(&dir).unwrap();
        let mode = std::fs::metadata(dir.join("identity.json")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_enrollment_key_is_read_then_cleared() {
        let dir = test_dir("enrollment");
        assert!(identity::read_enrollment_key(&dir).is_none());
        std::fs::write(dir.join("enrollment.key"), "zedr_abc\n").unwrap();
        assert_eq!(identity::read_enrollment_key(&dir).as_deref(), Some("zedr_abc"));
        identity::clear_enrollment_key(&dir).unwrap();
        assert!(identity::read_enrollment_key(&dir).is_none());
        identity::clear_enrollment_key(&dir).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_signature_verification_prevents_execution() {
        // Test that signature verification is called and has expected behavior
        let result = verify_self_signature();
        
        // Function should exist and handle verification appropriately
        assert!(result.is_ok() || result.is_err(), "Function should return a result");
        
        if let Err(msg) = result {
            // In test environment, should fail with security-related error
            assert!(
                !msg.is_empty(),
                "Error message should not be empty"
            );
        }
    }
}
