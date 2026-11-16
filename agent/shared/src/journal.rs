use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zedr_protocol::UpgradeCommand;

use crate::identity::replace_private_file;

const JOURNAL_FILE: &str = "accepted-commands.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AcceptedCommand {
    nonce: String,
    issued_at: u64,
}

pub struct CommandJournal {
    dir: PathBuf,
    commands: Vec<AcceptedCommand>,
}

impl CommandJournal {
    pub fn open(dir: &Path) -> Result<Self, String> {
        let commands = match fs::read_to_string(dir.join(JOURNAL_FILE)) {
            Ok(raw) => serde_json::from_str(&raw).map_err(|e| format!("Record of accepted commands is corrupt: {}", e))?,
            Err(e) if e.kind() == ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(format!("Failed to read the record of accepted commands: {}", e)),
        };

        Ok(Self { dir: dir.to_path_buf(), commands })
    }

    pub fn accept_upgrade(&mut self, command: &UpgradeCommand, now: u64) -> Result<(), String> {
        if self.commands.iter().any(|accepted| accepted.nonce == command.nonce) {
            return Err("Command was already accepted by this agent".to_string());
        }

        self.commands.push(AcceptedCommand { nonce: command.nonce.clone(), issued_at: command.issued_at });

        let written = self.persist(now);
        if written.is_err() {
            self.commands.retain(|accepted| accepted.nonce != command.nonce);
        }
        written
    }

    fn persist(&mut self, now: u64) -> Result<(), String> {
        self.commands.retain(|command| !crate::command_expired(command.issued_at, now));

        let encoded = serde_json::to_vec(&self.commands).map_err(|e| format!("Failed to encode the record of accepted commands: {}", e))?;
        replace_private_file(&self.dir, JOURNAL_FILE, "record of accepted commands", &encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUED_AT: u64 = 1_794_780_000;

    fn state_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zedr-journal-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn upgrade(nonce: &str, issued_at: u64) -> UpgradeCommand {
        UpgradeCommand { agent_id: "agent-a".to_string(), target_version: "0.2.0".to_string(), signature: Vec::new(), issued_at, nonce: nonce.to_string() }
    }

    fn nonces(commands: &[AcceptedCommand]) -> Vec<&str> {
        commands.iter().map(|command| command.nonce.as_str()).collect()
    }

    #[test]
    fn test_accepted_command_is_refused_by_the_process_that_comes_after() {
        let dir = state_dir("restart");
        let mut journal = CommandJournal::open(&dir).unwrap();
        assert_eq!(journal.accept_upgrade(&upgrade("u-1", ISSUED_AT), ISSUED_AT + 1), Ok(()));

        let mut after_restart = CommandJournal::open(&dir).unwrap();
        let refused = after_restart.accept_upgrade(&upgrade("u-1", ISSUED_AT), ISSUED_AT + 2).unwrap_err();
        assert!(refused.contains("already accepted"), "{}", refused);
        assert_eq!(after_restart.accept_upgrade(&upgrade("u-2", ISSUED_AT), ISSUED_AT + 2), Ok(()));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_accepted_command_is_forgotten_once_it_has_expired() {
        let dir = state_dir("forgotten");
        let mut journal = CommandJournal::open(&dir).unwrap();
        journal.accept_upgrade(&upgrade("old", ISSUED_AT), ISSUED_AT).unwrap();

        journal.accept_upgrade(&upgrade("at-the-limit", ISSUED_AT + 300), ISSUED_AT + 300).unwrap();
        assert!(journal.accept_upgrade(&upgrade("old", ISSUED_AT), ISSUED_AT + 300).is_err(), "kept for as long as the command would be accepted");

        journal.accept_upgrade(&upgrade("later", ISSUED_AT + 301), ISSUED_AT + 301).unwrap();
        let after_restart = CommandJournal::open(&dir).unwrap();
        assert_eq!(nonces(&after_restart.commands), vec!["at-the-limit", "later"]);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_record_written_by_an_earlier_agent_version_is_read() {
        let dir = state_dir("earlier-version");
        fs::write(dir.join(JOURNAL_FILE), format!("[{{\"nonce\":\"u-1\",\"issued_at\":{},\"answered\":true}}]", ISSUED_AT)).unwrap();

        let mut journal = CommandJournal::open(&dir).unwrap();
        let refused = journal.accept_upgrade(&upgrade("u-1", ISSUED_AT), ISSUED_AT + 1).unwrap_err();
        assert!(refused.contains("already accepted"), "{}", refused);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_command_that_cannot_be_recorded_is_not_accepted() {
        let dir = state_dir("unwritable");
        let mut journal = CommandJournal::open(&dir).unwrap();
        fs::remove_dir_all(&dir).unwrap();

        let refused = journal.accept_upgrade(&upgrade("u-1", ISSUED_AT), ISSUED_AT).unwrap_err();
        assert!(refused.contains("record of accepted commands"), "{}", refused);
        assert!(journal.commands.is_empty());
    }

    #[test]
    fn test_record_that_cannot_be_read_is_an_error() {
        let dir = state_dir("corrupt");
        fs::write(dir.join(JOURNAL_FILE), "[{\"nonce\":").unwrap();

        let refused = CommandJournal::open(&dir).err().unwrap();
        assert!(refused.contains("corrupt"), "{}", refused);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn test_record_is_readable_by_its_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = state_dir("permissions");
        let mut journal = CommandJournal::open(&dir).unwrap();
        journal.accept_upgrade(&upgrade("u-1", ISSUED_AT), ISSUED_AT).unwrap();

        let mode = fs::metadata(dir.join(JOURNAL_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!dir.join(format!("{}.tmp", JOURNAL_FILE)).exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
