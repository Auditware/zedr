use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};

use plist::Value;
use sha2::{Digest, Sha256};
use zedr_shared::sensor::PersistenceItem;
use zedr_shared::unix::{parse_authorized_keys, parse_crontab};
use zedr_shared::PersistenceKind;

use crate::files::{self, clip, file_name, Account, Listing, Loaded, UserNames};

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 256;

const LAUNCH_DAEMONS: &str = "/Library/LaunchDaemons";
const LAUNCH_AGENTS: &str = "/Library/LaunchAgents";
const LAUNCH_AGENTS_IN_HOME: &str = "Library/LaunchAgents";

const SYSTEM_CRONTAB: &str = "/etc/crontab";
const USER_CRONTABS: &str = "/usr/lib/cron/tabs";

const SYSTEM_PROFILES: [&str; 5] = ["/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/profile", "/etc/bashrc"];
const USER_PROFILES: [&str; 6] = [".bashrc", ".profile", ".bash_profile", ".zshenv", ".zprofile", ".zshrc"];
const AUTHORIZED_KEYS: [&str; 2] = [".ssh/authorized_keys", ".ssh/authorized_keys2"];

const ROOT: &str = "root";
const ROOT_HOME: &str = "/var/root";
const EVERY_USER: &str = "";

#[derive(Debug, PartialEq, Eq)]
pub struct LaunchJob {
    pub label: Option<String>,
    pub command: String,
    pub user: Option<String>,
    pub disabled: bool,
}

/// What launchd reads from a job definition, XML or binary. `Program` is what runs, `ProgramArguments` its argument vector,
/// so when both are set the first argument is only the name the program sees. launchd starts no job without a label and a program
pub fn parse_launch_job(bytes: &[u8]) -> Option<LaunchJob> {
    let value = Value::from_reader(Cursor::new(bytes)).ok()?;
    let job = value.as_dictionary()?;
    let text = |key: &str| job.get(key).and_then(Value::as_string).map(str::to_string);

    let arguments: Vec<&str> =
        job.get("ProgramArguments").and_then(Value::as_array).map(|list| list.iter().filter_map(Value::as_string).collect()).unwrap_or_default();
    let command = match job.get("Program").and_then(Value::as_string) {
        Some(program) => std::iter::once(program).chain(arguments.iter().skip(1).copied()).collect::<Vec<&str>>().join(" "),
        None => arguments.join(" "),
    };

    Some(LaunchJob { label: text("Label"), command, user: text("UserName"), disabled: job.get("Disabled").and_then(Value::as_boolean).unwrap_or(false) })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn label(text: &str) -> String {
    if text.len() <= MAX_NAME_BYTES {
        return text.to_string();
    }
    format!("{} {}", clip(text, MAX_NAME_BYTES), clip(&sha256_hex(text.as_bytes()), 16))
}

fn item(kind: PersistenceKind, name: &str, path: &Path, command: &str, user: &str, enabled: bool, hash: Option<String>) -> PersistenceItem {
    PersistenceItem {
        kind,
        name: name.to_string(),
        path: path.to_string_lossy().into_owned(),
        command: clip(command, MAX_COMMAND_BYTES).to_string(),
        user: clip(user, MAX_NAME_BYTES).to_string(),
        enabled,
        hash,
    }
}

fn unreadable(kind: PersistenceKind, path: &Path, user: &str) -> PersistenceItem {
    item(kind, &file_name(path), path, "", user, true, None)
}

/// Who a job runs as: the user its folder belongs to, or for a daemon the user it names
enum Owner<'a> {
    Daemon,
    Agent(&'a str),
}

struct Scan<'a> {
    root: &'a Path,
    items: Vec<PersistenceItem>,
}

impl Scan<'_> {
    fn load(&self, path: &Path) -> Loaded {
        files::load(self.root, path, MAX_FILE_BYTES)
    }

    fn entries(&mut self, kind: PersistenceKind, directory: &Path, user: &str) -> Vec<PathBuf> {
        match files::list(self.root, directory) {
            Listing::Entries(names) => names.iter().map(|name| directory.join(name)).collect(),
            Listing::Missing => Vec::new(),
            Listing::Unreadable => {
                self.items.push(unreadable(kind, directory, user));
                Vec::new()
            }
        }
    }

    fn whole_file(&mut self, kind: PersistenceKind, path: &Path, user: &str) {
        match self.load(path) {
            Loaded::File(bytes) => self.items.push(item(kind, &file_name(path), path, "", user, true, Some(sha256_hex(&bytes)))),
            Loaded::Unreadable => self.items.push(unreadable(kind, path, user)),
            Loaded::Missing => {}
        }
    }

    fn launch_jobs(&mut self, kind: PersistenceKind, directory: &Path, owner: Owner) {
        let folder_user = match owner {
            Owner::Daemon => ROOT,
            Owner::Agent(user) => user,
        };

        for path in self.entries(kind, directory, folder_user) {
            let bytes = match self.load(&path) {
                Loaded::File(bytes) => bytes,
                Loaded::Unreadable => {
                    self.items.push(unreadable(kind, &path, folder_user));
                    continue;
                }
                Loaded::Missing => continue,
            };
            let hash = Some(sha256_hex(&bytes));

            let Some(job) = parse_launch_job(&bytes) else {
                self.items.push(item(kind, &file_name(&path), &path, "", folder_user, false, hash));
                continue;
            };

            let name = job.label.as_deref().map_or_else(|| file_name(&path), label);
            let user = match owner {
                Owner::Daemon => job.user.as_deref().unwrap_or(ROOT),
                Owner::Agent(user) => user,
            };
            let starts = job.label.is_some() && !job.command.is_empty() && !job.disabled;
            self.items.push(item(kind, &name, &path, &job.command, user, starts, hash));
        }
    }

    fn launchd(&mut self, accounts: &[Account]) {
        self.launch_jobs(PersistenceKind::LaunchDaemon, Path::new(LAUNCH_DAEMONS), Owner::Daemon);
        self.launch_jobs(PersistenceKind::LaunchAgent, Path::new(LAUNCH_AGENTS), Owner::Agent(EVERY_USER));
        for account in accounts {
            self.launch_jobs(PersistenceKind::LaunchAgent, &account.home.join(LAUNCH_AGENTS_IN_HOME), Owner::Agent(&account.name));
        }
    }

    fn crontab(&mut self, path: &Path, owner: Option<&str>) {
        let bytes = match self.load(path) {
            Loaded::File(bytes) => bytes,
            Loaded::Unreadable => return self.items.push(unreadable(PersistenceKind::Cron, path, owner.unwrap_or(ROOT))),
            Loaded::Missing => return,
        };

        for entry in parse_crontab(&String::from_utf8_lossy(&bytes), owner.is_none()) {
            let user = entry.user.as_deref().or(owner).unwrap_or(ROOT);
            let hash = sha256_hex(entry.entry.as_bytes());
            self.items.push(item(PersistenceKind::Cron, &label(&entry.entry), path, &entry.command, user, true, Some(hash)));
        }
    }

    fn cron(&mut self) {
        self.crontab(Path::new(SYSTEM_CRONTAB), None);
        for path in self.entries(PersistenceKind::Cron, Path::new(USER_CRONTABS), ROOT) {
            self.crontab(&path, Some(&file_name(&path)));
        }
    }

    fn shell_profiles(&mut self, accounts: &[Account]) {
        for profile in SYSTEM_PROFILES {
            self.whole_file(PersistenceKind::ShellProfile, Path::new(profile), EVERY_USER);
        }
        for account in accounts {
            for profile in USER_PROFILES {
                self.whole_file(PersistenceKind::ShellProfile, &account.home.join(profile), &account.name);
            }
        }
    }

    fn authorized_keys(&mut self, accounts: &[Account]) {
        for account in accounts {
            for file in AUTHORIZED_KEYS {
                let path = account.home.join(file);
                let bytes = match self.load(&path) {
                    Loaded::File(bytes) => bytes,
                    Loaded::Unreadable => {
                        self.items.push(unreadable(PersistenceKind::AuthorizedKey, &path, &account.name));
                        continue;
                    }
                    Loaded::Missing => continue,
                };

                for key in parse_authorized_keys(&String::from_utf8_lossy(&bytes)) {
                    let name = format!("{} {} {}", key.key_type, key.fingerprint, key.comment);
                    self.items.push(item(
                        PersistenceKind::AuthorizedKey,
                        clip(name.trim_end(), MAX_NAME_BYTES),
                        &path,
                        &key.forced_command,
                        &account.name,
                        true,
                        Some(key.hash),
                    ));
                }
            }
        }
    }
}

/// Every account whose startup files and keys are read: root, whose home is not in /Users, and the accounts there
fn accounts(root: &Path, user_names: UserNames) -> Vec<Account> {
    let mut accounts = vec![Account { name: ROOT.to_string(), home: PathBuf::from(ROOT_HOME) }];
    accounts.extend(files::accounts(root, user_names));
    accounts
}

pub fn scan(root: &Path, user_names: UserNames) -> Result<Vec<PersistenceItem>, String> {
    let library = files::inside(root, Path::new("/Library"));
    fs::read_dir(&library).map_err(|e| format!("Failed to read {}: {}", library.display(), e))?;

    let mut scan = Scan { root, items: Vec::new() };
    let accounts = accounts(root, user_names);
    scan.launchd(&accounts);
    scan.cron();
    scan.shell_profiles(&accounts);
    scan.authorized_keys(&accounts);

    Ok(scan.items)
}
