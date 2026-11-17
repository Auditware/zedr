use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zedr_shared::sensor::PersistenceItem;
use zedr_shared::unix::{parse_authorized_keys, parse_crontab};
use zedr_shared::PersistenceKind;

use crate::files::{self, clip, locate, Opened};

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_LIBRARY_BYTES: u64 = 64 * 1024 * 1024;
const MAX_COMMAND_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 256;

const SYSTEM_UNITS: [&str; 5] =
    ["/etc/systemd/system", "/run/systemd/system", "/usr/local/lib/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"];
const USER_UNITS: [&str; 4] = ["/etc/systemd/user", "/run/systemd/user", "/usr/local/lib/systemd/user", "/usr/lib/systemd/user"];
const USER_UNITS_IN_HOME: &str = ".config/systemd/user";
const MASKED: &str = "/dev/null";

const SYSTEM_CRONTABS: &str = "/etc/crontab";
const SYSTEM_CRONTAB_DIRECTORY: &str = "/etc/cron.d";
const USER_CRONTAB_DIRECTORIES: [&str; 3] = ["/var/spool/cron/crontabs", "/var/spool/cron", "/etc/crontabs"];
const PERIODIC_DIRECTORIES: [&str; 4] = ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"];

const SYSTEM_PROFILES: [&str; 2] = ["/etc/profile", "/etc/bash.bashrc"];
const SYSTEM_PROFILE_DIRECTORY: &str = "/etc/profile.d";
const USER_PROFILES: [&str; 4] = [".bashrc", ".profile", ".bash_profile", ".zshrc"];
const AUTHORIZED_KEYS: [&str; 2] = [".ssh/authorized_keys", ".ssh/authorized_keys2"];

const PRELOAD: &str = "/etc/ld.so.preload";
const RC_LOCAL: &str = "/etc/rc.local";
const INIT_SCRIPTS: &str = "/etc/init.d";
const START_LEVELS: [&str; 5] = ["/etc/rcS.d", "/etc/rc2.d", "/etc/rc3.d", "/etc/rc4.d", "/etc/rc5.d"];
const OPENRC_LEVELS: &str = "/etc/runlevels";

const ROOT: &str = "root";
const EVERY_USER: &str = "";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Unit {
    pub exec_start: Vec<String>,
    pub user: Option<String>,
    pub activates: Option<String>,
}

pub fn parse_unit(fragments: &[&str]) -> Unit {
    let mut unit = Unit::default();

    for fragment in fragments {
        let mut section = String::new();
        let mut continued = String::new();

        for line in fragment.lines().map(str::trim) {
            if line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some(head) = line.strip_suffix('\\') {
                continued.push_str(head.trim_end());
                continued.push(' ');
                continue;
            }

            let logical = format!("{}{}", std::mem::take(&mut continued), line);
            let logical = logical.trim();
            if let Some(name) = logical.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) {
                section = name.to_string();
                continue;
            }
            let Some((key, value)) = logical.split_once('=') else {
                continue;
            };
            let value = value.trim();

            match (section.as_str(), key.trim()) {
                ("Service", "ExecStart") if value.is_empty() => unit.exec_start.clear(),
                ("Service", "ExecStart") => unit.exec_start.push(value.to_string()),
                ("Service", "User") => unit.user = (!value.is_empty()).then(|| value.to_string()),
                ("Timer", "Unit") => unit.activates = (!value.is_empty()).then(|| value.to_string()),
                _ => {}
            }
        }
    }

    unit
}

pub fn parse_preload(contents: &str) -> Vec<String> {
    contents
        .lines()
        .filter_map(|line| line.split('#').next())
        .flat_map(|line| line.split(|character: char| character.is_whitespace() || character == ':'))
        .filter(|library| !library.is_empty())
        .map(str::to_string)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub home: PathBuf,
}

pub fn parse_accounts(passwd: &str) -> Vec<Account> {
    let mut homes = HashSet::new();
    passwd
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.split(':').collect();
            let name = fields.first().filter(|name| !name.is_empty() && !name.starts_with('#'))?;
            let home = fields.get(5).filter(|home| home.starts_with('/'))?;
            homes.insert(*home).then(|| Account { name: name.to_string(), home: PathBuf::from(home) })
        })
        .collect()
}

pub fn started_by(link: &str) -> Option<String> {
    let script = link.strip_prefix('S')?.trim_start_matches(|character: char| character.is_ascii_digit());
    (!script.is_empty()).then(|| script.to_string())
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

fn file_name(path: &Path) -> String {
    match path.file_name() {
        Some(name) => name.to_string_lossy().into_owned(),
        None => path.to_string_lossy().into_owned(),
    }
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

struct Contents {
    bytes: Vec<u8>,
    executable: bool,
}

impl Contents {
    fn text(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.bytes)
    }
}

enum Loaded {
    Missing,
    Unreadable,
    File(Contents),
}

enum Listing {
    Missing,
    Unreadable,
    Entries(Vec<OsString>),
}

struct UnitFile {
    kind: PersistenceKind,
    name: String,
    path: PathBuf,
    effective: bool,
    unit: Unit,
    hash: String,
}

struct Scan<'a> {
    root: &'a Path,
    items: Vec<PersistenceItem>,
}

impl Scan<'_> {
    fn load(&self, path: &Path) -> Loaded {
        let (file, metadata) = match files::open(self.root, path) {
            Opened::File(file, metadata) => (file, metadata),
            Opened::Missing => return Loaded::Missing,
            Opened::Unreadable => return Loaded::Unreadable,
        };

        let mut bytes = Vec::new();
        match file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes) {
            Ok(read) if read as u64 <= MAX_FILE_BYTES => Loaded::File(Contents { bytes, executable: metadata.permissions().mode() & 0o111 != 0 }),
            _ => Loaded::Unreadable,
        }
    }

    fn digest(&self, path: &Path) -> Option<String> {
        let Opened::File(file, metadata) = files::open(self.root, path) else {
            return None;
        };
        if metadata.len() > MAX_LIBRARY_BYTES {
            return None;
        }

        let mut hasher = Sha256::new();
        io::copy(&mut file.take(MAX_LIBRARY_BYTES), &mut hasher).ok()?;
        Some(hex::encode(hasher.finalize()))
    }

    fn list(&self, directory: &Path) -> Listing {
        let Some(location) = locate(self.root, directory) else {
            return Listing::Unreadable;
        };

        match fs::read_dir(location) {
            Ok(entries) => {
                let mut names: Vec<OsString> =
                    entries.flatten().map(|entry| entry.file_name()).filter(|name| !name.to_string_lossy().starts_with('.')).collect();
                names.sort();
                Listing::Entries(names)
            }
            Err(e) if files::is_absent(&e) => Listing::Missing,
            Err(_) => Listing::Unreadable,
        }
    }

    fn names_in(&self, directory: &Path) -> Vec<OsString> {
        match self.list(directory) {
            Listing::Entries(names) => names,
            Listing::Missing | Listing::Unreadable => Vec::new(),
        }
    }

    fn entries(&mut self, kind: PersistenceKind, directory: &Path, user: &str) -> Vec<PathBuf> {
        match self.list(directory) {
            Listing::Entries(names) => names.iter().map(|name| directory.join(name)).collect(),
            Listing::Missing => Vec::new(),
            Listing::Unreadable => {
                self.items.push(unreadable(kind, directory, user));
                Vec::new()
            }
        }
    }

    fn distinct<'d>(&self, directories: &'d [PathBuf]) -> Vec<&'d PathBuf> {
        let mut visited = HashSet::new();
        directories.iter().filter(|directory| visited.insert(locate(self.root, directory))).collect()
    }

    fn link_target(&self, path: &Path) -> Option<PathBuf> {
        let parent = locate(self.root, path.parent()?)?;
        fs::read_link(parent.join(path.file_name()?)).ok()
    }

    fn whole_file(&mut self, kind: PersistenceKind, path: &Path, user: &str, enabled: impl FnOnce(&Contents) -> bool) {
        match self.load(path) {
            Loaded::File(contents) => {
                let hash = sha256_hex(&contents.bytes);
                self.items.push(item(kind, &file_name(path), path, "", user, enabled(&contents), Some(hash)));
            }
            Loaded::Unreadable => self.items.push(unreadable(kind, path, user)),
            Loaded::Missing => {}
        }
    }

    fn accounts(&self) -> Vec<Account> {
        match self.load(Path::new("/etc/passwd")) {
            Loaded::File(passwd) => parse_accounts(&passwd.text()),
            Loaded::Missing | Loaded::Unreadable => Vec::new(),
        }
    }

    fn units(&mut self, directories: &[PathBuf], owner: &str) {
        let locations: HashSet<PathBuf> = directories.iter().filter_map(|directory| locate(self.root, directory)).collect();
        let mut sources = Vec::new();
        let mut decided = HashSet::new();
        let mut started = HashSet::new();
        let mut drop_ins: BTreeMap<String, BTreeMap<OsString, Contents>> = BTreeMap::new();

        for directory in self.distinct(directories) {
            for path in self.entries(PersistenceKind::SystemdUnit, directory, owner) {
                let name = file_name(&path);

                if name.ends_with(".wants") || name.ends_with(".requires") {
                    for link in self.names_in(&path) {
                        let link = path.join(link);
                        started.extend(self.link_target(&link).map(|target| file_name(&target)));
                        started.insert(file_name(&link));
                    }
                    continue;
                }

                if let Some(unit) = name.strip_suffix(".d") {
                    for fragment in self.names_in(&path) {
                        if !fragment.to_string_lossy().ends_with(".conf") {
                            continue;
                        }
                        if let Loaded::File(contents) = self.load(&path.join(&fragment)) {
                            drop_ins.entry(unit.to_string()).or_default().entry(fragment).or_insert(contents);
                        }
                    }
                    continue;
                }

                let kind = match name.rsplit_once('.') {
                    Some((_, "service")) => PersistenceKind::SystemdUnit,
                    Some((_, "timer")) => PersistenceKind::SystemdTimer,
                    _ => continue,
                };

                if let Some(target) = self.link_target(&path) {
                    if target == Path::new(MASKED) {
                        decided.insert(name);
                        continue;
                    }
                    let is_alias = |location: PathBuf| location.parent().is_some_and(|parent| locations.contains(parent));
                    if locate(self.root, &path).is_some_and(is_alias) {
                        continue;
                    }
                }

                match self.load(&path) {
                    Loaded::File(contents) => sources.push((kind, decided.insert(name.clone()), name, path, contents)),
                    Loaded::Unreadable => self.items.push(unreadable(kind, &path, owner)),
                    Loaded::Missing => {}
                }
            }
        }

        let files: Vec<UnitFile> = sources
            .into_iter()
            .map(|(kind, effective, name, path, contents)| {
                let fragments: Vec<&Contents> = std::iter::once(&contents).chain(drop_ins.get(&name).into_iter().flat_map(BTreeMap::values)).collect();
                let texts: Vec<Cow<str>> = fragments.iter().map(|fragment| fragment.text()).collect();
                let texts: Vec<&str> = texts.iter().map(|text| text.as_ref()).collect();
                let mut hasher = Sha256::new();
                for fragment in &fragments {
                    hasher.update(&fragment.bytes);
                }

                UnitFile { kind, name, path, effective, unit: parse_unit(&texts), hash: hex::encode(hasher.finalize()) }
            })
            .collect();

        for file in &files {
            let runs = match file.kind {
                PersistenceKind::SystemdTimer => {
                    let activated = match &file.unit.activates {
                        Some(activated) => activated.clone(),
                        None => format!("{}.service", file.name.trim_end_matches(".timer")),
                    };
                    files.iter().find(|other| other.effective && other.name == activated).map(|other| &other.unit)
                }
                _ => Some(&file.unit),
            };
            let command = runs.map(|unit| unit.exec_start.join("\n")).unwrap_or_default();
            let user = runs.and_then(|unit| unit.user.as_deref()).unwrap_or(owner);
            let enabled = file.effective && started.contains(&file.name);

            self.items.push(item(file.kind, &file.name, &file.path, &command, user, enabled, Some(file.hash.clone())));
        }
    }

    fn systemd(&mut self, accounts: &[Account]) {
        self.units(&SYSTEM_UNITS.map(PathBuf::from), ROOT);
        self.units(&USER_UNITS.map(PathBuf::from), EVERY_USER);
        for account in accounts {
            self.units(&[account.home.join(USER_UNITS_IN_HOME)], &account.name);
        }
    }

    fn crontab(&mut self, path: &Path, owner: Option<&str>) {
        let contents = match self.load(path) {
            Loaded::File(contents) => contents,
            Loaded::Unreadable => return self.items.push(unreadable(PersistenceKind::Cron, path, owner.unwrap_or(ROOT))),
            Loaded::Missing => return,
        };

        for entry in parse_crontab(&contents.text(), owner.is_none()) {
            let user = entry.user.as_deref().or(owner).unwrap_or(ROOT);
            let hash = sha256_hex(entry.entry.as_bytes());
            self.items.push(item(PersistenceKind::Cron, &label(&entry.entry), path, &entry.command, user, true, Some(hash)));
        }
    }

    fn cron(&mut self) {
        self.crontab(Path::new(SYSTEM_CRONTABS), None);
        for path in self.entries(PersistenceKind::Cron, Path::new(SYSTEM_CRONTAB_DIRECTORY), ROOT) {
            self.crontab(&path, None);
        }

        for directory in self.distinct(&USER_CRONTAB_DIRECTORIES.map(PathBuf::from)) {
            for path in self.entries(PersistenceKind::Cron, directory, ROOT) {
                self.crontab(&path, Some(&file_name(&path)));
            }
        }

        for directory in PERIODIC_DIRECTORIES {
            for path in self.entries(PersistenceKind::Cron, Path::new(directory), ROOT) {
                self.whole_file(PersistenceKind::Cron, &path, ROOT, |script| script.executable);
            }
        }
    }

    fn shell_profiles(&mut self, accounts: &[Account]) {
        for profile in SYSTEM_PROFILES {
            self.whole_file(PersistenceKind::ShellProfile, Path::new(profile), EVERY_USER, |_| true);
        }
        for path in self.entries(PersistenceKind::ShellProfile, Path::new(SYSTEM_PROFILE_DIRECTORY), EVERY_USER) {
            self.whole_file(PersistenceKind::ShellProfile, &path, EVERY_USER, |_| true);
        }
        for account in accounts {
            for profile in USER_PROFILES {
                self.whole_file(PersistenceKind::ShellProfile, &account.home.join(profile), &account.name, |_| true);
            }
        }
    }

    fn authorized_keys(&mut self, accounts: &[Account]) {
        for account in accounts {
            for file in AUTHORIZED_KEYS {
                let path = account.home.join(file);
                let contents = match self.load(&path) {
                    Loaded::File(contents) => contents,
                    Loaded::Unreadable => {
                        self.items.push(unreadable(PersistenceKind::AuthorizedKey, &path, &account.name));
                        continue;
                    }
                    Loaded::Missing => continue,
                };

                for key in parse_authorized_keys(&contents.text()) {
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

    fn preloaded_libraries(&mut self) {
        let path = Path::new(PRELOAD);
        let contents = match self.load(path) {
            Loaded::File(contents) => contents,
            Loaded::Unreadable => return self.items.push(unreadable(PersistenceKind::LdPreload, path, ROOT)),
            Loaded::Missing => return,
        };

        for library in parse_preload(&contents.text()) {
            let hash = self.digest(Path::new(&library));
            self.items.push(item(PersistenceKind::LdPreload, &label(&library), path, "", ROOT, true, hash));
        }
    }

    fn boot_scripts(&mut self) {
        self.whole_file(PersistenceKind::RcLocal, Path::new(RC_LOCAL), ROOT, |script| script.executable);

        let mut started: HashSet<String> =
            START_LEVELS.iter().flat_map(|level| self.names_in(Path::new(level))).filter_map(|link| started_by(&link.to_string_lossy())).collect();
        for level in self.names_in(Path::new(OPENRC_LEVELS)) {
            let services = self.names_in(&Path::new(OPENRC_LEVELS).join(level));
            started.extend(services.iter().map(|service| service.to_string_lossy().into_owned()));
        }

        for path in self.entries(PersistenceKind::InitScript, Path::new(INIT_SCRIPTS), ROOT) {
            let enabled = started.contains(&file_name(&path));
            self.whole_file(PersistenceKind::InitScript, &path, ROOT, |_| enabled);
        }
    }
}

pub fn scan(root: &Path) -> Result<Vec<PersistenceItem>, String> {
    let configuration = root.join("etc");
    fs::read_dir(&configuration).map_err(|e| format!("Failed to read {}: {}", configuration.display(), e))?;

    let mut scan = Scan { root, items: Vec::new() };
    let accounts = scan.accounts();
    scan.systemd(&accounts);
    scan.cron();
    scan.shell_profiles(&accounts);
    scan.authorized_keys(&accounts);
    scan.preloaded_libraries();
    scan.boot_scripts();

    Ok(scan.items)
}
