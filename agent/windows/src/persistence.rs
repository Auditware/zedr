use std::fs;
use std::path::{Path, PathBuf};

use winreg::types::FromRegValue;
use winreg::RegKey;
use zedr_shared::sensor::PersistenceItem;
use zedr_shared::windows_text::{self, clip};
use zedr_shared::PersistenceKind;

use crate::hashing::{sha256_hex, HashCache};
use crate::registry::{self, Environment, Hive, Profile, MAX_COMMAND_BYTES, MAX_NAME_BYTES};

const MAX_TASK_BYTES: u64 = 1024 * 1024;
const MAX_TASK_DEPTH: usize = 8;
const MAX_TASKS: usize = 16_384;
const MAX_SERVICES: usize = 8_192;
const MAX_RUN_VALUES: usize = 1_024;
const MAX_STARTUP_FILES: usize = 1_024;

const EVERY_USER: &str = "";
const SYSTEM_ACCOUNT: &str = "SYSTEM";

const RUN_KEYS: [&str; 2] = [r"Microsoft\Windows\CurrentVersion\Run", r"Microsoft\Windows\CurrentVersion\RunOnce"];
const SERVICES: &str = r"SYSTEM\CurrentControlSet\Services";
const COMMON_STARTUP: &str = r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp";
const USER_STARTUP: &str = r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup";

/// Start values at which Windows starts a service or loads a driver by itself: boot, system and automatic. Manual is 3, disabled 4
const AUTOMATIC_START: [u32; 3] = [0, 1, 2];
/// A service runs as an account, a driver in the kernel, and the type tells them apart
const SERVICE_TYPES: u32 = 0x10 | 0x20;

fn item(kind: PersistenceKind, name: &str, path: &str, command: &str, user: &str, enabled: bool, hash: Option<String>) -> PersistenceItem {
    PersistenceItem {
        kind,
        name: clip(name, MAX_NAME_BYTES).to_string(),
        path: path.to_string(),
        command: clip(command, MAX_COMMAND_BYTES).to_string(),
        user: clip(user, MAX_NAME_BYTES).to_string(),
        enabled,
        hash,
    }
}

/// What is reported for something that is there and cannot be read, so that it is not mistaken for gone
fn unreadable(kind: PersistenceKind, name: &str, path: &str, user: &str) -> PersistenceItem {
    item(kind, name, path, "", user, true, None)
}

struct Scan<'a> {
    hashes: &'a mut HashCache,
    items: Vec<PersistenceItem>,
}

impl Scan<'_> {
    fn program_hash(&mut self, command: &str) -> Option<String> {
        let target = windows_text::command_target(command, &|path| HashCache::is_file(Path::new(path)))?;
        self.hashes.hash(Path::new(&target))
    }

    fn run_values(&mut self, root: &RegKey, root_name: &str, base: &str, user: &str, environment: &Environment) {
        for wow in [false, true] {
            for run in RUN_KEYS {
                let relative = if wow { format!(r"{}\Wow6432Node\{}", base, run) } else { format!(r"{}\{}", base, run) };
                let path = format!(r"{}\{}", root_name, relative);

                let key = match registry::open(root, &relative) {
                    Ok(Some(key)) => key,
                    Ok(None) => continue,
                    Err(_) => {
                        self.items.push(unreadable(PersistenceKind::RunKey, run.rsplit('\\').next().unwrap_or(run), &path, user));
                        continue;
                    }
                };

                for value in key.enum_values().map_while(Result::ok).take(MAX_RUN_VALUES) {
                    let (name, data) = value;
                    let Ok(raw) = String::from_reg_value(&data) else {
                        continue;
                    };
                    let command = environment.run_value(&raw);
                    let hash = self.program_hash(&command);
                    self.items.push(item(PersistenceKind::RunKey, &name, &path, &command, user, true, hash));
                }
            }
        }
    }

    fn run_keys(&mut self, hives: &[Hive]) {
        self.run_values(&registry::machine(), "HKLM", "SOFTWARE", EVERY_USER, &Environment::system());
        for hive in hives {
            self.run_values(&hive.key, &format!(r"HKU\{}", hive.profile.sid), "Software", &hive.profile.name, &hive.profile.environment());
        }
    }

    fn services(&mut self) -> Result<(), String> {
        let machine = registry::machine();
        let services =
            registry::open(&machine, SERVICES).map_err(|e| format!("Failed to read {}: {}", SERVICES, e))?.ok_or_else(|| format!("{} is missing", SERVICES))?;
        let environment = Environment::system();

        for name in registry::subkeys(&services, MAX_SERVICES) {
            let path = format!(r"HKLM\{}\{}", SERVICES, name);
            let key = match registry::open(&services, &name) {
                Ok(Some(key)) => key,
                Ok(None) => continue,
                Err(_) => {
                    self.items.push(unreadable(PersistenceKind::WindowsService, &name, &path, SYSTEM_ACCOUNT));
                    continue;
                }
            };

            let Some(image) = registry::text(&key, "ImagePath") else {
                continue;
            };
            let command = environment.normalize(&image);
            let enabled = registry::number(&key, "Start").is_some_and(|start| AUTOMATIC_START.contains(&start));
            let user = match (registry::number(&key, "Type"), registry::text(&key, "ObjectName")) {
                (Some(kind), Some(account)) if kind & SERVICE_TYPES != 0 => account,
                (Some(kind), None) if kind & SERVICE_TYPES != 0 => "LocalSystem".to_string(),
                _ => SYSTEM_ACCOUNT.to_string(),
            };
            let hash = self.program_hash(&command);
            self.items.push(item(PersistenceKind::WindowsService, &name, &path, &command, &user, enabled, hash));
        }

        Ok(())
    }

    fn task(&mut self, name: &str, path: &Path) {
        let location = path.to_string_lossy();
        let bytes = match fs::metadata(path) {
            Ok(metadata) if metadata.len() > MAX_TASK_BYTES => return self.items.push(unreadable(PersistenceKind::ScheduledTask, name, &location, "")),
            Ok(_) => fs::read(path),
            Err(e) => Err(e),
        };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(e) if registry::is_absent(&e) => return,
            Err(_) => return self.items.push(unreadable(PersistenceKind::ScheduledTask, name, &location, "")),
        };

        let hash = Some(sha256_hex(&bytes));
        let Ok(task) = windows_text::parse_task(&bytes) else {
            return self.items.push(item(PersistenceKind::ScheduledTask, name, &location, "", "", true, hash));
        };

        let environment = Environment::system();
        let user = if task.principal.is_empty() { String::new() } else { windows_text::account_name(&task.principal, None) };
        if task.actions.is_empty() {
            return self.items.push(item(PersistenceKind::ScheduledTask, name, &location, "", &user, task.enabled, hash));
        }

        for (index, action) in task.actions.iter().enumerate() {
            let label = if index == 0 { name.to_string() } else { format!("{} [{}]", name, index + 1) };
            let command = clip(&windows_text::task_command(action, &|variable| environment.get(variable)), MAX_COMMAND_BYTES).to_string();
            self.items.push(item(PersistenceKind::ScheduledTask, &label, &location, &command, &user, task.enabled, hash.clone()));
        }
    }

    fn tasks(&mut self) {
        let root = PathBuf::from(Environment::system().expand(r"%SystemRoot%\System32\Tasks"));
        let mut pending = vec![(root.clone(), 0usize)];
        let mut seen = 0usize;

        while let Some((directory, depth)) = pending.pop() {
            let entries = match fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(e) if registry::is_absent(&e) => continue,
                Err(_) => {
                    let location = directory.to_string_lossy();
                    self.items.push(unreadable(PersistenceKind::ScheduledTask, &location, &location, ""));
                    continue;
                }
            };

            let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            paths.sort();
            for path in paths {
                if path.is_dir() {
                    if depth < MAX_TASK_DEPTH {
                        pending.push((path, depth + 1));
                    }
                    continue;
                }
                if seen >= MAX_TASKS {
                    return;
                }
                seen += 1;

                let relative = path.strip_prefix(&root).unwrap_or(&path).to_string_lossy().into_owned();
                self.task(&format!(r"\{}", relative), &path);
            }
        }
    }

    fn startup_folder(&mut self, directory: &Path, user: &str) {
        let location = directory.to_string_lossy();
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(e) if registry::is_absent(&e) => return,
            Err(_) => return self.items.push(unreadable(PersistenceKind::StartupFolder, &location, &location, user)),
        };

        let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).filter(|path| !path.is_dir()).collect();
        paths.sort();
        for path in paths.into_iter().take(MAX_STARTUP_FILES) {
            let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
            if name.eq_ignore_ascii_case("desktop.ini") {
                continue;
            }

            let file = path.to_string_lossy().into_owned();
            let hash = self.hashes.hash(&path);
            self.items.push(item(PersistenceKind::StartupFolder, &name, &file, &file, user, true, hash));
        }
    }

    fn startup_folders(&mut self, profiles: &[Profile]) {
        self.startup_folder(Path::new(&Environment::system().expand(COMMON_STARTUP)), EVERY_USER);
        for profile in profiles.iter().filter(|profile| !profile.directory.is_empty()) {
            self.startup_folder(&Path::new(&profile.directory).join(USER_STARTUP), &profile.name);
        }
    }
}

/// Everything Windows starts by itself that the agent knows where to look for. A place that cannot be read is reported as an item
/// of its own, and only the services key being unreadable fails the scan, as without it there is nothing to compare against
pub fn scan(hashes: &mut HashCache) -> Result<Vec<PersistenceItem>, String> {
    let profiles = registry::profiles();
    let hives = registry::user_hives(&profiles);

    hashes.begin_scan();
    let mut scan = Scan { hashes, items: Vec::new() };
    let services = scan.services();
    scan.run_keys(&hives);
    scan.tasks();
    scan.startup_folders(&profiles);
    let items = scan.items;
    hashes.end_scan();

    services.map(|()| items)
}
